//! Per-file blake3 hash tracking in redb.
//!
//! [`IndexState`] stores file records and repository metadata for the
//! code-intelligence indexing pipeline. Immutable-generation callers provide
//! the shared database that also holds graph and publication tables.
//!
//! All redb operations are synchronous. Callers in async contexts **must**
//! wrap calls in [`tokio::task::spawn_blocking`].

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::private_database_witness::PrivateDatabaseWitness;
use crate::structural_ir::ExtractorOutput;

/// redb table: repo-level metadata keyed by string label.
const INDEX_META: TableDefinition<&str, &[u8]> = TableDefinition::new("index_meta");

/// redb table: per-file records keyed by relative path.
const INDEX_FILES: TableDefinition<&str, &[u8]> = TableDefinition::new("index_files");

/// Per-document extraction facts used to resolve a complete structural graph
/// without reparsing unchanged source files. The path is the binding key; the
/// embedded file hash is the authority check because extraction is path-sensitive
/// (for example, test-directory classification).
const INDEX_DOCUMENT_FACTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("index_document_facts_v2");

const INDEX_STATE_PUBLICATION_PROOF_SCHEMA: &str = "h00/index-state-publication-proof/v1";

#[cfg(test)]
thread_local! {
    static PUBLICATION_PROOF_CAPTURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PUBLICATION_PROOF_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Errors from index state operations.
#[derive(Debug, Error)]
pub enum IndexStateError {
    #[error("redb error: {0}")]
    Redb(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("index state was opened read-only")]
    ReadOnly,

    #[error("index-state content proof mismatch: {0}")]
    ContentProof(String),
}

/// Canonical digest and bounded work population for one persisted index-state
/// table. Length framing makes the digest independent of concatenation
/// ambiguity while redb's ordered iteration makes it deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IndexStatePopulationProof {
    blake3: String,
    records: u64,
    bytes: u64,
}

/// Manifest-bound proof for every source population that may seed a later
/// incremental generation. This is durable authority, not cache metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexStatePublicationProof {
    schema_version: String,
    metadata: IndexStatePopulationProof,
    files: IndexStatePopulationProof,
    document_facts: IndexStatePopulationProof,
}

pub(crate) type BoundIndexStatePublicationProof =
    PrivateDatabaseWitness<IndexStatePublicationProof>;

#[cfg(test)]
impl IndexStatePublicationProof {
    pub(crate) fn test_fixture() -> Self {
        let empty = IndexStatePopulationProof {
            blake3: "0".repeat(64),
            records: 0,
            bytes: 0,
        };
        Self {
            schema_version: INDEX_STATE_PUBLICATION_PROOF_SCHEMA.into(),
            metadata: empty.clone(),
            files: empty.clone(),
            document_facts: empty,
        }
    }
}

/// Repository-level metadata for the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexMetadata {
    /// Absolute path of the repository root that was indexed.
    pub repo_root: String,
    /// Timestamp (epoch millis) of the last full scan.
    pub last_full_scan: Option<i64>,
    /// Timestamp (epoch millis) of the last incremental or full update.
    pub last_update: Option<i64>,
    /// Git HEAD commit hash at time of last index.
    pub git_head: Option<String>,
    /// Total number of indexed files.
    pub total_files: u64,
    /// Total number of extracted symbols.
    pub total_symbols: u64,
    /// Total number of graph edges.
    pub total_edges: u64,
}

/// Per-file index record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    /// blake3 content hash of the file.
    pub blake3_hash: String,
    /// Timestamp (epoch millis) when the file was last indexed.
    pub last_indexed: i64,
    /// Number of symbols extracted from this file.
    pub symbol_count: u32,
    /// Programming language of the file (e.g. "rust").
    pub language: String,
}

/// Exact structural source authority loaded from one immutable generation.
///
/// A file record proves discovery and content identity. Presence in
/// `document_fact_paths` additionally proves that structural extraction
/// completed for that file, including the legitimate zero-symbol case.
#[derive(Debug, Clone)]
pub struct IndexedSourceSnapshot {
    files: Vec<(String, FileRecord)>,
    document_fact_paths: BTreeSet<String>,
}

impl IndexedSourceSnapshot {
    #[must_use]
    pub fn files(&self) -> &[(String, FileRecord)] {
        &self.files
    }

    #[must_use]
    pub const fn document_fact_paths(&self) -> &BTreeSet<String> {
        &self.document_fact_paths
    }
}

/// Minimal reusable input for a new immutable index generation.
///
/// This deliberately excludes the materialized graph, capability receipts,
/// provider payloads, and publication controls. Those are outputs that every
/// candidate must derive and validate anew.
#[derive(Debug, Clone)]
pub(crate) struct IncrementalIndexBasis {
    pub(crate) files: Vec<(String, FileRecord)>,
    pub(crate) document_facts: Vec<ExtractorOutput>,
}

pub(crate) struct ValidatedIndexStateContent {
    pub(crate) proof: IndexStatePublicationProof,
    pub(crate) metadata: Option<IndexMetadata>,
    pub(crate) indexed_sources: IndexedSourceSnapshot,
    pub(crate) basis: IncrementalIndexBasis,
}

/// Persistent index state backed by a caller-owned generation database.
pub struct IndexState {
    db: IndexDatabase,
}

enum IndexDatabase {
    ReadWrite(Arc<Database>),
    ReadOnly(Arc<ReadOnlyDatabase>),
}

impl IndexDatabase {
    fn begin_read(&self) -> Result<redb::ReadTransaction, redb::TransactionError> {
        match self {
            Self::ReadWrite(database) => database.begin_read(),
            Self::ReadOnly(database) => database.begin_read(),
        }
    }

    fn writable(&self) -> Result<&Database, IndexStateError> {
        match self {
            Self::ReadWrite(database) => Ok(database),
            Self::ReadOnly(_) => Err(IndexStateError::ReadOnly),
        }
    }

    const fn writable_database(&self) -> Result<&Arc<Database>, IndexStateError> {
        match self {
            Self::ReadWrite(database) => Ok(database),
            Self::ReadOnly(_) => Err(IndexStateError::ReadOnly),
        }
    }
}

impl IndexState {
    #[cfg(test)]
    pub(crate) fn reset_publication_proof_counts() {
        PUBLICATION_PROOF_CAPTURES.with(|count| count.set(0));
        PUBLICATION_PROOF_VALIDATIONS.with(|count| count.set(0));
    }

    #[cfg(test)]
    pub(crate) fn publication_proof_counts() -> (usize, usize) {
        (
            PUBLICATION_PROOF_CAPTURES.with(std::cell::Cell::get),
            PUBLICATION_PROOF_VALIDATIONS.with(std::cell::Cell::get),
        )
    }

    /// Create writable index state in a caller-owned database.
    ///
    /// The database may also contain graph and publication tables; this
    /// constructor creates only the index tables.
    pub fn new(db: Arc<Database>) -> Result<Self, IndexStateError> {
        let state = Self {
            db: IndexDatabase::ReadWrite(db),
        };
        state.ensure_tables()?;
        Ok(state)
    }

    /// Create read-only index state in a caller-owned OS-read-only database.
    ///
    /// This never creates tables, repairs the database, or writes auxiliary
    /// artifacts. Missing index tables remain typed redb read errors.
    pub const fn new_read_only(db: Arc<ReadOnlyDatabase>) -> Self {
        Self {
            db: IndexDatabase::ReadOnly(db),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_test(dir: &Path) -> Result<Self, IndexStateError> {
        let path = dir.join("index-state-test.redb");
        let db =
            Arc::new(Database::create(&path).map_err(|e| IndexStateError::Redb(e.to_string()))?);
        Self::new(db)
    }

    fn ensure_tables(&self) -> Result<(), IndexStateError> {
        let txn = self
            .db
            .writable()?
            .begin_write()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        {
            let _meta = txn
                .open_table(INDEX_META)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            let _files = txn
                .open_table(INDEX_FILES)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            let _document_facts = txn
                .open_table(INDEX_DOCUMENT_FACTS)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        Ok(())
    }

    /// Read repository metadata, if any has been stored.
    pub fn get_metadata(&self) -> Result<Option<IndexMetadata>, IndexStateError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        let table = txn
            .open_table(INDEX_META)
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        let guard = table
            .get("metadata")
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        match guard {
            Some(val) => {
                let meta: IndexMetadata = rmp_serde::from_slice(val.value())
                    .map_err(|e| IndexStateError::Serialization(e.to_string()))?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    /// Write (overwrite) repository metadata.
    pub fn set_metadata(&self, meta: &IndexMetadata) -> Result<(), IndexStateError> {
        let bytes = rmp_serde::to_vec_named(meta)
            .map_err(|e| IndexStateError::Serialization(e.to_string()))?;
        let txn = self
            .db
            .writable()?
            .begin_write()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        {
            let mut table = txn
                .open_table(INDEX_META)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            table
                .insert("metadata", bytes.as_slice())
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        Ok(())
    }

    /// Retrieve the file record for a given relative path.
    pub fn get_file(&self, path: &str) -> Result<Option<FileRecord>, IndexStateError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        let table = txn
            .open_table(INDEX_FILES)
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        let guard = table
            .get(path)
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        match guard {
            Some(val) => {
                let record: FileRecord = rmp_serde::from_slice(val.value())
                    .map_err(|e| IndexStateError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Insert or update a file record.
    pub fn set_file(&self, path: &str, record: &FileRecord) -> Result<(), IndexStateError> {
        let bytes = rmp_serde::to_vec_named(record)
            .map_err(|e| IndexStateError::Serialization(e.to_string()))?;
        let txn = self
            .db
            .writable()?
            .begin_write()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        {
            let mut table = txn
                .open_table(INDEX_FILES)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            table
                .insert(path, bytes.as_slice())
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        Ok(())
    }

    /// Remove a file record by path.
    pub fn remove_file(&self, path: &str) -> Result<(), IndexStateError> {
        let txn = self
            .db
            .writable()?
            .begin_write()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        {
            let mut table = txn
                .open_table(INDEX_FILES)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            table
                .remove(path)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        Ok(())
    }

    /// Return all file records as `(path, record)` pairs.
    pub fn all_files(&self) -> Result<Vec<(String, FileRecord)>, IndexStateError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        let table = txn
            .open_table(INDEX_FILES)
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        let mut results = Vec::new();
        for entry in table
            .iter()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?
        {
            let (key_guard, val_guard) = entry.map_err(|e| IndexStateError::Redb(e.to_string()))?;
            let path = key_guard.value().to_string();
            let record: FileRecord = rmp_serde::from_slice(val_guard.value())
                .map_err(|e| IndexStateError::Serialization(e.to_string()))?;
            results.push((path, record));
        }
        Ok(results)
    }

    /// Return every persisted per-document extraction result.
    ///
    /// Callers must still verify each fact's embedded path and content hash
    /// against the authoritative discovery/hash pass before reuse.
    pub fn all_document_facts(&self) -> Result<Vec<ExtractorOutput>, IndexStateError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        let table = txn
            .open_table(INDEX_DOCUMENT_FACTS)
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        let mut results = Vec::new();
        for entry in table
            .iter()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?
        {
            let (key_guard, value_guard) =
                entry.map_err(|e| IndexStateError::Redb(e.to_string()))?;
            let path = key_guard.value();
            let facts: ExtractorOutput = rmp_serde::from_slice(value_guard.value())
                .map_err(|e| IndexStateError::Serialization(e.to_string()))?;
            if facts.file_path != path {
                return Err(IndexStateError::Serialization(format!(
                    "document facts key `{path}` does not match embedded path `{}`",
                    facts.file_path
                )));
            }
            results.push(facts);
        }
        Ok(results)
    }

    /// Load file identity and exact structural extraction coverage together.
    /// The generation database is immutable while queried, so these two table
    /// reads cannot be spliced across publication generations.
    pub fn indexed_source_snapshot(&self) -> Result<IndexedSourceSnapshot, IndexStateError> {
        let files = self.all_files()?;
        let document_fact_paths = self
            .all_document_facts()?
            .into_iter()
            .map(|facts| facts.file_path)
            .collect();
        Ok(IndexedSourceSnapshot {
            files,
            document_fact_paths,
        })
    }

    /// Atomically replace the complete persisted document-fact population.
    ///
    /// Immutable-generation callers invoke this only on a private candidate,
    /// so readers never observe the clear-and-fill transaction.
    pub fn replace_document_facts(&self, facts: &[ExtractorOutput]) -> Result<(), IndexStateError> {
        let mut encoded = Vec::with_capacity(facts.len());
        for document in facts {
            let bytes = rmp_serde::to_vec_named(document)
                .map_err(|e| IndexStateError::Serialization(e.to_string()))?;
            encoded.push((document.file_path.as_str(), bytes));
        }

        let txn = self
            .db
            .writable()?
            .begin_write()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        {
            let mut table = txn
                .open_table(INDEX_DOCUMENT_FACTS)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            table
                .retain(|_, _| false)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            for (path, bytes) in &encoded {
                table
                    .insert(*path, bytes.as_slice())
                    .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            }
        }
        txn.commit()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        Ok(())
    }

    /// Capture the exact persisted metadata, file-record, and extraction-fact
    /// populations that publication will bind into the immutable manifest.
    pub(crate) fn capture_publication_proof(
        &self,
    ) -> Result<IndexStatePublicationProof, IndexStateError> {
        #[cfg(test)]
        PUBLICATION_PROOF_CAPTURES.with(|count| count.set(count.get().saturating_add(1)));
        Ok(self.read_validated_content()?.proof)
    }

    /// Bind a freshly captured proof to the exact writable candidate database
    /// that produced it. Publication consumes this witness once; a reopened or
    /// substituted database must validate and decode its persisted state.
    pub(crate) fn capture_bound_publication_proof(
        &self,
    ) -> Result<BoundIndexStatePublicationProof, IndexStateError> {
        let proof = self.capture_publication_proof()?;
        Ok(PrivateDatabaseWitness::bind(
            self.db.writable_database()?,
            proof,
        ))
    }

    /// Validate and decode all reusable source populations from the same redb
    /// handle. Returning the decoded values closes the proof-to-use gap: callers
    /// never authenticate one table read and hydrate a later independent read.
    pub(crate) fn validate_publication_proof(
        &self,
        expected: &IndexStatePublicationProof,
    ) -> Result<ValidatedIndexStateContent, IndexStateError> {
        #[cfg(test)]
        PUBLICATION_PROOF_VALIDATIONS.with(|count| count.set(count.get().saturating_add(1)));
        let content = self.read_validated_content()?;
        if content.proof != *expected {
            return Err(IndexStateError::ContentProof(
                "opened metadata, file, or extraction-fact population differs from the immutable manifest"
                    .into(),
            ));
        }
        Ok(content)
    }

    fn read_validated_content(&self) -> Result<ValidatedIndexStateContent, IndexStateError> {
        let transaction = self
            .db
            .begin_read()
            .map_err(|error| IndexStateError::Redb(error.to_string()))?;

        let metadata_table = transaction
            .open_table(INDEX_META)
            .map_err(|error| IndexStateError::Redb(error.to_string()))?;
        let mut metadata_entries = Vec::new();
        let mut metadata = None;
        for entry in metadata_table
            .iter()
            .map_err(|error| IndexStateError::Redb(error.to_string()))?
        {
            let (key, value) = entry.map_err(|error| IndexStateError::Redb(error.to_string()))?;
            let key = key.value().to_owned();
            let bytes = value.value().to_vec();
            if key == "metadata" {
                metadata = Some(
                    rmp_serde::from_slice(&bytes)
                        .map_err(|error| IndexStateError::Serialization(error.to_string()))?,
                );
            }
            metadata_entries.push((key, bytes));
        }

        let files_table = transaction
            .open_table(INDEX_FILES)
            .map_err(|error| IndexStateError::Redb(error.to_string()))?;
        let mut file_entries = Vec::new();
        let mut files = Vec::new();
        for entry in files_table
            .iter()
            .map_err(|error| IndexStateError::Redb(error.to_string()))?
        {
            let (key, value) = entry.map_err(|error| IndexStateError::Redb(error.to_string()))?;
            let path = key.value().to_owned();
            let bytes = value.value().to_vec();
            let record: FileRecord = rmp_serde::from_slice(&bytes)
                .map_err(|error| IndexStateError::Serialization(error.to_string()))?;
            file_entries.push((path.clone(), bytes));
            files.push((path, record));
        }

        let facts_table = transaction
            .open_table(INDEX_DOCUMENT_FACTS)
            .map_err(|error| IndexStateError::Redb(error.to_string()))?;
        let mut fact_entries = Vec::new();
        let mut document_facts = Vec::new();
        for entry in facts_table
            .iter()
            .map_err(|error| IndexStateError::Redb(error.to_string()))?
        {
            let (key, value) = entry.map_err(|error| IndexStateError::Redb(error.to_string()))?;
            let path = key.value().to_owned();
            let bytes = value.value().to_vec();
            let facts: ExtractorOutput = rmp_serde::from_slice(&bytes)
                .map_err(|error| IndexStateError::Serialization(error.to_string()))?;
            if facts.file_path != path {
                return Err(IndexStateError::Serialization(format!(
                    "document facts key `{path}` does not match embedded path `{}`",
                    facts.file_path
                )));
            }
            fact_entries.push((path, bytes));
            document_facts.push(facts);
        }

        let records = files
            .iter()
            .map(|(path, record)| (path.as_str(), record))
            .collect::<BTreeMap<_, _>>();
        for facts in &document_facts {
            let Some(record) = records.get(facts.file_path.as_str()) else {
                return Err(IndexStateError::Serialization(format!(
                    "document facts for `{}` have no file record",
                    facts.file_path
                )));
            };
            if record.blake3_hash != facts.file_hash {
                return Err(IndexStateError::Serialization(format!(
                    "document facts hash for `{}` does not match its file record",
                    facts.file_path
                )));
            }
        }

        let indexed_sources = IndexedSourceSnapshot {
            files: files.clone(),
            document_fact_paths: document_facts
                .iter()
                .map(|facts| facts.file_path.clone())
                .collect(),
        };
        Ok(ValidatedIndexStateContent {
            proof: IndexStatePublicationProof {
                schema_version: INDEX_STATE_PUBLICATION_PROOF_SCHEMA.into(),
                metadata: population_proof(b"h00/index-state/metadata/v1\0", &metadata_entries),
                files: population_proof(b"h00/index-state/files/v1\0", &file_entries),
                document_facts: population_proof(
                    b"h00/index-state/document-facts/v2\0",
                    &fact_entries,
                ),
            },
            metadata,
            indexed_sources,
            basis: IncrementalIndexBasis {
                files,
                document_facts,
            },
        })
    }

    /// Atomically persist the complete source-state basis for one private
    /// generation after indexing has finished.
    ///
    /// Every fact must be backed by an exact path/hash file record. File records
    /// without facts are allowed: the next diff treats them as changed and
    /// repairs the missing cache by re-extracting that document.
    pub(crate) fn replace_source_state(
        &self,
        files: &[(String, FileRecord)],
        document_facts: &[ExtractorOutput],
    ) -> Result<(), IndexStateError> {
        let mut records = std::collections::BTreeMap::new();
        for (path, record) in files {
            if records.insert(path.as_str(), record).is_some() {
                return Err(IndexStateError::Serialization(format!(
                    "duplicate file record for `{path}`"
                )));
            }
        }

        let mut encoded_facts = Vec::with_capacity(document_facts.len());
        let mut fact_paths = std::collections::BTreeSet::new();
        for facts in document_facts {
            if !fact_paths.insert(facts.file_path.as_str()) {
                return Err(IndexStateError::Serialization(format!(
                    "duplicate document facts for `{}`",
                    facts.file_path
                )));
            }
            let Some(record) = records.get(facts.file_path.as_str()) else {
                return Err(IndexStateError::Serialization(format!(
                    "document facts for `{}` have no file record",
                    facts.file_path
                )));
            };
            if record.blake3_hash != facts.file_hash {
                return Err(IndexStateError::Serialization(format!(
                    "document facts hash for `{}` does not match its file record",
                    facts.file_path
                )));
            }
            let bytes = rmp_serde::to_vec_named(facts)
                .map_err(|e| IndexStateError::Serialization(e.to_string()))?;
            encoded_facts.push((facts.file_path.as_str(), bytes));
        }
        let encoded_files = files
            .iter()
            .map(|(path, record)| {
                rmp_serde::to_vec_named(record)
                    .map(|bytes| (path.as_str(), bytes))
                    .map_err(|error| IndexStateError::Serialization(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let txn = self
            .db
            .writable()?
            .begin_write()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        {
            let mut files = txn
                .open_table(INDEX_FILES)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            files
                .retain(|_, _| false)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            for (path, bytes) in &encoded_files {
                files
                    .insert(*path, bytes.as_slice())
                    .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            }
        }
        {
            let mut facts = txn
                .open_table(INDEX_DOCUMENT_FACTS)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            facts
                .retain(|_, _| false)
                .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            for (path, bytes) in &encoded_facts {
                facts
                    .insert(*path, bytes.as_slice())
                    .map_err(|e| IndexStateError::Redb(e.to_string()))?;
            }
        }
        txn.commit()
            .map_err(|e| IndexStateError::Redb(e.to_string()))?;
        Ok(())
    }
}

fn population_proof(domain: &[u8], entries: &[(String, Vec<u8>)]) -> IndexStatePopulationProof {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    let mut bytes = 0_u64;
    for (key, value) in entries {
        let key = key.as_bytes();
        hasher.update(&(key.len() as u64).to_le_bytes());
        hasher.update(key);
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
        bytes = bytes.saturating_add(key.len() as u64);
        bytes = bytes.saturating_add(value.len() as u64);
    }
    IndexStatePopulationProof {
        blake3: hasher.finalize().to_hex().to_string(),
        records: entries.len() as u64,
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_temp() -> (TempDir, IndexState) {
        let dir = TempDir::new().expect("tempdir");
        let state = IndexState::new_test(dir.path()).expect("open");
        (dir, state)
    }

    #[test]
    fn set_and_get_file() {
        let (_dir, state) = open_temp();
        let record = FileRecord {
            blake3_hash: "abc123".into(),
            last_indexed: 1710000000000,
            symbol_count: 42,
            language: "rust".into(),
        };
        state.set_file("src/main.rs", &record).expect("set");
        let got = state.get_file("src/main.rs").expect("get");
        let got = got.expect("should exist");
        assert_eq!(got.blake3_hash, "abc123");
        assert_eq!(got.symbol_count, 42);
        assert_eq!(got.language, "rust");
        assert_eq!(got.last_indexed, 1710000000000);
    }

    #[test]
    fn indexed_source_snapshot_distinguishes_zero_symbols_from_failed_extraction() {
        let (_dir, state) = open_temp();
        let empty_facts = crate::extractor::extract_source("// no symbols\n", "src/empty.rs")
            .expect("extract legitimate zero-symbol source");
        for (path, hash) in [
            ("src/empty.rs", empty_facts.file_hash.as_str()),
            ("src/broken.rs", "failed-source-hash"),
        ] {
            state
                .set_file(
                    path,
                    &FileRecord {
                        blake3_hash: hash.into(),
                        last_indexed: 1,
                        symbol_count: 0,
                        language: "rust".into(),
                    },
                )
                .expect("persist measured source record");
        }
        state
            .replace_document_facts(&[empty_facts])
            .expect("persist successful extraction facts");

        let snapshot = state
            .indexed_source_snapshot()
            .expect("load indexed source authority");
        assert_eq!(snapshot.files().len(), 2);
        assert!(snapshot.document_fact_paths().contains("src/empty.rs"));
        assert!(!snapshot.document_fact_paths().contains("src/broken.rs"));
    }

    #[test]
    fn get_missing_file_returns_none() {
        let (_dir, state) = open_temp();
        let got = state.get_file("nonexistent.rs").expect("get");
        assert!(got.is_none());
    }

    #[test]
    fn remove_file() {
        let (_dir, state) = open_temp();
        let record = FileRecord {
            blake3_hash: "hash1".into(),
            last_indexed: 100,
            symbol_count: 5,
            language: "rust".into(),
        };
        state.set_file("lib.rs", &record).expect("set");
        state.remove_file("lib.rs").expect("remove");
        assert!(state.get_file("lib.rs").expect("get").is_none());
    }

    #[test]
    fn all_files_roundtrip() {
        let (_dir, state) = open_temp();
        for i in 0..3 {
            let record = FileRecord {
                blake3_hash: format!("hash_{i}"),
                last_indexed: i as i64 * 1000,
                symbol_count: i as u32,
                language: "rust".into(),
            };
            state
                .set_file(&format!("file_{i}.rs"), &record)
                .expect("set");
        }
        let all = state.all_files().expect("all_files");
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn document_facts_roundtrip_and_replace_exact_population() {
        let (_dir, state) = open_temp();
        let alpha = crate::extractor::extract_source("pub struct Alpha;\n", "src/alpha.rs")
            .expect("extract alpha facts");
        let beta = crate::extractor::extract_source("pub struct Beta;\n", "src/beta.rs")
            .expect("extract beta facts");

        state
            .replace_document_facts(std::slice::from_ref(&alpha))
            .expect("persist alpha facts");
        let first = state.all_document_facts().expect("read alpha facts");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].file_path, "src/alpha.rs");
        assert_eq!(first[0].file_hash, alpha.file_hash);
        assert_eq!(first[0].symbols[0].name, "Alpha");

        state
            .replace_document_facts(std::slice::from_ref(&beta))
            .expect("replace with beta facts");
        let second = state.all_document_facts().expect("read beta facts");
        assert_eq!(second.len(), 1, "replacement must remove stale facts");
        assert_eq!(second[0].file_path, "src/beta.rs");
        assert_eq!(second[0].file_hash, beta.file_hash);
        assert_eq!(second[0].symbols[0].name, "Beta");
    }

    #[test]
    fn typed_structural_capture_gaps_roundtrip_exactly() {
        let (_dir, state) = open_temp();
        let facts = crate::extractor::extract_source(
            "const base = { value: 1 };\nexport const extended = { ...base };\n",
            "src/contracts.ts",
        )
        .expect("extract TypeScript capture-gap facts");
        assert_eq!(facts.capture_gaps.len(), 1, "positive gap control");
        assert_eq!(facts.capture_gaps[0].kind, "unrepresented_object_spread");

        state
            .replace_document_facts(std::slice::from_ref(&facts))
            .expect("persist typed capture-gap facts");
        let restored = state
            .all_document_facts()
            .expect("restore typed capture-gap facts");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].capture_gaps, facts.capture_gaps);
    }

    #[test]
    fn invalid_incremental_basis_is_rejected_before_mutating_existing_state() {
        let (_dir, state) = open_temp();
        let alpha = crate::extractor::extract_source("pub struct Alpha;\n", "src/alpha.rs")
            .expect("extract alpha facts");
        let original = IncrementalIndexBasis {
            files: vec![(
                alpha.file_path.clone(),
                FileRecord {
                    blake3_hash: alpha.file_hash.clone(),
                    last_indexed: 1,
                    symbol_count: alpha.symbols.len() as u32,
                    language: "rust".into(),
                },
            )],
            document_facts: vec![alpha.clone()],
        };
        state
            .replace_source_state(&original.files, &original.document_facts)
            .expect("seed original basis");

        let mut mismatched = alpha;
        mismatched.file_hash = "not-the-record-hash".into();
        let invalid = IncrementalIndexBasis {
            files: original.files.clone(),
            document_facts: vec![mismatched],
        };
        let error = state
            .replace_source_state(&invalid.files, &invalid.document_facts)
            .expect_err("mismatched authority must be rejected");
        assert!(matches!(error, IndexStateError::Serialization(_)));

        let after = state
            .read_validated_content()
            .expect("read basis after refusal");
        let after = after.basis;
        assert_eq!(after.files.len(), 1);
        assert_eq!(after.files[0].0, "src/alpha.rs");
        assert_eq!(after.document_facts.len(), 1);
        assert_eq!(
            after.document_facts[0].file_hash,
            original.files[0].1.blake3_hash
        );
    }

    #[test]
    fn metadata_roundtrip() {
        let (_dir, state) = open_temp();
        assert!(state.get_metadata().expect("get").is_none());

        let meta = IndexMetadata {
            repo_root: "/home/user/project".into(),
            last_full_scan: Some(1710000000000),
            last_update: Some(1710000001000),
            git_head: Some("abc123def".into()),
            total_files: 100,
            total_symbols: 5000,
            total_edges: 3000,
        };
        state.set_metadata(&meta).expect("set");
        let got = state.get_metadata().expect("get").expect("should exist");
        assert_eq!(got.repo_root, "/home/user/project");
        assert_eq!(got.last_full_scan, Some(1710000000000));
        assert_eq!(got.git_head, Some("abc123def".into()));
        assert_eq!(got.total_files, 100);
        assert_eq!(got.total_symbols, 5000);
        assert_eq!(got.total_edges, 3000);
    }

    #[test]
    fn overwrite_file_record() {
        let (_dir, state) = open_temp();
        let r1 = FileRecord {
            blake3_hash: "old_hash".into(),
            last_indexed: 100,
            symbol_count: 5,
            language: "rust".into(),
        };
        state.set_file("main.rs", &r1).expect("set");

        let r2 = FileRecord {
            blake3_hash: "new_hash".into(),
            last_indexed: 200,
            symbol_count: 10,
            language: "rust".into(),
        };
        state.set_file("main.rs", &r2).expect("overwrite");

        let got = state.get_file("main.rs").expect("get").expect("exists");
        assert_eq!(got.blake3_hash, "new_hash");
        assert_eq!(got.symbol_count, 10);
    }
}
