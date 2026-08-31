//! Redb persistence for the knowledge graph.
//!
//! Provides [`GraphStore`] which can snapshot-save and snapshot-load a
//! [`KnowledgeGraph`] to/from a redb database. All redb I/O is wrapped in
//! [`tokio::task::spawn_blocking`] so this module is safe to call from async.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use redb::{Database, ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::graph::{GraphEdge, GraphNode, KnowledgeGraph, SourceSpan};
use crate::private_database_witness::PrivateDatabaseWitness;
use crate::reachability::{PersistedReachabilityEvidence, ReachabilityEvidence};

// ---------------------------------------------------------------------------
// Table definitions
// ---------------------------------------------------------------------------

/// Full graph snapshot: single key "latest" → bincode-serialized `GraphSnapshot`.
const GRAPH_SNAPSHOT: TableDefinition<&str, &[u8]> = TableDefinition::new("graph_snapshot");

/// Compact generation-local reachability projection. Graph-owned classified
/// node identities are represented by one population digest rather than
/// duplicated here. A graph-only save clears this table; only the combined
/// save path may attach evidence to the exact graph it validated.
const GRAPH_REACHABILITY_EVIDENCE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("graph_reachability_evidence");
const REACHABILITY_EVIDENCE_KEY: &str = "latest";

#[cfg(test)]
thread_local! {
    static PUBLICATION_SNAPSHOT_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PUBLICATION_PROOF_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Code-intel graph metadata: single key `"schema_version"` → the `u64`
/// schema version of the `GraphNode`/`GraphSnapshot` byte layout that produced
/// the persisted tables. Used to detect a schema bump on load.
const GRAPH_META: TableDefinition<&str, u64> = TableDefinition::new("graph_meta");

/// Workspace-origin stamp (ADR-0033, ROOT-8): single key
/// [`ORIGIN_KEY`] → the **canonical absolute workspace root** the persisted
/// code-intel graph was indexed from. Stored as a separate string table so it
/// can be read PRE-decode (before the snapshot bytes are touched) and yields a
/// real-path diagnostic on a mismatch. A read-intent load whose querying root
/// does not match this stamp refuses, fail-closed, rather than splice one
/// workspace's symbols/reachability onto another. The byte layout of this table
/// is independent of the bincode snapshot layout, so introducing it does not by
/// itself change [`SCHEMA_VERSION`].
const GRAPH_ORIGIN: TableDefinition<&str, &str> = TableDefinition::new("graph_origin");

/// The single key under which the canonical workspace root is stamped in
/// [`GRAPH_ORIGIN`].
const ORIGIN_KEY: &str = "workspace_root";

/// Index-time rustc/clippy oracle outcome for the exact persisted generation.
/// `1` means the pass completed authoritatively; `0` means it was disabled or
/// degraded. Current publications require this key—absence is not success.
const ORACLE_RAN_OK_KEY: &str = "oracle_ran_ok";

/// Classification provenance: the human build, exact classifier content, and
/// configuration that produced the persisted reachability classes.
///
/// Dedicated provenance table beside [`GRAPH_ORIGIN`]. Current immutable
/// publications require a complete record; partial or absent provenance cannot
/// become generation authority.
const GRAPH_CLASSIFIED_BY: TableDefinition<&str, &str> =
    TableDefinition::new("graph_classified_by");

/// Keys within [`GRAPH_CLASSIFIED_BY`]. Provider configuration and authority
/// are carried by immutable capability receipts, not duplicated in this table.
const CLASSIFIED_BY_BUILD_IDENTITY_KEY: &str = "build_identity";
const CLASSIFIED_BY_INDEXER_IDENTITY_KEY: &str = "indexer_identity";
const CLASSIFIED_BY_PROVER_CONFIG_KEY: &str = "prover_config";
const CLASSIFIED_BY_TIMESTAMP_KEY: &str = "timestamp";

/// This binary's identity — see [`crate::BUILD_IDENTITY`], which is where it now
/// lives.
///
/// Re-exported here because this module is the classification stamp's home and
/// every existing consumer path reads it from `graph_store`. The definition moved
/// to the crate root so a build without `code-intel` (which gates this whole
/// module) can still state what it is — a binary's identity is not a code-intel
/// concern.
pub use crate::BUILD_IDENTITY;

/// The PROVER configuration: what THIS binary was compiled with.
///
/// `code-intel` is the feature that gates the reachability classifier and the SCIP surface. The
/// memory-substrate features (`store`, `embed-*`) do not change a
/// classification and are deliberately excluded — folding them in would fire
/// the mismatch guard on builds that classify identically (the alarm-fatigue
/// direction D2 warns about).
#[must_use]
pub fn current_prover_config() -> String {
    format!("code-intel={}", u8::from(cfg!(feature = "code-intel")))
}

/// Why the human-facing build provenance is approximate.
///
/// This affects how provenance is rendered, not classification currency. The
/// latter keys on the separate exact [`crate::INDEXER_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproximateIdentity {
    /// Built from a tree with uncommitted changes. `+dirty` is a BOOLEAN, not a
    /// content hash: two DIFFERENT uncommitted trees at the same base commit
    /// stamp identically (the highest-risk dev case).
    Dirty,
    /// Built where git could not answer, so the identity degenerated to
    /// `{CARGO_PKG_VERSION}+nogit`. Every crate here is pinned `0.1.0`
    /// statically, so that is `0.1.0+nogit` for EVERY git-less build of EVERY
    /// revision — verbatim the `CARGO_PKG_VERSION`-only identity ADR-0046
    /// REJECTED as "vacuous by construction".
    NoGit,
}

/// The classification-provenance stamp: who classified, under what, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedBy {
    /// Human-facing artifact provenance — see [`BUILD_IDENTITY`].
    pub build_identity: String,
    /// Exact source/configuration digest for the classifier implementation.
    pub indexer_identity: String,
    /// What the classifying binary was compiled with — [`current_prover_config`].
    pub prover_config: String,
    /// RFC3339 classification time.
    pub timestamp: String,
}

/// Required metadata that makes one persisted graph generation interpretable.
///
/// These fields are written together for immutable publication. Treating any
/// of them as optional allowed an incomplete generation to manufacture
/// authority by defaulting missing evidence to success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphGenerationMetadata {
    pub classified_by: ClassifiedBy,
    pub oracle_ran_ok: bool,
}

impl GraphGenerationMetadata {
    #[must_use]
    pub fn now(oracle_ran_ok: bool) -> Self {
        Self {
            classified_by: ClassifiedBy::now(),
            oracle_ran_ok,
        }
    }
}

impl ClassifiedBy {
    /// The stamp for a classification performed now by this binary.
    ///
    /// Semantic-provider configuration and authority live in the immutable
    /// generation's capability receipts. Duplicating them here created two
    /// authorities that could contradict one another.
    #[must_use]
    pub fn now() -> Self {
        Self {
            build_identity: BUILD_IDENTITY.to_string(),
            indexer_identity: crate::INDEXER_IDENTITY.to_string(),
            prover_config: current_prover_config(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }
    }

    /// Whether — and why — this stamp's human build provenance is approximate.
    #[must_use]
    pub fn approximation(&self) -> Option<ApproximateIdentity> {
        if self.build_identity.ends_with("+dirty") {
            Some(ApproximateIdentity::Dirty)
        } else if self.build_identity.ends_with("+nogit") {
            Some(ApproximateIdentity::NoGit)
        } else {
            None
        }
    }

    /// Whether this stamp came from a build with uncommitted changes.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.approximation() == Some(ApproximateIdentity::Dirty)
    }

    /// One-line human rendering for report headers and `status`.
    #[must_use]
    pub fn render(&self) -> String {
        let approx = match self.approximation() {
            Some(ApproximateIdentity::Dirty) => " (provenance approximate — dirty build)",
            Some(ApproximateIdentity::NoGit) => " (provenance approximate — no git at build time)",
            None => "",
        };
        format!(
            "classified by build {} / classifier {} [{}] at {}{}",
            self.build_identity, self.indexer_identity, self.prover_config, self.timestamp, approx
        )
    }
}

// ---------------------------------------------------------------------------
// Three-axis classification currency (ADR-0046 D3 + rev-3 A2 / A2-bis)
// ---------------------------------------------------------------------------

/// One way the persisted classification can fail to be certifiable.
///
/// The gate's verdict text NAMES the axis — a gate that says only "UNKNOWN"
/// sends its reader hunting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrencyFailure {
    /// No valid persisted reachability evidence proves the exact document
    /// population the classifier was authorized to judge. Documents outside a
    /// valid scoped classification may remain explicitly `Unclassified`
    /// without failing this axis.
    ClassificationAuthorityUnavailable,
    /// Classes are persisted but carry no provenance stamp (a pre-ADR-0046
    /// store, or a transition-era binary that classified without stamping).
    StampAbsent,
    /// A different classifier implementation produced these classes.
    ClassifierIdentityMismatch { stamped: String, current: String },
    /// The current or persisted classifier identity is not an exact digest.
    ClassifierIdentityUnavailable { identity: String },
    /// Same classifier identity, but compiled with a different PROVER feature set,
    /// so a different classifier produced these classes.
    ProverConfigMismatch { stamped: String, current: String },
    /// Selected source or project-input bytes differ from the indexed
    /// generation, so the classes no longer describe the repository regardless
    /// of who computed them.
    IndexStale,
}

impl CurrencyFailure {
    /// Short axis name + the remedy, for the gate verdict and header lines.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::ClassificationAuthorityUnavailable => {
                "classification authority UNAVAILABLE (no valid reachability evidence proves \
                 the exact classified document scope) — run `h00ligan index`"
                    .to_string()
            }
            Self::StampAbsent => {
                "provenance stamp ABSENT (classified by an unknown build) — re-run \
                 `h00ligan index`"
                    .to_string()
            }
            Self::ClassifierIdentityMismatch { stamped, current } => format!(
                "CLASSIFIER-CONTENT mismatch (classified by `{stamped}`, running `{current}`) — re-run \
                 `h00ligan index`"
            ),
            Self::ClassifierIdentityUnavailable { identity } => format!(
                "CLASSIFIER-CONTENT identity is unavailable or invalid (`{identity}`) — rebuild \
                 h00ligan, then re-run `h00ligan index`"
            ),
            Self::ProverConfigMismatch { stamped, current } => format!(
                "PROVER-CONFIG mismatch (classified by a build configured `{stamped}`, this \
                 build is `{current}`) — re-run `h00ligan index`"
            ),
            Self::IndexStale => {
                "INDEX STALE (selected source or project-input content differs from the indexed \
                 generation) — re-run `h00ligan index`"
                    .to_string()
            }
        }
    }
}

/// Inputs to [`evaluate_classification_currency`]. Plain data, so the evaluation
/// itself does no I/O and both the shipped gate and its falsifier can drive it.
#[derive(Debug, Clone, Copy)]
pub struct CurrencyInputs<'a> {
    /// The persisted stamp, or `None` if unstamped.
    pub stamp: Option<&'a ClassifiedBy>,
    /// This binary's stamp-as-of-now.
    pub current: &'a ClassifiedBy,
    /// Whether valid reachability evidence proves the exact document population
    /// classified in this generation. This is scope authority, not a global
    /// assertion that every structurally indexed node has a reachability class.
    pub classification_authority_available: bool,
    /// Staleness of the index vs sources; `None` when it could not be determined.
    pub index_stale: Option<bool>,
}

/// Evaluate the classification currency axes and return every failure found.
///
/// # Why this is ONE callable (ADR-0046 rev-3 A2-bis, property 2)
///
/// The shipped `--fail-on-dead` gate and falsifier #7 both invoke THIS
/// function. A test that reimplemented the currency rule would certify a COPY
/// of the logic while the shipped path drifted — the failure mode is that the
/// copies diverge, so sharing the callable is the point.
///
/// This is the DETECTOR side of the ADR-0046 rev-3 A2-quater / A2-quinquies
/// rule: *proving a detector → share the path; measuring a subject → call it
/// freely but source the expectation from the spec.* Falsifier #1 is the other
/// side and deliberately does NOT share a path with the dump's bookkeeping.
///
/// Returns an EMPTY vec exactly when the classification is fully certifiable.
#[must_use]
pub fn evaluate_classification_currency(inputs: CurrencyInputs<'_>) -> Vec<CurrencyFailure> {
    let mut failures = Vec::new();

    if !inputs.classification_authority_available {
        failures.push(CurrencyFailure::ClassificationAuthorityUnavailable);
    }

    match inputs.stamp {
        None => failures.push(CurrencyFailure::StampAbsent),
        Some(stamp) => {
            if !is_exact_indexer_identity(&inputs.current.indexer_identity) {
                failures.push(CurrencyFailure::ClassifierIdentityUnavailable {
                    identity: inputs.current.indexer_identity.clone(),
                });
            } else if !is_exact_indexer_identity(&stamp.indexer_identity) {
                failures.push(CurrencyFailure::ClassifierIdentityUnavailable {
                    identity: stamp.indexer_identity.clone(),
                });
            } else if stamp.indexer_identity != inputs.current.indexer_identity {
                failures.push(CurrencyFailure::ClassifierIdentityMismatch {
                    stamped: stamp.indexer_identity.clone(),
                    current: inputs.current.indexer_identity.clone(),
                });
            }

            // The PROVER axis. Written, rendered and round-tripped since the
            // first cut — but never COMPARED, which made it a dead field: the
            // record was bought without the guard it was bought for. A binary
            // compiled WITHOUT `code-intel` runs a different classifier, and a
            // matching git SHA does not make its classes comparable.
            if stamp.prover_config != inputs.current.prover_config {
                failures.push(CurrencyFailure::ProverConfigMismatch {
                    stamped: stamp.prover_config.clone(),
                    current: inputs.current.prover_config.clone(),
                });
            }
        }
    }

    // Axis 1. `None` (undeterminable) is NOT treated as fresh — but it is also
    // not treated as stale, because a store with no baseline is the
    // never-indexed case already covered by NeverClassified/StampAbsent.
    if inputs.index_stale == Some(true) {
        failures.push(CurrencyFailure::IndexStale);
    }

    failures
}

fn is_exact_indexer_identity(identity: &str) -> bool {
    let Some(digest) = identity.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_classified_by(stamp: &ClassifiedBy) -> Result<(), GraphStoreError> {
    if stamp.build_identity.is_empty()
        || stamp.prover_config.is_empty()
        || stamp.timestamp.is_empty()
        || !is_exact_indexer_identity(&stamp.indexer_identity)
    {
        return Err(GraphStoreError::InvalidGenerationMetadata {
            field: "classified_by",
            reason: "build_identity, exact sha256 indexer_identity, prover_config, and timestamp are required".into(),
        });
    }
    Ok(())
}

/// Schema version of the code-intel graph store byte layout.
///
/// **Bump this whenever the bincode layout or structural identity semantics of
/// [`GraphNode`], [`GraphEdge`], or [`GraphSnapshot`] changes.** Because bincode
/// is non-self-describing and an incremental load would otherwise preserve an
/// obsolete graph basis, a version mismatch clears and rebuilds these derived
/// tables from source.
///
/// Version 12 retains v11's graph snapshot layout and replaces the duplicated
/// full classified-node evidence document with a compact population-bound
/// projection. Persisted graphs are derived state, so incompatible generations
/// are rebuilt rather than migrated or interpreted through a compatibility
/// layer.
const SCHEMA_VERSION: u64 = 12;

// ---------------------------------------------------------------------------
// Snapshot type (serializable representation of the full graph)
// ---------------------------------------------------------------------------

/// A serializable snapshot of the entire knowledge graph.
#[derive(Debug, Serialize, Deserialize)]
struct GraphSnapshot {
    nodes: Vec<GraphNode>,
    edges: Vec<(Uuid, Uuid, GraphEdge)>,
    source_spans: Vec<(Uuid, SourceSpan)>,
}

/// CPU and storage work performed by the combined graph/evidence save path.
///
/// This remains crate-private because it is indexing telemetry, not persisted
/// authority. The public save contract continues to return `()`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GraphSnapshotWriteTelemetry {
    pub evidence_validation: Duration,
    pub snapshot_materialization: Duration,
    pub snapshot_encoding: Duration,
    pub evidence_encoding: Duration,
    pub proof_hashing: Duration,
    pub database_write: Duration,
    pub graph_bytes: usize,
    pub evidence_bytes: usize,
    graph_blake3: [u8; 32],
    evidence_blake3: Option<[u8; 32]>,
}

/// Proof that the pipeline validated and encoded one exact graph/evidence pair.
///
/// Publication compares this opaque proof to the persisted raw values without
/// rebuilding the complete in-memory graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphPublicationProof {
    schema_version: u64,
    graph_blake3: [u8; 32],
    evidence_blake3: Option<[u8; 32]>,
    graph_bytes: usize,
    evidence_bytes: usize,
    origin: String,
    generation_metadata: GraphGenerationMetadata,
}

pub(crate) type BoundGraphPublicationProof = PrivateDatabaseWitness<GraphPublicationProof>;

#[cfg(test)]
impl GraphPublicationProof {
    pub(crate) fn test_fixture() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            graph_blake3: [0; 32],
            evidence_blake3: None,
            graph_bytes: 0,
            evidence_bytes: 0,
            origin: "test-fixture".into(),
            generation_metadata: GraphGenerationMetadata::now(false),
        }
    }
}

pub(crate) struct ValidatedGraphContent {
    pub(crate) graph: KnowledgeGraph,
    pub(crate) reachability_evidence: Result<Option<ReachabilityEvidence>, GraphStoreError>,
    pub(crate) origin: String,
    pub(crate) generation_metadata: GraphGenerationMetadata,
}

struct RawGraphPublicationContent {
    snapshot: Vec<u8>,
    evidence: Option<Vec<u8>>,
    origin: String,
    generation_metadata: GraphGenerationMetadata,
    proof: GraphPublicationProof,
}

impl GraphSnapshotWriteTelemetry {
    pub(crate) fn publication_proof(
        &self,
        repository_root: &Path,
        generation_metadata: GraphGenerationMetadata,
    ) -> Result<GraphPublicationProof, GraphStoreError> {
        let origin = repository_root
            .canonicalize()
            .map_err(|error| {
                GraphStoreError::Origin(format!(
                    "cannot canonicalize publication root `{}`: {error}",
                    repository_root.display()
                ))
            })?
            .to_string_lossy()
            .into_owned();
        Ok(GraphPublicationProof {
            schema_version: SCHEMA_VERSION,
            graph_blake3: self.graph_blake3,
            evidence_blake3: self.evidence_blake3,
            graph_bytes: self.graph_bytes,
            evidence_bytes: self.evidence_bytes,
            origin,
            generation_metadata,
        })
    }
}

impl GraphPublicationProof {
    pub(crate) const fn verified_bytes(&self) -> u64 {
        self.graph_bytes.saturating_add(self.evidence_bytes) as u64
    }

    pub(crate) fn validate_candidate_identity(
        &self,
        repository_root: &Path,
    ) -> Result<(), GraphStoreError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GraphStoreError::Origin(format!(
                "publication graph proof uses schema {}, expected {}",
                self.schema_version, SCHEMA_VERSION
            )));
        }
        let canonical_root = repository_root
            .canonicalize()
            .map_err(|error| {
                GraphStoreError::Origin(format!(
                    "cannot canonicalize publication root `{}`: {error}",
                    repository_root.display()
                ))
            })?
            .to_string_lossy()
            .into_owned();
        if self.origin != canonical_root {
            return Err(GraphStoreError::OriginMismatch {
                stored: self.origin.clone(),
                query: canonical_root,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from graph persistence operations.
#[derive(Debug, thiserror::Error)]
pub enum GraphStoreError {
    #[error("redb error: {0}")]
    Redb(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid graph snapshot: {0}")]
    InvalidSnapshot(String),

    #[error("reachability evidence error: {0}")]
    ReachabilityEvidence(String),

    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("graph store was opened read-only")]
    ReadOnly,

    /// The persisted code-intel graph was indexed from a different workspace
    /// root than the one querying it. Carries both the
    /// stored origin and the querying root so the caller can surface the
    /// "store belongs to `{stored}`; you are in `{query}` — run `h00ligan
    /// index`" diagnostic. Read-intent loads surface this fail-closed instead
    /// of silently serving foreign data.
    #[error(
        "code-intel graph store belongs to a different workspace: it was indexed from \
         `{stored}`, but you are querying from `{query}` — run `h00ligan index` in this \
         workspace to (re)build its graph"
    )]
    OriginMismatch { stored: String, query: String },

    /// The INDEX path found a persisted graph stamped with a DIFFERENT
    /// workspace origin, and adoption was not authorised. Adopting would
    /// `clear_graph_tables` — destroying another workspace's graph — so the
    /// index refuses fail-closed instead. Carries BOTH paths so the operator
    /// can see whose data was about to be destroyed.
    ///
    /// This is the WRITE-side twin of [`GraphStoreError::OriginMismatch`] (the
    /// read-side refusal). It fires ONLY when a snapshot is actually present:
    /// an empty store has nothing to destroy and still adopts silently, so a
    /// first-ever index never needs the flag.
    #[error(
        "code-intel graph store belongs to a different workspace: it was indexed from \
         `{stored}`, but you are indexing from `{query}` — continuing would CLEAR and \
         rebuild that workspace's graph, destroying it. Use a separate `--data-dir` per \
         workspace, or pass `--adopt-foreign-origin` to authorise the clear"
    )]
    OriginAdoptRequired { stored: String, query: String },

    /// Failed to stamp the workspace origin (e.g. the workspace root could not
    /// be canonicalized at save time). Distinct from a mismatch: this is a
    /// save-side failure to RECORD an origin, not a read-side rejection.
    #[error("graph origin stamp error: {0}")]
    Origin(String),

    #[error("generation metadata is incomplete: missing `{field}`")]
    MissingGenerationMetadata { field: &'static str },

    #[error("generation metadata `{field}` is invalid: {reason}")]
    InvalidGenerationMetadata { field: &'static str, reason: String },
}

impl From<redb::Error> for GraphStoreError {
    fn from(e: redb::Error) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::DatabaseError> for GraphStoreError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::TransactionError> for GraphStoreError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::TableError> for GraphStoreError {
    fn from(e: redb::TableError) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::CommitError> for GraphStoreError {
    fn from(e: redb::CommitError) -> Self {
        Self::Redb(e.to_string())
    }
}

impl From<redb::StorageError> for GraphStoreError {
    fn from(e: redb::StorageError) -> Self {
        Self::Redb(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// GraphStore
// ---------------------------------------------------------------------------

/// Persists a [`KnowledgeGraph`] to redb for crash recovery.
///
/// Uses a shared redb handle. Read-intent callers may select an OS-read-only
/// handle so loading cannot repair or otherwise modify the persisted file.
/// All redb operations are wrapped in `spawn_blocking`.
#[derive(Clone)]
pub struct GraphStore {
    db: Arc<GraphDatabase>,
}

enum GraphDatabase {
    ReadWrite(Arc<Database>),
    ReadOnly(Arc<ReadOnlyDatabase>),
}

impl GraphDatabase {
    fn begin_read(&self) -> Result<redb::ReadTransaction, redb::TransactionError> {
        match self {
            Self::ReadWrite(database) => database.begin_read(),
            Self::ReadOnly(database) => database.begin_read(),
        }
    }

    fn begin_write(&self) -> Result<redb::WriteTransaction, GraphStoreError> {
        match self {
            Self::ReadWrite(database) => Ok(database.begin_write()?),
            Self::ReadOnly(_) => Err(GraphStoreError::ReadOnly),
        }
    }

    const fn writable_database(&self) -> Result<&Arc<Database>, GraphStoreError> {
        match self {
            Self::ReadWrite(database) => Ok(database),
            Self::ReadOnly(_) => Err(GraphStoreError::ReadOnly),
        }
    }
}

impl GraphStore {
    /// Create a new `GraphStore` sharing the given redb database.
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db: Arc::new(GraphDatabase::ReadWrite(db)),
        }
    }

    /// Create a read-intent `GraphStore` over an existing OS-read-only handle.
    pub fn new_read_only(db: Arc<ReadOnlyDatabase>) -> Self {
        Self {
            db: Arc::new(GraphDatabase::ReadOnly(db)),
        }
    }

    fn materialize_snapshot(graph: &KnowledgeGraph) -> GraphSnapshot {
        GraphSnapshot {
            nodes: graph.all_nodes().into_iter().cloned().collect(),
            edges: graph
                .all_edges()
                .into_iter()
                .map(|(s, t, e)| (s, t, e.clone()))
                .collect(),
            source_spans: graph.all_source_spans(),
        }
    }

    fn encode_materialized_snapshot(snapshot: &GraphSnapshot) -> Result<Vec<u8>, GraphStoreError> {
        bincode::serde::encode_to_vec(snapshot, bincode::config::standard())
            .map_err(|error| GraphStoreError::Serialization(error.to_string()))
    }

    fn encode_snapshot(graph: &KnowledgeGraph) -> Result<Vec<u8>, GraphStoreError> {
        let snapshot = Self::materialize_snapshot(graph);
        Self::encode_materialized_snapshot(&snapshot)
    }

    fn encode_snapshot_profiled(
        graph: &KnowledgeGraph,
    ) -> Result<(Vec<u8>, Duration, Duration), GraphStoreError> {
        let materialization_start = Instant::now();
        let snapshot = GraphSnapshot {
            nodes: graph.all_nodes().into_iter().cloned().collect(),
            edges: graph
                .all_edges()
                .into_iter()
                .map(|(s, t, e)| (s, t, e.clone()))
                .collect(),
            source_spans: graph.all_source_spans(),
        };
        let materialization = materialization_start.elapsed();
        let encoding_start = Instant::now();
        let bytes = Self::encode_materialized_snapshot(&snapshot)?;
        Ok((bytes, materialization, encoding_start.elapsed()))
    }

    fn decode_snapshot(bytes: &[u8]) -> Result<KnowledgeGraph, GraphStoreError> {
        let (snapshot, consumed): (GraphSnapshot, usize) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                .map_err(|error| GraphStoreError::InvalidSnapshot(error.to_string()))?;
        if consumed != bytes.len() {
            return Err(GraphStoreError::InvalidSnapshot(format!(
                "snapshot decoder consumed {consumed} of {} bytes",
                bytes.len()
            )));
        }

        let GraphSnapshot {
            nodes,
            edges,
            source_spans,
        } = snapshot;
        let mut graph = KnowledgeGraph::new();
        for node in nodes {
            graph.add_node(node).map_err(|error| {
                GraphStoreError::InvalidSnapshot(format!("invalid persisted node: {error}"))
            })?;
        }

        let mut seen_spans = HashSet::with_capacity(source_spans.len());
        for (memory_id, span) in source_spans {
            if !seen_spans.insert(memory_id) {
                return Err(GraphStoreError::InvalidSnapshot(format!(
                    "duplicate persisted source span for node {memory_id}"
                )));
            }
            graph.set_source_span(memory_id, span).map_err(|error| {
                GraphStoreError::InvalidSnapshot(format!("invalid persisted source span: {error}"))
            })?;
        }

        let mut seen_edges = HashSet::with_capacity(edges.len());
        for (source, target, edge) in edges {
            if !seen_edges.insert((source, target, edge.kind)) {
                return Err(GraphStoreError::InvalidSnapshot(format!(
                    "duplicate persisted {:?} edge from {source} to {target}",
                    edge.kind
                )));
            }
            graph.add_edge(source, target, edge).map_err(|error| {
                GraphStoreError::InvalidSnapshot(format!("invalid persisted edge: {error}"))
            })?;
        }
        Ok(graph)
    }

    fn write_snapshot_bytes(
        db: &GraphDatabase,
        graph_bytes: &[u8],
        reachability_bytes: Option<&[u8]>,
    ) -> Result<(), GraphStoreError> {
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(GRAPH_SNAPSHOT)?;
            table.insert("latest", graph_bytes)?;
            let mut evidence_table = txn.open_table(GRAPH_REACHABILITY_EVIDENCE)?;
            if let Some(bytes) = reachability_bytes {
                evidence_table.insert(REACHABILITY_EVIDENCE_KEY, bytes)?;
            } else {
                evidence_table.retain(|_, _| false)?;
            }
            // Stamp the schema version this snapshot was written under so a
            // future load can detect a schema bump (clear-on-schema-bump).
            let mut meta = txn.open_table(GRAPH_META)?;
            meta.insert("schema_version", SCHEMA_VERSION)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Save the entire graph as a bincode-serialized snapshot.
    ///
    /// A graph-only save invalidates any prior reachability evidence in the
    /// same transaction. Call
    /// [`save_snapshot_with_reachability_evidence`](Self::save_snapshot_with_reachability_evidence)
    /// when both were derived together.
    pub async fn save_snapshot(&self, graph: &KnowledgeGraph) -> Result<(), GraphStoreError> {
        let bytes = Self::encode_snapshot(graph)?;

        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || -> Result<(), GraphStoreError> {
            Self::write_snapshot_bytes(&db, &bytes, None)
        })
        .await?
    }

    /// Atomically save a graph snapshot and the reachability evidence derived
    /// from that exact graph.
    pub async fn save_snapshot_with_reachability_evidence(
        &self,
        graph: &KnowledgeGraph,
        evidence: &ReachabilityEvidence,
    ) -> Result<(), GraphStoreError> {
        self.save_snapshot_with_reachability_evidence_profiled(graph, evidence)
            .await
            .map(|_| ())
    }

    /// Combined save with non-authoritative performance telemetry for the
    /// indexing profiler.
    pub(crate) async fn save_snapshot_with_reachability_evidence_profiled(
        &self,
        graph: &KnowledgeGraph,
        evidence: &ReachabilityEvidence,
    ) -> Result<GraphSnapshotWriteTelemetry, GraphStoreError> {
        self.save_snapshot_with_optional_reachability_profiled(graph, Some(evidence))
            .await
    }

    /// Save one graph and its optional independently-authorized reachability
    /// projection while retaining a proof over the exact persisted pair.
    ///
    /// `None` is the honest state for a structurally indexable population with
    /// no registered reachability owner. It removes any earlier evidence in
    /// the same transaction and produces a graph-only publication proof.
    pub(crate) async fn save_snapshot_with_optional_reachability_profiled(
        &self,
        graph: &KnowledgeGraph,
        evidence: Option<&ReachabilityEvidence>,
    ) -> Result<GraphSnapshotWriteTelemetry, GraphStoreError> {
        let validation_start = Instant::now();
        if let Some(evidence) = evidence {
            evidence
                .validate(graph)
                .map_err(|error| GraphStoreError::ReachabilityEvidence(error.to_string()))?;
        }
        let evidence_validation = validation_start.elapsed();
        let (graph_bytes, snapshot_materialization, snapshot_encoding) =
            Self::encode_snapshot_profiled(graph)?;
        let evidence_encoding_start = Instant::now();
        let evidence_bytes = evidence
            .map(|evidence| {
                serde_json::to_vec(&evidence.persisted_projection())
                    .map_err(|error| GraphStoreError::Serialization(error.to_string()))
            })
            .transpose()?;
        let evidence_encoding = evidence_encoding_start.elapsed();
        let graph_bytes_len = graph_bytes.len();
        let evidence_bytes_len = evidence_bytes.as_ref().map_or(0, Vec::len);
        let proof_hashing_start = Instant::now();
        let graph_blake3 = *blake3::hash(&graph_bytes).as_bytes();
        let evidence_blake3 = evidence_bytes
            .as_deref()
            .map(|bytes| *blake3::hash(bytes).as_bytes());
        let proof_hashing = proof_hashing_start.elapsed();
        let db = Arc::clone(&self.db);
        let database_write = tokio::task::spawn_blocking(move || {
            let write_start = Instant::now();
            Self::write_snapshot_bytes(&db, &graph_bytes, evidence_bytes.as_deref())?;
            Ok::<_, GraphStoreError>(write_start.elapsed())
        })
        .await??;
        Ok(GraphSnapshotWriteTelemetry {
            evidence_validation,
            snapshot_materialization,
            snapshot_encoding,
            evidence_encoding,
            proof_hashing,
            database_write,
            graph_bytes: graph_bytes_len,
            evidence_bytes: evidence_bytes_len,
            graph_blake3,
            evidence_blake3,
        })
    }

    pub(crate) fn bind_publication_proof(
        &self,
        telemetry: &GraphSnapshotWriteTelemetry,
        repository_root: &Path,
        generation_metadata: GraphGenerationMetadata,
    ) -> Result<BoundGraphPublicationProof, GraphStoreError> {
        let proof = telemetry.publication_proof(repository_root, generation_metadata)?;
        Ok(PrivateDatabaseWitness::bind(
            self.db.writable_database()?,
            proof,
        ))
    }

    /// Synchronous version of [`save_snapshot`] for use inside
    /// `spawn_blocking`. Serializes the graph and writes it to redb in one
    /// blocking call — no async, no await. Like the async graph-only save, this
    /// invalidates any prior reachability evidence atomically.
    pub fn save_snapshot_sync(&self, graph: &KnowledgeGraph) -> Result<(), GraphStoreError> {
        let bytes = Self::encode_snapshot(graph)?;
        Self::write_snapshot_bytes(&self.db, &bytes, None)
    }

    /// Load and graph-validate generation-local reachability evidence.
    ///
    /// Absence remains representable for legacy/synthetic graph snapshots. A
    /// present malformed, non-canonical, wrong-schema, or graph-inconsistent
    /// document is an explicit error rather than a false empty report.
    pub async fn load_reachability_evidence(
        &self,
        graph: &KnowledgeGraph,
    ) -> Result<Option<ReachabilityEvidence>, GraphStoreError> {
        let db = Arc::clone(&self.db);
        let persisted = tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read()?;
            let table = match read_txn.open_table(GRAPH_REACHABILITY_EVIDENCE) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(error) => return Err(GraphStoreError::from(error)),
            };
            let Some(guard) = table.get(REACHABILITY_EVIDENCE_KEY)? else {
                return Ok(None);
            };
            let bytes = guard.value();
            let evidence: PersistedReachabilityEvidence = serde_json::from_slice(bytes)
                .map_err(|error| GraphStoreError::Serialization(error.to_string()))?;
            let canonical = serde_json::to_vec(&evidence)
                .map_err(|error| GraphStoreError::Serialization(error.to_string()))?;
            if canonical != bytes {
                return Err(GraphStoreError::ReachabilityEvidence(
                    "persisted document is not in canonical encoding".into(),
                ));
            }
            Ok(Some(evidence))
        })
        .await??;
        persisted
            .map(|evidence| {
                ReachabilityEvidence::from_persisted_projection(graph, evidence)
                    .map_err(|error| GraphStoreError::ReachabilityEvidence(error.to_string()))
            })
            .transpose()
    }

    /// Load graph from the one authoritative whole-graph snapshot.
    ///
    /// This is the **read path**: it is DISCARD-WITHOUT-CLEAR and NEVER mutates
    /// the caller-owned generation database. Returns `None` when there is no usable current-schema
    /// snapshot — either because none has been saved yet, OR because the
    /// persisted graph is schema-stale / undecodable. In the stale case the
    /// on-disk bytes and the (old/absent) version stamp are left UNTOUCHED.
    ///
    /// ## Why read-intent must not clear (WU-0003 / CL-REACH read-path blocker)
    ///
    /// The index pipeline detects a stale store by the SURVIVING staleness signal
    /// (an old/absent [`GRAPH_META`] version stamp + bytes that fail to decode).
    /// If a read command cleared the tables and stamped the current
    /// [`SCHEMA_VERSION`], that signal would be erased: the next incremental
    /// `index` would see `cleared = false`, skip the forced full rebuild, and —
    /// because the surviving file-state tables make the diff report
    /// nothing changed — leave the graph PERMANENTLY at 0 nodes. That is the same
    /// silent-wipe class WU-0003 closes, shifted one trigger over. So the read
    /// path here discards without clearing, preserving the recovery signal that
    /// the index path (the SOLE clearer/stamper,
    /// [`load_snapshot_or_clear`](Self::load_snapshot_or_clear)) keys off and acts
    /// on by forcing a full re-extract.
    pub async fn load_snapshot(&self) -> Result<Option<KnowledgeGraph>, GraphStoreError> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || Self::load_snapshot_sync(&db)).await?
    }

    fn load_snapshot_sync(db: &GraphDatabase) -> Result<Option<KnowledgeGraph>, GraphStoreError> {
        // --- Schema-version gate (READ-ONLY: detect, never mutate) ---
        // DRY: the staleness rule lives in `version_mismatch_sync` (the
        // single source every load path inherits). On a mismatch, DISCARD
        // (return None) and leave the generation database untouched — the stale store
        // stays detectably stale on disk so the index path can recover it.
        if Self::version_mismatch_sync(db)?.0 {
            return Ok(None);
        }

        // --- Open the snapshot --------------------------------------
        let read_txn = db.begin_read()?;
        let table = match read_txn.open_table(GRAPH_SNAPSHOT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let guard = match table.get("latest")? {
            Some(g) => g,
            None => return Ok(None),
        };

        // Defence-in-depth: even at a matching schema version, an
        // undecodable snapshot must NOT hard-error a read — DISCARD it
        // (return None) WITHOUT clearing. The index path will detect and
        // rebuild; a read leaves the bytes intact.
        Ok(Self::decode_snapshot(guard.value()).ok())
    }

    /// Validate the graph payload that a low-level immutable publisher is about
    /// to make authoritative. This is synchronous so it can run while the
    /// publisher owns the private redb handle and before any head is advanced.
    #[cfg(test)]
    pub(crate) fn reset_publication_validation_counts() {
        PUBLICATION_SNAPSHOT_VALIDATIONS.with(|count| count.set(0));
        PUBLICATION_PROOF_VALIDATIONS.with(|count| count.set(0));
    }

    #[cfg(test)]
    pub(crate) fn publication_validation_counts() -> (usize, usize) {
        (
            PUBLICATION_SNAPSHOT_VALIDATIONS.with(std::cell::Cell::get),
            PUBLICATION_PROOF_VALIDATIONS.with(std::cell::Cell::get),
        )
    }

    /// Verify the exact raw graph and reachability values previously validated
    /// and encoded by the indexing pipeline, together with the origin and
    /// interpretation metadata written beside them.
    ///
    /// The proof is opaque outside this crate and bound to the same private
    /// database handle. A low-level publisher without such a proof continues
    /// to use [`Self::validate_publication_snapshot_sync`] and fully decode the
    /// candidate graph.
    #[cfg(test)]
    pub(crate) fn validate_publication_proof_sync(
        &self,
        repository_root: &Path,
        proof: &GraphPublicationProof,
    ) -> Result<(), GraphStoreError> {
        #[cfg(test)]
        PUBLICATION_PROOF_VALIDATIONS.with(|count| count.set(count.get().saturating_add(1)));
        self.read_raw_publication_content_sync(repository_root, Some(proof))
            .map(|_| ())
    }

    /// Capture a manifest-ready proof from a low-level private generation that
    /// did not receive the pipeline's write-time proof. The same validated read
    /// path is used later by immutable consumers.
    pub(crate) fn capture_publication_proof_sync(
        &self,
        repository_root: &Path,
    ) -> Result<GraphPublicationProof, GraphStoreError> {
        Ok(self
            .read_raw_publication_content_sync(repository_root, None)?
            .proof)
    }

    /// Validate and decode the exact raw graph/evidence populations from one
    /// opened database. Returning the decoded graph closes the proof-to-use gap
    /// that a second independent table read would reintroduce.
    pub(crate) fn validate_and_load_publication_proof_sync(
        &self,
        repository_root: &Path,
        expected: &GraphPublicationProof,
    ) -> Result<ValidatedGraphContent, GraphStoreError> {
        let raw = self.read_raw_publication_content_sync(repository_root, Some(expected))?;
        Self::decode_publication_content(raw)
    }

    fn read_publication_content_sync(
        &self,
        repository_root: &Path,
    ) -> Result<ValidatedGraphContent, GraphStoreError> {
        let raw = self.read_raw_publication_content_sync(repository_root, None)?;
        Self::decode_publication_content(raw)
    }

    fn read_raw_publication_content_sync(
        &self,
        repository_root: &Path,
        expected: Option<&GraphPublicationProof>,
    ) -> Result<RawGraphPublicationContent, GraphStoreError> {
        let canonical_query = repository_root
            .canonicalize()
            .map_err(|error| {
                GraphStoreError::Origin(format!(
                    "cannot canonicalize publication root `{}`: {error}",
                    repository_root.display()
                ))
            })?
            .to_string_lossy()
            .into_owned();
        if expected.is_some_and(|proof| proof.schema_version != SCHEMA_VERSION) {
            return Err(GraphStoreError::Origin(format!(
                "publication graph proof uses schema {}, expected {}",
                expected.map_or(0, |proof| proof.schema_version),
                SCHEMA_VERSION
            )));
        }
        let (version_mismatch, _) = Self::version_mismatch_sync(&self.db)?;
        if version_mismatch {
            return Err(GraphStoreError::Origin(
                "publication graph snapshot uses an incompatible schema".into(),
            ));
        }
        let stored_origin = Self::read_origin_sync(&self.db)?;
        if stored_origin.as_deref() != Some(canonical_query.as_str()) {
            return Err(GraphStoreError::OriginMismatch {
                stored: stored_origin.unwrap_or_else(|| "<no origin stamped>".into()),
                query: canonical_query,
            });
        }
        if let Some(proof) = expected
            && proof.origin != canonical_query
        {
            return Err(GraphStoreError::OriginMismatch {
                stored: proof.origin.clone(),
                query: canonical_query,
            });
        }
        let generation_metadata = Self::read_generation_metadata_sync(&self.db)?;
        if let Some(proof) = expected
            && proof.generation_metadata != generation_metadata
        {
            return Err(GraphStoreError::InvalidGenerationMetadata {
                field: "publication_proof",
                reason: "persisted generation metadata differs from the immutable manifest".into(),
            });
        }

        let read_txn = self.db.begin_read()?;
        let snapshot_table = read_txn.open_table(GRAPH_SNAPSHOT)?;
        let snapshot = snapshot_table.get("latest")?.ok_or_else(|| {
            GraphStoreError::InvalidSnapshot("publication database has no graph snapshot".into())
        })?;
        let snapshot_bytes = snapshot.value().to_vec();
        let graph_blake3 = *blake3::hash(&snapshot_bytes).as_bytes();
        let graph_bytes = snapshot_bytes.len();

        let evidence_bytes = match read_txn.open_table(GRAPH_REACHABILITY_EVIDENCE) {
            Ok(table) => table
                .get(REACHABILITY_EVIDENCE_KEY)?
                .map(|guard| guard.value().to_vec()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(error.into()),
        };
        let evidence_blake3 = evidence_bytes
            .as_deref()
            .map(|bytes| *blake3::hash(bytes).as_bytes());
        let evidence_bytes_len = evidence_bytes.as_ref().map_or(0, Vec::len);

        let proof = GraphPublicationProof {
            schema_version: SCHEMA_VERSION,
            graph_blake3,
            evidence_blake3,
            graph_bytes,
            evidence_bytes: evidence_bytes_len,
            origin: canonical_query.clone(),
            generation_metadata: generation_metadata.clone(),
        };
        if let Some(expected) = expected {
            if proof.graph_blake3 != expected.graph_blake3
                || proof.graph_bytes != expected.graph_bytes
            {
                return Err(GraphStoreError::InvalidSnapshot(
                    "opened graph bytes differ from the immutable manifest content proof".into(),
                ));
            }
            if proof.evidence_blake3 != expected.evidence_blake3
                || proof.evidence_bytes != expected.evidence_bytes
            {
                return Err(GraphStoreError::ReachabilityEvidence(
                    "opened reachability bytes differ from the immutable manifest content proof"
                        .into(),
                ));
            }
        }
        Ok(RawGraphPublicationContent {
            snapshot: snapshot_bytes,
            evidence: evidence_bytes,
            origin: canonical_query,
            generation_metadata,
            proof,
        })
    }

    fn decode_publication_content(
        raw: RawGraphPublicationContent,
    ) -> Result<ValidatedGraphContent, GraphStoreError> {
        let graph = Self::decode_snapshot(&raw.snapshot)?;
        let reachability_evidence = raw
            .evidence
            .as_deref()
            .map(|bytes| {
                let persisted: PersistedReachabilityEvidence = serde_json::from_slice(bytes)
                    .map_err(|error| GraphStoreError::Serialization(error.to_string()))?;
                let canonical = serde_json::to_vec(&persisted)
                    .map_err(|error| GraphStoreError::Serialization(error.to_string()))?;
                if canonical != bytes {
                    return Err(GraphStoreError::ReachabilityEvidence(
                        "persisted document is not in canonical encoding".into(),
                    ));
                }
                ReachabilityEvidence::from_persisted_projection(&graph, persisted)
                    .map_err(|error| GraphStoreError::ReachabilityEvidence(error.to_string()))
            })
            .transpose();
        Ok(ValidatedGraphContent {
            graph,
            reachability_evidence,
            origin: raw.origin,
            generation_metadata: raw.generation_metadata,
        })
    }

    pub fn validate_publication_snapshot_sync(
        &self,
        repository_root: &Path,
    ) -> Result<KnowledgeGraph, GraphStoreError> {
        #[cfg(test)]
        PUBLICATION_SNAPSHOT_VALIDATIONS.with(|count| count.set(count.get().saturating_add(1)));
        self.read_publication_content_sync(repository_root)
            .map(|content| content.graph)
    }

    // -----------------------------------------------------------------------
    // Workspace-origin gate (ADR-0033, ROOT-8)
    // -----------------------------------------------------------------------

    /// Read the stored canonical workspace-root origin from [`GRAPH_ORIGIN`],
    /// if any. Sync — intended for use inside a `spawn_blocking` closure or by
    /// the async [`get_origin`](Self::get_origin) wrapper. An absent table or
    /// key yields `None`.
    fn read_origin_sync(db: &GraphDatabase) -> Result<Option<String>, GraphStoreError> {
        let read_txn = db.begin_read()?;
        match read_txn.open_table(GRAPH_ORIGIN) {
            Ok(t) => Ok(t.get(ORIGIN_KEY)?.map(|g| g.value().to_string())),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Write (overwrite) the canonical workspace-root origin into
    /// [`GRAPH_ORIGIN`] in a single write transaction. Sync.
    fn write_origin_sync(db: &GraphDatabase, origin: &str) -> Result<(), GraphStoreError> {
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(GRAPH_ORIGIN)?;
            table.insert(ORIGIN_KEY, origin)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Report whether the one authoritative whole-graph snapshot is present.
    fn persisted_graph_data_sync(db: &GraphDatabase) -> Result<bool, GraphStoreError> {
        let read_txn = db.begin_read()?;
        let snapshot_present = match read_txn.open_table(GRAPH_SNAPSHOT) {
            Ok(table) => table.get("latest")?.is_some(),
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(error) => return Err(error.into()),
        };
        Ok(snapshot_present)
    }

    /// Compute the schema-version-mismatch verdict WITHOUT mutating the store —
    /// the SINGLE source of the staleness rule, shared by every load path
    /// ([`load_snapshot`](Self::load_snapshot),
    /// [`load_snapshot_checked`](Self::load_snapshot_checked), and
    /// [`load_snapshot_or_clear`](Self::load_snapshot_or_clear)) so the
    /// [`SCHEMA_VERSION`] bump is honored in exactly ONE place that all three
    /// inherit (ADR-0033 Decision 6).
    ///
    /// Returns `(mismatch, stored_version)`:
    /// - `mismatch` ⇒ the persisted graph is schema-stale (an old/absent version
    ///   stamp while graph data is present); the caller must treat the load as a
    ///   today-style version mismatch (discard / clear) and DO NOT run the origin
    ///   gate (ADR-0033 Decision 5).
    /// - `stored_version` — the persisted stamp (for the clear-path `warn!` log).
    fn version_mismatch_sync(db: &GraphDatabase) -> Result<(bool, Option<u64>), GraphStoreError> {
        let stored_version: Option<u64> = {
            let read_txn = db.begin_read()?;
            match read_txn.open_table(GRAPH_META) {
                Ok(meta) => meta.get("schema_version")?.map(|g| g.value()),
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(e.into()),
            }
        };

        let has_persisted_data = Self::persisted_graph_data_sync(db)?;

        Ok((
            has_persisted_data && stored_version != Some(SCHEMA_VERSION),
            stored_version,
        ))
    }

    /// Stamp the canonical absolute workspace `root` this graph was indexed from
    /// into [`GRAPH_ORIGIN`] (ADR-0033 Decision 1/8). The `root` is
    /// `canonicalize`d (symlink-resolved, lossy `String`) so it can be compared
    /// byte-for-byte against a likewise-canonicalized query root on load.
    ///
    /// A `canonicalize` failure (the root does not exist / is not accessible at
    /// save time) is surfaced as [`GraphStoreError::Origin`] rather than
    /// silently stamping a path that could never match on read.
    ///
    /// This OVERWRITES any existing origin (a re-index re-stamps to the current
    /// root). It writes only the dedicated [`GRAPH_ORIGIN`] table and never
    /// touches the snapshot or version stamp.
    pub async fn set_origin(&self, root: &Path) -> Result<(), GraphStoreError> {
        let canonical = root.canonicalize().map_err(|e| {
            GraphStoreError::Origin(format!(
                "cannot canonicalize workspace root `{}` for origin stamp: {e}",
                root.display()
            ))
        })?;
        let origin = canonical.to_string_lossy().into_owned();
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || Self::write_origin_sync(&db, &origin)).await?
    }

    /// Synchronous sibling of [`set_origin`](Self::set_origin) for use INSIDE a
    /// `spawn_blocking` closure (where `set_origin`'s own `spawn_blocking`
    /// cannot be `await`ed). Canonicalizes `root` and overwrites the
    /// [`GRAPH_ORIGIN`] stamp in one blocking write transaction.
    ///
    /// Used by [`reload_reclassify_save`](crate::reachability::reload_reclassify_save)
    /// to belt-and-suspenders re-stamp the origin alongside its in-closure
    /// `save_snapshot_sync`, upholding the ADR-0033 invariant that NO persisted
    /// graph lacks a matching origin stamp regardless of caller path.
    pub fn set_origin_sync(&self, root: &Path) -> Result<(), GraphStoreError> {
        let canonical = root.canonicalize().map_err(|e| {
            GraphStoreError::Origin(format!(
                "cannot canonicalize workspace root `{}` for origin stamp: {e}",
                root.display()
            ))
        })?;
        let origin = canonical.to_string_lossy().into_owned();
        Self::write_origin_sync(&self.db, &origin)
    }

    /// Read the stored canonical workspace-root origin, if any. `None` when no
    /// origin has been stamped (a legacy/pre-ADR-0033 store, or a fresh store).
    pub async fn get_origin(&self) -> Result<Option<String>, GraphStoreError> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || Self::read_origin_sync(&db)).await?
    }

    // -----------------------------------------------------------------------
    // Classification-provenance stamp (ADR-0046 D1/D2/D4)
    // -----------------------------------------------------------------------

    /// Read the classification-provenance stamp from [`GRAPH_CLASSIFIED_BY`].
    /// Sync — for use inside a `spawn_blocking` closure or by the async
    /// [`classified_by_stamp`](Self::classified_by_stamp) wrapper.
    ///
    /// A wholly absent table yields `None`. A partial or empty record is invalid
    /// metadata rather than evidence that can be defaulted.
    fn read_classified_by_sync(
        db: &GraphDatabase,
    ) -> Result<Option<ClassifiedBy>, GraphStoreError> {
        let read_txn = db.begin_read()?;
        let table = match read_txn.open_table(GRAPH_CLASSIFIED_BY) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let get = |k: &str| -> Result<Option<String>, GraphStoreError> {
            Ok(table.get(k)?.map(|g| g.value().to_string()))
        };
        let (build_identity, indexer_identity, prover_config, timestamp) = (
            get(CLASSIFIED_BY_BUILD_IDENTITY_KEY)?,
            get(CLASSIFIED_BY_INDEXER_IDENTITY_KEY)?,
            get(CLASSIFIED_BY_PROVER_CONFIG_KEY)?,
            get(CLASSIFIED_BY_TIMESTAMP_KEY)?,
        );
        let (build_identity, indexer_identity, prover_config, timestamp) =
            match (build_identity, indexer_identity, prover_config, timestamp) {
                (None, None, None, None) => return Ok(None),
                (
                    Some(build_identity),
                    Some(indexer_identity),
                    Some(prover_config),
                    Some(timestamp),
                ) => (build_identity, indexer_identity, prover_config, timestamp),
                _ => {
                    return Err(GraphStoreError::InvalidGenerationMetadata {
                        field: "classified_by",
                        reason: "record is only partially populated".into(),
                    });
                }
            };
        let stamp = ClassifiedBy {
            build_identity,
            indexer_identity,
            prover_config,
            timestamp,
        };
        validate_classified_by(&stamp)?;
        Ok(Some(stamp))
    }

    /// Write (overwrite) the classification-provenance stamp in a single write
    /// transaction. Sync.
    fn write_classified_by_sync(
        db: &GraphDatabase,
        cb: &ClassifiedBy,
    ) -> Result<(), GraphStoreError> {
        validate_classified_by(cb)?;
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(GRAPH_CLASSIFIED_BY)?;
            table.insert(CLASSIFIED_BY_BUILD_IDENTITY_KEY, cb.build_identity.as_str())?;
            table.insert(
                CLASSIFIED_BY_INDEXER_IDENTITY_KEY,
                cb.indexer_identity.as_str(),
            )?;
            table.insert(CLASSIFIED_BY_PROVER_CONFIG_KEY, cb.prover_config.as_str())?;
            table.insert(CLASSIFIED_BY_TIMESTAMP_KEY, cb.timestamp.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Stamp the human build provenance, exact classifier content, and prover
    /// configuration that produced the classes now persisted here.
    ///
    /// Called ON THE LINE BESIDE each production `set_origin` — the
    /// classify-then-persist call set. Writes only [`GRAPH_CLASSIFIED_BY`] and
    /// never touches the snapshot, version stamp, or origin.
    ///
    /// Deliberately NOT folded into `save_snapshot`: a persistence-only caller
    /// persists WITHOUT reclassifying (the loaded graph carries the PRODUCER's
    /// classification), so stamping at that chokepoint would attribute classes
    /// to a binary that never classified them — a fresh lie worse than the
    /// current silence.
    pub async fn set_classified_by(&self) -> Result<(), GraphStoreError> {
        let cb = ClassifiedBy::now();
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || Self::write_classified_by_sync(&db, &cb)).await?
    }

    /// Synchronous sibling for use inside a `spawn_blocking` closure.
    pub fn set_classified_by_sync(&self) -> Result<(), GraphStoreError> {
        Self::write_classified_by_sync(&self.db, &ClassifiedBy::now())
    }

    /// Write an EXPLICIT stamp rather than "this binary, now".
    ///
    /// Production code should call [`set_classified_by`](Self::set_classified_by)
    /// — a stamp naming classifier content that did not do the work is precisely
    /// the lie this mechanism exists to prevent. This variant exists so the
    /// currency falsifiers can plant mismatched identities and observe the guard. Keeping the
    /// planting here rather than in test code means the key names live in ONE
    /// place and a test cannot drift from the shipped layout.
    pub async fn set_classified_by_stamp(&self, cb: &ClassifiedBy) -> Result<(), GraphStoreError> {
        let cb = cb.clone();
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || Self::write_classified_by_sync(&db, &cb)).await?
    }

    /// Read the classification-provenance stamp, if any. `None` for a
    /// pre-ADR-0046 store — provenance unknown, refresh directed, never refused.
    pub async fn classified_by_stamp(&self) -> Result<Option<ClassifiedBy>, GraphStoreError> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || Self::read_classified_by_sync(&db)).await?
    }

    // -----------------------------------------------------------------------
    // Oracle-run-authoritative flag (OQ-ORACLE-INCREMENTAL-STALE, part b)
    // -----------------------------------------------------------------------

    /// Read the index-time oracle-run-authoritative flag from [`GRAPH_META`], if
    /// any. Only the canonical boolean encodings `0` and `1` are accepted.
    fn read_oracle_ran_ok_sync(db: &GraphDatabase) -> Result<Option<bool>, GraphStoreError> {
        let read_txn = db.begin_read()?;
        match read_txn.open_table(GRAPH_META) {
            Ok(t) => match t.get(ORACLE_RAN_OK_KEY)?.map(|g| g.value()) {
                None => Ok(None),
                Some(0) => Ok(Some(false)),
                Some(1) => Ok(Some(true)),
                Some(value) => Err(GraphStoreError::InvalidGenerationMetadata {
                    field: ORACLE_RAN_OK_KEY,
                    reason: format!("expected 0 or 1, found {value}"),
                }),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn write_generation_metadata_sync(
        db: &GraphDatabase,
        metadata: &GraphGenerationMetadata,
    ) -> Result<(), GraphStoreError> {
        validate_classified_by(&metadata.classified_by)?;
        let txn = db.begin_write()?;
        {
            let mut classified = txn.open_table(GRAPH_CLASSIFIED_BY)?;
            classified.insert(
                CLASSIFIED_BY_BUILD_IDENTITY_KEY,
                metadata.classified_by.build_identity.as_str(),
            )?;
            classified.insert(
                CLASSIFIED_BY_INDEXER_IDENTITY_KEY,
                metadata.classified_by.indexer_identity.as_str(),
            )?;
            classified.insert(
                CLASSIFIED_BY_PROVER_CONFIG_KEY,
                metadata.classified_by.prover_config.as_str(),
            )?;
            classified.insert(
                CLASSIFIED_BY_TIMESTAMP_KEY,
                metadata.classified_by.timestamp.as_str(),
            )?;
            let mut graph = txn.open_table(GRAPH_META)?;
            graph.insert(ORACLE_RAN_OK_KEY, u64::from(metadata.oracle_ran_ok))?;
        }
        txn.commit()?;
        Ok(())
    }

    fn read_generation_metadata_sync(
        db: &GraphDatabase,
    ) -> Result<GraphGenerationMetadata, GraphStoreError> {
        let classified_by = Self::read_classified_by_sync(db)?.ok_or(
            GraphStoreError::MissingGenerationMetadata {
                field: "classified_by",
            },
        )?;
        let oracle_ran_ok = Self::read_oracle_ran_ok_sync(db)?.ok_or(
            GraphStoreError::MissingGenerationMetadata {
                field: ORACLE_RAN_OK_KEY,
            },
        )?;
        Ok(GraphGenerationMetadata {
            classified_by,
            oracle_ran_ok,
        })
    }

    /// Atomically stamp every required interpretation input for a generation.
    pub async fn set_generation_metadata(
        &self,
        metadata: GraphGenerationMetadata,
    ) -> Result<(), GraphStoreError> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || Self::write_generation_metadata_sync(&db, &metadata))
            .await?
    }

    /// Synchronous sibling for callers that already execute off the async runtime.
    pub fn set_generation_metadata_sync(
        &self,
        metadata: &GraphGenerationMetadata,
    ) -> Result<(), GraphStoreError> {
        Self::write_generation_metadata_sync(&self.db, metadata)
    }

    /// Load the complete required metadata record for a current generation.
    pub async fn generation_metadata(&self) -> Result<GraphGenerationMetadata, GraphStoreError> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || Self::read_generation_metadata_sync(&db)).await?
    }

    /// Intent-aware, origin-gated read of the most recent snapshot (ADR-0033,
    /// ROOT-8). This is the read-path entrypoint that prevents one workspace's
    /// store from being spliced onto another.
    ///
    /// Ordering (ADR-0033 Decision 5): the **`SCHEMA_VERSION` check runs FIRST**
    /// and behaves EXACTLY as [`load_snapshot`](Self::load_snapshot) does today
    /// — a version-stale store yields `Ok(None)` (graceful discard), and the
    /// origin gate is consulted ONLY once the version matches. So a legacy v2
    /// store hits the version-mismatch clear/rebuild path, never a malformed
    /// "belongs to `<absent>`" origin refusal.
    ///
    /// Then the **origin gate** (Decision 2/8): `query_root` is `canonicalize`d
    /// (a `canonicalize` failure is treated as a mismatch, fail-closed) and
    /// compared against the stored [`GRAPH_ORIGIN`] stamp.
    /// - **Match** → serve the snapshot (`Ok(Some)`), via the existing
    ///   discard-without-clear read path.
    /// - **Mismatch OR absent origin** → a typed
    ///   [`GraphStoreError::OriginMismatch`] carrying both paths.
    ///
    /// Like [`load_snapshot`](Self::load_snapshot) this is **read-intent**: it
    /// never mutates the generation database (the version path discards without clearing,
    /// the origin path only reads the stamp).
    pub async fn load_snapshot_checked(
        &self,
        query_root: &Path,
    ) -> Result<Option<KnowledgeGraph>, GraphStoreError> {
        // Canonicalize the query root up front (Decision 8 — canonicalize BOTH
        // sides). A canonicalize failure (missing path / permission denied) maps
        // to `None`, which can never equal a stored origin ⇒ fail-closed.
        let canonical_query: Option<String> = query_root
            .canonicalize()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        // Read the version-mismatch verdict + the stored origin together in one
        // blocking read (no mutation).
        let db = Arc::clone(&self.db);
        let (version_mismatch, stored_origin) = tokio::task::spawn_blocking(
            move || -> Result<(bool, Option<String>), GraphStoreError> {
                let (version_mismatch, _stored_version) = Self::version_mismatch_sync(&db)?;
                let stored_origin = Self::read_origin_sync(&db)?;
                Ok((version_mismatch, stored_origin))
            },
        )
        .await??;

        // Decision 5: version check BEFORE origin check. A version mismatch
        // behaves exactly as today (discard → Ok(None)); the origin gate does
        // NOT run on a version-stale store.
        if version_mismatch {
            return Ok(None);
        }

        // Decision 2/8: origin gate. A present, equal canonical origin serves;
        // an absent OR differing origin (incl. a canonicalize failure above) is
        // a mismatch.
        let origin_matches = match (&stored_origin, &canonical_query) {
            (Some(stored), Some(query)) => stored == query,
            _ => false,
        };

        if origin_matches {
            // Version OK + origin OK → serve via the existing read path (which
            // re-checks the version cheaply and never mutates the generation database).
            return self.load_snapshot().await;
        }

        Err(GraphStoreError::OriginMismatch {
            stored: stored_origin.unwrap_or_else(|| "<no origin stamped>".to_string()),
            query: canonical_query.unwrap_or_else(|| query_root.display().to_string()),
        })
    }

    /// Load the graph, clearing the code-intel graph tables first if the
    /// persisted [`SCHEMA_VERSION`] does not match the current one (a schema
    /// bump), if the persisted graph cannot be reconstructed under the current
    /// snapshot layout (undecodable data),
    /// OR if the persisted store's stamped workspace origin does not match
    /// `query_root` (ADR-0033 ROOT-8 ADOPT — a foreign-origin store is cleared
    /// and rebuilt, NEVER merged; the version check runs FIRST, so a legacy
    /// un-stamped store hits the schema-clear, not a spurious origin adoption).
    /// The save site (`IndexPipeline::run`) re-stamps the origin to `query_root`
    /// after the rebuild.
    ///
    /// This is the **sole clearing loader** for graph tables. It MUST only be
    /// reached while building a private, unpublished generation owned by the
    /// immutable publisher. The index pipeline acts on `cleared = true` by
    /// forcing a full re-extract. READ-intent callers MUST use
    /// [`load_snapshot`](Self::load_snapshot) instead — it is
    /// discard-without-clear and never mutates the store, so the staleness
    /// signal this method relies on survives a read (WU-0003 / CL-REACH
    /// read-path blocker).
    ///
    /// Returns `(graph, cleared)`:
    /// - `graph` — `Some` when a usable, current-schema snapshot was loaded;
    ///   `None` when there is no snapshot yet OR the stale tables were cleared.
    /// - `cleared` — `true` iff stale, partial, undecodable, or explicitly
    ///   adopted graph data caused the code-intel graph tables to be wiped. The
    ///   caller MUST then perform a FULL re-extract (e.g. `IndexConfig::full`):
    ///   the graph is empty, and an incremental run keyed off unchanged file
    ///   hashes would otherwise leave the graph permanently empty.
    ///
    /// ## Safety fence (clear-on-schema-bump is scoped to the graph store ONLY)
    ///
    /// This clears ONLY the code-intel knowledge-graph tables — `GRAPH_SNAPSHOT`,
    /// `GRAPH_REACHABILITY_EVIDENCE`, and `GRAPH_META` — which all
    /// live in the caller-owned generation database behind `self.db`. The graph
    /// and its derived evidence are rebuildable from source. The handle owns
    /// only this generation database and cannot reach another bundle.
    ///
    /// ## Foreign-owner clears are GATED; same-owner recovery is automatic
    ///
    /// `adopt_foreign_origin` gates any current-schema clear whose persisted
    /// graph origin differs from `query_root`. Schema precedence remains automatic;
    /// after ownership matches, partial/undecodable graph recovery is also
    /// automatic because it destroys only regenerable data belonging to the
    /// SAME repo.
    ///
    /// With `adopt_foreign_origin = false` (the default everywhere) present,
    /// foreign-origin graph data yields
    /// [`GraphStoreError::OriginAdoptRequired`] and NOTHING is cleared.
    pub async fn load_snapshot_or_clear(
        &self,
        query_root: &Path,
        adopt_foreign_origin: bool,
    ) -> Result<(Option<KnowledgeGraph>, bool), GraphStoreError> {
        // Canonicalize the query root up front (ADR-0033 Decision 8 —
        // canonicalize BOTH sides). A canonicalize failure maps to `None`, which
        // can never equal a stored origin ⇒ treated as a mismatch (ADOPT: clear
        // + rebuild, and the save site re-stamps origin to the current root).
        let canonical_query: Option<String> = query_root
            .canonicalize()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        // Owned fallback for the refusal message — `query_root` is a borrow and
        // cannot cross into the 'static spawn_blocking closure.
        let query_display = query_root.display().to_string();

        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(
            move || -> Result<(Option<KnowledgeGraph>, bool), GraphStoreError> {
                // --- Schema-version gate (DRY: single source) ---------------
                // The staleness rule lives in `version_mismatch_sync`. A version
                // mismatch is handled FIRST and EXACTLY as before (clear +
                // rebuild); the origin gate does NOT run on a version-stale store
                // (ADR-0033 Decision 5) — a legacy v2 store hits THIS clear, never
                // a spurious origin adoption.
                let (version_mismatch, stored_version) = Self::version_mismatch_sync(&db)?;
                if version_mismatch {
                    tracing::warn!(
                        stored_version = ?stored_version,
                        current_version = SCHEMA_VERSION,
                        "code-intel graph schema changed — rebuilding from source. The persisted \
                         generation was written under graph schema version \
                         {stored_version:?}; the current layout is version {SCHEMA_VERSION}. \
                         Bincode is non-self-describing, so the stale tables are CLEARED and the \
                         graph is rebuilt from a full reindex. Only the selected derived \
                         code-intelligence generation is affected."
                    );
                    Self::clear_graph_tables(&db)?;
                    return Ok((None, true));
                }

                // --- Origin gate (ADR-0033 Decision 2/8, ADOPT intent) ------
                // Version OK. Read the stored origin and compare to the
                // (canonicalized) query root. The verdict is applied only once
                // persisted graph data is confirmed below — an EMPTY store has
                // nothing to clear and adopts the current root on first save.
                let stored_origin = Self::read_origin_sync(&db)?;
                let origin_matches = match (&stored_origin, &canonical_query) {
                    (Some(stored), Some(query)) => stored == query,
                    _ => false,
                };

                if !Self::persisted_graph_data_sync(&db)? {
                    return Ok((None, false));
                }

                // --- Open the snapshot --------------------------------------
                let read_txn = db.begin_read()?;
                let table = match read_txn.open_table(GRAPH_SNAPSHOT) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok((None, false)),
                    Err(e) => return Err(e.into()),
                };

                let guard = match table.get("latest")? {
                    Some(g) => g,
                    None => return Ok((None, false)),
                };

                // A snapshot IS present. If its origin does not match the query
                // root (a FOREIGN store, or an un-stamped legacy store at a
                // matching schema), ADOPT: clear the tables and report
                // `cleared = true` so the pipeline forces a FULL re-extract, and
                // the save re-stamps origin to this workspace. NEVER merge
                // foreign-origin data (ADR-0033 ROOT-8). Drop the read guard/txn
                // before opening the clear's write txn.
                if !origin_matches {
                    drop(guard);
                    drop(table);
                    drop(read_txn);

                    // WU-D: the ADOPT is DESTRUCTIVE to another workspace's
                    // graph. Refuse fail-closed unless explicitly authorised.
                    // NOTE: control only reaches here once a snapshot key is
                    // confirmed PRESENT above — an empty store returned early
                    // with `(None, false)` and still adopts silently, so a
                    // first-ever index never needs the flag.
                    if !adopt_foreign_origin {
                        return Err(GraphStoreError::OriginAdoptRequired {
                            stored: stored_origin
                                .unwrap_or_else(|| "<no origin stamped>".to_string()),
                            query: canonical_query.unwrap_or(query_display),
                        });
                    }

                    tracing::warn!(
                        stored_origin = ?stored_origin,
                        query_root = ?canonical_query,
                        "code-intel graph store origin differs from the current workspace root — \
                         ADOPTING: clearing the foreign-origin graph and rebuilding from a full \
                         reindex (the rebuild re-stamps the origin to this workspace). Only the \
                         selected derived code-intelligence generation is affected."
                    );
                    Self::clear_graph_tables(&db)?;
                    return Ok((None, true));
                }

                // Invalid derived state must not hard-error `index`. Clear it
                // and rebuild from source under the current exact schema.
                let graph = match Self::decode_snapshot(guard.value()) {
                    Ok(graph) => graph,
                    Err(e) => {
                        // Drop the read guard/txn before opening a write txn.
                        drop(guard);
                        drop(table);
                        drop(read_txn);
                        tracing::warn!(
                            error = %e,
                            "code-intel graph snapshot is invalid under the current schema — \
                             clearing the derived graph tables and rebuilding from source"
                        );
                        Self::clear_graph_tables(&db)?;
                        return Ok((None, true));
                    }
                };

                Ok((Some(graph), false))
            },
        )
        .await?
    }

    /// Clear ONLY the code-intel graph tables (`GRAPH_SNAPSHOT` and
    /// `GRAPH_REACHABILITY_EVIDENCE`) and stamp the current [`SCHEMA_VERSION`]
    /// into `GRAPH_META`, in a single write transaction. Used by the
    /// clear-on-schema-bump path.
    ///
    /// **Safety fence:** all three tables live in the generation database this
    /// `db` handle owns. The function is structurally scoped to that derived
    /// code-intelligence generation.
    fn clear_graph_tables(db: &GraphDatabase) -> Result<(), GraphStoreError> {
        let txn = db.begin_write()?;
        {
            // `retain` over the full table is the redb idiom for clearing all
            // entries while keeping the table itself (avoids a delete/recreate
            // dance and works whether or not the table pre-exists).
            let mut snapshot = txn.open_table(GRAPH_SNAPSHOT)?;
            snapshot.retain(|_, _| false)?;
            let mut evidence = txn.open_table(GRAPH_REACHABILITY_EVIDENCE)?;
            evidence.retain(|_, _| false)?;
            let mut meta = txn.open_table(GRAPH_META)?;
            meta.insert("schema_version", SCHEMA_VERSION)?;
        }
        txn.commit()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{EdgeKind, GraphEdge, GraphNode, SourceSpan};
    use crate::reachability::{
        ClassifiedNode, REACHABILITY_EVIDENCE_SCHEMA, ReachabilityClass, ReachabilityEvidence,
        ReachabilityReport, ReachabilitySummary,
    };
    use tempfile::{NamedTempFile, tempdir};

    fn make_node(name: &str) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.to_string(),
            kind: "function".to_string(),
            file_path: format!("src/{name}.rs"),
            content_hash: format!("hash_{name}"),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    fn calls_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Calls,
            weight: 1.0,
            ..Default::default()
        }
    }

    fn open_temp_db() -> Arc<Database> {
        let tmp = NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_owned();
        // Keep the file alive by leaking the tempfile handle (test only).
        std::mem::forget(tmp);
        Arc::new(Database::create(path).expect("create db"))
    }

    fn classified_graph_with_evidence() -> (KnowledgeGraph, ReachabilityEvidence) {
        let mut graph = KnowledgeGraph::new();
        let mut node = make_node("persisted");
        node.reachability_class = ReachabilityClass::Wired;
        let classified = ClassifiedNode {
            memory_id: node.memory_id,
            symbol_name: node.symbol_name.clone(),
            file_path: node.file_path.clone(),
            kind: node.kind.clone(),
            classification: node.reachability_class,
            has_retain_attr: false,
            has_uncaptured_items: false,
        };
        graph.add_node(node).expect("classified graph node");
        let evidence = ReachabilityEvidence {
            schema: REACHABILITY_EVIDENCE_SCHEMA.into(),
            report: ReachabilityReport {
                classified: vec![classified],
                summary: ReachabilitySummary {
                    total: 1,
                    wired: 1,
                    public_api: 0,
                    structural: 0,
                    test_only: 0,
                    dead: 0,
                    orphan_files: 0,
                    suspected: 0,
                    excluded: 0,
                },
                entry_points_used: Vec::new(),
                orphan_files: Vec::new(),
                test_chains: Default::default(),
            },
            classified_documents: vec!["src/persisted.rs".into()],
            entry_points: Vec::new(),
            trace_root_ids: Vec::new(),
        };
        evidence
            .validate(&graph)
            .expect("test evidence matches graph");
        (graph, evidence)
    }

    fn classified_graph_with_population(
        population: usize,
    ) -> (KnowledgeGraph, ReachabilityEvidence) {
        let mut graph = KnowledgeGraph::new();
        let mut classified = Vec::with_capacity(population);
        for index in 0..population {
            let name = format!("redundant-node-{index:04}");
            let mut node = make_node(&name);
            node.file_path = "src/population.rs".into();
            node.reachability_class = ReachabilityClass::Dead;
            classified.push(ClassifiedNode {
                memory_id: node.memory_id,
                symbol_name: node.symbol_name.clone(),
                file_path: node.file_path.clone(),
                kind: node.kind.clone(),
                classification: node.reachability_class,
                has_retain_attr: false,
                has_uncaptured_items: false,
            });
            graph.add_node(node).expect("population graph node");
        }
        classified.sort_by_key(|node| node.memory_id);
        let evidence = ReachabilityEvidence {
            schema: REACHABILITY_EVIDENCE_SCHEMA.into(),
            report: ReachabilityReport {
                classified,
                summary: ReachabilitySummary {
                    total: population,
                    wired: 0,
                    public_api: 0,
                    structural: 0,
                    test_only: 0,
                    dead: population,
                    orphan_files: 0,
                    suspected: 0,
                    excluded: 0,
                },
                entry_points_used: Vec::new(),
                orphan_files: Vec::new(),
                test_chains: Default::default(),
            },
            classified_documents: vec!["src/population.rs".into()],
            entry_points: Vec::new(),
            trace_root_ids: Vec::new(),
        };
        evidence
            .validate(&graph)
            .expect("population evidence matches graph");
        (graph, evidence)
    }

    fn overwrite_reachability_evidence(store: &GraphStore, bytes: &[u8]) {
        let txn = store.db.begin_write().expect("evidence write transaction");
        {
            let mut table = txn
                .open_table(GRAPH_REACHABILITY_EVIDENCE)
                .expect("evidence table");
            table
                .insert(REACHABILITY_EVIDENCE_KEY, bytes)
                .expect("overwrite evidence");
        }
        txn.commit().expect("commit evidence overwrite");
    }

    fn overwrite_graph_snapshot(store: &GraphStore, bytes: &[u8]) {
        let txn = store.db.begin_write().expect("graph write transaction");
        {
            let mut table = txn.open_table(GRAPH_SNAPSHOT).expect("graph table");
            table
                .insert("latest", bytes)
                .expect("overwrite graph snapshot");
        }
        txn.commit().expect("commit graph overwrite");
    }

    fn remove_reachability_evidence(store: &GraphStore) {
        let txn = store.db.begin_write().expect("evidence write transaction");
        {
            let mut table = txn
                .open_table(GRAPH_REACHABILITY_EVIDENCE)
                .expect("evidence table");
            table
                .remove(REACHABILITY_EVIDENCE_KEY)
                .expect("remove evidence");
        }
        txn.commit().expect("commit evidence removal");
    }

    struct PublicationProofFixture {
        root: tempfile::TempDir,
        store: GraphStore,
        proof: GraphPublicationProof,
    }

    async fn publication_proof_fixture() -> PublicationProofFixture {
        let root = tempdir().expect("publication root");
        let store = GraphStore::new(open_temp_db());
        let (graph, evidence) = classified_graph_with_evidence();
        let write = store
            .save_snapshot_with_reachability_evidence_profiled(&graph, &evidence)
            .await
            .expect("save exact graph and evidence");
        store
            .set_origin(root.path())
            .await
            .expect("stamp publication origin");
        let generation_metadata = GraphGenerationMetadata::now(true);
        store
            .set_generation_metadata(generation_metadata.clone())
            .await
            .expect("stamp publication metadata");
        let proof = write
            .publication_proof(root.path(), generation_metadata)
            .expect("bind publication proof");
        PublicationProofFixture { root, store, proof }
    }

    #[tokio::test]
    async fn publication_proof_accepts_only_its_intact_generation() {
        let fixture = publication_proof_fixture().await;
        GraphStore::reset_publication_validation_counts();

        fixture
            .store
            .validate_publication_proof_sync(fixture.root.path(), &fixture.proof)
            .expect("intact graph, evidence, origin, and metadata");

        assert_eq!(
            GraphStore::publication_validation_counts(),
            (0, 1),
            "the positive control must validate by proof without decoding the snapshot"
        );
    }

    #[tokio::test]
    async fn invalid_bound_reachability_evidence_is_capability_local() {
        let fixture = publication_proof_fixture().await;
        overwrite_reachability_evidence(&fixture.store, b"{not-json");
        let proof = fixture
            .store
            .capture_publication_proof_sync(fixture.root.path())
            .expect("bind the exact invalid optional document");

        let opened = fixture
            .store
            .validate_and_load_publication_proof_sync(fixture.root.path(), &proof)
            .expect("invalid optional evidence must not erase the authenticated graph");
        assert!(opened.graph.node_count() > 0, "positive graph control");
        assert!(matches!(
            opened.reachability_evidence,
            Err(GraphStoreError::Serialization(_))
        ));
    }

    #[tokio::test]
    async fn publication_proof_rejects_graph_byte_tampering() {
        let fixture = publication_proof_fixture().await;
        overwrite_graph_snapshot(&fixture.store, b"tampered graph bytes");

        let error = fixture
            .store
            .validate_publication_proof_sync(fixture.root.path(), &fixture.proof)
            .expect_err("changed graph bytes must invalidate the proof");
        assert!(matches!(error, GraphStoreError::InvalidSnapshot(_)));
    }

    #[tokio::test]
    async fn publication_proof_rejects_reachability_byte_tampering_or_removal() {
        let changed = publication_proof_fixture().await;
        overwrite_reachability_evidence(&changed.store, b"changed evidence bytes");
        let changed_error = changed
            .store
            .validate_publication_proof_sync(changed.root.path(), &changed.proof)
            .expect_err("changed reachability bytes must invalidate the proof");
        assert!(matches!(
            changed_error,
            GraphStoreError::ReachabilityEvidence(_)
        ));

        let missing = publication_proof_fixture().await;
        remove_reachability_evidence(&missing.store);
        let missing_error = missing
            .store
            .validate_publication_proof_sync(missing.root.path(), &missing.proof)
            .expect_err("missing reachability bytes must invalidate the proof");
        assert!(matches!(
            missing_error,
            GraphStoreError::ReachabilityEvidence(_)
        ));
    }

    #[tokio::test]
    async fn publication_proof_rejects_metadata_origin_and_schema_tampering() {
        let metadata = publication_proof_fixture().await;
        let mut changed_metadata = metadata.proof.generation_metadata.clone();
        changed_metadata.oracle_ran_ok = !changed_metadata.oracle_ran_ok;
        metadata
            .store
            .set_generation_metadata(changed_metadata)
            .await
            .expect("replace generation metadata");
        let metadata_error = metadata
            .store
            .validate_publication_proof_sync(metadata.root.path(), &metadata.proof)
            .expect_err("changed interpretation metadata must invalidate the proof");
        assert!(matches!(
            metadata_error,
            GraphStoreError::InvalidGenerationMetadata { .. }
        ));

        let query = publication_proof_fixture().await;
        let foreign_query = tempdir().expect("foreign query root");
        let query_error = query
            .store
            .validate_publication_proof_sync(foreign_query.path(), &query.proof)
            .expect_err("a proof cannot authorize a different query root");
        assert!(matches!(
            query_error,
            GraphStoreError::OriginMismatch { .. }
        ));

        let stored = publication_proof_fixture().await;
        let foreign_origin = tempdir().expect("foreign stored origin");
        stored
            .store
            .set_origin(foreign_origin.path())
            .await
            .expect("replace stored origin");
        let stored_error = stored
            .store
            .validate_publication_proof_sync(stored.root.path(), &stored.proof)
            .expect_err("a changed persisted origin must invalidate the proof");
        assert!(matches!(
            stored_error,
            GraphStoreError::OriginMismatch { .. }
        ));

        let schema = publication_proof_fixture().await;
        let mut changed_schema = schema.proof.clone();
        changed_schema.schema_version = SCHEMA_VERSION.saturating_add(1);
        let schema_error = schema
            .store
            .validate_publication_proof_sync(schema.root.path(), &changed_schema)
            .expect_err("a proof from another schema must be refused");
        assert!(matches!(schema_error, GraphStoreError::Origin(_)));
    }

    #[tokio::test]
    async fn snapshot_roundtrip() {
        let db = open_temp_db();
        let store = GraphStore::new(db);

        let mut graph = KnowledgeGraph::new();
        let a = make_node("alpha");
        let b = make_node("beta");
        let a_id = a.memory_id;
        let b_id = b.memory_id;
        graph.add_node(a).expect("add a");
        graph.add_node(b).expect("add b");
        graph
            .set_source_span(
                a_id,
                SourceSpan {
                    start_byte: 7,
                    end_byte: 19,
                },
            )
            .expect("alpha span");
        graph.add_edge(a_id, b_id, calls_edge()).expect("edge");

        store.save_snapshot(&graph).await.expect("save");
        let loaded = store
            .load_snapshot()
            .await
            .expect("load")
            .expect("should exist");

        assert_eq!(loaded.node_count(), 2);
        assert_eq!(loaded.edge_count(), 1);
        assert!(loaded.node(&a_id).is_some());
        assert!(loaded.node(&b_id).is_some());
        assert_eq!(
            loaded.source_span(&a_id),
            Some(SourceSpan {
                start_byte: 7,
                end_byte: 19,
            })
        );
        assert_eq!(loaded.source_span(&b_id), None);

        let neighbors = loaded.neighbors(&a_id);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].0, b_id);
    }

    #[test]
    fn snapshot_decoder_rejects_ambiguous_or_incomplete_graph_state() {
        fn encoded(snapshot: &GraphSnapshot) -> Vec<u8> {
            bincode::serde::encode_to_vec(snapshot, bincode::config::standard())
                .expect("encode corrupt snapshot fixture")
        }

        fn assert_invalid(snapshot: GraphSnapshot, expected: &str) {
            let error = match GraphStore::decode_snapshot(&encoded(&snapshot)) {
                Ok(_) => panic!("corrupt graph state must fail closed"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "expected {expected:?} in {error}"
            );
        }

        let source = make_node("source");
        let target = make_node("target");
        let source_id = source.memory_id;
        let target_id = target.memory_id;
        let span = SourceSpan {
            start_byte: 0,
            end_byte: 4,
        };

        assert_invalid(
            GraphSnapshot {
                nodes: vec![source.clone(), source.clone()],
                edges: Vec::new(),
                source_spans: Vec::new(),
            },
            "duplicate node",
        );
        assert_invalid(
            GraphSnapshot {
                nodes: vec![source.clone()],
                edges: Vec::new(),
                source_spans: vec![(source_id, span), (source_id, span)],
            },
            "duplicate persisted source span",
        );
        assert_invalid(
            GraphSnapshot {
                nodes: vec![source.clone()],
                edges: vec![(source_id, target_id, calls_edge())],
                source_spans: Vec::new(),
            },
            "node not found",
        );
        assert_invalid(
            GraphSnapshot {
                nodes: vec![source, target],
                edges: vec![
                    (source_id, target_id, calls_edge()),
                    (source_id, target_id, calls_edge()),
                ],
                source_spans: Vec::new(),
            },
            "duplicate persisted Calls edge",
        );

        let valid = GraphSnapshot {
            nodes: vec![make_node("valid")],
            edges: Vec::new(),
            source_spans: Vec::new(),
        };
        let mut trailing = encoded(&valid);
        trailing.push(0);
        let error = match GraphStore::decode_snapshot(&trailing) {
            Ok(_) => panic!("trailing bytes must not be accepted as an exact snapshot"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("decoder consumed"));
    }

    #[tokio::test]
    async fn reachability_evidence_roundtrips_with_its_exact_graph() {
        let store = GraphStore::new(open_temp_db());
        let (graph, evidence) = classified_graph_with_evidence();

        store
            .save_snapshot_with_reachability_evidence(&graph, &evidence)
            .await
            .expect("atomically save graph and evidence");
        let loaded_graph = store
            .load_snapshot()
            .await
            .expect("load graph")
            .expect("graph exists");
        let loaded_evidence = store
            .load_reachability_evidence(&loaded_graph)
            .await
            .expect("load valid evidence")
            .expect("evidence exists");

        assert_eq!(loaded_evidence, evidence);
    }

    /// STORAGE/PERFORMANCE FALSIFIER: the immutable graph already carries
    /// every classified node's UUID, identity, flags, and reachability class.
    /// The adjacent evidence payload must bind that population compactly
    /// rather than serializing the same full node projection a second time.
    #[tokio::test]
    async fn persisted_reachability_evidence_does_not_duplicate_graph_nodes() {
        let store = GraphStore::new(open_temp_db());
        let (graph, evidence) = classified_graph_with_population(512);
        let redundant_runtime_bytes =
            serde_json::to_vec(&evidence).expect("serialize positive duplicate population");
        let marker = b"redundant-node-0511";
        assert!(
            redundant_runtime_bytes
                .windows(marker.len())
                .any(|window| window == marker),
            "positive control must prove the runtime report contains node identities"
        );

        store
            .save_snapshot_with_reachability_evidence(&graph, &evidence)
            .await
            .expect("persist graph and compact evidence");
        let persisted = {
            let read = store.db.begin_read().expect("read transaction");
            let table = read
                .open_table(GRAPH_REACHABILITY_EVIDENCE)
                .expect("evidence table");
            table
                .get(REACHABILITY_EVIDENCE_KEY)
                .expect("read evidence")
                .expect("persisted evidence")
                .value()
                .to_vec()
        };
        assert!(
            !persisted
                .windows(marker.len())
                .any(|window| window == marker),
            "persisted evidence must not duplicate graph-owned symbol identities"
        );
        assert!(
            persisted.len().saturating_mul(10) < redundant_runtime_bytes.len(),
            "compact evidence must be materially smaller: persisted={} duplicate={}",
            persisted.len(),
            redundant_runtime_bytes.len()
        );
    }

    #[tokio::test]
    async fn every_graph_only_save_invalidates_prior_reachability_evidence() {
        let store = GraphStore::new(open_temp_db());
        let (graph, evidence) = classified_graph_with_evidence();

        store
            .save_snapshot_with_reachability_evidence(&graph, &evidence)
            .await
            .expect("seed graph and evidence");
        assert!(
            store
                .load_reachability_evidence(&graph)
                .await
                .expect("load seeded evidence")
                .is_some(),
            "positive control: combined save must publish evidence"
        );

        store
            .save_snapshot(&graph)
            .await
            .expect("async graph-only save");
        assert!(
            store
                .load_reachability_evidence(&graph)
                .await
                .expect("load after async graph-only save")
                .is_none(),
            "async graph-only save must invalidate evidence in its transaction"
        );

        store
            .save_snapshot_with_reachability_evidence(&graph, &evidence)
            .await
            .expect("reseed graph and evidence");
        store
            .save_snapshot_sync(&graph)
            .expect("sync graph-only save");
        assert!(
            store
                .load_reachability_evidence(&graph)
                .await
                .expect("load after sync graph-only save")
                .is_none(),
            "sync graph-only save must invalidate evidence in its transaction"
        );
    }

    #[tokio::test]
    async fn malformed_noncanonical_wrong_schema_and_graph_mismatch_are_refused() {
        let store = GraphStore::new(open_temp_db());
        let (graph, evidence) = classified_graph_with_evidence();
        store
            .save_snapshot_with_reachability_evidence(&graph, &evidence)
            .await
            .expect("seed graph and evidence");
        assert!(
            store
                .load_reachability_evidence(&graph)
                .await
                .expect("positive control: canonical evidence loads")
                .is_some()
        );

        overwrite_reachability_evidence(&store, b"{not-json");
        assert!(
            store.load_reachability_evidence(&graph).await.is_err(),
            "malformed JSON must never become absent or empty evidence"
        );

        let projection = evidence.persisted_projection();
        let pretty = serde_json::to_vec_pretty(&projection).expect("pretty evidence");
        overwrite_reachability_evidence(&store, &pretty);
        let noncanonical = store
            .load_reachability_evidence(&graph)
            .await
            .expect_err("noncanonical evidence must be refused");
        assert!(
            noncanonical
                .to_string()
                .contains("not in canonical encoding")
        );

        let mut wrong_schema = projection.clone();
        wrong_schema.schema = "h00/reachability-evidence/v999".into();
        let wrong_schema_bytes = serde_json::to_vec(&wrong_schema).expect("wrong-schema evidence");
        overwrite_reachability_evidence(&store, &wrong_schema_bytes);
        let schema_error = store
            .load_reachability_evidence(&graph)
            .await
            .expect_err("wrong-schema evidence must be refused");
        assert!(schema_error.to_string().contains("unsupported schema"));

        let canonical = serde_json::to_vec(&projection).expect("canonical evidence");
        overwrite_reachability_evidence(&store, &canonical);
        let mut different_graph = graph.clone();
        let mut added = make_node("later");
        added.reachability_class = ReachabilityClass::Dead;
        different_graph
            .add_node(added)
            .expect("different graph node");
        let mismatch = store
            .load_reachability_evidence(&different_graph)
            .await
            .expect_err("evidence for another graph population must be refused");
        assert!(
            mismatch
                .to_string()
                .contains("classified population digest")
        );

        let mut different_classification = graph.clone();
        different_classification
            .node_mut(&evidence.report.classified[0].memory_id)
            .expect("classified fixture node")
            .reachability_class = ReachabilityClass::Dead;
        let classification_mismatch = store
            .load_reachability_evidence(&different_classification)
            .await
            .expect_err("evidence may not authorize a different persisted classification");
        assert!(
            classification_mismatch
                .to_string()
                .contains("classified population digest")
        );
    }

    #[tokio::test]
    async fn load_empty_returns_none() {
        let db = open_temp_db();
        let store = GraphStore::new(db);

        let loaded = store.load_snapshot().await.expect("load");
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn generation_metadata_is_complete_atomic_and_strictly_decoded() {
        let db = open_temp_db();
        let store = GraphStore::new(Arc::clone(&db));

        let missing = store
            .generation_metadata()
            .await
            .expect_err("an unstamped store has no generation authority");
        assert!(matches!(
            missing,
            GraphStoreError::MissingGenerationMetadata {
                field: "classified_by"
            }
        ));

        let first = GraphGenerationMetadata::now(true);
        store
            .set_generation_metadata(first.clone())
            .await
            .expect("stamp complete metadata");
        assert_eq!(
            store.generation_metadata().await.expect("read metadata"),
            first
        );

        let mut unavailable_identity = first.clone();
        unavailable_identity.classified_by.indexer_identity = "unavailable".into();
        let invalid_write = store
            .set_generation_metadata(unavailable_identity)
            .await
            .expect_err("an inexact classifier identity must fail before persistence");
        assert!(matches!(
            invalid_write,
            GraphStoreError::InvalidGenerationMetadata {
                field: "classified_by",
                ..
            }
        ));
        assert_eq!(
            store
                .generation_metadata()
                .await
                .expect("metadata after rejected write"),
            first,
            "a rejected identity must not partially alter the prior complete stamp"
        );

        let transaction = db.begin_write().expect("corrupt metadata transaction");
        {
            let mut table = transaction.open_table(GRAPH_META).expect("graph metadata");
            table
                .insert(ORACLE_RAN_OK_KEY, 2)
                .expect("plant non-boolean oracle value");
        }
        transaction.commit().expect("commit corrupt metadata");
        let invalid = store
            .generation_metadata()
            .await
            .expect_err("non-canonical booleans must not become authority");
        assert!(matches!(
            invalid,
            GraphStoreError::InvalidGenerationMetadata {
                field: ORACLE_RAN_OK_KEY,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn snapshot_preserves_edge_weights() {
        let db = open_temp_db();
        let store = GraphStore::new(db);

        let mut graph = KnowledgeGraph::new();
        let a = make_node("a");
        let b = make_node("b");
        let a_id = a.memory_id;
        let b_id = b.memory_id;
        graph.add_node(a).expect("add a");
        graph.add_node(b).expect("add b");

        let edge = GraphEdge {
            kind: EdgeKind::Implements,
            weight: 0.42,
            ..Default::default()
        };
        graph.add_edge(a_id, b_id, edge).expect("edge");

        store.save_snapshot(&graph).await.expect("save");
        let loaded = store
            .load_snapshot()
            .await
            .expect("load")
            .expect("should exist");

        let neighbors = loaded.neighbors(&a_id);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].1.kind, EdgeKind::Implements);
        assert!((neighbors[0].1.weight - 0.42).abs() < f32::EPSILON);
    }

    /// Round-trip the current GraphSnapshot format and verify all fields
    /// survive serialization + deserialization.
    #[test]
    fn current_snapshot_fields_roundtrip() {
        let node_id = Uuid::new_v4();
        let node = GraphNode {
            memory_id: node_id,
            symbol_name: "my_fn".to_string(),
            kind: "function".to_string(),
            file_path: "src/my.rs".to_string(),
            content_hash: "hash_my".to_string(),
            signature: "fn my_fn(x: i32) -> bool".to_string(),
            reachability_class: ReachabilityClass::Wired,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            // WU-0003: the two persisted test-ness bits round-trip too.
            is_test_only: Some(true),
            is_test_root: true,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        };

        let other_id = Uuid::new_v4();
        let other = GraphNode {
            memory_id: other_id,
            symbol_name: "other_fn".to_string(),
            kind: "function".to_string(),
            file_path: "src/other.rs".to_string(),
            content_hash: "hash_other".to_string(),
            signature: String::new(),
            // WU-0003 RC5: an unclassified node round-trips as Unclassified.
            reachability_class: ReachabilityClass::Unclassified,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        };

        let edge = GraphEdge {
            kind: EdgeKind::Calls,
            weight: 2.5,
            access_count: 10,
            ..Default::default()
        };

        let snapshot = GraphSnapshot {
            nodes: vec![node, other],
            edges: vec![(node_id, other_id, edge)],
            source_spans: Vec::new(),
        };

        let bytes = bincode::serde::encode_to_vec(&snapshot, bincode::config::standard())
            .expect("serialize");
        let (deser, _): (GraphSnapshot, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("deserialize");

        assert_eq!(deser.nodes.len(), 2);
        assert_eq!(deser.edges.len(), 1);

        // Verify first node's new fields survived
        let n0 = &deser.nodes[0];
        assert_eq!(n0.memory_id, node_id);
        assert_eq!(n0.signature, "fn my_fn(x: i32) -> bool");
        assert_eq!(n0.reachability_class, ReachabilityClass::Wired);
        assert_eq!(n0.is_test_only, Some(true));
        assert!(n0.is_test_root);

        // Verify second node (empty signature, Unclassified reachability)
        let n1 = &deser.nodes[1];
        assert_eq!(n1.signature, "");
        assert_eq!(n1.reachability_class, ReachabilityClass::Unclassified);
        assert_eq!(n1.is_test_only, None);
        assert!(!n1.is_test_root);

        // Verify edge survived
        let (src, tgt, e) = &deser.edges[0];
        assert_eq!(*src, node_id);
        assert_eq!(*tgt, other_id);
        assert_eq!(e.kind, EdgeKind::Calls);
        assert!((e.weight - 2.5).abs() < f32::EPSILON);
        assert_eq!(e.access_count, 10);
    }

    /// F11 (POST-SCHEMA / migration): a snapshot blob that CANNOT decode under
    /// the current `GraphNode` schema (a pre-bump record) must NOT hard-error
    /// `load_snapshot` — it returns `Ok(None)` (discard the stale snapshot,
    /// rebuild cleanly), implementing the baked clear-on-schema-bump decision.
    /// Without this, `index` is un-runnable against any pre-bump data-dir.
    ///
    /// Under the WU-0003 clear-on-schema-bump fix this snapshot is present with
    /// NO `GRAPH_META` version stamp (a pre-bump store), so the version gate
    /// (`stored_version = None != Some(SCHEMA_VERSION)`) trips first and clears
    /// the table — the same observable `Ok(None)` result.
    #[tokio::test]
    async fn undecodable_old_snapshot_triggers_clean_rebuild_not_hard_error() {
        let db = open_temp_db();
        // Write an UNDECODABLE blob into the snapshot table directly (simulating
        // a snapshot serialized under the old layout that no longer parses).
        {
            let txn = db.begin_write().expect("begin write");
            {
                let mut table = txn.open_table(GRAPH_SNAPSHOT).expect("open table");
                // Garbage bytes that are not a valid GraphSnapshot under the new schema.
                table
                    .insert("latest", b"\xff\xff\xff\xff\xff\xff\xff\xff".as_slice())
                    .expect("insert");
            }
            txn.commit().expect("commit");
        }

        let store = GraphStore::new(db);
        let loaded = store.load_snapshot().await;
        let err_msg = loaded.as_ref().err().map(|e| e.to_string());
        assert!(
            loaded.is_ok(),
            "an undecodable old snapshot must NOT hard-error load_snapshot (got Err: {err_msg:?})"
        );
        assert!(
            loaded.expect("ok").is_none(),
            "an undecodable old snapshot must be discarded (Ok(None)) for a clean rebuild"
        );
    }

    /// A snapshot without the current schema stamp is disposable derived data.
    /// The write-side recovery path clears it and requires a source rebuild; it
    /// never attempts to migrate or reinterpret the bytes.
    #[tokio::test]
    async fn unstamped_snapshot_is_cleared_for_rebuild() {
        let db = open_temp_db();
        let obsolete = b"obsolete-derived-graph";
        {
            let txn = db.begin_write().expect("begin write");
            {
                let mut snap = txn.open_table(GRAPH_SNAPSHOT).expect("open snapshot");
                snap.insert("latest", obsolete.as_slice())
                    .expect("insert snap");
            }
            txn.commit().expect("commit");
        }

        let store = GraphStore::new(db.clone());
        let (graph, cleared) = store
            .load_snapshot_or_clear(std::path::Path::new("."), false)
            .await
            .expect("clear disposable snapshot");
        assert!(cleared);
        assert!(graph.is_none());

        let read = db.begin_read().expect("read");
        let snap = read.open_table(GRAPH_SNAPSHOT).expect("snap");
        assert!(snap.get("latest").expect("get").is_none());
        let meta = read.open_table(GRAPH_META).expect("meta");
        assert_eq!(
            meta.get("schema_version").expect("get").map(|g| g.value()),
            Some(SCHEMA_VERSION),
            "the clear must stamp the current schema version"
        );
    }

    /// GUARD: a CLEAN same-schema store must NOT be spuriously cleared. A
    /// current-schema snapshot (written via `save_snapshot`, which stamps the
    /// version) round-trips and reports `cleared = false`. Without this guard
    /// the version gate would nuke a valid store on every index.
    #[tokio::test]
    async fn same_schema_store_is_not_cleared() {
        let db = open_temp_db();
        let store = GraphStore::new(db);

        let mut graph = KnowledgeGraph::new();
        let a = make_node("alpha");
        let b = make_node("beta");
        let a_id = a.memory_id;
        let b_id = b.memory_id;
        graph.add_node(a).expect("add a");
        graph.add_node(b).expect("add b");
        graph.add_edge(a_id, b_id, calls_edge()).expect("edge");

        store.save_snapshot(&graph).await.expect("save");
        // Stamp the matching origin (production always stamps at the save site),
        // so the ADR-0033 origin gate serves rather than adopts this own-store.
        store
            .set_origin(std::path::Path::new("."))
            .await
            .expect("stamp origin");

        let (loaded, cleared) = store
            .load_snapshot_or_clear(std::path::Path::new("."), false)
            .await
            .expect("load");
        assert!(
            !cleared,
            "a same-schema store must NOT be cleared (no spurious rebuild every index)"
        );
        let loaded = loaded.expect("a same-schema store must load its graph");
        assert_eq!(loaded.node_count(), 2);
        assert_eq!(loaded.edge_count(), 1);
    }

    /// GUARD: a brand-new EMPTY store (no snapshot or version) must
    /// NOT report `cleared` — there is nothing stale to discard. It simply
    /// returns `(None, false)` so a first index proceeds normally.
    #[tokio::test]
    async fn empty_store_is_not_cleared() {
        let db = open_temp_db();
        let store = GraphStore::new(db);
        // Empty store: returns (None, false) before the origin gate is reached.
        let (loaded, cleared) = store
            .load_snapshot_or_clear(std::path::Path::new("."), false)
            .await
            .expect("load");
        assert!(!cleared, "an empty store has nothing to clear");
        assert!(loaded.is_none(), "an empty store has no graph yet");
    }

    /// FALSIFIER (WU-0003 / CL-REACH read-path blocker): a READ-intent
    /// `load_snapshot` against a schema-stale store must DISCARD-WITHOUT-CLEAR —
    /// it returns `None` AND leaves the on-disk `GRAPH_*` tables and the (absent)
    /// version stamp UNTOUCHED. Read commands must never mutate `graph.redb`.
    ///
    /// Why this matters: the index pipeline detects a stale store by the SURVIVING
    /// staleness signal (an old/absent version stamp + undecodable bytes). If a
    /// read command clears + stamps the current version, that signal is erased,
    /// so the next incremental `index` sees `cleared = false`, skips the forced
    /// full rebuild, and leaves the graph PERMANENTLY at 0 nodes — the same
    /// silent-wipe class, shifted one trigger over. This falsifier pins the
    /// read path as non-mutating so the recovery signal survives.
    ///
    /// RED before the fix: `load_snapshot` delegated to `load_snapshot_or_clear`,
    /// which on a stale store clears the tables and stamps `SCHEMA_VERSION`.
    /// GREEN after: the read path returns `None` with the on-disk bytes intact.
    #[tokio::test]
    async fn read_load_on_stale_store_does_not_clear_or_stamp() {
        let db = open_temp_db();

        let snap_bytes = b"stale-derived-snapshot".to_vec();

        {
            let txn = db.begin_write().expect("begin write");
            {
                let mut snap = txn.open_table(GRAPH_SNAPSHOT).expect("open snapshot");
                snap.insert("latest", snap_bytes.as_slice())
                    .expect("insert snap");
                // NO GRAPH_META version stamp — a pre-bump store.
            }
            txn.commit().expect("commit");
        }

        let store = GraphStore::new(db.clone());

        // READ path: must NOT hard-error, must return None, must NOT mutate disk.
        let loaded = store
            .load_snapshot()
            .await
            .expect("read load must not hard-error on a stale store");
        assert!(
            loaded.is_none(),
            "a stale store yields no usable graph on the read path (discard, no rebuild here)"
        );

        // The on-disk tables + version stamp must be UNCHANGED — the read path
        // leaves the staleness signal intact for the index path to detect.
        let read = db.begin_read().expect("read");
        let snap = read.open_table(GRAPH_SNAPSHOT).expect("snap");
        assert_eq!(
            snap.get("latest").expect("get").map(|g| g.value().to_vec()),
            Some(snap_bytes),
            "read load must NOT clear GRAPH_SNAPSHOT — the stale bytes must survive"
        );
        // The version stamp must remain ABSENT (we never wrote one, and the read
        // path must not stamp). If the read path stamped SCHEMA_VERSION, the
        // index path would no longer see a version mismatch and would skip the
        // forced full rebuild.
        match read.open_table(GRAPH_META) {
            Ok(meta) => assert!(
                meta.get("schema_version").expect("get").is_none(),
                "read load must NOT stamp a schema version on a pre-bump store"
            ),
            Err(redb::TableError::TableDoesNotExist(_)) => { /* never created — also fine */ }
            Err(e) => panic!("unexpected meta table error: {e}"),
        }
    }

    // -----------------------------------------------------------------------
    // ADR-0033 / ROOT-8 origin-gate falsifiers (store layer, L3a)
    // -----------------------------------------------------------------------

    /// Save a single-node current-schema snapshot into `store` so the origin
    /// gate has something to (refuse to) serve.
    async fn save_one_node(store: &GraphStore) {
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_node("alpha")).expect("add node");
        store.save_snapshot(&graph).await.expect("save snapshot");
    }

    /// (a) Save snapshot + `set_origin(A)`, then `load_snapshot_checked(A)`
    /// serves the snapshot — a matching canonical origin is not
    /// refused. Also exercises the `set_origin`/`get_origin` round-trip.
    #[tokio::test]
    async fn origin_match_serves_snapshot() {
        let db = open_temp_db();
        let store = GraphStore::new(db);
        let dir_a = tempdir().expect("tempdir A");
        save_one_node(&store).await;
        store.set_origin(dir_a.path()).await.expect("set origin A");

        // set/get round-trip: the stored stamp is the canonical form of A.
        let canon_a = dir_a
            .path()
            .canonicalize()
            .expect("canonicalize A")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            store.get_origin().await.expect("get origin"),
            Some(canon_a),
            "get_origin must return the canonical stamped root"
        );

        let loaded = store
            .load_snapshot_checked(dir_a.path())
            .await
            .expect("a matching origin must not error")
            .expect("a matching origin must serve the snapshot");
        assert_eq!(loaded.node_count(), 1, "the snapshot graph must be served");
    }

    /// (b) `load_snapshot_checked(B)` against a store stamped with
    /// origin A returns `Err(OriginMismatch)` whose message and fields carry
    /// BOTH the stored origin (A) and the querying root (B) — the data the
    /// "store belongs to /A; you are in /B" diagnostic needs.
    #[tokio::test]
    async fn origin_mismatch_errors_with_both_paths() {
        let db = open_temp_db();
        let store = GraphStore::new(db);
        let dir_a = tempdir().expect("tempdir A");
        let dir_b = tempdir().expect("tempdir B");
        save_one_node(&store).await;
        store.set_origin(dir_a.path()).await.expect("set origin A");

        // NB: `expect_err` would require the Ok type (`Option<KnowledgeGraph>`)
        // to be `Debug`, which `KnowledgeGraph` is not — so match the result.
        let err = match store.load_snapshot_checked(dir_b.path()).await {
            Err(e) => e,
            Ok(_) => panic!("a foreign origin must error, not serve a graph"),
        };

        let canon_a = dir_a
            .path()
            .canonicalize()
            .expect("canonicalize A")
            .to_string_lossy()
            .into_owned();
        let canon_b = dir_b
            .path()
            .canonicalize()
            .expect("canonicalize B")
            .to_string_lossy()
            .into_owned();

        let msg = err.to_string();
        assert!(
            msg.contains(&canon_a),
            "diagnostic must name the stored origin A; got: {msg}"
        );
        assert!(
            msg.contains(&canon_b),
            "diagnostic must name the querying root B; got: {msg}"
        );
        match err {
            GraphStoreError::OriginMismatch { stored, query } => {
                assert_eq!(stored, canon_a, "stored field must be canonical A");
                assert_eq!(query, canon_b, "query field must be canonical B");
            }
            other => panic!("expected OriginMismatch, got {other:?}"),
        }
    }

    /// (c) A store with a snapshot but no origin stamp errors: absence is a
    /// mismatch and is never served.
    #[tokio::test]
    async fn origin_absent_errors() {
        let db = open_temp_db();
        let store = GraphStore::new(db);
        let dir = tempdir().expect("tempdir");
        save_one_node(&store).await;
        // NOTE: deliberately NO set_origin — absent origin = mismatch.

        // Match (not `expect_err`) — the Ok type `Option<KnowledgeGraph>` is
        // not `Debug`.
        match store.load_snapshot_checked(dir.path()).await {
            Err(GraphStoreError::OriginMismatch { .. }) => {}
            Err(other) => panic!("absent origin must surface as OriginMismatch, got: {other:?}"),
            Ok(_) => panic!("an absent origin must error (fail-closed)"),
        }
    }

    /// (d) Negative control: a workspace querying its own
    /// (matching-origin) store must NOT refuse. A richer graph (two nodes + an
    /// edge) round-trips fully through the gate, proving the gate serves the
    /// home repo rather than locking it out.
    #[tokio::test]
    async fn origin_own_repo_is_not_refused() {
        let db = open_temp_db();
        let store = GraphStore::new(db);
        let home = tempdir().expect("tempdir home");

        let mut graph = KnowledgeGraph::new();
        let a = make_node("alpha");
        let b = make_node("beta");
        let a_id = a.memory_id;
        let b_id = b.memory_id;
        graph.add_node(a).expect("add a");
        graph.add_node(b).expect("add b");
        graph.add_edge(a_id, b_id, calls_edge()).expect("edge");
        store.save_snapshot(&graph).await.expect("save");
        store
            .set_origin(home.path())
            .await
            .expect("set origin home");

        let loaded = store
            .load_snapshot_checked(home.path())
            .await
            .expect("the home repo must NOT be refused against its own store")
            .expect("the home repo's snapshot must be served");
        assert_eq!(loaded.node_count(), 2, "all nodes served for the home repo");
        assert_eq!(loaded.edge_count(), 1, "the edge survives the gated load");
    }

    // -----------------------------------------------------------------------
    // WU-0015 Leg 2 — SCHEMA_VERSION bump + has_platform_cfg bincode round-trip.
    // -----------------------------------------------------------------------

    /// Pin the current whole-snapshot layout. Exact source spans are persisted
    /// with the graph and no incremental or compatibility format is admitted.
    #[test]
    fn schema_version_is_twelve_without_obsolete_shape_authority() {
        assert_eq!(
            SCHEMA_VERSION, 12,
            "removing persisted shape authority requires graph snapshot schema 11"
        );
    }

    /// SB2 (Leg F): a GraphNode carrying an `oracle_receipt` round-trips through
    /// the exact bincode path graph_store uses (positional/APPEND-LAST ordinal),
    /// byte-identical, and the default make_node (None) never spuriously reads
    /// Some. The append-LAST ordinal is guarded by the SCHEMA_VERSION pin test.
    #[test]
    fn graphnode_roundtrip_preserves_oracle_receipt() {
        let mut node = make_node("receipted");
        node.oracle_receipt = Some(crate::graph::OracleReceipt {
            code: "dead_code".to_string(),
            line: 41,
            subject: Some("dead_fn".to_string()),
        });

        let bytes = bincode::serde::encode_to_vec(&node, bincode::config::standard())
            .expect("encode GraphNode");
        let (decoded, _): (GraphNode, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode GraphNode");
        assert_eq!(
            decoded.oracle_receipt, node.oracle_receipt,
            "oracle_receipt must survive the bincode round-trip byte-identical"
        );

        // Default path: make_node round-trips as None — never a spurious Some.
        let clean = make_node("clean-receipt");
        assert!(
            clean.oracle_receipt.is_none(),
            "make_node default oracle_receipt is None"
        );
    }

    /// SB2 (Leg H): a GraphNode carrying has_uncaptured_items=true survives the
    /// exact bincode encode/decode path graph_store uses, and the default
    /// make_node (false) never spuriously reads true. (The append-LAST bincode
    /// ordinal is guarded by the SCHEMA_VERSION pin test — a same-version
    /// round-trip like this one passes regardless of field order.)
    #[test]
    fn graphnode_roundtrip_preserves_has_uncaptured_items() {
        let mut node = make_node("uncap");
        node.has_uncaptured_items = true;

        let bytes = bincode::serde::encode_to_vec(&node, bincode::config::standard())
            .expect("encode GraphNode");
        let (decoded, _): (GraphNode, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode GraphNode");
        assert!(
            decoded.has_uncaptured_items,
            "has_uncaptured_items=true must survive the bincode round-trip"
        );

        // Default path: make_node round-trips as false — never a spurious true.
        let clean = make_node("clean-uncap");
        assert!(!clean.has_uncaptured_items, "make_node default is false");
    }

    /// SB2: a GraphNode carrying has_platform_cfg=true round-trips through the
    /// exact bincode path graph_store uses (positional/APPEND-LAST ordinal), and
    /// #[serde(default)] means a value absent in a decoded record reads false.
    #[test]
    fn graphnode_roundtrip_preserves_has_platform_cfg() {
        let mut node = make_node("plat");
        node.has_platform_cfg = true;

        let bytes = bincode::serde::encode_to_vec(&node, bincode::config::standard())
            .expect("encode GraphNode");
        let (decoded, _): (GraphNode, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode GraphNode");
        assert!(
            decoded.has_platform_cfg,
            "has_platform_cfg=true must survive the bincode round-trip"
        );

        // Default path: make_node (which sets has_platform_cfg=false via the
        // literal ripple) round-trips as false — never a spurious true.
        let clean = make_node("clean");
        assert!(!clean.has_platform_cfg, "make_node default is false");
    }

    // -----------------------------------------------------------------------
    // WU-0015 Leg 3a — SCHEMA_VERSION 4→5 bump + rustc_flagged_dead round-trip.
    // -----------------------------------------------------------------------

    /// SB2 (Leg 3a): a GraphNode carrying rustc_flagged_dead=true round-trips
    /// through the exact bincode path graph_store uses (positional/APPEND-LAST
    /// ordinal), and the default make_node (false) never spuriously reads true.
    /// Complements the `_is_five` SB1: the bump is honored AND the appended field
    /// actually persists positionally (no earlier field shifted).
    #[test]
    fn graphnode_roundtrip_preserves_rustc_flagged_dead() {
        let mut node = make_node("flagged");
        node.rustc_flagged_dead = true;

        let bytes = bincode::serde::encode_to_vec(&node, bincode::config::standard())
            .expect("encode GraphNode");
        let (decoded, _): (GraphNode, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode GraphNode");
        assert!(
            decoded.rustc_flagged_dead,
            "rustc_flagged_dead=true must survive the bincode round-trip"
        );
        // The earlier appended field is unshifted: has_platform_cfg still false.
        assert!(
            !decoded.has_platform_cfg,
            "the prior appended field must be unaffected by the new one"
        );

        // Default path: make_node sets rustc_flagged_dead=false → round-trips
        // false, never a spurious true.
        let clean = make_node("clean");
        assert!(
            !clean.rustc_flagged_dead,
            "make_node default rustc_flagged_dead is false"
        );
    }

    // -----------------------------------------------------------------------
    // WU-0015 Leg J — SCHEMA_VERSION 5→6 bump + entry_retain round-trip.
    // -----------------------------------------------------------------------

    /// SB2 (Leg J): a GraphNode carrying a non-empty `entry_retain` mask
    /// round-trips through the exact bincode path graph_store uses
    /// (positional/APPEND-LAST ordinal, `#[serde(transparent)]` u8), and the
    /// prior appended fields are unshifted. Complements the `_is_six` SB1: the
    /// bump is honored AND the appended field actually persists positionally.
    #[test]
    fn graphnode_roundtrip_preserves_entry_retain() {
        use crate::graph::EntryRetainFlags;

        let mut node = make_node("retained");
        node.entry_retain = EntryRetainFlags::from_bits(
            EntryRetainFlags::NO_MANGLE | EntryRetainFlags::ALLOW_DEAD_CODE,
        );

        let bytes = bincode::serde::encode_to_vec(&node, bincode::config::standard())
            .expect("encode GraphNode");
        let (decoded, _): (GraphNode, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode GraphNode");
        assert_eq!(
            decoded.entry_retain.bits(),
            EntryRetainFlags::NO_MANGLE | EntryRetainFlags::ALLOW_DEAD_CODE,
            "the entry_retain mask must survive the bincode round-trip"
        );
        assert!(decoded.entry_retain.is_entry_point());
        assert!(decoded.entry_retain.has_retain_attr());
        // The earlier appended fields are unshifted.
        assert!(
            !decoded.has_platform_cfg && !decoded.rustc_flagged_dead,
            "prior appended fields must be unaffected by the new one"
        );

        // Default path: make_node's empty mask round-trips empty, never spurious.
        let clean = make_node("clean");
        assert_eq!(
            clean.entry_retain.bits(),
            0,
            "make_node default entry_retain is the empty mask"
        );
    }

    /// SB4 (Leg 3a): a store stamped at a PRE-bump schema_version=4 (with a
    /// snapshot present) must trip the version gate under the current
    /// SCHEMA_VERSION and return `Ok(None)` — the clear-safe derived-cache path —
    /// NOT a hard decode error. `#[serde(default)]` on the appended fields is
    /// belt-and-suspenders; the version gate fires first regardless. Reindex
    /// repopulates. (Any stale stamp trips it; 4 stands in for "older than now".)
    #[tokio::test]
    async fn pre_bump_v4_snapshot_clears_not_hard_errors() {
        let db = open_temp_db();
        {
            let txn = db.begin_write().expect("begin write");
            {
                // A snapshot blob is present (any bytes) so `has_persisted_data`
                // is true and the version gate is reached.
                let mut snap = txn.open_table(GRAPH_SNAPSHOT).expect("open snapshot");
                snap.insert("latest", b"any-bytes".as_slice())
                    .expect("insert snap");
                // Stamp a PRE-bump version explicitly (4 != the current version).
                let mut meta = txn.open_table(GRAPH_META).expect("open meta");
                meta.insert("schema_version", 4u64).expect("stamp v4");
            }
            txn.commit().expect("commit");
        }

        let store = GraphStore::new(db);
        let loaded = store.load_snapshot().await;
        let err_msg = loaded.as_ref().err().map(std::string::ToString::to_string);
        assert!(
            loaded.is_ok(),
            "a v4-stamped store must NOT hard-error under v5 (got Err: {err_msg:?})"
        );
        assert!(
            loaded.expect("ok").is_none(),
            "the 4→5 version mismatch must discard the stale snapshot (Ok(None)) for a clean rebuild"
        );
    }
}

// ---------------------------------------------------------------------------
// ADR-0046 — classification-provenance stamp + three-axis currency falsifiers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod classification_provenance_tests {
    use super::*;

    fn open_temp_db() -> Arc<Database> {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_owned();
        std::mem::forget(tmp);
        Arc::new(Database::create(path).expect("create db"))
    }

    /// A deterministic synthetic identity keeps the currency controls
    /// independent from whichever build configuration runs the test.
    fn clean_stamp() -> ClassifiedBy {
        ClassifiedBy {
            build_identity: "0.1.0+abc1234".to_string(),
            indexer_identity: format!("sha256:{}", "a".repeat(64)),
            prover_config: current_prover_config(),
            timestamp: "2026-07-20T00:00:00Z".to_string(),
        }
    }

    // -- Falsifier #2: the stamp round-trips (mirror of the set_origin tests) --

    #[tokio::test]
    async fn classified_by_roundtrips() {
        let store = GraphStore::new(open_temp_db());

        assert!(
            store.classified_by_stamp().await.expect("read").is_none(),
            "a fresh store must report NO stamp — absence is None, never an error"
        );

        store.set_classified_by().await.expect("stamp");
        let got = store
            .classified_by_stamp()
            .await
            .expect("read")
            .expect("a stamped store must return its stamp");

        assert_eq!(got.build_identity, BUILD_IDENTITY);
        assert_eq!(got.indexer_identity, crate::INDEXER_IDENTITY);
        assert_eq!(got.prover_config, current_prover_config());
        assert!(
            !got.timestamp.is_empty(),
            "the stamp must record WHEN classification happened"
        );
    }

    /// The load-bearing D1 invariant: an absent stamp NEVER fails closed.
    /// Reading provenance from an unstamped store is an `Ok(None)`, not an
    /// error, and must not disturb the store.
    #[tokio::test]
    async fn absent_stamp_degrades_and_never_refuses() {
        let store = GraphStore::new(open_temp_db());
        for _ in 0..3 {
            assert!(
                store
                    .classified_by_stamp()
                    .await
                    .expect("must not error")
                    .is_none(),
                "an unstamped store must read as None, repeatedly, without error"
            );
        }
    }

    /// The sync sibling writes the same shape as the async one — the two must
    /// not drift, since `reload_reclassify_save` uses the sync form.
    #[tokio::test]
    async fn sync_and_async_stamps_agree() {
        let store = GraphStore::new(open_temp_db());
        store.set_classified_by_sync().expect("sync stamp");
        let via_sync = store
            .classified_by_stamp()
            .await
            .expect("read")
            .expect("stamp");

        let store2 = GraphStore::new(open_temp_db());
        store2.set_classified_by().await.expect("async stamp");
        let via_async = store2
            .classified_by_stamp()
            .await
            .expect("read")
            .expect("stamp");

        assert_eq!(via_sync.build_identity, via_async.build_identity);
        assert_eq!(via_sync.indexer_identity, via_async.indexer_identity);
        assert_eq!(via_sync.prover_config, via_async.prover_config);
    }

    /// The PROVER axis is COMPARED, not merely recorded.
    ///
    /// It was written, rendered, round-tripped and tested — and never consulted
    /// by the evaluator. A dead field is a symptom: the record had been bought
    /// without the guard it was bought for.
    #[test]
    fn prover_config_mismatch_is_actually_compared() {
        let cur = clean_stamp();
        let stamped = ClassifiedBy {
            // Same binary, same index config — ONLY the prover config differs,
            // so nothing else can account for a failure here.
            prover_config: "code-intel=0".to_string(),
            ..clean_stamp()
        };
        let failures = eval(Some(&stamped), &cur, true, Some(false));
        assert!(
            failures
                .iter()
                .any(|f| matches!(f, CurrencyFailure::ProverConfigMismatch { .. })),
            "classes produced by a binary compiled WITHOUT the code-intel \
             classifier are not comparable to this build's, and a matching git \
             SHA does not make them so. Got: {failures:?}"
        );
    }

    // ------------------------------------------------------------------
    // Falsifier #7 — the three-axis currency detector, EVERY form
    // ------------------------------------------------------------------
    //
    // ADR-0046 rev-3 A2-bis: a single-instance break cannot certify this gate.
    // What rots is COVERAGE OF FORMS — one planted case passes green while the
    // other forms go uncovered. So every form of the UNKNOWN condition is
    // asserted here, PLUS the negative control.
    //
    // A2-quater / A2-quinquies: #7 proves a DETECTOR, so it drives the SAME
    // callable the shipped gate calls (`evaluate_classification_currency`)
    // rather than a reimplementation. Its EXPECTED VALUES come from the
    // ADR-0046 spec, not from the detector's own output.

    fn eval(
        stamp: Option<&ClassifiedBy>,
        current: &ClassifiedBy,
        classification_authority_available: bool,
        index_stale: Option<bool>,
    ) -> Vec<CurrencyFailure> {
        evaluate_classification_currency(CurrencyInputs {
            stamp,
            current,
            classification_authority_available,
            index_stale,
        })
    }

    /// THE NEGATIVE CONTROL — and it is not optional. A gate that fires on
    /// healthy stores gets suppressed, and a suppressed gate guards nothing.
    #[test]
    fn currency_form0_negative_control_fully_current_store_is_clean() {
        let cur = clean_stamp();
        let failures = eval(Some(&cur), &cur, true, Some(false));
        assert!(
            failures.is_empty(),
            "a fully current store must certify CLEAN — otherwise the gate \
             fires on healthy repos and gets turned off. Got: {failures:?}"
        );
    }

    #[test]
    fn currency_form1_classification_authority_unavailable() {
        let cur = clean_stamp();
        let failures = eval(Some(&cur), &cur, false, Some(false));
        assert!(
            failures.contains(&CurrencyFailure::ClassificationAuthorityUnavailable),
            "a generation without valid scoped evidence must fail the \
             ClassificationAuthorityUnavailable axis. Got: {failures:?}"
        );
    }

    #[test]
    fn currency_form2_stamp_absent() {
        let cur = clean_stamp();
        let failures = eval(None, &cur, true, Some(false));
        assert!(
            failures.contains(&CurrencyFailure::StampAbsent),
            "classes with no stamp must fail the StampAbsent axis. Got: {failures:?}"
        );
    }

    #[test]
    fn currency_form3_classifier_content_mismatch() {
        let cur = clean_stamp();
        let stamped = ClassifiedBy {
            indexer_identity: format!("sha256:{}", "b".repeat(64)),
            ..clean_stamp()
        };
        let failures = eval(Some(&stamped), &cur, true, Some(false));
        assert!(
            failures
                .iter()
                .any(|f| matches!(f, CurrencyFailure::ClassifierIdentityMismatch { .. })),
            "different classifier content must fail the machine-authority axis. Got: {failures:?}"
        );
    }

    /// ADR-0046 rev-3 A2 — the sibling fail-open the rev-2 review left standing:
    /// a store whose stamp MATCHES but whose sources moved on. The current #7
    /// without this case would pass it green.
    #[test]
    fn currency_form5_index_stale_under_a_matching_stamp() {
        let cur = clean_stamp();
        let failures = eval(Some(&cur), &cur, true, Some(true));
        assert!(
            failures.contains(&CurrencyFailure::IndexStale),
            "a MATCHING stamp over a stale index must still fail — the classes \
             no longer describe the code regardless of who computed them. This \
             is the A2 fail-open. Got: {failures:?}"
        );
    }

    /// Dirty Git provenance is informational when exact classifier content is
    /// recorded independently.
    #[test]
    fn currency_form6_dirty_build_certifies_with_exact_classifier_identity() {
        let dirty = ClassifiedBy {
            build_identity: "0.1.0+abc1234+dirty".to_string(),
            ..clean_stamp()
        };
        assert!(dirty.is_dirty(), "the +dirty suffix must be detected");

        let failures = eval(Some(&dirty), &dirty, true, Some(false));
        assert!(
            failures.is_empty(),
            "exact classifier content must certify independently of dirty Git provenance: {failures:?}"
        );
        assert!(
            dirty.render().contains("approximate"),
            "dirty human provenance must still render honestly"
        );
    }

    /// **THE BLOCKER FALSIFIER.** `+nogit` must NEVER certify — including
    /// (especially) when a `+nogit`-stamped store is read by a `+nogit` binary.
    ///
    /// `build.rs` degrades to `{CARGO_PKG_VERSION}+nogit` when git cannot
    /// answer. Every crate in this workspace is pinned `0.1.0` statically, so
    /// that identity is `0.1.0+nogit` for EVERY nogit build of EVERY revision —
    /// it is verbatim the `CARGO_PKG_VERSION`-only identity ADR-0046 REJECTED
    /// on measured grounds ("a provenance stamp that cannot fire is vacuous by
    /// construction"). A stamp that matches itself across unrelated builds is
    /// not provenance; it is a green light with no sensor behind it.
    ///
    /// Exact classifier content also works for source-tarball builds where Git
    /// provenance is unavailable.
    #[test]
    fn currency_form7_nogit_build_certifies_with_exact_classifier_identity() {
        let nogit = ClassifiedBy {
            build_identity: "0.1.0+nogit".to_string(),
            ..clean_stamp()
        };
        assert_eq!(
            nogit.approximation(),
            Some(ApproximateIdentity::NoGit),
            "a `+nogit` identity must be recognised as APPROXIMATE"
        );

        let failures = eval(Some(&nogit), &nogit, true, Some(false));
        assert!(
            failures.is_empty(),
            "exact classifier content must certify independently of missing Git provenance: {failures:?}"
        );
        assert!(
            nogit.render().contains("approximate"),
            "a nogit stamp must render as approximate, never as a clean match"
        );
    }

    /// Every failure NAMES its axis. A gate verdict that says only "UNKNOWN"
    /// sends its reader hunting (ADR-0046 rev-3 A2).
    #[test]
    fn every_currency_failure_names_its_axis_and_a_remedy() {
        let cases = vec![
            CurrencyFailure::ClassificationAuthorityUnavailable,
            CurrencyFailure::StampAbsent,
            CurrencyFailure::ClassifierIdentityMismatch {
                stamped: "a".into(),
                current: "b".into(),
            },
            CurrencyFailure::ClassifierIdentityUnavailable {
                identity: "unavailable".into(),
            },
            CurrencyFailure::ProverConfigMismatch {
                stamped: "a".into(),
                current: "b".into(),
            },
            CurrencyFailure::IndexStale,
        ];
        for c in cases {
            let d = c.describe();
            assert!(!d.is_empty(), "{c:?} must describe itself");
            assert!(
                d.contains("h00ligan index"),
                "{c:?} must name the one immutable-publication remedy, not just \
                 a complaint. Got: {d}"
            );
            assert!(
                !d.contains("reclassify"),
                "{c:?} must not advertise the retired in-place writer. Got: {d}"
            );
            if c == CurrencyFailure::IndexStale {
                assert!(
                    d.contains("source or project-input content") && !d.contains("newer"),
                    "exact content freshness must not be described as an mtime comparison: {d}"
                );
            }
        }
    }

    /// ADR-0046 falsifier **#6** — the shape-B negative: a `save_snapshot` that
    /// does NOT stamp must leave the PRIOR stamp intact, and the retained
    /// stamp's classes must still be the ones it describes (mechanism AND
    /// truth, not mechanism alone).
    ///
    /// This is why the stamp is written beside `set_origin` rather than folded
    /// into `save_snapshot`. A persistence-only caller
    /// (which has no classification authority)
    /// persists WITHOUT reclassifying — it saves Hebbian weight drift onto a
    /// graph that was classified by whatever indexer produced it, and it has no
    /// workspace root to reclassify against. Stamping there would attribute
    /// those classes to a binary that never classified them: a FRESH LIE, worse
    /// than the current silence.
    ///
    /// # The aliasing invariant this rests on (documented, not assumed)
    ///
    /// In-process, the agent-reindex path mutates the SAME `Arc<RwLock>` graph
    /// the persistence-only save re-saves, so a later save after reindex persists
    /// the FRESH classes under the FRESH stamp — the pair stays consistent.
    /// The CROSS-process residual (another process's non-stamping save
    /// overwriting a freshly-stamped shared store) is NOT closed by this and is
    /// disclosed in ADR-0046 Consequences rather than hidden.
    #[tokio::test]
    async fn save_snapshot_without_stamping_retains_the_prior_stamp_and_its_classes() {
        use crate::graph::KnowledgeGraph;

        let store = GraphStore::new(open_temp_db());

        // A classifying producer: classes + a stamp.
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(crate::graph::GraphNode {
                memory_id: uuid::Uuid::new_v4(),
                symbol_name: "alpha".to_string(),
                kind: "function".to_string(),
                file_path: "src/alpha.rs".to_string(),
                content_hash: "hash_alpha".to_string(),
                signature: String::new(),
                reachability_class: crate::reachability::ReachabilityClass::Wired,
                line_start: None,
                line_end: None,
                has_body: None,
                visibility: String::new(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add");
        store.save_snapshot(&graph).await.expect("save");
        let planted = clean_stamp();
        store
            .set_classified_by_stamp(&planted)
            .await
            .expect("stamp");

        // The persistence-only shape: save the SAME graph again, with NO stamp call.
        store.save_snapshot(&graph).await.expect("resave");

        let after = store
            .classified_by_stamp()
            .await
            .expect("read")
            .expect("the prior stamp must SURVIVE a non-stamping save");
        assert_eq!(
            after, planted,
            "a save_snapshot that does not classify must not disturb the stamp \
             — neither erasing it (losing provenance) nor rewriting it (a lie \
             attributing classes to a binary that never classified them)"
        );

        // ...and the classes it describes are still the ones on disk.
        let reloaded = store
            .load_snapshot()
            .await
            .expect("load")
            .expect("snapshot present");
        assert_eq!(
            reloaded.all_nodes()[0].reachability_class,
            crate::reachability::ReachabilityClass::Wired,
            "the retained stamp must still describe the persisted classes — a \
             stamp that survives while its classes change underneath it is the \
             lie this falsifier exists to exclude"
        );
    }

    /// Forms COMPOUND: several axes can fail at once and the gate must report
    /// all of them, not stop at the first. A reader who fixes only the axis
    /// they were told about would otherwise loop.
    #[test]
    fn multiple_failing_axes_are_all_reported() {
        let cur = clean_stamp();
        let stamped = ClassifiedBy {
            indexer_identity: format!("sha256:{}", "b".repeat(64)),
            ..clean_stamp()
        };
        let failures = eval(Some(&stamped), &cur, true, Some(true));
        assert!(
            failures.len() >= 2,
            "classifier-content mismatch + staleness must BOTH be reported. Got: {failures:?}"
        );
    }
}
