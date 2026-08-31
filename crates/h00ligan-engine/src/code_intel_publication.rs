//! Immutable code-intelligence generation publication.
//!
//! Writers build one private `generation.redb`, close and durably synchronize
//! it, move its generation directory into the immutable population, and only
//! then replace one of two checksummed head records. Readers never scan or
//! adopt unreferenced generations: they validate the newest referenced
//! generation and may fall back to the other head when the newest generation
//! is corrupt or incomplete.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::code_intel_callable_liveness::assess_callable_liveness_capability;
use crate::code_intel_calls::{
    assess_calls_capability, validate_callable_liveness_payload_structural_join,
    validate_calls_payload_structural_join,
};
use crate::code_intel_domain::{
    CapabilityCoverage, CapabilityCoverageStatus, CapabilityReceipt, CapabilityScope,
    CapabilityStatus, DocumentMembershipKind, GenerationId, ProjectInventory, RepositoryId,
    assess_language_capability,
};
use crate::code_intel_inventory::{
    canonical_project_inventory_bytes, parse_project_inventory_bytes,
};
use crate::code_intel_payload::{
    CanonicalProviderPayload, CapabilityReceiptId, NormalizedProviderPayload, ProviderPayload,
    ProviderPayloadCanonicalizationTimings, ProviderPayloadDescriptor, ProviderPayloadId,
    canonicalize_provider_payload_profiled, capability_receipt_id,
    parse_canonical_provider_payload_bytes,
};
use crate::code_intel_semantic_cache::{
    load_cached_canonical_semantic_bases, persist_cached_canonical_semantic_bases,
};
use crate::code_intel_semantic_provider_registry::SemanticProviderRegistry;
use crate::graph::KnowledgeGraph;
use crate::graph_store::{
    BoundGraphPublicationProof, GraphGenerationMetadata, GraphPublicationProof, GraphStore,
    ValidatedGraphContent,
};
use crate::index_pipeline::{
    IncrementalPipelineBasis, IndexConfig, IndexPhaseTiming, IndexPipeline, IndexPipelineError,
    IndexPipelineRuntime, IndexProgressPhase, IndexProgressState, IndexReport, IndexRunOutcome,
    IndexTimingAggregation, emit_progress, structural_receipts_match_records,
};
use crate::index_state::{
    BoundIndexStatePublicationProof, IncrementalIndexBasis, IndexMetadata, IndexState,
    IndexStatePublicationProof, IndexedSourceSnapshot, ValidatedIndexStateContent,
};
use crate::reachability::ReachabilityEvidence;
use crate::scip_normalizer::CanonicalSemanticBasis;

pub use crate::project_binding::IMMUTABLE_PUBLICATION_DIRECTORY as PUBLICATION_DIRECTORY;
pub const GENERATION_DATABASE_FILE: &str = "generation.redb";

const GENERATIONS_DIRECTORY: &str = "generations";
const WRITER_LOCK_FILE: &str = "publisher.lock";
const REPOSITORY_FILE: &str = "repository.json";
const HEAD_FILES: [&str; 2] = ["head-0.json", "head-1.json"];
const REPOSITORY_SCHEMA: &str = "h00/code-intel/repository/v1";
// The generation envelope versions every nested persisted contract. Bump it
// whenever an embedded authority document changes incompatibly so readers can
// distinguish authenticated obsolete derived state from damaged control data.
const GENERATION_SCHEMA: &str = "h00/code-intel/generation/v9";
const HEAD_SCHEMA: &str = "h00/code-intel/head/v4";
const MAX_CONTROL_FILE_BYTES: u64 = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PROJECT_INVENTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROVIDER_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROVIDER_PAYLOAD_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PROVIDER_PAYLOADS: usize = 4096;

const PUBLICATION_META: TableDefinition<&str, &[u8]> = TableDefinition::new("h00_publication_meta");
const PROJECT_INVENTORY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("h00_project_inventory");
const PROVIDER_PAYLOADS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("h00_provider_payloads");
const PROVIDER_WORKSPACE_PREFIX: &str = ".h00-provider-";
const MANIFEST_KEY: &str = "manifest";
const PROJECT_INVENTORY_KEY: &str = "inventory";

#[cfg(test)]
thread_local! {
    /// Exact number of full immutable-generation validations performed by one
    /// publication-path falsifier.
    static GENERATIONS_VALIDATED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_generations_validated() {
    GENERATIONS_VALIDATED.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn generations_validated() -> usize {
    GENERATIONS_VALIDATED.with(std::cell::Cell::get)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial: Option<u32>,
    #[cfg(windows)]
    file_index: Option<u64>,
}

impl DirectoryIdentity {
    fn from_directory(directory: &Dir) -> std::io::Result<Self> {
        let metadata = directory.try_clone()?.into_std_file().metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            Ok(Self {
                volume_serial: metadata.volume_serial_number(),
                file_index: metadata.file_index(),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = metadata;
            Ok(Self {})
        }
    }
}

/// An open capability for the exact graph directory admitted before indexing.
///
/// The lexical path is retained only for diagnostics and replacement checks.
/// Publication effects are performed relative to the open directory so a
/// later rename or symlink substitution cannot retarget them.
pub struct PreparedPublicationRoot {
    directory: Dir,
    path: PathBuf,
    identity: DirectoryIdentity,
}

impl std::fmt::Debug for PreparedPublicationRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedPublicationRoot")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl PreparedPublicationRoot {
    /// Capture the exact directory selected by project binding.
    pub fn capture(path: &Path) -> Result<Self, PublicationError> {
        require_directory(path, "prepared graph directory (not a symlink)")?;
        let canonical = canonical_directory(path, "canonicalize prepared graph directory")?;
        let directory =
            Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(|source| {
                PublicationError::Io {
                    operation: "open prepared graph directory capability",
                    path: canonical.clone(),
                    source,
                }
            })?;
        let identity = DirectoryIdentity::from_directory(&directory).map_err(|source| {
            PublicationError::Io {
                operation: "identify prepared graph directory capability",
                path: canonical.clone(),
                source,
            }
        })?;
        Ok(Self {
            directory,
            path: canonical,
            identity,
        })
    }

    fn verify_path_binding(&self) -> Result<(), PublicationError> {
        let current = match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                Dir::open_ambient_dir(&self.path, ambient_authority()).map_err(|source| {
                    PublicationError::Io {
                        operation: "reopen prepared graph directory for identity check",
                        path: self.path.clone(),
                        source,
                    }
                })?
            }
            Ok(_) | Err(_) => {
                return Err(PublicationError::PathBindingChanged {
                    path: self.path.clone(),
                });
            }
        };
        let current_identity =
            DirectoryIdentity::from_directory(&current).map_err(|source| PublicationError::Io {
                operation: "identify current graph directory binding",
                path: self.path.clone(),
                source,
            })?;
        if current_identity != self.identity {
            return Err(PublicationError::PathBindingChanged {
                path: self.path.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationManifest {
    pub schema_version: String,
    pub generation_id: GenerationId,
    pub repository_id: RepositoryId,
    pub parent_generation_id: Option<GenerationId>,
    pub source_revision: Option<String>,
    /// BLAKE3 of the closed database before publication metadata was added.
    pub payload_blake3: String,
    /// Logical proof for every graph population consumers hydrate from the
    /// opened immutable database.
    pub graph_publication_proof: GraphPublicationProof,
    /// Logical proof for every index-state population consumers hydrate or
    /// reuse from the opened immutable database.
    pub index_state_publication_proof: IndexStatePublicationProof,
    /// SHA-256 of the canonical project-inventory document stored in the same
    /// immutable database.
    pub project_inventory_sha256: String,
    pub receipts: Vec<CapabilityReceipt>,
    pub provider_payloads: Vec<ProviderPayloadDescriptor>,
}

/// Decoded product state authenticated against one immutable manifest through
/// the exact redb handle supplied by the caller.
///
/// Consumers must use these returned values rather than validating the handle
/// and then independently rereading the same tables.
pub struct ValidatedOpenGeneration {
    pub graph: KnowledgeGraph,
    pub reachability_evidence:
        Result<Option<ReachabilityEvidence>, crate::graph_store::GraphStoreError>,
    pub origin: PathBuf,
    pub generation_metadata: GraphGenerationMetadata,
    pub index_metadata: Option<IndexMetadata>,
    pub indexed_sources: IndexedSourceSnapshot,
    pub(crate) incremental_basis: IncrementalIndexBasis,
}

impl std::fmt::Debug for ValidatedOpenGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedOpenGeneration")
            .field("graph_nodes", &self.graph.node_count())
            .field("graph_edges", &self.graph.edge_count())
            .field(
                "reachability_evidence",
                &match &self.reachability_evidence {
                    Ok(Some(_)) => "available",
                    Ok(None) => "absent",
                    Err(_) => "invalid",
                },
            )
            .field("origin", &self.origin)
            .field("generation_metadata", &self.generation_metadata)
            .field("index_metadata", &self.index_metadata)
            .field("indexed_files", &self.indexed_sources.files().len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationDraft {
    pub source_revision: Option<String>,
    pub project_inventory: ProjectInventory,
    pub receipts: Vec<CapabilityReceipt>,
    pub provider_payloads: Vec<ProviderPayload>,
}

enum ProviderPayloadCandidates {
    Unvalidated(Vec<ProviderPayload>),
    Canonical(Vec<CanonicalProviderPayload>),
}

struct GenerationCandidateDraft {
    source_revision: Option<String>,
    project_inventory: ProjectInventory,
    receipts: Vec<CapabilityReceipt>,
    provider_payloads: ProviderPayloadCandidates,
}

impl From<GenerationDraft> for GenerationCandidateDraft {
    fn from(draft: GenerationDraft) -> Self {
        Self {
            source_revision: draft.source_revision,
            project_inventory: draft.project_inventory,
            receipts: draft.receipts,
            provider_payloads: ProviderPayloadCandidates::Unvalidated(draft.provider_payloads),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationHeadBody {
    pub schema_version: String,
    pub sequence: u64,
    pub repository_id: RepositoryId,
    pub generation_id: GenerationId,
    pub database_blake3: String,
    pub manifest_sha256: String,
    pub receipt_set_sha256: String,
    pub provider_payload_set_sha256: String,
    pub previous_generation_id: Option<GenerationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationHead {
    pub body: PublicationHeadBody,
    pub digest: String,
}

/// Opaque change-detection token for bounded publication control state.
///
/// Equality means only that the validated repository record and two bounded
/// head controls have not changed. It does not validate, open, or authorize a
/// referenced generation payload; callers must use [`resolve_generation`] for
/// semantic authority whenever this token changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicationControlToken(String);

impl PublicationControlToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque metadata witness for the bounded publication-control population.
///
/// This is deliberately weaker than [`PublicationControlToken`]: equality
/// means only that filesystem metadata for the graph directory, publication
/// directory, repository record, and two head slots appears unchanged. It is
/// a low-cost polling hint for long-lived processes, never publication or
/// query authority. A changed witness must be corroborated by a validated
/// control-token read, and periodic full reconciliation remains responsible
/// for adversarial same-metadata mutation or platform metadata limitations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationControlWitness {
    graph_directory: PublicationPathWitness,
    publication_directory: PublicationPathWitness,
    repository: PublicationPathWitness,
    heads: [PublicationPathWitness; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationPathKind {
    RegularFile,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicationPathWitness {
    Missing,
    Unreadable {
        kind: std::io::ErrorKind,
        raw_os_error: Option<i32>,
    },
    Present {
        kind: PublicationPathKind,
        len: u64,
        modified: Option<SystemTime>,
        #[cfg(unix)]
        device: u64,
        #[cfg(unix)]
        inode: u64,
        #[cfg(unix)]
        change_time_seconds: i64,
        #[cfg(unix)]
        change_time_nanoseconds: i64,
        #[cfg(windows)]
        volume_serial: Option<u32>,
        #[cfg(windows)]
        file_index: Option<u64>,
    },
}

impl PublicationPathWitness {
    fn capture(path: &Path) -> Self {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Self::Missing,
            Err(error) => {
                return Self::Unreadable {
                    kind: error.kind(),
                    raw_os_error: error.raw_os_error(),
                };
            }
        };
        let file_type = metadata.file_type();
        let kind = if file_type.is_file() {
            PublicationPathKind::RegularFile
        } else if file_type.is_dir() {
            PublicationPathKind::Directory
        } else if file_type.is_symlink() {
            PublicationPathKind::Symlink
        } else {
            PublicationPathKind::Other
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Self::Present {
                kind,
                len: metadata.len(),
                modified: metadata.modified().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
                change_time_seconds: metadata.ctime(),
                change_time_nanoseconds: metadata.ctime_nsec(),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            Self::Present {
                kind,
                len: metadata.len(),
                modified: metadata.modified().ok(),
                volume_serial: metadata.volume_serial_number(),
                file_index: metadata.file_index(),
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Self::Present {
                kind,
                len: metadata.len(),
                modified: metadata.modified().ok(),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RepositoryRecordBody {
    schema_version: String,
    repository_id: RepositoryId,
    root_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RepositoryRecord {
    body: RepositoryRecordBody,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGeneration {
    pub slot: usize,
    pub head: PublicationHead,
    pub manifest: GenerationManifest,
    pub project_inventory: Arc<ProjectInventory>,
    pub provider_payloads: Vec<NormalizedProviderPayload>,
    pub database_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedGeneration {
    pub slot: usize,
    pub head: PublicationHead,
    pub manifest: GenerationManifest,
    pub project_inventory: Arc<ProjectInventory>,
    pub provider_payloads: Vec<NormalizedProviderPayload>,
    pub database_path: PathBuf,
    pub maintenance: PublicationMaintenance,
}

/// Bounded-storage maintenance performed under the publication writer lock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationMaintenance {
    pub removed: Vec<String>,
    pub warnings: Vec<String>,
}

/// Explicit writer admission for a fresh immutable publication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PublicationRecovery {
    /// Preserve every existing authority boundary and refuse missing, damaged,
    /// conflicting, or foreign publication controls without mutation.
    #[default]
    Strict,
    /// Build a complete replacement generation and, only after that generation
    /// validates, rebind repository identity and repair both head slots.
    RecoverAndRebind,
}

/// Whether a new current generation may remove capability authority that the
/// current generation provides completely.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CapabilityFloorPolicy {
    /// Refuse the atomic head switch when the candidate would drop a complete
    /// capability for any language.
    #[default]
    Preserve,
    /// Permit an explicit, operator-visible capability downgrade.
    AllowDowngrade,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CapabilityFloorEntry {
    capability_id: String,
    configuration_id: String,
    language_id: String,
}

impl std::fmt::Display for CapabilityFloorEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.capability_id, self.configuration_id, self.language_id
        )
    }
}

fn complete_capability_floor(
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> BTreeSet<CapabilityFloorEntry> {
    let languages = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
        .map(|membership| membership.language_id.clone())
        .collect::<BTreeSet<_>>();
    let capability_configurations = receipts
        .iter()
        .map(|receipt| {
            (
                receipt.capability_id.clone(),
                receipt.scope.configuration_id().0.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut floor = BTreeSet::new();
    for (capability_id, configuration_id) in capability_configurations {
        let coverage = assess_language_capability(
            receipts,
            inventory,
            &capability_id,
            &configuration_id,
            languages.iter().cloned(),
        );
        floor.extend(
            coverage
                .languages
                .into_iter()
                .filter(|language| language.status == CapabilityCoverageStatus::Complete)
                .map(|language| CapabilityFloorEntry {
                    capability_id: capability_id.clone(),
                    configuration_id: configuration_id.clone(),
                    language_id: language.language_id.0,
                }),
        );
    }
    floor
}

fn enforce_capability_floor(
    current: Option<&ResolvedGeneration>,
    candidate_receipts: &[CapabilityReceipt],
    candidate_inventory: &ProjectInventory,
    policy: CapabilityFloorPolicy,
) -> Result<(), PublicationError> {
    let Some(current) = current.filter(|_| policy == CapabilityFloorPolicy::Preserve) else {
        return Ok(());
    };
    let current_floor =
        complete_capability_floor(&current.manifest.receipts, &current.project_inventory);
    let candidate_floor = complete_capability_floor(candidate_receipts, candidate_inventory);
    let lost = current_floor
        .difference(&candidate_floor)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if lost.is_empty() {
        Ok(())
    } else {
        Err(PublicationError::CapabilityDowngrade { lost })
    }
}

/// Telemetry and immutable publication produced by one fresh indexing run.
#[derive(Debug)]
pub struct PublishedIndexGeneration {
    pub telemetry: IndexReport,
    pub publication: PublishedGeneration,
    /// Compact, generation-authoritative Calls assessment computed while the
    /// exact graph, receipts, provider payloads, and inventory are co-resident.
    /// Terminal operation receipts retain this summary instead of retaining
    /// the potentially very large provider payload population.
    pub calls_authority: CapabilityCoverage,
    /// Compact assessment of the separately typed whole-program callable
    /// liveness evidence. This never substitutes for or manufactures Calls.
    pub callable_liveness_authority: CapabilityCoverage,
    /// Bounded detail for the durable-publication phase. Reused generations
    /// have no publication steps because no writer or head transition ran.
    pub publication_timings: Vec<PublicationStepTiming>,
}

/// Process-local acceleration state bound to one exact, already published
/// immutable head. It is accepted only after ordinary writer admission has
/// independently validated that same head; it never replaces on-disk
/// authority and may be dropped at any time.
#[derive(Clone)]
pub(crate) struct LiveGenerationAuthority {
    resolved: Arc<ResolvedGeneration>,
    control_token: PublicationControlToken,
}

pub(crate) struct LiveGenerationBasis {
    head: PublicationHeadBody,
    authority: Option<LiveGenerationAuthority>,
    source: IncrementalIndexBasis,
    graph: KnowledgeGraph,
    semantic_bases: Vec<CanonicalSemanticBasis>,
    project_inventory: Arc<ProjectInventory>,
}

impl LiveGenerationBasis {
    pub(crate) fn from_resolved(
        resolved: &ResolvedGeneration,
        control_token: PublicationControlToken,
        source: IncrementalIndexBasis,
        graph: KnowledgeGraph,
        semantic_bases: Vec<CanonicalSemanticBasis>,
    ) -> Self {
        Self {
            head: resolved.head.body.clone(),
            authority: Some(LiveGenerationAuthority {
                resolved: Arc::new(resolved.clone()),
                control_token,
            }),
            source,
            graph,
            semantic_bases,
            project_inventory: Arc::clone(&resolved.project_inventory),
        }
    }

    pub(crate) fn matches_published(&self, published: &PublishedGeneration) -> bool {
        self.head == published.head.body
    }

    pub(crate) fn authority_snapshot(&self) -> Option<LiveGenerationAuthority> {
        self.authority.clone()
    }

    #[cfg(test)]
    pub(crate) fn source_symbol_name_allocation(&self, symbol_name: &str) -> Option<usize> {
        self.graph
            .all_nodes()
            .into_iter()
            .find(|node| node.symbol_name == symbol_name)
            .map(|node| node.symbol_name.as_ptr() as usize)
    }

    #[cfg(test)]
    pub(crate) fn project_inventory_allocation(&self) -> usize {
        Arc::as_ptr(&self.project_inventory) as usize
    }
}

/// One non-overlapping durable-publication subphase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationStepTiming {
    pub label: &'static str,
    pub duration: Duration,
    pub work_items: u64,
    pub work_unit: &'static str,
}

/// One mutually exclusive component of immutable-generation resolution.
///
/// This is intentionally narrower than publication telemetry: it attributes
/// the durable-to-live authority boundary so long-lived callers can decide
/// whether retaining already-validated parsed state is worthwhile without
/// weakening the on-disk contract first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenerationResolutionStepTiming {
    pub(crate) label: &'static str,
    pub(crate) duration: Duration,
    pub(crate) work_items: u64,
    pub(crate) work_unit: &'static str,
}

fn record_generation_resolution_step(
    timings: Option<&mut Vec<GenerationResolutionStepTiming>>,
    label: &'static str,
    duration: Duration,
    work_items: u64,
    work_unit: &'static str,
) {
    let Some(timings) = timings else {
        return;
    };
    if let Some(existing) = timings.iter_mut().find(|timing| timing.label == label) {
        debug_assert_eq!(existing.work_unit, work_unit);
        existing.duration = existing.duration.saturating_add(duration);
        existing.work_items = existing.work_items.saturating_add(work_items);
    } else {
        timings.push(GenerationResolutionStepTiming {
            label,
            duration,
            work_items,
            work_unit,
        });
    }
}

fn measure_generation_resolution_step<T>(
    timings: Option<&mut Vec<GenerationResolutionStepTiming>>,
    label: &'static str,
    work_unit: &'static str,
    action: impl FnOnce() -> Result<(T, u64), PublicationError>,
) -> Result<T, PublicationError> {
    let started = Instant::now();
    let result = action();
    let work_items = result.as_ref().map_or(0, |(_, work_items)| *work_items);
    record_generation_resolution_step(timings, label, started.elapsed(), work_items, work_unit);
    result.map(|(value, _)| value)
}

fn record_publication_step(
    timings: &mut Vec<PublicationStepTiming>,
    label: &'static str,
    started: Instant,
    work_items: u64,
    work_unit: &'static str,
) {
    record_publication_duration(timings, label, started.elapsed(), work_items, work_unit);
}

fn record_publication_duration(
    timings: &mut Vec<PublicationStepTiming>,
    label: &'static str,
    duration: Duration,
    work_items: u64,
    work_unit: &'static str,
) {
    timings.push(PublicationStepTiming {
        label,
        duration,
        work_items,
        work_unit,
    });
}

struct PreparedProviderPayload {
    payload: NormalizedProviderPayload,
    descriptor: ProviderPayloadDescriptor,
    bytes: Vec<u8>,
}

struct PreparedProviderPayloadBatch {
    payloads: Vec<PreparedProviderPayload>,
    receipt_scope_validation: Duration,
    canonicalization: ProviderPayloadCanonicalizationTimings,
    inventory_coverage_validation: Duration,
    descriptor_linkage_validation: Duration,
}

/// A private generation database. Callers may clone the database handle for
/// GraphStore/IndexState work, but every clone must be dropped before finish.
pub struct GenerationWorkspace {
    repository_id: RepositoryId,
    generations_directory: PathBuf,
    staging_directory: PathBuf,
    staging_name: String,
    staging_capability: Dir,
    staging_identity: DirectoryIdentity,
    database: Arc<Database>,
}

impl GenerationWorkspace {
    pub fn database(&self) -> Arc<Database> {
        Arc::clone(&self.database)
    }

    pub fn staging_directory(&self) -> &Path {
        &self.staging_directory
    }
}

/// Process-independent single-writer authority for one publication root.
pub struct SemanticPublisher {
    publication_root: PreparedPublicationRoot,
    publication_directory: PathBuf,
    publication_capability: Dir,
    generations_directory: PathBuf,
    generations_capability: Dir,
    repository_root: PathBuf,
    repository: RepositoryRecord,
    recovery: PublicationRecovery,
    repository_needs_commit: bool,
    /// Current immutable generation validated while acquiring the writer lock.
    ///
    /// Final publication may reuse the parsed authority only after it rechecks
    /// the locked head and exact database digest. Head drift falls back to a
    /// fresh full resolution; byte drift fails closed.
    admitted_current: Option<ResolvedGeneration>,
    lock_file: File,
}

impl SemanticPublisher {
    pub fn acquire(
        graph_directory: &Path,
        repository_root: &Path,
    ) -> Result<Self, PublicationError> {
        Self::acquire_with_recovery(
            graph_directory,
            repository_root,
            PublicationRecovery::Strict,
        )
    }

    pub fn acquire_with_recovery(
        graph_directory: &Path,
        repository_root: &Path,
        recovery: PublicationRecovery,
    ) -> Result<Self, PublicationError> {
        let publication_root = PreparedPublicationRoot::capture(graph_directory)?;
        Self::acquire_prepared(publication_root, repository_root, recovery, None)
    }

    fn acquire_prepared(
        publication_root: PreparedPublicationRoot,
        repository_root: &Path,
        recovery: PublicationRecovery,
        prevalidated_current: Option<ResolvedGeneration>,
    ) -> Result<Self, PublicationError> {
        publication_root.verify_path_binding()?;
        let canonical_graph = publication_root.path.clone();
        let canonical_root = canonical_directory(repository_root, "canonicalize repository root")?;
        let publication_directory = canonical_graph.join(PUBLICATION_DIRECTORY);
        let publication_capability = ensure_cap_directory(
            &publication_root.directory,
            PUBLICATION_DIRECTORY,
            &publication_directory,
            "create descriptor-relative publication directory",
        )?;

        let lock_path = publication_directory.join(WRITER_LOCK_FILE);
        // Strict admission validates repository authority before creating or
        // touching the writer lock. Explicit recovery is itself the authority to
        // rebuild broken controls, so it acquires the one-writer lock first and
        // derives a provisional replacement identity only while holding it.
        let strict_repository = if recovery == PublicationRecovery::Strict {
            Some(load_or_create_repository_cap(
                &publication_capability,
                &publication_directory,
                &canonical_root,
            )?)
        } else {
            None
        };
        let lock_file =
            open_cap_regular_lock(&publication_capability, WRITER_LOCK_FILE, &lock_path)?;
        if let Err(error) = lock_file.try_lock() {
            return match error {
                std::fs::TryLockError::WouldBlock => {
                    Err(PublicationError::WriterBusy { path: lock_path })
                }
                std::fs::TryLockError::Error(source) => Err(PublicationError::Io {
                    operation: "acquire publication writer lock",
                    path: lock_path,
                    source,
                }),
            };
        }

        let (repository, repository_needs_commit) = match strict_repository {
            Some(repository) => {
                // Revalidate after acquiring the process-independent lock. A
                // control substitution between preflight and lock acquisition
                // must not become the authority held by this writer.
                let locked_repository = load_repository_cap(
                    &publication_capability,
                    &publication_directory,
                    &canonical_root,
                )?;
                if locked_repository != repository {
                    return Err(PublicationError::InvalidControl {
                        path: publication_directory.join(REPOSITORY_FILE),
                        reason: "repository identity changed during writer admission".into(),
                    });
                }
                (repository, false)
            }
            None => prepare_recovery_repository_cap(
                &publication_capability,
                &publication_directory,
                &canonical_root,
            )?,
        };
        let generations_directory = publication_directory.join(GENERATIONS_DIRECTORY);
        let (generations_capability, admitted_current) = if recovery == PublicationRecovery::Strict
        {
            let scan = scan_heads_cap(&publication_capability, &publication_directory)?;
            if scan.present.iter().any(|present| *present) {
                let capability = require_cap_directory(
                    &publication_capability,
                    GENERATIONS_DIRECTORY,
                    &generations_directory,
                )?;
                let admitted_current = match prevalidated_current {
                    Some(current)
                        if prevalidated_current_matches_locked_head(
                            &current,
                            &scan,
                            &generations_directory,
                            &repository.body.repository_id,
                        ) =>
                    {
                        Some(current)
                    }
                    _ => match resolve_from_scan(
                        &publication_directory,
                        &generations_directory,
                        &repository.body.repository_id,
                        &scan,
                    ) {
                        Ok(current) => current,
                        Err(PublicationError::NoCompatibleGenerationSchema { .. }) => None,
                        Err(error) => return Err(error),
                    },
                };
                (capability, admitted_current)
            } else {
                (
                    ensure_cap_directory(
                        &publication_capability,
                        GENERATIONS_DIRECTORY,
                        &generations_directory,
                        "create descriptor-relative generations directory",
                    )?,
                    None,
                )
            }
        } else {
            (
                ensure_cap_directory(
                    &publication_capability,
                    GENERATIONS_DIRECTORY,
                    &generations_directory,
                    "create descriptor-relative generations directory",
                )?,
                None,
            )
        };
        sync_cap_directory(&publication_capability, &publication_directory)?;
        publication_root.verify_path_binding()?;
        Ok(Self {
            publication_root,
            publication_directory,
            publication_capability,
            generations_directory,
            generations_capability,
            repository_root: canonical_root,
            repository,
            recovery,
            repository_needs_commit,
            admitted_current,
            lock_file,
        })
    }

    pub const fn repository_id(&self) -> &RepositoryId {
        &self.repository.body.repository_id
    }

    /// Capture only the reusable source facts from the current validated
    /// generation while holding the publication writer lock.
    ///
    /// Recovery never imports old authority. An incompatible extractor identity
    /// or absent fact table is a cache miss, not an error: the private candidate
    /// performs a complete extraction instead.
    fn capture_incremental_basis(
        &self,
        exclude_patterns: &[String],
    ) -> Result<Option<IncrementalIndexBasis>, PublicationError> {
        if self.recovery != PublicationRecovery::Strict || self.repository_needs_commit {
            return Ok(None);
        }
        self.publication_root.verify_path_binding()?;
        let Some(current) = self.admitted_current.as_ref() else {
            return Ok(None);
        };
        let database = Arc::new(ReadOnlyDatabase::open(&current.database_path).map_err(
            |error| PublicationError::Redb {
                operation: "open current generation for incremental seed",
                path: current.database_path.clone(),
                error: error.to_string(),
            },
        )?);
        let basis = validate_open_generation_authority(database, current, &self.repository_root)?
            .incremental_basis;
        if !incremental_basis_matches_current(current, &basis, exclude_patterns) {
            return Ok(None);
        }
        Ok(Some(basis))
    }

    /// Take an exact process-local basis only after normal writer admission
    /// has validated the same immutable head and the cached source facts still
    /// satisfy the current structural receipts.
    fn take_live_generation_basis(
        &self,
        live: LiveGenerationBasis,
        exclude_patterns: &[String],
    ) -> Option<(
        IncrementalIndexBasis,
        KnowledgeGraph,
        Vec<CanonicalSemanticBasis>,
        Arc<ProjectInventory>,
    )> {
        if self.recovery != PublicationRecovery::Strict || self.repository_needs_commit {
            return None;
        }
        let current = self.admitted_current.as_ref()?;
        if live.head != current.head.body
            || !incremental_basis_matches_current(current, &live.source, exclude_patterns)
        {
            return None;
        }
        Some((
            live.source,
            live.graph,
            live.semantic_bases,
            live.project_inventory,
        ))
    }

    /// Reclaim provider workspaces left by a writer that died before Rust's
    /// `TempDir` destructor could run. A live publisher already owns the
    /// process-independent writer lock. Descriptor-relative enumeration and
    /// removal keep a substituted graph-directory path outside this authority.
    fn cleanup_stale_provider_workspaces(&self) -> Result<usize, PublicationError> {
        self.publication_root.verify_path_binding()?;
        let entries = self
            .publication_root
            .directory
            .entries()
            .and_then(|entries| entries.collect::<Result<Vec<_>, _>>())
            .map_err(|source| PublicationError::Io {
                operation: "enumerate stale provider workspaces",
                path: self.publication_root.path.clone(),
                source,
            })?;
        let mut removed = 0;
        for entry in entries {
            let name = entry.file_name();
            let Some(name_text) = name.to_str() else {
                continue;
            };
            if !name_text.starts_with(PROVIDER_WORKSPACE_PREFIX) {
                continue;
            }
            let file_type = entry.file_type().map_err(|source| PublicationError::Io {
                operation: "inspect stale provider workspace",
                path: self.publication_root.path.join(&name),
                source,
            })?;
            // A crashed tempfile workspace is a real directory. Never follow
            // or remove a symlink/non-directory merely because its name uses
            // the reserved prefix.
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            self.publication_root
                .directory
                .remove_dir_all(Path::new(&name))
                .map_err(|source| PublicationError::Io {
                    operation: "remove stale provider workspace",
                    path: self.publication_root.path.join(&name),
                    source,
                })?;
            removed += 1;
        }
        if removed > 0 {
            sync_cap_directory(
                &self.publication_root.directory,
                &self.publication_root.path,
            )?;
        }
        self.publication_root.verify_path_binding()?;
        Ok(removed)
    }

    pub fn begin_generation(&self) -> Result<GenerationWorkspace, PublicationError> {
        self.publication_root.verify_path_binding()?;
        let staging_name = format!(".staging-{}", Uuid::new_v4().simple());
        let staging_directory = self.generations_directory.join(&staging_name);
        self.generations_capability
            .create_dir(&staging_name)
            .map_err(|source| PublicationError::Io {
                operation: "create descriptor-relative private generation staging directory",
                path: staging_directory.clone(),
                source,
            })?;
        sync_cap_directory(&self.generations_capability, &self.generations_directory)?;
        let staging_capability = require_cap_directory(
            &self.generations_capability,
            &staging_name,
            &staging_directory,
        )?;
        let staging_identity =
            DirectoryIdentity::from_directory(&staging_capability).map_err(|source| {
                PublicationError::Io {
                    operation: "identify private generation staging directory",
                    path: staging_directory.clone(),
                    source,
                }
            })?;
        let database_path = staging_directory.join(GENERATION_DATABASE_FILE);
        let database_file = staging_capability
            .open_with(
                GENERATION_DATABASE_FILE,
                &cap_read_write_options(false, true),
            )
            .map_err(|source| PublicationError::Io {
                operation: "create descriptor-relative private generation database",
                path: database_path.clone(),
                source,
            })?
            .into_std();
        let database = Database::builder()
            .create_file(database_file)
            .map_err(|error| PublicationError::Redb {
                operation: "create private generation database",
                path: database_path.clone(),
                error: error.to_string(),
            })?;
        let database = Arc::new(database);
        // A private staging database has no read authority. The indexing
        // pipeline writes the one real graph snapshot, origin, and generation
        // metadata before finish validates and publishes the candidate. Writing
        // an empty placeholder here duplicated that work and forced every
        // WATCH reconciliation through an unnecessary redb transaction.
        Ok(GenerationWorkspace {
            repository_id: self.repository.body.repository_id.clone(),
            generations_directory: self.generations_directory.clone(),
            staging_directory,
            staging_name,
            staging_capability,
            staging_identity,
            database,
        })
    }

    /// Discard a private generation that the current writer will not publish.
    ///
    /// Cooperative cancellation and other handled pipeline failures are not
    /// process crashes: they must close the private database and reclaim their
    /// descriptor-relative staging directory before returning to the caller.
    /// An abruptly terminated process can still leave a staging directory for
    /// the existing next-writer maintenance path to recover.
    fn discard_private_generation(
        &self,
        workspace: GenerationWorkspace,
    ) -> Result<(), PublicationError> {
        self.publication_root.verify_path_binding()?;
        validate_workspace(&workspace, self)?;
        let GenerationWorkspace {
            repository_id: _,
            generations_directory: _,
            staging_directory,
            staging_name,
            staging_capability,
            staging_identity,
            database,
        } = workspace;
        let database_path = staging_directory.join(GENERATION_DATABASE_FILE);
        let database = Arc::try_unwrap(database).map_err(|_| PublicationError::DatabaseBusy {
            path: database_path,
        })?;
        drop(database);
        verify_cap_child_binding(
            &self.generations_capability,
            &staging_name,
            &staging_identity,
            &staging_directory,
        )?;
        drop(staging_capability);
        quarantine_and_remove_directory_cap(
            &self.generations_capability,
            &self.generations_directory,
            &staging_name,
        )?;
        self.publication_root.verify_path_binding()
    }

    pub fn finish_generation(
        &mut self,
        workspace: GenerationWorkspace,
        draft: GenerationDraft,
    ) -> Result<PublishedGeneration, PublicationError> {
        self.finish_generation_with_capability_floor(
            workspace,
            draft,
            CapabilityFloorPolicy::Preserve,
        )
    }

    pub fn finish_generation_with_capability_floor(
        &mut self,
        workspace: GenerationWorkspace,
        draft: GenerationDraft,
        capability_floor: CapabilityFloorPolicy,
    ) -> Result<PublishedGeneration, PublicationError> {
        self.finish_generation_with_capability_floor_profiled(
            workspace,
            draft,
            capability_floor,
            None,
            None,
        )
        .map(|(publication, _timings)| publication)
    }

    fn finish_generation_with_capability_floor_profiled(
        &mut self,
        workspace: GenerationWorkspace,
        draft: GenerationDraft,
        capability_floor: CapabilityFloorPolicy,
        graph_publication_proof: Option<BoundGraphPublicationProof>,
        index_state_publication_proof: Option<BoundIndexStatePublicationProof>,
    ) -> Result<(PublishedGeneration, Vec<PublicationStepTiming>), PublicationError> {
        self.finish_generation_candidate_with_capability_floor_profiled(
            workspace,
            draft.into(),
            capability_floor,
            graph_publication_proof,
            index_state_publication_proof,
        )
    }

    fn finish_generation_candidate_with_capability_floor_profiled(
        &mut self,
        workspace: GenerationWorkspace,
        mut draft: GenerationCandidateDraft,
        capability_floor: CapabilityFloorPolicy,
        graph_publication_proof: Option<BoundGraphPublicationProof>,
        index_state_publication_proof: Option<BoundIndexStatePublicationProof>,
    ) -> Result<(PublishedGeneration, Vec<PublicationStepTiming>), PublicationError> {
        let mut publication_timings = Vec::with_capacity(20);
        let candidate_graph_validation_start = Instant::now();
        self.publication_root.verify_path_binding()?;
        validate_workspace(&workspace, self)?;
        let private_database_path = workspace.staging_directory.join(GENERATION_DATABASE_FILE);
        let (raw_candidate_graph, graph_publication_proof) = match graph_publication_proof {
            Some(witness) => {
                let proof = witness.authorize(&workspace.database).map_err(|error| {
                    PublicationError::InvalidGenerationGraph {
                        path: private_database_path.clone(),
                        reason: format!("fresh candidate graph witness is invalid: {error}"),
                    }
                })?;
                proof
                    .validate_candidate_identity(&self.repository_root)
                    .map_err(|error| PublicationError::InvalidGenerationGraph {
                        path: private_database_path.clone(),
                        reason: error.to_string(),
                    })?;
                (None, proof)
            }
            None => {
                let graph_store = GraphStore::new(workspace.database());
                let graph = graph_store
                    .validate_publication_snapshot_sync(&self.repository_root)
                    .map_err(|error| PublicationError::InvalidGenerationGraph {
                        path: private_database_path.clone(),
                        reason: error.to_string(),
                    })?;
                let proof = graph_store
                    .capture_publication_proof_sync(&self.repository_root)
                    .map_err(|error| PublicationError::InvalidGenerationGraph {
                        path: private_database_path.clone(),
                        reason: error.to_string(),
                    })?;
                (Some(graph), proof)
            }
        };
        let candidate_database_bytes = graph_publication_proof.verified_bytes();
        let index_state_publication_proof = match index_state_publication_proof {
            Some(witness) => witness.authorize(&workspace.database).map_err(|error| {
                PublicationError::InvalidControl {
                    path: private_database_path.clone(),
                    reason: format!("fresh candidate index-state witness is invalid: {error}"),
                }
            })?,
            None => {
                let index_state = IndexState::new(workspace.database()).map_err(|error| {
                    PublicationError::InvalidControl {
                        path: private_database_path.clone(),
                        reason: format!("open private generation index state: {error}"),
                    }
                })?;
                index_state.capture_publication_proof().map_err(|error| {
                    PublicationError::InvalidControl {
                        path: private_database_path.clone(),
                        reason: format!(
                            "validate private generation index-state content proof: {error}"
                        ),
                    }
                })?
            }
        };
        let candidate_database_bytes = if candidate_database_bytes == 0 {
            fs::metadata(&private_database_path).map_or(0, |metadata| metadata.len())
        } else {
            candidate_database_bytes
        };
        record_publication_step(
            &mut publication_timings,
            "candidate graph validation",
            candidate_graph_validation_start,
            candidate_database_bytes,
            "database bytes",
        );

        let candidate_receipt_validation_start = Instant::now();
        normalize_and_validate_receipts(&mut draft.receipts)?;
        validate_optional_label("source revision", draft.source_revision.as_deref())?;
        record_publication_step(
            &mut publication_timings,
            "candidate receipt validation",
            candidate_receipt_validation_start,
            draft.receipts.len() as u64,
            "receipt records",
        );

        let candidate_inventory_validation_start = Instant::now();
        let project_inventory_bytes =
            canonical_project_inventory_bytes(&draft.project_inventory)
                .map_err(|error| PublicationError::InvalidDraft(error.to_string()))?;
        if project_inventory_bytes.len() as u64 > MAX_PROJECT_INVENTORY_BYTES {
            return Err(PublicationError::ControlTooLarge {
                path: workspace.staging_directory.join(GENERATION_DATABASE_FILE),
                limit: MAX_PROJECT_INVENTORY_BYTES,
                actual: project_inventory_bytes.len() as u64,
            });
        }
        let project_inventory = parse_project_inventory_bytes(&project_inventory_bytes)
            .map_err(|error| PublicationError::InvalidDraft(error.to_string()))?;
        let project_inventory_sha256 = sha256_bytes(&project_inventory_bytes);
        let project_inventory_records = project_inventory
            .project_topology
            .units
            .len()
            .saturating_add(project_inventory.project_topology.memberships.len())
            .saturating_add(project_inventory.project_topology.relationships.len())
            .saturating_add(project_inventory.project_topology.dependency_graphs.len())
            .saturating_add(project_inventory.inputs.len())
            .saturating_add(project_inventory.issues.len());
        record_publication_step(
            &mut publication_timings,
            "candidate inventory validation",
            candidate_inventory_validation_start,
            project_inventory_records as u64,
            "inventory records",
        );

        let (provider_payload_records, provider_payload_documents) =
            provider_payload_candidate_counts(&draft.provider_payloads);
        let payloads_require_canonicalization = matches!(
            &draft.provider_payloads,
            ProviderPayloadCandidates::Unvalidated(_)
        );
        let prepared_provider_payload_batch = match draft.provider_payloads {
            ProviderPayloadCandidates::Unvalidated(payloads) => {
                prepare_provider_payloads(&payloads, &draft.receipts, &project_inventory)?
            }
            ProviderPayloadCandidates::Canonical(payloads) => {
                prepare_canonical_provider_payloads(payloads, &draft.receipts, &project_inventory)?
            }
        };
        let prepared_provider_payload_bytes = prepared_provider_payload_batch
            .payloads
            .iter()
            .map(|prepared| prepared.bytes.len() as u64)
            .sum::<u64>();
        record_publication_duration(
            &mut publication_timings,
            "candidate payload receipt-scope validation",
            prepared_provider_payload_batch.receipt_scope_validation,
            draft.receipts.len() as u64,
            "receipt records",
        );
        record_publication_duration(
            &mut publication_timings,
            "candidate payload normalization",
            prepared_provider_payload_batch
                .canonicalization
                .normalization,
            if payloads_require_canonicalization {
                provider_payload_records as u64
            } else {
                0
            },
            "provider evidence records",
        );
        record_publication_duration(
            &mut publication_timings,
            "candidate payload serialization",
            prepared_provider_payload_batch
                .canonicalization
                .serialization,
            if payloads_require_canonicalization {
                prepared_provider_payload_bytes
            } else {
                0
            },
            "payload bytes",
        );
        record_publication_duration(
            &mut publication_timings,
            "candidate payload descriptor binding",
            prepared_provider_payload_batch.canonicalization.descriptor,
            if payloads_require_canonicalization {
                prepared_provider_payload_bytes
            } else {
                0
            },
            "payload bytes",
        );
        record_publication_duration(
            &mut publication_timings,
            "candidate payload inventory coverage validation",
            prepared_provider_payload_batch.inventory_coverage_validation,
            provider_payload_documents as u64,
            "provider documents",
        );
        record_publication_duration(
            &mut publication_timings,
            "candidate payload descriptor linkage validation",
            prepared_provider_payload_batch.descriptor_linkage_validation,
            prepared_provider_payload_batch.payloads.len() as u64,
            "provider payloads",
        );
        let prepared_provider_payloads = prepared_provider_payload_batch.payloads;

        let candidate_payload_structural_join_start = Instant::now();
        if let Some(graph) = raw_candidate_graph.as_ref() {
            for prepared in &prepared_provider_payloads {
                match prepared.payload.payload() {
                    ProviderPayload::Calls(payload) => {
                        validate_calls_payload_structural_join(graph, payload).map_err(
                            |error| {
                                PublicationError::InvalidDraft(format!(
                                    "raw provider payload could not join the co-published structural graph: {error}"
                                ))
                            },
                        )?;
                    }
                    ProviderPayload::CallableLiveness(payload) => {
                        validate_callable_liveness_payload_structural_join(graph, payload)
                            .map_err(|error| {
                                PublicationError::InvalidDraft(format!(
                                    "raw callable-liveness payload could not join the co-published structural graph: {error}"
                                ))
                            })?;
                    }
                }
            }
        }
        record_publication_step(
            &mut publication_timings,
            "candidate payload structural join validation",
            candidate_payload_structural_join_start,
            if raw_candidate_graph.is_some() {
                prepared_provider_payloads.len() as u64
            } else {
                0
            },
            "provider payloads",
        );

        let candidate_result_materialization_start = Instant::now();
        let provider_payload_descriptors = prepared_provider_payloads
            .iter()
            .map(|prepared| prepared.descriptor.clone())
            .collect::<Vec<_>>();
        record_publication_step(
            &mut publication_timings,
            "candidate payload result materialization",
            candidate_result_materialization_start,
            provider_payload_descriptors.len() as u64,
            "payload descriptors",
        );

        let current_validation_start = Instant::now();
        let scan = if self.recovery == PublicationRecovery::RecoverAndRebind {
            scan_heads_cap_for_recovery(&self.publication_capability, &self.publication_directory)?
        } else {
            scan_heads_cap(&self.publication_capability, &self.publication_directory)?
        };
        let conflicting_heads = scan.valid.len() == 2
            && scan.valid[0].head.body.sequence == scan.valid[1].head.body.sequence
            && scan.valid[0].head != scan.valid[1].head;
        let skip_current = self.repository_needs_commit || conflicting_heads;
        let admitted_current_is_exact = !skip_current
            && revalidate_locked_admitted_current(
                self.admitted_current.as_ref(),
                &scan,
                &self.publication_directory,
                &self.generations_directory,
                &self.generations_capability,
                &self.repository.body.repository_id,
            )?;
        let resolved_current = if skip_current || admitted_current_is_exact {
            None
        } else {
            match resolve_from_scan(
                &self.publication_directory,
                &self.generations_directory,
                &self.repository.body.repository_id,
                &scan,
            ) {
                Ok(current) => current,
                // Valid, checksummed heads and payloads belonging to this
                // repository may name an older generation envelope after a
                // binary upgrade. That derived authority is intentionally not
                // interpreted or preserved; the validated replacement becomes
                // the first generation in the new envelope.
                Err(PublicationError::NoCompatibleGenerationSchema { .. }) => None,
                Err(
                    PublicationError::NoValidHead { .. }
                    | PublicationError::NoValidGeneration { .. },
                ) if self.recovery == PublicationRecovery::RecoverAndRebind => None,
                Err(error) => return Err(error),
            }
        };
        let current = if skip_current {
            None
        } else if admitted_current_is_exact {
            self.admitted_current.as_ref()
        } else {
            resolved_current.as_ref()
        };
        enforce_capability_floor(
            current,
            &draft.receipts,
            &project_inventory,
            capability_floor,
        )?;
        let current_generation_bytes = current
            .and_then(|resolved| fs::metadata(&resolved.database_path).ok())
            .map_or(0, |metadata| metadata.len());
        record_publication_step(
            &mut publication_timings,
            "current authority validation",
            current_validation_start,
            current_generation_bytes,
            "database bytes",
        );

        let authority_write_start = Instant::now();
        write_project_inventory(
            workspace.database.as_ref(),
            &private_database_path,
            &project_inventory_bytes,
        )?;
        write_provider_payloads(
            workspace.database.as_ref(),
            &private_database_path,
            &prepared_provider_payloads,
        )?;
        let authority_bytes = project_inventory_bytes.len() as u64
            + prepared_provider_payloads
                .iter()
                .map(|prepared| prepared.bytes.len() as u64)
                .sum::<u64>();
        let provider_payloads = prepared_provider_payloads
            .into_iter()
            .map(|prepared| prepared.payload)
            .collect::<Vec<_>>();
        record_publication_step(
            &mut publication_timings,
            "authority table writes",
            authority_write_start,
            authority_bytes,
            "payload bytes",
        );

        let candidate_close_start = Instant::now();
        let GenerationWorkspace {
            repository_id: _,
            generations_directory: _,
            staging_directory,
            staging_name,
            staging_capability,
            staging_identity,
            database,
        } = workspace;
        let database_path = staging_directory.join(GENERATION_DATABASE_FILE);
        let database = Arc::try_unwrap(database).map_err(|_| PublicationError::DatabaseBusy {
            path: database_path.clone(),
        })?;
        drop(database);
        verify_cap_child_binding(
            &self.generations_capability,
            &staging_name,
            &staging_identity,
            &staging_directory,
        )?;
        sync_cap_regular_file(
            &staging_capability,
            GENERATION_DATABASE_FILE,
            &database_path,
        )?;
        let candidate_payload_bytes =
            fs::metadata(&database_path).map_or(0, |metadata| metadata.len());
        record_publication_step(
            &mut publication_timings,
            "candidate close and sync",
            candidate_close_start,
            candidate_payload_bytes,
            "database bytes",
        );

        let payload_digest_start = Instant::now();
        let payload_blake3 = blake3_cap_file(
            &staging_capability,
            GENERATION_DATABASE_FILE,
            &database_path,
        )?;
        record_publication_step(
            &mut publication_timings,
            "candidate payload digest",
            payload_digest_start,
            candidate_payload_bytes,
            "database bytes",
        );

        let manifest_write_start = Instant::now();
        let parent_generation_id = current.map(|resolved| resolved.manifest.generation_id.clone());
        let mut manifest = GenerationManifest {
            schema_version: GENERATION_SCHEMA.into(),
            generation_id: GenerationId::new("pending"),
            repository_id: self.repository.body.repository_id.clone(),
            parent_generation_id,
            source_revision: draft.source_revision,
            payload_blake3,
            graph_publication_proof,
            index_state_publication_proof,
            project_inventory_sha256,
            receipts: draft.receipts,
            provider_payloads: provider_payload_descriptors,
        };
        manifest.generation_id = compute_generation_id(&manifest)?;
        let manifest_bytes = canonical_json(&manifest)?;
        if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(PublicationError::ControlTooLarge {
                path: database_path,
                limit: MAX_MANIFEST_BYTES,
                actual: manifest_bytes.len() as u64,
            });
        }
        write_manifest_cap(&staging_capability, &database_path, &manifest_bytes)?;
        sync_cap_regular_file(
            &staging_capability,
            GENERATION_DATABASE_FILE,
            &database_path,
        )?;
        record_publication_step(
            &mut publication_timings,
            "manifest seal and sync",
            manifest_write_start,
            manifest_bytes.len() as u64,
            "manifest bytes",
        );

        let database_digest_start = Instant::now();
        let database_blake3 = blake3_cap_file(
            &staging_capability,
            GENERATION_DATABASE_FILE,
            &database_path,
        )?;
        let sealed_database_bytes =
            fs::metadata(&database_path).map_or(0, |metadata| metadata.len());
        record_publication_step(
            &mut publication_timings,
            "sealed database digest",
            database_digest_start,
            sealed_database_bytes,
            "database bytes",
        );
        let manifest_sha256 = sha256_bytes(&manifest_bytes);
        let receipt_set_sha256 = sha256_bytes(&canonical_json(&manifest.receipts)?);
        let provider_payload_set_sha256 =
            sha256_bytes(&canonical_json(&manifest.provider_payloads)?);
        let final_name = manifest.generation_id.0.clone();
        let final_directory = self.generations_directory.join(&final_name);
        let generation_promotion_start = Instant::now();
        match self.generations_capability.symlink_metadata(&final_name) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                let existing = final_directory.join(GENERATION_DATABASE_FILE);
                let existing_capability = self
                    .generations_capability
                    .open_dir(&final_name)
                    .map_err(|source| PublicationError::Io {
                        operation: "open existing descriptor-relative immutable generation",
                        path: final_directory.clone(),
                        source,
                    })?;
                let existing_digest =
                    blake3_cap_file(&existing_capability, GENERATION_DATABASE_FILE, &existing)?;
                if existing_digest != database_blake3 {
                    return Err(PublicationError::GenerationCollision {
                        generation_id: manifest.generation_id,
                    });
                }
                self.generations_capability
                    .remove_dir_all(&staging_name)
                    .map_err(|source| PublicationError::Io {
                        operation:
                            "remove redundant descriptor-relative generation staging directory",
                        path: staging_directory.clone(),
                        source,
                    })?;
            }
            Ok(_) => {
                return Err(PublicationError::UnsafeArtifact {
                    path: final_directory,
                    expected: "directory",
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.generations_capability
                    .rename(&staging_name, &self.generations_capability, &final_name)
                    .map_err(|source| PublicationError::Io {
                        operation: "publish descriptor-relative immutable generation directory",
                        path: final_directory.clone(),
                        source,
                    })?;
                sync_cap_directory(&self.generations_capability, &self.generations_directory)?;
            }
            Err(source) => {
                return Err(PublicationError::Io {
                    operation: "inspect immutable generation destination",
                    path: final_directory,
                    source,
                });
            }
        }
        record_publication_step(
            &mut publication_timings,
            "immutable generation promotion",
            generation_promotion_start,
            1,
            "generation",
        );

        let head_commit_start = Instant::now();
        let maximum_sequence = scan
            .valid
            .iter()
            .map(|candidate| candidate.head.body.sequence)
            .max()
            .unwrap_or(0);
        let sequence = maximum_sequence
            .checked_add(1)
            .ok_or(PublicationError::SequenceOverflow)?;
        let head_body = PublicationHeadBody {
            schema_version: HEAD_SCHEMA.into(),
            sequence,
            repository_id: self.repository.body.repository_id.clone(),
            generation_id: manifest.generation_id.clone(),
            database_blake3,
            manifest_sha256,
            receipt_set_sha256,
            provider_payload_set_sha256,
            previous_generation_id: current.map(|resolved| resolved.manifest.generation_id.clone()),
        };
        let head = seal_head(head_body)?;
        let slot = select_publish_slot(&scan, current.map(|resolved| resolved.slot));
        self.publication_root.verify_path_binding()?;
        if self.repository_needs_commit {
            write_repository_record_cap(
                &self.publication_capability,
                &self.publication_directory,
                &self.repository,
            )?;
            self.repository_needs_commit = false;
        }
        write_head_cap(
            &self.publication_capability,
            &self.publication_directory,
            slot,
            &head,
        )?;
        if self.recovery == PublicationRecovery::RecoverAndRebind {
            write_head_cap(
                &self.publication_capability,
                &self.publication_directory,
                1 - slot,
                &head,
            )?;
        }
        record_publication_step(
            &mut publication_timings,
            "head commit",
            head_commit_start,
            if self.recovery == PublicationRecovery::RecoverAndRebind {
                2
            } else {
                1
            },
            "head records",
        );

        let cleanup_start = Instant::now();
        let maintenance = cleanup_generation_population_cap(
            &self.publication_capability,
            &self.publication_directory,
            &self.generations_capability,
            &self.generations_directory,
        );
        let maintenance_items = maintenance
            .removed
            .len()
            .saturating_add(maintenance.warnings.len());
        record_publication_step(
            &mut publication_timings,
            "bounded generation cleanup",
            cleanup_start,
            maintenance_items as u64,
            "maintenance records",
        );

        Ok((
            PublishedGeneration {
                slot,
                database_path: final_directory.join(GENERATION_DATABASE_FILE),
                head,
                manifest,
                project_inventory: Arc::new(project_inventory),
                provider_payloads,
                maintenance,
            },
            publication_timings,
        ))
    }
}

fn incremental_basis_matches_current(
    current: &ResolvedGeneration,
    basis: &IncrementalIndexBasis,
    exclude_patterns: &[String],
) -> bool {
    if !structural_receipts_match_records(
        &current.manifest.receipts,
        &basis.files,
        exclude_patterns,
    ) {
        return false;
    }
    let records = basis
        .files
        .iter()
        .map(|(path, record)| (path.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    basis.document_facts.iter().all(|facts| {
        records
            .get(facts.file_path.as_str())
            .is_some_and(|record| record.blake3_hash == facts.file_hash)
    })
}

impl Drop for SemanticPublisher {
    fn drop(&mut self) {
        let _ = self.lock_file.unlock();
    }
}

/// Build and publish one fresh code-intelligence generation.
///
/// This is the shared production ownership boundary between indexing and
/// immutable publication. The graph and index are built in the same private
/// database; the exact inventory and capability receipts returned by that run
/// are then committed with it. No prior-generation payload or authority is
/// copied into the new generation.
///
/// A dry run has no publishable evidence and is rejected before writer state is
/// acquired. Any later pipeline or publication error leaves the private
/// generation unreferenced and never writes a new head.
pub async fn publish_fresh_index_generation(
    graph_directory: &Path,
    config: &IndexConfig,
    source_revision: Option<String>,
) -> Result<PublishedIndexGeneration, IndexGenerationPublicationError> {
    publish_fresh_index_generation_with_policy(
        graph_directory,
        config,
        source_revision,
        PublicationRecovery::Strict,
        CapabilityFloorPolicy::Preserve,
    )
    .await
}

pub async fn publish_fresh_index_generation_with_recovery(
    graph_directory: &Path,
    config: &IndexConfig,
    source_revision: Option<String>,
    recovery: PublicationRecovery,
) -> Result<PublishedIndexGeneration, IndexGenerationPublicationError> {
    publish_fresh_index_generation_with_policy(
        graph_directory,
        config,
        source_revision,
        recovery,
        CapabilityFloorPolicy::Preserve,
    )
    .await
}

pub async fn publish_fresh_index_generation_with_policy(
    graph_directory: &Path,
    config: &IndexConfig,
    source_revision: Option<String>,
    recovery: PublicationRecovery,
    capability_floor: CapabilityFloorPolicy,
) -> Result<PublishedIndexGeneration, IndexGenerationPublicationError> {
    let publication_root = PreparedPublicationRoot::capture(graph_directory)?;
    publish_prepared_index_generation_with_recovery(
        publication_root,
        config,
        source_revision,
        recovery,
        capability_floor,
    )
    .await
}

/// Publish through the exact graph-directory capability captured during
/// [`crate::code_intel_indexing::BoundIndexPlan::prepare`].
pub async fn publish_prepared_index_generation_with_recovery(
    publication_root: PreparedPublicationRoot,
    config: &IndexConfig,
    source_revision: Option<String>,
    recovery: PublicationRecovery,
    capability_floor: CapabilityFloorPolicy,
) -> Result<PublishedIndexGeneration, IndexGenerationPublicationError> {
    let mut semantic_providers = SemanticProviderRegistry::default();
    publish_prepared_index_generation_with_live_basis(
        publication_root,
        config,
        source_revision,
        recovery,
        capability_floor,
        LivePublicationRuntime {
            prevalidated_current: None,
            live_basis: None,
            semantic_providers: &mut semantic_providers,
        },
    )
    .await
    .map(|(published, _)| published)
}

/// Process-local reuse and provider acceleration offered to one immutable
/// publication attempt. The publisher revalidates every authority-bearing
/// component before it can influence the committed generation.
pub(crate) struct LivePublicationRuntime<'a> {
    pub(crate) prevalidated_current: Option<ResolvedGeneration>,
    pub(crate) live_basis: Option<LiveGenerationBasis>,
    pub(crate) semantic_providers: &'a mut SemanticProviderRegistry,
}

fn finish_nested_profile_timing(
    timings: &mut Vec<IndexPhaseTiming>,
    phase: IndexProgressPhase,
    label: &'static str,
    started: Option<Instant>,
) {
    if let Some(started) = started {
        timings.push(IndexPhaseTiming {
            phase,
            label: label.into(),
            duration: started.elapsed(),
            aggregation: IndexTimingAggregation::ConcurrentSpan,
        });
    }
}

pub(crate) async fn publish_prepared_index_generation_with_live_basis(
    publication_root: PreparedPublicationRoot,
    config: &IndexConfig,
    source_revision: Option<String>,
    recovery: PublicationRecovery,
    capability_floor: CapabilityFloorPolicy,
    runtime: LivePublicationRuntime<'_>,
) -> Result<(PublishedIndexGeneration, LiveGenerationBasis), IndexGenerationPublicationError> {
    let LivePublicationRuntime {
        prevalidated_current,
        live_basis,
        semantic_providers,
    } = runtime;
    let operation_start = Instant::now();
    if config.cancellation.is_cancelled() {
        return Err(IndexPipelineError::Cancelled.into());
    }
    if config.dry_run {
        return Err(IndexGenerationPublicationError::EvidenceUnavailable);
    }

    let prepare_start = Instant::now();
    emit_progress(
        &config.progress,
        IndexProgressPhase::Prepare,
        IndexProgressState::Started,
        "preparing private generation",
        "acquiring writer authority and importing reusable source facts",
        None,
    );
    let mut prepare_profile_timings = Vec::with_capacity(if config.profile { 6 } else { 0 });
    let step_started = config.profile.then(Instant::now);
    let mut publisher = SemanticPublisher::acquire_prepared(
        publication_root,
        &config.root,
        recovery,
        prevalidated_current,
    )?;
    finish_nested_profile_timing(
        &mut prepare_profile_timings,
        IndexProgressPhase::Prepare,
        "profile: prepare / acquire publication authority",
        step_started,
    );
    let step_started = config.profile.then(Instant::now);
    publisher.cleanup_stale_provider_workspaces()?;
    finish_nested_profile_timing(
        &mut prepare_profile_timings,
        IndexProgressPhase::Prepare,
        "profile: prepare / cleanup provider workspaces",
        step_started,
    );
    let step_started = config.profile.then(Instant::now);
    let (incremental_basis, structural_graph_basis, semantic_basis, prior_project_inventory) =
        if config.full {
            (None, None, Vec::new(), None)
        } else if let Some((source, graph, semantic_bases, project_inventory)) = live_basis
            .and_then(|basis| publisher.take_live_generation_basis(basis, &config.exclude))
        {
            (
                Some(source),
                Some(graph),
                semantic_bases,
                Some(project_inventory),
            )
        } else {
            let source = publisher.capture_incremental_basis(&config.exclude)?;
            let project_inventory = source.as_ref().and_then(|_| {
                publisher
                    .admitted_current
                    .as_ref()
                    .map(|current| Arc::clone(&current.project_inventory))
            });
            let semantic_bases = if source.is_some() && config.scip.generates_artifacts() {
                publisher
                    .admitted_current
                    .as_ref()
                    .map_or_else(Vec::new, |current| {
                        load_cached_canonical_semantic_bases(
                            &publisher.publication_root.path,
                            &publisher.repository_root,
                            &current.provider_payloads,
                        )
                    })
            } else {
                Vec::new()
            };
            (source, None, semantic_bases, project_inventory)
        };
    finish_nested_profile_timing(
        &mut prepare_profile_timings,
        IndexProgressPhase::Prepare,
        "profile: prepare / resolve reusable basis",
        step_started,
    );
    let step_started = config.profile.then(Instant::now);
    let workspace = publisher.begin_generation()?;
    finish_nested_profile_timing(
        &mut prepare_profile_timings,
        IndexProgressPhase::Prepare,
        "profile: prepare / create private generation",
        step_started,
    );
    let step_started = config.profile.then(Instant::now);
    let database = workspace.database();
    let graph_store = GraphStore::new(Arc::clone(&database));
    let index_state = IndexState::new(Arc::clone(&database)).map_err(IndexPipelineError::from)?;
    finish_nested_profile_timing(
        &mut prepare_profile_timings,
        IndexProgressPhase::Prepare,
        "profile: prepare / open private stores",
        step_started,
    );
    let step_started = config.profile.then(Instant::now);
    let reusable_population = incremental_basis
        .as_ref()
        .map(|basis| (basis.files.len(), basis.document_facts.len()));
    let live_structural_basis_reused = structural_graph_basis.is_some();
    let incremental_basis = incremental_basis.map(|source| IncrementalPipelineBasis {
        source,
        graph: structural_graph_basis,
        semantic_bases: semantic_basis,
        project_inventory: prior_project_inventory
            .expect("an admitted incremental basis has a validated project inventory"),
    });
    finish_nested_profile_timing(
        &mut prepare_profile_timings,
        IndexProgressPhase::Prepare,
        "profile: prepare / assemble incremental basis",
        step_started,
    );
    let prepare_duration = prepare_start.elapsed();
    emit_progress(
        &config.progress,
        IndexProgressPhase::Prepare,
        IndexProgressState::Completed,
        "preparing private generation",
        reusable_population.map_or_else(
            || "private database ready; no reusable source facts admitted".to_owned(),
            |(files, facts)| format!(
                "private database ready; retained {files} file records and {facts} fact sets in memory"
            ),
        ),
        Some(prepare_duration),
    );
    let outcome = IndexPipeline::run_with_incremental_basis(
        &index_state,
        Some(&graph_store),
        config,
        None,
        IndexPipelineRuntime {
            incremental_basis,
            semantic_providers,
        },
    )
    .await;
    drop(index_state);
    drop(graph_store);
    drop(database);
    let prepared = match outcome {
        Ok(prepared) => prepared,
        Err(error) => {
            publisher.discard_private_generation(workspace)?;
            return Err(error.into());
        }
    };
    let structural_basis = match prepared.structural_basis {
        Some(basis) => basis,
        None => {
            publisher.discard_private_generation(workspace)?;
            return Err(IndexGenerationPublicationError::EvidenceUnavailable);
        }
    };
    let outcome = prepared.outcome;
    let (mut telemetry, evidence, publication_proof, index_state_publication_proof) = match outcome
    {
        IndexRunOutcome::Completed {
            telemetry,
            evidence,
            publication_proof,
            index_state_publication_proof,
        } => (
            telemetry,
            evidence,
            publication_proof,
            index_state_publication_proof,
        ),
        IndexRunOutcome::DryRun { .. } => {
            publisher.discard_private_generation(workspace)?;
            return Err(IndexGenerationPublicationError::EvidenceUnavailable);
        }
    };
    let mut timed_operation =
        Vec::with_capacity(1 + prepare_profile_timings.len() + telemetry.phase_timings.len());
    timed_operation.push(IndexPhaseTiming {
        phase: IndexProgressPhase::Prepare,
        label: "preparing private generation".into(),
        duration: prepare_duration,
        aggregation: IndexTimingAggregation::Exclusive,
    });
    timed_operation.append(&mut prepare_profile_timings);
    timed_operation.append(&mut telemetry.phase_timings);
    telemetry.phase_timings = timed_operation;
    if let Some((files, facts)) = reusable_population {
        telemetry.reusable_file_records = files;
        telemetry.reusable_document_fact_sets = facts;
    }
    telemetry.preindex_basis_rows_persisted = 0;
    telemetry.live_structural_basis_reused = live_structural_basis_reused;
    if config.cancellation.is_cancelled() {
        publisher.discard_private_generation(workspace)?;
        return Err(IndexPipelineError::Cancelled.into());
    }

    let publish_start = Instant::now();
    emit_progress(
        &config.progress,
        IndexProgressPhase::Publish,
        IndexProgressState::Started,
        "publishing generation",
        "durably committing the immutable generation and advancing the validated head",
        None,
    );
    let (publication, publication_timings) = match publisher
        .finish_generation_candidate_with_capability_floor_profiled(
            workspace,
            GenerationCandidateDraft {
                source_revision,
                project_inventory: evidence.project_inventory,
                receipts: evidence.capability_receipts,
                provider_payloads: ProviderPayloadCandidates::Canonical(evidence.provider_payloads),
            },
            capability_floor,
            publication_proof.map(|proof| *proof),
            Some(index_state_publication_proof),
        ) {
        Ok(publication) => publication,
        Err(error) => {
            emit_progress(
                &config.progress,
                IndexProgressPhase::Publish,
                IndexProgressState::Failed,
                "publishing generation",
                error.to_string(),
                Some(publish_start.elapsed()),
            );
            return Err(error.into());
        }
    };
    let publish_duration = publish_start.elapsed();
    if let Err(error) = persist_cached_canonical_semantic_bases(
        &publisher.publication_root.path,
        &structural_basis.semantic_bases,
    ) {
        tracing::warn!(
            error = %error,
            "canonical semantic snapshot cache was not persisted; later processes will safely execute providers"
        );
    }
    telemetry.phase_timings.push(IndexPhaseTiming {
        phase: IndexProgressPhase::Publish,
        label: "publishing generation".into(),
        duration: publish_duration,
        aggregation: IndexTimingAggregation::Exclusive,
    });
    telemetry.duration = operation_start.elapsed();
    emit_progress(
        &config.progress,
        IndexProgressPhase::Publish,
        IndexProgressState::Completed,
        "publishing generation",
        format!(
            "generation {} is current",
            publication.manifest.generation_id
        ),
        Some(publish_duration),
    );
    let authority = publication_control_token(&publisher.publication_root.path, &config.root)
        .ok()
        .map(|control_token| LiveGenerationAuthority {
            resolved: Arc::new(ResolvedGeneration {
                slot: publication.slot,
                head: publication.head.clone(),
                manifest: publication.manifest.clone(),
                project_inventory: Arc::clone(&publication.project_inventory),
                provider_payloads: publication.provider_payloads.clone(),
                database_path: publication.database_path.clone(),
            }),
            control_token,
        });
    let calls_authority = assess_calls_capability(
        &structural_basis.graph,
        &publication.manifest.receipts,
        &publication.provider_payloads,
        &publication.project_inventory,
    );
    let callable_liveness_authority = assess_callable_liveness_capability(
        &structural_basis.graph,
        &publication.manifest.receipts,
        &publication.provider_payloads,
        &publication.project_inventory,
    );
    let live_basis = LiveGenerationBasis {
        head: publication.head.body.clone(),
        authority,
        source: structural_basis.source,
        graph: structural_basis.graph,
        semantic_bases: structural_basis.semantic_bases,
        project_inventory: Arc::clone(&publication.project_inventory),
    };
    let published = PublishedIndexGeneration {
        telemetry: *telemetry,
        publication,
        calls_authority,
        callable_liveness_authority,
        publication_timings,
    };
    Ok((published, live_basis))
}

/// Resolve the newest valid referenced generation without creating, repairing,
/// locking, or otherwise mutating the publication root.
pub fn resolve_generation(
    graph_directory: &Path,
    repository_root: &Path,
) -> Result<ResolvedGeneration, PublicationError> {
    resolve_generation_with_control_token(graph_directory, repository_root)
        .map(|(resolved, _control_token)| resolved)
}

/// Resolve the newest valid referenced generation and return the bounded
/// publication-control token derived from the same control scan.
///
/// The paired token lets a consumer perform expensive validation exactly once,
/// then use a fresh bounded token read as its terminal linearization check.
/// A token mismatch grants no authority and requires ordinary reconciliation.
pub(crate) fn resolve_generation_with_control_token(
    graph_directory: &Path,
    repository_root: &Path,
) -> Result<(ResolvedGeneration, PublicationControlToken), PublicationError> {
    resolve_generation_with_control_token_internal(graph_directory, repository_root, None)
}

/// Profile the mutually exclusive work required to turn bounded publication
/// controls into one fully validated immutable generation.
pub(crate) fn resolve_generation_with_control_token_profiled(
    graph_directory: &Path,
    repository_root: &Path,
) -> (
    Result<(ResolvedGeneration, PublicationControlToken), PublicationError>,
    Vec<GenerationResolutionStepTiming>,
) {
    let mut timings = Vec::new();
    let resolved = resolve_generation_with_control_token_internal(
        graph_directory,
        repository_root,
        Some(&mut timings),
    );
    (resolved, timings)
}

fn resolve_generation_with_control_token_internal(
    graph_directory: &Path,
    repository_root: &Path,
    mut timings: Option<&mut Vec<GenerationResolutionStepTiming>>,
) -> Result<(ResolvedGeneration, PublicationControlToken), PublicationError> {
    let controls_started = Instant::now();
    let (publication_directory, repository, scan) =
        match read_publication_controls(graph_directory, repository_root) {
            Ok(controls) => controls,
            Err(error) => {
                record_generation_resolution_step(
                    timings.as_deref_mut(),
                    "reuse publication control resolution",
                    controls_started.elapsed(),
                    HEAD_FILES.len() as u64,
                    "head slots",
                );
                return Err(error);
            }
        };
    let control_token = match publication_control_token_from_scan(&repository, &scan) {
        Ok(token) => token,
        Err(error) => {
            record_generation_resolution_step(
                timings.as_deref_mut(),
                "reuse publication control resolution",
                controls_started.elapsed(),
                HEAD_FILES.len() as u64,
                "head slots",
            );
            return Err(error);
        }
    };
    record_generation_resolution_step(
        timings.as_deref_mut(),
        "reuse publication control resolution",
        controls_started.elapsed(),
        HEAD_FILES.len() as u64,
        "head slots",
    );
    let generations_directory = publication_directory.join(GENERATIONS_DIRECTORY);
    require_directory(&generations_directory, "generations directory")?;
    let resolved = resolve_from_scan_profiled(
        &publication_directory,
        &generations_directory,
        &repository.body.repository_id,
        &scan,
        timings,
    )?
    .ok_or(PublicationError::Unpublished {
        path: publication_directory,
    })?;
    Ok((resolved, control_token))
}

/// Revalidate process-local parsed authority for the narrow WATCH fast path.
///
/// Equality of the bounded control token proves that repository identity and
/// both head records still match the scan that admitted `authority`. Hashing
/// the exact immutable database then detects payload mutation even when the
/// controls are unchanged. This witness may prove that a dirty indexed hint
/// makes reuse impossible and may be handed to the writer, whose locked-head
/// and database-digest checks remain the final publication authority. It is
/// deliberately insufficient for returning an exact reused generation,
/// because that path must also bind the opened database handle.
pub(crate) fn revalidate_live_generation_authority_profiled(
    graph_directory: &Path,
    repository_root: &Path,
    authority: &LiveGenerationAuthority,
) -> (
    Option<(ResolvedGeneration, PublicationControlToken)>,
    Vec<GenerationResolutionStepTiming>,
) {
    let mut timings = Vec::new();
    let controls_started = Instant::now();
    let Ok((publication_directory, repository, scan)) =
        read_publication_controls(graph_directory, repository_root)
    else {
        record_generation_resolution_step(
            Some(&mut timings),
            "reuse publication control resolution",
            controls_started.elapsed(),
            HEAD_FILES.len() as u64,
            "head slots",
        );
        return (None, timings);
    };
    let Ok(control_token) = publication_control_token_from_scan(&repository, &scan) else {
        record_generation_resolution_step(
            Some(&mut timings),
            "reuse publication control resolution",
            controls_started.elapsed(),
            HEAD_FILES.len() as u64,
            "head slots",
        );
        return (None, timings);
    };
    record_generation_resolution_step(
        Some(&mut timings),
        "reuse publication control resolution",
        controls_started.elapsed(),
        HEAD_FILES.len() as u64,
        "head slots",
    );
    if control_token != authority.control_token {
        return (None, timings);
    }

    let generations_directory = publication_directory.join(GENERATIONS_DIRECTORY);
    let identity_started = Instant::now();
    let identity_matches = require_directory(&generations_directory, "generations directory")
        .is_ok()
        && prevalidated_current_matches_locked_head(
            authority.resolved.as_ref(),
            &scan,
            &generations_directory,
            &repository.body.repository_id,
        );
    record_generation_resolution_step(
        Some(&mut timings),
        "reuse generation identity validation",
        identity_started.elapsed(),
        1,
        "generations",
    );
    if !identity_matches {
        return (None, timings);
    }

    let digest_started = Instant::now();
    let digest = blake3_file_counted(&authority.resolved.database_path);
    let work_items = digest.as_ref().map_or(0, |(_, bytes)| *bytes);
    record_generation_resolution_step(
        Some(&mut timings),
        "reuse immutable database digest",
        digest_started.elapsed(),
        work_items,
        "bytes",
    );
    let Ok((actual_digest, _bytes)) = digest else {
        return (None, timings);
    };
    if actual_digest != authority.resolved.head.body.database_blake3 {
        return (None, timings);
    }

    (
        Some((authority.resolved.as_ref().clone(), control_token)),
        timings,
    )
}

/// Verify and decode the exact database handle opened by a consumer against
/// every manifest-bound authority population returned by
/// [`resolve_generation`].
///
/// Returning the decoded graph and index-state populations prevents a path
/// replacement between resolution and open—or a later independent table
/// read—from pairing unauthenticated product state with valid semantic
/// authority.
pub fn validate_open_generation_authority(
    database: Arc<ReadOnlyDatabase>,
    resolved: &ResolvedGeneration,
    repository_root: &Path,
) -> Result<ValidatedOpenGeneration, PublicationError> {
    let manifest_bytes = read_manifest_from_database(database.as_ref(), &resolved.database_path)?;
    let actual_manifest_digest = sha256_bytes(&manifest_bytes);
    if actual_manifest_digest != resolved.head.body.manifest_sha256 {
        return Err(PublicationError::DigestMismatch {
            path: resolved.database_path.clone(),
            expected: resolved.head.body.manifest_sha256.clone(),
            actual: actual_manifest_digest,
        });
    }
    let mut manifest: GenerationManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            PublicationError::InvalidControl {
                path: resolved.database_path.clone(),
                reason: format!("parse generation manifest from open database: {error}"),
            }
        })?;
    validate_manifest(&mut manifest).map_err(|error| PublicationError::InvalidControl {
        path: resolved.database_path.clone(),
        reason: error.to_string(),
    })?;
    if manifest != resolved.manifest {
        return Err(PublicationError::InvalidControl {
            path: resolved.database_path.clone(),
            reason: "open database manifest differs from resolved generation authority".into(),
        });
    }

    let project_inventory = read_project_inventory_from_database(
        database.as_ref(),
        &resolved.database_path,
        &manifest.project_inventory_sha256,
    )?;
    if project_inventory != *resolved.project_inventory {
        return Err(PublicationError::InvalidControl {
            path: resolved.database_path.clone(),
            reason: "open database project inventory differs from resolved generation authority"
                .into(),
        });
    }
    let provider_payloads = read_provider_payloads_from_database(
        database.as_ref(),
        &resolved.database_path,
        &manifest.provider_payloads,
        &manifest.receipts,
        &project_inventory,
    )?;
    if provider_payloads != resolved.provider_payloads {
        return Err(PublicationError::InvalidControl {
            path: resolved.database_path.clone(),
            reason: "open database provider payloads differ from resolved generation authority"
                .into(),
        });
    }
    let graph_store = GraphStore::new_read_only(Arc::clone(&database));
    let ValidatedGraphContent {
        graph,
        reachability_evidence,
        origin,
        generation_metadata,
    } = graph_store
        .validate_and_load_publication_proof_sync(
            repository_root,
            &manifest.graph_publication_proof,
        )
        .map_err(|error| PublicationError::InvalidControl {
            path: resolved.database_path.clone(),
            reason: format!("opened graph content proof is invalid: {error}"),
        })?;
    let index_state = IndexState::new_read_only(database);
    let ValidatedIndexStateContent {
        proof: _,
        metadata: index_metadata,
        indexed_sources,
        basis: incremental_basis,
    } = index_state
        .validate_publication_proof(&manifest.index_state_publication_proof)
        .map_err(|error| PublicationError::InvalidControl {
            path: resolved.database_path.clone(),
            reason: format!("opened index-state content proof is invalid: {error}"),
        })?;
    Ok(ValidatedOpenGeneration {
        graph,
        reachability_evidence,
        origin: PathBuf::from(origin),
        generation_metadata,
        index_metadata,
        indexed_sources,
        incremental_basis,
    })
}

/// Re-hash the referenced generation after a consumer has finished loading
/// from it.
///
/// Immutable writers never edit published generation bytes, so any
/// digest change is a failed integrity check rather than a reload signal.
pub fn revalidate_generation_database(
    resolved: &ResolvedGeneration,
) -> Result<(), PublicationError> {
    require_regular_file(&resolved.database_path, "immutable generation database")?;
    let actual = blake3_file(&resolved.database_path)?;
    if actual != resolved.head.body.database_blake3 {
        return Err(PublicationError::DigestMismatch {
            path: resolved.database_path.clone(),
            expected: resolved.head.body.database_blake3.clone(),
            actual,
        });
    }
    Ok(())
}

/// Read a cheap, bounded fingerprint of the publication controls without
/// opening, hashing, repairing, or otherwise inspecting `generation.redb`.
///
/// This is a reload hint, not capability authority. An unchanged token allows
/// a caller to retain an already validated snapshot; a changed token requires a
/// fresh [`resolve_generation`] before any newly referenced bytes are trusted.
pub fn publication_control_token(
    graph_directory: &Path,
    repository_root: &Path,
) -> Result<PublicationControlToken, PublicationError> {
    let (_publication_directory, repository, scan) =
        read_publication_controls(graph_directory, repository_root)?;
    publication_control_token_from_scan(&repository, &scan)
}

fn publication_control_token_from_scan(
    repository: &RepositoryRecord,
    scan: &HeadScan,
) -> Result<PublicationControlToken, PublicationError> {
    #[derive(Serialize)]
    struct TokenInput<'a> {
        repository_digest: &'a str,
        heads: &'a [HeadControlState; 2],
    }

    Ok(PublicationControlToken(sha256_bytes(&canonical_json(
        &TokenInput {
            repository_digest: &repository.digest,
            heads: &scan.controls,
        },
    )?)))
}

/// Capture a bounded, non-authoritative metadata witness for control drift.
///
/// The five `symlink_metadata` calls are intentionally independent of root
/// canonicalization, JSON parsing, control validation, and generation payload
/// I/O. Callers must read [`publication_control_token`] after a change before
/// scheduling authority from it.
#[must_use]
pub fn publication_control_witness(graph_directory: &Path) -> PublicationControlWitness {
    let publication_directory = graph_directory.join(PUBLICATION_DIRECTORY);
    PublicationControlWitness {
        graph_directory: PublicationPathWitness::capture(graph_directory),
        publication_directory: PublicationPathWitness::capture(&publication_directory),
        repository: PublicationPathWitness::capture(&publication_directory.join(REPOSITORY_FILE)),
        heads: HEAD_FILES.map(|file_name| {
            PublicationPathWitness::capture(&publication_directory.join(file_name))
        }),
    }
}

fn read_publication_controls(
    graph_directory: &Path,
    repository_root: &Path,
) -> Result<(PathBuf, RepositoryRecord, HeadScan), PublicationError> {
    match fs::symlink_metadata(graph_directory) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PublicationError::Unpublished {
                path: graph_directory.join(PUBLICATION_DIRECTORY),
            });
        }
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect graph directory",
                path: graph_directory.to_path_buf(),
                source,
            });
        }
    }
    let canonical_graph = canonical_directory(graph_directory, "canonicalize graph directory")?;
    let canonical_root = canonical_directory(repository_root, "canonicalize repository root")?;
    let publication_directory = canonical_graph.join(PUBLICATION_DIRECTORY);
    match fs::symlink_metadata(&publication_directory) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(PublicationError::UnsafeArtifact {
                path: publication_directory,
                expected: "publication directory",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PublicationError::Unpublished {
                path: publication_directory,
            });
        }
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect publication directory",
                path: publication_directory,
                source,
            });
        }
    }
    let repository = load_repository(&publication_directory, &canonical_root)?;
    let scan = scan_heads(&publication_directory)?;
    Ok((publication_directory, repository, scan))
}

#[derive(Debug)]
struct HeadCandidate {
    slot: usize,
    head: PublicationHead,
}

#[derive(Debug)]
struct HeadScan {
    valid: Vec<HeadCandidate>,
    invalid: Vec<(usize, String)>,
    present: [bool; 2],
    controls: [HeadControlState; 2],
}

fn prevalidated_current_matches_locked_head(
    current: &ResolvedGeneration,
    scan: &HeadScan,
    generations_directory: &Path,
    repository_id: &RepositoryId,
) -> bool {
    let expected_database_path = generations_directory
        .join(&current.head.body.generation_id.0)
        .join(GENERATION_DATABASE_FILE);
    current.head.body.repository_id == *repository_id
        && current.manifest.repository_id == *repository_id
        && current.manifest.generation_id == current.head.body.generation_id
        && current.database_path == expected_database_path
        && scan.valid.first().is_some_and(|candidate| {
            candidate.slot == current.slot && candidate.head == current.head
        })
}

/// Reuse already parsed generation authority only when the writer-locked head
/// still names that exact record and every database byte still matches its
/// admitted digest. A changed head is not an error here: the caller performs a
/// fresh full resolution so a legitimate newer generation retains its normal
/// admission path. Damage beneath an unchanged head is a hard refusal.
fn revalidate_locked_admitted_current(
    current: Option<&ResolvedGeneration>,
    scan: &HeadScan,
    publication_directory: &Path,
    generations_directory: &Path,
    generations_capability: &Dir,
    repository_id: &RepositoryId,
) -> Result<bool, PublicationError> {
    let Some(current) = current else {
        return Ok(false);
    };
    if !prevalidated_current_matches_locked_head(
        current,
        scan,
        generations_directory,
        repository_id,
    ) {
        return Ok(false);
    }

    let generation_name = &current.head.body.generation_id.0;
    let generation_directory = generations_directory.join(generation_name);
    let database_path = generation_directory.join(GENERATION_DATABASE_FILE);
    let revalidation = (|| {
        let generation_capability = require_cap_directory(
            generations_capability,
            generation_name,
            &generation_directory,
        )?;
        let actual = blake3_cap_file(
            &generation_capability,
            GENERATION_DATABASE_FILE,
            &database_path,
        )?;
        if actual != current.head.body.database_blake3 {
            return Err(PublicationError::DigestMismatch {
                path: database_path,
                expected: current.head.body.database_blake3.clone(),
                actual,
            });
        }
        Ok(())
    })();

    match revalidation {
        Ok(()) => Ok(true),
        Err(error) => Err(PublicationError::NoValidGeneration {
            path: publication_directory.to_path_buf(),
            details: vec![(current.slot, error.to_string())],
        }),
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum HeadControlState {
    Missing,
    Valid {
        digest: String,
    },
    Invalid {
        content_sha256: Option<String>,
        reason: String,
    },
}

fn scan_heads(publication_directory: &Path) -> Result<HeadScan, PublicationError> {
    scan_heads_with_conflict_policy(publication_directory, true)
}

fn scan_heads_with_conflict_policy(
    publication_directory: &Path,
    reject_conflict: bool,
) -> Result<HeadScan, PublicationError> {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    let mut present = [false; 2];
    let mut controls = std::array::from_fn(|_| HeadControlState::Missing);
    for (slot, file_name) in HEAD_FILES.iter().enumerate() {
        let path = publication_directory.join(file_name);
        let bytes = match read_optional_regular_bounded(&path, MAX_CONTROL_FILE_BYTES) {
            Ok(Some(bytes)) => {
                present[slot] = true;
                bytes
            }
            Ok(None) => continue,
            Err(error) => {
                present[slot] = true;
                let reason = error.to_string();
                controls[slot] = HeadControlState::Invalid {
                    content_sha256: None,
                    reason: reason.clone(),
                };
                invalid.push((slot, reason));
                continue;
            }
        };
        match parse_head(&path, &bytes) {
            Ok(head) => {
                controls[slot] = HeadControlState::Valid {
                    digest: head.digest.clone(),
                };
                valid.push(HeadCandidate { slot, head });
            }
            Err(error) => {
                let reason = error.to_string();
                controls[slot] = HeadControlState::Invalid {
                    content_sha256: Some(sha256_bytes(&bytes)),
                    reason: reason.clone(),
                };
                invalid.push((slot, reason));
            }
        }
    }
    if reject_conflict
        && valid.len() == 2
        && valid[0].head.body.sequence == valid[1].head.body.sequence
        && valid[0].head != valid[1].head
    {
        return Err(PublicationError::HeadConflict {
            sequence: valid[0].head.body.sequence,
            first: valid[0].head.body.generation_id.clone(),
            second: valid[1].head.body.generation_id.clone(),
        });
    }
    valid.sort_by(|left, right| {
        right
            .head
            .body
            .sequence
            .cmp(&left.head.body.sequence)
            .then_with(|| left.slot.cmp(&right.slot))
    });
    Ok(HeadScan {
        valid,
        invalid,
        present,
        controls,
    })
}

fn resolve_from_scan(
    publication_directory: &Path,
    generations_directory: &Path,
    repository_id: &RepositoryId,
    scan: &HeadScan,
) -> Result<Option<ResolvedGeneration>, PublicationError> {
    resolve_from_scan_profiled(
        publication_directory,
        generations_directory,
        repository_id,
        scan,
        None,
    )
}

fn resolve_from_scan_profiled(
    publication_directory: &Path,
    generations_directory: &Path,
    repository_id: &RepositoryId,
    scan: &HeadScan,
    mut timings: Option<&mut Vec<GenerationResolutionStepTiming>>,
) -> Result<Option<ResolvedGeneration>, PublicationError> {
    if scan.valid.is_empty() {
        if scan.present.iter().any(|present| *present) {
            return Err(PublicationError::NoValidHead {
                path: publication_directory.to_path_buf(),
                details: scan.invalid.clone(),
            });
        }
        return Ok(None);
    }

    let mut failures = scan.invalid.clone();
    let mut schemas_only = scan.invalid.is_empty();
    for candidate in &scan.valid {
        match validate_generation_profiled(
            generations_directory,
            repository_id,
            candidate,
            timings.as_deref_mut(),
        ) {
            Ok(resolved) => return Ok(Some(resolved)),
            Err(error) => {
                schemas_only &=
                    matches!(error, PublicationError::IncompatibleGenerationSchema { .. });
                failures.push((candidate.slot, error.to_string()));
            }
        }
    }
    if schemas_only {
        Err(PublicationError::NoCompatibleGenerationSchema {
            path: publication_directory.to_path_buf(),
            details: failures,
        })
    } else {
        Err(PublicationError::NoValidGeneration {
            path: publication_directory.to_path_buf(),
            details: failures,
        })
    }
}

fn validate_generation_profiled(
    generations_directory: &Path,
    repository_id: &RepositoryId,
    candidate: &HeadCandidate,
    mut timings: Option<&mut Vec<GenerationResolutionStepTiming>>,
) -> Result<ResolvedGeneration, PublicationError> {
    #[cfg(test)]
    GENERATIONS_VALIDATED.with(|count| count.set(count.get().saturating_add(1)));
    let database_path = measure_generation_resolution_step(
        timings.as_deref_mut(),
        "reuse generation identity validation",
        "generations",
        || {
            validate_generation_id(&candidate.head.body.generation_id)?;
            if &candidate.head.body.repository_id != repository_id {
                return Err(PublicationError::RepositoryMismatch {
                    expected: repository_id.clone(),
                    actual: candidate.head.body.repository_id.clone(),
                });
            }
            let generation_directory =
                generations_directory.join(&candidate.head.body.generation_id.0);
            require_directory(&generation_directory, "immutable generation directory")?;
            let database_path = generation_directory.join(GENERATION_DATABASE_FILE);
            require_regular_file(&database_path, "immutable generation database")?;
            Ok((database_path, 1))
        },
    )?;
    let actual_database_digest = measure_generation_resolution_step(
        timings.as_deref_mut(),
        "reuse immutable database digest",
        "bytes",
        || blake3_file_counted(&database_path),
    )?;
    if actual_database_digest != candidate.head.body.database_blake3 {
        return Err(PublicationError::DigestMismatch {
            path: database_path,
            expected: candidate.head.body.database_blake3.clone(),
            actual: actual_database_digest,
        });
    }
    let manifest = measure_generation_resolution_step(
        timings.as_deref_mut(),
        "reuse generation manifest validation",
        "bytes",
        || {
            let manifest_bytes = read_manifest(&database_path)?;
            let manifest_len = manifest_bytes.len() as u64;
            let actual_manifest_digest = sha256_bytes(&manifest_bytes);
            if actual_manifest_digest != candidate.head.body.manifest_sha256 {
                return Err(PublicationError::DigestMismatch {
                    path: database_path.clone(),
                    expected: candidate.head.body.manifest_sha256.clone(),
                    actual: actual_manifest_digest,
                });
            }
            let mut manifest: GenerationManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|error| PublicationError::InvalidControl {
                    path: database_path.clone(),
                    reason: format!("parse generation manifest: {error}"),
                })?;
            if manifest.schema_version != GENERATION_SCHEMA {
                return Err(PublicationError::IncompatibleGenerationSchema {
                    path: database_path.clone(),
                    expected: GENERATION_SCHEMA.into(),
                    actual: manifest.schema_version,
                });
            }
            validate_manifest(&mut manifest).map_err(|error| PublicationError::InvalidControl {
                path: database_path.clone(),
                reason: error.to_string(),
            })?;
            Ok((manifest, manifest_len))
        },
    )?;
    let project_inventory = measure_generation_resolution_step(
        timings.as_deref_mut(),
        "reuse project inventory validation",
        "memberships",
        || {
            let inventory =
                read_project_inventory(&database_path, &manifest.project_inventory_sha256)?;
            let memberships = inventory.project_topology.memberships.len() as u64;
            Ok((inventory, memberships))
        },
    )?;
    let provider_payloads = measure_generation_resolution_step(
        timings.as_deref_mut(),
        "reuse provider payload validation",
        "documents",
        || {
            let payloads = read_provider_payloads(
                &database_path,
                &manifest.provider_payloads,
                &manifest.receipts,
                &project_inventory,
            )?;
            let documents = payloads
                .iter()
                .map(|payload| payload.payload().documents().len() as u64)
                .sum();
            Ok((payloads, documents))
        },
    )?;
    measure_generation_resolution_step(
        timings,
        "reuse generation cross-authority validation",
        "authority records",
        || {
            if manifest.repository_id != *repository_id {
                return Err(PublicationError::RepositoryMismatch {
                    expected: repository_id.clone(),
                    actual: manifest.repository_id.clone(),
                });
            }
            if manifest.generation_id != candidate.head.body.generation_id {
                return Err(PublicationError::InvalidControl {
                    path: database_path.clone(),
                    reason: "head and manifest generation IDs differ".into(),
                });
            }
            let computed_generation_id = compute_generation_id(&manifest)?;
            if computed_generation_id != manifest.generation_id {
                return Err(PublicationError::InvalidControl {
                    path: database_path.clone(),
                    reason: format!(
                        "manifest generation ID {} does not match computed {}",
                        manifest.generation_id, computed_generation_id
                    ),
                });
            }
            if manifest.parent_generation_id != candidate.head.body.previous_generation_id {
                return Err(PublicationError::InvalidControl {
                    path: database_path.clone(),
                    reason: "head and manifest previous-generation IDs differ".into(),
                });
            }
            let actual_receipt_digest = sha256_bytes(&canonical_json(&manifest.receipts)?);
            if actual_receipt_digest != candidate.head.body.receipt_set_sha256 {
                return Err(PublicationError::DigestMismatch {
                    path: database_path.clone(),
                    expected: candidate.head.body.receipt_set_sha256.clone(),
                    actual: actual_receipt_digest,
                });
            }
            let actual_provider_payload_digest =
                sha256_bytes(&canonical_json(&manifest.provider_payloads)?);
            if actual_provider_payload_digest != candidate.head.body.provider_payload_set_sha256 {
                return Err(PublicationError::DigestMismatch {
                    path: database_path.clone(),
                    expected: candidate.head.body.provider_payload_set_sha256.clone(),
                    actual: actual_provider_payload_digest,
                });
            }
            let authority_records =
                (manifest.receipts.len() + manifest.provider_payloads.len()) as u64;
            Ok(((), authority_records))
        },
    )?;
    Ok(ResolvedGeneration {
        slot: candidate.slot,
        head: candidate.head.clone(),
        manifest,
        project_inventory: Arc::new(project_inventory),
        provider_payloads,
        database_path,
    })
}

fn validate_workspace(
    workspace: &GenerationWorkspace,
    publisher: &SemanticPublisher,
) -> Result<(), PublicationError> {
    if workspace.repository_id != publisher.repository.body.repository_id
        || workspace.generations_directory != publisher.generations_directory
    {
        return Err(PublicationError::WorkspaceMismatch {
            expected_repository: publisher.repository.body.repository_id.clone(),
            actual_repository: workspace.repository_id.clone(),
            expected_directory: publisher.generations_directory.clone(),
            actual_directory: workspace.generations_directory.clone(),
        });
    }
    let suffix = workspace
        .staging_name
        .strip_prefix(".staging-")
        .unwrap_or_default();
    if workspace.staging_directory.parent() != Some(&workspace.generations_directory)
        || workspace.staging_directory.file_name() != Some(workspace.staging_name.as_ref())
        || suffix.len() != 32
        || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PublicationError::UnsafeArtifact {
            path: workspace.staging_directory.clone(),
            expected: "private generation staging directory",
        });
    }
    verify_cap_child_binding(
        &publisher.generations_capability,
        &workspace.staging_name,
        &workspace.staging_identity,
        &workspace.staging_directory,
    )
}

fn validate_manifest(manifest: &mut GenerationManifest) -> Result<(), PublicationError> {
    if manifest.schema_version != GENERATION_SCHEMA {
        return Err(PublicationError::InvalidDraft(format!(
            "unsupported generation schema {}",
            manifest.schema_version
        )));
    }
    validate_generation_id(&manifest.generation_id)?;
    validate_blake3("payload digest", &manifest.payload_blake3)?;
    validate_sha256(
        "project inventory fingerprint",
        &manifest.project_inventory_sha256,
    )?;
    validate_optional_label("source revision", manifest.source_revision.as_deref())?;
    normalize_and_validate_receipts(&mut manifest.receipts)?;
    normalize_and_validate_payload_descriptors(&mut manifest.provider_payloads, &manifest.receipts)
}

fn normalize_and_validate_receipts(
    receipts: &mut [CapabilityReceipt],
) -> Result<(), PublicationError> {
    for receipt in receipts.iter() {
        validate_label("capability ID", &receipt.capability_id)?;
        validate_label("provider ID", &receipt.provider_id.0)?;
        if let Some(provider_version) = &receipt.provider_version {
            validate_label("provider version", provider_version)?;
        }
        validate_scope(&receipt.scope)?;
        if let Some(input_fingerprint) = &receipt.input_fingerprint {
            validate_sha256("receipt input fingerprint", input_fingerprint)?;
        }
        match receipt.status {
            CapabilityStatus::Complete
                if receipt.reason.is_some()
                    || receipt.reason_code.is_some()
                    || receipt.provider_version.is_none()
                    || receipt.input_fingerprint.is_none() =>
            {
                return Err(PublicationError::InvalidDraft(
                    "a complete receipt requires provider version and input fingerprint and cannot carry an unavailable reason or reason code".into(),
                ));
            }
            CapabilityStatus::Partial | CapabilityStatus::Unavailable
                if receipt.reason.as_deref().is_none_or(str::is_empty)
                    || receipt.reason_code.as_deref().is_none_or(str::is_empty) =>
            {
                return Err(PublicationError::InvalidDraft(
                    "partial and unavailable receipts require a non-empty reason and reason code"
                        .into(),
                ));
            }
            _ => {}
        }
    }
    receipts.sort_by(|left, right| {
        (&left.capability_id, &left.scope)
            .cmp(&(&right.capability_id, &right.scope))
            .then_with(|| left.provider_id.0.cmp(&right.provider_id.0))
    });
    for pair in receipts.windows(2) {
        if pair[0].capability_id == pair[1].capability_id
            && pair[0].scope == pair[1].scope
            && pair[0].provider_id == pair[1].provider_id
        {
            return Err(PublicationError::InvalidDraft(format!(
                "duplicate receipt for capability {}, scope {:?}, and provider {}",
                pair[0].capability_id, pair[0].scope, pair[0].provider_id
            )));
        }
    }
    Ok(())
}

fn prepare_provider_payloads(
    payloads: &[ProviderPayload],
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> Result<PreparedProviderPayloadBatch, PublicationError> {
    if payloads.len() > MAX_PROVIDER_PAYLOADS {
        return Err(PublicationError::InvalidDraft(format!(
            "provider payload count {} exceeds limit {MAX_PROVIDER_PAYLOADS}",
            payloads.len()
        )));
    }
    let receipt_scope_validation_started = Instant::now();
    validate_receipt_inventory(receipts, inventory)?;
    let receipt_scope_validation = receipt_scope_validation_started.elapsed();

    let mut total_bytes = 0u64;
    let mut prepared = Vec::with_capacity(payloads.len());
    let mut canonicalization = ProviderPayloadCanonicalizationTimings::default();
    let mut inventory_coverage_validation = Duration::ZERO;
    for payload in payloads {
        let (canonical, payload_timings) = canonicalize_provider_payload_profiled(payload)
            .map_err(|error| PublicationError::InvalidDraft(error.to_string()))?;
        canonicalization.normalization += payload_timings.normalization;
        canonicalization.serialization += payload_timings.serialization;
        canonicalization.descriptor += payload_timings.descriptor;
        let (payload, descriptor, bytes) = canonical.into_parts();
        let inventory_coverage_validation_started = Instant::now();
        validate_payload_inventory(payload.payload(), inventory)?;
        inventory_coverage_validation += inventory_coverage_validation_started.elapsed();
        if bytes.len() as u64 > MAX_PROVIDER_PAYLOAD_BYTES {
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload {} exceeds {MAX_PROVIDER_PAYLOAD_BYTES} bytes",
                descriptor.payload_id.0
            )));
        }
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
            PublicationError::InvalidDraft("provider payload byte total overflowed".into())
        })?;
        if total_bytes > MAX_PROVIDER_PAYLOAD_TOTAL_BYTES {
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload population exceeds {MAX_PROVIDER_PAYLOAD_TOTAL_BYTES} bytes"
            )));
        }
        prepared.push(PreparedProviderPayload {
            payload,
            descriptor,
            bytes,
        });
    }
    finish_prepared_provider_payloads(
        prepared,
        receipts,
        receipt_scope_validation,
        canonicalization,
        inventory_coverage_validation,
    )
}

fn finish_prepared_provider_payloads(
    mut prepared: Vec<PreparedProviderPayload>,
    receipts: &[CapabilityReceipt],
    receipt_scope_validation: Duration,
    canonicalization: ProviderPayloadCanonicalizationTimings,
    inventory_coverage_validation: Duration,
) -> Result<PreparedProviderPayloadBatch, PublicationError> {
    let descriptor_linkage_validation_started = Instant::now();
    prepared.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));
    let mut descriptors = prepared
        .iter()
        .map(|prepared| prepared.descriptor.clone())
        .collect::<Vec<_>>();
    normalize_and_validate_payload_descriptors(&mut descriptors, receipts)?;

    let receipt_by_id = complete_receipts_by_id(receipts)?;
    for prepared in &prepared {
        let receipt = receipt_by_id
            .get(&prepared.descriptor.receipt_id)
            .expect("descriptor linkage was validated");
        if prepared.payload.payload().receipt() != *receipt {
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload {} embeds a receipt that differs from its manifest receipt",
                prepared.descriptor.payload_id.0
            )));
        }
    }
    let descriptor_linkage_validation = descriptor_linkage_validation_started.elapsed();
    Ok(PreparedProviderPayloadBatch {
        payloads: prepared,
        receipt_scope_validation,
        canonicalization,
        inventory_coverage_validation,
        descriptor_linkage_validation,
    })
}

fn prepare_canonical_provider_payloads(
    payloads: Vec<CanonicalProviderPayload>,
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> Result<PreparedProviderPayloadBatch, PublicationError> {
    if payloads.len() > MAX_PROVIDER_PAYLOADS {
        return Err(PublicationError::InvalidDraft(format!(
            "provider payload count {} exceeds limit {MAX_PROVIDER_PAYLOADS}",
            payloads.len()
        )));
    }
    let receipt_scope_validation_started = Instant::now();
    validate_receipt_inventory(receipts, inventory)?;
    let receipt_scope_validation = receipt_scope_validation_started.elapsed();

    let mut total_bytes = 0u64;
    let mut prepared = Vec::with_capacity(payloads.len());
    let mut inventory_coverage_validation = Duration::ZERO;
    for canonical in payloads {
        let (payload, descriptor, bytes) = canonical.into_parts();
        let inventory_coverage_validation_started = Instant::now();
        validate_payload_inventory(payload.payload(), inventory)?;
        inventory_coverage_validation += inventory_coverage_validation_started.elapsed();
        if bytes.len() as u64 > MAX_PROVIDER_PAYLOAD_BYTES {
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload {} exceeds {MAX_PROVIDER_PAYLOAD_BYTES} bytes",
                descriptor.payload_id.0
            )));
        }
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
            PublicationError::InvalidDraft("provider payload byte total overflowed".into())
        })?;
        if total_bytes > MAX_PROVIDER_PAYLOAD_TOTAL_BYTES {
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload population exceeds {MAX_PROVIDER_PAYLOAD_TOTAL_BYTES} bytes"
            )));
        }
        prepared.push(PreparedProviderPayload {
            payload,
            descriptor,
            bytes,
        });
    }
    finish_prepared_provider_payloads(
        prepared,
        receipts,
        receipt_scope_validation,
        ProviderPayloadCanonicalizationTimings::default(),
        inventory_coverage_validation,
    )
}

fn normalize_and_validate_payload_descriptors(
    descriptors: &mut [ProviderPayloadDescriptor],
    receipts: &[CapabilityReceipt],
) -> Result<(), PublicationError> {
    if descriptors.len() > MAX_PROVIDER_PAYLOADS {
        return Err(PublicationError::InvalidDraft(format!(
            "provider payload descriptor count {} exceeds limit {MAX_PROVIDER_PAYLOADS}",
            descriptors.len()
        )));
    }
    descriptors.sort();
    let receipts_by_id = complete_receipts_by_id(receipts)?;
    let mut payload_ids = BTreeSet::new();
    let mut payload_receipt_ids = BTreeSet::new();
    for descriptor in descriptors.iter() {
        validate_prefixed_sha256("provider payload ID", &descriptor.payload_id.0, "payload-")?;
        validate_label(
            "provider payload schema",
            &descriptor.payload_schema_version,
        )?;
        validate_label("provider payload capability", &descriptor.capability_id)?;
        validate_label("provider payload provider", &descriptor.provider_id.0)?;
        validate_prefixed_sha256(
            "provider payload receipt ID",
            &descriptor.receipt_id.0,
            "receipt-",
        )?;
        validate_sha256("provider payload digest", &descriptor.payload_sha256)?;
        if descriptor.payload_id.0 != format!("payload-{}", descriptor.payload_sha256) {
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload ID {} does not match its digest",
                descriptor.payload_id.0
            )));
        }
        if !payload_ids.insert(descriptor.payload_id.clone()) {
            return Err(PublicationError::InvalidDraft(format!(
                "duplicate provider payload ID {}",
                descriptor.payload_id.0
            )));
        }
        if !payload_receipt_ids.insert(descriptor.receipt_id.clone()) {
            return Err(PublicationError::InvalidDraft(format!(
                "multiple provider payloads claim receipt {}",
                descriptor.receipt_id.0
            )));
        }
        let Some(receipt) = receipts_by_id.get(&descriptor.receipt_id) else {
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload {} has no matching complete manifest receipt",
                descriptor.payload_id.0
            )));
        };
        if descriptor.capability_id != receipt.capability_id
            || descriptor.provider_id != receipt.provider_id
        {
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload {} identity differs from its manifest receipt",
                descriptor.payload_id.0
            )));
        }
    }

    for (receipt_id, receipt) in receipts_by_id {
        if receipt.capability_id == "calls" && !payload_receipt_ids.contains(&receipt_id) {
            return Err(PublicationError::InvalidDraft(format!(
                "complete calls receipt {receipt_id:?} has no matching provider payload"
            )));
        }
    }
    Ok(())
}

fn complete_receipts_by_id(
    receipts: &[CapabilityReceipt],
) -> Result<BTreeMap<CapabilityReceiptId, &CapabilityReceipt>, PublicationError> {
    let mut by_id = BTreeMap::new();
    for receipt in receipts
        .iter()
        .filter(|receipt| receipt.status == CapabilityStatus::Complete)
    {
        let receipt_id = capability_receipt_id(receipt)
            .map_err(|error| PublicationError::InvalidDraft(error.to_string()))?;
        if by_id.insert(receipt_id.clone(), receipt).is_some() {
            return Err(PublicationError::InvalidDraft(format!(
                "duplicate complete receipt identity {}",
                receipt_id.0
            )));
        }
    }
    Ok(by_id)
}

fn validate_receipt_inventory(
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> Result<(), PublicationError> {
    for receipt in receipts {
        let (language_id, project_unit_ids) = match &receipt.scope {
            CapabilityScope::ProjectUnit {
                language_id,
                project_unit_id,
                ..
            } => (language_id, std::slice::from_ref(project_unit_id)),
            CapabilityScope::ProjectUnits {
                language_id,
                project_unit_ids,
                ..
            } => (language_id, project_unit_ids.as_slice()),
            CapabilityScope::Repository { .. } | CapabilityScope::Language { .. } => continue,
        };
        for project_unit_id in project_unit_ids {
            let Some(unit) = inventory
                .project_topology
                .units
                .iter()
                .find(|unit| &unit.project_unit_id == project_unit_id)
            else {
                return Err(PublicationError::InvalidDraft(format!(
                    "receipt references missing project unit {project_unit_id}"
                )));
            };
            if &unit.language_id != language_id {
                return Err(PublicationError::InvalidDraft(format!(
                    "receipt language {language_id} differs from project unit {project_unit_id} language {}",
                    unit.language_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_payload_inventory(
    payload: &ProviderPayload,
    inventory: &ProjectInventory,
) -> Result<(), PublicationError> {
    for document in payload.documents() {
        let owners = inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| {
                membership.document_path == document.document_path
                    && membership.language_id == document.language_id
                    && inventory.is_semantic_source_owner(membership)
            })
            .collect::<Vec<_>>();
        match &payload.receipt().scope {
            CapabilityScope::ProjectUnit {
                project_unit_id, ..
            } if !owners
                .iter()
                .any(|membership| &membership.project_unit_id == project_unit_id) =>
            {
                return Err(PublicationError::InvalidDraft(format!(
                    "provider payload document {} is not owned by receipt project unit {project_unit_id}",
                    document.document_path
                )));
            }
            CapabilityScope::ProjectUnits {
                project_unit_ids, ..
            } if !owners
                .iter()
                .any(|membership| project_unit_ids.contains(&membership.project_unit_id)) =>
            {
                return Err(PublicationError::InvalidDraft(format!(
                    "provider payload document {} is not owned by any project unit in the receipt scope",
                    document.document_path
                )));
            }
            CapabilityScope::Repository { .. } | CapabilityScope::Language { .. }
                if owners.is_empty() =>
            {
                return Err(PublicationError::InvalidDraft(format!(
                    "provider payload document {} has no indexed semantic source owner",
                    document.document_path
                )));
            }
            _ => {}
        }
    }

    // A complete Calls receipt is authoritative for empty results as well as
    // positive occurrences. Its persisted document population must therefore
    // cover every indexed semantic SourceOwner in the declared scope; one-way
    // membership validation would allow a payload to omit callers silently.
    if matches!(
        payload,
        ProviderPayload::Calls(_) | ProviderPayload::CallableLiveness(_)
    ) {
        let scope = &payload.receipt().scope;
        let expected = inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| inventory.is_semantic_source_owner(membership))
            .filter(|membership| match scope {
                CapabilityScope::Repository { .. } => true,
                CapabilityScope::Language { language_id, .. } => {
                    membership.language_id == *language_id
                }
                CapabilityScope::ProjectUnit {
                    language_id,
                    project_unit_id,
                    ..
                } => {
                    membership.language_id == *language_id
                        && membership.project_unit_id == *project_unit_id
                }
                CapabilityScope::ProjectUnits {
                    language_id,
                    project_unit_ids,
                    ..
                } => {
                    membership.language_id == *language_id
                        && project_unit_ids.contains(&membership.project_unit_id)
                }
            })
            .map(|membership| format!("{}:{}", membership.language_id.0, membership.document_path))
            .collect::<BTreeSet<_>>();
        let actual = payload
            .documents()
            .iter()
            .map(|document| format!("{}:{}", document.language_id.0, document.document_path))
            .collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected
                .difference(&actual)
                .take(16)
                .cloned()
                .collect::<Vec<_>>();
            let unexpected = actual
                .difference(&expected)
                .take(16)
                .cloned()
                .collect::<Vec<_>>();
            return Err(PublicationError::InvalidDraft(format!(
                "provider payload document population differs from complete receipt scope; missing={missing:?}, unexpected={unexpected:?}"
            )));
        }
    }
    Ok(())
}

const fn provider_payload_record_count(payload: &ProviderPayload) -> usize {
    match payload {
        ProviderPayload::Calls(payload) => 1usize
            .saturating_add(payload.documents.len())
            .saturating_add(payload.symbols.len())
            .saturating_add(payload.calls.len())
            .saturating_add(payload.callable_bindings.len())
            .saturating_add(payload.coverage_exclusions.len()),
        ProviderPayload::CallableLiveness(payload) => 1usize
            .saturating_add(payload.documents.len())
            .saturating_add(payload.callables.len())
            .saturating_add(payload.coverage_exclusions.len()),
    }
}

fn provider_payload_candidate_counts(candidates: &ProviderPayloadCandidates) -> (usize, usize) {
    let accumulate = |(records, documents): (usize, usize), payload: &ProviderPayload| {
        (
            records.saturating_add(provider_payload_record_count(payload)),
            documents.saturating_add(payload.documents().len()),
        )
    };
    match candidates {
        ProviderPayloadCandidates::Unvalidated(payloads) => {
            payloads.iter().fold((0, 0), accumulate)
        }
        ProviderPayloadCandidates::Canonical(payloads) => payloads
            .iter()
            .map(CanonicalProviderPayload::payload)
            .fold((0, 0), accumulate),
    }
}

fn validate_prefixed_sha256(
    label: &str,
    value: &str,
    prefix: &str,
) -> Result<(), PublicationError> {
    let Some(digest) = value.strip_prefix(prefix) else {
        return Err(PublicationError::InvalidDraft(format!(
            "{label} must start with {prefix}"
        )));
    };
    validate_sha256(label, digest)
}

fn validate_scope(scope: &CapabilityScope) -> Result<(), PublicationError> {
    match scope {
        CapabilityScope::Repository { configuration_id } => {
            validate_label("configuration ID", &configuration_id.0)
        }
        CapabilityScope::Language {
            language_id,
            configuration_id,
        } => {
            validate_label("language ID", &language_id.0)?;
            validate_label("configuration ID", &configuration_id.0)
        }
        CapabilityScope::ProjectUnit {
            language_id,
            project_unit_id,
            configuration_id,
        } => {
            validate_label("language ID", &language_id.0)?;
            validate_label("project-unit ID", &project_unit_id.0)?;
            validate_label("configuration ID", &configuration_id.0)
        }
        CapabilityScope::ProjectUnits {
            language_id,
            project_unit_ids,
            configuration_id,
        } => {
            validate_label("language ID", &language_id.0)?;
            if project_unit_ids.is_empty() {
                return Err(PublicationError::InvalidDraft(
                    "project-unit set must not be empty".into(),
                ));
            }
            for project_unit_id in project_unit_ids {
                validate_label("project-unit ID", &project_unit_id.0)?;
            }
            if project_unit_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(PublicationError::InvalidDraft(
                    "project-unit set must be sorted and unique".into(),
                ));
            }
            validate_label("configuration ID", &configuration_id.0)
        }
    }
}

fn compute_generation_id(manifest: &GenerationManifest) -> Result<GenerationId, PublicationError> {
    #[derive(Serialize)]
    struct GenerationIdentity<'a> {
        schema_version: &'a str,
        repository_id: &'a RepositoryId,
        parent_generation_id: &'a Option<GenerationId>,
        source_revision: &'a Option<String>,
        payload_blake3: &'a str,
        graph_publication_proof: &'a GraphPublicationProof,
        index_state_publication_proof: &'a IndexStatePublicationProof,
        project_inventory_sha256: &'a str,
        receipts: &'a [CapabilityReceipt],
        provider_payloads: &'a [ProviderPayloadDescriptor],
    }
    let identity = GenerationIdentity {
        schema_version: &manifest.schema_version,
        repository_id: &manifest.repository_id,
        parent_generation_id: &manifest.parent_generation_id,
        source_revision: &manifest.source_revision,
        payload_blake3: &manifest.payload_blake3,
        graph_publication_proof: &manifest.graph_publication_proof,
        index_state_publication_proof: &manifest.index_state_publication_proof,
        project_inventory_sha256: &manifest.project_inventory_sha256,
        receipts: &manifest.receipts,
        provider_payloads: &manifest.provider_payloads,
    };
    Ok(GenerationId::new(format!(
        "g-{}",
        sha256_bytes(&canonical_json(&identity)?)
    )))
}

fn seal_head(body: PublicationHeadBody) -> Result<PublicationHead, PublicationError> {
    let digest = sha256_bytes(&canonical_json(&body)?);
    Ok(PublicationHead { body, digest })
}

fn parse_head(path: &Path, bytes: &[u8]) -> Result<PublicationHead, PublicationError> {
    let head: PublicationHead =
        serde_json::from_slice(bytes).map_err(|error| PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: format!("parse publication head: {error}"),
        })?;
    if head.body.schema_version != HEAD_SCHEMA {
        return Err(PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: format!("unsupported head schema {}", head.body.schema_version),
        });
    }
    validate_generation_id(&head.body.generation_id)?;
    validate_blake3("head database digest", &head.body.database_blake3)?;
    validate_sha256("head manifest digest", &head.body.manifest_sha256)?;
    validate_sha256("head receipt-set digest", &head.body.receipt_set_sha256)?;
    validate_sha256(
        "head provider-payload-set digest",
        &head.body.provider_payload_set_sha256,
    )?;
    let expected = sha256_bytes(&canonical_json(&head.body)?);
    if head.digest != expected {
        return Err(PublicationError::DigestMismatch {
            path: path.to_path_buf(),
            expected,
            actual: head.digest,
        });
    }
    Ok(head)
}

fn select_publish_slot(scan: &HeadScan, selected_slot: Option<usize>) -> usize {
    if let Some((slot, _)) = scan.invalid.first() {
        return *slot;
    }
    match selected_slot {
        Some(0) => 1,
        Some(1) => 0,
        _ if !scan.present[0] => 0,
        _ => 1,
    }
}

fn new_repository_record(repository_root: &Path) -> Result<RepositoryRecord, PublicationError> {
    let body = RepositoryRecordBody {
        schema_version: REPOSITORY_SCHEMA.into(),
        repository_id: RepositoryId::new(format!("repo-{}", Uuid::new_v4().simple())),
        root_fingerprint: root_fingerprint(repository_root),
    };
    Ok(RepositoryRecord {
        digest: sha256_bytes(&canonical_json(&body)?),
        body,
    })
}

fn load_repository(
    publication_directory: &Path,
    repository_root: &Path,
) -> Result<RepositoryRecord, PublicationError> {
    let path = publication_directory.join(REPOSITORY_FILE);
    let bytes = read_regular_bounded(&path, MAX_CONTROL_FILE_BYTES)?;
    parse_repository_record(&bytes, &path, publication_directory, repository_root)
}

fn parse_repository_record(
    bytes: &[u8],
    path: &Path,
    publication_directory: &Path,
    repository_root: &Path,
) -> Result<RepositoryRecord, PublicationError> {
    let record: RepositoryRecord =
        serde_json::from_slice(bytes).map_err(|error| PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: format!("parse repository identity: {error}"),
        })?;
    if record.body.schema_version != REPOSITORY_SCHEMA {
        return Err(PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: format!(
                "unsupported repository identity schema {}",
                record.body.schema_version
            ),
        });
    }
    let expected_digest = sha256_bytes(&canonical_json(&record.body)?);
    if record.digest != expected_digest {
        return Err(PublicationError::DigestMismatch {
            path: path.to_path_buf(),
            expected: expected_digest,
            actual: record.digest,
        });
    }
    let actual_root = root_fingerprint(repository_root);
    if record.body.root_fingerprint != actual_root {
        return Err(PublicationError::RootMismatch {
            repository_id: record.body.repository_id,
            publication_directory: publication_directory.to_path_buf(),
            bound_root: repository_root.to_path_buf(),
        });
    }
    Ok(record)
}

fn load_repository_cap(
    publication: &Dir,
    publication_directory: &Path,
    repository_root: &Path,
) -> Result<RepositoryRecord, PublicationError> {
    let path = publication_directory.join(REPOSITORY_FILE);
    let bytes =
        read_cap_regular_bounded(publication, REPOSITORY_FILE, &path, MAX_CONTROL_FILE_BYTES)?;
    parse_repository_record(&bytes, &path, publication_directory, repository_root)
}

fn load_or_create_repository_cap(
    publication: &Dir,
    publication_directory: &Path,
    repository_root: &Path,
) -> Result<RepositoryRecord, PublicationError> {
    let path = publication_directory.join(REPOSITORY_FILE);
    match publication.symlink_metadata(REPOSITORY_FILE) {
        Ok(_) => return load_repository_cap(publication, publication_directory, repository_root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect descriptor-relative repository identity",
                path,
                source,
            });
        }
    }

    let mut surviving = publication
        .entries()
        .map_err(|source| PublicationError::Io {
            operation: "inspect descriptor-relative publication state before identity creation",
            path: publication_directory.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|source| PublicationError::Io {
                    operation:
                        "inspect descriptor-relative publication child before identity creation",
                    path: publication_directory.to_path_buf(),
                    source,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    surviving.sort();
    if surviving.iter().any(|name| name == REPOSITORY_FILE) {
        return load_repository_cap(publication, publication_directory, repository_root);
    }
    if !surviving.is_empty() {
        return Err(PublicationError::MissingRepositoryIdentity { path, surviving });
    }
    let record = new_repository_record(repository_root)?;
    let bytes = canonical_json(&record)?;
    match write_new_cap_synced(publication, REPOSITORY_FILE, &path, &bytes) {
        Ok(()) => {}
        Err(PublicationError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            return load_repository_cap(publication, publication_directory, repository_root);
        }
        Err(error) => return Err(error),
    }
    sync_cap_directory(publication, publication_directory)?;
    Ok(record)
}

fn prepare_recovery_repository_cap(
    publication: &Dir,
    publication_directory: &Path,
    repository_root: &Path,
) -> Result<(RepositoryRecord, bool), PublicationError> {
    let path = publication_directory.join(REPOSITORY_FILE);
    match publication.symlink_metadata(REPOSITORY_FILE) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(PublicationError::UnsafeArtifact {
                path,
                expected: "regular repository identity file",
            });
        }
        Ok(_) => match load_repository_cap(publication, publication_directory, repository_root) {
            Ok(repository) => return Ok((repository, false)),
            Err(
                PublicationError::RootMismatch { .. }
                | PublicationError::InvalidControl { .. }
                | PublicationError::DigestMismatch { .. }
                | PublicationError::ControlTooLarge { .. },
            ) => {}
            Err(error) => return Err(error),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect descriptor-relative repository identity for recovery",
                path,
                source,
            });
        }
    }
    Ok((new_repository_record(repository_root)?, true))
}

fn write_repository_record_cap(
    publication: &Dir,
    publication_directory: &Path,
    repository: &RepositoryRecord,
) -> Result<(), PublicationError> {
    let bytes = canonical_json(repository)?;
    let destination = publication_directory.join(REPOSITORY_FILE);
    if bytes.len() as u64 > MAX_CONTROL_FILE_BYTES {
        return Err(PublicationError::ControlTooLarge {
            path: destination,
            limit: MAX_CONTROL_FILE_BYTES,
            actual: bytes.len() as u64,
        });
    }
    let temporary_name = format!(".repository-{}.tmp", Uuid::new_v4().simple());
    let temporary = publication_directory.join(&temporary_name);
    write_new_cap_synced(publication, &temporary_name, &temporary, &bytes)?;
    match publication.symlink_metadata(REPOSITORY_FILE) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(PublicationError::UnsafeArtifact {
                path: destination,
                expected: "regular repository identity file",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect descriptor-relative repository identity destination",
                path: destination,
                source,
            });
        }
    }
    publication
        .rename(&temporary_name, publication, REPOSITORY_FILE)
        .map_err(|source| PublicationError::Io {
            operation: "atomically replace descriptor-relative repository identity",
            path: destination,
            source,
        })?;
    sync_cap_directory(publication, publication_directory)
}

fn write_head_cap(
    publication: &Dir,
    publication_directory: &Path,
    slot: usize,
    head: &PublicationHead,
) -> Result<(), PublicationError> {
    let bytes = canonical_json(head)?;
    let destination = publication_directory.join(HEAD_FILES[slot]);
    if bytes.len() as u64 > MAX_CONTROL_FILE_BYTES {
        return Err(PublicationError::ControlTooLarge {
            path: destination,
            limit: MAX_CONTROL_FILE_BYTES,
            actual: bytes.len() as u64,
        });
    }
    let temporary_name = format!(".head-{}-{}.tmp", slot, Uuid::new_v4().simple());
    let temporary = publication_directory.join(&temporary_name);
    write_new_cap_synced(publication, &temporary_name, &temporary, &bytes)?;
    match publication.symlink_metadata(HEAD_FILES[slot]) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(PublicationError::UnsafeArtifact {
                path: destination,
                expected: "regular head file",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect descriptor-relative publication head destination",
                path: destination,
                source,
            });
        }
    }
    publication
        .rename(&temporary_name, publication, HEAD_FILES[slot])
        .map_err(|source| PublicationError::Io {
            operation: "atomically replace descriptor-relative publication head",
            path: destination,
            source,
        })?;
    sync_cap_directory(publication, publication_directory)
}

fn scan_heads_cap(
    publication: &Dir,
    publication_directory: &Path,
) -> Result<HeadScan, PublicationError> {
    scan_heads_cap_with_conflict_policy(publication, publication_directory, true)
}

fn scan_heads_cap_for_recovery(
    publication: &Dir,
    publication_directory: &Path,
) -> Result<HeadScan, PublicationError> {
    scan_heads_cap_with_conflict_policy(publication, publication_directory, false)
}

fn scan_heads_cap_with_conflict_policy(
    publication: &Dir,
    publication_directory: &Path,
    reject_conflict: bool,
) -> Result<HeadScan, PublicationError> {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    let mut present = [false; 2];
    let mut controls = std::array::from_fn(|_| HeadControlState::Missing);
    for (slot, file_name) in HEAD_FILES.iter().enumerate() {
        let path = publication_directory.join(file_name);
        let bytes = match read_optional_cap_regular_bounded(
            publication,
            file_name,
            &path,
            MAX_CONTROL_FILE_BYTES,
        ) {
            Ok(Some(bytes)) => {
                present[slot] = true;
                bytes
            }
            Ok(None) => continue,
            Err(error) => {
                present[slot] = true;
                let reason = error.to_string();
                controls[slot] = HeadControlState::Invalid {
                    content_sha256: None,
                    reason: reason.clone(),
                };
                invalid.push((slot, reason));
                continue;
            }
        };
        match parse_head(&path, &bytes) {
            Ok(head) => {
                controls[slot] = HeadControlState::Valid {
                    digest: head.digest.clone(),
                };
                valid.push(HeadCandidate { slot, head });
            }
            Err(error) => {
                let reason = error.to_string();
                controls[slot] = HeadControlState::Invalid {
                    content_sha256: Some(sha256_bytes(&bytes)),
                    reason: reason.clone(),
                };
                invalid.push((slot, reason));
            }
        }
    }
    if reject_conflict
        && valid.len() == 2
        && valid[0].head.body.sequence == valid[1].head.body.sequence
        && valid[0].head != valid[1].head
    {
        return Err(PublicationError::HeadConflict {
            sequence: valid[0].head.body.sequence,
            first: valid[0].head.body.generation_id.clone(),
            second: valid[1].head.body.generation_id.clone(),
        });
    }
    valid.sort_by(|left, right| {
        right
            .head
            .body
            .sequence
            .cmp(&left.head.body.sequence)
            .then_with(|| left.slot.cmp(&right.slot))
    });
    Ok(HeadScan {
        valid,
        invalid,
        present,
        controls,
    })
}

fn write_project_inventory(
    database: &Database,
    path: &Path,
    inventory: &[u8],
) -> Result<(), PublicationError> {
    let transaction = database
        .begin_write()
        .map_err(|error| PublicationError::Redb {
            operation: "begin project inventory transaction",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    {
        let mut table =
            transaction
                .open_table(PROJECT_INVENTORY)
                .map_err(|error| PublicationError::Redb {
                    operation: "open project inventory table",
                    path: path.to_path_buf(),
                    error: error.to_string(),
                })?;
        let occupied = table
            .get(PROJECT_INVENTORY_KEY)
            .map_err(|error| PublicationError::Redb {
                operation: "inspect reserved project inventory value",
                path: path.to_path_buf(),
                error: error.to_string(),
            })?
            .is_some();
        if occupied {
            return Err(PublicationError::InvalidDraft(
                "the project inventory table is reserved for the publisher".into(),
            ));
        }
        table
            .insert(PROJECT_INVENTORY_KEY, inventory)
            .map_err(|error| PublicationError::Redb {
                operation: "write project inventory",
                path: path.to_path_buf(),
                error: error.to_string(),
            })?;
    }
    transaction
        .commit()
        .map_err(|error| PublicationError::Redb {
            operation: "commit project inventory",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    Ok(())
}

fn write_provider_payloads(
    database: &Database,
    path: &Path,
    payloads: &[PreparedProviderPayload],
) -> Result<(), PublicationError> {
    let transaction = database
        .begin_write()
        .map_err(|error| PublicationError::Redb {
            operation: "begin provider payload transaction",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    {
        let mut table =
            transaction
                .open_table(PROVIDER_PAYLOADS)
                .map_err(|error| PublicationError::Redb {
                    operation: "open provider payload table",
                    path: path.to_path_buf(),
                    error: error.to_string(),
                })?;
        let occupied = table
            .iter()
            .map_err(|error| PublicationError::Redb {
                operation: "inspect reserved provider payload table",
                path: path.to_path_buf(),
                error: error.to_string(),
            })?
            .next()
            .transpose()
            .map_err(|error| PublicationError::Redb {
                operation: "read reserved provider payload table entry",
                path: path.to_path_buf(),
                error: error.to_string(),
            })?
            .is_some();
        if occupied {
            return Err(PublicationError::InvalidDraft(
                "the provider payload table is reserved for the publisher".into(),
            ));
        }
        for payload in payloads {
            table
                .insert(
                    payload.descriptor.payload_id.0.as_str(),
                    payload.bytes.as_slice(),
                )
                .map_err(|error| PublicationError::Redb {
                    operation: "write provider payload",
                    path: path.to_path_buf(),
                    error: error.to_string(),
                })?;
        }
    }
    transaction
        .commit()
        .map_err(|error| PublicationError::Redb {
            operation: "commit provider payloads",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    Ok(())
}

fn read_project_inventory(
    path: &Path,
    expected_sha256: &str,
) -> Result<ProjectInventory, PublicationError> {
    let database = ReadOnlyDatabase::open(path).map_err(|error| PublicationError::Redb {
        operation: "open immutable generation database for project inventory",
        path: path.to_path_buf(),
        error: error.to_string(),
    })?;
    read_project_inventory_from_database(&database, path, expected_sha256)
}

fn read_project_inventory_from_database<D: ReadableDatabase>(
    database: &D,
    path: &Path,
    expected_sha256: &str,
) -> Result<ProjectInventory, PublicationError> {
    let transaction = database
        .begin_read()
        .map_err(|error| PublicationError::Redb {
            operation: "begin project inventory read",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    let table = transaction.open_table(PROJECT_INVENTORY).map_err(|error| {
        PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: format!("open project inventory table: {error}"),
        }
    })?;
    let value = table
        .get(PROJECT_INVENTORY_KEY)
        .map_err(|error| PublicationError::Redb {
            operation: "read project inventory",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?
        .ok_or_else(|| PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: "project inventory is absent".into(),
        })?;
    if value.value().len() as u64 > MAX_PROJECT_INVENTORY_BYTES {
        return Err(PublicationError::ControlTooLarge {
            path: path.to_path_buf(),
            limit: MAX_PROJECT_INVENTORY_BYTES,
            actual: value.value().len() as u64,
        });
    }
    let bytes = value.value().to_vec();
    let actual_sha256 = sha256_bytes(&bytes);
    if actual_sha256 != expected_sha256 {
        return Err(PublicationError::DigestMismatch {
            path: path.to_path_buf(),
            expected: expected_sha256.into(),
            actual: actual_sha256,
        });
    }
    parse_project_inventory_bytes(&bytes).map_err(|error| PublicationError::InvalidControl {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

fn read_provider_payloads(
    path: &Path,
    descriptors: &[ProviderPayloadDescriptor],
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> Result<Vec<NormalizedProviderPayload>, PublicationError> {
    let database = ReadOnlyDatabase::open(path).map_err(|error| PublicationError::Redb {
        operation: "open immutable generation database for provider payloads",
        path: path.to_path_buf(),
        error: error.to_string(),
    })?;
    read_provider_payloads_from_database(&database, path, descriptors, receipts, inventory)
}

fn read_provider_payloads_from_database<D: ReadableDatabase>(
    database: &D,
    path: &Path,
    descriptors: &[ProviderPayloadDescriptor],
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> Result<Vec<NormalizedProviderPayload>, PublicationError> {
    validate_receipt_inventory(receipts, inventory).map_err(|error| {
        PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    let receipt_by_id =
        complete_receipts_by_id(receipts).map_err(|error| PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let descriptor_by_id = descriptors
        .iter()
        .map(|descriptor| (descriptor.payload_id.0.as_str(), descriptor))
        .collect::<BTreeMap<_, _>>();
    let transaction = database
        .begin_read()
        .map_err(|error| PublicationError::Redb {
            operation: "begin provider payload read",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    let table = transaction.open_table(PROVIDER_PAYLOADS).map_err(|error| {
        PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: format!("open provider payload table: {error}"),
        }
    })?;

    let mut total_bytes = 0u64;
    let mut payload_by_id = BTreeMap::new();
    let entries = table.iter().map_err(|error| PublicationError::Redb {
        operation: "iterate provider payload table",
        path: path.to_path_buf(),
        error: error.to_string(),
    })?;
    for entry in entries {
        let (key, value) = entry.map_err(|error| PublicationError::Redb {
            operation: "read provider payload table entry",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
        let payload_id = key.value().to_owned();
        let Some(descriptor) = descriptor_by_id.get(payload_id.as_str()).copied() else {
            return Err(PublicationError::InvalidControl {
                path: path.to_path_buf(),
                reason: format!("orphan provider payload table entry {payload_id}"),
            });
        };
        let bytes = value.value();
        if bytes.len() as u64 > MAX_PROVIDER_PAYLOAD_BYTES {
            return Err(PublicationError::ControlTooLarge {
                path: path.to_path_buf(),
                limit: MAX_PROVIDER_PAYLOAD_BYTES,
                actual: bytes.len() as u64,
            });
        }
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
            PublicationError::InvalidControl {
                path: path.to_path_buf(),
                reason: "provider payload byte total overflowed".into(),
            }
        })?;
        if total_bytes > MAX_PROVIDER_PAYLOAD_TOTAL_BYTES {
            return Err(PublicationError::ControlTooLarge {
                path: path.to_path_buf(),
                limit: MAX_PROVIDER_PAYLOAD_TOTAL_BYTES,
                actual: total_bytes,
            });
        }
        let actual_sha256 = sha256_bytes(bytes);
        if actual_sha256 != descriptor.payload_sha256 {
            return Err(PublicationError::DigestMismatch {
                path: path.to_path_buf(),
                expected: descriptor.payload_sha256.clone(),
                actual: actual_sha256,
            });
        }
        let canonical = parse_canonical_provider_payload_bytes(bytes).map_err(|error| {
            PublicationError::InvalidControl {
                path: path.to_path_buf(),
                reason: error.to_string(),
            }
        })?;
        let actual_descriptor = canonical.descriptor();
        if actual_descriptor != descriptor {
            return Err(PublicationError::InvalidControl {
                path: path.to_path_buf(),
                reason: format!("provider payload descriptor mismatch for {payload_id}"),
            });
        }
        let Some(receipt) = receipt_by_id.get(&descriptor.receipt_id) else {
            return Err(PublicationError::InvalidControl {
                path: path.to_path_buf(),
                reason: format!("provider payload {payload_id} has no manifest receipt"),
            });
        };
        if canonical.payload().receipt() != *receipt {
            return Err(PublicationError::InvalidControl {
                path: path.to_path_buf(),
                reason: format!("provider payload {payload_id} receipt mismatch"),
            });
        }
        validate_payload_inventory(canonical.payload(), inventory).map_err(|error| {
            PublicationError::InvalidControl {
                path: path.to_path_buf(),
                reason: error.to_string(),
            }
        })?;
        payload_by_id.insert(ProviderPayloadId(payload_id), canonical.into_normalized());
    }

    if payload_by_id.len() != descriptors.len() {
        let missing = descriptors
            .iter()
            .find(|descriptor| !payload_by_id.contains_key(&descriptor.payload_id))
            .expect("different populations have a missing descriptor");
        return Err(PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: format!(
                "provider payload {} is absent from the immutable generation",
                missing.payload_id.0
            ),
        });
    }
    Ok(descriptors
        .iter()
        .map(|descriptor| {
            payload_by_id
                .remove(&descriptor.payload_id)
                .expect("payload population was validated")
        })
        .collect())
}

fn write_manifest_cap(
    staging: &Dir,
    database_path: &Path,
    manifest: &[u8],
) -> Result<(), PublicationError> {
    let file = staging
        .open_with(
            GENERATION_DATABASE_FILE,
            &cap_read_write_options(false, false),
        )
        .map_err(|source| PublicationError::Io {
            operation: "open descriptor-relative private generation database for manifest",
            path: database_path.to_path_buf(),
            source,
        })?
        .into_std();
    let database =
        Database::builder()
            .create_file(file)
            .map_err(|error| PublicationError::Redb {
                operation: "open descriptor-relative private generation database for manifest",
                path: database_path.to_path_buf(),
                error: error.to_string(),
            })?;
    write_manifest_to_database(&database, database_path, manifest)?;
    drop(database);
    Ok(())
}

fn write_manifest_to_database(
    database: &Database,
    path: &Path,
    manifest: &[u8],
) -> Result<(), PublicationError> {
    let transaction = database
        .begin_write()
        .map_err(|error| PublicationError::Redb {
            operation: "begin generation manifest transaction",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    {
        let mut table =
            transaction
                .open_table(PUBLICATION_META)
                .map_err(|error| PublicationError::Redb {
                    operation: "open generation manifest table",
                    path: path.to_path_buf(),
                    error: error.to_string(),
                })?;
        table
            .insert(MANIFEST_KEY, manifest)
            .map_err(|error| PublicationError::Redb {
                operation: "write generation manifest",
                path: path.to_path_buf(),
                error: error.to_string(),
            })?;
    }
    transaction
        .commit()
        .map_err(|error| PublicationError::Redb {
            operation: "commit generation manifest",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    Ok(())
}

fn read_manifest(path: &Path) -> Result<Vec<u8>, PublicationError> {
    let database = ReadOnlyDatabase::open(path).map_err(|error| PublicationError::Redb {
        operation: "open immutable generation database read-only",
        path: path.to_path_buf(),
        error: error.to_string(),
    })?;
    read_manifest_from_database(&database, path)
}

fn read_manifest_from_database<D: ReadableDatabase>(
    database: &D,
    path: &Path,
) -> Result<Vec<u8>, PublicationError> {
    let transaction = database
        .begin_read()
        .map_err(|error| PublicationError::Redb {
            operation: "begin generation manifest read",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?;
    let table =
        transaction
            .open_table(PUBLICATION_META)
            .map_err(|error| PublicationError::Redb {
                operation: "open generation manifest table read-only",
                path: path.to_path_buf(),
                error: error.to_string(),
            })?;
    let value = table
        .get(MANIFEST_KEY)
        .map_err(|error| PublicationError::Redb {
            operation: "read generation manifest",
            path: path.to_path_buf(),
            error: error.to_string(),
        })?
        .ok_or_else(|| PublicationError::InvalidControl {
            path: path.to_path_buf(),
            reason: "generation manifest is absent".into(),
        })?;
    if value.value().len() as u64 > MAX_MANIFEST_BYTES {
        return Err(PublicationError::ControlTooLarge {
            path: path.to_path_buf(),
            limit: MAX_MANIFEST_BYTES,
            actual: value.value().len() as u64,
        });
    }
    Ok(value.value().to_vec())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, PublicationError> {
    serde_json::to_vec(value).map_err(|error| PublicationError::Serialization(error.to_string()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    finish_sha256(hasher)
}

#[cfg(test)]
fn sha256_file(path: &Path) -> Result<String, PublicationError> {
    require_regular_file(path, "file to hash")?;
    let mut file = File::open(path).map_err(|source| PublicationError::Io {
        operation: "open file for SHA-256",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| PublicationError::Io {
                operation: "read file for SHA-256",
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(finish_sha256(hasher))
}

fn blake3_file(path: &Path) -> Result<String, PublicationError> {
    blake3_file_counted(path).map(|(digest, _bytes)| digest)
}

fn blake3_file_counted(path: &Path) -> Result<(String, u64), PublicationError> {
    require_regular_file(path, "file to hash")?;
    let mut file = File::open(path).map_err(|source| PublicationError::Io {
        operation: "open file for BLAKE3",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes_hashed = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| PublicationError::Io {
                operation: "read file for BLAKE3",
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        bytes_hashed = bytes_hashed.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    Ok((hasher.finalize().to_hex().to_string(), bytes_hashed))
}

fn root_fingerprint(root: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"h00-repository-root-v1\0");
    hasher.update(root.as_os_str().as_encoded_bytes());
    finish_sha256(hasher)
}

fn finish_sha256(hasher: Sha256) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest.iter().copied() {
        encoded.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn validate_generation_id(generation_id: &GenerationId) -> Result<(), PublicationError> {
    let Some(digest) = generation_id.0.strip_prefix("g-") else {
        return Err(PublicationError::InvalidDraft(format!(
            "invalid generation ID {}",
            generation_id.0
        )));
    };
    validate_sha256("generation ID", digest)
}

fn cleanup_generation_population_cap(
    publication: &Dir,
    publication_directory: &Path,
    generations: &Dir,
    generations_directory: &Path,
) -> PublicationMaintenance {
    let mut maintenance = PublicationMaintenance::default();
    let scan = match scan_heads_cap(publication, publication_directory) {
        Ok(scan) => scan,
        Err(error) => {
            maintenance
                .warnings
                .push(format!("head scan blocked generation cleanup: {error}"));
            return maintenance;
        }
    };
    let retain = scan
        .valid
        .iter()
        .map(|candidate| candidate.head.body.generation_id.0.as_str())
        .collect::<BTreeSet<_>>();
    let delete_unreferenced_generations = scan.invalid.is_empty();
    if !delete_unreferenced_generations {
        maintenance
            .warnings
            .push("invalid head control preserved all finalized generations for recovery".into());
    }

    let entries = match generations.entries() {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>(),
        Err(error) => {
            maintenance.warnings.push(format!(
                "could not enumerate immutable generation population: {error}"
            ));
            return maintenance;
        }
    };
    let mut entries = match entries {
        Ok(entries) => entries,
        Err(error) => {
            maintenance.warnings.push(format!(
                "could not inspect immutable generation population: {error}"
            ));
            return maintenance;
        }
    };
    entries.sort_by_key(cap_std::fs::DirEntry::file_name);

    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let staging = name
            .strip_prefix(".staging-")
            .is_some_and(valid_simple_uuid);
        let interrupted_cleanup = name.strip_prefix(".gc-").is_some_and(valid_simple_uuid);
        let generation = is_generation_directory_name(&name);
        let unreferenced_generation =
            delete_unreferenced_generations && generation && !retain.contains(name.as_str());
        if !(staging || interrupted_cleanup || unreferenced_generation) {
            continue;
        }
        match quarantine_and_remove_directory_cap(generations, generations_directory, &name) {
            Ok(()) => maintenance.removed.push(name),
            Err(error) => maintenance
                .warnings
                .push(format!("could not reclaim {name}: {error}")),
        }
    }
    maintenance
}

fn valid_simple_uuid(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_generation_directory_name(value: &str) -> bool {
    value.strip_prefix("g-").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn quarantine_and_remove_directory_cap(
    parent: &Dir,
    parent_path: &Path,
    name: &str,
) -> Result<(), PublicationError> {
    let quarantine_name = format!(".gc-{}", Uuid::new_v4().simple());
    let path = parent_path.join(name);
    let quarantine = parent_path.join(&quarantine_name);
    parent
        .rename(name, parent, &quarantine_name)
        .map_err(|source| PublicationError::Io {
            operation: "quarantine descriptor-relative unreferenced generation directory",
            path: path.clone(),
            source,
        })?;
    sync_cap_directory(parent, parent_path)?;
    match parent.symlink_metadata(&quarantine_name) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            let _ = parent.rename(&quarantine_name, parent, name);
            return Err(PublicationError::UnsafeArtifact {
                path,
                expected: "owned generation directory",
            });
        }
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect descriptor-relative quarantined generation directory",
                path: quarantine,
                source,
            });
        }
    }
    parent
        .remove_dir_all(&quarantine_name)
        .map_err(|source| PublicationError::Io {
            operation: "remove descriptor-relative quarantined generation directory",
            path: quarantine,
            source,
        })?;
    sync_cap_directory(parent, parent_path)
}

fn ensure_cap_directory(
    parent: &Dir,
    name: &str,
    display_path: &Path,
    operation: &'static str,
) -> Result<Dir, PublicationError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(PublicationError::UnsafeArtifact {
                path: display_path.to_path_buf(),
                expected: "directory",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            parent
                .create_dir(name)
                .map_err(|source| PublicationError::Io {
                    operation,
                    path: display_path.to_path_buf(),
                    source,
                })?;
            sync_cap_directory(parent, display_path.parent().unwrap_or(display_path))?;
        }
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect descriptor-relative directory",
                path: display_path.to_path_buf(),
                source,
            });
        }
    }
    parent
        .open_dir(name)
        .map_err(|source| PublicationError::Io {
            operation: "open descriptor-relative directory",
            path: display_path.to_path_buf(),
            source,
        })
}

fn require_cap_directory(
    parent: &Dir,
    name: &str,
    display_path: &Path,
) -> Result<Dir, PublicationError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            parent
                .open_dir(name)
                .map_err(|source| PublicationError::Io {
                    operation: "open required descriptor-relative directory",
                    path: display_path.to_path_buf(),
                    source,
                })
        }
        Ok(_) => Err(PublicationError::UnsafeArtifact {
            path: display_path.to_path_buf(),
            expected: "directory",
        }),
        Err(source) => Err(PublicationError::Io {
            operation: "inspect required descriptor-relative directory",
            path: display_path.to_path_buf(),
            source,
        }),
    }
}

fn cap_read_options() -> CapOpenOptions {
    let mut options = CapOpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
}

fn cap_read_write_options(create: bool, create_new: bool) -> CapOpenOptions {
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .create_new(create_new)
        .truncate(false);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
}

fn open_cap_regular_lock(
    directory: &Dir,
    name: &str,
    display_path: &Path,
) -> Result<File, PublicationError> {
    match directory.symlink_metadata(name) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(PublicationError::UnsafeArtifact {
                path: display_path.to_path_buf(),
                expected: "regular writer lock file",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect descriptor-relative publication writer lock",
                path: display_path.to_path_buf(),
                source,
            });
        }
    }
    directory
        .open_with(name, &cap_read_write_options(true, false))
        .map(cap_std::fs::File::into_std)
        .map_err(|source| PublicationError::Io {
            operation: "open descriptor-relative publication writer lock",
            path: display_path.to_path_buf(),
            source,
        })
}

fn read_optional_cap_regular_bounded(
    directory: &Dir,
    name: &str,
    display_path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>, PublicationError> {
    match directory.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_file() => {
            if metadata.len() > limit {
                return Err(PublicationError::ControlTooLarge {
                    path: display_path.to_path_buf(),
                    limit,
                    actual: metadata.len(),
                });
            }
        }
        Ok(_) => {
            return Err(PublicationError::UnsafeArtifact {
                path: display_path.to_path_buf(),
                expected: "regular control file",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect descriptor-relative control file",
                path: display_path.to_path_buf(),
                source,
            });
        }
    }
    read_cap_regular_bounded(directory, name, display_path, limit).map(Some)
}

fn read_cap_regular_bounded(
    directory: &Dir,
    name: &str,
    display_path: &Path,
    limit: u64,
) -> Result<Vec<u8>, PublicationError> {
    let metadata = directory
        .symlink_metadata(name)
        .map_err(|source| PublicationError::Io {
            operation: "inspect descriptor-relative bounded file",
            path: display_path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_file() {
        return Err(PublicationError::UnsafeArtifact {
            path: display_path.to_path_buf(),
            expected: "regular bounded control file",
        });
    }
    if metadata.len() > limit {
        return Err(PublicationError::ControlTooLarge {
            path: display_path.to_path_buf(),
            limit,
            actual: metadata.len(),
        });
    }
    let mut file = directory
        .open_with(name, &cap_read_options())
        .map_err(|source| PublicationError::Io {
            operation: "open descriptor-relative bounded file",
            path: display_path.to_path_buf(),
            source,
        })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| PublicationError::Io {
            operation: "read descriptor-relative bounded file",
            path: display_path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(PublicationError::ControlTooLarge {
            path: display_path.to_path_buf(),
            limit,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

fn write_new_cap_synced(
    directory: &Dir,
    name: &str,
    display_path: &Path,
    bytes: &[u8],
) -> Result<(), PublicationError> {
    let mut file = directory
        .open_with(name, &cap_read_write_options(false, true))
        .map_err(|source| PublicationError::Io {
            operation: "create descriptor-relative publication control file",
            path: display_path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes)
        .map_err(|source| PublicationError::Io {
            operation: "write descriptor-relative publication control file",
            path: display_path.to_path_buf(),
            source,
        })?;
    sync_file(&file.into_std()).map_err(|source| PublicationError::Io {
        operation: "durably sync descriptor-relative publication control file",
        path: display_path.to_path_buf(),
        source,
    })
}

fn sync_cap_regular_file(
    directory: &Dir,
    name: &str,
    display_path: &Path,
) -> Result<(), PublicationError> {
    let metadata = directory
        .symlink_metadata(name)
        .map_err(|source| PublicationError::Io {
            operation: "inspect descriptor-relative file for durable sync",
            path: display_path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_file() {
        return Err(PublicationError::UnsafeArtifact {
            path: display_path.to_path_buf(),
            expected: "regular file to synchronize",
        });
    }
    let file = directory
        .open_with(name, &cap_read_write_options(false, false))
        .map_err(|source| PublicationError::Io {
            operation: "open descriptor-relative file for durable sync",
            path: display_path.to_path_buf(),
            source,
        })?;
    sync_file(&file.into_std()).map_err(|source| PublicationError::Io {
        operation: "durably sync descriptor-relative file",
        path: display_path.to_path_buf(),
        source,
    })
}

fn blake3_cap_file(
    directory: &Dir,
    name: &str,
    display_path: &Path,
) -> Result<String, PublicationError> {
    let metadata = directory
        .symlink_metadata(name)
        .map_err(|source| PublicationError::Io {
            operation: "inspect descriptor-relative file for BLAKE3",
            path: display_path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_file() {
        return Err(PublicationError::UnsafeArtifact {
            path: display_path.to_path_buf(),
            expected: "regular file to hash",
        });
    }
    let mut file = directory
        .open_with(name, &cap_read_options())
        .map_err(|source| PublicationError::Io {
            operation: "open descriptor-relative file for BLAKE3",
            path: display_path.to_path_buf(),
            source,
        })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| PublicationError::Io {
                operation: "read descriptor-relative file for BLAKE3",
                path: display_path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn sync_cap_directory(directory: &Dir, display_path: &Path) -> Result<(), PublicationError> {
    let file = directory
        .open(".")
        .map_err(|source| PublicationError::Io {
            operation: "open descriptor-relative directory for durable sync",
            path: display_path.to_path_buf(),
            source,
        })?
        .into_std();
    sync_file(&file).map_err(|source| PublicationError::Io {
        operation: "durably sync descriptor-relative directory",
        path: display_path.to_path_buf(),
        source,
    })
}

fn verify_cap_child_binding(
    parent: &Dir,
    name: &str,
    expected: &DirectoryIdentity,
    display_path: &Path,
) -> Result<(), PublicationError> {
    let current = require_cap_directory(parent, name, display_path)?;
    let actual =
        DirectoryIdentity::from_directory(&current).map_err(|source| PublicationError::Io {
            operation: "identify descriptor-relative directory",
            path: display_path.to_path_buf(),
            source,
        })?;
    if &actual != expected {
        return Err(PublicationError::PathBindingChanged {
            path: display_path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<(), PublicationError> {
    validate_256_bit_hex_digest(label, value)
}

fn validate_blake3(label: &str, value: &str) -> Result<(), PublicationError> {
    validate_256_bit_hex_digest(label, value)
}

fn validate_256_bit_hex_digest(label: &str, value: &str) -> Result<(), PublicationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PublicationError::InvalidDraft(format!(
            "{label} must be a 256-bit lowercase hexadecimal digest"
        )));
    }
    Ok(())
}

fn validate_label(label: &str, value: &str) -> Result<(), PublicationError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(|character| character.is_control())
    {
        return Err(PublicationError::InvalidDraft(format!(
            "{label} must be non-empty, at most 256 bytes, and contain no control characters"
        )));
    }
    Ok(())
}

fn validate_optional_label(label: &str, value: Option<&str>) -> Result<(), PublicationError> {
    if let Some(value) = value {
        validate_label(label, value)?;
    }
    Ok(())
}

fn canonical_directory(path: &Path, operation: &'static str) -> Result<PathBuf, PublicationError> {
    let canonical = fs::canonicalize(path).map_err(|source| PublicationError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })?;
    require_directory(&canonical, "canonical directory")?;
    Ok(canonical)
}

fn require_directory(path: &Path, expected: &'static str) -> Result<(), PublicationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(PublicationError::UnsafeArtifact {
            path: path.to_path_buf(),
            expected,
        }),
        Err(source) => Err(PublicationError::Io {
            operation: "inspect required directory",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn require_regular_file(path: &Path, expected: &'static str) -> Result<(), PublicationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(PublicationError::UnsafeArtifact {
            path: path.to_path_buf(),
            expected,
        }),
        Err(source) => Err(PublicationError::Io {
            operation: "inspect required regular file",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_optional_regular_bounded(
    path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>, PublicationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            if metadata.len() > limit {
                return Err(PublicationError::ControlTooLarge {
                    path: path.to_path_buf(),
                    limit,
                    actual: metadata.len(),
                });
            }
        }
        Ok(_) => {
            return Err(PublicationError::UnsafeArtifact {
                path: path.to_path_buf(),
                expected: "regular control file",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(PublicationError::Io {
                operation: "inspect optional control file",
                path: path.to_path_buf(),
                source,
            });
        }
    }
    read_regular_bounded(path, limit).map(Some)
}

fn read_regular_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, PublicationError> {
    require_regular_file(path, "regular bounded control file")?;
    let metadata = fs::metadata(path).map_err(|source| PublicationError::Io {
        operation: "inspect bounded control file",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > limit {
        return Err(PublicationError::ControlTooLarge {
            path: path.to_path_buf(),
            limit,
            actual: metadata.len(),
        });
    }
    let file = File::open(path).map_err(|source| PublicationError::Io {
        operation: "open bounded control file",
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| PublicationError::Io {
            operation: "read bounded control file",
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(PublicationError::ControlTooLarge {
            path: path.to_path_buf(),
            limit,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

fn sync_file(file: &File) -> std::io::Result<()> {
    file.sync_all()?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PublicationError {
    #[error("graph directory changed after indexing was prepared: {path}")]
    PathBindingChanged { path: PathBuf },
    #[error("another semantic publisher holds {path}")]
    WriterBusy { path: PathBuf },
    #[error("no semantic publication exists at {path}")]
    Unpublished { path: PathBuf },
    #[error("publication has no valid head at {path}: {details:?}")]
    NoValidHead {
        path: PathBuf,
        details: Vec<(usize, String)>,
    },
    #[error("publication has no valid referenced generation at {path}: {details:?}")]
    NoValidGeneration {
        path: PathBuf,
        details: Vec<(usize, String)>,
    },
    #[error("publication contains only incompatible generation schemas at {path}: {details:?}")]
    NoCompatibleGenerationSchema {
        path: PathBuf,
        details: Vec<(usize, String)>,
    },
    #[error("incompatible generation schema at {path}: expected {expected}, found {actual}")]
    IncompatibleGenerationSchema {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error(
        "publication is missing repository identity at {path} while controlled state survives: {surviving:?}"
    )]
    MissingRepositoryIdentity {
        path: PathBuf,
        surviving: Vec<String>,
    },
    #[error("publication heads conflict at sequence {sequence}: {first} versus {second}")]
    HeadConflict {
        sequence: u64,
        first: GenerationId,
        second: GenerationId,
    },
    #[error("publication repository mismatch: expected {expected}, found {actual}")]
    RepositoryMismatch {
        expected: RepositoryId,
        actual: RepositoryId,
    },
    #[error(
        "publication at {publication_directory} belongs to repository {repository_id}, not selected root {bound_root}"
    )]
    RootMismatch {
        repository_id: RepositoryId,
        publication_directory: PathBuf,
        bound_root: PathBuf,
    },
    #[error("generation database still has live handles at {path}")]
    DatabaseBusy { path: PathBuf },
    #[error(
        "generation workspace belongs to repository {actual_repository} at {actual_directory:?}, not repository {expected_repository} at {expected_directory:?}"
    )]
    WorkspaceMismatch {
        expected_repository: RepositoryId,
        actual_repository: RepositoryId,
        expected_directory: PathBuf,
        actual_directory: PathBuf,
    },
    #[error("generation ID collision for {generation_id}")]
    GenerationCollision { generation_id: GenerationId },
    #[error("publication sequence overflow")]
    SequenceOverflow,
    #[error(
        "candidate generation would drop current complete capabilities {lost:?}; rerun only with explicit capability-downgrade authorization"
    )]
    CapabilityDowngrade { lost: Vec<String> },
    #[error("invalid publication draft: {0}")]
    InvalidDraft(String),
    #[error("invalid publication graph at {path}: {reason}")]
    InvalidGenerationGraph { path: PathBuf, reason: String },
    #[error("invalid publication control at {path}: {reason}")]
    InvalidControl { path: PathBuf, reason: String },
    #[error("unsafe publication artifact {path}; expected {expected}")]
    UnsafeArtifact {
        path: PathBuf,
        expected: &'static str,
    },
    #[error("publication control {path} exceeds {limit} bytes (actual {actual})")]
    ControlTooLarge {
        path: PathBuf,
        limit: u64,
        actual: u64,
    },
    #[error("publication digest mismatch for {path}: expected {expected}, got {actual}")]
    DigestMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{operation} failed for {path}: {error}")]
    Redb {
        operation: &'static str,
        path: PathBuf,
        error: String,
    },
    #[error("serialize publication control: {0}")]
    Serialization(String),
}

#[derive(Debug, Error)]
pub enum IndexGenerationPublicationError {
    #[error("semantic publication error: {0}")]
    Publication(#[from] PublicationError),
    #[error("index pipeline error: {0}")]
    Pipeline(#[from] IndexPipelineError),
    #[error("an indexing dry run has no evidence to publish")]
    EvidenceUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    use crate::code_intel_domain::{
        ConfigurationId, DocumentMembership, DocumentMembershipKind, EcosystemId, LanguageId,
        ProjectInventoryCoverage, ProjectUnit, ProjectUnitId, ProjectUnitKind, ProviderId,
    };
    use crate::code_intel_payload::{
        CallsProviderPayload, NormalizedSourceSpan, ProviderCall, ProviderDocument,
        ProviderLocation, ProviderSymbol, ProviderSymbolRole, canonical_provider_payload_bytes,
        provider_payload_descriptor,
    };
    use crate::graph::{GraphNode, KnowledgeGraph};
    use crate::graph_store::{
        ClassifiedBy, GraphGenerationMetadata, GraphStore, current_prover_config,
    };
    use crate::index_pipeline::{IndexConfig, IndexPipeline};
    use crate::index_state::{FileRecord, IndexMetadata, IndexState, IndexStateError};
    use crate::reachability::ReachabilityClass;
    use redb::TableDefinition;
    use tempfile::TempDir;

    const TEST_PAYLOAD: TableDefinition<&str, &str> =
        TableDefinition::new("h00_publication_test_payload");

    struct Fixture {
        _temporary: TempDir,
        root: PathBuf,
        graph: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = TempDir::new().expect("publication scratch directory");
            let root = temporary.path().join("repository");
            let graph = temporary.path().join("graph");
            fs::create_dir(&root).expect("repository root");
            fs::create_dir(&graph).expect("graph directory");
            Self {
                _temporary: temporary,
                root,
                graph,
            }
        }

        fn publication_directory(&self) -> PathBuf {
            self.graph.join(PUBLICATION_DIRECTORY)
        }

        fn head_path(&self, slot: usize) -> PathBuf {
            self.publication_directory().join(HEAD_FILES[slot])
        }
    }

    #[test]
    fn publisher_cleans_only_stale_provider_workspaces_while_holding_the_writer_lock() {
        let fixture = Fixture::new();
        let stale = fixture.graph.join(".h00-provider-crash-residue");
        let unrelated = fixture.graph.join("operator-owned-directory");
        fs::create_dir(&stale).expect("stale provider workspace");
        fs::write(stale.join("partial-artifact"), b"incomplete").expect("stale provider artifact");
        fs::create_dir(&unrelated).expect("unrelated graph child");

        let publisher = SemanticPublisher::acquire(&fixture.graph, &fixture.root)
            .expect("publisher owns the single-writer lock");
        publisher
            .cleanup_stale_provider_workspaces()
            .expect("stale provider cleanup");

        assert!(
            !stale.exists(),
            "crash residue must not survive the next writer"
        );
        assert!(
            unrelated.is_dir(),
            "cleanup must not widen beyond the provider workspace namespace"
        );
    }

    fn child_names(path: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(path)
            .expect("read scratch directory")
            .map(|entry| {
                entry
                    .expect("scratch directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    fn complete_receipt(capability_id: &str) -> CapabilityReceipt {
        CapabilityReceipt::complete(
            capability_id,
            "test-provider",
            "1.0.0",
            CapabilityScope::ProjectUnit {
                language_id: LanguageId::new("rust"),
                project_unit_id: ProjectUnitId::new("rust:test:package:Cargo.toml"),
                configuration_id: ConfigurationId::new("default"),
            },
            sha256_bytes(format!("{capability_id}-inputs").as_bytes()),
        )
    }

    fn test_inventory() -> ProjectInventory {
        let project_unit_id = ProjectUnitId::new("rust:test:package:Cargo.toml");
        ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: crate::code_intel_domain::ProjectTopology {
                units: vec![ProjectUnit {
                    project_unit_id: project_unit_id.clone(),
                    language_id: LanguageId::new("rust"),
                    ecosystem_id: EcosystemId::new("test"),
                    kind: ProjectUnitKind::Package,
                    root_path: String::new(),
                    manifest_path: Some("Cargo.toml".into()),
                    compilation_root_paths: Vec::new(),
                }],
                memberships: vec![DocumentMembership {
                    document_path: "src/lib.rs".into(),
                    language_id: LanguageId::new("rust"),
                    project_unit_id,
                    kind: DocumentMembershipKind::SourceOwner,
                }],
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        }
    }

    fn provider_payloads_for(
        receipts: &[CapabilityReceipt],
        inventory: &ProjectInventory,
    ) -> Vec<ProviderPayload> {
        receipts
            .iter()
            .filter(|receipt| {
                receipt.capability_id == "calls" && receipt.status == CapabilityStatus::Complete
            })
            .map(|receipt| {
                let documents = inventory
                    .project_topology
                    .memberships
                    .iter()
                    .filter(|membership| {
                        membership.kind == DocumentMembershipKind::SourceOwner
                            && match &receipt.scope {
                                CapabilityScope::Repository { .. } => true,
                                CapabilityScope::Language { language_id, .. } => {
                                    membership.language_id == *language_id
                                }
                                CapabilityScope::ProjectUnit {
                                    language_id,
                                    project_unit_id,
                                    ..
                                } => {
                                    membership.language_id == *language_id
                                        && membership.project_unit_id == *project_unit_id
                                }
                                CapabilityScope::ProjectUnits {
                                    language_id,
                                    project_unit_ids,
                                    ..
                                } => {
                                    membership.language_id == *language_id
                                        && project_unit_ids.contains(&membership.project_unit_id)
                                }
                            }
                    })
                    .map(|membership| {
                        (
                            membership.language_id.clone(),
                            membership.document_path.clone(),
                        )
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|(language_id, document_path)| ProviderDocument {
                        content_sha256: sha256_bytes(
                            format!("test-provider-document:{language_id}:{document_path}")
                                .as_bytes(),
                        ),
                        cross_document_surface_sha256: sha256_bytes(
                            format!("test-provider-surface:{language_id}:{document_path}")
                                .as_bytes(),
                        ),
                        document_path,
                        language_id,
                        byte_length: 0,
                    })
                    .collect();
                let mut payload = CallsProviderPayload::new(receipt.clone());
                payload.documents = documents;
                ProviderPayload::Calls(payload)
            })
            .collect()
    }

    fn populated_calls_payload(
        receipt: CapabilityReceipt,
        document_path: &str,
        identity_suffix: &str,
    ) -> ProviderPayload {
        let location = |start_byte, end_byte| ProviderLocation {
            document_path: document_path.into(),
            span: NormalizedSourceSpan {
                start_byte,
                end_byte,
                start_line: 0,
                start_utf8_byte_column: start_byte as u32,
                end_line: 0,
                end_utf8_byte_column: end_byte as u32,
            },
        };
        let caller_symbol_id = format!("caller-{identity_suffix}");
        let callee_symbol_id = format!("callee-{identity_suffix}");
        ProviderPayload::Calls(CallsProviderPayload {
            schema_version: crate::code_intel_payload::CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population:
                crate::code_intel_domain::CallsPopulation::ProviderResolvedExplicitSourceInvocations,
            receipt,
            semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
            execution_authority:
                crate::code_intel_payload::ProviderExecutionAuthority::InvocationBound {
                    provider_configurations_sha256: BTreeMap::new(),
                },
            canonical_snapshot_sha256: None,
            documents: vec![ProviderDocument {
                document_path: document_path.into(),
                language_id: LanguageId::new("rust"),
                content_sha256: sha256_bytes(identity_suffix.as_bytes()),
                cross_document_surface_sha256: sha256_bytes(
                    format!("surface:{identity_suffix}").as_bytes(),
                ),
                byte_length: 64,
            }],
            symbols: vec![
                ProviderSymbol {
                    provider_symbol_id: caller_symbol_id.clone(),
                    name: format!("caller_{identity_suffix}"),
                    provider_kind: "function".into(),
                    language_id: LanguageId::new("rust"),
                    role: ProviderSymbolRole::SourceInvocationTarget,
                    definition: Some(location(0, 6)),
                    structural_extent: Some(location(0, 32)),
                    call_owner_extent: Some(location(0, 32)),
                },
                ProviderSymbol {
                    provider_symbol_id: callee_symbol_id.clone(),
                    name: format!("callee_{identity_suffix}"),
                    provider_kind: "function".into(),
                    language_id: LanguageId::new("rust"),
                    role: ProviderSymbolRole::SourceInvocationTarget,
                    definition: Some(location(40, 48)),
                    structural_extent: Some(location(32, 64)),
                    call_owner_extent: Some(location(32, 64)),
                },
            ],
            calls: vec![ProviderCall {
                caller_symbol_id,
                callee_symbol_id,
                call_site: location(8, 14),
            }],
            callable_bindings: Vec::new(),
            coverage_exclusions: Vec::new(),
        })
    }

    fn graph_joining_populated_calls_payload(payload: &ProviderPayload) -> KnowledgeGraph {
        let ProviderPayload::Calls(payload) = payload else {
            unreachable!("Calls fixture")
        };
        assert!(
            !payload.calls.is_empty(),
            "positive Calls population control"
        );
        let mut graph = KnowledgeGraph::new();
        for symbol in &payload.symbols {
            let definition = symbol
                .definition
                .as_ref()
                .expect("populated fixture symbol definition");
            let extent = symbol
                .structural_extent
                .as_ref()
                .expect("populated fixture structural extent");
            let node = GraphNode {
                memory_id: Uuid::new_v4(),
                symbol_name: symbol.name.clone(),
                kind: "function".into(),
                file_path: definition.document_path.clone(),
                content_hash: format!("hash-{}", symbol.provider_symbol_id),
                signature: format!("fn {}()", symbol.name),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(definition.span.start_line as usize),
                line_end: Some(definition.span.end_line as usize),
                has_body: Some(true),
                visibility: "pub".into(),
                is_test_only: Some(false),
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            };
            let memory_id = node.memory_id;
            graph.add_node(node).expect("joined structural node");
            graph
                .set_source_span(
                    memory_id,
                    crate::graph::SourceSpan {
                        start_byte: extent.span.start_byte as usize,
                        end_byte: extent.span.end_byte as usize,
                    },
                )
                .expect("joined structural callable span");
        }
        graph
    }

    fn write_raw_provider_payload_entries(path: &Path, entries: &[(String, Vec<u8>)]) {
        let database = Database::create(path).expect("create provider payload fixture database");
        let transaction = database
            .begin_write()
            .expect("begin provider payload fixture write");
        {
            let mut table = transaction
                .open_table(PROVIDER_PAYLOADS)
                .expect("open provider payload fixture table");
            for (key, value) in entries {
                table
                    .insert(key.as_str(), value.as_slice())
                    .expect("write provider payload fixture entry");
            }
        }
        transaction
            .commit()
            .expect("commit provider payload fixture write");
        drop(database);
    }

    fn graph_node(name: &str) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.to_owned(),
            kind: "function".into(),
            file_path: format!("src/{name}.rs"),
            content_hash: format!("hash-{name}"),
            signature: format!("fn {name}()"),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(0),
            line_end: Some(0),
            has_body: Some(true),
            visibility: "pub".into(),
            is_test_only: Some(false),
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    fn publish(
        publisher: &mut SemanticPublisher,
        payload: &str,
        receipts: Vec<CapabilityReceipt>,
    ) -> PublishedGeneration {
        let workspace = workspace_with_payload(publisher, payload);
        let project_inventory = test_inventory();
        let provider_payloads = provider_payloads_for(&receipts, &project_inventory);
        publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some(payload.to_owned()),
                    project_inventory,
                    receipts,
                    provider_payloads,
                },
            )
            .expect("publish generation")
    }

    /// PERFORMANCE FALSIFIER: immutable-generation integrity requires two
    /// whole-database digests at distinct byte states. BLAKE3 provides the
    /// same 256-bit cryptographic content binding while avoiding SHA-256's
    /// measured hot-path cost; neither scan may be removed.
    #[test]
    fn immutable_database_integrity_uses_blake3() {
        let fixture = Fixture::new();
        let published = {
            let mut publisher =
                SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
            publish(&mut publisher, "blake3-integrity", Vec::new())
        };
        let bytes = fs::read(&published.database_path).expect("published database bytes");
        let sha256 = sha256_bytes(&bytes);
        let blake3 = blake3::hash(&bytes).to_hex().to_string();
        assert_ne!(sha256, blake3, "digest-algorithm positive control");
        assert_eq!(
            published.head.body.database_blake3, blake3,
            "whole-generation integrity must use the measured BLAKE3 primitive"
        );
        assert_ne!(
            published.head.body.database_blake3, sha256,
            "the whole-generation field must not silently retain SHA-256"
        );
    }

    /// PERFORMANCE FALSIFIER: writer admission already validates the current
    /// immutable generation while holding the one-writer lock. Capturing its
    /// reusable source basis must consume that admitted authority rather than
    /// scanning, hashing, parsing, and validating the same generation again.
    #[test]
    fn incremental_basis_reuses_the_generation_validated_at_writer_admission() {
        let fixture = Fixture::new();
        {
            let mut seed =
                SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("seed publisher");
            publish(&mut seed, "seed", Vec::new());
        }

        reset_generations_validated();
        let publisher = SemanticPublisher::acquire(&fixture.graph, &fixture.root)
            .expect("publisher validates the current generation at admission");
        assert_eq!(
            generations_validated(),
            1,
            "positive control: current generation must be validated at admission"
        );

        let _ = publisher
            .capture_incremental_basis(&[])
            .expect("capture reusable source basis");
        assert_eq!(
            generations_validated(),
            1,
            "basis capture revalidated the generation already admitted under the writer lock"
        );
    }

    /// PERFORMANCE FALSIFIER: a higher-level reuse probe may have fully
    /// validated the current immutable generation immediately before writer
    /// admission. Once the writer lock is held and the bounded head still
    /// names that exact record, admission must retain it instead of hashing and
    /// parsing the same database again. Final pre-head validation remains
    /// independent.
    #[test]
    fn writer_admission_reuses_an_exact_prevalidated_current_generation() {
        let fixture = Fixture::new();
        {
            let mut seed =
                SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("seed publisher");
            publish(&mut seed, "seed", Vec::new());
        }
        let prevalidated =
            resolve_generation(&fixture.graph, &fixture.root).expect("prevalidate current");
        let expected_head = prevalidated.head.clone();
        let publication_root =
            PreparedPublicationRoot::capture(&fixture.graph).expect("prepared publication root");

        reset_generations_validated();
        let publisher = SemanticPublisher::acquire_prepared(
            publication_root,
            &fixture.root,
            PublicationRecovery::Strict,
            Some(prevalidated),
        )
        .expect("admit exact prevalidated generation");

        assert_eq!(
            generations_validated(),
            0,
            "writer admission redundantly revalidated the exact generation supplied by the reuse probe"
        );
        assert_eq!(
            publisher
                .admitted_current
                .as_ref()
                .expect("admitted current")
                .head,
            expected_head
        );
    }

    #[test]
    fn writer_admission_revalidates_when_the_prevalidated_head_is_stale() {
        let fixture = Fixture::new();
        let old = {
            let mut seed =
                SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("seed publisher");
            publish(&mut seed, "old", Vec::new())
        };
        let prevalidated_old =
            resolve_generation(&fixture.graph, &fixture.root).expect("prevalidate old head");
        let newest = {
            let mut advance = SemanticPublisher::acquire(&fixture.graph, &fixture.root)
                .expect("advance publisher");
            publish(&mut advance, "new", Vec::new())
        };
        assert_ne!(
            newest.manifest.generation_id, old.manifest.generation_id,
            "positive control: the locked head must have advanced"
        );

        let publication_root =
            PreparedPublicationRoot::capture(&fixture.graph).expect("prepared publication root");
        reset_generations_validated();
        let publisher = SemanticPublisher::acquire_prepared(
            publication_root,
            &fixture.root,
            PublicationRecovery::Strict,
            Some(prevalidated_old),
        )
        .expect("fall back to validating the locked current head");

        assert_eq!(
            generations_validated(),
            1,
            "a stale preflight record must not suppress locked-head validation"
        );
        assert_eq!(
            publisher
                .admitted_current
                .as_ref()
                .expect("admitted newest generation")
                .manifest
                .generation_id,
            newest.manifest.generation_id
        );
    }

    #[test]
    fn final_publication_revalidates_a_fast_path_admitted_generation() {
        let fixture = Fixture::new();
        {
            let mut seed =
                SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("seed publisher");
            publish(&mut seed, "seed", Vec::new());
        }
        let prevalidated =
            resolve_generation(&fixture.graph, &fixture.root).expect("prevalidate current");
        let current_path = prevalidated.database_path.clone();
        let current_slot = prevalidated.slot;
        let head_before = fs::read(fixture.head_path(current_slot)).expect("current head bytes");
        let publication_root =
            PreparedPublicationRoot::capture(&fixture.graph).expect("prepared publication root");
        let mut publisher = SemanticPublisher::acquire_prepared(
            publication_root,
            &fixture.root,
            PublicationRecovery::Strict,
            Some(prevalidated),
        )
        .expect("fast-path writer admission");
        let workspace = workspace_with_payload(&publisher, "replacement");
        corrupt_file(&current_path);

        reset_generations_validated();
        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("replacement".into()),
                    project_inventory: test_inventory(),
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect_err("post-admission damage must still prevent publication");
        assert!(matches!(error, PublicationError::NoValidGeneration { .. }));
        assert_eq!(
            fs::read(fixture.head_path(current_slot)).expect("head after refusal"),
            head_before,
            "final validation failure must preserve the admitted head"
        );
        assert_eq!(
            generations_validated(),
            0,
            "an unchanged locked head already has fully parsed authority; final publication must detect byte damage from its exact database digest without parsing that generation again"
        );
    }

    #[test]
    fn final_publication_reuses_parsed_authority_after_exact_digest_recheck() {
        let fixture = Fixture::new();
        let seed = {
            let mut publisher =
                SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("seed publisher");
            publish(&mut publisher, "seed", Vec::new())
        };
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("admit seed");

        reset_generations_validated();
        let replacement = publish(&mut publisher, "replacement", Vec::new());

        assert_eq!(
            generations_validated(),
            0,
            "the unchanged locked head and exact database digest must retain the authority parsed at admission"
        );
        assert_eq!(
            replacement.manifest.parent_generation_id,
            Some(seed.manifest.generation_id),
            "positive control: the admitted generation remains the replacement's exact parent"
        );
    }

    /// PERFORMANCE FALSIFIER: the real indexing pipeline has already
    /// validated, encoded, hashed, and committed the graph plus reachability
    /// evidence to its still-private database. Publication must carry that
    /// authority through a witness bound to the exact live database handle,
    /// rather than reread the same payload before the handle is closed.
    #[tokio::test]
    async fn fresh_pipeline_does_not_revalidate_its_database_bound_candidate() {
        let fixture = Fixture::new();
        let source_directory = fixture.root.join("src");
        fs::create_dir(&source_directory).expect("source directory");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"publication-proof\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        fs::write(
            source_directory.join("lib.rs"),
            b"pub fn proof_positive_control() {}\n",
        )
        .expect("scratch source");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: false,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            ..IndexConfig::default()
        };

        GraphStore::reset_publication_validation_counts();
        IndexState::reset_publication_proof_counts();
        let published = publish_fresh_index_generation(&fixture.graph, &config, None)
            .await
            .expect("publish through the real pipeline");
        assert!(
            published.telemetry.nodes_total > 0,
            "positive control: a nonempty candidate graph was published"
        );
        let (fallback_decodes, proof_validations) = GraphStore::publication_validation_counts();
        assert_eq!(
            fallback_decodes, 0,
            "the pipeline-backed publisher redundantly decoded the complete candidate graph"
        );
        assert_eq!(
            proof_validations, 0,
            "the database-bound fresh-candidate witness must eliminate the redundant persisted-payload reread"
        );
        assert_eq!(
            IndexState::publication_proof_counts(),
            (1, 0),
            "index state must be captured once by its writer and not reread by the same candidate publication lifecycle"
        );
    }

    #[test]
    fn low_level_publisher_without_a_pipeline_proof_still_decodes_the_candidate() {
        let fixture = Fixture::new();
        let mut publisher = SemanticPublisher::acquire(&fixture.graph, &fixture.root)
            .expect("acquire low-level publisher");

        GraphStore::reset_publication_validation_counts();
        let published = publish(&mut publisher, "low-level-positive-control", Vec::new());
        assert!(
            published.database_path.is_file(),
            "positive control: the low-level candidate was published"
        );
        assert_eq!(
            GraphStore::publication_validation_counts(),
            (1, 0),
            "callers without a bound pipeline proof must retain full snapshot validation"
        );
    }

    /// The admission cache is a performance hint, not publication authority.
    /// Damage after incremental-basis capture must still be caught by the
    /// independent full validation immediately before a new head can advance.
    #[tokio::test]
    async fn final_publication_revalidates_the_admitted_generation() {
        let fixture = Fixture::new();
        let source_directory = fixture.root.join("src");
        fs::create_dir(&source_directory).expect("source directory");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"admission-revalidation\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        fs::write(
            source_directory.join("lib.rs"),
            b"pub fn reusable_source_fact() {}\n",
        )
        .expect("scratch source");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: false,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            ..IndexConfig::default()
        };
        let seed = publish_fresh_index_generation(&fixture.graph, &config, None)
            .await
            .expect("publish seed generation")
            .publication;
        let seed_slot = resolve_generation(&fixture.graph, &fixture.root)
            .expect("resolve seed generation")
            .slot;
        let head_before = fs::read(fixture.head_path(seed_slot)).expect("seed head bytes");

        let mut publisher = SemanticPublisher::acquire(&fixture.graph, &fixture.root)
            .expect("publisher admits the intact generation");
        assert!(
            publisher
                .capture_incremental_basis(&[])
                .expect("capture admitted basis")
                .is_some(),
            "positive control: the admitted generation supplied a reusable basis"
        );
        let workspace = workspace_with_payload(&publisher, "replacement");
        corrupt_file(&seed.database_path);

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("replacement".into()),
                    project_inventory: test_inventory(),
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect_err("post-admission generation damage must prevent publication");
        assert!(matches!(error, PublicationError::NoValidGeneration { .. }));
        assert_eq!(
            fs::read(fixture.head_path(seed_slot)).expect("head after refusal"),
            head_before,
            "final validation failure must not advance or rewrite the head"
        );
    }

    fn workspace_with_payload(publisher: &SemanticPublisher, payload: &str) -> GenerationWorkspace {
        let workspace = publisher
            .begin_generation()
            .expect("begin private generation");
        stamp_test_generation_authority(&workspace, &publisher.repository_root);
        let database = workspace.database();
        let transaction = database.begin_write().expect("begin payload write");
        {
            let mut table = transaction
                .open_table(TEST_PAYLOAD)
                .expect("open payload table");
            table
                .insert("content", payload)
                .expect("write payload value");
        }
        transaction.commit().expect("commit payload write");
        drop(database);
        workspace
    }

    fn stamp_test_generation_authority(workspace: &GenerationWorkspace, repository_root: &Path) {
        let graph_store = GraphStore::new(workspace.database());
        graph_store
            .save_snapshot_sync(&KnowledgeGraph::new())
            .expect("persist complete test graph snapshot");
        graph_store
            .set_origin_sync(repository_root)
            .expect("stamp complete test graph origin");
        graph_store
            .set_generation_metadata_sync(&GraphGenerationMetadata {
                classified_by: ClassifiedBy {
                    build_identity: crate::BUILD_IDENTITY.to_owned(),
                    indexer_identity: crate::INDEXER_IDENTITY.to_owned(),
                    prover_config: current_prover_config(),
                    timestamp: "2000-01-01T00:00:00Z".into(),
                },
                oracle_ran_ok: false,
            })
            .expect("stamp complete test generation metadata");
    }

    fn corrupt_file(path: &Path) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open scratch artifact for corruption");
        file.write_all(b"corrupt")
            .expect("corrupt scratch artifact");
    }

    fn replace_head(path: &Path, head: &PublicationHead) {
        fs::write(path, canonical_json(head).expect("serialize head fixture"))
            .expect("replace head fixture");
    }

    fn rewrite_generation_schema(
        fixture: &Fixture,
        published: &PublishedGeneration,
        schema_version: &str,
    ) -> (PathBuf, PathBuf) {
        let selected = resolve_generation(&fixture.graph, &fixture.root)
            .expect("resolve generation before schema rewrite");
        let old_directory = published
            .database_path
            .parent()
            .expect("generation directory");
        let generations_directory = old_directory.parent().expect("generations directory");
        let mut manifest = published.manifest.clone();
        manifest.schema_version = schema_version.into();
        manifest.generation_id = compute_generation_id(&manifest).expect("obsolete generation ID");
        let manifest_bytes = canonical_json(&manifest).expect("obsolete manifest bytes");

        let database = Database::create(&published.database_path)
            .expect("open generation database for schema rewrite");
        write_manifest_to_database(&database, &published.database_path, &manifest_bytes)
            .expect("write obsolete generation manifest");
        drop(database);

        let new_directory = generations_directory.join(&manifest.generation_id.0);
        fs::rename(old_directory, &new_directory).expect("rename obsolete generation directory");
        let database_path = new_directory.join(GENERATION_DATABASE_FILE);
        let mut head_body = published.head.body.clone();
        head_body.generation_id = manifest.generation_id;
        head_body.database_blake3 = blake3_file(&database_path).expect("obsolete database digest");
        head_body.manifest_sha256 = sha256_bytes(&manifest_bytes);
        let head = seal_head(head_body).expect("seal obsolete generation head");
        let head_path = fixture.head_path(selected.slot);
        replace_head(&head_path, &head);
        (head_path, database_path)
    }

    fn remove_heads(fixture: &Fixture) {
        for slot in 0..HEAD_FILES.len() {
            let path = fixture.head_path(slot);
            if path.exists() {
                fs::remove_file(path).expect("remove head fixture");
            }
        }
    }

    #[test]
    fn missing_graph_directory_is_unpublished_and_read_only() {
        let temporary = TempDir::new().expect("publication scratch directory");
        let root = temporary.path().join("repository");
        let graph = temporary.path().join("absent-graph");
        fs::create_dir(&root).expect("repository root");
        let before = child_names(temporary.path());

        assert!(matches!(
            publication_control_token(&graph, &root),
            Err(PublicationError::Unpublished { .. })
        ));
        assert!(matches!(
            resolve_generation(&graph, &root),
            Err(PublicationError::Unpublished { .. })
        ));
        assert_eq!(child_names(temporary.path()), before);
        assert!(!graph.exists());
    }

    #[test]
    fn resolving_an_unpublished_graph_is_read_only() {
        let fixture = Fixture::new();
        let before = child_names(&fixture.graph);

        let error = resolve_generation(&fixture.graph, &fixture.root)
            .expect_err("an unpublished graph has no generation");

        assert!(matches!(error, PublicationError::Unpublished { .. }));
        assert_eq!(child_names(&fixture.graph), before);
    }

    #[test]
    fn complete_calls_receipt_without_provider_payload_never_publishes_authority() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = workspace_with_payload(&publisher, "graph-only");

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("missing-provider-payload".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![complete_receipt("calls")],
                    provider_payloads: Vec::new(),
                },
            )
            .expect_err("complete Calls authority without matching payload is false authority");

        assert!(matches!(
            error,
            PublicationError::InvalidDraft(reason)
                if reason.contains("complete calls receipt")
                    && reason.contains("provider payload")
        ));
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
    }

    #[test]
    fn complete_calls_payload_must_cover_every_source_document_in_scope() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let receipt = complete_receipt("calls");
        let payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "incomplete");
        let mut inventory = test_inventory();
        inventory
            .project_topology
            .memberships
            .push(DocumentMembership {
                document_path: "src/other.rs".into(),
                language_id: LanguageId::new("rust"),
                project_unit_id: ProjectUnitId::new("rust:test:package:Cargo.toml"),
                kind: DocumentMembershipKind::SourceOwner,
            });
        let workspace = workspace_with_payload(&publisher, "incomplete-scope-population");

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: None,
                    project_inventory: inventory,
                    receipts: vec![receipt],
                    provider_payloads: vec![payload],
                },
            )
            .expect_err("complete Calls authority cannot omit an owned source document");

        assert!(matches!(
            error,
            PublicationError::InvalidDraft(reason)
                if reason.contains("document population")
                    && reason.contains("src/other.rs")
        ));
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
    }

    #[test]
    fn publish_and_resolve_round_trip_uses_one_immutable_database() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let repository_id = publisher.repository_id().clone();

        let published = publish(
            &mut publisher,
            "round-trip",
            vec![complete_receipt("calls")],
        );
        let resolved =
            resolve_generation(&fixture.graph, &fixture.root).expect("resolve generation");

        assert_eq!(published.head.body.sequence, 1);
        assert_eq!(published.manifest.repository_id, repository_id);
        assert_eq!(resolved.manifest, published.manifest);
        assert_eq!(resolved.project_inventory.as_ref(), &test_inventory());
        assert_eq!(published.project_inventory.as_ref(), &test_inventory());
        assert_eq!(resolved.head, published.head);
        assert_eq!(resolved.database_path, published.database_path);
        assert_eq!(
            resolved.database_path.file_name(),
            Some(std::ffi::OsStr::new(GENERATION_DATABASE_FILE))
        );

        let database =
            ReadOnlyDatabase::open(&resolved.database_path).expect("open immutable database");
        let transaction = database.begin_read().expect("read immutable database");
        let table = transaction
            .open_table(TEST_PAYLOAD)
            .expect("open immutable payload table");
        assert_eq!(
            table
                .get("content")
                .expect("read payload")
                .expect("payload exists")
                .value(),
            "round-trip"
        );
        assert_eq!(
            serde_json::from_slice::<GenerationManifest>(
                &read_manifest(&resolved.database_path).expect("read persisted manifest")
            )
            .expect("parse persisted manifest"),
            published.manifest
        );
    }

    #[test]
    fn provider_payload_preparation_normalizes_and_serializes_each_payload_once() {
        let receipt = complete_receipt("calls");
        let payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "single-pass");
        let expected = crate::code_intel_payload::normalize_provider_payload_typed(&payload)
            .expect("normalize expected payload");
        let inventory = test_inventory();
        crate::code_intel_payload::reset_provider_payload_normalizations();

        let prepared = prepare_provider_payloads(&[payload], &[receipt], &inventory)
            .expect("prepare one populated provider payload");
        let normalization_count = crate::code_intel_payload::provider_payload_normalizations();

        assert_eq!(
            prepared.payloads.len(),
            1,
            "positive prepared-population control"
        );
        assert!(
            !prepared.payloads[0].bytes.is_empty(),
            "positive byte control"
        );
        assert_eq!(prepared.payloads[0].payload, expected);
        assert_eq!(
            prepared.payloads[0].descriptor.payload_sha256,
            sha256_bytes(&prepared.payloads[0].bytes),
            "descriptor must bind the exact persisted bytes"
        );
        assert_eq!(
            normalization_count, 1,
            "one publication preparation must canonicalize one payload exactly once"
        );
    }

    #[test]
    fn canonical_provider_payload_preparation_never_repeats_normalization() {
        let receipt = complete_receipt("calls");
        let payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "sealed-once");
        let canonical = crate::code_intel_payload::canonicalize_provider_payload(&payload)
            .expect("seal one valid provider payload");
        let expected_payload = canonical.normalized_clone();
        let expected_descriptor = canonical.descriptor().clone();
        let expected_bytes = canonical.bytes().to_vec();
        let inventory = test_inventory();
        crate::code_intel_payload::reset_provider_payload_normalizations();

        let prepared = prepare_canonical_provider_payloads(vec![canonical], &[receipt], &inventory)
            .expect("admit one already-canonical payload");
        let normalization_count = crate::code_intel_payload::provider_payload_normalizations();

        assert_eq!(prepared.payloads.len(), 1, "positive population control");
        assert_eq!(prepared.payloads[0].payload, expected_payload);
        assert_eq!(prepared.payloads[0].descriptor, expected_descriptor);
        assert_eq!(prepared.payloads[0].bytes, expected_bytes);
        assert_eq!(
            normalization_count, 0,
            "a byte-bound canonical payload must not be normalized again at publication"
        );
    }

    /// RIGHT-REASON FALSIFIER: the public raw boundary cannot advertise a
    /// complete Calls payload whose local caller/callee definitions are absent
    /// from the graph being published beside it.
    #[test]
    fn raw_provider_payload_must_join_candidate_graph_before_publication() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let receipt = complete_receipt("calls");
        let payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "unjoined");
        let ProviderPayload::Calls(calls) = &payload else {
            unreachable!("Calls fixture")
        };
        assert_eq!(calls.calls.len(), 1, "positive provider Calls control");
        let workspace = workspace_with_payload(&publisher, "unjoined-provider-payload");

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("unjoined-provider-payload".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![receipt],
                    provider_payloads: vec![payload],
                },
            )
            .expect_err("raw complete Calls authority must join the candidate graph");
        assert!(matches!(
            error,
            PublicationError::InvalidDraft(reason)
                if reason.contains("co-published structural graph")
        ));
    }

    #[test]
    fn nonempty_provider_payload_round_trips_with_exact_generation_linkage() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let receipt = complete_receipt("calls");
        let payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "roundtrip");
        let normalized = crate::code_intel_payload::normalize_provider_payload_typed(&payload)
            .expect("normalize payload fixture");
        let descriptor =
            provider_payload_descriptor(normalized.payload()).expect("payload descriptor");
        let workspace = workspace_with_payload(&publisher, "nonempty-provider-payload");
        GraphStore::new(workspace.database())
            .save_snapshot_sync(&graph_joining_populated_calls_payload(&payload))
            .expect("persist graph joined to populated provider payload");

        let published = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("nonempty-provider-payload".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![receipt],
                    provider_payloads: vec![payload],
                },
            )
            .expect("publish nonempty provider payload");
        let resolved =
            resolve_generation(&fixture.graph, &fixture.root).expect("resolve provider payload");

        assert_eq!(published.provider_payloads, vec![normalized.clone()]);
        assert_eq!(resolved.provider_payloads, vec![normalized.clone()]);
        assert_eq!(
            published.manifest.provider_payloads,
            vec![descriptor.clone()]
        );
        assert_eq!(
            published.head.body.provider_payload_set_sha256,
            sha256_bytes(
                &canonical_json(&published.manifest.provider_payloads)
                    .expect("canonical payload descriptors")
            )
        );

        let database =
            ReadOnlyDatabase::open(&published.database_path).expect("open immutable generation");
        let transaction = database.begin_read().expect("read immutable generation");
        let table = transaction
            .open_table(PROVIDER_PAYLOADS)
            .expect("open provider payload table");
        let stored = table
            .get(descriptor.payload_id.0.as_str())
            .expect("read provider payload")
            .expect("provider payload exists");
        assert_eq!(
            stored.value(),
            canonical_provider_payload_bytes(normalized.payload())
                .expect("canonical provider payload")
                .as_slice()
        );
    }

    #[test]
    fn provider_payload_draft_rejects_duplicate_claims_reserved_table_and_inventory_escape() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let receipt = complete_receipt("calls");
        let payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "duplicate");

        let workspace = workspace_with_payload(&publisher, "duplicate-payload-id");
        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: None,
                    project_inventory: test_inventory(),
                    receipts: vec![receipt.clone()],
                    provider_payloads: vec![payload.clone(), payload.clone()],
                },
            )
            .expect_err("duplicate payload IDs must be rejected");
        assert!(matches!(
            error,
            PublicationError::InvalidDraft(reason)
                if reason.contains("duplicate provider payload ID")
        ));

        let workspace = workspace_with_payload(&publisher, "duplicate-receipt-claim");
        let second_payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "second");
        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: None,
                    project_inventory: test_inventory(),
                    receipts: vec![receipt.clone()],
                    provider_payloads: vec![payload.clone(), second_payload],
                },
            )
            .expect_err("one receipt cannot authorize multiple payloads");
        assert!(matches!(
            error,
            PublicationError::InvalidDraft(reason)
                if reason.contains("multiple provider payloads claim receipt")
        ));

        let workspace = workspace_with_payload(&publisher, "reserved-provider-table");
        GraphStore::new(workspace.database())
            .save_snapshot_sync(&graph_joining_populated_calls_payload(&payload))
            .expect("reserved-table fixture must pass the earlier structural join guard");
        let database = workspace.database();
        let transaction = database.begin_write().expect("begin reserved table write");
        {
            let mut table = transaction
                .open_table(PROVIDER_PAYLOADS)
                .expect("open reserved provider payload table");
            table
                .insert("payload-reserved", b"occupied".as_slice())
                .expect("occupy reserved provider payload table");
        }
        transaction.commit().expect("commit reserved table fixture");
        drop(database);
        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: None,
                    project_inventory: test_inventory(),
                    receipts: vec![receipt.clone()],
                    provider_payloads: vec![payload],
                },
            )
            .expect_err("callers cannot prepopulate the publisher-owned table");
        assert!(matches!(
            error,
            PublicationError::InvalidDraft(reason)
                if reason.contains("provider payload table is reserved")
        ));

        let workspace = workspace_with_payload(&publisher, "inventory-escape");
        let escaped = populated_calls_payload(receipt.clone(), "src/escaped.rs", "escaped");
        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: None,
                    project_inventory: test_inventory(),
                    receipts: vec![receipt],
                    provider_payloads: vec![escaped],
                },
            )
            .expect_err("payload documents cannot escape indexed SourceOwner authority");
        assert!(matches!(
            error,
            PublicationError::InvalidDraft(reason)
                if reason.contains("not owned by receipt project unit")
        ));
    }

    #[test]
    fn provider_payload_reader_fails_closed_for_missing_or_corrupt_linkage() {
        let temporary = TempDir::new().expect("provider payload reader controls");
        let receipt = complete_receipt("calls");
        let payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "reader");
        let descriptor = provider_payload_descriptor(&payload).expect("payload descriptor");
        let canonical = canonical_provider_payload_bytes(&payload).expect("canonical payload");
        let inventory = test_inventory();

        let missing_table = temporary.path().join("missing-table.redb");
        drop(Database::create(&missing_table).expect("create missing-table database"));
        let error = read_provider_payloads(
            &missing_table,
            std::slice::from_ref(&descriptor),
            std::slice::from_ref(&receipt),
            &inventory,
        )
        .expect_err("missing provider payload table must fail closed");
        assert!(matches!(error, PublicationError::InvalidControl { .. }));

        let missing_entry = temporary.path().join("missing-entry.redb");
        write_raw_provider_payload_entries(&missing_entry, &[]);
        let error = read_provider_payloads(
            &missing_entry,
            std::slice::from_ref(&descriptor),
            std::slice::from_ref(&receipt),
            &inventory,
        )
        .expect_err("missing provider payload entry must fail closed");
        assert!(matches!(
            error,
            PublicationError::InvalidControl { reason, .. }
                if reason.contains("absent from the immutable generation")
        ));

        let orphan_entry = temporary.path().join("orphan-entry.redb");
        write_raw_provider_payload_entries(
            &orphan_entry,
            &[("payload-orphan".into(), canonical.clone())],
        );
        let error = read_provider_payloads(
            &orphan_entry,
            &[],
            std::slice::from_ref(&receipt),
            &inventory,
        )
        .expect_err("orphan provider payload entry must fail closed");
        assert!(matches!(
            error,
            PublicationError::InvalidControl { reason, .. }
                if reason.contains("orphan provider payload table entry")
        ));

        let digest_mismatch = temporary.path().join("digest-mismatch.redb");
        write_raw_provider_payload_entries(
            &digest_mismatch,
            &[(descriptor.payload_id.0.clone(), b"altered".to_vec())],
        );
        let error = read_provider_payloads(
            &digest_mismatch,
            std::slice::from_ref(&descriptor),
            std::slice::from_ref(&receipt),
            &inventory,
        )
        .expect_err("altered provider payload bytes must fail their digest");
        assert!(matches!(error, PublicationError::DigestMismatch { .. }));

        let document: serde_json::Value =
            serde_json::from_slice(&canonical).expect("parse canonical provider payload");
        let noncanonical =
            serde_json::to_vec_pretty(&document).expect("serialize noncanonical payload");
        let noncanonical_digest = sha256_bytes(&noncanonical);
        let mut noncanonical_descriptor = descriptor.clone();
        noncanonical_descriptor.payload_sha256 = noncanonical_digest.clone();
        noncanonical_descriptor.payload_id =
            ProviderPayloadId(format!("payload-{noncanonical_digest}"));
        let noncanonical_path = temporary.path().join("noncanonical.redb");
        write_raw_provider_payload_entries(
            &noncanonical_path,
            &[(noncanonical_descriptor.payload_id.0.clone(), noncanonical)],
        );
        let error = read_provider_payloads(
            &noncanonical_path,
            std::slice::from_ref(&noncanonical_descriptor),
            std::slice::from_ref(&receipt),
            &inventory,
        )
        .expect_err("noncanonical provider payload bytes must fail closed");
        assert!(matches!(
            error,
            PublicationError::InvalidControl { reason, .. }
                if reason.contains("not canonical")
        ));

        let descriptor_mismatch = temporary.path().join("descriptor-mismatch.redb");
        let descriptor_key = descriptor.payload_id.0.clone();
        write_raw_provider_payload_entries(&descriptor_mismatch, &[(descriptor_key, canonical)]);
        let mut wrong_descriptor = descriptor;
        wrong_descriptor.provider_id = ProviderId::new("wrong-provider");
        let error = read_provider_payloads(
            &descriptor_mismatch,
            std::slice::from_ref(&wrong_descriptor),
            std::slice::from_ref(&receipt),
            &inventory,
        )
        .expect_err("descriptor identity must match canonical payload bytes");
        assert!(matches!(
            error,
            PublicationError::InvalidControl { reason, .. }
                if reason.contains("descriptor mismatch")
        ));

        let mut other_receipt = receipt.clone();
        other_receipt.provider_id = ProviderId::new("other-provider");
        let other_payload = populated_calls_payload(other_receipt, "src/lib.rs", "other-receipt");
        let other_descriptor =
            provider_payload_descriptor(&other_payload).expect("other payload descriptor");
        let other_bytes =
            canonical_provider_payload_bytes(&other_payload).expect("other payload bytes");
        let receipt_mismatch = temporary.path().join("receipt-mismatch.redb");
        write_raw_provider_payload_entries(
            &receipt_mismatch,
            &[(other_descriptor.payload_id.0.clone(), other_bytes)],
        );
        let error = read_provider_payloads(
            &receipt_mismatch,
            std::slice::from_ref(&other_descriptor),
            std::slice::from_ref(&receipt),
            &inventory,
        )
        .expect_err("payload receipt must exist exactly in the manifest");
        assert!(matches!(
            error,
            PublicationError::InvalidControl { reason, .. }
                if reason.contains("has no manifest receipt")
        ));

        let escaped_payload =
            populated_calls_payload(receipt.clone(), "src/escaped.rs", "reader-escape");
        let escaped_descriptor =
            provider_payload_descriptor(&escaped_payload).expect("escaped payload descriptor");
        let escaped_bytes =
            canonical_provider_payload_bytes(&escaped_payload).expect("escaped payload bytes");
        let inventory_mismatch = temporary.path().join("inventory-mismatch.redb");
        write_raw_provider_payload_entries(
            &inventory_mismatch,
            &[(escaped_descriptor.payload_id.0.clone(), escaped_bytes)],
        );
        let error = read_provider_payloads(
            &inventory_mismatch,
            std::slice::from_ref(&escaped_descriptor),
            std::slice::from_ref(&receipt),
            &inventory,
        )
        .expect_err("persisted payload cannot escape indexed SourceOwner authority");
        assert!(matches!(
            error,
            PublicationError::InvalidControl { reason, .. }
                if reason.contains("not owned by receipt project unit")
        ));
    }

    /// PERFORMANCE FALSIFIER: one persisted canonical payload must undergo one
    /// normalization pass, not a parse pass followed by descriptor
    /// recanonicalization over the same repository-sized value.
    #[test]
    fn provider_payload_reader_canonicalizes_each_payload_once() {
        let temporary = TempDir::new().expect("provider payload reader controls");
        let receipt = complete_receipt("calls");
        let payload = populated_calls_payload(receipt.clone(), "src/lib.rs", "reader-once");
        let descriptor = provider_payload_descriptor(&payload).expect("payload descriptor");
        let canonical = canonical_provider_payload_bytes(&payload).expect("canonical payload");
        let database_path = temporary.path().join("valid.redb");
        write_raw_provider_payload_entries(
            &database_path,
            &[(descriptor.payload_id.0.clone(), canonical)],
        );

        crate::code_intel_payload::reset_provider_payload_normalizations();
        let parsed = read_provider_payloads(
            &database_path,
            std::slice::from_ref(&descriptor),
            std::slice::from_ref(&receipt),
            &test_inventory(),
        )
        .expect("read one exact canonical payload");
        assert_eq!(parsed.len(), 1, "positive persisted payload control");
        assert_eq!(
            crate::code_intel_payload::provider_payload_normalizations(),
            1,
            "one persisted payload must be normalized exactly once"
        );
    }

    #[test]
    fn provider_payload_reader_classifies_receipt_inventory_mismatch_as_control_corruption() {
        let temporary = TempDir::new().expect("provider payload receipt inventory control");
        let path = temporary.path().join("receipt-inventory-mismatch.redb");
        write_raw_provider_payload_entries(&path, &[]);
        let receipt = complete_receipt("calls");
        let empty_inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: crate::code_intel_domain::ProjectTopology {
                units: Vec::new(),
                memberships: Vec::new(),
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };

        let error = read_provider_payloads(&path, &[], &[receipt], &empty_inventory)
            .expect_err("persisted receipt/inventory mismatch is corrupt control, not a draft");
        assert!(matches!(error, PublicationError::InvalidControl { .. }));
    }

    #[test]
    fn published_generation_contains_bound_project_inventory() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let published = publish(
            &mut publisher,
            "inventory-boundary",
            vec![complete_receipt("calls")],
        );

        let database =
            ReadOnlyDatabase::open(&published.database_path).expect("open immutable database");
        let transaction = database.begin_read().expect("read immutable database");
        let table = transaction
            .open_table(PROJECT_INVENTORY)
            .expect("published generation must contain the project inventory table");
        let bytes = table
            .get(PROJECT_INVENTORY_KEY)
            .expect("read project inventory")
            .expect("project inventory exists");
        assert_eq!(
            parse_project_inventory_bytes(bytes.value()).expect("parse project inventory"),
            test_inventory()
        );
        assert_eq!(
            published.manifest.project_inventory_sha256,
            sha256_bytes(bytes.value())
        );
    }

    #[test]
    fn project_inventory_reader_rejects_missing_malformed_noncanonical_and_wrong_digest() {
        let temporary = TempDir::new().expect("project inventory controls");

        let missing_path = temporary.path().join("missing.redb");
        drop(Database::create(&missing_path).expect("create missing-table database"));
        let error = read_project_inventory(&missing_path, &sha256_bytes(b"missing"))
            .expect_err("missing table must fail closed");
        assert!(matches!(error, PublicationError::InvalidControl { .. }));

        let malformed_path = temporary.path().join("malformed.redb");
        let malformed_database =
            Database::create(&malformed_path).expect("create malformed database");
        write_project_inventory(&malformed_database, &malformed_path, b"{not-json")
            .expect("write malformed fixture");
        drop(malformed_database);
        let error = read_project_inventory(&malformed_path, &sha256_bytes(b"{not-json"))
            .expect_err("malformed inventory must fail closed");
        assert!(matches!(error, PublicationError::InvalidControl { .. }));

        let canonical = canonical_project_inventory_bytes(&test_inventory())
            .expect("canonical project inventory");
        let document: serde_json::Value =
            serde_json::from_slice(&canonical).expect("parse canonical fixture");
        let noncanonical = serde_json::to_vec_pretty(&document).expect("pretty inventory fixture");
        let noncanonical_path = temporary.path().join("noncanonical.redb");
        let noncanonical_database =
            Database::create(&noncanonical_path).expect("create noncanonical database");
        write_project_inventory(&noncanonical_database, &noncanonical_path, &noncanonical)
            .expect("write noncanonical fixture");
        drop(noncanonical_database);
        let error = read_project_inventory(&noncanonical_path, &sha256_bytes(&noncanonical))
            .expect_err("noncanonical inventory must fail closed");
        assert!(matches!(error, PublicationError::InvalidControl { .. }));

        let mismatch_path = temporary.path().join("mismatch.redb");
        let mismatch_database = Database::create(&mismatch_path).expect("create mismatch database");
        write_project_inventory(&mismatch_database, &mismatch_path, &canonical)
            .expect("write canonical fixture");
        drop(mismatch_database);
        let error = read_project_inventory(&mismatch_path, &sha256_bytes(b"wrong-inventory"))
            .expect_err("inventory digest mismatch must fail closed");
        assert!(matches!(error, PublicationError::DigestMismatch { .. }));
    }

    #[test]
    fn generation_identity_changes_when_only_project_inventory_changes() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "same-payload", Vec::new());

        let mut changed_inventory = test_inventory();
        let project_unit_id = changed_inventory.project_topology.units[0]
            .project_unit_id
            .clone();
        changed_inventory
            .project_topology
            .memberships
            .push(DocumentMembership {
                document_path: "src/other.rs".into(),
                language_id: LanguageId::new("rust"),
                project_unit_id,
                kind: DocumentMembershipKind::SourceOwner,
            });
        let workspace = workspace_with_payload(&publisher, "same-payload");
        let second = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("same-payload".into()),
                    project_inventory: changed_inventory.clone(),
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect("publish changed inventory");

        assert_ne!(first.manifest.generation_id, second.manifest.generation_id);
        assert_ne!(
            first.manifest.project_inventory_sha256,
            second.manifest.project_inventory_sha256
        );
        assert_eq!(second.project_inventory.as_ref(), &changed_inventory);
        assert_eq!(
            resolve_generation(&fixture.graph, &fixture.root)
                .expect("resolve changed inventory")
                .project_inventory
                .as_ref(),
            &changed_inventory
        );
    }

    #[tokio::test]
    async fn graph_index_and_publication_tables_coexist_in_one_generation_database() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = publisher
            .begin_generation()
            .expect("begin private generation");
        let database = workspace.database();
        let graph_store = GraphStore::new(Arc::clone(&database));
        let index_state =
            IndexState::new(Arc::clone(&database)).expect("index tables in shared database");
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(graph_node("shared_boundary"))
            .expect("add graph node");
        graph_store
            .save_snapshot(&graph)
            .await
            .expect("write graph tables");
        graph_store
            .set_origin(&fixture.root)
            .await
            .expect("write graph origin");
        graph_store
            .set_generation_metadata(GraphGenerationMetadata::now(false))
            .await
            .expect("write required generation metadata");
        index_state
            .set_file(
                "src/shared_boundary.rs",
                &FileRecord {
                    blake3_hash: "file-hash".into(),
                    last_indexed: 42,
                    symbol_count: 1,
                    language: "rust".into(),
                },
            )
            .expect("write index file table");
        index_state
            .set_metadata(&IndexMetadata {
                repo_root: fixture.root.to_string_lossy().into_owned(),
                last_full_scan: Some(40),
                last_update: Some(42),
                git_head: Some("test-head".into()),
                total_files: 1,
                total_symbols: 1,
                total_edges: 0,
            })
            .expect("write index metadata table");
        drop(index_state);
        drop(graph_store);
        drop(database);

        let published = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("shared-database".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![complete_receipt("calls")],
                    provider_payloads: provider_payloads_for(
                        &[complete_receipt("calls")],
                        &test_inventory(),
                    ),
                },
            )
            .expect("publish shared database");
        let read_only = Arc::new(
            ReadOnlyDatabase::open(&published.database_path)
                .expect("open published database read-only"),
        );
        let read_graph = GraphStore::new_read_only(Arc::clone(&read_only));
        let read_index = IndexState::new_read_only(Arc::clone(&read_only));

        let loaded = read_graph
            .load_snapshot()
            .await
            .expect("read graph tables")
            .expect("graph snapshot exists");
        assert_eq!(loaded.node_count(), 1);
        assert_eq!(
            loaded
                .all_nodes()
                .first()
                .expect("published graph node")
                .symbol_name,
            "shared_boundary"
        );
        let file = read_index
            .get_file("src/shared_boundary.rs")
            .expect("read index file table")
            .expect("index file exists");
        assert_eq!(file.blake3_hash, "file-hash");
        assert_eq!(file.symbol_count, 1);
        let metadata = read_index
            .get_metadata()
            .expect("read index metadata table")
            .expect("index metadata exists");
        assert_eq!(metadata.total_files, 1);
        assert_eq!(metadata.total_symbols, 1);
        assert!(matches!(
            read_index.set_file("must-not-write.rs", &file),
            Err(IndexStateError::ReadOnly)
        ));
    }

    #[tokio::test]
    async fn real_index_pipeline_builds_and_publishes_from_a_private_generation() {
        let fixture = Fixture::new();
        let source_directory = fixture.root.join("src");
        fs::create_dir(&source_directory).expect("source directory");
        fs::write(
            source_directory.join("lib.rs"),
            b"pub fn publication_pipeline_symbol() -> usize { 42 }\n",
        )
        .expect("scratch Rust source");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"publication-pipeline-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        fs::write(
            fixture.root.join("build.rs"),
            br#"fn main() {
    let root = std::env::var_os("CARGO_MANIFEST_DIR").unwrap();
    std::fs::write(
        std::path::Path::new(&root).join("compiler-analysis-executed.txt"),
        b"implicit compiler analysis executed repository code\n",
    )
    .unwrap();
}
"#,
        )
        .expect("harmless mutation-control build script");
        let root_entries_before = child_names(&fixture.root);
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = publisher
            .begin_generation()
            .expect("begin private generation");
        let database = workspace.database();
        let graph_store = GraphStore::new(Arc::clone(&database));
        let index_state =
            IndexState::new(Arc::clone(&database)).expect("index state in private generation");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: true,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            ..IndexConfig::default()
        };

        let report = IndexPipeline::run(&index_state, Some(&graph_store), &config, None)
            .await
            .expect("run real private indexing pipeline");

        assert_eq!(report.files_discovered, 2);
        assert_eq!(report.files_changed, 2);
        assert!(report.symbols_extracted >= 1);
        assert!(report.nodes_added >= 1);
        assert_eq!(child_names(&fixture.root), root_entries_before);
        assert!(!fixture.root.join("index.scip").exists());
        assert!(!fixture.root.join("Cargo.lock").exists());
        assert!(!fixture.root.join("target").exists());
        assert!(
            !fixture.root.join("compiler-analysis-executed.txt").exists(),
            "structural indexing must not execute repository build scripts"
        );
        let evidence = report.evidence().expect("completed pipeline evidence");
        let project_inventory = evidence.project_inventory.clone();
        let receipts = evidence.capability_receipts.clone();
        drop(index_state);
        drop(graph_store);
        drop(database);

        let published = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("private-pipeline".into()),
                    project_inventory: project_inventory.clone(),
                    provider_payloads: provider_payloads_for(&receipts, &project_inventory),
                    receipts,
                },
            )
            .expect("publish private pipeline generation");
        assert_eq!(published.project_inventory.as_ref(), &project_inventory);
        let read_only = Arc::new(
            ReadOnlyDatabase::open(&published.database_path)
                .expect("open pipeline generation read-only"),
        );
        let read_graph = GraphStore::new_read_only(Arc::clone(&read_only));
        let read_index = IndexState::new_read_only(Arc::clone(&read_only));
        let loaded = read_graph
            .load_snapshot()
            .await
            .expect("read pipeline graph")
            .expect("pipeline graph exists");

        assert!(
            loaded
                .all_nodes()
                .iter()
                .any(|node| { node.symbol_name.contains("publication_pipeline_symbol") })
        );
        assert!(
            read_index
                .get_file("src/lib.rs")
                .expect("read pipeline file record")
                .is_some()
        );
        assert_eq!(
            read_index
                .get_metadata()
                .expect("read pipeline metadata")
                .expect("pipeline metadata exists")
                .total_files,
            2
        );
    }

    #[tokio::test]
    async fn immutable_publication_reuses_facts_and_re_resolves_cross_file_edges() {
        let fixture = Fixture::new();
        let source_directory = fixture.root.join("src");
        fs::create_dir(&source_directory).expect("source directory");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"incremental-publication\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        fs::write(
            source_directory.join("lib.rs"),
            b"pub mod target;\npub use crate::target::Widget;\n",
        )
        .expect("unchanged relationship source");
        let target = source_directory.join("target.rs");
        fs::write(&target, b"pub struct Widget;\n").expect("relationship target");

        let config = IndexConfig {
            root: fixture.root.clone(),
            full: false,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            ..IndexConfig::default()
        };
        let first = publish_fresh_index_generation(&fixture.graph, &config, None)
            .await
            .expect("publish initial generation");
        assert_eq!(first.telemetry.files_changed, 2);

        fs::write(
            &target,
            b"pub struct Widget;\nimpl Widget { pub fn new() -> Self { Self } }\n",
        )
        .expect("modify only relationship target");
        let second = publish_fresh_index_generation(&fixture.graph, &config, None)
            .await
            .expect("publish incremental generation");
        assert_eq!(second.telemetry.files_changed, 1);
        assert_eq!(second.telemetry.files_unchanged, 1);
        assert_ne!(
            first.publication.manifest.generation_id,
            second.publication.manifest.generation_id
        );

        let database = Arc::new(
            ReadOnlyDatabase::open(&second.publication.database_path)
                .expect("open incremental generation"),
        );
        let graph = GraphStore::new_read_only(Arc::clone(&database))
            .load_snapshot()
            .await
            .expect("read incremental graph")
            .expect("incremental graph snapshot");
        let state = IndexState::new_read_only(database);
        let fact_symbol_count = state
            .all_document_facts()
            .expect("read incremental document facts")
            .iter()
            .map(|facts| facts.symbols.len() as u64)
            .sum::<u64>();
        let metadata = state
            .get_metadata()
            .expect("read incremental metadata")
            .expect("incremental metadata");
        assert_eq!(metadata.total_files, 2);
        assert_eq!(metadata.total_symbols, fact_symbol_count);
        assert_eq!(metadata.total_edges, graph.edge_count() as u64);
        let widget_id = graph
            .all_nodes()
            .into_iter()
            .find(|node| {
                node.file_path == "src/target.rs"
                    && node.symbol_name == "Widget"
                    && node.kind == "struct"
            })
            .expect("recreated Widget node")
            .memory_id;
        assert!(
            graph.all_edges().into_iter().any(|(_, target, edge)| {
                target == widget_id && edge.kind == crate::graph::EdgeKind::References
            }),
            "immutable incremental publication must resolve edges from unchanged facts"
        );
    }

    #[tokio::test]
    async fn real_mixed_pipeline_receipts_round_trip_without_invented_project_units() {
        use crate::code_intel_domain::{CapabilityScope, CapabilityStatus};

        let fixture = Fixture::new();
        fs::create_dir(fixture.root.join("src")).expect("Rust source directory");
        fs::write(
            fixture.root.join("src/lib.rs"),
            b"pub fn rust_pipeline_symbol() -> usize { 42 }\n",
        )
        .expect("scratch Rust source");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"mixed-pipeline-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        fs::write(
            fixture.root.join("main.go"),
            b"package main\nfunc goPipelineSymbol() int { return 42 }\n",
        )
        .expect("scratch Go source");
        fs::write(
            fixture.root.join("go.mod"),
            b"module example.test/mixed\n\ngo 1.25\n",
        )
        .expect("scratch Go manifest");

        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = publisher
            .begin_generation()
            .expect("begin private generation");
        let database = workspace.database();
        let graph_store = GraphStore::new(Arc::clone(&database));
        let index_state =
            IndexState::new(Arc::clone(&database)).expect("index state in private generation");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: true,
            scip: crate::index_pipeline::ScipMode::Disabled,
            ..IndexConfig::default()
        };

        let outcome = IndexPipeline::run(&index_state, Some(&graph_store), &config, None)
            .await
            .expect("run real mixed indexing pipeline");
        let evidence = outcome
            .evidence()
            .expect("a completed non-dry run must return publication evidence");
        let receipts = evidence.capability_receipts.clone();
        let project_inventory = evidence.project_inventory.clone();
        assert_eq!(
            receipts.len(),
            4,
            "structural + Calls evidence per language"
        );
        for language in ["go", "rust"] {
            assert!(
                receipts.iter().any(|receipt| {
                    receipt.capability_id == "structural_graph"
                        && receipt.status == CapabilityStatus::Complete
                        && matches!(
                            &receipt.scope,
                            CapabilityScope::Language { language_id, .. }
                                if language_id.0 == language
                        )
                }),
                "missing complete structural receipt for {language}: {receipts:?}"
            );
            assert!(
                receipts.iter().any(|receipt| {
                    receipt.capability_id == "calls"
                        && receipt.status != CapabilityStatus::Complete
                        && receipt.reason_code.as_deref() == Some("provider_not_requested")
                        && matches!(
                            &receipt.scope,
                            CapabilityScope::Language { language_id, .. }
                                if language_id.0 == language
                        )
                }),
                "missing honest unavailable Calls receipt for {language}: {receipts:?}"
            );
        }
        assert!(receipts.iter().all(|receipt| {
            !matches!(receipt.scope, CapabilityScope::ProjectUnit { .. })
                && receipt
                    .input_fingerprint
                    .as_ref()
                    .is_none_or(|fingerprint| {
                        fingerprint.len() == 64
                            && fingerprint
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    })
        }));
        drop(index_state);
        drop(graph_store);
        drop(database);

        let published = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("mixed-pipeline".into()),
                    project_inventory: project_inventory.clone(),
                    receipts: receipts.clone(),
                    provider_payloads: provider_payloads_for(&receipts, &project_inventory),
                },
            )
            .expect("publish real pipeline receipts");
        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("resolve mixed pipeline generation");
        assert_eq!(published.manifest.receipts, receipts);
        assert_eq!(resolved.manifest.receipts, receipts);
        assert_eq!(published.project_inventory.as_ref(), &project_inventory);
        assert_eq!(resolved.project_inventory.as_ref(), &project_inventory);
    }

    #[tokio::test]
    async fn fresh_index_generation_pipeline_failure_never_publishes_a_head() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.root.join("src")).expect("source directory");
        fs::write(
            fixture.root.join("src/lib.rs"),
            b"pub fn must_not_be_published() {}\n",
        )
        .expect("scratch Rust source");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"failed-publication-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: true,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            exclude: vec!["[".into()],
            ..IndexConfig::default()
        };

        let error = publish_fresh_index_generation(
            &fixture.graph,
            &config,
            Some("pipeline-must-fail".into()),
        )
        .await
        .expect_err("invalid discovery override must fail before publication");

        assert!(
            matches!(
                &error,
                IndexGenerationPublicationError::Pipeline(IndexPipelineError::SourceDiscovery(
                    crate::source_discovery::SourceDiscoveryError::InvalidExclusion { .. }
                ))
            ),
            "unexpected pipeline failure variant: {error:?}"
        );
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
        assert!(
            HEAD_FILES
                .iter()
                .all(|head| !fixture.publication_directory().join(head).exists())
        );
    }

    #[tokio::test]
    async fn fresh_index_generation_publishes_one_coherent_database() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.root.join("src")).expect("source directory");
        fs::write(
            fixture.root.join("src/lib.rs"),
            b"pub fn coherent_generation_symbol() -> usize { 42 }\n",
        )
        .expect("scratch Rust source");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"coherent-publication-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: true,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            ..IndexConfig::default()
        };

        let outcome = publish_fresh_index_generation(
            &fixture.graph,
            &config,
            Some("coherent-generation".into()),
        )
        .await
        .expect("publish fresh index generation");
        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("resolve published generation");

        assert_eq!(outcome.telemetry.files_discovered, 1);
        assert_eq!(
            resolved.manifest.generation_id,
            outcome.publication.manifest.generation_id
        );
        assert_eq!(
            resolved.project_inventory,
            outcome.publication.project_inventory
        );
        assert_eq!(
            resolved.manifest.receipts,
            outcome.publication.manifest.receipts
        );
        assert!(!resolved.manifest.receipts.is_empty());

        let database = Arc::new(
            ReadOnlyDatabase::open(&resolved.database_path)
                .expect("open coherent generation read-only"),
        );
        let graph_store = GraphStore::new_read_only(Arc::clone(&database));
        let index_state = IndexState::new_read_only(Arc::clone(&database));
        let graph = graph_store
            .load_snapshot()
            .await
            .expect("read coherent graph")
            .expect("coherent graph exists");
        assert!(
            graph
                .all_nodes()
                .iter()
                .any(|node| node.symbol_name.contains("coherent_generation_symbol"))
        );
        assert!(
            index_state
                .get_file("src/lib.rs")
                .expect("read coherent index")
                .is_some()
        );
    }

    /// RIGHT-REASON FALSIFIER: the path digest that selected a generation does
    /// not authenticate a different redb handle opened later. A valid copied
    /// database can retain every currently checked authority table while its
    /// graph population differs. Open-handle admission must reject that graph
    /// before it can become a reusable live basis.
    #[tokio::test]
    async fn open_generation_authority_rejects_substituted_graph_population() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.root.join("src")).expect("source directory");
        fs::write(
            fixture.root.join("src/lib.rs"),
            b"pub fn graph_population_control() -> usize { 42 }\n",
        )
        .expect("scratch Rust source");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"open-handle-population-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: true,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            ..IndexConfig::default()
        };

        publish_fresh_index_generation(
            &fixture.graph,
            &config,
            Some("open-handle-population".into()),
        )
        .await
        .expect("publish populated control generation");
        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("resolve populated control generation");
        let original_database = Arc::new(
            ReadOnlyDatabase::open(&resolved.database_path)
                .expect("open original generation handle"),
        );
        validate_open_generation_authority(
            Arc::clone(&original_database),
            &resolved,
            &fixture.root,
        )
        .expect("unmodified opened generation remains a positive control");
        let original_graph = GraphStore::new_read_only(Arc::clone(&original_database))
            .load_snapshot_checked(&fixture.root)
            .await
            .expect("load original graph")
            .expect("original graph population");
        let original_node = original_graph
            .all_nodes()
            .into_iter()
            .find(|node| node.symbol_name == "graph_population_control")
            .expect("populated graph known-positive");
        let memory_id = original_node.memory_id;
        let original_signature = original_node.signature.clone();
        let original_files = IndexState::new_read_only(Arc::clone(&original_database))
            .all_files()
            .expect("populated source records");
        assert_eq!(original_files.len(), 1, "nonempty source-record control");
        drop(original_database);

        let substituted_path = fixture.graph.join("substituted-generation.redb");
        fs::copy(&resolved.database_path, &substituted_path)
            .expect("copy exact generation before graph substitution");
        let substituted_database = Arc::new(
            Database::open(&substituted_path).expect("open substituted generation for mutation"),
        );
        let substituted_store = GraphStore::new(Arc::clone(&substituted_database));
        let mut substituted_graph = substituted_store
            .load_snapshot()
            .await
            .expect("load substituted graph")
            .expect("substituted graph population");
        let substituted_node = substituted_graph
            .node_mut(&memory_id)
            .expect("same deterministic node exists in substituted graph");
        substituted_node.signature = "fn graph_population_control() -> &'static str".into();
        assert_ne!(
            substituted_node.signature, original_signature,
            "positive control: substituted graph bytes differ"
        );
        substituted_store
            .save_snapshot(&substituted_graph)
            .await
            .expect("persist substituted graph without changing authority tables");
        drop(substituted_store);
        drop(substituted_database);

        assert_eq!(
            read_manifest(&substituted_path).expect("substituted manifest"),
            read_manifest(&resolved.database_path).expect("original manifest"),
            "the currently checked manifest authority remains byte-identical"
        );
        let substituted_database = Arc::new(
            ReadOnlyDatabase::open(&substituted_path)
                .expect("open substituted generation read-only"),
        );
        let error =
            validate_open_generation_authority(substituted_database, &resolved, &fixture.root)
                .expect_err("substituted graph population must not inherit original authority");
        assert!(
            error.to_string().contains("content proof"),
            "rejection must identify opened population authority, not an unrelated guard: {error}"
        );
    }

    /// Sibling falsifier for the source facts used by incremental WATCH. A
    /// copied database whose manifest and graph remain intact must not be able
    /// to substitute different extraction facts under the original generation
    /// authority.
    #[tokio::test]
    async fn open_generation_authority_rejects_substituted_source_fact_population() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.root.join("src")).expect("source directory");
        fs::write(
            fixture.root.join("src/lib.rs"),
            b"pub fn source_fact_control() -> usize { 42 }\n",
        )
        .expect("scratch Rust source");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"open-handle-source-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: true,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            ..IndexConfig::default()
        };

        publish_fresh_index_generation(
            &fixture.graph,
            &config,
            Some("open-handle-source-population".into()),
        )
        .await
        .expect("publish populated control generation");
        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("resolve populated control generation");
        let original_database = Arc::new(
            ReadOnlyDatabase::open(&resolved.database_path)
                .expect("open original generation handle"),
        );
        let opened =
            validate_open_generation_authority(original_database, &resolved, &fixture.root)
                .expect("unmodified source facts remain a positive control");
        assert!(
            opened
                .graph
                .all_nodes()
                .iter()
                .any(|node| node.symbol_name == "source_fact_control"),
            "nonempty graph known-positive"
        );
        let mut basis = opened.incremental_basis;
        let source_fact = basis
            .document_facts
            .iter_mut()
            .find(|facts| facts.file_path == "src/lib.rs")
            .expect("populated source-fact known-positive");
        let symbol = source_fact
            .symbols
            .iter_mut()
            .find(|symbol| symbol.name == "source_fact_control")
            .expect("populated extracted-symbol known-positive");
        let original_signature = symbol.signature.clone();
        symbol.signature = "fn source_fact_control() -> &'static str".into();
        assert_ne!(
            symbol.signature, original_signature,
            "positive control: substituted extraction facts differ"
        );

        let substituted_path = fixture.graph.join("substituted-source-generation.redb");
        fs::copy(&resolved.database_path, &substituted_path)
            .expect("copy exact generation before source-fact substitution");
        let substituted_database = Arc::new(
            Database::open(&substituted_path)
                .expect("open substituted generation for source-state mutation"),
        );
        let substituted_state =
            IndexState::new(Arc::clone(&substituted_database)).expect("open substituted state");
        substituted_state
            .replace_source_state(&basis.files, &basis.document_facts)
            .expect("persist substituted source facts");
        drop(substituted_state);
        drop(substituted_database);

        assert_eq!(
            read_manifest(&substituted_path).expect("substituted manifest"),
            read_manifest(&resolved.database_path).expect("original manifest"),
            "the manifest authority remains byte-identical"
        );
        let substituted_database = Arc::new(
            ReadOnlyDatabase::open(&substituted_path)
                .expect("open substituted generation read-only"),
        );
        let error =
            validate_open_generation_authority(substituted_database, &resolved, &fixture.root)
                .expect_err("substituted source facts must not inherit original authority");
        assert!(
            error.to_string().contains("index-state content proof"),
            "rejection must identify source-population authority: {error}"
        );
    }

    #[test]
    fn abandoned_and_unreferenced_generations_are_never_adopted() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");

        let abandoned = workspace_with_payload(&publisher, "abandoned");
        assert!(abandoned.staging_directory().is_dir());
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
        drop(abandoned);

        let published = publish(
            &mut publisher,
            "valid-but-unreferenced",
            vec![complete_receipt("calls")],
        );
        assert_eq!(
            resolve_generation(&fixture.graph, &fixture.root)
                .expect("referenced generation positive control")
                .manifest
                .generation_id,
            published.manifest.generation_id
        );
        remove_heads(&fixture);

        assert!(published.database_path.is_file());
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
    }

    #[test]
    fn successful_publication_reclaims_abandoned_staging_and_old_generations() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let abandoned = publisher.begin_generation().expect("abandoned workspace");
        let abandoned_path = abandoned.staging_directory().to_path_buf();
        drop(abandoned);

        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let third = publish(&mut publisher, "third", vec![complete_receipt("calls")]);

        assert!(
            !abandoned_path.exists(),
            "abandoned staging must be reclaimed"
        );
        assert!(
            !first.database_path.exists(),
            "a generation no longer named by either head must be reclaimed"
        );
        assert!(second.database_path.is_file());
        assert!(third.database_path.is_file());
        let generation_children =
            child_names(&fixture.publication_directory().join(GENERATIONS_DIRECTORY));
        assert_eq!(generation_children.len(), 2);
        assert!(
            generation_children.contains(&second.manifest.generation_id.0)
                && generation_children.contains(&third.manifest.generation_id.0)
        );
    }

    #[test]
    fn corrupt_newest_generation_falls_back_to_the_older_reference() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);

        corrupt_file(&second.database_path);

        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("older referenced generation remains valid");
        assert_eq!(
            resolved.manifest.generation_id,
            first.manifest.generation_id
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_newest_generation_falls_back_without_following_it() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let generation_directory = second
            .database_path
            .parent()
            .expect("generation directory")
            .to_path_buf();
        let displaced = fixture.graph.join("displaced-generation");
        fs::rename(&generation_directory, &displaced).expect("displace newest generation");
        symlink(&displaced, &generation_directory).expect("symlink newest generation fixture");

        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("older referenced generation remains valid");
        assert_eq!(
            resolved.manifest.generation_id,
            first.manifest.generation_id
        );
    }

    #[test]
    fn resolving_a_valid_generation_does_not_rewrite_publication_bytes() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let published = publish(&mut publisher, "read-only", vec![complete_receipt("calls")]);
        drop(publisher);
        let publication_directory = fixture.publication_directory();
        let repository_path = publication_directory.join(REPOSITORY_FILE);
        let active = resolve_generation(&fixture.graph, &fixture.root).expect("active generation");
        let head_path = fixture.head_path(active.slot);
        let publication_entries_before = child_names(&publication_directory);
        let generation_entries_before =
            child_names(publication_directory.join(GENERATIONS_DIRECTORY).as_path());
        let repository_hash_before = sha256_file(&repository_path).expect("repository digest");
        let head_hash_before = sha256_file(&head_path).expect("head digest");
        let database_hash_before =
            sha256_file(&published.database_path).expect("generation digest");

        let resolved =
            resolve_generation(&fixture.graph, &fixture.root).expect("resolve read-only");

        assert_eq!(
            resolved.manifest.generation_id,
            published.manifest.generation_id
        );
        assert_eq!(
            child_names(&publication_directory),
            publication_entries_before
        );
        assert_eq!(
            child_names(publication_directory.join(GENERATIONS_DIRECTORY).as_path()),
            generation_entries_before
        );
        assert_eq!(
            sha256_file(&repository_path).expect("repository digest after read"),
            repository_hash_before
        );
        assert_eq!(
            sha256_file(&head_path).expect("head digest after read"),
            head_hash_before
        );
        assert_eq!(
            sha256_file(&published.database_path).expect("generation digest after read"),
            database_hash_before
        );
    }

    #[test]
    fn resolved_generation_token_is_from_the_admitting_control_population() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);

        let (resolved, admitted_token) =
            resolve_generation_with_control_token(&fixture.graph, &fixture.root)
                .expect("resolve generation with admitting controls");
        assert_eq!(
            resolved.manifest.generation_id, first.manifest.generation_id,
            "positive control: the paired token must accompany the selected generation"
        );
        assert_eq!(
            admitted_token,
            publication_control_token(&fixture.graph, &fixture.root)
                .expect("unchanged terminal control read")
        );

        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let advanced_token = publication_control_token(&fixture.graph, &fixture.root)
            .expect("advanced terminal control read");
        assert_ne!(
            advanced_token, admitted_token,
            "a concurrent head advance must invalidate the admitting token"
        );
        assert_ne!(
            second.manifest.generation_id, resolved.manifest.generation_id,
            "positive control: publication must actually advance to new generation evidence"
        );
    }

    #[test]
    fn bounded_head_token_detects_control_changes_without_reading_generation_payload() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let first_token = publication_control_token(&fixture.graph, &fixture.root)
            .expect("read first bounded control token");
        let first_witness = publication_control_witness(&fixture.graph);

        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let second_token = publication_control_token(&fixture.graph, &fixture.root)
            .expect("read second bounded control token");
        let second_witness = publication_control_witness(&fixture.graph);
        assert_ne!(
            first_token, second_token,
            "publishing a new head must change the control token"
        );
        assert_ne!(
            first_witness, second_witness,
            "publishing a new head must change the bounded metadata witness"
        );

        fs::remove_file(&second.database_path).expect("remove referenced payload fixture");
        fs::create_dir(&second.database_path)
            .expect("replace referenced payload with a non-file fixture");
        let token_with_unreadable_payload =
            publication_control_token(&fixture.graph, &fixture.root)
                .expect("control-token reads must not inspect generation payloads");
        assert_eq!(
            token_with_unreadable_payload, second_token,
            "payload state is outside the bounded change-detection token"
        );
        assert_eq!(
            publication_control_witness(&fixture.graph),
            second_witness,
            "payload state must also remain outside the bounded metadata witness"
        );

        assert!(first.database_path.is_file(), "positive payload control");
        assert!(
            matches!(
                resolve_generation(&fixture.graph, &fixture.root),
                Ok(resolved) if resolved.manifest.generation_id == first.manifest.generation_id
            ),
            "full validation remains the separate semantic authority and must fall back"
        );
    }

    #[test]
    fn all_invalid_referenced_generations_fail_closed() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        corrupt_file(&first.database_path);
        corrupt_file(&second.database_path);

        let error = resolve_generation(&fixture.graph, &fixture.root)
            .expect_err("no corrupt referenced generation may be used");
        assert!(matches!(error, PublicationError::NoValidGeneration { .. }));
    }

    #[test]
    fn normal_publisher_replaces_only_authenticated_obsolete_generation_schemas() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "obsolete", Vec::new());
        drop(publisher);

        let (obsolete_head, obsolete_database) =
            rewrite_generation_schema(&fixture, &first, "h00/code-intel/generation/v3");
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::NoCompatibleGenerationSchema { .. })
        ));

        // Non-vacuity/sabotage control: one malformed head makes the
        // population ambiguous rather than "merely old" and must keep strict
        // admission fail-closed without changing any surviving authority.
        let invalid_head = fixture.head_path(1);
        fs::write(&invalid_head, b"invalid-head-control").expect("invalid second head");
        let repository_path = fixture.publication_directory().join(REPOSITORY_FILE);
        let repository_before = sha256_file(&repository_path).expect("repository digest before");
        let head_before = sha256_file(&obsolete_head).expect("obsolete head digest before");
        let database_before =
            sha256_file(&obsolete_database).expect("obsolete database digest before");
        let error = match SemanticPublisher::acquire(&fixture.graph, &fixture.root) {
            Ok(_) => panic!("mixed malformed and obsolete controls must be refused"),
            Err(error) => error,
        };
        assert!(matches!(error, PublicationError::NoValidGeneration { .. }));
        assert_eq!(
            sha256_file(&repository_path).expect("repository digest after refusal"),
            repository_before
        );
        assert_eq!(
            sha256_file(&obsolete_head).expect("obsolete head digest after refusal"),
            head_before
        );
        assert_eq!(
            sha256_file(&obsolete_database).expect("obsolete database digest after refusal"),
            database_before
        );
        assert_eq!(
            fs::read(&invalid_head).expect("invalid head after refusal"),
            b"invalid-head-control"
        );
        fs::remove_file(&invalid_head).expect("remove sabotage control");

        let mut replacement_publisher = SemanticPublisher::acquire(&fixture.graph, &fixture.root)
            .expect("normal publisher admits authenticated obsolete derived state");
        let replacement = publish(&mut replacement_publisher, "replacement", Vec::new());
        drop(replacement_publisher);
        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("resolve replacement generation");
        assert_eq!(
            resolved.manifest.generation_id,
            replacement.manifest.generation_id
        );
        assert_eq!(resolved.manifest.schema_version, GENERATION_SCHEMA);
        assert_eq!(
            sha256_file(&repository_path).expect("repository digest after replacement"),
            repository_before,
            "schema replacement must retain the same repository authority"
        );
    }

    #[test]
    fn equal_sequence_heads_with_different_generations_fail_closed() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let newest = resolve_generation(&fixture.graph, &fixture.root).expect("newest generation");
        assert_eq!(newest.manifest.generation_id, second.manifest.generation_id);
        let older_slot = 1 - newest.slot;
        let mut conflicting_body = first.head.body;
        conflicting_body.sequence = newest.head.body.sequence;
        let conflicting = seal_head(conflicting_body).expect("seal conflicting head fixture");
        replace_head(&fixture.head_path(older_slot), &conflicting);

        let error = resolve_generation(&fixture.graph, &fixture.root)
            .expect_err("equal sequence cannot be tie-broken silently");
        assert!(matches!(error, PublicationError::HeadConflict { .. }));
    }

    #[test]
    fn only_one_publisher_can_hold_the_publication_lock() {
        let fixture = Fixture::new();
        let first =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("first publisher");

        let error = match SemanticPublisher::acquire(&fixture.graph, &fixture.root) {
            Ok(_) => panic!("second publisher must be refused"),
            Err(error) => error,
        };
        assert!(matches!(error, PublicationError::WriterBusy { .. }));

        drop(first);
        SemanticPublisher::acquire(&fixture.graph, &fixture.root)
            .expect("lock is released with publisher");
    }

    #[test]
    fn publisher_lock_child_process() {
        use std::time::{Duration, Instant};

        if std::env::var_os("H00_PUBLICATION_LOCK_CHILD").is_none() {
            return;
        }
        let graph = PathBuf::from(
            std::env::var_os("H00_PUBLICATION_LOCK_GRAPH").expect("child graph path"),
        );
        let root =
            PathBuf::from(std::env::var_os("H00_PUBLICATION_LOCK_ROOT").expect("child root path"));
        let ready = PathBuf::from(
            std::env::var_os("H00_PUBLICATION_LOCK_READY").expect("child ready path"),
        );
        let release = PathBuf::from(
            std::env::var_os("H00_PUBLICATION_LOCK_RELEASE").expect("child release path"),
        );
        let _publisher = SemanticPublisher::acquire(&graph, &root).expect("child publisher");
        fs::write(&ready, b"ready").expect("signal child publisher ready");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !release.exists() {
            assert!(
                Instant::now() < deadline,
                "parent did not release child lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn writer_lock_excludes_a_separate_process() {
        use std::process::Command;
        use std::time::{Duration, Instant};

        let fixture = Fixture::new();
        let ready = fixture.graph.join("child-ready");
        let release = fixture.graph.join("child-release");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "code_intel_publication::tests::publisher_lock_child_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("H00_PUBLICATION_LOCK_CHILD", "1")
            .env("H00_PUBLICATION_LOCK_GRAPH", &fixture.graph)
            .env("H00_PUBLICATION_LOCK_ROOT", &fixture.root)
            .env("H00_PUBLICATION_LOCK_READY", &ready)
            .env("H00_PUBLICATION_LOCK_RELEASE", &release)
            .spawn()
            .expect("spawn publisher lock child");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            if let Some(status) = child.try_wait().expect("poll publisher lock child") {
                panic!("publisher lock child exited before ready: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "publisher lock child was not ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let error = match SemanticPublisher::acquire(&fixture.graph, &fixture.root) {
            Ok(_) => panic!("parent must not acquire child-held publisher lock"),
            Err(error) => error,
        };
        assert!(matches!(error, PublicationError::WriterBusy { .. }));
        fs::write(&release, b"release").expect("release child publisher lock");
        assert!(
            child
                .wait()
                .expect("wait for publisher lock child")
                .success()
        );
    }

    #[test]
    fn a_workspace_cannot_cross_publication_boundaries() {
        let first_fixture = Fixture::new();
        let second_fixture = Fixture::new();
        let first_publisher = SemanticPublisher::acquire(&first_fixture.graph, &first_fixture.root)
            .expect("first publisher");
        let mut second_publisher =
            SemanticPublisher::acquire(&second_fixture.graph, &second_fixture.root)
                .expect("second publisher");
        let workspace = workspace_with_payload(&first_publisher, "first-publication-payload");
        let first_staging = workspace.staging_directory().to_path_buf();

        let error = second_publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("cross-publication".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![complete_receipt("calls")],
                    provider_payloads: provider_payloads_for(
                        &[complete_receipt("calls")],
                        &test_inventory(),
                    ),
                },
            )
            .expect_err("foreign workspace must not be published");

        assert!(error.to_string().contains("workspace"));
        assert!(first_staging.is_dir());
        assert!(matches!(
            resolve_generation(&second_fixture.graph, &second_fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_substituted_staging_directory_is_rejected_before_use() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = workspace_with_payload(&publisher, "private-payload");
        let staging = workspace.staging_directory().to_path_buf();
        let displaced = fixture.graph.join("displaced-private-generation");
        let outside = fixture.graph.join("outside-directory");
        fs::create_dir(&outside).expect("outside directory fixture");
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, b"unchanged").expect("outside sentinel");
        fs::rename(&staging, &displaced).expect("displace private staging directory");
        symlink(&outside, &staging).expect("substitute staging directory with symlink");

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("substituted".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![complete_receipt("calls")],
                    provider_payloads: provider_payloads_for(
                        &[complete_receipt("calls")],
                        &test_inventory(),
                    ),
                },
            )
            .expect_err("substituted staging directory must be rejected");

        assert!(matches!(error, PublicationError::UnsafeArtifact { .. }));
        assert_eq!(
            fs::read(&sentinel).expect("outside sentinel remains"),
            b"unchanged"
        );
        assert!(displaced.is_dir());
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
    }

    #[test]
    fn identical_unreferenced_rebuild_reuses_the_content_addressed_generation() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(
            &mut publisher,
            "repeatable",
            vec![complete_receipt("calls")],
        );
        remove_heads(&fixture);
        let workspace = workspace_with_payload(&publisher, "repeatable");
        let redundant_staging = workspace.staging_directory().to_path_buf();
        let second = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("repeatable".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![complete_receipt("calls")],
                    provider_payloads: provider_payloads_for(
                        &[complete_receipt("calls")],
                        &test_inventory(),
                    ),
                },
            )
            .expect("identical rebuild is idempotent");

        assert_eq!(second.manifest.generation_id, first.manifest.generation_id);
        assert_eq!(second.database_path, first.database_path);
        assert!(!redundant_staging.exists());
        assert_eq!(
            resolve_generation(&fixture.graph, &fixture.root)
                .expect("reused generation is referenced")
                .manifest
                .generation_id,
            first.manifest.generation_id
        );
    }

    #[test]
    fn an_existing_generation_with_different_bytes_is_a_collision() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "collision", vec![complete_receipt("calls")]);
        remove_heads(&fixture);
        corrupt_file(&first.database_path);
        let workspace = workspace_with_payload(&publisher, "collision");

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("collision".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![complete_receipt("calls")],
                    provider_payloads: provider_payloads_for(
                        &[complete_receipt("calls")],
                        &test_inventory(),
                    ),
                },
            )
            .expect_err("same generation ID with different bytes must fail");

        assert!(matches!(
            error,
            PublicationError::GenerationCollision { .. }
        ));
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
    }

    #[test]
    fn repository_identity_rejects_a_different_root_without_rewriting_it() {
        let fixture = Fixture::new();
        let other_root = fixture.graph.join("other-repository");
        fs::create_dir(&other_root).expect("other repository root");
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        publish(&mut publisher, "owned", vec![complete_receipt("calls")]);
        drop(publisher);
        let repository_path = fixture.publication_directory().join(REPOSITORY_FILE);
        let before = fs::read(&repository_path).expect("repository identity before refusal");

        assert!(matches!(
            resolve_generation(&fixture.graph, &other_root),
            Err(PublicationError::RootMismatch { .. })
        ));
        assert!(matches!(
            SemanticPublisher::acquire(&fixture.graph, &other_root),
            Err(PublicationError::RootMismatch { .. })
        ));
        assert_eq!(
            fs::read(&repository_path).expect("repository identity after refusal"),
            before
        );
    }

    #[test]
    fn missing_repository_identity_with_surviving_publication_state_is_not_rebound() {
        let fixture = Fixture::new();
        let other_root = fixture.graph.join("other-repository");
        fs::create_dir(&other_root).expect("other repository root");
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        publish(&mut publisher, "owned", vec![complete_receipt("calls")]);
        drop(publisher);

        let publication_directory = fixture.publication_directory();
        let repository_path = publication_directory.join(REPOSITORY_FILE);
        let lock_path = publication_directory.join(WRITER_LOCK_FILE);
        fs::remove_file(&repository_path).expect("remove repository identity fixture");
        fs::remove_file(&lock_path).expect("remove inert writer-lock fixture");
        let before = child_names(&publication_directory);
        assert!(before.iter().any(|name| name.starts_with("head-")));
        assert!(before.iter().any(|name| name == GENERATIONS_DIRECTORY));

        let error = match SemanticPublisher::acquire(&fixture.graph, &other_root) {
            Ok(_) => panic!("surviving publication state must not acquire a new identity"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("missing repository identity"));
        assert_eq!(child_names(&publication_directory), before);
        assert!(!repository_path.exists());
        assert!(!lock_path.exists());
    }

    #[test]
    fn low_level_publisher_rejects_a_foreign_graph_origin_before_advancing_a_head() {
        let fixture = Fixture::new();
        let foreign_root = fixture.graph.join("foreign-repository");
        fs::create_dir(&foreign_root).expect("foreign repository root");
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = publisher.begin_generation().expect("generation workspace");
        let graph_store = GraphStore::new(workspace.database());
        graph_store
            .save_snapshot_sync(&KnowledgeGraph::new())
            .expect("persist foreign graph fixture");
        graph_store
            .set_origin_sync(&foreign_root)
            .expect("plant foreign graph origin");

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("foreign-origin".into()),
                    project_inventory: test_inventory(),
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect_err("foreign graph bytes must not become publication authority");
        assert!(matches!(
            error,
            PublicationError::InvalidGenerationGraph { .. }
        ));
        assert!(!fixture.head_path(0).exists());
        assert!(!fixture.head_path(1).exists());
    }

    #[tokio::test]
    async fn private_generation_starts_without_placeholder_graph_authority() {
        let fixture = Fixture::new();
        let publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = publisher.begin_generation().expect("generation workspace");
        let graph_store = GraphStore::new(workspace.database());

        assert!(
            graph_store
                .load_snapshot()
                .await
                .expect("inspect private graph")
                .is_none(),
            "a private candidate must not pay to persist a placeholder graph that no reader can observe"
        );
        assert_eq!(
            graph_store
                .get_origin()
                .await
                .expect("inspect private origin"),
            None,
            "origin authority belongs to the completed candidate graph, not an empty staging placeholder"
        );
        let database = workspace.database();
        let read = database.begin_read().expect("inspect private tables");
        let index_meta: TableDefinition<&str, &[u8]> = TableDefinition::new("index_meta");
        assert!(
            matches!(
                read.open_table(index_meta),
                Err(redb::TableError::TableDoesNotExist(_))
            ),
            "candidate creation must not commit empty index tables before an index-state owner opens them"
        );
        drop(read);
        drop(database);

        // Non-vacuity: the same store can persist and read a real candidate
        // graph when the indexing pipeline supplies one.
        graph_store
            .save_snapshot(&KnowledgeGraph::new())
            .await
            .expect("persist explicit candidate graph");
        graph_store
            .set_origin(&fixture.root)
            .await
            .expect("stamp explicit candidate origin");
        assert!(
            graph_store
                .load_snapshot()
                .await
                .expect("read explicit candidate graph")
                .is_some(),
            "positive control: explicit graph persistence must remain observable"
        );
    }

    #[test]
    fn low_level_publisher_rejects_missing_generation_metadata_before_advancing_a_head() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = publisher.begin_generation().expect("generation workspace");
        let graph_store = GraphStore::new(workspace.database());
        graph_store
            .save_snapshot_sync(&KnowledgeGraph::new())
            .expect("persist graph fixture without generation metadata");
        graph_store
            .set_origin_sync(&fixture.root)
            .expect("stamp graph fixture origin");

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("missing-generation-metadata".into()),
                    project_inventory: test_inventory(),
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect_err("an incomplete graph generation must never become authority");
        let PublicationError::InvalidGenerationGraph { reason, .. } = error else {
            panic!("expected invalid graph generation, got {error}");
        };
        assert!(
            reason.contains("generation metadata"),
            "refusal must identify the missing current-format invariant: {reason}"
        );
        assert!(!fixture.head_path(0).exists());
        assert!(!fixture.head_path(1).exists());
    }

    #[test]
    fn wrong_root_refusal_does_not_create_a_writer_lock() {
        let fixture = Fixture::new();
        let other_root = fixture.graph.join("other-repository");
        fs::create_dir(&other_root).expect("other repository root");
        let publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        drop(publisher);
        let lock_path = fixture.publication_directory().join(WRITER_LOCK_FILE);
        fs::remove_file(&lock_path).expect("remove lock fixture");

        assert!(matches!(
            SemanticPublisher::acquire(&fixture.graph, &other_root),
            Err(PublicationError::RootMismatch { .. })
        ));
        assert!(!lock_path.exists());
    }

    #[test]
    fn malformed_repository_identity_is_rejected() {
        let fixture = Fixture::new();
        let publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        drop(publisher);
        fs::write(
            fixture.publication_directory().join(REPOSITORY_FILE),
            b"not-json",
        )
        .expect("malformed repository fixture");

        let error = resolve_generation(&fixture.graph, &fixture.root)
            .expect_err("malformed repository identity is not authority");
        assert!(matches!(error, PublicationError::InvalidControl { .. }));
    }

    #[test]
    fn oversized_repository_identity_is_rejected_before_parsing() {
        let fixture = Fixture::new();
        let publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        drop(publisher);
        fs::write(
            fixture.publication_directory().join(REPOSITORY_FILE),
            vec![b'x'; (MAX_CONTROL_FILE_BYTES + 1) as usize],
        )
        .expect("oversized repository fixture");

        let error = resolve_generation(&fixture.graph, &fixture.root)
            .expect_err("oversized repository identity is not authority");
        assert!(matches!(error, PublicationError::ControlTooLarge { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_repository_identity_is_never_followed() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        drop(publisher);
        let repository_path = fixture.publication_directory().join(REPOSITORY_FILE);
        let target = fixture.graph.join("repository-target");
        fs::rename(&repository_path, &target).expect("move repository identity fixture");
        symlink(&target, &repository_path).expect("symlink repository identity fixture");

        let error = resolve_generation(&fixture.graph, &fixture.root)
            .expect_err("symlinked repository identity is unsafe");
        assert!(matches!(error, PublicationError::UnsafeArtifact { .. }));
    }

    #[tokio::test]
    async fn current_complete_capability_requires_explicit_downgrade_authority() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(
            &mut publisher,
            "complete",
            vec![CapabilityReceipt::complete(
                "calls",
                "test-provider",
                "1.0.0",
                CapabilityScope::Language {
                    language_id: LanguageId::new("rust"),
                    configuration_id: ConfigurationId::new(
                        crate::code_intel_domain::CALLS_CONFIGURATION_ID,
                    ),
                },
                sha256_bytes(b"complete-calls-inputs"),
            )],
        );
        drop(publisher);
        fs::create_dir(fixture.root.join("src")).expect("source directory");
        fs::write(
            fixture.root.join("src/lib.rs"),
            b"pub fn current_unavailable_generation() {}\n",
        )
        .expect("scratch Rust source");
        fs::write(
            fixture.root.join("Cargo.toml"),
            b"[package]\nname = \"current-unavailable-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("scratch Cargo manifest");
        let config = IndexConfig {
            root: fixture.root.clone(),
            full: true,
            scip: crate::index_pipeline::ScipMode::Disabled,
            languages: vec!["rust".into()],
            ..IndexConfig::default()
        };

        let error = publish_fresh_index_generation(
            &fixture.graph,
            &config,
            Some("current-unavailable".into()),
        )
        .await
        .expect_err("implicit capability loss must not advance current authority");
        assert!(matches!(
            error,
            IndexGenerationPublicationError::Publication(
                PublicationError::CapabilityDowngrade { .. }
            )
        ));
        let resolved =
            resolve_generation(&fixture.graph, &fixture.root).expect("current generation resolves");
        assert_eq!(
            resolved.manifest.generation_id,
            first.manifest.generation_id
        );

        let second = publish_fresh_index_generation_with_policy(
            &fixture.graph,
            &config,
            Some("explicit-current-unavailable".into()),
            PublicationRecovery::Strict,
            CapabilityFloorPolicy::AllowDowngrade,
        )
        .await
        .expect("explicit capability loss must publish current truth");
        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("explicitly downgraded generation resolves");
        assert_eq!(
            resolved.manifest.generation_id,
            second.publication.manifest.generation_id
        );
        assert_eq!(
            resolved.manifest.parent_generation_id.as_ref(),
            Some(&first.manifest.generation_id)
        );
        assert!(resolved.manifest.receipts.iter().any(|receipt| {
            receipt.capability_id == "calls"
                && receipt.status == CapabilityStatus::Unavailable
                && receipt.reason_code.as_deref() == Some("provider_not_requested")
        }));
    }

    #[test]
    fn head_sequence_and_parent_linkage_advance_monotonically() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let third = publish(&mut publisher, "third", vec![complete_receipt("calls")]);

        assert_eq!(
            [
                first.head.body.sequence,
                second.head.body.sequence,
                third.head.body.sequence,
            ],
            [1, 2, 3]
        );
        assert_eq!(
            second.manifest.parent_generation_id,
            Some(first.manifest.generation_id)
        );
        assert_eq!(
            third.manifest.parent_generation_id,
            Some(second.manifest.generation_id)
        );
        assert_eq!(
            third.head.body.previous_generation_id,
            third.manifest.parent_generation_id
        );
        assert_eq!(
            resolve_generation(&fixture.graph, &fixture.root)
                .expect("newest generation")
                .manifest
                .generation_id,
            third.manifest.generation_id
        );
    }

    #[test]
    fn temporary_head_files_are_not_publication_authority() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let published = publish(&mut publisher, "published", vec![complete_receipt("calls")]);
        fs::write(
            fixture.publication_directory().join(".head-0-crash.tmp"),
            b"newer-looking but uncommitted",
        )
        .expect("temporary head fixture");

        let resolved =
            resolve_generation(&fixture.graph, &fixture.root).expect("resolve committed head");
        assert_eq!(
            resolved.manifest.generation_id,
            published.manifest.generation_id
        );
    }

    #[cfg(unix)]
    #[test]
    fn publisher_never_replaces_or_follows_a_symlinked_head_slot() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let active = resolve_generation(&fixture.graph, &fixture.root).expect("first generation");
        let target_slot = 1 - active.slot;
        let target = fixture.graph.join("head-sentinel");
        fs::write(&target, b"unchanged").expect("head sentinel");
        symlink(&target, fixture.head_path(target_slot)).expect("symlinked target head slot");
        let workspace = workspace_with_payload(&publisher, "second");

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("second".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![complete_receipt("calls")],
                    provider_payloads: provider_payloads_for(
                        &[complete_receipt("calls")],
                        &test_inventory(),
                    ),
                },
            )
            .expect_err("publisher must not replace an unsafe head slot");

        assert!(matches!(error, PublicationError::UnsafeArtifact { .. }));
        assert_eq!(
            fs::read(&target).expect("head sentinel remains"),
            b"unchanged"
        );
        assert_eq!(
            resolve_generation(&fixture.graph, &fixture.root)
                .expect("first head remains authoritative")
                .manifest
                .generation_id,
            first.manifest.generation_id
        );
    }

    #[test]
    fn oversized_newest_head_falls_back_to_the_older_valid_reference() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let newest = resolve_generation(&fixture.graph, &fixture.root).expect("newest generation");
        fs::write(
            fixture.head_path(newest.slot),
            vec![b'x'; (MAX_CONTROL_FILE_BYTES + 1) as usize],
        )
        .expect("oversized newest head fixture");

        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("older referenced generation remains usable");
        assert_eq!(
            resolved.manifest.generation_id,
            first.manifest.generation_id
        );
    }

    #[test]
    fn no_valid_head_is_distinct_from_no_valid_generation() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        for slot in 0..HEAD_FILES.len() {
            fs::write(fixture.head_path(slot), b"not-json").expect("malformed head fixture");
        }

        let error = resolve_generation(&fixture.graph, &fixture.root)
            .expect_err("malformed heads cannot name a generation");
        assert!(matches!(error, PublicationError::NoValidHead { .. }));
    }

    #[test]
    fn invalid_heads_require_explicit_recovery_and_republish_both_slots() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        drop(publisher);
        for slot in 0..HEAD_FILES.len() {
            fs::write(fixture.head_path(slot), format!("invalid-head-{slot}"))
                .expect("malformed head fixture");
        }
        let malformed = HEAD_FILES
            .iter()
            .map(|file| fs::read(fixture.publication_directory().join(file)).unwrap())
            .collect::<Vec<_>>();

        let strict = match SemanticPublisher::acquire(&fixture.graph, &fixture.root) {
            Ok(_) => panic!("strict admission must reject a publication with no valid head"),
            Err(error) => error,
        };
        assert!(matches!(strict, PublicationError::NoValidHead { .. }));
        for (slot, expected) in malformed.iter().enumerate() {
            assert_eq!(
                fs::read(fixture.head_path(slot)).expect("head after strict refusal"),
                *expected,
                "strict refusal must not reinterpret or repair malformed controls"
            );
        }

        let mut recovery = SemanticPublisher::acquire_with_recovery(
            &fixture.graph,
            &fixture.root,
            PublicationRecovery::RecoverAndRebind,
        )
        .expect("explicit recovery publisher");
        let repaired = publish(&mut recovery, "repaired", vec![complete_receipt("calls")]);
        drop(recovery);

        let first_head = parse_head(
            &fixture.head_path(0),
            &fs::read(fixture.head_path(0)).expect("first repaired head"),
        )
        .expect("valid first repaired head");
        let second_head = parse_head(
            &fixture.head_path(1),
            &fs::read(fixture.head_path(1)).expect("second repaired head"),
        )
        .expect("valid second repaired head");
        assert_eq!(first_head, second_head);
        assert_eq!(
            first_head.body.generation_id,
            repaired.manifest.generation_id
        );
        assert_eq!(
            resolve_generation(&fixture.graph, &fixture.root)
                .expect("repaired publication")
                .manifest
                .generation_id,
            repaired.manifest.generation_id
        );
    }

    #[test]
    fn conflicting_heads_require_explicit_recovery_and_republish_both_slots() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let newest = resolve_generation(&fixture.graph, &fixture.root).expect("newest generation");
        assert_eq!(newest.manifest.generation_id, second.manifest.generation_id);
        let older_slot = 1 - newest.slot;
        let mut conflicting_body = first.head.body;
        conflicting_body.sequence = newest.head.body.sequence;
        let conflicting = seal_head(conflicting_body).expect("seal conflicting head fixture");
        replace_head(&fixture.head_path(older_slot), &conflicting);
        drop(publisher);
        let conflicting_bytes = HEAD_FILES
            .iter()
            .map(|file| fs::read(fixture.publication_directory().join(file)).unwrap())
            .collect::<Vec<_>>();

        let strict = match SemanticPublisher::acquire(&fixture.graph, &fixture.root) {
            Ok(_) => panic!("strict admission must reject conflicting heads"),
            Err(error) => error,
        };
        assert!(matches!(strict, PublicationError::HeadConflict { .. }));
        for (slot, expected) in conflicting_bytes.iter().enumerate() {
            assert_eq!(
                fs::read(fixture.head_path(slot)).expect("head after strict refusal"),
                *expected,
                "strict refusal must preserve conflicting control bytes"
            );
        }

        let mut recovery = SemanticPublisher::acquire_with_recovery(
            &fixture.graph,
            &fixture.root,
            PublicationRecovery::RecoverAndRebind,
        )
        .expect("explicit conflict recovery publisher");
        let repaired = publish(
            &mut recovery,
            "conflict-repaired",
            vec![complete_receipt("calls")],
        );
        drop(recovery);

        let first_head = parse_head(
            &fixture.head_path(0),
            &fs::read(fixture.head_path(0)).expect("first repaired head"),
        )
        .expect("valid first repaired head");
        let second_head = parse_head(
            &fixture.head_path(1),
            &fs::read(fixture.head_path(1)).expect("second repaired head"),
        )
        .expect("valid second repaired head");
        assert_eq!(first_head, second_head);
        assert_eq!(
            first_head.body.generation_id,
            repaired.manifest.generation_id
        );
        assert_eq!(
            resolve_generation(&fixture.graph, &fixture.root)
                .expect("repaired publication")
                .manifest
                .generation_id,
            repaired.manifest.generation_id
        );
    }

    #[test]
    fn missing_repository_identity_requires_explicit_rebind_after_validation() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let original = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        drop(publisher);
        let repository_path = fixture.publication_directory().join(REPOSITORY_FILE);
        fs::remove_file(&repository_path).expect("remove repository identity fixture");
        let head_bytes = HEAD_FILES
            .iter()
            .map(|file| fs::read(fixture.publication_directory().join(file)).ok())
            .collect::<Vec<_>>();

        let strict = match SemanticPublisher::acquire(&fixture.graph, &fixture.root) {
            Ok(_) => panic!("strict admission must reject surviving state without identity"),
            Err(error) => error,
        };
        assert!(matches!(
            strict,
            PublicationError::MissingRepositoryIdentity { .. }
        ));
        assert!(!repository_path.exists());
        for (slot, expected) in head_bytes.iter().enumerate() {
            assert_eq!(
                fs::read(fixture.head_path(slot)).ok(),
                *expected,
                "strict refusal must preserve every surviving head byte"
            );
        }

        let mut recovery = SemanticPublisher::acquire_with_recovery(
            &fixture.graph,
            &fixture.root,
            PublicationRecovery::RecoverAndRebind,
        )
        .expect("explicit identity recovery");
        assert!(
            !repository_path.exists(),
            "recovery admission must defer identity replacement until a generation validates"
        );
        let rebound = publish(&mut recovery, "rebound", vec![complete_receipt("calls")]);
        drop(recovery);
        assert_ne!(
            rebound.manifest.repository_id,
            original.manifest.repository_id
        );
        assert_eq!(
            resolve_generation(&fixture.graph, &fixture.root)
                .expect("rebound publication")
                .manifest
                .generation_id,
            rebound.manifest.generation_id
        );
    }

    #[test]
    fn failed_recovery_generation_does_not_commit_provisional_identity_or_heads() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        drop(publisher);
        let repository_path = fixture.publication_directory().join(REPOSITORY_FILE);
        fs::remove_file(&repository_path).expect("remove repository identity fixture");
        let head_bytes = HEAD_FILES
            .iter()
            .map(|file| fs::read(fixture.publication_directory().join(file)).ok())
            .collect::<Vec<_>>();

        let mut recovery = SemanticPublisher::acquire_with_recovery(
            &fixture.graph,
            &fixture.root,
            PublicationRecovery::RecoverAndRebind,
        )
        .expect("explicit identity recovery");
        let workspace = recovery.begin_generation().expect("generation workspace");
        let foreign_root = fixture._temporary.path().join("foreign-repository");
        fs::create_dir(&foreign_root).expect("foreign repository root");
        GraphStore::new(workspace.database())
            .set_origin_sync(&foreign_root)
            .expect("plant foreign graph origin");

        let error = recovery
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("must-not-rebind".into()),
                    project_inventory: test_inventory(),
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect_err("invalid private generation must not commit recovery authority");
        assert!(matches!(
            error,
            PublicationError::InvalidGenerationGraph { .. }
        ));
        drop(recovery);

        assert!(
            !repository_path.exists(),
            "failed validation must not persist the provisional repository identity"
        );
        for (slot, expected) in head_bytes.iter().enumerate() {
            assert_eq!(
                fs::read(fixture.head_path(slot)).ok(),
                *expected,
                "failed validation must not rewrite either publication head"
            );
        }
        let error = resolve_generation(&fixture.graph, &fixture.root)
            .expect_err("missing identity must leave the publication unavailable");
        assert!(
            matches!(
                error,
                PublicationError::Io { ref source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound
            ),
            "unexpected failure after preserving missing identity: {error}"
        );
    }

    #[test]
    fn moved_root_requires_explicit_rebind_and_rejects_the_old_root_afterward() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let original = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        drop(publisher);
        let moved_root = fixture._temporary.path().join("moved-repository");
        fs::create_dir(&moved_root).expect("moved repository root");

        let strict = match SemanticPublisher::acquire(&fixture.graph, &moved_root) {
            Ok(_) => panic!("strict admission must refuse a publication bound to another root"),
            Err(error) => error,
        };
        assert!(matches!(strict, PublicationError::RootMismatch { .. }));

        let mut recovery = SemanticPublisher::acquire_with_recovery(
            &fixture.graph,
            &moved_root,
            PublicationRecovery::RecoverAndRebind,
        )
        .expect("explicit moved-root recovery");
        let rebound = publish(&mut recovery, "moved", vec![complete_receipt("calls")]);
        drop(recovery);
        assert_ne!(
            rebound.manifest.repository_id,
            original.manifest.repository_id
        );
        assert_eq!(
            resolve_generation(&fixture.graph, &moved_root)
                .expect("moved-root publication")
                .manifest
                .generation_id,
            rebound.manifest.generation_id
        );
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::RootMismatch { .. })
        ));
    }

    #[test]
    fn live_database_handles_prevent_premature_publication() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let workspace = workspace_with_payload(&publisher, "busy");
        let live_handle = workspace.database();

        let error = publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("busy".into()),
                    project_inventory: test_inventory(),
                    receipts: vec![complete_receipt("calls")],
                    provider_payloads: provider_payloads_for(
                        &[complete_receipt("calls")],
                        &test_inventory(),
                    ),
                },
            )
            .expect_err("live database handle must block publication");

        assert!(matches!(error, PublicationError::DatabaseBusy { .. }));
        assert!(matches!(
            resolve_generation(&fixture.graph, &fixture.root),
            Err(PublicationError::Unpublished { .. })
        ));
        drop(live_handle);
    }

    #[test]
    fn distinct_providers_can_receipt_same_capability_scope() {
        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = complete_receipt("calls");
        let mut second = first.clone();
        second.provider_id = ProviderId::new("alternate-provider");
        second.provider_version = Some("2.0.0".into());
        second.input_fingerprint = Some(sha256_bytes(b"alternate-provider-inputs"));

        let published = publish(&mut publisher, "multi-provider", vec![first, second]);
        let provider_ids: Vec<_> = published
            .manifest
            .receipts
            .iter()
            .map(|receipt| receipt.provider_id.0.as_str())
            .collect();

        assert_eq!(provider_ids, ["alternate-provider", "test-provider"]);
    }

    #[test]
    fn duplicate_or_unexplained_receipts_are_rejected() {
        let duplicate = complete_receipt("calls");
        let mut receipts = vec![duplicate.clone(), duplicate];
        assert!(matches!(
            normalize_and_validate_receipts(&mut receipts),
            Err(PublicationError::InvalidDraft(_))
        ));

        let mut unavailable = complete_receipt("calls");
        unavailable.status = CapabilityStatus::Unavailable;
        unavailable.reason_code = Some("test_unavailable".into());
        unavailable.reason = None;
        assert!(matches!(
            normalize_and_validate_receipts(std::slice::from_mut(&mut unavailable)),
            Err(PublicationError::InvalidDraft(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_newest_head_falls_back_to_the_older_valid_reference() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let mut publisher =
            SemanticPublisher::acquire(&fixture.graph, &fixture.root).expect("publisher");
        let first = publish(&mut publisher, "first", vec![complete_receipt("calls")]);
        let second = publish(&mut publisher, "second", vec![complete_receipt("calls")]);
        let newest = resolve_generation(&fixture.graph, &fixture.root).expect("newest generation");
        assert_eq!(newest.manifest.generation_id, second.manifest.generation_id);

        let newest_head = fixture.head_path(newest.slot);
        let symlink_target = fixture.graph.join("untrusted-head-target");
        fs::write(&symlink_target, b"not a publication head").expect("symlink target");
        fs::remove_file(&newest_head).expect("remove newest head fixture");
        symlink(&symlink_target, &newest_head).expect("unsafe newest head fixture");

        let resolved = resolve_generation(&fixture.graph, &fixture.root)
            .expect("older referenced generation remains usable");
        assert_eq!(
            resolved.manifest.generation_id,
            first.manifest.generation_id
        );
        assert_ne!(resolved.slot, newest.slot);
    }
}
