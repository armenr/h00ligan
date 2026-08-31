//! Orchestrator for the standalone code-intelligence indexing pipeline.
//!
//! The pipeline stages are:
//! 1. **DISCOVER** — walk the file tree respecting `.gitignore`
//! 2. **DIFF** — blake3-hash each file, compare against [`IndexState`]
//! 3. **EXTRACT** — tree-sitter symbol extraction via [`extract_file`]
//! 4. **GRAPH** — build knowledge graph edges via [`build_graph`]
//! 5. **SEMANTIC** — run selected compiler-backed providers and normalize their artifacts
//! 6. **STATE** — bind source facts, graph state, and capability evidence
//! 7. **REPORT** — return [`IndexReport`]
//!
//! Steps 1-4 are blocking (file I/O, tree-sitter, rayon) and run inside
//! `spawn_blocking`. Semantic-provider execution and publication are asynchronous.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use h00ligan_provider_protocol::ProviderOperation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing;

use crate::code_intel_calls::{
    CallsGraphProjectionStats, assess_calls_capability_refs, project_calls_payload_structural_join,
    validate_callable_liveness_payload_structural_join,
};
use crate::code_intel_cancellation::IndexCancellation;
use crate::code_intel_domain::{
    CALLS_CONFIGURATION_ID, CapabilityCoverageStatus, CapabilityReceipt, CapabilityScope,
    CapabilityStatus, ConfigurationId, LanguageId, ProjectInventory, ProjectInventoryCoverage,
    STRUCTURAL_GRAPH_CONFIGURATION_ID, sort_capability_receipts,
};
use crate::code_intel_inventory::{
    InventorySource, build_project_inventory, go_execution_root_inventory_fingerprints,
    go_project_input_execution_roots, semantic_provider_document_execution_roots,
    semantic_provider_execution_roots, semantic_provider_inventory_fingerprint,
};
use crate::code_intel_payload::{
    CanonicalProviderPayload, ProviderExecutionAuthority, ProviderPayload,
    ProviderPayloadCanonicalizationTimings, canonicalize_normalized_provider_payload_profiled,
};
#[cfg(test)]
use crate::code_intel_semantic_provider_coordinator::provider_root_parallelism_for;
use crate::code_intel_semantic_provider_coordinator::{
    SemanticProviderActivity, SemanticProviderActivityRecord, SemanticProviderAdmittedRefreshKind,
    SemanticProviderRefreshTiming, SemanticProviderSessionOpenMetrics, provider_root_parallelism,
};
use crate::code_intel_semantic_provider_registry::{
    PersistentSemanticProvider, SemanticProviderRegistry,
};
use crate::code_intel_toolchain::{
    ResolvedToolchain, SCIP_GO_REUSE_CONTRACT_ID, ToolchainBoundAuthorityInput, ToolchainResolver,
    resolve_toolchain_population, toolchain_bound_execution_authority,
    toolchain_provider_configuration_population, toolchain_provider_configuration_sha256,
    toolchain_provider_implementation_sha256,
};
use crate::edge_builder::{self, BuildStats};
use crate::extractor;
use crate::graph::KnowledgeGraph;
use crate::graph_store::{BoundGraphPublicationProof, GraphGenerationMetadata, GraphStore};
use crate::index_state::{
    BoundIndexStatePublicationProof, FileRecord, IncrementalIndexBasis, IndexMetadata, IndexState,
    IndexStateError,
};
use crate::project_binding::{PROVIDER_CACHE_DIRECTORY, inspect_generated_directory};
use crate::reachability::classify_and_writeback_with_inventory_evidence;
use crate::scip_normalizer::{
    CanonicalScipSnapshot, CanonicalSemanticBasis, CanonicalSourceSyntaxCache,
    IndexedSourceEvidence, ScipArtifactEvidence, ScipArtifactInput, ScipArtifactSetNormalization,
    ScipNormalizationTimings, ScipProviderSpec,
    normalize_canonical_scip_snapshot_with_source_syntax_cache,
    normalize_scip_artifact_set_for_inventory_coverage,
};
use crate::structural_ir::ExtractorOutput;

/// Nominal apparent-byte budget for non-authoritative semantic-provider
/// caches under one selected data directory. Current-operation partitions are
/// never erased merely to satisfy this budget: doing so turns every successful
/// large-workspace run into the next run's cold rebuild. Older inactive
/// partitions are evicted least-recently-modified first; published evidence
/// never depends on any cache entry.
const PROVIDER_CACHE_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
#[derive(Debug)]
struct ProviderCacheEntry {
    path: PathBuf,
    apparent_bytes: u64,
    modified: std::time::SystemTime,
}

fn provider_cache_entry_stats(
    path: &std::path::Path,
) -> std::io::Result<(u64, std::time::SystemTime)> {
    let metadata = std::fs::symlink_metadata(path)?;
    let mut modified = metadata
        .modified()
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Ok((metadata.len(), modified));
    }
    let mut bytes = 0_u64;
    for entry in std::fs::read_dir(path)? {
        let (entry_bytes, entry_modified) = provider_cache_entry_stats(&entry?.path())?;
        bytes = bytes.saturating_add(entry_bytes);
        modified = modified.max(entry_modified);
    }
    Ok((bytes, modified))
}

fn provider_cache_apparent_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    provider_cache_entry_stats(path).map(|(bytes, _)| bytes)
}

#[cfg(unix)]
fn make_provider_cache_removable(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Ok(());
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o700);
    std::fs::set_permissions(path, permissions)?;
    for entry in std::fs::read_dir(path)? {
        make_provider_cache_removable(&entry?.path())?;
    }
    Ok(())
}

#[cfg(windows)]
fn make_provider_cache_removable(path: &std::path::Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions)?;
    }
    if metadata.file_type().is_dir() {
        for entry in std::fs::read_dir(path)? {
            make_provider_cache_removable(&entry?.path())?;
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn make_provider_cache_removable(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

fn sorted_cache_children(path: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let mut children = std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    children.sort();
    Ok(children)
}

fn plain_cache_directory(path: &std::path::Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Return independently disposable cache partitions without descending into
/// provider-owned tool layout. Rust and Go caches are partitioned by exact
/// toolchain/profile/execution-root workspaces. Unknown entries are evicted
/// only as whole paths.
fn provider_cache_partitions(cache_root: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let mut partitions = Vec::new();
    for language_entry in sorted_cache_children(cache_root)? {
        if !matches!(
            language_entry.file_name().and_then(std::ffi::OsStr::to_str),
            Some("rust" | "go")
        ) || !plain_cache_directory(&language_entry)?
        {
            partitions.push(language_entry);
            continue;
        }
        for toolchain_entry in sorted_cache_children(&language_entry)? {
            if !plain_cache_directory(&toolchain_entry)? {
                partitions.push(toolchain_entry);
                continue;
            }
            let workspaces = toolchain_entry.join("workspaces");
            if !plain_cache_directory(&workspaces)? {
                partitions.push(toolchain_entry);
                continue;
            }
            partitions.extend(sorted_cache_children(&workspaces)?);
            partitions.extend(
                sorted_cache_children(&toolchain_entry)?
                    .into_iter()
                    .filter(|path| path != &workspaces),
            );
        }
    }
    Ok(partitions)
}

fn cache_paths_overlap(left: &std::path::Path, right: &std::path::Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn remove_provider_cache_entry(path: &std::path::Path) -> std::io::Result<()> {
    make_provider_cache_removable(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

fn trim_provider_cache_to_budget(
    cache_root: &std::path::Path,
    max_bytes: u64,
    protected: &BTreeSet<PathBuf>,
) -> Result<bool, IndexPipelineError> {
    inspect_generated_directory(cache_root)?;
    let mut current_bytes = provider_cache_apparent_bytes(cache_root)?;
    if current_bytes <= max_bytes {
        return Ok(false);
    }
    let before_bytes = current_bytes;
    let mut entries = provider_cache_partitions(cache_root)?
        .into_iter()
        .map(|path| {
            let (apparent_bytes, modified) = provider_cache_entry_stats(&path)?;
            Ok(ProviderCacheEntry {
                path,
                apparent_bytes,
                modified,
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by(|left, right| {
        left.modified
            .cmp(&right.modified)
            .then_with(|| left.path.cmp(&right.path))
    });

    let mut evicted_entries = 0_u64;
    for entry in entries {
        if current_bytes <= max_bytes {
            break;
        }
        if protected
            .iter()
            .any(|protected| cache_paths_overlap(&entry.path, protected))
        {
            continue;
        }
        remove_provider_cache_entry(&entry.path)?;
        current_bytes = current_bytes.saturating_sub(entry.apparent_bytes);
        evicted_entries = evicted_entries.saturating_add(1);
    }

    if current_bytes > max_bytes {
        tracing::warn!(
            current_bytes,
            max_bytes,
            protected_entries = protected.len(),
            path = %cache_root.display(),
            "active semantic-provider cache working set exceeds nominal budget; retained current partitions"
        );
    } else {
        tracing::warn!(
            before_bytes,
            current_bytes,
            max_bytes,
            evicted_entries,
            path = %cache_root.display(),
            "evicted inactive semantic-provider cache partitions"
        );
    }
    Ok(evicted_entries > 0)
}

fn cargo_package_count(project_inventory: &ProjectInventory) -> usize {
    project_inventory
        .project_topology
        .units
        .iter()
        .filter(|unit| {
            unit.kind == crate::code_intel_domain::ProjectUnitKind::Package
                && unit.ecosystem_id.0 == "cargo"
        })
        .count()
}

fn bounded_structural_join_reason(
    capability: &str,
    error: &crate::code_intel_domain::DomainError,
) -> String {
    const DETAIL_LIMIT: usize = 384;
    let detail = error.to_string();
    let mut bounded = detail.chars().take(DETAIL_LIMIT).collect::<String>();
    if detail.chars().count() > DETAIL_LIMIT {
        bounded.push('…');
    }
    format!(
        "normalized {capability} evidence could not join the co-published structural graph: {bounded}"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicationReadySemanticEvidence {
    language_id: LanguageId,
    receipt: CapabilityReceipt,
    payload: Option<CanonicalProviderPayload>,
}

#[derive(Debug, Clone, Copy)]
struct CallsProviderPolicy {
    ecosystem: &'static str,
    default_provider_id: &'static str,
    admitted_provider_ids: &'static [&'static str],
    missing_execution_root_reason: &'static str,
}

const RUST_CALLS_PROVIDER_IDS: &[&str] = &[
    "rust-analyzer-scip",
    h00ligan_provider_protocol::H00_RUST_ANALYZER_PROVIDER_ID,
];
const GO_CALLS_PROVIDER_IDS: &[&str] = &["scip-go", h00ligan_provider_protocol::H00_GO_PROVIDER_ID];
const PYTHON_CALLS_PROVIDER_IDS: &[&str] = &[h00ligan_provider_protocol::H00_PYREFLY_PROVIDER_ID];
const TYPESCRIPT_CALLS_PROVIDER_IDS: &[&str] =
    &[h00ligan_provider_protocol::H00_TYPESCRIPT_PROVIDER_ID];

fn calls_provider_policy(language: &str) -> Option<CallsProviderPolicy> {
    match language {
        "rust" => Some(CallsProviderPolicy {
            ecosystem: "cargo",
            default_provider_id: "rust-analyzer-scip",
            admitted_provider_ids: RUST_CALLS_PROVIDER_IDS,
            missing_execution_root_reason: "Rust Calls requires an indexed Cargo.toml source owner or workspace",
        }),
        "go" => Some(CallsProviderPolicy {
            ecosystem: "go",
            default_provider_id: "scip-go",
            admitted_provider_ids: GO_CALLS_PROVIDER_IDS,
            missing_execution_root_reason: "Go Calls requires an indexed go.mod module or go.work workspace",
        }),
        "python" => Some(CallsProviderPolicy {
            ecosystem: "python",
            default_provider_id: h00ligan_provider_protocol::H00_PYREFLY_PROVIDER_ID,
            admitted_provider_ids: PYTHON_CALLS_PROVIDER_IDS,
            missing_execution_root_reason: "Python Calls requires an indexed Python package or module source owner",
        }),
        "typescript" => Some(CallsProviderPolicy {
            ecosystem: "node",
            default_provider_id: h00ligan_provider_protocol::H00_TYPESCRIPT_PROVIDER_ID,
            admitted_provider_ids: TYPESCRIPT_CALLS_PROVIDER_IDS,
            missing_execution_root_reason: "TypeScript Calls requires an indexed Node package source owner",
        }),
        _ => None,
    }
}

fn default_calls_provider(language: &str) -> &'static str {
    calls_provider_policy(language).map_or("unassigned-semantic-provider", |policy| {
        policy.default_provider_id
    })
}

fn calls_evidence_identity_matches(
    language: &str,
    evidence: &PublicationReadySemanticEvidence,
) -> bool {
    let provider_is_admitted = calls_provider_policy(language).is_some_and(|policy| {
        policy
            .admitted_provider_ids
            .contains(&evidence.receipt.provider_id.0.as_str())
    });
    let receipt_scope_matches = match &evidence.receipt.scope {
        CapabilityScope::Language {
            language_id,
            configuration_id,
        }
        | CapabilityScope::ProjectUnit {
            language_id,
            configuration_id,
            ..
        }
        | CapabilityScope::ProjectUnits {
            language_id,
            configuration_id,
            ..
        } => {
            language_id == &LanguageId::new(language)
                && configuration_id == &ConfigurationId::new(CALLS_CONFIGURATION_ID)
        }
        CapabilityScope::Repository { .. } => false,
    };
    evidence.language_id == LanguageId::new(language)
        && evidence.receipt.capability_id == "calls"
        && provider_is_admitted
        && receipt_scope_matches
        && evidence
            .payload
            .as_ref()
            .is_none_or(|payload| payload.payload().receipt() == &evidence.receipt)
}

fn inconsistent_calls_evidence_receipt(language: &str) -> CapabilityReceipt {
    CapabilityReceipt::unavailable(
        "calls",
        default_calls_provider(language),
        None,
        CapabilityScope::Language {
            language_id: LanguageId::new(language),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        },
        None,
        "provider_evidence_inconsistent",
        "SCIP normalization returned evidence for a different capability, provider, or scope",
    )
}

/// Cross the final fallible payload boundary before any provider evidence can
/// mutate the candidate graph. The returned payload is byte-bound to its
/// descriptor and can be moved unchanged into immutable publication.
fn seal_scip_artifact_evidence(
    evidence: ScipArtifactEvidence,
) -> (
    PublicationReadySemanticEvidence,
    ProviderPayloadCanonicalizationTimings,
) {
    let ScipArtifactEvidence {
        language_id,
        receipt,
        payload,
    } = evidence;
    match (receipt.status, payload) {
        (CapabilityStatus::Complete, Some(payload)) => {
            if payload.payload().receipt() != &receipt {
                let unavailable = CapabilityReceipt::unavailable(
                    receipt.capability_id,
                    receipt.provider_id.0,
                    receipt.provider_version,
                    receipt.scope,
                    receipt.input_fingerprint,
                    "provider_evidence_inconsistent",
                    "normalized provider payload embeds a different capability receipt",
                );
                return (
                    PublicationReadySemanticEvidence {
                        language_id,
                        receipt: unavailable,
                        payload: None,
                    },
                    ProviderPayloadCanonicalizationTimings::default(),
                );
            }
            match canonicalize_normalized_provider_payload_profiled(payload) {
                Ok((payload, timings)) => (
                    PublicationReadySemanticEvidence {
                        language_id,
                        receipt,
                        payload: Some(payload),
                    },
                    timings,
                ),
                Err(error) => {
                    let unavailable = CapabilityReceipt::unavailable(
                        receipt.capability_id,
                        receipt.provider_id.0,
                        receipt.provider_version,
                        receipt.scope,
                        receipt.input_fingerprint,
                        "provider_payload_seal_failed",
                        format!("normalized provider payload could not be sealed: {error}"),
                    );
                    (
                        PublicationReadySemanticEvidence {
                            language_id,
                            receipt: unavailable,
                            payload: None,
                        },
                        ProviderPayloadCanonicalizationTimings::default(),
                    )
                }
            }
        }
        (CapabilityStatus::Partial | CapabilityStatus::Unavailable, None) => (
            PublicationReadySemanticEvidence {
                language_id,
                receipt,
                payload: None,
            },
            ProviderPayloadCanonicalizationTimings::default(),
        ),
        _ => (
            PublicationReadySemanticEvidence {
                language_id,
                receipt: CapabilityReceipt::unavailable(
                    receipt.capability_id,
                    receipt.provider_id.0,
                    receipt.provider_version,
                    receipt.scope,
                    receipt.input_fingerprint,
                    "provider_evidence_inconsistent",
                    "semantic normalization returned an inconsistent receipt and payload pair",
                ),
                payload: None,
            },
            ProviderPayloadCanonicalizationTimings::default(),
        ),
    }
}

fn enforce_callable_liveness_structural_join(
    graph: &KnowledgeGraph,
    evidence: &mut PublicationReadySemanticEvidence,
) {
    let error = match evidence
        .payload
        .as_ref()
        .map(CanonicalProviderPayload::payload)
    {
        Some(ProviderPayload::CallableLiveness(payload)) => {
            match validate_callable_liveness_payload_structural_join(graph, payload) {
                Ok(()) => return,
                Err(error) => error,
            }
        }
        _ => return,
    };
    let complete = &evidence.receipt;
    evidence.receipt = CapabilityReceipt::partial(
        complete.capability_id.clone(),
        complete.provider_id.0.clone(),
        complete.provider_version.clone(),
        complete.scope.clone(),
        complete.input_fingerprint.clone(),
        "provider_structural_join_incomplete",
        bounded_structural_join_reason("callable-liveness", &error),
    );
    evidence.payload = None;
}

fn enforce_and_project_calls_structural_join(
    graph: &mut KnowledgeGraph,
    evidence: &mut PublicationReadySemanticEvidence,
) -> CallsGraphProjectionStats {
    let language = evidence.language_id.0.clone();
    if !calls_evidence_identity_matches(&language, evidence) {
        evidence.receipt = inconsistent_calls_evidence_receipt(&language);
        evidence.payload = None;
        return CallsGraphProjectionStats::default();
    }
    let projection = match evidence
        .payload
        .as_ref()
        .map(CanonicalProviderPayload::payload)
    {
        Some(ProviderPayload::Calls(payload)) => {
            project_calls_payload_structural_join(graph, payload)
        }
        Some(ProviderPayload::CallableLiveness(_)) => {
            return CallsGraphProjectionStats::default();
        }
        None => return CallsGraphProjectionStats::default(),
    };
    let error = match projection {
        Ok(stats) => return stats,
        Err(error) => error,
    };

    let complete = &evidence.receipt;
    evidence.receipt = CapabilityReceipt::partial(
        complete.capability_id.clone(),
        complete.provider_id.0.clone(),
        complete.provider_version.clone(),
        complete.scope.clone(),
        complete.input_fingerprint.clone(),
        "provider_structural_join_incomplete",
        bounded_structural_join_reason("Calls", &error),
    );
    evidence.payload = None;
    CallsGraphProjectionStats::default()
}

// -----------------------------------------------------------------------
// Profiling infrastructure
// -----------------------------------------------------------------------

/// Per-phase wall-clock timing.
struct PhaseTiming {
    name: &'static str,
    phase_num: u8,
    duration: Duration,
    detail: String,
}

/// Per-file extraction timing.
struct FileExtractTiming {
    file_path: String,
    wall_time: Duration,
    symbols_extracted: usize,
}

/// Collects timing data during an indexing run.
///
/// When `enabled == false` all methods are no-ops and allocate nothing.
struct ProfileCollector {
    enabled: bool,
    phase_timings: Vec<PhaseTiming>,
    graph_build_steps: Vec<edge_builder::GraphBuildStepTiming>,
    extraction_files: Vec<FileExtractTiming>,
    total_start: Instant,
}

impl ProfileCollector {
    /// Create a new collector. When `enabled` is false, no allocations occur.
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            phase_timings: if enabled {
                Vec::with_capacity(8)
            } else {
                Vec::new()
            },
            graph_build_steps: if enabled {
                Vec::with_capacity(9)
            } else {
                Vec::new()
            },
            extraction_files: if enabled {
                Vec::with_capacity(256)
            } else {
                Vec::new()
            },
            total_start: Instant::now(),
        }
    }

    /// Record a phase timing.
    #[inline]
    fn record_phase(
        &mut self,
        name: &'static str,
        phase_num: u8,
        duration: Duration,
        detail: String,
    ) {
        if !self.enabled {
            return;
        }
        self.phase_timings.push(PhaseTiming {
            name,
            phase_num,
            duration,
            detail,
        });
    }

    /// Merge per-file extraction timings collected from rayon threads.
    #[inline]
    fn merge_extraction_files(&mut self, files: Vec<FileExtractTiming>) {
        if !self.enabled {
            return;
        }
        self.extraction_files = files;
    }

    /// Retain graph-materialization detail without double-counting it as a
    /// top-level phase.
    #[inline]
    fn merge_graph_build_steps(&mut self, steps: Vec<edge_builder::GraphBuildStepTiming>) {
        if !self.enabled {
            return;
        }
        self.graph_build_steps = steps;
    }

    /// Retain the useful internal profile spans in the machine-readable
    /// terminal telemetry. The stable product phases remain the exclusive
    /// wall-clock partition; these rows are deliberately nested spans so a
    /// consumer can rank them without adding them to the parent duration.
    fn append_machine_timings(&self, target: &mut Vec<IndexPhaseTiming>) {
        if !self.enabled {
            return;
        }

        target.extend(self.phase_timings.iter().filter_map(|timing| {
            let phase = match timing.phase_num {
                1..=6 => IndexProgressPhase::Structural,
                8 => IndexProgressPhase::Finalize,
                // Semantic-provider work already exports its own
                // structured exclusive and concurrent timing rows.
                7 | 9..=u8::MAX => return None,
                0 => return None,
            };
            Some(IndexPhaseTiming {
                phase,
                label: format!("profile: {}", timing.name),
                duration: timing.duration,
                aggregation: IndexTimingAggregation::ConcurrentSpan,
            })
        }));
        target.extend(
            self.graph_build_steps
                .iter()
                .map(|timing| IndexPhaseTiming {
                    phase: IndexProgressPhase::Structural,
                    label: format!("profile: graph build / {}", timing.label),
                    duration: timing.duration,
                    aggregation: IndexTimingAggregation::ConcurrentSpan,
                }),
        );
    }

    /// Print the summary table to stderr.
    fn finish(&self) {
        if !self.enabled {
            return;
        }

        let total_elapsed = self.total_start.elapsed();
        let phase_sum: Duration = self.phase_timings.iter().map(|p| p.duration).sum();
        let dead_time = total_elapsed.saturating_sub(phase_sum);

        // Find bottleneck phase.
        let bottleneck = self.phase_timings.iter().max_by_key(|p| p.duration);

        eprintln!();
        eprintln!("INDEX PERFORMANCE PROFILE");
        eprintln!(
            "\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}"
        );
        for pt in &self.phase_timings {
            eprintln!(
                "Phase {} ({:<16}): {:>8.3}s    {}",
                pt.phase_num,
                pt.name,
                pt.duration.as_secs_f64(),
                pt.detail,
            );
        }
        if !self.graph_build_steps.is_empty() {
            eprintln!("  Graph build detail:");
            for step in &self.graph_build_steps {
                eprintln!(
                    "    {:<33} {:>8.3}ms    {} item(s)",
                    step.label,
                    step.duration.as_secs_f64() * 1_000.0,
                    step.items,
                );
            }
        }
        eprintln!(
            "{:<27}: {:>8.3}s    (gaps between phases)",
            "Dead time",
            dead_time.as_secs_f64(),
        );
        eprintln!(
            "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}"
        );
        eprintln!("{:<27}: {:>8.3}s", "TOTAL", total_elapsed.as_secs_f64(),);

        if let Some(bn) = bottleneck {
            let pct = if total_elapsed.as_nanos() > 0 {
                (bn.duration.as_secs_f64() / total_elapsed.as_secs_f64()) * 100.0
            } else {
                0.0
            };
            eprintln!(
                "{:<27}: Phase {} ({}) \u{2014} {:.1}% of wall time",
                "BOTTLENECK", bn.phase_num, bn.name, pct,
            );
        }

        if let Some(slowest) = self
            .extraction_files
            .iter()
            .max_by_key(|file| file.wall_time)
        {
            let symbols = self
                .extraction_files
                .iter()
                .map(|file| file.symbols_extracted)
                .sum::<usize>();
            let wall = self
                .extraction_files
                .iter()
                .map(|file| file.wall_time)
                .sum::<Duration>();
            eprintln!(
                "Extraction files           : {}, {} symbols, {:.1}s aggregate; slowest {} ({:.1}ms)",
                self.extraction_files.len(),
                symbols,
                wall.as_secs_f64(),
                slowest.file_path,
                slowest.wall_time.as_secs_f64() * 1000.0,
            );
        }
    }
}

/// Errors from the indexing pipeline.
#[derive(Debug, Error)]
pub enum IndexPipelineError {
    #[error("indexing operation cancelled before publication")]
    Cancelled,

    #[error("index state error: {0}")]
    State(#[from] IndexStateError),

    #[error("extractor error: {0}")]
    Extractor(#[from] crate::structural_ir::ExtractorError),

    #[error("graph error: {0}")]
    Graph(#[from] crate::graph::GraphError),

    #[error("graph store error: {0}")]
    GraphStore(#[from] crate::graph_store::GraphStoreError),

    #[error("SCIP loader error: {0}")]
    ScipLoader(#[from] crate::scip_loader::ScipLoaderError),

    #[error("required complete Calls authority was not produced: {evidence}")]
    SemanticProvidersUnsatisfied { evidence: String },

    #[error("project path error: {0}")]
    ProjectPath(#[from] crate::project_binding::ProjectPathError),

    #[error("source discovery error: {0}")]
    SourceDiscovery(#[from] crate::source_discovery::SourceDiscoveryError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("{0}")]
    Other(String),
}

/// How an indexing run may use SCIP providers and artifacts.
///
/// A single enum keeps provider execution, artifact replacement, and edge
/// ingestion from drifting apart as independent booleans. In particular,
/// [`Self::Disabled`] is a hard effect boundary: it neither probes a provider
/// nor loads a pre-existing SCIP artifact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScipMode {
    /// Do not probe providers, generate artifacts, or merge SCIP edges.
    #[default]
    Disabled,
    /// Invoke every detected provider with disposable artifacts and private,
    /// reusable build/download caches under the selected data directory.
    Refresh,
}

/// Stable coarse phases exposed to human progress renderers and retained
/// timing telemetry. These are product phases, not implementation spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexProgressPhase {
    Reuse,
    Prepare,
    Structural,
    SemanticProvider,
    Finalize,
    Publish,
}

impl IndexProgressPhase {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reuse => "reuse",
            Self::Prepare => "prepare",
            Self::Structural => "structural",
            Self::SemanticProvider => "semantic_provider",
            Self::Finalize => "finalize",
            Self::Publish => "publish",
        }
    }
}

/// Lifecycle state for one progress phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexProgressState {
    Started,
    Completed,
    Skipped,
    Failed,
}

/// One bounded progress event. The optional sender lives only for the duration
/// of a write operation; it is not persisted into publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexProgressEvent {
    pub phase: IndexProgressPhase,
    pub state: IndexProgressState,
    pub label: String,
    pub detail: String,
    pub elapsed: Option<Duration>,
}

/// How one timing row participates in duration arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexTimingAggregation {
    /// The row is disjoint from other exclusive rows in the same phase and may
    /// be summed into that phase's direct wall-clock partition.
    Exclusive,
    /// The row measures a nested summary or worker whose lifetime may overlap
    /// other rows. It is useful for ranking work, but must not be added to
    /// exclusive rows.
    ConcurrentSpan,
}

impl IndexTimingAggregation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::ConcurrentSpan => "concurrent_span",
        }
    }
}

/// Coarse timing retained in the indexing result for human and machine output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexPhaseTiming {
    pub phase: IndexProgressPhase,
    pub label: String,
    pub duration: Duration,
    pub aggregation: IndexTimingAggregation,
}

/// Flatten one normalizer run into mutually exclusive components. The direct
/// total remains internal so a machine consumer can safely rank or sum the
/// exported population without counting parent spans beside their children.
fn semantic_normalizer_components(
    label: &str,
    timings: ScipNormalizationTimings,
) -> Vec<IndexPhaseTiming> {
    let measured = [
        timings.setup,
        timings.source_validation,
        timings.coverage_exclusion_setup,
        timings.occurrence_indexing,
        timings.definition_collection,
        timings.definition_canonicalization,
        timings.binding_and_lookup_indexing,
        timings.call_resolution,
        timings.coverage_validation,
        timings.payload_finalization,
    ];
    let measured_total = measured
        .into_iter()
        .fold(Duration::ZERO, Duration::saturating_add);
    debug_assert!(
        measured_total <= timings.total,
        "non-overlapping normalizer components cannot exceed their direct wall clock"
    );
    let orchestration = timings.total.saturating_sub(measured_total);
    [
        ("normalizer setup".to_owned(), timings.setup),
        (
            format!(
                "source validation and syntax census ({}/{} cache hits)",
                timings.syntax_cache_hits, timings.source_documents,
            ),
            timings.source_validation,
        ),
        (
            "coverage exclusion setup".to_owned(),
            timings.coverage_exclusion_setup,
        ),
        (
            format!(
                "occurrence indexing ({}/{} document cache hits)",
                timings.provider_document_cache_hits, timings.provider_documents,
            ),
            timings.occurrence_indexing,
        ),
        (
            format!(
                "definition collection ({}/{} document cache hits)",
                timings.definition_document_cache_hits, timings.provider_documents,
            ),
            timings.definition_collection,
        ),
        (
            format!(
                "definition canonicalization ({}/{} group reuse hits)",
                timings.definition_group_reuse_hits, timings.definition_groups,
            ),
            timings.definition_canonicalization,
        ),
        (
            "binding and lookup indexing".to_owned(),
            timings.binding_and_lookup_indexing,
        ),
        (
            format!(
                "call resolution ({}/{} document reuse hits)",
                timings.call_document_reuse_hits, timings.call_documents,
            ),
            timings.call_resolution,
        ),
        (
            "coverage validation".to_owned(),
            timings.coverage_validation,
        ),
        (
            "payload finalization".to_owned(),
            timings.payload_finalization,
        ),
        ("normalizer orchestration".to_owned(), orchestration),
    ]
    .into_iter()
    .map(|(component, duration)| IndexPhaseTiming {
        phase: IndexProgressPhase::SemanticProvider,
        label: format!("{label} {component}"),
        duration,
        aggregation: IndexTimingAggregation::Exclusive,
    })
    .collect()
}

pub(crate) fn emit_progress(
    sender: &Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
    phase: IndexProgressPhase,
    state: IndexProgressState,
    label: impl Into<String>,
    detail: impl Into<String>,
    elapsed: Option<Duration>,
) {
    if let Some(sender) = sender {
        let _ = sender.send(IndexProgressEvent {
            phase,
            state,
            label: label.into(),
            detail: detail.into(),
            elapsed,
        });
    }
}

fn ensure_index_active(cancellation: &IndexCancellation) -> Result<(), IndexPipelineError> {
    if cancellation.is_cancelled() {
        Err(IndexPipelineError::Cancelled)
    } else {
        Ok(())
    }
}

impl ScipMode {
    /// Whether this run invokes providers and writes ephemeral artifacts under
    /// the selected data directory.
    #[must_use]
    pub const fn generates_artifacts(self) -> bool {
        matches!(self, Self::Refresh)
    }
}

/// Configuration for an indexing run.
#[derive(Debug, Clone)]
pub struct IndexConfig {
    /// Root directory to index.
    pub root: PathBuf,
    /// Force a full re-index, ignoring cached hashes.
    pub full: bool,
    /// Only compute the diff — do not extract or store.
    pub dry_run: bool,
    /// Provider execution and artifact-ingestion intent for SCIP enrichment.
    pub scip: ScipMode,
    /// Refuse the candidate before publication unless every callable language
    /// has complete Calls authority. Provider refresh is otherwise best-effort.
    pub require_complete_calls: bool,
    /// Selected data root for provider-owned state. Artifacts live in an
    /// automatically removed workspace beneath this root; non-authoritative
    /// build/download caches live in a stable child so successive publications
    /// can be warm without touching the project or global tool caches.
    pub provider_data_root: Option<PathBuf>,
    /// Product-owned semantic toolchain resolver. Provider refresh never
    /// discovers executable or environment authority inside the engine; a
    /// missing resolver yields honest unavailable evidence for providers that
    /// require one.
    pub toolchain_resolver: Option<Arc<dyn ToolchainResolver>>,
    /// Language extensions to include (e.g. `["rs"]`). Empty = all supported.
    pub languages: Vec<String>,
    /// Glob patterns to exclude from discovery.
    pub exclude: Vec<String>,
    /// Parallelism limit for rayon. `None` = rayon default.
    pub jobs: Option<usize>,
    /// Emit debug tracing.
    pub debug: bool,
    /// Collect and print detailed per-phase timing diagnostics.
    pub profile: bool,
    /// Optional adapter-owned progress channel. Long-lived MCP adapters retain
    /// a bounded operation log; human CLI adapters may render it on stderr
    /// without contaminating stdout.
    pub progress: Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
    /// Runtime-neutral cooperative cancellation shared with blocking provider
    /// processes. Cancellation is observed only at safe boundaries and never
    /// turns a private partial generation into current publication state.
    pub cancellation: IndexCancellation,
    /// Authorise ADOPTING a graph store stamped with a DIFFERENT workspace
    /// origin. Adoption CLEARS that workspace's persisted graph and rebuilds
    /// from this root — i.e. it destroys another repo's work — so it is
    /// **`false` by default** and the index refuses fail-closed
    /// ([`GraphStoreError::OriginAdoptRequired`](crate::graph_store::GraphStoreError::OriginAdoptRequired))
    /// unless set.
    ///
    /// Scope: this gates ONLY the origin arm. Schema-bump and decode-failure
    /// clears remain automatic — they discard only regenerable data belonging
    /// to the SAME repo. An EMPTY store is likewise unaffected (nothing to
    /// destroy), so a first-ever index never needs this.
    ///
    /// A FLAG, not a prompt, deliberately: MCP tool calls, agents and CI have
    /// no interactive channel to answer one.
    pub adopt_foreign_origin: bool,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            full: false,
            dry_run: false,
            scip: ScipMode::Disabled,
            require_complete_calls: false,
            provider_data_root: None,
            toolchain_resolver: None,
            languages: Vec::new(),
            exclude: Vec::new(),
            jobs: None,
            debug: false,
            profile: false,
            progress: None,
            cancellation: IndexCancellation::new(),
            // Fail-closed: never destroy a foreign workspace's graph unless
            // the caller explicitly authorises it.
            adopt_foreign_origin: false,
        }
    }
}

/// Process-local semantic-provider work performed by one indexing run.
///
/// This is bounded operational telemetry, not persisted semantic authority.
/// It lets CLI/MCP/WATCH adapters distinguish an exact basis admission from a
/// live affected-document refresh or a full provider certification without
/// inferring lifecycle state from timing labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticProviderActivityTelemetry {
    Reused {
        language_id: String,
        session_open: Option<SemanticProviderSessionOpenTelemetry>,
    },
    Admitted {
        language_id: String,
        lane: SemanticProviderRefreshLane,
        operation: ProviderOperation,
        documents: Vec<String>,
        session_open: Option<SemanticProviderSessionOpenTelemetry>,
    },
    Failed {
        language_id: String,
        attempted_operations: Vec<ProviderOperation>,
        session_open: Option<SemanticProviderSessionOpenTelemetry>,
    },
}

impl SemanticProviderActivityTelemetry {
    #[must_use]
    pub fn language_id(&self) -> &str {
        match self {
            Self::Reused { language_id, .. }
            | Self::Admitted { language_id, .. }
            | Self::Failed { language_id, .. } => language_id,
        }
    }

    #[must_use]
    pub fn json_value(&self) -> serde_json::Value {
        fn session_json(
            session: &Option<SemanticProviderSessionOpenTelemetry>,
        ) -> Option<serde_json::Value> {
            session.as_ref().map(|open| {
                serde_json::json!({
                    "execution_roots": open.execution_roots,
                    "max_parallelism": open.max_parallelism,
                    "duration_ms": open.duration_ms,
                })
            })
        }

        match self {
            Self::Reused {
                language_id,
                session_open,
            } => serde_json::json!({
                "language": language_id,
                "lane": "reused",
                "operation": null,
                "documents": [],
                "session_open": session_json(session_open),
            }),
            Self::Admitted {
                language_id,
                lane,
                operation,
                documents,
                session_open,
            } => serde_json::json!({
                "language": language_id,
                "lane": lane.label(),
                "operation": operation,
                "documents": documents,
                "session_open": session_json(session_open),
            }),
            Self::Failed {
                language_id,
                attempted_operations,
                session_open,
            } => serde_json::json!({
                "language": language_id,
                "lane": "failed",
                "operation": null,
                "attempted_operations": attempted_operations,
                "documents": [],
                "session_open": session_json(session_open),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticProviderSessionOpenTelemetry {
    pub execution_roots: usize,
    pub max_parallelism: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticProviderRefreshLane {
    AffectedDocuments,
    AffectedRoots,
    Full,
}

impl SemanticProviderRefreshLane {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AffectedDocuments => "affected_documents",
            Self::AffectedRoots => "affected_roots",
            Self::Full => "full",
        }
    }
}

fn record_semantic_provider_activity(
    refreshes: &mut Vec<SemanticProviderActivityTelemetry>,
    language_id: &str,
    record: Option<SemanticProviderActivityRecord>,
) -> Vec<SemanticProviderRefreshTiming> {
    let Some(record) = record else {
        return Vec::new();
    };

    let session_open = |open: Option<SemanticProviderSessionOpenMetrics>| {
        open.map(|open| SemanticProviderSessionOpenTelemetry {
            execution_roots: open.execution_roots,
            max_parallelism: open.max_parallelism,
            duration_ms: u64::try_from(open.duration.as_millis()).unwrap_or(u64::MAX),
        })
    };
    let activity = match record.activity {
        SemanticProviderActivity::Reused { session_open: open } => {
            SemanticProviderActivityTelemetry::Reused {
                language_id: language_id.to_owned(),
                session_open: session_open(open),
            }
        }
        SemanticProviderActivity::Admitted {
            refresh,
            operation,
            session_open: open,
        } => {
            let (lane, documents) = match refresh {
                SemanticProviderAdmittedRefreshKind::Affected { documents } => (
                    SemanticProviderRefreshLane::AffectedDocuments,
                    documents.into_iter().collect(),
                ),
                SemanticProviderAdmittedRefreshKind::AffectedRoots { .. } => {
                    (SemanticProviderRefreshLane::AffectedRoots, Vec::new())
                }
                SemanticProviderAdmittedRefreshKind::Full => {
                    (SemanticProviderRefreshLane::Full, Vec::new())
                }
            };
            SemanticProviderActivityTelemetry::Admitted {
                language_id: language_id.to_owned(),
                lane,
                operation,
                documents,
                session_open: session_open(open),
            }
        }
        SemanticProviderActivity::Failed {
            attempted_operations,
            session_open: open,
        } => SemanticProviderActivityTelemetry::Failed {
            language_id: language_id.to_owned(),
            attempted_operations,
            session_open: session_open(open),
        },
    };
    refreshes.push(activity);
    record.timings
}

fn record_semantic_provider_execution_timings(
    phase_timings: &mut Vec<IndexPhaseTiming>,
    language_id: &str,
    summary_label: &str,
    provider_duration: Duration,
    normalization_duration: Duration,
    timings: Vec<SemanticProviderRefreshTiming>,
) {
    let provider_work = provider_duration.saturating_sub(normalization_duration);
    phase_timings.push(IndexPhaseTiming {
        phase: IndexProgressPhase::SemanticProvider,
        label: summary_label.to_owned(),
        duration: provider_work,
        aggregation: IndexTimingAggregation::ConcurrentSpan,
    });

    let measured: Duration = timings.iter().map(|timing| timing.duration).sum();
    debug_assert!(measured <= provider_work);
    phase_timings.extend(timings.into_iter().map(|timing| IndexPhaseTiming {
        phase: IndexProgressPhase::SemanticProvider,
        label: format!("{language_id} provider {}", timing.label),
        duration: timing.duration,
        aggregation: IndexTimingAggregation::Exclusive,
    }));
    phase_timings.push(IndexPhaseTiming {
        phase: IndexProgressPhase::SemanticProvider,
        label: format!("{language_id} semantic provider coordination remainder"),
        duration: provider_work.saturating_sub(measured),
        aggregation: IndexTimingAggregation::Exclusive,
    });
}

struct PersistentSemanticProviderLaneOutcome {
    normalization: Option<ScipArtifactSetNormalization>,
    reused: bool,
    failure: Option<ScipArtifactEvidence>,
    refreshes: Vec<SemanticProviderActivityTelemetry>,
    phase_timings: Vec<IndexPhaseTiming>,
}

impl PersistentSemanticProviderLaneOutcome {
    const fn empty() -> Self {
        Self {
            normalization: None,
            reused: false,
            failure: None,
            refreshes: Vec::new(),
            phase_timings: Vec::new(),
        }
    }
}

async fn run_persistent_semantic_provider_lane(
    provider: &mut dyn PersistentSemanticProvider,
    repository_root: &std::path::Path,
    inventory: &ProjectInventory,
    indexed_sources: &[IndexedSourceEvidence],
    prior_bases: &[CanonicalSemanticBasis],
    cancellation: &IndexCancellation,
    progress: &Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
) -> Result<PersistentSemanticProviderLaneOutcome, IndexPipelineError> {
    let mut outcome = PersistentSemanticProviderLaneOutcome::empty();
    let language = provider.language();
    let operation_label = provider.operation_label();
    let execution_roots =
        semantic_provider_execution_roots(inventory, language, provider.ecosystem())
            .into_iter()
            .map(|relative| repository_root.join(relative))
            .collect::<Vec<_>>();
    if execution_roots.is_empty() {
        return Ok(outcome);
    }

    let reuse_started = Instant::now();
    if let Some(normalization) = provider
        .reuse_exact_canonical_basis(
            repository_root,
            inventory,
            indexed_sources,
            prior_bases,
            cancellation,
        )
        .await
    {
        let reuse_duration = reuse_started.elapsed();
        let refresh_timings = record_semantic_provider_activity(
            &mut outcome.refreshes,
            language,
            provider.take_last_activity(),
        );
        debug_assert!(normalization.timings.total <= reuse_duration);
        record_semantic_provider_execution_timings(
            &mut outcome.phase_timings,
            language,
            &format!("{language} exact semantic basis admission"),
            reuse_duration,
            normalization.timings.total,
            refresh_timings,
        );
        outcome.normalization = Some(normalization);
        outcome.reused = true;
        return Ok(outcome);
    }

    let provider_started = Instant::now();
    emit_progress(
        progress,
        IndexProgressPhase::SemanticProvider,
        IndexProgressState::Started,
        operation_label,
        format!("{} exact project root(s)", execution_roots.len()),
        None,
    );
    match provider
        .refresh(
            repository_root,
            &execution_roots,
            indexed_sources,
            inventory,
            cancellation,
        )
        .await
    {
        Ok(normalization) => {
            let provider_duration = provider_started.elapsed();
            let refresh_timings = record_semantic_provider_activity(
                &mut outcome.refreshes,
                language,
                provider.take_last_activity(),
            );
            emit_progress(
                progress,
                IndexProgressPhase::SemanticProvider,
                IndexProgressState::Completed,
                operation_label,
                format!("{} exact project root(s)", execution_roots.len()),
                Some(provider_duration),
            );
            debug_assert!(normalization.timings.total <= provider_duration);
            record_semantic_provider_execution_timings(
                &mut outcome.phase_timings,
                language,
                &format!("{operation_label} execution and cache work"),
                provider_duration,
                normalization.timings.total,
                refresh_timings,
            );
            outcome.normalization = Some(normalization);
        }
        Err(error) => {
            if cancellation.is_cancelled() {
                return Err(IndexPipelineError::Cancelled);
            }
            let provider_duration = provider_started.elapsed();
            let refresh_timings = record_semantic_provider_activity(
                &mut outcome.refreshes,
                language,
                provider.take_last_activity(),
            );
            emit_progress(
                progress,
                IndexProgressPhase::SemanticProvider,
                IndexProgressState::Failed,
                operation_label,
                format!("{error}; Calls authority for {language} is unavailable"),
                Some(provider_duration),
            );
            record_semantic_provider_execution_timings(
                &mut outcome.phase_timings,
                language,
                &format!("{operation_label} certification failed"),
                provider_duration,
                Duration::ZERO,
                refresh_timings,
            );
            tracing::warn!(
                language,
                error = %error,
                "persistent semantic provider failed; refusing weaker one-shot authority"
            );
            outcome.failure = Some(ScipArtifactEvidence {
                language_id: LanguageId::new(language),
                receipt: CapabilityReceipt::unavailable(
                    "calls",
                    provider.provider_id(),
                    None,
                    CapabilityScope::Language {
                        language_id: LanguageId::new(language),
                        configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
                    },
                    None,
                    "provider_failed_or_unavailable",
                    format!(
                        "the persistent h00ligan {language} provider failed its authority or health contract; weaker one-shot authority was refused"
                    ),
                ),
                payload: None,
            });
        }
    }
    Ok(outcome)
}

/// Summary report returned after an indexing run.
#[derive(Debug, Clone, Default)]
pub struct IndexReport {
    /// Whether exact input and evidence verification returned the current
    /// immutable generation instead of rebuilding it.
    pub reused_generation: bool,
    /// Total files discovered by the walker.
    pub files_discovered: usize,
    /// Files whose blake3 hash changed (or are new).
    pub files_changed: usize,
    /// Files whose blake3 hash matched the cached state.
    pub files_unchanged: usize,
    /// Files present in state but no longer on disk.
    pub files_deleted: usize,
    /// Validated file records admitted from the preceding immutable generation
    /// as reusable input for this candidate.
    pub reusable_file_records: usize,
    /// Validated extraction-fact sets admitted from the preceding immutable
    /// generation as reusable input for this candidate.
    pub reusable_document_fact_sets: usize,
    /// Reusable rows persisted into the private candidate before indexing
    /// begins. This makes redundant seed persistence observable while the
    /// publication pipeline is being optimized.
    pub preindex_basis_rows_persisted: usize,
    /// Whether a long-lived supervisor supplied an exact generation-bound
    /// in-memory structural graph instead of reconstructing every source node.
    pub live_structural_basis_reused: bool,
    /// Total symbols extracted from changed files.
    pub symbols_extracted: usize,
    /// Graph nodes added.
    pub nodes_added: usize,
    /// Graph edges added.
    pub edges_added: usize,
    /// Total graph nodes in the completed candidate or exactly reused
    /// generation.
    pub nodes_total: usize,
    /// Total graph edges in the completed candidate or exactly reused
    /// generation.
    pub edges_total: usize,
    /// Complete reachability population for the resulting graph.
    pub reachability: Option<crate::graph_stats::ReachabilitySummary>,
    /// Declared relationships whose target is outside the indexed project
    /// domain. Informational: external supertypes are expected in every
    /// supported language.
    pub edges_skipped_external_relation: usize,
    /// EC-12 (WU-0001): edges skipped for any other reason (genuine NodeNotFound).
    pub edges_skipped_other: usize,
    /// EC-12 (WU-0001): distinct external-trait anchor nodes synthesized (the
    /// positive-signal proof the Implements/HasImpl producer now fires).
    pub external_traits_synthesized: usize,
    /// Total pipeline wall-clock duration.
    pub duration: Duration,
    /// Always-collected coarse phase timings. Detailed per-file/batch profiling
    /// remains opt-in through `profile`.
    pub phase_timings: Vec<IndexPhaseTiming>,
    /// Bounded typed refresh lanes for persistent semantic providers.
    pub semantic_provider_refreshes: Vec<SemanticProviderActivityTelemetry>,
}

/// Source population measured by one completed indexing run for one language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageSourceInventory {
    pub language_id: LanguageId,
    pub files_discovered: usize,
    pub files_covered: usize,
    pub extraction_failures: usize,
    /// Stable digest of ordered repository-relative paths and source hashes.
    pub source_fingerprint: String,
}

/// Machine evidence produced by a completed, non-dry indexing run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEvidence {
    pub source_inventory: Vec<LanguageSourceInventory>,
    pub project_inventory: ProjectInventory,
    pub capability_receipts: Vec<CapabilityReceipt>,
    pub provider_payloads: Vec<CanonicalProviderPayload>,
}

/// Indexing telemetry is always available; publishable evidence exists only
/// after extraction and persistence phases complete.
#[derive(Debug)]
pub(crate) enum IndexRunOutcome {
    DryRun {
        telemetry: IndexReport,
    },
    Completed {
        telemetry: Box<IndexReport>,
        evidence: IndexEvidence,
        /// Opaque graph/evidence proof is carried across the async pipeline
        /// boundary once, so keep its sizeable fixed representation behind
        /// indirection instead of inflating every outcome value.
        publication_proof: Option<Box<BoundGraphPublicationProof>>,
        index_state_publication_proof: BoundIndexStatePublicationProof,
    },
}

/// Exact in-memory structural state produced by a completed pipeline run.
/// Publication binds this basis to the immutable generation only after the
/// candidate is durably committed; it is never authority by itself.
pub(crate) struct CompletedStructuralBasis {
    pub(crate) source: IncrementalIndexBasis,
    pub(crate) graph: KnowledgeGraph,
    pub(crate) semantic_bases: Vec<CanonicalSemanticBasis>,
}

pub(crate) struct IncrementalPipelineBasis {
    pub(crate) source: IncrementalIndexBasis,
    pub(crate) graph: Option<KnowledgeGraph>,
    pub(crate) semantic_bases: Vec<CanonicalSemanticBasis>,
    /// Validated immutable inventory paired with the retained semantic basis.
    /// A fresh candidate uses it only to localize provider-input drift; the
    /// newly discovered inventory remains publication authority.
    pub(crate) project_inventory: Arc<ProjectInventory>,
}

/// Disposable process-local acceleration supplied to one pipeline run.
///
/// Neither input is publication authority: the incremental basis has already
/// been admitted by the publisher, and semantic-provider evidence must still
/// pass the normalizer and capability gates before it can be published.
pub(crate) struct IndexPipelineRuntime<'a> {
    pub(crate) incremental_basis: Option<IncrementalPipelineBasis>,
    pub(crate) semantic_providers: &'a mut SemanticProviderRegistry,
}

pub(crate) struct PreparedIndexRun {
    pub(crate) outcome: IndexRunOutcome,
    pub(crate) structural_basis: Option<CompletedStructuralBasis>,
}

impl IndexRunOutcome {
    pub(crate) const fn telemetry(&self) -> &IndexReport {
        match self {
            Self::DryRun { telemetry } => telemetry,
            Self::Completed { telemetry, .. } => telemetry,
        }
    }

    #[cfg(test)]
    pub(crate) const fn evidence(&self) -> Option<&IndexEvidence> {
        match self {
            Self::DryRun { .. } => None,
            Self::Completed { evidence, .. } => Some(evidence),
        }
    }
}

impl std::ops::Deref for IndexRunOutcome {
    type Target = IndexReport;

    fn deref(&self) -> &Self::Target {
        self.telemetry()
    }
}

struct RoutedSemanticEvidence {
    calls_by_language: BTreeMap<String, Vec<PublicationReadySemanticEvidence>>,
    additional_receipts: Vec<CapabilityReceipt>,
    additional_payloads: Vec<CanonicalProviderPayload>,
}

/// Route each sealed provider capability before capability-specific
/// selection. A provider may return canonical SCIP documents and independent
/// typed analyses in one terminal, but those outputs must never become
/// competing candidates for Calls merely because they share a language and
/// provider process.
fn route_semantic_evidence(
    evidence: Vec<PublicationReadySemanticEvidence>,
) -> RoutedSemanticEvidence {
    let mut calls_by_language = BTreeMap::<String, Vec<_>>::new();
    let mut additional_receipts = Vec::new();
    let mut additional_payloads = Vec::new();
    for evidence in evidence {
        if evidence.receipt.capability_id == "calls" {
            calls_by_language
                .entry(evidence.language_id.0.clone())
                .or_default()
                .push(evidence);
            continue;
        }

        let PublicationReadySemanticEvidence {
            language_id,
            receipt,
            payload,
        } = evidence;
        let identity_matches = receipt.scope.language_id() == Some(&language_id)
            && payload.as_ref().is_none_or(|payload| {
                payload.payload().receipt() == &receipt
                    && !matches!(payload.payload(), ProviderPayload::Calls(_))
            });
        if identity_matches {
            additional_receipts.push(receipt);
            if let Some(payload) = payload {
                additional_payloads.push(payload);
            }
        } else {
            additional_receipts.push(CapabilityReceipt::unavailable(
                receipt.capability_id,
                receipt.provider_id.0,
                receipt.provider_version,
                receipt.scope,
                receipt.input_fingerprint,
                "provider_evidence_inconsistent",
                "semantic provider evidence differs from its language, capability, or payload identity",
            ));
        }
    }
    RoutedSemanticEvidence {
        calls_by_language,
        additional_receipts,
        additional_payloads,
    }
}

fn build_index_evidence(
    config: &IndexConfig,
    blocking: &BlockingPhaseResult,
    indexed_files: &[(String, FileRecord)],
    project_inventory: ProjectInventory,
    semantic_evidence: Vec<PublicationReadySemanticEvidence>,
    configured_calls_languages: &BTreeSet<String>,
) -> IndexEvidence {
    let RoutedSemanticEvidence {
        mut calls_by_language,
        additional_receipts,
        additional_payloads,
    } = route_semantic_evidence(semantic_evidence);
    let mut inputs_by_language: BTreeMap<String, Vec<&SourceInput>> = BTreeMap::new();
    for input in &blocking.source_inputs {
        inputs_by_language
            .entry(input.language.clone())
            .or_default()
            .push(input);
    }

    let mut extraction_failures_by_language: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (path, _) in &blocking.extraction_errors {
        let language = path
            .extension()
            .and_then(|extension| extension.to_str())
            .and_then(extension_to_language)
            .unwrap_or("unknown")
            .to_owned();
        let relative = path
            .strip_prefix(&config.root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        extraction_failures_by_language
            .entry(language)
            .or_default()
            .insert(relative);
    }

    let mut capture_gaps_by_language: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut capture_gap_kinds_by_language: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> =
        BTreeMap::new();
    for facts in &blocking.document_facts {
        if !facts.has_uncaptured_items() {
            continue;
        }
        let language = std::path::Path::new(&facts.file_path)
            .extension()
            .and_then(|extension| extension.to_str())
            .and_then(extension_to_language)
            .unwrap_or("unknown")
            .to_owned();
        capture_gaps_by_language
            .entry(language.clone())
            .or_default()
            .insert(facts.file_path.clone());
        for gap in &facts.capture_gaps {
            capture_gap_kinds_by_language
                .entry(language.clone())
                .or_default()
                .entry(gap.kind.clone())
                .or_default()
                .insert(facts.file_path.clone());
        }
    }

    // Extraction can succeed yet still produce two symbols with the same
    // graph identity (for example mutually exclusive cfg arms). Graph
    // insertion currently retains one node. Detect that representational loss
    // from the authoritative per-file symbol count and downgrade the receipt;
    // never publish the collapsed graph as complete.
    let mut identity_collisions_by_language: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (path, record) in indexed_files {
        if extraction_failures_by_language
            .get(&record.language)
            .is_some_and(|failures| failures.contains(path))
        {
            continue;
        }
        if blocking.graph.nodes_for_file(path).len() != record.symbol_count as usize {
            identity_collisions_by_language
                .entry(record.language.clone())
                .or_default()
                .insert(path.clone());
        }
    }

    let mut source_inventory = Vec::with_capacity(inputs_by_language.len());
    let mut capability_receipts =
        Vec::with_capacity(inputs_by_language.len() * 2 + additional_receipts.len());
    capability_receipts.extend(additional_receipts);
    let mut provider_payloads = additional_payloads;
    let configuration_id = ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID);
    for (language, mut inputs) in inputs_by_language {
        inputs.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let extraction_failures = extraction_failures_by_language
            .get(&language)
            .map_or(0, BTreeSet::len);
        let identity_collisions = identity_collisions_by_language
            .get(&language)
            .map_or(0, BTreeSet::len);
        let capture_gap_paths = capture_gaps_by_language
            .get(&language)
            .cloned()
            .unwrap_or_default();
        let capture_gaps = capture_gap_paths.len();
        let mut uncovered_paths = extraction_failures_by_language
            .get(&language)
            .cloned()
            .unwrap_or_default();
        uncovered_paths.extend(
            identity_collisions_by_language
                .get(&language)
                .into_iter()
                .flat_map(|paths| paths.iter().cloned()),
        );
        uncovered_paths.extend(capture_gap_paths.iter().cloned());
        let fingerprint = structural_input_fingerprint(&language, &inputs, &config.exclude);
        let scope = CapabilityScope::Language {
            language_id: LanguageId::new(&language),
            configuration_id: configuration_id.clone(),
        };
        source_inventory.push(LanguageSourceInventory {
            language_id: LanguageId::new(&language),
            files_discovered: inputs.len(),
            files_covered: inputs.len().saturating_sub(uncovered_paths.len()),
            extraction_failures,
            source_fingerprint: fingerprint.clone(),
        });

        let structural = if identity_collisions > 0 {
            CapabilityReceipt::partial(
                "structural_graph",
                "h00-structural",
                Some(crate::INDEXER_IDENTITY.to_owned()),
                scope.clone(),
                Some(fingerprint.clone()),
                "structural_identity_collision",
                format!(
                    "{identity_collisions} {language} source file(s) contain extracted symbol identities the graph collapsed"
                ),
            )
        } else if extraction_failures > 0 {
            CapabilityReceipt::partial(
                "structural_graph",
                "h00-structural",
                Some(crate::INDEXER_IDENTITY.to_owned()),
                scope.clone(),
                Some(fingerprint.clone()),
                "source_extraction_failed",
                format!("{extraction_failures} {language} source file(s) could not be extracted"),
            )
        } else if capture_gaps > 0 {
            let gap_kinds = capture_gap_kinds_by_language.get(&language);
            let mut kind_counts = gap_kinds
                .into_iter()
                .flat_map(|kinds| kinds.iter())
                .map(|(kind, paths)| (kind.as_str(), paths.len()))
                .collect::<Vec<_>>();
            kind_counts
                .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
            let kinds = kind_counts
                .into_iter()
                .take(8)
                .map(|(kind, files)| {
                    let example = gap_kinds
                        .and_then(|kinds| kinds.get(kind))
                        .and_then(|paths| paths.first())
                        .map_or("<unknown>", String::as_str);
                    format!("{kind}={files} [{example}]")
                })
                .collect::<Vec<_>>()
                .join(", ");
            CapabilityReceipt::partial(
                "structural_graph",
                "h00-structural",
                Some(crate::INDEXER_IDENTITY.to_owned()),
                scope.clone(),
                Some(fingerprint.clone()),
                "structural_capture_incomplete",
                format!(
                    "{capture_gaps} {language} source file(s) contain declaration shapes not represented by the structural graph (gap kinds and examples: {kinds})"
                ),
            )
        } else if !config.exclude.is_empty() {
            CapabilityReceipt::partial(
                "structural_graph",
                "h00-structural",
                Some(crate::INDEXER_IDENTITY.to_owned()),
                scope.clone(),
                Some(fingerprint.clone()),
                "source_population_filtered",
                "explicit exclusion patterns prevent complete language coverage",
            )
        } else {
            CapabilityReceipt::complete(
                "structural_graph",
                "h00-structural",
                crate::INDEXER_IDENTITY,
                scope.clone(),
                fingerprint,
            )
        };
        capability_receipts.push(structural);

        let semantic_sources_present =
            project_inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.language_id.0 == language
                        && project_inventory.is_semantic_source_owner(membership)
                });
        if semantic_sources_present {
            let calls = select_calls_evidence(
                config.scip,
                &language,
                calls_provider_execution_root_available(&project_inventory, &language),
                configured_calls_languages.contains(&language),
                calls_by_language.remove(&language).unwrap_or_default(),
                &mut provider_payloads,
            );
            capability_receipts.push(calls);
        }
    }
    sort_capability_receipts(&mut capability_receipts);
    IndexEvidence {
        source_inventory,
        project_inventory,
        capability_receipts,
        provider_payloads,
    }
}

fn admitted_canonical_semantic_bases(
    snapshots: Vec<(CanonicalScipSnapshot, Option<CanonicalSourceSyntaxCache>)>,
    evidence: &IndexEvidence,
) -> Vec<CanonicalSemanticBasis> {
    snapshots
        .into_iter()
        .filter_map(|(snapshot, source_syntax_cache)| {
            let mut payloads = evidence.provider_payloads.iter().filter(|payload| {
                let receipt = payload.payload().receipt();
                matches!(payload.payload(), ProviderPayload::Calls(_))
                    && receipt.status == CapabilityStatus::Complete
                    && receipt.provider_id.0 == snapshot.provider_id()
                    && receipt.provider_version.as_deref()
                        == Some(snapshot.executed_provider_version())
            });
            let payload = payloads.next()?;
            if payloads.next().is_some() {
                return None;
            }
            let receipt = payload.payload().receipt().clone();
            let language_id = receipt.scope.language_id()?.clone();
            let supplemental_evidence = evidence
                .provider_payloads
                .iter()
                .filter(|candidate| {
                    let candidate_receipt = candidate.payload().receipt();
                    !matches!(candidate.payload(), ProviderPayload::Calls(_))
                        && candidate_receipt.status == CapabilityStatus::Complete
                        && candidate_receipt.provider_id == receipt.provider_id
                        && candidate_receipt.provider_version == receipt.provider_version
                        && candidate_receipt.scope.language_id() == Some(&language_id)
                })
                .map(|candidate| ScipArtifactEvidence {
                    language_id: language_id.clone(),
                    receipt: candidate.payload().receipt().clone(),
                    payload: Some(candidate.normalized_clone()),
                })
                .collect();
            Some(CanonicalSemanticBasis {
                snapshot,
                evidence: ScipArtifactEvidence {
                    language_id,
                    receipt,
                    payload: Some(payload.normalized_clone()),
                },
                supplemental_evidence,
                source_syntax_cache,
            })
        })
        .collect()
}

fn require_requested_semantic_authority(
    config: &IndexConfig,
    evidence: &IndexEvidence,
    graph: &KnowledgeGraph,
) -> Result<(), IndexPipelineError> {
    if !config.require_complete_calls {
        return Ok(());
    }

    let provider_payloads = evidence
        .provider_payloads
        .iter()
        .map(|payload| payload.payload())
        .collect::<Vec<_>>();
    let coverage = assess_calls_capability_refs(
        graph,
        &evidence.capability_receipts,
        &provider_payloads,
        &evidence.project_inventory,
    );
    if coverage.all_callable_languages_complete() {
        return Ok(());
    }

    let gaps = coverage
        .languages
        .iter()
        .filter(|language| language.status != CapabilityCoverageStatus::Complete)
        .flat_map(|language| {
            if !language.qualifications.is_empty() {
                return language
                    .qualifications
                    .iter()
                    .map(|qualification| {
                        format!(
                            "{}:{}:{}: {}",
                            language.language_id,
                            qualification.provider_id,
                            qualification.reason_code,
                            qualification.reason,
                        )
                    })
                    .collect::<Vec<_>>();
            }
            if language.gaps.is_empty() {
                return vec![format!(
                    "{}:{:?}: no complete provider evidence",
                    language.language_id, language.status
                )];
            }
            language
                .gaps
                .iter()
                .map(|gap| {
                    format!(
                        "{}:{}:{}: {}",
                        language.language_id,
                        gap.provider_id
                            .as_ref()
                            .map_or("unassigned", |provider| provider.0.as_str()),
                        gap.reason_code,
                        gap.reason,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    Err(IndexPipelineError::SemanticProvidersUnsatisfied {
        evidence: if gaps.is_empty() {
            "the callable source population had no complete Calls evidence".into()
        } else {
            gaps.join("; ")
        },
    })
}

fn select_calls_evidence(
    scip_mode: ScipMode,
    language: &str,
    execution_root_available: bool,
    provider_configured: bool,
    mut evidence: Vec<PublicationReadySemanticEvidence>,
    provider_payloads: &mut Vec<CanonicalProviderPayload>,
) -> CapabilityReceipt {
    let default_provider = default_calls_provider(language);
    let scope = CapabilityScope::Language {
        language_id: LanguageId::new(language),
        configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
    };
    if scip_mode == ScipMode::Disabled {
        return CapabilityReceipt::unavailable(
            "calls",
            default_provider,
            None,
            scope,
            None,
            "provider_not_requested",
            "semantic Calls provider execution was not requested",
        );
    }
    if evidence.is_empty() {
        let (reason_code, reason) = match calls_provider_policy(language) {
            Some(policy) if !execution_root_available => (
                "provider_execution_root_unavailable",
                policy.missing_execution_root_reason,
            ),
            Some(_) if !provider_configured => (
                "provider_not_configured",
                "this h00ligan product does not configure a semantic Calls provider for this language",
            ),
            Some(_) => (
                "provider_failed_or_unavailable",
                "a configured semantic Calls provider did not produce validated scoped evidence",
            ),
            None => (
                "provider_not_configured",
                "no semantic Calls provider is configured for this language",
            ),
        };
        return CapabilityReceipt::unavailable(
            "calls",
            default_provider,
            None,
            scope,
            None,
            reason_code,
            reason,
        );
    }
    if evidence.len() > 1 {
        return CapabilityReceipt::partial(
            "calls",
            default_provider,
            None,
            scope,
            None,
            "provider_artifact_ambiguous",
            "multiple SCIP artifacts claimed the same language scope",
        );
    }

    let evidence = evidence.pop().expect("one SCIP evidence item");
    if !calls_evidence_identity_matches(language, &evidence) {
        return inconsistent_calls_evidence_receipt(language);
    }

    match (evidence.receipt.status, evidence.payload) {
        (CapabilityStatus::Complete, Some(payload)) => {
            provider_payloads.push(payload);
            evidence.receipt
        }
        (CapabilityStatus::Partial | CapabilityStatus::Unavailable, None) => evidence.receipt,
        _ => CapabilityReceipt::unavailable(
            "calls",
            default_provider,
            None,
            scope,
            None,
            "provider_evidence_inconsistent",
            "SCIP normalization returned inconsistent receipt and payload evidence",
        ),
    }
}

fn calls_provider_execution_root_available(inventory: &ProjectInventory, language: &str) -> bool {
    calls_provider_policy(language).is_some_and(|policy| {
        !semantic_provider_execution_roots(inventory, language, policy.ecosystem).is_empty()
    })
}

fn structural_input_fingerprint(
    language: &str,
    inputs: &[&SourceInput],
    exclude_patterns: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"h00/structural-input/v3\0");
    hasher.update(language.as_bytes());
    hasher.update(b"\0");
    let mut excludes = exclude_patterns.to_vec();
    excludes.sort();
    for exclude in excludes {
        hasher.update(b"exclude\0");
        hasher.update(exclude.as_bytes());
        hasher.update(b"\0");
    }
    for input in inputs {
        hasher.update(input.relative_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(input.content_hash.as_bytes());
        hasher.update(b"\0");
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The index pipeline orchestrator.
pub struct IndexPipeline;

/// Partition extraction results into successes and failures.
fn partition_results(
    paths: &[PathBuf],
    results: Vec<Result<ExtractorOutput, crate::structural_ir::ExtractorError>>,
) -> (Vec<ExtractorOutput>, Vec<(PathBuf, String)>) {
    let mut ok_results = Vec::new();
    let mut err_results = Vec::new();
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(output) => ok_results.push(output),
            Err(e) => err_results.push((paths[i].clone(), e.to_string())),
        }
    }
    (ok_results, err_results)
}

/// Map a file extension to its canonical language name.
///
/// Thin delegate to [`crate::language::language_for_extension`] — the registry
/// is the single source of truth (ADR-0024 §F DRY rider). Kept as a named fn so
/// its call sites (memory-metadata language + `FileRecord.language`) are stable.
fn extension_to_language(ext: &str) -> Option<&'static str> {
    crate::language::language_for_extension(ext)
}

/// Return the set of supported file extensions, filtered by the config.
///
/// Derived from the single-source [`crate::language`] registry (ADR-0024 §F DRY
/// rider), replacing the old inline `vec![("rs", "rust")]`. An empty
/// `config.languages` yields every registered extension; otherwise only the
/// extensions whose language is named in `config.languages`.
fn supported_extensions(config: &IndexConfig) -> HashSet<String> {
    crate::language::extensions_for_languages(&config.languages)
}

/// Result of the blocking discover+diff+extract phase.
struct BlockingPhaseResult {
    discovered_paths: Vec<PathBuf>,
    changed_paths: Vec<PathBuf>,
    unchanged_count: usize,
    deleted_paths: Vec<String>,
    /// Successfully extracted files from this run only.
    outputs: Vec<ExtractorOutput>,
    /// Complete, hash-validated extraction facts for the current source
    /// population. Relationship resolution always consumes this population,
    /// including facts reused for unchanged documents.
    document_facts: Vec<ExtractorOutput>,
    extraction_errors: Vec<(PathBuf, String)>,
    source_inputs: Vec<SourceInput>,
    /// Exact source-owner/dependency authority consumed by structural
    /// relationship resolution and later semantic publication.
    project_inventory: Option<ProjectInventory>,
    graph: KnowledgeGraph,
    build_stats: BuildStats,
    // Profiling data (only populated when config.profile == true).
    profile_discovery_dur: Option<Duration>,
    profile_diff_dur: Option<Duration>,
    profile_inventory_dur: Option<Duration>,
    profile_extract_dur: Option<Duration>,
    profile_graph_dur: Option<Duration>,
    profile_file_timings: Vec<FileExtractTiming>,
}

#[derive(Debug, Clone)]
struct SourceInput {
    relative_path: String,
    language: String,
    content_hash: String,
}

/// Recompute structural receipt fingerprints from one immutable generation's
/// persisted source records under the exact current indexer identity. `None`
/// is a fail-closed signal: callers must rebuild when build-time identity could
/// not be measured.
pub(crate) fn structural_input_fingerprints_from_records(
    indexed_files: &[(String, FileRecord)],
    exclude_patterns: &[String],
) -> Option<BTreeMap<String, String>> {
    if crate::INDEXER_IDENTITY == "unavailable" {
        return None;
    }
    let mut by_language = BTreeMap::<String, Vec<SourceInput>>::new();
    for (relative_path, record) in indexed_files {
        by_language
            .entry(record.language.clone())
            .or_default()
            .push(SourceInput {
                relative_path: relative_path.clone(),
                language: record.language.clone(),
                content_hash: record.blake3_hash.clone(),
            });
    }
    Some(
        by_language
            .into_iter()
            .map(|(language, mut inputs)| {
                inputs.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
                let references = inputs.iter().collect::<Vec<_>>();
                let fingerprint =
                    structural_input_fingerprint(&language, &references, exclude_patterns);
                (language, fingerprint)
            })
            .collect(),
    )
}

/// Verify that a generation's structural receipts describe the exact indexed
/// file population under the current structural extractor identity.
pub(crate) fn structural_receipts_match_records(
    receipts: &[CapabilityReceipt],
    indexed_files: &[(String, FileRecord)],
    exclude_patterns: &[String],
) -> bool {
    let Some(expected) =
        structural_input_fingerprints_from_records(indexed_files, exclude_patterns)
    else {
        return false;
    };
    let mut observed = BTreeMap::new();
    for receipt in receipts
        .iter()
        .filter(|receipt| receipt.capability_id == "structural_graph")
    {
        let CapabilityScope::Language {
            language_id,
            configuration_id,
        } = &receipt.scope
        else {
            return false;
        };
        // Partial is a truthful coverage qualification, not an identity
        // failure. Exact source fingerprints under the current extractor make
        // both Complete and Partial structural graphs reusable; Unavailable
        // evidence has no graph authority and remains fail-closed.
        if !matches!(
            receipt.status,
            CapabilityStatus::Complete | CapabilityStatus::Partial
        ) || receipt.provider_id.0 != "h00-structural"
            || configuration_id.0 != crate::code_intel_domain::STRUCTURAL_GRAPH_CONFIGURATION_ID
            || receipt.provider_version.as_deref() != Some(crate::INDEXER_IDENTITY)
        {
            return false;
        }
        let Some(fingerprint) = receipt.input_fingerprint.clone() else {
            return false;
        };
        if observed
            .insert(language_id.0.clone(), fingerprint)
            .is_some()
        {
            return false;
        }
    }
    observed == expected
}

#[derive(Debug)]
struct GeneratedProviderArtifact {
    artifact: crate::scip_loader::GeneratedScipArtifact,
    spec: ScipProviderSpec,
    execution_root: PathBuf,
    provider_configuration_sha256: String,
}

struct GoProviderExecution {
    execution_root: PathBuf,
    timing_label: String,
    provider_configuration_sha256: String,
    duration: Duration,
    result: Result<crate::scip_loader::GeneratedScipArtifact, crate::scip_loader::ScipLoaderError>,
}

fn invocation_provider_configuration_sha256(
    spec: ScipProviderSpec,
    artifact: &crate::scip_loader::GeneratedScipArtifact,
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        b"h00/invocation-bound-scip-provider/v1\0".as_slice(),
        spec.language.as_bytes(),
        spec.provider_id.as_bytes(),
        artifact.provider_version.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn go_cross_process_reuse_is_bounded(
    repository_root: &std::path::Path,
    inventory: &ProjectInventory,
    toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
) -> bool {
    if inventory.coverage != ProjectInventoryCoverage::IndexedSourcePopulationComplete
        || !inventory.issues.is_empty()
        || toolchains.is_empty()
    {
        return false;
    }
    for execution_root in toolchains.keys() {
        if execution_root.join("vendor").exists() {
            return false;
        }
    }
    for input in inventory
        .inputs
        .iter()
        .filter(|input| input.language_id.0 == "go")
    {
        let absolute_input = repository_root.join(&input.path);
        let Ok(bytes) = std::fs::read(&absolute_input) else {
            return false;
        };
        if input.path.ends_with("go.mod")
            && !go_mod_local_replacements_are_repository_bound(
                repository_root,
                absolute_input.parent().unwrap_or(repository_root),
                &bytes,
            )
        {
            return false;
        }
        if input.path.ends_with("go.work")
            && !go_work_uses_are_repository_bound(
                repository_root,
                absolute_input.parent().unwrap_or(repository_root),
                &bytes,
            )
        {
            return false;
        }
    }
    true
}

fn go_local_path_is_repository_bound(
    repository_root: &std::path::Path,
    declaration_root: &std::path::Path,
    value: &str,
) -> bool {
    let path = std::path::Path::new(value);
    let local = path.is_absolute() || value.starts_with('.');
    if !local {
        return true;
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        declaration_root.join(path)
    };
    let (Ok(repository_root), Ok(candidate)) = (
        std::fs::canonicalize(repository_root),
        std::fs::canonicalize(candidate),
    ) else {
        return false;
    };
    candidate.is_dir() && candidate.starts_with(repository_root)
}

fn go_mod_local_replacements_are_repository_bound(
    repository_root: &std::path::Path,
    module_root: &std::path::Path,
    bytes: &[u8],
) -> bool {
    let Ok(source) = std::str::from_utf8(bytes) else {
        return false;
    };
    source.lines().all(|line| {
        let Some((_, replacement)) = line.split_once("=>") else {
            return true;
        };
        let Some(target) = replacement.split_whitespace().next() else {
            return false;
        };
        go_local_path_is_repository_bound(repository_root, module_root, target)
    })
}

fn go_work_uses_are_repository_bound(
    repository_root: &std::path::Path,
    workspace_root: &std::path::Path,
    bytes: &[u8],
) -> bool {
    let Ok(source) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut use_group = false;
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if line == "use (" {
            use_group = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("use ") {
            let Some(target) = rest.split_whitespace().next() else {
                return false;
            };
            if !(std::path::Path::new(target).is_absolute() || target.starts_with('.'))
                || !go_local_path_is_repository_bound(repository_root, workspace_root, target)
            {
                return false;
            }
            continue;
        }
        if use_group {
            if line == ")" {
                use_group = false;
                continue;
            }
            let Some(target) = line.split_whitespace().next() else {
                return false;
            };
            if !(std::path::Path::new(target).is_absolute() || target.starts_with('.'))
                || !go_local_path_is_repository_bound(repository_root, workspace_root, target)
            {
                return false;
            }
        }
    }
    !use_group
}

fn go_provider_documents_have_bounded_external_inputs(
    repository_root: &std::path::Path,
    payload: &crate::code_intel_payload::CallsProviderPayload,
) -> bool {
    let omitted_documents = payload
        .coverage_exclusions
        .iter()
        .filter(|exclusion| exclusion.reason_code == "provider_document_omitted")
        .map(|exclusion| exclusion.location.document_path.as_str())
        .collect::<BTreeSet<_>>();
    payload
        .documents
        .iter()
        .filter(|document| !omitted_documents.contains(document.document_path.as_str()))
        .all(|document| {
            let Ok(bytes) = std::fs::read(repository_root.join(&document.document_path)) else {
                return false;
            };
            let mut import_group = false;
            for line in bytes.split(|byte| *byte == b'\n') {
                let line = line.trim_ascii_start();
                if line.starts_with(b"//go:embed") {
                    return false;
                }
                if let Some(rest) = line.strip_prefix(b"import") {
                    let rest = rest.trim_ascii_start();
                    if rest.starts_with(b"\"C\"") {
                        return false;
                    }
                    import_group = rest.starts_with(b"(");
                    continue;
                }
                if import_group {
                    if line.starts_with(b")") {
                        import_group = false;
                    } else if line.starts_with(b"\"C\"") {
                        return false;
                    }
                }
            }
            true
        })
}

#[derive(Clone)]
enum GoSemanticReusePlan {
    Exact(CanonicalSemanticBasis),
    AffectedRoots {
        basis: CanonicalSemanticBasis,
        roots: BTreeSet<PathBuf>,
    },
}

impl GoSemanticReusePlan {
    fn roots_to_execute(
        &self,
        toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
    ) -> Vec<(PathBuf, ResolvedToolchain)> {
        match self {
            Self::Exact(_) => Vec::new(),
            Self::AffectedRoots { roots, .. } => roots
                .iter()
                .filter_map(|root| {
                    toolchains
                        .get(root)
                        .cloned()
                        .map(|toolchain| (root.clone(), toolchain))
                })
                .collect(),
        }
    }

    fn expected_provider_executions(&self) -> usize {
        match self {
            Self::Exact(_) => 0,
            Self::AffectedRoots { roots, .. } => roots.len(),
        }
    }
}

fn go_retained_semantic_inputs_are_current(
    repository_root: &std::path::Path,
    prior_inputs: &h00ligan_provider_protocol::ProviderSemanticInputs,
    prior_inventory: &ProjectInventory,
    current_inventory: &ProjectInventory,
    expected_roots: &BTreeSet<String>,
    retained_roots: &BTreeSet<String>,
) -> bool {
    if prior_inputs.coverage != h00ligan_provider_protocol::ProviderSemanticInputCoverage::Complete
        || !prior_inputs.environment.is_empty()
        || !prior_inputs.issues.is_empty()
    {
        return false;
    }
    let Some(prior_input_roots) = go_project_input_execution_roots(prior_inventory, expected_roots)
    else {
        return false;
    };
    let Some(current_input_roots) =
        go_project_input_execution_roots(current_inventory, expected_roots)
    else {
        return false;
    };
    let prior_paths = prior_inputs
        .paths
        .iter()
        .map(|input| (input.path.clone(), input))
        .collect::<BTreeMap<_, _>>();
    if prior_paths.keys().collect::<BTreeSet<_>>()
        != prior_input_roots.keys().collect::<BTreeSet<_>>()
    {
        return false;
    }
    let current_paths = current_input_roots.keys().cloned().collect::<BTreeSet<_>>();
    let Ok(current_inputs) = h00ligan_provider_protocol::capture_provider_semantic_inputs(
        repository_root,
        &current_paths,
        &BTreeSet::new(),
        &h00ligan_provider_protocol::ProviderFrameLimits::default(),
    ) else {
        return false;
    };
    let current_paths = current_inputs
        .paths
        .iter()
        .map(|input| (input.path.clone(), input))
        .collect::<BTreeMap<_, _>>();
    let all_paths = prior_input_roots
        .keys()
        .chain(current_input_roots.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    all_paths.into_iter().all(|path| {
        let owners = prior_input_roots
            .get(&path)
            .into_iter()
            .chain(current_input_roots.get(&path))
            .flat_map(|roots| roots.iter().cloned())
            .collect::<BTreeSet<_>>();
        owners.is_disjoint(retained_roots) || prior_paths.get(&path) == current_paths.get(&path)
    })
}

fn go_toolchain_bound_authority(
    repository_root: &std::path::Path,
    inventory: &ProjectInventory,
    toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
    resolver_policy_id: Option<&str>,
) -> Option<ProviderExecutionAuthority> {
    if !go_cross_process_reuse_is_bounded(repository_root, inventory, toolchains) {
        return None;
    }
    let resolver_policy_id = resolver_policy_id?;
    let provider_implementation =
        toolchain_provider_implementation_sha256(toolchains, "scip-go").ok()?;
    let configurations = toolchain_provider_configuration_population(
        repository_root,
        SCIP_GO_REUSE_CONTRACT_ID,
        toolchains,
    )
    .ok()?;
    toolchain_bound_execution_authority(ToolchainBoundAuthorityInput {
        repository_root,
        inventory,
        language: "go",
        ecosystem: "go",
        resolver_policy_id,
        reuse_contract_id: SCIP_GO_REUSE_CONTRACT_ID,
        provider_implementation_sha256: &provider_implementation,
        provider_configurations_sha256: &configurations,
        reconstruction_descriptors: None,
        toolchains,
    })
    .ok()
}

#[allow(clippy::too_many_arguments)]
fn go_semantic_reuse_plan(
    repository_root: &std::path::Path,
    prior: &[CanonicalSemanticBasis],
    current_authority: Option<&ProviderExecutionAuthority>,
    toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
    debug: bool,
    prior_inventory: Option<&ProjectInventory>,
    inventory: &ProjectInventory,
    changed_paths: &[PathBuf],
    deleted_paths: &[String],
    existing_files: &std::collections::HashMap<String, FileRecord>,
) -> Option<GoSemanticReusePlan> {
    macro_rules! refuse {
        ($reason:literal) => {{
            tracing::debug!(reason = $reason, "Go semantic basis reuse refused");
            if debug {
                eprintln!("Debug: Go semantic basis reuse refused: {}", $reason);
            }
            return None;
        }};
    }
    let mut candidates = prior.iter().filter(|basis| {
        basis.evidence.language_id.0 == "go" && basis.snapshot.provider_id() == "scip-go"
    });
    let Some(candidate) = candidates.next() else {
        refuse!("no retained canonical scip-go basis");
    };
    if candidates.next().is_some()
        || candidate.evidence.receipt.status != CapabilityStatus::Complete
        || candidate.evidence.receipt.provider_id.0 != "scip-go"
    {
        refuse!("retained Go basis population or receipt is invalid");
    }
    let Some(ProviderPayload::Calls(payload)) = candidate
        .evidence
        .payload
        .as_ref()
        .map(|payload| payload.payload())
    else {
        refuse!("retained Go basis has no Calls payload");
    };
    let Some(authority) = current_authority else {
        refuse!("current Go toolchain-bound authority is unavailable");
    };
    if payload.receipt != candidate.evidence.receipt
        || payload.receipt.provider_version.as_deref()
            != Some(candidate.snapshot.executed_provider_version())
    {
        refuse!("retained Go receipt or provider version is stale");
    }

    let ProviderExecutionAuthority::ToolchainBound {
        resolver_policy_id: prior_resolver_policy,
        ecosystem_id: prior_ecosystem,
        reuse_contract_id: prior_reuse_contract,
        provider_implementation_sha256: prior_implementation,
        provider_inventory_sha256: prior_inventory_sha256,
        roots: prior_roots,
    } = &payload.execution_authority
    else {
        refuse!("retained Go basis is not toolchain-bound");
    };
    let ProviderExecutionAuthority::ToolchainBound {
        resolver_policy_id: current_resolver_policy,
        ecosystem_id: current_ecosystem,
        reuse_contract_id: current_reuse_contract,
        provider_implementation_sha256: current_implementation,
        provider_inventory_sha256: current_inventory_sha256,
        roots: current_roots,
    } = authority
    else {
        refuse!("current Go authority is not toolchain-bound");
    };
    if prior_resolver_policy != current_resolver_policy
        || prior_ecosystem != current_ecosystem
        || prior_reuse_contract != current_reuse_contract
        || prior_implementation != current_implementation
    {
        refuse!("Go resolver, ecosystem, reuse contract, or provider implementation changed");
    }
    let Some(prior_inventory) = prior_inventory else {
        refuse!("validated prior project inventory is unavailable");
    };
    let Some(measured_prior_inventory) =
        semantic_provider_inventory_fingerprint(prior_inventory, "go", "go").ok()
    else {
        refuse!("validated prior Go inventory cannot be fingerprinted");
    };
    let Some(measured_current_inventory) =
        semantic_provider_inventory_fingerprint(inventory, "go", "go").ok()
    else {
        refuse!("current Go inventory cannot be fingerprinted");
    };
    if &measured_prior_inventory != prior_inventory_sha256
        || &measured_current_inventory != current_inventory_sha256
    {
        refuse!("persisted or current whole-Go inventory identity is inconsistent");
    }
    let prior_roots = prior_roots
        .iter()
        .map(|root| (root.execution_root.clone(), root))
        .collect::<BTreeMap<_, _>>();
    let current_roots = current_roots
        .iter()
        .map(|root| (root.execution_root.clone(), root))
        .collect::<BTreeMap<_, _>>();
    if prior_roots.keys().collect::<Vec<_>>() != current_roots.keys().collect::<Vec<_>>()
        || current_roots.len() != toolchains.len()
    {
        refuse!("Go execution-root population changed or is incomplete");
    }
    let expected_root_labels = current_roots.keys().cloned().collect::<BTreeSet<_>>();
    let Some(prior_inventory_by_root) =
        go_execution_root_inventory_fingerprints(prior_inventory, &expected_root_labels)
    else {
        refuse!("prior Go inventory cannot be partitioned by execution root");
    };
    let Some(current_inventory_by_root) =
        go_execution_root_inventory_fingerprints(inventory, &expected_root_labels)
    else {
        refuse!("current Go inventory cannot be partitioned by execution root");
    };

    let current_document_roots = semantic_provider_document_execution_roots(inventory, "go", "go");
    let execution_root_for_prior_document = |document_path: &str| {
        prior_roots
            .values()
            .filter(|root| {
                root.execution_root.is_empty()
                    || PathBuf::from(document_path).starts_with(&root.execution_root)
            })
            .max_by(|left, right| {
                PathBuf::from(&left.execution_root)
                    .components()
                    .count()
                    .cmp(&PathBuf::from(&right.execution_root).components().count())
                    .then_with(|| left.execution_root.cmp(&right.execution_root))
            })
            .map(|root| root.execution_root.as_str())
    };
    let canonical_execution_root = |relative_root: &std::path::Path| {
        std::fs::canonicalize(repository_root.join(relative_root))
            .ok()
            .filter(|root| toolchains.contains_key(root))
    };
    let mut affected_roots = BTreeSet::new();
    for (relative_root, current_root) in &current_roots {
        let canonical_root = canonical_execution_root(std::path::Path::new(relative_root))?;
        let toolchain = toolchains.get(&canonical_root)?;
        let expected_configuration = toolchain_provider_configuration_sha256(
            SCIP_GO_REUSE_CONTRACT_ID,
            toolchain.fingerprint_sha256(),
        );
        let snapshot_configuration = candidate
            .snapshot
            .provider_configuration_sha256_for_execution_root(&canonical_root)
            .ok()
            .flatten();
        if prior_roots.get(relative_root) != Some(current_root)
            || prior_inventory_by_root.get(relative_root)
                != current_inventory_by_root.get(relative_root)
            || snapshot_configuration != Some(expected_configuration.as_str())
        {
            affected_roots.insert(canonical_root);
        }
    }
    for path in changed_paths.iter().filter(|path| {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(extension_to_language)
            == Some("go")
    }) {
        let relative = path
            .strip_prefix(repository_root)
            .ok()?
            .to_string_lossy()
            .replace('\\', "/");
        let root = current_document_roots.get(&relative)?;
        affected_roots.insert(canonical_execution_root(root)?);
    }
    for path in deleted_paths.iter().filter(|path| {
        existing_files
            .get(path.as_str())
            .is_some_and(|record| record.language == "go")
    }) {
        let prior_root = execution_root_for_prior_document(path)?;
        affected_roots.insert(canonical_execution_root(std::path::Path::new(prior_root))?);
    }

    let retained_root_labels = current_roots
        .keys()
        .filter(|root| {
            canonical_execution_root(std::path::Path::new(root))
                .is_some_and(|root| !affected_roots.contains(&root))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if !go_retained_semantic_inputs_are_current(
        repository_root,
        &payload.semantic_inputs,
        prior_inventory,
        inventory,
        &expected_root_labels,
        &retained_root_labels,
    ) {
        refuse!("a semantic path input for a retained Go root is stale or inconsistent");
    }

    if affected_roots.is_empty() {
        if &payload.execution_authority != authority {
            refuse!("whole-Go authority changed without a localized root difference");
        }
        tracing::debug!("admitted exact retained Go semantic basis");
        return Some(GoSemanticReusePlan::Exact(candidate.clone()));
    }
    tracing::debug!(
        affected_root_count = affected_roots.len(),
        total_root_count = toolchains.len(),
        "localized retained Go semantic basis"
    );
    (affected_roots.len() < toolchains.len()).then(|| GoSemanticReusePlan::AffectedRoots {
        basis: candidate.clone(),
        roots: affected_roots,
    })
}

impl IndexPipeline {
    /// Run the full indexing pipeline.
    ///
    /// - `state`: the index state database for hash tracking.
    /// - `graph_store`: optional graph persistence.
    /// - `config`: pipeline configuration.
    #[tracing::instrument(skip_all, fields(root = %config.root.display()))]
    #[cfg(test)]
    pub(crate) async fn run(
        state: &IndexState,
        graph_store: Option<&GraphStore>,
        config: &IndexConfig,
        enrichment_store: Option<&Arc<crate::enrichment::EnrichmentStore>>,
    ) -> Result<IndexRunOutcome, IndexPipelineError> {
        let mut semantic_providers = SemanticProviderRegistry::default();
        Self::run_with_incremental_basis(
            state,
            graph_store,
            config,
            enrichment_store,
            IndexPipelineRuntime {
                incremental_basis: None,
                semantic_providers: &mut semantic_providers,
            },
        )
        .await
        .map(|prepared| prepared.outcome)
    }

    /// Run against an already validated reusable source-fact basis without
    /// first persisting that basis into the private candidate database.
    ///
    /// Immutable publication is the sole production caller. The candidate
    /// persists the complete resulting source state once, during finalization.
    #[tracing::instrument(skip_all, fields(root = %config.root.display()))]
    pub(crate) async fn run_with_incremental_basis(
        state: &IndexState,
        graph_store: Option<&GraphStore>,
        config: &IndexConfig,
        enrichment_store: Option<&Arc<crate::enrichment::EnrichmentStore>>,
        runtime: IndexPipelineRuntime<'_>,
    ) -> Result<PreparedIndexRun, IndexPipelineError> {
        let IndexPipelineRuntime {
            incremental_basis,
            semantic_providers,
        } = runtime;
        // Freeze product configuration before any provider lifecycle begins.
        // Rust and Go have native one-shot lanes in the pipeline; other
        // languages exist only when the assembled product registered a
        // persistent provider. Final receipts must never infer execution from
        // the language policy table alone.
        let mut configured_calls_languages = semantic_providers
            .languages()
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        configured_calls_languages.insert("rust".into());
        configured_calls_languages.insert("go".into());
        ensure_index_active(&config.cancellation)?;
        let start = Instant::now();
        let mut report = IndexReport::default();
        let mut profiler = ProfileCollector::new(config.profile);
        let structural_start = Instant::now();
        emit_progress(
            &config.progress,
            IndexProgressPhase::Structural,
            IndexProgressState::Started,
            "structural scan",
            "discovering, hashing, extracting, and building the structural graph",
            None,
        );

        // ---------------------------------------------------------------
        // PHASES 1-4: DISCOVER → DIFF → EXTRACT → GRAPH (blocking)
        // ---------------------------------------------------------------
        // Production immutable publication carries its validated reusable
        // source basis directly from the current generation. Lower-level
        // callers may still use the state database as their incremental basis.
        let external_basis_supplied = incremental_basis.is_some();
        let (
            existing_file_records,
            existing_fact_sets,
            structural_graph_basis,
            prior_semantic_bases,
            prior_project_inventory,
        ) = match incremental_basis {
            Some(basis) => (
                basis.source.files,
                basis.source.document_facts,
                basis.graph,
                basis.semantic_bases,
                Some(basis.project_inventory),
            ),
            None => (
                state.all_files()?,
                state.all_document_facts()?,
                None,
                Vec::new(),
                None,
            ),
        };
        let existing_files: std::collections::HashMap<String, FileRecord> =
            existing_file_records.into_iter().collect();
        let existing_document_facts: std::collections::HashMap<String, ExtractorOutput> =
            existing_fact_sets
                .into_iter()
                .map(|facts| (facts.file_path.clone(), facts))
                .collect();

        // Choose the structural materialization basis. Immutable publication
        // may supply an exact, generation-bound process-local graph only after
        // normal writer admission has validated that same published head.
        // Lower-level callers may instead load a persisted snapshot. A full run
        // invalidates every source and therefore rebuilds from current facts
        // even if such a lower-level snapshot exists.
        //
        // WU-0003 / CL-REACH clear-on-schema-bump: if the persisted code-intel
        // graph was written under an older schema, `load_snapshot_or_clear`
        // wipes the stale graph tables and reports `cleared = true`. A
        // cleared graph is EMPTY, so we MUST force a FULL re-extract — otherwise
        // the incremental diff would see unchanged file hashes (the file-state
        // tables survive the graph clear), extract nothing, and leave the graph
        // permanently empty (the migration hole). The rebuild signal overrides the
        // incremental path below.
        let (existing_graph, graph_requires_full_reextract) = if let Some(graph) =
            structural_graph_basis
        {
            (graph, false)
        } else if let Some(gs) = graph_store {
            // ADR-0033 ROOT-8: pass the workspace root so a foreign-origin store
            // is ADOPTED (cleared + rebuilt + re-stamped at the save below),
            // never merged. `cleared` forces the full re-extract either way.
            //
            // WU-D: the adopt is now GATED. With `adopt_foreign_origin = false`
            // (the default) PRESENT foreign-origin graph data makes this `?`
            // propagate `OriginAdoptRequired` — a fatal, non-zero-exit refusal —
            // rather than silently clearing another workspace's graph. Schema
            // and decode clears are unaffected; an empty store still adopts.
            let (graph, cleared) = gs
                .load_snapshot_or_clear(&config.root, config.adopt_foreign_origin)
                .await?;
            let graph_basis_missing =
                graph.is_none() && !existing_files.is_empty() && !external_basis_supplied;
            if graph_basis_missing && !cleared {
                tracing::warn!(
                    indexed_files = existing_files.len(),
                    "file-hash state exists without a usable graph snapshot; forcing full source re-extraction"
                );
            }
            (
                graph.unwrap_or_else(KnowledgeGraph::new),
                cleared || graph_basis_missing,
            )
        } else {
            (KnowledgeGraph::new(), false)
        };
        ensure_index_active(&config.cancellation)?;

        let mut cfg = config.clone();
        if graph_requires_full_reextract {
            // A cleared graph and a missing graph with surviving file-hash
            // state are both unusable incremental bases. Re-extract every
            // discovered source before issuing structural evidence.
            cfg.full = true;
        }
        let mut blocking_result = match Self::blocking_phase(
            &cfg,
            &existing_files,
            &existing_document_facts,
            existing_graph,
        ) {
            Ok(result) => result,
            Err(error) => {
                emit_progress(
                    &config.progress,
                    IndexProgressPhase::Structural,
                    IndexProgressState::Failed,
                    "structural scan",
                    error.to_string(),
                    Some(structural_start.elapsed()),
                );
                return Err(error);
            }
        };
        ensure_index_active(&config.cancellation)?;
        let structural_duration = structural_start.elapsed();
        report.phase_timings.push(IndexPhaseTiming {
            phase: IndexProgressPhase::Structural,
            label: "structural scan".into(),
            duration: structural_duration,
            aggregation: IndexTimingAggregation::Exclusive,
        });
        emit_progress(
            &config.progress,
            IndexProgressPhase::Structural,
            IndexProgressState::Completed,
            "structural scan",
            format!(
                "{} files discovered; {} changed; {} deleted; build work: {} nodes, {} edges; candidate total: {} nodes, {} edges",
                blocking_result.discovered_paths.len(),
                blocking_result.changed_paths.len(),
                blocking_result.deleted_paths.len(),
                blocking_result.build_stats.nodes_added,
                blocking_result.build_stats.edges_added,
                blocking_result.graph.node_count(),
                blocking_result.graph.edge_count(),
            ),
            Some(structural_duration),
        );

        // Transfer profiling data from blocking phase.
        if let Some(dur) = blocking_result.profile_discovery_dur {
            profiler.record_phase(
                "discovery",
                1,
                dur,
                format!("{} files", blocking_result.discovered_paths.len()),
            );
        }
        if let Some(dur) = blocking_result.profile_diff_dur {
            profiler.record_phase(
                "change detect",
                2,
                dur,
                format!(
                    "{} checked, {} changed",
                    blocking_result.discovered_paths.len(),
                    blocking_result.changed_paths.len(),
                ),
            );
        }

        report.files_discovered = blocking_result.discovered_paths.len();
        report.files_changed = blocking_result.changed_paths.len();
        report.files_unchanged = blocking_result.unchanged_count;
        report.files_deleted = blocking_result.deleted_paths.len();

        if config.debug && !blocking_result.extraction_errors.is_empty() {
            for (path, err) in &blocking_result.extraction_errors {
                tracing::warn!(path = %path.display(), error = %err, "extraction failed");
            }
        }

        if config.dry_run {
            report.duration = start.elapsed();
            profiler.finish();
            return Ok(PreparedIndexRun {
                outcome: IndexRunOutcome::DryRun { telemetry: report },
                structural_basis: None,
            });
        }

        report.symbols_extracted = blocking_result
            .outputs
            .iter()
            .map(|o| o.symbols.len())
            .sum();
        report.nodes_added = blocking_result.build_stats.nodes_added;
        report.edges_added = blocking_result.build_stats.edges_added;
        report.edges_skipped_external_relation =
            blocking_result.build_stats.edges_skipped_external_relation;
        report.edges_skipped_other = blocking_result.build_stats.edges_skipped_other;
        report.external_traits_synthesized =
            blocking_result.build_stats.external_traits_synthesized;

        if let Some(dur) = blocking_result.profile_extract_dur {
            profiler.record_phase(
                "extraction",
                3,
                dur,
                format!(
                    "{} symbols from {} files",
                    report.symbols_extracted,
                    blocking_result.changed_paths.len(),
                ),
            );
        }
        if let Some(dur) = blocking_result.profile_graph_dur {
            profiler.record_phase(
                "graph build",
                4,
                dur,
                format!(
                    "{} nodes, {} edges, {} skipped (external relation: {}), {} ext-traits synth",
                    blocking_result.build_stats.nodes_added,
                    blocking_result.build_stats.edges_added,
                    blocking_result.build_stats.total_skipped(),
                    blocking_result.build_stats.edges_skipped_external_relation,
                    blocking_result.build_stats.external_traits_synthesized,
                ),
            );
        }
        profiler.merge_graph_build_steps(std::mem::take(
            &mut blocking_result.build_stats.profile_timings,
        ));
        profiler.merge_extraction_files(std::mem::take(&mut blocking_result.profile_file_timings));

        // Embedding and memory-store publication belonged to h00's memory
        // substrate, not to h00ligan's code-intelligence product. The
        // standalone pipeline proceeds directly from structural facts to
        // semantic-provider normalization and immutable publication.

        // Structural relationship resolution already consumed this exact
        // inventory. Move the same authority value into semantic normalization
        // and final publication; never rediscover or clone it between phases.
        ensure_index_active(&config.cancellation)?;
        let project_inventory = blocking_result.project_inventory.take().ok_or_else(|| {
            IndexPipelineError::Other(
                "blocking structural phase omitted its project inventory".into(),
            )
        })?;
        if let Some(duration) = blocking_result.profile_inventory_dur {
            profiler.record_phase(
                "project inventory",
                7,
                duration,
                format!(
                    "{} sources, {} units, {} inputs",
                    blocking_result.source_inputs.len(),
                    project_inventory.project_topology.units.len(),
                    project_inventory.inputs.len(),
                ),
            );
        }
        let semantic_surfaces = blocking_result
            .document_facts
            .iter()
            .map(|facts| {
                (
                    facts.file_path.as_str(),
                    facts.cross_document_surface_sha256.as_str(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let indexed_source_evidence = blocking_result
            .source_inputs
            .iter()
            .map(|input| IndexedSourceEvidence {
                relative_path: input.relative_path.clone(),
                language: input.language.clone(),
                blake3_hash: input.content_hash.clone(),
                cross_document_surface_sha256: semantic_surfaces
                    .get(input.relative_path.as_str())
                    .map(|surface| (*surface).to_owned()),
            })
            .collect::<Vec<_>>();

        // ---------------------------------------------------------------
        // PHASE 7: SCIP (auto-detection)
        // ---------------------------------------------------------------
        // SCIP providers write artifacts only to a disposable workspace under
        // the selected data directory. Their normalized evidence and graph
        // edges persist in the immutable generation. Non-authoritative build
        // and download caches survive under `provider-cache-v1`; neither class
        // decorates the indexed project or uses global tool caches.

        let semantic_phase_started = Instant::now();
        let mut scip_evidence = Vec::new();
        let mut canonical_scip_snapshots = Vec::new();
        let mut provider_payload_canonicalization =
            ProviderPayloadCanonicalizationTimings::default();

        let needs_scip_generation = config.scip.generates_artifacts();
        let provider_workspace = if needs_scip_generation {
            let mut builder = tempfile::Builder::new();
            builder.prefix(".h00-provider-");
            Some(match &config.provider_data_root {
                Some(parent) => builder.tempdir_in(parent)?,
                None => builder.tempdir()?,
            })
        } else {
            None
        };
        let provider_artifact_root = provider_workspace
            .as_ref()
            .map(|workspace| workspace.path().join("artifacts"));
        let provider_cache_preparation_start = needs_scip_generation.then(Instant::now);
        let provider_cache_root = if needs_scip_generation {
            config.provider_data_root.as_ref().map(|data_root| {
                let cache_root = data_root.join(PROVIDER_CACHE_DIRECTORY);
                inspect_generated_directory(&cache_root)?;
                std::fs::create_dir_all(&cache_root)?;
                inspect_generated_directory(&cache_root)?;
                Ok::<_, IndexPipelineError>(cache_root)
            })
        } else {
            None
        }
        .transpose()?;
        let provider_cache_preparation_duration = provider_cache_root
            .as_ref()
            .and_then(|_| provider_cache_preparation_start.map(|started| started.elapsed()));
        match config.scip {
            ScipMode::Disabled => {
                tracing::info!("SCIP analysis disabled");
            }
            ScipMode::Refresh => {
                tracing::info!("Refreshing SCIP artifacts");
            }
        }

        let rust_execution_roots =
            semantic_provider_execution_roots(&project_inventory, "rust", "cargo")
                .into_iter()
                .map(|relative| config.root.join(relative))
                .collect::<Vec<_>>();
        let go_execution_roots = semantic_provider_execution_roots(&project_inventory, "go", "go")
            .into_iter()
            .map(|relative| config.root.join(relative))
            .collect::<Vec<_>>();

        let rust_source_count = project_inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| {
                membership.language_id.0 == "rust"
                    && project_inventory.is_semantic_source_owner(membership)
            })
            .count();
        let go_source_count = project_inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| {
                membership.language_id.0 == "go"
                    && project_inventory.is_semantic_source_owner(membership)
            })
            .count();

        // One-shot providers receive an exact product-resolved toolchain for
        // every execution root. Resolve the complete Go population before
        // starting any provider so a missing or ambiguous root cannot yield a
        // partially authoritative language generation.
        let persistent_go_authority = semantic_providers.contains("go");
        let go_toolchain_resolution_started =
            (needs_scip_generation && !go_execution_roots.is_empty() && !persistent_go_authority)
                .then(Instant::now);
        let (resolved_go_toolchains, go_resolution_warning) = if needs_scip_generation
            && !go_execution_roots.is_empty()
            && !persistent_go_authority
        {
            match resolve_toolchain_population(
                config.toolchain_resolver.as_ref(),
                "go",
                &go_execution_roots,
                &config.cancellation,
            )
            .await
            {
                Ok(toolchains) => (toolchains, None),
                Err(crate::code_intel_toolchain::ToolchainResolutionError::Cancelled) => {
                    return Err(IndexPipelineError::Cancelled);
                }
                Err(error) => (
                    BTreeMap::new(),
                    Some(format!(
                        "Go semantic toolchain resolution failed; scip-go was not executed: {error}"
                    )),
                ),
            }
        } else {
            (BTreeMap::new(), None)
        };
        if let Some(started) = go_toolchain_resolution_started {
            report.phase_timings.push(IndexPhaseTiming {
                phase: IndexProgressPhase::SemanticProvider,
                label: "go toolchain authority resolution".into(),
                duration: started.elapsed(),
                aggregation: IndexTimingAggregation::Exclusive,
            });
        }
        let go_resolver_policy_id = config
            .toolchain_resolver
            .as_ref()
            .and_then(|resolver| resolver.policy_id("go").ok())
            .map(str::to_owned);
        let initial_go_execution_authority = go_toolchain_bound_authority(
            &config.root,
            &project_inventory,
            &resolved_go_toolchains,
            go_resolver_policy_id.as_deref(),
        );
        let go_reuse_plan_started = Instant::now();
        let go_reuse_plan = (needs_scip_generation && !persistent_go_authority).then(|| {
            go_semantic_reuse_plan(
                &config.root,
                &prior_semantic_bases,
                initial_go_execution_authority.as_ref(),
                &resolved_go_toolchains,
                config.debug,
                prior_project_inventory.as_deref(),
                &project_inventory,
                &blocking_result.changed_paths,
                &blocking_result.deleted_paths,
                &existing_files,
            )
        });
        let mut go_reuse_plan = go_reuse_plan.flatten();
        let go_reuse_plan_validation_duration = go_reuse_plan
            .as_ref()
            .map(|_| go_reuse_plan_started.elapsed());

        let mut admitted_persistent_normalizations = Vec::new();
        let mut admitted_reused_normalizations = Vec::new();
        let mut persistent_failures = Vec::new();
        // A configured persistent provider is the sole semantic authority for
        // its language. Independent language coordinators may execute
        // concurrently, but each remains the only mutable owner of its own
        // process/session lifecycle. Results are merged afterward in the
        // registry's stable language-key order.
        let persistent_rust_authority = semantic_providers.contains("rust");
        let rust_roots_for_one_shot = if persistent_rust_authority {
            Vec::new()
        } else {
            rust_execution_roots.clone()
        };
        let persistent_outcomes = if needs_scip_generation {
            semantic_providers
                .map_providers(|provider| {
                    Box::pin(run_persistent_semantic_provider_lane(
                        provider,
                        &config.root,
                        &project_inventory,
                        &indexed_source_evidence,
                        &prior_semantic_bases,
                        &config.cancellation,
                        &config.progress,
                    ))
                })
                .await
        } else {
            Vec::new()
        };
        for persistent_outcome in persistent_outcomes {
            let persistent_outcome = persistent_outcome?;
            report
                .semantic_provider_refreshes
                .extend(persistent_outcome.refreshes);
            report
                .phase_timings
                .extend(persistent_outcome.phase_timings);
            if let Some(normalization) = persistent_outcome.normalization {
                if persistent_outcome.reused {
                    admitted_reused_normalizations.push(normalization);
                } else {
                    admitted_persistent_normalizations.push(normalization);
                }
            }
            if let Some(failure) = persistent_outcome.failure {
                persistent_failures.push(failure);
            }
        }

        let (mut generated_scip_artifacts, mut provider_timings) = if needs_scip_generation {
            let artifact_root = provider_artifact_root
                .clone()
                .expect("provider workspace exists in Refresh mode");
            let rust_roots = rust_roots_for_one_shot;
            let rust_has_execution_roots = !rust_execution_roots.is_empty();
            let go_has_execution_roots = !go_execution_roots.is_empty();
            let go_roots = go_reuse_plan.as_ref().map_or_else(
                || {
                    resolved_go_toolchains
                        .values()
                        .cloned()
                        .map(|toolchain| (toolchain.execution_root.clone(), toolchain))
                        .collect::<Vec<_>>()
                },
                |plan| plan.roots_to_execute(&resolved_go_toolchains),
            );
            let go_resolution_warning_for_task = go_resolution_warning.clone();
            let project_root = config.root.clone();
            let provider_jobs = config.jobs;
            let provider_cache_for_task = provider_cache_root.clone();
            let provider_progress = config.progress.clone();
            let provider_cancellation = config.cancellation.clone();
            let provider_result = tokio::task::spawn_blocking(move || {
                let mut generated = Vec::new();
                let mut warns: Vec<String> = Vec::new();
                let mut timings = Vec::new();
                if let Some(warning) = go_resolution_warning_for_task {
                    warns.push(warning);
                }
                if !rust_has_execution_roots && rust_source_count > 0 {
                    let detail = format!(
                        "{rust_source_count} Rust source file(s) are loose sources; no Cargo.toml owner or workspace"
                    );
                    emit_progress(
                        &provider_progress,
                        IndexProgressPhase::SemanticProvider,
                        IndexProgressState::Skipped,
                        "rust-analyzer SCIP",
                        &detail,
                        Some(Duration::ZERO),
                    );
                    timings.push(IndexPhaseTiming {
                        phase: IndexProgressPhase::SemanticProvider,
                        label: "rust-analyzer SCIP (skipped)".into(),
                        duration: Duration::ZERO,
                        aggregation: IndexTimingAggregation::Exclusive,
                    });
                }
                for (index, execution_root) in rust_roots.into_iter().enumerate() {
                    if provider_cancellation.is_cancelled() {
                        return Err(crate::scip_loader::ScipLoaderError::Cancelled {
                            what: "semantic provider refresh",
                        });
                    }
                    let root_label = execution_root
                        .strip_prefix(&project_root)
                        .ok()
                        .filter(|relative| !relative.as_os_str().is_empty())
                        .map_or_else(|| ".".into(), |relative| relative.display().to_string());
                    let label = format!("rust-analyzer SCIP ({root_label})");
                    let provider_start = Instant::now();
                    emit_progress(
                        &provider_progress,
                        IndexProgressPhase::SemanticProvider,
                        IndexProgressState::Started,
                        "rust-analyzer SCIP",
                        format!("project unit {root_label}"),
                        None,
                    );
                    // SHIP-FLOOR default (ADR-0030): index against ALL features
                    // so feature-gated symbols are not false-DEAD for lack of a
                    // SCIP edge.
                    let result = crate::scip_loader::generate_scip_index(
                        &execution_root,
                        &artifact_root.join(format!("rust-{index}.scip")),
                        &provider_cache_for_task.as_ref().map_or_else(
                            || artifact_root.join("rust-cache"),
                            |root| root.join("rust"),
                        ),
                        &crate::scip_loader::SHIP_FLOOR_RUST_FEATURES,
                        &provider_cancellation,
                    );
                    let provider_duration = provider_start.elapsed();
                    timings.push(IndexPhaseTiming {
                        phase: IndexProgressPhase::SemanticProvider,
                        label,
                        duration: provider_duration,
                        aggregation: IndexTimingAggregation::Exclusive,
                    });
                    match result {
                        Ok(artifact) => {
                            emit_progress(
                                &provider_progress,
                                IndexProgressPhase::SemanticProvider,
                                IndexProgressState::Completed,
                                "rust-analyzer SCIP",
                                format!("project unit {root_label}"),
                                Some(provider_duration),
                            );
                            generated.push(GeneratedProviderArtifact {
                                provider_configuration_sha256:
                                    invocation_provider_configuration_sha256(
                                        ScipProviderSpec::rust_analyzer(),
                                        &artifact,
                                    ),
                                artifact,
                                spec: ScipProviderSpec::rust_analyzer(),
                                execution_root,
                            });
                        }
                        Err(e @ crate::scip_loader::ScipLoaderError::GeneratedArtifact(_)) => {
                            emit_progress(
                                &provider_progress,
                                IndexProgressPhase::SemanticProvider,
                                IndexProgressState::Failed,
                                "rust-analyzer SCIP",
                                e.to_string(),
                                Some(provider_duration),
                            );
                            return Err(e);
                        }
                        Err(e @ crate::scip_loader::ScipLoaderError::Cancelled { .. }) => {
                            return Err(e);
                        }
                        Err(e) => {
                            emit_progress(
                                &provider_progress,
                                IndexProgressPhase::SemanticProvider,
                                IndexProgressState::Failed,
                                "rust-analyzer SCIP",
                                e.to_string(),
                                Some(provider_duration),
                            );
                            warns.push(format!(
                                "rust-analyzer SCIP generation failed for {}: {e}",
                                execution_root.display()
                            ));
                        }
                    }
                }

                if !go_has_execution_roots && go_source_count > 0 {
                    let detail = format!(
                        "{go_source_count} Go source file(s) are loose sources; no go.mod module or go.work workspace"
                    );
                    emit_progress(
                        &provider_progress,
                        IndexProgressPhase::SemanticProvider,
                        IndexProgressState::Skipped,
                        "scip-go",
                        &detail,
                        Some(Duration::ZERO),
                    );
                    timings.push(IndexPhaseTiming {
                        phase: IndexProgressPhase::SemanticProvider,
                        label: "scip-go (skipped)".into(),
                        duration: Duration::ZERO,
                        aggregation: IndexTimingAggregation::Exclusive,
                    });
                }
                let go_parallelism = provider_root_parallelism(go_roots.len(), provider_jobs);
                let go_tasks = go_roots
                    .into_iter()
                    .enumerate()
                    .map(|(index, (execution_root, toolchain))| {
                        let root_label = execution_root
                            .strip_prefix(&project_root)
                            .ok()
                            .filter(|relative| !relative.as_os_str().is_empty())
                            .map_or_else(
                                || ".".into(),
                                |relative| relative.display().to_string(),
                            );
                        (index, execution_root, root_label, toolchain)
                    })
                    .collect::<Vec<_>>();
                for (_, _, root_label, _) in &go_tasks {
                    emit_progress(
                        &provider_progress,
                        IndexProgressPhase::SemanticProvider,
                        IndexProgressState::Started,
                        "scip-go",
                        format!("project unit {root_label}"),
                        None,
                    );
                }
                let run_go_root = |(index, execution_root, root_label, toolchain): (
                    usize,
                    PathBuf,
                    String,
                    ResolvedToolchain,
                )| {
                    if provider_cancellation.is_cancelled() {
                        return GoProviderExecution {
                            execution_root,
                            timing_label: format!("scip-go ({root_label})"),
                            provider_configuration_sha256:
                                toolchain_provider_configuration_sha256(
                                    SCIP_GO_REUSE_CONTRACT_ID,
                                    toolchain.fingerprint_sha256(),
                                ),
                            duration: Duration::ZERO,
                            result: Err(crate::scip_loader::ScipLoaderError::Cancelled {
                                what: "semantic provider refresh",
                            }),
                        };
                    }
                    let provider_configuration_sha256 =
                        toolchain_provider_configuration_sha256(
                            SCIP_GO_REUSE_CONTRACT_ID,
                            toolchain.fingerprint_sha256(),
                        );
                    let timing_label = format!("scip-go ({root_label})");
                    let provider_start = Instant::now();
                    let result = crate::scip_loader::generate_scip_go_index(
                        &execution_root,
                        &artifact_root.join(format!("go-{index}.scip")),
                        &provider_cache_for_task.as_ref().map_or_else(
                            || artifact_root.join("go-cache"),
                            |root| root.join("go"),
                        ),
                        &toolchain,
                        &provider_cancellation,
                    );
                    let provider_duration = provider_start.elapsed();
                    match &result {
                        Ok(_) => {
                            emit_progress(
                                &provider_progress,
                                IndexProgressPhase::SemanticProvider,
                                IndexProgressState::Completed,
                                "scip-go",
                                format!("project unit {root_label}"),
                                Some(provider_duration),
                            );
                        }
                        Err(crate::scip_loader::ScipLoaderError::Cancelled { .. }) => {}
                        Err(error) => {
                            emit_progress(
                                &provider_progress,
                                IndexProgressPhase::SemanticProvider,
                                IndexProgressState::Failed,
                                "scip-go",
                                error.to_string(),
                                Some(provider_duration),
                            );
                        }
                    }
                    GoProviderExecution {
                        execution_root,
                        timing_label,
                        provider_configuration_sha256,
                        duration: provider_duration,
                        result,
                    }
                };
                let go_provider_pool_started =
                    (go_parallelism > 1).then(std::time::Instant::now);
                let go_executions = if go_parallelism <= 1 {
                    go_tasks.into_iter().map(&run_go_root).collect::<Vec<_>>()
                } else {
                    use rayon::prelude::*;
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(go_parallelism)
                        .thread_name(|index| format!("h00-go-provider-{index}"))
                        .build()
                        .map_err(|error| {
                            crate::scip_loader::ScipLoaderError::Io(std::io::Error::other(
                                format!("cannot create semantic provider worker pool: {error}"),
                            ))
                        })?;
                    pool.install(|| {
                        go_tasks
                            .into_par_iter()
                            .map(&run_go_root)
                            .collect::<Vec<_>>()
                        })
                };
                if let Some(started) = go_provider_pool_started {
                    timings.push(IndexPhaseTiming {
                        phase: IndexProgressPhase::SemanticProvider,
                        label: format!("scip-go provider pool ({go_parallelism} workers)"),
                        duration: started.elapsed(),
                        aggregation: IndexTimingAggregation::Exclusive,
                    });
                }
                for execution in go_executions {
                    timings.push(IndexPhaseTiming {
                        phase: IndexProgressPhase::SemanticProvider,
                        label: execution.timing_label,
                        duration: execution.duration,
                        aggregation: if go_parallelism > 1 {
                            IndexTimingAggregation::ConcurrentSpan
                        } else {
                            IndexTimingAggregation::Exclusive
                        },
                    });
                    match execution.result {
                        Ok(artifact) => generated.push(GeneratedProviderArtifact {
                            provider_configuration_sha256: execution
                                .provider_configuration_sha256,
                            artifact,
                            spec: ScipProviderSpec::scip_go(),
                            execution_root: execution.execution_root,
                        }),
                        Err(error @ crate::scip_loader::ScipLoaderError::GeneratedArtifact(_)) => {
                            return Err(error);
                        }
                        Err(error @ crate::scip_loader::ScipLoaderError::Cancelled { .. }) => {
                            return Err(error);
                        }
                        Err(error) => warns.push(format!(
                            "scip-go generation failed for {}: {error}",
                            execution.execution_root.display()
                        )),
                    }
                }

                Ok((generated, warns, timings))
            })
            .await;
            let provider_cache_maintenance_duration = if let Some(cache_root) = &provider_cache_root
            {
                let started = Instant::now();
                let mut protected = semantic_providers.active_cache_directories();
                if !resolved_go_toolchains.is_empty() {
                    protected.insert(cache_root.join("go"));
                }
                trim_provider_cache_to_budget(cache_root, PROVIDER_CACHE_MAX_BYTES, &protected)?;
                Some(started.elapsed())
            } else {
                None
            };
            let (generated, mut timings) = match provider_result {
                Ok(Ok((generated, warns, timings))) => {
                    if !generated.is_empty() {
                        tracing::info!("SCIP index generated successfully");
                    }
                    for w in warns {
                        tracing::warn!(warning = %w, "SCIP generation (non-fatal, continuing)");
                        eprintln!("Warning: {w}");
                    }
                    if generated.is_empty()
                        && admitted_persistent_normalizations.is_empty()
                        && go_reuse_plan.is_none()
                    {
                        eprintln!(
                            "Note: no precise SCIP index generated — graph will not include Calls edges."
                        );
                    }
                    (generated, timings)
                }
                Ok(Err(crate::scip_loader::ScipLoaderError::Cancelled { .. })) => {
                    return Err(IndexPipelineError::Cancelled);
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(e) => {
                    tracing::warn!(error = %e, "SCIP generation task panicked (non-fatal)");
                    (Vec::new(), Vec::new())
                }
            };
            if let Some(duration) = provider_cache_maintenance_duration {
                timings.push(IndexPhaseTiming {
                    phase: IndexProgressPhase::SemanticProvider,
                    label: "semantic provider cache maintenance".into(),
                    duration,
                    aggregation: IndexTimingAggregation::Exclusive,
                });
            }
            (generated, timings)
        } else {
            (Vec::new(), Vec::new())
        };

        // A composed Go population is atomic across execution roots. Recheck
        // every toolchain after provider completion; a changed executable,
        // environment, version, sysroot, or root discards all Go artifacts
        // from this candidate rather than publishing mixed-epoch evidence.
        let generated_go_count = generated_scip_artifacts
            .iter()
            .filter(|generated| generated.spec.language == "go")
            .count();
        let mut go_execution_authority = None;
        let mut partial_go_basis = None;
        if generated_go_count > 0 || go_reuse_plan.is_some() {
            let go_toolchain_revalidation_started = Instant::now();
            let post_execution_toolchains = resolve_toolchain_population(
                config.toolchain_resolver.as_ref(),
                "go",
                &go_execution_roots,
                &config.cancellation,
            )
            .await;
            provider_timings.push(IndexPhaseTiming {
                phase: IndexProgressPhase::SemanticProvider,
                label: "go toolchain authority revalidation".into(),
                duration: go_toolchain_revalidation_started.elapsed(),
                aggregation: IndexTimingAggregation::Exclusive,
            });
            let exact_toolchains = post_execution_toolchains
                .as_ref()
                .is_ok_and(|current| current == &resolved_go_toolchains);
            let expected_provider_executions = go_reuse_plan.as_ref().map_or(
                resolved_go_toolchains.len(),
                GoSemanticReusePlan::expected_provider_executions,
            );
            let exact_population = generated_go_count == expected_provider_executions;
            if !exact_population || !exact_toolchains {
                generated_scip_artifacts.retain(|generated| generated.spec.language != "go");
                let detail = if !exact_population {
                    "not every Go execution root produced an artifact"
                } else {
                    "the resolved Go toolchain changed during provider execution"
                };
                tracing::warn!(detail, "discarding composed Go semantic evidence");
                eprintln!("Warning: discarding Go semantic evidence because {detail}.");
            } else {
                match go_reuse_plan.take() {
                    Some(GoSemanticReusePlan::Exact(basis)) => {
                        admitted_reused_normalizations.push(ScipArtifactSetNormalization {
                            evidence: basis.evidence,
                            supplemental_evidence: basis.supplemental_evidence,
                            canonical_snapshot: Some(basis.snapshot),
                            source_syntax_cache: basis.source_syntax_cache,
                            timings: Default::default(),
                        });
                        if let Some(duration) = go_reuse_plan_validation_duration {
                            provider_timings.push(IndexPhaseTiming {
                                phase: IndexProgressPhase::SemanticProvider,
                                label: "go exact semantic basis reuse".into(),
                                duration,
                                aggregation: IndexTimingAggregation::Exclusive,
                            });
                        }
                    }
                    Some(GoSemanticReusePlan::AffectedRoots { basis, .. }) => {
                        partial_go_basis = Some(basis);
                        go_execution_authority = initial_go_execution_authority.clone();
                        if let Some(duration) = go_reuse_plan_validation_duration {
                            provider_timings.push(IndexPhaseTiming {
                                phase: IndexProgressPhase::SemanticProvider,
                                label: "go affected-root basis validation".into(),
                                duration,
                                aggregation: IndexTimingAggregation::Exclusive,
                            });
                        }
                    }
                    None => {
                        go_execution_authority = initial_go_execution_authority.clone();
                    }
                }
            }
        }
        if let Some(duration) = provider_cache_preparation_duration {
            provider_timings.insert(
                0,
                IndexPhaseTiming {
                    phase: IndexProgressPhase::SemanticProvider,
                    label: "semantic provider cache preparation".into(),
                    duration,
                    aggregation: IndexTimingAggregation::Exclusive,
                },
            );
        }
        ensure_index_active(&config.cancellation)?;
        report.phase_timings.append(&mut provider_timings);
        let has_semantic_evidence = !generated_scip_artifacts.is_empty()
            || !admitted_persistent_normalizations.is_empty()
            || !admitted_reused_normalizations.is_empty();
        let semantic_processing_start = has_semantic_evidence.then(|| {
            emit_progress(
                &config.progress,
                IndexProgressPhase::SemanticProvider,
                IndexProgressState::Started,
                "semantic evidence processing",
                "normalizing provider evidence and projecting admitted relationships",
                None,
            );
            Instant::now()
        });
        let generated_provider_count = generated_scip_artifacts.len()
            + admitted_persistent_normalizations.len()
            + admitted_reused_normalizations.len();

        // Merge only the exact artifacts returned by this invocation's
        // providers. Pre-existing project files are neither discovered nor
        // inferred from conventional filenames.
        if has_semantic_evidence {
            let graph_ref = &mut blocking_result.graph;
            let normalization_root = config.root.clone();
            let normalization_sources = indexed_source_evidence.clone();
            let normalization_inventory = project_inventory.clone();
            let go_execution_authority = go_execution_authority.clone();
            // Local package identity comes from real definition occurrences in
            // the already admitted repository documents. Packages with no
            // repository definition remain unresolvable, so no language-
            // specific metadata command or manifest probe is needed here.
            let merge_result = tokio::task::spawn_blocking({
                let mut temp_graph = std::mem::take(graph_ref);
                move || {
                    // Compose each provider/language population before
                    // normalization and graph loading. This preserves global
                    // symbol identity across detached execution roots.
                    let mut aggregate = crate::scip_loader::ScipStats::default();
                    let mut any_ok = false;
                    let mut last_err = None;
                    let mut normalized = Vec::new();
                    let mut canonical_snapshots = Vec::new();
                    let mut semantic_timings = Vec::new();
                    let mut payload_canonicalization =
                        ProviderPayloadCanonicalizationTimings::default();
                    let go_semantic_inputs = {
                        let paths = normalization_inventory
                            .inputs
                            .iter()
                            .filter(|input| input.language_id.0 == "go")
                            .map(|input| input.path.clone())
                            .collect::<BTreeSet<_>>();
                        h00ligan_provider_protocol::capture_provider_semantic_inputs(
                            &normalization_root,
                            &paths,
                            &BTreeSet::new(),
                            &h00ligan_provider_protocol::ProviderFrameLimits::default(),
                        )
                        .ok()
                    };
                    let bind_go_authority =
                        |normalization: &mut ScipArtifactSetNormalization| {
                            if let Some(normalized_payload) =
                                normalization.evidence.payload.as_mut()
                                && let Some(semantic_inputs) = go_semantic_inputs.as_ref()
                            {
                                let ProviderPayload::Calls(payload) = normalized_payload.payload()
                                else {
                                    return Ok::<(), crate::scip_loader::ScipLoaderError>(());
                                };
                                let execution_authority = if let Some(authority) =
                                    go_execution_authority.as_ref()
                                    && go_provider_documents_have_bounded_external_inputs(
                                        &normalization_root,
                                        payload,
                                    )
                                {
                                    authority.clone()
                                } else {
                                    payload.execution_authority.clone()
                                };
                                normalized_payload
                                    .bind_semantic_authority(
                                        semantic_inputs.clone(),
                                        execution_authority,
                                    )
                                    .map_err(|error| {
                                    crate::scip_loader::ScipLoaderError::DocumentPath(format!(
                                        "normalized Go execution authority is invalid: {error}"
                                    ))
                                })?;
                            }
                            Ok::<(), crate::scip_loader::ScipLoaderError>(())
                        };
                    let mut normalizations = admitted_persistent_normalizations
                        .into_iter()
                        .map(|normalization| {
                            (
                                format!(
                                    "{} persistent",
                                    normalization.evidence.language_id.0
                                ),
                                normalization,
                            )
                        })
                        .collect::<Vec<_>>();
                    normalizations.extend(admitted_reused_normalizations.into_iter().map(
                        |normalization| {
                            (
                                format!(
                                    "{} retained exact",
                                    normalization.evidence.language_id.0
                                ),
                                normalization,
                            )
                        },
                    ));
                    let mut generated_scip_artifacts = generated_scip_artifacts;
                    if let Some(CanonicalSemanticBasis {
                        snapshot,
                        source_syntax_cache,
                        ..
                    }) = partial_go_basis
                    {
                        let evidence_start = Instant::now();
                        let mut retained_snapshot = snapshot;
                        let mut remaining = Vec::new();
                        let mut affected_go_artifacts = Vec::new();
                        for generated in generated_scip_artifacts {
                            if generated.spec.language == "go" {
                                affected_go_artifacts.push(generated);
                            } else {
                                remaining.push(generated);
                            }
                        }
                        affected_go_artifacts.sort_by(|left, right| {
                            left.execution_root.cmp(&right.execution_root)
                        });
                        for generated in affected_go_artifacts {
                            retained_snapshot = retained_snapshot
                                .replace_execution_root_artifact(&ScipArtifactInput {
                                    artifact_path: generated.artifact.path,
                                    execution_root: generated.execution_root,
                                    executed_provider_version: generated.artifact.provider_version,
                                    provider_configuration_sha256: generated
                                        .provider_configuration_sha256,
                                })
                                .map_err(|error| {
                                    crate::scip_loader::ScipLoaderError::DocumentPath(format!(
                                        "cannot compose retained Go execution roots: {error}"
                                    ))
                                })?;
                        }
                        let mut normalization =
                            normalize_canonical_scip_snapshot_with_source_syntax_cache(
                                &normalization_root,
                                retained_snapshot,
                                &normalization_sources,
                                &normalization_inventory,
                                source_syntax_cache.as_ref(),
                            );
                        bind_go_authority(&mut normalization)?;
                        let evidence_duration = evidence_start.elapsed();
                        debug_assert!(normalization.timings.total <= evidence_duration);
                        semantic_timings.push(IndexPhaseTiming {
                            phase: IndexProgressPhase::SemanticProvider,
                            label: "go affected-root composition and authority binding".into(),
                            duration: evidence_duration
                                .saturating_sub(normalization.timings.total),
                            aggregation: IndexTimingAggregation::Exclusive,
                        });
                        normalizations.push(("go affected-root".into(), normalization));
                        generated_scip_artifacts = remaining;
                    }
                    let mut by_language = BTreeMap::<&str, Vec<&GeneratedProviderArtifact>>::new();
                    for generated in &generated_scip_artifacts {
                        by_language
                            .entry(generated.spec.language)
                            .or_default()
                            .push(generated);
                    }
                    for generated_set in by_language.into_values() {
                        let spec = generated_set[0].spec;
                        let inputs = generated_set
                            .iter()
                            .map(|generated| ScipArtifactInput {
                                artifact_path: generated.artifact.path.clone(),
                                execution_root: generated.execution_root.clone(),
                                executed_provider_version: generated
                                    .artifact
                                    .provider_version
                                    .clone(),
                                provider_configuration_sha256: generated
                                    .provider_configuration_sha256
                                    .clone(),
                            })
                            .collect::<Vec<_>>();
                        let evidence_start = Instant::now();
                        let mut normalization = normalize_scip_artifact_set_for_inventory_coverage(
                            &normalization_root,
                            spec,
                            &inputs,
                            &normalization_sources,
                            &normalization_inventory,
                        );
                        if spec.language == "go" {
                            bind_go_authority(&mut normalization)?;
                        }
                        let evidence_duration = evidence_start.elapsed();
                        debug_assert!(normalization.timings.total <= evidence_duration);
                        semantic_timings.push(IndexPhaseTiming {
                            phase: IndexProgressPhase::SemanticProvider,
                            label: format!(
                                "{} artifact composition and authority binding",
                                spec.language
                            ),
                            duration: evidence_duration
                                .saturating_sub(normalization.timings.total),
                            aggregation: IndexTimingAggregation::Exclusive,
                        });
                        normalizations.push((spec.language.into(), normalization));
                    }
                    for (label, normalization) in normalizations {
                        let ScipArtifactSetNormalization {
                            evidence,
                            supplemental_evidence,
                            canonical_snapshot,
                            source_syntax_cache,
                            timings: normalization_timings,
                        } = normalization;
                        if normalization_timings.source_documents > 0 {
                            semantic_timings
                                .extend(semantic_normalizer_components(&label, normalization_timings));
                        }
                        let (mut evidence, sealing_timings) =
                            seal_scip_artifact_evidence(evidence);
                        payload_canonicalization.normalization += sealing_timings.normalization;
                        payload_canonicalization.serialization += sealing_timings.serialization;
                        payload_canonicalization.descriptor += sealing_timings.descriptor;
                        let calls_projection_start = Instant::now();
                        let calls_projection = enforce_and_project_calls_structural_join(
                            &mut temp_graph,
                            &mut evidence,
                        );
                        semantic_timings.push(IndexPhaseTiming {
                            phase: IndexProgressPhase::SemanticProvider,
                            label: format!("{label} normalized Calls projection"),
                            duration: calls_projection_start.elapsed(),
                            aggregation: IndexTimingAggregation::Exclusive,
                        });
                        aggregate.novel_edges += calls_projection.novel_edges;
                        let trusted_for_residual_merge = evidence.receipt.status
                            == CapabilityStatus::Complete
                            && evidence.payload.is_some();
                        normalized.push(evidence);
                        if !trusted_for_residual_merge {
                            continue;
                        }
                        for supplemental in supplemental_evidence {
                            let (mut supplemental, sealing_timings) =
                                seal_scip_artifact_evidence(supplemental);
                            payload_canonicalization.normalization +=
                                sealing_timings.normalization;
                            payload_canonicalization.serialization +=
                                sealing_timings.serialization;
                            payload_canonicalization.descriptor += sealing_timings.descriptor;
                            enforce_callable_liveness_structural_join(
                                &temp_graph,
                                &mut supplemental,
                            );
                            normalized.push(supplemental);
                        }
                        let residual_projection_start = Instant::now();
                        let Some(canonical_snapshot) = canonical_snapshot else {
                            last_err = Some(crate::scip_loader::ScipLoaderError::DocumentPath(
                                "complete normalized evidence did not retain its admitted canonical SCIP snapshot"
                                    .into(),
                            ));
                            continue;
                        };
                        let load_result = {
                            let mut loader =
                                crate::scip_loader::ScipLoader::new(&mut temp_graph);
                            loader.load_scip_documents_in_memory(canonical_snapshot.documents())
                        };
                        match load_result {
                            Ok(s) => {
                                any_ok = true;
                                aggregate.novel_edges += s.novel_edges;
                                aggregate.merged_with_existing += s.merged_with_existing;
                            }
                            Err(e) => last_err = Some(e),
                        }
                        canonical_snapshots.push((canonical_snapshot, source_syntax_cache));
                        semantic_timings.push(IndexPhaseTiming {
                            phase: IndexProgressPhase::SemanticProvider,
                            label: format!("{label} residual SCIP projection"),
                            duration: residual_projection_start.elapsed(),
                            aggregation: IndexTimingAggregation::Exclusive,
                        });
                    }
                    Ok::<_, crate::scip_loader::ScipLoaderError>((
                        temp_graph,
                        any_ok,
                        aggregate,
                        last_err,
                        normalized,
                        canonical_snapshots,
                        semantic_timings,
                        payload_canonicalization,
                    ))
                }
            })
            .await
            .map_err(|e| {
                IndexPipelineError::Other(format!("spawn_blocking panicked during SCIP merge: {e}"))
            })??;
            // Put the graph back.
            let (
                merged_graph,
                any_ok,
                aggregate,
                last_err,
                normalized,
                admitted_snapshots,
                mut semantic_timings,
                payload_canonicalization,
            ) = merge_result;
            blocking_result.graph = merged_graph;
            ensure_index_active(&config.cancellation)?;
            scip_evidence = normalized;
            canonical_scip_snapshots = admitted_snapshots;
            provider_payload_canonicalization = payload_canonicalization;
            report.phase_timings.append(&mut semantic_timings);
            report.edges_added += aggregate.novel_edges;
            if any_ok || aggregate.novel_edges > 0 || aggregate.merged_with_existing > 0 {
                tracing::info!(
                    novel_edges = aggregate.novel_edges,
                    merged = aggregate.merged_with_existing,
                    "SCIP edges merged into pipeline graph"
                );
            }
            if let Some(e) = last_err {
                tracing::warn!(
                    error = %e,
                    "a SCIP index merge failed (non-fatal, graph saved without those edges)"
                );
            }
        }
        for failure in persistent_failures {
            scip_evidence.push(seal_scip_artifact_evidence(failure).0);
        }
        let provider_workspace_cleanup_start = provider_workspace.as_ref().map(|_| Instant::now());
        drop(provider_workspace);
        if let Some(started) = provider_workspace_cleanup_start {
            report.phase_timings.push(IndexPhaseTiming {
                phase: IndexProgressPhase::SemanticProvider,
                label: "semantic provider workspace cleanup".into(),
                duration: started.elapsed(),
                aggregation: IndexTimingAggregation::Exclusive,
            });
        }
        if let Some(semantic_processing_start) = semantic_processing_start {
            let duration = semantic_processing_start.elapsed();
            emit_progress(
                &config.progress,
                IndexProgressPhase::SemanticProvider,
                IndexProgressState::Completed,
                "semantic evidence processing",
                format!("{generated_provider_count} trusted provider artifact(s)"),
                Some(duration),
            );
        }
        let semantic_duration = semantic_phase_started.elapsed();
        // `exclusive` semantic timings form an exact, mutually exclusive
        // partition. Concurrent worker spans remain available for ranking but
        // are intentionally excluded from wall-clock arithmetic. Attribute
        // scheduling, channel, and bookkeeping gaps explicitly so a machine
        // can sum the exclusive population without hidden time or double count.
        let semantic_component_count = report
            .phase_timings
            .iter()
            .filter(|timing| {
                timing.phase == IndexProgressPhase::SemanticProvider
                    && timing.aggregation == IndexTimingAggregation::Exclusive
            })
            .count();
        let measured_semantic_duration = report
            .phase_timings
            .iter()
            .filter(|timing| {
                timing.phase == IndexProgressPhase::SemanticProvider
                    && timing.aggregation == IndexTimingAggregation::Exclusive
            })
            .map(|timing| timing.duration)
            .sum::<Duration>();
        debug_assert!(
            measured_semantic_duration <= semantic_duration,
            "exclusive semantic components cannot exceed their direct wall clock"
        );
        if semantic_component_count > 0 {
            report.phase_timings.push(IndexPhaseTiming {
                phase: IndexProgressPhase::SemanticProvider,
                label: "semantic orchestration".into(),
                duration: semantic_duration.saturating_sub(measured_semantic_duration),
                aggregation: IndexTimingAggregation::Exclusive,
            });
        }
        profiler.record_phase(
            "semantic providers",
            7,
            semantic_duration,
            format!(
                "{} provider/normalization steps",
                report
                    .phase_timings
                    .iter()
                    .filter(|timing| timing.phase == IndexProgressPhase::SemanticProvider)
                    .count()
            ),
        );

        ensure_index_active(&config.cancellation)?;

        let finalize_start = Instant::now();
        emit_progress(
            &config.progress,
            IndexProgressPhase::Finalize,
            IndexProgressState::Started,
            "finalizing generation",
            "persisting state, classifying reachability, and validating capability evidence",
            None,
        );

        // ---------------------------------------------------------------
        // PHASE 8: STATE — update IndexState with results
        // ---------------------------------------------------------------
        let state_update_start = Instant::now();
        let now_ms = chrono::Utc::now().timestamp_millis();

        // Build the complete final file-record population in memory. The
        // candidate may have started empty even when reusable facts came from a
        // preceding generation, so unchanged records must be carried here
        // explicitly rather than relying on a preparatory database copy.
        let source_inputs_by_path = blocking_result
            .source_inputs
            .iter()
            .map(|input| (input.relative_path.as_str(), input))
            .collect::<std::collections::HashMap<_, _>>();
        let mut final_file_records = existing_files
            .iter()
            .filter(|(path, _)| source_inputs_by_path.contains_key(path.as_str()))
            .map(|(path, record)| (path.clone(), record.clone()))
            .collect::<BTreeMap<_, _>>();

        // Replace records for successfully extracted changed files.
        for output in &blocking_result.outputs {
            let record = FileRecord {
                blake3_hash: output.file_hash.clone(),
                last_indexed: now_ms,
                symbol_count: output.symbols.len() as u32,
                language: PathBuf::from(&output.file_path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .and_then(extension_to_language)
                    .unwrap_or("unknown")
                    .to_string(),
            };
            final_file_records.insert(output.file_path.clone(), record);
        }

        // A failed changed document is still part of the measured source
        // population. Record its current hash with zero covered symbols. The
        // absent document facts make the next incremental diff retry it even
        // when the bytes have not changed again.
        for (path, _) in &blocking_result.extraction_errors {
            let relative_path = path
                .strip_prefix(&config.root)
                .unwrap_or(path)
                .to_string_lossy();
            if let Some(input) = source_inputs_by_path.get(relative_path.as_ref()) {
                final_file_records.insert(
                    input.relative_path.clone(),
                    FileRecord {
                        blake3_hash: input.content_hash.clone(),
                        last_indexed: now_ms,
                        symbol_count: 0,
                        language: input.language.clone(),
                    },
                );
            }
        }

        // Persist source records and facts together once. The transaction
        // removes deleted/failed stale facts and makes the final database the
        // exact reusable basis for its successor generation.
        let indexed_files = final_file_records.into_iter().collect::<Vec<_>>();
        state.replace_source_state(&indexed_files, &blocking_result.document_facts)?;
        profiler.record_phase(
            "state update",
            8,
            state_update_start.elapsed(),
            format!(
                "{} files, {} document fact sets",
                indexed_files.len(),
                blocking_result.document_facts.len()
            ),
        );

        // ---------------------------------------------------------------
        // PHASE 8d: DEPENDENCY EDGES — add inter-crate DependsOn edges.
        // ---------------------------------------------------------------
        // Runs BEFORE reachability classification so the structural BFS in
        // `classify_and_writeback` accounts for inter-crate edges (a callee in
        // another crate is reachable only once the DependsOn edge exists).
        // Enrichment (Phase 8c, below) is unaffected by the reorder: its
        // `is_enrichment_dep` filter EXCLUDES DependsOn (only Calls/Implements/
        // References/TypeOf participate in fan/depth), so DependsOn edges are
        // invisible to enrichment regardless of when they are added.
        let dependency_edges_start = Instant::now();
        {
            let workspace_root = config.root.clone();
            let cargo_package_count = cargo_package_count(&project_inventory);
            let graph_ref = &mut blocking_result.graph;
            // build_dependency_edges uses std::fs — but we're modifying the
            // in-memory graph directly (no redb I/O), so the fs reads are
            // for Cargo.toml parsing. Wrap in spawn_blocking.
            let mut graph_for_deps = std::mem::take(graph_ref);
            let (deps_graph, dep_count) = tokio::task::spawn_blocking(move || {
                // OBS-3: surface the Err arm rather than swallowing it to 0
                // silently — a future zero-edges regression must be visible.
                let count = match crate::edge_builder::build_dependency_edges(
                    &mut graph_for_deps,
                    &workspace_root,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(error = %e, "Phase 8d: build_dependency_edges failed");
                        0
                    }
                };
                (graph_for_deps, count)
            })
            .await
            .map_err(|e| {
                IndexPipelineError::Other(format!("dependency edge task panicked: {e}"))
            })?;
            *graph_ref = deps_graph;
            report.edges_added += dep_count;
            if dep_count > 0 {
                tracing::info!(dep_count, "Phase 8d: inter-crate DependsOn edges added");
            } else if cargo_package_count > 1 {
                // OBS-3: zero inter-crate edges for a multi-member workspace is a
                // probable regression (e.g. the CL-EDGE FromStr bug) — surface it.
                tracing::warn!(
                    cargo_package_count,
                    "Phase 8d: 0 DependsOn edges for multi-crate workspace — possible regression"
                );
            }
        }
        profiler.record_phase(
            "dependency edges",
            8,
            dependency_edges_start.elapsed(),
            format!(
                "{} graph edges after dependency resolution",
                blocking_result.graph.edge_count()
            ),
        );

        // ---------------------------------------------------------------
        // PHASE 8b: REACHABILITY — classify every node before persisting.
        // ---------------------------------------------------------------
        // Running reachability at index time ensures all nodes have
        // `reachability_class` populated. Without this, downstream tool
        // calls (signature_check, is_wired, blast_radius) hit the
        // `needs_analysis` guard which triggers a full BFS over the entire
        // graph on every invocation — a 5-7s penalty per tool call.
        //
        // Routed through the inventory-owned reachability chokepoint. Invalid
        // discovery for a supported project remains a hard error. A source
        // population with no registered reachability owner instead publishes
        // exact structural truth with every node explicitly Unclassified and
        // no reachability evidence. Runs AFTER Phase 8d so the BFS sees
        // inter-crate DependsOn edges, and BEFORE Phase 8c so enrichment sees
        // the final classified-or-explicitly-unclassified graph.
        let reachability_start = Instant::now();
        let reachability_evidence = {
            let root = config.root.clone();
            let inventory = project_inventory.clone();
            let mut graph_for_classify = std::mem::take(&mut blocking_result.graph);
            let (classified_graph, classify_result) = tokio::task::spawn_blocking(move || {
                let result = classify_and_writeback_with_inventory_evidence(
                    &mut graph_for_classify,
                    &root,
                    &inventory,
                );
                (graph_for_classify, result)
            })
            .await
            .map_err(|e| {
                IndexPipelineError::Other(format!(
                    "spawn_blocking panicked during reachability classification: {e}"
                ))
            })?;
            blocking_result.graph = classified_graph;
            let reach_report = classify_result.map_err(|e| {
                IndexPipelineError::Other(format!(
                    "reachability classification failed (entry-point discovery): {e}"
                ))
            })?;
            if let Some(reach_report) = &reach_report {
                tracing::info!(
                    classified = reach_report.report.classified.len(),
                    wired = reach_report.report.summary.wired,
                    dead = reach_report.report.summary.dead,
                    "Phase 8b: reachability analysis complete"
                );
            } else {
                tracing::info!(
                    nodes = blocking_result.graph.node_count(),
                    "Phase 8b: reachability unavailable; structural graph remains unclassified"
                );
            }
            reach_report
        };
        report.nodes_total = blocking_result.graph.node_count();
        report.edges_total = blocking_result.graph.edge_count();
        report.reachability = reachability_evidence
            .as_ref()
            .map(|_| crate::graph_stats::compute_reachability_summary(&blocking_result.graph));
        profiler.record_phase(
            "reachability",
            8,
            reachability_start.elapsed(),
            if reachability_evidence.is_some() {
                format!("{} nodes classified", blocking_result.graph.node_count())
            } else {
                format!(
                    "{} nodes structurally indexed; no reachability owner",
                    blocking_result.graph.node_count()
                )
            },
        );

        // ---------------------------------------------------------------
        // PHASE 8c: ENRICHMENT — compute topology metrics and risk scores.
        // ---------------------------------------------------------------
        // Non-fatal: enrichment failure does not crash the pipeline. The
        // EnrichmentStore simply remains empty and downstream consumers
        // (surfacer, CLI) degrade gracefully.
        let enrichment_start = Instant::now();
        if let Some(estore) = enrichment_store {
            // Collect git churn metrics before enrichment (non-fatal).
            // Uses a temporary redb database for caching — the cache is a
            // performance optimization, not a correctness requirement.
            let churn_data = {
                let repo_root = config.root.clone();
                let churn_result: Option<
                    std::collections::HashMap<String, crate::git_metrics::FileChurnMetrics>,
                > = match tokio::task::spawn_blocking(move || {
                    let tmp_path = std::env::temp_dir()
                        .join(format!("h00-git-churn-{}.redb", std::process::id()));
                    let db = redb::Database::create(&tmp_path)
                        .map_err(|e| format!("redb create {}: {e}", tmp_path.display()))?;
                    let collector = crate::git_metrics::GitMetricsCollector::new(
                        std::sync::Arc::new(db),
                        repo_root,
                    )
                    .map_err(|e| format!("GitMetricsCollector: {e}"))?;
                    Ok::<_, String>((collector, tmp_path))
                })
                .await
                {
                    Ok(Ok((collector, tmp_path))) => {
                        let metrics = collector.collect().await;
                        // Clean up the temporary database.
                        let _ = tokio::fs::remove_file(&tmp_path).await;
                        if !metrics.is_empty() {
                            tracing::info!(
                                files = metrics.len(),
                                "Phase 8c: collected git churn metrics"
                            );
                            Some(metrics)
                        } else {
                            None
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            error = %e,
                            "Phase 8c: git metrics collector init failed (non-fatal)"
                        );
                        None
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Phase 8c: git metrics spawn_blocking panicked (non-fatal)"
                        );
                        None
                    }
                };
                churn_result
            };

            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let enrichments =
                    crate::enrichment::compute_node_enrichments(&blocking_result.graph);
                let risk_scores = crate::enrichment::compute_file_risk_scores(
                    &enrichments,
                    &blocking_result.graph,
                    churn_data.as_ref(),
                );
                (enrichments, risk_scores)
            })) {
                Ok((enrichments, risk_scores)) => {
                    let node_count = enrichments.len();
                    let file_count = risk_scores.len();
                    estore.set_node_enrichments(enrichments);
                    estore.set_file_risk_scores(risk_scores);
                    // Populate churn metrics in the enrichment store so
                    // downstream consumers (surfacer, CLI) can access them.
                    if let Some(churn) = churn_data {
                        estore.set_file_churn_metrics(churn);
                    }
                    tracing::info!(
                        nodes_enriched = node_count,
                        files_scored = file_count,
                        "Phase 8c: enrichment complete"
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        "Phase 8c: enrichment panicked (non-fatal, continuing without enrichment data)"
                    );
                }
            }
        }
        profiler.record_phase(
            "enrichment",
            8,
            enrichment_start.elapsed(),
            if enrichment_store.is_some() {
                "enabled".into()
            } else {
                "disabled".into()
            },
        );

        // Indexing never executes repository build scripts or procedural
        // macros. Compiler-backed evidence, if reintroduced, belongs behind an
        // isolated semantic-provider contract rather than a library-only
        // in-place escape hatch.
        let oracle_ran_ok = false;

        let metadata_start = Instant::now();
        let meta = IndexMetadata {
            repo_root: config.root.to_string_lossy().to_string(),
            // `cfg.full` (not `config.full`): a clear-on-schema-bump forces a
            // full re-extract even when the caller requested an incremental run,
            // so record it as a full scan.
            last_full_scan: if cfg.full {
                Some(now_ms)
            } else {
                state
                    .get_metadata()?
                    .and_then(|metadata| metadata.last_full_scan)
            },
            last_update: Some(now_ms),
            git_head: None,
            total_files: indexed_files.len() as u64,
            total_symbols: indexed_files
                .iter()
                .map(|(_, record)| u64::from(record.symbol_count))
                .sum(),
            total_edges: blocking_result.graph.edge_count() as u64,
        };
        state.set_metadata(&meta)?;
        profiler.record_phase(
            "metadata",
            8,
            metadata_start.elapsed(),
            format!(
                "{} files, {} symbols, {} edges",
                meta.total_files, meta.total_symbols, meta.total_edges
            ),
        );

        // ---------------------------------------------------------------
        // Persist graph snapshot if graph_store provided.
        // ---------------------------------------------------------------
        let graph_persistence_start = Instant::now();
        let mut publication_proof = None;
        if let Some(gs) = graph_store {
            let write_telemetry = gs
                .save_snapshot_with_optional_reachability_profiled(
                    &blocking_result.graph,
                    reachability_evidence.as_ref(),
                )
                .await?;
            // ADR-0033 ROOT-8: stamp the canonical workspace origin AFTER the
            // snapshot save (save_snapshot writes GRAPH_SNAPSHOT/GRAPH_META only,
            // never GRAPH_ORIGIN). This is the PRIMARY, canonical origin stamp:
            // it overwrites any foreign origin left behind by an adopt-clear.
            gs.set_origin(&config.root).await?;
            // Stamp all required interpretation inputs in one transaction.
            // Immutable capability receipts remain the separate authority for
            // provider-backed semantics such as Calls.
            let generation_metadata = GraphGenerationMetadata::now(oracle_ran_ok);
            gs.set_generation_metadata(generation_metadata.clone())
                .await?;
            publication_proof = Some(gs.bind_publication_proof(
                &write_telemetry,
                &config.root,
                generation_metadata,
            )?);
            let measured = write_telemetry
                .evidence_validation
                .saturating_add(write_telemetry.snapshot_materialization)
                .saturating_add(write_telemetry.snapshot_encoding)
                .saturating_add(write_telemetry.evidence_encoding)
                .saturating_add(write_telemetry.proof_hashing)
                .saturating_add(write_telemetry.database_write);
            let persistence_overhead = graph_persistence_start.elapsed().saturating_sub(measured);
            profiler.record_phase(
                "graph validation",
                8,
                write_telemetry.evidence_validation,
                if reachability_evidence.is_some() {
                    "reachability evidence".into()
                } else {
                    "no reachability evidence".into()
                },
            );
            profiler.record_phase(
                "graph materialize",
                8,
                write_telemetry.snapshot_materialization,
                format!(
                    "{} nodes, {} edges",
                    blocking_result.graph.node_count(),
                    blocking_result.graph.edge_count()
                ),
            );
            profiler.record_phase(
                "graph encode",
                8,
                write_telemetry
                    .snapshot_encoding
                    .saturating_add(write_telemetry.evidence_encoding),
                format!(
                    "{} graph bytes, {} evidence bytes",
                    write_telemetry.graph_bytes, write_telemetry.evidence_bytes
                ),
            );
            profiler.record_phase(
                "graph proof",
                8,
                write_telemetry.proof_hashing,
                format!(
                    "{} graph/evidence bytes",
                    write_telemetry
                        .graph_bytes
                        .saturating_add(write_telemetry.evidence_bytes)
                ),
            );
            profiler.record_phase(
                "graph database write",
                8,
                write_telemetry.database_write,
                "snapshot, optional evidence, and schema transaction".into(),
            );
            profiler.record_phase(
                "graph metadata writes",
                8,
                persistence_overhead,
                "origin and generation metadata".into(),
            );
        } else {
            profiler.record_phase(
                "graph persist",
                8,
                graph_persistence_start.elapsed(),
                "disabled".into(),
            );
        }
        let index_state_publication_proof = state.capture_bound_publication_proof()?;
        ensure_index_active(&config.cancellation)?;

        // ---------------------------------------------------------------
        // PHASE 9: REPORT + PROFILE OUTPUT
        // ---------------------------------------------------------------
        let evidence_start = Instant::now();
        let evidence = build_index_evidence(
            config,
            &blocking_result,
            &indexed_files,
            project_inventory,
            scip_evidence,
            &configured_calls_languages,
        );
        if !evidence.provider_payloads.is_empty() {
            report.phase_timings.push(IndexPhaseTiming {
                phase: IndexProgressPhase::Finalize,
                label: "canonical provider payload serialization".into(),
                duration: provider_payload_canonicalization.serialization,
                aggregation: IndexTimingAggregation::ConcurrentSpan,
            });
            report.phase_timings.push(IndexPhaseTiming {
                phase: IndexProgressPhase::Finalize,
                label: "canonical provider payload descriptor binding".into(),
                duration: provider_payload_canonicalization.descriptor,
                aggregation: IndexTimingAggregation::ConcurrentSpan,
            });
        }
        if let Err(error) =
            require_requested_semantic_authority(config, &evidence, &blocking_result.graph)
        {
            emit_progress(
                &config.progress,
                IndexProgressPhase::Finalize,
                IndexProgressState::Failed,
                "finalizing generation",
                error.to_string(),
                Some(finalize_start.elapsed()),
            );
            return Err(error);
        }
        let semantic_bases = admitted_canonical_semantic_bases(canonical_scip_snapshots, &evidence);
        profiler.record_phase(
            "evidence",
            8,
            evidence_start.elapsed(),
            format!(
                "{} receipts, {} provider payloads",
                evidence.capability_receipts.len(),
                evidence.provider_payloads.len()
            ),
        );
        let finalize_duration = finalize_start.elapsed();
        report.phase_timings.push(IndexPhaseTiming {
            phase: IndexProgressPhase::Finalize,
            label: "finalizing generation".into(),
            duration: finalize_duration,
            aggregation: IndexTimingAggregation::Exclusive,
        });
        profiler.append_machine_timings(&mut report.phase_timings);
        emit_progress(
            &config.progress,
            IndexProgressPhase::Finalize,
            IndexProgressState::Completed,
            "finalizing generation",
            "candidate graph and capability evidence validated",
            Some(finalize_duration),
        );
        report.duration = start.elapsed();
        profiler.finish();
        let structural_basis = CompletedStructuralBasis {
            source: IncrementalIndexBasis {
                files: indexed_files,
                document_facts: blocking_result.document_facts,
            },
            graph: blocking_result.graph,
            semantic_bases,
        };
        Ok(PreparedIndexRun {
            outcome: IndexRunOutcome::Completed {
                telemetry: Box::new(report),
                evidence,
                publication_proof: publication_proof.map(Box::new),
                index_state_publication_proof,
            },
            structural_basis: Some(structural_basis),
        })
    }

    /// Phases 1-4 run synchronously (file I/O, tree-sitter, rayon).
    ///
    /// `existing_files` contains the current state records, read from
    /// [`IndexState`] before entering this blocking phase.
    ///
    /// `existing_graph` is the previously saved graph snapshot (if any).
    /// Changed and deleted files are invalidated from it before merging
    /// new extraction results, enabling incremental graph builds.
    fn blocking_phase(
        config: &IndexConfig,
        existing_files: &std::collections::HashMap<String, FileRecord>,
        existing_document_facts: &std::collections::HashMap<String, ExtractorOutput>,
        existing_graph: KnowledgeGraph,
    ) -> Result<BlockingPhaseResult, IndexPipelineError> {
        ensure_index_active(&config.cancellation)?;
        let profiling = config.profile;

        // PHASE 1: DISCOVER
        let p1_start = if profiling {
            Some(Instant::now())
        } else {
            None
        };
        let extensions = supported_extensions(config);
        let discovered = Self::discover(&config.root, &extensions, &config.exclude)?;
        ensure_index_active(&config.cancellation)?;
        let p1_dur = p1_start.map(|s| s.elapsed());

        let discovered_rel: Vec<(PathBuf, String)> = discovered
            .iter()
            .map(|p| {
                let rel = p
                    .strip_prefix(&config.root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .to_string();
                (p.clone(), rel)
            })
            .collect();

        let discovered_rel_set: HashSet<&str> =
            discovered_rel.iter().map(|(_, r)| r.as_str()).collect();

        // Detect deleted files.
        let deleted_paths: Vec<String> = existing_files
            .keys()
            .filter(|k| !discovered_rel_set.contains(k.as_str()))
            .cloned()
            .collect();

        // PHASE 2: DIFF — Compute hashes and partition into changed/unchanged.
        let p2_start = if profiling {
            Some(Instant::now())
        } else {
            None
        };
        let mut changed_paths: Vec<PathBuf> = Vec::new();
        let mut unchanged_count: usize = 0;
        let mut source_inputs = Vec::with_capacity(discovered_rel.len());

        for (abs_path, rel_path) in &discovered_rel {
            ensure_index_active(&config.cancellation)?;
            let contents = std::fs::read(abs_path)?;
            let hash = blake3::hash(&contents).to_hex().to_string();
            let language = abs_path
                .extension()
                .and_then(|extension| extension.to_str())
                .and_then(extension_to_language)
                .unwrap_or("unknown")
                .to_owned();
            source_inputs.push(SourceInput {
                relative_path: rel_path.clone(),
                language,
                content_hash: hash.clone(),
            });

            if config.full {
                changed_paths.push(abs_path.clone());
                continue;
            }

            match (
                existing_files.get(rel_path),
                existing_document_facts.get(rel_path),
            ) {
                (Some(record), Some(facts))
                    if record.blake3_hash == hash
                        && facts.file_path == rel_path.as_str()
                        && facts.file_hash == hash =>
                {
                    unchanged_count += 1;
                }
                _ => {
                    changed_paths.push(abs_path.clone());
                }
            }
        }
        let p2_dur = p2_start.map(|s| s.elapsed());
        ensure_index_active(&config.cancellation)?;

        // Project ownership is an input to cross-document structural
        // resolution, not metadata to decorate the graph after construction.
        // Build it once from the exact hashed source population and carry that
        // same value through provider normalization and publication.
        let project_inventory_start = profiling.then(Instant::now);
        let inventory_sources = source_inputs
            .iter()
            .map(|input| InventorySource::new(&input.relative_path, &input.language))
            .collect::<Vec<_>>();
        let project_inventory = build_project_inventory(&config.root, &inventory_sources);
        let profile_inventory_dur = project_inventory_start.map(|start| start.elapsed());
        ensure_index_active(&config.cancellation)?;

        // PHASE 3: EXTRACT (using rayon for parallelism)
        let p3_start = if profiling {
            Some(Instant::now())
        } else {
            None
        };

        // Thread-safe collector for per-file timings (only allocated when profiling).
        let file_timings: Option<std::sync::Mutex<Vec<FileExtractTiming>>> = if profiling {
            Some(std::sync::Mutex::new(Vec::with_capacity(
                changed_paths.len(),
            )))
        } else {
            None
        };

        let (outputs, extraction_errors) = if config.jobs == Some(1) {
            // Single-threaded mode — no rayon.
            #[allow(clippy::option_if_let_else)]
            if let Some(ref ft) = file_timings {
                let mut results_ok = Vec::new();
                let mut results_err = Vec::new();
                for p in &changed_paths {
                    ensure_index_active(&config.cancellation)?;
                    let t = Instant::now();
                    match extractor::extract_file(p, &config.root) {
                        Ok(output) => {
                            let syms = output.symbols.len();
                            results_ok.push(output);
                            ft.lock()
                                .expect("profiling lock poisoned")
                                .push(FileExtractTiming {
                                    file_path: p.to_string_lossy().to_string(),
                                    wall_time: t.elapsed(),
                                    symbols_extracted: syms,
                                });
                        }
                        Err(e) => {
                            results_err.push((p.clone(), e.to_string()));
                        }
                    }
                }
                (results_ok, results_err)
            } else {
                let results = extractor::extract_files(&changed_paths, &config.root);
                partition_results(&changed_paths, results)
            }
        } else {
            use rayon::prelude::*;

            // Configure rayon thread pool if jobs is specified.
            let pool = config
                .jobs
                .map(|n| {
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(n)
                        .build()
                        .map_err(|e| IndexPipelineError::Other(e.to_string()))
                })
                .transpose()?;

            let extract_fn = || {
                changed_paths
                    .par_iter()
                    .map(|p| {
                        let t = if profiling {
                            Some(Instant::now())
                        } else {
                            None
                        };
                        let result = extractor::extract_file(p, &config.root);
                        if let (Some(elapsed_start), Some(ft), Ok(output)) =
                            (&t, &file_timings, &result)
                            && let Ok(mut guard) = ft.lock()
                        {
                            guard.push(FileExtractTiming {
                                file_path: p.to_string_lossy().to_string(),
                                wall_time: elapsed_start.elapsed(),
                                symbols_extracted: output.symbols.len(),
                            });
                        }
                        (p.clone(), result)
                    })
                    .collect::<Vec<_>>()
            };

            let par_results = pool
                .as_ref()
                .map_or_else(extract_fn, |p| p.install(extract_fn));

            let mut ok_results = Vec::new();
            let mut err_results = Vec::new();
            for (path, result) in par_results {
                match result {
                    Ok(output) => ok_results.push(output),
                    Err(e) => err_results.push((path, e.to_string())),
                }
            }
            (ok_results, err_results)
        };
        ensure_index_active(&config.cancellation)?;
        let p3_dur = p3_start.map(|s| s.elapsed());

        // PHASE 4: RESOLVE + MATERIALIZE GRAPH
        let p4_start = if profiling {
            Some(Instant::now())
        } else {
            None
        };
        // Extraction is incremental; relationship resolution is global. A
        // materialized graph is not sufficient source data because incoming
        // edges disappear when their target is replaced and several edge kinds
        // require symbol facts that GraphNode intentionally does not carry.
        // Reuse only facts whose path + content hash passed the authoritative
        // discovery pass and combine them with freshly extracted documents.
        // The complete fact population then either reconciles an admitted live
        // structural-node basis or materializes a new graph; relationships and
        // derived reachability are rebuilt globally in both cases.
        let changed_rel: HashSet<String> = changed_paths
            .iter()
            .map(|path| {
                path.strip_prefix(&config.root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        let fresh_by_path: std::collections::HashMap<&str, &ExtractorOutput> = outputs
            .iter()
            .map(|output| (output.file_path.as_str(), output))
            .collect();
        let source_hash_by_path: std::collections::HashMap<&str, &str> = source_inputs
            .iter()
            .map(|input| (input.relative_path.as_str(), input.content_hash.as_str()))
            .collect();
        let mut document_facts = Vec::with_capacity(discovered_rel.len());
        for (_, relative_path) in &discovered_rel {
            if let Some(output) = fresh_by_path.get(relative_path.as_str()) {
                document_facts.push((*output).clone());
                continue;
            }
            if changed_rel.contains(relative_path) {
                // Extraction failed for a changed document. Never retain its
                // previous facts; capability evidence reports the failure.
                continue;
            }
            if let (Some(facts), Some(current_hash)) = (
                existing_document_facts.get(relative_path),
                source_hash_by_path.get(relative_path.as_str()),
            ) && facts.file_path == relative_path.as_str()
                && facts.file_hash == *current_hash
            {
                document_facts.push(facts.clone());
            }
        }

        // Preserve learned weights only for relationships that the complete
        // current fact population independently re-materializes. Semantic edges
        // from an older provider run are intentionally not carried into a
        // structural-only generation.
        let prior_ids = existing_graph
            .all_nodes()
            .into_iter()
            .map(|node| node.memory_id)
            .collect::<Vec<_>>();
        let hebbian_snapshot = existing_graph.snapshot_hebbian_weights(&prior_ids);
        let reuse_structural_nodes = existing_graph.node_count() > 0;
        let mut graph = existing_graph;
        if reuse_structural_nodes {
            for path in changed_rel.iter().chain(deleted_paths.iter()) {
                graph.invalidate_file(path);
            }
        }
        let build_stats = edge_builder::build_graph_with_inventory(
            &document_facts,
            &mut graph,
            &project_inventory,
            profiling,
            reuse_structural_nodes,
        )?;
        ensure_index_active(&config.cancellation)?;

        // Restore Hebbian weights to re-created edges.  Since UUIDs are
        // deterministic (blake3 of file_path:symbol_name), edges between
        // unchanged symbols get the same UUID pair and can be matched.
        let restored = graph.restore_hebbian_weights(&hebbian_snapshot);
        if restored > 0 {
            tracing::info!(
                restored_edges = restored,
                "Hebbian weights preserved across invalidation"
            );
        }
        let p4_dur = p4_start.map(|s| s.elapsed());

        let profile_file_timings = file_timings
            .map(|ft| ft.into_inner().expect("profiling lock poisoned"))
            .unwrap_or_default();

        Ok(BlockingPhaseResult {
            discovered_paths: discovered,
            changed_paths,
            unchanged_count,
            deleted_paths,
            outputs,
            document_facts,
            extraction_errors,
            source_inputs,
            project_inventory: Some(project_inventory),
            graph,
            build_stats,
            profile_discovery_dur: p1_dur,
            profile_diff_dur: p2_dur,
            profile_inventory_dur,
            profile_extract_dur: p3_dur,
            profile_graph_dur: p4_dur,
            profile_file_timings,
        })
    }

    /// Walk the file tree respecting `.gitignore` and extension filters.
    fn discover(
        root: &std::path::Path,
        extensions: &HashSet<String>,
        exclude_patterns: &[String],
    ) -> Result<Vec<PathBuf>, IndexPipelineError> {
        crate::source_discovery::discover_source_files(root, extensions, exclude_patterns)
            .map_err(IndexPipelineError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn semantic_normalizer_timings_are_an_exact_component_partition() {
        let timings = ScipNormalizationTimings {
            total: Duration::from_millis(72),
            setup: Duration::from_millis(1),
            source_validation: Duration::from_millis(2),
            coverage_exclusion_setup: Duration::from_millis(3),
            occurrence_indexing: Duration::from_millis(4),
            definition_collection: Duration::from_millis(5),
            definition_canonicalization: Duration::from_millis(6),
            binding_and_lookup_indexing: Duration::from_millis(7),
            call_resolution: Duration::from_millis(8),
            coverage_validation: Duration::from_millis(9),
            payload_finalization: Duration::from_millis(10),
            source_documents: 3,
            syntax_cache_hits: 2,
            provider_documents: 3,
            provider_document_cache_hits: 2,
            definition_document_cache_hits: 2,
            definition_groups: 3,
            definition_group_reuse_hits: 2,
            call_documents: 3,
            call_document_reuse_hits: 2,
        };

        let components = semantic_normalizer_components("rust", timings);
        assert_eq!(components.len(), 11, "positive component population");
        assert!(components.iter().any(|timing| {
            timing.label == "rust source validation and syntax census (2/3 cache hits)"
        }));
        assert!(components.iter().any(|timing| {
            timing.label == "rust occurrence indexing (2/3 document cache hits)"
        }));
        assert!(components.iter().any(|timing| {
            timing.label == "rust definition collection (2/3 document cache hits)"
        }));
        assert!(components.iter().any(|timing| {
            timing.label == "rust definition canonicalization (2/3 group reuse hits)"
        }));
        assert!(
            components
                .iter()
                .any(|timing| { timing.label == "rust call resolution (2/3 document reuse hits)" })
        );
        assert!(components.iter().all(|timing| {
            !timing.label.contains("global semantic resolution")
                && timing.label != "rust definition indexing"
        }));
        assert_eq!(
            components
                .iter()
                .map(|timing| timing.duration)
                .sum::<Duration>(),
            timings.total,
            "the machine-readable components must sum to the direct normalizer wall clock"
        );
        assert_eq!(
            components
                .iter()
                .find(|timing| timing.label == "rust normalizer orchestration")
                .expect("explicit unmeasured interval")
                .duration,
            Duration::from_millis(17),
        );
    }

    #[test]
    fn semantic_provider_activity_telemetry_preserves_success_reuse_and_failure() {
        let mut refreshes = Vec::new();
        let timings = record_semantic_provider_activity(
            &mut refreshes,
            "rust",
            Some(SemanticProviderActivityRecord {
                activity: SemanticProviderActivity::Admitted {
                    refresh: SemanticProviderAdmittedRefreshKind::Full,
                    operation: ProviderOperation::CertifyFull,
                    session_open: None,
                },
                timings: Vec::new(),
            }),
        );
        assert!(timings.is_empty());
        assert_eq!(refreshes.len(), 1, "positive telemetry population");
        assert!(matches!(
            &refreshes[0],
            SemanticProviderActivityTelemetry::Admitted {
                lane: SemanticProviderRefreshLane::Full,
                operation: ProviderOperation::CertifyFull,
                ..
            }
        ));

        refreshes.clear();
        record_semantic_provider_activity(
            &mut refreshes,
            "rust",
            Some(SemanticProviderActivityRecord {
                activity: SemanticProviderActivity::Reused { session_open: None },
                timings: Vec::new(),
            }),
        );
        assert_eq!(refreshes.len(), 1, "reused positive control");
        assert!(matches!(
            &refreshes[0],
            SemanticProviderActivityTelemetry::Reused { .. }
        ));

        refreshes.clear();
        record_semantic_provider_activity(
            &mut refreshes,
            "rust",
            Some(SemanticProviderActivityRecord {
                activity: SemanticProviderActivity::Failed {
                    attempted_operations: vec![
                        ProviderOperation::OpenSession,
                        ProviderOperation::CertifyFull,
                    ],
                    session_open: None,
                },
                timings: Vec::new(),
            }),
        );
        assert!(matches!(
            &refreshes[0],
            SemanticProviderActivityTelemetry::Failed {
                attempted_operations,
                ..
            } if attempted_operations == &vec![
                ProviderOperation::OpenSession,
                ProviderOperation::CertifyFull,
            ]
        ));
        assert_eq!(
            refreshes[0].json_value()["lane"],
            "failed",
            "failed provider work must remain typed at the product boundary"
        );
    }

    #[test]
    fn semantic_provider_execution_timings_partition_the_old_aggregate() {
        let mut phase_timings = Vec::new();
        record_semantic_provider_execution_timings(
            &mut phase_timings,
            "go",
            "persistent gopls execution and cache work",
            Duration::from_millis(100),
            Duration::from_millis(20),
            vec![
                SemanticProviderRefreshTiming {
                    label: "apply source epoch",
                    duration: Duration::from_millis(30),
                },
                SemanticProviderRefreshTiming {
                    label: "export affected documents",
                    duration: Duration::from_millis(10),
                },
            ],
        );

        assert_eq!(phase_timings.len(), 4, "non-empty timing population");
        let summary = phase_timings
            .iter()
            .find(|timing| timing.label == "persistent gopls execution and cache work")
            .expect("nested provider summary");
        assert_eq!(summary.duration, Duration::from_millis(80));
        assert_eq!(summary.aggregation, IndexTimingAggregation::ConcurrentSpan);
        assert_eq!(
            phase_timings
                .iter()
                .filter(|timing| timing.aggregation == IndexTimingAggregation::Exclusive)
                .map(|timing| timing.duration)
                .sum::<Duration>(),
            summary.duration,
            "exclusive stages plus the explicit remainder must exactly partition provider work"
        );
        assert!(phase_timings.iter().any(|timing| {
            timing.label == "go semantic provider coordination remainder"
                && timing.duration == Duration::from_millis(40)
        }));
    }

    #[test]
    fn provider_root_parallelism_is_bounded_by_roots_cpus_and_jobs() {
        assert_eq!(provider_root_parallelism_for(0, None, 32), 0);
        assert_eq!(provider_root_parallelism_for(9, None, 32), 4);
        assert_eq!(provider_root_parallelism_for(9, None, 8), 2);
        assert_eq!(provider_root_parallelism_for(9, None, 4), 1);
        assert_eq!(provider_root_parallelism_for(2, Some(2), 2), 2);
        assert_eq!(provider_root_parallelism_for(9, Some(1), 32), 1);
        assert_eq!(provider_root_parallelism_for(9, Some(0), 32), 1);
        assert_eq!(provider_root_parallelism_for(2, Some(4), 32), 2);
    }

    fn create_test_project(dir: &std::path::Path) {
        // A Cargo.toml is required for entry-point discovery: the pipeline's
        // Phase-8b `classify_and_writeback` chokepoint treats a workspace with
        // no discoverable manifest as a HARD error (ADR-0028 OQ-2), so a fixture
        // exercised through `IndexPipeline::run` must be a real Cargo project.
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"test-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write Cargo.toml");
        let src = dir.join("src");
        fs::create_dir_all(&src).expect("mkdir");
        fs::write(src.join("main.rs"), "fn main() { println!(\"hello\"); }\n")
            .expect("write main.rs");
        fs::write(
            src.join("lib.rs"),
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        )
        .expect("write lib.rs");
    }

    #[test]
    fn go_inventory_fingerprints_localize_module_input_drift() {
        let temporary = TempDir::new().expect("multi-root inventory scratch");
        let root = temporary.path();
        for module in ["alpha", "beta"] {
            fs::create_dir_all(root.join(module)).expect("module directory");
            fs::write(
                root.join(module).join("go.mod"),
                format!("module example.test/{module}\n\ngo 1.27\n"),
            )
            .expect("module manifest");
            fs::write(
                root.join(module).join("module.go"),
                format!("package {module}\nfunc Target() int {{ return 1 }}\n"),
            )
            .expect("module source");
        }
        let sources = [
            InventorySource::new("alpha/module.go", "go"),
            InventorySource::new("beta/module.go", "go"),
        ];
        let roots = BTreeSet::from(["alpha".to_owned(), "beta".to_owned()]);
        let before = build_project_inventory(root, &sources);
        let before = go_execution_root_inventory_fingerprints(&before, &roots)
            .expect("baseline root-local inventory fingerprints");

        fs::write(
            root.join("alpha/go.mod"),
            "module example.test/alpha\n\ngo 1.27\n\n// project-input drift\n",
        )
        .expect("change alpha manifest");
        let after = build_project_inventory(root, &sources);
        let after = go_execution_root_inventory_fingerprints(&after, &roots)
            .expect("changed root-local inventory fingerprints");

        assert_ne!(before["alpha"], after["alpha"], "alpha positive control");
        assert_eq!(
            before["beta"], after["beta"],
            "alpha-only project-input drift contaminated beta's inventory identity"
        );
    }

    #[test]
    fn go_local_module_controls_admit_only_repository_owned_paths() {
        let temporary = TempDir::new().expect("Go authority scratch");
        let repository = temporary.path().join("repo");
        let module = repository.join("core");
        let local_replacement = module.join("third_party/x-vt");
        let sibling_module = repository.join("tools/helper");
        let outside = temporary.path().join("outside");
        for directory in [&local_replacement, &sibling_module, &outside] {
            fs::create_dir_all(directory).expect("fixture directory");
        }

        assert!(go_mod_local_replacements_are_repository_bound(
            &repository,
            &module,
            b"module example.test/core\nreplace example.test/vt => ./third_party/x-vt\n",
        ));
        assert!(go_mod_local_replacements_are_repository_bound(
            &repository,
            &module,
            b"module example.test/core\nreplace example.test/vt => example.test/fork v1.2.3\n",
        ));
        assert!(!go_mod_local_replacements_are_repository_bound(
            &repository,
            &module,
            format!(
                "module example.test/core\nreplace example.test/vt => {}\n",
                outside.display()
            )
            .as_bytes(),
        ));
        assert!(go_work_uses_are_repository_bound(
            &repository,
            &repository,
            b"go 1.26\nuse (\n ./core\n ./tools/helper\n)\n",
        ));
        assert!(!go_work_uses_are_repository_bound(
            &repository,
            &repository,
            format!("go 1.26\nuse {}\n", outside.display()).as_bytes(),
        ));
    }

    #[test]
    fn provider_cache_under_budget_survives_intact() {
        let data = TempDir::new().expect("scratch data directory");
        let cache_root = data.path().join(PROVIDER_CACHE_DIRECTORY);
        fs::create_dir_all(cache_root.join("rust")).expect("provider cache directory");
        let sentinel = cache_root.join("rust/sentinel");
        fs::write(&sentinel, b"warm-cache").expect("provider cache fixture");

        assert!(
            !trim_provider_cache_to_budget(&cache_root, 10, &BTreeSet::new())
                .expect("cache census"),
            "an at-budget cache must remain reusable"
        );
        assert_eq!(
            fs::read(&sentinel).expect("surviving cache entry"),
            b"warm-cache"
        );
    }

    #[test]
    fn provider_cache_over_budget_evicts_an_inactive_partition() {
        let data = TempDir::new().expect("scratch data directory");
        let cache_root = data.path().join(PROVIDER_CACHE_DIRECTORY);
        fs::create_dir_all(cache_root.join("go")).expect("provider cache directory");
        fs::write(cache_root.join("go/oversized"), b"too-large").expect("provider cache fixture");

        assert!(
            trim_provider_cache_to_budget(&cache_root, 8, &BTreeSet::new())
                .expect("cache eviction"),
            "an over-budget cache must be evicted"
        );
        assert!(cache_root.is_dir(), "cache root must remain available");
        assert!(
            !cache_root.join("go/oversized").exists(),
            "the inactive over-budget partition must be evicted"
        );
        assert_eq!(
            provider_cache_apparent_bytes(&cache_root).expect("post-eviction cache census"),
            0,
            "empty provider namespace directories do not consume the byte budget"
        );
    }

    /// RIGHT-REASON REGRESSION: post-run maintenance must never erase the
    /// exact partitions the completed operation just populated. If the active
    /// working set alone exceeds the nominal budget, retain it and report the
    /// soft overage after evicting inactive data.
    #[test]
    fn provider_cache_budget_never_self_evicts_the_active_working_set() {
        let data = TempDir::new().expect("scratch data directory");
        let cache_root = data.path().join(PROVIDER_CACHE_DIRECTORY);
        let workspaces = cache_root.join("rust/toolchain/workspaces");
        let active = workspaces.join("active");
        let stale = workspaces.join("stale");
        fs::create_dir_all(&active).expect("active cache partition");
        fs::create_dir_all(&stale).expect("stale cache partition");
        fs::write(active.join("payload"), b"active-cache").expect("active cache payload");
        fs::write(stale.join("payload"), b"stale-cache").expect("stale cache payload");

        assert!(
            trim_provider_cache_to_budget(&cache_root, 8, &BTreeSet::from([active.clone()]),)
                .expect("partition-aware cache eviction"),
            "the stale partition makes eviction non-vacuous"
        );
        assert_eq!(
            fs::read(active.join("payload")).expect("active cache survives"),
            b"active-cache"
        );
        assert!(
            !stale.exists(),
            "inactive partition must be removed before an active partition"
        );
        assert!(
            provider_cache_apparent_bytes(&cache_root).expect("post-eviction census") > 8,
            "the active working set may honestly exceed the nominal budget"
        );
    }

    /// RIGHT-REASON REGRESSION: Go cache ownership is execution-root scoped,
    /// just like Cargo target ownership. Treating the whole Go cache as one
    /// indivisible partition either evicts a live gopls/Go build cache or lets
    /// one active root pin every stale workspace forever.
    #[test]
    fn provider_cache_budget_partitions_go_workspaces_around_the_active_session() {
        let data = TempDir::new().expect("scratch data directory");
        let cache_root = data.path().join(PROVIDER_CACHE_DIRECTORY);
        let workspaces = cache_root.join("go/toolchain/workspaces");
        let active = workspaces.join("active");
        let stale = workspaces.join("stale");
        fs::create_dir_all(&active).expect("active Go cache partition");
        fs::create_dir_all(&stale).expect("stale Go cache partition");
        fs::write(active.join("payload"), b"active-cache").expect("active Go cache payload");
        fs::write(stale.join("payload"), b"stale-cache").expect("stale Go cache payload");

        assert!(
            trim_provider_cache_to_budget(&cache_root, 12, &BTreeSet::from([active.clone()]),)
                .expect("partition-aware Go cache eviction"),
            "the inactive Go workspace must be independently evictable"
        );
        assert_eq!(
            fs::read(active.join("payload")).expect("active Go cache survives"),
            b"active-cache"
        );
        assert!(
            !stale.exists(),
            "inactive Go cache partition must be evicted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn provider_cache_reset_unlinks_symlinks_without_following_targets() {
        use std::os::unix::fs::symlink;

        let data = TempDir::new().expect("scratch data directory");
        let outside = TempDir::new().expect("outside directory");
        let cache_root = data.path().join(PROVIDER_CACHE_DIRECTORY);
        fs::create_dir_all(cache_root.join("rust")).expect("provider cache directory");
        fs::write(cache_root.join("rust/oversized"), b"too-large").expect("provider cache fixture");
        let outside_sentinel = outside.path().join("sentinel");
        let outside_bytes = b"must-not-be-touched";
        fs::write(&outside_sentinel, outside_bytes).expect("outside sentinel");
        symlink(&outside_sentinel, cache_root.join("rust/outside-link"))
            .expect("cache symlink fixture");

        assert!(
            trim_provider_cache_to_budget(&cache_root, 8, &BTreeSet::new())
                .expect("cache eviction"),
            "the ordinary cache file makes this reset non-vacuous"
        );
        assert_eq!(
            fs::read(&outside_sentinel).expect("outside sentinel after reset"),
            outside_bytes,
            "cache eviction must never follow or mutate a symlink target"
        );
        assert!(!cache_root.join("rust/oversized").exists());
        assert!(!cache_root.join("rust/outside-link").exists());
    }

    #[test]
    fn mixed_rust_go_root_is_one_cargo_package_not_a_multi_crate_workspace() {
        let dir = TempDir::new().expect("tmpdir");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"mixed\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("write Cargo.toml");
        fs::create_dir_all(dir.path().join("src")).expect("create Rust source directory");
        fs::write(dir.path().join("src/lib.rs"), "pub fn rust_symbol() {}\n")
            .expect("write Rust source");
        fs::write(
            dir.path().join("go.mod"),
            "module example.invalid/mixed\n\ngo 1.26\n",
        )
        .expect("write go.mod");
        fs::create_dir_all(dir.path().join("go")).expect("create Go source directory");
        fs::write(
            dir.path().join("go/sample.go"),
            "package sample\n\nfunc GoSymbol() {}\n",
        )
        .expect("write Go source");

        let inventory = build_project_inventory(
            dir.path(),
            &[
                InventorySource::new("src/lib.rs", "rust"),
                InventorySource::new("go/sample.go", "go"),
            ],
        );

        assert_eq!(
            cargo_package_count(&inventory),
            1,
            "a Go module beside one Cargo package must not trigger the multi-crate warning"
        );
    }

    #[test]
    fn discover_respects_extensions() {
        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());
        // Write a non-Rust file.
        fs::write(dir.path().join("src").join("notes.txt"), "hello").expect("write");

        let extensions: HashSet<String> = vec!["rs".to_string()].into_iter().collect();
        let paths = IndexPipeline::discover(dir.path(), &extensions, &[]).expect("discover");
        assert_eq!(paths.len(), 2, "should find 2 .rs files, not txt");
        for p in &paths {
            assert!(p.extension().is_some_and(|e| e == "rs"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn discover_refuses_supported_source_symlinks_without_reading_their_targets() {
        use std::os::unix::fs::symlink;

        let project = TempDir::new().expect("project root");
        let outside = TempDir::new().expect("outside root");
        fs::create_dir_all(project.path().join("src")).expect("source directory");
        let ordinary = project.path().join("src/ordinary.rs");
        fs::write(&ordinary, "pub fn ordinary() {}\n").expect("ordinary source");
        let external = outside.path().join("external.rs");
        let external_bytes = b"pub fn external_secret() {}\n";
        fs::write(&external, external_bytes).expect("external source");
        let linked = project.path().join("src/linked.rs");
        symlink(&external, &linked).expect("source symlink");
        let extensions = HashSet::from(["rs".to_string()]);

        let error = IndexPipeline::discover(project.path(), &extensions, &[])
            .expect_err("a supported source symlink must make repository coverage fail closed");
        assert!(error.to_string().contains("symlink"), "{error}");
        assert_eq!(
            fs::read(&external).expect("external source"),
            external_bytes
        );

        fs::remove_file(&linked).expect("remove rejected symlink");
        let discovered = IndexPipeline::discover(project.path(), &extensions, &[])
            .expect("ordinary source positive control");
        assert_eq!(discovered, vec![ordinary]);
    }

    #[test]
    fn extension_to_language_mapping_is_registry_complete() {
        for (extension, language) in [
            ("rs", "rust"),
            ("go", "go"),
            ("py", "python"),
            ("pyi", "python"),
            ("ts", "typescript"),
            ("tsx", "typescript"),
            ("mts", "typescript"),
            ("cts", "typescript"),
        ] {
            assert_eq!(extension_to_language(extension), Some(language));
        }
        assert_eq!(extension_to_language("txt"), None);
        assert_eq!(extension_to_language(""), None);
    }

    #[test]
    fn supported_extensions_default_includes_every_registered_language() {
        let config = IndexConfig::default();
        let exts = supported_extensions(&config);
        for extension in ["rs", "go", "py", "pyi", "ts", "tsx", "mts", "cts"] {
            assert!(exts.contains(extension), "missing .{extension}");
        }
        assert!(!exts.contains("txt"), "negative extension control");
    }

    #[test]
    fn default_index_config_does_not_authorise_external_providers() {
        let config = IndexConfig::default();
        assert_eq!(config.scip, ScipMode::Disabled);
    }

    #[test]
    fn scip_generation_is_explicit() {
        assert!(!ScipMode::Disabled.generates_artifacts());
        assert!(ScipMode::Refresh.generates_artifacts());
    }

    fn calls_scope(language: &str) -> CapabilityScope {
        CapabilityScope::Language {
            language_id: LanguageId::new(language),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        }
    }

    fn normalized_calls_payload(
        receipt: CapabilityReceipt,
    ) -> crate::code_intel_payload::NormalizedProviderPayload {
        crate::code_intel_payload::normalize_provider_payload_typed(&ProviderPayload::Calls(
            crate::code_intel_payload::CallsProviderPayload::new(receipt),
        ))
        .expect("fixture Calls payload is normalized")
    }

    fn select_calls_evidence_for_test(
        scip_mode: ScipMode,
        language: &str,
        execution_root_available: bool,
        evidence: Vec<ScipArtifactEvidence>,
        provider_payloads: &mut Vec<CanonicalProviderPayload>,
    ) -> CapabilityReceipt {
        let mut canonicalization = ProviderPayloadCanonicalizationTimings::default();
        let evidence = evidence
            .into_iter()
            .map(|evidence| {
                let (evidence, timings) = seal_scip_artifact_evidence(evidence);
                canonicalization.normalization += timings.normalization;
                canonicalization.serialization += timings.serialization;
                canonicalization.descriptor += timings.descriptor;
                evidence
            })
            .collect();
        let receipt = select_calls_evidence(
            scip_mode,
            language,
            execution_root_available,
            true,
            evidence,
            provider_payloads,
        );
        assert_eq!(
            canonicalization.normalization,
            Duration::ZERO,
            "typed semantic evidence must not be normalized again during selection"
        );
        receipt
    }

    fn complete_calls_evidence(language: &str) -> ScipArtifactEvidence {
        let provider = default_calls_provider(language);
        let receipt = CapabilityReceipt::complete(
            "calls",
            provider,
            "fixture-provider-1.0.0",
            calls_scope(language),
            "a".repeat(64),
        );
        ScipArtifactEvidence {
            language_id: LanguageId::new(language),
            payload: Some(normalized_calls_payload(receipt.clone())),
            receipt,
        }
    }

    fn complete_callable_liveness_evidence(language: &str) -> ScipArtifactEvidence {
        use crate::code_intel_payload::{CallableLivenessProviderPayload, ProviderDocument};

        let receipt = CapabilityReceipt::complete(
            "callable_liveness",
            h00ligan_provider_protocol::H00_GO_PROVIDER_ID,
            "fixture-provider-1.0.0",
            CapabilityScope::Language {
                language_id: LanguageId::new(language),
                configuration_id: ConfigurationId::new(
                    crate::code_intel_domain::CALLABLE_LIVENESS_CONFIGURATION_ID,
                ),
            },
            "d".repeat(64),
        );
        let mut payload = CallableLivenessProviderPayload::new(receipt.clone());
        payload.documents.push(ProviderDocument {
            document_path: "main.go".into(),
            language_id: LanguageId::new(language),
            content_sha256: "e".repeat(64),
            cross_document_surface_sha256: "f".repeat(64),
            byte_length: 16,
        });
        let payload = crate::code_intel_payload::normalize_provider_payload_typed(
            &ProviderPayload::CallableLiveness(payload),
        )
        .expect("fixture callable-liveness payload is normalized");
        ScipArtifactEvidence {
            language_id: LanguageId::new(language),
            receipt,
            payload: Some(payload),
        }
    }

    /// RIGHT-REASON FALSIFIER: one provider terminal can carry canonical SCIP
    /// Calls plus a separately typed analysis attachment. Publication must
    /// route by capability before Calls selection, not count both as competing
    /// SCIP artifacts for the same language.
    #[test]
    fn typed_analysis_evidence_is_not_a_second_calls_candidate() {
        let (calls, _) = seal_scip_artifact_evidence(complete_calls_evidence("go"));
        let (liveness, _) = seal_scip_artifact_evidence(complete_callable_liveness_evidence("go"));
        let routed = route_semantic_evidence(vec![liveness, calls]);

        assert_eq!(
            routed.calls_by_language.get("go").map(Vec::len),
            Some(1),
            "positive control: the canonical SCIP payload remains one Calls candidate"
        );
        assert_eq!(routed.additional_receipts.len(), 1);
        assert_eq!(
            routed.additional_receipts[0].capability_id,
            "callable_liveness"
        );
        assert_eq!(routed.additional_payloads.len(), 1);
        assert!(matches!(
            routed.additional_payloads[0].payload(),
            ProviderPayload::CallableLiveness(_)
        ));
    }

    /// RIGHT-REASON FALSIFIER: the graph must not retain provider-backed
    /// Calls edges when the exact payload carrying their authority cannot be
    /// sealed for immutable publication.
    #[test]
    fn provider_payload_seal_failure_cannot_leave_projected_calls_edges() {
        use crate::code_intel_payload::{
            CallsProviderPayload, NormalizedSourceSpan, ProviderCall, ProviderDocument,
            ProviderLocation, ProviderSymbol, ProviderSymbolRole,
        };
        use crate::graph::{EdgeKind, EdgeSource, GraphNode, SourceSpan};
        use crate::reachability::ReachabilityClass;

        const DOCUMENT: &str = "src/lib.rs";
        let receipt = CapabilityReceipt::complete(
            "calls",
            "rust-analyzer-scip",
            "fixture-provider-1.0.0",
            calls_scope("rust"),
            "a".repeat(64),
        );
        let location = |line: u32, start_byte: u64, end_byte: u64| ProviderLocation {
            document_path: DOCUMENT.into(),
            span: NormalizedSourceSpan {
                start_byte,
                end_byte,
                start_line: line,
                start_utf8_byte_column: 4,
                end_line: line,
                end_utf8_byte_column: 4 + (end_byte - start_byte) as u32,
            },
        };
        let mut calls = CallsProviderPayload::new(receipt.clone());
        calls.documents.push(ProviderDocument {
            document_path: DOCUMENT.into(),
            language_id: LanguageId::new("rust"),
            content_sha256: "b".repeat(64),
            cross_document_surface_sha256: "c".repeat(64),
            byte_length: 1_024,
        });
        calls.symbols = vec![
            ProviderSymbol {
                provider_symbol_id: "provider-caller".into(),
                name: "caller".into(),
                provider_kind: "function".into(),
                language_id: LanguageId::new("rust"),
                role: ProviderSymbolRole::SourceInvocationTarget,
                definition: Some(location(0, 4, 10)),
                structural_extent: Some(location(0, 0, 80)),
                call_owner_extent: Some(location(0, 0, 80)),
            },
            ProviderSymbol {
                provider_symbol_id: "provider-target".into(),
                name: "target".into(),
                provider_kind: "function".into(),
                language_id: LanguageId::new("rust"),
                role: ProviderSymbolRole::SourceInvocationTarget,
                definition: Some(location(9, 904, 910)),
                structural_extent: Some(location(9, 900, 980)),
                call_owner_extent: Some(location(9, 900, 980)),
            },
        ];
        calls.calls.push(ProviderCall {
            caller_symbol_id: "provider-caller".into(),
            callee_symbol_id: "provider-target".into(),
            call_site: location(0, 40, 46),
        });
        let normalized = crate::code_intel_payload::normalize_provider_payload_typed(
            &ProviderPayload::Calls(calls),
        )
        .expect("normalized populated Calls fixture");
        let evidence = ScipArtifactEvidence {
            language_id: LanguageId::new("rust"),
            receipt,
            payload: Some(normalized),
        };

        let mut graph = KnowledgeGraph::new();
        let node = |name: &str, line: usize| GraphNode {
            memory_id: uuid::Uuid::new_v4(),
            symbol_name: name.into(),
            kind: "function".into(),
            file_path: DOCUMENT.into(),
            content_hash: format!("hash-{name}"),
            signature: format!("fn {name}()"),
            reachability_class: ReachabilityClass::Wired,
            line_start: Some(line),
            line_end: Some(line),
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
        let caller = node("caller", 0);
        let caller_id = caller.memory_id;
        graph.add_node(caller).expect("caller node");
        graph
            .set_source_span(
                caller_id,
                SourceSpan {
                    start_byte: 0,
                    end_byte: 80,
                },
            )
            .expect("caller span");
        let target = node("target", 9);
        let target_id = target.memory_id;
        graph.add_node(target).expect("target node");
        graph
            .set_source_span(
                target_id,
                SourceSpan {
                    start_byte: 900,
                    end_byte: 980,
                },
            )
            .expect("target span");

        crate::code_intel_payload::fail_next_provider_payload_seal();
        let (mut evidence, _) = seal_scip_artifact_evidence(evidence);
        assert_eq!(
            evidence.receipt.reason_code.as_deref(),
            Some("provider_payload_seal_failed"),
            "the injected fault must reach the intended seal boundary"
        );
        let projected = enforce_and_project_calls_structural_join(&mut graph, &mut evidence);
        assert_eq!(
            projected.novel_edges, 0,
            "an unsealed payload cannot reach projection"
        );
        let mut payloads = Vec::new();
        let selected = select_calls_evidence(
            ScipMode::Refresh,
            "rust",
            true,
            true,
            vec![evidence],
            &mut payloads,
        );
        assert_eq!(
            selected.reason_code.as_deref(),
            Some("provider_payload_seal_failed"),
            "the injected fault must reach the intended seal boundary"
        );
        assert!(payloads.is_empty(), "an unsealed payload is not authority");
        assert!(
            graph.all_edges().into_iter().all(|(_, _, edge)| {
                edge.kind != EdgeKind::Calls || edge.source != EdgeSource::Scip
            }),
            "a rejected seal must leave no provider-backed Calls relation"
        );
    }

    #[test]
    fn duplicate_scip_artifacts_are_ambiguous_and_order_independent() {
        let first = complete_calls_evidence("rust");
        let second = first.clone();
        let mut payloads = Vec::new();
        let forward = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "rust",
            true,
            vec![first.clone(), second.clone()],
            &mut payloads,
        );
        assert_eq!(forward.status, CapabilityStatus::Partial);
        assert_eq!(
            forward.reason_code.as_deref(),
            Some("provider_artifact_ambiguous")
        );
        assert!(payloads.is_empty());

        let reverse = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "rust",
            true,
            vec![second, first],
            &mut payloads,
        );
        assert_eq!(reverse, forward);
        assert!(payloads.is_empty());
    }

    #[test]
    fn missing_provider_root_is_not_reported_as_an_execution_failure() {
        let mut payloads = Vec::new();
        let missing_go_root = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "go",
            false,
            Vec::new(),
            &mut payloads,
        );
        assert_eq!(
            missing_go_root.reason_code.as_deref(),
            Some("provider_execution_root_unavailable")
        );
        assert!(
            missing_go_root
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("go.mod") && reason.contains("go.work"))
        );

        let failed_provider = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "go",
            true,
            Vec::new(),
            &mut payloads,
        );
        assert_eq!(
            failed_provider.reason_code.as_deref(),
            Some("provider_failed_or_unavailable"),
            "positive control: an available execution root takes the provider-failure branch"
        );

        let absent_python_provider = select_calls_evidence(
            ScipMode::Refresh,
            "python",
            true,
            false,
            Vec::new(),
            &mut payloads,
        );
        assert_eq!(
            absent_python_provider.reason_code.as_deref(),
            Some("provider_not_configured"),
            "an eligible project does not prove that this product configured its provider"
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn calls_evidence_selection_requires_matching_complete_receipt_and_payload() {
        let complete = complete_calls_evidence("go");
        let expected_receipt = complete.receipt.clone();
        let mut payloads = Vec::new();
        let selected = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "go",
            true,
            vec![complete],
            &mut payloads,
        );
        assert_eq!(selected, expected_receipt);
        assert_eq!(payloads.len(), 1);

        payloads.clear();
        let missing_payload = ScipArtifactEvidence {
            language_id: LanguageId::new("go"),
            receipt: expected_receipt,
            payload: None,
        };
        let inconsistent = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "go",
            true,
            vec![missing_payload],
            &mut payloads,
        );
        assert_eq!(inconsistent.status, CapabilityStatus::Unavailable);
        assert_eq!(
            inconsistent.reason_code.as_deref(),
            Some("provider_evidence_inconsistent")
        );
        assert!(payloads.is_empty());

        let foreign_scope = complete_calls_evidence("rust");
        let foreign = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "go",
            true,
            vec![foreign_scope],
            &mut payloads,
        );
        assert_eq!(foreign.status, CapabilityStatus::Unavailable);
        assert_eq!(
            foreign.reason_code.as_deref(),
            Some("provider_evidence_inconsistent")
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn calls_evidence_selection_retains_the_distinct_persistent_rust_provider_lineage() {
        let receipt = CapabilityReceipt::complete(
            "calls",
            h00ligan_provider_protocol::H00_RUST_ANALYZER_PROVIDER_ID,
            "fixture-provider-1.0.0",
            calls_scope("rust"),
            "b".repeat(64),
        );
        let evidence = ScipArtifactEvidence {
            language_id: LanguageId::new("rust"),
            payload: Some(normalized_calls_payload(receipt.clone())),
            receipt: receipt.clone(),
        };
        let mut payloads = Vec::new();
        let selected = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "rust",
            true,
            vec![evidence],
            &mut payloads,
        );
        assert_eq!(selected, receipt);
        assert_eq!(payloads.len(), 1);

        let unavailable_receipt = CapabilityReceipt::unavailable(
            "calls",
            h00ligan_provider_protocol::H00_RUST_ANALYZER_PROVIDER_ID,
            None,
            calls_scope("rust"),
            None,
            "provider_failed_or_unavailable",
            "persistent provider fixture failed",
        );
        let unavailable = ScipArtifactEvidence {
            language_id: LanguageId::new("rust"),
            receipt: unavailable_receipt.clone(),
            payload: None,
        };
        payloads.clear();
        let selected = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "rust",
            true,
            vec![unavailable],
            &mut payloads,
        );
        assert_eq!(selected, unavailable_receipt);
        assert_eq!(
            selected.provider_id.0,
            h00ligan_provider_protocol::H00_RUST_ANALYZER_PROVIDER_ID,
            "a persistent-provider failure must not be relabeled as the legacy one-shot provider"
        );
        assert!(payloads.is_empty());

        let foreign_receipt = CapabilityReceipt::complete(
            "calls",
            "foreign-rust-provider",
            "fixture-provider-1.0.0",
            calls_scope("rust"),
            "c".repeat(64),
        );
        let foreign = ScipArtifactEvidence {
            language_id: LanguageId::new("rust"),
            payload: Some(normalized_calls_payload(foreign_receipt.clone())),
            receipt: foreign_receipt,
        };
        payloads.clear();
        let refused = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "rust",
            true,
            vec![foreign],
            &mut payloads,
        );
        assert_eq!(refused.status, CapabilityStatus::Unavailable);
        assert_eq!(
            refused.reason_code.as_deref(),
            Some("provider_evidence_inconsistent")
        );
        assert!(payloads.is_empty());
    }

    /// RIGHT-REASON REGRESSION: the persistent gopls/scip-go composition is a
    /// distinct exact provider lineage, just like the retained rust-analyzer
    /// process. Final capability selection must not relabel or reject it merely
    /// because the older one-shot implementation used provider ID `scip-go`.
    #[test]
    fn calls_evidence_selection_retains_the_distinct_persistent_go_provider_lineage() {
        let receipt = CapabilityReceipt::complete(
            "calls",
            h00ligan_provider_protocol::H00_GO_PROVIDER_ID,
            "fixture-provider-1.0.0",
            calls_scope("go"),
            "d".repeat(64),
        );
        let evidence = ScipArtifactEvidence {
            language_id: LanguageId::new("go"),
            payload: Some(normalized_calls_payload(receipt.clone())),
            receipt: receipt.clone(),
        };
        let mut payloads = Vec::new();
        let selected = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "go",
            true,
            vec![evidence],
            &mut payloads,
        );
        assert_eq!(selected, receipt);
        assert_eq!(payloads.len(), 1);

        let unavailable_receipt = CapabilityReceipt::unavailable(
            "calls",
            h00ligan_provider_protocol::H00_GO_PROVIDER_ID,
            None,
            calls_scope("go"),
            None,
            "provider_document_omitted",
            "persistent Go provider fixture omitted a document",
        );
        let unavailable = ScipArtifactEvidence {
            language_id: LanguageId::new("go"),
            receipt: unavailable_receipt.clone(),
            payload: None,
        };
        payloads.clear();
        let selected = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "go",
            true,
            vec![unavailable],
            &mut payloads,
        );
        assert_eq!(selected, unavailable_receipt);
        assert_eq!(
            selected.provider_id.0,
            h00ligan_provider_protocol::H00_GO_PROVIDER_ID,
            "a persistent-provider failure must retain its real provider lineage"
        );
        assert!(payloads.is_empty());
    }

    /// RIGHT-REASON REGRESSION: the generic persistent-provider lifecycle and
    /// SCIP normalizer already admitted Python and TypeScript, but the final
    /// Calls boundary used a separate two-language whitelist and silently
    /// downgraded their exact evidence. Every product-native language must
    /// cross this last boundary under its real lineage; an unknown lineage
    /// remains a non-vacuous refusal control.
    #[test]
    fn product_native_python_and_typescript_evidence_crosses_final_admission() {
        for (language, expected_provider) in [
            (
                "python",
                h00ligan_provider_protocol::H00_PYREFLY_PROVIDER_ID,
            ),
            (
                "typescript",
                h00ligan_provider_protocol::H00_TYPESCRIPT_PROVIDER_ID,
            ),
        ] {
            let evidence = complete_calls_evidence(language);
            let expected_receipt = evidence.receipt.clone();
            let mut payloads = Vec::new();
            let selected = select_calls_evidence_for_test(
                ScipMode::Refresh,
                language,
                true,
                vec![evidence],
                &mut payloads,
            );
            assert_eq!(selected, expected_receipt);
            assert_eq!(selected.provider_id.0, expected_provider);
            assert_eq!(payloads.len(), 1, "{language} payload was not admitted");
        }

        let foreign_receipt = CapabilityReceipt::complete(
            "calls",
            "foreign-typescript-provider",
            "fixture-provider-1.0.0",
            calls_scope("typescript"),
            "e".repeat(64),
        );
        let foreign = ScipArtifactEvidence {
            language_id: LanguageId::new("typescript"),
            payload: Some(normalized_calls_payload(foreign_receipt.clone())),
            receipt: foreign_receipt,
        };
        let mut payloads = Vec::new();
        let refused = select_calls_evidence_for_test(
            ScipMode::Refresh,
            "typescript",
            true,
            vec![foreign],
            &mut payloads,
        );
        assert_eq!(refused.status, CapabilityStatus::Unavailable);
        assert_eq!(
            refused.reason_code.as_deref(),
            Some("provider_evidence_inconsistent")
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn supported_extensions_filter_by_language() {
        let config = IndexConfig {
            languages: vec!["rust".to_string()],
            ..Default::default()
        };
        let exts = supported_extensions(&config);
        assert!(exts.contains("rs"));
        assert_eq!(exts.len(), 1);
    }

    #[test]
    fn blocking_phase_discovers_and_extracts() {
        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());

        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            ..Default::default()
        };

        let existing = std::collections::HashMap::new();
        let result = IndexPipeline::blocking_phase(
            &config,
            &existing,
            &std::collections::HashMap::new(),
            KnowledgeGraph::new(),
        )
        .expect("blocking_phase");
        assert_eq!(result.discovered_paths.len(), 2);
        assert_eq!(result.changed_paths.len(), 2);
        assert_eq!(result.unchanged_count, 0);
        assert!(!result.outputs.is_empty());
        assert!(result.build_stats.nodes_added > 0);
    }

    #[test]
    fn structural_relationships_follow_exact_project_unit_dependencies() {
        let temporary = TempDir::new().expect("Cargo relationship repository");
        let root = temporary.path();
        for package in ["target", "caller", "independent"] {
            std::fs::create_dir_all(root.join(package).join("src"))
                .expect("package source directory");
        }
        std::fs::write(
            root.join("target/Cargo.toml"),
            "[package]\nname = \"target_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("target manifest");
        std::fs::write(
            root.join("caller/Cargo.toml"),
            concat!(
                "[package]\nname = \"caller\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                "\n[dependencies]\ntarget_pkg = { path = \"../target\" }\n",
            ),
        )
        .expect("caller manifest");
        std::fs::write(
            root.join("independent/Cargo.toml"),
            "[package]\nname = \"independent\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("independent manifest");
        std::fs::write(root.join("target/src/lib.rs"), "pub struct Widget;\n")
            .expect("target source");
        for package in ["caller", "independent"] {
            std::fs::write(
                root.join(package).join("src/lib.rs"),
                "use target_pkg::Widget;\npub fn consume(_: Widget) {}\n",
            )
            .expect("referencing source");
        }

        let sources = ["target", "caller", "independent"]
            .map(|package| InventorySource::new(format!("{package}/src/lib.rs"), "rust"));
        let inventory = build_project_inventory(root, &sources);
        let dependency_graph = inventory
            .project_topology
            .dependency_graphs
            .iter()
            .find(|graph| graph.language_id.0 == "rust")
            .expect("Cargo dependency authority");
        assert_eq!(
            dependency_graph.coverage,
            crate::code_intel_domain::ProjectUnitDependencyGraphCoverage::Complete,
            "positive control: dependency absence is authoritative"
        );
        assert_eq!(
            dependency_graph.project_unit_ids.len(),
            3,
            "unit population"
        );
        assert_eq!(
            dependency_graph.dependencies.len(),
            1,
            "only caller declares target_pkg"
        );

        let config = IndexConfig {
            root: root.to_path_buf(),
            full: true,
            languages: vec!["rust".into()],
            ..Default::default()
        };
        let result = IndexPipeline::blocking_phase(
            &config,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            KnowledgeGraph::new(),
        )
        .expect("structural graph");
        let node = |name: &str, file: &str| {
            result
                .graph
                .all_nodes()
                .into_iter()
                .find(|node| node.symbol_name == name && node.file_path == file)
                .unwrap_or_else(|| panic!("missing positive node {file}:{name}"))
                .memory_id
        };
        let target = node("Widget", "target/src/lib.rs");
        let caller_use = node("target_pkg::Widget", "caller/src/lib.rs");
        let independent_use = node("target_pkg::Widget", "independent/src/lib.rs");
        let references_target = |source| {
            result
                .graph
                .neighbors(&source)
                .into_iter()
                .any(|(candidate, edge)| {
                    candidate == target && edge.kind == crate::graph::EdgeKind::References
                })
        };
        assert!(
            references_target(caller_use),
            "positive control: a declared local dependency may resolve structurally"
        );
        assert!(
            !references_target(independent_use),
            "an independent package cannot acquire a relationship through a repository-global homonym"
        );
    }

    #[test]
    fn diff_detects_unchanged_files() {
        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());

        // First run: full index to populate state.
        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            ..Default::default()
        };
        let existing_empty = std::collections::HashMap::new();
        let result1 = IndexPipeline::blocking_phase(
            &config,
            &existing_empty,
            &std::collections::HashMap::new(),
            KnowledgeGraph::new(),
        )
        .expect("first run");
        assert_eq!(result1.changed_paths.len(), 2);

        // Build existing_files map from the first run's outputs.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut existing_populated = std::collections::HashMap::new();
        for output in &result1.outputs {
            let rel = PathBuf::from(&output.file_path)
                .strip_prefix(dir.path())
                .unwrap_or(&PathBuf::from(&output.file_path))
                .to_string_lossy()
                .to_string();
            let record = FileRecord {
                blake3_hash: output.file_hash.clone(),
                last_indexed: now_ms,
                symbol_count: output.symbols.len() as u32,
                language: "rust".into(),
            };
            existing_populated.insert(rel, record);
        }
        let existing_facts = result1
            .document_facts
            .iter()
            .cloned()
            .map(|facts| (facts.file_path.clone(), facts))
            .collect::<std::collections::HashMap<_, _>>();

        // Second run: incremental — nothing changed.
        let config2 = IndexConfig {
            root: dir.path().to_path_buf(),
            full: false,
            ..Default::default()
        };
        let result2 = IndexPipeline::blocking_phase(
            &config2,
            &existing_populated,
            &existing_facts,
            KnowledgeGraph::new(),
        )
        .expect("second run");
        assert_eq!(result2.unchanged_count, 2);
        assert_eq!(result2.changed_paths.len(), 0);
    }

    #[test]
    fn incremental_diff_reextracts_files_whose_document_facts_are_missing() {
        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());
        let full = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            ..Default::default()
        };
        let first = IndexPipeline::blocking_phase(
            &full,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            KnowledgeGraph::new(),
        )
        .expect("full extraction");
        let indexed_files = first
            .document_facts
            .iter()
            .map(|facts| {
                (
                    facts.file_path.clone(),
                    FileRecord {
                        blake3_hash: facts.file_hash.clone(),
                        last_indexed: 0,
                        symbol_count: facts.symbols.len() as u32,
                        language: "rust".into(),
                    },
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let incremental = IndexConfig {
            full: false,
            ..full
        };

        let repaired = IndexPipeline::blocking_phase(
            &incremental,
            &indexed_files,
            &std::collections::HashMap::new(),
            first.graph,
        )
        .expect("missing facts trigger safe re-extraction");
        assert_eq!(repaired.changed_paths.len(), 2);
        assert_eq!(repaired.unchanged_count, 0);
        assert_eq!(repaired.document_facts.len(), 2);
    }

    #[test]
    fn incremental_rebuild_preserves_relationships_from_unchanged_files() {
        let dir = TempDir::new().expect("tmpdir");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("mkdir src");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"incremental-facts\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("write Cargo.toml");
        fs::write(
            src.join("lib.rs"),
            "pub mod target;\npub use crate::target::Widget;\n",
        )
        .expect("write unchanged relationship source");
        let target = src.join("target.rs");
        fs::write(&target, "pub struct Widget;\n").expect("write relationship target");

        let full = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            languages: vec!["rust".to_string()],
            ..Default::default()
        };
        let first = IndexPipeline::blocking_phase(
            &full,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            KnowledgeGraph::new(),
        )
        .expect("full structural build");

        let widget_id = first
            .graph
            .all_nodes()
            .into_iter()
            .find(|node| {
                node.file_path == "src/target.rs"
                    && node.symbol_name == "Widget"
                    && node.kind == "struct"
            })
            .expect("full build must materialize the target node")
            .memory_id;
        let reference_id = first
            .graph
            .all_edges()
            .into_iter()
            .find(|(_, target, edge)| {
                *target == widget_id && edge.kind == crate::graph::EdgeKind::References
            })
            .map(|(source, _, _)| source)
            .expect("positive control: full build must resolve the cross-file reference");

        let symbol_counts = first
            .outputs
            .iter()
            .map(|output| (output.file_path.as_str(), output.symbols.len() as u32))
            .collect::<std::collections::HashMap<_, _>>();
        let indexed_files = first
            .source_inputs
            .iter()
            .map(|input| {
                (
                    input.relative_path.clone(),
                    FileRecord {
                        blake3_hash: input.content_hash.clone(),
                        last_indexed: 0,
                        symbol_count: symbol_counts
                            .get(input.relative_path.as_str())
                            .copied()
                            .unwrap_or_default(),
                        language: input.language.clone(),
                    },
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let indexed_facts = first
            .document_facts
            .iter()
            .cloned()
            .map(|facts| (facts.file_path.clone(), facts))
            .collect::<std::collections::HashMap<_, _>>();

        // Change only the target file while retaining the referenced symbol.
        // A correct incremental resolver must restore the unchanged lib.rs use
        // edge after target invalidation recreates Widget.
        fs::write(
            &target,
            "pub struct Widget;\nimpl Widget { pub fn new() -> Self { Self } }\n",
        )
        .expect("modify relationship target");
        let incremental = IndexConfig {
            full: false,
            ..full
        };
        let second = IndexPipeline::blocking_phase(
            &incremental,
            &indexed_files,
            &indexed_facts,
            first.graph,
        )
        .expect("incremental structural build");

        assert_eq!(second.changed_paths, vec![target]);
        assert_eq!(
            second.unchanged_count, 1,
            "the relationship source must remain unchanged so the test exercises re-resolution"
        );
        assert!(
            second.graph.node(&reference_id).is_some(),
            "the unchanged reference source node must survive"
        );
        assert!(
            second.graph.node(&widget_id).is_some(),
            "the changed target node must be recreated with stable identity"
        );
        assert!(
            second
                .graph
                .all_edges()
                .into_iter()
                .any(|(source, target, edge)| {
                    source == reference_id
                        && target == widget_id
                        && edge.kind == crate::graph::EdgeKind::References
                }),
            "incremental target replacement must re-resolve relationships originating in unchanged files"
        );
    }

    #[tokio::test]
    async fn persisted_incremental_run_re_resolves_unchanged_relationship_sources() {
        let dir = TempDir::new().expect("tmpdir");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("mkdir src");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"incremental-facts\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("write Cargo.toml");
        fs::write(
            src.join("lib.rs"),
            "pub mod target;\npub use crate::target::Widget;\n",
        )
        .expect("write unchanged relationship source");
        let target = src.join("target.rs");
        fs::write(&target, "pub struct Widget;\n").expect("write relationship target");

        let state = IndexState::new_test(dir.path()).expect("open index state");
        let graph_db = Arc::new(
            redb::Database::create(dir.path().join("graph.redb")).expect("create graph database"),
        );
        let graph_store = GraphStore::new(graph_db);
        let full = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            languages: vec!["rust".to_string()],
            ..Default::default()
        };
        IndexPipeline::run(&state, Some(&graph_store), &full, None)
            .await
            .expect("full pipeline run");

        fs::write(
            &target,
            "pub struct Widget;\nimpl Widget { pub fn new() -> Self { Self } }\n",
        )
        .expect("modify relationship target");
        let incremental = IndexConfig {
            full: false,
            ..full
        };
        let report = IndexPipeline::run(&state, Some(&graph_store), &incremental, None)
            .await
            .expect("incremental pipeline run");
        assert_eq!(report.files_changed, 1);
        assert_eq!(report.files_unchanged, 1);

        let graph = graph_store
            .load_snapshot()
            .await
            .expect("load graph snapshot")
            .expect("persisted graph snapshot");
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
            "production pipeline must rebuild references from unchanged document facts"
        );
    }

    #[tokio::test]
    async fn full_pipeline_run() {
        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());

        let state = IndexState::new_test(dir.path()).expect("open state");
        let (progress, mut progress_events) = tokio::sync::mpsc::unbounded_channel();
        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            progress: Some(progress),
            ..Default::default()
        };

        let report = IndexPipeline::run(&state, None, &config, None)
            .await
            .expect("pipeline run");

        assert_eq!(report.files_discovered, 2);
        assert_eq!(report.files_changed, 2);
        assert!(report.symbols_extracted > 0);
        assert!(report.nodes_added > 0);
        assert!(report.duration.as_nanos() > 0);
        assert!(report.phase_timings.iter().any(|timing| {
            timing.phase == IndexProgressPhase::Structural && timing.duration.as_nanos() > 0
        }));
        assert!(report.phase_timings.iter().any(|timing| {
            timing.phase == IndexProgressPhase::Finalize && timing.duration.as_nanos() > 0
        }));

        let mut events = Vec::new();
        while let Ok(event) = progress_events.try_recv() {
            events.push(event);
        }
        assert!(events.iter().any(|event| {
            event.phase == IndexProgressPhase::Structural
                && event.state == IndexProgressState::Started
        }));
        assert!(events.iter().any(|event| {
            event.phase == IndexProgressPhase::Structural
                && event.state == IndexProgressState::Completed
        }));
        assert!(events.iter().any(|event| {
            event.phase == IndexProgressPhase::Finalize
                && event.state == IndexProgressState::Completed
        }));
    }

    /// Provider refresh owns only its disposable workspace. Conventional SCIP
    /// filenames already present in the indexed project are unrelated source
    /// material: they are neither ingested nor mutated.
    #[tokio::test]
    async fn provider_refresh_preserves_project_root_scip_artifacts() {
        let dir = TempDir::new().expect("tmpdir");
        fs::create_dir_all(dir.path().join("src")).expect("mkdir src");
        fs::write(dir.path().join("src/lib.rs"), "pub fn fixture() {}\n").expect("write source");
        fs::write(dir.path().join("index.scip"), b"stale rust scip")
            .expect("write primary sentinel");
        fs::write(dir.path().join("index.go.scip"), b"stale go scip")
            .expect("write secondary sentinel");

        let state = IndexState::new_test(dir.path()).expect("open state");
        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            scip: ScipMode::Refresh,
            ..Default::default()
        };

        // This fixture deliberately has no Cargo.toml or go.mod, so generation
        // soft-skips without invoking an external tool. The preservation check
        // still proves root artifacts are outside the provider workspace.
        let _ = IndexPipeline::run(&state, None, &config, None).await;

        assert_eq!(
            fs::read(dir.path().join("index.scip")).expect("primary sentinel"),
            b"stale rust scip",
            "provider refresh must preserve the primary project-root artifact"
        );
        assert_eq!(
            fs::read(dir.path().join("index.go.scip")).expect("secondary sentinel"),
            b"stale go scip",
            "provider refresh must preserve the secondary project-root artifact"
        );
    }

    #[tokio::test]
    async fn dry_run_does_not_extract() {
        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());

        let state = IndexState::new_test(dir.path()).expect("open state");
        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            dry_run: true,
            ..Default::default()
        };

        let report = IndexPipeline::run(&state, None, &config, None)
            .await
            .expect("dry run");

        assert_eq!(report.files_discovered, 2);
        assert_eq!(report.files_changed, 2);
        // dry_run exits before extract, so symbols should be 0.
        assert_eq!(report.symbols_extracted, 0);
        assert!(
            report.evidence().is_none(),
            "a diff-only dry run must never expose publishable capability evidence"
        );
    }

    #[tokio::test]
    async fn extraction_failure_downgrades_only_the_affected_language_receipt() {
        use crate::code_intel_domain::{CapabilityScope, CapabilityStatus};

        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());
        fs::write(
            dir.path().join("main.go"),
            "package main\nfunc validGo() int { return 1 }\n",
        )
        .expect("valid Go source");
        fs::write(dir.path().join("broken.go"), [0xff, 0xfe, 0xfd])
            .expect("invalid UTF-8 Go source");

        let state = IndexState::new_test(dir.path()).expect("open state");
        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            ..Default::default()
        };
        let outcome = IndexPipeline::run(&state, None, &config, None)
            .await
            .expect("pipeline run");
        let receipts = &outcome
            .evidence()
            .expect("completed run evidence")
            .capability_receipts;

        let structural = |language: &str| {
            receipts
                .iter()
                .find(|receipt| {
                    receipt.capability_id == "structural_graph"
                        && matches!(
                            &receipt.scope,
                            CapabilityScope::Language { language_id, .. }
                                if language_id.0 == language
                        )
                })
                .unwrap_or_else(|| panic!("missing structural receipt for {language}"))
        };
        assert_eq!(structural("rust").status, CapabilityStatus::Complete);
        assert_eq!(structural("go").status, CapabilityStatus::Partial);
        assert_eq!(
            structural("go").reason_code.as_deref(),
            Some("source_extraction_failed")
        );

        let failed_record = state
            .get_file("broken.go")
            .expect("read failed source record")
            .expect("failed source remains in the measured population");
        assert_eq!(failed_record.symbol_count, 0);
        assert_eq!(
            failed_record.blake3_hash,
            blake3::hash(&[0xff, 0xfe, 0xfd]).to_hex().to_string()
        );
        assert!(
            state
                .all_document_facts()
                .expect("read document facts")
                .iter()
                .all(|facts| facts.file_path != "broken.go"),
            "failed extraction must not retain stale document facts"
        );

        let retry = IndexConfig {
            full: false,
            ..config
        };
        let retry = IndexPipeline::run(&state, None, &retry, None)
            .await
            .expect("retry partial generation");
        assert_eq!(
            retry.files_changed, 1,
            "missing facts must retry the failed document without reparsing covered files"
        );
    }

    #[tokio::test]
    async fn capture_gap_downgrades_only_the_affected_language_receipt() {
        use crate::code_intel_domain::{CapabilityScope, CapabilityStatus};

        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());
        fs::write(
            dir.path().join("contracts.ts"),
            "const base = { value: 1 };\nexport const extended = { ...base };\n",
        )
        .expect("valid partially represented TypeScript source");

        let state = IndexState::new_test(dir.path()).expect("open state");
        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            ..Default::default()
        };
        let outcome = IndexPipeline::run(&state, None, &config, None)
            .await
            .expect("pipeline run");
        let evidence = outcome.evidence().expect("completed run evidence");
        let structural = |language: &str| {
            evidence
                .capability_receipts
                .iter()
                .find(|receipt| {
                    receipt.capability_id == "structural_graph"
                        && matches!(
                            &receipt.scope,
                            CapabilityScope::Language { language_id, .. }
                                if language_id.0 == language
                        )
                })
                .unwrap_or_else(|| panic!("missing structural receipt for {language}"))
        };
        assert_eq!(structural("rust").status, CapabilityStatus::Complete);
        let typescript = structural("typescript");
        assert_eq!(typescript.status, CapabilityStatus::Partial);
        assert_eq!(
            typescript.reason_code.as_deref(),
            Some("structural_capture_incomplete")
        );
        assert!(
            typescript.reason.as_deref().is_some_and(|detail| {
                detail.contains("unrepresented_object_spread=1 [contracts.ts]")
            }),
            "bounded receipt detail must bind each reported gap kind to a real affected file"
        );

        let inventory = evidence
            .source_inventory
            .iter()
            .find(|inventory| inventory.language_id.0 == "typescript")
            .expect("TypeScript source inventory");
        assert_eq!(inventory.files_discovered, 1);
        assert_eq!(inventory.files_covered, 0);
        assert_eq!(inventory.extraction_failures, 0);
    }

    /// RIGHT-REASON REGRESSION: a truthful Partial structural receipt still
    /// binds an exact graph to its indexed source bytes and extractor identity.
    /// Requiring Complete here made every WATCH epoch over a known capture gap
    /// discard its reusable basis and reparse the entire repository.
    #[tokio::test]
    async fn partial_structural_receipt_is_exact_reuse_evidence_for_unchanged_records() {
        use crate::code_intel_domain::{CapabilityScope, CapabilityStatus};

        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());
        fs::write(
            dir.path().join("contracts.ts"),
            "const base = { value: 1 };\nexport const extended = { ...base };\n",
        )
        .expect("valid partially represented TypeScript source");

        let state = IndexState::new_test(dir.path()).expect("open state");
        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            ..Default::default()
        };
        let outcome = IndexPipeline::run(&state, None, &config, None)
            .await
            .expect("pipeline run");
        let receipts = outcome
            .evidence()
            .expect("completed run evidence")
            .capability_receipts
            .clone();
        let indexed_files = state.all_files().expect("indexed file population");
        let typescript = receipts
            .iter()
            .find(|receipt| {
                receipt.capability_id == "structural_graph"
                    && matches!(
                        &receipt.scope,
                        CapabilityScope::Language { language_id, .. }
                            if language_id.0 == "typescript"
                    )
            })
            .expect("TypeScript structural receipt");
        assert_eq!(typescript.status, CapabilityStatus::Partial);
        assert_eq!(indexed_files.len(), 3, "positive indexed population");
        assert!(
            structural_receipts_match_records(&receipts, &indexed_files, &config.exclude),
            "an exact Partial receipt must authorize reuse without claiming Complete coverage"
        );

        let mut wrong_fingerprint = receipts.clone();
        wrong_fingerprint
            .iter_mut()
            .find(|receipt| receipt.status == CapabilityStatus::Partial)
            .expect("partial sabotage target")
            .input_fingerprint = Some("0".repeat(64));
        assert!(
            !structural_receipts_match_records(&wrong_fingerprint, &indexed_files, &config.exclude),
            "a Partial label must not override a changed source fingerprint"
        );

        let mut unavailable = receipts.clone();
        unavailable
            .iter_mut()
            .find(|receipt| receipt.status == CapabilityStatus::Partial)
            .expect("unavailable sabotage target")
            .status = CapabilityStatus::Unavailable;
        assert!(
            !structural_receipts_match_records(&unavailable, &indexed_files, &config.exclude),
            "Unavailable structural evidence must remain inadmissible"
        );

        let mut foreign_extractor = receipts;
        foreign_extractor
            .iter_mut()
            .find(|receipt| receipt.status == CapabilityStatus::Partial)
            .expect("extractor sabotage target")
            .provider_version = Some("foreign-extractor".into());
        assert!(
            !structural_receipts_match_records(&foreign_extractor, &indexed_files, &config.exclude),
            "Partial evidence from another extractor identity must remain inadmissible"
        );
    }

    #[tokio::test]
    async fn rust_item_macro_receipt_names_missing_expansion_authority() {
        use crate::code_intel_domain::{CapabilityScope, CapabilityStatus};

        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());
        fs::write(
            dir.path().join("src/generated.rs"),
            "macro_rules! generate { ($name:ident) => { pub struct $name; } }\n\
             generate!(Generated);\n",
        )
        .expect("valid item-macro source");

        let state = IndexState::new_test(dir.path()).expect("open state");
        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            ..Default::default()
        };
        let outcome = IndexPipeline::run(&state, None, &config, None)
            .await
            .expect("pipeline run");
        let evidence = outcome.evidence().expect("completed run evidence");
        let rust = evidence
            .capability_receipts
            .iter()
            .find(|receipt| {
                receipt.capability_id == "structural_graph"
                    && matches!(
                        &receipt.scope,
                        CapabilityScope::Language { language_id, .. }
                            if language_id.0 == "rust"
                    )
            })
            .expect("Rust structural receipt");

        assert_eq!(rust.status, CapabilityStatus::Partial);
        assert_eq!(
            rust.reason_code.as_deref(),
            Some("structural_capture_incomplete")
        );
        assert!(
            rust.reason.as_deref().is_some_and(|detail| {
                detail.contains("unexpanded_rust_item_macro=1 [src/generated.rs]")
            }),
            "the shipped receipt must name unavailable macro expansion, not a tree-sitter expression wrapper"
        );

        let inventory = evidence
            .source_inventory
            .iter()
            .find(|inventory| inventory.language_id.0 == "rust")
            .expect("Rust source inventory");
        assert_eq!(inventory.files_discovered, 3, "positive source population");
        assert_eq!(inventory.files_covered, 2);
        assert_eq!(inventory.extraction_failures, 0);
    }

    #[tokio::test]
    async fn scip_refresh_never_mutates_dry_run_or_disabled_mode() {
        for (case, dry_run, scip) in [
            ("dry-run", true, ScipMode::Refresh),
            ("disabled", false, ScipMode::Disabled),
        ] {
            let dir = TempDir::new().expect("tmpdir");
            create_test_project(dir.path());
            let state = IndexState::new_test(dir.path()).expect("open state");
            let scip_path = dir.path().join("index.scip");
            let sentinel = format!("{case}-sentinel").into_bytes();
            fs::write(&scip_path, &sentinel).expect("write SCIP sentinel");

            let config = IndexConfig {
                root: dir.path().to_path_buf(),
                full: true,
                dry_run,
                scip,
                ..Default::default()
            };
            IndexPipeline::run(&state, None, &config, None)
                .await
                .unwrap_or_else(|error| panic!("{case} pipeline: {error}"));

            assert_eq!(
                fs::read(&scip_path).expect("read preserved SCIP sentinel"),
                sentinel,
                "{case} must preserve unrelated project-root artifacts"
            );
        }
    }

    /// Structural-only mode neither triggers provider execution nor loads an
    /// ambient project-root artifact.
    #[tokio::test]
    async fn disabled_mode_preserves_existing_scip_without_loading_or_regeneration() {
        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());

        let state = IndexState::new_test(dir.path()).expect("open state");

        // --- Run 1: full index to populate state ---
        let config1 = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            scip: ScipMode::Disabled,
            ..Default::default()
        };
        let report1 = IndexPipeline::run(&state, None, &config1, None)
            .await
            .expect("first run");
        assert!(report1.files_changed > 0, "first run should index files");

        // --- Place a sentinel index.scip file ---
        // This simulates unrelated project data with a conventional provider
        // filename. The pipeline must not overwrite or ingest it.
        let sentinel_content = b"SENTINEL_SCIP_DATA_DO_NOT_OVERWRITE";
        let scip_path = dir.path().join("index.scip");
        fs::write(&scip_path, sentinel_content).expect("write sentinel");

        // --- Modify a source file so files_changed > 0 on incremental ---
        let main_rs = dir.path().join("src").join("main.rs");
        fs::write(&main_rs, "fn main() { println!(\"modified\"); }\n").expect("modify main.rs");

        // --- Run 2: structural-only incremental reindex. ---
        let config2 = IndexConfig {
            root: dir.path().to_path_buf(),
            full: false,
            scip: ScipMode::Disabled,
            ..Default::default()
        };
        let report2 = IndexPipeline::run(&state, None, &config2, None)
            .await
            .expect("incremental run");

        // The incremental run should detect the changed file.
        assert!(
            report2.files_changed > 0,
            "incremental run should detect modified main.rs"
        );

        // The sentinel index.scip must still exist with original content. A
        // structural-only run neither invokes a provider nor ingests ambient
        // compiler output.
        assert!(scip_path.exists(), "index.scip should still exist");
        let actual_content = fs::read(&scip_path).expect("read sentinel");
        assert_eq!(
            actual_content, sentinel_content,
            "index.scip should be untouched — SCIP regeneration should NOT have triggered"
        );
    }

    /// After a full pipeline run with a graph store, every node in the
    /// persisted graph must have `reachability_class` populated (not `None`).
    /// This prevents the 5-7s `needs_analysis` penalty in tool handlers
    /// like `signature_check` and `is_wired`.
    #[tokio::test]
    async fn index_pipeline_sets_reachability_on_all_nodes() {
        let dir = TempDir::new().expect("tmpdir");

        // Create a minimal Cargo project so `discover_entry_points` succeeds.
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("mkdir src");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write Cargo.toml");
        fs::write(
            src.join("main.rs"),
            "fn main() { helper(); }\nfn helper() { println!(\"hi\"); }\n",
        )
        .expect("write main.rs");
        fs::write(
            src.join("lib.rs"),
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        )
        .expect("write lib.rs");

        let state = IndexState::new_test(dir.path()).expect("open state");

        // Open a redb database for the graph store.
        let db_path = dir.path().join("graph.redb");
        let db = Arc::new(redb::Database::create(&db_path).expect("create redb"));
        let graph_store = GraphStore::new(db);

        let config = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            scip: ScipMode::Disabled,
            ..Default::default()
        };

        let report = IndexPipeline::run(&state, Some(&graph_store), &config, None)
            .await
            .expect("pipeline run");

        assert!(report.nodes_added > 0, "pipeline should discover nodes");

        // Load the persisted graph and verify reachability.
        let graph = graph_store
            .load_snapshot()
            .await
            .expect("load snapshot")
            .expect("snapshot should exist");

        let all_nodes = graph.all_nodes();
        assert!(
            !all_nodes.is_empty(),
            "graph should contain at least one node"
        );

        for node in &all_nodes {
            // WU-0003 RC5: after indexing + classification, every node must have
            // a real class — NOT the `Unclassified` sentinel. (The RC4 chokepoint
            // guarantee that classification ran is extended in Leg C.)
            assert_ne!(
                node.reachability_class,
                crate::reachability::ReachabilityClass::Unclassified,
                "node '{}' in {} should have reachability_class set, but it is Unclassified",
                node.symbol_name,
                node.file_path,
            );
        }
    }

    /// FALSIFIER (WU-0003 / CL-REACH clear-on-schema-bump, pipeline layer):
    /// a code-intel graph store written under an OLDER schema (an undecodable
    /// snapshot + no version stamp), with the index-state file-hashes SURVIVING,
    /// must on the next reindex (1) NOT hard-error, and (2) REBUILD the graph
    /// from source rather than leaving it empty.
    ///
    /// RED before the fix: the snapshot-discard left the graph empty because the
    /// incremental diff saw unchanged file hashes and re-extracted nothing — the
    /// migration hole that wiped the live user graph to 0 nodes. GREEN after:
    /// `load_snapshot_or_clear` reports `cleared`, the pipeline forces a full
    /// re-extract, and the graph comes back populated.
    #[tokio::test]
    async fn schema_bump_forces_full_rebuild_not_empty_graph() {
        use redb::{ReadableDatabase, TableDefinition};

        let dir = TempDir::new().expect("tmpdir");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("mkdir src");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write Cargo.toml");
        fs::write(
            src.join("main.rs"),
            "fn main() { helper(); }\nfn helper() { println!(\"hi\"); }\n",
        )
        .expect("write main.rs");

        let state = IndexState::new_test(dir.path()).expect("open state");
        let db_path = dir.path().join("graph.redb");
        let db = Arc::new(redb::Database::create(&db_path).expect("create redb"));
        let graph_store = GraphStore::new(Arc::clone(&db));

        // --- Run 1: full index populates graph + index-state hashes ---
        let config_full = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            scip: ScipMode::Disabled,
            ..Default::default()
        };
        let report1 = IndexPipeline::run(&state, Some(&graph_store), &config_full, None)
            .await
            .expect("first run");
        assert!(
            report1.nodes_added > 0,
            "first run should populate the graph"
        );

        // --- Simulate a SCHEMA BUMP: overwrite the snapshot with an undecodable
        //     blob and remove the version stamp, mimicking a store written by an
        //     OLDER binary. The index-state (index.redb) hashes are LEFT INTACT,
        //     reproducing the migration hole's preconditions exactly. ---
        const GRAPH_SNAPSHOT: TableDefinition<&str, &[u8]> = TableDefinition::new("graph_snapshot");
        const GRAPH_META: TableDefinition<&str, u64> = TableDefinition::new("graph_meta");
        {
            let txn = db.begin_write().expect("begin write");
            {
                let mut snap = txn.open_table(GRAPH_SNAPSHOT).expect("snap");
                snap.insert("latest", b"\xff\xff\xff\xff\xff\xff\xff\xff".as_slice())
                    .expect("poison snapshot");
                // Clear any version stamp so it reads as a pre-bump store.
                let mut meta = txn.open_table(GRAPH_META).expect("meta");
                meta.retain(|_, _| false).expect("clear meta");
            }
            txn.commit().expect("commit");
        }

        // Sanity: the index-state still records the files (so a naive incremental
        // would extract nothing).
        assert!(
            !state.all_files().expect("all_files").is_empty(),
            "index-state hashes must survive the graph poison (precondition for the hole)"
        );

        // --- Run 2: INCREMENTAL reindex on the poisoned store. The fix must
        //     detect the schema bump, clear+rebuild, and NOT leave 0 nodes. ---
        let config_incr = IndexConfig {
            root: dir.path().to_path_buf(),
            full: false, // incremental — the bug's trigger
            scip: ScipMode::Disabled,
            ..Default::default()
        };
        let report2 = IndexPipeline::run(&state, Some(&graph_store), &config_incr, None)
            .await
            .expect("incremental reindex must NOT hard-error on a schema-bumped store");

        assert!(
            report2.nodes_added > 0,
            "schema-bump must force a FULL re-extract: graph rebuilt, NOT left empty \
             (nodes_added = {})",
            report2.nodes_added
        );

        // The persisted graph must come back populated (not the wiped 0-node state).
        let graph = graph_store
            .load_snapshot()
            .await
            .expect("load")
            .expect("a rebuilt graph must exist");
        assert!(
            graph.node_count() > 0,
            "after a schema-bump reindex the graph must be REBUILT, not wiped to 0 nodes"
        );

        // The version stamp must now be the current one, so a subsequent index
        // does NOT spuriously clear again.
        let read = db.begin_read().expect("read");
        let meta = read.open_table(GRAPH_META).expect("meta");
        assert!(
            meta.get("schema_version").expect("get").is_some(),
            "after rebuild the schema version must be stamped"
        );
    }

    /// A current file-hash index is not, by itself, an incremental graph basis.
    /// If `index.redb` survives while `graph.redb` is absent, every source may
    /// compare unchanged even though there are no prior graph nodes to carry
    /// forward. The pipeline must rebuild from the locally available sources
    /// before it can issue Complete structural evidence.
    #[tokio::test]
    async fn incremental_run_rebuilds_when_file_state_survives_but_graph_basis_is_missing() {
        let dir = TempDir::new().expect("tmpdir");
        create_test_project(dir.path());

        let state = IndexState::new_test(dir.path()).expect("open state");
        let graph_path = dir.path().join("graph.redb");
        let graph_db = Arc::new(redb::Database::create(&graph_path).expect("create graph db"));
        let graph_store = GraphStore::new(Arc::clone(&graph_db));
        let full = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            scip: ScipMode::Disabled,
            ..Default::default()
        };

        let initial = IndexPipeline::run(&state, Some(&graph_store), &full, None)
            .await
            .expect("initial full run");
        assert!(
            initial.nodes_added > 0,
            "full run must establish a graph basis"
        );

        let incremental = IndexConfig {
            full: false,
            ..full.clone()
        };
        let healthy = IndexPipeline::run(&state, Some(&graph_store), &incremental, None)
            .await
            .expect("healthy incremental run");
        assert_eq!(
            healthy.files_changed, 0,
            "a usable prior graph must not spuriously force full extraction"
        );
        assert!(
            graph_store
                .load_snapshot()
                .await
                .expect("load healthy graph")
                .expect("healthy graph snapshot")
                .node_count()
                > 0,
            "the unchanged incremental control must retain its prior graph"
        );

        drop(graph_store);
        drop(graph_db);
        fs::remove_file(&graph_path).expect("remove only the scratch graph basis");
        assert!(
            !state.all_files().expect("surviving file state").is_empty(),
            "the falsifier requires unchanged file hashes to survive"
        );
        let replacement_db =
            Arc::new(redb::Database::create(&graph_path).expect("create empty replacement graph"));
        let replacement_store = GraphStore::new(replacement_db);
        let recovered = IndexPipeline::run(&state, Some(&replacement_store), &incremental, None)
            .await
            .expect("incremental run with missing graph basis");

        assert!(
            recovered.files_changed > 0,
            "missing prior graph basis must force source re-extraction despite surviving hashes"
        );
        let rebuilt = replacement_store
            .load_snapshot()
            .await
            .expect("load rebuilt graph")
            .expect("rebuilt graph snapshot");
        assert!(
            rebuilt.node_count() > 0,
            "missing prior graph basis must rebuild a populated graph"
        );
        assert!(
            recovered
                .evidence()
                .expect("completed evidence")
                .capability_receipts
                .iter()
                .filter(|receipt| receipt.capability_id == "structural_graph")
                .all(|receipt| {
                    receipt.status == crate::code_intel_domain::CapabilityStatus::Complete
                }),
            "Complete structural receipts are justified only after the forced rebuild"
        );
    }

    /// FALSIFIER (WU-0003 / CL-REACH read-path blocker, pipeline layer): the
    /// read-clear → incremental-index ORDERING. A READ command (`load_snapshot`)
    /// fired FIRST against a schema-stale store, FOLLOWED by an incremental
    /// `index`, must still REBUILD the graph — the read must not have erased the
    /// staleness signal the index path keys off.
    ///
    /// RED before the fix: `load_snapshot` delegated to `load_snapshot_or_clear`,
    /// which on the stale store CLEARED the `GRAPH_*` tables AND STAMPED the
    /// current `SCHEMA_VERSION`. The read does no rebuild, so the next incremental
    /// index sees `has_persisted_data = false` / version already current →
    /// `cleared = false` → no forced full → surviving `index.redb` hashes →
    /// `files_changed = 0` → graph PERMANENTLY at 0 nodes. (Driven firsthand:
    /// status-first on a stale scratch store → incremental index → 0 nodes,
    /// stays 0.)
    ///
    /// GREEN after the fix: the read path is discard-without-clear, the stale
    /// store stays detectably-stale on disk, so the incremental index's
    /// version-mismatch detection still fires → clears + force-fulls → rebuilds
    /// with `nodes_added > 0`.
    #[tokio::test]
    async fn read_load_then_incremental_index_recovers() {
        use redb::{ReadableDatabase, TableDefinition};

        let dir = TempDir::new().expect("tmpdir");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("mkdir src");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write Cargo.toml");
        fs::write(
            src.join("main.rs"),
            "fn main() { helper(); }\nfn helper() { println!(\"hi\"); }\n",
        )
        .expect("write main.rs");

        let state = IndexState::new_test(dir.path()).expect("open state");
        let db_path = dir.path().join("graph.redb");
        let db = Arc::new(redb::Database::create(&db_path).expect("create redb"));
        let graph_store = GraphStore::new(Arc::clone(&db));

        // --- Run 1: full index populates graph + index-state hashes ---
        let config_full = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            scip: ScipMode::Disabled,
            ..Default::default()
        };
        let report1 = IndexPipeline::run(&state, Some(&graph_store), &config_full, None)
            .await
            .expect("first run");
        assert!(
            report1.nodes_added > 0,
            "first run should populate the graph"
        );

        // --- Simulate a SCHEMA BUMP: undecodable snapshot + no version stamp,
        //     index-state (index.redb) hashes LEFT INTACT (the hole's
        //     preconditions). ---
        const GRAPH_SNAPSHOT: TableDefinition<&str, &[u8]> = TableDefinition::new("graph_snapshot");
        const GRAPH_META: TableDefinition<&str, u64> = TableDefinition::new("graph_meta");
        {
            let txn = db.begin_write().expect("begin write");
            {
                let mut snap = txn.open_table(GRAPH_SNAPSHOT).expect("snap");
                snap.insert("latest", b"\xff\xff\xff\xff\xff\xff\xff\xff".as_slice())
                    .expect("poison snapshot");
                let mut meta = txn.open_table(GRAPH_META).expect("meta");
                meta.retain(|_, _| false).expect("clear meta");
            }
            txn.commit().expect("commit");
        }

        // --- READ FIRST: a read-intent command loads the stale store. On the
        //     BUGGY tree this clears + stamps the version (erasing the signal).
        //     On the FIXED tree it discards-without-clear (signal survives). ---
        let read_loaded = graph_store
            .load_snapshot()
            .await
            .expect("read load must not hard-error on a stale store");
        assert!(
            read_loaded.is_none(),
            "the read on a stale store yields no usable graph"
        );

        // Sanity: index-state hashes still present (a naive incremental would
        // extract nothing).
        assert!(
            !state.all_files().expect("all_files").is_empty(),
            "index-state hashes must survive (precondition for the hole)"
        );

        // --- Run 2: INCREMENTAL index AFTER the read. The fix must STILL detect
        //     the staleness (the read left it intact) and rebuild — NOT 0 nodes. ---
        let config_incr = IndexConfig {
            root: dir.path().to_path_buf(),
            full: false, // incremental — the bug's trigger
            scip: ScipMode::Disabled,
            ..Default::default()
        };
        let report2 = IndexPipeline::run(&state, Some(&graph_store), &config_incr, None)
            .await
            .expect("incremental reindex must NOT hard-error after a read on a stale store");

        assert!(
            report2.nodes_added > 0,
            "read-first must NOT erase the recovery signal: the incremental index \
             must still force a FULL re-extract and REBUILD the graph, NOT leave it \
             at 0 nodes (nodes_added = {})",
            report2.nodes_added
        );

        // The persisted graph must come back populated, NOT the wiped 0-node state.
        let graph = graph_store
            .load_snapshot()
            .await
            .expect("load")
            .expect("a rebuilt graph must exist after the recovering index");
        assert!(
            graph.node_count() > 0,
            "after read-first + incremental index the graph must be REBUILT, not 0 nodes"
        );

        // And the version stamp must now be current (the index path stamped it),
        // so a subsequent index does not spuriously clear again.
        let read = db.begin_read().expect("read");
        let meta = read.open_table(GRAPH_META).expect("meta");
        assert!(
            meta.get("schema_version").expect("get").is_some(),
            "after the recovering index the schema version must be stamped"
        );
    }

    /// FALSIFIER (WU-0003 / CL-REACH, RC4): this test guards the **8b-before-8c**
    /// ordering ONLY — Phase-8c enrichment must observe a CLASSIFIED graph, i.e.
    /// reachability classification (`classify_and_writeback`, Phase 8b) MUST run
    /// BEFORE enrichment (Phase 8c).
    ///
    /// SCOPE — what this does NOT guard: it does NOT guard the C1 **8d-before-8b**
    /// reorder (running Phase-8d inter-crate `DependsOn` edges BEFORE Phase-8b
    /// classification). Reverting that reorder leaves this test GREEN: its fixture
    /// is single-crate, so it has zero `DependsOn` edges and the 8d/8b order is
    /// invisible to it.
    ///
    /// (CL-EDGE LANDED, WU-0001 reopen.) `edge_builder::build_dependency_edges`
    /// NOW parses Cargo manifests via `toml::from_str` (was `content.parse()` /
    /// `FromStr`, which ERRORED on a real multi-section manifest under
    /// `toml = "1.0.6"` and short-circuited to `Ok(0)`), so Phase-8d again emits
    /// inter-crate `DependsOn` edges for a real workspace. The CL-EDGE bug is
    /// captured + reproduced by the now-un-ignored
    /// `edge_builder::tests::build_dependency_edges_emits_cross_crate_dependson`.
    /// A genuine falsifier for the 8d-before-8b reorder (R5-F1) is therefore now
    /// UNBLOCKED as a follow-up WU; until it lands, this test still only guards
    /// 8b-before-8c (its single-crate fixture has zero `DependsOn` edges).
    ///
    /// `enrichment::compute_node_enrichments` assigns `depth_from_entry =
    /// Some(0)` ONLY to a `Wired`/`PublicApi` node that is an entry root (see
    /// enrichment.rs Pass 2, ~line 224-242). If enrichment ran against an
    /// all-`Unclassified` graph (the bug — enrichment before classification),
    /// the `is_entry`/`is_main` predicates are never satisfied and NO node gets
    /// `depth_from_entry == Some(0)`. So a single `Some(0)` is a non-vacuous
    /// proof that the graph enrichment saw was already classified.
    ///
    /// Fixture: a real Cargo crate `fn main(){helper();} fn helper(){}` — `main`
    /// classifies as `Wired` (it is an entry point) and the enrichment entry
    /// predicate matches it (`symbol_name.contains("main")` + `Wired`), so a
    /// correct ordering yields `main.depth_from_entry == Some(0)`.
    ///
    /// RED-PROOF (recorded, then reverted in place): temporarily neutering the
    /// Phase-8b write-back so enrichment sees an all-`Unclassified` graph makes
    /// this test FAIL at the depth assert (no node carries `Some(0)`), confirming
    /// the assertion is non-vacuous and genuinely guards the 8b-before-8c ordering.
    #[tokio::test]
    async fn enrichment_observes_classified_graph() {
        use crate::enrichment::EnrichmentStore;

        let dir = TempDir::new().expect("tmpdir");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("mkdir src");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write Cargo.toml");
        // `main` calls `helper`; `main` is an entry point → classifies Wired,
        // and is the depth-from-entry BFS root (depth 0).
        fs::write(src.join("main.rs"), "fn main(){helper();}\nfn helper(){}\n")
            .expect("write main.rs");

        let state = IndexState::new_test(dir.path()).expect("open state");
        let db_path = dir.path().join("graph.redb");
        let db = Arc::new(redb::Database::create(&db_path).expect("create redb"));
        let graph_store = GraphStore::new(Arc::clone(&db));
        let enrichment_store = Arc::new(EnrichmentStore::new());

        let config_full = IndexConfig {
            root: dir.path().to_path_buf(),
            full: true,
            scip: ScipMode::Disabled,
            ..Default::default()
        };

        // Run the REAL pipeline with both a graph store AND an enrichment store,
        // so Phase 8b (classify) → Phase 8c (enrich) execute in production order.
        let report = IndexPipeline::run(
            &state,
            Some(&graph_store),
            &config_full,
            Some(&enrichment_store),
        )
        .await
        .expect("pipeline run");
        assert!(report.nodes_added > 0, "the run must populate the graph");

        // Load the persisted (classified) graph to enumerate node ids, then
        // query the enrichment store each node accumulated during Phase 8c.
        let graph = graph_store
            .load_snapshot()
            .await
            .expect("load snapshot")
            .expect("a populated graph must exist");

        let zero_depth_count = graph
            .all_nodes()
            .iter()
            .filter_map(|n| enrichment_store.node_enrichment(&n.memory_id))
            .filter(|enr| enr.depth_from_entry == Some(0))
            .count();

        assert!(
            zero_depth_count >= 1,
            "enrichment must observe a CLASSIFIED graph: at least one node should \
             carry depth_from_entry == Some(0), which Pass 2 assigns ONLY to a \
             Wired/PublicApi entry root. Zero such nodes means enrichment ran \
             against an all-Unclassified graph (classification did not run first)."
        );
    }
}
