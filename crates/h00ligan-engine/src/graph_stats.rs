//! Shared graph statistics helpers for code intelligence tools.
//!
//! Provides graph/reachability summaries, exact immutable-generation source
//! freshness, and display-only index age shared by CLI and MCP adapters.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

#[cfg(feature = "code-intel")]
use rayon::prelude::*;
#[cfg(all(test, feature = "code-intel"))]
use std::sync::{Mutex, OnceLock};

use crate::code_intel_domain::{CapabilityCoverage, CapabilityCoverageStatus};
use crate::graph::{EdgeKind, EdgeSource, KnowledgeGraph};
use crate::reachability::ReachabilityClass;
use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

// ============================================================================
// Types
// ============================================================================

/// Node/edge counts and edge kind distribution.
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    /// Edge kind name to count. Consumers that need sorted output should
    /// collect into a `Vec` and sort at display time.
    pub edge_kinds: HashMap<String, usize>,
}

/// Reachability class distribution across all graph nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReachabilitySummary {
    pub wired: usize,
    pub public_api: usize,
    pub structural: usize,
    pub test_only: usize,
    pub dead: usize,
    pub orphan: usize,
    pub unclassified: usize,
    /// WU-0015 / ADR-0036 v6: the directed-call-reachability review tier
    /// (call-unreachable, never a delete authority). The 8th summary bucket.
    pub suspected: usize,
    /// ADR-0045: symbols OUT of the production-reachability census (D1 detached/
    /// nested-crate files + D2 fixture-corpus dirs). The 9th summary bucket.
    pub excluded: usize,
}

/// Maximum selected source-file population the exact content checker will
/// authorize as fresh. Larger generations fail closed to `Unknown`.
pub const MAX_STALENESS_FILES: usize = 50_000;

/// Why a staleness verdict is [`StalenessVerdict::Unknown`] (ADR-0034 L4,
/// Decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalenessReason {
    /// The indexed or live population exceeded [`MAX_STALENESS_FILES`].
    Truncated,
    /// No selected source files were found to compare.
    NoSourceFound,
    /// The immutable generation did not carry readable per-file content
    /// records. An mtime comparison is not an acceptable substitute for
    /// content authority.
    IndexedSourceSnapshotUnavailable,
    /// Exact source discovery or byte hashing failed. Freshness fails closed
    /// rather than silently treating an unreadable path as unchanged.
    SourceVerificationFailed,
    /// A semantic provider disclosed that some non-source input could not be
    /// reproduced safely by a fresh process, or its persisted input manifest
    /// could not be re-observed.
    ProviderSemanticInputsUnverifiable,
}

/// Failures while comparing the live repository to an immutable generation's
/// exact indexed-source records.
#[derive(Debug, thiserror::Error)]
pub enum IndexedSourceFreshnessError {
    #[error("indexed source record is invalid for {path}: {reason}")]
    InvalidRecord { path: String, reason: String },

    #[error("source discovery failed: {0}")]
    Discovery(#[from] crate::source_discovery::SourceDiscoveryError),

    #[error("indexed source path escaped the repository root: {path}")]
    EscapedRoot { path: PathBuf },

    #[error("read source file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(all(test, feature = "code-intel"))]
#[derive(Default)]
struct TestHashProbe {
    delay: bool,
    in_flight: usize,
    max_in_flight: usize,
}

#[cfg(all(test, feature = "code-intel"))]
fn test_hash_probes() -> &'static Mutex<HashMap<PathBuf, TestHashProbe>> {
    static PROBES: OnceLock<Mutex<HashMap<PathBuf, TestHashProbe>>> = OnceLock::new();
    PROBES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(all(test, feature = "code-intel"))]
struct TestHashFlightGuard {
    root: Option<PathBuf>,
}

#[cfg(all(test, feature = "code-intel"))]
struct TestHashDelayGuard {
    root: PathBuf,
}

#[cfg(all(test, feature = "code-intel"))]
impl TestHashDelayGuard {
    fn enable(root: &Path) -> Self {
        let root = root.to_path_buf();
        let previous = test_hash_probes()
            .lock()
            .expect("source-hash probe state")
            .insert(
                root.clone(),
                TestHashProbe {
                    delay: true,
                    ..TestHashProbe::default()
                },
            );
        assert!(previous.is_none(), "duplicate source-hash probe root");
        Self { root }
    }
}

#[cfg(all(test, feature = "code-intel"))]
impl Drop for TestHashDelayGuard {
    fn drop(&mut self) {
        test_hash_probes()
            .lock()
            .expect("source-hash probe state")
            .remove(&self.root);
    }
}

#[cfg(all(test, feature = "code-intel"))]
impl TestHashFlightGuard {
    fn enter(root: &Path) -> Self {
        let delay = {
            let mut probes = test_hash_probes().lock().expect("source-hash probe state");
            let Some(probe) = probes.get_mut(root) else {
                return Self { root: None };
            };
            probe.in_flight = probe.in_flight.saturating_add(1);
            probe.max_in_flight = probe.max_in_flight.max(probe.in_flight);
            let delay = probe.delay;
            drop(probes);
            delay
        };
        if delay {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        Self {
            root: Some(root.to_path_buf()),
        }
    }
}

#[cfg(all(test, feature = "code-intel"))]
impl Drop for TestHashFlightGuard {
    fn drop(&mut self) {
        let Some(root) = &self.root else {
            return;
        };
        let mut probes = test_hash_probes().lock().expect("source-hash probe state");
        if let Some(probe) = probes.get_mut(root) {
            probe.in_flight = probe.in_flight.saturating_sub(1);
        }
        drop(probes);
    }
}

#[cfg(all(test, feature = "code-intel"))]
fn test_hash_max_in_flight(root: &Path) -> usize {
    test_hash_probes()
        .lock()
        .expect("source-hash probe state")
        .get(root)
        .map_or(0, |probe| probe.max_in_flight)
}

#[cfg(feature = "code-intel")]
fn read_source_digest(_root: &Path, path: &Path) -> Result<String, std::io::Error> {
    #[cfg(test)]
    let _flight = TestHashFlightGuard::enter(_root);
    let bytes = std::fs::read(path)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Exact live-input freshness relative to one immutable generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalenessVerdict {
    /// Selected source population, source bytes, and project-input bytes match.
    Fresh,
    /// At least one selected source or project input differs.
    Stale,
    /// Freshness could not be determined honestly (fail-closed).
    Unknown {
        /// Why the verdict is unknown.
        reason: StalenessReason,
        /// Files scanned before the verdict was reached — the `N` in the
        /// "scanned N files" disclosure surfaced on `status`.
        files_checked: usize,
    },
}

/// Index-time age telemetry + incremental-drift signal read from index state.
/// Freshness never depends on this wall-clock value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexBaseline {
    /// `last_update` (fallback `last_full_scan`) as display-only wall-clock age.
    pub baseline: Option<SystemTime>,
    /// `last_update > last_full_scan` — `true` after the first incremental
    /// reindex (Decision 7 / R2-M5). NON-suppressing: surfaced informationally,
    /// never a `dead`/`status` suppress trigger.
    pub incremental_drift: bool,
}

// ============================================================================
// Functions
// ============================================================================

/// Compute basic graph statistics: node count, edge count, edge kind breakdown.
pub fn compute_graph_stats(graph: &KnowledgeGraph) -> GraphStats {
    let edges = graph.all_edges();
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    for (_, _, edge) in &edges {
        *kind_counts
            .entry(edge.kind.as_str().to_owned())
            .or_default() += 1;
    }

    GraphStats {
        node_count: graph.node_count(),
        edge_count: graph.edge_count(),
        edge_kinds: kind_counts,
    }
}

/// Count nodes in each reachability tier.
pub fn compute_reachability_summary(graph: &KnowledgeGraph) -> ReachabilitySummary {
    let nodes = graph.all_nodes();
    let mut summary = ReachabilitySummary {
        wired: 0,
        public_api: 0,
        structural: 0,
        test_only: 0,
        dead: 0,
        orphan: 0,
        unclassified: 0,
        suspected: 0,
        excluded: 0,
    };
    for node in &nodes {
        match node.reachability_class {
            ReachabilityClass::Wired => summary.wired += 1,
            ReachabilityClass::PublicApi => summary.public_api += 1,
            ReachabilityClass::Structural => summary.structural += 1,
            ReachabilityClass::TestOnly => summary.test_only += 1,
            ReachabilityClass::Dead => summary.dead += 1,
            ReachabilityClass::Orphan => summary.orphan += 1,
            ReachabilityClass::Unclassified => summary.unclassified += 1,
            ReachabilityClass::Suspected => summary.suspected += 1,
            ReachabilityClass::Excluded => summary.excluded += 1,
        }
    }
    summary
}

/// Read display-age and incremental-drift telemetry through an already-open
/// immutable-generation index-state handle.
///
/// This lets a coherent bundle reader hold one OS-read-only redb handle across
/// both fingerprint captures instead of reopening `index.redb` inside the
/// guarded window. Metadata remains best-effort: an absent table, key, or
/// undecodable value yields [`IndexBaseline::default`]. Neither field is used
/// to authorize freshness; exact source and project-input bytes do that.
#[must_use]
pub fn read_index_baseline_from_state(state: &crate::index_state::IndexState) -> IndexBaseline {
    let Ok(Some(meta)) = state.get_metadata() else {
        return IndexBaseline::default();
    };
    let baseline = meta
        .last_update
        .or(meta.last_full_scan)
        .and_then(millis_to_system_time);
    let incremental_drift = matches!(
        (meta.last_update, meta.last_full_scan),
        (Some(u), Some(f)) if u > f
    );
    IndexBaseline {
        baseline,
        incremental_drift,
    }
}

/// Convert epoch-millis (`i64`, as stored in `IndexMetadata`) to a `SystemTime`.
/// Returns `None` for a negative timestamp (pre-epoch — never produced by the
/// indexer).
fn millis_to_system_time(ms: i64) -> Option<SystemTime> {
    u64::try_from(ms)
        .ok()
        .map(|m| SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(m))
}

/// Compare the live indexed-source population and bytes to one immutable
/// generation's persisted [`crate::index_state::FileRecord`] set.
///
/// This is the authoritative freshness check for immutable code-intelligence
/// generations. Modification times are deliberately irrelevant: a file whose
/// bytes changed and whose mtime was restored is still stale. Discovery uses
/// the same registry, ignore, hidden-file, and symlink policy as indexing and
/// must exactly match the persisted file-record population. Graph capability
/// completeness is deliberately independent from this input-currency verdict.
#[cfg(feature = "code-intel")]
pub fn check_indexed_source_freshness(
    workspace: &Path,
    indexed_files: &[(String, crate::index_state::FileRecord)],
) -> Result<StalenessVerdict, IndexedSourceFreshnessError> {
    if indexed_files.is_empty() {
        return Ok(StalenessVerdict::Unknown {
            reason: StalenessReason::NoSourceFound,
            files_checked: 0,
        });
    }
    if indexed_files.len() > MAX_STALENESS_FILES {
        return Ok(StalenessVerdict::Unknown {
            reason: StalenessReason::Truncated,
            files_checked: MAX_STALENESS_FILES,
        });
    }

    let observation_started = std::time::Instant::now();
    let record_validation_started = std::time::Instant::now();
    let registered_languages = crate::language::registered_languages()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut expected = BTreeMap::new();
    for (path, record) in indexed_files {
        let relative = Path::new(path);
        if path.is_empty()
            || relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(IndexedSourceFreshnessError::InvalidRecord {
                path: path.clone(),
                reason: "path must be non-empty and repository-relative".into(),
            });
        }
        if !registered_languages.contains(record.language.as_str()) {
            return Err(IndexedSourceFreshnessError::InvalidRecord {
                path: path.clone(),
                reason: format!("unregistered language {}", record.language),
            });
        }
        if record.blake3_hash.len() != 64
            || !record
                .blake3_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(IndexedSourceFreshnessError::InvalidRecord {
                path: path.clone(),
                reason: "BLAKE3 digest must be 64 lowercase hexadecimal characters".into(),
            });
        }
        if expected.insert(path.clone(), &record.blake3_hash).is_some() {
            return Err(IndexedSourceFreshnessError::InvalidRecord {
                path: path.clone(),
                reason: "duplicate indexed path".into(),
            });
        }
    }
    let record_validation_elapsed = record_validation_started.elapsed();

    // A generation must become stale when the repository gains its first file
    // in another registered language. Restricting discovery to languages that
    // already appear in `indexed_files` makes that transition invisible.
    let extensions = crate::language::extensions_for_languages(&[]);
    let discovery_started = std::time::Instant::now();
    let discovered = crate::source_discovery::discover_source_files(workspace, &extensions, &[])?;
    let discovery_elapsed = discovery_started.elapsed();
    if discovered.len() > MAX_STALENESS_FILES {
        return Ok(StalenessVerdict::Unknown {
            reason: StalenessReason::Truncated,
            files_checked: MAX_STALENESS_FILES,
        });
    }

    let mut live = BTreeMap::new();
    for path in discovered {
        let relative = path
            .strip_prefix(workspace)
            .map_err(|_| IndexedSourceFreshnessError::EscapedRoot { path: path.clone() })?
            .to_string_lossy()
            .into_owned();
        live.insert(relative, path);
    }
    if live.len() != expected.len() || live.keys().ne(expected.keys()) {
        return Ok(StalenessVerdict::Stale);
    }

    let hashing_started = std::time::Instant::now();
    // Read independent files concurrently, then consume the indexed parallel
    // result in canonical path order. Error selection and stale short-circuit
    // behavior therefore remain deterministic even though the I/O overlaps.
    let observations = live
        .into_iter()
        .collect::<Vec<_>>()
        .into_par_iter()
        .map(|(relative, path)| {
            let digest = read_source_digest(workspace, &path);
            (relative, path, digest)
        })
        .collect::<Vec<_>>();
    for (relative, path, digest) in observations {
        let actual = digest.map_err(|source| IndexedSourceFreshnessError::Read { path, source })?;
        if expected
            .get(&relative)
            .is_none_or(|expected| **expected != actual)
        {
            return Ok(StalenessVerdict::Stale);
        }
    }
    tracing::trace!(
        target: "h00ligan::live_inputs",
        indexed_files = indexed_files.len(),
        record_validation_ms = record_validation_elapsed.as_secs_f64() * 1_000.0,
        discovery_ms = discovery_elapsed.as_secs_f64() * 1_000.0,
        hashing_ms = hashing_started.elapsed().as_secs_f64() * 1_000.0,
        total_ms = observation_started.elapsed().as_secs_f64() * 1_000.0,
        "exact indexed-source observation completed"
    );
    Ok(StalenessVerdict::Fresh)
}

/// Format a `SystemTime` age as a human-readable string (e.g. "5 minutes ago").
pub fn format_age(mtime: SystemTime) -> String {
    SystemTime::now().duration_since(mtime).map_or_else(
        |_| "unknown".to_string(),
        |elapsed| {
            let secs = elapsed.as_secs();
            if secs < 60 {
                "just now".to_string()
            } else if secs < 3600 {
                let mins = secs / 60;
                format!("{mins} minute{} ago", if mins == 1 { "" } else { "s" })
            } else if secs < 86400 {
                let hours = secs / 3600;
                format!("{hours} hour{} ago", if hours == 1 { "" } else { "s" })
            } else {
                let days = secs / 86400;
                format!("{days} day{} ago", if days == 1 { "" } else { "s" })
            }
        },
    )
}

// ============================================================================
// Call-edge coverage signal (ADR-0034 L4, Decision 1)
// ============================================================================

/// Actionable guidance when a generation lacks authoritative `Calls` evidence.
pub const CALLS_ACTIONABLE_GAP_GUIDANCE: &str = "resolve the reported per-language capability gaps, then run `h00ligan index --scip`; use `--require-complete-calls` when incomplete Calls must refuse publication";

/// Informational guidance when semantic indexing already did every operation
/// available for the discovered project units.
pub const CALLS_BEST_EFFORT_LIMIT_GUIDANCE: &str = "whole-project dead-code totals remain unavailable because source without a provider execution root has no Calls authority; this best-effort generation already covers every available project unit";
pub const CALLS_QUALIFIED_GUIDANCE: &str = "Calls results are exact within provider-covered source, but explicit source regions remain excluded; inspect the reported qualifications before relying on negative results";

/// One machine- and human-facing decision about an unavailable aggregate
/// dead-code population. A message never implies an action unless
/// `action_needed` is true.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CapabilityCoverageGuidance {
    pub action_needed: bool,
    pub message: String,
}

/// Explain an indexed population that has structural facts but no
/// authoritative reachability classification.
///
/// This is independent of whether the semantic capability census has an
/// applicable provider scope: loose or auxiliary source must not disappear
/// merely because it cannot authorize a provider execution root.
#[must_use]
pub fn unclassified_population_guidance(
    unclassified_node_count: usize,
) -> Option<CapabilityCoverageGuidance> {
    (unclassified_node_count > 0).then(|| CapabilityCoverageGuidance {
        action_needed: true,
        message: format!(
            "this indexed generation has {unclassified_node_count} unclassified graph node(s); resolve their project ownership or capability evidence, then publish a new semantic generation. Re-running the same unchanged indexing request cannot improve this state"
        ),
    })
}

/// Distinguish an actionable provider/configuration failure from a stable
/// loose-source limitation.
///
/// This is shared by Overview and Audit so neither surface can prescribe an
/// indexing loop that Status already knows is inert.
#[must_use]
pub fn calls_coverage_guidance(
    coverage: &CapabilityCoverage,
) -> Option<CapabilityCoverageGuidance> {
    if !matches!(
        coverage.status,
        CapabilityCoverageStatus::Qualified
            | CapabilityCoverageStatus::Partial
            | CapabilityCoverageStatus::Unavailable
    ) {
        return None;
    }
    let action_needed = !coverage.satisfies_best_effort_provider_intent();
    Some(CapabilityCoverageGuidance {
        action_needed,
        message: if coverage.status == CapabilityCoverageStatus::Qualified {
            CALLS_QUALIFIED_GUIDANCE
        } else if action_needed {
            CALLS_ACTIONABLE_GAP_GUIDANCE
        } else {
            CALLS_BEST_EFFORT_LIMIT_GUIDANCE
        }
        .into(),
    })
}

/// Explain why one aggregate dead-code total is unavailable without collapsing
/// graph classification, graph population, and Calls capability into one bit.
#[must_use]
pub fn dead_code_unknown_guidance(
    coverage: &CapabilityCoverage,
    graph_is_classified: bool,
    graph_is_nonempty: bool,
) -> CapabilityCoverageGuidance {
    if !graph_is_nonempty {
        return CapabilityCoverageGuidance {
            action_needed: true,
            message: "publish a non-empty immutable generation".into(),
        };
    }
    if !graph_is_classified {
        return CapabilityCoverageGuidance {
            action_needed: true,
            message: "publish a freshly classified immutable generation".into(),
        };
    }
    calls_coverage_guidance(coverage).unwrap_or_else(|| CapabilityCoverageGuidance {
        action_needed: true,
        message: "the published call graph cannot authorize a whole-project dead-code total; publish a fresh semantic generation"
            .into(),
    })
}

/// Structural diagnostics for the loaded graph's `Calls` population.
///
/// Capability authority is supplied explicitly by the immutable generation's
/// scoped receipts. These counts describe the graph but never establish that a
/// provider ran or that a language is covered.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CallEdgeCoverage {
    /// Whether the exact query scope has at least one complete, validated Calls
    /// receipt. This is supplied by the caller's immutable capability decision;
    /// it is never inferred from edge counts or mutable graph metadata.
    pub calls_authority_available: bool,
    /// ALL graph nodes (every kind), not just function-like. The LEAK-1
    /// discriminator (WU-0023 P3b): `total_nodes == 0` is a total-extraction-
    /// failure / empty store (DEGENERATE-empty → suppress to UNKNOWN), whereas
    /// `total_nodes > 0 && total_fn_nodes == 0` is an AUTHORITATIVE-empty scope
    /// (e.g. a Go type/const-only package — "not applicable", never a bare 0).
    pub total_nodes: usize,
    /// All source-level callable nodes.
    pub total_fn_nodes: usize,
    /// Function nodes NOT in `{Dead, Orphan}` — the candidate-excluded
    /// denominator for `ratio_live` (R2-M4: genuinely-dead fns have no `Calls`
    /// edges by construction, so including them would invert the ratio).
    pub live_fn_nodes: usize,
    /// Live function nodes touching >= 1 `Calls` edge (either direction).
    pub fn_with_calls_live: usize,
    /// `Calls` edges whose source is SCIP-derived (`Scip` or `Both`). For Rust
    /// ALL production `Calls` edges are SCIP-derived, so this is the absolute
    /// data-presence count.
    pub scip_calls_edges: usize,
    /// `fn_with_calls_live / live_fn_nodes`; `None` when `live_fn_nodes == 0`.
    /// A diagnostic only: no uncalibrated threshold turns it into authority.
    pub ratio_live: Option<f32>,
}

/// Coverage tier for the `dead`/`status` honesty gate (ADR-0034 L4, Decision 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageTier {
    /// No function-like nodes, but the store DID extract nodes
    /// (`total_nodes > 0 && total_fn_nodes == 0`) — an AUTHORITATIVE-empty scope
    /// (e.g. a Go type/const-only package). The call-edge coverage question does
    /// not apply, but this is NOT a suppress: it renders "not applicable — no
    /// callable functions in scope" (never a bare `dead_code:0`/`fresh`) and does
    /// NOT mask dead NON-function nodes (WU-0023 P3b LEAK-1).
    NotApplicable,
    /// Total extraction failure / empty store (`total_nodes == 0`) — the
    /// DEGENERATE-empty case (WU-0023 P3b LEAK-1). A bare `dead_code:0`/`fresh`
    /// here is a false-CLEAN (the extractor produced nothing, so "nothing is
    /// dead" is unearned), so this tier SUPPRESSES to verb-level UNKNOWN through
    /// the shared [`crate::graph_query::suppresses`] chokepoint.
    Degenerate,
    /// No complete Calls receipt authorizes any callable language in the query
    /// scope. The verdict is uncomputable ⇒ verb-level UNKNOWN (SUPPRESS).
    Unavailable,
    /// At least one callable language in the query scope has complete Calls
    /// authority. Uncovered languages remain explicitly segmented as UNKNOWN.
    Sufficient,
}

impl CoverageTier {
    /// Stable machine label shared by every CLI and MCP projection.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotApplicable => "NotApplicable",
            Self::Degenerate => "Degenerate",
            Self::Unavailable => "Unavailable",
            Self::Sufficient => "Sufficient",
        }
    }
}

/// True for a source-level callable graph node (the population the coverage
/// signal measures across every registered language).
fn is_fn_node(node: &crate::graph::GraphNode) -> bool {
    symbol_kind_has_role(&node.kind, SymbolRole::Callable)
}

/// Compute structural Calls diagnostics for a loaded graph and attach the
/// caller's receipt-derived authority decision for the exact query scope.
pub fn call_edge_coverage(
    graph: &KnowledgeGraph,
    calls_authority_available: bool,
) -> CallEdgeCoverage {
    let nodes = graph.all_nodes();
    let total_nodes = nodes.len();
    let fn_nodes: Vec<&crate::graph::GraphNode> =
        nodes.iter().copied().filter(|n| is_fn_node(n)).collect();
    let total_fn_nodes = fn_nodes.len();

    // SCIP-derived Calls edges (the absolute data-presence count) + the set of
    // node ids touching any Calls edge (either direction), for the live ratio.
    let mut scip_calls_edges = 0usize;
    let mut nodes_touching_calls: std::collections::HashSet<uuid::Uuid> =
        std::collections::HashSet::new();
    for (src, tgt, edge) in graph.all_edges() {
        if edge.kind == EdgeKind::Calls {
            if matches!(edge.source, EdgeSource::Scip | EdgeSource::Both) {
                scip_calls_edges += 1;
            }
            nodes_touching_calls.insert(src);
            nodes_touching_calls.insert(tgt);
        }
    }

    let live_fn_nodes = fn_nodes
        .iter()
        .filter(|n| {
            !matches!(
                n.reachability_class,
                ReachabilityClass::Dead | ReachabilityClass::Orphan
            )
        })
        .count();
    let fn_with_calls_live = fn_nodes
        .iter()
        .filter(|n| {
            !matches!(
                n.reachability_class,
                ReachabilityClass::Dead | ReachabilityClass::Orphan
            ) && nodes_touching_calls.contains(&n.memory_id)
        })
        .count();

    let ratio_live = if live_fn_nodes == 0 {
        None
    } else {
        #[allow(clippy::cast_precision_loss)]
        Some(fn_with_calls_live as f32 / live_fn_nodes as f32)
    };

    CallEdgeCoverage {
        calls_authority_available,
        total_nodes,
        total_fn_nodes,
        live_fn_nodes,
        fn_with_calls_live,
        scip_calls_edges,
        ratio_live,
    }
}

/// Classify a [`CallEdgeCoverage`] into a [`CoverageTier`] (ADR-0034 L4,
/// Decision 1).
///
/// - `NotApplicable` ⇐ no function-like nodes.
/// - `Unavailable` (SUPPRESS) ⇐ functions exist and no complete Calls receipt
///   authorizes the query scope.
/// - `Sufficient` (EMIT) ⇐ at least one callable language has complete receipt
///   authority; uncovered languages remain segmented as UNKNOWN.
#[must_use]
pub const fn coverage_tier(cov: &CallEdgeCoverage) -> CoverageTier {
    if cov.total_fn_nodes == 0 {
        // WU-0023 P3b LEAK-1 split. Discriminate on `total_nodes`-PRIMARY (the
        // RULED-safe discriminator): a store that extracted ZERO nodes at all is
        // a total-extraction failure — rendering `dead_code:0`/`fresh` there is a
        // false-CLEAN, so route it to the SUPPRESSING `Degenerate` tier. A store
        // with nodes but no callable functions (a Go type/const-only package) is
        // AUTHORITATIVE-empty: the coverage question does not apply, but the dead
        // report of non-function nodes stands, so it is `NotApplicable` (renders
        // "not applicable", never suppress). (Swapping to a
        // `total_fn_nodes`-primary discriminator would mis-render (b) as
        // "not applicable" — the exact false-CLEAN this split closes.)
        if cov.total_nodes == 0 {
            return CoverageTier::Degenerate;
        }
        return CoverageTier::NotApplicable;
    }
    if !cov.calls_authority_available {
        return CoverageTier::Unavailable;
    }
    CoverageTier::Sufficient
}

/// The machine-readable `coverage` block (ADR-0034 L4, Decision 4).
///
/// Emitted in both the `dead` and `status` JSON on BOTH surfaces — defined ONCE
/// here so the CLI and MCP payloads are byte-identical by construction.
#[must_use]
pub fn coverage_block_json(cov: &CallEdgeCoverage, tier: CoverageTier) -> serde_json::Value {
    let mut block = serde_json::json!({
        "tier": tier.label(),
        "calls_authority_available": cov.calls_authority_available,
        "scip_calls_edges": cov.scip_calls_edges,
        "fn_with_calls_live": cov.fn_with_calls_live,
        "live_fn_nodes": cov.live_fn_nodes,
        // WU-0023 P3b LEAK-1: surface both census counts for CI + the
        // NotApplicable-vs-Degenerate discriminator.
        "total_nodes": cov.total_nodes,
        "total_fn_nodes": cov.total_fn_nodes,
        "ratio_live": cov.ratio_live,
    });
    // WU-0023 P3b LEAK-1: the AUTHORITATIVE-empty render — "not applicable — no
    // callable functions", NEVER a bare `dead_code:0`/`fresh`. Single-sourced
    // here so the CLI + MCP dead/overview/status coverage blocks carry the SAME
    // note by construction.
    if matches!(tier, CoverageTier::NotApplicable) {
        block["note"] = serde_json::Value::String(NOT_APPLICABLE_NOTE.to_string());
    }
    block
}

/// Attach the generation-authoritative capability evidence that justified the
/// legacy graph-shape coverage tier.
///
/// The numeric fields remain useful diagnostics, but they are not authority:
/// a Calls edge from one language cannot certify another language. Both CLI and
/// MCP use this helper so every machine-readable coverage block carries the
/// exact receipt-backed per-language status and reason codes.
#[must_use]
pub fn coverage_block_json_with_authority(
    cov: &CallEdgeCoverage,
    tier: CoverageTier,
    authority: &crate::code_intel_domain::CapabilityCoverage,
) -> serde_json::Value {
    let mut block = coverage_block_json(cov, tier);
    block["authority"] = serde_json::json!(authority);
    block
}

/// The AUTHORITATIVE-empty coverage note (WU-0023 P3b LEAK-1).
///
/// Surfaced in the `coverage` block when the tier is
/// [`CoverageTier::NotApplicable`] so a reader sees "the coverage question does
/// not apply", never a false-CLEAN `0`/`fresh`. A statement about FUNCTION
/// coverage ONLY — it does not claim the store is clean of dead non-function
/// nodes.
pub const NOT_APPLICABLE_NOTE: &str = "not applicable — no callable functions in scope";

// ============================================================================
// DEC-R5a — per-language coverage floor (WU-0023 P3b)
// ============================================================================

/// The registered language a graph node belongs to (DEC-R5a partition key).
///
/// Derived from the node's file extension via the [`crate::language`] registry.
/// `None` for an extension with no registered extractor (never true for a node
/// the pipeline emitted, since only registered extensions are extracted).
///
/// It distinguishes a Rust `.rs` node
/// (precise SCIP-resolved) from a Go `.go` node (structural-tags floor until
/// scip-go lands), so the coverage floor can suppress an uncovered LANGUAGE
/// slice without whole-verb-suppressing the honest slices.
#[must_use]
pub fn node_language(node: &crate::graph::GraphNode) -> Option<&'static str> {
    std::path::Path::new(&node.file_path)
        .extension()
        .and_then(|e| e.to_str())
        .and_then(crate::language::language_for_extension)
}

/// The set of registered languages whose call-graph coverage is INSUFFICIENT —
/// their function nodes must render UNKNOWN, never be summed into an
/// authoritative dead total (DEC-R5a, WU-0023 P3b).
///
/// Partitions the graph's function nodes by [`node_language`] and, for each
/// language present, asks `precise_resolver_ran(lang)` — TRUE iff that language's
/// precise resolver (Rust→rust-analyzer SCIP; Go→scip-go, absent at the P3b tags
/// floor) ran + merged. A language with function nodes whose precise resolver did
/// NOT run is coverage-uncovered → returned here → its nodes are excluded from the
/// (Path-B, reporting) dead verdict as UNKNOWN.
///
/// SEGMENTED, never whole-verb: on a MIXED Rust+Go store the Rust slice is
/// covered by a complete scoped receipt and renders normally, while the Go slice is
/// uncovered and renders UNKNOWN — the honest Rust verdicts are NOT regressed to
/// UNKNOWN (the charter's deciding axis). On a Rust-only store the only language
/// present is `rust`, whose resolver status comes from the same generation's
/// scoped capability receipts, so the
/// returned set is EMPTY and the dead report is byte-identical (RUST
/// NO-REGRESSION).
#[must_use]
pub fn coverage_suppressed_languages(
    graph: &KnowledgeGraph,
    precise_resolver_ran: impl Fn(&str) -> bool,
) -> std::collections::HashSet<&'static str> {
    let mut langs: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
    for node in graph.all_nodes() {
        if is_fn_node(node)
            && let Some(lang) = node_language(node)
        {
            langs.insert(lang);
        }
    }
    langs.retain(|lang| !precise_resolver_ran(lang));
    langs
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn format_age_just_now() {
        let now = SystemTime::now();
        let result = format_age(now);
        assert_eq!(result, "just now");
    }

    #[test]
    fn format_age_minutes() {
        let five_min_ago = SystemTime::now() - Duration::from_secs(300);
        let result = format_age(five_min_ago);
        assert_eq!(result, "5 minutes ago");
    }

    #[test]
    fn format_age_hours() {
        let two_hours_ago = SystemTime::now() - Duration::from_secs(7200);
        let result = format_age(two_hours_ago);
        assert_eq!(result, "2 hours ago");
    }

    #[test]
    fn format_age_days() {
        let three_days_ago = SystemTime::now() - Duration::from_secs(259200);
        let result = format_age(three_days_ago);
        assert_eq!(result, "3 days ago");
    }

    #[test]
    fn format_age_singular() {
        let one_min_ago = SystemTime::now() - Duration::from_secs(60);
        assert_eq!(format_age(one_min_ago), "1 minute ago");

        let one_hour_ago = SystemTime::now() - Duration::from_secs(3600);
        assert_eq!(format_age(one_hour_ago), "1 hour ago");

        let one_day_ago = SystemTime::now() - Duration::from_secs(86400);
        assert_eq!(format_age(one_day_ago), "1 day ago");
    }

    #[test]
    fn format_age_future_returns_unknown() {
        // A time in the future should return "unknown" since duration_since fails.
        let future = SystemTime::now() + Duration::from_secs(3600);
        assert_eq!(format_age(future), "unknown");
    }

    #[cfg(feature = "code-intel")]
    #[test]
    fn indexed_source_freshness_detects_byte_drift_with_restored_mtime() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source_dir = dir.path().join("src");
        std::fs::create_dir(&source_dir).expect("source directory");
        let source_path = source_dir.join("lib.rs");
        let original = b"pub fn answer() -> u32 { 42 }\n";
        std::fs::write(&source_path, original).expect("source fixture");
        let original_metadata = std::fs::metadata(&source_path).expect("source metadata");
        let original_modified = original_metadata.modified().expect("source mtime");
        let original_accessed = original_metadata.accessed().expect("source atime");
        let indexed_files = vec![(
            "src/lib.rs".into(),
            crate::index_state::FileRecord {
                blake3_hash: blake3::hash(original).to_hex().to_string(),
                last_indexed: 1,
                symbol_count: 1,
                language: "rust".into(),
            },
        )];

        assert_eq!(
            check_indexed_source_freshness(dir.path(), &indexed_files).unwrap(),
            StalenessVerdict::Fresh,
            "positive control: byte-identical indexed source must be fresh"
        );

        std::fs::write(&source_path, b"pub fn answer() -> u32 { 43 }\n")
            .expect("change source bytes");
        let source = std::fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .expect("open changed source");
        source
            .set_times(
                std::fs::FileTimes::new()
                    .set_accessed(original_accessed)
                    .set_modified(original_modified),
            )
            .expect("restore source timestamps");
        assert_eq!(
            std::fs::metadata(&source_path)
                .expect("restored source metadata")
                .modified()
                .expect("restored mtime"),
            original_modified,
            "falsifier requires unchanged mtime"
        );
        assert_eq!(
            check_indexed_source_freshness(dir.path(), &indexed_files).unwrap(),
            StalenessVerdict::Stale,
            "source content, not mtime, must decide freshness"
        );
    }

    /// FALSIFIER: exact freshness remains a complete byte observation, but
    /// independent source files must not be read and hashed serially.
    #[cfg(feature = "code-intel")]
    #[test]
    #[serial_test::serial]
    fn indexed_source_freshness_hashes_independent_files_concurrently() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source_dir = dir.path().join("src");
        std::fs::create_dir(&source_dir).expect("source directory");
        let mut indexed_files = Vec::new();
        for index in 0..24 {
            let relative = format!("src/file_{index:02}.rs");
            let bytes = format!("pub fn item_{index:02}() -> usize {{ {index} }}\n");
            std::fs::write(dir.path().join(&relative), &bytes).expect("source fixture");
            indexed_files.push((
                relative,
                crate::index_state::FileRecord {
                    blake3_hash: blake3::hash(bytes.as_bytes()).to_hex().to_string(),
                    last_indexed: 1,
                    symbol_count: 1,
                    language: "rust".into(),
                },
            ));
        }

        let _delay = TestHashDelayGuard::enable(dir.path());
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("four-thread falsifier pool");
        let verdict = pool.install(|| {
            check_indexed_source_freshness(dir.path(), &indexed_files)
                .expect("exact source observation")
        });

        assert_eq!(verdict, StalenessVerdict::Fresh);
        assert!(
            test_hash_max_in_flight(dir.path()) > 1,
            "positive multi-thread control must observe overlapping independent file hashes"
        );
    }

    #[cfg(feature = "code-intel")]
    #[test]
    fn indexed_source_freshness_detects_first_file_of_another_registered_language() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source_dir = dir.path().join("src");
        std::fs::create_dir(&source_dir).expect("source directory");
        let rust_bytes = b"pub fn answer() -> u32 { 42 }\n";
        std::fs::write(source_dir.join("lib.rs"), rust_bytes).expect("Rust source");
        let indexed_files = vec![(
            "src/lib.rs".into(),
            crate::index_state::FileRecord {
                blake3_hash: blake3::hash(rust_bytes).to_hex().to_string(),
                last_indexed: 1,
                symbol_count: 1,
                language: "rust".into(),
            },
        )];

        assert_eq!(
            check_indexed_source_freshness(dir.path(), &indexed_files).unwrap(),
            StalenessVerdict::Fresh,
            "positive control: the indexed Rust-only population begins fresh"
        );

        std::fs::write(dir.path().join("main.go"), "package main\nfunc main() {}\n")
            .expect("first Go source");
        assert_eq!(
            check_indexed_source_freshness(dir.path(), &indexed_files).unwrap(),
            StalenessVerdict::Stale,
            "adding the first file of another registered language must invalidate the generation"
        );
    }

    #[cfg(feature = "code-intel")]
    #[test]
    fn indexed_source_freshness_fails_closed_for_missing_or_oversized_evidence() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert_eq!(
            check_indexed_source_freshness(dir.path(), &[]).unwrap(),
            StalenessVerdict::Unknown {
                reason: StalenessReason::NoSourceFound,
                files_checked: 0,
            }
        );

        let record = crate::index_state::FileRecord {
            blake3_hash: "0".repeat(64),
            last_indexed: 1,
            symbol_count: 1,
            language: "rust".into(),
        };
        let oversized = (0..=MAX_STALENESS_FILES)
            .map(|index| (format!("src/f{index}.rs"), record.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            check_indexed_source_freshness(dir.path(), &oversized).unwrap(),
            StalenessVerdict::Unknown {
                reason: StalenessReason::Truncated,
                files_checked: MAX_STALENESS_FILES,
            }
        );
    }

    /// Display-age and incremental-drift telemetry come from the already-open
    /// immutable generation, never from a mutable file mtime.
    #[test]
    fn read_index_timing_from_open_state_reads_last_update_and_drift() {
        use crate::index_state::{IndexMetadata, IndexState};
        let dir = tempfile::tempdir().expect("temp dir");
        let state = IndexState::new_test(dir.path()).expect("open index state");
        state
            .set_metadata(&IndexMetadata {
                repo_root: "/x".to_string(),
                last_full_scan: Some(1_710_000_000_000),
                last_update: Some(1_710_000_001_000),
                git_head: None,
                total_files: 1,
                total_symbols: 1,
                total_edges: 0,
            })
            .expect("set metadata");
        let ib = read_index_baseline_from_state(&state);
        assert_eq!(
            ib.baseline,
            Some(SystemTime::UNIX_EPOCH + Duration::from_millis(1_710_000_001_000)),
            "display age must use last_update"
        );
        assert!(
            ib.incremental_drift,
            "last_update > last_full_scan must register as incremental drift"
        );
    }

    // ------------------------------------------------------------------
    // Receipt-authorized coverage tier classifier.
    // ------------------------------------------------------------------

    fn cov(
        calls_authority_available: bool,
        scip_calls_edges: usize,
        ratio: Option<f32>,
    ) -> CallEdgeCoverage {
        CallEdgeCoverage {
            calls_authority_available,
            total_nodes: 20,
            total_fn_nodes: 10,
            live_fn_nodes: 10,
            fn_with_calls_live: 5,
            scip_calls_edges,
            ratio_live: ratio,
        }
    }

    /// Functions exist but no complete receipt authorizes Calls → Unavailable.
    #[test]
    fn coverage_tier_unavailable_without_receipt_authority() {
        assert_eq!(
            coverage_tier(&cov(false, 0, Some(0.0))),
            CoverageTier::Unavailable
        );
        // Edge presence cannot manufacture provider authority.
        assert_eq!(
            coverage_tier(&cov(false, 3, Some(0.3))),
            CoverageTier::Unavailable
        );
    }

    /// A complete receipt authorizes a genuine zero-call leaf without inferring
    /// authority from the zero edge count itself.
    #[test]
    fn coverage_tier_leaf_with_receipt_authority_is_sufficient() {
        assert_eq!(
            coverage_tier(&cov(true, 0, Some(0.0))),
            CoverageTier::Sufficient
        );
    }

    /// The uncalibrated ratio remains diagnostic and cannot override a complete
    /// immutable receipt in either direction.
    #[test]
    fn coverage_ratio_is_diagnostic_not_authority() {
        let partial = cov(true, 5, Some(0.5));
        assert_eq!(coverage_tier(&partial), CoverageTier::Sufficient);
        assert_eq!(
            coverage_tier(&cov(true, 20, Some(0.9))),
            CoverageTier::Sufficient
        );
    }

    /// AUTHORITATIVE-empty: nodes exist but no function-like nodes
    /// (`total_nodes > 0 && total_fn_nodes == 0`) → NotApplicable (the coverage
    /// question does not apply), regardless of the flag. WU-0023 P3b LEAK-1: this
    /// is the (a) branch — a Go type/const-only package renders "not applicable",
    /// NOT a bare `dead_code:0`.
    #[test]
    fn coverage_tier_not_applicable_on_no_functions() {
        let empty = CallEdgeCoverage {
            calls_authority_available: false,
            total_nodes: 5,
            total_fn_nodes: 0,
            live_fn_nodes: 0,
            fn_with_calls_live: 0,
            scip_calls_edges: 0,
            ratio_live: None,
        };
        assert_eq!(coverage_tier(&empty), CoverageTier::NotApplicable);
    }

    /// DEGENERATE-empty: a total-extraction-failure store (`total_nodes == 0`) →
    /// the new suppressing `Degenerate` tier, NEVER `NotApplicable` (WU-0023 P3b
    /// LEAK-1, the (b) branch). NON-VACUOUS discriminator control: a
    /// `total_fn_nodes`-primary discriminator would mis-render this as
    /// `NotApplicable` (a false-CLEAN) — the `total_nodes`-primary split is what
    /// routes it to suppression.
    #[test]
    fn coverage_tier_degenerate_on_total_extraction_failure() {
        let degenerate = CallEdgeCoverage {
            calls_authority_available: true,
            total_nodes: 0,
            total_fn_nodes: 0,
            live_fn_nodes: 0,
            fn_with_calls_live: 0,
            scip_calls_edges: 0,
            ratio_live: None,
        };
        assert_eq!(
            coverage_tier(&degenerate),
            CoverageTier::Degenerate,
            "total_nodes==0 must route to the suppressing Degenerate tier, not NotApplicable"
        );
        // The coverage block surfaces both census counts for CI.
        let block = coverage_block_json(&degenerate, CoverageTier::Degenerate);
        assert_eq!(block["tier"], "Degenerate");
        assert_eq!(block["total_nodes"], 0);
    }

    /// The AUTHORITATIVE-empty coverage block carries the "not applicable" note
    /// (never a bare clean verdict); a normal store does not.
    #[test]
    fn coverage_block_not_applicable_note() {
        let empty = CallEdgeCoverage {
            calls_authority_available: false,
            total_nodes: 5,
            total_fn_nodes: 0,
            live_fn_nodes: 0,
            fn_with_calls_live: 0,
            scip_calls_edges: 0,
            ratio_live: None,
        };
        let block = coverage_block_json(&empty, CoverageTier::NotApplicable);
        assert_eq!(block["note"], NOT_APPLICABLE_NOTE);
        // A Sufficient store carries NO note (no false "not applicable" framing).
        let normal = coverage_block_json(&cov(true, 5, Some(0.9)), CoverageTier::Sufficient);
        assert!(normal.get("note").is_none());
    }
}
