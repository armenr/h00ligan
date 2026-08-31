//! SCIP index loader — merges precise call/type edges from rust-analyzer
//! into the existing [`KnowledgeGraph`].
//!
//! SCIP (Sourcegraph Code Intelligence Protocol) indexes provide precise,
//! semantically-analyzed edges that complement the tree-sitter structural
//! analysis. When both sources agree on an edge, confidence is boosted.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tracing::{debug, trace};
use uuid::Uuid;

use crate::code_intel_cancellation::IndexCancellation;
use crate::graph::{EdgeKind, EdgeScope, EdgeSource, GraphEdge, KnowledgeGraph};
use crate::project_binding::{
    GeneratedArtifactState, ProjectPathError, inspect_generated_artifact,
    inspect_generated_directory,
};

// Re-export the scip protobuf types we use.
use protobuf::Enum as _;
use protobuf::Message as _;
use scip::types::{Document, Index, Occurrence, SymbolRole};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during SCIP index loading.
#[derive(Debug, thiserror::Error)]
pub enum ScipLoaderError {
    #[error("I/O error reading SCIP index: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse SCIP protobuf: {0}")]
    ProtobufParse(#[from] protobuf::Error),

    #[error("graph operation failed: {0}")]
    Graph(#[from] crate::graph::GraphError),

    #[error("generated SCIP artifact refused: {0}")]
    GeneratedArtifact(#[from] ProjectPathError),

    #[error("invalid SCIP document path: {0}")]
    DocumentPath(String),

    #[error("{what} timed out after {secs}s (killed)")]
    Timeout { what: &'static str, secs: u64 },

    #[error("{what} cancelled (provider process group killed and reaped)")]
    Cancelled { what: &'static str },
}

/// One invocation-scoped provider artifact and its executable identity.
///
/// Callers carry this tuple into normalization rather than reconstructing
/// provider authority from a filename or embedded metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedScipArtifact {
    pub path: std::path::PathBuf,
    pub provider_version: String,
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Statistics from a SCIP index load operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScipStats {
    /// Total symbols found in the SCIP index.
    pub symbols_found: usize,
    /// Number of `TypeOf` edges added.
    pub typeof_edges_added: usize,
    /// Number of existing edges that were merged (upgraded to `Both` source).
    pub merged_with_existing: usize,
    /// Number of novel SCIP-only edges added.
    pub novel_edges: usize,
    /// Number of occurrences skipped due to parse errors.
    pub skipped_unparseable: usize,
    /// ADR-0044: resolvable NON-local reference occurrences whose exact target
    /// symbol had NO indexed definition (fail-closed → no edge). The MEASURED
    /// recall-loss signal for the exact-symbol identity join (never assumed).
    pub refs_target_unindexed: usize,
    /// ADR-0044: resolvable `local N` reference occurrences with no matching
    /// per-document local definition (fail-closed → no edge).
    pub refs_target_local: usize,
    /// Reference occurrences whose exact TARGET resolved but whose enclosing
    /// definition (the edge SOURCE) was not found in the document (fail-closed
    /// → no edge). Until 2026-07-19 this was the ONLY pass-2 drop path with no
    /// counter — an unmetered silent miss in a pipeline whose misses are
    /// supposed to be MEASURED (found chasing the `NdjsonReceiverStream`
    /// false-DEAD; the resolved-target-dropped-for-lack-of-source class).
    pub refs_no_enclosing_def: usize,
    /// ADR-0044: second REAL definition of an already-present non-local symbol
    /// resolving to a DIFFERENT node id. The identity becomes unusably
    /// ambiguous; this counts and logs the collision.
    pub global_defs_clobbers: usize,
    /// Task #29: a DEF descriptor whose file-local resolution landed on an ALIAS
    /// slot ([`build_node_lookup`]'s generic-stripped / bare-trait / macro-bang
    /// tier) holding MORE than one node id — a genuine same-file naming collision.
    /// [`resolve_node`] fails closed on it (`single()`→`None`, NO join: no edge
    /// beats a wrong edge) and counts it here so the previously-silent alias
    /// ambiguity is MEASURED rather than swallowed. Only the alias tier is
    /// counted; an exact-tier (node `symbol_name`) collision keeps HEAD's silent
    /// fall-through, since it is a duplicate NODE, not the alias ambiguity the new
    /// GAP-1/GAP-2 aliases can introduce.
    pub def_resolve_ambiguous: usize,
    /// ADR-0044 Q4: resolvable NON-local RELATIONSHIP target (an Implements /
    /// TypeOf / References edge from `SymbolInformation.relationships`) whose
    /// exact symbol had NO indexed definition (fail-closed → no edge). The
    /// relationship-edge analogue of `refs_target_unindexed`; the MEASURED
    /// recall-loss signal for the relationship-path identity join.
    pub rels_target_unindexed: usize,
    /// ADR-0044 Q4: resolvable `local N` relationship target with no matching
    /// per-document local definition (fail-closed → no edge). The
    /// relationship-edge analogue of `refs_target_local`.
    pub rels_target_local: usize,
}

/// Per-document definition maps produced by pass 1 and consumed by pass 2
/// (ADR-0044). `definitions` is the reference SOURCE resolver (every resolved
/// definition in this document, local or not); `local_defs` holds this
/// document's `local N` TARGETS, which are document-scoped and never global.
struct DocDefs {
    /// scip-symbol → node_id for every resolved definition in this document,
    /// used by exact relationship-source identity joins.
    definitions: HashMap<String, Uuid>,
    /// scip-symbol → node_id for this document's `local N` definitions only.
    local_defs: HashMap<String, Uuid>,
    /// Exact provider-declared lexical extents for reference source ownership.
    /// Definitions without an enclosing extent are deliberately absent: a
    /// nearest preceding definition is not ownership authority.
    owners: DefinitionOwnerIndex,
}

/// Cross-document provider identity after all definitions have been observed.
/// A duplicated non-local symbol that joins to different structural nodes has
/// no authoritative target; retaining the first writer would manufacture a
/// residual cross-root relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobalDefinitionSlot {
    Unique(Uuid),
    Ambiguous,
}

impl GlobalDefinitionSlot {
    const fn unique(self) -> Option<Uuid> {
        match self {
            Self::Unique(node_id) => Some(node_id),
            Self::Ambiguous => None,
        }
    }
}

type GlobalDefinitions = HashMap<String, GlobalDefinitionSlot>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct ScipPosition(u64);

impl ScipPosition {
    fn new(line: i32, column: i32) -> Option<Self> {
        let line = u32::try_from(line).ok()?;
        let column = u32::try_from(column).ok()?;
        Some(Self((u64::from(line) << 32) | u64::from(column)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DefinitionOwnerInterval {
    start: ScipPosition,
    end: ScipPosition,
    node_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DefinitionOwnerAmbiguity {
    start: ScipPosition,
    end: ScipPosition,
}

#[derive(Debug, Default)]
struct DefinitionOwnerGroup {
    start: ScipPosition,
    /// Sorted by tightest end first, then stable node identity.
    candidates: Vec<(ScipPosition, Uuid)>,
}

/// Immutable per-document exact owner index.
///
/// Starts are sorted once. A max-end segment tree finds the rightmost start
/// group that still contains a reference in `O(log D)`, then a binary search
/// selects the tightest end in that group. Equal-span conflicting owners fail
/// closed. A construction-time sweep records the exact regions where malformed
/// crossing (non-laminar) extents cannot prove a unique lexical owner; lookups
/// in those regions also fail closed. This replaces the former `O(R × N)` scan
/// over every occurrence.
#[derive(Debug, Default)]
struct DefinitionOwnerIndex {
    groups: Vec<DefinitionOwnerGroup>,
    segment_base: usize,
    max_end_tree: Vec<ScipPosition>,
    ambiguities: Vec<DefinitionOwnerAmbiguity>,
}

impl DefinitionOwnerIndex {
    fn new(mut intervals: Vec<DefinitionOwnerInterval>) -> Self {
        intervals.retain(|interval| interval.start < interval.end);
        intervals.sort_unstable_by_key(|interval| (interval.start, interval.end, interval.node_id));
        intervals.dedup();
        let ambiguities = definition_owner_ambiguities(&intervals);

        let mut by_start =
            std::collections::BTreeMap::<ScipPosition, Vec<(ScipPosition, Uuid)>>::new();
        for interval in intervals {
            by_start
                .entry(interval.start)
                .or_default()
                .push((interval.end, interval.node_id));
        }
        let groups = by_start
            .into_iter()
            .map(|(start, mut candidates)| {
                candidates.sort_unstable();
                candidates.dedup();
                DefinitionOwnerGroup { start, candidates }
            })
            .collect::<Vec<_>>();
        let segment_base = groups.len().max(1).next_power_of_two();
        let mut max_end_tree = vec![ScipPosition::default(); segment_base * 2];
        for (index, group) in groups.iter().enumerate() {
            max_end_tree[segment_base + index] = group
                .candidates
                .iter()
                .map(|(end, _)| *end)
                .max()
                .unwrap_or_default();
        }
        for node in (1..segment_base).rev() {
            max_end_tree[node] = max_end_tree[node * 2].max(max_end_tree[node * 2 + 1]);
        }
        Self {
            groups,
            segment_base,
            max_end_tree,
            ambiguities,
        }
    }

    fn resolve(&self, reference: &Occurrence) -> Option<Uuid> {
        let position = occurrence_start_position(reference)?;
        let ambiguity_index = self
            .ambiguities
            .partition_point(|ambiguity| ambiguity.start <= position);
        if ambiguity_index > 0 && position < self.ambiguities[ambiguity_index - 1].end {
            return None;
        }
        let upper = self.groups.partition_point(|group| group.start <= position);
        let group_index =
            self.find_rightmost_containing(1, 0, self.segment_base, upper, position)?;
        let candidates = &self.groups.get(group_index)?.candidates;
        let candidate_index = candidates.partition_point(|(end, _)| *end <= position);
        let (tightest_end, node_id) = *candidates.get(candidate_index)?;
        let conflicting = candidates[candidate_index + 1..]
            .iter()
            .take_while(|(end, _)| *end == tightest_end)
            .any(|(_, candidate)| *candidate != node_id);
        (!conflicting).then_some(node_id)
    }

    fn find_rightmost_containing(
        &self,
        tree_node: usize,
        start: usize,
        end: usize,
        upper: usize,
        position: ScipPosition,
    ) -> Option<usize> {
        if start >= upper || self.max_end_tree.get(tree_node).copied()? <= position {
            return None;
        }
        if end - start == 1 {
            return (start < self.groups.len()).then_some(start);
        }
        let middle = start + (end - start) / 2;
        self.find_rightmost_containing(tree_node * 2 + 1, middle, end, upper, position)
            .or_else(|| {
                self.find_rightmost_containing(tree_node * 2, start, middle, upper, position)
            })
    }
}

/// Return the merged half-open regions in which the active owner extents do
/// not have one interval that is contained by every other active interval.
/// Valid lexical extents are laminar, so their maximum start and minimum end
/// belong to the same interval. Crossing extents separate those extrema and
/// cannot authorize either owner inside the overlap.
fn definition_owner_ambiguities(
    intervals: &[DefinitionOwnerInterval],
) -> Vec<DefinitionOwnerAmbiguity> {
    type BoundaryEvents = (Vec<usize>, Vec<usize>);

    let mut events = std::collections::BTreeMap::<ScipPosition, BoundaryEvents>::new();
    for (index, interval) in intervals.iter().enumerate() {
        events.entry(interval.start).or_default().0.push(index);
        events.entry(interval.end).or_default().1.push(index);
    }
    let boundaries = events.keys().copied().collect::<Vec<_>>();
    let mut active_starts =
        std::collections::BTreeMap::<ScipPosition, std::collections::BTreeSet<usize>>::new();
    let mut active_ends =
        std::collections::BTreeMap::<ScipPosition, std::collections::BTreeSet<usize>>::new();
    let mut ambiguities = Vec::<DefinitionOwnerAmbiguity>::new();

    for boundary_pair in boundaries.windows(2) {
        let point = boundary_pair[0];
        let next = boundary_pair[1];
        let Some((starting, ending)) = events.get(&point) else {
            continue;
        };

        // Extents are half-open: remove endings before admitting starts at the
        // same position.
        for &index in ending {
            let interval = intervals[index];
            remove_active_owner(&mut active_starts, interval.start, index);
            remove_active_owner(&mut active_ends, interval.end, index);
        }
        for &index in starting {
            let interval = intervals[index];
            active_starts
                .entry(interval.start)
                .or_default()
                .insert(index);
            active_ends.entry(interval.end).or_default().insert(index);
        }

        if point >= next || active_starts.is_empty() {
            continue;
        }
        let (Some((_, latest_starts)), Some((&earliest_end, _))) = (
            active_starts.last_key_value(),
            active_ends.first_key_value(),
        ) else {
            continue;
        };
        let mut proven_owner = None;
        let ambiguous = latest_starts
            .iter()
            .filter_map(|&index| {
                let interval = intervals[index];
                (interval.end == earliest_end).then_some(interval.node_id)
            })
            .any(|owner| {
                proven_owner.map_or_else(
                    || {
                        proven_owner = Some(owner);
                        false
                    },
                    |proven| proven != owner,
                )
            })
            || proven_owner.is_none();

        if ambiguous {
            if let Some(previous) = ambiguities.last_mut()
                && previous.end == point
            {
                previous.end = next;
            } else {
                ambiguities.push(DefinitionOwnerAmbiguity {
                    start: point,
                    end: next,
                });
            }
        }
    }

    ambiguities
}

fn remove_active_owner(
    active: &mut std::collections::BTreeMap<ScipPosition, std::collections::BTreeSet<usize>>,
    position: ScipPosition,
    index: usize,
) {
    let remove_group = active.get_mut(&position).is_some_and(|indices| {
        indices.remove(&index);
        indices.is_empty()
    });
    if remove_group {
        active.remove(&position);
    }
}

fn occurrence_start_position(occurrence: &Occurrence) -> Option<ScipPosition> {
    match occurrence.range.as_slice() {
        [line, start_column, _] | [line, start_column, _, _] => {
            ScipPosition::new(*line, *start_column)
        }
        _ => None,
    }
}

fn definition_owner_interval(
    occurrence: &Occurrence,
    node_id: Uuid,
) -> Option<DefinitionOwnerInterval> {
    let (start, end) = match occurrence.enclosing_range.as_slice() {
        [line, start_column, end_column] => (
            ScipPosition::new(*line, *start_column)?,
            ScipPosition::new(*line, *end_column)?,
        ),
        [start_line, start_column, end_line, end_column] => (
            ScipPosition::new(*start_line, *start_column)?,
            ScipPosition::new(*end_line, *end_column)?,
        ),
        _ => return None,
    };
    (start < end).then_some(DefinitionOwnerInterval {
        start,
        end,
        node_id,
    })
}

/// The FILE-KEYED, TWO-TIER node lookup [`build_node_lookup`](ScipLoader::build_node_lookup)
/// produces and [`resolve_node`] consumes (task #29 mod 2).
///
/// [`resolve_node`] tries the `exact` tier FIRST (exact key then leading-`::`
/// suffix strip) and consults `alias` ONLY on an exact-tier miss, so a derived
/// alias key can never shadow or regress an exact identity hit. A multi-candidate
/// `alias` slot is a genuine same-file collision and fails closed + counted; a
/// multi-candidate `exact` slot (a duplicate NODE) keeps HEAD's silent
/// fall-through.
struct NodeLookup {
    /// `(file_path, symbol_name) -> ids` — the node's own tree-sitter name.
    exact: HashMap<(String, String), Vec<Uuid>>,
    /// `(file_path, alias_key) -> ids` — generic-stripped, bare-trait (GAP 1),
    /// and macro-bang (GAP 2) cross-naming aliases; deduped by id at build time.
    alias: HashMap<(String, String), Vec<Uuid>>,
}

// ---------------------------------------------------------------------------
// Confidence constants
// ---------------------------------------------------------------------------

/// Confidence for edges confirmed by both tree-sitter and SCIP.
const CONFIDENCE_BOTH: f32 = 0.95;
/// Confidence for SCIP-only edges.
const CONFIDENCE_SCIP: f32 = 0.9;

// ---------------------------------------------------------------------------
// Bounded subprocess execution (WU-0014 L5 / item #19)
// ---------------------------------------------------------------------------

/// Upper bound on a single `rust-analyzer scip` invocation.
///
/// Generous (a cold SCIP index of a large workspace can legitimately take
/// minutes) but FINITE, so a wedged rust-analyzer cannot hang indexing forever.
/// Sized well above a slow-but-finishing real index so the real-SCIP fixture
/// negative control is never killed.
const SCIP_INDEX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Upper bound on the `rust-analyzer --version` availability probe.
///
/// A near-instant call; 30s bounds the pathological hang without false kills.
const RUST_ANALYZER_VERSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Put a provider command in a private process group so a timeout owns every
/// ordinary descendant it spawned (Cargo, rustc, build scripts, and helper
/// processes), not only the direct provider PID.
#[cfg(unix)]
fn configure_provider_process_group(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: `setpgid(0, 0)` runs in the forked child immediately before
    // `exec`, making that child the leader of a new process group. Returning
    // an error prevents `spawn` from claiming confinement it did not obtain.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

#[cfg(not(unix))]
fn configure_provider_process_group(_cmd: &mut std::process::Command) {}

/// Terminate the private provider process group and always reap its leader.
#[cfg(unix)]
fn terminate_provider_process_group(child: &mut std::process::Child) {
    let pid = child.id();
    // SAFETY: a successfully spawned child was made its own process-group
    // leader by `configure_provider_process_group`, so its PID is the PGID.
    let group_killed = unsafe { libc::killpg(pid as libc::pid_t, libc::SIGKILL) == 0 };
    if !group_killed {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(not(unix))]
fn terminate_provider_process_group(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Wait synchronously with a bounded, portable polling interval. This avoids
/// signal-handler/self-pipe implementations, which can abort under syscall
/// sandboxes that forbid writes from a SIGCHLD handler.
enum ProviderWaitOutcome {
    Exited(std::process::ExitStatus),
    TimedOut,
    Cancelled,
}

fn wait_for_child_until(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
    cancellation: Option<&IndexCancellation>,
) -> std::io::Result<ProviderWaitOutcome> {
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(ProviderWaitOutcome::Exited(status));
        }
        if cancellation.is_some_and(IndexCancellation::is_cancelled) {
            return Ok(ProviderWaitOutcome::Cancelled);
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Ok(ProviderWaitOutcome::TimedOut);
        }
        std::thread::sleep(remaining.min(POLL_INTERVAL));
    }
}

/// Run `cmd` to completion, capturing its output, but KILL it and return
/// [`ScipLoaderError::Timeout`] if it does not finish within `timeout`.
///
/// `what` names the operation for the timeout error. stdout/stderr are drained
/// on dedicated threads so a verbose provider cannot deadlock on a full pipe
/// while we wait. Synchronous
/// by design — callers run inside `spawn_blocking`.
fn output_with_timeout(
    mut cmd: std::process::Command,
    timeout: std::time::Duration,
    what: &'static str,
    cancellation: Option<&IndexCancellation>,
) -> Result<std::process::Output, ScipLoaderError> {
    use std::io::Read as _;
    use std::process::Stdio;

    if cancellation.is_some_and(IndexCancellation::is_cancelled) {
        return Err(ScipLoaderError::Cancelled { what });
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_provider_process_group(&mut cmd);
    let mut child = cmd.spawn().map_err(ScipLoaderError::Io)?;

    // Drain pipes concurrently to avoid a full-buffer deadlock; the reader
    // threads return once the child exits (or is killed) and its pipes close.
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let status = match wait_for_child_until(&mut child, timeout, cancellation)
        .map_err(ScipLoaderError::Io)?
    {
        ProviderWaitOutcome::Exited(status) => status,
        ProviderWaitOutcome::TimedOut => {
            // Hung past the bound: kill the provider's whole process group,
            // reap its leader, and surface a typed error. Provider children may
            // include Cargo, rustc, build scripts, and compiler helpers.
            terminate_provider_process_group(&mut child);
            let _ = out_handle.join();
            let _ = err_handle.join();
            return Err(ScipLoaderError::Timeout {
                what,
                secs: timeout.as_secs(),
            });
        }
        ProviderWaitOutcome::Cancelled => {
            terminate_provider_process_group(&mut child);
            let _ = out_handle.join();
            let _ = err_handle.join();
            return Err(ScipLoaderError::Cancelled { what });
        }
    };

    // `unwrap_or_default` here recovers an empty buffer on the (unreachable)
    // reader-thread panic rather than propagating a panic out of library code.
    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

// ---------------------------------------------------------------------------
// ScipLoader
// ---------------------------------------------------------------------------

/// Loads SCIP protobuf indexes and merges edges into a [`KnowledgeGraph`].
pub struct ScipLoader<'g> {
    graph: &'g mut KnowledgeGraph,
    /// Repository-local SCIP package names this loader treats as resolvable.
    ///
    /// [`Self::process_index`] derives this population from the
    /// `Document.symbols` entries SCIP defines as repository-document-owned.
    /// Package-less (`local N` / intra-file) symbols remain local. A dependency
    /// package that appears only in occurrences or external-symbol metadata is
    /// absent, so it cannot steal a local graph node through a common name.
    local_packages: HashSet<String>,
}

impl<'g> ScipLoader<'g> {
    /// Create a SCIP loader targeting the given graph.
    ///
    /// Repository-local package authority is derived from the exact admitted
    /// index when it is processed; callers do not need a language-specific
    /// package-manager probe.
    ///
    /// Note: not `const fn` because [`HashSet::new`] is not const-constructible.
    /// No production caller relies on const construction — all loaders are
    /// built at runtime inside `spawn_blocking`.
    pub fn new(graph: &'g mut KnowledgeGraph) -> Self {
        Self {
            graph,
            local_packages: HashSet::new(),
        }
    }

    /// Create a SCIP loader with additional caller-supplied local package names.
    ///
    /// This remains available for narrow compatibility controls. Production
    /// projection derives locality from admitted repository definitions and
    /// uses [`ScipLoader::new`].
    pub const fn with_local_packages(
        graph: &'g mut KnowledgeGraph,
        local_packages: HashSet<String>,
    ) -> Self {
        Self {
            graph,
            local_packages,
        }
    }

    /// Load a SCIP index from disk and merge its edges into the graph.
    ///
    /// This is designed to be called from a `spawn_blocking` context (the caller
    /// handles that). The method itself uses `std::fs::read` which is fine
    /// because it runs on a blocking thread.
    pub fn load_scip_index(&mut self, path: &Path) -> Result<ScipStats, ScipLoaderError> {
        let bytes = std::fs::read(path)?;
        self.load_scip_bytes(&bytes)
    }

    /// Project an already admitted canonical document population without
    /// materializing a second monolithic protobuf `Index`. The canonical
    /// snapshot owns metadata and identity validation; this boundary consumes
    /// only the immutable document shards needed by residual graph projection.
    pub(crate) fn load_scip_documents_in_memory<'a>(
        &mut self,
        documents: impl IntoIterator<Item = &'a Document>,
    ) -> Result<ScipStats, ScipLoaderError> {
        let documents = documents.into_iter().collect::<Vec<_>>();
        self.process_documents(&documents)
    }

    /// Load a SCIP index from raw bytes and merge its edges into the graph.
    ///
    /// Useful for testing with programmatically-built fixtures.
    pub fn load_scip_bytes(&mut self, bytes: &[u8]) -> Result<ScipStats, ScipLoaderError> {
        let index = Index::parse_from_bytes(bytes)?;
        self.process_index(&index)
    }

    /// Process a parsed SCIP `Index` and merge edges into the graph.
    ///
    /// ADR-0044 "Target-Only Global Identity Join" — TWO passes:
    ///   1. [`collect_definitions`](Self::collect_definitions) folds every
    ///      NON-local, NON-forward Definition across ALL documents into a global
    ///      `scip_symbol → unique node_id` index (conflicts become ambiguous), plus per-document
    ///      `definitions` (reference SOURCE) and `local_defs` (document-scoped
    ///      `local N` targets) maps.
    ///   2. [`process_references`](Self::process_references) resolves reference
    ///      AND relationship TARGETS by exact `Occurrence.symbol` identity against
    ///      the COMPLETE global index, fail-closed to no edge on a miss.
    ///
    /// Splitting into two passes makes reference resolution independent of
    /// document order (the global index is complete before any target lookup) and
    /// lets the `SymbolInformation.relationships` edge build see cross-document
    /// definitions it could not on HEAD.
    fn process_index(&mut self, index: &Index) -> Result<ScipStats, ScipLoaderError> {
        let documents = index.documents.iter().collect::<Vec<_>>();
        self.process_documents(&documents)
    }

    fn process_documents(&mut self, documents: &[&Document]) -> Result<ScipStats, ScipLoaderError> {
        let mut stats = ScipStats::default();

        // Every document admitted here is already rebased to the exact indexed
        // repository source population. SCIP's `Document.symbols` population
        // explicitly names symbols defined by that document, so its packages
        // are a language-neutral locality witness. Definition-shaped
        // occurrences alone are insufficient: providers may attach occurrences
        // for external symbols to a repository document. References to packages
        // with no repository-owned SymbolInformation remain unresolvable.
        self.local_packages
            .extend(repository_definition_packages_from_documents(documents));

        // Build a reverse lookup: (file_path, symbol_descriptor) → Uuid
        // from existing graph nodes, so we can match SCIP symbols to graph nodes.
        let node_lookup = self.build_node_lookup();

        // Pass 1: fold every document's definitions into the global identity
        // index, retaining per-document source + local maps for pass 2.
        let mut global_defs = GlobalDefinitions::new();
        let mut per_doc: Vec<DocDefs> = Vec::with_capacity(documents.len());
        for doc in documents {
            let doc_defs =
                self.collect_definitions(doc, &node_lookup, &mut global_defs, &mut stats);
            per_doc.push(doc_defs);
        }

        // Pass 2: resolve reference + relationship targets against the COMPLETE
        // global index (identity join, fail-closed).
        for (doc, doc_defs) in documents.iter().zip(per_doc.iter()) {
            self.process_references(doc, doc_defs, &global_defs, &mut stats)?;
        }

        debug!(
            symbols_found = stats.symbols_found,
            typeof_ = stats.typeof_edges_added,
            merged = stats.merged_with_existing,
            novel = stats.novel_edges,
            skipped = stats.skipped_unparseable,
            refs_target_unindexed = stats.refs_target_unindexed,
            refs_target_local = stats.refs_target_local,
            refs_no_enclosing_def = stats.refs_no_enclosing_def,
            rels_target_unindexed = stats.rels_target_unindexed,
            rels_target_local = stats.rels_target_local,
            global_defs_clobbers = stats.global_defs_clobbers,
            def_resolve_ambiguous = stats.def_resolve_ambiguous,
            "SCIP index loaded"
        );

        Ok(stats)
    }

    /// Build the FILE-KEYED, TWO-TIER node lookup ([`NodeLookup`]) from existing
    /// graph nodes, so a SCIP definition occurrence can match its tree-sitter node
    /// within the file the definition lives in.
    ///
    /// - The **exact** tier maps `(file_path, symbol_name) -> Vec<Uuid>` — the
    ///   node's own tree-sitter name. Normally one id per key.
    /// - The **alias** tier holds the derived, cross-naming keys and is consulted
    ///   by [`resolve_node`] ONLY after the exact tier misses, so an alias can
    ///   never shadow or regress an exact identity hit (task #29 mod 2). Three
    ///   alias families, all keyed by the node's OWN file_path:
    ///   1. **Generic-stripped** (branch a, ADR-0044 Q1): a decorated
    ///      `impl ReachabilityAnalyzer<'g>::analyze` node also answers to the
    ///      un-decorated `impl ReachabilityAnalyzer::analyze` the SCIP descriptor
    ///      carries. WAS in the single-map exact tier on HEAD; moved here so it
    ///      cannot pre-empt an exact hit.
    ///   2. **Bare-trait** (GAP 1, task #29): a trait-impl node written with a
    ///      QUALIFIED or GENERIC trait — `impl crate::llm::LlmClient for
    ///      ClaudeCliClient::stream` — also answers to the bare, generic-erased
    ///      `impl LlmClient for ClaudeCliClient::stream` that
    ///      `convert_scip_impl_notation` produces (SCIP emits the trait bare). The
    ///      qualifier sits MID-STRING inside `impl … for …`, unreachable by
    ///      leading-segment stripping — so only a node-side alias can bridge it.
    ///   3. **Macro-bang** (GAP 2, task #29): a `kind == "macro"` node named bare
    ///      (`rpc_with_reconnect`) also answers to the `rpc_with_reconnect!` the
    ///      SCIP descriptor carries. Kind-gated: no non-macro node ever receives a
    ///      bang key and no exact key contains `!`, so a `foo!` descriptor is
    ///      structurally incapable of binding a `fn foo`.
    ///
    /// Alias insertions are DEDUPED by node id (mod 3): if a node's generic-strip
    /// and bare-trait aliases produce the SAME key (a generic-but-unqualified
    /// impl), the key is inserted ONCE for that id, never twice — a `[id, id]`
    /// slot would fail `single()` and REGRESS a previously-working join. A slot
    /// with two DIFFERENT ids is a real collision and stays fail-closed + counted
    /// (`def_resolve_ambiguous`).
    ///
    /// ADR-0044: the former empty-file-path (`""`) cross-file last-segment slots
    /// are GONE — with the cross-file name-heuristic tower deleted (references +
    /// relationships now resolve by exact global identity, definitions are capped
    /// to file-local), nothing reads a `""`-keyed slot, so building one is dead.
    fn build_node_lookup(&self) -> NodeLookup {
        let mut exact: HashMap<(String, String), Vec<Uuid>> = HashMap::new();
        let mut alias: HashMap<(String, String), Vec<Uuid>> = HashMap::new();

        // Insert `id` under alias `key` for `file`, deduped by id: a slot never
        // holds the same id twice, so a node's own two aliases collapsing to one
        // key cannot self-collide into a `single()`→None regression (mod 3).
        let mut push_alias = |file: &str, key: String, id: Uuid| {
            let slot = alias.entry((file.to_string(), key)).or_default();
            if !slot.contains(&id) {
                slot.push(id);
            }
        };

        for node in self.graph.all_nodes() {
            let file = node.file_path.as_str();
            let name = &node.symbol_name;

            // Exact tier: the node's own tree-sitter name (file-keyed).
            exact
                .entry((node.file_path.clone(), name.clone()))
                .or_default()
                .push(node.memory_id);

            // Alias 1 — generic-stripped (branch a). Only when it differs.
            let stripped = strip_generic_params(name);
            if stripped != *name {
                push_alias(file, stripped, node.memory_id);
            }

            // Alias 2 — bare-trait (GAP 1). Only when it differs from `name`.
            if let Some(bare) = bare_trait_impl_alias(name) {
                push_alias(file, bare, node.memory_id);
            }

            // Alias 3 — macro-bang (GAP 2). Kind-gated to `"macro"` nodes.
            if node.kind == "macro" {
                push_alias(file, format!("{name}!"), node.memory_id);
            }
        }

        NodeLookup { exact, alias }
    }

    /// Pass 1 (ADR-0044): collect this document's definitions.
    ///
    /// Folds every NON-local, NON-forward Definition (occurrence-level AND
    /// `SymbolInformation`-level) into the cross-document `global_defs` index
    /// (a second REAL def to a DIFFERENT node id invalidates that identity,
    /// increments `global_defs_clobbers`, and is logged), and returns the per-document maps
    /// pass 2 consumes: `definitions` (the reference SOURCE resolver, unchanged
    /// behavior) and `local_defs` (document-scoped `local N` targets, which never
    /// enter the global index). Relationship edges are NOT built here — they move
    /// to pass 2 so they see the completed global index.
    fn collect_definitions(
        &self,
        doc: &Document,
        node_lookup: &NodeLookup,
        global_defs: &mut GlobalDefinitions,
        stats: &mut ScipStats,
    ) -> DocDefs {
        let file_path = &doc.relative_path;
        let mut definitions: HashMap<String, Uuid> = HashMap::new();
        let mut local_defs: HashMap<String, Uuid> = HashMap::new();
        let mut owner_intervals = Vec::new();

        for occ in &doc.occurrences {
            if occ.symbol.is_empty() {
                continue;
            }

            stats.symbols_found += 1;

            let is_definition = (occ.symbol_roles & SymbolRole::Definition.value()) != 0;
            if !is_definition {
                continue;
            }
            // A ForwardDefinition (a forward declaration) must NEVER claim the
            // global slot — a REAL Definition of the same symbol wins regardless
            // of document order (ADR-0044 F7).
            let is_forward = (occ.symbol_roles & SymbolRole::ForwardDefinition.value()) != 0;
            if is_forward {
                continue;
            }
            // Skip external-crate definitions — resolving them against the local
            // graph causes spurious matches (see `is_resolvable_symbol`).
            if !self.is_resolvable_symbol(&occ.symbol) {
                continue;
            }
            // A definition's file is known: resolve it file-locally (capped).
            let descriptor = extract_descriptor(&occ.symbol);
            let Some(node_id) = resolve_node(file_path, &descriptor, node_lookup, stats) else {
                continue;
            };
            if let Some(interval) = definition_owner_interval(occ, node_id) {
                owner_intervals.push(interval);
            }
            self.fold_definition(
                &occ.symbol,
                node_id,
                global_defs,
                &mut definitions,
                &mut local_defs,
                stats,
            );
        }

        // Also pull in definitions from the document's SymbolInformation entries
        // (same non-local fold rule; `SymbolInformation` carries no role bits, so
        // there is no ForwardDefinition to screen here).
        for sym_info in &doc.symbols {
            if sym_info.symbol.is_empty() {
                continue;
            }
            if !self.is_resolvable_symbol(&sym_info.symbol) {
                continue;
            }
            let descriptor = extract_descriptor(&sym_info.symbol);
            let Some(node_id) = resolve_node(file_path, &descriptor, node_lookup, stats) else {
                continue;
            };
            self.fold_definition(
                &sym_info.symbol,
                node_id,
                global_defs,
                &mut definitions,
                &mut local_defs,
                stats,
            );
        }

        DocDefs {
            definitions,
            local_defs,
            owners: DefinitionOwnerIndex::new(owner_intervals),
        }
    }

    /// Fold one resolved definition into the global + per-document maps under the
    /// ADR-0044 LOCAL-symbol guard: a `local N` symbol is document-scoped, so it
    /// routes to `local_defs` ONLY and NEVER enters `global_defs`; a non-local
    /// symbol folds into `global_defs` only while it identifies one structural
    /// node. A conflicting second definition makes the identity ambiguous and
    /// therefore unusable by every residual target join. Every resolved
    /// definition also enters the per-document `definitions` source map.
    fn fold_definition(
        &self,
        symbol: &str,
        node_id: Uuid,
        global_defs: &mut GlobalDefinitions,
        definitions: &mut HashMap<String, Uuid>,
        local_defs: &mut HashMap<String, Uuid>,
        stats: &mut ScipStats,
    ) {
        if symbol.starts_with("local ") {
            // Document-scoped local: per-doc map only.
            local_defs.insert(symbol.to_string(), node_id);
        } else {
            match global_defs.get_mut(symbol) {
                None => {
                    global_defs.insert(symbol.to_string(), GlobalDefinitionSlot::Unique(node_id));
                }
                Some(slot) => {
                    if matches!(*slot, GlobalDefinitionSlot::Unique(existing) if existing != node_id)
                    {
                        stats.global_defs_clobbers += 1;
                        *slot = GlobalDefinitionSlot::Ambiguous;
                        debug!(
                            symbol = %symbol,
                            "ADR-0044 global_defs clobber: a second definition of a \
                             non-local symbol resolved to a different node id; \
                             residual target identity is now ambiguous"
                        );
                    }
                }
            }
        }
        // Per-document exact symbol map used by relationship-source joins.
        definitions.insert(symbol.to_string(), node_id);
    }

    /// Pass 2 (ADR-0044): resolve this document's reference + relationship
    /// TARGETS against the COMPLETE global identity index, fail-closed.
    ///
    /// TARGET = exact `Occurrence.symbol` identity: `local N` symbols route to the
    /// per-document `local_defs`, every other symbol to `global_defs`; a miss is
    /// fail-closed (no edge, counted) — never a name heuristic. SOURCE resolution
    /// uses the prebuilt exact enclosing-extent index. The
    /// `SymbolInformation.relationships` edge build lives here so its target
    /// lookup sees cross-document definitions.
    fn process_references(
        &mut self,
        doc: &Document,
        doc_defs: &DocDefs,
        global_defs: &GlobalDefinitions,
        stats: &mut ScipStats,
    ) -> Result<(), ScipLoaderError> {
        let file_path = &doc.relative_path;

        // EC-7 (WU-0001): every novel edge built in this document has its SOURCE
        // (the enclosing definition) within this document — so the source's file
        // IS `doc.relative_path`. Compute the edge scope once per document and
        // thread it into every `add_or_merge_edge` call. The only test-ness
        // signal available to the SCIP loader is the file path (SCIP carries no
        // per-occurrence cfg(test) signal, and GraphNode carries no is_test_only
        // until WU-0003), so this is a file-LEVEL discrimination.
        //
        // CEILING (WU-0001): this CANNOT detect a #[cfg(test)] fn inside a
        // production .rs file — such a source stays Production until GraphNode
        // carries is_test_only (WU-0003 / CL-REACH-06). Reuses the extractor's
        // anchored `file_is_test` (NOT graph_query's unanchored `test_` substring
        // check, CL-REACH-06's target).
        let doc_scope = if crate::extractor::file_is_test(file_path) {
            EdgeScope::Test
        } else {
            EdgeScope::Production
        };

        // Relationship edges (MOVED from pass 1): SOURCE is per-document (a
        // relationship is intra-document); TARGET is the exact global identity,
        // fail-closed. Resolving against the COMPLETE global index fixes a latent
        // cross-document ordering dependency the per-pass build had on HEAD.
        for sym_info in &doc.symbols {
            if sym_info.symbol.is_empty() {
                continue;
            }
            let Some(from_id) = doc_defs.definitions.get(&sym_info.symbol).copied() else {
                continue;
            };
            for rel in &sym_info.relationships {
                if rel.symbol.is_empty() {
                    continue;
                }
                // Relationship targets to external crates cannot be resolved
                // against the local graph without causing inflation.
                if !self.is_resolvable_symbol(&rel.symbol) {
                    continue;
                }
                let is_local = rel.symbol.starts_with("local ");
                let to_id = if is_local {
                    doc_defs.local_defs.get(&rel.symbol).copied()
                } else {
                    global_defs
                        .get(&rel.symbol)
                        .copied()
                        .and_then(GlobalDefinitionSlot::unique)
                };
                let Some(to_id) = to_id else {
                    // Relationship target has no indexed definition → fail-closed
                    // (no edge; the miss is MEASURED, never a name heuristic).
                    if is_local {
                        stats.rels_target_local += 1;
                    } else {
                        stats.rels_target_unindexed += 1;
                    }
                    continue;
                };
                if rel.is_type_definition {
                    self.add_or_merge_edge(from_id, to_id, EdgeKind::TypeOf, doc_scope, stats)?;
                    stats.typeof_edges_added += 1;
                }
                if rel.is_implementation {
                    self.add_or_merge_edge(from_id, to_id, EdgeKind::Implements, doc_scope, stats)?;
                }
                if rel.is_reference {
                    self.add_or_merge_edge(from_id, to_id, EdgeKind::References, doc_scope, stats)?;
                }
            }
        }

        // Reference occurrences → residual TypeOf/References edges by exact
        // identity. Calls are projected only from normalized explicit-invocation
        // evidence after its source and structural joins succeed; raw symbol
        // shape cannot distinguish `let f = target` from `target()`.
        for occ in &doc.occurrences {
            if occ.symbol.is_empty() {
                continue;
            }

            let is_definition = (occ.symbol_roles & SymbolRole::Definition.value()) != 0;
            if is_definition {
                // Definitions were handled in pass 1.
                continue;
            }

            // CRITICAL: skip references to external-crate symbols BEFORE
            // attempting resolution (preserves the singleton-common-method-name
            // inflation guard — an external `.len()` never resolves to a local
            // singleton `len`).
            if !self.is_resolvable_symbol(&occ.symbol) {
                continue;
            }

            // TARGET = exact `Occurrence.symbol` identity join, fail-closed. A
            // resolvable reference whose target has no indexed definition gets NO
            // edge (Q2: no edge beats a wrong edge); the miss is MEASURED.
            let is_local = occ.symbol.starts_with("local ");
            let target_id = if is_local {
                doc_defs.local_defs.get(&occ.symbol).copied()
            } else {
                global_defs
                    .get(&occ.symbol)
                    .copied()
                    .and_then(GlobalDefinitionSlot::unique)
            };
            let Some(target_id) = target_id else {
                if is_local {
                    stats.refs_target_local += 1;
                } else {
                    stats.refs_target_unindexed += 1;
                    trace!(
                        symbol = %occ.symbol,
                        doc = %doc.relative_path,
                        "SCIP ref dropped: resolvable target has no indexed definition"
                    );
                }
                continue;
            };

            // SOURCE = the enclosing definition (per-document, unchanged).
            let Some(source_id) = doc_defs.owners.resolve(occ) else {
                stats.refs_no_enclosing_def += 1;
                trace!(
                    symbol = %occ.symbol,
                    doc = %doc.relative_path,
                    "SCIP ref dropped: target resolved but no enclosing definition (no edge source)"
                );
                continue;
            };

            if source_id == target_id {
                // Self-reference, skip.
                continue;
            }

            // Determine edge kind based on context.
            let edge_kind = classify_reference_edge(occ);

            self.add_or_merge_edge(source_id, target_id, edge_kind, doc_scope, stats)?;
            if edge_kind == EdgeKind::TypeOf {
                stats.typeof_edges_added += 1;
            }
        }

        Ok(())
    }

    /// Whether a SCIP symbol should be resolved against the local graph.
    ///
    /// Returns `true` for:
    /// - package-less symbols (`local N`-style intra-file references, whose
    ///   `extract_package` is `None`), and
    /// - symbols whose package is a member of this loader's derived
    ///   `local_packages` set.
    ///
    /// Returns `false` for any packaged symbol NOT in the set — every
    /// external-crate symbol (std/core/alloc/serde/tokio/…) and, when the set
    /// is empty (the permissive fallback), every packaged symbol. This is the
    /// gate that preserves the singleton-common-method-name inflation guard:
    /// because externals are never inserted into the derived set, an external
    /// `Vec::len` reference can never resolve to a local singleton `len` node.
    ///
    /// Replaces the former hardcoded `is_local_package` whitelist (ADR-0030 F4
    /// / ADR-0026 R2): the local-package set is now derived from project
    /// metadata at index time rather than hardcoded to a product-specific crate list, so
    /// non-h00 repositories resolve their own intra-workspace edges.
    fn is_resolvable_symbol(&self, scip_symbol: &str) -> bool {
        // Package-less (`local N` / malformed) → `None` → intra-file local,
        // always resolvable. Packaged → resolvable only if the package is in
        // the derived local set (externals are never inserted, preserving the
        // inflation guard).
        extract_package(scip_symbol).is_none_or(|pkg| self.local_packages.contains(pkg))
    }

    /// Add an edge or merge with an existing one (fusion logic).
    ///
    /// If an edge with the same `EdgeKind` already exists between the two nodes:
    /// - Update `source` to `EdgeSource::Both`
    /// - Set `confidence` to `CONFIDENCE_BOTH` (0.95)
    ///
    /// If this is a novel SCIP-only edge:
    /// - Set `source` to `EdgeSource::Scip`
    /// - Set `confidence` to `CONFIDENCE_SCIP` (0.9)
    fn add_or_merge_edge(
        &mut self,
        from: Uuid,
        to: Uuid,
        kind: EdgeKind,
        scope: EdgeScope,
        stats: &mut ScipStats,
    ) -> Result<(), ScipLoaderError> {
        // Check if an edge already exists with this kind.
        if let Some(existing) = self.find_edge_by_kind(from, to, kind) {
            // Merge: upgrade source and confidence. The existing edge keeps its
            // own scope (it was tagged at its own construction site — EC-7
            // tags only NOVEL edges; a merge does not re-scope).
            existing.source = EdgeSource::Both;
            existing.confidence = CONFIDENCE_BOTH;
            stats.merged_with_existing += 1;
        } else {
            // Novel SCIP edge. EC-7 (WU-0001): scope is derived from the source
            // document's file path by the caller (`doc_scope`).
            let edge = GraphEdge {
                kind,
                weight: 1.0,
                source: EdgeSource::Scip,
                confidence: CONFIDENCE_SCIP,
                scope,
                ..Default::default()
            };
            match self.graph.add_edge(from, to, edge) {
                Ok(()) => {
                    stats.novel_edges += 1;
                }
                Err(crate::graph::GraphError::NodeNotFound(_)) => {
                    // One of the nodes was removed since we built the lookup.
                    // Skip silently.
                    stats.skipped_unparseable += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Find a mutable reference to an existing edge between two nodes with a
    /// specific `EdgeKind`. Returns `None` if no such edge exists.
    fn find_edge_by_kind(
        &mut self,
        from: Uuid,
        to: Uuid,
        kind: EdgeKind,
    ) -> Option<&mut GraphEdge> {
        self.graph.find_edge_by_kind_mut(from, to, kind)
    }
}

// ---------------------------------------------------------------------------
// Helper: generate SCIP index by shelling out to rust-analyzer
// ---------------------------------------------------------------------------

/// Which Cargo feature set the SCIP indexer should compile against.
///
/// This is the **Rust instance of a per-language indexer feature-config**: a
/// typed knob that controls how the language's indexer (here, `rust-analyzer
/// scip`) is told which conditional-compilation surface to analyze. It is named
/// and shaped so a future per-language Resolver (ADR-0024 / ADR-0025) can lift
/// it cleanly — each language's indexer carries its own `…Features` config of
/// the same flavor (`Default` / `All` / an explicit `List`), and the dispatch
/// site selects one without a rewrite. **Do not collapse this back into an
/// inline `cargo.features = "all"` string** — the type *is* the seam.
///
/// # Why this matters (the false-DEAD bug it fixes, ADR-0030)
///
/// `rust-analyzer scip` compiles against the crate's **default** features. Code
/// behind a non-default `#[cfg(feature = "…")]` gate (e.g. `embed-ollama`,
/// `embed-openai`) is parsed by tree-sitter (cfg-blind — it still emits a graph
/// *node*) but omitted by SCIP (feature-scoped — it emits **no** edge). The
/// result is a false-DEAD: the symbol has a node but zero incoming SCIP edges.
/// Selecting [`ScipFeatures::All`] makes the indexer analyze every feature, so
/// the gated edges appear and the symbols classify correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScipFeatures {
    /// Compile against the crate's default feature set (rust-analyzer's native
    /// behavior — **no** `--config-path`). Preserves the historical default.
    Default,
    /// Compile against **all** features (maps to `cargo.features = "all"`).
    /// This is the SHIP-FLOOR default for our own indexing: it surfaces the
    /// feature-gated edges that would otherwise read as false-DEAD.
    All,
    /// Compile against an explicit list of features.
    List(Vec<String>),
}

impl ScipFeatures {
    /// Serialize this feature selection into the **`rust-analyzer scip`
    /// `--config-path` JSON** body, or `None` for [`ScipFeatures::Default`]
    /// (which needs no config file at all).
    ///
    /// The shape is the **nested** `{"cargo":{"features": …}}` form. This is
    /// load-bearing and was verified empirically against rust-analyzer 1.94.0:
    /// the *dotted* `{"rust-analyzer.cargo.features": …}` form is **silently
    /// ignored** (byte-identical output to default, exit 0) — a no-op trap. The
    /// nested form is the one that actually toggles feature compilation.
    fn config_json(&self) -> Option<serde_json::Value> {
        match self {
            Self::Default => None,
            Self::All => Some(serde_json::json!({ "cargo": { "features": "all" } })),
            Self::List(features) => Some(serde_json::json!({ "cargo": { "features": features } })),
        }
    }
}

/// The SHIP-FLOOR Rust feature selection for our own indexing (ADR-0030).
///
/// **Every production `generate_scip_index` call site passes THIS const**, and a
/// structural falsifier (`ship_floor_features_are_used_at_every_production_site`
/// in the h00ligan provenance suite) discovers those sites and asserts it, so a
/// site that quietly switches to [`ScipFeatures::Default`] fails a test.
pub const SHIP_FLOOR_RUST_FEATURES: ScipFeatures = ScipFeatures::All;

/// The argument vector + an optional live temp-config-file guard for a
/// `rust-analyzer scip` invocation.
///
/// `config_file` is kept alive (held by the caller) for as long as the spawned
/// process needs to read it; when it drops, the temp file is removed.
struct ScipCommand {
    /// Args passed to `rust-analyzer` (always begins `["scip", "."]`).
    args: Vec<String>,
    /// The temp config file, kept alive until after the process runs. `None`
    /// for [`ScipFeatures::Default`].
    config_file: Option<tempfile::TempPath>,
}

/// Build the `rust-analyzer scip` argument vector for the given feature
/// selection, writing a temp `--config-path` JSON file when one is required.
///
/// This is split out from [`generate_scip_index`] so the arg-vector is pure and
/// inspectable in a unit test **without** shelling the real binary: for
/// [`ScipFeatures::Default`] it returns exactly `["scip", "."]` and no temp
/// file; for [`ScipFeatures::All`] / [`ScipFeatures::List`] it writes the
/// nested-shape config and appends `--config-path <tmp>`.
fn build_scip_command(
    _root: &Path,
    output: &Path,
    features: &ScipFeatures,
) -> Result<ScipCommand, ScipLoaderError> {
    use std::io::Write as _;

    let mut args = vec![
        "scip".to_string(),
        ".".to_string(),
        "--output".to_string(),
        output.to_string_lossy().into_owned(),
    ];

    let mut cargo =
        serde_json::Map::from_iter([("extraArgs".to_string(), serde_json::json!(["--locked"]))]);
    if let Some(config) = features.config_json()
        && let Some(feature_selection) = config.get("cargo").and_then(|cargo| cargo.get("features"))
    {
        cargo.insert("features".to_string(), feature_selection.clone());
    }
    let config = serde_json::json!({"cargo": cargo});
    let mut tmp = tempfile::NamedTempFile::new().map_err(ScipLoaderError::Io)?;
    let body = serde_json::to_vec(&config).map_err(|e| {
        ScipLoaderError::Io(std::io::Error::other(format!(
            "failed to serialize SCIP provider config: {e}"
        )))
    })?;
    tmp.write_all(&body).map_err(ScipLoaderError::Io)?;
    tmp.flush().map_err(ScipLoaderError::Io)?;
    let path = tmp.into_temp_path();
    args.push("--config-path".to_string());
    args.push(path.to_string_lossy().into_owned());
    let config_file = Some(path);

    Ok(ScipCommand { args, config_file })
}

/// Shell out to `rust-analyzer scip .` to generate a SCIP index outside the
/// bound project.
///
/// `features` selects the Cargo feature surface the indexer compiles against —
/// pass [`ScipFeatures::All`] to surface feature-gated edges that would
/// otherwise read as false-DEAD (see [`ScipFeatures`]). [`ScipFeatures::Default`]
/// preserves the historical behavior (index.scip at the project root, no config
/// file).
///
/// Cargo is locked against manifest repair and every build artifact is confined
/// to `cache_root`. Shipped callers retain that non-authoritative directory
/// beneath the selected data root so successive publications can reuse Cargo's
/// validated build cache. This is designed to be called from a
/// `spawn_blocking` context.
pub fn generate_scip_index(
    root: &Path,
    output: &Path,
    cache_root: &Path,
    features: &ScipFeatures,
    cancellation: &IndexCancellation,
) -> Result<GeneratedScipArtifact, ScipLoaderError> {
    use std::process::Command;

    let provider_version = provider_version(
        Path::new("rust-analyzer"),
        "rust-analyzer",
        Some(cancellation),
    )?
    .ok_or_else(|| {
        ScipLoaderError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "rust-analyzer not found in PATH or its version probe failed",
        ))
    })?;
    inspect_generated_directory(cache_root)?;
    std::fs::create_dir_all(cache_root).map_err(ScipLoaderError::Io)?;
    inspect_generated_directory(cache_root)?;
    let cargo_target = cache_root.join("cargo-target");
    inspect_generated_directory(&cargo_target)?;
    std::fs::create_dir_all(&cargo_target).map_err(ScipLoaderError::Io)?;
    inspect_generated_directory(&cargo_target)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(ScipLoaderError::Io)?;
    }
    inspect_generated_artifact(output)?;
    let command = build_scip_command(root, output, features)?;

    let mut cmd = Command::new("rust-analyzer");
    cmd.args(&command.args)
        .current_dir(root)
        .env("CARGO_TARGET_DIR", cargo_target);
    // Bounded wait + kill: a wedged rust-analyzer must not hang indexing forever
    // (WU-0014 L5 #19). SCIP_INDEX_TIMEOUT is sized above a slow real index.
    let process_output = output_with_timeout(
        cmd,
        SCIP_INDEX_TIMEOUT,
        "rust-analyzer scip",
        Some(cancellation),
    )?;

    // Keep the temp config file alive until after rust-analyzer has run and we
    // have its output; dropping it earlier would unlink the config mid-flight.
    drop(command.config_file);

    if !process_output.status.success() {
        let stderr = String::from_utf8_lossy(&process_output.stderr);
        return Err(ScipLoaderError::Io(std::io::Error::other(format!(
            "rust-analyzer scip failed: {stderr}"
        ))));
    }

    match inspect_generated_artifact(output)? {
        GeneratedArtifactState::RegularFile => Ok(GeneratedScipArtifact {
            path: output.to_path_buf(),
            provider_version,
        }),
        GeneratedArtifactState::Absent => Err(ScipLoaderError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "rust-analyzer did not produce the requested SCIP artifact at {}",
                output.display()
            ),
        ))),
    }
}

// ---------------------------------------------------------------------------
// Free functions: SCIP symbol parsing and matching
// ---------------------------------------------------------------------------

/// Extract the package-name field from a SCIP symbol string.
///
/// SCIP symbols follow the format:
///   `scheme manager package_name version descriptor.`
///
/// For rust-analyzer, this looks like:
///   `rust-analyzer cargo h00ligan_engine 0.1.0 search/DistributionAwareReranker#normalize().`
///
/// The package_name is the third space-delimited token (index 2). For local
/// (intra-file) symbols (`local N`), this function returns `None` — local
/// symbols are considered part of the current compilation unit and must not
/// be treated as external.
fn extract_package(scip_symbol: &str) -> Option<&str> {
    // `local N` style symbols have no package field; treat as local.
    if scip_symbol.starts_with("local ") {
        return None;
    }

    let mut spaces_seen = 0;
    let mut field_start = 0;
    for (i, ch) in scip_symbol.char_indices() {
        if ch == ' ' {
            spaces_seen += 1;
            match spaces_seen {
                2 => field_start = i + 1,
                3 => return Some(&scip_symbol[field_start..i]),
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
fn repository_definition_packages(index: &Index) -> HashSet<String> {
    let documents = index.documents.iter().collect::<Vec<_>>();
    repository_definition_packages_from_documents(&documents)
}

fn repository_definition_packages_from_documents(documents: &[&Document]) -> HashSet<String> {
    documents
        .iter()
        .copied()
        .flat_map(|document| &document.symbols)
        .filter_map(|symbol| scip::symbol::parse_symbol(&symbol.symbol).ok())
        .filter_map(|symbol| symbol.package.as_ref().map(|package| package.name.clone()))
        .filter(|name| !name.is_empty())
        .collect()
}

/// Extract the human-readable descriptor portion from a SCIP symbol string.
///
/// SCIP symbols follow the format:
///   `scheme manager package_name version descriptor.`
///
/// For rust-analyzer, this looks like:
///   `rust-analyzer cargo h00ligan_engine 0.1.0 search/DistributionAwareReranker#normalize().`
///
/// We extract the descriptor portion (after the 4th space-separated token)
/// and convert it to a Rust-style name by replacing `/` with `::` and
/// stripping SCIP suffix markers (`#`, `.`, `()`, etc.).
fn extract_descriptor(scip_symbol: &str) -> String {
    // Local symbols have format "local N"
    if scip_symbol.starts_with("local ") {
        return scip_symbol.to_string();
    }

    // Global symbols: skip scheme + package (4 space-delimited fields).
    let mut spaces_seen = 0;
    let mut descriptor_start = 0;
    for (i, ch) in scip_symbol.char_indices() {
        if ch == ' ' {
            spaces_seen += 1;
            if spaces_seen == 4 {
                descriptor_start = i + 1;
                break;
            }
        }
    }

    if spaces_seen < 4 {
        // Malformed symbol — return as-is.
        return scip_symbol.to_string();
    }

    let raw_descriptor = &scip_symbol[descriptor_start..];

    // Convert SCIP descriptor to a more Rust-friendly name.
    // E.g. "graph/EdgeKind#TypeOf." → "EdgeKind::TypeOf"
    // The SCIP descriptor uses:
    //   `/` for namespace separator
    //   `#` for type members
    //   `.` for term/value members
    //   `()` for method signatures
    // EC-4c (WU-0001): strip the SCIP method-signature suffix. `().` is a plain
    // call; `(+<digits>).` is an overload index (rust-analyzer emits arbitrary
    // counts, not just 1/2/3). Strip ANY `(+<digits>).` generically, but NEVER
    // a non-digit `(+...)` (which may be a legitimate part of a name).
    let cleaned = raw_descriptor.replace(['/', '#'], "::").replace("().", "");
    let cleaned = strip_overload_markers(&cleaned);

    // Strip trailing `.` or `::` if present.
    let cleaned = cleaned.trim_end_matches('.').trim_end_matches("::");

    // Post-process: convert SCIP impl notation to tree-sitter convention.
    // rust-analyzer emits `impl#[Type]method` which after '#' → '::' becomes
    // `impl::[Type]method`. Tree-sitter names these as `impl Type::method`
    // (inherent) or `impl Trait for Type::method` (trait impl).
    convert_scip_impl_notation(cleaned)
}

/// EC-4c (WU-0001): strip every `(+<digits>).` overload marker from a SCIP
/// descriptor, leaving any non-digit `(+...)` sequence untouched.
///
/// rust-analyzer disambiguates overloaded methods with a `(+N)` index where `N`
/// is an arbitrary count (`(+1).`, `(+7).`, `(+12).`, …), not the fixed `{1,2,3}`
/// the old code special-cased. The strip is digit-count-agnostic and only fires
/// on the exact `(+ <one-or-more ASCII digits> ).` shape — a `(+x)` or any other
/// non-digit body is preserved verbatim.
fn strip_overload_markers(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        // Look for the start of a `(+<digits>).` marker.
        if bytes[i] == b'(' && i + 1 < bytes.len() && bytes[i + 1] == b'+' {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            // Require at least one digit, then a literal `).`.
            if j > i + 2 && j + 1 < bytes.len() && bytes[j] == b')' && bytes[j + 1] == b'.' {
                // Skip the whole `(+<digits>).` run.
                i = j + 2;
                continue;
            }
        }
        // `is_char_boundary`-safe: ASCII markers only matched above; copy the
        // next full char to preserve any multibyte content unchanged.
        let ch_len = s[i..].chars().next().map_or(1, |c| c.len_utf8());
        out.push_str(&s[i..i + ch_len]);
        i += ch_len;
    }
    out
}

/// Convert SCIP impl notation to tree-sitter naming convention.
///
/// After the initial `#` → `::` and `/` → `::` replacements, SCIP impl
/// descriptors look like `impl::[Type]method` or `impl::[Type][Trait]method`.
/// Tree-sitter names these as:
/// - Inherent impl: `impl Type::method`
/// - Trait impl:    `impl Trait for Type::method`
///
/// This function also strips backtick-quoted generics (e.g. `` `Type<T>` ``
/// → `Type`) since tree-sitter uses bare type names without generics in
/// `extract_impl_name`.
fn convert_scip_impl_notation(input: &str) -> String {
    // Find `impl::[` in the string. If not present, nothing to convert.
    let Some(impl_prefix_pos) = input.find("impl::[") else {
        return input.to_string();
    };

    // Everything before `impl::[` is the module prefix (e.g. `lance_store::`)
    let prefix = &input[..impl_prefix_pos];
    let after_impl = &input[impl_prefix_pos + "impl::[".len()..];

    // Parse first bracketed segment: the type name.
    let Some(first_close) = after_impl.find(']') else {
        return input.to_string();
    };
    let first_bracket_content = &after_impl[..first_close];
    let remainder = &after_impl[first_close + 1..];

    // Check if there's a second bracketed segment (trait impl).
    if let Some(inner) = remainder.strip_prefix('[') {
        // Trait impl: `impl::[Type][Trait]method` → `impl Trait for Type::method`
        let Some(second_close) = inner.find(']') else {
            return input.to_string();
        };
        let second_bracket_content = &inner[..second_close];
        let method_name = &inner[second_close + 1..];

        let type_name = strip_backtick_generics(first_bracket_content);
        let trait_name = strip_backtick_generics(second_bracket_content);

        if method_name.is_empty() {
            format!("{prefix}impl {trait_name} for {type_name}")
        } else {
            format!("{prefix}impl {trait_name} for {type_name}::{method_name}")
        }
    } else {
        // Inherent impl: `impl::[Type]method` → `impl Type::method`
        let type_name = strip_backtick_generics(first_bracket_content);
        let method_name = remainder;

        if method_name.is_empty() {
            format!("{prefix}impl {type_name}")
        } else {
            format!("{prefix}impl {type_name}::{method_name}")
        }
    }
}

/// Strip backtick-quoted generics from a type name.
///
/// rust-analyzer sometimes wraps type names with generics in backticks:
/// `` `Store<T>` `` → `Store`. Tree-sitter uses bare type names.
fn strip_backtick_generics(name: &str) -> &str {
    let name = name.trim_matches('`');
    // Strip generic parameters: `Store<T>` → `Store`
    name.find('<').map_or(name, |pos| &name[..pos])
}

/// Extract just the last segment of a descriptor for fuzzy matching.
///
/// E.g. `"graph::EdgeKind::TypeOf"` → `"TypeOf"`
fn last_segment(descriptor: &str) -> &str {
    descriptor.rsplit("::").next().unwrap_or(descriptor)
}

/// Try to resolve a SCIP DEFINITION descriptor to an existing graph node,
/// FILE-LOCALLY ONLY (ADR-0044 branch a), across the two-tier [`NodeLookup`].
///
/// Matching precedence (all keyed by the definition's own `file_path`):
/// 1. **Exact tier** — exact match on `(file_path, descriptor)`, then a
///    leading-`::` suffix strip (bridges SCIP module prefixes like
///    `lance_store::LanceStore::search_inner` to the unprefixed tree-sitter name).
///    An exact-tier hit ALWAYS wins; an alias may never shadow it (task #29 mod 2).
/// 2. **Alias tier** — consulted ONLY on an exact-tier miss, same exact-then-suffix
///    ladder over the generic-stripped / bare-trait (GAP 1) / macro-bang (GAP 2)
///    alias keys. A multi-candidate alias slot is a genuine same-file collision:
///    it fails closed (`single()`→`None`, NO join) AND increments
///    `stats.def_resolve_ambiguous` — no edge beats a wrong edge.
///
/// A file-local miss returns `None` (capped): the cross-file name-heuristic tower
/// is deleted, so references/relationships resolve their targets by the exact
/// global identity join instead, and a definition (whose file is known) never
/// guesses cross-file. An empty `file_path` yields `None`.
fn resolve_node(
    file_path: &str,
    descriptor: &str,
    lookup: &NodeLookup,
    stats: &mut ScipStats,
) -> Option<Uuid> {
    if file_path.is_empty() {
        // ADR-0044 (branch a): with a known file the resolve is file-local; with
        // an empty file there is nothing to resolve against (the cross-file tower
        // is deleted) → None.
        return None;
    }

    // Tier 1 — EXACT. A same-file multi-candidate here is a duplicate NODE, not
    // the alias ambiguity `def_resolve_ambiguous` measures, so it keeps HEAD's
    // silent `single()`→None fall-through (count_ambiguous = false).
    if let Some(id) = resolve_in_tier(file_path, descriptor, &lookup.exact, false, stats) {
        return Some(id);
    }

    // Tier 2 — ALIAS. Consulted only after the exact tier misses, so an alias can
    // never regress an exact hit; multi-candidate alias slots fail closed +
    // counted (count_ambiguous = true).
    resolve_in_tier(file_path, descriptor, &lookup.alias, true, stats)
}

/// File-local exact-then-suffix resolution within ONE tier of the lookup.
///
/// Tries `(file_path, descriptor)` first, then progressively strips leading `::`
/// segments off the descriptor. Each consulted slot goes through
/// [`single_or_count`]: exactly one id wins; a multi-candidate slot fails closed
/// and — when `count_ambiguous` — increments `stats.def_resolve_ambiguous`.
fn resolve_in_tier(
    file_path: &str,
    descriptor: &str,
    tier: &HashMap<(String, String), Vec<Uuid>>,
    count_ambiguous: bool,
    stats: &mut ScipStats,
) -> Option<Uuid> {
    if let Some(id) = single_or_count(
        tier.get(&(file_path.to_string(), descriptor.to_string())),
        count_ambiguous,
        stats,
    ) {
        return Some(id);
    }

    let mut remaining = descriptor;
    while let Some(pos) = remaining.find("::") {
        remaining = &remaining[pos + 2..];
        if remaining.is_empty() {
            break;
        }
        if let Some(id) = single_or_count(
            tier.get(&(file_path.to_string(), remaining.to_string())),
            count_ambiguous,
            stats,
        ) {
            return Some(id);
        }
    }
    None
}

/// Return the single id of a file-keyed lookup slot, if exactly one candidate is
/// present. A multi-candidate slot is genuinely ambiguous and falls through to
/// `None`; when `count_ambiguous` (the alias tier), it also increments
/// `stats.def_resolve_ambiguous` so the previously-silent collision is MEASURED.
fn single_or_count(
    ids: Option<&Vec<Uuid>>,
    count_ambiguous: bool,
    stats: &mut ScipStats,
) -> Option<Uuid> {
    match ids {
        Some(v) if v.len() == 1 => Some(v[0]),
        Some(v) if v.len() > 1 => {
            if count_ambiguous {
                stats.def_resolve_ambiguous += 1;
            }
            None
        }
        _ => None,
    }
}

/// Strip balanced `<…>` generic-parameter groups from a tree-sitter symbol name,
/// so a decorated node aliases to the un-decorated form a SCIP descriptor carries
/// (ADR-0044 branch a): `impl ReachabilityAnalyzer<'g>::analyze` → `impl
/// ReachabilityAnalyzer::analyze`, `Store<T>` → `Store`. Depth-tracked so nested
/// generics (`Map<K, Vec<V>>`) strip cleanly; unbalanced `>` is tolerated.
fn strip_generic_params(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut depth = 0usize;
    for ch in name.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

/// GAP 1 (task #29): the bare, generic-erased trait-impl alias key for a
/// tree-sitter node whose trait is written QUALIFIED and/or GENERIC in source.
///
/// `extractor::extract_impl_name` emits the trait's RAW source text, so a node is
/// named `impl crate::llm::LlmClient for ClaudeCliClient::stream` (qualified) or
/// `impl From<redb::TableError> for GraphStoreError::from` (generic). SCIP emits
/// the trait BARE (`LlmClient` / `From`), so `convert_scip_impl_notation` yields
/// the bare descriptor `impl LlmClient for ClaudeCliClient::stream`. The
/// qualifier/generic sits MID-STRING inside `impl … for …`, which
/// [`resolve_node`]'s leading-`::` suffix strip can never reach — so the join
/// misses unless the NODE side offers the bare key.
///
/// Returns the bare alias key, or `None` when the node is not a trait-impl or the
/// bare form is identical to `symbol_name` (nothing to bridge). The predicate is
/// WIDENED (mod 1) to match `impl ` at string start OR immediately after a `::`
/// boundary, so the module-nested `<mod>::impl …` nodes are covered too; the
/// module prefix is KEPT in the key so [`resolve_node`]'s file-local suffix match
/// still bridges the SCIP module prefix.
///
/// The trait's generics are stripped BEFORE the last-`::`-segment is taken
/// (`From<redb::TableError>` → `From`, never splitting inside the generic), and
/// the WHOLE candidate is generic-stripped once more to normalize a generic
/// self-type in the `for …` remainder.
fn bare_trait_impl_alias(symbol_name: &str) -> Option<String> {
    // Locate the `impl ` token: at string start, or right after a `::`.
    let impl_at = if symbol_name.starts_with("impl ") {
        0
    } else {
        // `+ 2` steps past the `::` so the split point is the `impl ` token.
        symbol_name.find("::impl ").map(|p| p + 2)?
    };
    let (prefix, body) = symbol_name.split_at(impl_at); // prefix is "" or "…::"
    let after_impl = body.strip_prefix("impl ")?;
    // Trait impls carry a ` for ` separator; inherent impls (`impl Type::m`) and
    // free `impl Trait` return-position types do not — split on the FIRST one.
    let (trait_seg, rest) = after_impl.split_once(" for ")?;

    // Strip generics BEFORE last-segment so a generic trait path
    // (`From<redb::TableError>`) yields `From`, never `TableError>` from a
    // `::`-split inside the generic argument.
    let trait_stripped = strip_generic_params(trait_seg);
    let trait_bare = last_segment(&trait_stripped);
    // Normalize a generic self-type in `rest` (e.g. `GraphStore<T>::from`) with a
    // final whole-key generic strip — matches the SCIP-derived bare key.
    let candidate = strip_generic_params(&format!("{prefix}impl {trait_bare} for {rest}"));
    if candidate == symbol_name {
        None
    } else {
        Some(candidate)
    }
}

/// Classify a raw reference occurrence as a residual semantic edge.
///
/// Only exact normalized invocation evidence may create `Calls`. A raw SCIP
/// reference whose symbol happens to name a function is still merely a
/// `References` edge here because its occurrence may be a function value,
/// callback, import, or invocation. Types remain `TypeOf`; everything else is
/// the honest residual `References` relation.
fn classify_reference_edge(occ: &Occurrence) -> EdgeKind {
    let symbol = &occ.symbol;

    // SCIP descriptor suffixes are the provider's language-neutral identity
    // contract: `#` denotes a type descriptor. Capitalization is not evidence
    // because exported Go values and Rust constants commonly begin uppercase.
    if symbol.ends_with('#') {
        return EdgeKind::TypeOf;
    }

    EdgeKind::References
}

fn provider_version(
    bin: &Path,
    tool_name: &str,
    cancellation: Option<&IndexCancellation>,
) -> Result<Option<String>, ScipLoaderError> {
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("--version");
    let output = output_with_timeout(
        cmd,
        RUST_ANALYZER_VERSION_TIMEOUT,
        "provider version",
        cancellation,
    )?;
    if !output.status.success() {
        return Ok(None);
    }
    let Some(first_line) = std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|output| output.lines().next())
        .map(str::trim)
    else {
        return Ok(None);
    };
    let version = first_line
        .strip_prefix(tool_name)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(first_line);
    Ok((!version.is_empty()).then(|| version.to_owned()))
}

/// Return the bounded executable version of `rust-analyzer` from `PATH`.
/// This is blocking I/O; callers in async contexts must wrap in `spawn_blocking`.
fn rust_analyzer_version() -> Option<String> {
    provider_version(Path::new("rust-analyzer"), "rust-analyzer", None)
        .ok()
        .flatten()
}

/// Check whether a version-identifiable `rust-analyzer` is available in PATH.
pub fn rust_analyzer_available() -> bool {
    rust_analyzer_version().is_some()
}

// ---------------------------------------------------------------------------
// Go: scip-go indexer seam (WU-0023 P3b Bundle-3)
// ---------------------------------------------------------------------------

/// Shell out to `scip-go index` to generate a SCIP index for the Go module
/// rooted at `root`, writing it to `output` (WU-0023 P3b Bundle-3).
///
/// The Go analogue of [`generate_scip_index`]. This adapter currently indexes
/// one deterministic default Go configuration (`GOFLAGS=-mod=readonly`). Go
/// build tags, GOOS, and GOARCH can select different source populations; when
/// this provider omits an indexed source document, normalization retains the
/// covered evidence and records the omitted file as an exact query-visible
/// qualification. Selecting and publishing additional configurations is a
/// separate capability contract. The `output` path keeps a Go index distinct
/// from a Rust `index.scip` in a mixed repo, so providers cannot clobber one
/// another's artifacts. `cache_root` retains Go's content-addressed build cache
/// and downloaded module cache beneath h00ligan's selected data directory.
///
/// Designed to be called from a `spawn_blocking` context.
pub fn generate_scip_go_index(
    root: &Path,
    output: &Path,
    cache_root: &Path,
    toolchain: &crate::code_intel_toolchain::ResolvedToolchain,
    cancellation: &IndexCancellation,
) -> Result<GeneratedScipArtifact, ScipLoaderError> {
    use std::process::Command;

    inspect_generated_directory(cache_root)?;
    std::fs::create_dir_all(cache_root).map_err(ScipLoaderError::Io)?;
    inspect_generated_directory(cache_root)?;
    let build_cache = cache_root.join("build");
    let module_cache = cache_root.join("modules");
    for cache in [&build_cache, &module_cache] {
        inspect_generated_directory(cache)?;
        std::fs::create_dir_all(cache).map_err(ScipLoaderError::Io)?;
        inspect_generated_directory(cache)?;
    }
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(ScipLoaderError::Io)?;
    }
    inspect_generated_artifact(output)?;
    let canonical_root = std::fs::canonicalize(root).map_err(ScipLoaderError::Io)?;
    if toolchain.language != "go" || toolchain.execution_root != canonical_root {
        return Err(ScipLoaderError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "resolved Go toolchain does not govern the requested execution root",
        )));
    }
    let provider = toolchain.components.get("scip-go").ok_or_else(|| {
        ScipLoaderError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "resolved Go toolchain has no scip-go component",
        ))
    })?;
    if !toolchain.components.contains_key("go") {
        return Err(ScipLoaderError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "resolved Go toolchain has no go component",
        )));
    }
    let provider_version = provider.version.clone();

    let mut cmd = Command::new(&provider.executable);
    // `--module-root .` (cwd == root) + `-o <output>` + `./...` (index every
    // package recursively — scip-go's default pattern, spelled explicitly).
    cmd.arg("index")
        .arg("--module-root")
        .arg(".")
        .arg("-o")
        .arg(output)
        .arg("./...")
        .current_dir(root)
        .env_clear()
        .envs(toolchain.process_environment())
        .env("GOFLAGS", "-mod=readonly")
        .env("GOCACHE", build_cache)
        .env("GOMODCACHE", module_cache);
    // Same generous-but-finite bound as the rust-analyzer index (a wedged
    // scip-go must not hang indexing forever).
    let out = output_with_timeout(cmd, SCIP_INDEX_TIMEOUT, "scip-go index", Some(cancellation))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(ScipLoaderError::Io(std::io::Error::other(format!(
            "scip-go index failed: {stderr}"
        ))));
    }
    match inspect_generated_artifact(output)? {
        GeneratedArtifactState::RegularFile => Ok(GeneratedScipArtifact {
            path: output.to_path_buf(),
            provider_version,
        }),
        GeneratedArtifactState::Absent => Err(ScipLoaderError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "scip-go did not produce the expected index file",
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reachability::ReachabilityClass;

    /// Explicit package seed for narrow resolver tests that intentionally omit
    /// the `Document.symbols` population. Production indexes derive the same
    /// authority from their repository-owned symbol information.
    fn h00_local_packages() -> HashSet<String> {
        [
            "h00ligan_engine",
            "h00ligan_interface",
            "h00_cli",
            "h00_core",
            "h00_sdl",
            "h00ligan",
            "h00_bench",
            "h00ligan-engine",
            "h00ligan-interface",
            "h00-cli",
            "h00-core",
            "h00-sdl",
            "h00ligan",
            "h00-bench",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn owner_interval(
        start_line: i32,
        start_column: i32,
        end_line: i32,
        end_column: i32,
        node_id: Uuid,
    ) -> DefinitionOwnerInterval {
        DefinitionOwnerInterval {
            start: ScipPosition::new(start_line, start_column).expect("valid start"),
            end: ScipPosition::new(end_line, end_column).expect("valid end"),
            node_id,
        }
    }

    fn reference_at(line: i32, column: i32) -> Occurrence {
        let mut occurrence = Occurrence::new();
        occurrence.range = vec![line, column, column + 1];
        occurrence
    }

    #[test]
    fn definition_owner_index_selects_the_tightest_nested_exact_extent() {
        let outer = Uuid::new_v4();
        let same_start_inner = Uuid::new_v4();
        let nested = Uuid::new_v4();
        let index = DefinitionOwnerIndex::new(vec![
            owner_interval(0, 0, 100, 0, outer),
            owner_interval(0, 0, 60, 0, same_start_inner),
            owner_interval(20, 0, 40, 0, nested),
        ]);

        assert_eq!(
            index.resolve(&reference_at(25, 0)),
            Some(nested),
            "latest nested start must select the innermost containing definition"
        );
        assert_eq!(
            index.resolve(&reference_at(50, 0)),
            Some(same_start_inner),
            "equal starts must select the tightest containing end"
        );
        assert_eq!(index.resolve(&reference_at(80, 0)), Some(outer));
        assert_eq!(
            index.resolve(&reference_at(100, 0)),
            None,
            "definition extents are half-open"
        );
    }

    #[test]
    fn definition_owner_index_fails_closed_on_equal_extent_conflicts() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let ambiguous = DefinitionOwnerIndex::new(vec![
            owner_interval(10, 0, 20, 0, first),
            owner_interval(10, 0, 20, 0, second),
        ]);
        assert_eq!(
            ambiguous.resolve(&reference_at(15, 0)),
            None,
            "two different definitions cannot own one exact extent"
        );

        let duplicate = DefinitionOwnerIndex::new(vec![
            owner_interval(10, 0, 20, 0, first),
            owner_interval(10, 0, 20, 0, first),
        ]);
        assert_eq!(
            duplicate.resolve(&reference_at(15, 0)),
            Some(first),
            "idempotent duplicate evidence is not an ownership conflict"
        );
    }

    #[test]
    fn definition_owner_index_fails_closed_only_where_extents_cross() {
        let left = Uuid::new_v4();
        let right = Uuid::new_v4();
        let index = DefinitionOwnerIndex::new(vec![
            owner_interval(0, 0, 90, 0, left),
            owner_interval(10, 0, 100, 0, right),
        ]);

        assert_eq!(
            index.resolve(&reference_at(5, 0)),
            Some(left),
            "the non-overlapping left extent still has one proven owner"
        );
        assert_eq!(
            index.resolve(&reference_at(50, 0)),
            None,
            "crossing non-nested extents cannot prove a unique owner"
        );
        assert_eq!(
            index.resolve(&reference_at(95, 0)),
            Some(right),
            "the non-overlapping right extent still has one proven owner"
        );
    }

    #[test]
    fn test_extract_descriptor_global_symbol() {
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 graph/EdgeKind#TypeOf.";
        assert_eq!(extract_descriptor(sym), "graph::EdgeKind::TypeOf");
    }

    #[test]
    fn test_extract_descriptor_method() {
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 search/Reranker#normalize().";
        assert_eq!(extract_descriptor(sym), "search::Reranker::normalize");
    }

    #[test]
    fn test_extract_descriptor_local() {
        let sym = "local 42";
        assert_eq!(extract_descriptor(sym), "local 42");
    }

    #[test]
    fn test_extract_descriptor_malformed() {
        let sym = "malformed";
        assert_eq!(extract_descriptor(sym), "malformed");
    }

    #[test]
    fn test_last_segment() {
        assert_eq!(last_segment("graph::EdgeKind::TypeOf"), "TypeOf");
        assert_eq!(last_segment("simple"), "simple");
        assert_eq!(last_segment(""), "");
    }

    #[test]
    fn function_shaped_reference_is_not_sufficient_calls_evidence() {
        let mut occ = Occurrence::new();
        occ.symbol = "rust-analyzer cargo pkg 0.1.0 mod/Struct#method().".to_string();
        assert_eq!(
            classify_reference_edge(&occ),
            EdgeKind::References,
            "raw symbol shape cannot distinguish `let f = target` from `target()`; only normalized invocation evidence may create Calls"
        );
    }

    #[test]
    fn test_classify_reference_type() {
        let mut occ = Occurrence::new();
        occ.symbol = "rust-analyzer cargo pkg 0.1.0 mod/MyStruct#".to_string();
        assert_eq!(classify_reference_edge(&occ), EdgeKind::TypeOf);
    }

    #[test]
    fn test_classify_reference_default() {
        let mut occ = Occurrence::new();
        occ.symbol = "rust-analyzer cargo pkg 0.1.0 mod/some_value.".to_string();
        assert_eq!(classify_reference_edge(&occ), EdgeKind::References);
    }

    #[test]
    fn capitalized_term_descriptor_is_still_a_value_reference() {
        let mut occ = Occurrence::new();
        occ.symbol = "scip-go gomod example.invalid/pkg 1.0.0 DefaultHandler.".to_string();
        assert_eq!(
            classify_reference_edge(&occ),
            EdgeKind::References,
            "SCIP descriptor suffix, not source-language capitalization convention, determines type identity"
        );
    }

    // --- resolve_node suffix matching tests (Bug 1 regression) ---

    /// A [`NodeLookup`] whose `exact` tier is seeded from `entries` and whose
    /// `alias` tier is seeded from `aliases` (task #29: tests drive the two-tier
    /// resolver directly).
    fn make_lookup(entries: &[(&str, &str, Uuid)], aliases: &[(&str, &str, Uuid)]) -> NodeLookup {
        let mut exact: HashMap<(String, String), Vec<Uuid>> = HashMap::new();
        let mut alias: HashMap<(String, String), Vec<Uuid>> = HashMap::new();
        for (file, name, id) in entries {
            exact
                .entry(((*file).to_string(), (*name).to_string()))
                .or_default()
                .push(*id);
        }
        for (file, name, id) in aliases {
            alias
                .entry(((*file).to_string(), (*name).to_string()))
                .or_default()
                .push(*id);
        }
        NodeLookup { exact, alias }
    }

    /// Build a lookup simulating a graph where tree-sitter extracted
    /// `LanceStore::search_inner` (no module prefix) in `lance_store.rs`.
    fn make_test_lookup() -> (NodeLookup, Uuid, Uuid) {
        let search_inner_id = Uuid::new_v4();
        let hybrid_search_id = Uuid::new_v4();
        let lookup = make_lookup(
            &[
                (
                    "src/lance_store.rs",
                    "LanceStore::search_inner",
                    search_inner_id,
                ),
                ("src/search.rs", "hybrid_search", hybrid_search_id),
            ],
            &[],
        );
        (lookup, search_inner_id, hybrid_search_id)
    }

    #[test]
    fn resolve_node_exact_match_with_file_path() {
        let (lookup, _, hybrid_search_id) = make_test_lookup();
        let mut stats = ScipStats::default();
        // Direct exact match: tree-sitter name matches directly.
        let result = resolve_node("src/search.rs", "hybrid_search", &lookup, &mut stats);
        assert_eq!(result, Some(hybrid_search_id));
    }

    #[test]
    fn resolve_node_suffix_match_strips_module_prefix() {
        let (lookup, search_inner_id, _) = make_test_lookup();
        let mut stats = ScipStats::default();
        // SCIP descriptor includes module prefix; tree-sitter symbol does not.
        // Without suffix matching, this would fall through to cross-file.
        // With suffix matching, it finds the file-local match.
        let result = resolve_node(
            "src/lance_store.rs",
            "lance_store::LanceStore::search_inner",
            &lookup,
            &mut stats,
        );
        assert_eq!(result, Some(search_inner_id));
    }

    /// ADR-0044 test migration: was `resolve_node_cross_file_last_segment`
    /// (asserted the DELETED cross-file last-segment resolution). INVERTED: with
    /// the tower capped to file-local, an empty `file_path` (the old cross-file
    /// entry point) resolves to `None` — references/relationships now use the
    /// exact global identity join, not this resolver's cross-file path. The
    /// genuinely-ambiguous `module::new` case (formerly two separate tests) is
    /// subsumed: every empty-`file_path` call is `None` now.
    #[test]
    fn resolve_node_cross_file_capped_to_none() {
        let (lookup, _, _) = make_test_lookup();
        let mut stats = ScipStats::default();
        // Cross-file (empty file_path) resolution is removed → None.
        assert_eq!(
            resolve_node("", "search::hybrid_search", &lookup, &mut stats),
            None
        );

        // Even a would-be-ambiguous cross-file lookup is simply None (no tower).
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let lookup2 = make_lookup(&[("src/a.rs", "new", id_a), ("src/b.rs", "new", id_b)], &[]);
        assert_eq!(resolve_node("", "module::new", &lookup2, &mut stats), None);
    }

    #[test]
    fn resolve_node_suffix_match_preferred_over_cross_file() {
        let correct_id = Uuid::new_v4();
        let wrong_id = Uuid::new_v4();
        let mut stats = ScipStats::default();

        // File-local node: `Store::search` in `store.rs`; another file has a
        // different `search`. (The deleted cross-file tower is gone; this pins
        // that the file-local exact-tier match binds the correct node.)
        let lookup = make_lookup(
            &[
                ("src/store.rs", "Store::search", correct_id),
                ("src/other.rs", "Other::search", wrong_id),
            ],
            &[],
        );

        // SCIP descriptor: `store::Store::search`
        // File-local suffix matching should find `(src/store.rs, Store::search)`.
        let result = resolve_node("src/store.rs", "store::Store::search", &lookup, &mut stats);
        assert_eq!(result, Some(correct_id));
    }

    // --- Integration test: SCIP edge creation with module prefix mismatch ---

    #[test]
    fn scip_creates_residual_reference_edge_across_module_prefix_mismatch() {
        use crate::graph::GraphNode;

        let mut graph = KnowledgeGraph::new();

        // Node for `search_inner` (tree-sitter name: `impl LanceStore::search_inner`)
        let caller_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: caller_id,
                symbol_name: "impl LanceStore::search_inner".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/lance_store.rs".to_string(),
                content_hash: "abc".to_string(),
                signature: "async fn search_inner()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(1170),
                line_end: Some(1200),
                has_body: Some(true),
                visibility: "pub(crate)".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add caller node");

        // Node for `hybrid_search` (tree-sitter name: `hybrid_search`)
        let target_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: target_id,
                symbol_name: "hybrid_search".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/search.rs".to_string(),
                content_hash: "def".to_string(),
                signature: "pub async fn hybrid_search()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(65),
                line_end: Some(160),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add target node");

        // Build a SCIP document that simulates rust-analyzer's output for
        // lance_store.rs. It has:
        // 1. A definition for `search_inner` with module-prefixed SCIP symbol
        // 2. A reference to `hybrid_search` from within `search_inner`
        let mut doc = Document::new();
        doc.relative_path = "crates/h00ligan-engine/src/lance_store.rs".to_string();

        // Definition: search_inner at line 1170
        // Real rust-analyzer format for impl methods: `impl#[Type]method().`
        let mut def_occ = Occurrence::new();
        def_occ.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 lance_store/impl#[LanceStore]search_inner()."
                .to_string();
        def_occ.symbol_roles = SymbolRole::Definition.value();
        def_occ.range = vec![1170, 14, 1170, 26]; // line 1170
        def_occ.enclosing_range = vec![1170, 0, 1201, 0];

        // Reference: hybrid_search at line 1191 (inside search_inner body)
        let mut ref_occ = Occurrence::new();
        ref_occ.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 search/hybrid_search().".to_string();
        ref_occ.symbol_roles = 0; // reference, not definition
        ref_occ.range = vec![1191, 16, 1191, 29]; // line 1191

        doc.occurrences = vec![def_occ, ref_occ];

        // ADR-0044 test migration: the hybrid_search TARGET must be an indexed
        // DEFINITION for the exact identity join to bind the edge (the
        // name-heuristic cross-file target resolution is deleted). The
        // module-prefix-mismatch aspect this test guards is the SOURCE
        // (search_inner) def resolving file-locally via suffix-strip — unchanged.
        let mut search_doc = Document::new();
        search_doc.relative_path = "crates/h00ligan-engine/src/search.rs".to_string();
        let mut hs_def = Occurrence::new();
        hs_def.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 search/hybrid_search().".to_string();
        hs_def.symbol_roles = SymbolRole::Definition.value();
        hs_def.range = vec![65, 0, 65, 13];
        search_doc.occurrences = vec![hs_def];

        let mut index = Index::new();
        index.documents = vec![doc, search_doc];

        // Load SCIP edges into graph.
        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");

        // The exact residual reference edge must survive the module-prefix
        // mismatch. Calls itself is projected from normalized invocation proof.
        assert!(
            stats.novel_edges > 0,
            "expected at least 1 residual edge, got 0. Stats: symbols_found={}, novel={}, skipped={}",
            stats.symbols_found,
            stats.novel_edges,
            stats.skipped_unparseable,
        );

        // Verify the edge exists in the graph.
        let neighbors = graph.neighbors(&caller_id);
        let has_reference_to_target = neighbors
            .iter()
            .any(|(id, edge)| *id == target_id && edge.kind == EdgeKind::References);
        assert!(
            has_reference_to_target,
            "expected residual reference edge from search_inner to hybrid_search"
        );
    }

    // ── EC-7b (WU-0001): novel SCIP edge scope from the source document path ─
    //
    // `add_or_merge_edge`'s novel branch built `GraphEdge { .., ..Default }`, so
    // edge.scope fell to EdgeScope::default()==Production with NO test
    // discrimination. A novel SCIP edge whose SOURCE occurrence lives in a test
    // FILE must be Test-scoped. The signal is the document's relative_path
    // (process_document binds it for every add_or_merge_edge call site); the only
    // test-ness signal available to the SCIP loader is the file path, since SCIP
    // carries no per-occurrence cfg(test) signal and GraphNode carries no
    // is_test_only until WU-0003. EdgeScope has no reader yet, so the proof is a
    // direct edge.scope assertion on the constructed graph.

    /// Build a fresh graph with a caller def node + a target node, run a SCIP
    /// document (relative_path = `doc_path`) carrying a def-occ for the caller
    /// and a ref-occ to the target — forming a NOVEL residual reference edge — and return
    /// `(graph, caller_id, target_id)`. Modeled on
    /// `scip_creates_calls_edge_across_module_prefix_mismatch`.
    fn build_novel_reference_edge_in_doc(doc_path: &str) -> (KnowledgeGraph, Uuid, Uuid) {
        use crate::graph::GraphNode;

        let mut graph = KnowledgeGraph::new();

        // Caller def node: `Caller::run` (tree-sitter name `impl Caller::run`),
        // living in the SAME file the SCIP document describes (so the def-occ
        // resolves file-locally and becomes the enclosing definition / source).
        let caller_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: caller_id,
                symbol_name: "impl Caller::run".to_string(),
                kind: "Function".to_string(),
                file_path: doc_path.to_string(),
                content_hash: "caller".to_string(),
                signature: "fn run()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(10),
                line_end: Some(20),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add caller node");

        // Target node: `helper` (cross-file, resolved via last-segment fallback).
        let target_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: target_id,
                symbol_name: "helper".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/helpers.rs".to_string(),
                content_hash: "helper".to_string(),
                signature: "pub fn helper()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(5),
                line_end: Some(8),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add target node");

        let mut doc = Document::new();
        doc.relative_path = doc_path.to_string();

        // Definition: Caller::run at line 10 (impl-method SCIP notation).
        let mut def_occ = Occurrence::new();
        def_occ.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 caller/impl#[Caller]run().".to_string();
        def_occ.symbol_roles = SymbolRole::Definition.value();
        def_occ.range = vec![10, 7, 10, 10];
        def_occ.enclosing_range = vec![10, 0, 21, 0];

        // Reference: helper() at line 12 (inside run's body).
        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 helpers/helper().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![12, 8, 12, 14];

        doc.occurrences = vec![def_occ, ref_occ];

        // ADR-0044 test migration: index the `helper` TARGET as a DEFINITION in
        // its own file's document so the exact identity join binds the edge
        // (cross-file name resolution is deleted). The novel-edge SCOPE behavior
        // these EC-7b tests assert — derived from the REF's document path — is
        // unchanged.
        let mut helper_doc = Document::new();
        helper_doc.relative_path = "crates/h00ligan-engine/src/helpers.rs".to_string();
        let mut helper_def = Occurrence::new();
        helper_def.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 helpers/helper().".to_string();
        helper_def.symbol_roles = SymbolRole::Definition.value();
        helper_def.range = vec![5, 0, 5, 6];
        helper_doc.occurrences = vec![helper_def];

        let mut index = Index::new();
        index.documents = vec![doc, helper_doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");
        assert!(
            stats.novel_edges > 0,
            "fixture must produce a NOVEL edge (not a merge); novel={}, skipped={}",
            stats.novel_edges,
            stats.skipped_unparseable,
        );

        (graph, caller_id, target_id)
    }

    #[test]
    fn ec7b_novel_scip_edge_source_in_test_file_is_test_scope() {
        // DISCRIMINATION-POSITIVE (RED on HEAD): the source occurrence lives in a
        // test FILE ("/tests/"), so the novel Calls edge must be Test-scoped.
        // RED on HEAD because the novel branch defaults scope to Production.
        let (graph, caller_id, target_id) =
            build_novel_reference_edge_in_doc("crates/h00ligan-engine/tests/it.rs");
        let edge = graph
            .neighbors(&caller_id)
            .into_iter()
            .find(|(t, e)| *t == target_id && e.kind == EdgeKind::References)
            .map(|(_, e)| (e.scope, e.source));
        assert_eq!(
            edge.map(|(s, _)| s),
            Some(EdgeScope::Test),
            "EC-7b: a novel SCIP edge whose source is in a test FILE must be Test-scoped"
        );
        // Confirm it is the novel branch, not a merge.
        assert_eq!(
            edge.map(|(_, src)| src),
            Some(EdgeSource::Scip),
            "EC-7b: the edge must be the novel SCIP branch (source==Scip)"
        );
    }

    #[test]
    fn ec7b_novel_scip_edge_source_in_prod_file_stays_production() {
        // ANTI-OVER-TAG (GREEN today, regression-pin): the same novel-edge shape
        // with a normal production src path must stay Production. Pins against a
        // blanket-Test mis-fix or an inverted file_is_test predicate.
        let (graph, caller_id, target_id) =
            build_novel_reference_edge_in_doc("crates/h00ligan-engine/src/lance_store.rs");
        let scope = graph
            .neighbors(&caller_id)
            .into_iter()
            .find(|(t, e)| *t == target_id && e.kind == EdgeKind::References)
            .map(|(_, e)| e.scope);
        assert_eq!(
            scope,
            Some(EdgeScope::Production),
            "EC-7b: a novel SCIP edge whose source is in a production file must stay Production"
        );
    }

    #[test]
    fn ec7b_ceiling_cfg_test_fn_in_production_file_stays_production() {
        // CEILING-PIN (GREEN today AND after the WU-0001 fix): the source models a
        // #[cfg(test)] fn living inside a PRODUCTION-path .rs file. SCIP carries
        // no per-occurrence cfg(test) signal, so the only available signal is the
        // file path — which says production. This edge therefore stays Production.
        //
        // CEILING (WU-0001): file-level file_is_test CANNOT detect a #[cfg(test)]
        // fn inside a production .rs; this stays Production until GraphNode carries
        // is_test_only — WU-0003 / CL-REACH-06. This is NOT a bug being fixed; the
        // pin makes the documented limitation a TESTED invariant (mirrors the
        // EC-3-miss lesson: make the silent-miss case an explicit assertion).
        // Without it a reader might wrongly assume EC-7b fully satisfies "SCIP
        // source is a #[cfg(test)] fn → scope==Test" (it only does for test-FILE
        // sources in WU-0001).
        let (graph, caller_id, target_id) =
            build_novel_reference_edge_in_doc("crates/h00ligan-engine/src/lance_store.rs");
        let scope = graph
            .neighbors(&caller_id)
            .into_iter()
            .find(|(t, e)| *t == target_id && e.kind == EdgeKind::References)
            .map(|(_, e)| e.scope);
        assert_eq!(
            scope,
            Some(EdgeScope::Production),
            "EC-7b CEILING: a cfg(test) fn inside a production .rs stays Production \
             (file-level signal cannot see it; WU-0003/CL-REACH-06 fixes this)"
        );
    }

    // --- extract_descriptor: SCIP impl notation conversion tests ---

    #[test]
    fn test_extract_descriptor_inherent_impl_method() {
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 lance_store/impl#[LanceStore]search_inner().";
        assert_eq!(
            extract_descriptor(sym),
            "lance_store::impl LanceStore::search_inner"
        );
    }

    #[test]
    fn test_extract_descriptor_trait_impl_method() {
        let sym =
            "rust-analyzer cargo h00ligan_engine 0.1.0 config/impl#[Config][Default]default().";
        assert_eq!(
            extract_descriptor(sym),
            "config::impl Default for Config::default"
        );
    }

    #[test]
    fn test_extract_descriptor_generic_type_impl() {
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 store/impl#[`Store<T>`]get().";
        assert_eq!(extract_descriptor(sym), "store::impl Store::get");
    }

    #[test]
    fn test_extract_descriptor_non_impl_method_unchanged() {
        // Free functions should not be affected by impl conversion.
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 search/hybrid_search().";
        assert_eq!(extract_descriptor(sym), "search::hybrid_search");
    }

    #[test]
    fn test_extract_descriptor_type_member_unchanged() {
        // Type members (not impl blocks) should pass through unchanged.
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 graph/EdgeKind#TypeOf.";
        assert_eq!(extract_descriptor(sym), "graph::EdgeKind::TypeOf");
    }

    // --- convert_scip_impl_notation unit tests ---

    #[test]
    fn test_convert_scip_impl_notation_no_impl() {
        assert_eq!(
            convert_scip_impl_notation("search::hybrid_search"),
            "search::hybrid_search"
        );
    }

    #[test]
    fn test_convert_scip_impl_notation_inherent() {
        assert_eq!(
            convert_scip_impl_notation("lance_store::impl::[LanceStore]search_inner"),
            "lance_store::impl LanceStore::search_inner"
        );
    }

    #[test]
    fn test_convert_scip_impl_notation_trait() {
        assert_eq!(
            convert_scip_impl_notation("config::impl::[Config][Default]default"),
            "config::impl Default for Config::default"
        );
    }

    #[test]
    fn test_convert_scip_impl_notation_generic() {
        assert_eq!(
            convert_scip_impl_notation("store::impl::[`Store<T>`]get"),
            "store::impl Store::get"
        );
    }

    #[test]
    fn test_convert_scip_impl_notation_no_method() {
        // Impl block reference without method name
        assert_eq!(
            convert_scip_impl_notation("mod::impl::[MyType]"),
            "mod::impl MyType"
        );
    }

    #[test]
    fn test_strip_backtick_generics_simple() {
        assert_eq!(strip_backtick_generics("Store"), "Store");
    }

    #[test]
    fn test_strip_backtick_generics_with_backticks_and_params() {
        assert_eq!(strip_backtick_generics("`Store<T>`"), "Store");
    }

    #[test]
    fn test_strip_backtick_generics_with_angle_brackets() {
        assert_eq!(strip_backtick_generics("HashMap<K, V>"), "HashMap");
    }

    // --- Integration test: trait impl Calls edge ---

    #[test]
    fn scip_creates_residual_reference_edge_for_trait_impl_method() {
        use crate::graph::GraphNode;

        let mut graph = KnowledgeGraph::new();

        // Node for `default` (tree-sitter name: `impl Default for Config::default`)
        let caller_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: caller_id,
                symbol_name: "impl Default for Config::default".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/config.rs".to_string(),
                content_hash: "aaa".to_string(),
                signature: "fn default() -> Self".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(50),
                line_end: Some(60),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add caller node");

        // Node for `validate` (free function)
        let target_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: target_id,
                symbol_name: "validate".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/config.rs".to_string(),
                content_hash: "bbb".to_string(),
                signature: "fn validate(cfg: &Config)".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(10),
                line_end: Some(20),
                has_body: Some(true),
                visibility: "pub(crate)".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add target node");

        let mut doc = Document::new();
        doc.relative_path = "crates/h00ligan-engine/src/config.rs".to_string();

        // Definition: Default::default for Config (trait impl format)
        let mut def_occ = Occurrence::new();
        def_occ.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 config/impl#[Config][Default]default()."
                .to_string();
        def_occ.symbol_roles = SymbolRole::Definition.value();
        def_occ.range = vec![50, 8, 50, 15];
        def_occ.enclosing_range = vec![50, 0, 61, 0];

        // Reference: validate() called from within default()
        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 config/validate().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![55, 12, 55, 20];

        // ADR-0044 test migration: index the `validate` TARGET as a definition
        // (same file) so the exact identity join binds the edge — the deleted
        // cross-file/file-local name heuristic no longer conjures the target.
        let mut validate_def = Occurrence::new();
        validate_def.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 config/validate().".to_string();
        validate_def.symbol_roles = SymbolRole::Definition.value();
        validate_def.range = vec![10, 4, 10, 12];

        doc.occurrences = vec![def_occ, validate_def, ref_occ];

        let mut index = Index::new();
        index.documents = vec![doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");

        assert!(stats.novel_edges > 0, "expected a residual semantic edge");

        let neighbors = graph.neighbors(&caller_id);
        let has_reference_to_target = neighbors
            .iter()
            .any(|(id, edge)| *id == target_id && edge.kind == EdgeKind::References);
        assert!(
            has_reference_to_target,
            "expected residual reference edge from Default::default to validate"
        );
    }

    // --- Repository package authority / extract_package tests ---

    #[test]
    fn extract_package_pulls_third_field() {
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 search/hybrid_search().";
        assert_eq!(extract_package(sym), Some("h00ligan_engine"));
    }

    #[test]
    fn extract_package_returns_none_for_local_symbol() {
        // `local N` symbols have no package field.
        assert_eq!(extract_package("local 5"), None);
    }

    #[test]
    fn extract_package_returns_none_for_malformed_symbol() {
        // Symbols with fewer than 3 space-delimited fields are malformed.
        assert_eq!(extract_package("too short"), None);
        assert_eq!(extract_package(""), None);
    }

    #[test]
    fn is_resolvable_symbol_accepts_local_and_rejects_external() {
        // The gate is now a `&self` method consulting the derived
        // `local_packages` set (F4): a loader carrying its derived local set resolves those
        // packages and rejects externals — the same behavior the old hardcoded
        // whitelist provided, now derived rather than baked in.
        let mut graph = KnowledgeGraph::new();
        let loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());

        // Local package symbol: resolvable.
        assert!(loader.is_resolvable_symbol(
            "rust-analyzer cargo h00ligan_engine 0.1.0 search/hybrid_search()."
        ));
        // External crate method: NOT resolvable (not in the set).
        assert!(
            !loader
                .is_resolvable_symbol("rust-analyzer cargo alloc 0.0.0 alloc/vec/impl#[Vec]len().")
        );
        assert!(
            !loader.is_resolvable_symbol(
                "rust-analyzer cargo core 0.0.0 core/slice/impl#[slice]len()."
            )
        );
        assert!(
            !loader.is_resolvable_symbol(
                "rust-analyzer cargo std 0.0.0 std/string/impl#[String]len()."
            )
        );
        // `local N` symbols: resolvable (intra-file, package-less).
        assert!(loader.is_resolvable_symbol("local 5"));
    }

    #[test]
    fn empty_local_set_resolves_only_package_less_symbols() {
        // The permissive fallback (F4): with an EMPTY set, only package-less
        // (`local N` / malformed) symbols resolve; every packaged symbol —
        // local OR external — is skipped. This is what `ScipLoader::new`
        // (empty default) provides, and it introduces zero cross-crate
        // inflation.
        let mut graph = KnowledgeGraph::new();
        let loader = ScipLoader::new(&mut graph);

        // Package-less: resolvable.
        assert!(loader.is_resolvable_symbol("local 5"));
        assert!(loader.is_resolvable_symbol("too short")); // malformed → None pkg
        // Any packaged symbol (even a fixture-local one): NOT resolvable with empty set.
        assert!(!loader.is_resolvable_symbol(
            "rust-analyzer cargo h00ligan_engine 0.1.0 search/hybrid_search()."
        ));
        assert!(
            !loader
                .is_resolvable_symbol("rust-analyzer cargo alloc 0.0.0 alloc/vec/impl#[Vec]len().")
        );
    }

    #[test]
    fn loader_with_local_set_still_drops_genuinely_external_singleton_name() {
        // F4-NEG-B: a NON-empty derived set is still membership-scoped. A loader
        // carrying {acme_widget} must STILL drop a genuinely-external symbol
        // whose package is std/core/alloc and whose last-segment name collides
        // with a local singleton — proving derived-set membership gating, not
        // "any non-empty set resolves everything." Built in-memory through the
        // real `is_resolvable_symbol` gate (process_index).
        use crate::graph::GraphNode;

        let mut graph = KnowledgeGraph::new();

        // Local caller in package acme_widget.
        let caller_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: caller_id,
                symbol_name: "do_work".to_string(),
                kind: "Function".to_string(),
                file_path: "src/work.rs".to_string(),
                content_hash: "caller".to_string(),
                signature: "fn do_work(v: &Vec<u64>) -> usize".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(10),
                line_end: Some(20),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add caller");

        // Singleton local `len` node (the only node with last-segment `len`).
        let singleton_len_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: singleton_len_id,
                symbol_name: "impl Widget::len".to_string(),
                kind: "Function".to_string(),
                file_path: "src/widget.rs".to_string(),
                content_hash: "local_len".to_string(),
                signature: "pub fn len(&self) -> usize".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(5),
                line_end: Some(7),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add singleton len");

        let mut doc = Document::new();
        doc.relative_path = "src/work.rs".to_string();

        // Definition: do_work in package acme_widget (IN the set).
        let mut def_occ = Occurrence::new();
        def_occ.symbol = "rust-analyzer cargo acme_widget 0.1.0 work/do_work().".to_string();
        def_occ.symbol_roles = SymbolRole::Definition.value();
        def_occ.range = vec![10, 4, 10, 11];

        // Reference: a std `len` — external, NOT in the set, even though the set
        // is non-empty. Must be dropped.
        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo std 0.0.0 std/string/impl#[String]len().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![12, 8, 12, 15];

        doc.occurrences = vec![def_occ, ref_occ];

        let mut index = Index::new();
        index.documents = vec![doc];

        // Non-empty set that DOES contain acme_widget but NOT std.
        let local_set: HashSet<String> = std::iter::once("acme_widget".to_string()).collect();
        let mut loader = ScipLoader::with_local_packages(&mut graph, local_set);
        let _stats = loader.process_index(&index).expect("process_index");

        // The std `len` reference must NOT resolve to the local singleton, even
        // though the loader's set is non-empty.
        let neighbors = graph.neighbors(&caller_id);
        let spurious = neighbors
            .iter()
            .any(|(id, edge)| *id == singleton_len_id && edge.kind == EdgeKind::References);
        assert!(
            !spurious,
            "F4-NEG-B: a std `len` ref resolved to a local singleton despite \
             std not being in the (non-empty) derived local-package set",
        );
    }

    // --- FIX-1: SCIP resolver skips external-crate references ---

    /// Regression test for the "singleton common-method-name" inflation bug.
    ///
    /// Before FIX-1, a SCIP reference occurrence whose symbol pointed to an
    /// external-crate method (e.g., `Vec::len` from `alloc`) would fall
    /// through `resolve_node`'s cross-file last-segment lookup and match any
    /// singleton local node that happened to share the same method name —
    /// turning every `.len()` call in the codebase into a spurious Calls
    /// edge targeting the sole local `len` node (`HebbianSnapshot::len`,
    /// observed at 688 incoming edges, of which ≤10 were genuine).
    #[test]
    fn scip_skips_external_crate_references_to_singleton_local_names() {
        use crate::graph::GraphNode;

        let mut graph = KnowledgeGraph::new();

        // Local caller — a function that would "call .len() on a Vec".
        let caller_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: caller_id,
                symbol_name: "process_items".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/foo.rs".to_string(),
                content_hash: "caller".to_string(),
                signature: "fn process_items(v: &Vec<u64>) -> usize".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(10),
                line_end: Some(20),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add caller");

        // Local singleton `len` node — this is the SAME shape as
        // `HebbianSnapshot::len` in the real graph: the only node whose
        // last-segment name is `len`.
        let singleton_len_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: singleton_len_id,
                symbol_name: "impl HebbianSnapshot::len".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/graph.rs".to_string(),
                content_hash: "local_len".to_string(),
                signature: "pub fn len(&self) -> usize".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(238),
                line_end: Some(240),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add singleton len");

        let mut doc = Document::new();
        doc.relative_path = "crates/h00ligan-engine/src/foo.rs".to_string();

        // Definition: process_items at line 10.
        let mut def_occ = Occurrence::new();
        def_occ.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 foo/process_items().".to_string();
        def_occ.symbol_roles = SymbolRole::Definition.value();
        def_occ.range = vec![10, 4, 10, 17];

        // Reference: `v.len()` at line 12 — the SCIP symbol for this resolves
        // to alloc's `Vec::len`, which is external. Before FIX-1 this
        // produced a Calls edge from process_items → impl HebbianSnapshot::len.
        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo alloc 0.0.0 alloc/vec/impl#[Vec]len().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![12, 8, 12, 15];

        doc.occurrences = vec![def_occ, ref_occ];

        let mut index = Index::new();
        index.documents = vec![doc];

        let mut loader = ScipLoader::new(&mut graph);
        let _stats = loader.process_index(&index).expect("process_index");

        // The critical assertion: the external-crate reference must NOT have
        // produced a Calls edge to the local singleton.
        let neighbors = graph.neighbors(&caller_id);
        let spurious_edge_exists = neighbors
            .iter()
            .any(|(id, edge)| *id == singleton_len_id && edge.kind == EdgeKind::References);
        assert!(
            !spurious_edge_exists,
            "FIX-1 regression: external-crate Vec::len reference wrongly \
             resolved to local singleton `impl HebbianSnapshot::len`",
        );
    }

    /// Complementary guard-rail: local-package references must still resolve.
    #[test]
    fn scip_still_resolves_references_inside_local_package() {
        use crate::graph::GraphNode;

        let mut graph = KnowledgeGraph::new();

        let caller_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: caller_id,
                symbol_name: "caller_fn".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/foo.rs".to_string(),
                content_hash: "caller".to_string(),
                signature: "fn caller_fn()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(5),
                line_end: Some(15),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add caller");

        let target_id = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: target_id,
                symbol_name: "target_fn".to_string(),
                kind: "Function".to_string(),
                file_path: "crates/h00ligan-engine/src/bar.rs".to_string(),
                content_hash: "target".to_string(),
                signature: "fn target_fn()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(1),
                line_end: Some(3),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add target");

        let mut doc = Document::new();
        doc.relative_path = "crates/h00ligan-engine/src/foo.rs".to_string();

        let mut def_occ = Occurrence::new();
        def_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 foo/caller_fn().".to_string();
        def_occ.symbol_roles = SymbolRole::Definition.value();
        def_occ.range = vec![5, 4, 5, 13];
        def_occ.enclosing_range = vec![5, 0, 16, 0];

        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 bar/target_fn().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![8, 8, 8, 17];

        doc.occurrences = vec![def_occ, ref_occ];

        // ADR-0044 test migration: index the `target_fn` TARGET as a definition
        // in its own file so the exact identity join binds the intra-workspace
        // edge (the deleted name heuristic no longer conjures the target).
        let mut target_doc = Document::new();
        target_doc.relative_path = "crates/h00ligan-engine/src/bar.rs".to_string();
        let mut target_def = Occurrence::new();
        target_def.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 bar/target_fn().".to_string();
        target_def.symbol_roles = SymbolRole::Definition.value();
        target_def.range = vec![1, 4, 1, 13];
        target_doc.occurrences = vec![target_def];

        let mut index = Index::new();
        index.documents = vec![doc, target_doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");

        assert!(
            stats.novel_edges > 0,
            "intra-workspace reference was dropped"
        );
        let neighbors = graph.neighbors(&caller_id);
        let has_reference = neighbors
            .iter()
            .any(|(id, edge)| *id == target_id && edge.kind == EdgeKind::References);
        assert!(has_reference, "expected local residual reference edge");
    }

    // -----------------------------------------------------------------------
    // EC-4c (WU-0001): extract_descriptor must strip a trailing `(+<digits>)`
    // overload marker GENERICALLY (any index), not a fixed {1,2,3} list — and
    // must NEVER mangle a non-digit `(+...)` that is part of a real name.
    // -----------------------------------------------------------------------

    #[test]
    fn ec4c_extract_descriptor_strips_high_overload_index_plus7() {
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 search/Reranker#normalize(+7).";
        assert_eq!(extract_descriptor(sym), "search::Reranker::normalize");
    }

    #[test]
    fn ec4c_extract_descriptor_strips_overload_index_plus12() {
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 graph/Builder#build(+12).";
        assert_eq!(extract_descriptor(sym), "graph::Builder::build");
    }

    #[test]
    fn ec4c_extract_descriptor_non_trailing_plus_paren_not_mangled() {
        // `(+x)` is NOT a digit overload index — it must survive untouched.
        // Guards against an over-general fix that strips any `(+...)`.
        let sym = "rust-analyzer cargo h00ligan_engine 0.1.0 macros/plus_macro(+x).";
        assert_eq!(extract_descriptor(sym), "macros::plus_macro(+x)");
    }

    // -----------------------------------------------------------------------
    // EC-4d (WU-0001): build_node_lookup nil-poison → Vec<Uuid>; resolve_node
    // disambiguates by a TOTAL deterministic order (file-local exact > longest
    // module-prefix overlap > shortest symbol_name > None), never HashMap order.
    // -----------------------------------------------------------------------

    #[test]
    fn ec4d_common_name_cross_file_calls_edge_resolved_not_dropped() {
        use crate::graph::GraphNode;

        let mut graph = KnowledgeGraph::new();

        // Two distinct `new` methods in different files — the classic poison.
        // The CALLER lives in a THIRD file (caller.rs) so resolution cannot take
        // a file-local shortcut and MUST go through the cross-file `new` lookup
        // (which is poisoned to nil today → the reference is dropped).
        let foo_new = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: foo_new,
                symbol_name: "Foo::new".to_string(),
                kind: "Function".to_string(),
                file_path: "src/foo.rs".to_string(),
                content_hash: "h1".to_string(),
                signature: "fn new()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(20),
                line_end: Some(22),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add Foo::new");
        let bar_new = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: bar_new,
                symbol_name: "Bar::new".to_string(),
                kind: "Function".to_string(),
                file_path: "src/bar.rs".to_string(),
                content_hash: "h2".to_string(),
                signature: "fn new()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(10),
                line_end: Some(12),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add Bar::new");
        // The caller, in caller.rs (NOT the callee's file → no file-local match).
        let caller = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: caller,
                symbol_name: "Builder::assemble".to_string(),
                kind: "Function".to_string(),
                file_path: "src/caller.rs".to_string(),
                content_hash: "h3".to_string(),
                signature: "fn assemble()".to_string(),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(30),
                line_end: Some(40),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add Builder::assemble");

        // SCIP document for src/caller.rs: def of Builder::assemble + a reference
        // to Foo::new. The reference descriptor's module path (`foo::Foo`) shares
        // the `Foo` module segment with Foo::new but not with Bar::new.
        let mut doc = Document::new();
        doc.relative_path = "src/caller.rs".to_string();

        let mut def_occ = Occurrence::new();
        def_occ.symbol =
            "rust-analyzer cargo h00ligan_engine 0.1.0 caller/Builder#assemble().".to_string();
        def_occ.symbol_roles = SymbolRole::Definition.value();
        def_occ.range = vec![30, 4, 30, 12];
        def_occ.enclosing_range = vec![30, 0, 40, 1];

        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 foo/Foo#new().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![35, 8, 35, 11];

        doc.occurrences = vec![def_occ, ref_occ];

        // ADR-0044 test migration: index Foo::new as a DEFINITION in foo.rs. The
        // ref carries `foo/Foo#new().`, whose EXACT symbol identity is Foo::new —
        // so the join binds it deterministically to Foo::new with no module-
        // overlap heuristic, and the same-named Bar::new (never defined by a ref
        // occ here) stays unwired. Stronger than the deleted disambiguation:
        // exact identity, not a name-similarity tiebreak.
        let mut foo_doc = Document::new();
        foo_doc.relative_path = "src/foo.rs".to_string();
        let mut foo_new_def = Occurrence::new();
        foo_new_def.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 foo/Foo#new().".to_string();
        foo_new_def.symbol_roles = SymbolRole::Definition.value();
        foo_new_def.range = vec![20, 4, 20, 7];
        foo_doc.occurrences = vec![foo_new_def];

        let mut index = Index::new();
        index.documents = vec![doc, foo_doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");

        // The residual edge must resolve to FOO's new by EXACT identity, NOT
        // bar's new, and must NOT be dropped.
        let has_reference_to_foo_new = graph
            .neighbors(&caller)
            .into_iter()
            .any(|(t, e)| t == foo_new && e.kind == EdgeKind::References);
        assert!(
            has_reference_to_foo_new,
            "ADR-0044: common-name `new` reference must resolve to Foo::new by \
             exact symbol identity, not be dropped"
        );
        let has_reference_to_bar_new = graph
            .neighbors(&caller)
            .into_iter()
            .any(|(t, e)| t == bar_new && e.kind == EdgeKind::References);
        assert!(
            !has_reference_to_bar_new,
            "EC-4d: the `new` reference must NOT wire to the cross-module Bar::new"
        );
    }

    // ADR-0044 test migration: RETIRED with the deleted cross-file heuristic
    // tower — `ec4d_resolve_node_deterministic_tiebreak_shortest_name_not_map_order`
    // (shortest-name tier), `ec4d_resolve_node_longest_module_prefix_overlap_wins`
    // (module_prefix_overlap tier), and
    // `ec4d_resolve_node_cross_file_poisoned_returns_none_preserved`
    // (disambiguation tie → None) all asserted behavior of `disambiguate_cross_file`
    // / `module_prefix_overlap`, which no longer exist. The cross-file entry point
    // now returns None unconditionally (`resolve_node_cross_file_capped_to_none`),
    // and the common-name resolution they modeled is covered STRONGER by exact
    // identity in `ec4d_common_name_cross_file_calls_edge_resolved_not_dropped`
    // and the ADR-0044 F1/F2/F6 falsifiers.

    // -----------------------------------------------------------------------
    // EC-4e (WU-0001): find_enclosing_definition must use `occ.enclosing_range`
    // (the body span) FIRST to attribute a reference to the def whose body
    // actually encloses it, falling back to `occ.range`'s start-line behavior
    // only when enclosing_range is empty (SCIP-OPTIONAL).
    // -----------------------------------------------------------------------

    /// Add a resolvable free-fn / method node to the graph in `file`.
    fn add_fn(graph: &mut KnowledgeGraph, id: Uuid, name: &str, file: &str, ls: usize, le: usize) {
        use crate::graph::GraphNode;
        graph
            .add_node(GraphNode {
                memory_id: id,
                symbol_name: name.to_string(),
                kind: "Function".to_string(),
                file_path: file.to_string(),
                content_hash: format!("h_{name}"),
                signature: format!("fn {name}()"),
                reachability_class: ReachabilityClass::Unclassified,
                line_start: Some(ls),
                line_end: Some(le),
                has_body: Some(true),
                visibility: "pub".to_string(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("add_fn");
    }

    #[test]
    fn ec4e_enclosing_range_picks_body_owner_not_closest_start_line() {
        let mut graph = KnowledgeGraph::new();
        let helper = Uuid::new_v4();
        let outer_run = Uuid::new_v4();
        let outer_cfg = Uuid::new_v4();
        add_fn(&mut graph, helper, "helper", "src/m.rs", 60, 70);
        add_fn(&mut graph, outer_run, "Outer::run", "src/m.rs", 14, 40);
        add_fn(&mut graph, outer_cfg, "Outer::cfg", "src/m.rs", 20, 22);

        let mut doc = Document::new();
        doc.relative_path = "src/m.rs".to_string();

        // def Outer::run: name-token range line 14, BODY enclosing_range [14,40].
        let mut def_run = Occurrence::new();
        def_run.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 m/Outer#run().".to_string();
        def_run.symbol_roles = SymbolRole::Definition.value();
        def_run.range = vec![14, 4, 14, 7];
        def_run.enclosing_range = vec![14, 0, 40, 1];

        // def Outer::cfg: short sibling, BODY [20,22] — does NOT enclose line 30.
        let mut def_cfg = Occurrence::new();
        def_cfg.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 m/Outer#cfg().".to_string();
        def_cfg.symbol_roles = SymbolRole::Definition.value();
        def_cfg.range = vec![20, 4, 20, 7];
        def_cfg.enclosing_range = vec![20, 0, 22, 1];

        // reference to helper at line 30: inside Outer::run [14,40], AFTER
        // Outer::cfg's start line 20 (the start-line trap).
        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 m/helper().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![30, 8, 30, 14];

        // ADR-0044 test migration: index the `helper` TARGET as a definition so
        // the exact join binds the edge; its body [60,70] does not enclose the
        // ref at line 30, so SOURCE attribution (Outer::run vs Outer::cfg) — the
        // property under test — is unaffected.
        let mut helper_def = Occurrence::new();
        helper_def.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 m/helper().".to_string();
        helper_def.symbol_roles = SymbolRole::Definition.value();
        helper_def.range = vec![60, 4, 60, 10];
        helper_def.enclosing_range = vec![60, 0, 70, 1];

        doc.occurrences = vec![def_run, def_cfg, helper_def, ref_occ];
        let mut index = Index::new();
        index.documents = vec![doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");

        // The residual edge to helper must originate from Outer::run (body owner),
        // not Outer::cfg (closest preceding start line).
        let run_references_helper = graph
            .neighbors(&outer_run)
            .into_iter()
            .any(|(t, e)| t == helper && e.kind == EdgeKind::References);
        assert!(
            run_references_helper,
            "EC-4e: helper reference edge must originate from Outer::run whose \
             enclosing_range body [14,40] contains line 30"
        );
        let cfg_references_helper = graph
            .neighbors(&outer_cfg)
            .into_iter()
            .any(|(t, e)| t == helper && e.kind == EdgeKind::References);
        assert!(
            !cfg_references_helper,
            "EC-4e: helper reference edge must NOT be attributed to Outer::cfg \
             (its body [20,22] does not enclose line 30)"
        );
    }

    #[test]
    fn crossing_enclosing_ranges_cannot_publish_a_guessed_residual_edge() {
        let mut graph = KnowledgeGraph::new();
        let left = Uuid::new_v4();
        let right = Uuid::new_v4();
        let target = Uuid::new_v4();
        add_fn(&mut graph, left, "left", "src/cross.rs", 0, 90);
        add_fn(&mut graph, right, "right", "src/cross.rs", 10, 100);
        add_fn(&mut graph, target, "target", "src/cross.rs", 110, 120);

        let definition = |symbol: &str, range: Vec<i32>, enclosing_range: Vec<i32>| {
            let mut occurrence = Occurrence::new();
            occurrence.symbol = symbol.to_string();
            occurrence.symbol_roles = SymbolRole::Definition.value();
            occurrence.range = range;
            occurrence.enclosing_range = enclosing_range;
            occurrence
        };
        let left_symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 cross/left().";
        let right_symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 cross/right().";
        let target_symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 cross/target().";
        let mut reference = Occurrence::new();
        reference.symbol = target_symbol.to_string();
        reference.range = vec![50, 0, 6];

        let mut document = Document::new();
        document.relative_path = "src/cross.rs".to_string();
        document.occurrences = vec![
            definition(left_symbol, vec![0, 0, 4], vec![0, 0, 90, 0]),
            definition(right_symbol, vec![10, 0, 5], vec![10, 0, 100, 0]),
            definition(target_symbol, vec![110, 0, 6], vec![110, 0, 120, 0]),
            reference,
        ];
        let mut index = Index::new();
        index.documents = vec![document];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader
            .process_index(&index)
            .expect("process malformed index");

        assert_eq!(
            stats.refs_target_unindexed, 0,
            "target identity is the positive control"
        );
        assert_eq!(
            stats.refs_no_enclosing_def, 1,
            "the crossing overlap must be measured as lacking a proven owner"
        );
        assert!(
            !has_reference_edge(&graph, left, target) && !has_reference_edge(&graph, right, target),
            "residual projection must not guess either crossing owner"
        );
    }

    #[test]
    fn ec4e_four_elem_enclosing_range_endline_is_third_element() {
        let mut graph = KnowledgeGraph::new();
        let sub = Uuid::new_v4();
        let big = Uuid::new_v4();
        let tiny = Uuid::new_v4();
        add_fn(&mut graph, sub, "sub", "src/w.rs", 80, 90);
        add_fn(&mut graph, big, "Wrapper::big", "src/w.rs", 5, 60);
        add_fn(&mut graph, tiny, "Wrapper::tiny", "src/w.rs", 50, 52);

        let mut doc = Document::new();
        doc.relative_path = "src/w.rs".to_string();

        // def Wrapper::big: name-token line 5, 4-elem enclosing_range body [5,60].
        let mut def_big = Occurrence::new();
        def_big.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 w/Wrapper#big().".to_string();
        def_big.symbol_roles = SymbolRole::Definition.value();
        def_big.range = vec![5, 4, 5, 7];
        def_big.enclosing_range = vec![5, 0, 60, 1];

        // def Wrapper::tiny: a later, NON-enclosing def, body [50,52], starts at
        // 50 (≤55) so start-line ordering wrongly prefers it on HEAD.
        let mut def_tiny = Occurrence::new();
        def_tiny.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 w/Wrapper#tiny().".to_string();
        def_tiny.symbol_roles = SymbolRole::Definition.value();
        def_tiny.range = vec![50, 4, 50, 7];
        def_tiny.enclosing_range = vec![50, 0, 52, 1];

        // reference to sub at line 55: within Wrapper::big [5,60] (enc[2]==60≥55)
        // but NOT within Wrapper::tiny [50,52].
        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 w/sub().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![55, 8, 55, 11];

        // ADR-0044 test migration: index the `sub` TARGET as a definition; its
        // body [80,90] does not enclose the ref at line 55, so the endLine-from-
        // enclosing_range property under test (Wrapper::big vs Wrapper::tiny) is
        // unaffected.
        let mut sub_def = Occurrence::new();
        sub_def.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 w/sub().".to_string();
        sub_def.symbol_roles = SymbolRole::Definition.value();
        sub_def.range = vec![80, 4, 80, 7];
        sub_def.enclosing_range = vec![80, 0, 90, 1];

        doc.occurrences = vec![def_big, def_tiny, sub_def, ref_occ];
        let mut index = Index::new();
        index.documents = vec![doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");

        let big_references_sub = graph
            .neighbors(&big)
            .into_iter()
            .any(|(t, e)| t == sub && e.kind == EdgeKind::References);
        assert!(
            big_references_sub,
            "EC-4e: sub reference edge must originate from Wrapper::big — endLine \
             must be read from the 4-elem enclosing_range's 3rd index (enc[2]==60)"
        );
        let tiny_references_sub = graph
            .neighbors(&tiny)
            .into_iter()
            .any(|(t, e)| t == sub && e.kind == EdgeKind::References);
        assert!(
            !tiny_references_sub,
            "EC-4e: sub reference edge must NOT be attributed to Wrapper::tiny \
             (body [50,52] excludes line 55)"
        );
    }

    #[test]
    fn enclosing_range_absence_cannot_authorize_a_preceding_definition_owner() {
        // A definition with no exact body extent plus a later reference cannot
        // prove lexical ownership. The old nearest-predecessor fallback silently
        // attributed sibling/module references to whichever definition happened
        // to start most recently.
        let mut graph = KnowledgeGraph::new();
        let caller = Uuid::new_v4();
        let callee = Uuid::new_v4();
        add_fn(&mut graph, caller, "outer_fn", "src/n.rs", 1170, 1200);
        add_fn(&mut graph, callee, "inner_fn", "src/n.rs", 1300, 1320);

        let mut doc = Document::new();
        doc.relative_path = "src/n.rs".to_string();

        let mut def_occ = Occurrence::new();
        def_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 n/outer_fn().".to_string();
        def_occ.symbol_roles = SymbolRole::Definition.value();
        def_occ.range = vec![1170, 14, 1170, 26];
        // enclosing_range deliberately left empty (default Vec::new()).

        let mut ref_occ = Occurrence::new();
        ref_occ.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 n/inner_fn().".to_string();
        ref_occ.symbol_roles = 0;
        ref_occ.range = vec![1191, 16, 1191, 29];

        // Index the target definition so target identity is a positive control;
        // only source ownership is intentionally absent.
        let mut inner_def = Occurrence::new();
        inner_def.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 n/inner_fn().".to_string();
        inner_def.symbol_roles = SymbolRole::Definition.value();
        inner_def.range = vec![1300, 4, 1300, 13];

        doc.occurrences = vec![def_occ, ref_occ, inner_def];
        let mut index = Index::new();
        index.documents = vec![doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");

        assert_eq!(
            stats.refs_target_unindexed, 0,
            "target identity must resolve"
        );
        assert_eq!(
            stats.refs_no_enclosing_def, 1,
            "missing exact owner extent must be measured"
        );
        let edge_from_caller = graph
            .neighbors(&caller)
            .into_iter()
            .any(|(t, _)| t == callee);
        assert!(
            !edge_from_caller,
            "a nearest preceding definition is not lexical ownership authority"
        );
    }

    // -----------------------------------------------------------------------
    // F1 (ADR-0030): feature-gated SCIP coverage — ScipFeatures / the
    // build_scip_command arg-vector. These assert on the *pure* command
    // builder so the unit leg never shells the real rust-analyzer binary.
    // -----------------------------------------------------------------------

    /// Helper: read back the JSON written to the `--config-path` file in an
    /// argv, returning `(config_path, parsed_json)`. Panics (test-only) if the
    /// flag/path/file is missing — that *is* the failure the caller asserts on.
    fn config_from_argv(args: &[String]) -> (std::path::PathBuf, serde_json::Value) {
        let idx = args
            .iter()
            .position(|a| a == "--config-path")
            .expect("argv must contain --config-path");
        let path = std::path::PathBuf::from(
            args.get(idx + 1)
                .expect("--config-path must be followed by a path"),
        );
        let body = std::fs::read_to_string(&path).expect("config file must exist on disk");
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("config file must be valid JSON");
        (path, json)
    }

    /// F1-UNIT-argvec-allfeatures: `ScipFeatures::All` emits `--config-path`
    /// pointing at a live temp file whose JSON is the *nested* `all` shape.
    /// Pins the EXACT nested shape so a regression to the dotted form (a silent
    /// rust-analyzer no-op) fails here, not silently in production.
    #[test]
    fn build_scip_command_all_features_passes_config_path_with_nested_all_features_json() {
        let root = std::path::Path::new(".");
        let output = std::path::Path::new("/tmp/h00-scip-test/index.scip");
        let command = build_scip_command(root, output, &ScipFeatures::All)
            .expect("build_scip_command(All) must Ok");

        // (a) starts with ["scip", "."].
        assert_eq!(
            &command.args[..2],
            &["scip".to_string(), ".".to_string()],
            "argv must begin with the scip subcommand on the current dir"
        );

        // (b) --config-path immediately followed by an existing path.
        let (config_path, json) = config_from_argv(&command.args);
        assert!(
            config_path.exists(),
            "the --config-path target must exist on disk while the command lives"
        );

        // (c) the file is the empirically-verified NESTED shape, NOT the dotted
        //     {"rust-analyzer.cargo.features":"all"} form (silently ignored by
        //     rust-analyzer 1.94.0 — verified byte-identical to default output).
        assert_eq!(
            json,
            serde_json::json!({
                "cargo": {"extraArgs": ["--locked"], "features": "all"}
            }),
            "config must combine immutable Cargo inputs with the nested feature shape"
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|args| args == ["--output", output.to_str().unwrap()])
        );

        // The temp-file guard is kept alive (Some), and no process was spawned.
        assert!(
            command.config_file.is_some(),
            "the TempPath guard must be returned so the file outlives the call"
        );
    }

    /// F1-UNIT-argvec-default-unchanged: `ScipFeatures::Default` is exactly the
    /// historical behavior — `["scip", "."]`, no `--config-path`, no temp file.
    /// Guards against the refactor silently always writing a config file.
    #[test]
    fn build_scip_command_default_still_locks_inputs_and_externalizes_output() {
        let root = std::path::Path::new(".");
        let output = std::path::Path::new("/tmp/h00-scip-test/index.scip");
        let command = build_scip_command(root, output, &ScipFeatures::Default)
            .expect("build_scip_command(Default) must Ok");

        assert!(
            command
                .args
                .windows(2)
                .any(|args| args == ["--output", output.to_str().unwrap()]),
            "provider output must never default into the project root"
        );
        let (_, json) = config_from_argv(&command.args);
        assert_eq!(
            json,
            serde_json::json!({"cargo": {"extraArgs": ["--locked"]}})
        );
        assert!(
            command.config_file.is_some(),
            "the immutable Cargo-input config must outlive the provider"
        );
    }

    /// F1-UNIT-argvec-list: `ScipFeatures::List` writes the nested *array* shape
    /// `{"cargo":{"features":[..]}}` and wires `--config-path` to it. Locks the
    /// List serialization so a per-language Resolver lift (ADR-0024/0025)
    /// inherits a verified-correct shape.
    #[test]
    fn build_scip_command_list_writes_nested_features_array_json() {
        let root = std::path::Path::new(".");
        let features =
            ScipFeatures::List(vec!["embed-ollama".to_string(), "embed-openai".to_string()]);
        let command = build_scip_command(root, std::path::Path::new("index.scip"), &features)
            .expect("build_scip_command(List) must Ok");

        let (config_path, json) = config_from_argv(&command.args);
        assert!(config_path.exists(), "List config file must exist on disk");
        assert_eq!(
            json,
            serde_json::json!({
                "cargo": {
                    "extraArgs": ["--locked"],
                    "features": ["embed-ollama", "embed-openai"]
                }
            }),
            "List must serialize to the nested features-array shape"
        );
        assert!(
            command.config_file.is_some(),
            "List must keep its TempPath guard alive"
        );
    }

    /// The all-features provider selection must yield a `--config-path` argv;
    /// otherwise a caller can silently request default feature coverage.
    #[test]
    fn generate_scip_index_all_features_builds_config_path() {
        let root = std::path::Path::new(".");
        let command =
            build_scip_command(root, std::path::Path::new("index.scip"), &ScipFeatures::All)
                .expect("All command must build");
        assert!(
            command.args.iter().any(|a| a == "--config-path"),
            "the floor default (All) must drive a --config-path invocation, \
             proving the callers wire feature coverage rather than Default"
        );
    }

    // -----------------------------------------------------------------------
    // WU-0014 L5 #19 — bounded subprocess timeout (falsifier + neg control).
    // -----------------------------------------------------------------------

    /// FALSIFIER (#19): a slow child driven through `output_with_timeout` with a
    /// tight bound must be KILLED and surface a `Timeout` error promptly — it
    /// must NOT block for the child's full runtime. On HEAD the helper does not
    /// exist (the call sites used unbounded `.output()`), so this is
    /// structurally RED there. We launch a `sleep 60` with a 200ms bound and
    /// assert it returns `Timeout` in well under a second (proving the child was
    /// killed, not awaited to completion; the helper's `wait()` after `kill()`
    /// reaps it, so no zombie remains).
    #[cfg(unix)]
    #[test]
    fn output_with_timeout_kills_a_hung_child() {
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("60");
        let start = std::time::Instant::now();
        let res = output_with_timeout(
            cmd,
            std::time::Duration::from_millis(200),
            "sleep-test",
            None,
        );
        let elapsed = start.elapsed();

        assert!(
            matches!(res, Err(ScipLoaderError::Timeout { .. })),
            "a child exceeding the bound must return Timeout, got: {res:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the helper must kill the child near the 200ms bound, not wait out \
             the 60s sleep; elapsed = {elapsed:?}"
        );
    }

    /// A provider can spawn build-script/compiler grandchildren. Killing only
    /// its direct process leaves those descendants alive and still writing to
    /// the disposable workspace, so the timeout boundary must own a process
    /// group rather than one PID.
    #[cfg(unix)]
    #[test]
    fn output_with_timeout_kills_a_hung_child_process_group() {
        let temporary = tempfile::TempDir::new().expect("temporary process fixture");
        let heartbeat = temporary.path().join("heartbeat");
        let child_pid = temporary.path().join("child.pid");
        let mut cmd = std::process::Command::new("sh");
        cmd.args([
            "-c",
            "while :; do printf x >> \"$1\"; sleep 0.05; done & echo $! > \"$2\"; wait",
            "sh",
        ])
        .arg(&heartbeat)
        .arg(&child_pid);

        let result = output_with_timeout(
            cmd,
            std::time::Duration::from_millis(250),
            "process-group-test",
            None,
        );
        assert!(matches!(result, Err(ScipLoaderError::Timeout { .. })));

        let pid = std::fs::read_to_string(&child_pid)
            .expect("grandchild pid fixture")
            .trim()
            .parse::<libc::pid_t>()
            .expect("numeric grandchild pid");
        let bytes_after_timeout = std::fs::metadata(&heartbeat)
            .expect("heartbeat after timeout")
            .len();
        std::thread::sleep(std::time::Duration::from_millis(250));
        let bytes_after_grace = std::fs::metadata(&heartbeat)
            .expect("heartbeat after grace")
            .len();

        // Always clean up the deliberately leaked negative-control process so
        // the RED test cannot leave residue on an implementation that kills
        // only the direct child.
        if bytes_after_grace != bytes_after_timeout {
            // SAFETY: `pid` was written by the fixture's own direct descendant
            // and is used only to terminate that disposable test process.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert_eq!(
            bytes_after_grace, bytes_after_timeout,
            "no grandchild may keep writing after the timeout returns"
        );
    }

    #[cfg(unix)]
    #[test]
    fn output_with_timeout_cancellation_kills_and_reaps_provider_group() {
        let temporary = tempfile::TempDir::new().expect("temporary cancellation fixture");
        let heartbeat = temporary.path().join("heartbeat");
        let mut cmd = std::process::Command::new("sh");
        cmd.args([
            "-c",
            "while :; do printf x >> \"$1\"; sleep 0.05; done & wait",
            "sh",
        ])
        .arg(&heartbeat);

        let cancellation = IndexCancellation::new();
        let cancel_from_thread = cancellation.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            cancel_from_thread.cancel();
        });
        let started = std::time::Instant::now();
        let result = output_with_timeout(
            cmd,
            std::time::Duration::from_secs(30),
            "provider-cancellation-test",
            Some(&cancellation),
        );
        canceller.join().expect("canceller thread");

        assert!(matches!(result, Err(ScipLoaderError::Cancelled { .. })));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "cancellation must not wait for the provider timeout"
        );
        let bytes_after_cancel = std::fs::metadata(&heartbeat)
            .expect("heartbeat after cancellation")
            .len();
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert_eq!(
            std::fs::metadata(&heartbeat)
                .expect("heartbeat after cancellation grace")
                .len(),
            bytes_after_cancel,
            "no provider descendant may survive a completed cancellation"
        );
    }

    /// NEGATIVE CONTROL (#19): a child that finishes WELL within the bound must
    /// return `Ok` (not killed). `true` exits ~instantly under a 5s bound.
    #[cfg(unix)]
    #[test]
    fn output_with_timeout_lets_a_fast_child_finish() {
        let cmd = std::process::Command::new("true");
        let res = output_with_timeout(cmd, std::time::Duration::from_secs(5), "true-test", None)
            .expect("a fast child must not be killed");
        assert!(
            res.status.success(),
            "`true` must exit 0 within the bound (Ok, not Timeout)"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ADR-0044 exact-symbol-join falsifiers (RED-on-HEAD; falsifier author ≠
    // code author). Each asserts the POST-FIX behavior and therefore FAILS on
    // the current clean tree, for the mechanism named in ADR-0044's falsifier
    // plan. They drive the real `process_index` reference path via programmatic
    // Index/Document/Occurrence fixtures + graph nodes. No production code is
    // modified; the WU build phase turns them GREEN.
    // ═══════════════════════════════════════════════════════════════════════

    /// Minimal graph node: id / tree-sitter `symbol_name` / file, big body span.
    fn adr44_node(id: Uuid, symbol_name: &str, file: &str) -> crate::graph::GraphNode {
        crate::graph::GraphNode {
            memory_id: id,
            symbol_name: symbol_name.to_string(),
            kind: "Function".to_string(),
            file_path: file.to_string(),
            content_hash: format!("h-{symbol_name}"),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(1),
            line_end: Some(999),
            has_body: Some(true),
            visibility: "pub".to_string(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    /// A SCIP definition occurrence for `symbol` at `line`.
    fn def_occ_at(symbol: &str, line: i32) -> Occurrence {
        let mut o = Occurrence::new();
        o.symbol = symbol.to_string();
        o.symbol_roles = SymbolRole::Definition.value();
        o.range = vec![line, 0, line, 10];
        o
    }

    /// A definition with an exact provider-declared lexical body extent.
    fn owner_def_occ_at(symbol: &str, start_line: i32, end_line: i32) -> Occurrence {
        let mut occurrence = def_occ_at(symbol, start_line);
        occurrence.enclosing_range = vec![start_line, 0, end_line, 0];
        occurrence
    }

    /// A SCIP reference occurrence for `symbol` at `line`.
    fn ref_occ_at(symbol: &str, line: i32) -> Occurrence {
        let mut o = Occurrence::new();
        o.symbol = symbol.to_string();
        o.symbol_roles = 0;
        o.range = vec![line, 0, line, 10];
        o
    }

    /// True iff a residual `References` edge `from -> to` exists in the graph.
    fn has_reference_edge(graph: &KnowledgeGraph, from: Uuid, to: Uuid) -> bool {
        graph
            .neighbors(&from)
            .iter()
            .any(|(id, e)| *id == to && e.kind == EdgeKind::References)
    }

    /// F1 — bare-vs-qualified NO-STEAL. A ref carrying the QUALIFIED impl-method
    /// symbol must land on the impl node (file R), never the bare same-named fn
    /// (file T). RED on HEAD: the cross-file tower's Tier-2 shortest-name pick
    /// steals the edge onto the bare `analyze` fn (`ReachabilityAnalyzer<'g>`'s
    /// generic decoration makes module-prefix overlap 0, so shortest-name wins).
    #[test]
    fn adr44_f1_qualified_ref_lands_on_impl_not_bare() {
        let file_r = "crates/h00ligan-engine/src/reachability.rs";
        let file_t = "crates/h00ligan-engine/src/tools.rs";

        let impl_a = Uuid::new_v4(); // impl ReachabilityAnalyzer<'g>::analyze (R) — intended target
        let bare_b = Uuid::new_v4(); // bare `analyze` fn                      (T) — the thief
        let drive_c = Uuid::new_v4(); // caller `drive`                        (R) — the source

        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(adr44_node(
                impl_a,
                "impl ReachabilityAnalyzer<'g>::analyze",
                file_r,
            ))
            .unwrap();
        graph
            .add_node(adr44_node(bare_b, "analyze", file_t))
            .unwrap();
        graph
            .add_node(adr44_node(drive_c, "drive", file_r))
            .unwrap();

        let analyze_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 reachability/impl#[ReachabilityAnalyzer]analyze().";
        let drive_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 reachability/drive().";

        let mut doc = Document::new();
        doc.relative_path = file_r.to_string();
        doc.occurrences = vec![
            owner_def_occ_at(drive_sym, 10, 30), // exact source owner
            def_occ_at(analyze_sym, 40), // impl-method DEF (join key post-fix); after the ref
            ref_occ_at(analyze_sym, 20), // caller-in-R ref carrying the qualified symbol
        ];
        let mut index = Index::new();
        index.documents = vec![doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");

        assert!(
            has_reference_edge(&graph, drive_c, impl_a),
            "F1: qualified ref must resolve to the impl node (file R), not steal onto the bare fn"
        );
        assert!(
            !has_reference_edge(&graph, drive_c, bare_b),
            "F1: qualified ref must NOT create an edge to the bare same-named fn (file T)"
        );
    }

    /// F1 non-vacuous CONTROL. Drop the impl-method DEF occ (keeping the caller
    /// def and the qualified ref). Post-fix the exact join has no target → NO
    /// edge. RED on HEAD: the name heuristic still fabricates an edge to the bare
    /// fn with NO def occ present — proving HEAD's edge is a surviving heuristic,
    /// not a def↔ref identity join.
    #[test]
    fn adr44_f1_control_no_def_occ_yields_no_edge() {
        let file_r = "crates/h00ligan-engine/src/reachability.rs";
        let file_t = "crates/h00ligan-engine/src/tools.rs";
        let impl_a = Uuid::new_v4();
        let bare_b = Uuid::new_v4();
        let drive_c = Uuid::new_v4();

        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(adr44_node(
                impl_a,
                "impl ReachabilityAnalyzer<'g>::analyze",
                file_r,
            ))
            .unwrap();
        graph
            .add_node(adr44_node(bare_b, "analyze", file_t))
            .unwrap();
        graph
            .add_node(adr44_node(drive_c, "drive", file_r))
            .unwrap();

        let analyze_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 reachability/impl#[ReachabilityAnalyzer]analyze().";
        let drive_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 reachability/drive().";

        let mut doc = Document::new();
        doc.relative_path = file_r.to_string();
        // NOTE: analyze DEF occ intentionally absent (unindexed target).
        doc.occurrences = vec![
            owner_def_occ_at(drive_sym, 10, 30),
            ref_occ_at(analyze_sym, 20),
        ];
        let mut index = Index::new();
        index.documents = vec![doc];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");

        assert!(
            !has_reference_edge(&graph, drive_c, bare_b)
                && !has_reference_edge(&graph, drive_c, impl_a),
            "F1-control: with the impl-method def occ absent, the exact join must yield NO edge; \
             any edge here is a surviving name heuristic"
        );
    }

    /// F2 — cross-file target wins over a same-file homonym. A ref in file A
    /// whose exact def lives in file B must edge to B, even though A holds an
    /// unrelated node of the same name. RED on HEAD: cross-file disambiguation
    /// ties to None, then the file-local suffix fallback binds the ref to A's
    /// homonym.
    #[test]
    fn adr44_f2_cross_file_target_over_same_file_homonym() {
        let file_a = "crates/h00ligan-engine/src/api.rs";
        let file_b = "crates/h00ligan-engine/src/store.rs";

        let target_p = Uuid::new_v4(); // helper in file B — the exact target
        let homonym_q = Uuid::new_v4(); // helper in file A — unrelated same-name
        let caller_r = Uuid::new_v4(); // caller_a in file A — the source

        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(adr44_node(target_p, "helper", file_b))
            .unwrap();
        graph
            .add_node(adr44_node(homonym_q, "helper", file_a))
            .unwrap();
        graph
            .add_node(adr44_node(caller_r, "caller_a", file_a))
            .unwrap();

        let helper_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 store/helper().";
        let caller_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 api/caller_a().";

        // Doc B defines helper (the exact join key post-fix).
        let mut doc_b = Document::new();
        doc_b.relative_path = file_b.to_string();
        doc_b.occurrences = vec![def_occ_at(helper_sym, 5)];

        // Doc A: caller_a def + a ref to store::helper.
        let mut doc_a = Document::new();
        doc_a.relative_path = file_a.to_string();
        doc_a.occurrences = vec![
            owner_def_occ_at(caller_sym, 10, 20),
            ref_occ_at(helper_sym, 15),
        ];

        let mut index = Index::new();
        index.documents = vec![doc_b, doc_a];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");

        assert!(
            has_reference_edge(&graph, caller_r, target_p),
            "F2: ref must edge to the exact cross-file target (store.rs::helper)"
        );
        assert!(
            !has_reference_edge(&graph, caller_r, homonym_q),
            "F2: ref must NOT bind to the same-file homonym (api.rs::helper)"
        );
    }

    /// F4 — FAIL-CLOSED on an unindexed target (+ positive control). A ref to a
    /// resolvable symbol that has NO def occurrence anywhere must produce NO
    /// edge, even though a wrongly-named node shares its last segment. RED on
    /// HEAD: the name heuristic fabricates a spurious edge to that node
    /// (fail-OPEN). CONTROL (scenario 2): once the matching def occ IS indexed,
    /// the edge legitimately appears (guards against a "delete all edges" fix).
    #[test]
    fn adr44_f4_fail_closed_on_unindexed_target() {
        let file_w = "crates/h00ligan-engine/src/widget.rs";
        let file_o = "crates/h00ligan-engine/src/other.rs";
        let frob_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 gadget/frob().";
        let caller_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 widget/caller_f4().";

        // ── Scenario 1: unindexed target → fail-closed → NO edge (RED on HEAD).
        {
            let node_w = Uuid::new_v4(); // `frob` — name-matches, but NEVER defined by SCIP
            let caller = Uuid::new_v4();
            let mut graph = KnowledgeGraph::new();
            graph.add_node(adr44_node(node_w, "frob", file_o)).unwrap();
            graph
                .add_node(adr44_node(caller, "caller_f4", file_w))
                .unwrap();

            let mut doc = Document::new();
            doc.relative_path = file_w.to_string();
            // No def occ for frob anywhere → the target is UNINDEXED.
            doc.occurrences = vec![
                owner_def_occ_at(caller_sym, 10, 20),
                ref_occ_at(frob_sym, 15),
            ];
            let mut index = Index::new();
            index.documents = vec![doc];

            let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
            loader.process_index(&index).expect("process_index");

            assert!(
                !has_reference_edge(&graph, caller, node_w),
                "F4: a ref to an UNINDEXED target must fail-closed to no edge, not name-match `frob`"
            );
        }

        // ── Scenario 2 (positive control): index the def → edge appears.
        {
            let node_w = Uuid::new_v4();
            let caller = Uuid::new_v4();
            let mut graph = KnowledgeGraph::new();
            graph.add_node(adr44_node(node_w, "frob", file_o)).unwrap();
            graph
                .add_node(adr44_node(caller, "caller_f4", file_w))
                .unwrap();

            let mut doc_o = Document::new();
            doc_o.relative_path = file_o.to_string();
            doc_o.occurrences = vec![def_occ_at(frob_sym, 3)]; // frob NOW indexed

            let mut doc_w = Document::new();
            doc_w.relative_path = file_w.to_string();
            doc_w.occurrences = vec![
                owner_def_occ_at(caller_sym, 10, 20),
                ref_occ_at(frob_sym, 15),
            ];

            let mut index = Index::new();
            index.documents = vec![doc_o, doc_w];

            let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
            loader.process_index(&index).expect("process_index");

            assert!(
                has_reference_edge(&graph, caller, node_w),
                "F4-control: with the def occ indexed, the edge to `frob` legitimately appears"
            );
        }
    }

    /// RIGHT-REASON REGRESSION: locality belongs to admitted repository
    /// definitions, not a hardcoded list of language package managers. A new
    /// provider with exact definition/reference identities must resolve its
    /// own cross-file edge without adding another Cargo/Go metadata probe.
    #[test]
    fn repository_definition_population_establishes_provider_locality() {
        for (provider, extension) in [
            ("rust-analyzer cargo", "rs"),
            ("scip-go gomod", "go"),
            ("scip-python pip", "py"),
            ("scip-typescript npm", "ts"),
        ] {
            let caller_id = Uuid::new_v4();
            let target_id = Uuid::new_v4();
            let caller_path = format!("src/caller.{extension}");
            let target_path = format!("src/target.{extension}");
            let mut graph = KnowledgeGraph::new();
            graph
                .add_node(adr44_node(caller_id, "caller", &caller_path))
                .unwrap();
            graph
                .add_node(adr44_node(target_id, "target", &target_path))
                .unwrap();

            let caller_symbol = format!("{provider} app 1.0.0 caller().");
            let target_symbol = format!("{provider} app 1.0.0 target().");
            let external_symbol = format!("{provider} dependency 9.0.0 map().");
            let mut target = Document::new();
            target.relative_path = target_path;
            target.occurrences = vec![def_occ_at(&target_symbol, 1)];
            target.symbols = vec![sym_info_with_rels(&target_symbol, vec![])];
            let mut caller = Document::new();
            caller.relative_path = caller_path;
            caller.occurrences = vec![
                owner_def_occ_at(&caller_symbol, 1, 20),
                ref_occ_at(&target_symbol, 10),
                ref_occ_at(&external_symbol, 15),
                def_occ_at(&external_symbol, 30),
            ];
            caller.symbols = vec![sym_info_with_rels(&caller_symbol, vec![])];
            let mut index = Index::new();
            index.documents = vec![caller, target];
            assert_eq!(
                repository_definition_packages(&index),
                HashSet::from(["app".to_string()]),
                "{provider}: only real repository definitions establish local package authority"
            );

            let mut loader = ScipLoader::new(&mut graph);
            loader
                .process_index(&index)
                .expect("process generic provider index");
            assert!(
                has_reference_edge(&graph, caller_id, target_id),
                "{provider}: an exact repository-backed definition must make its provider package local"
            );
        }
    }

    /// F6 — Go cross-package homonym recall (dissolves OQ-GO-XPKG-HOMONYM-RECALL).
    /// Two Go packages each expose a free `Handle` fn with DISTINCT scip-go
    /// symbols; two refs carry the distinct symbols. Each must edge to its own
    /// package's `Handle`. RED on HEAD: the last-segment/shortest-name tier
    /// cannot tell the two apart (equal-length names → len-tie → None; the
    /// caller lives in a third file so file-local recovery also misses) → both
    /// correct edges are LOST.
    #[test]
    fn adr44_f6_go_cross_package_homonym() {
        let module = "github.com/acme/app";
        let file_a = "pkga/handler.go";
        let file_b = "pkgb/handler.go";
        let file_main = "cmd/main.go";

        let handle_a = Uuid::new_v4(); // pkga.Handle
        let handle_b = Uuid::new_v4(); // pkgb.Handle
        let run = Uuid::new_v4(); // cmd.Run — the caller/source

        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(adr44_node(handle_a, "Handle", file_a))
            .unwrap();
        graph
            .add_node(adr44_node(handle_b, "Handle", file_b))
            .unwrap();
        graph.add_node(adr44_node(run, "Run", file_main)).unwrap();

        let run_sym = format!("scip-go gomod {module} v0.0.0 cmd/Run().");
        let handle_a_sym = format!("scip-go gomod {module} v0.0.0 pkga/Handle().");
        let handle_b_sym = format!("scip-go gomod {module} v0.0.0 pkgb/Handle().");

        // Package docs define each Handle (the distinct join keys post-fix).
        let mut doc_a = Document::new();
        doc_a.relative_path = file_a.to_string();
        doc_a.occurrences = vec![def_occ_at(&handle_a_sym, 3)];
        let mut doc_b = Document::new();
        doc_b.relative_path = file_b.to_string();
        doc_b.occurrences = vec![def_occ_at(&handle_b_sym, 3)];

        // main.go: Run def + a ref to each package's Handle.
        let mut doc_main = Document::new();
        doc_main.relative_path = file_main.to_string();
        doc_main.occurrences = vec![
            owner_def_occ_at(&run_sym, 5, 30),
            ref_occ_at(&handle_a_sym, 10),
            ref_occ_at(&handle_b_sym, 20),
        ];

        let mut index = Index::new();
        index.documents = vec![doc_a, doc_b, doc_main];

        let go_pkgs: HashSet<String> = std::iter::once(module.to_string()).collect();
        let mut loader = ScipLoader::with_local_packages(&mut graph, go_pkgs);
        loader.process_index(&index).expect("process_index");

        assert!(
            has_reference_edge(&graph, run, handle_a),
            "F6: ref carrying pkga's distinct scip-go symbol must edge to pkga.Handle"
        );
        assert!(
            has_reference_edge(&graph, run, handle_b),
            "F6: ref carrying pkgb's distinct scip-go symbol must edge to pkgb.Handle"
        );
    }

    /// True iff ANY edge `from -> to` exists (kind-agnostic).
    fn has_any_edge(graph: &KnowledgeGraph, from: Uuid, to: Uuid) -> bool {
        graph.neighbors(&from).iter().any(|(id, _)| *id == to)
    }

    /// F3 — document-order-independence + determinism (the MAJOR-1 property). The
    /// exact-symbol join completes the global index before any target lookup, so
    /// the resulting edge set is INVARIANT under `index.documents` order and
    /// IDENTICAL across repeated loads. A same-named decoy (never defined) is
    /// never wired regardless of order.
    #[test]
    fn adr44_f3_document_order_independent_and_deterministic() {
        let target = Uuid::from_u128(0xF3_0001);
        let decoy = Uuid::from_u128(0xF3_0002); // shares the last segment, never defined
        let caller = Uuid::from_u128(0xF3_0003);

        let file_b = "crates/h00ligan-engine/src/store.rs";
        let file_a = "crates/h00ligan-engine/src/api.rs";
        let file_d = "crates/h00ligan-engine/src/decoy.rs";

        let helper_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 store/helper().";
        let caller_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 api/caller().";

        // Returns the edge set as a sorted (from, to, kind-debug) vector so it is
        // comparable across independently-built graphs (stable node ids above).
        let run = |reversed: bool| -> Vec<(Uuid, Uuid, String)> {
            let mut graph = KnowledgeGraph::new();
            graph
                .add_node(adr44_node(target, "helper", file_b))
                .unwrap();
            graph.add_node(adr44_node(decoy, "helper", file_d)).unwrap();
            graph
                .add_node(adr44_node(caller, "caller", file_a))
                .unwrap();

            let mut doc_b = Document::new();
            doc_b.relative_path = file_b.to_string();
            doc_b.occurrences = vec![def_occ_at(helper_sym, 5)];

            let mut doc_a = Document::new();
            doc_a.relative_path = file_a.to_string();
            doc_a.occurrences = vec![
                owner_def_occ_at(caller_sym, 10, 20),
                ref_occ_at(helper_sym, 15),
            ];

            let mut index = Index::new();
            index.documents = if reversed {
                vec![doc_a, doc_b]
            } else {
                vec![doc_b, doc_a]
            };

            let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
            loader.process_index(&index).expect("process_index");

            let mut edges: Vec<(Uuid, Uuid, String)> = graph
                .all_edges()
                .into_iter()
                .map(|(f, t, e)| (f, t, format!("{:?}", e.kind)))
                .collect();
            edges.sort();
            edges
        };

        let forward = run(false);
        let reversed = run(true);
        assert_eq!(
            forward, reversed,
            "F3: the edge set must be independent of document order"
        );
        assert!(
            forward.contains(&(caller, target, format!("{:?}", EdgeKind::References))),
            "F3: the exact cross-document edge caller -> store::helper must be present"
        );
        assert!(
            !forward.iter().any(|(_, t, _)| *t == decoy),
            "F3: the same-named decoy (never defined) must never be wired"
        );
        for _ in 0..3 {
            assert_eq!(run(false), forward, "F3: repeated loads must be identical");
        }
    }

    /// F5 — `local N` symbols are document-scoped: two documents each emit the
    /// SAME `local 4` def+ref, and each ref must bind to ITS OWN document's local
    /// node, never the other's. (`local N` refs classify as `References` edges, so
    /// this checks edge presence kind-agnostically.)
    #[test]
    fn adr44_f5_local_symbol_non_collision() {
        let file0 = "crates/h00ligan-engine/src/mod0.rs";
        let file1 = "crates/h00ligan-engine/src/mod1.rs";

        let c0 = Uuid::new_v4();
        let l0 = Uuid::new_v4();
        let c1 = Uuid::new_v4();
        let l1 = Uuid::new_v4();

        let mut graph = KnowledgeGraph::new();
        graph.add_node(adr44_node(c0, "caller0", file0)).unwrap();
        graph.add_node(adr44_node(l0, "local 4", file0)).unwrap();
        graph.add_node(adr44_node(c1, "caller1", file1)).unwrap();
        graph.add_node(adr44_node(l1, "local 4", file1)).unwrap();

        let c0_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 mod0/caller0().";
        let c1_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 mod1/caller1().";

        // The caller def carries an enclosing body span so IT (not the inner
        // `local 4` def) is the enclosing SOURCE of the local ref.
        let caller_def = |sym: &str| {
            let mut o = def_occ_at(sym, 10);
            o.enclosing_range = vec![10, 0, 30, 1];
            o
        };

        let mut doc0 = Document::new();
        doc0.relative_path = file0.to_string();
        doc0.occurrences = vec![
            caller_def(c0_sym),
            def_occ_at("local 4", 12),
            ref_occ_at("local 4", 15),
        ];

        let mut doc1 = Document::new();
        doc1.relative_path = file1.to_string();
        doc1.occurrences = vec![
            caller_def(c1_sym),
            def_occ_at("local 4", 12),
            ref_occ_at("local 4", 15),
        ];

        let mut index = Index::new();
        index.documents = vec![doc0, doc1];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");

        assert!(
            has_any_edge(&graph, c0, l0),
            "F5: doc0's `local 4` ref must bind doc0's local node"
        );
        assert!(
            has_any_edge(&graph, c1, l1),
            "F5: doc1's `local 4` ref must bind doc1's local node"
        );
        assert!(
            !has_any_edge(&graph, c0, l1),
            "F5: doc0's `local 4` ref must NOT cross into doc1's local node"
        );
        assert!(
            !has_any_edge(&graph, c1, l0),
            "F5: doc1's `local 4` ref must NOT cross into doc0's local node"
        );
    }

    /// F7 — ForwardDefinition precedence. A `Definition | ForwardDefinition` occ
    /// (a forward declaration) must NEVER claim the global slot: a REAL Definition
    /// of the same symbol wins under BOTH document orderings, so the ref edges to
    /// the real node, never the forward declaration's node.
    #[test]
    fn adr44_f7_forward_definition_yields_to_real_definition() {
        let file_fwd = "crates/h00ligan-engine/src/decl.rs";
        let file_real = "crates/h00ligan-engine/src/imp.rs";
        let file_caller = "crates/h00ligan-engine/src/site.rs";

        let thing_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 pkg/Thing#method().";
        let caller_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 site/caller().";

        let run = |real_first: bool| -> (bool, bool) {
            let fwd_node = Uuid::new_v4();
            let real_node = Uuid::new_v4();
            let caller = Uuid::new_v4();

            let mut graph = KnowledgeGraph::new();
            graph
                .add_node(adr44_node(fwd_node, "Thing::method", file_fwd))
                .unwrap();
            graph
                .add_node(adr44_node(real_node, "Thing::method", file_real))
                .unwrap();
            graph
                .add_node(adr44_node(caller, "caller", file_caller))
                .unwrap();

            // Forward declaration — Definition | ForwardDefinition. Must be skipped.
            let mut fwd = def_occ_at(thing_sym, 3);
            fwd.symbol_roles =
                SymbolRole::Definition.value() | SymbolRole::ForwardDefinition.value();
            let mut doc_fwd = Document::new();
            doc_fwd.relative_path = file_fwd.to_string();
            doc_fwd.occurrences = vec![fwd];

            let mut doc_real = Document::new();
            doc_real.relative_path = file_real.to_string();
            doc_real.occurrences = vec![def_occ_at(thing_sym, 5)];

            let mut doc_caller = Document::new();
            doc_caller.relative_path = file_caller.to_string();
            doc_caller.occurrences = vec![
                owner_def_occ_at(caller_sym, 10, 20),
                ref_occ_at(thing_sym, 15),
            ];

            let mut index = Index::new();
            index.documents = if real_first {
                vec![doc_real, doc_fwd, doc_caller]
            } else {
                vec![doc_fwd, doc_real, doc_caller]
            };

            let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
            loader.process_index(&index).expect("process_index");
            (
                has_reference_edge(&graph, caller, real_node),
                has_reference_edge(&graph, caller, fwd_node),
            )
        };

        for real_first in [true, false] {
            let (to_real, to_fwd) = run(real_first);
            assert!(
                to_real,
                "F7: the ref must edge to the REAL definition (real_first={real_first})"
            );
            assert!(
                !to_fwd,
                "F7: the ref must NEVER edge to the forward declaration (real_first={real_first})"
            );
        }
    }

    /// F10 — the ADR-0044 recall/diagnostic counters are surfaced and populated:
    /// `refs_target_unindexed` (a resolvable global ref with no indexed def),
    /// `refs_target_local` (a `local N` ref with no matching local def), and
    /// `global_defs_clobbers` (the same non-local symbol really-defined twice to
    /// DIFFERENT nodes).
    #[test]
    fn adr44_f10_recall_counters_surfaced() {
        let d0 = Uuid::new_v4();
        let d1 = Uuid::new_v4();
        let caller = Uuid::new_v4();

        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(adr44_node(d0, "Thing::d", "src/c0.rs"))
            .unwrap();
        graph
            .add_node(adr44_node(d1, "Thing::d", "src/c1.rs"))
            .unwrap();
        graph
            .add_node(adr44_node(caller, "Caller::run", "src/caller.rs"))
            .unwrap();

        let d_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 pkg/Thing#d().";
        let caller_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 pkg/Caller#run().";
        let ghost_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 ghost/ghost().";

        // Ref to an undefined global target + a `local 9` ref with no local def.
        let mut doc_a = Document::new();
        doc_a.relative_path = "src/a.rs".to_string();
        doc_a.occurrences = vec![ref_occ_at(ghost_sym, 5), ref_occ_at("local 9", 6)];

        // The same non-local symbol defined twice → a clobber (different nodes).
        let mut doc_c0 = Document::new();
        doc_c0.relative_path = "src/c0.rs".to_string();
        doc_c0.occurrences = vec![def_occ_at(d_sym, 3)];
        let mut doc_c1 = Document::new();
        doc_c1.relative_path = "src/c1.rs".to_string();
        doc_c1.occurrences = vec![def_occ_at(d_sym, 3)];

        let mut doc_caller = Document::new();
        doc_caller.relative_path = "src/caller.rs".to_string();
        doc_caller.occurrences = vec![owner_def_occ_at(caller_sym, 1, 10), ref_occ_at(d_sym, 5)];

        let mut index = Index::new();
        index.documents = vec![doc_a, doc_c0, doc_c1, doc_caller];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");

        assert!(
            stats.refs_target_unindexed >= 1,
            "F10: a resolvable ref to an unindexed global target must be counted, got {}",
            stats.refs_target_unindexed
        );
        assert!(
            stats.refs_target_local >= 1,
            "F10: a `local N` ref with no matching local def must be counted, got {}",
            stats.refs_target_local
        );
        assert!(
            stats.global_defs_clobbers >= 1,
            "F10: a real re-definition to a different node must be counted, got {}",
            stats.global_defs_clobbers
        );
        assert!(
            !has_reference_edge(&graph, caller, d0) && !has_reference_edge(&graph, caller, d1),
            "an ambiguous non-local identity must not first-writer-win a residual edge"
        );
    }

    /// F10b — the resolved-target-but-no-enclosing-source drop is COUNTED, not
    /// silent: a reference whose exact target resolves against `global_defs`
    /// but whose own document contains no enclosing definition occurrence (so
    /// there is no edge SOURCE) must increment `refs_no_enclosing_def` and add
    /// no edge. Until 2026-07-19 this was the only pass-2 miss path with no
    /// counter (found chasing the `NdjsonReceiverStream` false-DEAD).
    #[test]
    fn adr44_f10b_no_enclosing_def_drop_is_counted() {
        let t0 = Uuid::new_v4();

        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(adr44_node(t0, "Target::t", "src/b.rs"))
            .unwrap();

        let t_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 pkg/Target#t().";

        // doc_b defines the target — so the ref's TARGET resolves.
        let mut doc_b = Document::new();
        doc_b.relative_path = "src/b.rs".to_string();
        doc_b.occurrences = vec![def_occ_at(t_sym, 3)];

        // doc_a references it but contains NO definition occurrences at all,
        // so `find_enclosing_definition` has no candidate source.
        let mut doc_a = Document::new();
        doc_a.relative_path = "src/a.rs".to_string();
        doc_a.occurrences = vec![ref_occ_at(t_sym, 5)];

        let mut index = Index::new();
        index.documents = vec![doc_b, doc_a];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");

        assert_eq!(
            stats.refs_no_enclosing_def, 1,
            "F10b: a resolved-target ref with no enclosing definition must be counted, got {}",
            stats.refs_no_enclosing_def
        );
        // Fail-closed: the drop really is a drop — no edge landed on the target.
        assert!(
            graph.incoming_neighbors(&t0).is_empty(),
            "F10b: the dropped ref must not produce an edge"
        );
    }

    /// F11 — Go two-document `local N` non-collision (the Go analogue of F5). Two
    /// scip-go package documents each emit the same `local 3` def+ref; each ref
    /// binds only within its own document. `local N` is scheme-agnostic, so the
    /// segregation holds identically for scip-go.
    #[test]
    fn adr44_f11_go_two_doc_local_non_collision() {
        let module = "github.com/acme/app";
        let file0 = "pkga/a.go";
        let file1 = "pkgb/b.go";

        let c0 = Uuid::new_v4();
        let l0 = Uuid::new_v4();
        let c1 = Uuid::new_v4();
        let l1 = Uuid::new_v4();

        let mut graph = KnowledgeGraph::new();
        graph.add_node(adr44_node(c0, "Run0", file0)).unwrap();
        graph.add_node(adr44_node(l0, "local 3", file0)).unwrap();
        graph.add_node(adr44_node(c1, "Run1", file1)).unwrap();
        graph.add_node(adr44_node(l1, "local 3", file1)).unwrap();

        let c0_sym = format!("scip-go gomod {module} v0.0.0 pkga/Run0().");
        let c1_sym = format!("scip-go gomod {module} v0.0.0 pkgb/Run1().");

        let caller_def = |sym: &str| {
            let mut o = def_occ_at(sym, 10);
            o.enclosing_range = vec![10, 0, 30, 1];
            o
        };

        let mut doc0 = Document::new();
        doc0.relative_path = file0.to_string();
        doc0.occurrences = vec![
            caller_def(&c0_sym),
            def_occ_at("local 3", 12),
            ref_occ_at("local 3", 15),
        ];

        let mut doc1 = Document::new();
        doc1.relative_path = file1.to_string();
        doc1.occurrences = vec![
            caller_def(&c1_sym),
            def_occ_at("local 3", 12),
            ref_occ_at("local 3", 15),
        ];

        let mut index = Index::new();
        index.documents = vec![doc0, doc1];

        let go_pkgs: HashSet<String> = std::iter::once(module.to_string()).collect();
        let mut loader = ScipLoader::with_local_packages(&mut graph, go_pkgs);
        loader.process_index(&index).expect("process_index");

        assert!(
            has_any_edge(&graph, c0, l0),
            "F11: pkga's `local 3` ref must bind pkga's local node"
        );
        assert!(
            has_any_edge(&graph, c1, l1),
            "F11: pkgb's `local 3` ref must bind pkgb's local node"
        );
        assert!(
            !has_any_edge(&graph, c0, l1),
            "F11: pkga's `local 3` ref must NOT cross into pkgb's local node"
        );
        assert!(
            !has_any_edge(&graph, c1, l0),
            "F11: pkgb's `local 3` ref must NOT cross into pkga's local node"
        );
    }

    // ── Relationship-edge helpers (ADR-0044 Q4) ─────────────────────────────
    use scip::types::{Relationship, SymbolInformation};

    /// A `SymbolInformation` for `symbol` carrying `rels`.
    fn sym_info_with_rels(symbol: &str, rels: Vec<Relationship>) -> SymbolInformation {
        let mut si = SymbolInformation::new();
        si.symbol = symbol.to_string();
        si.relationships = rels;
        si
    }

    /// An `is_implementation` relationship to `symbol`.
    fn impl_rel(symbol: &str) -> Relationship {
        let mut r = Relationship::new();
        r.symbol = symbol.to_string();
        r.is_implementation = true;
        r
    }

    /// An `is_type_definition` relationship to `symbol`.
    fn typedef_rel(symbol: &str) -> Relationship {
        let mut r = Relationship::new();
        r.symbol = symbol.to_string();
        r.is_type_definition = true;
        r
    }

    /// True iff a `from -> to` edge of exactly `kind` exists.
    fn has_edge_of_kind(graph: &KnowledgeGraph, from: Uuid, to: Uuid, kind: EdgeKind) -> bool {
        graph
            .neighbors(&from)
            .iter()
            .any(|(id, e)| *id == to && e.kind == kind)
    }

    /// F8 — relationship-edge PARITY falsifier (ADR-0044 Q4). The
    /// `SymbolInformation.relationships` edge build must resolve its TARGET by
    /// the SAME exact global-identity join as the reference path: a GENUINE
    /// `is_implementation` whose `rel.symbol` EXACTLY matches an indexed
    /// definition lands an `Implements` edge on the RIGHT node; a HOMONYM
    /// `rel.symbol` (same last segment as an unrelated indexed node, but whose
    /// EXACT symbol is undefined) fails closed to NO edge and is COUNTED in
    /// `rels_target_unindexed`.
    ///
    /// NON-VACUOUS control (verified 2026-07-16): temporarily routing the
    /// non-local `to_id` through a last-segment lookup (instead of
    /// `global_defs.get(&rel.symbol)`) resolves the homonym `Bar#helper` onto
    /// the unrelated `Foo::helper` node — so `has_edge_of_kind(dog, foohelper,
    /// Implements)` becomes TRUE (assertion 2 goes RED) and
    /// `rels_target_unindexed` stays 0 (assertion 3 goes RED). Restoring the
    /// exact-identity join returns both to green. The guard has been seen to
    /// fail for the right reason.
    #[test]
    fn adr44_f8_relationship_edge_parity_identity_join() {
        let file_dog = "crates/h00ligan-engine/src/dog.rs";
        let file_animal = "crates/h00ligan-engine/src/animal.rs";
        let file_foo = "crates/h00ligan-engine/src/foo.rs";

        let dog = Uuid::new_v4(); // source: Dog::speak (the impl)
        let animal = Uuid::new_v4(); // genuine target: Animal::speak (the trait)
        let foohelper = Uuid::new_v4(); // unrelated homonym decoy: Foo::helper

        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(adr44_node(dog, "Dog::speak", file_dog))
            .unwrap();
        graph
            .add_node(adr44_node(animal, "Animal::speak", file_animal))
            .unwrap();
        graph
            .add_node(adr44_node(foohelper, "Foo::helper", file_foo))
            .unwrap();

        let dog_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 dog/Dog#speak().";
        let animal_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 animal/Animal#speak().";
        let foo_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 foo/Foo#helper().";
        // Homonym: last segment `helper` matches Foo::helper, but this EXACT
        // symbol (Bar#helper) is never defined anywhere.
        let homonym_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 bar/Bar#helper().";

        // Genuine target + unrelated decoy both enter global_defs via real defs.
        let mut doc_animal = Document::new();
        doc_animal.relative_path = file_animal.to_string();
        doc_animal.occurrences = vec![def_occ_at(animal_sym, 3)];

        let mut doc_foo = Document::new();
        doc_foo.relative_path = file_foo.to_string();
        doc_foo.occurrences = vec![def_occ_at(foo_sym, 3)];

        // Source doc: one SymbolInformation (Dog::speak) with a GENUINE impl rel
        // and a HOMONYM impl rel.
        let mut doc_dog = Document::new();
        doc_dog.relative_path = file_dog.to_string();
        doc_dog.symbols = vec![sym_info_with_rels(
            dog_sym,
            vec![impl_rel(animal_sym), impl_rel(homonym_sym)],
        )];

        let mut index = Index::new();
        index.documents = vec![doc_animal, doc_foo, doc_dog];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");

        // (a) GENUINE: Implements edge to the RIGHT node.
        assert!(
            has_edge_of_kind(&graph, dog, animal, EdgeKind::Implements),
            "F8(a): genuine is_implementation must land an Implements edge Dog::speak -> Animal::speak"
        );
        // (b) HOMONYM: NO wrong edge onto the same-last-segment unrelated node.
        assert!(
            !has_any_edge(&graph, dog, foohelper),
            "F8(b): homonym rel must NOT edge onto the unrelated same-last-segment node (fail-closed identity join)"
        );
        // (b) HOMONYM: the fail-closed miss is MEASURED.
        assert!(
            stats.rels_target_unindexed >= 1,
            "F8(b): a resolvable relationship target with no indexed def must be counted, got {}",
            stats.rels_target_unindexed
        );
    }

    /// F8b — DIRECT `is_type_definition` relationship through `process_index`:
    /// a genuine type-definition relationship whose `rel.symbol` exactly matches
    /// an indexed definition lands a `TypeOf` edge on the right node and bumps
    /// `typeof_edges_added`; a homonym `local N` target with no matching local
    /// def fails closed and is counted in `rels_target_local`.
    #[test]
    fn adr44_f8b_relationship_typeof_direct() {
        let file_holder = "crates/h00ligan-engine/src/holder.rs";
        let file_widget = "crates/h00ligan-engine/src/widget.rs";

        let holder = Uuid::new_v4(); // source: Holder
        let widget = Uuid::new_v4(); // genuine type target: Widget

        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(adr44_node(holder, "Holder", file_holder))
            .unwrap();
        graph
            .add_node(adr44_node(widget, "Widget", file_widget))
            .unwrap();

        let holder_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 holder/Holder#";
        let widget_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 widget/Widget#";

        let mut doc_widget = Document::new();
        doc_widget.relative_path = file_widget.to_string();
        doc_widget.occurrences = vec![def_occ_at(widget_sym, 3)];

        let mut doc_holder = Document::new();
        doc_holder.relative_path = file_holder.to_string();
        // Genuine TypeOf rel (Widget#, indexed) + a homonym `local 7` target
        // with no matching local def in this document → fail-closed + counted.
        doc_holder.symbols = vec![sym_info_with_rels(
            holder_sym,
            vec![typedef_rel(widget_sym), typedef_rel("local 7")],
        )];

        let mut index = Index::new();
        index.documents = vec![doc_widget, doc_holder];

        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");

        assert!(
            has_edge_of_kind(&graph, holder, widget, EdgeKind::TypeOf),
            "F8b: genuine is_type_definition must land a TypeOf edge Holder -> Widget"
        );
        assert!(
            stats.typeof_edges_added >= 1,
            "F8b: a genuine TypeOf relationship must bump typeof_edges_added, got {}",
            stats.typeof_edges_added
        );
        assert!(
            stats.rels_target_local >= 1,
            "F8b: a `local N` relationship target with no matching local def must be counted, got {}",
            stats.rels_target_local
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Task #29 — SCIP identity-join extension (GAP 1 qualified/generic trait
    // two-bracket · GAP 2 macro bang). Falsifiers author ≠ code author; each
    // pins the POST-FIX behavior. "Red-on-HEAD" for the GAP aliases is proven by
    // the alias-ablation non-vacuity controls (removing the alias returns None) —
    // captured verbatim during the build. Declared-green guards state so.
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a two-tier [`NodeLookup`] from `(symbol_name, kind, file)` nodes via
    /// the REAL `build_node_lookup`, returning the lookup + the nodes' ids in
    /// order. Exercises the alias-production path, not a hand-seeded map.
    fn lookup_from_nodes(nodes: &[(&str, &str, &str)]) -> (NodeLookup, Vec<Uuid>) {
        let mut graph = KnowledgeGraph::new();
        let mut ids = Vec::with_capacity(nodes.len());
        for (name, kind, file) in nodes {
            let id = Uuid::new_v4();
            ids.push(id);
            let mut node = adr44_node(id, name, file);
            node.kind = (*kind).to_string();
            graph.add_node(node).expect("add node");
        }
        let loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        (loader.build_node_lookup(), ids)
    }

    // ── bare_trait_impl_alias unit coverage (the GAP-1 key transform) ────────

    #[test]
    fn bare_trait_impl_alias_qualified_trait() {
        assert_eq!(
            bare_trait_impl_alias("impl crate::llm::LlmClient for ClaudeCliClient::stream")
                .as_deref(),
            Some("impl LlmClient for ClaudeCliClient::stream"),
        );
    }

    #[test]
    fn bare_trait_impl_alias_generic_trait_strips_before_last_segment() {
        // `From<redb::TableError>` must bare to `From`, NEVER `TableError>` from a
        // `::`-split INSIDE the generic argument (strip generics BEFORE last-seg).
        assert_eq!(
            bare_trait_impl_alias("impl From<redb::TableError> for GraphStoreError::from")
                .as_deref(),
            Some("impl From for GraphStoreError::from"),
        );
    }

    #[test]
    fn bare_trait_impl_alias_widened_predicate_module_nested() {
        // mod 1: `impl ` immediately after a `::` boundary is matched; the module
        // prefix is KEPT in the key.
        assert_eq!(
            bare_trait_impl_alias("store::impl crate::db::Backend for RedbStore::open").as_deref(),
            Some("store::impl Backend for RedbStore::open"),
        );
    }

    #[test]
    fn bare_trait_impl_alias_normalizes_generic_self_type() {
        // The outer whole-candidate generic strip normalizes a generic self-type
        // in the `for …` remainder.
        assert_eq!(
            bare_trait_impl_alias("impl Foo for GraphStore<T>::from").as_deref(),
            Some("impl Foo for GraphStore::from"),
        );
    }

    #[test]
    fn bare_trait_impl_alias_none_when_already_bare_or_not_trait_impl() {
        // Already-bare trait → nothing to bridge.
        assert_eq!(
            bare_trait_impl_alias("impl LlmClient for ClaudeCliClient::stream"),
            None,
        );
        // Inherent impl (no ` for `) → not a trait impl.
        assert_eq!(bare_trait_impl_alias("impl LanceStore::search_inner"), None);
        // Free function → no `impl ` token.
        assert_eq!(bare_trait_impl_alias("hybrid_search"), None);
        // A type merely CONTAINING "impl" mid-identifier is not matched.
        assert_eq!(bare_trait_impl_alias("Reimplement::run"), None);
    }

    // ── F1 / F2 — the GAP aliases resolve (resolve_node level) ───────────────

    #[test]
    fn task29_f1_gap1_bare_trait_alias_resolves() {
        // GAP 1: a trait-impl method node written with a QUALIFIED trait
        // (`extract_impl_name` emits raw source text) must resolve from the BARE
        // descriptor SCIP produces. RED without the bare-trait alias: resolve_node
        // returns None (the `crate::llm::` qualifier is MID-STRING inside
        // `impl … for …`, unreachable by leading-`::` suffix stripping).
        let file = "crates/h00ligan-interface/src/cli_client.rs";
        let (lookup, ids) = lookup_from_nodes(&[(
            "impl crate::llm::LlmClient for ClaudeCliClient::stream",
            "function",
            file,
        )]);
        let scip = "rust-analyzer cargo h00ligan_interface 0.1.0 cli_client/impl#[ClaudeCliClient][LlmClient]stream().";
        let descriptor = extract_descriptor(scip);
        assert_eq!(
            descriptor, "cli_client::impl LlmClient for ClaudeCliClient::stream",
            "precondition: extract_descriptor yields the bare, module-prefixed key"
        );
        let mut stats = ScipStats::default();
        assert_eq!(
            resolve_node(file, &descriptor, &lookup, &mut stats),
            Some(ids[0]),
            "GAP-1: qualified-trait impl-method must resolve via the bare-trait alias"
        );
    }

    #[test]
    fn task29_f2_gap2_bang_alias_resolves() {
        // GAP 2: a macro node named bare must resolve from the bang-suffixed
        // descriptor. RED without the macro-bang alias: the trailing `!` never
        // matches the bare node key and no bang alias exists.
        let file = "crates/h00ligan-engine/src/tarpc_store.rs";
        let (lookup, ids) = lookup_from_nodes(&[("rpc_with_reconnect", "macro", file)]);
        let scip = "rust-analyzer cargo h00ligan_engine 0.1.0 tarpc_store/rpc_with_reconnect!";
        let descriptor = extract_descriptor(scip);
        assert_eq!(descriptor, "tarpc_store::rpc_with_reconnect!");
        let mut stats = ScipStats::default();
        assert_eq!(
            resolve_node(file, &descriptor, &lookup, &mut stats),
            Some(ids[0]),
            "GAP-2: macro node must resolve via the macro-bang alias"
        );
    }

    // ── F3 — kind-negative regression guard (DECLARED-green) ─────────────────

    #[test]
    fn task29_f3_bang_does_not_bind_non_macro_declared_green() {
        // A `foo!` descriptor must NEVER bind a `fn foo`: the bang alias is
        // kind-gated to `"macro"` nodes. DECLARED-green — on HEAD there is no bang
        // alias at all, so this already returns None; non-vacuity is the
        // break-restore control (remove the kind gate → `foo!` binds `fn foo`),
        // NOT a HEAD red.
        let file = "src/x.rs";
        let (lookup, _ids) = lookup_from_nodes(&[("foo", "function", file)]);
        // Confirm the guard is being exercised: NO bang alias exists for `foo`.
        assert!(
            !lookup
                .alias
                .contains_key(&(file.to_string(), "foo!".to_string())),
            "kind gate: a non-macro node must receive no bang alias"
        );
        let mut stats = ScipStats::default();
        assert_eq!(
            resolve_node(file, "foo!", &lookup, &mut stats),
            None,
            "kind gate: a bang descriptor must not bind a non-macro node"
        );
    }

    // ── mod 1 / mod 2 / mod 3 — the mandatory review mods ────────────────────

    #[test]
    fn task29_mod1_widened_predicate_module_nested_impl_resolves() {
        // mod 1: the 111 module-nested `<mod>::impl …` nodes must receive an alias
        // too. `starts_with("impl ")` would have excluded them.
        let file = "src/store.rs";
        let (lookup, ids) = lookup_from_nodes(&[(
            "store::impl crate::db::Backend for RedbStore::open",
            "function",
            file,
        )]);
        let mut stats = ScipStats::default();
        assert_eq!(
            resolve_node(
                file,
                "store::impl Backend for RedbStore::open",
                &lookup,
                &mut stats,
            ),
            Some(ids[0]),
            "mod 1: a module-nested qualified-trait impl must resolve via the widened predicate"
        );
    }

    #[test]
    fn task29_mod2_exact_tier_wins_over_alias() {
        // mod 2: an exact identity hit must never be shadowed by an alias. Node A's
        // exact name equals node B's bare-trait alias key; resolve_node on that key
        // must return A (exact), never B (alias), and never touch the alias tier.
        let file = "src/x.rs";
        let (lookup, ids) = lookup_from_nodes(&[
            ("impl T for Y::m", "function", file), // A: literal exact name
            ("impl a::b::T for Y::m", "function", file), // B: bare alias == A's name
        ]);
        let (a, _b) = (ids[0], ids[1]);
        let mut stats = ScipStats::default();
        assert_eq!(
            resolve_node(file, "impl T for Y::m", &lookup, &mut stats),
            Some(a),
            "mod 2: the exact tier must win; the alias must not shadow it"
        );
        assert_eq!(
            stats.def_resolve_ambiguous, 0,
            "an exact hit must never consult (or count) the alias tier"
        );
    }

    #[test]
    fn task29_mod3_generic_and_bare_trait_alias_dedupe_no_regression() {
        // mod 3: a generic-but-UNQUALIFIED trait impl's generic-stripped alias and
        // bare-trait alias produce the SAME key for the SAME id. Deduped, the slot
        // holds ONE id → resolve_node still binds it (a `[id, id]` slot would fail
        // single() and REGRESS a previously-working join).
        let file = "src/x.rs";
        let (lookup, ids) =
            lookup_from_nodes(&[("impl Trait for Store<T>::get", "function", file)]);
        let key = (file.to_string(), "impl Trait for Store::get".to_string());
        assert_eq!(
            lookup.alias.get(&key).map(Vec::len),
            Some(1),
            "mod 3: the two aliases collapsing to one key must dedupe to a single id"
        );
        let mut stats = ScipStats::default();
        assert_eq!(
            resolve_node(file, "impl Trait for Store::get", &lookup, &mut stats),
            Some(ids[0]),
            "mod 3: the deduped alias must still resolve (no self-collision regression)"
        );
        assert_eq!(
            stats.def_resolve_ambiguous, 0,
            "a same-id self-collapse is not an ambiguity"
        );
    }

    // ── F5 — alias collision fails closed + counted (NEW-BEHAVIOR, mod 6) ─────

    #[test]
    fn task29_f5_alias_collision_fails_closed_and_counts() {
        // NEW-BEHAVIOR characterization (mod 6): two same-file nodes with DIFFERENT
        // qualified traits sharing a last segment alias to the SAME bare key. The
        // slot holds two DIFFERENT ids → resolve_node fails closed (None) AND
        // increments def_resolve_ambiguous. Not claimed red-on-HEAD (the counter
        // field is new); the ablation control below proves the count is real.
        let file = "src/x.rs";
        let (lookup, _ids) = lookup_from_nodes(&[
            ("impl a::T for X::m", "function", file),
            ("impl b::T for X::m", "function", file),
        ]);
        let key = (file.to_string(), "impl T for X::m".to_string());
        assert_eq!(
            lookup.alias.get(&key).map(Vec::len),
            Some(2),
            "two different-id nodes must share the colliding alias slot"
        );
        let mut stats = ScipStats::default();
        assert_eq!(
            resolve_node(file, "impl T for X::m", &lookup, &mut stats),
            None,
            "F5: a multi-candidate alias slot must fail closed (no edge beats a wrong edge)"
        );
        assert_eq!(
            stats.def_resolve_ambiguous, 1,
            "F5: the fail-closed alias collision must be COUNTED"
        );
    }

    // ── F4 — external-crate screen protects the widened alias surface ────────

    #[test]
    fn task29_f4_external_def_screened_from_widened_alias_surface() {
        // The GAP-1 widening enlarges the node-alias surface, but is_resolvable_symbol
        // still screens external-crate DEFs BEFORE resolve_node — an external
        // `impl#[Vec][Clone]clone` def must never bind a local homonym. The bind it
        // would otherwise make is REAL (the descriptor's suffix strip reaches the
        // local exact key `impl Clone for Vec::clone`), so the screen — not a miss —
        // is what blocks it. DECLARED-green (the screen pre-exists); the ablation is
        // the non-vacuity control.
        let file = "src/x.rs";
        let ext = "rust-analyzer cargo alloc 0.0.0 alloc/vec/impl#[Vec][Clone]clone().";
        let run = |local_set: HashSet<String>| -> bool {
            let mut graph = KnowledgeGraph::new();
            let homonym = Uuid::new_v4();
            let caller = Uuid::new_v4();
            let mut h = adr44_node(homonym, "impl Clone for Vec::clone", file);
            h.kind = "function".to_string();
            graph.add_node(h).unwrap();
            let mut c = adr44_node(caller, "caller", file);
            c.kind = "function".to_string();
            graph.add_node(c).unwrap();
            let mut doc = Document::new();
            doc.relative_path = file.to_string();
            doc.occurrences = vec![
                owner_def_occ_at(
                    "rust-analyzer cargo h00ligan_engine 0.1.0 x/caller().",
                    5,
                    9,
                ),
                def_occ_at(ext, 10),
                ref_occ_at(ext, 6),
            ];
            let mut index = Index::new();
            index.documents = vec![doc];
            let mut loader = ScipLoader::with_local_packages(&mut graph, local_set);
            loader.process_index(&index).expect("process_index");
            has_reference_edge(&graph, caller, homonym)
        };
        assert!(
            !run(h00_local_packages()),
            "F4: an external two-bracket def must be screened, never bound to a local homonym"
        );
        let mut permissive = h00_local_packages();
        permissive.insert("alloc".to_string());
        assert!(
            run(permissive),
            "F4 control: bypassing the screen makes the external def bind the local homonym \
             (the exact suffix-strip miss the screen exists to prevent)"
        );
    }

    // ── F6 / F7 — GAP aliases form real edges through process_index ──────────

    #[test]
    fn task29_f6_gap1_trait_impl_def_resolves_and_ref_edges() {
        // GAP-1 edge-formation: once the qualified-trait method DEF resolves (via
        // the bare-trait alias) it enters global_defs, so a REF carrying the
        // IDENTICAL raw SCIP symbol forms a Calls edge. RED without the alias: the
        // def never resolves → the ref drops as refs_target_unindexed → no edge.
        let file = "crates/h00ligan-interface/src/cli_client.rs";
        let method = Uuid::new_v4();
        let caller = Uuid::new_v4();
        let mut graph = KnowledgeGraph::new();
        let mut m = adr44_node(
            method,
            "impl crate::llm::LlmClient for ClaudeCliClient::stream",
            file,
        );
        m.kind = "function".to_string();
        graph.add_node(m).unwrap();
        let mut c = adr44_node(caller, "run", file);
        c.kind = "function".to_string();
        graph.add_node(c).unwrap();
        let method_sym = "rust-analyzer cargo h00ligan_interface 0.1.0 cli_client/impl#[ClaudeCliClient][LlmClient]stream().";
        let run_sym = "rust-analyzer cargo h00ligan_interface 0.1.0 cli_client/run().";
        let mut doc = Document::new();
        doc.relative_path = file.to_string();
        doc.occurrences = vec![
            owner_def_occ_at(run_sym, 5, 10),
            def_occ_at(method_sym, 40),
            ref_occ_at(method_sym, 6),
        ];
        let mut index = Index::new();
        index.documents = vec![doc];
        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");
        assert!(
            has_reference_edge(&graph, caller, method),
            "F6: the bare-trait alias resolves the qualified method def → the ref forms a Calls edge"
        );
    }

    #[test]
    fn task29_f7_gap2_macro_def_resolves_and_ref_edges() {
        // GAP-2 edge-formation: the macro DEF resolves (via the bang alias) and
        // enters global_defs, so a macro-invocation REF forms an edge. The bang
        // symbol classifies as a References edge (no `().`) — admitted by the
        // classifier's EdgeClass::Call walk. RED without the alias: no edge.
        let file = "crates/h00ligan-engine/src/tarpc_store.rs";
        let macro_id = Uuid::new_v4();
        let caller = Uuid::new_v4();
        let mut graph = KnowledgeGraph::new();
        let mut mac = adr44_node(macro_id, "rpc_with_reconnect", file);
        mac.kind = "macro".to_string();
        graph.add_node(mac).unwrap();
        let mut c = adr44_node(caller, "impl MemoryStore::store", file);
        c.kind = "function".to_string();
        graph.add_node(c).unwrap();
        let macro_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 tarpc_store/rpc_with_reconnect!";
        let store_sym =
            "rust-analyzer cargo h00ligan_engine 0.1.0 tarpc_store/impl#[MemoryStore]store().";
        let mut doc = Document::new();
        doc.relative_path = file.to_string();
        doc.occurrences = vec![
            owner_def_occ_at(store_sym, 185, 200),
            def_occ_at(macro_sym, 151),
            ref_occ_at(macro_sym, 190),
        ];
        let mut index = Index::new();
        index.documents = vec![doc];
        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        loader.process_index(&index).expect("process_index");
        assert!(
            has_edge_of_kind(&graph, caller, macro_id, EdgeKind::References),
            "F7: the macro-bang alias resolves the macro def → the invocation ref forms an edge"
        );
    }

    // ── mod 7(a) — macro DEF enclosing_range sources a body ref to the macro ──

    #[test]
    fn task29_mod7a_macro_enclosing_range_sources_body_ref_to_macro() {
        // mod 7(a): GAP-2's SOURCE-side rescue (body refs re-sourcing to the macro
        // node, not the whole-file module) requires the macro_rules DEF occurrence
        // to carry an enclosing_range spanning the body. This pins the CODE PATH:
        // with such a range, a helper ref on a line INSIDE the body sources to the
        // macro node (tier-1 enclosing), forming a macro-node edge, and does NOT
        // fall through to no-enclosing. (The REAL-DATA question — does
        // rust-analyzer actually emit this range on a macro_rules def — is answered
        // separately against index.scip; see the build return.)
        let file = "crates/h00ligan-engine/src/tarpc_store.rs";
        let macro_id = Uuid::new_v4();
        let helper = Uuid::new_v4();
        let mut graph = KnowledgeGraph::new();
        let mut mac = adr44_node(macro_id, "rpc_with_reconnect", file);
        mac.kind = "macro".to_string();
        graph.add_node(mac).unwrap();
        let mut h = adr44_node(helper, "wire_err", file);
        h.kind = "function".to_string();
        graph.add_node(h).unwrap();

        let macro_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 tarpc_store/rpc_with_reconnect!";
        let helper_sym = "rust-analyzer cargo h00ligan_engine 0.1.0 tarpc_store/wire_err().";

        // Macro DEF with an enclosing_range spanning the macro_rules body 151..175.
        let mut macro_def = def_occ_at(macro_sym, 151);
        macro_def.enclosing_range = vec![151, 0, 175, 1];
        let mut doc = Document::new();
        doc.relative_path = file.to_string();
        doc.occurrences = vec![
            macro_def,
            def_occ_at(helper_sym, 107),
            ref_occ_at(helper_sym, 169), // inside the macro body (151..175)
        ];
        let mut index = Index::new();
        index.documents = vec![doc];
        let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
        let stats = loader.process_index(&index).expect("process_index");
        assert!(
            has_reference_edge(&graph, macro_id, helper),
            "mod 7a: a body ref inside the macro's enclosing_range must source to the MACRO node"
        );
        assert_eq!(
            stats.refs_no_enclosing_def, 0,
            "mod 7a: the body ref must find its enclosing source (the macro), not drop"
        );
    }

    // ── F8 — the test-double safety backstop (rebuilt per mod 4) ─────────────

    /// Run the classifier from a single Binary entry point at `src/main.rs`
    /// (mirrors reachability's own `analyze_with_main`).
    fn analyze_from_main(graph: &KnowledgeGraph) -> crate::reachability::ReachabilityReport {
        use crate::entry_points::{EntryPoint, EntryPointKind};
        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: std::path::PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };
        crate::reachability::ReachabilityAnalyzer::new(graph, vec![ep]).analyze()
    }

    /// A full classifier fixture node with an explicit test-ness bit + root bit.
    fn reach_node(
        name: &str,
        kind: &str,
        file: &str,
        visibility: &str,
        is_test_only: Option<bool>,
        is_test_root: bool,
    ) -> crate::graph::GraphNode {
        crate::graph::GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.to_string(),
            kind: kind.to_string(),
            file_path: file.to_string(),
            content_hash: format!("h-{name}"),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(1),
            line_end: Some(9),
            has_body: Some(true),
            visibility: visibility.to_string(),
            is_test_only,
            is_test_root,
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
            ..GraphEdge::default()
        }
    }

    #[test]
    fn task29_f8_test_impl_alias_target_stays_test_only_not_wired() {
        // REBUILT per mod 4. The GAP-1 alias resolves a MODULE-NESTED test impl
        // (`tests::impl SomeTrait for SomeMock::method`) — so its body edges now
        // exist. The safety property: a target reached ONLY through that test-impl
        // must classify TestOnly, NEVER Wired. The REAL backstop is the persisted
        // `is_test_only` bit consulted by the production-BFS prune
        // (`is_test_module_symbol`, graph_query.rs:1012-1013 / reachability.rs:566),
        // NOT the guard-rescue cap — so the fixture aims a PRODUCTION edge INTO the
        // test-impl method and proves the prune blocks it.
        //
        // Graph: main [Binary root] --Calls--> serve [test-impl method] --Calls-->
        // only_from_mock;  a #[test] root also --Calls--> serve (so the test pass
        // reaches only_from_mock → TestOnly, not Dead).
        let file = "crates/h00ligan-interface/src/cli_client.rs";
        let serve_name = "tests::impl crate::llm::LlmClient for FailingLlmClient::stream";

        // Precondition (mod 4): serve is a module-nested test impl that ACTUALLY
        // RECEIVES a bare-trait alias under the widened predicate.
        assert_eq!(
            bare_trait_impl_alias(serve_name).as_deref(),
            Some("tests::impl LlmClient for FailingLlmClient::stream"),
            "mod 4 precondition: the test-impl node must be alias-eligible"
        );

        let build = |serve_test_bit: Option<bool>| -> crate::reachability::ReachabilityReport {
            let main = reach_node("main", "function", "src/main.rs", "pub", None, false);
            let test_fn = reach_node(
                "tests::exercises_stream",
                "function",
                file,
                "private",
                Some(true),
                true, // #[test] root
            );
            // The test-impl method: alias-eligible name; test-ness carried by the
            // persisted bit (the ablated variable).
            let serve = reach_node(
                serve_name,
                "function",
                file,
                "private",
                serve_test_bit,
                false,
            );
            let only_from_mock =
                reach_node("only_from_mock", "function", file, "private", None, false);

            let (main_id, test_id, serve_id, tgt_id) = (
                main.memory_id,
                test_fn.memory_id,
                serve.memory_id,
                only_from_mock.memory_id,
            );
            let mut graph = KnowledgeGraph::new();
            for n in [main, test_fn, serve, only_from_mock] {
                graph.add_node(n).unwrap();
            }
            // A PRODUCTION edge into the test-impl method (what the prune blocks).
            graph.add_edge(main_id, serve_id, calls_edge()).unwrap();
            // A #[test] root reaches it too (so the TEST pass classifies the target).
            graph.add_edge(test_id, serve_id, calls_edge()).unwrap();
            // The alias-created body edge under test.
            graph.add_edge(serve_id, tgt_id, calls_edge()).unwrap();
            analyze_from_main(&graph)
        };

        // POSITIVE: with the test bit set, the production BFS prunes serve, so the
        // target is reached ONLY in the test pass → TestOnly (never Wired).
        let report = build(Some(true));
        let tgt = report
            .classified
            .iter()
            .find(|c| c.symbol_name == "only_from_mock")
            .expect("target classified");
        assert_eq!(
            tgt.classification,
            ReachabilityClass::TestOnly,
            "F8: a target reached only through a test-impl must be TestOnly, never Wired"
        );

        // NON-VACUITY ABLATION: flip ONLY the persisted bit to Some(false) — now
        // is_test_module_symbol returns false, the prune no longer fires, and the
        // production BFS reaches the target → Wired (the false-WIRED this guards).
        let ablated = build(Some(false));
        let tgt2 = ablated
            .classified
            .iter()
            .find(|c| c.symbol_name == "only_from_mock")
            .expect("target classified");
        assert_eq!(
            tgt2.classification,
            ReachabilityClass::Wired,
            "F8 control: ablating the is_test_only bit must flip the target to Wired \
             (proving the prune is the load-bearing backstop)"
        );
    }
}
