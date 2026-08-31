//! Reachability analysis for the code knowledge graph.
//!
//! Classifies every symbol in the graph as WIRED, PUBLIC_API, TEST_ONLY,
//! DEAD, or ORPHAN using multi-root BFS from discovered entry points.
//!
//! ## Algorithm
//!
//! 1. **Production pass**: BFS from binary `main()` entry points. Mark reachable as `Wired`.
//! 2. **Public API pass**: BFS from library root public items. Mark remaining as `PublicApi`.
//! 3. **Test pass**: BFS from `#[cfg(test)]` module roots. Mark remaining as `TestOnly`.
//! 4. **Remainder**: Everything not visited in any pass is `Dead`.
//! 5. **Orphan detection**: Walk `src/` directories for `.rs` files not in the graph.

use crate::entry_points::{EntryPoint, EntryPointKind};
use crate::graph::{EdgeKind, KnowledgeGraph};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

// ---------------------------------------------------------------------------
// Classification types
// ---------------------------------------------------------------------------

/// Reachability classification for a symbol in the knowledge graph.
///
/// `Default` is [`Self::Unclassified`] (WU-0003 / CL-REACH RC5): the
/// `#[serde(default)]` on `GraphNode::reachability_class` resolves a
/// physically-absent field (old snapshots) to `Unclassified`, never silently to
/// `Dead`.
///
/// The derived `Ord` follows VARIANT DECLARATION ORDER and is load-bearing: the
/// WU-0019 container roll-up selects a container's most-alive child via `.min()`
/// (`Wired < PublicApi < Structural < TestOnly < Dead < …`). Reordering variants
/// silently changes roll-up tier propagation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum ReachabilityClass {
    /// Reachable from a binary `main()` via production call chains.
    Wired,
    /// Public item in a library crate — reachable as API surface.
    PublicApi,
    /// Compile-time dependency (use, const, static, type_alias, macro) in a file
    /// containing wired or public API code. Not directly called, but required for
    /// compilation — removing it would break the build.
    Structural,
    /// Reachable only from `#[cfg(test)]` modules.
    TestOnly,
    /// Not reachable from any entry point.
    Dead,
    /// Source file exists on disk but has no `mod` declaration (orphan file).
    Orphan,
    /// Classification has not run for this node — a first-class, never-clean
    /// "don't know" state (WU-0003 / CL-REACH RC5). Surfaced as its own bucket,
    /// NEVER folded into wired or dead: an unclassified graph reports
    /// `UNCLASSIFIED`, never a false-clean `dead=0`. APPENDED for bincode
    /// variant-ordinal stability; `#[default]` so a missing serde field resolves
    /// here.
    #[default]
    Unclassified,
    /// Call-unreachable residual that is NOT a delete authority — a
    /// confidence-ranked review candidate (WU-0015 / ADR-0036 v6). Absorbs the
    /// directed-call-reachability residue: pub items with zero real in-workspace
    /// callers (external-API-vs-wiring-gap), guard-rescued impl/trait methods,
    /// and — in Leg 1, where NO corroborating rustc/cfg oracle exists yet —
    /// EVERY private call-unreachable symbol too. `action_tier == Review`: never
    /// `Healthy` (never reported clean) and NEVER a delete tier (the Leg-1
    /// delete-authority tier is EMPTY; `ReachabilityClass::Dead` + its
    /// `SafeDelete` gate arrive only in Leg 3). APPENDED LAST (after
    /// `Unclassified`) for bincode variant-ordinal stability: existing ordinals
    /// are unchanged and `reachability_class` is recomputed on every reindex, so
    /// old snapshots simply carry no `Suspected` value.
    Suspected,
    /// ADR-0045 — OUT of the production-reachability census: the symbol's file is
    /// not part of the root build unit (a deliberately-detached / nested-
    /// `[workspace]` crate — **D1**) or is a fixture-corpus INPUT the extractor
    /// consumes rather than code-under-analysis (an excluded-dir path segment such
    /// as `testdata`/`vendor`/`third_party`/`node_modules` — **D2**). It is an
    /// honest NON-reachable, NON-actionable disposition: `action_tier == Healthy`
    /// (never a delete/review candidate — no verdict about out-of-scope code is
    /// meaningful), yet still first-class + machine-queryable (persisted, counted,
    /// reportable) so over-exclusion can never SILENTLY swallow a finding. The
    /// ONLY transitions into it are {Dead, Suspected, TestOnly} → Excluded; nothing
    /// moves toward Wired/PublicApi. APPENDED LAST (after `Suspected`) for bincode
    /// variant-ordinal stability: existing ordinals are unchanged and
    /// `reachability_class` is recomputed on every reindex, so old snapshots simply
    /// carry no `Excluded` value.
    Excluded,
}

impl std::fmt::Display for ReachabilityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wired => f.write_str("WIRED"),
            Self::PublicApi => f.write_str("PUBLIC_API"),
            Self::Structural => f.write_str("STRUCTURAL"),
            Self::TestOnly => f.write_str("TEST_ONLY"),
            Self::Dead => f.write_str("DEAD"),
            Self::Orphan => f.write_str("ORPHAN"),
            Self::Unclassified => f.write_str("UNCLASSIFIED"),
            Self::Suspected => f.write_str("SUSPECTED"),
            Self::Excluded => f.write_str("EXCLUDED"),
        }
    }
}

/// Actionable urgency tier derived from [`ReachabilityClass`].
///
/// Maps the six-variant classification into three tiers that drive
/// CLI output grouping and CI gating decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActionTier {
    /// Preserve -- no action needed (Wired, PublicApi, Structural).
    Healthy,
    /// Review -- may be intentional or unreachable, needs human judgment
    /// (TestOnly, Suspected, and — post-demote (WU-0016 / ADR-0039) — Dead and
    /// Orphan). The former `Action` (auto-delete) tier is COLLAPSED into this:
    /// static analysis is advisory, never a delete authority, so a dead symbol
    /// is a review candidate, not an auto-delete verdict. DEAD stays
    /// distinguishable via `ReachabilityClass` / `reachability_label`.
    Review,
    /// Unknown -- classification has not run (Unclassified). A conservative
    /// "don't know" tier (WU-0003 / CL-REACH RC5): NEVER `Healthy` (so it is
    /// never reported clean). Run an index, then re-classify.
    Unknown,
}

impl ActionTier {
    /// The single-source render label for this tier (WU-0016 / ADR-0039 RC-D2).
    ///
    /// The ONE place the `ReachabilityClass → action_tier` string is produced;
    /// the CLI (`h00ligan`) and MCP (`h00ligan-interface`) render sites call this instead
    /// of re-implementing a drifted local map (the historical `HEALTHY`-vs-
    /// `PRESERVE` divergence is fixed by construction).
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "PRESERVE",
            Self::Review => "REVIEW",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for ActionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl ReachabilityClass {
    /// Map this classification to an [`ActionTier`].
    pub const fn action_tier(&self) -> ActionTier {
        match self {
            Self::Wired | Self::PublicApi | Self::Structural => ActionTier::Healthy,
            Self::TestOnly => ActionTier::Review,
            // WU-0016 / ADR-0039: the auto-delete tier is COLLAPSED into Review.
            // Static analysis is advisory (delete authority demoted) — a dead /
            // orphan symbol is a review candidate, never an auto-delete verdict.
            Self::Dead | Self::Orphan => ActionTier::Review,
            // Conservative: never Healthy (not reported clean). An honest
            // "classification did not run."
            Self::Unclassified => ActionTier::Unknown,
            // WU-0015 / ADR-0036 v6: a review candidate, never a delete
            // authority — the Leg-1 delete tier is EMPTY.
            Self::Suspected => ActionTier::Review,
            // ADR-0045: OUT of the census (detached/nested crate or fixture
            // corpus). Out-of-scope code is neither clean-nor-dead — no delete
            // OR review verdict about it is meaningful — so it is `Healthy`
            // (never a delete/review candidate), NOT `Review`.
            Self::Excluded => ActionTier::Healthy,
        }
    }
}

/// A graph node with its reachability classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedNode {
    /// The node's memory ID in the graph.
    pub memory_id: Uuid,
    /// Fully-qualified symbol name.
    pub symbol_name: String,
    /// Source file path.
    pub file_path: String,
    /// Symbol kind (e.g. "function", "struct").
    pub kind: String,
    /// Reachability classification.
    pub classification: ReachabilityClass,
    /// Whether the node carries an `#[allow(dead_code)]` retain attribute
    /// (WU-0015 Leg J). A projection of
    /// [`EntryRetainFlags::has_retain_attr`](crate::graph::EntryRetainFlags::has_retain_attr)
    /// carried on the classified node so the ligan file-surface consumer
    /// (`graph_cmd`'s `fully_dead`/`fully_dead_files` labels) can EXCLUDE a
    /// retain-attr node from the `dead == total` fully-dead numerator WITHOUT a
    /// graph lookup — a still-`Dead`-class node the author flagged "keep" should
    /// not paint its file "fully dead". Defaults to `false`
    /// (`#[serde(default)]`) for old reports; ClassifiedNode is a transient
    /// query result (not under the `graph_store` SCHEMA_VERSION).
    #[serde(default)]
    pub has_retain_attr: bool,
    /// Whether the node's source FILE holds an item-position construct the
    /// extractor whitelist DROPS (WU-0016 Leg H /
    /// OQ-FILE-TIER-CAPTURE-COMPLETENESS). A projection of
    /// [`GraphNode::has_uncaptured_items`](crate::graph::GraphNode::has_uncaptured_items)
    /// carried on the classified node so the ligan file-tier consumer
    /// (`graph_cmd::compute_file_tiers`) can WITHHOLD the `fully_dead` claim from
    /// a not-capture-complete file WITHOUT a graph lookup — a file whose captured
    /// symbols are all Dead but which holds an uncaptured item-generating
    /// construct is NOT delete-safe (deleting it drops the generated item,
    /// E0425). Defaults to `false` (`#[serde(default)]`) for old reports;
    /// ClassifiedNode is a transient query result (not under the `graph_store`
    /// SCHEMA_VERSION).
    #[serde(default)]
    pub has_uncaptured_items: bool,
}

/// Summary statistics from a reachability analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilitySummary {
    /// Total symbols analyzed.
    pub total: usize,
    /// Symbols reachable from production entry points.
    pub wired: usize,
    /// Public API symbols in library crates.
    pub public_api: usize,
    /// Compile-time dependencies (use, const, static, type_alias, macro) in
    /// files containing wired or public API code.
    #[serde(default)]
    pub structural: usize,
    /// Symbols reachable only from test code.
    pub test_only: usize,
    /// Unreachable symbols.
    pub dead: usize,
    /// Orphan .rs files not in any module tree.
    pub orphan_files: usize,
    /// WU-0015 / ADR-0036 v6: call-unreachable review candidates (never a delete
    /// authority). APPENDED LAST for serde/bincode field-ordinal stability.
    #[serde(default)]
    pub suspected: usize,
    /// ADR-0045: symbols OUT of the production-reachability census (D1 detached/
    /// nested-crate files + D2 fixture-corpus dirs). A first-class reported count
    /// so over-exclusion is never silent. APPENDED LAST for serde/bincode
    /// field-ordinal stability.
    #[serde(default)]
    pub excluded: usize,
}

/// Full reachability analysis report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityReport {
    /// Per-node classifications.
    pub classified: Vec<ClassifiedNode>,
    /// Aggregate summary.
    pub summary: ReachabilitySummary,
    /// Names of entry points used as BFS roots.
    pub entry_points_used: Vec<String>,
    /// Orphan file paths (files on disk with no graph representation).
    pub orphan_files: Vec<String>,
    /// Test coverage chains: maps a test-helper UUID to the chain(s) of symbol
    /// names from the `#[test]` function down to that helper.
    ///
    /// Each chain is a `Vec<String>` like `[test_fn, intermediate_helper, this_helper]`.
    /// Only populated for `TestOnly` helpers that are NOT `#[test]` functions themselves.
    #[serde(default)]
    pub test_chains: BTreeMap<Uuid, Vec<Vec<String>>>,
}

/// Schema carried by the generation-local reachability evidence document.
pub const REACHABILITY_EVIDENCE_SCHEMA: &str = "h00/reachability-evidence/v2";

/// One entry point captured at index time with a generation-relative path.
///
/// [`EntryPoint`] is the discovery type and may carry an absolute path. That is
/// useful while indexing, but it would bake machine identity into an immutable
/// generation. This persisted form retains the typed target identity while
/// requiring a normalized repository-relative path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedEntryPoint {
    pub name: String,
    pub kind: EntryPointKind,
    pub file_path: String,
    pub crate_name: String,
}

impl PersistedEntryPoint {
    /// Materialize the discovery-domain type without consulting live manifests.
    #[must_use]
    pub fn as_entry_point(&self) -> EntryPoint {
        EntryPoint {
            name: self.name.clone(),
            kind: self.kind.clone(),
            file_path: PathBuf::from(&self.file_path),
            crate_name: self.crate_name.clone(),
        }
    }

    fn display_label(&self) -> String {
        format!("{} [{}] ({})", self.name, self.kind, self.crate_name)
    }
}

/// Complete reachability evidence produced and consumed within one immutable
/// code-intelligence generation.
///
/// The report is never reconstructed from live source. Persisted generations
/// store only the independent reachability projection; on load the complete
/// runtime report is reconstructed from the co-published immutable graph and
/// verified against that projection's population digest, summary, entry
/// points, orphan files, and trace roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachabilityEvidence {
    pub schema: String,
    pub report: ReachabilityReport,
    /// Exact repository-relative source documents over which this evidence may
    /// make reachability claims. Registered source outside this population is
    /// present in `report.classified` only as `Unclassified`.
    pub classified_documents: Vec<String>,
    pub entry_points: Vec<PersistedEntryPoint>,
    pub trace_root_ids: Vec<Uuid>,
}

/// Compact storage projection for reachability evidence.
///
/// `GraphNode` already owns every classified UUID, symbol identity, flag, and
/// reachability class. Persisting the full [`ReachabilityReport::classified`]
/// population beside the graph duplicated that payload. This envelope keeps
/// the genuinely independent facts plus a canonical digest that binds the
/// reconstructed runtime population to the exact graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedReachabilityEvidence {
    pub(crate) schema: String,
    pub(crate) classified_population_blake3: String,
    pub(crate) summary: ReachabilitySummary,
    pub(crate) classified_documents: Vec<String>,
    pub(crate) entry_points: Vec<PersistedEntryPoint>,
    pub(crate) orphan_files: Vec<String>,
    pub(crate) trace_root_ids: Vec<Uuid>,
}

/// A reachability evidence document is present but internally inconsistent.
#[derive(Debug, thiserror::Error)]
pub enum ReachabilityEvidenceError {
    #[error("entry-point discovery failed: {0}")]
    EntryPoints(#[from] crate::entry_points::EntryPointError),
    #[error("invalid reachability evidence: {0}")]
    Invalid(String),
}

impl ReachabilityEvidence {
    fn from_analysis(
        graph: &KnowledgeGraph,
        workspace_root: &Path,
        mut report: ReachabilityReport,
        entry_points: Vec<EntryPoint>,
        mut classified_documents: Vec<String>,
    ) -> Result<Self, ReachabilityEvidenceError> {
        let canonical_root = workspace_root.canonicalize().map_err(|error| {
            ReachabilityEvidenceError::Invalid(format!(
                "canonicalize workspace root {}: {error}",
                workspace_root.display()
            ))
        })?;
        let mut persisted_entry_points = entry_points
            .into_iter()
            .map(|entry_point| {
                let relative = if entry_point.file_path.is_absolute() {
                    entry_point
                        .file_path
                        .strip_prefix(&canonical_root)
                        .map_err(|_| {
                            ReachabilityEvidenceError::Invalid(format!(
                                "entry point {} escapes workspace root {}",
                                entry_point.file_path.display(),
                                canonical_root.display()
                            ))
                        })?
                        .to_path_buf()
                } else {
                    entry_point.file_path
                };
                let file_path = normalize_entry_point_path(&entry_point.kind, &relative)?;
                Ok(PersistedEntryPoint {
                    name: entry_point.name,
                    kind: entry_point.kind,
                    file_path,
                    crate_name: entry_point.crate_name,
                })
            })
            .collect::<Result<Vec<_>, ReachabilityEvidenceError>>()?;
        persisted_entry_points.sort();
        if persisted_entry_points
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(ReachabilityEvidenceError::Invalid(
                "duplicate persisted entry point".into(),
            ));
        }

        for document in &classified_documents {
            let normalized = normalize_reachability_document_path(Path::new(document))?;
            if normalized != *document {
                return Err(ReachabilityEvidenceError::Invalid(format!(
                    "classified document {document:?} is not normalized"
                )));
            }
        }
        classified_documents.sort();
        if classified_documents
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(ReachabilityEvidenceError::Invalid(
                "duplicate classified document".into(),
            ));
        }

        report.classified.sort_by_key(|node| node.memory_id);
        report.orphan_files.sort();
        if report
            .orphan_files
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(ReachabilityEvidenceError::Invalid(
                "duplicate orphan-file path".into(),
            ));
        }
        // Detailed test paths are a bounded query-time projection over the
        // provider-backed Calls graph (`code_intel_tests`). Persisting the
        // analyzer's eager helper × test-root chains duplicates that graph and
        // grows combinatorially on test-heavy workspaces. Keep the explicit
        // analyzer API available, but generations retain no redundant path
        // cache.
        report.test_chains.clear();
        report.entry_points_used = persisted_entry_points
            .iter()
            .map(PersistedEntryPoint::display_label)
            .collect();

        let materialized = persisted_entry_points
            .iter()
            .map(PersistedEntryPoint::as_entry_point)
            .collect::<Vec<_>>();
        let mut trace_root_ids =
            crate::graph_query::resolve_production_root_ids(graph, &materialized);
        trace_root_ids.sort_unstable();
        trace_root_ids.dedup();

        let evidence = Self {
            schema: REACHABILITY_EVIDENCE_SCHEMA.into(),
            report,
            classified_documents,
            entry_points: persisted_entry_points,
            trace_root_ids,
        };
        evidence.validate(graph)?;
        Ok(evidence)
    }

    /// Project the complete runtime evidence into its non-duplicative storage
    /// envelope. Callers validate the runtime evidence against the graph before
    /// admitting this projection to an immutable generation.
    pub(crate) fn persisted_projection(&self) -> PersistedReachabilityEvidence {
        PersistedReachabilityEvidence {
            schema: self.schema.clone(),
            classified_population_blake3: classified_population_blake3(&self.report.classified),
            summary: self.report.summary.clone(),
            classified_documents: self.classified_documents.clone(),
            entry_points: self.entry_points.clone(),
            orphan_files: self.report.orphan_files.clone(),
            trace_root_ids: self.trace_root_ids.clone(),
        }
    }

    /// Rebuild the complete runtime report only from the co-published graph and
    /// compact persisted evidence. No live source or project metadata is read.
    pub(crate) fn from_persisted_projection(
        graph: &KnowledgeGraph,
        persisted: PersistedReachabilityEvidence,
    ) -> Result<Self, ReachabilityEvidenceError> {
        let classified = classified_population_from_graph(graph);
        let actual_digest = classified_population_blake3(&classified);
        if persisted.classified_population_blake3 != actual_digest {
            return Err(ReachabilityEvidenceError::Invalid(
                "classified population digest differs from the persisted graph".into(),
            ));
        }
        let entry_points_used = persisted
            .entry_points
            .iter()
            .map(PersistedEntryPoint::display_label)
            .collect();
        let evidence = Self {
            schema: persisted.schema,
            report: ReachabilityReport {
                classified,
                summary: persisted.summary,
                entry_points_used,
                orphan_files: persisted.orphan_files,
                test_chains: BTreeMap::new(),
            },
            classified_documents: persisted.classified_documents,
            entry_points: persisted.entry_points,
            trace_root_ids: persisted.trace_root_ids,
        };
        evidence.validate(graph)?;
        Ok(evidence)
    }

    /// Recreate typed roots entirely from persisted generation evidence.
    #[must_use]
    pub fn materialized_entry_points(&self) -> Vec<EntryPoint> {
        self.entry_points
            .iter()
            .map(PersistedEntryPoint::as_entry_point)
            .collect()
    }

    /// Recreate the exact generation-scoped analyzer used to produce this
    /// evidence. Query-time root reconstruction must not widen back to every
    /// registered document in the graph.
    #[must_use]
    pub fn analyzer<'g>(&self, graph: &'g KnowledgeGraph) -> ReachabilityAnalyzer<'g> {
        ReachabilityAnalyzer::for_classified_documents(
            graph,
            self.materialized_entry_points(),
            self.classified_documents.iter().cloned(),
        )
    }

    /// Validate that every reported semantic fact belongs to `graph`.
    pub fn validate(&self, graph: &KnowledgeGraph) -> Result<(), ReachabilityEvidenceError> {
        if self.schema != REACHABILITY_EVIDENCE_SCHEMA {
            return Err(ReachabilityEvidenceError::Invalid(format!(
                "unsupported schema {:?}; expected {REACHABILITY_EVIDENCE_SCHEMA}",
                self.schema
            )));
        }
        if !self
            .classified_documents
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(ReachabilityEvidenceError::Invalid(
                "classified documents are not strictly ordered and unique".into(),
            ));
        }
        for document in &self.classified_documents {
            let normalized = normalize_reachability_document_path(Path::new(document))?;
            if normalized != *document {
                return Err(ReachabilityEvidenceError::Invalid(format!(
                    "classified document {document:?} is not normalized"
                )));
            }
        }
        if self.entry_points.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ReachabilityEvidenceError::Invalid(
                "entry points are not strictly ordered and unique".into(),
            ));
        }
        for entry_point in &self.entry_points {
            if entry_point.name.is_empty() || entry_point.crate_name.is_empty() {
                return Err(ReachabilityEvidenceError::Invalid(
                    "entry-point name and crate name must be non-empty".into(),
                ));
            }
            let normalized =
                normalize_entry_point_path(&entry_point.kind, Path::new(&entry_point.file_path))?;
            if normalized != entry_point.file_path {
                return Err(ReachabilityEvidenceError::Invalid(format!(
                    "entry-point path {:?} is not normalized",
                    entry_point.file_path
                )));
            }
        }

        let expected_entry_labels = self
            .entry_points
            .iter()
            .map(PersistedEntryPoint::display_label)
            .collect::<Vec<_>>();
        if self.report.entry_points_used != expected_entry_labels {
            return Err(ReachabilityEvidenceError::Invalid(
                "report entry-point labels differ from typed entry points".into(),
            ));
        }

        let graph_nodes = graph.all_nodes();
        let classified_documents = self
            .classified_documents
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if self.report.classified.len() != graph_nodes.len() {
            return Err(ReachabilityEvidenceError::Invalid(format!(
                "classified population {} differs from graph node population {}",
                self.report.classified.len(),
                graph_nodes.len()
            )));
        }
        if !self
            .report
            .classified
            .windows(2)
            .all(|pair| pair[0].memory_id < pair[1].memory_id)
        {
            return Err(ReachabilityEvidenceError::Invalid(
                "classified node IDs are not strictly ordered and unique".into(),
            ));
        }

        for classified in &self.report.classified {
            let node = graph.node(&classified.memory_id).ok_or_else(|| {
                ReachabilityEvidenceError::Invalid(format!(
                    "classified node {} is absent from the graph",
                    classified.memory_id
                ))
            })?;
            let identity_matches = classified.symbol_name == node.symbol_name
                && classified.file_path == node.file_path
                && classified.kind == node.kind;
            let classification_matches = classified.classification == node.reachability_class;
            let flags_match = classified.has_retain_attr == node.entry_retain.has_retain_attr()
                && classified.has_uncaptured_items == node.has_uncaptured_items;
            if !(identity_matches && classification_matches && flags_match) {
                return Err(ReachabilityEvidenceError::Invalid(format!(
                    "classified node {} does not match its persisted graph node",
                    classified.memory_id
                )));
            }
            if crate::graph_stats::node_language(node).is_some() {
                let document_is_covered = classified_documents.contains(node.file_path.as_str());
                let carries_verdict = classified.classification != ReachabilityClass::Unclassified;
                if document_is_covered != carries_verdict {
                    return Err(ReachabilityEvidenceError::Invalid(format!(
                        "registered source node {} reachability verdict disagrees with classified-document scope",
                        classified.memory_id
                    )));
                }
            }
        }

        let mut expected_summary = ReachabilitySummary {
            total: graph_nodes.len(),
            wired: 0,
            public_api: 0,
            structural: 0,
            test_only: 0,
            dead: 0,
            orphan_files: self.report.orphan_files.len(),
            suspected: 0,
            excluded: 0,
        };
        for classified in &self.report.classified {
            match classified.classification {
                ReachabilityClass::Wired => expected_summary.wired += 1,
                ReachabilityClass::PublicApi => expected_summary.public_api += 1,
                ReachabilityClass::Structural => expected_summary.structural += 1,
                ReachabilityClass::TestOnly => expected_summary.test_only += 1,
                ReachabilityClass::Dead => expected_summary.dead += 1,
                ReachabilityClass::Suspected => expected_summary.suspected += 1,
                ReachabilityClass::Excluded => expected_summary.excluded += 1,
                ReachabilityClass::Orphan | ReachabilityClass::Unclassified => {}
            }
        }
        if self.report.summary != expected_summary {
            return Err(ReachabilityEvidenceError::Invalid(
                "report summary differs from its classified graph population".into(),
            ));
        }

        if !self
            .report
            .orphan_files
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(ReachabilityEvidenceError::Invalid(
                "orphan-file paths are not strictly ordered and unique".into(),
            ));
        }
        for (helper_id, chains) in &self.report.test_chains {
            let Some(helper) = graph.node(helper_id) else {
                return Err(ReachabilityEvidenceError::Invalid(format!(
                    "test-chain helper {helper_id} is absent from the graph"
                )));
            };
            if helper.reachability_class != ReachabilityClass::TestOnly
                || chains.is_empty()
                || !chains.windows(2).all(|pair| pair[0] < pair[1])
            {
                return Err(ReachabilityEvidenceError::Invalid(format!(
                    "test-chain evidence for {helper_id} is inconsistent"
                )));
            }
        }

        if !self.trace_root_ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ReachabilityEvidenceError::Invalid(
                "trace-root IDs are not strictly ordered and unique".into(),
            ));
        }
        let materialized = self.materialized_entry_points();
        let mut expected_trace_roots =
            crate::graph_query::resolve_production_root_ids(graph, &materialized);
        expected_trace_roots.sort_unstable();
        expected_trace_roots.dedup();
        if self.trace_root_ids != expected_trace_roots {
            return Err(ReachabilityEvidenceError::Invalid(
                "trace-root IDs do not resolve from the persisted entry points and graph".into(),
            ));
        }
        if self
            .trace_root_ids
            .iter()
            .any(|root_id| graph.node(root_id).is_none())
        {
            return Err(ReachabilityEvidenceError::Invalid(
                "trace-root evidence references a missing graph node".into(),
            ));
        }

        Ok(())
    }
}

fn classified_population_from_graph(graph: &KnowledgeGraph) -> Vec<ClassifiedNode> {
    let mut classified = graph
        .all_nodes()
        .into_iter()
        .map(|node| ClassifiedNode {
            memory_id: node.memory_id,
            symbol_name: node.symbol_name.clone(),
            file_path: node.file_path.clone(),
            kind: node.kind.clone(),
            classification: node.reachability_class,
            has_retain_attr: node.entry_retain.has_retain_attr(),
            has_uncaptured_items: node.has_uncaptured_items,
        })
        .collect::<Vec<_>>();
    classified.sort_by_key(|node| node.memory_id);
    classified
}

fn classified_population_blake3(classified: &[ClassifiedNode]) -> String {
    fn update_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    const fn class_tag(classification: ReachabilityClass) -> u8 {
        match classification {
            ReachabilityClass::Wired => 0,
            ReachabilityClass::PublicApi => 1,
            ReachabilityClass::Structural => 2,
            ReachabilityClass::TestOnly => 3,
            ReachabilityClass::Dead => 4,
            ReachabilityClass::Orphan => 5,
            ReachabilityClass::Unclassified => 6,
            ReachabilityClass::Suspected => 7,
            ReachabilityClass::Excluded => 8,
        }
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"h00/reachability-classified-population/v1\0");
    hasher.update(&(classified.len() as u64).to_le_bytes());
    for node in classified {
        hasher.update(node.memory_id.as_bytes());
        update_bytes(&mut hasher, node.symbol_name.as_bytes());
        update_bytes(&mut hasher, node.file_path.as_bytes());
        update_bytes(&mut hasher, node.kind.as_bytes());
        hasher.update(&[
            class_tag(node.classification),
            u8::from(node.has_retain_attr),
            u8::from(node.has_uncaptured_items),
        ]);
    }
    hasher.finalize().to_hex().to_string()
}

fn normalize_reachability_document_path(path: &Path) -> Result<String, ReachabilityEvidenceError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => parts.push(part.to_str().ok_or_else(|| {
                ReachabilityEvidenceError::Invalid(format!(
                    "classified document path {} is not UTF-8",
                    path.display()
                ))
            })?),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ReachabilityEvidenceError::Invalid(format!(
                    "classified document path {} is not repository-relative",
                    path.display()
                )));
            }
        }
    }
    if parts.is_empty() {
        return Err(ReachabilityEvidenceError::Invalid(
            "classified document path is empty".into(),
        ));
    }
    Ok(parts.join("/"))
}

fn normalize_entry_point_path(
    kind: &EntryPointKind,
    path: &Path,
) -> Result<String, ReachabilityEvidenceError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => parts.push(part.to_str().ok_or_else(|| {
                ReachabilityEvidenceError::Invalid(format!(
                    "entry-point path {} is not UTF-8",
                    path.display()
                ))
            })?),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ReachabilityEvidenceError::Invalid(format!(
                    "entry-point path {} is not repository-relative",
                    path.display()
                )));
            }
        }
    }
    if parts.is_empty() {
        if *kind == EntryPointKind::LibRoot && path.as_os_str().is_empty() {
            // A root-level Go library package is represented by the repository
            // directory itself. The empty relative path is canonical for that
            // directory root; executable/test entry points must still name a
            // concrete file.
            return Ok(String::new());
        }
        return Err(ReachabilityEvidenceError::Invalid(
            "entry-point path is empty".into(),
        ));
    }
    Ok(parts.join("/"))
}

// ---------------------------------------------------------------------------
// Report grouping helpers
// ---------------------------------------------------------------------------

impl ReachabilityReport {
    /// Group classified nodes by source file path (deterministic order).
    pub fn grouped_by_file(&self) -> BTreeMap<&str, Vec<&ClassifiedNode>> {
        let mut map: BTreeMap<&str, Vec<&ClassifiedNode>> = BTreeMap::new();
        for node in &self.classified {
            map.entry(node.file_path.as_str()).or_default().push(node);
        }
        map
    }

    /// Group classified nodes by action tier (deterministic order).
    pub fn grouped_by_action(&self) -> BTreeMap<ActionTier, Vec<&ClassifiedNode>> {
        let mut map: BTreeMap<ActionTier, Vec<&ClassifiedNode>> = BTreeMap::new();
        for node in &self.classified {
            map.entry(node.classification.action_tier())
                .or_default()
                .push(node);
        }
        map
    }

    /// Return only nodes matching a specific classification.
    pub fn nodes_with_class(&self, class: ReachabilityClass) -> Vec<&ClassifiedNode> {
        self.classified
            .iter()
            .filter(|n| n.classification == class)
            .collect()
    }

    /// Percentage of symbols in each classification (0.0 -- 100.0).
    ///
    /// Returns an empty map when `classified` is empty to avoid division by zero.
    pub fn class_percentages(&self) -> BTreeMap<ReachabilityClass, f64> {
        let total = self.classified.len();
        if total == 0 {
            return BTreeMap::new();
        }
        let mut counts: BTreeMap<ReachabilityClass, usize> = BTreeMap::new();
        for node in &self.classified {
            *counts.entry(node.classification).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(k, v)| (k, (v as f64 / total as f64) * 100.0))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Baseline save / load / diff
// ---------------------------------------------------------------------------

/// Serializable snapshot of reachability metrics for CI diffing.
///
/// Saved as JSON at `{data_dir}/wiring-baseline.json`. The diff key is
/// `(symbol_name, file_path, kind)` -- NOT UUID, so baselines survive
/// re-indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityBaseline {
    /// ISO 8601 timestamp when the baseline was captured.
    pub captured_at: String,
    /// Git commit hash (if available).
    pub git_commit: Option<String>,
    /// Summary metrics at capture time.
    pub summary: ReachabilitySummary,
    /// Dead symbol identifiers for diffing (sorted for stable comparison).
    /// Each entry is `"symbol_name\tfile_path\tkind"`.
    pub dead_symbols: Vec<String>,
    /// Orphan file paths at capture time.
    pub orphan_files: Vec<String>,
}

/// Diff between a current [`ReachabilityReport`] and a saved [`ReachabilityBaseline`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityDiff {
    /// Git commit of the baseline (if known).
    pub baseline_commit: Option<String>,
    /// Capture timestamp of the baseline.
    pub baseline_captured_at: String,
    /// Delta in dead symbol count (positive = regression).
    pub dead_delta: i64,
    /// Delta in orphan file count (positive = regression).
    pub orphan_delta: i64,
    /// Dead symbols in current report but not in baseline.
    pub new_dead: Vec<String>,
    /// Dead symbols in baseline that are now resolved.
    pub resolved_dead: Vec<String>,
    /// Orphan files in current report but not in baseline.
    pub new_orphans: Vec<String>,
    /// Orphan files in baseline that are now resolved.
    pub resolved_orphans: Vec<String>,
}

impl ReachabilityBaseline {
    /// Create a baseline snapshot from a report.
    ///
    /// `git_commit` is optional -- pass `None` when the repo is dirty or unknown.
    pub fn from_report(report: &ReachabilityReport, git_commit: Option<String>) -> Self {
        let mut dead_symbols: Vec<String> = report
            .classified
            .iter()
            .filter(|n| n.classification == ReachabilityClass::Dead)
            .map(|n| format!("{}\t{}\t{}", n.symbol_name, n.file_path, n.kind))
            .collect();
        dead_symbols.sort();

        let mut orphan_files = report.orphan_files.clone();
        orphan_files.sort();

        Self {
            captured_at: chrono::Utc::now().to_rfc3339(),
            git_commit,
            summary: report.summary.clone(),
            dead_symbols,
            orphan_files,
        }
    }

    /// Save baseline to a JSON file (human-readable, git-diff-friendly).
    ///
    /// Uses `std::fs` -- caller is responsible for wrapping in `spawn_blocking`
    /// when called from async context.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load baseline from a JSON file.
    ///
    /// Uses `std::fs` -- caller is responsible for wrapping in `spawn_blocking`
    /// when called from async context.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Diff the current report against this baseline.
    ///
    /// The diff key is `(symbol_name, file_path, kind)` encoded as a
    /// tab-separated string, so results survive re-indexing (UUIDs change).
    pub fn diff(&self, current: &ReachabilityReport) -> ReachabilityDiff {
        let baseline_set: HashSet<&str> = self.dead_symbols.iter().map(|s| s.as_str()).collect();

        let mut current_dead: Vec<String> = current
            .classified
            .iter()
            .filter(|n| n.classification == ReachabilityClass::Dead)
            .map(|n| format!("{}\t{}\t{}", n.symbol_name, n.file_path, n.kind))
            .collect();
        current_dead.sort();

        let current_set: HashSet<&str> = current_dead.iter().map(|s| s.as_str()).collect();

        let new_dead: Vec<String> = current_dead
            .iter()
            .filter(|s| !baseline_set.contains(s.as_str()))
            .cloned()
            .collect();

        let resolved_dead: Vec<String> = self
            .dead_symbols
            .iter()
            .filter(|s| !current_set.contains(s.as_str()))
            .cloned()
            .collect();

        let baseline_orphans: HashSet<&str> =
            self.orphan_files.iter().map(|s| s.as_str()).collect();
        let current_orphans: HashSet<&str> =
            current.orphan_files.iter().map(|s| s.as_str()).collect();

        let new_orphans: Vec<String> = current
            .orphan_files
            .iter()
            .filter(|s| !baseline_orphans.contains(s.as_str()))
            .cloned()
            .collect();

        let resolved_orphans: Vec<String> = self
            .orphan_files
            .iter()
            .filter(|s| !current_orphans.contains(s.as_str()))
            .cloned()
            .collect();

        ReachabilityDiff {
            baseline_commit: self.git_commit.clone(),
            baseline_captured_at: self.captured_at.clone(),
            dead_delta: current_dead.len() as i64 - self.dead_symbols.len() as i64,
            orphan_delta: current.orphan_files.len() as i64 - self.orphan_files.len() as i64,
            new_dead,
            resolved_dead,
            new_orphans,
            resolved_orphans,
        }
    }
}

impl ReachabilityDiff {
    /// Returns `true` if the diff represents a regression (more dead code or orphans).
    pub const fn is_regression(&self) -> bool {
        self.dead_delta > 0 || self.orphan_delta > 0
    }

    /// Returns `true` if the dead-code regression exceeds the given threshold.
    pub const fn exceeds_threshold(&self, max_dead_delta: i64) -> bool {
        self.dead_delta > max_dead_delta
    }
}

// ---------------------------------------------------------------------------
// Entry-symbol resolution helpers (WU-0003 / CL-REACH-05)
// ---------------------------------------------------------------------------

/// The single function symbol an executable entry point seeds.
///
/// Every Rust binary's entry is `fn main` (whether `src/main.rs`, `src/bin/*.rs`,
/// or a `[[bin]]` target), and Cargo build scripts enter through `fn main` too.
/// The target name is not the function name. CL-REACH-05: seed strictly this
/// symbol, never every top-level function in the file.
const fn executable_entry_symbol(_ep: &EntryPoint) -> &'static str {
    "main"
}

/// Short (last `::`-segment) name of a fully-qualified symbol, so a nested
/// `app::main` still matches the `main` entry symbol.
fn short_symbol_name(full: &str) -> &str {
    full.rsplit("::").next().unwrap_or(full)
}

/// ADR-0045 D3b — the std marker-trait allowlist: external/std traits that
/// genuinely define ZERO methods, so a compile-required-only `impl` of one on a
/// live type is `Structural` (not Dead). Keyed by the trait's SHORT name because
/// an external trait is a synthesized childless sentinel — "zero captured
/// children" cannot distinguish a real marker (`Eq`) from a method-bearing
/// external trait (`Display`/`From`/`Ord`) that was also synthesized childless.
/// Only these std marker traits are trustworthy on the sentinel; every other
/// external trait keeps its original tier (typically Wired). A FIRST-PARTY
/// no-method trait is handled by the reliable zero-children branch, not this list.
const STD_MARKER_TRAITS: &[&str] = &[
    "Eq",
    "Copy",
    "Send",
    "Sync",
    "Unpin",
    "Sized",
    "Unsize",
    "RefUnwindSafe",
    "UnwindSafe",
];

/// Returns `true` if a data member's owning field container is alive
/// (WU-0003 / CL-REACH-10).
///
/// Direct members normally carry a `Contains` edge, but enum-payload fields can
/// have an unmaterialized variant between the field and its type. Qualified-name
/// prefix resolution is a uniform fallback for both shapes: `Type::field` and
/// `Enum::Variant::N` progressively shorten until an alive field container is
/// found. Prefix anchoring cannot match an unrelated type that merely shares a
/// name fragment.
fn field_parent_type_is_alive(field_name: &str, alive_container_names: &HashSet<String>) -> bool {
    let mut prefix = field_name;
    while let Some(idx) = prefix.rfind("::") {
        prefix = &prefix[..idx];
        if alive_container_names.contains(prefix) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Test-module symbol detection
// ---------------------------------------------------------------------------

/// Returns `true` if the given node belongs to a test module (`tests::` or
/// `::tests::`) or IS a test module (kind `"module"` with short name `"tests"`).
///
/// Used by the production BFS pass to avoid traversing into `#[cfg(test)]`
/// children of production files.
///
/// `pub(crate)` so the ONE traversal core
/// ([`crate::graph_query::graph_walk`]) owns the symmetric `skip_test_modules`
/// prune off this single canonical predicate (WU-0003 / CL-REACH RC2) — the
/// walks cannot diverge on what counts as a test module.
pub(crate) fn is_test_module_symbol(graph: &KnowledgeGraph, node_id: &Uuid) -> bool {
    let Some(node) = graph.node(node_id) else {
        return false;
    };

    // WU-0003 / CL-REACH-06: prefer the PERSISTED `is_test_only` AST bit — a
    // node inside a `#[cfg(test)]` module carries `Some(true)`, so the prune
    // reads the AST fact rather than re-deriving it from the symbol name. The
    // name heuristic below is the fallback ONLY for SCIP/old nodes whose bit is
    // `None`, anchored on the `tests` module/`tests::` qualified-name convention.
    if let Some(bit) = node.is_test_only {
        return bit;
    }

    let name = &node.symbol_name;

    // Module named "tests" (inline test module)
    if node.kind == "module" {
        let short = name.rsplit("::").next().unwrap_or(name);
        if short == "tests" {
            return true;
        }
    }

    // Symbol inside a tests:: module
    name.starts_with("tests::") || name.contains("::tests::")
}

// ---------------------------------------------------------------------------
// BFS spec — the ONE parameterized walk (WU-0003 / CL-REACH RC2)
// ---------------------------------------------------------------------------

/// Which edge directions a walk follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfsDirection {
    /// Follow outgoing edges only (caller → callee, parent → child).
    Out,
    /// Follow incoming edges only (callee → caller, child → parent).
    In,
    /// Follow both directions (undirected within a connected component).
    Both,
}

/// The typed walk-shaping bundle that replaces the old `{Production, Test}`
/// `BfsMode` enum (WU-0003 / CL-REACH RC2).
///
/// Every reachability/connectivity walk derives its per-edge decision from a
/// `BfsSpec` so the walks cannot diverge on *which* edges they follow or *how*
/// they prune. The two prune flags apply SYMMETRICALLY across both edge
/// directions inside the one walk (closing CL-REACH-04's incoming/outgoing
/// asymmetry). Construct via the named presets below, never field-by-field at
/// the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BfsSpec {
    /// Which edge kinds are admitted (the ONE admission surface, RC1).
    pub edge_class: crate::graph_query::EdgeClass,
    /// Which edge directions to follow.
    pub direction: BfsDirection,
    /// Skip outgoing `HasImpl` edges (a WIRED trait does not auto-mark every
    /// implementor reachable). Applied symmetrically: also skips incoming
    /// `HasImpl` so the prune is direction-agnostic (RC2 / CL-REACH-04).
    pub skip_has_impl: bool,
    /// Skip `tests::` module symbols so production files don't pull their
    /// `#[cfg(test)]` children in via `Contains`.
    pub skip_test_modules: bool,
    /// Bridge trait↔impl across dispatch boundaries off the `Implements`/
    /// `HasImpl` EDGES (not symbol-name string parsing) (RC2 / CL-REACH-05).
    pub trait_bridge: bool,
    /// Whether `Contains` edges are followed. `false` realizes the historical
    /// `Dependency`-minus-`Contains` (6-kind) inline admit-set as a
    /// walk-shaping option, NOT a third `EdgeClass` (ADR-0028 baked decision).
    pub include_contains: bool,
}

impl BfsSpec {
    /// WU-0015 / ADR-0036 v6 — the DIRECTED call-reachability verdict walk.
    /// `EdgeClass::Call` (admits `{Calls, References, TypeOf, FieldOf, Extends}`,
    /// drops `Contains` + `DependsOn`), `Forward` (from roots, OUTGOING only,
    /// following use-edges), `include_contains: false`. Containment is NOT use —
    /// a module owning a symbol, or a type owning a method, does not USE it — so
    /// the old undirected-`Contains` sibling pollution (a reached child flowing
    /// backward to its module then forward to every sibling → `recall ≈ 0`)
    /// cannot occur. Reachability is now "a use-chain from a root reaches this
    /// symbol." `Implements`/`HasImpl` are consumed STRUCTURALLY by the guard
    /// post-passes, not walked here.
    pub const fn classifier_calls() -> Self {
        Self {
            edge_class: crate::graph_query::EdgeClass::Call,
            direction: BfsDirection::Out,
            skip_has_impl: true,
            skip_test_modules: true,
            trait_bridge: false,
            include_contains: false,
        }
    }

    /// Reachability tracing must use the exact same traversal contract as the
    /// persisted liveness verdict; a trace is explanatory evidence, not a
    /// second classifier with subtly different pruning.
    pub const fn reachability_trace() -> Self {
        Self::classifier_calls()
    }

    /// Relevance-expansion / forward structural reachability: `Structural`
    /// edges, OUTGOING only, no prune. Drives [`crate::graph::KnowledgeGraph::reachable`]
    /// (the depth-limited relevance walk) — same admission as the classifier so
    /// the two cannot diverge on which kinds they follow (RC2). Wires
    /// [`BfsDirection::Out`].
    pub const fn reachable_out() -> Self {
        Self {
            edge_class: crate::graph_query::EdgeClass::Structural,
            direction: BfsDirection::Out,
            skip_has_impl: false,
            skip_test_modules: false,
            trait_bridge: false,
            include_contains: true,
        }
    }

    /// Reverse structural reach used by the test-chain tracer
    /// (`build_test_chains`): `Structural` edges, INCOMING only, no prune.
    /// Matches the historical `is_traversable_edge` admission the reverse test
    /// walk used. Wires [`BfsDirection::In`].
    pub const fn structural_reverse() -> Self {
        Self {
            edge_class: crate::graph_query::EdgeClass::Structural,
            direction: BfsDirection::In,
            skip_has_impl: false,
            skip_test_modules: false,
            trait_bridge: false,
            include_contains: true,
        }
    }

    /// Reverse dependents preset: `Dependency` edges (7-kind), INCOMING only,
    /// edge-driven trait bridging on. Drives `reverse_bfs`, the CLI `impact`
    /// walk, and the `blast-radius` walk — they cannot diverge on admission or
    /// on which trait↔impl edges they bridge (RC2 / CL-REACH-05). Wires
    /// [`BfsDirection::In`] + `trait_bridge`.
    pub const fn dependents() -> Self {
        Self {
            edge_class: crate::graph_query::EdgeClass::Dependency,
            direction: BfsDirection::In,
            skip_has_impl: false,
            skip_test_modules: false,
            trait_bridge: true,
            include_contains: true,
        }
    }

    /// Test-caller preset: `Dependency` edges (7-kind, incl. `Contains`),
    /// INCOMING only, no prune, **no trait bridge**. Drives `find_test_callers`
    /// — the reverse transitive walk over the historical `is_dependency_edge`
    /// admission that collects `#[test]`/`tests::` functions reaching a symbol
    /// (RC2 / WU-0003 finish-collapse). Distinct from [`BfsSpec::dependents`]:
    /// it does NOT bridge trait↔impl (the legacy walk never did), and it does
    /// NOT skip test modules (it is *looking for* test functions). Wires
    /// [`BfsDirection::In`].
    pub const fn test_callers() -> Self {
        Self {
            edge_class: crate::graph_query::EdgeClass::Dependency,
            direction: BfsDirection::In,
            skip_has_impl: false,
            skip_test_modules: false,
            trait_bridge: false,
            include_contains: true,
        }
    }

    /// Whether this spec follows outgoing edges (`Out` or `Both`).
    pub const fn follows_out(&self) -> bool {
        matches!(self.direction, BfsDirection::Out | BfsDirection::Both)
    }

    /// Whether this spec follows incoming edges (`In` or `Both`).
    pub const fn follows_in(&self) -> bool {
        matches!(self.direction, BfsDirection::In | BfsDirection::Both)
    }

    /// Returns whether an edge of `kind` is followed in the given physical
    /// direction under this spec. The SINGLE per-edge decision shared by all
    /// `BfsSpec`-driven walks: routes through the RC1 `admits` surface, then
    /// applies the symmetric `HasImpl`/`Contains` prune.
    pub fn admits_edge(&self, kind: EdgeKind, _outgoing: bool) -> bool {
        if !crate::graph_query::admits(self.edge_class, kind) {
            return false;
        }
        // Symmetric HasImpl prune (RC2 / CL-REACH-04): historically only the
        // outgoing direction was pruned, leaving an incoming-`HasImpl`
        // asymmetry. The prune now applies regardless of direction.
        if self.skip_has_impl && kind == EdgeKind::HasImpl {
            return false;
        }
        if !self.include_contains && kind == EdgeKind::Contains {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// ReachabilityAnalyzer
// ---------------------------------------------------------------------------

/// The default configurable fixture-directory exclusion list (ADR-0045 D2).
///
/// A node whose file path contains any of these as an exact PATH SEGMENT is
/// analysis INPUT (fixture corpus the extractor consumes), not code-under-analysis
/// → [`ReachabilityClass::Excluded`]. `testdata` is Go-normative (the `go` tool
/// itself ignores it — already honored in `entry_points`); the rest cover the
/// common cross-language fixture / vendored-dependency conventions Rust has no
/// single equivalent for. Carried as a VALUE on [`CensusScope`] (so a target can
/// tune it), not a hardcoded predicate. No CLI/config surface wires an override
/// yet — deferred as disproportionate for this build (ADR-0045 discoveries).
pub const DEFAULT_EXCLUDED_DIRS: &[&str] = &["testdata", "vendor", "third_party", "node_modules"];

#[cfg(test)]
thread_local! {
    /// Exact number of census-scope evaluations performed by one test thread.
    /// Production builds carry no counter or branch.
    static CENSUS_SCOPE_EVALUATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_census_scope_evaluations() {
    CENSUS_SCOPE_EVALUATIONS.with(|count| count.set(0));
}

#[cfg(test)]
fn census_scope_evaluations() -> usize {
    CENSUS_SCOPE_EVALUATIONS.with(std::cell::Cell::get)
}

/// The census-scope inputs threaded into classification (ADR-0045 D1 + D2).
///
/// Decides which nodes fall OUT of the 5-tier production-reachability census into
/// [`ReachabilityClass::Excluded`]. Built from the workspace at INDEX time via
/// [`CensusScope::for_workspace`] (FS-coupled — it resolves real paths);
/// [`CensusScope::unscoped`] disables BOTH D1 and D2 and is the default for
/// synthetic-graph tests and any caller without a real workspace on disk (exclude
/// nothing). `analyze()` uses `unscoped`; the production `analyze_with_orphans`
/// path builds a real scope.
#[derive(Debug, Clone, Default)]
pub struct CensusScope {
    /// Canonicalized workspace root — resolves workspace-relative node paths to
    /// real filesystem paths for the D1 real-file check. `None` disables D1.
    root: Option<std::path::PathBuf>,
    /// Canonicalized member-crate directories of the root build unit. A node whose
    /// REAL file resolves under `root` but under NONE of these → D1 Excluded.
    /// `None` disables D1 (no Cargo workspace context / synthetic test).
    members: Option<Vec<std::path::PathBuf>>,
    /// D2 excluded-dir path SEGMENTS (exact-segment match, not substring). Empty
    /// disables D2.
    excluded_dirs: Vec<String>,
}

impl CensusScope {
    /// The no-op scope: exclude nothing (D1 + D2 both disabled). Used by
    /// [`ReachabilityAnalyzer::analyze`] and every synthetic-graph test — a
    /// synthetic node's fake path must never be swept into `Excluded`.
    pub fn unscoped() -> Self {
        Self::default()
    }

    /// Build the real census scope for a workspace on disk (ADR-0045).
    ///
    /// D1: the member-crate set comes from
    /// [`resolve_census_members`](crate::entry_points::resolve_census_members)
    /// (`None` on a Go-only / no-`Cargo.toml` repo → D1 disabled). D2: the default
    /// [`DEFAULT_EXCLUDED_DIRS`] list. `root` is canonicalized so D1's `starts_with`
    /// tests compare canonical-to-canonical.
    pub fn for_workspace(workspace_root: &Path) -> Self {
        Self {
            root: workspace_root.canonicalize().ok(),
            members: crate::entry_points::resolve_census_members(workspace_root),
            excluded_dirs: DEFAULT_EXCLUDED_DIRS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }

    /// Test/tuning constructor: an explicit scope. `root`/`members` enable D1
    /// (both canonicalized by the caller for a real-FS fixture); `excluded_dirs`
    /// drives D2.
    pub const fn with_parts(
        root: Option<std::path::PathBuf>,
        members: Option<Vec<std::path::PathBuf>>,
        excluded_dirs: Vec<String>,
    ) -> Self {
        Self {
            root,
            members,
            excluded_dirs,
        }
    }

    /// D2: does the file path contain an excluded-dir EXACT PATH SEGMENT?
    /// `src/testdata_loader.rs` (substring, not a segment) is NOT matched; only a
    /// `/testdata/` path component is.
    fn d2_excluded(&self, file_path: &str) -> bool {
        if self.excluded_dirs.is_empty() {
            return false;
        }
        std::path::Path::new(file_path).components().any(|c| {
            matches!(c, std::path::Component::Normal(seg)
                if seg.to_str().is_some_and(|s| self.excluded_dirs.iter().any(|d| d == s)))
        })
    }

    /// D1: does the file resolve to a REAL filesystem path under `root` but under
    /// NO member crate? A path that fails to canonicalize (a synthesized sentinel
    /// such as `<external-trait>`, or any SCIP-only non-file node) returns `false`
    /// — the load-bearing SENTINEL EXEMPTION: D1 fires ONLY on a path that actually
    /// resolves under a detached/nested crate dir. A path resolving OUTSIDE the
    /// workspace subtree (e.g. an external dependency file) is not D1's business.
    fn d1_excluded(&self, file_path: &str) -> bool {
        let (Some(root), Some(members)) = (&self.root, &self.members) else {
            return false;
        };
        let Ok(canon) = root.join(file_path).canonicalize() else {
            return false;
        };
        if !canon.starts_with(root) {
            return false;
        }
        !members.iter().any(|m| canon.starts_with(m))
    }

    /// Whether this node's file is OUT of the census (D2 fixture corpus OR D1
    /// detached/nested crate). D2 is checked first (no FS access).
    fn is_excluded(&self, file_path: &str) -> bool {
        #[cfg(test)]
        CENSUS_SCOPE_EVALUATIONS.with(|count| count.set(count.get().saturating_add(1)));
        self.d2_excluded(file_path) || self.d1_excluded(file_path)
    }
}

/// Performs reachability analysis on a `KnowledgeGraph`.
///
/// This is a standalone struct that borrows the graph immutably.
/// It does NOT mutate the graph.
pub struct ReachabilityAnalyzer<'g> {
    graph: &'g KnowledgeGraph,
    entry_points: Vec<EntryPoint>,
    /// `None` retains the legacy all-registered-documents analysis API used by
    /// synthetic controls. Production evidence supplies the exact document
    /// population owned by registered reachability classifiers.
    classified_documents: Option<BTreeSet<String>>,
}

/// Structural roots resolved independently from any persisted reachability
/// verdict or call-edge population.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReachabilityRootSets {
    pub production: Vec<Uuid>,
    pub public_api: Vec<Uuid>,
    pub tests: Vec<Uuid>,
}

impl<'g> ReachabilityAnalyzer<'g> {
    /// Create a new analyzer.
    pub const fn new(graph: &'g KnowledgeGraph, entry_points: Vec<EntryPoint>) -> Self {
        Self {
            graph,
            entry_points,
            classified_documents: None,
        }
    }

    /// Bind classification and every reachability traversal to one exact
    /// generation-local document population. Registered source outside this
    /// set remains explicit structural truth but cannot seed, bridge, or receive
    /// a reachability verdict. Synthetic graph nodes without a registered source
    /// extension remain eligible because they are derived from covered source.
    #[must_use]
    pub fn for_classified_documents(
        graph: &'g KnowledgeGraph,
        entry_points: Vec<EntryPoint>,
        classified_documents: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            graph,
            entry_points,
            classified_documents: Some(classified_documents.into_iter().collect()),
        }
    }

    fn classifies_node(&self, node: &crate::graph::GraphNode) -> bool {
        self.classified_documents.as_ref().is_none_or(|documents| {
            crate::graph_stats::node_language(node).is_none()
                || documents.contains(node.file_path.as_str())
        })
    }

    fn classifies_node_id(&self, node_id: &Uuid) -> bool {
        self.graph
            .node(node_id)
            .is_some_and(|node| self.classifies_node(node))
    }

    /// Resolve the roots used by the classifier without running its graph
    /// traversal or consulting any per-node reachability label. Derived use
    /// cases can therefore share entry-point/public/test semantics while using
    /// a different authoritative relationship population.
    #[must_use]
    pub fn resolved_roots(&self) -> ReachabilityRootSets {
        let all_nodes = self
            .graph
            .all_nodes()
            .into_iter()
            .filter(|node| self.classifies_node(node))
            .collect::<Vec<_>>();
        let mut file_to_nodes: HashMap<&str, Vec<Uuid>> = HashMap::new();
        for node in &all_nodes {
            file_to_nodes
                .entry(node.file_path.as_str())
                .or_default()
                .push(node.memory_id);
        }

        let mut production = self.resolve_production_roots(&file_to_nodes);
        production.extend(self.resolve_entry_file_roots(&file_to_nodes, &[EntryPointKind::Bench]));
        production.extend(self.resolve_entry_attr_roots(&all_nodes));

        let mut tests = self.resolve_test_roots(&all_nodes);
        tests.extend(self.resolve_entry_file_roots(
            &file_to_nodes,
            &[EntryPointKind::IntegrationTest, EntryPointKind::Example],
        ));

        let mut public_api = self.resolve_pub_api_roots(&all_nodes);
        for roots in [&mut production, &mut public_api, &mut tests] {
            roots.sort_unstable();
            roots.dedup();
        }
        ReachabilityRootSets {
            production,
            public_api,
            tests,
        }
    }

    /// WU-0015 / ADR-0036 V4-3 — real-use in-degree of a node.
    ///
    /// Counts INCOMING edges filtered to `{Calls, References}` ONLY —
    /// deliberately EXCLUDING `Contains`/`HasImpl`/`TypeOf`/`FieldOf`: a raw
    /// incoming count would re-admit the original `Contains`-as-caller pollution
    /// (a parent module "using" its child), re-creating the recall bug through
    /// the in-degree signal. `> 0` means "some symbol genuinely calls or
    /// references this," the V3-1 seed-vs-classify split's clean-PublicApi
    /// signal for a pub root.
    fn use_in_degree(&self, node_id: Uuid) -> usize {
        self.graph
            .incoming_neighbors(&node_id)
            .iter()
            .filter(|(src, edge)| {
                self.classifies_node_id(src)
                    && matches!(edge.kind, EdgeKind::Calls | EdgeKind::References)
            })
            .count()
    }

    /// WU-0015 / ADR-0036 V2-3/V3-4/V3-5 — the structural trait-dispatch guard.
    ///
    /// Given a residual (call-unreachable) FUNCTION node, decide whether it is a
    /// trait/impl method legitimately reachable through a dispatch path the call
    /// graph cannot see, and if so return the tier to rescue it to. Consults the
    /// `Contains`/`Implements` edges STRUCTURALLY (never symbol-name prefixing,
    /// V3-5) and is `#[async_trait]`-desugar tolerant: it keys off the enclosing
    /// impl's type/trait NODE being reached, NOT the SCIP trait-method symbol.
    ///
    /// Returns `Some(tier)` when the method's parent is (V3-4) a reached trait
    /// DEFINITION node, or (guard a/b) an impl block whose trait node OR concrete
    /// type node is reached. Otherwise `None` (stays residual → `Suspected`).
    /// Rescues to the REACHED tier (never a delete-eligible tier) so the guard is
    /// non-vacuous: disabling it drops the method to `Suspected`.
    ///
    /// # The test-ness cap (Wave 2 — blind-spot #2)
    ///
    /// Every rescue tier is CAPPED at [`ReachabilityClass::TestOnly`] when the
    /// method ITSELF, or the enclosing parent it is rescued through (its `impl`
    /// block, its trait, or — for Go — its receiver type), is test-only:
    /// `is_test = self_is_test || parent_is_test`. WHY this cannot be read
    /// off the code below: the arms take the tier of the *reached trait/type* as
    /// DISPATCH EVIDENCE — "something calls this trait dynamically, so an
    /// implementor's method is live" — and that evidence belongs to the REAL
    /// production implementors. A test double implementing the same production
    /// trait FREE-RIDES on it: the guard consults the trait's tier and never the
    /// implementor's own test-ness, so a `#[cfg(test)]` mock inherits Wired
    /// despite being unreachable from production BY CONSTRUCTION. That is a
    /// false-WIRED — the worst direction, since it tells a consumer dead code is
    /// live with no review flag.
    ///
    /// MEASURED mechanism proof (2026-07-16 dogfood, 47 nodes across 9 test
    /// doubles): `tests::MockContextProvider`'s five INHERENT methods classify
    /// TestOnly correctly, while its single TRAIT method `surface` classifies
    /// Wired — same struct, same file, same test module. The only difference is
    /// that the trait method reaches this guard. Every one of the 47 is a
    /// trait-impl member; not one is inherent. The cap binds at EVERY return
    /// path, not just arm (a) — a mock rescued via the trait arm, via arm (b)
    /// (a test-only `impl` on a reached struct), or via the Go receiver-type arm
    /// free-rides identically. Each return path carries its own falsifier
    /// (F1a/F1b/F3a/F3b, and G1/G2 for the two Go returns), plus the
    /// production-side negative controls that pin the cap to test-ness rather
    /// than to "is a rescued method" (F2, G3).
    ///
    /// The cap only ever moves a tier toward LESS-alive (`Wired`/`PublicApi` →
    /// `TestOnly`); a production implementor's rescue is untouched, so the guard
    /// keeps rescuing the handlers that legitimately dispatch today.
    fn guard_rescue_tier(
        &self,
        node_id: Uuid,
        class_by_id: &HashMap<Uuid, ReachabilityClass>,
    ) -> Option<ReachabilityClass> {
        let reached_tier = |id: &Uuid| -> Option<ReachabilityClass> {
            match class_by_id.get(id) {
                Some(ReachabilityClass::Wired) => Some(ReachabilityClass::Wired),
                Some(ReachabilityClass::TestOnly) => Some(ReachabilityClass::TestOnly),
                Some(ReachabilityClass::PublicApi | ReachabilityClass::Structural) => {
                    Some(ReachabilityClass::PublicApi)
                }
                _ => None,
            }
        };

        // The test-ness cap. NOTE the `ReachabilityClass` Ord is LOWER-ordinal ==
        // MORE-alive (`Wired(0) < PublicApi(1) < Structural(2) < TestOnly(3) <
        // Dead(4) < …`), so `t < TestOnly` selects the tiers that are MORE alive
        // than TestOnly and clamps them DOWN to it. A tier already at or below
        // TestOnly's aliveness is returned unchanged — the cap never promotes.
        let cap = |t: ReachabilityClass, is_test: bool| -> ReachabilityClass {
            if is_test && t < ReachabilityClass::TestOnly {
                ReachabilityClass::TestOnly
            } else {
                t
            }
        };
        // The method's own test-ness, computed once (it is parent-independent).
        let self_is_test = is_test_module_symbol(self.graph, &node_id);

        // Parents via INCOMING `Contains` edges (parent → child).
        for (parent_id, edge) in self.graph.incoming_neighbors(&node_id) {
            if edge.kind != EdgeKind::Contains {
                continue;
            }
            let Some(parent) = self.graph.node(&parent_id) else {
                continue;
            };
            // The enclosing trait/impl/receiver-type's own test-ness. An `impl`
            // block inside `#[cfg(test)] mod tests` marks its members test-only
            // even when a member's own bit is absent (SCIP/old nodes).
            let parent_is_test = is_test_module_symbol(self.graph, &parent_id);
            let is_test = self_is_test || parent_is_test;
            match parent.kind.as_str() {
                // V3-4: trait-DEFINITION default method (parent is a trait node).
                "trait" => {
                    if let Some(t) = reached_tier(&parent_id) {
                        return Some(cap(t, is_test));
                    }
                }
                // guard a/b: a method inside an impl block. Rescue when the impl's
                // trait node (outgoing `Implements`) OR concrete type node
                // (incoming `Contains` from a struct/enum) is reached.
                "impl" => {
                    for (tgt, e) in self.graph.neighbors(&parent_id) {
                        if e.kind == EdgeKind::Implements
                            && let Some(t) = reached_tier(&tgt)
                        {
                            return Some(cap(t, is_test));
                        }
                    }
                    for (src, e) in self.graph.incoming_neighbors(&parent_id) {
                        if e.kind == EdgeKind::Contains
                            && let Some(n) = self.graph.node(&src)
                            && symbol_kind_has_role(&n.kind, SymbolRole::ConcreteType)
                            && let Some(t) = reached_tier(&src)
                        {
                            return Some(cap(t, is_test));
                        }
                    }
                }
                // WU-0023 P3b Bundle-3 (DEC-IFACE): a Go method's incoming-Contains
                // parent is its RECEIVER TYPE (kind "struct"/"enum"), never an
                // `impl` block — Go has no impl blocks; `edge_builder` links the
                // method straight to its receiver type (same-file Phase 2, or the
                // package-dir cross-file linker). Mirror the impl-arm's conservative
                // report-only policy: rescue the method to the reached tier when the
                // receiver type is itself reached OR implements a reached interface
                // ("trait") via an outgoing `Implements` edge. This favors
                // false-CLEAN over false-DEAD (the accepted P3b direction). A Rust
                // method NEVER has a struct/enum Contains-parent (Rust methods sit
                // in an `impl` block), so this arm cannot fire for a Rust-only store
                // — the RUST NO-REGRESSION byte-identity holds by construction.
                "struct" | "enum" => {
                    if let Some(t) = reached_tier(&parent_id) {
                        return Some(cap(t, is_test));
                    }
                    for (tgt, e) in self.graph.neighbors(&parent_id) {
                        if e.kind == EdgeKind::Implements
                            && let Some(t) = reached_tier(&tgt)
                        {
                            return Some(cap(t, is_test));
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// WU-0015 / ADR-0036 V3-1 — the pub seed-vs-classify split predicate.
    ///
    /// A pub item is always SEEDED as a PublicApi root (so it anchors its
    /// callees' reachability), but classifies `PublicApi`-clean only if it has a
    /// REAL caller: `use_in_degree > 0` (≥1 incoming `Calls`/`References`), OR it
    /// is reached from a caller root via any admitted use-edge (`Calls`/
    /// `References`/`TypeOf`/`FieldOf`/`Extends`) whose SOURCE is itself
    /// reachable. `Contains` is excluded (V4-3 — a raw in-degree would re-admit
    /// the containment pollution). A pub root failing this → `Suspected` (the
    /// external-API-vs-wiring-gap review surface, e.g. `set_generation_metadata_sync`).
    fn pub_root_has_real_caller(&self, node_id: Uuid, reachable_union: &HashSet<Uuid>) -> bool {
        if self.use_in_degree(node_id) > 0 {
            return true;
        }
        self.graph
            .incoming_neighbors(&node_id)
            .iter()
            .any(|(src, edge)| {
                *src != node_id
                    && matches!(
                        edge.kind,
                        EdgeKind::Calls
                            | EdgeKind::References
                            | EdgeKind::TypeOf
                            | EdgeKind::FieldOf
                            | EdgeKind::Extends
                    )
                    && reachable_union.contains(src)
            })
    }

    /// ADR-0045 D3a — is this Dead trait-DEFINITION method compile-required
    /// (→ `Structural`)?
    ///
    /// A `function` node whose parent (incoming `Contains`) is a `trait` node T is
    /// `Structural` IFF it is **abstract (no default body)** with ≥1 non-Dead
    /// implementor of T, OR **≥1 non-Dead implementor OVERRIDES it** (a same-named
    /// non-Dead method inside an impl of T). Else it stays Dead:
    /// - a trait with ZERO implementors (`ConstraintChecker`, DEC-082 — **the
    ///   canary**) finds no impl → returns `false`;
    /// - a **defaulted-never-overridden-uncalled** method (has a body, no impl
    ///   overrides it) is genuinely removable → `false`.
    ///
    /// "Non-Dead implementor" is judged on the impl's own child method nodes'
    /// current class (alive == `Wired`/`PublicApi`/`Structural`/`TestOnly`): an
    /// abstract method's implementor necessarily provides a (typically WIRED) child
    /// method; a defaulted method is "overridden" only when the impl provides its
    /// own same-named non-Dead method. Structural is the accurate PER-NODE verdict —
    /// you cannot remove one trait method without breaking the wired impl; the
    /// coarser whole-abstraction-removable signal is a distinct future concern
    /// (ADR-0045 D3 flip-condition).
    fn d3a_trait_method_is_structural(
        &self,
        method_id: Uuid,
        method_abstract: bool,
        method_short: &str,
        class_by_id: &HashMap<Uuid, ReachabilityClass>,
    ) -> bool {
        let is_alive = |id: &Uuid| -> bool {
            matches!(
                class_by_id.get(id),
                Some(
                    ReachabilityClass::Wired
                        | ReachabilityClass::PublicApi
                        | ReachabilityClass::Structural
                        | ReachabilityClass::TestOnly
                )
            )
        };

        // Parent trait DEFINITION node: incoming `Contains` from a `trait`.
        let mut trait_id: Option<Uuid> = None;
        for (parent_id, edge) in self.graph.incoming_neighbors(&method_id) {
            if edge.kind == EdgeKind::Contains
                && self
                    .graph
                    .node(&parent_id)
                    .is_some_and(|p| p.kind == "trait")
            {
                trait_id = Some(parent_id);
                break;
            }
        }
        let Some(trait_id) = trait_id else {
            return false;
        };

        // Implementors of T: incoming `Implements` edges (impl --Implements--> T).
        let mut any_alive_impl = false;
        for (impl_id, e) in self.graph.incoming_neighbors(&trait_id) {
            if e.kind != EdgeKind::Implements {
                continue;
            }
            let mut impl_has_alive_child = false;
            let mut overrides_alive = false;
            for (child_id, ce) in self.graph.neighbors(&impl_id) {
                if ce.kind != EdgeKind::Contains {
                    continue;
                }
                let Some(child) = self.graph.node(&child_id) else {
                    continue;
                };
                if !symbol_kind_has_role(&child.kind, SymbolRole::Callable) || !is_alive(&child_id)
                {
                    continue;
                }
                impl_has_alive_child = true;
                if short_symbol_name(&child.symbol_name) == method_short {
                    overrides_alive = true;
                }
            }
            // A live implementor explicitly overriding this method → Structural
            // (covers both an overridden defaulted method AND an abstract method
            // whose implementor's override node is present).
            if overrides_alive {
                return true;
            }
            if impl_has_alive_child {
                any_alive_impl = true;
            }
        }
        // Abstract-with-a-live-implementor: every implementor MUST provide the
        // method, so the abstract signature is compile-required by that live impl
        // even if the extractor did not capture the override method node.
        method_abstract && any_alive_impl
    }

    /// ADR-0045 D3b — is this Dead impl block a compile-required MARKER impl
    /// (→ `Structural`)?
    ///
    /// An `impl` node is `Structural` IFF **the trait it implements is a TRUE
    /// marker (genuinely zero method items)** AND its **Self type is non-Dead**.
    ///
    /// "True marker" is decided by the trait node's provenance, NOT by a naive
    /// "the captured trait node has zero `function` children" test — that test is
    /// a lie for EXTERNAL/synthesized trait anchors (D3b remediation, 2026-07-18):
    /// `edge_builder::synthesize_external_trait_node` mints a childless sentinel for
    /// EVERY external trait, so `Display`/`From`/`Ord`/`Default`/`Debug` (which DO
    /// have methods — `fmt`/`from`/`cmp`/`default`) look identical to `Eq`/`Copy`
    /// (which genuinely have none). Keying on "zero captured children" there
    /// mislabels ~79 genuinely-Wired external-trait impls `Structural`, silently
    /// destroying their "actively used" signal. So:
    /// - a **synthesized external trait** (`file_path == EXTERNAL_TRAIT_SENTINEL`)
    ///   is a marker ONLY when its name is in the hardcoded [`STD_MARKER_TRAITS`]
    ///   allowlist (the std marker traits that truly have zero methods);
    /// - a **first-party trait** (real file path) is a marker when it has zero
    ///   `function` `Contains`-children — reliable there because we actually
    ///   captured its method items.
    ///
    /// This mirrors the sentinel-exemption discipline D1 already applies (a
    /// synthesized anchor is not a real source fact). Keyed on the trait's marker
    /// nature, NOT "the impl body is empty" — an empty `impl DefaultedTrait for T {}`
    /// still exposes callable defaulted methods and must not be Structural-ized. The
    /// `Self non-Dead` conjunct keeps a marker impl on a genuinely-dead type Dead.
    fn d3b_marker_impl_is_structural(
        &self,
        impl_id: Uuid,
        class_by_id: &HashMap<Uuid, ReachabilityClass>,
    ) -> bool {
        // The implemented trait: outgoing `Implements` (impl --Implements--> T).
        // An inherent impl (no trait) has none → not a marker impl.
        let mut trait_id: Option<Uuid> = None;
        for (tgt, e) in self.graph.neighbors(&impl_id) {
            if e.kind == EdgeKind::Implements {
                trait_id = Some(tgt);
                break;
            }
        }
        let Some(trait_id) = trait_id else {
            return false;
        };
        let Some(trait_node) = self.graph.node(&trait_id) else {
            return false;
        };

        // Is the implemented trait a TRUE marker (genuinely zero methods)?
        let trait_is_marker =
            if trait_node.file_path == crate::edge_builder::EXTERNAL_TRAIT_SENTINEL {
                // Synthesized external/std anchor: it has NO captured children
                // regardless of whether it really has methods, so "zero children"
                // is unreliable. Only the hardcoded allowlist is trustworthy —
                // `Display`/`From`/`Ord`/`Default`/`Debug` are external but have
                // methods and must NOT be treated as markers.
                STD_MARKER_TRAITS.contains(&short_symbol_name(&trait_node.symbol_name))
            } else {
                // First-party trait with a real source file: we captured its method
                // items, so "zero `function` `Contains`-children" reliably means a
                // genuine no-method marker trait.
                !self
                    .graph
                    .neighbors(&trait_id)
                    .into_iter()
                    .any(|(child, e)| {
                        e.kind == EdgeKind::Contains
                            && self.graph.node(&child).is_some_and(|node| {
                                symbol_kind_has_role(&node.kind, SymbolRole::Callable)
                            })
                    })
            };
        if !trait_is_marker {
            return false;
        }

        // Self type (the struct/enum that `Contains` this impl) must be non-Dead.
        self.graph
            .incoming_neighbors(&impl_id)
            .into_iter()
            .any(|(src, e)| {
                e.kind == EdgeKind::Contains
                    && self.graph.node(&src).is_some_and(|node| {
                        symbol_kind_has_role(&node.kind, SymbolRole::ConcreteType)
                    })
                    && matches!(
                        class_by_id.get(&src),
                        Some(
                            ReachabilityClass::Wired
                                | ReachabilityClass::PublicApi
                                | ReachabilityClass::Structural
                                | ReachabilityClass::TestOnly
                        )
                    )
            })
    }

    /// Run the full reachability analysis with NO census scoping (ADR-0045).
    ///
    /// Performs three BFS passes (production, public API, test), then marks
    /// the remainder as dead. Returns a complete report. Excludes nothing — every
    /// node is in the census. Synthetic-graph tests and callers without a real
    /// workspace on disk use this; the production path uses
    /// [`Self::analyze_with_orphans`], which builds a real [`CensusScope`].
    pub fn analyze(&self) -> ReachabilityReport {
        self.analyze_scoped(&CensusScope::unscoped())
    }

    /// Run the full reachability analysis under a census scope (ADR-0045).
    ///
    /// Identical to [`Self::analyze`] plus the D1/D2 `Excluded` sweep: after every
    /// verdict/rescue/roll-up pass, any node whose file is OUT of the census
    /// (`scope.is_excluded`) is set to [`ReachabilityClass::Excluded`], overriding
    /// its computed tier. The sweep runs LAST (before the final summary recompute)
    /// so it can never perturb the reachability of the in-census population — the
    /// non-excluded classification is byte-identical to `analyze` with an unscoped
    /// scope.
    pub fn analyze_scoped(&self, scope: &CensusScope) -> ReachabilityReport {
        self.analyze_scoped_internal(scope, true)
    }

    fn analyze_scoped_for_persistence(&self, scope: &CensusScope) -> ReachabilityReport {
        self.analyze_scoped_internal(scope, false)
    }

    fn analyze_scoped_internal(
        &self,
        scope: &CensusScope,
        include_test_chains: bool,
    ) -> ReachabilityReport {
        let all_nodes = self.graph.all_nodes();
        let reachability_nodes = all_nodes
            .iter()
            .copied()
            .filter(|node| self.classifies_node(node))
            .collect::<Vec<_>>();

        // Build a map from file_path suffix to node UUIDs for entry point matching.
        let mut file_to_nodes: HashMap<&str, Vec<Uuid>> = HashMap::new();
        for node in &reachability_nodes {
            file_to_nodes
                .entry(node.file_path.as_str())
                .or_default()
                .push(node.memory_id);
        }

        // --- Resolve entry point roots ---
        let production_roots = self.resolve_production_roots(&file_to_nodes);
        let pub_api_roots = self.resolve_pub_api_roots(&reachability_nodes);
        let test_roots = self.resolve_test_roots(&reachability_nodes);
        // CL-REACH-04: convention entry-point FILES (tests/, benches/, examples/)
        // resolve to every graph node in those files. Benches are prod-adjacent
        // (seeded into the production pass); integration-test + example files are
        // test-adjacent and seeded into the test traversal.
        let bench_file_roots =
            self.resolve_entry_file_roots(&file_to_nodes, &[EntryPointKind::Bench]);
        let test_file_roots = self.resolve_entry_file_roots(
            &file_to_nodes,
            &[EntryPointKind::IntegrationTest, EntryPointKind::Example],
        );
        // WU-0015 Leg J: ABI/linker entry-point retain roots (`#[no_mangle]` /
        // `#[export_name]` / `#[used]`) — production roots the compiler-visible
        // call graph cannot reach. Seeded into the production pass so a private
        // `#[no_mangle] fn` or a `#[used]` static classifies Wired, not Dead.
        let entry_attr_roots = self.resolve_entry_attr_roots(&reachability_nodes);

        tracing::debug!(
            production_roots = production_roots.len(),
            pub_api_roots = pub_api_roots.len(),
            test_roots = test_roots.len(),
            bench_file_roots = bench_file_roots.len(),
            test_file_roots = test_file_roots.len(),
            entry_attr_roots = entry_attr_roots.len(),
            "resolved entry point roots"
        );

        // WU-0015 / ADR-0036 v6: all three verdict passes use the DIRECTED
        // call-reachability walk (`classifier_calls` — Forward, `EdgeClass::Call`,
        // no `Contains`/`DependsOn`). Reachability now means "a use-chain from a
        // root reaches this symbol"; the old undirected-`Contains` sibling
        // pollution (recall ≈ 0) is gone.

        // --- Pass 1: Production BFS ---
        // Benches are prod-adjacent (CL-REACH-04), so their entry files seed the
        // production pass — their reachable code classifies WIRED, never residual.
        // Leg J: entry-point retain roots seed here too (Wired, never residual).
        let mut production_seeds = production_roots;
        production_seeds.extend(bench_file_roots.iter().copied());
        production_seeds.extend(entry_attr_roots.iter().copied());
        let wired_set = self.multi_root_bfs(&production_seeds, BfsSpec::classifier_calls());

        // --- Pass 2: Public API BFS ---
        // Seeds the COMPREHENSIVE pub surface (V2-2: pub methods/fields/nested).
        // Seeding a pub item as a root anchors its callees' reachability; the
        // item's OWN classification is split downstream by V3-1 (a pub root with
        // zero real callers → Suspected, not PublicApi-by-fiat).
        let pub_api_bfs = self.multi_root_bfs(&pub_api_roots, BfsSpec::classifier_calls());
        let pub_api_set: HashSet<Uuid> = pub_api_bfs.difference(&wired_set).copied().collect();

        // --- Pass 3: Test BFS ---
        // Seeds the `is_test_root` `#[test]` FUNCTION nodes (V2-2 finding-3), NOT
        // the `tests` module node — with `Contains` dropped a module reaches
        // nothing. The forward `Calls` walk from each test fn reaches the helpers
        // it exercises → TestOnly. `skip_test_modules:false` so the walk MAY enter
        // test-module helpers (unlike the production/pub passes). Integration-test
        // + example entry FILES seed this pass too (CL-REACH-04).
        let mut test_seeds = test_roots;
        test_seeds.extend(test_file_roots.iter().copied());
        let test_spec = BfsSpec {
            skip_test_modules: false,
            ..BfsSpec::classifier_calls()
        };
        let test_bfs = self.multi_root_bfs(&test_seeds, test_spec);
        let already_classified: HashSet<Uuid> = wired_set.union(&pub_api_set).copied().collect();
        let test_set: HashSet<Uuid> = test_bfs.difference(&already_classified).copied().collect();

        // The union of everything reached by any verdict pass — the "is this
        // symbol used by reachable code?" oracle for the V3-1 caller check.
        let reachable_union: HashSet<Uuid> = test_set.union(&already_classified).copied().collect();
        let pub_api_root_set: HashSet<Uuid> = pub_api_roots.iter().copied().collect();

        // --- Pass 4: Classify all nodes ---
        let mut classified = Vec::with_capacity(all_nodes.len());
        let mut summary = ReachabilitySummary {
            total: all_nodes.len(),
            wired: 0,
            public_api: 0,
            structural: 0,
            test_only: 0,
            dead: 0,
            orphan_files: 0,
            suspected: 0,
            excluded: 0,
        };

        for node in &all_nodes {
            let classification = if !self.classifies_node(node) {
                ReachabilityClass::Unclassified
            } else if wired_set.contains(&node.memory_id) {
                summary.wired += 1;
                ReachabilityClass::Wired
            } else if pub_api_set.contains(&node.memory_id) {
                summary.public_api += 1;
                ReachabilityClass::PublicApi
            } else if test_set.contains(&node.memory_id) {
                summary.test_only += 1;
                ReachabilityClass::TestOnly
            } else {
                summary.dead += 1;
                ReachabilityClass::Dead
            };

            classified.push(ClassifiedNode {
                memory_id: node.memory_id,
                symbol_name: node.symbol_name.clone(),
                file_path: node.file_path.clone(),
                kind: node.kind.clone(),
                classification,
                // WU-0015 Leg J: carry the retain-attr projection for the ligan
                // file-surface consumer (fully-dead file label exclusion).
                has_retain_attr: node.entry_retain.has_retain_attr(),
                // WU-0016 Leg H: carry the capture-completeness projection for
                // the ligan file-tier consumer (fully_dead capture-complete
                // conjunct).
                has_uncaptured_items: node.has_uncaptured_items,
            });
        }

        // --- Pass 5: Structural reclassification ---
        //
        // Symbols of kinds that are compile-time dependencies (use, const,
        // static, type_alias, macro) are never "called" — they have no
        // incoming Calls edges and thus land in DEAD after BFS.  But if
        // they live in a file that contains WIRED or PUBLIC_API code,
        // removing them would break the build.  Reclassify them as
        // STRUCTURAL.
        //
        // F3 (WU-0009 / ADR-0030): a bare `mod foo;` declaration is the same
        // shape — it is a compile-time wiring artifact with no incoming Calls
        // edge, so an UNREACHED module decl living in an ALIVE file lands in
        // DEAD and false-flags as deletable, even though removing it breaks the
        // build. Adding "module" rescues it to STRUCTURAL. The `alive_files`
        // guard below prevents over-rescue: a `mod` in a DEAD file stays DEAD.
        //
        // SEAM (note, not a framework): this list is Rust-specific (`use` /
        // `module` / `macro` are Rust kinds). When another language is indexed
        // it contributes its own structural kinds here — no per-language
        // registry now (YAGNI per ADR-0030).
        const STRUCTURAL_KINDS: &[&str] =
            &["use", "const", "static", "type_alias", "macro", "module"];

        // Collect files containing at least one alive (WIRED or PUBLIC_API) node.
        let alive_files: HashSet<String> = classified
            .iter()
            .filter(|n| {
                matches!(
                    n.classification,
                    ReachabilityClass::Wired | ReachabilityClass::PublicApi
                )
            })
            .map(|n| n.file_path.clone())
            .collect();

        for node in &mut classified {
            if node.classification == ReachabilityClass::Dead
                && STRUCTURAL_KINDS.contains(&node.kind.as_str())
                && alive_files.contains(&node.file_path)
            {
                node.classification = ReachabilityClass::Structural;
                summary.structural += 1;
                summary.dead -= 1;
            }
        }

        // --- Pass 5b: live-type data-member reclassification (CL-REACH-10) ---
        //
        // A field/property is not called, so call reachability alone leaves it
        // Dead even when it is a structural part of an alive type. Direct
        // members normally have a Contains edge, while an enum payload can have
        // an unmaterialized variant between the field and enum. Qualified-name
        // prefix resolution covers both without depending on one language's
        // field spelling or graph shape.
        //
        // A member of a DEAD owner remains Dead (narrowness: no blanket
        // all-members-alive rescue).
        // Owned set so the immutable borrow of `classified` is released before
        // the mutating reclassification loop below.
        let alive_field_container_names: HashSet<String> = classified
            .iter()
            .filter(|n| {
                matches!(
                    n.classification,
                    ReachabilityClass::Wired
                        | ReachabilityClass::PublicApi
                        | ReachabilityClass::Structural
                ) && symbol_kind_has_role(&n.kind, SymbolRole::FieldContainer)
            })
            .map(|n| n.symbol_name.clone())
            .collect();

        for node in &mut classified {
            if node.classification != ReachabilityClass::Dead
                || !symbol_kind_has_role(&node.kind, SymbolRole::DataMember)
            {
                continue;
            }
            if field_parent_type_is_alive(&node.symbol_name, &alive_field_container_names) {
                node.classification = ReachabilityClass::Structural;
                summary.structural += 1;
                summary.dead -= 1;
            }
        }

        // --- V3-1 seed-vs-classify split (WU-0015 / ADR-0036 V3-1) ---
        // A pub-api-SEEDED root anchors others' reachability, but classifies
        // PublicApi-clean only if it has a real caller. A pub root with zero real
        // callers → Suspected (the external-API-vs-wiring-gap review candidate),
        // reconciling the census surfacing without false-DEADing the pub surface.
        // Runs BEFORE the guards so a guard's "is my type/trait node reached?"
        // check sees GENUINE reachability — a pub-zero-caller node (incl. a
        // synthesized external-trait anchor) is already Suspected here, so it can
        // no longer fool the guard into rescuing an impl method off a merely-seeded
        // (not genuinely-used) trait/type.
        {
            let mut downgrades: Vec<usize> = Vec::new();
            for (i, node) in classified.iter().enumerate() {
                if node.classification == ReachabilityClass::PublicApi
                    && pub_api_root_set.contains(&node.memory_id)
                    && !self.pub_root_has_real_caller(node.memory_id, &reachable_union)
                {
                    downgrades.push(i);
                }
            }
            for i in downgrades {
                classified[i].classification = ReachabilityClass::Suspected;
            }
        }

        // --- Guard post-passes + TRANSITIVE re-walk (WU-0015 / ADR-0036
        //     V2-3/V3-4/V3-5; blind-spot #1 Wave 1) ---
        // Rescue residual trait/impl methods that dispatch reaches but the call
        // graph cannot see, to the tier of their reached type/trait node
        // (Contains/Implements edges, async-trait-desugar tolerant) — AND then
        // make the rescue TRANSITIVE: the verdict walk (`classifier_calls`) is
        // Forward/OUT-only, so it finished before a method was Wired-BY-RELABEL,
        // leaving a node reachable ONLY through a rescued method false-DEAD
        // (e.g. `find_containing_symbol` ← `GrepContextHandler::execute`). After
        // rescuing, re-seed `multi_root_bfs` from the rescued nodes over
        // `classifier_calls()` and fold still-Dead reached nodes into that tier.
        //
        // INTERLEAVE to a FIXPOINT: the re-walk admits `TypeOf`/`References`/… so
        // it can newly-REACH a `struct`/`trait` node, which makes a DIFFERENT
        // dyn-dispatched method guard-eligible on the NEXT round; the loop drains
        // that cascade. TERMINATION: every write is a monotone move toward
        // more-alive over a finite `ReachabilityClass` lattice — a node folds
        // Dead→alive at most once and then only ever upgrades to a strictly
        // more-alive tier (≤3 steps), so `changed` eventually stays false. This
        // is the same monotone-over-finite-lattice argument the WU-0019 container
        // roll-up (below) already relies on.
        //
        // TIER PRECEDENCE (most-alive wins, ACROSS rounds — design-review MAJOR):
        // the per-tier walks run most-alive-first [Wired, PublicApi, TestOnly],
        // and the fold admits a node when it is still `Dead` OR was already folded
        // by THIS pass to a STRICTLY-less-alive tier (`tier < cur` by the
        // load-bearing `ReachabilityClass` Ord). The `folded` set (persisted
        // across rounds) is what lets a round-2 Wired cascade reclaim a helper a
        // round-1 TestOnly walk folded — WITHOUT ever touching a node the main
        // verdict passes classified (those never enter `folded`), so this stays
        // scoped to the Dead-origin population (Wave-1 fence; Suspected/TestOnly
        // widening is Wave 2). This mirrors the roll-up's most-alive `.min()`.
        //
        // The TestOnly walk keeps the Pass-3 `skip_test_modules:false` admission
        // (may enter test-module helpers); the Wired/PublicApi walks keep
        // `skip_test_modules:true` so production/pub reachability never pulls test
        // helpers in — preserving the Pass-1/Pass-3 asymmetry.
        //
        // Runs IN PLACE (after V3-1, before the residual visibility sweep + the
        // container roll-up). `id_to_index` is built once and relies on
        // `classified` never being reordered inside the loop (only in-place
        // `.classification` writes occur).
        {
            let id_to_index: HashMap<Uuid, usize> = classified
                .iter()
                .enumerate()
                .map(|(i, c)| (c.memory_id, i))
                .collect();
            let test_spec = BfsSpec {
                skip_test_modules: false,
                ..BfsSpec::classifier_calls()
            };
            // Node indices this pass has folded/rescued — eligible for a later,
            // strictly-more-alive upgrade. Persists across rounds.
            let mut folded: HashSet<usize> = HashSet::new();

            loop {
                // (A) GUARD ROUND — snapshot classes; collect Dead trait/impl
                //     methods whose reached type/trait node now makes them
                //     dispatch-reachable.
                let class_by_id: HashMap<Uuid, ReachabilityClass> = classified
                    .iter()
                    .map(|c| (c.memory_id, c.classification))
                    .collect();
                let mut guard_rescued: Vec<(usize, ReachabilityClass)> = Vec::new();
                for (i, node) in classified.iter().enumerate() {
                    if node.classification == ReachabilityClass::Dead
                        && symbol_kind_has_role(&node.kind, SymbolRole::Callable)
                        && let Some(tier) = self.guard_rescue_tier(node.memory_id, &class_by_id)
                    {
                        guard_rescued.push((i, tier));
                    }
                }

                // Apply guard rescues; bucket the newly-rescued anchors by tier
                // ([Wired, PublicApi, TestOnly] == the most-alive-first walk
                // order). `guard_rescue_tier` only ever yields these three.
                let mut roots_by_tier: [Vec<Uuid>; 3] = [Vec::new(), Vec::new(), Vec::new()];
                let mut changed = false;
                for (i, tier) in guard_rescued {
                    classified[i].classification = tier;
                    folded.insert(i);
                    changed = true;
                    let slot = match tier {
                        ReachabilityClass::Wired => 0,
                        ReachabilityClass::PublicApi => 1,
                        ReachabilityClass::TestOnly => 2,
                        _ => continue,
                    };
                    roots_by_tier[slot].push(classified[i].memory_id);
                }

                // (B) TRANSITIVE RE-WALK — from each tier's newly-rescued anchors,
                //     forward `classifier_calls` BFS; fold reached nodes into that
                //     tier when it is strictly more-alive than their current class
                //     (and they are Dead or already folded by this pass).
                for (slot, tier, spec) in [
                    (
                        0usize,
                        ReachabilityClass::Wired,
                        BfsSpec::classifier_calls(),
                    ),
                    (1, ReachabilityClass::PublicApi, BfsSpec::classifier_calls()),
                    (2, ReachabilityClass::TestOnly, test_spec),
                ] {
                    if roots_by_tier[slot].is_empty() {
                        continue;
                    }
                    let reached = self.multi_root_bfs(&roots_by_tier[slot], spec);
                    for id in &reached {
                        if let Some(&idx) = id_to_index.get(id) {
                            let cur = classified[idx].classification;
                            if (cur == ReachabilityClass::Dead || folded.contains(&idx))
                                && tier < cur
                            {
                                classified[idx].classification = tier;
                                folded.insert(idx);
                                changed = true;
                            }
                        }
                    }
                }

                if !changed {
                    break;
                }
            }
        }

        // --- Pass 5c: dead-abstraction reclassification (ADR-0045 D3) ---
        //
        // Two compile-required-but-call-unreachable shapes land in Dead after the
        // BFS + the Pass-5/5b structural rescues + the guard transitive re-walk, yet
        // removing either breaks the build — so the EXISTING Structural definition
        // ("removing it breaks the build," NOT "reachable") applies:
        //
        //   D3a — a trait-DEFINITION method a NON-DEAD implementor compile-requires
        //     (abstract with a live impl, OR overridden by a live impl). A trait
        //     with ZERO implementors (`ConstraintChecker`, DEC-082 — the canary)
        //     stays Dead; a defaulted-never-overridden-uncalled method stays Dead.
        //   D3b — an impl of a genuine MARKER trait (Eq/Copy/Send/… via the
        //     [`STD_MARKER_TRAITS`] allowlist for synthesized external anchors, or a
        //     first-party no-method trait) on a non-Dead Self type.
        //
        // 🔴 ORDERING (D3b remediation, 2026-07-18 — load-bearing): this pass runs
        // AFTER the guard post-passes + TRANSITIVE re-walk, NOT before. D3a's
        // "≥1 non-Dead implementor" test reads the impl's own child method nodes,
        // and those children (e.g. `impl GraphBackend for KnowledgeGraph`'s 13
        // methods, reached only by dyn-dispatch the call graph cannot see) are
        // Wired-BY-RELABEL by the guard re-walk — which had NOT yet run at the
        // original Pass-5c position, so every `GraphBackend::*` abstract method
        // false-stayed Dead (the D3a MISS the drive measured). Running here, the
        // impl children are alive and D3a fires. Still BEFORE the residual
        // visibility sweep (so a Dead trait method is not pre-downgraded to
        // Suspected out from under D3a) and BEFORE the container roll-up (so the
        // roll-up can lift a trait/impl HEADER whose children this pass made
        // Structural — e.g. `trait GraphBackend` Suspected → Structural). NEVER
        // moves anything toward Wired/PublicApi (ADR-0045 prime directive).
        {
            let class_by_id: HashMap<Uuid, ReachabilityClass> = classified
                .iter()
                .map(|c| (c.memory_id, c.classification))
                .collect();
            let mut rescued: Vec<usize> = Vec::new();
            for (i, node) in classified.iter().enumerate() {
                if node.classification != ReachabilityClass::Dead {
                    continue;
                }
                let is_structural = match node.kind.as_str() {
                    "function" => {
                        // Abstract == no default body (the persisted AST `has_body`
                        // bit on the graph node is `Some(false)`).
                        let method_abstract =
                            self.graph.node(&node.memory_id).and_then(|n| n.has_body)
                                == Some(false);
                        self.d3a_trait_method_is_structural(
                            node.memory_id,
                            method_abstract,
                            short_symbol_name(&node.symbol_name),
                            &class_by_id,
                        )
                    }
                    "impl" => self.d3b_marker_impl_is_structural(node.memory_id, &class_by_id),
                    _ => false,
                };
                if is_structural {
                    rescued.push(i);
                }
            }
            for i in rescued {
                classified[i].classification = ReachabilityClass::Structural;
                summary.structural += 1;
                summary.dead -= 1;
            }
        }

        // --- Residual sweep: VISIBILITY-GATED (WU-0015 Leg-3b / ADR-0036 v6) ---
        // A node still classed `Dead` at this point is call-unreachable AND
        // guard-free BY CONSTRUCTION (it survived Pass 4 + Pass 5/5b + the V3-1
        // pub-zero-caller split + the guard post-pass). Leg-3b promotes ONLY the
        // PRIVATE such residual to the delete-authority `Dead` tier; a PUBLIC
        // (exported-surface) residual is the external-API-vs-wiring-gap review
        // candidate and is downgraded to `Suspected` (never delete-eligible).
        // Visibility lives on the `GraphNode` (`ClassifiedNode` carries none), so
        // it is looked up here. GUARD: a graph miss OR an empty visibility string
        // (old snapshots / SCIP-only nodes) is treated as NOT-private → downgraded
        // (over-conservative — an empty-visibility node never gains delete
        // authority). PRIVATE ≡ visibility ∉ {`pub`, ``} (the delete-eligible set
        // {`private`, `pub(crate)`, `pub(super)`, `pub(in …)`}; `pub(crate)` IS
        // eligible — a cross-crate use of it is privacy-forbidden). The
        // delete-authority `SafeDelete` gate that reads this `Dead` class still
        // requires the full 4-way conjunction (rustc-oracle + cfg-clean crate) in
        // `graph_query::classify_dead_action`.
        for node in &mut classified {
            if node.classification == ReachabilityClass::Dead {
                let is_private = self
                    .graph
                    .node(&node.memory_id)
                    .map(|n| crate::graph_query::visibility_is_deletable(&n.visibility))
                    .unwrap_or(false);
                if !is_private {
                    node.classification = ReachabilityClass::Suspected;
                }
            }
        }

        // --- Container roll-up (WU-0019) ---
        // A `Dead`/`Suspected` CONTAINER node (`impl`/`trait`/`module` header)
        // whose OUTGOING `Contains` children include a genuinely-alive node is
        // itself structurally required — deleting it would break the build — so it
        // rolls up to its MOST-ALIVE child tier (tier propagation, NOT blanket
        // Wired). This is the classification-side twin of OQ-TRAIT-GUARD-RESIDUAL:
        // `guard_rescue_tier` above rescues a dead METHOD via its alive parent (the
        // container→child direction); an impl/trait/module HEADER is a DISTINCT
        // graph node from its children and no existing pass rescues it via an alive
        // CHILD, so it false-DEADed even when it owns wired code (e.g. the `impl`
        // block of `StalenessCheck` whose `verdict()` has real wired call sites, or
        // a `SUSPECTED` bare `pub mod foo;` decl whose module content is alive —
        // the file-scoped Pass-5 `STRUCTURAL_KINDS` rescue is Dead-only and cannot
        // reach a `Suspected` pub-mod decl, so this child-content check is a
        // separate, module-scoped rescue).
        //
        // ORDERING (load-bearing): runs AFTER every existing rescue pass (Pass
        // 5/5b structural, the V3-1 pub split, the `guard_rescue_tier` post-pass,
        // the residual visibility sweep) and NEVER re-invokes `guard_rescue_tier`.
        // This pass mutates ONLY the container node's own class, never a child's,
        // so a container rescued through ONE alive child cannot drag its
        // genuinely-dead SIBLING method alive. (Feeding the rollup back into the
        // guard would let a just-rolled-up trait rescue its own uncalled default
        // method — the ordering here forbids that.)
        //
        // NESTING: iterates to a FIXPOINT. A container is structural iff it OWNS
        // (directly `Contains`) an alive node, but "alive" may itself be a
        // container this pass just rescued — e.g. `mod m` reaches wired code only
        // THROUGH an inner `impl S` (`m` Contains `{S, impl S}`; `impl S` Contains
        // the wired `go()`; `go` is a grandchild of `m`). One local rule
        // (most-alive alive DIRECT child) at a fixpoint composes correctly at every
        // nesting depth. It is monotone (a node only ever becomes MORE alive) over
        // a finite lattice ⇒ it terminates in ≤ (#containers) rounds. Chosen over a
        // single bottom-up pass (fragile `Contains` topo-order) and a
        // transitive-descendant check (which conflates a structural child with
        // transitive content and muddies tier propagation).
        loop {
            // Snapshot classes so a rescue applied THIS round is visible to a
            // parent container only on the NEXT round (deterministic cascade).
            let class_by_id: HashMap<Uuid, ReachabilityClass> = classified
                .iter()
                .map(|c| (c.memory_id, c.classification))
                .collect();

            let mut rescues: Vec<(usize, ReachabilityClass)> = Vec::new();
            for (i, node) in classified.iter().enumerate() {
                let is_container = matches!(node.kind.as_str(), "impl" | "trait" | "module");
                if !is_container
                    || !matches!(
                        node.classification,
                        ReachabilityClass::Dead | ReachabilityClass::Suspected
                    )
                {
                    continue;
                }
                // Most-alive alive DIRECT child (min by `ReachabilityClass` Ord:
                // Wired < PublicApi < Structural < TestOnly). `None` ⇒ ZERO alive
                // children ⇒ the container stays non-alive (the honest review
                // surface — never widen a genuinely-dead container).
                let most_alive = self
                    .graph
                    .neighbors(&node.memory_id)
                    .into_iter()
                    .filter(|(_, edge)| edge.kind == EdgeKind::Contains)
                    .filter_map(|(child_id, _)| class_by_id.get(&child_id).copied())
                    .filter(|c| {
                        matches!(
                            c,
                            ReachabilityClass::Wired
                                | ReachabilityClass::PublicApi
                                | ReachabilityClass::Structural
                                | ReachabilityClass::TestOnly
                        )
                    })
                    .min();
                if let Some(tier) = most_alive {
                    rescues.push((i, tier));
                }
            }
            if rescues.is_empty() {
                break;
            }
            for (i, tier) in rescues {
                classified[i].classification = tier;
            }
        }

        // --- Census-scope EXCLUDED sweep (ADR-0045 D1 + D2) ---
        //
        // A node whose file is OUT of the production-reachability census — a
        // deliberately-detached / nested-`[workspace]` crate (D1) or a fixture-
        // corpus directory the extractor consumes as INPUT (D2, an excluded-dir
        // path SEGMENT) — is reclassified `Excluded`, OVERRIDING its computed tier.
        // Runs LAST (after every verdict/rescue/roll-up pass) so the in-census
        // population's reachability is never perturbed: with an `unscoped` scope
        // this loop is a no-op and the classification is byte-identical to the
        // pre-ADR-0045 result. `Excluded` is out-of-scope, NOT dead — it never
        // seeds/reaches anything (this is pure relabelling), and per the prime
        // directive nothing moves toward Wired/PublicApi (only {Dead, Suspected,
        // TestOnly} realistically land here — but the override is class-agnostic:
        // an excluded file is out of scope regardless of what tier it computed to).
        //
        // 🔴 SENTINEL EXEMPTION (`scope.is_excluded`): D1 fires only on a path that
        // canonicalizes to a REAL file under a non-member dir, so synthesized
        // external-trait anchors + SCIP-only non-file nodes (sentinel `file_path`)
        // are never swept — they do not resolve to a real file. D2 keys on an exact
        // path SEGMENT, so `src/testdata_loader.rs` is untouched.
        // Census membership is file-level authority. Resolve each distinct
        // path once: D1 canonicalizes a real path, so evaluating it per symbol
        // multiplies filesystem work by the number of symbols in that file.
        let mut excluded_by_file: HashMap<&str, bool> = HashMap::new();
        for node in &all_nodes {
            if !self.classifies_node(node) {
                continue;
            }
            let file_path = node.file_path.as_str();
            excluded_by_file
                .entry(file_path)
                .or_insert_with(|| scope.is_excluded(file_path));
        }
        for node in &mut classified {
            if excluded_by_file
                .get(node.file_path.as_str())
                .copied()
                .unwrap_or(false)
            {
                node.classification = ReachabilityClass::Excluded;
            }
        }

        // Recompute the summary from the FINAL classifications — the
        // reclassification post-passes above moved counts between tiers.
        summary = ReachabilitySummary {
            total: all_nodes.len(),
            wired: 0,
            public_api: 0,
            structural: 0,
            test_only: 0,
            dead: 0,
            orphan_files: summary.orphan_files,
            suspected: 0,
            excluded: 0,
        };
        for node in &classified {
            match node.classification {
                ReachabilityClass::Wired => summary.wired += 1,
                ReachabilityClass::PublicApi => summary.public_api += 1,
                ReachabilityClass::Structural => summary.structural += 1,
                ReachabilityClass::TestOnly => summary.test_only += 1,
                ReachabilityClass::Suspected => summary.suspected += 1,
                ReachabilityClass::Dead => summary.dead += 1,
                ReachabilityClass::Excluded => summary.excluded += 1,
                ReachabilityClass::Orphan | ReachabilityClass::Unclassified => {}
            }
        }

        let entry_points_used: Vec<String> = self
            .entry_points
            .iter()
            .map(|ep| format!("{} [{}] ({})", ep.name, ep.kind, ep.crate_name))
            .collect();

        // --- Pass 6: Test coverage chain tracing ---
        //
        // For TestOnly helper functions (not `#[test]` themselves), trace
        // reverse BFS through incoming edges to find the `#[test]` functions
        // that ultimately call them. This lets the report show WHY a helper
        // is classified as TestOnly.
        let test_chains = if include_test_chains {
            self.build_test_chains(&classified)
        } else {
            BTreeMap::new()
        };

        ReachabilityReport {
            classified,
            summary,
            entry_points_used,
            orphan_files: Vec::new(), // Populated by detect_orphans() separately
            test_chains,
        }
    }

    /// Detect orphan `.rs` files under the workspace `src/` directories.
    ///
    /// Walks each crate's `src/` directory and finds files not represented
    /// in the graph. Excludes common generated files and `include!()` targets.
    pub fn detect_orphans(&self, workspace_root: &Path) -> Vec<String> {
        let graph_files: HashSet<String> = self
            .graph
            .all_nodes()
            .iter()
            .map(|n| n.file_path.clone())
            .collect();

        let mut orphans = Vec::new();

        // Walk crate directories looking for src/ trees.
        let crates_dir = workspace_root.join("crates");
        if crates_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&crates_dir)
        {
            for entry in entries.flatten() {
                let src_dir = entry.path().join("src");
                if src_dir.is_dir() {
                    collect_rs_files_recursive(
                        &src_dir,
                        workspace_root,
                        &graph_files,
                        &mut orphans,
                    );
                }
            }
        }

        // Also check root src/ if it exists.
        let root_src = workspace_root.join("src");
        if root_src.is_dir() {
            collect_rs_files_recursive(&root_src, workspace_root, &graph_files, &mut orphans);
        }

        orphans
    }

    /// Run a complete analysis including orphan detection (the production path).
    ///
    /// Builds the real [`CensusScope`] from `workspace_root` (ADR-0045 D1 member
    /// set + D2 default fixture-dir list) so detached/nested-crate + fixture-corpus
    /// nodes classify [`ReachabilityClass::Excluded`], then runs orphan detection.
    pub fn analyze_with_orphans(&self, workspace_root: &Path) -> ReachabilityReport {
        self.analyze_with_orphans_internal(workspace_root, true)
    }

    fn analyze_with_orphans_for_persistence(&self, workspace_root: &Path) -> ReachabilityReport {
        self.analyze_with_orphans_internal(workspace_root, false)
    }

    fn analyze_with_orphans_internal(
        &self,
        workspace_root: &Path,
        include_test_chains: bool,
    ) -> ReachabilityReport {
        // The generation inventory is the exact cross-language source owner.
        // Its classified-document population replaces both the Cargo-only D1
        // member heuristic and the D2 directory-name heuristic: an auxiliary
        // `testdata` tree is absent from the population, while a nested Go
        // module that deliberately owns that same path remains eligible. The
        // filesystem-derived census survives only for the legacy analyzer API
        // that has no inventory evidence.
        let scope = if self.classified_documents.is_some() {
            CensusScope::unscoped()
        } else {
            CensusScope::for_workspace(workspace_root)
        };
        let mut report = if include_test_chains {
            self.analyze_scoped(&scope)
        } else {
            self.analyze_scoped_for_persistence(&scope)
        };
        report.orphan_files = self.detect_orphans(workspace_root);
        report.summary.orphan_files = report.orphan_files.len();
        report
    }

    // -----------------------------------------------------------------------
    // Internal BFS
    // -----------------------------------------------------------------------

    /// Multi-root BFS from a set of starting node UUIDs.
    ///
    /// Follows all traversable edges (Calls, Contains, Implements, References,
    /// TypeOf, DependsOn, Extends). Skips RelatedTo.
    ///
    /// Traverses BOTH outgoing AND incoming edges. This makes the BFS
    /// bidirectional within connected components -- if a file Contains symbol S,
    /// reaching the file reaches S (outgoing Contains) and reaching S also
    /// reaches the file (incoming Contains). Without Calls edges from SCIP,
    /// this is necessary for meaningful reachability through structural edges.
    ///
    /// In [`BfsMode::Production`] mode, two additional filters apply:
    ///
    /// 1. **HasImpl skip**: Outgoing `HasImpl` edges are NOT followed. This
    ///    prevents a WIRED trait from automatically marking all its implementors
    ///    as WIRED. The reverse direction (incoming `Implements`) still works:
    ///    if an implementor is independently WIRED, the traits it implements
    ///    remain WIRED.
    ///
    /// 2. **Test-module skip**: Nodes inside `tests::` modules are not enqueued.
    ///    This prevents production files from pulling their `#[cfg(test)]`
    ///    children into the WIRED set via `Contains` edges.
    fn multi_root_bfs(&self, roots: &[Uuid], spec: BfsSpec) -> HashSet<Uuid> {
        // RC2: route through the ONE traversal core. The closure just collects
        // every traversed node into the WIRED/PUBLIC_API/TEST_ONLY set the
        // classifier reads back; direction, the RC1 `admits` admission, and the
        // symmetric `HasImpl`/test-module prune all live in `graph_walk` + the
        // spec, so this pass cannot diverge from the other walks.
        let mut visited = HashSet::new();
        crate::graph_query::graph_walk(self.graph, roots, &spec, None, |step| {
            if self.classifies_node_id(&step.node_id) {
                visited.insert(step.node_id);
                crate::graph_query::WalkControl::Continue
            } else {
                // An uncovered structural document is not merely omitted from
                // the verdict: it cannot bridge two covered nodes either.
                crate::graph_query::WalkControl::SkipChildren
            }
        });
        visited
    }

    // -----------------------------------------------------------------------
    // Test chain tracing
    // -----------------------------------------------------------------------

    /// Build test coverage chains for TestOnly helper functions.
    ///
    /// For each TestOnly function that is NOT a `#[test]` itself, performs a
    /// reverse BFS through the graph's incoming edges to discover which
    /// `#[test]` functions transitively call it. Returns a map from the
    /// helper's UUID to the list of chains (each chain is a sequence of
    /// symbol names from the `#[test]` root down to the helper).
    fn build_test_chains(&self, classified: &[ClassifiedNode]) -> BTreeMap<Uuid, Vec<Vec<String>>> {
        // Collect TestOnly function nodes.
        let test_only_fns: Vec<&ClassifiedNode> = classified
            .iter()
            .filter(|node| {
                node.classification == ReachabilityClass::TestOnly
                    && symbol_kind_has_role(&node.kind, SymbolRole::Callable)
            })
            .collect();

        if test_only_fns.is_empty() {
            return BTreeMap::new();
        }

        // Determine which TestOnly functions are `#[test]` roots by checking
        // their source for `#[test]` or `#[tokio::test]` attributes.
        let mut is_test_fn: HashSet<Uuid> = HashSet::new();
        for cn in &test_only_fns {
            if let Some(node) = self.graph.node(&cn.memory_id)
                && self.has_test_attribute(node)
            {
                is_test_fn.insert(cn.memory_id);
            }
        }

        // For each helper (TestOnly function that is NOT #[test]), do a
        // reverse BFS to find #[test] callers and record the chain.
        let mut result: BTreeMap<Uuid, Vec<Vec<String>>> = BTreeMap::new();

        for cn in &test_only_fns {
            if is_test_fn.contains(&cn.memory_id) {
                continue; // Skip actual test functions — only trace helpers.
            }

            let chains = self.reverse_bfs_to_test_roots(cn.memory_id, &is_test_fn);
            if !chains.is_empty() {
                result.insert(cn.memory_id, chains);
            }
        }

        result
    }

    /// Check whether a graph node is a `#[test]`-style test ROOT.
    ///
    /// WU-0003 / CL-REACH-09: consult the PERSISTED `is_test_root` bit, captured
    /// from the AST at index time. The previous implementation did a
    /// `std::fs::read_to_string(node.file_path)` and scanned source lines — a
    /// staleness hazard (the file may have moved/changed since indexing) that
    /// silently returned `false` on any I/O error (`Err(_) => false`), so a
    /// moved/absent source file dropped the test root entirely. The persisted bit
    /// is the index-time AST fact and needs no disk access.
    const fn has_test_attribute(&self, node: &crate::graph::GraphNode) -> bool {
        node.is_test_root
    }

    /// Reverse BFS from a helper node to find `#[test]` root functions.
    ///
    /// Follows incoming edges backwards (callee → caller direction), stopping
    /// when a `#[test]` function is reached. Returns one chain per discovered
    /// `#[test]` root, ordered from root to helper.
    fn reverse_bfs_to_test_roots(
        &self,
        helper_id: Uuid,
        test_root_ids: &HashSet<Uuid>,
    ) -> Vec<Vec<String>> {
        use crate::graph_query::{WalkControl, graph_walk};

        // RC2: route through the ONE traversal core (`structural_reverse` =
        // INCOMING / `Structural` admission, matching the historical
        // `is_traversable_edge`). The closure records parent pointers off
        // `step.from` to reconstruct each `#[test]`-root → helper chain, and
        // `SkipChildren` at a test root reproduces the old "don't traverse
        // past a test root" early-stop.
        let mut parents: HashMap<Uuid, Uuid> = HashMap::new();
        let mut chains: Vec<Vec<String>> = Vec::new();

        graph_walk(
            self.graph,
            &[helper_id],
            &BfsSpec::structural_reverse(),
            None,
            |step| {
                if !self.classifies_node_id(&step.node_id) {
                    return WalkControl::SkipChildren;
                }
                if let Some(from) = step.from {
                    parents.insert(step.node_id, from);
                }
                if step.node_id != helper_id && test_root_ids.contains(&step.node_id) {
                    // Walk the parent chain helper-ward, then reverse to
                    // root → … → helper.
                    let mut chain_ids = vec![step.node_id];
                    let mut current = step.node_id;
                    while current != helper_id {
                        match parents.get(&current) {
                            Some(&p) => {
                                chain_ids.push(p);
                                current = p;
                            }
                            None => break,
                        }
                    }
                    let mut chain: Vec<String> = chain_ids
                        .iter()
                        .filter_map(|id| self.graph.node(id).map(|n| n.symbol_name.clone()))
                        .collect();
                    chain.reverse();
                    chains.push(chain);
                    // Don't traverse past a test root.
                    return WalkControl::SkipChildren;
                }
                WalkControl::Continue
            },
        );

        chains
    }

    // -----------------------------------------------------------------------
    // Root resolution
    // -----------------------------------------------------------------------

    /// Resolve binary and build-script production entry points to graph node UUIDs.
    ///
    /// Matches entry point file paths against graph node file paths using
    /// suffix matching. Entry points are canonicalized (absolute), graph paths
    /// may be absolute or relative -- normalize by stripping `./` prefixes and
    /// using bidirectional suffix matching.
    ///
    /// CL-REACH-05: seed ONLY the actual entry SYMBOL (`main` for bins; the
    /// declared target name otherwise), never every top-level function in the
    /// entry file. The historical `kind == "function" || "module"` over-seed
    /// marked every sibling function in a bin file as a root — falsely WIRING
    /// deliberately-uncalled bin helpers. BFS reaches the genuinely-called rest
    /// via the production `Calls`/`Contains` edges. The empty-roots fallback is
    /// NARROW: it seeds the entry file's nodes ONLY when no entry symbol
    /// resolves (e.g. an SCIP-only file whose `main` node is absent) — it never
    /// re-introduces the all-functions over-seed.
    fn resolve_production_roots(&self, file_to_nodes: &HashMap<&str, Vec<Uuid>>) -> Vec<Uuid> {
        let mut roots = Vec::new();

        for ep in &self.entry_points {
            if !matches!(
                ep.kind,
                EntryPointKind::Binary | EntryPointKind::BuildScript
            ) {
                continue;
            }

            let ep_path_str = ep.file_path.to_string_lossy();
            let ep_normalized = ep_path_str.strip_prefix("./").unwrap_or(&ep_path_str);
            let entry_symbol = executable_entry_symbol(ep);

            // Track whether this entry file matched any graph file at all, so the
            // narrow fallback can fire only for entry files whose symbol we
            // genuinely could not resolve.
            let mut file_matched = false;
            let mut symbol_resolved = false;

            for (&graph_path, node_ids) in file_to_nodes {
                let gp_normalized = graph_path.strip_prefix("./").unwrap_or(graph_path);
                if ep_normalized.ends_with(gp_normalized) || gp_normalized.ends_with(ep_normalized)
                {
                    file_matched = true;
                    // Seed ONLY the entry symbol (e.g. `main`), matched on the
                    // short name so a qualified `app::main` still resolves.
                    for &node_id in node_ids {
                        if let Some(node) = self.graph.node(&node_id)
                            && symbol_kind_has_role(&node.kind, SymbolRole::Callable)
                            && short_symbol_name(&node.symbol_name) == entry_symbol
                        {
                            roots.push(node_id);
                            symbol_resolved = true;
                        }
                    }
                }
            }

            // Narrow fallback: an entry file matched but its entry symbol did NOT
            // resolve (e.g. an SCIP-only node set without a `main` node). Seed
            // that file's nodes rather than dropping the entry entirely. This
            // does NOT re-introduce the cross-file all-functions over-seed.
            if file_matched && !symbol_resolved {
                for (&graph_path, node_ids) in file_to_nodes {
                    let gp_normalized = graph_path.strip_prefix("./").unwrap_or(graph_path);
                    if ep_normalized.ends_with(gp_normalized)
                        || gp_normalized.ends_with(ep_normalized)
                    {
                        roots.extend(node_ids);
                    }
                }
            }
        }

        // Every package-level Go `func init()` runs before package use or
        // program startup. It is a production root independently of whether
        // the package is a binary or importable library, and a package may
        // declare several init functions across files.
        for node_ids in file_to_nodes.values() {
            for &node_id in node_ids {
                if let Some(node) = self.graph.node(&node_id)
                    && node.file_path.ends_with(".go")
                    && !node.file_path.ends_with("_test.go")
                    && symbol_kind_has_role(&node.kind, SymbolRole::Callable)
                    && node.symbol_name == "init"
                    && node.is_test_only != Some(true)
                {
                    roots.push(node_id);
                }
            }
        }

        roots
    }

    /// Resolve every graph node living in an entry-point FILE of one of the
    /// given kinds (WU-0003 / CL-REACH-04). Unlike [`Self::resolve_production_roots`]
    /// (which seeds a single entry SYMBOL), convention test/bench/example files
    /// have no single canonical entry symbol — the whole file is the seed set so
    /// every top-level `#[test]`/`fn main`/helper in it is reached.
    fn resolve_entry_file_roots(
        &self,
        file_to_nodes: &HashMap<&str, Vec<Uuid>>,
        kinds: &[EntryPointKind],
    ) -> Vec<Uuid> {
        let mut roots = Vec::new();
        for ep in &self.entry_points {
            if !kinds.contains(&ep.kind) {
                continue;
            }
            let ep_path_str = ep.file_path.to_string_lossy();
            let ep_normalized = ep_path_str.strip_prefix("./").unwrap_or(&ep_path_str);
            for (&graph_path, node_ids) in file_to_nodes {
                let gp_normalized = graph_path.strip_prefix("./").unwrap_or(graph_path);
                if ep_normalized.ends_with(gp_normalized) || gp_normalized.ends_with(ep_normalized)
                {
                    roots.extend(node_ids);
                }
            }
        }
        roots
    }

    /// Resolve ABI/linker ENTRY-POINT retain roots (WU-0015 Leg J /
    /// OQ-RETAIN-ATTRIBUTE-ENTRYPOINT-BLINDNESS).
    ///
    /// Every node whose captured
    /// [`EntryRetainFlags::is_entry_point`](crate::graph::EntryRetainFlags::is_entry_point)
    /// holds — `#[no_mangle]` / `#[export_name]` / `#[used]` — is a PRODUCTION
    /// root: the linker retains it even with no Rust caller, so the
    /// compiler-visible call graph cannot reach it and it would otherwise
    /// false-classify `Dead`. Seeded into the production BFS alongside the
    /// binary/bench roots.
    ///
    /// Unlike [`Self::resolve_production_roots`] this does NOT filter by
    /// `kind == "function"`: a `#[used]` STATIC must seed too. Reads the
    /// persisted `GraphNode` bit directly (no `EntryPointKind`), mirroring
    /// [`Self::resolve_pub_api_roots`]. Safe-direction: this only ADDS roots
    /// (Dead → Wired), never removes.
    fn resolve_entry_attr_roots(&self, all_nodes: &[&crate::graph::GraphNode]) -> Vec<Uuid> {
        all_nodes
            .iter()
            .filter(|n| n.entry_retain.is_entry_point())
            .map(|n| n.memory_id)
            .collect()
    }

    /// Resolve public API roots from library crates.
    ///
    /// Uses a heuristic: top-level items (no `::` in symbol name) of kinds
    /// function, struct, enum, trait, type_alias are considered public API
    /// candidates. Only top-level PUBLIC (`visibility == "pub"`) items of those
    /// kinds are seeded; private and pub(crate) items reach production only via
    /// a real Pass-1 caller, never as self-seeded API surface (CL-REACH-11).
    fn resolve_pub_api_roots(&self, all_nodes: &[&crate::graph::GraphNode]) -> Vec<Uuid> {
        // Rust LibRoot files (paths ending `.rs`) — consumed by the UNTOUCHED
        // `/src/` needle below. Go LibRoot directories (WU-0023 P3b — every other
        // LibRoot path, workspace-relative) — consumed by the language-neutral
        // importable-unit predicate (exact package-dir match). Splitting the set
        // by extension keeps the Rust needle byte-identical (RUST NO-REGRESSION):
        // on a Rust-only store `go_lib_dirs` is empty and `lib_entry_files` ==
        // the pre-WU set.
        let normalize = |s: &str| -> String {
            s.strip_prefix("./")
                .unwrap_or(s)
                .trim_end_matches('/')
                .to_string()
        };
        let mut lib_entry_files: HashSet<String> = HashSet::new();
        let mut go_lib_dirs: HashSet<String> = HashSet::new();
        for ep in self
            .entry_points
            .iter()
            .filter(|ep| matches!(ep.kind, EntryPointKind::LibRoot))
        {
            let s = ep.file_path.to_string_lossy();
            if s.ends_with(".rs") {
                lib_entry_files.insert(normalize(&s));
            } else {
                go_lib_dirs.insert(normalize(&s));
            }
        }

        let mut roots = Vec::new();

        for node in all_nodes {
            let node_path = node.file_path.strip_prefix("./").unwrap_or(&node.file_path);

            // Public syntax inside test-owned source is not production API.
            // Keep this gate language-neutral: Rust `#[cfg(test)]` items and
            // integration-test files have the same authority boundary as Go
            // `_test.go` declarations.  Without it, an exported test helper
            // self-seeds in the production/public pass, is later downgraded to
            // Suspected, and cannot be rescued into TestOnly with the helpers it
            // actually uses.
            if is_test_module_symbol(self.graph, &node.memory_id)
                || crate::extractor::file_is_test(node_path)
            {
                continue;
            }

            // WU-0023 P3b: language-gate the importable-unit predicate. A Go node
            // is in an importable library package iff its OWN package directory
            // (the parent dir of its `.go` file) EXACTLY matches an emitted Go
            // LibRoot dir — never the Rust single-package `/src/` fallback (which
            // must not leak into Go). The Rust `/src/` needle below is untouched.
            let lang = crate::graph_stats::node_language(node);
            if matches!(lang, Some("go")) {
                let node_pkg_dir = normalize(
                    std::path::Path::new(node_path)
                        .parent()
                        .and_then(|p| p.to_str())
                        .unwrap_or(""),
                );
                let in_go_lib = go_lib_dirs.contains(&node_pkg_dir);
                if in_go_lib && go_is_pub_api_root(node) {
                    roots.push(node.memory_id);
                }
                continue;
            }

            // Check if this node is in a library crate by matching file paths.
            //
            // FD-1: node paths are WORKSPACE-RELATIVE (extractor.rs ~255) but lib
            // entry paths are ABSOLUTE (entry_points canonicalizes the workspace
            // root). The old `rfind("/src/")` on the absolute lib path produced an
            // absolute `crate_prefix` that a relative node path could never
            // `contains()`; the workspace shape only survived by the suffix
            // fallback, which itself required the node path to contain "/src/".
            // A single-package node ("src/lib.rs") has NO leading "/src/" → the
            // fallback collapsed → the ENTIRE public API was false-DEAD/SAFE_DELETE.
            //
            // Fix: derive the node's crate dir RELATIVE to the workspace, then
            // match it against the lib's absolute path by substring (bases stay
            // comparable). Single-package nodes carry no crate dir → match any
            // lib (the only lib in a single-package repo; in a root-package
            // workspace this can over-seed = the SAFE false-WIRE direction, never
            // a false-DEAD).
            // node paths are workspace-RELATIVE; lib entry paths are ABSOLUTE in
            // production but RELATIVE in synthetic tests. Normalize every path to a
            // single leading "/" so the "/<cratedir>/src/" membership probe is
            // base-agnostic. A single-package node ("src/..") has no crate dir →
            // match any root-level lib (the only lib in a single-package repo).
            // "crates/h00ligan-engine/src/x.rs" -> "crates/h00ligan-engine"; "src/lib.rs"
            // (single package) -> "" (the root crate).
            let node_crate_dir = node_path.find("/src/").map_or("", |i| &node_path[..i]);
            let crate_needle = if node_crate_dir.is_empty() {
                "/src/".to_string()
            } else {
                format!("/{node_crate_dir}/src/")
            };
            let in_lib_crate = lib_entry_files.iter().any(|lib_path| {
                format!("/{}", lib_path.trim_start_matches('/')).contains(&crate_needle)
            });

            if !in_lib_crate {
                continue;
            }

            // Heuristic: top-level PUBLIC items in non-test files. Private and
            // pub(crate)/pub(super)/pub(in ...) items are NOT API surface — they
            // reach production only via a real Pass-1 caller, so they must NOT
            // self-seed here (CL-REACH-11). `visibility == "pub"` is the exact
            // string the extractor's Visibility Display impl emits for a fully
            // public item (extractor.rs:88).
            // WU-0015 / ADR-0036 V2-2: DROP the `is_top_level`
            // (`!symbol_name.contains("::")`) filter. With `Contains` dropped
            // from the verdict walk, a pub struct/module can no longer reach its
            // own methods/fields via containment, so the ENTIRE public surface —
            // pub METHODS (`Type::method`), pub FIELDS, pub items in pub NESTED
            // modules — must self-seed as PublicApi ROOTS (else the external API
            // of an embeddable library false-DEADs). `visibility == "pub"` + the
            // lib-crate + not-test-module gates still bound the seed set;
            // classification of each seed is then split by V3-1 (a pub root with
            // zero real callers → Suspected, not PublicApi-by-fiat).
            //
            // WU-0015 DEVIATION from build-plan item 2a (add `"field"`): pub FIELDS
            // are deliberately NOT seeded as pub-api roots. A field's TYPE is
            // already anchored by its owning struct's `FieldOf` edge (walked in the
            // Call edge-set), and the field NODE's correct classification is
            // Structural (a compile-time part of an alive type) via the Pass-5b
            // rescue. Seeding the field as a pub root instead makes it PublicApi at
            // Pass 4 → skips Pass 5b → the V3-1 split downgrades it to Suspected,
            // LOSING the honest Structural classification (regressing rc10). The
            // ADR under-specified this interaction; Pass 5b handles fields better.
            let is_api_kind = matches!(
                node.kind.as_str(),
                "function" | "struct" | "enum" | "trait" | "type_alias" | "module"
            );
            let is_public = node.visibility == "pub";
            let is_test_module = node.kind == "module"
                && (node.symbol_name == "tests" || node.symbol_name.ends_with("::tests"));

            if is_api_kind && is_public && !is_test_module {
                roots.push(node.memory_id);
            }
        }

        roots
    }

    /// Resolve test module roots from the graph.
    ///
    /// Identifies modules named "tests" (convention for `#[cfg(test)]` modules).
    fn resolve_test_roots(&self, all_nodes: &[&crate::graph::GraphNode]) -> Vec<Uuid> {
        // WU-0015 / ADR-0036 V2-2 (finding 3): reseed test roots to the
        // `is_test_root == true` FUNCTION nodes (the persisted `#[test]`/
        // `#[tokio::test]` AST bit), NOT the `tests` MODULE node. Under the
        // directed `Calls` walk with `Contains` dropped, a `tests` module reaches
        // NOTHING (module → `#[test]` fn is a `Contains` edge, dropped), so
        // seeding the module node would false-residual every test-only helper.
        // Seeding the real test FUNCTIONS lets the forward `Calls` walk reach the
        // helpers they exercise → TestOnly (never residual/Suspected/SafeDelete).
        all_nodes
            .iter()
            .filter(|node| {
                symbol_kind_has_role(&node.kind, SymbolRole::Callable) && node.is_test_root
            })
            .map(|node| node.memory_id)
            .collect()
    }
}

/// Whether a Go graph node is an exported top-level API root (WU-0023 P3b —
/// DEC-R8-PUBAPI, importability-aware).
///
/// Go's exported (capitalized-first-rune) top-level identifiers self-seed as
/// PublicApi roots. Unlike Rust's inline `is_api_kind`, this INCLUDES
/// `const`/`static`: a Go exported package-level `const`/`var` is public API. The
/// const/static addition is LANGUAGE-GATED to Go here (never added to the shared
/// Rust `matches!`) — the Rust extractor also emits `const`/`static` kinds, so a
/// shared addition would seed caller-less Rust pub const/static as pub-api roots
/// and downgrade them to Suspected (skipping the Pass-5 Structural rescue),
/// tripping the RUST NO-REGRESSION falsifier. `visibility == "pub"` already
/// matches Go exports (the Go extractor maps a capitalized first rune → Public).
fn go_is_pub_api_root(node: &crate::graph::GraphNode) -> bool {
    let is_api_kind = matches!(
        node.kind.as_str(),
        "function" | "struct" | "enum" | "trait" | "type_alias" | "module" | "const" | "static"
    );
    let is_public = node.visibility == "pub";
    let is_test_module = node.kind == "module"
        && (node.symbol_name == "tests" || node.symbol_name.ends_with("::tests"));
    is_api_kind && is_public && !is_test_module
}

// ---------------------------------------------------------------------------
// Helper: recursive .rs file collection for orphan detection
// ---------------------------------------------------------------------------

/// Recursively collect `.rs` files and check if they appear in the graph.
fn collect_rs_files_recursive(
    dir: &Path,
    workspace_root: &Path,
    graph_files: &HashSet<String>,
    orphans: &mut Vec<String>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files_recursive(&path, workspace_root, graph_files, orphans);
        } else if path.extension().is_some_and(|e| e == "rs") {
            // Skip common non-module files.
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            if file_name == "build.rs" {
                continue;
            }

            // Convert to relative path for comparison against graph file paths.
            let relative = path
                .strip_prefix(workspace_root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            // Check if this file appears in the graph.
            let in_graph = graph_files
                .iter()
                .any(|gf| gf == &relative || relative.ends_with(gf) || gf.ends_with(&relative));

            if !in_graph {
                orphans.push(relative);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RC4 — the one classify-writeback chokepoint (WU-0003 / CL-REACH / ADR-0028)
// ---------------------------------------------------------------------------

/// The SOLE reachability writer: discover entry points, classify every node,
/// and write each node's [`ReachabilityClass`] back into the graph.
///
/// This is the **RC4 chokepoint** (ADR-0028). Every production code path that
/// persists the knowledge graph routes through this function *before* the save,
/// so no production save can persist an unclassified or stale-classification
/// graph. It standardizes the whole tree on [`ReachabilityAnalyzer::analyze_with_orphans`]
/// (the reindex copies previously used plain `analyze()`, a divergent surface
/// this collapses).
///
/// The function is **synchronous** (entry-point discovery is `std::fs`,
/// classification is CPU-bound, write-back is in-memory). Async callers wrap it
/// in [`tokio::task::spawn_blocking`]; the synchronous shutdown path can call it
/// directly inside its own blocking section.
///
/// Entry-point discovery failure is a **hard error** ([`EntryPointError`]) — the
/// previous swallow (`let _ = save_snapshot(...)`) and the non-fatal index-pipeline
/// warn are replaced by propagation, so a save can never silently persist an
/// unclassified graph because discovery failed (ADR-0028 OQ-2).
///
/// Returns the full [`ReachabilityReport`] so callers that need the analysis
/// output (trace, JSON, fail-on-dead/orphan thresholds, distribution counts) can
/// reuse it without re-running the analysis.
pub fn classify_and_writeback(
    graph: &mut KnowledgeGraph,
    workspace_root: &Path,
) -> Result<ReachabilityReport, crate::entry_points::EntryPointError> {
    classify_and_writeback_core(graph, workspace_root).map(|(report, _)| report)
}

/// Classify and write back while retaining the complete generation-local
/// evidence needed by read-only reachability consumers.
pub fn classify_and_writeback_with_evidence(
    graph: &mut KnowledgeGraph,
    workspace_root: &Path,
) -> Result<ReachabilityEvidence, ReachabilityEvidenceError> {
    let entry_points = crate::entry_points::discover_entry_points(workspace_root)?;
    let classified_documents = registered_graph_documents(graph);
    let report = analyze_and_writeback(graph, workspace_root, &entry_points, false, None);
    ReachabilityEvidence::from_analysis(
        graph,
        workspace_root,
        report,
        entry_points,
        classified_documents,
    )
}

/// Classify one indexing generation from the exact project inventory that also
/// authorizes provider execution and publication.
///
/// Unlike [`classify_and_writeback_with_evidence`], this does not require the
/// repository root itself to be a Cargo workspace or Go module. Independent
/// nested project units remain first-class while reachability uses the same
/// indexed source ownership boundary as the rest of the generation.
pub fn classify_and_writeback_with_inventory_evidence(
    graph: &mut KnowledgeGraph,
    workspace_root: &Path,
    inventory: &crate::code_intel_domain::ProjectInventory,
) -> Result<Option<ReachabilityEvidence>, ReachabilityEvidenceError> {
    let plan =
        match crate::entry_points::discover_entry_points_from_inventory(workspace_root, inventory)?
        {
            crate::entry_points::InventoryEntryPointDiscovery::Available(plan) => plan,
            crate::entry_points::InventoryEntryPointDiscovery::Unavailable => {
                // A graph reused from an earlier generation may carry valid old
                // classifications. Once no registered reachability owner covers
                // the current inventory, those classifications are no longer
                // authoritative and must not survive structural publication.
                let node_ids = graph
                    .all_nodes()
                    .into_iter()
                    .map(|node| node.memory_id)
                    .collect::<Vec<_>>();
                for node_id in node_ids {
                    if let Some(node) = graph.node_mut(&node_id) {
                        node.reachability_class = ReachabilityClass::Unclassified;
                    }
                }
                return Ok(None);
            }
        };
    let report = analyze_and_writeback(
        graph,
        workspace_root,
        &plan.entry_points,
        false,
        Some(&plan.classified_documents),
    );
    ReachabilityEvidence::from_analysis(
        graph,
        workspace_root,
        report,
        plan.entry_points,
        plan.classified_documents,
    )
    .map(Some)
}

fn classify_and_writeback_core(
    graph: &mut KnowledgeGraph,
    workspace_root: &Path,
) -> Result<(ReachabilityReport, Vec<EntryPoint>), crate::entry_points::EntryPointError> {
    // Entry-point discovery (std::fs). A failure here is fatal — a save must
    // never persist an unclassified graph because discovery was skipped.
    let entry_points = crate::entry_points::discover_entry_points(workspace_root)?;

    let report = analyze_and_writeback(graph, workspace_root, &entry_points, true, None);

    Ok((report, entry_points))
}

fn analyze_and_writeback(
    graph: &mut KnowledgeGraph,
    workspace_root: &Path,
    entry_points: &[EntryPoint],
    include_test_chains: bool,
    classified_documents: Option<&[String]>,
) -> ReachabilityReport {
    // The analyzer borrows `graph` immutably; scope it so the borrow is released
    // before the `node_mut` write-back below. `analyze_with_orphans` is the
    // standardized entry point (orphan-file detection + per-node verdict).
    let report = {
        let analyzer = classified_documents.map_or_else(
            || ReachabilityAnalyzer::new(graph, entry_points.to_vec()),
            |documents| {
                ReachabilityAnalyzer::for_classified_documents(
                    graph,
                    entry_points.to_vec(),
                    documents.iter().cloned(),
                )
            },
        );
        if include_test_chains {
            analyzer.analyze_with_orphans(workspace_root)
        } else {
            analyzer.analyze_with_orphans_for_persistence(workspace_root)
        }
    };

    for classified in &report.classified {
        if let Some(node) = graph.node_mut(&classified.memory_id) {
            node.reachability_class = classified.classification;
        }
    }
    report
}

fn registered_graph_documents(graph: &KnowledgeGraph) -> Vec<String> {
    graph
        .all_nodes()
        .into_iter()
        .filter(|node| crate::graph_stats::node_language(node).is_some())
        .map(|node| node.file_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

// ---------------------------------------------------------------------------
// OBS-1 reload chokepoint (ADR-0029)
// ---------------------------------------------------------------------------

/// Error from the post-index reload chokepoint
/// [`reload_reclassify_save`].
///
/// Distinguishes the three ways a post-index snapshot reload can fail, so each
/// caller can `.map_err` into its local error type and surface the failure
/// instead of silently reporting a SUCCESS computed from a stale graph
/// (the OBS-1 silent-swallow class this closes — ADR-0029).
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// The redb snapshot load itself failed (lock/permission/IO/corruption at
    /// the redb header level — a `begin_read`/decode error surfaced as `Err`).
    #[error("graph snapshot reload failed: {0}")]
    Store(#[from] crate::graph_store::GraphStoreError),

    /// Entry-point discovery or reachability classification failed.
    #[error("reachability classification failed: {0}")]
    Classify(#[from] crate::entry_points::EntryPointError),

    /// The classify/save `spawn_blocking` task panicked or was cancelled.
    #[error("reload task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// The post-index snapshot reload returned no graph. Because callers MUST
    /// pass `Some(store)` to `IndexPipeline::run` (which persists a snapshot
    /// unconditionally on success), an `Ok(None)` here means the freshly
    /// written snapshot failed to load — i.e. corruption, a REAL failure, NOT
    /// genuine absence (ADR-0029).
    #[error(
        "post-index snapshot reload returned no graph (freshly written snapshot failed to load — likely corruption)"
    )]
    EmptyAfterIndex,
}

/// Reload the persisted graph snapshot, re-run reachability classification, and
/// write the classified graph back to the store — the SINGLE OBS-1 reload
/// chokepoint (ADR-0029).
///
/// This collapses the three structurally-identical inline reload gates
/// (`code_intel.rs` MCP reindex, `h00ligan.rs` index, `graph_cmd.rs` reindex)
/// into one composition so the omitted-failure-arm bug is *unrepresentable*:
/// there is no per-site arm to forget, and every failure mode maps to a
/// [`ReloadError`] the caller surfaces.
///
/// # Behavior
///
/// - `Ok(Some(g))` from [`GraphStore::load_snapshot`](crate::graph_store::GraphStore::load_snapshot)
///   → [`classify_and_writeback`] + [`save_snapshot_sync`](crate::graph_store::GraphStore::save_snapshot_sync)
///   (in one `spawn_blocking`, off the async executor) → `Ok(g)`.
/// - `Ok(None)` → [`ReloadError::EmptyAfterIndex`] (post-index, this means the
///   just-written snapshot failed to load → corruption, a real failure).
/// - `Err(e)` → [`ReloadError::Store`].
///
/// # Precondition (load-bearing)
///
/// Callers MUST have just run the index pipeline with `Some(store)`
/// (`IndexPipeline::run`), so a fresh snapshot is guaranteed to have been
/// persisted on success. `save_snapshot` writes `latest` and stamps
/// `SCHEMA_VERSION` unconditionally, so post-index the ONLY `Ok(None)` arms are
/// the corruption arms — hence treating `Ok(None)` as `EmptyAfterIndex` is
/// sound. Calling this WITHOUT a preceding successful index would mis-report a
/// genuinely-absent snapshot as corruption.
///
/// # Async shape
///
/// Two hops: [`load_snapshot`](crate::graph_store::GraphStore::load_snapshot)
/// is itself `async` with its own internal `spawn_blocking`, so it cannot be
/// nested inside this fn's `spawn_blocking`. We `await` the load first, then run
/// the CPU-bound classify + the blocking save in a SECOND `spawn_blocking`.
pub async fn reload_reclassify_save(
    store: &crate::graph_store::GraphStore,
    root: &Path,
) -> Result<KnowledgeGraph, ReloadError> {
    let opt = store.load_snapshot().await?;
    match opt {
        Some(g) => {
            let store2 = store.clone();
            let root2 = root.to_path_buf();
            tokio::task::spawn_blocking(move || -> Result<KnowledgeGraph, ReloadError> {
                let mut g = g;
                classify_and_writeback(&mut g, &root2)?;
                store2.save_snapshot_sync(&g)?;
                // ADR-0033 ROOT-8 (belt-and-suspenders): re-stamp the workspace
                // origin in the SAME blocking write as the save, so NO persisted
                // graph can ever lack a matching origin stamp regardless of caller
                // path. `set_origin` is async and cannot be awaited inside this
                // `spawn_blocking`; `set_origin_sync` canonicalizes `root2` and
                // overwrites GRAPH_ORIGIN synchronously.
                store2.set_origin_sync(&root2)?;
                // ADR-0046 D1 + rev-3 A1: stamp WHO classified, beside the
                // origin stamp. The sync sibling, for the same reason
                // `set_origin_sync` is used here — the async form cannot be
                // awaited inside this `spawn_blocking`.
                //
                // PRESERVING, not asserting: this chokepoint re-classifies an
                // ALREADY-BUILT graph and never re-runs SCIP, so it genuinely
                // changed WHO classified and genuinely did not change what the
                // index was generated under. Writing this binary's would-be
                // config here would ERASE a differing prior value — silently
                // converting a detectable mismatch into a false match.
                store2.set_classified_by_sync()?;
                Ok(g)
            })
            .await?
        }
        None => Err(ReloadError::EmptyAfterIndex),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdge, GraphNode, KnowledgeGraph};
    use std::path::PathBuf;

    fn make_node(name: &str, kind: &str, file_path: &str) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.to_string(),
            kind: kind.to_string(),
            file_path: file_path.to_string(),
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

    /// PERFORMANCE FALSIFIER: census membership is a file-level fact, so one
    /// analysis must evaluate it once per distinct file path, not once per
    /// symbol node (which would repeat canonicalization for every symbol).
    #[test]
    fn census_scope_is_evaluated_once_per_distinct_file() {
        let mut graph = KnowledgeGraph::new();
        for index in 0..1_024 {
            graph
                .add_node(make_node(
                    &format!("symbol_{index}"),
                    "function",
                    "src/lib.rs",
                ))
                .expect("unique fixture node");
        }
        let scope = CensusScope::with_parts(None, None, vec!["vendor".into()]);
        let analyzer = ReachabilityAnalyzer::new(&graph, Vec::new());

        reset_census_scope_evaluations();
        let report = analyzer.analyze_scoped(&scope);
        let evaluations = census_scope_evaluations();

        assert_eq!(report.classified.len(), 1_024, "positive node population");
        assert_eq!(report.summary.excluded, 0, "positive in-scope control");
        assert_eq!(
            evaluations, 1,
            "one shared source file triggered {evaluations} census evaluations"
        );
    }

    #[test]
    fn root_library_entry_point_has_a_canonical_persisted_path() {
        assert_eq!(
            normalize_entry_point_path(&EntryPointKind::LibRoot, Path::new(""))
                .expect("repository-root library directory"),
            ""
        );
        let error = normalize_entry_point_path(&EntryPointKind::Binary, Path::new(""))
            .expect_err("a binary entry point must name its source file");
        assert!(error.to_string().contains("entry-point path is empty"));
    }

    #[test]
    fn root_go_library_classification_persists_its_repository_directory() {
        let workspace = tempfile::tempdir().expect("Go fixture workspace");
        std::fs::write(
            workspace.path().join("go.mod"),
            "module example.test/rootlib\n\ngo 1.26\n",
        )
        .expect("Go module");
        std::fs::write(
            workspace.path().join("api.go"),
            "package rootlib\n\nfunc Exported() {}\n",
        )
        .expect("Go source");
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(make_node_vis("Exported", "function", "api.go", "pub"))
            .expect("Go graph node");

        let evidence = classify_and_writeback_with_evidence(&mut graph, workspace.path())
            .expect("classify root-level Go library");
        assert_eq!(evidence.entry_points.len(), 1);
        assert_eq!(evidence.entry_points[0].kind, EntryPointKind::LibRoot);
        assert_eq!(evidence.entry_points[0].file_path, "");
        evidence
            .validate(&graph)
            .expect("validate root-level Go reachability evidence");
    }

    #[test]
    fn go_init_function_is_a_production_root() {
        let mut graph = KnowledgeGraph::new();
        let init = make_node_vis("init", "function", "root.go", "private");
        let initialize = make_node_vis("initialize", "function", "root.go", "private");
        let exported = make_node_vis("Exported", "function", "api.go", "pub");
        let (init_id, initialize_id) = (init.memory_id, initialize.memory_id);
        for node in [init, initialize, exported] {
            graph.add_node(node).expect("Go graph node");
        }
        graph
            .add_edge(init_id, initialize_id, calls_edge())
            .expect("Go init call");
        let entry_point = EntryPoint {
            name: "rootlib".into(),
            kind: EntryPointKind::LibRoot,
            file_path: PathBuf::new(),
            crate_name: "example.test/rootlib".into(),
        };

        let report = ReachabilityAnalyzer::new(&graph, vec![entry_point]).analyze();
        let classification = |name: &str| {
            report
                .classified
                .iter()
                .find(|node| node.symbol_name == name)
                .unwrap_or_else(|| panic!("classified Go symbol {name}"))
                .classification
        };
        assert_eq!(classification("init"), ReachabilityClass::Wired);
        assert_eq!(classification("initialize"), ReachabilityClass::Wired);
    }

    #[test]
    fn build_script_main_is_a_production_root_without_seeding_its_siblings() {
        let mut graph = KnowledgeGraph::new();
        let build_main = make_node_vis("main", "function", "build.rs", "private");
        let generated = make_node_vis("generate_bindings", "function", "build.rs", "private");
        let unused = make_node_vis("unused_build_helper", "function", "build.rs", "private");
        let (build_main_id, generated_id, unused_id) =
            (build_main.memory_id, generated.memory_id, unused.memory_id);
        for node in [build_main, generated, unused] {
            graph.add_node(node).expect("build-script graph node");
        }
        graph
            .add_edge(build_main_id, generated_id, calls_edge())
            .expect("build-script call");
        let entry_point = EntryPoint {
            name: "build".into(),
            kind: EntryPointKind::BuildScript,
            file_path: PathBuf::from("/workspace/build.rs"),
            crate_name: "fixture".into(),
        };

        assert_eq!(
            crate::graph_query::resolve_production_root_ids(
                &graph,
                std::slice::from_ref(&entry_point),
            ),
            vec![build_main_id],
            "persisted trace roots must use the same build-script entry authority"
        );
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![entry_point]);
        let roots = analyzer.resolved_roots();
        assert_eq!(roots.production, vec![build_main_id]);
        let report = analyzer.analyze();
        let class = |id| {
            report
                .classified
                .iter()
                .find(|node| node.memory_id == id)
                .expect("classified build-script node")
                .classification
        };
        assert_eq!(class(build_main_id), ReachabilityClass::Wired);
        assert_eq!(class(generated_id), ReachabilityClass::Wired);
        assert_ne!(
            class(unused_id),
            ReachabilityClass::Wired,
            "recognizing build.rs must not seed every sibling function in the file"
        );
    }

    /// Like `make_node`, but sets an explicit visibility string (e.g. "pub",
    /// "pub(crate)", "private"). The pub-api seed gate (CL-REACH-11) keys on
    /// `visibility == "pub"`, so tests that exercise PublicApi seeding must set
    /// a real visibility rather than the empty default `make_node` produces.
    fn make_node_vis(name: &str, kind: &str, file_path: &str, visibility: &str) -> GraphNode {
        GraphNode {
            visibility: visibility.to_string(),
            ..make_node(name, kind, file_path)
        }
    }

    fn calls_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Calls,
            ..GraphEdge::default()
        }
    }

    fn contains_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Contains,
            ..GraphEdge::default()
        }
    }

    #[test]
    fn empty_graph_all_dead() {
        let graph = KnowledgeGraph::new();
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![]);
        let report = analyzer.analyze();

        assert_eq!(report.summary.total, 0);
        assert_eq!(report.summary.dead, 0);
        assert_eq!(report.summary.wired, 0);
    }

    #[test]
    fn single_node_no_entry_point_is_suspected() {
        let mut graph = KnowledgeGraph::new();
        let node = make_node("orphan_fn", "function", "src/orphan.rs");
        graph.add_node(node).unwrap();

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![]);
        let report = analyzer.analyze();

        // WU-0015 REBASELINE (Dead → Suspected): Leg 1 emits NO Dead — a
        // call-unreachable residual is a non-delete Suspected review candidate.
        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.dead, 0);
        assert_eq!(report.summary.suspected, 1);
        assert_eq!(report.summary.wired, 0);
    }

    #[test]
    fn wired_through_call_chain() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let helper = make_node("helper", "function", "src/lib.rs");
        let deep = make_node("deep", "function", "src/lib.rs");
        let unrelated = make_node("unrelated", "function", "src/other.rs");

        let main_id = main_node.memory_id;
        let helper_id = helper.memory_id;
        let deep_id = deep.memory_id;

        graph.add_node(main_node).unwrap();
        graph.add_node(helper).unwrap();
        graph.add_node(deep).unwrap();
        graph.add_node(unrelated).unwrap();

        graph.add_edge(main_id, helper_id, calls_edge()).unwrap();
        graph.add_edge(helper_id, deep_id, calls_edge()).unwrap();

        // Create an entry point matching src/main.rs.
        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        assert_eq!(
            report.summary.wired, 3,
            "main + helper + deep should be wired"
        );
        // WU-0015 REBASELINE (Dead → Suspected).
        assert_eq!(report.summary.dead, 0);
        assert_eq!(report.summary.suspected, 1, "unrelated should be suspected");

        // Verify specific classifications.
        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        assert_eq!(find("main").classification, ReachabilityClass::Wired);
        assert_eq!(find("helper").classification, ReachabilityClass::Wired);
        assert_eq!(find("deep").classification, ReachabilityClass::Wired);
        assert_eq!(
            find("unrelated").classification,
            ReachabilityClass::Suspected
        );
    }

    #[test]
    fn test_module_classified_as_test_only() {
        // WU-0015 REBASELINE: test roots reseed to the `is_test_root` `#[test]`
        // FUNCTION nodes (not the `tests` MODULE node); the forward `Calls` walk
        // from the test fn reaches its helper → both TestOnly. The `tests` module
        // node has no incoming `Calls`/`References` edge so it is never
        // call-reached; WU-0019 REBASELINE: the container roll-up then lifts it to
        // its most-alive `Contains`-child tier (TestOnly) — restoring the
        // classification this test's name promises (pre-WU-0019 it was Suspected).
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let tests_mod = make_node("tests", "module", "src/lib.rs");
        let mut test_fn = make_node("t", "function", "src/lib.rs");
        test_fn.is_test_root = true;
        let test_helper = make_node("test_helper", "function", "src/lib.rs");

        let tests_id = tests_mod.memory_id;
        let test_fn_id = test_fn.memory_id;
        let helper_id = test_helper.memory_id;

        graph.add_node(main_node).unwrap();
        graph.add_node(tests_mod).unwrap();
        graph.add_node(test_fn).unwrap();
        graph.add_node(test_helper).unwrap();

        // tests module contains the test fn; the test fn CALLS the helper.
        graph
            .add_edge(tests_id, test_fn_id, contains_edge())
            .unwrap();
        graph.add_edge(test_fn_id, helper_id, calls_edge()).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };
        assert_eq!(
            find("t").classification,
            ReachabilityClass::TestOnly,
            "the #[test] fn is a test root"
        );
        assert_eq!(
            find("test_helper").classification,
            ReachabilityClass::TestOnly,
            "the helper is reached from the test fn via Calls"
        );
        // WU-0019: the `tests` MODULE owns a TestOnly child (`t`) via `Contains`,
        // so the container roll-up reclassifies it to its most-alive child tier
        // (TestOnly), NOT a blanket clean tier — the module is structurally
        // required by the test code. This is the private-module analogue of the
        // pub-mod-with-test-only-content rescue.
        assert_eq!(
            find("tests").classification,
            ReachabilityClass::TestOnly,
            "the tests module rolls up to its TestOnly content (matching this test's name)"
        );
        assert_eq!(
            report.summary.test_only, 3,
            "test fn + helper + the rolled-up tests module"
        );
        assert_eq!(report.summary.wired, 1, "only main is wired");
    }

    #[test]
    fn related_to_edges_not_traversed() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let related = make_node("related_fn", "function", "src/related.rs");

        let main_id = main_node.memory_id;
        let related_id = related.memory_id;

        graph.add_node(main_node).unwrap();
        graph.add_node(related).unwrap();

        // RelatedTo edge should NOT make related_fn wired.
        let related_edge = GraphEdge {
            kind: EdgeKind::RelatedTo,
            ..GraphEdge::default()
        };
        graph.add_edge(main_id, related_id, related_edge).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        assert_eq!(report.summary.wired, 1, "only main via entry point");
        // WU-0015 REBASELINE (Dead → Suspected): RelatedTo is still not traversed,
        // so related_fn is call-unreachable → Suspected (never Dead in Leg 1).
        assert_eq!(report.summary.dead, 0);
        assert_eq!(
            report.summary.suspected, 1,
            "related_fn should be suspected"
        );
    }

    #[test]
    fn report_serialization_roundtrip() {
        let report = ReachabilityReport {
            classified: vec![ClassifiedNode {
                memory_id: Uuid::new_v4(),
                symbol_name: "test_fn".to_string(),
                file_path: "src/lib.rs".to_string(),
                kind: "function".to_string(),
                classification: ReachabilityClass::Wired,
                has_retain_attr: false,
                has_uncaptured_items: false,
            }],
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
            entry_points_used: vec!["example-bin (example-crate)".to_string()],
            orphan_files: vec![],
            test_chains: BTreeMap::new(),
        };

        let json = serde_json::to_string(&report).expect("serialize");
        let deser: ReachabilityReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.summary.total, 1);
        assert_eq!(deser.summary.wired, 1);
        assert_eq!(deser.classified[0].classification, ReachabilityClass::Wired);
    }

    #[test]
    fn pub_api_roots_identified_for_lib_crates() {
        let mut graph = KnowledgeGraph::new();

        let lib_fn = make_node_vis(
            "public_fn",
            "function",
            "crates/h00ligan-engine/src/search.rs",
            "pub",
        );
        let tests_mod = make_node("tests", "module", "crates/h00ligan-engine/src/search.rs");

        graph.add_node(lib_fn).unwrap();
        graph.add_node(tests_mod).unwrap();

        let ep = EntryPoint {
            name: "h00ligan-engine".to_string(),
            kind: EntryPointKind::LibRoot,
            file_path: PathBuf::from("/workspace/crates/h00ligan-engine/src/lib.rs"),
            crate_name: "h00ligan-engine".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        // public_fn should be PUBLIC_API, tests module should be TEST_ONLY.
        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        // WU-0015 REBASELINE (V3-1): `public_fn` is SEEDED as a pub-api root, but
        // with zero real callers it classifies Suspected (not PublicApi-by-fiat).
        assert_eq!(
            find("public_fn").classification,
            ReachabilityClass::Suspected
        );
        // The `tests` module node is a `module`-kind structural node; Pass 5 runs
        // BEFORE the V3-1 downgrade (item 10), so at that point `public_fn` is
        // still PublicApi → search.rs is an ALIVE file → the module decl is
        // rescued to Structural (a compile-time wiring artifact, non-delete).
        assert_eq!(find("tests").classification, ReachabilityClass::Structural);
    }

    // RED on HEAD before CL-REACH-11: a private no-caller top-level lib item
    // self-seeds as PublicApi (Pass-2 `resolve_pub_api_roots` ignored
    // visibility), so it classified PublicApi, not Dead. GREEN after gating the
    // seed on `visibility == "pub"`.
    #[test]
    fn cl_reach_11_private_no_caller_lib_item_is_dead_not_pub_api() {
        let mut graph = KnowledgeGraph::new();

        // Two top-level fns in a lib file, NEITHER with any caller. They differ
        // ONLY by visibility.
        let private_fn = make_node_vis(
            "private_orphan",
            "function",
            "crates/h00ligan-engine/src/search.rs",
            "private",
        );
        // CONTROL: a real `pub` item with no caller MUST still be PublicApi.
        let public_fn = make_node_vis(
            "public_api_fn",
            "function",
            "crates/h00ligan-engine/src/search.rs",
            "pub",
        );

        graph.add_node(private_fn).unwrap();
        graph.add_node(public_fn).unwrap();

        let ep = EntryPoint {
            name: "h00ligan-engine".to_string(),
            kind: EntryPointKind::LibRoot,
            file_path: PathBuf::from("/workspace/crates/h00ligan-engine/src/lib.rs"),
            crate_name: "h00ligan-engine".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        // WU-0015 Leg-3b REBASELINE: a PRIVATE no-caller lib item is
        // call-unreachable → Dead (the visibility-gated residual sweep promotes the
        // private residual). It still does NOT self-seed as PublicApi (the
        // visibility gate on SEEDING is intact) — but the residual tier is now Dead.
        assert_eq!(
            find("private_orphan").classification,
            ReachabilityClass::Dead,
            "private no-caller lib item → Dead (never self-seeded PublicApi)"
        );

        // WU-0015 REBASELINE: a `pub` item is SEEDED as a PublicApi root, but V3-1
        // classifies it PublicApi-clean ONLY with a real caller. A pub no-caller
        // item → Suspected (the external-API-vs-wiring-gap review candidate),
        // reconciling the census surfacing without false-DEADing the pub surface.
        assert_eq!(
            find("public_api_fn").classification,
            ReachabilityClass::Suspected,
            "pub no-caller lib item → Suspected under the V3-1 split"
        );
    }

    // -----------------------------------------------------------------------
    // ActionTier + grouping + baseline tests
    // -----------------------------------------------------------------------

    fn make_classified(
        name: &str,
        kind: &str,
        file_path: &str,
        class: ReachabilityClass,
    ) -> ClassifiedNode {
        ClassifiedNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.to_string(),
            file_path: file_path.to_string(),
            kind: kind.to_string(),
            classification: class,
            has_retain_attr: false,
            has_uncaptured_items: false,
        }
    }

    fn sample_report() -> ReachabilityReport {
        ReachabilityReport {
            classified: vec![
                make_classified("main", "function", "src/main.rs", ReachabilityClass::Wired),
                make_classified("run", "function", "src/main.rs", ReachabilityClass::Wired),
                make_classified(
                    "Config",
                    "struct",
                    "src/config.rs",
                    ReachabilityClass::PublicApi,
                ),
                make_classified(
                    "test_foo",
                    "function",
                    "src/lib.rs",
                    ReachabilityClass::TestOnly,
                ),
                make_classified("dead_fn", "function", "src/old.rs", ReachabilityClass::Dead),
                make_classified(
                    "stale_fn",
                    "function",
                    "src/old.rs",
                    ReachabilityClass::Dead,
                ),
            ],
            summary: ReachabilitySummary {
                total: 6,
                wired: 2,
                public_api: 1,
                structural: 0,
                test_only: 1,
                dead: 2,
                orphan_files: 1,
                suspected: 0,
                excluded: 0,
            },
            entry_points_used: vec!["main".to_string()],
            orphan_files: vec!["src/orphan.rs".to_string()],
            test_chains: BTreeMap::new(),
        }
    }

    #[test]
    fn action_tier_mapping() {
        assert_eq!(ReachabilityClass::Wired.action_tier(), ActionTier::Healthy);
        assert_eq!(
            ReachabilityClass::PublicApi.action_tier(),
            ActionTier::Healthy
        );
        assert_eq!(
            ReachabilityClass::Structural.action_tier(),
            ActionTier::Healthy
        );
        assert_eq!(
            ReachabilityClass::TestOnly.action_tier(),
            ActionTier::Review
        );
        // WU-0016 / ADR-0039: Dead/Orphan collapse into the Review tier
        // (auto-delete tier removed — static analysis is advisory).
        assert_eq!(ReachabilityClass::Dead.action_tier(), ActionTier::Review);
        assert_eq!(ReachabilityClass::Orphan.action_tier(), ActionTier::Review);
    }

    #[test]
    fn grouped_by_file_groups_correctly() {
        let report = sample_report();
        let by_file = report.grouped_by_file();

        assert_eq!(by_file.len(), 4); // main.rs, config.rs, lib.rs, old.rs
        assert_eq!(by_file["src/main.rs"].len(), 2);
        assert_eq!(by_file["src/old.rs"].len(), 2);
        assert_eq!(by_file["src/config.rs"].len(), 1);
        assert_eq!(by_file["src/lib.rs"].len(), 1);
    }

    #[test]
    fn grouped_by_action_groups_correctly() {
        let report = sample_report();
        let by_action = report.grouped_by_action();

        assert_eq!(by_action[&ActionTier::Healthy].len(), 3); // 2 Wired + 1 PublicApi
        // WU-0016 / ADR-0039: Dead collapses into Review (auto-delete tier gone).
        assert_eq!(by_action[&ActionTier::Review].len(), 3); // 1 TestOnly + 2 Dead
    }

    #[test]
    fn nodes_with_class_filters_correctly() {
        let report = sample_report();
        let dead = report.nodes_with_class(ReachabilityClass::Dead);
        assert_eq!(dead.len(), 2);
        assert!(
            dead.iter()
                .all(|n| n.classification == ReachabilityClass::Dead)
        );
    }

    #[test]
    fn class_percentages_correct() {
        let report = sample_report();
        let pcts = report.class_percentages();

        let wired_pct = pcts[&ReachabilityClass::Wired];
        let dead_pct = pcts[&ReachabilityClass::Dead];
        // 2 of 6 = 33.33...%
        assert!((wired_pct - 33.333).abs() < 0.01);
        assert!((dead_pct - 33.333).abs() < 0.01);
    }

    #[test]
    fn class_percentages_empty_report() {
        let report = ReachabilityReport {
            classified: vec![],
            summary: ReachabilitySummary {
                total: 0,
                wired: 0,
                public_api: 0,
                structural: 0,
                test_only: 0,
                dead: 0,
                orphan_files: 0,
                suspected: 0,
                excluded: 0,
            },
            entry_points_used: vec![],
            orphan_files: vec![],
            test_chains: BTreeMap::new(),
        };
        assert!(report.class_percentages().is_empty());
    }

    #[test]
    fn baseline_from_report_roundtrip() {
        let report = sample_report();
        let baseline = ReachabilityBaseline::from_report(&report, Some("abc123".to_string()));

        assert_eq!(baseline.git_commit.as_deref(), Some("abc123"));
        assert_eq!(baseline.dead_symbols.len(), 2);
        assert_eq!(baseline.orphan_files.len(), 1);
        assert_eq!(baseline.summary.total, 6);

        // Save and reload
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("baseline.json");
        baseline.save(&path).expect("save");
        let loaded = ReachabilityBaseline::load(&path).expect("load");

        assert_eq!(loaded.git_commit, baseline.git_commit);
        assert_eq!(loaded.dead_symbols, baseline.dead_symbols);
        assert_eq!(loaded.orphan_files, baseline.orphan_files);
        assert_eq!(loaded.summary.total, baseline.summary.total);
    }

    #[test]
    fn baseline_diff_detects_regression() {
        let report_v1 = sample_report();
        let baseline = ReachabilityBaseline::from_report(&report_v1, Some("v1".to_string()));

        // Create v2 with one more dead symbol.
        let mut report_v2 = sample_report();
        report_v2.classified.push(make_classified(
            "new_dead",
            "function",
            "src/new.rs",
            ReachabilityClass::Dead,
        ));
        report_v2.orphan_files.push("src/new_orphan.rs".to_string());

        let diff = baseline.diff(&report_v2);

        assert_eq!(diff.dead_delta, 1);
        assert_eq!(diff.orphan_delta, 1);
        assert_eq!(diff.new_dead.len(), 1);
        assert!(diff.resolved_dead.is_empty());
        assert_eq!(diff.new_orphans.len(), 1);
        assert!(diff.resolved_orphans.is_empty());
        assert!(diff.is_regression());
        assert!(diff.exceeds_threshold(0));
        assert!(!diff.exceeds_threshold(1));
    }

    #[test]
    fn baseline_diff_detects_resolution() {
        let report_v1 = sample_report();
        let baseline = ReachabilityBaseline::from_report(&report_v1, None);

        // Create v2 where dead_fn is now wired (resolved).
        let mut report_v2 = sample_report();
        report_v2.classified.retain(|n| n.symbol_name != "dead_fn");
        report_v2.classified.push(make_classified(
            "dead_fn",
            "function",
            "src/old.rs",
            ReachabilityClass::Wired,
        ));
        report_v2.orphan_files.clear();

        let diff = baseline.diff(&report_v2);

        assert_eq!(diff.dead_delta, -1);
        assert_eq!(diff.orphan_delta, -1);
        assert!(diff.new_dead.is_empty());
        assert_eq!(diff.resolved_dead.len(), 1);
        assert_eq!(diff.resolved_orphans.len(), 1);
        assert!(!diff.is_regression());
    }

    // -----------------------------------------------------------------------
    // Structural reclassification tests
    // -----------------------------------------------------------------------

    #[test]
    fn use_node_in_wired_file_becomes_structural() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let use_node = make_node("std::io", "use", "src/main.rs");

        let _main_id = main_node.memory_id;
        graph.add_node(main_node).unwrap();
        graph.add_node(use_node).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        assert_eq!(find("main").classification, ReachabilityClass::Wired);
        assert_eq!(
            find("std::io").classification,
            ReachabilityClass::Structural
        );
        assert_eq!(report.summary.structural, 1);
        // Structural should NOT be counted as dead
        assert_eq!(report.summary.dead, 0);
    }

    #[test]
    fn const_node_in_wired_file_becomes_structural() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let const_node = make_node("MAX_SIZE", "const", "src/main.rs");

        graph.add_node(main_node).unwrap();
        graph.add_node(const_node).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        assert_eq!(
            find("MAX_SIZE").classification,
            ReachabilityClass::Structural
        );
        assert_eq!(report.summary.structural, 1);
        assert_eq!(report.summary.dead, 0);
    }

    #[test]
    fn use_node_in_dead_only_file_stays_dead() {
        let mut graph = KnowledgeGraph::new();

        // A file with no wired functions -- only dead code.
        let dead_fn = make_node("dead_fn", "function", "src/unused.rs");
        let use_node = make_node("std::collections", "use", "src/unused.rs");

        graph.add_node(dead_fn).unwrap();
        graph.add_node(use_node).unwrap();

        // No entry points that reach src/unused.rs
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        // WU-0015 REBASELINE (Dead → Suspected): the Pass-5 structural rescue only
        // fires in ALIVE files, so a `use` in a dead-only file is NOT rescued to
        // Structural; both nodes are call-unreachable residual → Suspected (Leg 1
        // emits no Dead). The anti-over-rescue intent (no Structural here) holds.
        assert_eq!(find("dead_fn").classification, ReachabilityClass::Suspected);
        assert_eq!(
            find("std::collections").classification,
            ReachabilityClass::Suspected
        );
        assert_eq!(report.summary.structural, 0);
        assert_eq!(report.summary.dead, 0);
        assert_eq!(report.summary.suspected, 2);
    }

    #[test]
    fn macro_node_in_wired_file_becomes_structural() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let macro_node = make_node("my_macro", "macro", "src/main.rs");

        graph.add_node(main_node).unwrap();
        graph.add_node(macro_node).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        assert_eq!(
            find("my_macro").classification,
            ReachabilityClass::Structural
        );
        assert_eq!(report.summary.structural, 1);
    }

    #[test]
    fn static_and_type_alias_in_wired_file_become_structural() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let static_node = make_node("GLOBAL", "static", "src/main.rs");
        let alias_node = make_node("MyResult", "type_alias", "src/main.rs");

        graph.add_node(main_node).unwrap();
        graph.add_node(static_node).unwrap();
        graph.add_node(alias_node).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        assert_eq!(find("GLOBAL").classification, ReachabilityClass::Structural);
        assert_eq!(
            find("MyResult").classification,
            ReachabilityClass::Structural
        );
        assert_eq!(report.summary.structural, 2);
        assert_eq!(report.summary.dead, 0);
    }

    #[test]
    fn structural_display_and_serde_roundtrip() {
        // Display
        assert_eq!(format!("{}", ReachabilityClass::Structural), "STRUCTURAL");

        // Serde roundtrip
        let json = serde_json::to_string(&ReachabilityClass::Structural).unwrap();
        let back: ReachabilityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ReachabilityClass::Structural);
    }

    #[test]
    fn structural_not_counted_in_dead_stats() {
        // A report with structural nodes should have correct summary counts.
        let report = ReachabilityReport {
            classified: vec![
                make_classified("main", "function", "src/main.rs", ReachabilityClass::Wired),
                make_classified(
                    "std::io",
                    "use",
                    "src/main.rs",
                    ReachabilityClass::Structural,
                ),
                make_classified(
                    "dead_fn",
                    "function",
                    "src/unused.rs",
                    ReachabilityClass::Dead,
                ),
            ],
            summary: ReachabilitySummary {
                total: 3,
                wired: 1,
                public_api: 0,
                structural: 1,
                test_only: 0,
                dead: 1,
                orphan_files: 0,
                suspected: 0,
                excluded: 0,
            },
            entry_points_used: vec![],
            orphan_files: vec![],
            test_chains: BTreeMap::new(),
        };

        // nodes_with_class should not conflate structural with dead
        let dead = report.nodes_with_class(ReachabilityClass::Dead);
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].symbol_name, "dead_fn");

        let structural = report.nodes_with_class(ReachabilityClass::Structural);
        assert_eq!(structural.len(), 1);
        assert_eq!(structural[0].symbol_name, "std::io");
    }

    #[test]
    fn function_in_wired_file_stays_dead_not_structural() {
        // Only structural KINDS should be reclassified, not functions.
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let unused_fn = make_node("unused_helper", "function", "src/main.rs");

        graph.add_node(main_node).unwrap();
        graph.add_node(unused_fn).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        // main is wired via BFS
        assert_eq!(find("main").classification, ReachabilityClass::Wired);
        // unused_helper is a "function" kind -- should stay DEAD, not be reclassified
        // (Note: BFS may reach it through bidirectional traversal if in same file.
        // If that happens, it'll be Wired which is also correct. The key assertion
        // is that it is NOT Structural.)
        assert_ne!(
            find("unused_helper").classification,
            ReachabilityClass::Structural
        );
    }

    // -----------------------------------------------------------------------
    // WU-0023 P3b Bundle-3 — Go receiver-type rescue arm falsifier
    // -----------------------------------------------------------------------

    fn references_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::References,
            ..GraphEdge::default()
        }
    }

    /// FALSIFIER (Bundle-3, the load-bearing DEC-IFACE item): an
    /// interface-dispatched Go method whose receiver type is UNREACHED but
    /// IMPLEMENTS a reached interface is RESCUED to the reached tier, not left
    /// Suspected/Dead. RED on HEAD: `guard_rescue_tier` matched only trait/impl
    /// parents; a Go method's Contains-parent is its receiver TYPE (`struct`),
    /// which hit `_ => {}` → never rescued. NON-VACUOUS runnable control: the
    /// SAME shape whose receiver implements a DEAD interface is NOT rescued
    /// (stays Suspected) — so the rescue is discriminating, not a blanket pass;
    /// and manually removing the `"struct" | "enum"` arm drops `Impl::Handle`
    /// itself to Suspected (verified by the build agent, documented in the WU).
    #[test]
    fn go_method_on_unreached_receiver_implementing_reached_iface_is_rescued() {
        let mut graph = KnowledgeGraph::new();

        // main (wired via entry) --References--> Handler (reached interface).
        let main_node = make_node("main", "function", "pkg/main.go");
        let mut handler = make_node("Handler", "trait", "pkg/api.go");
        handler.visibility = "pub".to_string();
        // Impl (struct) is NOT referenced by anything reached → residual. Its
        // method Handle is interface-dispatched (no direct Calls edge).
        let mut impl_ty = make_node("Impl", "struct", "pkg/impl.go");
        impl_ty.visibility = "pub".to_string();
        let mut handle = make_node("Impl::Handle", "function", "pkg/impl.go");
        handle.visibility = "pub".to_string();

        // Negative control: Orphan implements a DEAD interface → NOT rescued.
        let mut dead_iface = make_node("DeadIface", "trait", "pkg/dead.go");
        dead_iface.visibility = "pub".to_string();
        let mut orphan_ty = make_node("Orphan", "struct", "pkg/orphan.go");
        orphan_ty.visibility = "pub".to_string();
        let mut lost = make_node("Orphan::Lost", "function", "pkg/orphan.go");
        lost.visibility = "pub".to_string();

        let (main_id, handler_id) = (main_node.memory_id, handler.memory_id);
        let (impl_id, handle_id) = (impl_ty.memory_id, handle.memory_id);
        let (dead_iface_id, orphan_id, lost_id) =
            (dead_iface.memory_id, orphan_ty.memory_id, lost.memory_id);

        for n in [
            main_node, handler, impl_ty, handle, dead_iface, orphan_ty, lost,
        ] {
            graph.add_node(n).unwrap();
        }

        // Reached path: main references the interface (so Handler is reached),
        // but NOTHING reaches Impl or Orphan directly.
        graph
            .add_edge(main_id, handler_id, references_edge())
            .unwrap();
        // Impl.Handle: receiver Contains method + receiver Implements the reached
        // interface (the rescue anchor).
        graph.add_edge(impl_id, handle_id, contains_edge()).unwrap();
        graph
            .add_edge(impl_id, handler_id, implements_edge())
            .unwrap();
        // Orphan.Lost: receiver Contains method + receiver Implements a DEAD
        // interface (never reached) → control must NOT rescue.
        graph.add_edge(orphan_id, lost_id, contains_edge()).unwrap();
        graph
            .add_edge(orphan_id, dead_iface_id, implements_edge())
            .unwrap();

        // Only a Binary entry (NO LibRoot) so the Bundle-1 Go pub-api seeding
        // does not pre-seed the methods — they must reach the classifier as
        // residual `Dead` for the rescue post-pass to be the thing under test.
        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/pkg/main.go"),
            crate_name: "pkg".to_string(),
        };
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();
        let class_of = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
                .classification
        };

        // RESCUED: the method on the unreached receiver that implements the
        // reached interface is NOT Dead/Suspected.
        assert!(
            !matches!(
                class_of("Impl::Handle"),
                ReachabilityClass::Dead | ReachabilityClass::Suspected
            ),
            "interface-dispatched Go method must be RESCUED, got {:?}",
            class_of("Impl::Handle")
        );
        // DISCRIMINATING CONTROL: the method whose receiver implements only a
        // DEAD interface is NOT rescued (Suspected for a pub residual, or Dead).
        assert!(
            matches!(
                class_of("Orphan::Lost"),
                ReachabilityClass::Suspected | ReachabilityClass::Dead
            ),
            "a method whose receiver implements only a DEAD interface must NOT be \
             rescued, got {:?}",
            class_of("Orphan::Lost")
        );
    }

    // -----------------------------------------------------------------------
    // WAVE-1 — NON-TRANSITIVE GUARD RESCUE falsifiers
    //
    // Blind-spot #1 (dogfood/2026-07-16-reachability-classifier-blindspots.md):
    // `guard_rescue_tier` RELABELS a dyn-dispatched trait/impl method to its
    // reached tier, but the forward `classifier_calls` BFS already finished, so
    // a node reachable ONLY THROUGH a rescued (relabel-Wired) method stays
    // false-DEAD. The fix makes the rescue TRANSITIVE: re-seed the BFS from each
    // rescued node over `classifier_calls()` and fold still-Dead reached nodes
    // into the rescuing tier, interleaved with the guard to a fixpoint.
    // -----------------------------------------------------------------------

    /// POSITIVE (the bug — RED on HEAD, GREEN after Wave 1). A reached trait `T`
    /// (main `References` T, so T is Wired); an impl `I` that `Contains` a
    /// dyn-dispatched method `M` and `Implements` T (so the guard rescues M to
    /// Wired); and a private helper `H` whose SOLE caller is `M` (`M` `Calls`
    /// `H`). On HEAD the single-shot guard never re-walked M→H, so H reads Dead;
    /// the transitive re-walk from the Wired-rescued M folds H to Wired. This is
    /// the `find_containing_symbol` ← `GrepContextHandler::execute` shape reduced
    /// to a fixture.
    #[test]
    fn transitive_guard_rescue_folds_sole_callee_of_rescued_method() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("T", "trait", "src/t.rs", "pub");
        let i = make_node("impl T for I", "impl", "src/i.rs");
        // M is dyn-dispatched — no incoming Calls edge; residual Dead pre-guard.
        let m = make_node_vis("I::exec", "function", "src/i.rs", "pub");
        // H's SOLE inbound is M --Calls--> H; private so it stays Dead on HEAD.
        let h = make_node_vis("find_containing_symbol", "function", "src/i.rs", "private");

        let (main_id, t_id, i_id, m_id, h_id) = (
            main_node.memory_id,
            t.memory_id,
            i.memory_id,
            m.memory_id,
            h.memory_id,
        );
        for n in [main_node, t, i, m, h] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, t_id, references_edge()).unwrap();
        graph.add_edge(i_id, m_id, contains_edge()).unwrap();
        graph.add_edge(i_id, t_id, implements_edge()).unwrap();
        graph.add_edge(m_id, h_id, calls_edge()).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();
        let class_of = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
                .classification
        };

        assert_eq!(
            class_of("T"),
            ReachabilityClass::Wired,
            "trait reached by main"
        );
        assert_eq!(
            class_of("I::exec"),
            ReachabilityClass::Wired,
            "the dyn method is guard-rescued to its reached trait's tier"
        );
        // THE BUG: H is reachable ONLY through the rescued method M. On HEAD it
        // reads Dead (the guard never re-walked M→H); Wave 1 folds it Wired.
        assert_eq!(
            class_of("find_containing_symbol"),
            ReachabilityClass::Wired,
            "helper reachable only through a rescued method must fold to that tier"
        );
    }

    /// NEGATIVE CONTROL 1 (no over-rescue via non-forward adjacency — GREEN on
    /// HEAD and after). Same rescued-method shape, plus: `Dcaller --Calls--> M`
    /// (INCOMING to the rescued node — the forward OUT-only walk must not reach
    /// it) and `Iso` (a private function with no edges at all). Both must stay
    /// Dead, proving the transitive fold admits only OUTGOING `classifier_calls`
    /// chains and never a file/module sibling.
    #[test]
    fn transitive_guard_rescue_leaves_incoming_and_isolated_dead() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("T", "trait", "src/t.rs", "pub");
        let i = make_node("impl T for I", "impl", "src/i.rs");
        let m = make_node_vis("I::exec", "function", "src/i.rs", "pub");
        let h = make_node_vis("real_callee", "function", "src/i.rs", "private");
        // Dcaller CALLS M (incoming to the rescued node) — must NOT be reached.
        let dcaller = make_node_vis("d_caller", "function", "src/i.rs", "private");
        // Iso shares no edge with anything — must NOT be swept alive.
        let iso = make_node_vis("isolated", "function", "src/i.rs", "private");

        let (main_id, t_id, i_id, m_id, h_id, dc_id) = (
            main_node.memory_id,
            t.memory_id,
            i.memory_id,
            m.memory_id,
            h.memory_id,
            dcaller.memory_id,
        );
        for n in [main_node, t, i, m, h, dcaller, iso] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, t_id, references_edge()).unwrap();
        graph.add_edge(i_id, m_id, contains_edge()).unwrap();
        graph.add_edge(i_id, t_id, implements_edge()).unwrap();
        graph.add_edge(m_id, h_id, calls_edge()).unwrap();
        graph.add_edge(dc_id, m_id, calls_edge()).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();
        let class_of = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
                .classification
        };

        // The genuine forward callee IS rescued (sanity — same as the positive).
        assert_eq!(class_of("real_callee"), ReachabilityClass::Wired);
        // An INCOMING caller of the rescued node is not on any forward chain.
        assert_eq!(
            class_of("d_caller"),
            ReachabilityClass::Dead,
            "OUT-only walk must not reach an incoming caller of the rescued method"
        );
        assert_eq!(
            class_of("isolated"),
            ReachabilityClass::Dead,
            "an edgeless private node must never be folded alive"
        );
    }

    /// NEGATIVE CONTROL 2 (no reached parent ⇒ never a transitive seed — GREEN
    /// on HEAD and after). A `ConstraintChecker::check_*`-shaped method whose
    /// impl `Implements` a trait that is NEVER reached (and whose type is never
    /// reached). The guard never rescues it, so it is never a transitive root
    /// and never a forward-callee of one — it stays Dead.
    #[test]
    fn transitive_guard_rescue_no_reached_parent_stays_dead() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        // The trait is present but UNREACHED (nothing references it).
        let unreached_trait = make_node_vis("Constraint", "trait", "src/c.rs", "pub");
        let ci = make_node("impl Constraint for CC", "impl", "src/c.rs");
        let check = make_node_vis("CC::check_bounds", "function", "src/c.rs", "private");

        let (main_id, ut_id, ci_id, check_id) = (
            main_node.memory_id,
            unreached_trait.memory_id,
            ci.memory_id,
            check.memory_id,
        );
        for n in [main_node, unreached_trait, ci, check] {
            graph.add_node(n).unwrap();
        }
        // main is wired but reaches nothing. The impl Implements the trait, but
        // the trait is never reached, so the guard sees no reached parent.
        graph.add_edge(ci_id, check_id, contains_edge()).unwrap();
        graph.add_edge(ci_id, ut_id, implements_edge()).unwrap();
        let _ = main_id;

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();
        let class_of = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
                .classification
        };

        assert_eq!(
            class_of("CC::check_bounds"),
            ReachabilityClass::Dead,
            "a method whose impl parent has no reached trait/type is never rescued"
        );
    }

    /// TIER PRECEDENCE (within-round most-alive) + TestOnly test-module reach.
    /// A shared helper reachable from BOTH a Wired-rescued method and a
    /// TestOnly-rescued method resolves to Wired (most-alive; the Wired walk runs
    /// first and the `== Dead` fold gate means the TestOnly walk skips it). A
    /// test-module helper (`is_test_only`) reachable from BOTH methods stays
    /// TestOnly — proving the TestOnly walk uses `skip_test_modules:false` while
    /// the Wired walk prunes it (`skip_test_modules:true`).
    #[test]
    fn transitive_guard_rescue_tier_precedence_and_test_module_asymmetry() {
        let mut graph = KnowledgeGraph::new();

        // Wired side: main --References--> Twired ⇒ Wired; Iwired Implements it,
        // Contains Mwired (dyn ⇒ guard Wired).
        let main_node = make_node("main", "function", "src/main.rs");
        let twired = make_node_vis("Twired", "trait", "src/tw.rs", "pub");
        let iwired = make_node("impl Twired for Iw", "impl", "src/iw.rs");
        let mwired = make_node_vis("Iw::exec", "function", "src/iw.rs", "pub");

        // TestOnly side: test_fn (test root) --References--> Ttest ⇒ TestOnly;
        // Itest Implements it, Contains Mtest (dyn ⇒ guard TestOnly).
        let mut test_fn = make_node("t_root", "function", "src/it.rs");
        test_fn.is_test_root = true;
        let ttest = make_node_vis("Ttest", "trait", "src/it.rs", "pub");
        let itest = make_node("impl Ttest for It", "impl", "src/it.rs");
        let mtest = make_node_vis("It::exec", "function", "src/it.rs", "pub");

        // Shared production helper (NOT a test module) — most-alive ⇒ Wired.
        let hshared = make_node_vis("shared_helper", "function", "src/shared.rs", "private");
        // Test-module helper — pruned by the Wired walk, reached by TestOnly.
        let mut htest = make_node_vis("test_helper", "function", "src/it.rs", "private");
        htest.is_test_only = Some(true);

        let main_id = main_node.memory_id;
        let twired_id = twired.memory_id;
        let iwired_id = iwired.memory_id;
        let mwired_id = mwired.memory_id;
        let test_fn_id = test_fn.memory_id;
        let ttest_id = ttest.memory_id;
        let itest_id = itest.memory_id;
        let mtest_id = mtest.memory_id;
        let hshared_id = hshared.memory_id;
        let htest_id = htest.memory_id;

        for n in [
            main_node, twired, iwired, mwired, test_fn, ttest, itest, mtest, hshared, htest,
        ] {
            graph.add_node(n).unwrap();
        }

        graph
            .add_edge(main_id, twired_id, references_edge())
            .unwrap();
        graph
            .add_edge(iwired_id, mwired_id, contains_edge())
            .unwrap();
        graph
            .add_edge(iwired_id, twired_id, implements_edge())
            .unwrap();

        graph
            .add_edge(test_fn_id, ttest_id, references_edge())
            .unwrap();
        graph.add_edge(itest_id, mtest_id, contains_edge()).unwrap();
        graph
            .add_edge(itest_id, ttest_id, implements_edge())
            .unwrap();

        // Both methods call BOTH helpers.
        graph.add_edge(mwired_id, hshared_id, calls_edge()).unwrap();
        graph.add_edge(mtest_id, hshared_id, calls_edge()).unwrap();
        graph.add_edge(mwired_id, htest_id, calls_edge()).unwrap();
        graph.add_edge(mtest_id, htest_id, calls_edge()).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();
        let class_of = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
                .classification
        };

        assert_eq!(class_of("Iw::exec"), ReachabilityClass::Wired);
        assert_eq!(class_of("It::exec"), ReachabilityClass::TestOnly);
        // Reachable from a Wired AND a TestOnly rescued method ⇒ most-alive Wired.
        assert_eq!(
            class_of("shared_helper"),
            ReachabilityClass::Wired,
            "a helper reached by both tiers takes the most-alive (Wired) tier"
        );
        // The Wired walk prunes the test-module helper (skip_test_modules:true);
        // only the TestOnly walk (skip_test_modules:false) reaches it.
        assert_eq!(
            class_of("test_helper"),
            ReachabilityClass::TestOnly,
            "the Wired walk must skip the test-module helper; TestOnly folds it"
        );
    }

    /// CASCADE / FIXPOINT (two-hop — RED on HEAD, GREEN after). A rescued method
    /// `M1` --References--> a second trait `T2` (previously unreached); the
    /// re-walk folds T2 alive, which on the NEXT round makes `T2`'s dyn impl
    /// method `M2` guard-eligible, whose helper `H2` then folds. A single
    /// guard+walk pass would miss the second hop; the interleave drains it.
    #[test]
    fn transitive_guard_rescue_drains_two_hop_cascade() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let t1 = make_node_vis("T1", "trait", "src/t1.rs", "pub");
        let i1 = make_node("impl T1 for I1", "impl", "src/i1.rs");
        let m1 = make_node_vis("I1::exec", "function", "src/i1.rs", "pub");
        // Second hop: M1 References T2 (unreached until the re-walk).
        let t2 = make_node_vis("T2", "trait", "src/t2.rs", "pub");
        let i2 = make_node("impl T2 for I2", "impl", "src/i2.rs");
        let m2 = make_node_vis("I2::exec", "function", "src/i2.rs", "pub");
        let h2 = make_node_vis("second_hop_helper", "function", "src/i2.rs", "private");

        let main_id = main_node.memory_id;
        let t1_id = t1.memory_id;
        let i1_id = i1.memory_id;
        let m1_id = m1.memory_id;
        let t2_id = t2.memory_id;
        let i2_id = i2.memory_id;
        let m2_id = m2.memory_id;
        let h2_id = h2.memory_id;

        for n in [main_node, t1, i1, m1, t2, i2, m2, h2] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, t1_id, references_edge()).unwrap();
        graph.add_edge(i1_id, m1_id, contains_edge()).unwrap();
        graph.add_edge(i1_id, t1_id, implements_edge()).unwrap();
        // The cascade edge: the round-1 Wired-rescued M1 references T2.
        graph.add_edge(m1_id, t2_id, references_edge()).unwrap();
        graph.add_edge(i2_id, m2_id, contains_edge()).unwrap();
        graph.add_edge(i2_id, t2_id, implements_edge()).unwrap();
        graph.add_edge(m2_id, h2_id, calls_edge()).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();
        let class_of = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
                .classification
        };

        assert_eq!(class_of("I1::exec"), ReachabilityClass::Wired);
        assert_eq!(
            class_of("T2"),
            ReachabilityClass::Wired,
            "the re-walk reaches T2 through the rescued M1"
        );
        assert_eq!(
            class_of("I2::exec"),
            ReachabilityClass::Wired,
            "round-2 guard rescues M2 once T2 is folded alive"
        );
        assert_eq!(
            class_of("second_hop_helper"),
            ReachabilityClass::Wired,
            "the two-hop cascade helper folds alive at the fixpoint"
        );
    }

    /// CROSS-ROUND TIER PRECEDENCE (the design-review MAJOR — RED on HEAD).
    /// Guards against a within-round-only 'most-alive' guarantee: helper `H` is
    /// folded TestOnly in round 1 (via a TestOnly-rescued method `Mt`), but a
    /// Wired reach to `H` only MATERIALIZES in round 2 (through `Mw2`, which is
    /// guard-rescued only after `Tw` is folded Wired in round 1). A naive
    /// `== Dead`-only fold would leave H stuck TestOnly; the cross-round upgrade
    /// (fold gate admits an already-folded node when the reaching tier is
    /// strictly more-alive) lifts H to Wired.
    #[test]
    fn transitive_guard_rescue_cross_round_upgrades_to_most_alive() {
        let mut graph = KnowledgeGraph::new();

        // Wired cascade chain (materializes the Wired reach to H in round 2).
        let main_node = make_node("main", "function", "src/main.rs");
        let t1 = make_node_vis("T1", "trait", "src/t1.rs", "pub");
        let i1 = make_node("impl T1 for I1", "impl", "src/i1.rs");
        let mw = make_node_vis("I1::exec", "function", "src/i1.rs", "pub");
        let tw = make_node_vis("Tw", "trait", "src/tw.rs", "pub");
        let i2 = make_node("impl Tw for I2", "impl", "src/i2.rs");
        let mw2 = make_node_vis("I2::exec", "function", "src/i2.rs", "pub");

        // TestOnly chain (folds H TestOnly in round 1).
        let mut test_fn = make_node("t_root", "function", "src/it.rs");
        test_fn.is_test_root = true;
        let tt = make_node_vis("Tt", "trait", "src/it.rs", "pub");
        let it = make_node("impl Tt for It", "impl", "src/it.rs");
        let mt = make_node_vis("It::exec", "function", "src/it.rs", "pub");

        // The contested helper: reached by Mt (round 1, TestOnly) AND Mw2
        // (round 2, Wired). Must end Wired.
        let h = make_node_vis("contested_helper", "function", "src/h.rs", "private");

        let main_id = main_node.memory_id;
        let t1_id = t1.memory_id;
        let i1_id = i1.memory_id;
        let mw_id = mw.memory_id;
        let tw_id = tw.memory_id;
        let i2_id = i2.memory_id;
        let mw2_id = mw2.memory_id;
        let test_fn_id = test_fn.memory_id;
        let tt_id = tt.memory_id;
        let it_id = it.memory_id;
        let mt_id = mt.memory_id;
        let h_id = h.memory_id;

        for n in [main_node, t1, i1, mw, tw, i2, mw2, test_fn, tt, it, mt, h] {
            graph.add_node(n).unwrap();
        }

        // Wired chain: main -> T1 (Wired); I1 Implements T1, Contains Mw (Wired);
        // Mw References Tw (folds Tw Wired in round 1); I2 Implements Tw,
        // Contains Mw2 (guard-rescued Wired in round 2); Mw2 Calls H.
        graph.add_edge(main_id, t1_id, references_edge()).unwrap();
        graph.add_edge(i1_id, mw_id, contains_edge()).unwrap();
        graph.add_edge(i1_id, t1_id, implements_edge()).unwrap();
        graph.add_edge(mw_id, tw_id, references_edge()).unwrap();
        graph.add_edge(i2_id, mw2_id, contains_edge()).unwrap();
        graph.add_edge(i2_id, tw_id, implements_edge()).unwrap();
        graph.add_edge(mw2_id, h_id, calls_edge()).unwrap();

        // TestOnly chain: test_fn -> Tt (TestOnly); It Implements Tt, Contains Mt
        // (guard-rescued TestOnly round 1); Mt Calls H (folds H TestOnly round 1).
        graph
            .add_edge(test_fn_id, tt_id, references_edge())
            .unwrap();
        graph.add_edge(it_id, mt_id, contains_edge()).unwrap();
        graph.add_edge(it_id, tt_id, implements_edge()).unwrap();
        graph.add_edge(mt_id, h_id, calls_edge()).unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();
        let class_of = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
                .classification
        };

        assert_eq!(class_of("It::exec"), ReachabilityClass::TestOnly);
        assert_eq!(class_of("I2::exec"), ReachabilityClass::Wired);
        // The contested helper is folded TestOnly in round 1, then a Wired reach
        // materializes in round 2 — the most-alive tier must win ACROSS rounds.
        assert_eq!(
            class_of("contested_helper"),
            ReachabilityClass::Wired,
            "a cross-round Wired cascade must upgrade a helper folded TestOnly earlier"
        );
    }

    // -----------------------------------------------------------------------
    // Fix-REACH: HasImpl / test-module false-positive prevention tests
    // -----------------------------------------------------------------------

    fn has_impl_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::HasImpl,
            ..GraphEdge::default()
        }
    }

    fn implements_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Implements,
            ..GraphEdge::default()
        }
    }

    /// Test 1: Production BFS from a WIRED trait does NOT reach an
    /// unregistered implementor via HasImpl.
    #[test]
    fn production_bfs_skips_has_impl_to_unregistered_implementor() {
        let mut graph = KnowledgeGraph::new();

        // main -> calls -> registry_fn -> TypeOf -> MyTrait --HasImpl--> UnregisteredImpl
        let main_node = make_node("main", "function", "src/main.rs");
        let registry_fn = make_node("register", "function", "src/registry.rs");
        let trait_node = make_node("MyTrait", "trait", "src/traits.rs");
        let unregistered = make_node("UnregisteredImpl", "struct", "src/impls.rs");

        let main_id = main_node.memory_id;
        let registry_id = registry_fn.memory_id;
        let trait_id = trait_node.memory_id;
        let unregistered_id = unregistered.memory_id;

        graph.add_node(main_node).unwrap();
        graph.add_node(registry_fn).unwrap();
        graph.add_node(trait_node).unwrap();
        graph.add_node(unregistered).unwrap();

        // main -> Calls -> register
        graph.add_edge(main_id, registry_id, calls_edge()).unwrap();
        // register -> TypeOf -> MyTrait (trait is reachable via production)
        graph
            .add_edge(
                registry_id,
                trait_id,
                GraphEdge {
                    kind: EdgeKind::TypeOf,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        // MyTrait --HasImpl--> UnregisteredImpl (should be SKIPPED in production)
        graph
            .add_edge(trait_id, unregistered_id, has_impl_edge())
            .unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        assert_eq!(find("main").classification, ReachabilityClass::Wired);
        assert_eq!(find("register").classification, ReachabilityClass::Wired);
        // MyTrait stays WIRED: reached via TypeOf (admitted by the Call edge-set).
        assert_eq!(find("MyTrait").classification, ReachabilityClass::Wired);
        // The key assertion (WU-0015 REBASELINE Dead → Suspected): the HasImpl edge
        // is NOT walked (never in the Call edge-set), so the unregistered
        // implementor is NOT auto-WIRED — it is a non-delete Suspected residual.
        assert_eq!(
            find("UnregisteredImpl").classification,
            ReachabilityClass::Suspected,
            "Unregistered implementor should be SUSPECTED, not auto-WIRED via HasImpl"
        );
    }

    /// Test 2: Production BFS does NOT reach test-module symbols through
    /// Contains edges from production files.
    #[test]
    fn production_bfs_skips_test_module_via_contains() {
        let mut graph = KnowledgeGraph::new();

        // prod_fn --Contains--> tests::test_helper  (in same file)
        let main_node = make_node("main", "function", "src/main.rs");
        let prod_fn = make_node("do_work", "function", "src/lib.rs");
        let file_mod = make_node("lib", "module", "src/lib.rs");
        let tests_mod = make_node("tests", "module", "src/lib.rs");
        // WU-0015: test roots reseed to `is_test_root` `#[test]` FUNCTION nodes.
        let mut test_fn = make_node("tests::test_do_work", "function", "src/lib.rs");
        test_fn.is_test_root = true;

        let main_id = main_node.memory_id;
        let prod_fn_id = prod_fn.memory_id;
        let file_mod_id = file_mod.memory_id;
        let tests_mod_id = tests_mod.memory_id;
        let test_fn_id = test_fn.memory_id;

        graph.add_node(main_node).unwrap();
        graph.add_node(prod_fn).unwrap();
        graph.add_node(file_mod).unwrap();
        graph.add_node(tests_mod).unwrap();
        graph.add_node(test_fn).unwrap();

        // main -> Calls -> do_work
        graph.add_edge(main_id, prod_fn_id, calls_edge()).unwrap();
        // file module contains production fn and tests module
        graph
            .add_edge(file_mod_id, prod_fn_id, contains_edge())
            .unwrap();
        graph
            .add_edge(file_mod_id, tests_mod_id, contains_edge())
            .unwrap();
        // tests module contains test function
        graph
            .add_edge(tests_mod_id, test_fn_id, contains_edge())
            .unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        assert_eq!(find("main").classification, ReachabilityClass::Wired);
        assert_eq!(find("do_work").classification, ReachabilityClass::Wired);
        // Test module and its children should NOT be WIRED.
        assert_ne!(
            find("tests").classification,
            ReachabilityClass::Wired,
            "tests:: module should not be WIRED from production BFS"
        );
        assert_ne!(
            find("tests::test_do_work").classification,
            ReachabilityClass::Wired,
            "tests::test_do_work should not be WIRED from production BFS"
        );
        // WU-0015 REBASELINE: the `#[test]` fn (an `is_test_root` FUNCTION) is a
        // test root → TestOnly. The `tests` MODULE node is no longer a root
        // (Contains dropped; roots reseeded to the test fns) → Suspected. Neither
        // is WIRED from production, which is the load-bearing safe-direction claim.
        assert_eq!(
            find("tests::test_do_work").classification,
            ReachabilityClass::TestOnly,
            "the #[test] fn is a test root → TestOnly"
        );
        // The `tests` MODULE node is no longer a test root; it is a `module`-kind
        // node in the ALIVE src/lib.rs (do_work is Wired), so Pass 5 rescues it to
        // Structural (a compile-time wiring artifact, non-delete) — never WIRED.
        assert_eq!(
            find("tests").classification,
            ReachabilityClass::Structural,
            "the tests module node → Structural (Pass 5 rescue in an alive file)"
        );
    }

    /// Test 3: A legitimate implementor that is independently called IS
    /// still classified as WIRED (reached via Calls, not HasImpl).
    #[test]
    fn legitimate_implementor_still_wired_via_calls() {
        let mut graph = KnowledgeGraph::new();

        // main -> Calls -> create_store -> Calls -> LanceStore::open
        // MyTrait --HasImpl--> LanceStore  (this edge exists but isn't the wiring path)
        let main_node = make_node("main", "function", "src/main.rs");
        let create_store = make_node("create_store", "function", "src/setup.rs");
        let trait_node = make_node("MemoryStore", "trait", "src/traits.rs");
        let lance_store = make_node("LanceStore", "struct", "src/lance.rs");
        let lance_open = make_node("LanceStore::open", "function", "src/lance.rs");

        let main_id = main_node.memory_id;
        let create_store_id = create_store.memory_id;
        let trait_id = trait_node.memory_id;
        let lance_store_id = lance_store.memory_id;
        let lance_open_id = lance_open.memory_id;

        graph.add_node(main_node).unwrap();
        graph.add_node(create_store).unwrap();
        graph.add_node(trait_node).unwrap();
        graph.add_node(lance_store).unwrap();
        graph.add_node(lance_open).unwrap();

        // main -> Calls -> create_store -> Calls -> LanceStore::open
        graph
            .add_edge(main_id, create_store_id, calls_edge())
            .unwrap();
        graph
            .add_edge(create_store_id, lance_open_id, calls_edge())
            .unwrap();
        // LanceStore::open is contained in LanceStore (bidirectional BFS reaches the struct)
        graph
            .add_edge(lance_store_id, lance_open_id, contains_edge())
            .unwrap();
        // LanceStore implements MemoryStore (trait should also be WIRED via incoming Implements)
        graph
            .add_edge(lance_store_id, trait_id, implements_edge())
            .unwrap();
        // MemoryStore --HasImpl--> LanceStore (this edge exists but is skipped in production BFS)
        graph
            .add_edge(trait_id, lance_store_id, has_impl_edge())
            .unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        // The CALLED method stays WIRED (reached via the real Calls chain).
        assert_eq!(
            find("LanceStore::open").classification,
            ReachabilityClass::Wired,
            "Legitimately called method should be WIRED"
        );
        // WU-0015 REBASELINE: in this synthetic graph the `LanceStore` STRUCT is
        // linked to its method only by a `Contains` edge (dropped) and to the
        // trait only by `Implements` (not walked), with no construction/use edge —
        // so it is call-unreachable → Suspected (finding 7: construction
        // reachability is thinner than the old undirected walk; non-delete in
        // Leg 1). Likewise the trait, reachable only via the non-walked Implements
        // edge, → Suspected.
        assert_eq!(
            find("LanceStore").classification,
            ReachabilityClass::Suspected,
        );
        assert_eq!(
            find("MemoryStore").classification,
            ReachabilityClass::Suspected,
        );
    }

    /// Test 4 (WU-0015 REBASELINE): the directed-call test pass does NOT follow
    /// `HasImpl` (never in the Call edge-set) and reseeds test roots to `#[test]`
    /// FUNCTION nodes — so a test-only implementor reached ONLY via `HasImpl` from
    /// a module node (no `#[test]` root, no `Calls` edge) is call-unreachable →
    /// Suspected, NEVER auto-TestOnly-via-HasImpl. Non-delete in Leg 1.
    #[test]
    fn test_pass_does_not_follow_has_impl() {
        let mut graph = KnowledgeGraph::new();

        // Trait --HasImpl--> MockImpl (only in tests)
        // tests:: module contains MockImpl
        let trait_node = make_node("Embedder", "trait", "src/traits.rs");
        let mock_impl = make_node("MockEmbedder", "struct", "src/test_utils.rs");
        let tests_mod = make_node("tests", "module", "src/test_utils.rs");

        let trait_id = trait_node.memory_id;
        let mock_id = mock_impl.memory_id;
        let tests_id = tests_mod.memory_id;

        graph.add_node(trait_node).unwrap();
        graph.add_node(mock_impl).unwrap();
        graph.add_node(tests_mod).unwrap();

        // tests module contains the mock
        graph.add_edge(tests_id, mock_id, contains_edge()).unwrap();
        // Trait --HasImpl--> MockEmbedder
        graph.add_edge(trait_id, mock_id, has_impl_edge()).unwrap();

        // No production entry points -- only test entry points via tests:: module.
        let analyzer = ReachabilityAnalyzer::new(&graph, vec![]);
        let report = analyzer.analyze();

        let find = |name: &str| {
            report
                .classified
                .iter()
                .find(|c| c.symbol_name == name)
                .unwrap()
        };

        // WU-0015 REBASELINE: HasImpl is no longer walked, so a mock reached only
        // via HasImpl (with no #[test]-root caller) is call-unreachable → Suspected.
        assert_eq!(
            find("MockEmbedder").classification,
            ReachabilityClass::Suspected,
            "HasImpl-only implementor → Suspected (HasImpl not walked)"
        );
        // The `tests` MODULE node is no longer a test root → Suspected.
        assert_eq!(find("tests").classification, ReachabilityClass::Suspected);
        // The trait is not reachable by any use-edge here → not WIRED (Suspected).
        assert_ne!(
            find("Embedder").classification,
            ReachabilityClass::Wired,
            "Trait with only test implementors should not be WIRED"
        );
    }

    /// Test 5: After full analysis, the sum of all reachability class counts
    /// equals the total node count (arithmetic invariant).
    #[test]
    fn arithmetic_all_classes_sum_to_total() {
        let mut graph = KnowledgeGraph::new();

        // Build a non-trivial graph with nodes in each expected class.
        let main_node = make_node("main", "function", "src/main.rs");
        let helper = make_node("helper", "function", "src/lib.rs");
        let trait_node = make_node("MyTrait", "trait", "src/traits.rs");
        let dead_impl = make_node("DeadImpl", "struct", "src/dead.rs");
        let use_node = make_node("std::io", "use", "src/lib.rs");
        let tests_mod = make_node("tests", "module", "src/lib.rs");
        let test_fn = make_node("tests::it_works", "function", "src/lib.rs");
        let dead_fn = make_node("dead_fn", "function", "src/dead.rs");

        let main_id = main_node.memory_id;
        let helper_id = helper.memory_id;
        let trait_id = trait_node.memory_id;
        let dead_impl_id = dead_impl.memory_id;
        let tests_id = tests_mod.memory_id;
        let test_fn_id = test_fn.memory_id;

        graph.add_node(main_node).unwrap();
        graph.add_node(helper).unwrap();
        graph.add_node(trait_node).unwrap();
        graph.add_node(dead_impl).unwrap();
        graph.add_node(use_node).unwrap();
        graph.add_node(tests_mod).unwrap();
        graph.add_node(test_fn).unwrap();
        graph.add_node(dead_fn).unwrap();

        // Wiring: main -> helper
        graph.add_edge(main_id, helper_id, calls_edge()).unwrap();
        // Trait --HasImpl--> DeadImpl (won't make it WIRED in production)
        graph
            .add_edge(trait_id, dead_impl_id, has_impl_edge())
            .unwrap();
        // tests module contains test fn
        graph
            .add_edge(tests_id, test_fn_id, contains_edge())
            .unwrap();

        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };

        let analyzer = ReachabilityAnalyzer::new(&graph, vec![ep]);
        let report = analyzer.analyze();

        let s = &report.summary;
        // WU-0015 REBASELINE: the arithmetic invariant now includes the 8th
        // bucket, `suspected`.
        let computed_total =
            s.wired + s.public_api + s.structural + s.test_only + s.dead + s.suspected;
        assert_eq!(
            computed_total,
            s.total,
            "WIRED({}) + PUBLIC_API({}) + STRUCTURAL({}) + TEST_ONLY({}) + DEAD({}) + SUSPECTED({}) = {} but total = {}",
            s.wired,
            s.public_api,
            s.structural,
            s.test_only,
            s.dead,
            s.suspected,
            computed_total,
            s.total
        );

        // Also verify via classified nodes count.
        assert_eq!(
            report.classified.len(),
            s.total,
            "classified node count must equal summary.total"
        );
    }

    // ------------------------------------------------------------------
    // WU-0003 / CL-REACH RC5 falsifiers — the Unclassified variant contract.
    // ------------------------------------------------------------------

    /// F8 (POST-SCHEMA): `Unclassified.action_tier()` is the NEW conservative
    /// tier — NEVER `Healthy` (so it is never reported clean). (WU-0016 /
    /// ADR-0039: the `Action` auto-delete tier was removed; there is no
    /// delete tier to guard against.)
    #[test]
    fn unclassified_action_tier_is_conservative_never_healthy() {
        let tier = ReachabilityClass::Unclassified.action_tier();
        assert_eq!(
            tier,
            ActionTier::Unknown,
            "Unclassified maps to the Unknown tier"
        );
        assert_ne!(
            tier,
            ActionTier::Healthy,
            "Unclassified must NEVER be Healthy (never reported clean)"
        );
    }

    /// F9 (POST-SCHEMA): the Display label is the uppercase token `UNCLASSIFIED`.
    #[test]
    fn unclassified_display_label_is_uppercase_token() {
        assert_eq!(
            format!("{}", ReachabilityClass::Unclassified),
            "UNCLASSIFIED"
        );
        assert_eq!(format!("{}", ActionTier::Unknown), "UNKNOWN");
    }

    /// F (POST-SCHEMA): `Default` for `ReachabilityClass` is `Unclassified` —
    /// so `#[serde(default)]` on the non-`Option` `GraphNode` field resolves a
    /// missing field to `Unclassified`, never `Dead`.
    #[test]
    fn reachability_class_default_is_unclassified() {
        assert_eq!(
            ReachabilityClass::default(),
            ReachabilityClass::Unclassified
        );
    }

    // ------------------------------------------------------------------
    // WU-0003 / CL-REACH RC4 falsifier (b): the chokepoint contract —
    // no Unclassified survives a classify, and every node gets a real class.
    // ------------------------------------------------------------------

    /// Build a minimal single-crate Cargo project on disk so that
    /// `discover_entry_points` (which `classify_and_writeback` calls) succeeds.
    fn write_min_cargo_project(root: &Path) {
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("mkdir src");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"choke-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write Cargo.toml");
        std::fs::write(
            src.join("main.rs"),
            "fn main() { helper(); }\nfn helper() { let _ = 1 + 1; }\n",
        )
        .expect("write main.rs");
        std::fs::write(
            src.join("lib.rs"),
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        )
        .expect("write lib.rs");
    }

    /// A graph built by `full_scan` alone carries `Unclassified` nodes, while
    /// routing the same graph through `classify_and_writeback` leaves none.
    /// This keeps the classification chokepoint non-vacuous for every future
    /// publisher without retaining a retired graph-only writer.
    #[test]
    fn classify_and_writeback_leaves_zero_unclassified() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_min_cargo_project(dir.path());

        // Build the deliberately pre-classification control graph.
        let mut graph = KnowledgeGraph::new();
        let _stats =
            crate::edge_builder::full_scan(dir.path(), &mut graph).expect("full_scan succeeds");
        assert!(
            !graph.all_nodes().is_empty(),
            "fixture must extract at least one node"
        );

        // RED branch: the pre-classify graph (what HEAD's scip paths persisted)
        // contains Unclassified nodes.
        let unclassified_before = graph
            .all_nodes()
            .iter()
            .filter(|n| n.reachability_class == ReachabilityClass::Unclassified)
            .count();
        assert!(
            unclassified_before > 0,
            "pre-classify graph (the HEAD scip-save state) must contain Unclassified \
             nodes — otherwise this falsifier is vacuous"
        );

        // Route through the chokepoint.
        let report = classify_and_writeback(&mut graph, dir.path())
            .expect("classify_and_writeback succeeds on a valid Cargo project");
        assert!(
            report.summary.total > 0,
            "the report should classify at least one node"
        );

        // GREEN: after the chokepoint, ZERO nodes remain Unclassified.
        let unclassified_after = graph
            .all_nodes()
            .iter()
            .filter(|n| n.reachability_class == ReachabilityClass::Unclassified)
            .count();
        assert_eq!(
            unclassified_after, 0,
            "after classify_and_writeback, no node may remain Unclassified \
             (the RC4 chokepoint guarantee)"
        );
    }

    /// FALSIFIER (RC4 chokepoint, hard-error contract): entry-point discovery
    /// failure (no Cargo.toml) is a HARD error, not a swallowed `None`. This is
    /// the ADR-0028 OQ-2 disposition for the former `let _ = save_snapshot(...)`
    /// swallow at `code_intel.rs:672` and the index-pipeline non-fatal warn.
    #[test]
    fn classify_and_writeback_hard_errors_without_cargo_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A bare directory with a source file but NO Cargo.toml.
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(src.join("main.rs"), "fn main() {}\n").expect("write");

        let mut graph = KnowledgeGraph::new();
        let _ = crate::edge_builder::full_scan(dir.path(), &mut graph);

        let result = classify_and_writeback(&mut graph, dir.path());
        assert!(
            result.is_err(),
            "entry-point discovery failure must be a hard error, never swallowed"
        );
    }

    // -----------------------------------------------------------------------
    // F1 (ADR-0029 OBS-1): reload_reclassify_save surfaces every failure mode
    // -----------------------------------------------------------------------

    use crate::graph_store::GraphStore;
    use redb::Database;
    use std::sync::Arc;

    /// Build a real `GraphStore` over an empty in-memory redb. `load_snapshot`
    /// on this store returns genuine `Ok(None)` — which the reload chokepoint,
    /// per its documented post-index precondition, treats as
    /// [`ReloadError::EmptyAfterIndex`].
    fn empty_mem_store() -> GraphStore {
        let backend = redb::backends::InMemoryBackend::new();
        let db = Database::builder()
            .create_with_backend(backend)
            .expect("create in-mem redb");
        GraphStore::new(Arc::new(db))
    }

    /// A `StorageBackend` that wraps a real on-disk `FileBackend` and, once
    /// "armed", returns an IO error from every backend access. Mirrors redb's
    /// own `FailingBackend` test pattern (db.rs `crash_regression4`). A file
    /// backend (unlike the in-memory one) actually re-reads pages from storage,
    /// so arming it AFTER a fresh open — with a cold page cache — forces
    /// `load_snapshot`'s table reads to hit the backend and return `Err`,
    /// exercising the [`ReloadError::Store`] arm via the REAL load path (no
    /// graph_store.rs edit, no mock GraphStore).
    #[derive(Debug)]
    struct FailReadBackend {
        inner: redb::backends::FileBackend,
        armed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl FailReadBackend {
        fn fail_if_armed(&self) -> Result<(), std::io::Error> {
            if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::other("injected backend failure"));
            }
            Ok(())
        }
    }

    impl redb::StorageBackend for FailReadBackend {
        fn len(&self) -> Result<u64, std::io::Error> {
            self.inner.len()
        }
        fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
            self.fail_if_armed()?;
            self.inner.read(offset, out)
        }
        fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
            self.inner.set_len(len)
        }
        fn sync_data(&self) -> Result<(), std::io::Error> {
            self.inner.sync_data()
        }
        fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
            self.fail_if_armed()?;
            self.inner.write(offset, data)
        }
    }

    /// F1 (a): a post-index reload that yields no graph is surfaced as
    /// `EmptyAfterIndex`, NOT a silent stale-stats success.
    #[tokio::test]
    async fn reload_reclassify_save_empty_after_index_is_error() {
        let store = empty_mem_store();
        let dir = tempfile::tempdir().expect("tempdir");
        let result = reload_reclassify_save(&store, dir.path()).await;
        assert!(
            matches!(result, Err(ReloadError::EmptyAfterIndex)),
            "an empty post-index snapshot must surface EmptyAfterIndex (got Ok or wrong error)"
        );
    }

    /// F1 (b): a `load_snapshot` `Err` (backend read failure) is surfaced as
    /// `ReloadError::Store`, not swallowed.
    #[tokio::test]
    async fn reload_reclassify_save_store_err_propagates() {
        // Phase 1: build a real on-disk redb, persist a snapshot, then drop the
        // handle so the bytes are flushed to a file we can reopen.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_owned();
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .expect("open db file");
            let backend = redb::backends::FileBackend::new(file).expect("file backend");
            let db = Database::builder()
                .create_with_backend(backend)
                .expect("create file redb");
            let store = GraphStore::new(Arc::new(db));
            let mut graph = KnowledgeGraph::new();
            // Many nodes so the persisted snapshot spans multiple data pages
            // that a cold-cache load MUST read from the backend (a tiny
            // single-node snapshot can fit in pages already warmed at init).
            for i in 0..2000 {
                graph
                    .add_node(make_node(
                        &format!("sym_{i}"),
                        "function",
                        &format!("src/m{i}.rs"),
                    ))
                    .expect("add node");
            }
            store.save_snapshot(&graph).await.expect("save snapshot");
            // store + db dropped here -> bytes persisted on disk.
        }

        // Phase 2: reopen over an arm-able FileBackend. Init reads succeed
        // (disarmed); then ARM so the cold-cache snapshot reads inside
        // load_snapshot hit the backend and fail. The arm switch is a shared
        // Arc<AtomicBool> so the test keeps a handle after the backend moves
        // into the Database.
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("reopen db file");
        let backend = FailReadBackend {
            inner: redb::backends::FileBackend::new(file).expect("file backend"),
            armed: Arc::clone(&armed),
        };
        // cache_size(0): redb's default builder warms a 1 GiB read cache that
        // would serve every page from memory, so a post-init armed read never
        // fires. Zero the cache so cold snapshot reads hit the backend.
        let db = Database::builder()
            .set_cache_size(0)
            .create_with_backend(backend)
            .expect("reopen file redb (disarmed)");
        let store = GraphStore::new(Arc::new(db));

        // Arm: the next backend read (inside load_snapshot) fails.
        armed.store(true, std::sync::atomic::Ordering::SeqCst);

        let dir = tempfile::tempdir().expect("tempdir");
        let result = reload_reclassify_save(&store, dir.path()).await;
        armed.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            matches!(result, Err(ReloadError::Store(_))),
            "a snapshot load Err must surface ReloadError::Store (got Ok or wrong error)"
        );
    }

    /// F1 (c): when the snapshot loads `Ok(Some(g))` but entry-point discovery
    /// fails (no Cargo.toml at the classify root), the failure is surfaced as
    /// `ReloadError::Classify`, not a silent success.
    #[tokio::test]
    async fn reload_reclassify_save_classify_err_propagates() {
        // A store with a real persisted snapshot so load yields Ok(Some(_)).
        let store = empty_mem_store();
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(make_node("alpha", "function", "src/alpha.rs"))
            .expect("add node");
        store.save_snapshot(&graph).await.expect("save snapshot");

        // A classify root WITHOUT a Cargo.toml -> discover_entry_points Err.
        let dir = tempfile::tempdir().expect("tempdir");
        let result = reload_reclassify_save(&store, dir.path()).await;
        assert!(
            matches!(result, Err(ReloadError::Classify(_))),
            "an entry-point discovery Err must surface ReloadError::Classify (got Ok or wrong error)"
        );
    }

    // -----------------------------------------------------------------------
    // WAVE-2 — the TEST-NESS CAP on guard rescue
    //
    // Blind-spot #2 (dogfood/2026-07-16-reachability-classifier-blindspots.md):
    // MEASURED[47] nodes inside `#[cfg(test)] mod tests` — unreachable from
    // production BY CONSTRUCTION — classified `Wired` at HEAD. All 47 are
    // trait-impl members (38 fns + 9 impls across 9 test doubles); not one is an
    // inherent method. `guard_rescue_tier` took the reached TRAIT's tier as
    // dispatch evidence without ever consulting the implementor's own
    // test-ness, so a test double free-rode on the real implementors' evidence.
    // Mechanism proof in the live graph: `tests::MockContextProvider`'s five
    // INHERENT methods are correctly TestOnly while its one TRAIT method
    // (`surface`) is Wired — same struct, same file, same test module.
    //
    // The fix caps every rescue at TestOnly when the method / its impl / (arm b)
    // its concrete type is test-module. These falsifiers pin the POSITIVE (the
    // cap fires), the NEGATIVE CONTROL (it does NOT over-fire on production),
    // and the two arms beyond arm (a).
    // -----------------------------------------------------------------------

    /// Like `make_node_vis`, but marks the node test-only via the PERSISTED
    /// `is_test_only` AST bit — the signal `is_test_module_symbol` reads FIRST
    /// (the `tests::` name heuristic is only its `None` fallback). These
    /// fixtures therefore exercise the bit, not the name.
    fn make_node_test(name: &str, kind: &str, file_path: &str, visibility: &str) -> GraphNode {
        GraphNode {
            is_test_only: Some(true),
            ..make_node_vis(name, kind, file_path, visibility)
        }
    }

    /// F1 POSITIVE (the bug — on HEAD `m` reads **Wired**; after the cap it is
    /// **TestOnly**). The real `HintingFailHandler` shape: a production trait `T`
    /// reached from `main` (→ Wired); a TEST-MODULE struct `M`; `impl T for M`
    /// (`Implements` → T); and a dyn-dispatched method `m` inside that impl with
    /// no incoming `Calls` (→ residual Dead, so the `== Dead` candidate gate
    /// calls the guard). Arm (a) reads T's Wired tier as dispatch evidence and,
    /// uncapped, hands it to a `#[cfg(test)]` double that production cannot
    /// reach by construction.
    ///
    /// `m` is deliberately NOT `pub`: a `pub` fn is seeded as a pub-api root and
    /// `pub_root_has_real_caller` would classify it before the guard ever sees
    /// it. The real handler methods are trait-impl methods, not `pub` — mirrored
    /// here so the fixture actually reaches the code under test.
    ///
    /// F1 is SPLIT across F1a/F1b so each conjunct of
    /// `is_test = self_is_test || parent_is_test` is pinned INDEPENDENTLY: a
    /// single fixture marking both the method and its impl test-only cannot say
    /// which term carries the verdict, so a regression deleting either term
    /// would still pass it.
    ///
    /// F1a — ONLY the METHOD is test-only (`self_is_test`); its impl block is a
    /// production node. This is the `#[cfg(test)]`-method-in-a-production-impl
    /// shape, and it is RED if `self_is_test` is dropped from the disjunction.
    #[test]
    fn guard_rescue_caps_via_method_own_test_bit() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("FailHandler", "trait", "src/handler.rs", "pub");
        // PRODUCTION impl block — carries no test-ness signal.
        let m_impl = make_node_vis(
            "impl FailHandler for HintingFailHandler",
            "impl",
            "src/handler.rs",
            "",
        );
        let m = make_node_test(
            "HintingFailHandler::handle",
            "function",
            "src/handler.rs",
            "private",
        );

        let (main_id, t_id, impl_id, m_id) = (
            main_node.memory_id,
            t.memory_id,
            m_impl.memory_id,
            m.memory_id,
        );
        for n in [main_node, t, m_impl, m] {
            graph.add_node(n).unwrap();
        }
        // main --References--> T  => T is Wired (the dispatch evidence).
        graph.add_edge(main_id, t_id, references_edge()).unwrap();
        graph.add_edge(impl_id, m_id, contains_edge()).unwrap();
        graph.add_edge(impl_id, t_id, implements_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "FailHandler"),
            ReachabilityClass::Wired,
            "fixture precondition: the trait must be reached, else the guard never fires"
        );
        assert_eq!(
            class_of(&report, "HintingFailHandler::handle"),
            ReachabilityClass::TestOnly,
            "the METHOD's OWN test bit (`self_is_test`) must cap the rescue: a \
             #[cfg(test)] method must not inherit the trait's production Wired tier \
             (HEAD returns Wired: the false-WIRED this cap exists to kill)"
        );
    }

    /// F1b — ONLY the IMPL BLOCK is test-only (`parent_is_test`); the method
    /// carries NO test-ness signal (its `is_test_only` bit is absent and its
    /// name does not match the `tests::` fallback heuristic). This is the whole
    /// `#[cfg(test)] impl T for Mock` shape — the real dogfood mechanism, where
    /// SCIP/old nodes may leave a member's own bit unset — and it is RED if
    /// `parent_is_test` is dropped from the disjunction.
    #[test]
    fn guard_rescue_caps_via_enclosing_impl_test_bit() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("FailHandler", "trait", "src/handler.rs", "pub");
        let m_impl = make_node_test(
            "impl FailHandler for MockFailHandler",
            "impl",
            "src/handler.rs",
            "",
        );
        // The METHOD carries no test-ness of its own — `parent_is_test` is the
        // only signal in this graph.
        let m = make_node_vis(
            "MockFailHandler::handle",
            "function",
            "src/handler.rs",
            "private",
        );

        let (main_id, t_id, impl_id, m_id) = (
            main_node.memory_id,
            t.memory_id,
            m_impl.memory_id,
            m.memory_id,
        );
        for n in [main_node, t, m_impl, m] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, t_id, references_edge()).unwrap();
        graph.add_edge(impl_id, m_id, contains_edge()).unwrap();
        graph.add_edge(impl_id, t_id, implements_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "FailHandler"),
            ReachabilityClass::Wired,
            "fixture precondition: the trait must be reached, else the guard never fires"
        );
        assert_eq!(
            class_of(&report, "MockFailHandler::handle"),
            ReachabilityClass::TestOnly,
            "the ENCLOSING IMPL's test bit (`parent_is_test`) must cap the rescue even \
             when the method's own bit is absent (HEAD returns Wired)"
        );
    }

    /// F2 NEGATIVE CONTROL (MANDATORY — the cap must NOT over-fire). The SAME
    /// shape as F1 with a PRODUCTION struct: `m` must still rescue to **Wired**,
    /// on HEAD and after. This is what proves the cap leaves the handlers that
    /// legitimately rescue today untouched — the cap keys on test-ness, not on
    /// "is a trait-impl method".
    #[test]
    fn guard_rescue_does_not_cap_production_trait_impl_method() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("FailHandler", "trait", "src/handler.rs", "pub");
        let p_impl = make_node_vis(
            "impl FailHandler for RealFailHandler",
            "impl",
            "src/handler.rs",
            "",
        );
        let m = make_node_vis(
            "RealFailHandler::handle",
            "function",
            "src/handler.rs",
            "private",
        );

        let (main_id, t_id, impl_id, m_id) = (
            main_node.memory_id,
            t.memory_id,
            p_impl.memory_id,
            m.memory_id,
        );
        for n in [main_node, t, p_impl, m] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, t_id, references_edge()).unwrap();
        graph.add_edge(impl_id, m_id, contains_edge()).unwrap();
        graph.add_edge(impl_id, t_id, implements_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "RealFailHandler::handle"),
            ReachabilityClass::Wired,
            "a PRODUCTION implementor's dyn-dispatched method must still rescue to the \
             trait's reached tier — the cap must not fire on it"
        );
    }

    /// F3a — the TRAIT arm is bound too (a design that capped only arm (a) was
    /// BLOCKED; these two tests are what show the other arms are genuinely
    /// bound). A PRODUCTION trait reached from `main` (→ Wired) with a
    /// test-module member: the V3-4 trait arm hands out the trait node's Wired
    /// tier, so without the cap the member reads Wired.
    ///
    /// The reached trait MUST be production: a test-only trait is pruned by the
    /// production/pub-api walks and so can never classify Wired/PublicApi —
    /// meaning the test-ness here necessarily comes from the MEMBER's own bit
    /// (`self_is_test`).
    #[test]
    fn guard_rescue_trait_arm_caps_test_module_member() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("Validator", "trait", "src/v.rs", "pub");
        let dm = make_node_test("Validator::validate", "function", "src/v.rs", "private");

        let (main_id, t_id, dm_id) = (main_node.memory_id, t.memory_id, dm.memory_id);
        for n in [main_node, t, dm] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, t_id, references_edge()).unwrap();
        graph.add_edge(t_id, dm_id, contains_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "Validator"),
            ReachabilityClass::Wired,
            "fixture precondition: the trait must be reached, else the trait arm never fires"
        );
        assert_eq!(
            class_of(&report, "Validator::validate"),
            ReachabilityClass::TestOnly,
            "the TRAIT arm must cap a test-module member (HEAD: Wired) — arm (a) is not \
             the only rescue path that free-rides on production dispatch evidence"
        );
    }

    /// F3b — impl arm (b) (the concrete `struct`/`enum` `Contains` path, taken
    /// when the impl has NO `Implements` edge) is bound. A PRODUCTION struct
    /// reached from `main` (→ Wired) carrying a `#[cfg(test)]` inherent impl:
    /// arm (b) reads the struct's Wired tier, so without the cap the method
    /// inside that test-only impl reads Wired.
    ///
    /// The method's own bit is deliberately absent and its name does not match
    /// the `tests::` heuristic — the ONLY test-ness signal available is the impl
    /// block's (`parent_is_test`), so this pins arm (b)'s return path
    /// specifically.
    #[test]
    fn guard_rescue_arm_b_caps_test_module_impl_on_production_struct() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let s = make_node_vis("Engine", "struct", "src/engine.rs", "pub");
        let t_impl = make_node_test("impl Engine (test helpers)", "impl", "src/engine.rs", "");
        let m = make_node_vis(
            "Engine::test_helper",
            "function",
            "src/engine.rs",
            "private",
        );

        let (main_id, s_id, impl_id, m_id) = (
            main_node.memory_id,
            s.memory_id,
            t_impl.memory_id,
            m.memory_id,
        );
        for n in [main_node, s, t_impl, m] {
            graph.add_node(n).unwrap();
        }
        // main --References--> Engine  => the concrete type is reached (Wired).
        graph.add_edge(main_id, s_id, references_edge()).unwrap();
        // struct --Contains--> impl --Contains--> method  (arm (b): no Implements)
        graph.add_edge(s_id, impl_id, contains_edge()).unwrap();
        graph.add_edge(impl_id, m_id, contains_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "Engine"),
            ReachabilityClass::Wired,
            "fixture precondition: the concrete type must be reached, else arm (b) never fires"
        );
        assert_eq!(
            class_of(&report, "Engine::test_helper"),
            ReachabilityClass::TestOnly,
            "impl arm (b) must cap a #[cfg(test)] impl's method against the production \
             struct's Wired tier (HEAD: Wired)"
        );
    }

    // -----------------------------------------------------------------------
    // WAVE-2 — the GO arm of the cap (`"struct" | "enum"` parent)
    //
    // The Go arm is the ONLY arm whose Contains-parent is a `struct`/`enum`:
    // Go has no impl blocks, so `edge_builder` links a method straight to its
    // RECEIVER TYPE (WU-0023 P3b Bundle-3 / DEC-IFACE). None of F1a/F1b/F3a/F3b
    // builds that topology, so without G1/G2 BOTH of the Go arm's returns would
    // ship the cap unpinned.
    //
    // The cap FIRES on real Go by the same persisted bit these fixtures set:
    // `language/go.rs:124` computes `file_is_test = file_path.ends_with(
    // "_test.go")` and `:229` stores it as `is_test_only`, which
    // `is_test_module_symbol` reads FIRST. So a Go test double in `_test.go`
    // carries `Some(true)` exactly as `make_node_test` does — these fixtures
    // model the real mechanism, not the `tests::` name fallback (which Go
    // symbol names never match anyway).
    // -----------------------------------------------------------------------

    /// G1 — the Go arm's FIRST return (the RECEIVER TYPE is itself reached).
    /// `main --References--> Server` makes the receiver Wired; `Server.Handle`
    /// lives in `srv_test.go` (`is_test_only: Some(true)`) and has no incoming
    /// `Calls`, so it is residual Dead and the `== Dead` candidate gate calls
    /// the guard. Uncapped, the Go arm hands the receiver's production Wired
    /// tier to a `_test.go` double. RED without the cap (left: Wired).
    #[test]
    fn go_guard_rescue_caps_test_file_method_on_reached_receiver() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        // Go receiver TYPE — production file, reached from main.
        let server = make_node_vis("Server", "struct", "srv.go", "pub");
        // Go method in a `_test.go` file: the receiver-type Contains-parent and
        // NO impl block is what routes this to the Go arm.
        let handle = make_node_test("Server.Handle", "function", "srv_test.go", "private");

        let (main_id, srv_id, h_id) = (main_node.memory_id, server.memory_id, handle.memory_id);
        for n in [main_node, server, handle] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, srv_id, references_edge()).unwrap();
        // receiver --Contains--> method (NO impl block: the Go topology).
        graph.add_edge(srv_id, h_id, contains_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "Server"),
            ReachabilityClass::Wired,
            "fixture precondition: the Go receiver type must be reached, else the Go \
             arm's first return never fires"
        );
        assert_eq!(
            class_of(&report, "Server.Handle"),
            ReachabilityClass::TestOnly,
            "a Go method in a `_test.go` file must NOT inherit its reached receiver \
             type's production Wired tier (HEAD returns Wired)"
        );
    }

    /// G2 — the Go arm's SECOND return (the receiver IMPLEMENTS a reached
    /// interface). The receiver is deliberately UNREACHED and private, so
    /// `reached_tier(&parent_id)` is `None` and the first return is skipped —
    /// that is what pins the second return specifically. This is the real Go
    /// shape of an unexported type satisfying an exported, dynamically
    /// dispatched interface. RED without the cap (left: Wired).
    #[test]
    fn go_guard_rescue_caps_test_file_method_via_receiver_implements() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        // The reached PRODUCTION interface — the dispatch evidence.
        let iface = make_node_vis("Handler", "trait", "iface.go", "pub");
        // Unexported, UNREACHED receiver => reached_tier(receiver) == None, so
        // the Go arm falls through its first return to the Implements loop.
        let server = make_node_vis("server", "struct", "srv.go", "private");
        let handle = make_node_test("server.Handle", "function", "srv_test.go", "private");

        let (main_id, iface_id, srv_id, h_id) = (
            main_node.memory_id,
            iface.memory_id,
            server.memory_id,
            handle.memory_id,
        );
        for n in [main_node, iface, server, handle] {
            graph.add_node(n).unwrap();
        }
        graph
            .add_edge(main_id, iface_id, references_edge())
            .unwrap();
        graph.add_edge(srv_id, iface_id, implements_edge()).unwrap();
        graph.add_edge(srv_id, h_id, contains_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "Handler"),
            ReachabilityClass::Wired,
            "fixture precondition: the interface must be reached, else the Go arm's \
             Implements return never fires"
        );
        // Pin the precondition to what `reached_tier` ACTUALLY gates on, not to a
        // proxy: it maps Wired->Wired, TestOnly->TestOnly and PublicApi|Structural
        // ->PublicApi, so the Go arm's FIRST return fires on ANY of those four. A
        // bare `!= Wired` would let a future change (e.g. `struct` entering
        // STRUCTURAL_KINDS) route this test through the FIRST return while it
        // stayed green — silently un-pinning the SECOND, the only return G2 exists
        // to cover.
        assert!(
            matches!(
                class_of(&report, "server"),
                ReachabilityClass::Dead
                    | ReachabilityClass::Suspected
                    | ReachabilityClass::Orphan
                    | ReachabilityClass::Unclassified
            ),
            "fixture precondition: `reached_tier(receiver)` must be None — the receiver's \
             class must be one `reached_tier` maps to None, NOT Wired/PublicApi/Structural/\
             TestOnly — else the Go arm's FIRST return fires and this test pins the wrong \
             return (got {:?})",
            class_of(&report, "server")
        );
        assert_eq!(
            class_of(&report, "server.Handle"),
            ReachabilityClass::TestOnly,
            "a Go method in a `_test.go` file must NOT inherit the tier of the interface \
             its receiver implements (HEAD returns Wired)"
        );
    }

    /// G3 — the GO NEGATIVE CONTROL (mandatory). The SAME topology as G1 with a
    /// PRODUCTION method (`srv.go`, `is_test_only: Some(false)` — exactly what
    /// `language/go.rs` stores for a non-`_test.go` file): it must still rescue
    /// to **Wired**. This is what proves the Go cap keys on test-ness and does
    /// NOT over-fire on the production Go methods the P4 Go-cert track depends
    /// on. It passes both WITH and WITHOUT the cap.
    #[test]
    fn go_guard_rescue_does_not_cap_production_method_on_reached_receiver() {
        let mut graph = KnowledgeGraph::new();

        let main_node = make_node("main", "function", "src/main.rs");
        let server = make_node_vis("Server", "struct", "srv.go", "pub");
        // A PRODUCTION Go method: the Go extractor sets `is_test_only: false`
        // for every symbol in a non-`_test.go` file.
        let handle = GraphNode {
            is_test_only: Some(false),
            ..make_node_vis("Server.Handle", "function", "srv.go", "private")
        };

        let (main_id, srv_id, h_id) = (main_node.memory_id, server.memory_id, handle.memory_id);
        for n in [main_node, server, handle] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, srv_id, references_edge()).unwrap();
        graph.add_edge(srv_id, h_id, contains_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "Server"),
            ReachabilityClass::Wired,
            "fixture precondition: the Go receiver type must be reached"
        );
        assert_eq!(
            class_of(&report, "Server.Handle"),
            ReachabilityClass::Wired,
            "a PRODUCTION Go method under a reached receiver must STILL rescue to Wired \
             — the cap must not over-fire on the Go arm"
        );
    }

    /// Export syntax inside `_test.go` does not make a symbol part of the
    /// production package API.  In particular, an exported method on a test
    /// double must remain in the test reachability lane so the guard re-walk can
    /// carry exact uses in its body to other test-only symbols.
    #[test]
    fn go_test_file_exports_are_not_production_api_roots() {
        let mut graph = KnowledgeGraph::new();

        let production_api = GraphNode {
            is_test_only: Some(false),
            ..make_node_vis("Exported", "function", "api.go", "pub")
        };
        let test_root = GraphNode {
            is_test_root: true,
            ..make_node_test("TestMissingSecret", "function", "secret_test.go", "pub")
        };
        let test_double = make_node_test("fakeSMAPI", "struct", "secret_test.go", "private");
        let exported_method = make_node_test(
            "fakeSMAPI::GetSecretValue",
            "function",
            "secret_test.go",
            "pub",
        );
        let constructed_error = make_node_test("smNotFound", "struct", "secret_test.go", "private");

        let (api_id, test_id, double_id, method_id, error_id) = (
            production_api.memory_id,
            test_root.memory_id,
            test_double.memory_id,
            exported_method.memory_id,
            constructed_error.memory_id,
        );
        for node in [
            production_api,
            test_root,
            test_double,
            exported_method,
            constructed_error,
        ] {
            graph.add_node(node).unwrap();
        }
        graph
            .add_edge(
                test_id,
                double_id,
                GraphEdge {
                    kind: EdgeKind::TypeOf,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        graph
            .add_edge(double_id, method_id, contains_edge())
            .unwrap();
        graph
            .add_edge(
                method_id,
                error_id,
                GraphEdge {
                    kind: EdgeKind::TypeOf,
                    ..GraphEdge::default()
                },
            )
            .unwrap();

        let analyzer = ReachabilityAnalyzer::new(
            &graph,
            vec![EntryPoint {
                name: "fixture".into(),
                kind: EntryPointKind::LibRoot,
                file_path: PathBuf::new(),
                crate_name: "fixture".into(),
            }],
        );
        let roots = analyzer.resolved_roots();
        assert!(
            roots.public_api.contains(&api_id),
            "control: a production Go export must remain a public API root"
        );
        assert!(
            !roots.public_api.contains(&method_id),
            "an exported method in `_test.go` is not production API"
        );

        let report = analyzer.analyze();
        assert_eq!(
            class_of(&report, "fakeSMAPI::GetSecretValue"),
            ReachabilityClass::TestOnly,
            "the reached test double must rescue its exported method only into the test lane"
        );
        assert_eq!(
            class_of(&report, "smNotFound"),
            ReachabilityClass::TestOnly,
            "the guard re-walk must retain a type constructed by the rescued test method"
        );
    }

    /// Shared Wave-2 fixture driver: classify `graph` against a single binary
    /// entry point at `src/main.rs` (the `main` node every fixture above adds).
    fn analyze_with_main(graph: &KnowledgeGraph) -> ReachabilityReport {
        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("/workspace/src/main.rs"),
            crate_name: "test".to_string(),
        };
        ReachabilityAnalyzer::new(graph, vec![ep]).analyze()
    }

    fn class_of(report: &ReachabilityReport, name: &str) -> ReachabilityClass {
        report
            .classified
            .iter()
            .find(|c| c.symbol_name == name)
            .unwrap_or_else(|| panic!("fixture node `{name}` missing from the report"))
            .classification
    }

    // =======================================================================
    // ADR-0045 — census-scope falsifiers (D1 detached crates · D2 fixture
    // corpus · D3 dead abstractions). Each is the on-disk fossil of a behavior
    // this ADR adds; the guard/canary tests carry their non-vacuity break in
    // the doc comment.
    // =======================================================================

    /// A function node with an explicit `has_body` bit (D3a keys on
    /// abstract == `Some(false)`).
    fn make_fn_body(name: &str, file_path: &str, has_body: Option<bool>) -> GraphNode {
        GraphNode {
            has_body,
            ..make_node(name, "function", file_path)
        }
    }

    /// Find a classified node by BOTH name and file (D1 fixtures reuse the
    /// symbol `main` across the member bin and the detached bench).
    fn class_of_in(report: &ReachabilityReport, name: &str, file: &str) -> ReachabilityClass {
        report
            .classified
            .iter()
            .find(|c| c.symbol_name == name && c.file_path == file)
            .unwrap_or_else(|| panic!("fixture node `{name}` @ `{file}` missing"))
            .classification
    }

    /// Build a real on-disk workspace fixture for the D1 tests: a root
    /// `Cargo.toml` (`members = ["crates/*"]`), one real member crate `rc`, and a
    /// deliberately-detached `benches/db` crate (its own empty `[workspace]`).
    /// The census-scope D1 real-file check needs the files to actually exist.
    fn d1_workspace_fixture() -> tempfile::TempDir {
        use std::fs;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("crates/rc/src")).unwrap();
        fs::write(
            root.join("crates/rc/Cargo.toml"),
            "[package]\nname = \"rc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("crates/rc/src/main.rs"), "fn main() {}\n").unwrap();
        fs::create_dir_all(root.join("benches/db/src")).unwrap();
        fs::write(
            root.join("benches/db/Cargo.toml"),
            "[workspace]\n[package]\nname = \"db\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("benches/db/src/main.rs"), "fn main() {}\n").unwrap();
        dir
    }

    /// **F1** — a node in a deliberately-detached / nested-`[workspace]` crate is
    /// `Excluded`, not Dead; a real member-crate bin still classifies normally.
    /// RED on HEAD (no `Excluded` classifier): the bench nodes stay Dead.
    #[test]
    fn d1_detached_bench_excluded_not_dead() {
        let dir = d1_workspace_fixture();
        let root = dir.path();

        let mut graph = KnowledgeGraph::new();
        let rc_main = make_node("main", "function", "crates/rc/src/main.rs");
        let rc_helper = make_node("rc_helper", "function", "crates/rc/src/main.rs");
        let bench_main = make_node("bmain", "function", "benches/db/src/main.rs");
        let bench_helper = make_node("bench_helper", "function", "benches/db/src/main.rs");
        let (rc_main_id, rc_helper_id, bench_main_id, bench_helper_id) = (
            rc_main.memory_id,
            rc_helper.memory_id,
            bench_main.memory_id,
            bench_helper.memory_id,
        );
        for n in [rc_main, rc_helper, bench_main, bench_helper] {
            graph.add_node(n).unwrap();
        }
        graph
            .add_edge(rc_main_id, rc_helper_id, calls_edge())
            .unwrap();
        graph
            .add_edge(bench_main_id, bench_helper_id, calls_edge())
            .unwrap();

        let ep = EntryPoint {
            name: "rc".to_string(),
            kind: EntryPointKind::Binary,
            file_path: root.join("crates/rc/src/main.rs"),
            crate_name: "rc".to_string(),
        };
        let scope = CensusScope::for_workspace(root);
        let report = ReachabilityAnalyzer::new(&graph, vec![ep]).analyze_scoped(&scope);

        // The member bin classifies NORMALLY (Wired via its own main + call), NOT
        // Excluded.
        assert_eq!(
            class_of_in(&report, "main", "crates/rc/src/main.rs"),
            ReachabilityClass::Wired,
            "member-crate main is in the census and wired"
        );
        assert_eq!(
            class_of_in(&report, "rc_helper", "crates/rc/src/main.rs"),
            ReachabilityClass::Wired
        );
        // The detached bench (nested `[workspace]`, not a member) → Excluded.
        assert_eq!(
            class_of_in(&report, "bmain", "benches/db/src/main.rs"),
            ReachabilityClass::Excluded,
            "detached-bench main is OUT of the census"
        );
        assert_eq!(
            class_of_in(&report, "bench_helper", "benches/db/src/main.rs"),
            ReachabilityClass::Excluded
        );
    }

    /// **F2** (the BLOCKER guard) — a synthesized external-trait sentinel node
    /// (sentinel `file_path`, under no member crate) is NEVER swept by D1, even
    /// with D1 active. NON-VACUITY BREAK: replace the `canonicalize`/real-file
    /// check in `CensusScope::d1_excluded` with a lexical `root.join(..).starts_with`
    /// test → the sentinel (`<external-trait>`, not under a member) wrongly becomes
    /// Excluded → this test goes RED. Proven by the co-asserted bench node (D1 IS
    /// firing, so the sentinel's survival is not vacuous).
    #[test]
    fn d1_synthesized_sentinel_node_not_excluded() {
        let dir = d1_workspace_fixture();
        let root = dir.path();

        let mut graph = KnowledgeGraph::new();
        // A synthesized external-trait anchor — sentinel path, kind trait, pub.
        let sentinel = make_node_vis(
            "Serialize",
            "trait",
            crate::edge_builder::EXTERNAL_TRAIT_SENTINEL,
            "pub",
        );
        // A real detached-bench node (proves D1 is active in this run).
        let bench = make_node("bfn", "function", "benches/db/src/main.rs");
        let sentinel_id = sentinel.memory_id;
        for n in [sentinel, bench] {
            graph.add_node(n).unwrap();
        }

        let scope = CensusScope::for_workspace(root);
        let report = ReachabilityAnalyzer::new(&graph, vec![]).analyze_scoped(&scope);

        assert_ne!(
            report
                .classified
                .iter()
                .find(|c| c.memory_id == sentinel_id)
                .unwrap()
                .classification,
            ReachabilityClass::Excluded,
            "the external-trait sentinel is not a real file and must never be D1-excluded"
        );
        assert_eq!(
            class_of_in(&report, "bfn", "benches/db/src/main.rs"),
            ReachabilityClass::Excluded,
            "D1 IS firing (the bench node is excluded) — the sentinel's survival is non-vacuous"
        );
    }

    /// **F3** — a single-crate / no-`[workspace]` repo: the sole crate IS the
    /// census, so NOTHING is D1-excluded on the member-boundary ground.
    /// NON-VACUITY BREAK: change `resolve_workspace_members`'s no-workspace
    /// fallback to return an EMPTY member set → every node (under root, under no
    /// member) wrongly excludes → this test goes RED.
    #[test]
    fn d1_single_crate_no_workspace_census() {
        use std::fs;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"solo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("src/lib.rs"), "\n").unwrap();

        let mut graph = KnowledgeGraph::new();
        let mainn = make_node("main", "function", "src/main.rs");
        // An uncalled helper — would be Suspected/Dead, but must NOT be Excluded.
        let helper = make_node("solo_helper", "function", "src/lib.rs");
        let main_id = mainn.memory_id;
        for n in [mainn, helper] {
            graph.add_node(n).unwrap();
        }
        let _ = main_id;

        let ep = EntryPoint {
            name: "solo".to_string(),
            kind: EntryPointKind::Binary,
            file_path: root.join("src/main.rs"),
            crate_name: "solo".to_string(),
        };
        let scope = CensusScope::for_workspace(root);
        let report = ReachabilityAnalyzer::new(&graph, vec![ep]).analyze_scoped(&scope);

        assert_ne!(
            class_of(&report, "solo_helper"),
            ReachabilityClass::Excluded,
            "the sole crate is the census — nothing is D1-excluded"
        );
        assert_ne!(class_of(&report, "main"), ReachabilityClass::Excluded);
    }

    /// **F4** — a `/testdata/` (and a `/vendor/`) path SEGMENT is D2-Excluded;
    /// `src/testdata_loader.rs` (substring, not a segment) is NOT. RED on HEAD
    /// (no `Excluded`): the fixture nodes stay Dead/Suspected.
    #[test]
    fn d2_excluded_dir_segment() {
        let mut graph = KnowledgeGraph::new();
        let td = make_node("fixture_fn", "function", "crates/x/testdata/shape.rs");
        let vend = make_node("vend_fn", "function", "vendor/foo/lib.rs");
        // Substring, NOT a path segment — must NOT be excluded.
        let loader = make_node("loader_fn", "function", "src/testdata_loader.rs");
        for n in [td, vend, loader] {
            graph.add_node(n).unwrap();
        }

        // D2 active, D1 disabled (root/members None).
        let scope = CensusScope::with_parts(
            None,
            None,
            DEFAULT_EXCLUDED_DIRS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        );
        let report = ReachabilityAnalyzer::new(&graph, vec![]).analyze_scoped(&scope);

        assert_eq!(
            class_of(&report, "fixture_fn"),
            ReachabilityClass::Excluded,
            "a `/testdata/` path segment is fixture corpus → Excluded"
        );
        assert_eq!(
            class_of(&report, "vend_fn"),
            ReachabilityClass::Excluded,
            "a `/vendor/` path segment → Excluded"
        );
        assert_ne!(
            class_of(&report, "loader_fn"),
            ReachabilityClass::Excluded,
            "`testdata_loader.rs` is a SUBSTRING not a path SEGMENT — NOT excluded"
        );
    }

    /// **F5** — a GraphBackend-shaped trait: an ABSTRACT trait-def method with a
    /// non-Dead (wired) implementor is `Structural`. RED on HEAD (no D3a): the
    /// trait-def method stays Dead.
    #[test]
    fn d3a_trait_with_wired_impl_abstract_method_is_structural() {
        let mut graph = KnowledgeGraph::new();
        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("Backend", "trait", "src/g.rs", "pub");
        // Abstract trait-def method (no body) — private, so NOT pub-api-seeded.
        let td = make_fn_body("Backend::neighbors", "src/g.rs", Some(false));
        let mut td = td;
        td.visibility = "private".to_string();
        let impl_b = make_node_vis("impl Backend for KG", "impl", "src/g.rs", "");
        // The impl's override method — reached from main → Wired.
        let im = make_node("KG::neighbors", "function", "src/g.rs");

        let (main_id, t_id, td_id, impl_id, im_id) = (
            main_node.memory_id,
            t.memory_id,
            td.memory_id,
            impl_b.memory_id,
            im.memory_id,
        );
        let _ = td_id;
        for n in [main_node, t, td, impl_b, im] {
            graph.add_node(n).unwrap();
        }
        // trait Contains its def method.
        graph.add_edge(t_id, td_id, contains_edge()).unwrap();
        // impl Implements trait; impl Contains its override; main Calls the override.
        graph.add_edge(impl_id, t_id, implements_edge()).unwrap();
        graph.add_edge(impl_id, im_id, contains_edge()).unwrap();
        graph.add_edge(main_id, im_id, calls_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "KG::neighbors"),
            ReachabilityClass::Wired,
            "the impl's override is the wired implementor"
        );
        assert_eq!(
            class_of(&report, "Backend::neighbors"),
            ReachabilityClass::Structural,
            "abstract trait-def method with a wired implementor is compile-required → Structural"
        );
    }

    /// **F6** (the D3a tightening guard) — a DEFAULTED, never-overridden,
    /// never-called trait method STAYS Dead even though the trait has a live
    /// implementor. NON-VACUITY BREAK: loosen D3a to "trait has ≥1 non-Dead impl"
    /// (drop the abstract-or-overridden refinement) → this defaulted-unoverridden
    /// method false-Structural-izes → RED. (Green on HEAD by design — a "stays
    /// Dead" guard.)
    #[test]
    fn d3a_defaulted_unoverridden_uncalled_method_stays_dead() {
        let mut graph = KnowledgeGraph::new();
        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("Backend", "trait", "src/g.rs", "pub");
        // DEFAULTED trait method (has a body), never overridden, never called.
        let mut td = make_fn_body("Backend::helper", "src/g.rs", Some(true));
        td.visibility = "private".to_string();
        let impl_b = make_node_vis("impl Backend for KG", "impl", "src/g.rs", "");
        // The impl provides a DIFFERENT wired method — makes it a live impl, but
        // it does NOT override `helper`.
        let im = make_node("KG::other", "function", "src/g.rs");

        let (main_id, t_id, td_id, impl_id, im_id) = (
            main_node.memory_id,
            t.memory_id,
            td.memory_id,
            impl_b.memory_id,
            im.memory_id,
        );
        for n in [main_node, t, td, impl_b, im] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(t_id, td_id, contains_edge()).unwrap();
        graph.add_edge(impl_id, t_id, implements_edge()).unwrap();
        graph.add_edge(impl_id, im_id, contains_edge()).unwrap();
        graph.add_edge(main_id, im_id, calls_edge()).unwrap();

        let report = analyze_with_main(&graph);
        // The defaulted-unoverridden-uncalled method is genuinely removable.
        assert_ne!(
            class_of(&report, "Backend::helper"),
            ReachabilityClass::Structural,
            "a defaulted, never-overridden, never-called method is NOT compile-required"
        );
    }

    /// **F7** (THE CANARY) — a trait with ZERO implementors keeps its abstract
    /// method Dead. NON-VACUITY BREAK: weaken D3a to "∃ implementor OR the trait
    /// is pub" → `ConstraintChecker` (pub, 0 impls) falsely rescues → RED. (Green
    /// on HEAD by design.)
    #[test]
    fn constraint_checker_stays_dead() {
        let mut graph = KnowledgeGraph::new();
        let main_node = make_node("main", "function", "src/main.rs");
        let t = make_node_vis("ConstraintChecker", "trait", "src/k1.rs", "pub");
        let mut td = make_fn_body("ConstraintChecker::check", "src/k1.rs", Some(false));
        td.visibility = "private".to_string();
        let (t_id, td_id) = (t.memory_id, td.memory_id);
        for n in [main_node, t, td] {
            graph.add_node(n).unwrap();
        }
        // trait Contains its def method — but there is NO impl anywhere.
        graph.add_edge(t_id, td_id, contains_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "ConstraintChecker::check"),
            ReachabilityClass::Dead,
            "a trait with zero implementors is genuinely dead — the canary must stay Dead"
        );
    }

    /// **F8** — an empty MARKER impl (`impl Eq for ScoredCandidate {}`, the trait
    /// has ZERO method items) on a non-Dead Self type is `Structural`. RED on HEAD
    /// (no D3b): the impl block stays Dead.
    #[test]
    fn d3b_empty_marker_impl_on_wired_type_is_structural() {
        let mut graph = KnowledgeGraph::new();
        let main_node = make_node("main", "function", "src/main.rs");
        // A wired Self type (reached from main via References).
        let sc = make_node_vis("ScoredCandidate", "struct", "src/g.rs", "pub");
        // A zero-method marker trait (no Contains children).
        let eq = make_node_vis("Eq", "trait", "src/g.rs", "pub");
        let impl_eq = make_node_vis("impl Eq for ScoredCandidate", "impl", "src/g.rs", "");

        let (main_id, sc_id, eq_id, impl_id) = (
            main_node.memory_id,
            sc.memory_id,
            eq.memory_id,
            impl_eq.memory_id,
        );
        for n in [main_node, sc, eq, impl_eq] {
            graph.add_node(n).unwrap();
        }
        // main References the struct → Wired Self type.
        graph.add_edge(main_id, sc_id, references_edge()).unwrap();
        // struct Contains the impl (the Self-type link); impl Implements Eq.
        graph.add_edge(sc_id, impl_id, contains_edge()).unwrap();
        graph.add_edge(impl_id, eq_id, implements_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "ScoredCandidate"),
            ReachabilityClass::Wired
        );
        assert_eq!(
            class_of(&report, "impl Eq for ScoredCandidate"),
            ReachabilityClass::Structural,
            "a zero-method marker impl on a wired type is compile-required → Structural"
        );
    }

    /// **F9** (the D3b tightening guard) — an EMPTY impl of a trait that DEFINES a
    /// method item (a defaulted method) STAYS Dead: it is not a marker impl, and
    /// its empty body still exposes the callable default. NON-VACUITY BREAK: key
    /// D3b on "impl body empty" instead of "trait has zero method items" → this
    /// empty impl false-Structural-izes → RED. (Green on HEAD by design.)
    #[test]
    fn d3b_empty_impl_of_defaulted_trait_stays_dead() {
        let mut graph = KnowledgeGraph::new();
        let main_node = make_node("main", "function", "src/main.rs");
        let w = make_node_vis("Widget", "struct", "src/g.rs", "pub");
        // A trait WITH a method item (a defaulted method) — NOT a marker.
        let greet = make_node_vis("Greet", "trait", "src/g.rs", "pub");
        let mut greet_m = make_fn_body("Greet::hello", "src/g.rs", Some(true));
        greet_m.visibility = "private".to_string();
        // An EMPTY impl (no Contains children) of that defaulted trait.
        let impl_g = make_node_vis("impl Greet for Widget", "impl", "src/g.rs", "");

        let (main_id, w_id, greet_id, greet_m_id, impl_id) = (
            main_node.memory_id,
            w.memory_id,
            greet.memory_id,
            greet_m.memory_id,
            impl_g.memory_id,
        );
        for n in [main_node, w, greet, greet_m, impl_g] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, w_id, references_edge()).unwrap();
        graph
            .add_edge(greet_id, greet_m_id, contains_edge())
            .unwrap();
        graph.add_edge(w_id, impl_id, contains_edge()).unwrap();
        graph
            .add_edge(impl_id, greet_id, implements_edge())
            .unwrap();

        let report = analyze_with_main(&graph);
        assert_ne!(
            class_of(&report, "impl Greet for Widget"),
            ReachabilityClass::Structural,
            "an empty impl of a DEFAULTED (non-marker) trait is not a compile-required marker"
        );
    }

    /// **F10** — the over-exclusion guard: an `Excluded` node is a REPORTED,
    /// machine-queryable disposition (a `summary.excluded` count + an `EXCLUDED`
    /// label), never silently swallowed. RED on HEAD (no `excluded` field / label).
    #[test]
    fn excluded_bucket_is_reported() {
        let mut graph = KnowledgeGraph::new();
        let td = make_node("fixture_fn", "function", "crates/x/testdata/shape.rs");
        graph.add_node(td).unwrap();

        let scope = CensusScope::with_parts(
            None,
            None,
            DEFAULT_EXCLUDED_DIRS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        );
        let report = ReachabilityAnalyzer::new(&graph, vec![]).analyze_scoped(&scope);

        assert_eq!(
            report.summary.excluded, 1,
            "the Excluded count is reported in the summary, not dropped to invisibility"
        );
        assert_eq!(
            crate::graph_query::reachability_label(ReachabilityClass::Excluded),
            "EXCLUDED",
            "Excluded renders a machine-queryable label"
        );
    }

    /// **F5-move** (D3a REMEDIATION 2026-07-18) — the ordering falsifier the
    /// original F5 could not catch. Here the sole implementor's override method is
    /// reached ONLY by the guard TRANSITIVE re-walk (via its impl block's reached
    /// Self type — no direct call), exactly the real `impl GraphBackend for
    /// KnowledgeGraph` shape (its 13 methods are dyn-dispatched, invisible to the
    /// call graph). So at Pass-5c time the override is alive ONLY IF Pass 5c runs
    /// AFTER the guard re-walk. RED-ON-HEAD BREAK: move Pass 5c back before the
    /// guard post-passes → the override is still Dead when D3a reads the impl's
    /// children → `any_alive_impl` false → the abstract method false-stays Dead →
    /// this assert goes RED. (This is the exact bug the drive measured: Dead 21 not
    /// 9, the 12 `GraphBackend::*` stuck Dead.)
    #[test]
    fn d3a_abstract_method_structural_via_guard_rescued_impl() {
        let mut graph = KnowledgeGraph::new();
        let main_node = make_node("main", "function", "src/main.rs");
        // The reached Self type (main References it → Wired).
        let kg = make_node_vis("KG", "struct", "src/g.rs", "pub");
        let t = make_node_vis("Backend", "trait", "src/g.rs", "pub");
        // Abstract trait-def method (no body), private.
        let mut td = make_fn_body("Backend::neighbors", "src/g.rs", Some(false));
        td.visibility = "private".to_string();
        let impl_b = make_node_vis("impl Backend for KG", "impl", "src/g.rs", "");
        // The override — NOT directly called; reachable ONLY via the guard re-walk
        // off the impl's reached Self type (`KG`).
        let im = make_node("impl Backend for KG::neighbors", "function", "src/g.rs");

        let (main_id, kg_id, t_id, td_id, impl_id, im_id) = (
            main_node.memory_id,
            kg.memory_id,
            t.memory_id,
            td.memory_id,
            impl_b.memory_id,
            im.memory_id,
        );
        for n in [main_node, kg, t, td, impl_b, im] {
            graph.add_node(n).unwrap();
        }
        // main References KG → KG Wired.
        graph.add_edge(main_id, kg_id, references_edge()).unwrap();
        // KG Contains the impl block (Self-type link that lets the guard rescue the
        // impl's methods); impl Implements Backend; impl Contains its override;
        // trait Contains its abstract def method. NO call to the override.
        graph.add_edge(kg_id, impl_id, contains_edge()).unwrap();
        graph.add_edge(impl_id, t_id, implements_edge()).unwrap();
        graph.add_edge(impl_id, im_id, contains_edge()).unwrap();
        graph.add_edge(t_id, td_id, contains_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "KG"),
            ReachabilityClass::Wired,
            "fixture precondition: the Self type must be reached"
        );
        // The guard re-walk must rescue the override (not directly called).
        assert_ne!(
            class_of(&report, "impl Backend for KG::neighbors"),
            ReachabilityClass::Dead,
            "fixture precondition: the override is guard-rescued via its reached Self type"
        );
        assert_eq!(
            class_of(&report, "Backend::neighbors"),
            ReachabilityClass::Structural,
            "an abstract trait method whose impl is alive ONLY via the guard re-walk is \
             compile-required → Structural (Pass 5c must run AFTER the guard re-walk)"
        );
    }

    /// **F8-ext** (D3b REMEDIATION 2026-07-18) — the allowlist branch. An EXTERNAL
    /// `Eq` marker anchor (synthesized `<external-trait>` sentinel path, zero
    /// captured children) impl on a wired type is `Structural` because `Eq` is in
    /// [`STD_MARKER_TRAITS`]. This is the real `impl Eq for ScoredCandidate` shape
    /// (F8 uses a first-party `Eq`; this proves the sentinel/allowlist path).
    #[test]
    fn d3b_external_marker_eq_impl_is_structural() {
        let mut graph = KnowledgeGraph::new();
        let main_node = make_node("main", "function", "src/main.rs");
        let sc = make_node_vis("ScoredCandidate", "struct", "src/g.rs", "pub");
        // A SYNTHESIZED external `Eq` anchor: sentinel file path, zero children.
        let eq = make_node_vis(
            "Eq",
            "trait",
            crate::edge_builder::EXTERNAL_TRAIT_SENTINEL,
            "pub",
        );
        let impl_eq = make_node_vis("impl Eq for ScoredCandidate", "impl", "src/g.rs", "");

        let (main_id, sc_id, eq_id, impl_id) = (
            main_node.memory_id,
            sc.memory_id,
            eq.memory_id,
            impl_eq.memory_id,
        );
        for n in [main_node, sc, eq, impl_eq] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, sc_id, references_edge()).unwrap();
        graph.add_edge(sc_id, impl_id, contains_edge()).unwrap();
        graph.add_edge(impl_id, eq_id, implements_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "impl Eq for ScoredCandidate"),
            ReachabilityClass::Structural,
            "an external Eq marker (allowlist) impl on a wired type is compile-required → Structural"
        );
    }

    /// **F8-overfire** (D3b REMEDIATION 2026-07-18 — the over-fire falsifier). An
    /// impl of an EXTERNAL METHOD-BEARING trait (`Display`/`Ord`/…) is synthesized
    /// with a childless sentinel anchor, so the naive "trait has zero captured
    /// children" test cannot tell it from a real marker. Such an impl (Dead at
    /// Pass-5c time, with a wired method child so the roll-up would lift it to
    /// Wired) must STAY Wired, NOT be demoted to Structural. RED-ON-HEAD BREAK: key
    /// D3b on "trait has zero `function` children" instead of the marker allowlist →
    /// `Display` (childless sentinel) is treated as a marker → the Dead impl is
    /// false-Structural-ized before the roll-up can lift it → this assert goes RED.
    /// (This is the exact +79 over-fire the drive measured — a genuinely-Wired impl
    /// mislabeled Structural, destroying its "actively used" signal.)
    #[test]
    fn d3b_external_method_bearing_trait_impl_stays_wired() {
        let mut graph = KnowledgeGraph::new();
        let main_node = make_node("main", "function", "src/main.rs");
        let x = make_node_vis("X", "struct", "src/g.rs", "pub");
        // A SYNTHESIZED external `Display` anchor: sentinel path, zero children
        // (even though the real `Display` HAS a method — `fmt`).
        let display = make_node_vis(
            "Display",
            "trait",
            crate::edge_builder::EXTERNAL_TRAIT_SENTINEL,
            "pub",
        );
        let impl_d = make_node_vis("impl Display for X", "impl", "src/g.rs", "");
        // The impl's `fmt` method IS reached (direct call) → Wired; the roll-up then
        // lifts the (Dead-at-Pass-5c) impl block to Wired.
        let fmt = make_node("impl Display for X::fmt", "function", "src/g.rs");

        let (main_id, x_id, display_id, impl_id, fmt_id) = (
            main_node.memory_id,
            x.memory_id,
            display.memory_id,
            impl_d.memory_id,
            fmt.memory_id,
        );
        for n in [main_node, x, display, impl_d, fmt] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(main_id, x_id, references_edge()).unwrap();
        graph.add_edge(x_id, impl_id, contains_edge()).unwrap();
        graph
            .add_edge(impl_id, display_id, implements_edge())
            .unwrap();
        graph.add_edge(impl_id, fmt_id, contains_edge()).unwrap();
        // main directly Calls the fmt override → Wired.
        graph.add_edge(main_id, fmt_id, calls_edge()).unwrap();

        let report = analyze_with_main(&graph);
        assert_eq!(
            class_of(&report, "impl Display for X::fmt"),
            ReachabilityClass::Wired,
            "fixture precondition: the impl's method is directly called → Wired"
        );
        assert_eq!(
            class_of(&report, "impl Display for X"),
            ReachabilityClass::Wired,
            "an impl of an external METHOD-BEARING trait is NOT a marker — it must roll up to \
             Wired, never be demoted to Structural by D3b"
        );
    }
}
