//! Converts tree-sitter extractor output into knowledge graph nodes and edges.
//!
//! This module bridges the gap between the raw [`ExtractorOutput`] (flat list of
//! [`CodeSymbol`]s per file) and the [`KnowledgeGraph`] (nodes + typed edges).
//!
//! **Phase 1 edges** (structurally deterministic — no semantic analysis required):
//! - [`EdgeKind::Contains`] — parent symbol contains child symbol
//! - [`EdgeKind::Implements`] — impl block implements a trait
//! - [`EdgeKind::References`] — use statement references an external symbol

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, Instant},
};

#[cfg(test)]
thread_local! {
    /// Exact candidate population touched by build-time edge resolution.
    ///
    /// This is observation-only test instrumentation: production builds carry
    /// no counter or branch. It lets the performance contract assert algorithmic
    /// work instead of relying on a wall-clock threshold that flakes under load.
    static RESOLUTION_CANDIDATES_EXAMINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Exact same-document symbol population examined while resolving lexical
    /// parent relationships.
    static SOURCE_PARENT_CANDIDATES_EXAMINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_resolution_candidates_examined() {
    RESOLUTION_CANDIDATES_EXAMINED.with(|count| count.set(0));
}

#[cfg(test)]
fn resolution_candidates_examined() -> usize {
    RESOLUTION_CANDIDATES_EXAMINED.with(std::cell::Cell::get)
}

#[cfg(test)]
fn record_resolution_candidates_examined(count: usize) {
    RESOLUTION_CANDIDATES_EXAMINED.with(|total| total.set(total.get().saturating_add(count)));
}

#[cfg(test)]
fn reset_source_parent_candidates_examined() {
    SOURCE_PARENT_CANDIDATES_EXAMINED.with(|count| count.set(0));
}

#[cfg(test)]
fn source_parent_candidates_examined() -> usize {
    SOURCE_PARENT_CANDIDATES_EXAMINED.with(std::cell::Cell::get)
}

#[cfg(test)]
fn record_source_parent_candidates_examined(count: usize) {
    SOURCE_PARENT_CANDIDATES_EXAMINED.with(|total| total.set(total.get().saturating_add(count)));
}

use uuid::Uuid;

use crate::code_intel_domain::{
    DocumentMembershipKind, ProjectInventory, ProjectUnitDependencyGraphCoverage, ProjectUnitId,
    ProjectUnitKind,
};
use crate::graph::{
    EdgeKind, EdgeScope, GraphEdge, GraphError, GraphNode, KnowledgeGraph, SourceSpan,
};
use crate::reachability::ReachabilityClass;
use crate::structural_ir::{
    CodeSymbol, ExtractorOutput, StructuralDocumentTarget, StructuralRelation, SymbolKind,
    SymbolRole, symbol_kind_has_role,
};

/// Statistics returned from a graph build operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildStats {
    /// Number of graph nodes added (real extracted symbols only — NOT the
    /// synthetic external-trait anchors, which are counted in
    /// [`BuildStats::external_traits_synthesized`]).
    pub nodes_added: usize,
    /// Number of graph edges added.
    pub edges_added: usize,
    /// Declared `Extends`/`Implements` relationships whose target is outside the
    /// indexed project domain. This is normal for external Rust traits, Python
    /// base classes, and TypeScript interfaces; it is telemetry, not an
    /// under-production warning.
    pub edges_skipped_external_relation: usize,
    /// Edges skipped for any OTHER reason (genuine `NodeNotFound`: a `use` or
    /// field-type or struct target absent from the graph). Reason-broken-down
    /// from the old single `edges_skipped` so under-production is operator-visible.
    /// This bucket also holds intentional skips of built-in auto/marker traits.
    pub edges_skipped_other: usize,
    /// EC-12 (WU-0001): count of DISTINCT external-trait anchor nodes synthesized
    /// this build (the positive-signal complement to the skip count — cheap proof
    /// the producer now fires). One per distinct external trait NAME index-wide.
    pub external_traits_synthesized: usize,
    /// Detailed graph-materialization timings, populated only by the profiling
    /// entrypoint used by the immutable index pipeline.
    pub(crate) profile_timings: Vec<GraphBuildStepTiming>,
}

/// One measured step inside structural graph materialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GraphBuildStepTiming {
    pub(crate) label: &'static str,
    pub(crate) duration: Duration,
    pub(crate) items: usize,
}

impl BuildStats {
    /// Total edges skipped across all reasons.
    pub const fn total_skipped(&self) -> usize {
        self.edges_skipped_external_relation + self.edges_skipped_other
    }
}

/// Exact project-unit domain for cross-document structural relationships.
///
/// Tree-sitter facts can establish a candidate name, but they cannot prove
/// that two same-language documents belong to the same build or import graph.
/// The indexed project inventory owns that decision. Same-unit candidates are
/// admitted directly (except repository-wide loose-source collections), and
/// cross-unit candidates are admitted only through a complete directed local
/// dependency graph. Missing, duplicate, partial, or malformed ownership fails
/// closed for cross-document edges while same-document structure remains useful.
#[derive(Debug)]
struct StructuralRelationshipScope {
    owners: HashMap<String, StructuralDocumentOwner>,
    dependency_closure: HashMap<ProjectUnitId, HashSet<ProjectUnitId>>,
    compilation_roots: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StructuralDocumentOwner {
    project_unit_id: ProjectUnitId,
    kind: ProjectUnitKind,
}

impl StructuralRelationshipScope {
    fn from_inventory(inventory: &ProjectInventory) -> Self {
        let units = inventory
            .project_topology
            .units
            .iter()
            .map(|unit| (unit.project_unit_id.clone(), unit))
            .collect::<HashMap<_, _>>();
        let mut owner_candidates = HashMap::<String, Vec<StructuralDocumentOwner>>::new();
        for membership in inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
        {
            let Some(unit) = units.get(&membership.project_unit_id) else {
                continue;
            };
            if unit.language_id != membership.language_id {
                continue;
            }
            owner_candidates
                .entry(membership.document_path.clone())
                .or_default()
                .push(StructuralDocumentOwner {
                    project_unit_id: unit.project_unit_id.clone(),
                    kind: unit.kind,
                });
        }
        let owners = owner_candidates
            .into_iter()
            .filter_map(|(document, mut candidates)| {
                (candidates.len() == 1)
                    .then(|| (document, candidates.pop().expect("length checked")))
            })
            .collect::<HashMap<_, _>>();
        let compilation_roots = units
            .values()
            .flat_map(|unit| {
                unit.compilation_root_paths.iter().filter(|path| {
                    owners
                        .get(*path)
                        .is_some_and(|owner| owner.project_unit_id == unit.project_unit_id)
                })
            })
            .cloned()
            .collect();

        let mut dependency_closure = HashMap::new();
        let mut ambiguous_units = HashSet::new();
        for dependency_graph in
            inventory
                .project_topology
                .dependency_graphs
                .iter()
                .filter(|graph| {
                    graph.coverage == ProjectUnitDependencyGraphCoverage::Complete
                        && graph.gaps.is_empty()
                })
        {
            let graph_units = dependency_graph
                .project_unit_ids
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            let graph_is_valid = graph_units.len() == dependency_graph.project_unit_ids.len()
                && graph_units.iter().all(|unit_id| {
                    units.get(unit_id).is_some_and(|unit| {
                        unit.language_id == dependency_graph.language_id
                            && unit.ecosystem_id == dependency_graph.ecosystem_id
                    })
                })
                && dependency_graph.dependencies.iter().all(|dependency| {
                    dependency.dependent_project_unit_id != dependency.dependency_project_unit_id
                        && graph_units.contains(&dependency.dependent_project_unit_id)
                        && graph_units.contains(&dependency.dependency_project_unit_id)
                });
            if !graph_is_valid {
                continue;
            }

            for source_unit in &dependency_graph.project_unit_ids {
                let mut reachable = HashSet::from([source_unit.clone()]);
                loop {
                    let before = reachable.len();
                    for dependency in &dependency_graph.dependencies {
                        if reachable.contains(&dependency.dependent_project_unit_id) {
                            reachable.insert(dependency.dependency_project_unit_id.clone());
                        }
                    }
                    if reachable.len() == before {
                        break;
                    }
                }
                if dependency_closure
                    .insert(source_unit.clone(), reachable)
                    .is_some()
                {
                    ambiguous_units.insert(source_unit.clone());
                }
            }
        }
        for ambiguous_unit in ambiguous_units {
            dependency_closure.remove(&ambiguous_unit);
        }

        Self {
            owners,
            dependency_closure,
            compilation_roots,
        }
    }

    fn admits(&self, source_file: &str, candidate_file: &str) -> bool {
        let (Some(source), Some(candidate)) = (
            self.owners.get(source_file),
            self.owners.get(candidate_file),
        ) else {
            return false;
        };
        if source.project_unit_id == candidate.project_unit_id {
            return source.kind != ProjectUnitKind::LooseSources;
        }
        self.dependency_closure
            .get(&source.project_unit_id)
            .is_some_and(|dependencies| dependencies.contains(&candidate.project_unit_id))
    }

    fn is_compilation_root(&self, document: &str) -> bool {
        self.compilation_roots.contains(document)
    }

    /// Refine only loose Rust-source fallback ownership through exact,
    /// adapter-emitted document declarations. This closes custom Cargo target
    /// module trees without granting an entire sibling directory to the
    /// package. A target already owned by another concrete unit is never
    /// rewritten, and competing declarations fail closed.
    fn refine_contained_document_ownership(&mut self, outputs: &[ExtractorOutput]) {
        let indexed_documents = outputs
            .iter()
            .map(|output| output.file_path.as_str())
            .collect::<HashSet<_>>();
        loop {
            let mut proposals = BTreeMap::<String, Vec<StructuralDocumentOwner>>::new();
            for output in outputs {
                let Some(source_owner) = self.owners.get(&output.file_path).cloned() else {
                    continue;
                };
                if matches!(
                    source_owner.kind,
                    ProjectUnitKind::LooseSources | ProjectUnitKind::AuxiliarySources
                ) {
                    continue;
                }
                for symbol in &output.symbols {
                    for relation in &symbol.relations {
                        let StructuralRelation::ContainsDocument {
                            inline_path,
                            target,
                        } = relation
                        else {
                            continue;
                        };
                        let mut candidates = contained_document_candidates(
                            &output.file_path,
                            &symbol.name,
                            inline_path,
                            target,
                            Some(self.is_compilation_root(&output.file_path)),
                        );
                        candidates.sort();
                        candidates.dedup();
                        let mut resolved = candidates
                            .into_iter()
                            .filter(|candidate| indexed_documents.contains(candidate.as_str()))
                            .filter(|candidate| {
                                registered_language_for_file(&output.file_path)
                                    == registered_language_for_file(candidate)
                            })
                            .collect::<Vec<_>>();
                        if resolved.len() != 1 {
                            continue;
                        }
                        let candidate = resolved.pop().expect("length checked");
                        if self
                            .owners
                            .get(&candidate)
                            .is_some_and(|owner| owner.kind == ProjectUnitKind::LooseSources)
                        {
                            proposals
                                .entry(candidate)
                                .or_default()
                                .push(source_owner.clone());
                        }
                    }
                }
            }

            let mut changed = false;
            for (document, candidates) in proposals {
                let Some(first) = candidates.first() else {
                    continue;
                };
                if candidates.iter().all(|candidate| candidate == first) {
                    self.owners.insert(document, first.clone());
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
}

/// EC-12 (WU-0001): sentinel `file_path` marking a synthesized EXTERNAL-trait
/// anchor node (a trait we did not index — `Default`, `Display`, `From`,
/// `serde::Serialize`, …). Encoded in the EXISTING `file_path: String` field so
/// NO `GraphNode` schema field is added (the bincode/serde boundary is not
/// crossed). `<` is not a legal path character, so this never collides with a
/// real indexed source path. The anchor's `memory_id` is derived from this
/// sentinel (file-INDEPENDENT) so every impl of the same trait name maps to ONE
/// node index-wide (dedup).
pub(crate) const EXTERNAL_TRAIT_SENTINEL: &str = "<external-trait>";

/// EC-12 (WU-0001): synthesize (or reuse) the deduped external-trait anchor node
/// for `trait_name` and return its id. Idempotent: the deterministic id is keyed
/// on the file-independent [`EXTERNAL_TRAIT_SENTINEL`], so a second impl of the
/// same trait name resolves to the same node — `add_node` returns
/// `Err(DuplicateNode)`, which we treat as already-present (the Phase-1 pattern).
///
/// Returns `(id, newly_synthesized)` so the caller can count distinct anchors.
/// The node carries `kind = "trait"` so a later same-name impl's `find_trait_node`
/// resolves to it (collapsing repeats), and `reachability_class = Unclassified`
/// — the RC4 classifier chokepoint writes the real class (the anchor classifies
/// `Wired`/`TestOnly` via its inbound `Implements` edge, never `Dead` while it
/// has a non-dead impl, so it does NOT inflate the Dead count).
fn synthesize_external_trait_node(
    graph: &mut KnowledgeGraph,
    trait_name: &str,
) -> Result<(Uuid, bool), GraphError> {
    let ext_id = deterministic_id(EXTERNAL_TRAIT_SENTINEL, trait_name);
    let node = GraphNode {
        memory_id: ext_id,
        symbol_name: trait_name.to_string(),
        kind: "trait".to_string(),
        file_path: EXTERNAL_TRAIT_SENTINEL.to_string(),
        content_hash: String::new(),
        signature: format!("extern trait {trait_name}"),
        reachability_class: ReachabilityClass::Unclassified,
        line_start: None,
        line_end: None,
        has_body: Some(false),
        visibility: "pub".to_string(),
        is_test_only: Some(false),
        is_test_root: false,
        has_platform_cfg: false,
        // WU-0015 Leg 3a: external-trait sentinels are never oracle-flagged.
        rustc_flagged_dead: false,
        entry_retain: Default::default(),
        // WU-0016 Leg H: an external-trait sentinel has no source file to scan.
        has_uncaptured_items: false,
        oracle_receipt: None,
    };
    match graph.add_node(node) {
        Ok(_) => Ok((ext_id, true)),
        Err(GraphError::DuplicateNode(_)) => Ok((ext_id, false)),
        Err(e) => Err(e),
    }
}

/// Generate a deterministic [`Uuid`] for a code symbol based on file path and name.
///
/// Uses blake3 to hash `"file_path:symbol_name"` and takes the first 16 bytes
/// as a UUID. This ensures the same symbol always gets the same ID across
/// extractions, enabling incremental graph updates via invalidation + re-insertion.
pub fn deterministic_id(file_path: &str, symbol_name: &str) -> Uuid {
    let input = format!("{}:{}", file_path, symbol_name);
    let hash = blake3::hash(input.as_bytes());
    let bytes: [u8; 16] = hash.as_bytes()[..16]
        .try_into()
        .expect("blake3 hash is always 32 bytes; slicing 16 is infallible");
    Uuid::from_bytes(bytes)
}

/// Generate one deterministic identity per extracted source occurrence.
///
/// A qualified name is a lookup key, not a unique source identity: valid Rust
/// may contain multiple inherent `impl Type` blocks and valid Go may contain
/// multiple package-level `init` functions in one file. The occurrence ordinal
/// is counted independently for each qualified-name population in source-
/// extraction order. Kind remains node metadata rather than part of identity,
/// so changing a declaration's kind does not manufacture a delete/add pair.
/// Unrelated symbols can move or be added without changing an existing symbol's
/// identity. Occurrence zero deliberately keeps the canonical path/name ID;
/// only repeated occurrences need an ordinal discriminator.
#[must_use]
pub fn source_symbol_ids(file_path: &str, symbols: &[CodeSymbol]) -> Vec<Uuid> {
    source_symbol_ids_and_names(file_path, symbols).0
}

fn source_symbol_ids_and_names(
    file_path: &str,
    symbols: &[CodeSymbol],
) -> (Vec<Uuid>, Vec<String>) {
    let names = symbols.iter().map(qualified_name).collect::<Vec<_>>();
    let mut groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, name) in names.iter().enumerate() {
        groups.entry(name).or_default().push(index);
    }

    let mut ids = vec![None; symbols.len()];
    for (name, indices) in &mut groups {
        indices.sort_unstable_by_key(|index| {
            let symbol = &symbols[*index];
            (
                symbol.span.0,
                symbol.span.1,
                symbol.kind.to_string(),
                *index,
            )
        });
        for (occurrence, index) in indices.iter().copied().enumerate() {
            ids[index] = Some(source_symbol_id(file_path, name, occurrence as u64));
        }
    }
    let ids = ids
        .into_iter()
        .map(|id| id.expect("every source symbol belongs to one occurrence group"))
        .collect();
    (ids, names)
}

struct SourceSymbolIndex {
    ids: Vec<Uuid>,
    qualified_names: Vec<String>,
    indices_by_qualified_name: HashMap<String, Vec<usize>>,
}

fn source_symbol_index(file_path: &str, symbols: &[CodeSymbol]) -> SourceSymbolIndex {
    let (ids, qualified_names) = source_symbol_ids_and_names(file_path, symbols);
    let mut indices_by_qualified_name = HashMap::with_capacity(qualified_names.len());
    for (index, name) in qualified_names.iter().enumerate() {
        indices_by_qualified_name
            .entry(name.clone())
            .or_insert_with(Vec::new)
            .push(index);
    }
    SourceSymbolIndex {
        ids,
        qualified_names,
        indices_by_qualified_name,
    }
}

fn source_symbol_id(file_path: &str, qualified_name: &str, occurrence: u64) -> Uuid {
    if occurrence == 0 {
        return deterministic_id(file_path, qualified_name);
    }

    fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"h00/source-symbol/v1\0");
    hash_field(&mut hasher, file_path.as_bytes());
    hash_field(&mut hasher, qualified_name.as_bytes());
    hasher.update(&occurrence.to_le_bytes());
    let hash = hasher.finalize();
    let bytes: [u8; 16] = hash.as_bytes()[..16]
        .try_into()
        .expect("blake3 hash is always 32 bytes; slicing 16 is infallible");
    Uuid::from_bytes(bytes)
}

/// Build a fully-qualified symbol name for a [`CodeSymbol`].
///
/// If the symbol has a parent, the name is `"parent::name"`, otherwise just `"name"`.
pub fn qualified_name(sym: &CodeSymbol) -> String {
    sym.parent.as_ref().map_or_else(
        || sym.name.clone(),
        |parent| format!("{parent}::{}", sym.name),
    )
}

/// Convert a [`CodeSymbol`] into a [`GraphNode`].
fn symbol_to_node(
    sym: &CodeSymbol,
    memory_id: Uuid,
    qualified_name: &str,
    file_path: &str,
    has_platform_cfg: bool,
    has_uncaptured_items: bool,
) -> GraphNode {
    // WU-0003 / CL-REACH-06: persist the AST-derived test-only bit instead of
    // dropping it (the EC-7 write-only divergence). `Some(ast)` records that an
    // AST symbol set it; for an AST symbol that did NOT flag test-only we still
    // honor the anchored file-level signal (`file_is_test`) so a node under
    // `tests/` is recognized — preserving provenance (`Some`) while never
    // letting a file-level guess masquerade as a definite non-test fact.
    let is_test_only = Some(sym.is_test_only || crate::extractor::file_is_test(file_path));
    GraphNode {
        memory_id,
        symbol_name: qualified_name.to_string(),
        kind: sym.kind.to_string(),
        file_path: file_path.to_string(),
        content_hash: sym.content_hash.clone(),
        signature: sym.signature.clone(),
        // WU-0003 / CL-REACH RC5: constructed `Unclassified`, never `None` —
        // the classifier writes the real class through the RC4 chokepoint.
        reachability_class: ReachabilityClass::Unclassified,
        line_start: Some(sym.line_range.0),
        line_end: Some(sym.line_range.1),
        has_body: Some(sym.has_body),
        visibility: format!("{}", sym.visibility),
        is_test_only,
        is_test_root: sym.is_test_root,
        // WU-0015 Leg 2: the per-FILE platform-cfg scan result, stamped onto
        // EVERY node this file produces (the producer→node wiring for the signal).
        has_platform_cfg,
        // WU-0015 Leg 3a: the rustc/clippy dead-code oracle runs AFTER nodes
        // exist (index pipeline Phase 8e), so the producer stamps `false` here;
        // `rustc_oracle::apply_oracle` sets the bit on exact span matches later.
        rustc_flagged_dead: false,
        // WU-0015 Leg J: the AST-captured entry-point/retain attribute bitmask
        // carried straight from the `CodeSymbol` (the producer→node wiring).
        entry_retain: sym.entry_retain,
        // WU-0016 Leg H: the per-FILE uncaptured-item scan result, stamped onto
        // EVERY node this file produces (the producer→node wiring for the
        // capture-completeness signal).
        has_uncaptured_items,
        // WU-0016 Leg F: the corroborating oracle receipt is stamped by
        // `rustc_oracle::apply_oracle` at Phase 8e (beside `rustc_flagged_dead`),
        // AFTER nodes exist — so the producer stamps `None` here.
        oracle_receipt: None,
    }
}

/// Resolve a source symbol's same-file parent occurrence.
///
/// Nested Rust parents contain their children in byte space, which uniquely
/// disambiguates repeated impl/module names. Go receiver types are not lexical
/// containers, so a sole same-file name candidate remains a valid fallback.
/// Multiple non-containing candidates are ambiguous and deliberately skipped.
fn source_parent_id(
    output: &ExtractorOutput,
    source_index: &SourceSymbolIndex,
    child_index: usize,
    parent_name: &str,
) -> Option<Uuid> {
    let child = output.symbols.get(child_index)?;
    let candidate_indices = source_index.indices_by_qualified_name.get(parent_name)?;
    #[cfg(test)]
    record_source_parent_candidates_examined(candidate_indices.len());

    let mut candidate_count = 0_usize;
    let mut sole_candidate = None;
    let mut smallest_containing: Option<(usize, usize, usize)> = None;
    let mut smallest_span_tied = false;
    for index in candidate_indices.iter().copied() {
        if index == child_index {
            continue;
        }
        let candidate = output.symbols.get(index)?;
        candidate_count += 1;
        sole_candidate = Some(index);
        if candidate.span.0 <= child.span.0 && candidate.span.1 >= child.span.1 {
            let proposed = (
                candidate.span.1.saturating_sub(candidate.span.0),
                candidate.span.0,
                index,
            );
            match smallest_containing {
                None => {
                    smallest_containing = Some(proposed);
                    smallest_span_tied = false;
                }
                Some(current) if (proposed.0, proposed.1) < (current.0, current.1) => {
                    smallest_containing = Some(proposed);
                    smallest_span_tied = false;
                }
                Some(current) if (proposed.0, proposed.1) == (current.0, current.1) => {
                    smallest_span_tied = true;
                }
                Some(_) => {}
            }
        }
    }

    if let Some((_, _, index)) = smallest_containing
        && !smallest_span_tied
    {
        return source_index.ids.get(index).copied();
    }
    if candidate_count == 1 {
        return sole_candidate.and_then(|index| source_index.ids.get(index).copied());
    }
    None
}

/// Build the knowledge graph from extractor outputs.
///
/// For each [`ExtractorOutput`], this function:
/// 1. Converts every [`CodeSymbol`] into a [`GraphNode`] and inserts it.
/// 2. Materializes structural edges:
///    - **Contains** from the adapter's exact lexical parent;
///    - non-lexical relationships from typed [`StructuralRelation`] facts.
///
/// The builder resolves adapter facts under project ownership and dependency
/// scope. It does not reconstruct semantics from display names or signatures.
///
/// Duplicate nodes (same `memory_id`) are silently skipped — this supports
/// incremental rebuilds where some nodes already exist.
pub fn build_graph(
    outputs: &[ExtractorOutput],
    graph: &mut KnowledgeGraph,
) -> Result<BuildStats, GraphError> {
    build_graph_internal(outputs, graph, None, false, false)
}

/// Materialize production structural relationships under the exact indexed
/// project inventory.
///
/// The low-level public builders above remain useful for isolated extractor
/// and graph tests. Immutable indexing must use this path so repository-global
/// name collisions cannot outrank project ownership and declared dependencies.
pub(crate) fn build_graph_with_inventory(
    outputs: &[ExtractorOutput],
    graph: &mut KnowledgeGraph,
    inventory: &ProjectInventory,
    profile: bool,
    reconcile_existing: bool,
) -> Result<BuildStats, GraphError> {
    let mut relationship_scope = StructuralRelationshipScope::from_inventory(inventory);
    relationship_scope.refine_contained_document_ownership(outputs);
    build_graph_internal(
        outputs,
        graph,
        Some(&relationship_scope),
        profile,
        reconcile_existing,
    )
}

fn record_profile_step(
    stats: &mut BuildStats,
    started: Option<Instant>,
    label: &'static str,
    items: usize,
) {
    if let Some(started) = started {
        stats.profile_timings.push(GraphBuildStepTiming {
            label,
            duration: started.elapsed(),
            items,
        });
    }
}

fn record_profile_edge_step(
    stats: &mut BuildStats,
    started: Option<Instant>,
    label: &'static str,
    edges_before: usize,
) {
    let edges_added = stats.edges_added.saturating_sub(edges_before);
    record_profile_step(stats, started, label, edges_added);
}

fn add_structural_edge(
    graph: &mut KnowledgeGraph,
    stats: &mut BuildStats,
    source: Uuid,
    target: Uuid,
    kind: EdgeKind,
    weight: f32,
    scope: EdgeScope,
) -> Result<(), GraphError> {
    if source == target {
        return Ok(());
    }
    let confidence = if kind == EdgeKind::Extends { 0.85 } else { 0.7 };
    let edge = GraphEdge {
        kind,
        weight,
        confidence,
        scope,
        ..Default::default()
    };
    match graph.add_edge(source, target, edge) {
        Ok(()) => stats.edges_added += 1,
        Err(GraphError::NodeNotFound(_)) => stats.edges_skipped_other += 1,
        Err(error) => return Err(error),
    }
    Ok(())
}

fn build_graph_internal(
    outputs: &[ExtractorOutput],
    graph: &mut KnowledgeGraph,
    relationship_scope: Option<&StructuralRelationshipScope>,
    profile: bool,
    reconcile_existing: bool,
) -> Result<BuildStats, GraphError> {
    let mut stats = BuildStats::default();
    let symbol_count = outputs.iter().map(|output| output.symbols.len()).sum();
    let step_start = profile.then(Instant::now);
    let source_indexes = outputs
        .iter()
        .map(|output| source_symbol_index(&output.file_path, &output.symbols))
        .collect::<Vec<_>>();
    record_profile_step(
        &mut stats,
        step_start,
        "source occurrence identities",
        symbol_count,
    );

    if reconcile_existing {
        let current_source_ids = source_indexes
            .iter()
            .flat_map(|index| index.ids.iter().copied())
            .collect::<HashSet<_>>();
        graph.prepare_structural_rebuild(&current_source_ids);
    }

    // Phase 1: Insert all nodes.
    let step_start = profile.then(Instant::now);
    for (output, source_index) in outputs.iter().zip(&source_indexes) {
        for ((sym, memory_id), qualified_name) in output
            .symbols
            .iter()
            .zip(&source_index.ids)
            .zip(&source_index.qualified_names)
        {
            if reconcile_existing && graph.node(memory_id).is_some() {
                continue;
            }
            let node = symbol_to_node(
                sym,
                *memory_id,
                qualified_name,
                &output.file_path,
                output.has_platform_cfg,
                output.has_uncaptured_items(),
            );
            let memory_id = node.memory_id;
            match graph.add_node(node) {
                Ok(_) => stats.nodes_added += 1,
                Err(GraphError::DuplicateNode(_)) => {
                    // Already present — skip silently for incremental rebuilds.
                }
                Err(e) => return Err(e),
            }
            graph.set_source_span(
                memory_id,
                SourceSpan {
                    start_byte: sym.span.0,
                    end_byte: sym.span.1,
                },
            )?;
        }
    }
    let nodes_added = stats.nodes_added;
    record_profile_step(&mut stats, step_start, "node materialization", nodes_added);

    // Exact adapter-level lexical roots by source document. Cross-document
    // containment resolves only against this current fact population; it does
    // not infer top-level status from a qualified-name string or inspect the
    // filesystem.
    let mut top_level_by_file = BTreeMap::<String, Vec<Uuid>>::new();
    for (output, source_index) in outputs.iter().zip(&source_indexes) {
        for (symbol, id) in output.symbols.iter().zip(&source_index.ids) {
            if symbol.parent.is_none()
                && symbol_kind_has_role(symbol.kind.label(), SymbolRole::Definition)
            {
                top_level_by_file
                    .entry(output.file_path.clone())
                    .or_default()
                    .push(*id);
            }
        }
    }

    // Phase 2: Infer edges.
    let step_start = profile.then(Instant::now);
    let edges_before = stats.edges_added;
    for (output, source_index) in outputs.iter().zip(&source_indexes) {
        for (symbol_index, (sym, this_id)) in
            output.symbols.iter().zip(&source_index.ids).enumerate()
        {
            let this_id = *this_id;

            // Determine edge scope from the source symbol's test flag.
            let scope = if sym.is_test_only {
                EdgeScope::Test
            } else {
                EdgeScope::Production
            };

            // Contains edges: parent → child.
            if let Some(ref parent_name) = sym.parent {
                if let Some(parent_id) =
                    source_parent_id(output, source_index, symbol_index, parent_name)
                    && graph.node(&parent_id).is_some()
                {
                    let edge = GraphEdge {
                        kind: EdgeKind::Contains,
                        weight: 1.0,
                        scope,
                        ..Default::default()
                    };
                    match graph.add_edge(parent_id, this_id, edge) {
                        Ok(()) => stats.edges_added += 1,
                        Err(GraphError::NodeNotFound(_)) => stats.edges_skipped_other += 1,
                        Err(e) => return Err(e),
                    }
                } else {
                    stats.edges_skipped_other += 1;
                }
            }

            // Typed language-adapter facts are the only source of non-lexical
            // structural relationships. The graph builder resolves their
            // source-level names under project ownership and dependency scope;
            // it never reverse-parses a Rust display signature.
            for relation in &sym.relations {
                match relation {
                    StructuralRelation::References { target } => {
                        let target = last_segment(target);
                        if let Some(target_id) =
                            find_symbol_node(graph, &target, &output.file_path, relationship_scope)
                        {
                            add_structural_edge(
                                graph,
                                &mut stats,
                                this_id,
                                target_id,
                                EdgeKind::References,
                                0.5,
                                scope,
                            )?;
                        } else {
                            stats.edges_skipped_other += 1;
                        }
                    }
                    StructuralRelation::FieldOf { target }
                    | StructuralRelation::TypeOf { target } => {
                        if let Some(target_id) =
                            find_type_node(graph, target, &output.file_path, relationship_scope)
                        {
                            let (kind, weight) =
                                if matches!(relation, StructuralRelation::FieldOf { .. }) {
                                    (EdgeKind::FieldOf, 0.8)
                                } else {
                                    (EdgeKind::TypeOf, 0.7)
                                };
                            add_structural_edge(
                                graph, &mut stats, this_id, target_id, kind, weight, scope,
                            )?;
                        }
                    }
                    StructuralRelation::Extends { target } => {
                        if let Some(target_id) =
                            find_type_node(graph, target, &output.file_path, relationship_scope)
                        {
                            add_structural_edge(
                                graph,
                                &mut stats,
                                this_id,
                                target_id,
                                EdgeKind::Extends,
                                1.0,
                                scope,
                            )?;
                        } else if is_marker_supertrait(target) {
                            stats.edges_skipped_other += 1;
                        } else {
                            stats.edges_skipped_external_relation += 1;
                        }
                    }
                    StructuralRelation::Implements {
                        abstraction,
                        implementation,
                        synthesize_external,
                    } => {
                        let mut abstraction_id = find_abstraction_node(
                            graph,
                            abstraction,
                            &output.file_path,
                            relationship_scope,
                        );
                        if abstraction_id.is_none()
                            && *synthesize_external
                            && registered_language_for_file(&output.file_path) == Some("rust")
                        {
                            let (id, newly) = synthesize_external_trait_node(graph, abstraction)?;
                            if newly {
                                stats.external_traits_synthesized += 1;
                            }
                            abstraction_id = Some(id);
                        }
                        let Some(abstraction_id) = abstraction_id else {
                            stats.edges_skipped_external_relation += 1;
                            continue;
                        };
                        add_structural_edge(
                            graph,
                            &mut stats,
                            this_id,
                            abstraction_id,
                            EdgeKind::Implements,
                            1.0,
                            scope,
                        )?;
                        let implementation_id = implementation.as_deref().and_then(|target| {
                            find_type_node(graph, target, &output.file_path, relationship_scope)
                        });
                        if let Some(implementation_id) = implementation_id.or_else(|| {
                            symbol_kind_has_role(sym.kind.label(), SymbolRole::Type)
                                .then_some(this_id)
                        }) {
                            add_structural_edge(
                                graph,
                                &mut stats,
                                abstraction_id,
                                implementation_id,
                                EdgeKind::HasImpl,
                                1.0,
                                scope,
                            )?;
                        }
                    }
                    StructuralRelation::ContainedBy { target } => {
                        if let Some(container_id) =
                            find_type_node(graph, target, &output.file_path, relationship_scope)
                        {
                            add_structural_edge(
                                graph,
                                &mut stats,
                                container_id,
                                this_id,
                                EdgeKind::Contains,
                                1.0,
                                scope,
                            )?;
                        } else {
                            stats.edges_skipped_other += 1;
                        }
                    }
                    StructuralRelation::ContainsDocument {
                        inline_path,
                        target,
                    } => {
                        let is_compilation_root = relationship_scope
                            .map(|scope| scope.is_compilation_root(&output.file_path));
                        let mut candidates = contained_document_candidates(
                            &output.file_path,
                            &sym.name,
                            inline_path,
                            target,
                            is_compilation_root,
                        );
                        candidates.sort();
                        candidates.dedup();
                        let mut resolved = candidates
                            .into_iter()
                            .filter(|candidate| top_level_by_file.contains_key(candidate))
                            .filter(|candidate| {
                                document_candidate_is_in_source_domain(
                                    &output.file_path,
                                    candidate,
                                    relationship_scope,
                                )
                            })
                            .collect::<Vec<_>>();
                        if resolved.len() != 1 {
                            stats.edges_skipped_other += 1;
                            continue;
                        }
                        let candidate = resolved.pop().expect("length checked");
                        for &target_id in top_level_by_file
                            .get(&candidate)
                            .expect("resolved populated document")
                        {
                            if target_id == this_id {
                                continue;
                            }
                            add_structural_edge(
                                graph,
                                &mut stats,
                                this_id,
                                target_id,
                                EdgeKind::Contains,
                                1.0,
                                scope,
                            )?;
                        }
                    }
                }
            }
        }
    }

    record_profile_edge_step(
        &mut stats,
        step_start,
        "same-document relationships",
        edges_before,
    );

    // Phase 3c: package-dir-scoped cross-file Go method → receiver-type Contains
    // edges (WU-0023 P3b Bundle-3, THE rescue-guard enabler).
    //
    // A Go method is extracted as `kind == "function"` with `parent =
    // <receiver type name>` (go.rs `receiver_type_name`), so its qualified name
    // is `Receiver::method`. Phase 2's Contains linker is SAME-FILE ONLY
    // (`deterministic_id(&file_path, receiver)` must resolve in the method's own
    // file), but idiomatic Go routinely SPLITS a method and its receiver type
    // across files of the SAME package. When they are split, Phase 2 emits no
    // Contains edge, so `guard_rescue_tier`'s Go struct/enum arm (which walks the
    // method's incoming Contains) finds no receiver → the method false-DEADs even
    // WITH scip-go Calls/Implements edges.
    //
    // This pass links each such split-file method to its receiver type, scoped to
    // the package DIRECTORY (Go guarantees a method and its receiver share a
    // package == directory, and a package's top-level type names are unique). We
    // deliberately do NOT link across directories: same-named top-level types in
    // DIFFERENT packages are a real hazard (OQ-GO-XPKG-HOMONYM) and a mis-wired
    // edge is worse than a missing one — so a receiver name that is ambiguous
    // within its own directory (never true for valid Go, but defended anyway) is
    // skipped, never guessed. Rust is untouched: Rust methods live in an `impl`
    // block (never a struct/enum Contains-parent) and this pass only considers
    // `.go` files, so a Rust-only graph gains ZERO edges here (byte-identical).
    let step_start = profile.then(Instant::now);
    let edges_before = stats.edges_added;
    {
        // Candidate receiver-type nodes: top-level Go type nodes keyed by
        // (package_dir, type_name). A `Vec` value records within-directory
        // collisions so an ambiguous receiver is skipped, never mis-wired.
        let mut receiver_types: BTreeMap<(String, String), Vec<Uuid>> = BTreeMap::new();
        for n in graph.all_nodes() {
            if !is_go_path(&n.file_path) {
                continue;
            }
            // Top-level (parent == None ⇒ no `::`) type-shaped node. Go receiver
            // types are `struct` (structs + non-interface defined types) or, for
            // completeness, `enum`.
            if n.symbol_name.contains("::") || !matches!(n.kind.as_str(), "struct" | "enum") {
                continue;
            }
            receiver_types
                .entry((
                    go_package_dir(&n.file_path).to_string(),
                    n.symbol_name.clone(),
                ))
                .or_default()
                .push(n.memory_id);
        }

        for (output, source_index) in outputs.iter().zip(&source_indexes) {
            if !is_go_path(&output.file_path) {
                continue;
            }
            for (symbol_index, (sym, method_id)) in
                output.symbols.iter().zip(&source_index.ids).enumerate()
            {
                // Go method: a function whose `parent` is its receiver type.
                let Some(receiver) = sym.parent.as_deref() else {
                    continue;
                };
                if sym.kind != SymbolKind::Function {
                    continue;
                }
                let method_id = *method_id;

                // Skip when the receiver type is SAME-FILE: Phase 2 already linked
                // it (linking again would be a duplicate).
                if source_parent_id(output, source_index, symbol_index, receiver)
                    .is_some_and(|same_file_parent| graph.node(&same_file_parent).is_some())
                {
                    continue;
                }

                // Resolve the receiver type within the SAME package directory.
                let key = (
                    go_package_dir(&output.file_path).to_string(),
                    receiver.to_string(),
                );
                let Some(candidates) = receiver_types.get(&key) else {
                    // No same-package receiver type (e.g. an embedded/external
                    // type, or a type-alias LEAK not materialized) — silently
                    // skip, never link cross-directory.
                    continue;
                };
                let [receiver_id] = candidates.as_slice() else {
                    // 0 or >1 candidates: ambiguous within the package — never
                    // guess (OQ-GO-XPKG-HOMONYM safety: no edge beats a mis-wire).
                    continue;
                };
                if *receiver_id == method_id {
                    continue;
                }

                let scope = if sym.is_test_only {
                    EdgeScope::Test
                } else {
                    EdgeScope::Production
                };
                let edge = GraphEdge {
                    kind: EdgeKind::Contains,
                    weight: 1.0,
                    scope,
                    ..Default::default()
                };
                match graph.add_edge(*receiver_id, method_id, edge) {
                    Ok(()) => stats.edges_added += 1,
                    Err(GraphError::NodeNotFound(_)) => stats.edges_skipped_other += 1,
                    Err(e) => return Err(e),
                }
            }
        }
    }

    record_profile_edge_step(
        &mut stats,
        step_start,
        "Go receiver relationships",
        edges_before,
    );

    tracing::debug!(
        "build_graph: {} nodes, {} edges ({} skipped: {} external relation / {} other), {} external traits synthesized",
        stats.nodes_added,
        stats.edges_added,
        stats.total_skipped(),
        stats.edges_skipped_external_relation,
        stats.edges_skipped_other,
        stats.external_traits_synthesized,
    );

    Ok(stats)
}

/// Parse the target struct/type name from an impl block's symbol name.
///
/// - `"impl ToolHandler for BlastRadiusHandler"` → `Some("BlastRadiusHandler")`
/// - `"impl LanceStore"` → `Some("LanceStore")`
/// - `"foo::impl Bar"` → `Some("Bar")` (module-nested inherent impl)
/// - `"a::b::impl Tr for X"` → `Some("X")` (deeply-nested trait impl)
/// - `"impl ?"` → `None`
#[cfg(test)]
fn parse_struct_from_impl(impl_name: &str) -> Option<String> {
    // EC-10 (WU-0001 addendum): accept BOTH the top-level `impl <…>` form and
    // the module-qualified `<module-path>::impl <…>` form. A module-nested impl
    // is qualified by the EC-1 module recursion (extractor.rs:423) +
    // qualified_name() into e.g. `foo::impl Bar` / `a::b::impl Tr for X`, for
    // which a bare `strip_prefix("impl ")` returns None — silently dropping the
    // struct→impl Contains edge for EVERY module-nested impl (pervasive: esp.
    // `#[cfg(test)] mod tests { impl … }`). `strip_prefix` still fires FIRST for
    // top-level names (regression-safe); only the qualified form falls through
    // to `rsplit_once("::impl ")`, which splits at the LAST `::impl ` and so
    // handles multi-segment prefixes (`a::b::impl X` → rest `"X"`). The existing
    // " for " split + strip_generic_args below run unchanged on `rest`.
    let stripped = impl_name
        .strip_prefix("impl ")
        .or_else(|| impl_name.rsplit_once("::impl ").map(|(_, rest)| rest))?;
    let raw = stripped
        .find(" for ")
        .map_or(stripped, |for_idx| &stripped[for_idx + 5..]);
    // EC-2 (WU-0001): strip generic args so `impl Tr for Bar<T>` resolves to `Bar`.
    let type_name = strip_generic_args(raw.trim());
    if type_name.is_empty() || type_name == "?" {
        None
    } else {
        Some(type_name.to_string())
    }
}

/// Perform a full scan: extract all `.rs` files under `dir`, build graph.
///
/// After building structural edges, also creates `DependsOn` edges between
/// workspace crates by parsing Cargo.toml files.
pub fn full_scan(
    dir: &std::path::Path,
    graph: &mut KnowledgeGraph,
) -> Result<BuildStats, FullScanError> {
    let outputs = crate::extractor::extract_directory(dir)?;
    let mut stats = build_graph(&outputs, graph)?;

    // Add DependsOn edges between workspace crates.
    let dep_edges = build_dependency_edges(graph, dir)?;
    stats.edges_added += dep_edges;

    Ok(stats)
}

/// Incremental update: invalidate a single file, re-extract, rebuild edges.
///
/// This is the core of the incremental pipeline:
/// 1. Remove all nodes from the file (cascades edge removal).
/// 2. Re-extract symbols from the file.
/// 3. Insert new nodes + infer edges.
///
/// `root` is the workspace root for computing relative file paths.
///
/// Note: edges FROM other files TO symbols in this file are lost and would
/// need a full rebuild to restore. This is acceptable for Phase 1 —
/// a smarter incremental strategy is planned for CI9.
pub fn incremental_update(
    file_path: &std::path::Path,
    root: &std::path::Path,
    graph: &mut KnowledgeGraph,
) -> Result<BuildStats, FullScanError> {
    let rel = file_path.strip_prefix(root).unwrap_or(file_path);
    let path_str = rel.to_string_lossy().to_string();

    // Snapshot Hebbian weights before invalidation so they survive the
    // remove-then-rebuild cycle.
    let ids = graph.node_ids_for_file(&path_str);
    let snapshot = graph.snapshot_hebbian_weights(&ids);

    // Step 1: Invalidate existing nodes for this file.
    graph.invalidate_file(&path_str);

    // Step 2: Re-extract.
    let output = crate::extractor::extract_file(file_path, root)?;

    // Step 3: Rebuild.
    let mut stats = build_graph(&[output], graph)?;

    // Step 3b: Rebuild DependsOn edges (Cargo.toml may reference this crate).
    let dep_edges = build_dependency_edges(graph, root)?;
    stats.edges_added += dep_edges;

    // Step 4: Restore Hebbian weights to re-created edges.
    let restored = graph.restore_hebbian_weights(&snapshot);
    tracing::debug!(
        restored_edges = restored,
        file = %path_str,
        "Hebbian weights preserved in incremental update"
    );

    Ok(stats)
}

/// Parse trait name from an impl block name like `"impl Display for MyType"`.
///
/// Returns `Some("Display")` for `"impl Display for MyType"`,
/// `None` for `"impl MyType"` (inherent impl).
#[cfg(test)]
fn parse_trait_from_impl(impl_name: &str) -> Option<String> {
    // Pattern: "impl <Trait> for <Type>"
    let stripped = impl_name.strip_prefix("impl ")?;
    let for_idx = stripped.find(" for ")?;
    // EC-2 (WU-0001): strip generic args on the trait portion too (`Tr<X>` → `Tr`).
    let trait_name = strip_generic_args(stripped[..for_idx].trim());
    if trait_name.is_empty() {
        None
    } else {
        Some(trait_name.to_string())
    }
}

/// Extract the last segment from a path like `"std::collections::HashMap"` → `"HashMap"`.
fn last_segment(path: &str) -> String {
    path.rsplit("::").next().unwrap_or(path).to_string()
}

/// WU-0023 P3b Bundle-3: whether a workspace-relative path is a Go source file.
///
/// Used to fence the cross-file Go method→receiver Contains linker (Phase 3c) to
/// Go nodes ONLY, so a Rust-only graph gains zero edges from that pass (the RUST
/// NO-REGRESSION byte-identity).
fn is_go_path(file_path: &str) -> bool {
    file_path.ends_with(".go")
}

/// WU-0023 P3b Bundle-3: the Go PACKAGE directory of a workspace-relative source
/// path — everything up to the last `/` (a Go package == its directory).
///
/// `internal/wiring/opts.go` → `internal/wiring`; a bare `main.go` (no
/// directory) → `""` (the module-root package). The cross-file linker keys on
/// this so a method is only ever linked to a receiver type in its OWN package
/// directory, never across packages (OQ-GO-XPKG-HOMONYM safety).
fn go_package_dir(file_path: &str) -> &str {
    file_path.rfind('/').map_or("", |i| &file_path[..i])
}

/// EC-2 (WU-0001): strip a trailing generic argument list, returning the head.
/// `Bar<T>` → `Bar`, `Foo<{N}>` → `Foo`, `&T` / `u8` / `(A, B)` → unchanged.
/// NOT `unwrap_generic_types` (which would emit the inner `T` and drop primitives).
#[cfg(test)]
fn strip_generic_args(s: &str) -> &str {
    s.find('<').map_or(s, |i| s[..i].trim_end())
}

/// EC-4a (WU-0001): derive a coarse "crate" key from a node's file path so the
/// tie-break policy can express a same-crate tier between same-file and global.
///
/// The crate is approximated by the leading `crates/<name>/` segment when
/// present (the workspace layout), else the first path component. Bare file
/// names like `a.rs` have no shared crate prefix, so the same-crate tier is a
/// no-op for them and resolution falls through to global / no-locality.
///
/// This is the **canonical** crate-key derivation, shared by the build-time
/// resolver here and the query-time `graph_query::locality_pick` (ADR-0027 OD-1:
/// `crate_of` is the only DRY shared between the two resolvers).
pub(crate) fn crate_of(file_path: &str) -> &str {
    let p = file_path;
    if let Some(rest) = p.strip_prefix("crates/") {
        return rest.split('/').next().unwrap_or(rest);
    }
    p.split('/').next().unwrap_or(p)
}

/// Return the registered structural language for a source path.
///
/// Cross-document structural relationships are meaningful only inside a
/// language-owned resolution domain. Project-unit ownership narrows this
/// further at a later pipeline stage; this fence prevents a repository-global
/// homonym from manufacturing an edge across language grammars in the meantime.
fn registered_language_for_file(file_path: &str) -> Option<&'static str> {
    std::path::Path::new(file_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .and_then(crate::language::language_for_extension)
}

fn contained_document_candidates(
    declaring_document: &str,
    symbol_name: &str,
    inline_path: &[String],
    target: &StructuralDocumentTarget,
    is_compilation_root: Option<bool>,
) -> Vec<String> {
    std::path::Path::new(declaring_document)
        .extension()
        .and_then(|extension| extension.to_str())
        .and_then(crate::language::extractor_for_extension)
        .map_or_else(Vec::new, |adapter| {
            adapter.contained_document_candidates(
                declaring_document,
                symbol_name,
                inline_path,
                target,
                is_compilation_root,
            )
        })
}

fn document_candidate_is_in_source_domain(
    source_file: &str,
    candidate_file: &str,
    relationship_scope: Option<&StructuralRelationshipScope>,
) -> bool {
    let same_language = matches!(
        (
            registered_language_for_file(source_file),
            registered_language_for_file(candidate_file),
        ),
        (Some(source_language), Some(candidate_language)) if source_language == candidate_language
    );
    same_language
        && relationship_scope.is_none_or(|scope| scope.admits(source_file, candidate_file))
}

/// Whether `candidate` belongs to the source document's structural resolution
/// domain.
///
/// Same-document relationships remain valid even for synthetic unit fixtures.
/// Cross-document resolution fails closed unless both paths map to the same
/// registered language and, when production inventory is supplied, the exact
/// project-unit relationship permits the target. Derived nodes such as
/// external-trait anchors are not admitted here; their owning resolver handles
/// them explicitly after local source candidates have been exhausted.
fn candidate_is_in_source_domain(
    candidate: &GraphNode,
    source_file: &str,
    relationship_scope: Option<&StructuralRelationshipScope>,
) -> bool {
    if candidate.file_path == source_file {
        return true;
    }

    document_candidate_is_in_source_domain(source_file, &candidate.file_path, relationship_scope)
}

/// EC-4a (WU-0001) / EP2 (ADR-0027, Wave 2 OD-3): a kind constraint applied on
/// top of the build-time candidate pool's unconditional `use`-exclusion.
///
/// The three edge-resolver shapes have different kind needs, so EP2 models them
/// as a 3-way filter rather than a flat required kind (which would silently
/// narrow `find_symbol_node`):
/// - `Any` — no kind constraint beyond the always-on `use`-exclusion
///   (`find_symbol_node`).
/// - `One(k)` — `kind == k` (`find_trait_node`: `One("trait")`).
/// - `AnyOf(set)` — `set.contains(&kind)` (the type-kinds membership shape).
#[derive(Debug, Clone, Copy)]
pub(crate) enum KindFilter {
    /// No kind constraint beyond the unconditional `use`-exclusion.
    Any,
    /// Exactly one kind (`kind == k`). Test-only mutation-control shape.
    #[cfg(test)]
    One(&'static str),
    /// Membership in a fixed set of kinds.
    /// Used by `find_struct_for_impl` while retaining that resolver's distinct
    /// first-global fallback policy.
    AnyOf(&'static [&'static str]),
    /// Any kind carrying the named language-neutral role.
    Role(SymbolRole),
}

impl KindFilter {
    /// Whether a node of the given `kind` passes this filter. The `use`-exclusion
    /// is applied separately in [`candidates_for`] (it is unconditional, never
    /// part of the kind constraint), so `Any` accepts every non-`use` kind here.
    fn accepts(self, kind: &str) -> bool {
        match self {
            Self::Any => true,
            #[cfg(test)]
            Self::One(k) => kind == k,
            Self::AnyOf(set) => set.contains(&kind),
            Self::Role(role) => symbol_kind_has_role(kind, role),
        }
    }
}

/// EC-4a (WU-0001): collect every graph node whose `symbol_name` matches `name`,
/// split into exact matches and `::`-suffix matches, with `use` nodes excluded
/// (import statements are never valid edge targets) and an additional EP2
/// `kind_filter` applied (ADR-0027 Wave 2 OD-3).
///
/// This helper is **edge_builder-PRIVATE** — it is the build-time edge resolver's
/// candidate pool, NOT WU-0002's query-side F8 input (that is over
/// `graph_query::find_all_nodes_by_name`). The two resolvers share only the
/// CITED tie-break policy (per the FRAGO contract), never a function. The
/// `use`-exclusion is **unconditional** and applied before the `kind_filter`, so
/// a `kind == "use"` node with the exact query name is never a candidate under
/// ANY filter shape.
fn candidates_for<'g>(
    graph: &'g KnowledgeGraph,
    name: &str,
    source_file: &str,
    relationship_scope: Option<&StructuralRelationshipScope>,
    kind_filter: KindFilter,
) -> (Vec<&'g GraphNode>, Vec<&'g GraphNode>) {
    let suffix = format!("::{name}");
    let mut exact = Vec::new();
    let mut suffixed = Vec::new();
    let exact_population = graph.nodes_by_exact_name(name);
    let terminal = name.rsplit("::").next().unwrap_or(name);
    let suffix_population = graph.nodes_by_terminal_name(terminal);
    #[cfg(test)]
    record_resolution_candidates_examined(
        exact_population
            .len()
            .saturating_add(suffix_population.len()),
    );
    for n in exact_population {
        if !candidate_is_in_source_domain(n, source_file, relationship_scope) {
            continue;
        }
        if !symbol_kind_has_role(&n.kind, SymbolRole::Definition) {
            continue;
        }
        if !kind_filter.accepts(&n.kind) {
            continue;
        }
        exact.push(n);
    }
    for n in suffix_population {
        if !candidate_is_in_source_domain(n, source_file, relationship_scope) {
            continue;
        }
        if n.symbol_name == name || !symbol_kind_has_role(&n.kind, SymbolRole::Definition) {
            continue;
        }
        if !kind_filter.accepts(&n.kind) {
            continue;
        }
        if n.symbol_name.ends_with(&suffix) {
            suffixed.push(n);
        }
    }
    (exact, suffixed)
}

/// EP2 (ADR-0027): resolve `query` to a single build-time edge target, scoped to
/// `source_file` for locality and constrained by `kind`.
///
/// A **thin wrap** over the landed candidate source + tie-break policy: it builds
/// the (exact, suffixed) candidate pools via [`candidates_for`] (which bakes in
/// the unconditional `use`-exclusion + the EP2 `kind` filter) and applies
/// [`resolve_with_locality`] **verbatim** (the same-file then same-crate then
/// global-unique then suffix-tiers then shortest-name-unique-or-skip ladder). The
/// only added shape is the `Option<Uuid>`-to-`Option<SymbolId>` newtype wrap
/// (ADR-0027 typed identity).
///
/// Build-time "ambiguous with no locality" still resolves to `None` (skip) — no
/// edge beats a mis-wired edge. `find_symbol_node` / `find_trait_node` are
/// re-expressed onto this one candidate source.
#[cfg(test)]
pub(crate) fn resolve_for_edge(
    graph: &KnowledgeGraph,
    query: &str,
    source_file: &str,
    kind: KindFilter,
) -> Option<crate::graph_query::SymbolId> {
    resolve_for_edge_in_scope(graph, query, source_file, kind, None)
}

fn resolve_for_edge_in_scope(
    graph: &KnowledgeGraph,
    query: &str,
    source_file: &str,
    kind: KindFilter,
    relationship_scope: Option<&StructuralRelationshipScope>,
) -> Option<crate::graph_query::SymbolId> {
    let (exact, suffixed) = candidates_for(graph, query, source_file, relationship_scope, kind);
    resolve_with_locality(&exact, &suffixed, source_file).map(crate::graph_query::SymbolId::from)
}

/// EC-4a (WU-0001): apply the decided tie-break policy to a candidate pool,
/// scoped to `source_file` for locality.
///
/// Canonical order (cited by WU-0001 build-time + WU-0002 query-time so they
/// provably cannot drift): `same-file exact > same-crate exact > global exact
/// (only if unique) > same-file suffix > same-crate suffix > global suffix
/// (only if unique) > tie with no locality: shortest symbol_name > else None`.
///
/// Build-time "ambiguous" → skip (return `None`): no edge beats a mis-wired edge.
fn resolve_with_locality(
    exact: &[&GraphNode],
    suffixed: &[&GraphNode],
    source_file: &str,
) -> Option<Uuid> {
    let src_crate = crate_of(source_file);

    // Tier helper: given a candidate slice, pick the same-file node, then the
    // same-crate node, then a globally-unique node — returning early at the
    // first tier that yields a definite answer.
    let pick_tier = |cands: &[&GraphNode]| -> Option<Uuid> {
        // same-file (only meaningful when source_file is known).
        if !source_file.is_empty() {
            let same_file: Vec<&GraphNode> = cands
                .iter()
                .filter(|n| n.file_path == source_file)
                .copied()
                .collect();
            if same_file.len() == 1 {
                return Some(same_file[0].memory_id);
            }
            if same_file.len() > 1 {
                // Multiple same-file matches: shortest symbol_name wins
                // deterministically (most specific / least nested).
                return shortest_name(&same_file);
            }
            // same-crate (excluding same-file, which had none).
            let same_crate: Vec<&GraphNode> = cands
                .iter()
                .filter(|n| crate_of(&n.file_path) == src_crate)
                .copied()
                .collect();
            if same_crate.len() == 1 {
                return Some(same_crate[0].memory_id);
            }
            if same_crate.len() > 1 {
                return shortest_name(&same_crate);
            }
        }
        // global: accept ONLY if unique.
        if cands.len() == 1 {
            return Some(cands[0].memory_id);
        }
        None
    };

    // Exact matches take priority over suffix matches.
    if let Some(id) = pick_tier(exact) {
        return Some(id);
    }
    if let Some(id) = pick_tier(suffixed) {
        return Some(id);
    }

    // Last resort — tie with no locality: shortest symbol_name across the
    // combined pool, but ONLY when the shortest is unambiguous. Distinct
    // files / equal-length distinct names cannot be disambiguated → None/skip.
    let mut combined: Vec<&GraphNode> = Vec::with_capacity(exact.len() + suffixed.len());
    combined.extend_from_slice(exact);
    combined.extend_from_slice(suffixed);
    shortest_name_unique(&combined)
}

/// Shortest `symbol_name` wins; on a length tie the first (after a stable sort
/// by name then file) is returned for determinism. Used within a locality tier
/// where a definite pick is required.
fn shortest_name(cands: &[&GraphNode]) -> Option<Uuid> {
    let mut sorted: Vec<&GraphNode> = cands.to_vec();
    sorted.sort_by(|a, b| {
        a.symbol_name
            .len()
            .cmp(&b.symbol_name.len())
            .then_with(|| a.symbol_name.cmp(&b.symbol_name))
            .then_with(|| a.file_path.cmp(&b.file_path))
    });
    sorted.first().map(|n| n.memory_id)
}

/// Shortest `symbol_name` wins ONLY when strictly unique by length; a length
/// tie among distinct nodes is genuinely ambiguous → `None` (build-time skip).
fn shortest_name_unique(cands: &[&GraphNode]) -> Option<Uuid> {
    let mut min_len = usize::MAX;
    let mut min_id: Option<Uuid> = None;
    let mut tie = false;
    for n in cands {
        match n.symbol_name.len().cmp(&min_len) {
            std::cmp::Ordering::Less => {
                min_len = n.symbol_name.len();
                min_id = Some(n.memory_id);
                tie = false;
            }
            std::cmp::Ordering::Equal => {
                if min_id != Some(n.memory_id) {
                    tie = true;
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }
    if tie { None } else { min_id }
}

/// EC-13 (WU-0001): is `name` a built-in auto/marker trait that is never a
/// useful `Extends` target?
///
/// `Send`/`Sync`/`Sized`/`Unpin` are compiler auto/marker traits with no local
/// node and no domain meaning as a supertrait edge. They are the overwhelming
/// majority of `trait Foo: Send + Sync + 'static` bounds in this workspace, so
/// counting each skip as `edges_skipped_external_relation` cry-wolfs the
/// under-production WARN on EVERY full reindex. A real external DOMAIN supertrait
/// (`Display`, `Serialize`, …) returns `false` and stays honestly counted.
fn is_marker_supertrait(name: &str) -> bool {
    matches!(name, "Send" | "Sync" | "Sized" | "Unpin")
}

/// Find any symbol node in the graph by name, locality-scoped to `source_file`.
///
/// Tries exact matches first, then `::`-suffix matches, applying the decided
/// tie-break policy so that a same-file target wins over any cross-file homonym
/// and a genuinely-ambiguous no-locality reference resolves to `None` (skip).
/// EC-4a (WU-0001): `source_file` threading is what makes resolution prefer the
/// same-file node instead of the first-inserted one.
fn find_symbol_node(
    graph: &KnowledgeGraph,
    name: &str,
    source_file: &str,
    relationship_scope: Option<&StructuralRelationshipScope>,
) -> Option<Uuid> {
    // EP2 (ADR-0027): re-expressed onto the single candidate source with NO kind
    // constraint (only `candidates_for`'s unconditional `use`-exclusion). The
    // map-to-uuid keeps the call sites (which feed `graph.add_edge`) untouched —
    // zero behavior change.
    resolve_for_edge_in_scope(
        graph,
        name,
        source_file,
        KindFilter::Any,
        relationship_scope,
    )
    .map(|symbol| symbol.uuid())
}

fn find_type_node(
    graph: &KnowledgeGraph,
    name: &str,
    source_file: &str,
    relationship_scope: Option<&StructuralRelationshipScope>,
) -> Option<Uuid> {
    resolve_for_edge_in_scope(
        graph,
        name,
        source_file,
        KindFilter::Role(SymbolRole::Type),
        relationship_scope,
    )
    .map(|symbol| symbol.uuid())
}

fn find_abstraction_node(
    graph: &KnowledgeGraph,
    name: &str,
    source_file: &str,
    relationship_scope: Option<&StructuralRelationshipScope>,
) -> Option<Uuid> {
    const ABSTRACTION_KINDS: &[&str] = &["trait", "interface"];
    resolve_for_edge_in_scope(
        graph,
        name,
        source_file,
        KindFilter::AnyOf(ABSTRACTION_KINDS),
        relationship_scope,
    )
    .map(|symbol| symbol.uuid())
}

/// Group all graph nodes by their source file path.
///
/// Returns a sorted map from file path to the list of [`GraphNode`] references
/// in that file. This provides the input data for module-level operations like
/// LLM summarization: "here are all symbols in module X."
pub fn group_nodes_by_file(graph: &KnowledgeGraph) -> BTreeMap<String, Vec<&GraphNode>> {
    let mut groups: BTreeMap<String, Vec<&GraphNode>> = BTreeMap::new();
    for node in graph.all_nodes() {
        groups.entry(node.file_path.clone()).or_default().push(node);
    }
    groups
}

/// Build `DependsOn` edges between workspace crates by parsing Cargo.toml files.
///
/// For each workspace member, reads its `Cargo.toml` `[dependencies]` section,
/// identifies intra-workspace dependencies (those using `path = "../..."` syntax),
/// and creates a `DependsOn` edge from this crate's root module node to the
/// dependency's root module node.
///
/// Returns the number of `DependsOn` edges added.
pub fn build_dependency_edges(
    graph: &mut KnowledgeGraph,
    workspace_root: &std::path::Path,
) -> Result<usize, GraphError> {
    let workspace_toml = workspace_root.join("Cargo.toml");
    let content = match std::fs::read_to_string(&workspace_toml) {
        Ok(c) => c,
        Err(_) => return Ok(0), // No workspace Cargo.toml — nothing to do.
    };

    // Parse workspace members from Cargo.toml.
    // Use `toml::from_str` (Deserialize), NOT `content.parse()` (the `FromStr`
    // path): under toml 1.0 `FromStr` ERRORS on a real multi-section Cargo
    // manifest, silently returning `Ok(0)` here and emitting zero inter-crate
    // `DependsOn` edges. See edge_builder.rs witness test.
    let doc: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    // Resolve workspace member directories. Members can be globs like "crates/*".
    let member_patterns: Vec<&str> = doc
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    if member_patterns.is_empty() {
        return Ok(0);
    }

    // Expand member patterns to actual directories.
    // Handles simple trailing `/*` globs (e.g. "crates/*") via read_dir,
    // and literal paths otherwise. No external glob crate needed.
    let mut member_dirs: Vec<std::path::PathBuf> = Vec::new();
    for pattern in &member_patterns {
        if let Some(parent) = pattern.strip_suffix("/*") {
            // Strip the trailing "/*" to get the parent directory.
            let parent_dir = workspace_root.join(parent);
            if let Ok(entries) = std::fs::read_dir(&parent_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.join("Cargo.toml").exists() {
                        member_dirs.push(path);
                    }
                }
            }
        } else {
            // Literal directory path.
            let dir = workspace_root.join(pattern);
            if dir.is_dir() && dir.join("Cargo.toml").exists() {
                member_dirs.push(dir);
            }
        }
    }

    // Build a map: package name → relative path to src/lib.rs or src/main.rs.
    let mut crate_root_paths: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for dir in &member_dirs {
        let cargo_path = dir.join("Cargo.toml");
        let cargo_content = match std::fs::read_to_string(&cargo_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // `toml::from_str` (Deserialize), NOT `cargo_content.parse()` (`FromStr`):
        // the `FromStr` path errors on a real `[package]`+`[dependencies]` member
        // manifest under toml 1.0, dropping the crate from the edge build.
        let cargo_doc: toml::Value = match toml::from_str(&cargo_content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let pkg_name = cargo_doc
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();

        if pkg_name.is_empty() {
            continue;
        }

        // Determine the crate root file (lib.rs preferred, then main.rs).
        let lib_rs = dir.join("src/lib.rs");
        let main_rs = dir.join("src/main.rs");
        let root_file = if lib_rs.exists() {
            lib_rs
        } else if main_rs.exists() {
            main_rs
        } else {
            continue;
        };

        // Convert to a relative path from workspace root.
        let rel = root_file.strip_prefix(workspace_root).unwrap_or(&root_file);
        crate_root_paths.insert(pkg_name, rel.to_string_lossy().to_string());
    }

    // For each member crate, parse its dependencies and create DependsOn edges.
    let mut edges_added: usize = 0;

    for dir in &member_dirs {
        let cargo_path = dir.join("Cargo.toml");
        let cargo_content = match std::fs::read_to_string(&cargo_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // `toml::from_str` (Deserialize), NOT `cargo_content.parse()` (`FromStr`):
        // the `FromStr` path errors on a real `[package]`+`[dependencies]` member
        // manifest under toml 1.0, dropping the crate from the edge build.
        let cargo_doc: toml::Value = match toml::from_str(&cargo_content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let pkg_name = cargo_doc
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();

        if pkg_name.is_empty() {
            continue;
        }

        // Get this crate's root module path.
        let from_path = match crate_root_paths.get(&pkg_name) {
            Some(p) => p.clone(),
            None => continue,
        };

        // Parse [dependencies] for workspace-local deps (identified by `path` key).
        let deps_table = cargo_doc.get("dependencies").and_then(|d| d.as_table());
        if let Some(deps) = deps_table {
            for (dep_name, dep_val) in deps {
                // A workspace-local dep has a `path` key in its table value.
                let is_local = dep_val
                    .as_table()
                    .and_then(|t| t.get("path"))
                    .and_then(|p| p.as_str())
                    .is_some();

                if !is_local {
                    continue;
                }

                // Find the target crate's root path.
                let to_path = match crate_root_paths.get(dep_name) {
                    Some(p) => p.clone(),
                    None => continue,
                };

                // Find the root module node for this crate.
                // The root module node has kind == "module" and file_path matching
                // the crate root. We generate a deterministic ID for the module
                // based on the file path and a conventional module name.
                let from_id = find_crate_root_node(graph, &from_path);
                let to_id = find_crate_root_node(graph, &to_path);

                if let (Some(from_id), Some(to_id)) = (from_id, to_id) {
                    let edge = GraphEdge {
                        kind: EdgeKind::DependsOn,
                        weight: 1.0,
                        source: crate::graph::EdgeSource::TreeSitter,
                        confidence: 0.95,
                        scope: EdgeScope::Production,
                        ..Default::default()
                    };
                    match graph.add_edge(from_id, to_id, edge) {
                        Ok(()) => edges_added += 1,
                        Err(GraphError::NodeNotFound(_)) => {
                            // Node not in graph yet — skip silently.
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    tracing::debug!(
        edges_added,
        "build_dependency_edges: DependsOn edges created"
    );

    Ok(edges_added)
}

/// Find the root module node for a crate given its root file path.
///
/// Looks for a node with `kind == "module"` whose `file_path` matches the
/// given path. Falls back to any node in that file if no module is found.
fn find_crate_root_node(graph: &KnowledgeGraph, root_file_path: &str) -> Option<Uuid> {
    let all = graph.all_nodes();

    // First pass: look for a module node in this file.
    let module_node = all
        .iter()
        .find(|n| n.kind == "module" && n.file_path == root_file_path);
    if let Some(node) = module_node {
        return Some(node.memory_id);
    }

    // Fallback: any node in this file (prefer the first one alphabetically
    // for determinism).
    let mut candidates: Vec<&&crate::graph::GraphNode> = all
        .iter()
        .filter(|n| n.file_path == root_file_path)
        .collect();
    candidates.sort_by_key(|n| &n.symbol_name);
    candidates.first().map(|n| n.memory_id)
}

/// Errors from a full-scan or incremental-update operation.
#[derive(Debug, thiserror::Error)]
pub enum FullScanError {
    /// Extractor failed.
    #[error("extraction failed: {0}")]
    Extractor(#[from] crate::structural_ir::ExtractorError),
    /// Graph operation failed.
    #[error("graph error: {0}")]
    Graph(#[from] GraphError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_intel_domain::{
        DocumentMembership, DocumentMembershipKind, EcosystemId, LanguageId,
        ProjectInventoryCoverage, ProjectTopology, ProjectUnit, ProjectUnitId, ProjectUnitKind,
    };
    use crate::graph::KnowledgeGraph;
    use crate::structural_ir::{CodeSymbol, ExtractorOutput, SymbolKind, Visibility};
    use chrono::Utc;

    fn make_symbol(name: &str, kind: SymbolKind, parent: Option<&str>) -> CodeSymbol {
        let mut relations = Vec::new();
        if kind == SymbolKind::Impl
            && let Some(target) = parse_struct_from_impl(name)
        {
            relations.push(StructuralRelation::ContainedBy {
                target: target.clone(),
            });
            if let Some(abstraction) = parse_trait_from_impl(name) {
                relations.push(StructuralRelation::Implements {
                    abstraction,
                    implementation: Some(target),
                    synthesize_external: true,
                });
            }
        }
        if kind == SymbolKind::Use {
            relations.push(StructuralRelation::References {
                target: name.to_string(),
            });
        }
        CodeSymbol {
            name: name.to_string(),
            kind,
            span: (0, 100),
            line_range: (0, 10),
            signature: format!("fn {}()", name),
            doc_comment: None,
            content_hash: format!("hash_{}", name),
            visibility: Visibility::Public,
            parent: parent.map(|s| s.to_string()),
            is_test_only: false,
            is_test_root: false,
            has_body: true,
            relations,
            entry_retain: Default::default(),
        }
    }

    fn make_output(file: &str, symbols: Vec<CodeSymbol>) -> ExtractorOutput {
        ExtractorOutput {
            file_path: file.to_string(),
            file_hash: "filehash".to_string(),
            cross_document_surface_sha256: "0".repeat(64),
            symbols,
            extracted_at: Utc::now(),
            has_platform_cfg: false,
            capture_gaps: Vec::new(),
        }
    }

    fn scoped_inventory(documents: &[(&str, &str, &str)]) -> ProjectInventory {
        let mut units = BTreeMap::<ProjectUnitId, ProjectUnit>::new();
        let mut memberships = Vec::new();
        for (document, language, unit_id) in documents {
            let unit_id = ProjectUnitId::new(*unit_id);
            units.entry(unit_id.clone()).or_insert_with(|| ProjectUnit {
                project_unit_id: unit_id.clone(),
                language_id: LanguageId::new(*language),
                ecosystem_id: EcosystemId::new(if *language == "rust" {
                    "cargo"
                } else {
                    *language
                }),
                kind: ProjectUnitKind::Package,
                root_path: String::new(),
                manifest_path: None,
                compilation_root_paths: Vec::new(),
            });
            memberships.push(DocumentMembership {
                document_path: (*document).into(),
                language_id: LanguageId::new(*language),
                project_unit_id: unit_id,
                kind: DocumentMembershipKind::SourceOwner,
            });
        }
        for (document, language, unit_id) in documents {
            if *language == "rust"
                && (document.ends_with("/lib.rs")
                    || document.ends_with("/main.rs")
                    || *document == "lib.rs"
                    || *document == "main.rs")
                && let Some(unit) = units.get_mut(&ProjectUnitId::new(*unit_id))
            {
                unit.compilation_root_paths.push((*document).into());
            }
        }
        ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: ProjectTopology {
                units: units.into_values().collect(),
                memberships,
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        }
    }

    /// The shared graph boundary consumes language-neutral facts. A TypeScript
    /// or Python adapter must not need Rust's `impl` display grammar,
    /// `supertraits`, or `field_types` side channels to obtain the same typed
    /// graph relationships.
    #[test]
    fn polyglot_structural_facts_materialize_without_rust_syntax() {
        let mut base = make_symbol("Base", SymbolKind::Class, None);
        base.signature = "class Base {}".into();
        let contract = make_symbol("Runnable", SymbolKind::Interface, None);
        let mut derived = make_symbol("Derived", SymbolKind::Class, None);
        derived.relations = vec![
            StructuralRelation::Extends {
                target: "Base".into(),
            },
            StructuralRelation::Implements {
                abstraction: "Runnable".into(),
                implementation: None,
                synthesize_external: false,
            },
        ];
        let mut property = make_symbol("owner", SymbolKind::Property, Some("Derived"));
        property.relations = vec![StructuralRelation::TypeOf {
            target: "Base".into(),
        }];
        let method = make_symbol("run", SymbolKind::Method, Some("Derived"));
        let output = make_output(
            "src/model.ts",
            vec![base, contract, derived, property, method],
        );

        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).expect("language-neutral graph build");

        let base_id = deterministic_id("src/model.ts", "Base");
        let contract_id = deterministic_id("src/model.ts", "Runnable");
        let derived_id = deterministic_id("src/model.ts", "Derived");
        let property_id = deterministic_id("src/model.ts", "Derived::owner");
        let method_id = deterministic_id("src/model.ts", "Derived::run");
        let has_edge = |source, target, kind| {
            graph
                .neighbors(&source)
                .iter()
                .any(|(candidate, edge)| *candidate == target && edge.kind == kind)
        };

        assert!(has_edge(derived_id, base_id, EdgeKind::Extends));
        assert!(has_edge(derived_id, contract_id, EdgeKind::Implements));
        assert!(has_edge(contract_id, derived_id, EdgeKind::HasImpl));
        assert!(has_edge(derived_id, property_id, EdgeKind::Contains));
        assert!(has_edge(derived_id, method_id, EdgeKind::Contains));
        assert!(has_edge(property_id, base_id, EdgeKind::TypeOf));
    }

    #[test]
    fn project_relationship_scope_requires_complete_directed_authority() {
        use crate::code_intel_domain::{
            EcosystemId, LanguageId, ProjectInventoryCoverage, ProjectUnit, ProjectUnitDependency,
            ProjectUnitDependencyGap, ProjectUnitDependencyGraph,
        };

        let unit = |id: &str, kind: ProjectUnitKind| ProjectUnit {
            project_unit_id: ProjectUnitId::new(id),
            language_id: LanguageId::new("rust"),
            ecosystem_id: EcosystemId::new(if kind == ProjectUnitKind::LooseSources {
                "rust"
            } else {
                "cargo"
            }),
            kind,
            root_path: id.into(),
            manifest_path: (kind == ProjectUnitKind::Package).then(|| format!("{id}/Cargo.toml")),
            compilation_root_paths: Vec::new(),
        };
        let membership =
            |document: &str, unit: &str| crate::code_intel_domain::DocumentMembership {
                document_path: document.into(),
                language_id: LanguageId::new("rust"),
                project_unit_id: ProjectUnitId::new(unit),
                kind: DocumentMembershipKind::SourceOwner,
            };
        let package_ids = ["caller", "middle", "target", "independent"]
            .map(ProjectUnitId::new)
            .to_vec();
        let dependencies = vec![
            ProjectUnitDependency {
                dependent_project_unit_id: ProjectUnitId::new("caller"),
                dependency_project_unit_id: ProjectUnitId::new("middle"),
            },
            ProjectUnitDependency {
                dependent_project_unit_id: ProjectUnitId::new("middle"),
                dependency_project_unit_id: ProjectUnitId::new("target"),
            },
        ];
        let mut inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: crate::code_intel_domain::ProjectTopology {
                units: ["caller", "middle", "target", "independent"]
                    .map(|id| unit(id, ProjectUnitKind::Package))
                    .into_iter()
                    .chain(std::iter::once(unit(
                        "loose",
                        ProjectUnitKind::LooseSources,
                    )))
                    .collect(),
                memberships: vec![
                    membership("caller/src/a.rs", "caller"),
                    membership("caller/src/b.rs", "caller"),
                    membership("middle/src/lib.rs", "middle"),
                    membership("target/src/lib.rs", "target"),
                    membership("independent/src/lib.rs", "independent"),
                    membership("loose/a.rs", "loose"),
                    membership("loose/b.rs", "loose"),
                ],
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: vec![ProjectUnitDependencyGraph {
                    language_id: LanguageId::new("rust"),
                    ecosystem_id: EcosystemId::new("cargo"),
                    coverage: ProjectUnitDependencyGraphCoverage::Partial,
                    project_unit_ids: package_ids,
                    dependencies,
                    gaps: vec![ProjectUnitDependencyGap {
                        reason_code: "falsifier".into(),
                        project_unit_id: None,
                        path: "<fixture>".into(),
                        detail: "partial authority must not admit even a recorded edge".into(),
                    }],
                }],
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };

        let partial = StructuralRelationshipScope::from_inventory(&inventory);
        assert!(
            partial.admits("caller/src/a.rs", "caller/src/b.rs"),
            "same-package ownership is an independent positive control"
        );
        assert!(
            !partial.admits("caller/src/a.rs", "target/src/lib.rs"),
            "a partial dependency graph cannot authorize a cross-package target"
        );
        assert!(
            !partial.admits("loose/a.rs", "loose/b.rs"),
            "a repository-wide loose-source bucket cannot manufacture cross-document ownership"
        );

        inventory.project_topology.dependency_graphs[0].coverage =
            ProjectUnitDependencyGraphCoverage::Complete;
        inventory.project_topology.dependency_graphs[0].gaps.clear();
        let complete = StructuralRelationshipScope::from_inventory(&inventory);
        assert!(
            complete.admits("caller/src/a.rs", "target/src/lib.rs"),
            "complete directed authority must admit transitive dependencies"
        );
        assert!(
            !complete.admits("target/src/lib.rs", "caller/src/a.rs"),
            "dependency direction is load-bearing"
        );
        assert!(
            !complete.admits("independent/src/lib.rs", "target/src/lib.rs"),
            "a populated complete graph proves the independent package is outside the target domain"
        );

        inventory
            .project_topology
            .memberships
            .push(membership("caller/src/a.rs", "independent"));
        let ambiguous = StructuralRelationshipScope::from_inventory(&inventory);
        assert!(
            !ambiguous.admits("caller/src/a.rs", "target/src/lib.rs"),
            "duplicate source ownership must fail closed"
        );
    }

    /// PERFORMANCE FALSIFIER: resolving a small number of named relationships
    /// must inspect only their bounded name populations, not every unrelated
    /// node once per relationship. This counts deterministic algorithmic work,
    /// so the guard remains stable under host load.
    #[test]
    fn edge_resolution_does_not_rescan_the_whole_graph_per_relationship() {
        let mut symbols = Vec::with_capacity(2_065);
        symbols.push(make_symbol("Target", SymbolKind::Struct, None));
        for index in 0..2_000 {
            symbols.push(make_symbol(
                &format!("Unrelated{index}"),
                SymbolKind::Function,
                None,
            ));
        }
        for index in 0..64 {
            let mut container = make_symbol(&format!("Container{index}"), SymbolKind::Struct, None);
            container.relations.push(StructuralRelation::FieldOf {
                target: "Target".to_string(),
            });
            symbols.push(container);
        }

        reset_resolution_candidates_examined();
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&[make_output("src/lib.rs", symbols)], &mut graph)
            .expect("fixture graph builds");
        let examined = resolution_candidates_examined();

        assert_eq!(
            stats.edges_added, 64,
            "positive control: every field resolves"
        );
        assert!(examined > 0, "non-vacuity: the resolver must be exercised");
        assert!(
            examined <= 256,
            "64 one-candidate lookups examined {examined} nodes; unrelated graph population was rescanned"
        );
    }

    /// PERFORMANCE FALSIFIER: resolving many children in one document must use
    /// one document-local parent index. Scanning every symbol again for every
    /// child turns ordinary large modules into quadratic graph-build work.
    #[test]
    fn same_document_parent_resolution_is_indexed_per_file() {
        const CHILDREN: usize = 1_024;
        let mut symbols = Vec::with_capacity(CHILDREN + 1);
        let mut parent = make_symbol("Container", SymbolKind::Module, None);
        parent.span = (0, CHILDREN * 10 + 10);
        symbols.push(parent);
        for index in 0..CHILDREN {
            let mut child = make_symbol(
                &format!("child_{index}"),
                SymbolKind::Function,
                Some("Container"),
            );
            child.span = (index * 10 + 1, index * 10 + 9);
            symbols.push(child);
        }

        reset_source_parent_candidates_examined();
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&[make_output("src/lib.rs", symbols)], &mut graph)
            .expect("fixture graph builds");
        let examined = source_parent_candidates_examined();

        assert_eq!(
            stats.edges_added, CHILDREN,
            "positive control: every child must retain its Contains edge"
        );
        assert!(examined > 0, "non-vacuity: parent resolution must run");
        assert!(
            examined <= CHILDREN + 1,
            "{CHILDREN} parent lookups examined {examined} source symbols; the document was rescanned per child"
        );
    }

    /// PERFORMANCE FALSIFIER: a qualified type target forces the impl resolver
    /// past its exact-name fast path, but must still inspect only the matching
    /// terminal-name population rather than every unrelated graph node.
    #[test]
    fn impl_target_resolution_does_not_scan_unrelated_nodes() {
        let mut symbols = Vec::with_capacity(2_002);
        symbols.push(make_symbol("Target", SymbolKind::Struct, Some("module")));
        for index in 0..2_000 {
            symbols.push(make_symbol(
                &format!("Unrelated{index}"),
                SymbolKind::Struct,
                None,
            ));
        }
        symbols.push(make_symbol("impl Target", SymbolKind::Impl, None));

        reset_resolution_candidates_examined();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[make_output("src/lib.rs", symbols)], &mut graph)
            .expect("fixture graph builds");
        let examined = resolution_candidates_examined();

        let target_id = deterministic_id("src/lib.rs", "module::Target");
        let impl_id = deterministic_id("src/lib.rs", "impl Target");
        assert!(
            graph
                .neighbors(&target_id)
                .into_iter()
                .any(|(to, edge)| to == impl_id && edge.kind == EdgeKind::Contains),
            "positive control: the qualified target must own the impl edge"
        );
        assert!(examined > 0, "non-vacuity: the resolver must be exercised");
        assert!(
            examined <= 4,
            "one matching impl target examined {examined} nodes; unrelated graph population was rescanned"
        );
    }

    /// FALSIFIER (WU-0023 P3b Bundle-3, Phase 3c): a Go method declared in a
    /// DIFFERENT file from its receiver type — but the SAME package directory —
    /// gets a `Contains` edge from the receiver type, so the reachability rescue
    /// guard can walk it. RED on HEAD: Phase 2's Contains linker is same-file
    /// only (`deterministic_id(&file, receiver)` misses a cross-file receiver),
    /// so no such edge existed. NON-VACUOUS runnable control: a method whose
    /// receiver type of the SAME NAME lives in a DIFFERENT package DIRECTORY is
    /// NOT linked (the OQ-GO-XPKG-HOMONYM safety — never a cross-package
    /// mis-wire); and disabling the Phase-3c pass drops the cross-file method to
    /// false-DEAD (verified by the build agent, documented in the WU).
    #[test]
    fn go_cross_file_method_links_to_same_package_receiver_only() {
        // Same package `pkg`: receiver `Widget` in types.go, method in methods.go.
        let types_go = make_output(
            "pkg/types.go",
            vec![make_symbol("Widget", SymbolKind::Struct, None)],
        );
        let methods_go = make_output(
            "pkg/methods.go",
            vec![
                // Cross-file method on the same-package `Widget` → MUST link.
                make_symbol("Do", SymbolKind::Function, Some("Widget")),
                // Method on `Gadget`, whose type lives in a DIFFERENT package
                // (`other/`) → MUST NOT link (package-dir scoping).
                make_symbol("Run", SymbolKind::Function, Some("Gadget")),
            ],
        );
        // A same-named `Gadget` type in a DIFFERENT directory — the homonym trap.
        let other_go = make_output(
            "other/gadget.go",
            vec![make_symbol("Gadget", SymbolKind::Struct, None)],
        );

        let mut graph = KnowledgeGraph::new();
        build_graph(&[types_go, methods_go, other_go], &mut graph).unwrap();

        let widget_id = deterministic_id("pkg/types.go", "Widget");
        let do_id = deterministic_id("pkg/methods.go", "Widget::Do");
        let gadget_id = deterministic_id("other/gadget.go", "Gadget");
        let run_id = deterministic_id("pkg/methods.go", "Gadget::Run");

        let has_contains = |from: Uuid, to: Uuid| {
            graph
                .neighbors(&from)
                .iter()
                .any(|(t, e)| *t == to && e.kind == EdgeKind::Contains)
        };

        assert!(
            has_contains(widget_id, do_id),
            "a cross-file same-package Go method must get a Contains edge from its receiver type"
        );
        assert!(
            !has_contains(gadget_id, run_id),
            "a Go method must NOT link cross-PACKAGE to a same-named receiver type \
             (OQ-GO-XPKG-HOMONYM safety)"
        );
    }

    /// The Phase-3c linker must NOT double-emit when the receiver type IS in the
    /// method's own file (Phase 2 already linked it) — exactly one Contains edge.
    #[test]
    fn go_same_file_method_not_double_linked_by_phase_3c() {
        let one_file = make_output(
            "pkg/all.go",
            vec![
                make_symbol("Widget", SymbolKind::Struct, None),
                make_symbol("Do", SymbolKind::Function, Some("Widget")),
            ],
        );
        let mut graph = KnowledgeGraph::new();
        build_graph(&[one_file], &mut graph).unwrap();

        let widget_id = deterministic_id("pkg/all.go", "Widget");
        let do_id = deterministic_id("pkg/all.go", "Widget::Do");
        let contains_count = graph
            .neighbors(&widget_id)
            .iter()
            .filter(|(t, e)| *t == do_id && e.kind == EdgeKind::Contains)
            .count();
        assert_eq!(
            contains_count, 1,
            "same-file Go method must have exactly one Contains edge (Phase 2 only, no Phase-3c dup)"
        );
    }

    #[test]
    fn ec1_nested_module_contains_edge_end_to_end() {
        // EC-1 (WU-0001): a doubly-nested fn must get a Contains edge from its
        // QUALIFIED parent module. Driven end-to-end through the real extractor —
        // a fabricated make_symbol with parent="outer::inner" would be GREEN today
        // and vacuous (the bug is the extractor threading the SHORT parent name).
        use crate::extractor::extract_rust_symbols;
        let output =
            extract_rust_symbols("mod outer { mod inner { fn child() {} } }", "test.rs").unwrap();
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&[output], &mut graph).unwrap();

        let inner_id = deterministic_id("test.rs", "outer::inner");
        let child_id = deterministic_id("test.rs", "outer::inner::child");
        let has_contains = graph
            .neighbors(&inner_id)
            .iter()
            .any(|(t, e)| *t == child_id && e.kind == EdgeKind::Contains);
        assert!(
            has_contains,
            "EC-1: inner module must Contains the nested child fn"
        );
        assert_eq!(
            stats.total_skipped(),
            0,
            "EC-1: no edge skipped for a nested-module child"
        );
    }

    #[test]
    fn ec2_generic_impl_hasimpl_edge() {
        // EC-2 (WU-0001): `impl Tr for Bar<T>` must resolve to the `Bar` node
        // (generics stripped) and create the HasImpl edge Tr -> Bar. Before the
        // fix, parse_struct_from_impl returns "Bar<T>" which matches no node.
        use crate::extractor::extract_rust_symbols;
        let output = extract_rust_symbols(
            "pub trait Tr {} pub struct Bar<T>(T); impl Tr for Bar<T> { fn m(&self) {} }",
            "test.rs",
        )
        .unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();
        let tr_id = deterministic_id("test.rs", "Tr");
        let bar_id = deterministic_id("test.rs", "Bar");
        let has_hasimpl = graph
            .neighbors(&tr_id)
            .iter()
            .any(|(t, e)| *t == bar_id && e.kind == EdgeKind::HasImpl);
        assert!(
            has_hasimpl,
            "EC-2: Tr must HasImpl Bar (generic args stripped from Bar<T>)"
        );
    }

    #[test]
    fn f2_serde_default_and_with_emit_references_edge() {
        // F2 (WU-0009, ADR-0030): a field annotated `#[serde(default = "fn")]`
        // and a field annotated `#[serde(with = "mod")]` must each cause a
        // `References` edge to be built to the named local helper / module, so
        // the helper is reachable whenever its struct is. Driven END-TO-END
        // through the real extractor -> build_graph (NOT make_symbol, which has no
        // serde awareness and would be vacuous).
        //
        // CARRIER-AGNOSTIC: asserts only that SOME node has a `References` edge
        // INTO the helper/module node (works whether the builder carries
        // `serde_refs` on the FIELD node or on the parent STRUCT node).
        use crate::extractor::extract_rust_symbols;
        let src = "fn default_retries() -> u32 { 3 }\n\
                   mod ts_millis { }\n\
                   pub struct Cfg {\n\
                     #[serde(default = \"default_retries\")]\n\
                     pub retries: u32,\n\
                     #[serde(with = \"ts_millis\")]\n\
                     pub at: u64,\n\
                     // NEGATIVE-CONTROL FIELD: bare `#[serde(default)]` (no `= path`)\n\
                     // names NO symbol and must emit NO edge.\n\
                     #[serde(default)]\n\
                     pub note: String,\n\
                   }\n";
        let output = extract_rust_symbols(src, "src/cfg.rs").unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let helper_id = deterministic_id("src/cfg.rs", "default_retries");
        let module_id = deterministic_id("src/cfg.rs", "ts_millis");

        // A `References` edge must terminate at the `default = "..."` helper fn.
        let refs_to_helper = graph
            .all_edges()
            .iter()
            .any(|(_, to, e)| *to == helper_id && e.kind == EdgeKind::References);
        assert!(
            refs_to_helper,
            "F2: `#[serde(default = \"default_retries\")]` must build a References \
             edge to the `default_retries` helper fn"
        );

        // A `References` edge must terminate at the `with = "..."` module.
        let refs_to_module = graph
            .all_edges()
            .iter()
            .any(|(_, to, e)| *to == module_id && e.kind == EdgeKind::References);
        assert!(
            refs_to_module,
            "F2: `#[serde(with = \"ts_millis\")]` must build a References edge to \
             the `ts_millis` module"
        );

        // NEGATIVE CONTROL (load-bearing non-vacuity): the bare `#[serde(default)]`
        // on `note` names NO symbol, so NO serde-origin References edge may target
        // a `note`/`String` node, AND the total number of serde-origin References
        // edges in this graph must be EXACTLY 2 (one per `= path` site) — proving
        // the two `= path` sites, not the bare default, create the edges.
        //
        // "serde-origin" = a References edge whose source node is the struct OR one
        // of its fields (carrier-agnostic). The only other References emitter is
        // the Use->References block, and this fixture has no `use` items, so every
        // References edge here is serde-origin.
        let serde_ref_edges: Vec<_> = graph
            .all_edges()
            .into_iter()
            .filter(|(_, _, e)| e.kind == EdgeKind::References)
            .collect();
        assert_eq!(
            serde_ref_edges.len(),
            2,
            "F2: exactly 2 serde-origin References edges expected (one per `= path` \
             site); the bare `#[serde(default)]` must contribute none — got {serde_ref_edges:?}"
        );
        let note_targets_a_ref = serde_ref_edges.iter().any(|(_, to, _)| {
            graph
                .node(to)
                .is_some_and(|n| n.symbol_name == "note" || n.symbol_name == "String")
        });
        assert!(
            !note_targets_a_ref,
            "F2: bare `#[serde(default)]` on `note` must NOT produce a References \
             edge to a `note`/`String` node"
        );
    }

    #[test]
    fn f3_module_contains_edge_built_from_mod_decl_to_helper_file_symbol() {
        // F3 (WU-0009, ADR-0030): a bare cross-file `mod helper;` in lib.rs must
        // build a `Contains` edge from the `helper` module-decl node to EACH
        // top-level symbol of the SIBLING helper.rs file (resolved against the
        // INDEXED graph, never the filesystem). On HEAD, Phase-2 Contains is
        // same-file only (deterministic_id(&output.file_path, parent_name)) and a
        // bare `mod helper;` has no inline body, so no edge links lib.rs's module
        // node to helper.rs's symbols. Driven END-TO-END through the real
        // extractor (NOT make_symbol, which has no module-decl/cross-file
        // awareness and would be vacuous).
        use crate::extractor::extract_rust_symbols;
        let lib =
            extract_rust_symbols("pub mod helper;\npub fn api() {}\n", "crates/tc/src/lib.rs")
                .unwrap();
        let helper =
            extract_rust_symbols("pub fn the_helper() {}\n", "crates/tc/src/helper.rs").unwrap();
        let inventory = scoped_inventory(&[
            ("crates/tc/src/lib.rs", "rust", "rust-package"),
            ("crates/tc/src/helper.rs", "rust", "rust-package"),
        ]);
        let mut graph = KnowledgeGraph::new();
        build_graph_with_inventory(&[lib, helper], &mut graph, &inventory, false, false).unwrap();

        // The `mod helper;` decl node lives in lib.rs; the resolved sibling
        // symbol lives in helper.rs (DIFFERENT file_path => DIFFERENT
        // deterministic_id => the cross-file edge cannot exist on HEAD).
        let module_id = deterministic_id("crates/tc/src/lib.rs", "helper");
        let helper_fn_id = deterministic_id("crates/tc/src/helper.rs", "the_helper");

        let has_cross_file_contains = graph
            .neighbors(&module_id)
            .iter()
            .any(|(t, e)| *t == helper_fn_id && e.kind == EdgeKind::Contains);
        assert!(
            has_cross_file_contains,
            "F3: `mod helper;` in lib.rs must Contains the top-level `the_helper` \
             in the sibling helper.rs (cross-file module containment)"
        );

        // SILENT-SKIP control: an INLINE `mod inline {}` (a declaration_list body,
        // no separate file) and an UNINDEXED `mod absent;` resolve to NO sibling
        // file => NO fabricated cross-file Contains edge. This proves the F3 pass
        // resolves against the INDEXED graph (CORRECTION-1: no fs I/O), not the
        // filesystem, and never blanket-fabricates edges.
        let lib2 = extract_rust_symbols(
            "pub mod inline { pub fn x() {} }\npub mod absent;\npub fn api() {}\n",
            "crates/tc2/src/lib.rs",
        )
        .unwrap();
        let mut g2 = KnowledgeGraph::new();
        // NOTE: no crates/tc2/src/absent.rs and no inline.rs are indexed.
        build_graph(&[lib2], &mut g2).unwrap();
        let absent_mod_id = deterministic_id("crates/tc2/src/lib.rs", "absent");
        let absent_has_cross_file = g2
            .neighbors(&absent_mod_id)
            .iter()
            .any(|(_, e)| e.kind == EdgeKind::Contains);
        assert!(
            !absent_has_cross_file,
            "F3: an unindexed/inline module must NOT fabricate a cross-file \
             Contains edge (silent-skip; resolve against the indexed graph, never \
             the filesystem)"
        );
    }

    /// A Rust module declaration is a compiler-owned document relationship,
    /// not a sibling-filename hint. Modern nested modules resolve below the
    /// declaring module stem, while `#[path]` names the exact target document.
    /// A decoy at the historical sibling guess makes both damaging directions
    /// observable: the intended edge must exist and the guessed edge must not.
    #[test]
    fn rust_module_documents_follow_language_semantics_not_sibling_guesses() {
        use crate::extractor::extract_rust_symbols;

        let outputs = [
            extract_rust_symbols("pub mod inner;\n", "src/outer.rs").unwrap(),
            extract_rust_symbols("pub fn intended_nested() {}\n", "src/outer/inner.rs").unwrap(),
            extract_rust_symbols("pub fn nested_decoy() {}\n", "src/inner.rs").unwrap(),
            extract_rust_symbols(
                "#[path = \"alternate.rs\"]\npub mod custom;\n",
                "src/lib.rs",
            )
            .unwrap(),
            extract_rust_symbols("pub fn intended_override() {}\n", "src/alternate.rs").unwrap(),
            extract_rust_symbols("pub fn override_decoy() {}\n", "src/custom.rs").unwrap(),
        ];
        let inventory = scoped_inventory(
            &outputs
                .iter()
                .map(|output| (output.file_path.as_str(), "rust", "rust-package"))
                .collect::<Vec<_>>(),
        );
        let mut graph = KnowledgeGraph::new();
        build_graph_with_inventory(&outputs, &mut graph, &inventory, false, false).unwrap();

        let has_contains = |source, target| {
            graph
                .neighbors(&source)
                .iter()
                .any(|(candidate, edge)| *candidate == target && edge.kind == EdgeKind::Contains)
        };
        let nested_module = deterministic_id("src/outer.rs", "inner");
        assert!(
            has_contains(
                nested_module,
                deterministic_id("src/outer/inner.rs", "intended_nested")
            ),
            "a non-root `outer.rs` module must resolve `mod inner` below `outer/`"
        );
        assert!(
            !has_contains(
                nested_module,
                deterministic_id("src/inner.rs", "nested_decoy")
            ),
            "the historical sibling guess must not outrank Rust's nested-module rule"
        );

        let override_module = deterministic_id("src/lib.rs", "custom");
        assert!(
            has_contains(
                override_module,
                deterministic_id("src/alternate.rs", "intended_override")
            ),
            "an explicit `#[path]` must name the contained document"
        );
        assert!(
            !has_contains(
                override_module,
                deterministic_id("src/custom.rs", "override_decoy")
            ),
            "a conventional filename must not override an explicit `#[path]`"
        );
    }

    /// Cross-document structure may not bypass the exact project-unit owner.
    /// The positive control proves the module and target are both populated;
    /// the only absent authority is a same-unit/dependency relationship.
    #[test]
    fn rust_module_documents_cannot_cross_inventory_ownership() {
        use crate::extractor::extract_rust_symbols;

        let declaration = extract_rust_symbols("pub mod child;\n", "package/src/lib.rs").unwrap();
        let child =
            extract_rust_symbols("pub fn populated_target() {}\n", "package/src/child.rs").unwrap();
        let inventory = scoped_inventory(&[
            ("package/src/lib.rs", "rust", "outer-package"),
            ("package/src/child.rs", "rust", "nested-package"),
        ]);
        let mut graph = KnowledgeGraph::new();
        build_graph_with_inventory(&[declaration, child], &mut graph, &inventory, false, false)
            .unwrap();

        let module_id = deterministic_id("package/src/lib.rs", "child");
        let target_id = deterministic_id("package/src/child.rs", "populated_target");
        assert!(graph.node(&module_id).is_some(), "positive module control");
        assert!(graph.node(&target_id).is_some(), "positive target control");
        assert!(
            !graph
                .neighbors(&module_id)
                .iter()
                .any(|(candidate, edge)| *candidate == target_id
                    && edge.kind == EdgeKind::Contains),
            "a filename match cannot bypass distinct project-unit ownership"
        );
    }

    /// Shared symbol kinds do not authorize shared path semantics. A
    /// TypeScript `module` node beside an indexed Rust file is a populated
    /// negative control for accidental Rust filename dispatch.
    #[test]
    fn non_rust_module_nodes_do_not_receive_rust_document_rules() {
        let source = make_output(
            "src/source.ts",
            vec![make_symbol("helper", SymbolKind::Module, None)],
        );
        let target = make_output(
            "src/helper.rs",
            vec![make_symbol("rust_target", SymbolKind::Function, None)],
        );
        let inventory = scoped_inventory(&[
            ("src/source.ts", "typescript", "typescript-package"),
            ("src/helper.rs", "rust", "rust-package"),
        ]);
        let mut graph = KnowledgeGraph::new();
        build_graph_with_inventory(&[source, target], &mut graph, &inventory, false, false)
            .unwrap();

        let module_id = deterministic_id("src/source.ts", "helper");
        let target_id = deterministic_id("src/helper.rs", "rust_target");
        assert!(graph.node(&module_id).is_some(), "positive module control");
        assert!(graph.node(&target_id).is_some(), "positive target control");
        assert!(
            !graph
                .neighbors(&module_id)
                .iter()
                .any(|(candidate, edge)| *candidate == target_id
                    && edge.kind == EdgeKind::Contains),
            "shared graph code must not apply Rust document rules by symbol kind"
        );
    }

    /// A module enabled only in the test configuration carries its containment
    /// edge into test scope; hard-coding Production creates false production
    /// reachability even when both endpoints are otherwise exact.
    #[test]
    fn external_test_module_containment_retains_test_scope() {
        use crate::extractor::extract_rust_symbols;

        let declaration =
            extract_rust_symbols("#[cfg(test)]\npub mod support;\n", "src/lib.rs").unwrap();
        let support = extract_rust_symbols("pub fn helper() {}\n", "src/support.rs").unwrap();
        let inventory = scoped_inventory(&[
            ("src/lib.rs", "rust", "rust-package"),
            ("src/support.rs", "rust", "rust-package"),
        ]);
        let mut graph = KnowledgeGraph::new();
        build_graph_with_inventory(
            &[declaration, support],
            &mut graph,
            &inventory,
            false,
            false,
        )
        .unwrap();

        let module_id = deterministic_id("src/lib.rs", "support");
        let target_id = deterministic_id("src/support.rs", "helper");
        let edge = graph
            .neighbors(&module_id)
            .into_iter()
            .find_map(|(candidate, edge)| {
                (candidate == target_id && edge.kind == EdgeKind::Contains).then_some(edge)
            })
            .expect("populated external-module containment control");
        assert_eq!(edge.scope, EdgeScope::Test);
    }

    /// The manifest-defined crate root, not its filename, decides whether a
    /// child module is a sibling. Exact module declarations may refine a loose
    /// fallback document into the declaring package, but an unrelated decoy is
    /// never adopted. The nested child proves refinement reaches a fixed point.
    #[test]
    fn custom_cargo_target_roots_drive_exact_module_ownership() {
        use crate::code_intel_inventory::{InventorySource, build_project_inventory};
        use crate::extractor::extract_rust_symbols;

        let temporary = tempfile::tempdir().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("custom/helper")).expect("module directories");
        std::fs::create_dir_all(root.join("custom/entry")).expect("decoy directory");
        std::fs::write(
            root.join("Cargo.toml"),
            r#"
                [package]
                name = "custom-root"
                version = "0.1.0"
                edition = "2024"
                autolib = false
                autobins = false

                [[bin]]
                name = "custom-root"
                path = "custom/entry.rs"
            "#,
        )
        .expect("manifest");
        let sources = [
            ("custom/entry.rs", "pub mod helper;\n"),
            (
                "custom/helper.rs",
                "pub mod nested;\npub fn intended() {}\n",
            ),
            ("custom/helper/nested.rs", "pub fn nested() {}\n"),
            ("custom/entry/helper.rs", "pub fn decoy() {}\n"),
        ];
        for (path, source) in sources {
            std::fs::write(root.join(path), source).expect("source fixture");
        }
        let inventory = build_project_inventory(
            root,
            &sources
                .iter()
                .map(|(path, _)| InventorySource::new(*path, "rust"))
                .collect::<Vec<_>>(),
        );
        let package = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| unit.kind == ProjectUnitKind::Package)
            .expect("Cargo package");
        assert_eq!(
            package.compilation_root_paths,
            ["custom/entry.rs"],
            "the exact manifest target must survive inventory construction"
        );

        let outputs = sources
            .iter()
            .map(|(path, source)| extract_rust_symbols(source, path).expect("extract source"))
            .collect::<Vec<_>>();
        let mut graph = KnowledgeGraph::new();
        build_graph_with_inventory(&outputs, &mut graph, &inventory, false, false).unwrap();
        let root_module = deterministic_id("custom/entry.rs", "helper");
        let intended = deterministic_id("custom/helper.rs", "intended");
        let decoy = deterministic_id("custom/entry/helper.rs", "decoy");
        assert!(
            graph
                .neighbors(&root_module)
                .iter()
                .any(|(candidate, edge)| *candidate == intended && edge.kind == EdgeKind::Contains),
            "a custom crate root must use crate-root module lookup"
        );
        assert!(
            !graph
                .neighbors(&root_module)
                .iter()
                .any(|(candidate, edge)| *candidate == decoy && edge.kind == EdgeKind::Contains),
            "the same filename treated as a non-root must not win"
        );
        let nested_module = deterministic_id("custom/helper.rs", "nested");
        let nested = deterministic_id("custom/helper/nested.rs", "nested");
        assert!(
            graph
                .neighbors(&nested_module)
                .iter()
                .any(|(candidate, edge)| *candidate == nested && edge.kind == EdgeKind::Contains),
            "exact ownership refinement must propagate through nested modules"
        );
    }

    #[test]
    fn inline_and_path_redirected_modules_follow_rust_reference_directories() {
        use crate::extractor::extract_rust_symbols;

        let root = extract_rust_symbols(
            r#"
                pub mod outer { pub mod inner; }
                #[path = "thread_files"]
                pub mod thread {
                    #[path = "tls.rs"]
                    pub mod local;
                }
            "#,
            "src/lib.rs",
        )
        .unwrap();
        let nested = extract_rust_symbols("pub fn nested() {}\n", "src/outer/inner.rs").unwrap();
        let redirected =
            extract_rust_symbols("pub fn redirected() {}\n", "src/thread_files/tls.rs").unwrap();
        let inventory = scoped_inventory(&[
            ("src/lib.rs", "rust", "rust-package"),
            ("src/outer/inner.rs", "rust", "rust-package"),
            ("src/thread_files/tls.rs", "rust", "rust-package"),
        ]);
        let mut graph = KnowledgeGraph::new();
        build_graph_with_inventory(
            &[root, nested, redirected],
            &mut graph,
            &inventory,
            false,
            false,
        )
        .unwrap();

        for (module, target) in [
            (
                deterministic_id("src/lib.rs", "outer::inner"),
                deterministic_id("src/outer/inner.rs", "nested"),
            ),
            (
                deterministic_id("src/lib.rs", "thread::local"),
                deterministic_id("src/thread_files/tls.rs", "redirected"),
            ),
        ] {
            assert!(
                graph.neighbors(&module).iter().any(
                    |(candidate, edge)| *candidate == target && edge.kind == EdgeKind::Contains
                ),
                "inline module directory semantics must reach the exact target"
            );
        }
    }

    #[test]
    fn ambiguous_or_conditional_module_documents_fail_closed() {
        use crate::extractor::extract_rust_symbols;

        let ambiguous = extract_rust_symbols("pub mod duplicate;\n", "src/lib.rs").unwrap();
        let flat = extract_rust_symbols("pub fn flat() {}\n", "src/duplicate.rs").unwrap();
        let legacy = extract_rust_symbols("pub fn legacy() {}\n", "src/duplicate/mod.rs").unwrap();
        let conditional = extract_rust_symbols(
            "#[cfg_attr(unix, path = \"unix.rs\")]\npub mod platform;\n",
            "src/conditional.rs",
        )
        .unwrap();
        assert!(
            conditional
                .capture_gaps
                .iter()
                .any(|gap| gap.kind == "rust_module_path_unresolved"),
            "conditional path syntax must remain visible as an authority gap"
        );
        let default =
            extract_rust_symbols("pub fn default_path() {}\n", "src/conditional/platform.rs")
                .unwrap();
        let unix = extract_rust_symbols("pub fn unix() {}\n", "src/unix.rs").unwrap();
        let outputs = [ambiguous, flat, legacy, conditional, default, unix];
        let inventory = scoped_inventory(
            &outputs
                .iter()
                .map(|output| (output.file_path.as_str(), "rust", "rust-package"))
                .collect::<Vec<_>>(),
        );
        let mut graph = KnowledgeGraph::new();
        build_graph_with_inventory(&outputs, &mut graph, &inventory, false, false).unwrap();

        for module in [
            deterministic_id("src/lib.rs", "duplicate"),
            deterministic_id("src/conditional.rs", "platform"),
        ] {
            assert!(
                graph
                    .neighbors(&module)
                    .iter()
                    .all(|(_, edge)| edge.kind != EdgeKind::Contains),
                "ambiguous or conditional document resolution must emit no guessed edge"
            );
        }
    }

    // ── EC-7a (WU-0001): Phase-3 struct→impl Contains edge scope ────────────
    //
    // The Phase-3 "Post-hoc struct → impl block Contains edges" pass iterates
    // `graph.all_nodes()` (GraphNode, which carries NO is_test_only) rather than
    // `outputs` (CodeSymbol, which does). It must still tag the Contains edge's
    // scope from the IMPL block's cfg(test)-ness, deriving it via a side-map
    // keyed on the impl node id. EdgeScope has no reader yet (the reachability
    // filter is WU-0003/CL-REACH-06), so the ONLY non-vacuous proof is asserting
    // edge.scope directly on the constructed graph. All three fixtures drive
    // END-TO-END through the real extractor (NOT make_symbol, which hardcodes
    // is_test_only:false) so the real cfg(test) → has_cfg_test_attribute →
    // is_test_only chain is exercised — a make_symbol fixture would be vacuous.

    #[test]
    fn ec7a_cfg_test_mod_impl_contains_edge_is_test_scope() {
        // DISCRIMINATION-POSITIVE (RED on HEAD): a `#[cfg(test)]` struct S with a
        // `#[cfg(test)]` inherent `impl S` — both nodes are is_test_only=true, so
        // the struct→impl Contains edge must be Test-scoped. RED on HEAD because
        // Phase-3 hardcodes Production.
        //
        // NB the fixture uses TOP-LEVEL `#[cfg(test)]` items rather than a
        // `#[cfg(test)] mod { ... }` wrapper: Phase-3 only builds the struct→impl
        // Contains edge for impls whose `symbol_name` starts with `impl ` (it
        // calls `parse_struct_from_impl`, which strips the `impl ` prefix). An
        // impl nested in a module is qualified as `tests::impl S`, so Phase-3
        // never builds its Contains edge today — a pre-existing module-nesting
        // gap orthogonal to EC-7. The top-level form keeps the impl name `impl S`
        // (Phase-3 builds the edge) while still exercising the real extractor's
        // cfg(test) → has_cfg_test_attribute → is_test_only chain end-to-end.
        use crate::extractor::extract_rust_symbols;
        let output = extract_rust_symbols(
            "#[cfg(test)]\nstruct S;\n#[cfg(test)]\nimpl S { fn m(&self) {} }",
            "src/prod.rs",
        )
        .unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let s_id = deterministic_id("src/prod.rs", "S");
        let impl_id = deterministic_id("src/prod.rs", "impl S");
        let contains = graph
            .neighbors(&s_id)
            .into_iter()
            .find(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains)
            .map(|(_, e)| e.scope);
        assert_eq!(
            contains,
            Some(EdgeScope::Test),
            "EC-7a: a #[cfg(test)] impl block's struct→impl Contains edge must be Test-scoped"
        );
    }

    #[test]
    fn ec7a_production_struct_impl_contains_edge_stays_production() {
        // ANTI-OVER-TAG (GREEN today, regression-pin): a pure-production
        // struct+inherent-impl must keep its Contains edge Production after the
        // fix. Pins against a blanket `scope = Test` / inverted-condition mis-fix.
        use crate::extractor::extract_rust_symbols;
        let output =
            extract_rust_symbols("struct P; impl P { fn m(&self) {} }", "src/prod.rs").unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let p_id = deterministic_id("src/prod.rs", "P");
        let impl_id = deterministic_id("src/prod.rs", "impl P");
        let contains = graph
            .neighbors(&p_id)
            .into_iter()
            .find(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains)
            .map(|(_, e)| e.scope);
        assert_eq!(
            contains,
            Some(EdgeScope::Production),
            "EC-7a: a production struct→impl Contains edge must stay Production"
        );
    }

    #[test]
    fn ec7a_scope_follows_impl_not_struct() {
        // SCOPE-FOLLOWS-IMPL (RED on HEAD): a TOP-LEVEL production struct P with
        // a `#[cfg(test)]` impl P. The struct is_test_only=false; the impl
        // carries its own #[cfg(test)] attribute → is_test_only=true. The
        // Contains edge must follow the IMPL's test-ness (Test), NOT the
        // production struct's. This is the decisive discriminator: a naive
        // "read the STRUCT's is_test_only" mis-fix would (wrongly) yield
        // Production here yet still pass the cfg-test-mod case (where struct AND
        // impl are both test). Only keying the side-map on the IMPL node id
        // yields Test.
        use crate::extractor::extract_rust_symbols;
        let output = extract_rust_symbols(
            "struct P;\n#[cfg(test)]\nimpl P { fn m(&self) {} }",
            "src/prod.rs",
        )
        .unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let p_id = deterministic_id("src/prod.rs", "P");
        let impl_id = deterministic_id("src/prod.rs", "impl P");
        let contains = graph
            .neighbors(&p_id)
            .into_iter()
            .find(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains)
            .map(|(_, e)| e.scope);
        assert_eq!(
            contains,
            Some(EdgeScope::Test),
            "EC-7a: scope must follow the IMPL's cfg(test)-ness, not the production struct's"
        );
    }

    // ── EC-10 (WU-0001 addendum): module-nested impls get their struct→impl ──
    // Contains edge ──────────────────────────────────────────────────────────
    //
    // The Phase-3 "Post-hoc struct → impl block Contains edges" pass calls
    // `parse_struct_from_impl(symbol_name)` where `symbol_name` is the QUALIFIED
    // node name. For a module-nested impl the extractor emits a qualified name
    // like `foo::impl Bar` (the EC-1 module recursion at extractor.rs:423 passes
    // the module's own qualified path as parent; build_graph's qualified_name()
    // then prefixes it). On HEAD `parse_struct_from_impl` begins with
    // `strip_prefix("impl ")?`, which returns None for `foo::impl Bar` (it
    // starts with `foo::`, not `impl `), so Phase-3 `continue`s and the
    // struct→impl Contains edge is NEVER built for ANY module-nested impl — a
    // latent false-DEAD source feeding CL-REACH/WU-0003. EC-10 widens
    // `parse_struct_from_impl` to also accept the qualified `<path>::impl <…>`
    // form via `rsplit_once("::impl ")`.
    //
    // All fixtures drive END-TO-END through the real extractor
    // (`extract_rust_symbols` → `build_graph`), NOT `make_symbol` (which would
    // hardcode parent and emit a bare `impl Bar` without the `foo::` prefix,
    // reproducing neither the bug nor the real qualified id). This is the
    // anti-green-by-construction mandate (the trap that made EC-3/EC-7 vacuous).

    #[test]
    fn ec10_inherent_mod_nested_impl_gets_struct_contains_edge() {
        // DISCRIMINATION-POSITIVE (RED on HEAD): an inherent impl nested in a
        // module. The extractor emits the struct as `foo::Bar` and the impl as
        // `foo::impl Bar`. The struct→impl Contains edge must exist. RED on HEAD
        // because `parse_struct_from_impl("foo::impl Bar")` → strip_prefix("impl
        // ") = None → Phase-3 skips it; only the Phase-2 module→impl edge
        // (`foo` Contains `foo::impl Bar`) exists.
        use crate::extractor::extract_rust_symbols;
        let output = extract_rust_symbols(
            "mod foo { struct Bar; impl Bar { fn m(&self) {} } }",
            "test.rs",
        )
        .unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let bar_id = deterministic_id("test.rs", "foo::Bar");
        let impl_id = deterministic_id("test.rs", "foo::impl Bar");
        assert!(
            graph
                .neighbors(&bar_id)
                .iter()
                .any(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains),
            "EC-10: foo::Bar must Contains foo::impl Bar"
        );
    }

    #[test]
    fn ec10_mod_nested_trait_impl_gets_struct_contains_edge() {
        // DISCRIMINATION-POSITIVE (RED on HEAD): a TRAIT impl nested in a module.
        // The impl is emitted as `foo::impl Tr for Bar`. Exercises the existing
        // " for " split AFTER the module-prefix strip: rsplit_once("::impl ")
        // yields `Tr for Bar`, then `.find(" for ")` takes `Bar`. RED on HEAD
        // (strip_prefix("impl ") = None for the qualified name).
        use crate::extractor::extract_rust_symbols;
        let output = extract_rust_symbols(
            "mod foo { trait Tr { fn m(&self); } struct Bar; impl Tr for Bar { fn m(&self) {} } }",
            "test.rs",
        )
        .unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let bar_id = deterministic_id("test.rs", "foo::Bar");
        let impl_id = deterministic_id("test.rs", "foo::impl Tr for Bar");
        assert!(
            graph
                .neighbors(&bar_id)
                .iter()
                .any(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains),
            "EC-10: foo::Bar must Contains foo::impl Tr for Bar"
        );
    }

    #[test]
    fn ec10_deeply_nested_impl_gets_struct_contains_edge() {
        // DISCRIMINATION-POSITIVE (RED on HEAD): a doubly-nested impl. The
        // extractor emits `a::b::X` and `a::b::impl X`. Proves the fix's
        // `rsplit_once("::impl ")` splits at the LAST `::impl ` and so handles a
        // multi-segment (`a::b::`) module prefix, not just single-segment. RED
        // on HEAD (strip_prefix("impl ") = None).
        use crate::extractor::extract_rust_symbols;
        let output = extract_rust_symbols(
            "mod a { mod b { struct X; impl X { fn m(&self) {} } } }",
            "test.rs",
        )
        .unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let x_id = deterministic_id("test.rs", "a::b::X");
        let impl_id = deterministic_id("test.rs", "a::b::impl X");
        assert!(
            graph
                .neighbors(&x_id)
                .iter()
                .any(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains),
            "EC-10: a::b::X must Contains a::b::impl X (rsplit_once handles multi-segment prefix)"
        );
    }

    #[test]
    fn ec10_toplevel_impl_struct_contains_edge_still_builds() {
        // REGRESSION-PIN (GREEN today, MUST stay GREEN): a top-level inherent
        // impl has NO module prefix — emitted as `impl P` (parent = None). On
        // HEAD `parse_struct_from_impl("impl P")` hits the existing
        // strip_prefix("impl ") = Some("P") branch. The fix is
        // `strip_prefix("impl ").or_else(rsplit_once)`, so strip_prefix still
        // fires FIRST for top-level names and the rsplit branch is never reached
        // — top-level behavior is unchanged. Pins that the fix does not break
        // the top-level strip path.
        use crate::extractor::extract_rust_symbols;
        let output =
            extract_rust_symbols("struct P; impl P { fn m(&self) {} }", "test.rs").unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let p_id = deterministic_id("test.rs", "P");
        let impl_id = deterministic_id("test.rs", "impl P");
        assert!(
            graph
                .neighbors(&p_id)
                .iter()
                .any(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains),
            "EC-10 regression-pin: top-level P must STILL Contains impl P"
        );
    }

    #[test]
    fn ec10_same_module_resolution_known_limitation_do_not_force_green() {
        // DOCUMENTED-LIMITATION (NOT an EC-10 correctness assert).
        //
        // Two modules each declare a `struct Bar`; only `foo` has an impl. EC-10
        // (parse-only) now BUILDS a struct→impl Contains edge where HEAD built
        // none — that is the property this test pins: the edge EXISTS to SOME
        // Bar. It does NOT assert WHICH Bar, because `find_struct_for_impl`
        // (edge_builder.rs:463) is same-FILE-first, NOT same-MODULE-first: in
        // this single-file fixture both `Bar` structs share `test.rs`, so the
        // linear suffix-scan (`ends_with("::Bar")`) returns the FIRST same-file
        // match by petgraph insertion order. With `foo` declared BEFORE `baz`
        // the edge happens to resolve to `foo::Bar` — but that is insertion-order
        // luck, not module-aware resolution (FIRSTHAND-PROVEN order dependence:
        // declaring `baz` first resolves to the WRONG `baz::Bar`). Fixing WHICH
        // Bar is find_struct_for_impl's job, deferred to CL-RESOLVE-6 / WU-0002;
        // it is explicitly NOT EC-10's to fix, and forcing a which-Bar correctness
        // assert green here would be green-by-construction.
        use crate::extractor::extract_rust_symbols;
        let output = extract_rust_symbols(
            "mod foo { struct Bar; impl Bar { fn fm(&self) {} } }  mod baz { struct Bar; }",
            "test.rs",
        )
        .unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let foo_bar_id = deterministic_id("test.rs", "foo::Bar");
        let baz_bar_id = deterministic_id("test.rs", "baz::Bar");
        let impl_id = deterministic_id("test.rs", "foo::impl Bar");

        // EC-10's property: the edge is now built (HEAD built NONE) — to SOME Bar.
        let foo_has_edge = graph
            .neighbors(&foo_bar_id)
            .iter()
            .any(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains);
        let baz_has_edge = graph
            .neighbors(&baz_bar_id)
            .iter()
            .any(|(t, e)| *t == impl_id && e.kind == EdgeKind::Contains);
        assert!(
            foo_has_edge || baz_has_edge,
            "EC-10: the module-nested impl must now have a struct→impl Contains edge to SOME Bar \
             (HEAD built none); which Bar is find_struct_for_impl's order-dependent limitation, \
             deferred to CL-RESOLVE-6 / WU-0002"
        );
        // Order-dependent observation (foo-first ⇒ resolves to foo::Bar). This is
        // luck, not correctness — documented above, intentionally not asserted as
        // an EC-10 acceptance criterion.
    }

    #[test]
    fn test_contains_edges_from_impl_methods() {
        let mut graph = KnowledgeGraph::new();
        let output = make_output(
            "src/foo.rs",
            vec![
                make_symbol("impl MyStruct", SymbolKind::Impl, None),
                make_symbol("do_thing", SymbolKind::Function, Some("impl MyStruct")),
                make_symbol("other", SymbolKind::Function, Some("impl MyStruct")),
            ],
        );

        let stats = build_graph(&[output], &mut graph).unwrap();

        assert_eq!(stats.nodes_added, 3);
        assert_eq!(stats.edges_added, 2); // two Contains edges
        assert_eq!(
            stats.total_skipped(),
            1,
            "the fixture intentionally omits the impl's concrete type"
        );

        // Verify edge direction: parent → child.
        let parent_id = deterministic_id("src/foo.rs", "impl MyStruct");
        let neighbors = graph.neighbors(&parent_id);
        assert_eq!(neighbors.len(), 2);
        // Both edges should be Contains.
        for (_, edge) in &neighbors {
            assert_eq!(edge.kind, EdgeKind::Contains);
        }
    }

    #[test]
    fn test_implements_edges_from_trait_impl() {
        let mut graph = KnowledgeGraph::new();

        // First file: defines the trait.
        let trait_output = make_output(
            "src/traits.rs",
            vec![make_symbol("Display", SymbolKind::Trait, None)],
        );

        // Second file: implements the trait.
        let impl_output = make_output(
            "src/my_type.rs",
            vec![make_symbol(
                "impl Display for MyType",
                SymbolKind::Impl,
                None,
            )],
        );

        let stats = build_graph(&[trait_output, impl_output], &mut graph).unwrap();

        assert_eq!(stats.nodes_added, 2);
        assert_eq!(stats.edges_added, 1); // one Implements edge
        assert_eq!(
            stats.total_skipped(),
            1,
            "the fixture intentionally omits the implementation type"
        );

        // Verify: impl node → trait node.
        let impl_id = deterministic_id("src/my_type.rs", "impl Display for MyType");
        let neighbors = graph.neighbors(&impl_id);
        assert_eq!(neighbors.len(), 1);
        let (target_id, edge) = &neighbors[0];
        assert_eq!(edge.kind, EdgeKind::Implements);
        // The target should be the Display trait node.
        let target_node = graph.node(target_id).expect("target node must exist");
        assert_eq!(target_node.symbol_name, "Display");
    }

    #[test]
    fn ec12_external_trait_impl_emits_implements_and_hasimpl_deduped() {
        // EC-12 (WU-0001): an impl of an EXTERNAL trait (no node in the graph,
        // e.g. std::fmt::Display) must synthesize ONE deduped external-trait
        // anchor node and emit `impl --Implements--> ExternalTrait` +
        // `ExternalTrait --HasImpl--> ConcreteType`. RED on HEAD: today
        // find_trait_node returns None for an external trait and BOTH edges are
        // silently skipped (zero such edges in the live graph).
        let mut graph = KnowledgeGraph::new();

        // File A: struct X + impl Display for X. NO `Display` trait symbol exists
        // anywhere in the outputs (external/std trait).
        let out_a = make_output(
            "src/a.rs",
            vec![
                make_symbol("X", SymbolKind::Struct, None),
                make_symbol("impl Display for X", SymbolKind::Impl, None),
            ],
        );
        // File B: struct Y + impl Display for Y — proves DEDUP (one Display node).
        let out_b = make_output(
            "src/b.rs",
            vec![
                make_symbol("Y", SymbolKind::Struct, None),
                make_symbol("impl Display for Y", SymbolKind::Impl, None),
            ],
        );

        let stats = build_graph(&[out_a, out_b], &mut graph).expect("build_graph");

        // (a) Implements edge from impl(X) → synthetic Display node.
        let impl_x_id = deterministic_id("src/a.rs", "impl Display for X");
        let impl_x_neighbors = graph.neighbors(&impl_x_id);
        let implements_target = impl_x_neighbors
            .iter()
            .find(|(_, e)| e.kind == EdgeKind::Implements)
            .map(|(t, _)| *t);
        let display_id =
            implements_target.expect("impl X must Implements an external Display node");

        // (b) the resolved target is the synthetic external-trait node.
        let display_node = graph.node(&display_id).expect("Display node must exist");
        assert_eq!(display_node.symbol_name, "Display");
        assert_eq!(display_node.kind, "trait");
        assert_eq!(display_node.file_path, EXTERNAL_TRAIT_SENTINEL);
        assert_eq!(
            display_node.signature, "extern trait Display",
            "the shared structural DTO must retain external-trait identity instead of \
             publishing an indistinguishable generic signature"
        );

        // (c) HasImpl edge: Display --HasImpl--> X (the concrete struct).
        let x_id = deterministic_id("src/a.rs", "X");
        let display_neighbors = graph.neighbors(&display_id);
        assert!(
            display_neighbors
                .iter()
                .any(|(t, e)| *t == x_id && e.kind == EdgeKind::HasImpl),
            "Display must HasImpl the concrete struct X"
        );

        // (d) DEDUP: impl(Y) Implements the SAME Display node (one node index-wide).
        let impl_y_id = deterministic_id("src/b.rs", "impl Display for Y");
        let impl_y_implements_target = graph
            .neighbors(&impl_y_id)
            .iter()
            .find(|(_, e)| e.kind == EdgeKind::Implements)
            .map(|(t, _)| *t);
        assert_eq!(
            impl_y_implements_target,
            Some(display_id),
            "impl Y must Implements the SAME synthetic Display node (dedup)"
        );

        // Exactly ONE synthesized external-trait node across both files.
        assert_eq!(
            stats.external_traits_synthesized, 1,
            "one distinct external trait name => one synthesized node"
        );
    }

    #[test]
    fn ec13_local_supertrait_emits_extends_edge() {
        // EC-13 (WU-0001) — CHARACTERIZATION / regression guard (GREEN on HEAD by
        // design; NOT a fix-falsifier). Locks the previously-UNFALSIFIED Phase-5
        // Extends producer (edge_builder.rs :515): a LOCAL supertrait
        // `trait Foo: Bar` (Bar resolves via find_trait_node's same-file tie-break)
        // must emit `Foo --Extends--> Bar`. Drives the REAL build_graph path.
        let mut bar = make_symbol("Bar", SymbolKind::Trait, None);
        bar.relations = Vec::new();
        let mut foo = make_symbol("Foo", SymbolKind::Trait, None);
        foo.relations = vec![StructuralRelation::Extends {
            target: "Bar".to_string(),
        }];
        let outputs = vec![make_output("src/lib.rs", vec![bar, foo])];
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&outputs, &mut graph).expect("build_graph");
        let foo_id = deterministic_id("src/lib.rs", "Foo");
        let bar_id = deterministic_id("src/lib.rs", "Bar");
        assert!(
            graph
                .neighbors(&foo_id)
                .iter()
                .any(|(t, e)| *t == bar_id && e.kind == EdgeKind::Extends),
            "EC-13 T1: local supertrait Foo: Bar must emit Foo --Extends--> Bar"
        );
        assert_eq!(
            stats.edges_skipped_external_relation, 0,
            "EC-13 T1: a resolved local supertrait is not a skip"
        );
    }

    #[test]
    fn ec13_marker_supertrait_not_flagged_as_under_production() {
        // EC-13 (WU-0001) — THE REAL FALSIFIER (RED on HEAD, GREEN after fix).
        // An auto/marker supertrait (`Send`, unresolved, no local node) must NOT
        // trip the under-production telemetry. On HEAD the else-branch at
        // edge_builder.rs :533 unconditionally does
        // `edges_skipped_external_relation += 1` for ANY unresolved supertrait, so a
        // Send-only fixture yields `_external_trait == 1` (RED: left 1, right 0).
        // After the fix Send is recognized as a marker and routed to the existing
        // `_other` bucket => `_external_trait == 0` (GREEN).
        let mut baz = make_symbol("Baz", SymbolKind::Trait, None);
        baz.relations = vec![StructuralRelation::Extends {
            target: "Send".to_string(),
        }]; // unresolved auto/marker trait, NO local node
        let outputs = vec![make_output("src/lib.rs", vec![baz])];
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&outputs, &mut graph).expect("build_graph");
        assert_eq!(
            stats.edges_skipped_external_relation, 0,
            "EC-13 T2: an auto/marker supertrait (Send) must NOT trip the under-production telemetry"
        );
        assert_eq!(
            stats.edges_skipped_other, 1,
            "EC-13 T2: the skipped marker supertrait lands in the _other bucket"
        );
    }

    #[test]
    fn ec13_external_domain_supertrait_still_flagged() {
        // EC-13 (WU-0001) — NARROWNESS (GREEN both before and after). Proves the
        // marker filter does NOT over-suppress: a real external DOMAIN supertrait
        // (`Display`, not in {Send,Sync,Sized,Unpin}, no local node) is STILL
        // honestly counted as under-production. If this flips to 0 after the fix,
        // the filter is too broad.
        let mut q = make_symbol("Q", SymbolKind::Trait, None);
        q.relations = vec![StructuralRelation::Extends {
            target: "Display".to_string(),
        }]; // real external DOMAIN trait, NOT a marker, NO local node
        let outputs = vec![make_output("src/lib.rs", vec![q])];
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&outputs, &mut graph).expect("build_graph");
        assert_eq!(
            stats.edges_skipped_external_relation, 1,
            "EC-13 T3: a real external DOMAIN supertrait (Display) is STILL honestly counted as under-production"
        );
    }

    #[test]
    fn test_references_edges_from_use() {
        let mut graph = KnowledgeGraph::new();
        let output = make_output(
            "src/lib.rs",
            vec![
                make_symbol("HashMap", SymbolKind::Struct, None),
                make_symbol("std::collections::HashMap", SymbolKind::Use, None),
            ],
        );

        let stats = build_graph(&[output], &mut graph).unwrap();

        assert_eq!(stats.nodes_added, 2);
        assert_eq!(stats.edges_added, 1); // References edge from use → HashMap
        assert_eq!(stats.total_skipped(), 0);
    }

    #[test]
    fn test_deterministic_uuids() {
        let id1 = deterministic_id("src/foo.rs", "my_fn");
        let id2 = deterministic_id("src/foo.rs", "my_fn");
        let id3 = deterministic_id("src/bar.rs", "my_fn");

        assert_eq!(id1, id2, "same input must produce same UUID");
        assert_ne!(id1, id3, "different file must produce different UUID");
    }

    #[test]
    fn valid_rust_duplicate_impl_occurrences_are_not_collapsed() {
        let output = crate::extractor::extract_source(
            concat!(
                "pub struct Widget;\n",
                "impl Widget { pub fn first(&self) {} }\n",
                "impl Widget { pub fn second(&self) {} }\n",
            ),
            "src/lib.rs",
        )
        .expect("extract valid repeated inherent impls");
        assert_eq!(
            output
                .symbols
                .iter()
                .filter(|symbol| {
                    symbol.kind == SymbolKind::Impl && qualified_name(symbol) == "impl Widget"
                })
                .count(),
            2,
            "positive control: Rust permits multiple inherent impl blocks for one type"
        );

        let extracted = output.symbols.len();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).expect("build repeated-impl graph");
        let represented = graph.nodes_for_file("src/lib.rs");
        assert_eq!(
            represented.len(),
            extracted,
            "every extracted Rust source occurrence must retain a distinct graph identity"
        );
        assert_eq!(
            represented
                .iter()
                .filter(|node| node.kind == "impl" && node.symbol_name == "impl Widget")
                .count(),
            2,
            "both valid impl occurrences must remain addressable"
        );
        for method_name in ["impl Widget::first", "impl Widget::second"] {
            let method = represented
                .iter()
                .find(|node| node.symbol_name == method_name)
                .unwrap_or_else(|| panic!("method occurrence {method_name}"));
            let parents = graph
                .incoming_neighbors(&method.memory_id)
                .into_iter()
                .filter(|(_, edge)| edge.kind == EdgeKind::Contains)
                .collect::<Vec<_>>();
            assert_eq!(
                parents.len(),
                1,
                "{method_name} must belong to exactly one impl occurrence"
            );
            let parent = graph.node(&parents[0].0).expect("impl parent node");
            assert_eq!(parent.symbol_name, "impl Widget");
            let parent_span = graph
                .source_span(&parent.memory_id)
                .expect("impl source span");
            let method_span = graph
                .source_span(&method.memory_id)
                .expect("method source span");
            assert!(
                parent_span.start_byte <= method_span.start_byte
                    && parent_span.end_byte >= method_span.end_byte,
                "{method_name} must be attached to the lexically containing impl"
            );
        }
    }

    #[test]
    fn valid_go_duplicate_init_occurrences_are_not_collapsed() {
        let output = crate::extractor::extract_source(
            concat!(
                "package worker\n",
                "func init() { first() }\n",
                "func init() { second() }\n",
                "func first() {}\n",
                "func second() {}\n",
            ),
            "worker.go",
        )
        .expect("extract valid repeated Go init functions");
        assert_eq!(
            output
                .symbols
                .iter()
                .filter(|symbol| {
                    symbol.kind == SymbolKind::Function && qualified_name(symbol) == "init"
                })
                .count(),
            2,
            "positive control: Go permits multiple package init functions"
        );

        let extracted = output.symbols.len();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).expect("build repeated-init graph");
        let represented = graph.nodes_for_file("worker.go");
        assert_eq!(
            represented.len(),
            extracted,
            "every extracted Go source occurrence must retain a distinct graph identity"
        );
        assert_eq!(
            represented
                .iter()
                .filter(|node| node.kind == "function" && node.symbol_name == "init")
                .count(),
            2,
            "both valid init occurrences must remain addressable"
        );
    }

    #[test]
    fn test_build_stats_accuracy() {
        let mut graph = KnowledgeGraph::new();

        // A use statement referencing a symbol that does NOT exist → skipped edge.
        let output = make_output(
            "src/lib.rs",
            vec![
                make_symbol("MyStruct", SymbolKind::Struct, None),
                make_symbol("crate::missing::Thing", SymbolKind::Use, None),
            ],
        );

        let stats = build_graph(&[output], &mut graph).unwrap();

        assert_eq!(stats.nodes_added, 2);
        assert_eq!(stats.edges_added, 0);
        // EC-12: a missing `use` target is a genuine NodeNotFound → the `other`
        // bucket (NOT external-trait, which is the Implements/Extends path).
        assert_eq!(stats.total_skipped(), 1); // "Thing" not found
        assert_eq!(stats.edges_skipped_other, 1);
        assert_eq!(stats.edges_skipped_external_relation, 0);
    }

    #[test]
    fn test_parse_trait_from_impl() {
        assert_eq!(
            parse_trait_from_impl("impl Display for MyType"),
            Some("Display".to_string())
        );
        assert_eq!(parse_trait_from_impl("impl MyType"), None);
        assert_eq!(
            parse_trait_from_impl("impl Iterator for MyIter"),
            Some("Iterator".to_string())
        );
    }

    #[test]
    fn test_last_segment() {
        assert_eq!(last_segment("std::collections::HashMap"), "HashMap");
        assert_eq!(last_segment("HashMap"), "HashMap");
        assert_eq!(last_segment("crate::foo::bar::Baz"), "Baz");
    }

    #[test]
    fn test_incremental_update_replaces_nodes() {
        // Write a temp file so we have a real file path for both initial and update.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("foo.rs");
        let root = dir.path();

        // Initial extraction: file contains old_fn.
        std::fs::write(&file_path, "fn old_fn() {}\n").unwrap();
        let output = crate::extractor::extract_file(&file_path, root).unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();
        let initial_count = graph.node_count();
        assert!(initial_count >= 1);

        // Overwrite with new content.
        std::fs::write(&file_path, "fn new_fn() {}\n").unwrap();

        let stats = incremental_update(&file_path, root, &mut graph).unwrap();

        // old_fn should be gone (invalidated), new_fn should be present.
        assert!(stats.nodes_added >= 1);
        // file_path in graph is now relative ("foo.rs"), not absolute.
        let old_id = deterministic_id("foo.rs", "old_fn");
        assert!(
            graph.node(&old_id).is_none(),
            "old_fn node should have been invalidated"
        );
    }

    #[test]
    fn test_group_nodes_by_file() {
        let mut graph = KnowledgeGraph::new();
        let outputs = vec![
            make_output(
                "src/foo.rs",
                vec![
                    make_symbol("FooStruct", SymbolKind::Struct, None),
                    make_symbol("foo_fn", SymbolKind::Function, None),
                ],
            ),
            make_output(
                "src/bar.rs",
                vec![make_symbol("BarStruct", SymbolKind::Struct, None)],
            ),
        ];

        build_graph(&outputs, &mut graph).unwrap();

        let groups = group_nodes_by_file(&graph);

        assert_eq!(groups.len(), 2, "should have two file groups");
        assert_eq!(
            groups["src/foo.rs"].len(),
            2,
            "foo.rs should have 2 symbols"
        );
        assert_eq!(groups["src/bar.rs"].len(), 1, "bar.rs should have 1 symbol");
        // Verify BTreeMap ordering (alphabetical)
        let keys: Vec<_> = groups.keys().collect();
        assert_eq!(keys, vec!["src/bar.rs", "src/foo.rs"]);
    }

    #[test]
    fn test_group_nodes_by_file_empty_graph() {
        let graph = KnowledgeGraph::new();
        let groups = group_nodes_by_file(&graph);
        assert!(groups.is_empty(), "empty graph should produce empty groups");
    }

    // -----------------------------------------------------------------------
    // Phase 3: struct → impl Contains edge tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_struct_from_impl_trait_impl() {
        assert_eq!(
            parse_struct_from_impl("impl Display for MyType"),
            Some("MyType".to_string()),
        );
    }

    #[test]
    fn test_parse_struct_from_impl_inherent_impl() {
        assert_eq!(
            parse_struct_from_impl("impl LanceStore"),
            Some("LanceStore".to_string()),
        );
    }

    #[test]
    fn test_parse_struct_from_impl_question_mark() {
        assert_eq!(parse_struct_from_impl("impl ?"), None);
    }

    #[test]
    fn test_parse_struct_from_impl_no_prefix() {
        assert_eq!(parse_struct_from_impl("not an impl"), None);
    }

    #[test]
    fn test_struct_to_impl_contains_edge_trait_impl() {
        // A struct + a trait impl for that struct should produce a
        // Contains edge from the struct to the impl block.
        let mut graph = KnowledgeGraph::new();
        let output = make_output(
            "src/handler.rs",
            vec![
                make_symbol("BlastRadiusHandler", SymbolKind::Struct, None),
                make_symbol(
                    "impl ToolHandler for BlastRadiusHandler",
                    SymbolKind::Impl,
                    None,
                ),
                make_symbol(
                    "execute",
                    SymbolKind::Function,
                    Some("impl ToolHandler for BlastRadiusHandler"),
                ),
            ],
        );

        let stats = build_graph(&[output], &mut graph).unwrap();

        // 3 real symbols added. EC-12: the synthesized external `ToolHandler`
        // anchor is NOT counted in nodes_added (it's tracked separately in
        // external_traits_synthesized), so this stays 3.
        assert_eq!(stats.nodes_added, 3);
        assert_eq!(
            stats.external_traits_synthesized, 1,
            "EC-12: ToolHandler is external (no local trait node) → one synthesized anchor"
        );

        let struct_id = deterministic_id("src/handler.rs", "BlastRadiusHandler");
        let impl_id = deterministic_id("src/handler.rs", "impl ToolHandler for BlastRadiusHandler");

        // Verify: struct has ONE outgoing edge — Contains(struct → impl). The
        // EC-12 HasImpl edge (ToolHandler → struct) is INCOMING to the struct, so
        // its outgoing-neighbor count is unchanged.
        let struct_neighbors = graph.neighbors(&struct_id);
        assert_eq!(
            struct_neighbors.len(),
            1,
            "struct should have one outgoing edge (to impl block)"
        );
        let (target_id, edge) = &struct_neighbors[0];
        assert_eq!(edge.kind, EdgeKind::Contains);
        assert_eq!(*target_id, impl_id);

        // EC-12 (flipped from the old silent-skip behavior): the impl now emits an
        // Implements edge to the synthesized external ToolHandler anchor.
        let impl_neighbors = graph.neighbors(&impl_id);
        let implements_target = impl_neighbors
            .iter()
            .find(|(_, e)| e.kind == EdgeKind::Implements)
            .map(|(t, _)| *t);
        let toolhandler_id =
            implements_target.expect("EC-12: impl must Implements the external ToolHandler anchor");
        let toolhandler = graph.node(&toolhandler_id).expect("anchor node exists");
        assert_eq!(toolhandler.symbol_name, "ToolHandler");
        assert_eq!(toolhandler.kind, "trait");
        assert_eq!(toolhandler.file_path, EXTERNAL_TRAIT_SENTINEL);
        // And the reverse HasImpl edge: ToolHandler → BlastRadiusHandler.
        assert!(
            graph
                .neighbors(&toolhandler_id)
                .iter()
                .any(|(t, e)| *t == struct_id && e.kind == EdgeKind::HasImpl),
            "EC-12: external ToolHandler anchor must HasImpl the concrete struct"
        );
    }

    #[test]
    fn test_struct_to_impl_contains_edge_inherent_impl() {
        // An inherent impl ("impl MyStruct") should get a Contains edge
        // from the struct node.
        let mut graph = KnowledgeGraph::new();
        let output = make_output(
            "src/store.rs",
            vec![
                make_symbol("LanceStore", SymbolKind::Struct, None),
                make_symbol("impl LanceStore", SymbolKind::Impl, None),
                make_symbol("new", SymbolKind::Function, Some("impl LanceStore")),
            ],
        );

        let stats = build_graph(&[output], &mut graph).unwrap();

        assert_eq!(stats.nodes_added, 3);

        let struct_id = deterministic_id("src/store.rs", "LanceStore");
        let impl_id = deterministic_id("src/store.rs", "impl LanceStore");

        let struct_neighbors = graph.neighbors(&struct_id);
        assert_eq!(
            struct_neighbors.len(),
            1,
            "struct should have one outgoing edge (to impl block)"
        );
        let (target_id, edge) = &struct_neighbors[0];
        assert_eq!(edge.kind, EdgeKind::Contains);
        assert_eq!(*target_id, impl_id);
    }

    #[test]
    fn test_struct_to_impl_trait_node_does_not_get_contains() {
        // For "impl Display for MyType", the Contains edge goes from
        // MyType (struct) to the impl block, NOT from Display (trait).
        let mut graph = KnowledgeGraph::new();
        let trait_output = make_output(
            "src/traits.rs",
            vec![make_symbol("Display", SymbolKind::Trait, None)],
        );
        let impl_output = make_output(
            "src/my_type.rs",
            vec![
                make_symbol("MyType", SymbolKind::Struct, None),
                make_symbol("impl Display for MyType", SymbolKind::Impl, None),
            ],
        );

        let stats = build_graph(&[trait_output, impl_output], &mut graph).unwrap();

        assert_eq!(stats.nodes_added, 3);

        let trait_id = deterministic_id("src/traits.rs", "Display");
        let struct_id = deterministic_id("src/my_type.rs", "MyType");
        let impl_id = deterministic_id("src/my_type.rs", "impl Display for MyType");

        // The trait node should have NO outgoing Contains edges.
        let trait_neighbors = graph.neighbors(&trait_id);
        let trait_contains_count = trait_neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::Contains)
            .count();
        assert_eq!(
            trait_contains_count, 0,
            "trait node must not have Contains edges to impl blocks"
        );

        // The struct node should have the Contains edge to the impl block.
        let struct_neighbors = graph.neighbors(&struct_id);
        assert_eq!(struct_neighbors.len(), 1);
        let (target_id, edge) = &struct_neighbors[0];
        assert_eq!(edge.kind, EdgeKind::Contains);
        assert_eq!(*target_id, impl_id);

        // The impl block should still have Implements edge to the trait.
        let impl_neighbors = graph.neighbors(&impl_id);
        let implements: Vec<_> = impl_neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::Implements)
            .collect();
        assert_eq!(
            implements.len(),
            1,
            "impl block should have Implements edge to trait"
        );
        let (impl_target, _) = implements[0];
        assert_eq!(*impl_target, trait_id);
    }

    #[test]
    fn test_struct_to_impl_multiple_impls() {
        // A struct with both an inherent impl and a trait impl should get
        // two Contains edges (one to each impl block).
        let mut graph = KnowledgeGraph::new();
        let output = make_output(
            "src/multi.rs",
            vec![
                make_symbol("MyStruct", SymbolKind::Struct, None),
                make_symbol("impl MyStruct", SymbolKind::Impl, None),
                make_symbol("impl Display for MyStruct", SymbolKind::Impl, None),
            ],
        );

        let stats = build_graph(&[output], &mut graph).unwrap();

        assert_eq!(stats.nodes_added, 3);

        let struct_id = deterministic_id("src/multi.rs", "MyStruct");
        let struct_neighbors = graph.neighbors(&struct_id);

        let contains_count = struct_neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::Contains)
            .count();
        assert_eq!(
            contains_count, 2,
            "struct should have Contains edges to both impl blocks"
        );
    }

    #[test]
    fn test_existing_contains_edges_unchanged() {
        // The original Phase 2 Contains edges (impl → method) must still exist
        // alongside the new Phase 3 edges (struct → impl).
        let mut graph = KnowledgeGraph::new();
        let output = make_output(
            "src/foo.rs",
            vec![
                make_symbol("MyStruct", SymbolKind::Struct, None),
                make_symbol("impl MyStruct", SymbolKind::Impl, None),
                make_symbol("do_thing", SymbolKind::Function, Some("impl MyStruct")),
                make_symbol("other", SymbolKind::Function, Some("impl MyStruct")),
            ],
        );

        let stats = build_graph(&[output], &mut graph).unwrap();

        assert_eq!(stats.nodes_added, 4);
        // Phase 2: 2 Contains (impl → method1, impl → method2)
        // Phase 3: 1 Contains (struct → impl)
        // Total Contains: 3
        assert_eq!(stats.edges_added, 3);

        // Verify impl → method edges still exist.
        let impl_id = deterministic_id("src/foo.rs", "impl MyStruct");
        let impl_neighbors = graph.neighbors(&impl_id);
        let impl_contains_count = impl_neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::Contains)
            .count();
        assert_eq!(
            impl_contains_count, 2,
            "impl block should still have 2 Contains edges to methods"
        );

        // Verify struct → impl edge exists.
        let struct_id = deterministic_id("src/foo.rs", "MyStruct");
        let struct_neighbors = graph.neighbors(&struct_id);
        assert_eq!(
            struct_neighbors.len(),
            1,
            "struct should have 1 Contains edge to impl"
        );
        assert_eq!(struct_neighbors[0].1.kind, EdgeKind::Contains);
    }

    // ---------------------------------------------------------------
    // HasImpl edge tests
    // ---------------------------------------------------------------

    #[test]
    fn test_has_impl_edge_created_for_trait_impl() {
        // Given: a trait MyTrait and impl MyTrait for MyHandler
        let symbols = vec![
            make_symbol("MyTrait", SymbolKind::Trait, None),
            make_symbol("MyHandler", SymbolKind::Struct, None),
            make_symbol("impl MyTrait for MyHandler", SymbolKind::Impl, None),
            make_symbol(
                "handle",
                SymbolKind::Function,
                Some("impl MyTrait for MyHandler"),
            ),
        ];
        let output = make_output("src/lib.rs", symbols);
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&[output], &mut graph).expect("build_graph");

        // The trait should have a HasImpl edge to MyHandler.
        let trait_id = deterministic_id("src/lib.rs", "MyTrait");
        let trait_neighbors = graph.neighbors(&trait_id);
        let has_impl_edges: Vec<_> = trait_neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::HasImpl)
            .collect();

        assert_eq!(
            has_impl_edges.len(),
            1,
            "trait should have 1 HasImpl edge; stats: {} added, {} skipped",
            stats.edges_added,
            stats.total_skipped()
        );

        // Verify the target of HasImpl is the struct, not the impl block.
        let handler_id = deterministic_id("src/lib.rs", "MyHandler");
        assert_eq!(
            has_impl_edges[0].0, handler_id,
            "HasImpl should point to the concrete struct"
        );
    }

    // ---------------------------------------------------------------
    // FieldOf edge tests
    // ---------------------------------------------------------------

    #[test]
    fn test_fieldof_edges_from_struct_field_types() {
        // Given: struct Engine with field types [GraphBackend, EngineConfig]
        // and those types exist as nodes in the graph.
        let mut engine_sym = make_symbol("Engine", SymbolKind::Struct, None);
        engine_sym.relations = ["GraphBackend", "EngineConfig"]
            .into_iter()
            .map(|target| StructuralRelation::FieldOf {
                target: target.to_string(),
            })
            .collect();

        let symbols = vec![
            engine_sym,
            make_symbol("GraphBackend", SymbolKind::Trait, None),
            make_symbol("EngineConfig", SymbolKind::Struct, None),
        ];
        let output = make_output("src/lib.rs", symbols);
        let mut graph = KnowledgeGraph::new();
        let _stats = build_graph(&[output], &mut graph).expect("build_graph");

        let engine_id = deterministic_id("src/lib.rs", "Engine");
        let neighbors = graph.neighbors(&engine_id);
        let fieldof_edges: Vec<_> = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .collect();

        assert_eq!(fieldof_edges.len(), 2, "Engine should have 2 FieldOf edges");

        let target_ids: std::collections::HashSet<Uuid> =
            fieldof_edges.into_iter().map(|(id, _)| *id).collect();
        let backend_id = deterministic_id("src/lib.rs", "GraphBackend");
        let config_id = deterministic_id("src/lib.rs", "EngineConfig");
        assert!(target_ids.contains(&backend_id));
        assert!(target_ids.contains(&config_id));
    }

    #[test]
    fn test_fieldof_skips_unknown_types() {
        // Given: struct with field type that doesn't exist in the graph
        let mut my_struct = make_symbol("MyStruct", SymbolKind::Struct, None);
        my_struct.relations = vec![StructuralRelation::FieldOf {
            target: "UnknownType".to_string(),
        }];

        let symbols = vec![my_struct];
        let output = make_output("src/lib.rs", symbols);
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&[output], &mut graph).expect("build_graph");

        let struct_id = deterministic_id("src/lib.rs", "MyStruct");
        let neighbors = graph.neighbors(&struct_id);
        let fieldof_count = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .count();

        assert_eq!(
            fieldof_count, 0,
            "FieldOf edges should not be created for unknown types"
        );
        // UnknownType lookup should have been skipped (not errored).
        assert!(stats.total_skipped() == 0 || stats.edges_added > 0);
    }

    #[test]
    fn test_find_symbol_node_suffix_matching() {
        // Given: a struct "Engine" with field_types = ["MemoryStore"],
        // and a trait node stored with a qualified name "core::store::MemoryStore".
        // The suffix matcher should resolve "MemoryStore" → "core::store::MemoryStore".
        let mut engine_sym = make_symbol("Engine", SymbolKind::Struct, None);
        engine_sym.relations = vec![StructuralRelation::FieldOf {
            target: "MemoryStore".to_string(),
        }];

        // Create the MemoryStore trait with a parent so its qualified name
        // becomes "store::MemoryStore" (simulating a nested module path).
        let mut store_trait = make_symbol("MemoryStore", SymbolKind::Trait, Some("store"));
        store_trait.content_hash = "hash_store_MemoryStore".to_string();

        let symbols = vec![engine_sym, store_trait];
        let output = make_output("src/lib.rs", symbols);
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&[output], &mut graph).expect("build_graph");

        // The Engine struct should have a FieldOf edge to store::MemoryStore
        // even though field_types only contains the short name "MemoryStore".
        let engine_id = deterministic_id("src/lib.rs", "Engine");
        let neighbors = graph.neighbors(&engine_id);
        let fieldof_edges: Vec<_> = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .collect();

        assert_eq!(
            fieldof_edges.len(),
            1,
            "Engine should have 1 FieldOf edge via suffix match (got {})",
            fieldof_edges.len()
        );

        let target_id = deterministic_id("src/lib.rs", "store::MemoryStore");
        assert_eq!(
            fieldof_edges[0].0, target_id,
            "FieldOf target should be store::MemoryStore"
        );
        assert!(
            stats.edges_added >= 1,
            "At least one edge (the FieldOf) should be added"
        );
    }

    #[test]
    fn test_find_symbol_node_prefers_exact_match() {
        // If both an exact match and a suffix match exist, exact should win.
        let mut engine_sym = make_symbol("Engine", SymbolKind::Struct, None);
        engine_sym.relations = vec![StructuralRelation::FieldOf {
            target: "Config".to_string(),
        }];

        // "Config" (exact match candidate)
        let exact_match = make_symbol("Config", SymbolKind::Struct, None);
        // "app::Config" (suffix match candidate)
        let mut suffix_match = make_symbol("Config", SymbolKind::Struct, Some("app"));
        suffix_match.content_hash = "hash_app_Config".to_string();

        let symbols = vec![engine_sym, exact_match, suffix_match];
        let output = make_output("src/lib.rs", symbols);
        let mut graph = KnowledgeGraph::new();
        let _stats = build_graph(&[output], &mut graph).expect("build_graph");

        let engine_id = deterministic_id("src/lib.rs", "Engine");
        let neighbors = graph.neighbors(&engine_id);
        let fieldof_edges: Vec<_> = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .collect();

        assert_eq!(fieldof_edges.len(), 1, "Engine should have 1 FieldOf edge");

        // Should point to "Config" (exact), not "app::Config" (suffix).
        let exact_id = deterministic_id("src/lib.rs", "Config");
        assert_eq!(
            fieldof_edges[0].0, exact_id,
            "FieldOf should prefer exact match over suffix match"
        );
    }

    #[test]
    fn test_find_symbol_node_shortest_suffix_wins() {
        // When multiple suffix matches exist, shortest symbol_name wins.
        let mut engine_sym = make_symbol("Engine", SymbolKind::Struct, None);
        engine_sym.relations = vec![StructuralRelation::FieldOf {
            target: "Store".to_string(),
        }];

        // Two suffix candidates: "mod::Store" and "deep::mod::Store"
        let mut short = make_symbol("Store", SymbolKind::Struct, Some("mod"));
        short.content_hash = "hash_mod_Store".to_string();
        let mut long = make_symbol("Store", SymbolKind::Struct, Some("deep::mod"));
        long.content_hash = "hash_deep_mod_Store".to_string();

        let symbols = vec![engine_sym, short, long];
        let output = make_output("src/lib.rs", symbols);
        let mut graph = KnowledgeGraph::new();
        let _stats = build_graph(&[output], &mut graph).expect("build_graph");

        let engine_id = deterministic_id("src/lib.rs", "Engine");
        let neighbors = graph.neighbors(&engine_id);
        let fieldof_edges: Vec<_> = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .collect();

        assert_eq!(fieldof_edges.len(), 1);

        let short_id = deterministic_id("src/lib.rs", "mod::Store");
        assert_eq!(
            fieldof_edges[0].0, short_id,
            "FieldOf should prefer shortest suffix match"
        );
    }

    #[test]
    fn test_extends_edges_from_supertraits() {
        // Create a trait with supertraits and verify Extends edges are created.
        let mut base_trait = make_symbol("BaseTrait", SymbolKind::Trait, None);
        base_trait.relations = Vec::new();

        let mut child_trait = make_symbol("ChildTrait", SymbolKind::Trait, None);
        child_trait.relations = vec![StructuralRelation::Extends {
            target: "BaseTrait".to_string(),
        }];

        let outputs = vec![make_output("src/lib.rs", vec![base_trait, child_trait])];

        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&outputs, &mut graph).expect("build_graph");

        let child_id = deterministic_id("src/lib.rs", "ChildTrait");
        let base_id = deterministic_id("src/lib.rs", "BaseTrait");

        // Check that ChildTrait has an Extends edge to BaseTrait.
        let neighbors = graph.neighbors(&child_id);
        let extends_edges: Vec<_> = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::Extends)
            .collect();

        assert_eq!(
            extends_edges.len(),
            1,
            "ChildTrait should have 1 Extends edge"
        );
        assert_eq!(
            extends_edges[0].0, base_id,
            "Extends edge should point to BaseTrait"
        );
        assert!((extends_edges[0].1.confidence - 0.85).abs() < f32::EPSILON);
        assert!(stats.edges_added >= 1);
    }

    #[test]
    fn test_extends_edge_skips_external_supertraits() {
        // When a supertrait is not in the graph, the edge should be skipped.
        let mut child_trait = make_symbol("MyTrait", SymbolKind::Trait, None);
        child_trait.relations = ["Clone", "Send"]
            .into_iter()
            .map(|target| StructuralRelation::Extends {
                target: target.to_string(),
            })
            .collect();

        let outputs = vec![make_output("src/lib.rs", vec![child_trait])];

        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&outputs, &mut graph).expect("build_graph");

        let child_id = deterministic_id("src/lib.rs", "MyTrait");
        let neighbors = graph.neighbors(&child_id);
        let extends_count = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::Extends)
            .count();

        // Clone and Send are not in the graph, so no Extends edges.
        assert_eq!(extends_count, 0);
        // EC-13 (WU-0001): the two external supertraits skip on the Extends path,
        // but are now ROUTED BY KIND. `Send` is an auto/marker trait → routed to
        // `edges_skipped_other` (intentional, not under-production). `Clone` is a
        // real external DOMAIN trait → stays in `edges_skipped_external_relation`
        // (honest under-production, the residual the build_graph `warn!` surfaces).
        // Total skipped is still 2 (1 marker + 1 domain).
        assert_eq!(stats.total_skipped(), 2);
        assert_eq!(
            stats.edges_skipped_external_relation, 1,
            "EC-13: only the real domain supertrait (Clone) trips the under-production bucket"
        );
        assert_eq!(
            stats.edges_skipped_other, 1,
            "EC-13: the marker supertrait (Send) is routed to the _other bucket"
        );
    }

    #[test]
    fn test_contains_edges_from_struct_to_fields() {
        // A struct with two fields should produce Contains edges.
        let my_struct = make_symbol("MyStruct", SymbolKind::Struct, None);

        let mut field_a = make_symbol("field_a", SymbolKind::Field, Some("MyStruct"));
        field_a.signature = "String".to_string();
        field_a.has_body = false;

        let mut field_b = make_symbol("field_b", SymbolKind::Field, Some("MyStruct"));
        field_b.signature = "i32".to_string();
        field_b.has_body = false;

        let outputs = vec![make_output("src/lib.rs", vec![my_struct, field_a, field_b])];

        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&outputs, &mut graph).expect("build_graph");

        // Struct should have Contains edges to both fields.
        let struct_id = deterministic_id("src/lib.rs", "MyStruct");
        let neighbors = graph.neighbors(&struct_id);
        let contains_edges: Vec<_> = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::Contains)
            .collect();
        assert_eq!(
            contains_edges.len(),
            2,
            "Expected 2 Contains edges from struct to fields, got {}",
            contains_edges.len()
        );

        // Verify the targets are the field nodes.
        let field_a_id = deterministic_id("src/lib.rs", "MyStruct::field_a");
        let field_b_id = deterministic_id("src/lib.rs", "MyStruct::field_b");
        let target_ids: Vec<Uuid> = contains_edges.iter().map(|(id, _)| *id).collect();
        assert!(
            target_ids.contains(&field_a_id),
            "Missing Contains edge to field_a"
        );
        assert!(
            target_ids.contains(&field_b_id),
            "Missing Contains edge to field_b"
        );

        // Verify node counts: 1 struct + 2 fields = 3 nodes.
        assert_eq!(stats.nodes_added, 3);
    }

    #[test]
    fn test_typeof_edges_from_field_to_resolved_type() {
        // A struct field whose type matches a graph node should get a TypeOf edge.
        let my_struct = make_symbol("MyStruct", SymbolKind::Struct, None);
        let config_struct = make_symbol("Config", SymbolKind::Struct, None);

        let mut field_config = make_symbol("config", SymbolKind::Field, Some("MyStruct"));
        field_config.signature = "Config".to_string();
        field_config.has_body = false;
        field_config.relations = vec![StructuralRelation::TypeOf {
            target: "Config".into(),
        }];

        // A field whose type is NOT in the graph (stdlib type).
        let mut field_name = make_symbol("name", SymbolKind::Field, Some("MyStruct"));
        field_name.signature = "String".to_string();
        field_name.has_body = false;
        field_name.relations = vec![StructuralRelation::TypeOf {
            target: "String".into(),
        }];

        let outputs = vec![make_output(
            "src/lib.rs",
            vec![my_struct, config_struct, field_config, field_name],
        )];

        let mut graph = KnowledgeGraph::new();
        let _stats = build_graph(&outputs, &mut graph).expect("build_graph");

        // field_config should have a TypeOf edge to Config.
        let field_config_id = deterministic_id("src/lib.rs", "MyStruct::config");
        let neighbors = graph.neighbors(&field_config_id);
        let typeof_edges: Vec<_> = neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::TypeOf)
            .collect();
        assert_eq!(
            typeof_edges.len(),
            1,
            "Expected 1 TypeOf edge from config field to Config struct"
        );

        let config_id = deterministic_id("src/lib.rs", "Config");
        assert_eq!(typeof_edges[0].0, config_id);

        // field_name should have NO TypeOf edge (String is filtered as primitive).
        let field_name_id = deterministic_id("src/lib.rs", "MyStruct::name");
        let name_neighbors = graph.neighbors(&field_name_id);
        let name_typeof_count = name_neighbors
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::TypeOf)
            .count();
        assert_eq!(
            name_typeof_count, 0,
            "String field should have no TypeOf edge"
        );
    }

    // -----------------------------------------------------------------------
    // EC-4a (WU-0001): edge_builder locality scoping for find_symbol_node /
    // find_trait_node / find_struct_for_impl. Resolution must prefer the
    // same-file target, never an arbitrary cross-file homonym.
    // -----------------------------------------------------------------------

    #[test]
    fn ec4a_hasimpl_struct_resolves_same_file_not_first_inserted() {
        // a.rs holds the CORRECT target: trait Tr + struct Config + impl Tr for Config.
        let oa = make_output(
            "a.rs",
            vec![
                make_symbol("Tr", SymbolKind::Trait, None),
                make_symbol("Config", SymbolKind::Struct, None),
                make_symbol("impl Tr for Config", SymbolKind::Impl, None),
            ],
        );
        // b.rs holds a DECOY struct Config inserted FIRST so it wins petgraph
        // insertion order + the name_index slot.
        let ob = make_output(
            "b.rs",
            vec![make_symbol("Config", SymbolKind::Struct, None)],
        );

        let mut graph = KnowledgeGraph::new();
        build_graph(&[ob, oa], &mut graph).unwrap();

        let want = deterministic_id("a.rs", "Config");
        let decoy = deterministic_id("b.rs", "Config");
        let tr_id = deterministic_id("a.rs", "Tr");

        let hasimpl: Vec<_> = graph
            .neighbors(&tr_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::HasImpl)
            .collect();
        assert_eq!(
            hasimpl.len(),
            1,
            "EC-4a: Tr must have exactly one HasImpl edge"
        );
        assert_eq!(
            hasimpl[0].0, want,
            "EC-4a: HasImpl must target same-file a.rs::Config, not the wrong-file \
             decoy b.rs::Config (decoy id {decoy})"
        );
    }

    #[test]
    fn ec4a_hasimpl_ambiguous_no_locality_skips_edge() {
        // a.rs: trait Tr + impl Tr for Config, but Config is NOT defined here
        // (no same-file Config, no use import).
        let oa = make_output(
            "a.rs",
            vec![
                make_symbol("Tr", SymbolKind::Trait, None),
                make_symbol("impl Tr for Config", SymbolKind::Impl, None),
            ],
        );
        // Two equally-distant cross-file Config candidates → no locality signal.
        let ob = make_output(
            "b.rs",
            vec![make_symbol("Config", SymbolKind::Struct, None)],
        );
        let oc = make_output(
            "c.rs",
            vec![make_symbol("Config", SymbolKind::Struct, None)],
        );

        let mut graph = KnowledgeGraph::new();
        build_graph(&[oa, ob, oc], &mut graph).unwrap();

        let tr_id = deterministic_id("a.rs", "Tr");
        let hasimpl_count = graph
            .neighbors(&tr_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::HasImpl)
            .count();
        assert_eq!(
            hasimpl_count, 0,
            "EC-4a: genuinely-ambiguous no-locality HasImpl must skip, not \
             mis-wire to an arbitrary file"
        );
    }

    #[test]
    fn ec4a_implements_trait_resolves_same_file() {
        // b.rs holds a DECOY trait Draw, inserted first.
        let ob = make_output("b.rs", vec![make_symbol("Draw", SymbolKind::Trait, None)]);
        // a.rs holds the CORRECT trait Draw + impl Draw for Widget + struct Widget.
        let oa = make_output(
            "a.rs",
            vec![
                make_symbol("Draw", SymbolKind::Trait, None),
                make_symbol("Widget", SymbolKind::Struct, None),
                make_symbol("impl Draw for Widget", SymbolKind::Impl, None),
            ],
        );

        let mut graph = KnowledgeGraph::new();
        build_graph(&[ob, oa], &mut graph).unwrap();

        let impl_id = deterministic_id("a.rs", "impl Draw for Widget");
        let want = deterministic_id("a.rs", "Draw");
        let decoy = deterministic_id("b.rs", "Draw");

        let implements: Vec<_> = graph
            .neighbors(&impl_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::Implements)
            .collect();
        assert_eq!(
            implements.len(),
            1,
            "EC-4a: exactly one Implements edge expected"
        );
        assert_eq!(
            implements[0].0, want,
            "EC-4a: Implements must resolve same-file trait a.rs::Draw, not \
             decoy b.rs::Draw (decoy id {decoy})"
        );
    }

    #[test]
    fn ec4a_extends_supertrait_resolves_same_file() {
        // b.rs holds a DECOY trait Base, inserted first.
        let ob = make_output("b.rs", vec![make_symbol("Base", SymbolKind::Trait, None)]);
        // a.rs holds the CORRECT trait Base + child trait Child : Base.
        let mut child = make_symbol("Child", SymbolKind::Trait, None);
        child.relations = vec![StructuralRelation::Extends {
            target: "Base".to_string(),
        }];
        let oa = make_output(
            "a.rs",
            vec![make_symbol("Base", SymbolKind::Trait, None), child],
        );

        let mut graph = KnowledgeGraph::new();
        build_graph(&[ob, oa], &mut graph).unwrap();

        let child_id = deterministic_id("a.rs", "Child");
        let want = deterministic_id("a.rs", "Base");
        let decoy = deterministic_id("b.rs", "Base");

        let extends: Vec<_> = graph
            .neighbors(&child_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::Extends)
            .collect();
        assert_eq!(extends.len(), 1, "EC-4a: exactly one Extends edge expected");
        assert_eq!(
            extends[0].0, want,
            "EC-4a: Extends must resolve same-file supertrait a.rs::Base, not \
             decoy b.rs::Base (decoy id {decoy})"
        );
    }

    #[test]
    fn ec4a_fieldof_resolves_same_file_not_first_inserted() {
        // b.rs holds a DECOY struct Inner, inserted first.
        let ob = make_output("b.rs", vec![make_symbol("Inner", SymbolKind::Struct, None)]);
        // a.rs holds the CORRECT struct Inner + struct Outer with a field of type Inner.
        let mut outer = make_symbol("Outer", SymbolKind::Struct, None);
        outer.relations = vec![StructuralRelation::FieldOf {
            target: "Inner".to_string(),
        }];
        let oa = make_output(
            "a.rs",
            vec![make_symbol("Inner", SymbolKind::Struct, None), outer],
        );

        let mut graph = KnowledgeGraph::new();
        build_graph(&[ob, oa], &mut graph).unwrap();

        let outer_id = deterministic_id("a.rs", "Outer");
        let want = deterministic_id("a.rs", "Inner");
        let decoy = deterministic_id("b.rs", "Inner");

        let fieldof: Vec<_> = graph
            .neighbors(&outer_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .collect();
        assert_eq!(fieldof.len(), 1, "EC-4a: exactly one FieldOf edge expected");
        assert_eq!(
            fieldof[0].0, want,
            "EC-4a: FieldOf must resolve same-file type a.rs::Inner, not \
             decoy b.rs::Inner (decoy id {decoy})"
        );
    }

    #[test]
    fn ec4a_find_struct_for_impl_fastpath_gated_on_same_file() {
        // a.rs holds the CORRECT struct Store + inherent impl Store.
        let oa = make_output(
            "a.rs",
            vec![
                make_symbol("Store", SymbolKind::Struct, None),
                make_symbol("impl Store", SymbolKind::Impl, None),
            ],
        );
        // b.rs holds a DECOY struct Store. Post-Wave-1 the name_index is
        // multi-valued; `node_by_name` returns None on a >1 collision, so the
        // fast-path only fires for a globally-unique name — a homonym (here
        // "Store" in both a.rs and b.rs) falls through to the same-file scan,
        // which still attaches the edge to a.rs::Store. (The companion test
        // `ec4a_find_struct_for_impl_fastpath_unique_name` covers the actual
        // node_by_name Some-arm with a globally-unique name.)
        let ob = make_output("b.rs", vec![make_symbol("Store", SymbolKind::Struct, None)]);

        let mut graph = KnowledgeGraph::new();
        build_graph(&[oa, ob], &mut graph).unwrap();

        let a_struct = deterministic_id("a.rs", "Store");
        let b_struct = deterministic_id("b.rs", "Store");
        let impl_id = deterministic_id("a.rs", "impl Store");

        // The Phase-3 Contains struct->impl edge must attach to a.rs::Store.
        let a_has_impl = graph
            .neighbors(&a_struct)
            .into_iter()
            .any(|(t, e)| t == impl_id && e.kind == EdgeKind::Contains);
        assert!(
            a_has_impl,
            "EC-4a: same-file a.rs::Store must Contains a.rs::impl Store \
             (find_struct_for_impl fast-path must be same-file gated)"
        );
        // And the wrong-file decoy must NOT own the impl Contains edge.
        let b_has_impl = graph
            .neighbors(&b_struct)
            .into_iter()
            .any(|(t, e)| t == impl_id && e.kind == EdgeKind::Contains);
        assert!(
            !b_has_impl,
            "EC-4a: wrong-file b.rs::Store must NOT Contains a.rs::impl Store"
        );
    }

    // -----------------------------------------------------------------------
    // ADR-0027 / WU-0002 EP2 — resolve_for_edge falsifiers.
    //
    // EP2 is a THIN WRAP over candidates_for (use-exclusion + KindFilter) +
    // resolve_with_locality (verbatim). These tests build a graph with explicit
    // `kind` strings via `add_node` and assert resolve_for_edge's SymbolId
    // round-trips to the intended node.
    // -----------------------------------------------------------------------

    /// Build a `GraphNode` with an explicit kind string (EP2 tests need precise
    /// `kind` control — "use", "trait", "struct", "function" — that `make_symbol`
    /// + `build_graph` would not give directly).
    fn make_kind_node(name: &str, kind: &str, file: &str) -> GraphNode {
        GraphNode {
            // Distinct id per node so same-(file,name) homonyms of different
            // KIND coexist (a real graph dedups same-(file,qname) to one node —
            // OQ-DUPNODE territory — but these EP2 tests probe the kind filter,
            // which needs the candidates to actually exist as separate nodes).
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: kind.into(),
            file_path: file.into(),
            content_hash: format!("hash_{name}_{file}"),
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

    /// EP2: `KindFilter::Any` applies ONLY the use-exclusion (no kind constraint)
    /// — a non-type node with the exact query name IS a candidate
    /// (re-expresses `find_symbol_node`).
    #[test]
    fn ep2_kindfilter_any_includes_non_type() {
        let mut graph = KnowledgeGraph::new();
        let helper = make_kind_node("helper", "function", "src/a.rs");
        let want = helper.memory_id;
        graph.add_node(helper).unwrap();

        let got = resolve_for_edge(&graph, "helper", "src/a.rs", KindFilter::Any)
            .expect("Any must resolve a function node");
        assert_eq!(got.uuid(), want, "Any must include the non-type function");
    }

    /// EP2: `KindFilter::One("trait")` rejects a same-name struct decoy and
    /// resolves only the trait (re-expresses `find_trait_node`'s hard filter).
    /// Control: `One("struct")` on the same graph resolves the struct — proving
    /// the filter selects by kind, not hardcodes "trait".
    #[test]
    fn ep2_kindfilter_one_trait_rejects_struct_decoy() {
        let mut graph = KnowledgeGraph::new();
        let struct_node = make_kind_node("Foo", "struct", "src/a.rs");
        let trait_node = make_kind_node("Foo", "trait", "src/a.rs");
        let struct_id = struct_node.memory_id;
        let trait_id = trait_node.memory_id;
        graph.add_node(struct_node).unwrap();
        graph.add_node(trait_node).unwrap();

        let got_trait = resolve_for_edge(&graph, "Foo", "src/a.rs", KindFilter::One("trait"))
            .expect("One(trait) must resolve the trait");
        assert_eq!(
            got_trait.uuid(),
            trait_id,
            "One(trait) must resolve the trait, not the struct decoy"
        );

        let got_struct = resolve_for_edge(&graph, "Foo", "src/a.rs", KindFilter::One("struct"))
            .expect("One(struct) must resolve the struct");
        assert_eq!(
            got_struct.uuid(),
            struct_id,
            "One(struct) must resolve the struct — the filter selects, not hardcodes"
        );
    }

    /// EP2 LOAD-BEARING: a `kind == "use"` node with the exact query name is
    /// NEVER returned under ANY `KindFilter` shape (the unconditional
    /// use-exclusion in `candidates_for` survives the EP2 refactor). Also
    /// exercises `KindFilter::AnyOf`.
    #[test]
    fn ep2_use_exclusion_never_returned() {
        // Graph 1: the ONLY node is a `use` — must resolve to None under every shape.
        let mut g1 = KnowledgeGraph::new();
        g1.add_node(make_kind_node("Target", "use", "src/a.rs"))
            .unwrap();
        assert!(
            resolve_for_edge(&g1, "Target", "src/a.rs", KindFilter::Any).is_none(),
            "Any: a lone use node must be invisible"
        );
        assert!(
            resolve_for_edge(&g1, "Target", "src/a.rs", KindFilter::One("use")).is_none(),
            "One(use): even an explicit use filter cannot return a use node (exclusion is first)"
        );
        assert!(
            resolve_for_edge(
                &g1,
                "Target",
                "src/a.rs",
                KindFilter::AnyOf(&["use", "struct"])
            )
            .is_none(),
            "AnyOf: a use node is excluded before the kind membership test"
        );

        // Graph 2: a real struct homonym alongside the use node — the struct
        // resolves, the use node is invisible.
        let mut g2 = KnowledgeGraph::new();
        g2.add_node(make_kind_node("Target", "use", "src/a.rs"))
            .unwrap();
        let real = make_kind_node("Target", "struct", "src/b.rs");
        let real_id = real.memory_id;
        g2.add_node(real).unwrap();
        let got = resolve_for_edge(&g2, "Target", "src/a.rs", KindFilter::Any)
            .expect("the struct homonym resolves");
        assert_eq!(
            got.uuid(),
            real_id,
            "Any must resolve the struct in src/b.rs, never the use node"
        );
    }

    /// EP2: `resolve_for_edge` calls `resolve_with_locality` VERBATIM — a
    /// same-file candidate wins over a cross-file homonym (zero-behavior-change
    /// of `find_symbol_node`). Mirrors the EC-4a same-file-not-first-inserted
    /// guarantee at the `resolve_for_edge` surface.
    #[test]
    fn ep2_resolve_with_locality_verbatim_same_file_wins() {
        let mut graph = KnowledgeGraph::new();
        // other.rs added FIRST (first-inserted decoy), here.rs SECOND.
        graph
            .add_node(make_kind_node("Widget", "struct", "crates/x/src/other.rs"))
            .unwrap();
        let here = make_kind_node("Widget", "struct", "crates/x/src/here.rs");
        let here_id = here.memory_id;
        graph.add_node(here).unwrap();

        let got = resolve_for_edge(&graph, "Widget", "crates/x/src/here.rs", KindFilter::Any)
            .expect("same-file Widget resolves");
        assert_eq!(
            got.uuid(),
            here_id,
            "resolve_for_edge must pick the same-file here.rs node, not first-inserted other.rs"
        );
    }

    // -----------------------------------------------------------------------
    // ADR-0027 / WU-0002 ORDER 4 — mutant test-strength pins.
    //
    // find_struct_for_impl (7 survivors) + resolve_with_locality (6 survivors)
    // per findings-register exit-crit #2. `find_struct_for_impl` shares the
    // bounded name/kind candidate machinery but NOT EP2's tie-break: it keeps
    // its own first-global no-locality policy, pinned independently here.
    // -----------------------------------------------------------------------

    /// MUTANT (find_struct_for_impl, :494 is_type / :507 type_kinds.contains):
    /// a non-type node with the same SHORT name must NOT be picked — the
    /// Contains struct→impl edge targets the struct, never a function decoy.
    #[test]
    fn mutant_find_struct_for_impl_kind_gate() {
        // The decoy function is `helpers::Store` (a DIFFERENT qualified name, so a
        // distinct node) — it suffix-matches "Store" but is kind=function, so the
        // type_kinds filter must skip it. The real struct is a.rs::Store.
        let oa = make_output(
            "a.rs",
            vec![
                make_symbol("Store", SymbolKind::Function, Some("helpers")),
                make_symbol("Store", SymbolKind::Struct, None),
                make_symbol("impl Store", SymbolKind::Impl, None),
            ],
        );
        let mut graph = KnowledgeGraph::new();
        build_graph(&[oa], &mut graph).unwrap();

        let struct_id = deterministic_id("a.rs", "Store");
        let decoy_fn_id = deterministic_id("a.rs", "helpers::Store");
        let impl_id = deterministic_id("a.rs", "impl Store");

        // The struct, not the function decoy, must own the Contains edge.
        let struct_has_impl = graph
            .neighbors(&struct_id)
            .into_iter()
            .any(|(t, e)| t == impl_id && e.kind == EdgeKind::Contains);
        assert!(
            struct_has_impl,
            "kind-gate: struct a.rs::Store must Contains the impl"
        );
        let decoy_has_impl = graph
            .neighbors(&decoy_fn_id)
            .into_iter()
            .any(|(t, e)| t == impl_id && e.kind == EdgeKind::Contains);
        assert!(
            !decoy_has_impl,
            "kind-gate: the function decoy must NOT own the impl Contains edge"
        );
    }

    /// MUTANT (find_struct_for_impl fast-path, :494-497 node_by_name Some-arm):
    /// COMPANION to the homonym test. Only a GLOBALLY-UNIQUE name reaches
    /// node_by_name's `[id] => Some` arm post-Wave-1, so the fast-path
    /// kind+same-file gate is ONLY under test with a unique name.
    #[test]
    fn ec4a_find_struct_for_impl_fastpath_unique_name() {
        // Globally-unique struct name → node_by_name returns Some → the fast-path
        // is_type && same_file gate at :494-496 fires.
        let oa = make_output(
            "a.rs",
            vec![
                make_symbol("UniqueStore", SymbolKind::Struct, None),
                make_symbol("impl UniqueStore", SymbolKind::Impl, None),
            ],
        );
        let mut graph = KnowledgeGraph::new();
        build_graph(&[oa], &mut graph).unwrap();

        let struct_id = deterministic_id("a.rs", "UniqueStore");
        let impl_id = deterministic_id("a.rs", "impl UniqueStore");
        let has_contains = graph
            .neighbors(&struct_id)
            .into_iter()
            .any(|(t, e)| t == impl_id && e.kind == EdgeKind::Contains);
        assert!(
            has_contains,
            "fast-path: globally-unique a.rs::UniqueStore must Contains its impl \
             (node_by_name Some-arm + is_type + same-file gate)"
        );
    }

    /// MUTANT (find_struct_for_impl, :511 ends_with suffix match): a qualified
    /// struct name resolves via the `::struct_name` suffix branch — driven from a
    /// different file so the suffix path is the only resolution.
    #[test]
    fn mutant_find_struct_for_impl_suffix_match() {
        // Struct is qualified "mod::Widget" in a.rs. The impl "impl Widget" lives
        // in b.rs (different file), so no same-file struct exists — resolution
        // must use the ends_with("::Widget") suffix branch + .or(any_file).
        let oa = make_output(
            "a.rs",
            vec![make_symbol("Widget", SymbolKind::Struct, Some("mod"))],
        );
        let ob = make_output(
            "b.rs",
            vec![make_symbol("impl Widget", SymbolKind::Impl, None)],
        );
        let mut graph = KnowledgeGraph::new();
        build_graph(&[oa, ob], &mut graph).unwrap();

        let struct_id = deterministic_id("a.rs", "mod::Widget");
        let impl_id = deterministic_id("b.rs", "impl Widget");
        let has_contains = graph
            .neighbors(&struct_id)
            .into_iter()
            .any(|(t, e)| t == impl_id && e.kind == EdgeKind::Contains);
        assert!(
            has_contains,
            "suffix: qualified mod::Widget must Contains the cross-file impl via \
             the ends_with(::Widget) branch"
        );
    }

    /// MUTANT (find_struct_for_impl, :522 `.or(any_file)`): when NO same-file
    /// candidate exists, the cross-file struct still gets the Contains edge — the
    /// any_file fallback fires (this is find_struct_for_impl's no-locality
    /// divergence from resolve_with_locality's skip-on-tie, OD-2).
    #[test]
    fn mutant_find_struct_for_impl_or_any_file() {
        // The struct "Gadget" lives ONLY in a.rs; the impl in b.rs. No same-file
        // candidate → same_file is None → `.or(any_file)` must supply a.rs::Gadget.
        let oa = make_output(
            "a.rs",
            vec![make_symbol("Gadget", SymbolKind::Struct, None)],
        );
        let ob = make_output(
            "b.rs",
            vec![make_symbol("impl Gadget", SymbolKind::Impl, None)],
        );
        let mut graph = KnowledgeGraph::new();
        build_graph(&[oa, ob], &mut graph).unwrap();

        let struct_id = deterministic_id("a.rs", "Gadget");
        let impl_id = deterministic_id("b.rs", "impl Gadget");
        let has_contains = graph
            .neighbors(&struct_id)
            .into_iter()
            .any(|(t, e)| t == impl_id && e.kind == EdgeKind::Contains);
        assert!(
            has_contains,
            "or-any_file: cross-file-only a.rs::Gadget must Contains b.rs::impl \
             Gadget (the .or(any_file) fallback)"
        );
    }

    /// MUTANT (resolve_with_locality, :694-697 same_file.len()>1 → shortest_name):
    /// multiple same-file matches resolve via the SHORTEST symbol_name
    /// deterministically. Driven via find_symbol_node (FieldOf).
    #[test]
    fn mutant_resolve_with_locality_same_file_gt1_shortest() {
        // Engine has a field of type "Store". In the SAME file: a short exact
        // "Store" and a longer suffix "deep::Store" — both same-file candidates of
        // DIFFERENT length. The exact tier wins first, but to force the
        // same_file>1 branch we make BOTH suffix matches (no exact): use
        // "mod::Store" (short) and "deeper::mod::Store" (long), same file.
        let mut engine = make_symbol("Engine", SymbolKind::Struct, None);
        engine.relations = vec![StructuralRelation::FieldOf {
            target: "Store".to_string(),
        }];
        let short = make_symbol("Store", SymbolKind::Struct, Some("mod"));
        let long = make_symbol("Store", SymbolKind::Struct, Some("deeper::mod"));
        let oa = make_output("a.rs", vec![engine, short, long]);
        let mut graph = KnowledgeGraph::new();
        build_graph(&[oa], &mut graph).unwrap();

        let engine_id = deterministic_id("a.rs", "Engine");
        let short_id = deterministic_id("a.rs", "mod::Store");
        let fieldof: Vec<_> = graph
            .neighbors(&engine_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .collect();
        assert_eq!(fieldof.len(), 1, "exactly one FieldOf edge expected");
        assert_eq!(
            fieldof[0].0, short_id,
            "same_file>1: shortest symbol_name (mod::Store) must win over deeper::mod::Store"
        );
    }

    /// MUTANT (resolve_with_locality, :700-710 same-crate tier): with no same-file
    /// match, a same-crate candidate wins over a different-crate one.
    #[test]
    fn mutant_resolve_with_locality_same_crate_tier() {
        // Engine in crates/x/src/here.rs has a field "Thing". Candidate A is in
        // crates/x/src/other.rs (same crate x); candidate B in crates/y/src/z.rs
        // (crate y). No same-file Thing → same-crate tier must pick A.
        let mut engine = make_symbol("Engine", SymbolKind::Struct, None);
        engine.relations = vec![StructuralRelation::FieldOf {
            target: "Thing".to_string(),
        }];
        let here = make_output("crates/x/src/here.rs", vec![engine]);
        let other = make_output(
            "crates/x/src/other.rs",
            vec![make_symbol("Thing", SymbolKind::Struct, None)],
        );
        let zfar = make_output(
            "crates/y/src/z.rs",
            vec![make_symbol("Thing", SymbolKind::Struct, None)],
        );
        let mut graph = KnowledgeGraph::new();
        build_graph(&[here, other, zfar], &mut graph).unwrap();

        let engine_id = deterministic_id("crates/x/src/here.rs", "Engine");
        let want = deterministic_id("crates/x/src/other.rs", "Thing");
        let fieldof: Vec<_> = graph
            .neighbors(&engine_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .collect();
        assert_eq!(fieldof.len(), 1, "exactly one FieldOf edge expected");
        assert_eq!(
            fieldof[0].0, want,
            "same-crate tier: crate-x Thing must win over crate-y Thing"
        );
    }

    /// MUTANT (resolve_with_locality, :720-723 exact-before-suffix): pick_tier on
    /// the exact pool must run before the suffix pool.
    #[test]
    fn mutant_resolve_with_locality_exact_before_suffix() {
        // Engine field "Config": an EXACT "Config" and a SUFFIX "app::Config",
        // both same file. Exact must win (mirrors test_find_symbol_node_prefers_
        // exact_match at the resolve_with_locality tier).
        let mut engine = make_symbol("Engine", SymbolKind::Struct, None);
        engine.relations = vec![StructuralRelation::FieldOf {
            target: "Config".to_string(),
        }];
        let exact = make_symbol("Config", SymbolKind::Struct, None);
        let suffix = make_symbol("Config", SymbolKind::Struct, Some("app"));
        let oa = make_output("a.rs", vec![engine, exact, suffix]);
        let mut graph = KnowledgeGraph::new();
        build_graph(&[oa], &mut graph).unwrap();

        let engine_id = deterministic_id("a.rs", "Engine");
        let exact_id = deterministic_id("a.rs", "Config");
        let fieldof: Vec<_> = graph
            .neighbors(&engine_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .collect();
        assert_eq!(fieldof.len(), 1, "exactly one FieldOf edge expected");
        assert_eq!(
            fieldof[0].0, exact_id,
            "exact tier must be tried before suffix tier"
        );
    }

    /// MUTANT (resolve_with_locality, :733/:753-772 shortest_name_unique tie→None):
    /// a no-locality length-tie among DISTINCT nodes resolves to None (build-time
    /// skip), never an arbitrary pick. Mirrors
    /// ec4a_hasimpl_ambiguous_no_locality_skips_edge but for the equal-length tie.
    #[test]
    fn mutant_resolve_with_locality_shortest_name_unique_tie_none() {
        // Engine (no shared crate prefix — bare file) has field "Bar". Two
        // EQUAL-LENGTH distinct candidates "Bar" in unrelated bare files → no
        // same-file, no same-crate, equal length → genuine tie → None (skip).
        let mut engine = make_symbol("Engine", SymbolKind::Struct, None);
        engine.relations = vec![StructuralRelation::FieldOf {
            target: "Bar".to_string(),
        }];
        let host = make_output("host.rs", vec![engine]);
        let oa = make_output("aaa.rs", vec![make_symbol("Bar", SymbolKind::Struct, None)]);
        let ob = make_output("bbb.rs", vec![make_symbol("Bar", SymbolKind::Struct, None)]);
        let mut graph = KnowledgeGraph::new();
        build_graph(&[host, oa, ob], &mut graph).unwrap();

        let engine_id = deterministic_id("host.rs", "Engine");
        let fieldof_count = graph
            .neighbors(&engine_id)
            .into_iter()
            .filter(|(_, e)| e.kind == EdgeKind::FieldOf)
            .count();
        assert_eq!(
            fieldof_count, 0,
            "equal-length distinct no-locality tie must skip (None), not mis-wire"
        );
    }

    // ------------------------------------------------------------------
    // WU-0003 / CL-REACH RC3+RC5 falsifiers — symbol_to_node un-drop + the
    // Unclassified constructor. Driven end-to-end through the real producer
    // (`extract_rust_symbols` -> `build_graph`), never a hand-fabricated node.
    // ------------------------------------------------------------------

    /// F4 (POST-SCHEMA): the AST-derived `is_test_only` bit is PERSISTED onto
    /// the GraphNode (the EC-7 write-only drop the contract fixes). A helper
    /// inside `#[cfg(test)] mod tests` produces `is_test_only == Some(true)`.
    #[test]
    fn symbol_to_node_persists_is_test_only_from_ast() {
        use crate::extractor::extract_rust_symbols;
        let output = extract_rust_symbols(
            "#[cfg(test)] mod tests { fn helper() -> i32 { 1 } }",
            "crates/app/src/lib.rs",
        )
        .unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let helper_id = deterministic_id("crates/app/src/lib.rs", "tests::helper");
        let node = graph.node(&helper_id).expect("helper node materialized");
        assert_eq!(
            node.is_test_only,
            Some(true),
            "AST-derived is_test_only must be PERSISTED on the GraphNode, not dropped (EC-7)"
        );
    }

    /// F4b (POST-SCHEMA): a `#[test]` root is persisted with `is_test_root`.
    #[test]
    fn symbol_to_node_persists_is_test_root_from_ast() {
        use crate::extractor::extract_rust_symbols;
        let output =
            extract_rust_symbols("#[test] fn my_test() {}", "crates/app/src/widget.rs").unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let id = deterministic_id("crates/app/src/widget.rs", "my_test");
        let node = graph.node(&id).expect("test fn node materialized");
        assert!(
            node.is_test_root,
            "the #[test]-root bit must be PERSISTED on the GraphNode"
        );
    }

    /// F5 (POST-SCHEMA): the file-level fallback. A symbol in a file under
    /// `tests/` that the AST did NOT flag as test-only still gets
    /// `is_test_only == Some(true)` via `extractor::file_is_test` — provenance
    /// preserved (`Some`), a file-level signal never silently lost.
    #[test]
    fn symbol_to_node_file_fallback_for_test_path() {
        use crate::extractor::extract_rust_symbols;
        // A plain fn (AST is_test_only == false) but the FILE is under tests/.
        let output =
            extract_rust_symbols("fn integration_helper() {}", "crates/app/tests/it.rs").unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        let id = deterministic_id("crates/app/tests/it.rs", "integration_helper");
        let node = graph.node(&id).expect("node materialized");
        assert_eq!(
            node.is_test_only,
            Some(true),
            "a symbol in a tests/ file gets is_test_only via the file_is_test fallback"
        );
    }

    /// Build a 2-crate workspace `crate_a` -> `crate_b` (path dependency) on
    /// disk and return its root tempdir. `crate_a`'s lib calls into `crate_b`.
    /// Used by the `build_dependency_edges` coverage tests below.
    fn write_two_crate_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("create temp workspace");
        let root = dir.path();
        // Root workspace manifest with an explicit (non-glob) member list.
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crate_a\", \"crate_b\"]\nresolver = \"2\"\n",
        )
        .expect("write workspace Cargo.toml");

        // crate_a: a lib that depends on crate_b via a path dependency.
        let a_src = root.join("crate_a/src");
        std::fs::create_dir_all(&a_src).expect("mkdir crate_a/src");
        std::fs::write(
            root.join("crate_a/Cargo.toml"),
            "[package]\nname = \"crate_a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncrate_b = { path = \"../crate_b\" }\n",
        )
        .expect("write crate_a/Cargo.toml");
        std::fs::write(
            a_src.join("lib.rs"),
            "pub fn a_entry() { crate_b::b_api(); }\n",
        )
        .expect("write crate_a/src/lib.rs");

        // crate_b: a leaf lib with a public API.
        let b_src = root.join("crate_b/src");
        std::fs::create_dir_all(&b_src).expect("mkdir crate_b/src");
        std::fs::write(
            root.join("crate_b/Cargo.toml"),
            "[package]\nname = \"crate_b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write crate_b/Cargo.toml");
        std::fs::write(
            b_src.join("lib.rs"),
            "pub fn b_api() { b_inner(); }\nfn b_inner() {}\n",
        )
        .expect("write crate_b/src/lib.rs");

        dir
    }

    /// COVERAGE (CL-EDGE): `build_dependency_edges` had ZERO direct unit tests.
    /// This is the firsthand probe that settles whether it emits inter-crate
    /// `DependsOn` edges for a real workspace shape: a `[workspace] members = [...]`
    /// list, inline `path =` deps, and relative node `file_path`s that match
    /// `find_crate_root_node`'s relative lookup.
    ///
    /// Asserts at least one `DependsOn` edge (crate_a's root -> crate_b's root)
    /// is created.
    ///
    /// CL-EDGE BUG (firsthand, 2026-06-23) — FIXED, WU-0001 reopen. This test was
    /// `#[ignore]`d because it FAILED (`edges_added == 0`): `build_dependency_edges`
    /// parsed the workspace `Cargo.toml` via `content.parse::<toml::Value>()` (the
    /// `FromStr` path, edge_builder.rs:933, also :984/:1025). Under
    /// `toml = "1.0.6+spec-1.1.0"` that `FromStr` impl ERRORED on a real Cargo
    /// manifest — verified on BOTH this fixture (`TOML parse error at line 1,
    /// column 12`) and a large wildcard Cargo workspace (`members = ["crates/*"]`,
    /// `TOML parse error at line 1, column 1`), while `toml::from_str(&content)`
    /// parsed both fine. So the `match … { Err(_) => return Ok(0) }` at line 933
    /// fired FIRST (before the members check), and `build_dependency_edges`
    /// returned `Ok(0)` for EVERY workspace: NO inter-crate `DependsOn` edge was
    /// ever built in production. THE FIX (now landed) is `content.parse()` ->
    /// `toml::from_str(&content)` at edge_builder.rs:933/984/1025 (matching the
    /// correct `entry_points.rs:360` idiom); with `#[ignore]` removed this test is
    /// the GREEN end-to-end falsifier through the real producer.
    #[test]
    fn build_dependency_edges_emits_cross_crate_dependson() {
        let dir = write_two_crate_workspace();
        let root = dir.path();

        // full_scan extracts every crate's symbols AND calls
        // build_dependency_edges internally; call the latter again explicitly so
        // we can read its return count as the firsthand evidence.
        let mut graph = KnowledgeGraph::new();
        let _ = full_scan(root, &mut graph).expect("full_scan over the 2-crate workspace");

        // Firsthand node evidence (kinds + relative file_paths the resolver keys on).
        for n in graph.all_nodes() {
            eprintln!(
                "EDGE-PROBE node kind={} file={} name={}",
                n.kind, n.file_path, n.symbol_name
            );
        }

        let edges_added = build_dependency_edges(&mut graph, root).expect("build_dependency_edges");
        eprintln!("EDGE-PROBE build_dependency_edges edges_added={edges_added}");

        // Enumerate the actual DependsOn edges present in the graph.
        let mut dependson_pairs = Vec::new();
        for n in graph.all_nodes() {
            for (t, e) in graph.neighbors(&n.memory_id) {
                if e.kind == EdgeKind::DependsOn {
                    let tn = graph
                        .node(&t)
                        .map(|x| format!("{} ({})", x.symbol_name, x.file_path))
                        .unwrap_or_default();
                    eprintln!(
                        "EDGE-PROBE DependsOn {} ({}) -> {}",
                        n.symbol_name, n.file_path, tn
                    );
                    dependson_pairs.push((n.file_path.clone(), tn));
                }
            }
        }

        assert!(
            !dependson_pairs.is_empty(),
            "build_dependency_edges must emit >= 1 cross-crate DependsOn edge for a \
             workspace with a path dependency (crate_a -> crate_b); got 0. \
             dependson_pairs={dependson_pairs:?}"
        );
        // The edge must originate in crate_a's root file and target crate_b's root file.
        assert!(
            dependson_pairs
                .iter()
                .any(|(from, to)| from.contains("crate_a") && to.contains("crate_b")),
            "the DependsOn edge must go crate_a -> crate_b; got {dependson_pairs:?}"
        );
    }

    /// F6 (POST-SCHEMA, the anti-false-clean ctor invariant): a freshly-built
    /// graph (before any classifier run) has every node `Unclassified` — the
    /// un-dropped ctor sets `Unclassified`, NEVER `None` and NEVER `Dead`.
    #[test]
    fn symbol_to_node_constructs_unclassified_not_dead() {
        use crate::extractor::extract_rust_symbols;
        use crate::reachability::ReachabilityClass;
        let output = extract_rust_symbols("fn a() {} fn b() {}", "crates/app/src/lib.rs").unwrap();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).unwrap();

        for node in graph.all_nodes() {
            assert_eq!(
                node.reachability_class,
                ReachabilityClass::Unclassified,
                "a fresh graph node must be Unclassified (never None/Dead) before classification"
            );
            assert_ne!(
                node.reachability_class,
                ReachabilityClass::Dead,
                "the constructor must NEVER produce Dead (the false-clean)"
            );
        }
    }
}
