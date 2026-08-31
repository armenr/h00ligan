//! Raw architecture Overview extraction for the code-intelligence graph.
//!
//! The public authority-qualified Overview contract lives in
//! `code_intel_overview`; the scoped Audit contract lives independently in
//! `code_intel_audit`. This module keeps only their low-level architecture
//! projection helpers.
//!
//! All functions are **synchronous** — callers in async contexts should use
//! `tokio::task::spawn_blocking` if needed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use uuid::Uuid;

use crate::code_intel_domain::{
    DocumentMembershipKind, ProjectInventory, ProjectInventoryCoverage, ProjectInventoryIssue,
    ProjectUnit, ProjectUnitId, ProjectUnitKind, ProjectUnitRelationship,
};
use crate::graph::{EdgeKind, GraphNode, KnowledgeGraph};
use crate::reachability::ReachabilityClass;
use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

// ============================================================================
// Types
// ============================================================================

/// Per-project-unit health derived from reachability classification.
#[derive(Debug, Clone, Default)]
pub struct ProjectUnitHealth {
    pub wired: usize,
    pub dead: usize,
    pub test_only: usize,
}

/// A type (struct/enum/trait) ranked by fan-in within a crate.
#[derive(Debug, Clone)]
pub struct KeyType {
    pub symbol_name: String,
    pub kind: String,
    pub fan_in: usize,
}

/// One persisted project unit with graph-derived health and key types.
#[derive(Debug, Clone)]
pub struct ProjectUnitOverview {
    pub unit: ProjectUnit,
    pub label: String,
    pub owned_node_count: usize,
    pub callable_node_count: usize,
    pub health: ProjectUnitHealth,
    pub key_types: Vec<KeyType>,
}

/// A dependency edge between source-owning project units.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ProjectUnitDependency {
    pub from_project_unit_id: ProjectUnitId,
    pub to_project_unit_id: ProjectUnitId,
}

/// Complete overview data for the workspace.
#[derive(Debug)]
pub struct OverviewData {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub project_units: Vec<ProjectUnitOverview>,
    pub project_unit_relationships: Vec<ProjectUnitRelationship>,
    pub project_unit_dependencies: Vec<ProjectUnitDependency>,
    pub project_inventory_coverage: ProjectInventoryCoverage,
    pub project_inventory_issues: Vec<ProjectInventoryIssue>,
    /// Graph nodes without a source-owner membership in this generation.
    pub unassigned_node_count: usize,
    pub dead_code_count: usize,
    /// Count of nodes whose reachability has NOT been classified (WU-0003 /
    /// CL-REACH-08). A non-zero value means the graph was not (re)classified —
    /// `dead_code_count` is then NOT trustworthy as a clean signal, and the
    /// caller MUST surface an `UNCLASSIFIED — run index first` banner rather than
    /// reporting a false-clean `dead=0`. `0` on a fully-classified graph.
    pub unclassified_count: usize,
}

impl OverviewData {
    /// Whether the UNCLASSIFIED banner must be shown (any node is unclassified).
    ///
    /// WU-0003 / CL-REACH-08: when this is `true`, a `dead=0` report is a
    /// false-clean — the classifier never ran. Callers print
    /// `UNCLASSIFIED — run index first`.
    pub const fn needs_unclassified_banner(&self) -> bool {
        self.unclassified_count > 0
    }
}

/// The healthy/dead/test/unclassified bucket a [`ReachabilityClass`] maps to for
/// overview accounting (WU-0003 / CL-REACH-08).
///
/// The ONE typed routing point for the four `reachability_class` reads in this
/// module, so an unclassified node can never silently fall into the `dead=0`
/// no-op arm (the `matches!`-based reads were exactly that RC5-caveat
/// false-clean re-introduction risk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverviewBucket {
    /// Wired / PublicApi / Structural — counts as alive.
    Alive,
    /// Dead / Orphan — counts toward `dead_code_count`.
    Dead,
    /// TestOnly.
    Test,
    /// Unclassified — never alive, never dead; drives the banner.
    Unclassified,
    /// WU-0015 / ADR-0036 v6 — the directed-call-reachability review tier.
    /// Neutral for overview accounting: NOT counted toward `dead_code_count`
    /// (it is not a delete authority) and NOT toward the `unclassified` banner
    /// (classification DID run). Surfaced instead through the `dead`/`assess`
    /// SUSPECTED report tier.
    Suspected,
    /// ADR-0045 — OUT of the production-reachability census (D1 detached/nested
    /// crate + D2 fixture corpus). Neutral for overview accounting: NOT dead (no
    /// delete authority), NOT alive-counted, NOT unclassified (classification ran).
    Excluded,
}

/// Route a [`ReachabilityClass`] to its [`OverviewBucket`] — the single typed
/// classifier read shared across every Overview health projection.
const fn overview_bucket(class: ReachabilityClass) -> OverviewBucket {
    match class {
        ReachabilityClass::Wired | ReachabilityClass::PublicApi | ReachabilityClass::Structural => {
            OverviewBucket::Alive
        }
        ReachabilityClass::Dead | ReachabilityClass::Orphan => OverviewBucket::Dead,
        ReachabilityClass::TestOnly => OverviewBucket::Test,
        ReachabilityClass::Unclassified => OverviewBucket::Unclassified,
        ReachabilityClass::Suspected => OverviewBucket::Suspected,
        ReachabilityClass::Excluded => OverviewBucket::Excluded,
    }
}

// ============================================================================
// Project-unit projection (generation-local)
// ============================================================================

fn source_owners(inventory: &ProjectInventory) -> BTreeMap<&str, &ProjectUnitId> {
    inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
        .map(|membership| {
            (
                membership.document_path.as_str(),
                &membership.project_unit_id,
            )
        })
        .collect()
}

/// A deterministic human label derived only from persisted unit metadata.
///
/// The project-unit ID remains the machine identity. The label is deliberately
/// not reconstructed from a live package manifest.
pub fn project_unit_label(unit: &ProjectUnit) -> String {
    if let Some(label) = unit
        .root_path
        .rsplit('/')
        .find(|component| !component.is_empty())
    {
        return label.to_string();
    }
    match unit.kind {
        ProjectUnitKind::Workspace => "repository workspace".into(),
        ProjectUnitKind::Package => "repository package".into(),
        ProjectUnitKind::Module => "repository module".into(),
        ProjectUnitKind::LooseSources => format!("{} loose sources", unit.language_id),
        ProjectUnitKind::AuxiliarySources => {
            format!("{} auxiliary sources", unit.language_id)
        }
    }
}

/// Extract architecture data from one graph and its exact persisted inventory.
///
/// Both inputs belong to the same immutable generation. Query-time filesystem
/// discovery is intentionally absent: adding or removing manifests after
/// publication cannot change this answer.
pub fn extract_overview_data(graph: &KnowledgeGraph, inventory: &ProjectInventory) -> OverviewData {
    let all_nodes = graph.all_nodes();
    let all_edges = graph.all_edges();
    let owners = source_owners(inventory);
    let owner_for = |node: &GraphNode| owners.get(node.file_path.as_str()).copied();

    let mut health = BTreeMap::<ProjectUnitId, ProjectUnitHealth>::new();
    let mut owned_node_counts = BTreeMap::<ProjectUnitId, usize>::new();
    let mut callable_node_counts = BTreeMap::<ProjectUnitId, usize>::new();
    let mut unassigned_node_count = 0usize;
    for node in &all_nodes {
        let Some(unit_id) = owner_for(node) else {
            unassigned_node_count += 1;
            continue;
        };
        *owned_node_counts.entry(unit_id.clone()).or_default() += 1;
        if symbol_kind_has_role(&node.kind, SymbolRole::Callable) {
            *callable_node_counts.entry(unit_id.clone()).or_default() += 1;
        }
        let entry = health.entry(unit_id.clone()).or_default();
        match overview_bucket(node.reachability_class) {
            OverviewBucket::Alive => entry.wired += 1,
            OverviewBucket::Dead => entry.dead += 1,
            OverviewBucket::Test => entry.test_only += 1,
            OverviewBucket::Unclassified | OverviewBucket::Suspected | OverviewBucket::Excluded => {
            }
        }
    }

    let mut project_unit_dependencies = BTreeSet::new();
    for (from_id, to_id, edge) in &all_edges {
        if edge.kind != EdgeKind::DependsOn {
            continue;
        }
        let Some(from_unit) = graph.node(from_id).and_then(&owner_for) else {
            continue;
        };
        let Some(to_unit) = graph.node(to_id).and_then(&owner_for) else {
            continue;
        };
        if from_unit != to_unit {
            project_unit_dependencies.insert(ProjectUnitDependency {
                from_project_unit_id: from_unit.clone(),
                to_project_unit_id: to_unit.clone(),
            });
        }
    }

    // Key types by fan-in (top 5 per source-owning project unit).
    let mut fan_in_counts = HashMap::<Uuid, usize>::new();
    for (_from_id, to_id, edge) in &all_edges {
        if edge.kind.is_observed_coupling() {
            *fan_in_counts.entry(*to_id).or_default() += 1;
        }
    }
    let mut key_types = BTreeMap::<ProjectUnitId, Vec<KeyType>>::new();
    for node in &all_nodes {
        if !["struct", "enum", "trait"].contains(&node.kind.as_str()) {
            continue;
        }
        let fan_in = fan_in_counts.get(&node.memory_id).copied().unwrap_or(0);
        if fan_in == 0 {
            continue;
        }
        let Some(unit_id) = owner_for(node) else {
            continue;
        };
        key_types.entry(unit_id.clone()).or_default().push(KeyType {
            symbol_name: node.symbol_name.clone(),
            kind: node.kind.clone(),
            fan_in,
        });
    }
    for types in key_types.values_mut() {
        types.sort_by(|left, right| {
            right
                .fan_in
                .cmp(&left.fan_in)
                .then_with(|| left.symbol_name.cmp(&right.symbol_name))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        types.truncate(5);
    }

    let project_units = inventory
        .project_topology
        .units
        .iter()
        .cloned()
        .map(|unit| {
            let project_unit_id = &unit.project_unit_id;
            ProjectUnitOverview {
                label: project_unit_label(&unit),
                owned_node_count: owned_node_counts
                    .remove(project_unit_id)
                    .unwrap_or_default(),
                callable_node_count: callable_node_counts
                    .remove(project_unit_id)
                    .unwrap_or_default(),
                health: health.remove(project_unit_id).unwrap_or_default(),
                key_types: key_types.remove(project_unit_id).unwrap_or_default(),
                unit,
            }
        })
        .collect();

    let mut dead_code_count = 0usize;
    let mut unclassified_count = 0usize;
    for node in &all_nodes {
        match overview_bucket(node.reachability_class) {
            OverviewBucket::Dead => dead_code_count += 1,
            OverviewBucket::Unclassified => unclassified_count += 1,
            OverviewBucket::Alive
            | OverviewBucket::Test
            | OverviewBucket::Suspected
            | OverviewBucket::Excluded => {}
        }
    }

    OverviewData {
        total_nodes: all_nodes.len(),
        total_edges: all_edges.len(),
        project_units,
        project_unit_relationships: inventory.project_topology.relationships.clone(),
        project_unit_dependencies: project_unit_dependencies.into_iter().collect(),
        project_inventory_coverage: inventory.coverage,
        project_inventory_issues: inventory.issues.clone(),
        unassigned_node_count,
        dead_code_count,
        unclassified_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_unit_label_is_derived_only_from_persisted_metadata() {
        let unit = ProjectUnit {
            project_unit_id: ProjectUnitId::new("rust:cargo:package:crates/member/Cargo.toml"),
            language_id: crate::code_intel_domain::LanguageId::new("rust"),
            ecosystem_id: crate::code_intel_domain::EcosystemId::new("cargo"),
            kind: ProjectUnitKind::Package,
            root_path: "crates/member".into(),
            manifest_path: Some("crates/member/Cargo.toml".into()),
            compilation_root_paths: Vec::new(),
        };
        assert_eq!(project_unit_label(&unit), "member");
    }

    // BUG-8: fan-in counts only Calls + FieldOf, not all edge types.
    #[test]
    fn observed_coupling_counts_calls_and_field_of_only() {
        // Calls and FieldOf should be counted.
        assert!(
            EdgeKind::Calls.is_observed_coupling(),
            "Calls should be a fan-in edge"
        );
        assert!(
            EdgeKind::FieldOf.is_observed_coupling(),
            "FieldOf should be a fan-in edge"
        );

        // These should NOT be counted for fan-in.
        assert!(
            !EdgeKind::References.is_observed_coupling(),
            "References (use imports) should not be a fan-in edge"
        );
        assert!(
            !EdgeKind::TypeOf.is_observed_coupling(),
            "TypeOf should not be a fan-in edge"
        );
        assert!(
            !EdgeKind::Contains.is_observed_coupling(),
            "Contains should not be a fan-in edge"
        );
        assert!(
            !EdgeKind::Implements.is_observed_coupling(),
            "Implements should not be a fan-in edge"
        );
        assert!(
            !EdgeKind::HasImpl.is_observed_coupling(),
            "HasImpl should not be a fan-in edge"
        );
    }
}
