//! Exact architecture Overview projection over one immutable generation.
//!
//! The graph/inventory extractor remains transport-neutral raw evidence. This
//! module owns the public result: generation identity, repository binding,
//! Calls authority, per-project-unit health admission, and stable serialization.
//! CLI and MCP adapters render or serialize this value without rebuilding it.

use serde::Serialize;

use crate::code_intel_callable_liveness::assess_callable_liveness_capability;
use crate::code_intel_calls::assess_calls_capability;
use crate::code_intel_dead::{
    ProjectUnitCallableLivenessResolver, ProjectUnitCallableVerdict, callable_root_sets,
};
use crate::code_intel_domain::{
    CapabilityCoverage, CapabilityCoverageStatus, DomainError, EcosystemId, GenerationId,
    LanguageId, ProjectInventoryCoverage, ProjectInventoryIssue, ProjectUnitId, ProjectUnitKind,
    ProjectUnitRelationship, RepositoryBinding,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::repository_binding;
use crate::graph::KnowledgeGraph;
use crate::graph_overview::{KeyType, ProjectUnitDependency, extract_overview_data};
use crate::graph_stats::{
    CoverageTier, call_edge_coverage, coverage_tier, dead_code_unknown_guidance,
};
use crate::project_binding::ProjectBinding;
use crate::reachability::ReachabilityEvidence;

pub const OVERVIEW_SCHEMA_VERSION: &str = "h00/code-intel/overview/v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverviewHealthStatus {
    Complete,
    Partial,
    Unavailable,
    NotApplicable,
    Unclassified,
    Degenerate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverviewCapabilities {
    pub calls: CapabilityCoverage,
    pub callable_liveness: CapabilityCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverviewUnitHealth {
    /// Source-owned callables reached from a retained production/public root.
    pub wired: usize,
    /// Source-owned callables with complete negative Calls authority and no
    /// retained-root path.
    pub dead: usize,
    /// Source-owned callables reached from tests or conservatively retained by
    /// structural test ownership.
    pub test_only: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverviewKeyType {
    pub name: String,
    pub kind: String,
    pub fan_in: usize,
}

impl From<&KeyType> for OverviewKeyType {
    fn from(value: &KeyType) -> Self {
        Self {
            name: value.symbol_name.clone(),
            kind: value.kind.clone(),
            fan_in: value.fan_in,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverviewProjectUnit {
    pub project_unit_id: ProjectUnitId,
    pub label: String,
    pub language_id: LanguageId,
    pub ecosystem_id: EcosystemId,
    pub kind: ProjectUnitKind,
    pub root_path: String,
    pub manifest_path: Option<String>,
    /// `None` means the unit is structural-only or the generation cannot
    /// authorize callable liveness for it. Zeroes are authoritative zeroes.
    pub health: Option<OverviewUnitHealth>,
    /// This ranking mixes Calls and structural FieldOf fan-in, so it follows
    /// the same unit-local Calls authority as health rather than leaking an
    /// unqualified partial metric.
    pub top_types: Option<Vec<OverviewKeyType>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverviewProjectInventory {
    pub coverage: ProjectInventoryCoverage,
    pub issues: Vec<ProjectInventoryIssue>,
    pub unassigned_node_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactOverviewResult {
    pub schema_version: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub project_units: Vec<OverviewProjectUnit>,
    pub project_unit_relationships: Vec<ProjectUnitRelationship>,
    pub project_unit_dependencies: Vec<ProjectUnitDependency>,
    pub project_inventory: OverviewProjectInventory,
    pub dead_code_count: Option<usize>,
    pub health_status: OverviewHealthStatus,
    pub health_action_needed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_guidance: Option<String>,
    pub unclassified_count: usize,
    pub needs_unclassified: bool,
    pub capabilities: OverviewCapabilities,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn query_published_overview(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    reachability: Option<&ReachabilityEvidence>,
) -> Result<ExactOverviewResult, DomainError> {
    let overview = extract_overview_data(graph, &generation.project_inventory);
    let calls = assess_calls_capability(
        graph,
        &generation.manifest.receipts,
        &generation.provider_payloads,
        &generation.project_inventory,
    );
    let callable_liveness = assess_callable_liveness_capability(
        graph,
        &generation.manifest.receipts,
        &generation.provider_payloads,
        &generation.project_inventory,
    );
    let roots = reachability
        .map(|evidence| callable_root_sets(graph, evidence))
        .transpose()?;
    let mut authoritative_nonempty_units = 0usize;
    let mut withheld_nonempty_units = 0usize;
    let mut canonical_dead_code_count = 0usize;
    let mut liveness_resolver = roots
        .as_ref()
        .map(|roots| ProjectUnitCallableLivenessResolver::new(graph, generation, roots));
    let project_units = overview
        .project_units
        .iter()
        .map(|info| -> Result<OverviewProjectUnit, DomainError> {
            let semantic_unit = info.unit.kind.grants_semantic_authority();
            let health = if !semantic_unit || info.owned_node_count == 0 {
                None
            } else if info.callable_node_count == 0 {
                Some(OverviewUnitHealth {
                    wired: 0,
                    dead: 0,
                    test_only: 0,
                })
            } else if let Some(resolver) = liveness_resolver.as_mut() {
                let liveness = resolver.resolve(&info.unit.project_unit_id)?;
                if liveness.items.len() != info.callable_node_count {
                    return Err(DomainError::ProjectInventoryMismatch {
                        document_path: format!(
                            "<project unit {}>",
                            info.unit.project_unit_id
                        ),
                        reason: format!(
                            "shared callable liveness returned {} item(s) for a {}-callable source-owner population",
                            liveness.items.len(), info.callable_node_count
                        ),
                    });
                }
                if liveness.is_complete() {
                    let dead = liveness.count(ProjectUnitCallableVerdict::Unreached);
                    canonical_dead_code_count += dead;
                    Some(OverviewUnitHealth {
                        wired: liveness.count(ProjectUnitCallableVerdict::LiveProduction),
                        dead,
                        test_only: liveness.count(ProjectUnitCallableVerdict::LiveTest)
                            + liveness.count(ProjectUnitCallableVerdict::RetainedTest),
                    })
                } else {
                    None
                }
            } else {
                None
            };
            if semantic_unit && info.owned_node_count > 0 {
                if health.is_some() {
                    authoritative_nonempty_units += 1;
                } else {
                    withheld_nonempty_units += 1;
                }
            }
            Ok(OverviewProjectUnit {
                project_unit_id: info.unit.project_unit_id.clone(),
                label: info.label.clone(),
                language_id: info.unit.language_id.clone(),
                ecosystem_id: info.unit.ecosystem_id.clone(),
                kind: info.unit.kind,
                root_path: info.unit.root_path.clone(),
                manifest_path: info.unit.manifest_path.clone(),
                top_types: health
                    .as_ref()
                    .map(|_| info.key_types.iter().map(OverviewKeyType::from).collect()),
                health,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let all_nonempty_units_authoritative =
        authoritative_nonempty_units > 0 && withheld_nonempty_units == 0;
    let coverage = call_edge_coverage(graph, all_nonempty_units_authoritative);
    let tier = coverage_tier(&coverage);
    let health_status = health_status(&calls, tier, roots.is_some());
    let aggregate_health_authoritative = match health_status {
        OverviewHealthStatus::NotApplicable => true,
        OverviewHealthStatus::Complete => all_nonempty_units_authoritative,
        _ => false,
    };

    let mut warnings = Vec::new();
    if generation.project_inventory.coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationPartial
    {
        warnings.push(format!(
            "project inventory is partial and reports {} issue(s)",
            generation.project_inventory.issues.len()
        ));
    }
    if matches!(health_status, OverviewHealthStatus::Partial) {
        warnings.push(
            "aggregate health is unknown; only project units with complete language-local Calls authority expose health"
                .into(),
        );
    }

    let health_guidance = (!aggregate_health_authoritative)
        .then(|| dead_code_unknown_guidance(&calls, roots.is_some(), graph.node_count() > 0));
    let health_action_needed = health_guidance
        .as_ref()
        .is_some_and(|guidance| guidance.action_needed);
    let needs_unclassified = overview.needs_unclassified_banner();

    Ok(ExactOverviewResult {
        schema_version: OVERVIEW_SCHEMA_VERSION.into(),
        generation_id: generation.manifest.generation_id.clone(),
        repository: repository_binding(binding, generation),
        total_nodes: overview.total_nodes,
        total_edges: overview.total_edges,
        project_units,
        project_unit_relationships: overview.project_unit_relationships,
        project_unit_dependencies: overview.project_unit_dependencies,
        project_inventory: OverviewProjectInventory {
            coverage: overview.project_inventory_coverage,
            issues: overview.project_inventory_issues,
            unassigned_node_count: overview.unassigned_node_count,
        },
        dead_code_count: aggregate_health_authoritative.then_some(canonical_dead_code_count),
        health_status,
        health_action_needed,
        health_guidance: health_guidance.map(|guidance| guidance.message),
        unclassified_count: overview.unclassified_count,
        needs_unclassified,
        capabilities: OverviewCapabilities {
            calls,
            callable_liveness,
        },
        warnings,
    })
}

const fn health_status(
    calls: &CapabilityCoverage,
    tier: CoverageTier,
    reachability_available: bool,
) -> OverviewHealthStatus {
    if matches!(calls.status, CapabilityCoverageStatus::NotApplicable) {
        return OverviewHealthStatus::NotApplicable;
    }
    if !reachability_available {
        return OverviewHealthStatus::Unclassified;
    }
    match tier {
        CoverageTier::Degenerate => OverviewHealthStatus::Degenerate,
        CoverageTier::NotApplicable => OverviewHealthStatus::NotApplicable,
        CoverageTier::Sufficient => OverviewHealthStatus::Complete,
        CoverageTier::Unavailable => match calls.status {
            CapabilityCoverageStatus::Qualified | CapabilityCoverageStatus::Partial => {
                OverviewHealthStatus::Partial
            }
            CapabilityCoverageStatus::Unavailable => OverviewHealthStatus::Unavailable,
            CapabilityCoverageStatus::Complete => OverviewHealthStatus::Unavailable,
            CapabilityCoverageStatus::NotApplicable => OverviewHealthStatus::NotApplicable,
        },
    }
}
