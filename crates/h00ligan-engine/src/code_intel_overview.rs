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
    LanguageId, MAX_GENERATION_ENGINE_RESULT_CHARS, ProjectInventoryCoverage,
    ProjectInventoryIssue, ProjectUnitId, ProjectUnitKind, ProjectUnitRelationship,
    RepositoryBinding,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::repository_binding;
use crate::graph::KnowledgeGraph;
use crate::graph_overview::{KeyType, ProjectUnitDependency, extract_overview_data};
use crate::graph_stats::{
    CoverageTier, call_edge_coverage, coverage_tier, dead_code_unknown_guidance,
    unclassified_population_guidance,
};
use crate::project_binding::ProjectBinding;
use crate::reachability::ReachabilityEvidence;

pub const OVERVIEW_SCHEMA_VERSION: &str = "h00/code-intel/overview/v4";
pub const DEFAULT_OVERVIEW_COLLECTION_LIMIT: usize = 50;
pub const MAX_OVERVIEW_COLLECTION_LIMIT: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverviewRequest {
    /// Maximum preview rows retained in each Overview collection. Overview is
    /// a bounded summary; operation-specific tools expose detailed populations.
    pub limit: usize,
}

impl Default for OverviewRequest {
    fn default() -> Self {
        Self {
            limit: DEFAULT_OVERVIEW_COLLECTION_LIMIT,
        }
    }
}

pub fn validate_overview_request(request: &OverviewRequest) -> Result<(), DomainError> {
    if !(1..=MAX_OVERVIEW_COLLECTION_LIMIT).contains(&request.limit) {
        return Err(DomainError::InvalidRequest {
            operation: "overview",
            field: "limit",
            reason: format!("must be between 1 and {MAX_OVERVIEW_COLLECTION_LIMIT}"),
        });
    }
    Ok(())
}

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
pub struct OverviewCollectionProjection {
    pub returned: usize,
    pub total_items: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverviewProjection {
    pub requested_limit: usize,
    pub effective_limit: usize,
    pub project_units: OverviewCollectionProjection,
    pub project_unit_relationships: OverviewCollectionProjection,
    pub project_unit_dependencies: OverviewCollectionProjection,
    pub project_inventory_issues: OverviewCollectionProjection,
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
    pub projection: OverviewProjection,
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
    request: &OverviewRequest,
) -> Result<ExactOverviewResult, DomainError> {
    validate_overview_request(request)?;
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
    let total_callable_nodes = graph
        .all_nodes()
        .iter()
        .filter(|node| {
            crate::structural_ir::symbol_kind_has_role(
                &node.kind,
                crate::structural_ir::SymbolRole::Callable,
            )
        })
        .count();
    let mut authoritative_callable_nodes = 0usize;
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
                    authoritative_callable_nodes += liveness.items.len();
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
    let coverage = call_edge_coverage(graph, authoritative_callable_nodes > 0);
    let tier = coverage_tier(&coverage);
    let has_unclassified_nodes = overview.unclassified_count > 0;
    let health_status = health_status(
        &calls,
        tier,
        roots.is_some(),
        has_unclassified_nodes,
        authoritative_callable_nodes,
        total_callable_nodes,
    );
    let aggregate_health_authoritative = matches!(
        health_status,
        OverviewHealthStatus::NotApplicable | OverviewHealthStatus::Complete
    );

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

    let health_guidance = (!aggregate_health_authoritative).then(|| {
        unclassified_population_guidance(overview.unclassified_count).unwrap_or_else(|| {
            dead_code_unknown_guidance(&calls, roots.is_some(), graph.node_count() > 0)
        })
    });
    let health_action_needed = health_guidance
        .as_ref()
        .is_some_and(|guidance| guidance.action_needed);
    let needs_unclassified = overview.needs_unclassified_banner();

    let result = ExactOverviewResult {
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
        projection: OverviewProjection {
            requested_limit: request.limit,
            effective_limit: request.limit,
            project_units: OverviewCollectionProjection {
                returned: 0,
                total_items: 0,
                truncated: false,
            },
            project_unit_relationships: OverviewCollectionProjection {
                returned: 0,
                total_items: 0,
                truncated: false,
            },
            project_unit_dependencies: OverviewCollectionProjection {
                returned: 0,
                total_items: 0,
                truncated: false,
            },
            project_inventory_issues: OverviewCollectionProjection {
                returned: 0,
                total_items: 0,
                truncated: false,
            },
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
    };
    bound_overview_result(result, request.limit)
}

fn bound_overview_result(
    mut result: ExactOverviewResult,
    requested_limit: usize,
) -> Result<ExactOverviewResult, DomainError> {
    let project_units_total = result.project_units.len();
    let relationships_total = result.project_unit_relationships.len();
    let dependencies_total = result.project_unit_dependencies.len();
    let inventory_issues_total = result.project_inventory.issues.len();
    let base_warning_count = result.warnings.len();
    let mut smallest_result_chars = usize::MAX;

    for effective_limit in (1..=requested_limit).rev() {
        result.project_units.truncate(effective_limit);
        result.project_unit_relationships.truncate(effective_limit);
        result.project_unit_dependencies.truncate(effective_limit);
        result.project_inventory.issues.truncate(effective_limit);
        result.projection = OverviewProjection {
            requested_limit,
            effective_limit,
            project_units: collection_projection(result.project_units.len(), project_units_total),
            project_unit_relationships: collection_projection(
                result.project_unit_relationships.len(),
                relationships_total,
            ),
            project_unit_dependencies: collection_projection(
                result.project_unit_dependencies.len(),
                dependencies_total,
            ),
            project_inventory_issues: collection_projection(
                result.project_inventory.issues.len(),
                inventory_issues_total,
            ),
        };
        result.warnings.truncate(base_warning_count);
        let truncated = [
            &result.projection.project_units,
            &result.projection.project_unit_relationships,
            &result.projection.project_unit_dependencies,
            &result.projection.project_inventory_issues,
        ]
        .into_iter()
        .any(|collection| collection.truncated);
        if effective_limit < requested_limit || truncated {
            result.warnings.push(format!(
                "Overview is a bounded architecture summary: at most {effective_limit} rows are returned per collection; use operation-specific queries for detailed populations"
            ));
        }

        let result_chars = serde_json::to_string(&result)
            .map_err(|error| DomainError::PublishedGenerationInvalid {
                reason: format!("serialize Overview result for size validation: {error}"),
            })?
            .chars()
            .count();
        smallest_result_chars = result_chars;
        if result_chars <= MAX_GENERATION_ENGINE_RESULT_CHARS {
            return Ok(result);
        }
    }
    Err(DomainError::result_too_large(
        "overview",
        smallest_result_chars,
        MAX_GENERATION_ENGINE_RESULT_CHARS,
        "Use a narrower Overview limit; required generation identity, authority, and one preview row do not fit",
    ))
}

const fn collection_projection(
    returned: usize,
    total_items: usize,
) -> OverviewCollectionProjection {
    OverviewCollectionProjection {
        returned,
        total_items,
        truncated: returned < total_items,
    }
}

const fn health_status(
    calls: &CapabilityCoverage,
    tier: CoverageTier,
    reachability_available: bool,
    has_unclassified_nodes: bool,
    authoritative_callable_nodes: usize,
    total_callable_nodes: usize,
) -> OverviewHealthStatus {
    if has_unclassified_nodes {
        return OverviewHealthStatus::Unclassified;
    }
    match tier {
        CoverageTier::Degenerate => OverviewHealthStatus::Degenerate,
        CoverageTier::NotApplicable => OverviewHealthStatus::NotApplicable,
        CoverageTier::Unavailable | CoverageTier::Sufficient => {
            if !reachability_available {
                return OverviewHealthStatus::Unclassified;
            }
            if total_callable_nodes > 0 && authoritative_callable_nodes == total_callable_nodes {
                return OverviewHealthStatus::Complete;
            }
            if authoritative_callable_nodes > 0 {
                return OverviewHealthStatus::Partial;
            }
            match calls.status {
                CapabilityCoverageStatus::Qualified | CapabilityCoverageStatus::Partial => {
                    OverviewHealthStatus::Partial
                }
                CapabilityCoverageStatus::Unavailable
                | CapabilityCoverageStatus::Complete
                | CapabilityCoverageStatus::NotApplicable => OverviewHealthStatus::Unavailable,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overview_with_units(count: usize, label_chars: usize) -> ExactOverviewResult {
        let project_units = (0..count)
            .map(|index| OverviewProjectUnit {
                project_unit_id: ProjectUnitId::new(format!("rust:cargo:unit-{index}")),
                label: format!("unit-{index}-{}", "x".repeat(label_chars)),
                language_id: LanguageId::new("rust"),
                ecosystem_id: EcosystemId::new("cargo"),
                kind: ProjectUnitKind::Package,
                root_path: format!("packages/unit-{index}"),
                manifest_path: Some(format!("packages/unit-{index}/Cargo.toml")),
                health: None,
                top_types: None,
            })
            .collect::<Vec<_>>();
        ExactOverviewResult {
            schema_version: OVERVIEW_SCHEMA_VERSION.into(),
            generation_id: GenerationId::new("generation"),
            repository: RepositoryBinding {
                repository_id: crate::code_intel_domain::RepositoryId::new("repository"),
                root_label: "fixture".into(),
                live_inputs: None,
            },
            total_nodes: count,
            total_edges: 0,
            project_units,
            project_unit_relationships: Vec::new(),
            project_unit_dependencies: Vec::new(),
            project_inventory: OverviewProjectInventory {
                coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
                issues: Vec::new(),
                unassigned_node_count: 0,
            },
            projection: OverviewProjection {
                requested_limit: count.max(1),
                effective_limit: count.max(1),
                project_units: collection_projection(count, count),
                project_unit_relationships: collection_projection(0, 0),
                project_unit_dependencies: collection_projection(0, 0),
                project_inventory_issues: collection_projection(0, 0),
            },
            dead_code_count: None,
            health_status: OverviewHealthStatus::Unavailable,
            health_action_needed: true,
            health_guidance: Some("fixture authority unavailable".into()),
            unclassified_count: 0,
            needs_unclassified: false,
            capabilities: OverviewCapabilities {
                calls: CapabilityCoverage {
                    capability_id: "calls".into(),
                    status: CapabilityCoverageStatus::Unavailable,
                    languages: Vec::new(),
                },
                callable_liveness: CapabilityCoverage {
                    capability_id: "callable_liveness".into(),
                    status: CapabilityCoverageStatus::Unavailable,
                    languages: Vec::new(),
                },
            },
            warnings: Vec::new(),
        }
    }

    #[test]
    fn unclassified_population_outranks_not_applicable_capability_census() {
        let not_applicable = CapabilityCoverage {
            capability_id: "calls".into(),
            status: CapabilityCoverageStatus::NotApplicable,
            languages: Vec::new(),
        };
        assert_eq!(
            health_status(
                &not_applicable,
                CoverageTier::NotApplicable,
                true,
                true,
                0,
                0,
            ),
            OverviewHealthStatus::Unclassified,
            "positive unclassified population must prevent a false authoritative zero"
        );
        assert_eq!(
            health_status(
                &not_applicable,
                CoverageTier::NotApplicable,
                true,
                false,
                0,
                0,
            ),
            OverviewHealthStatus::NotApplicable,
            "known-empty capability population remains a distinct control"
        );
    }

    #[test]
    fn not_applicable_calls_census_cannot_erase_an_observed_callable_population() {
        let not_applicable = CapabilityCoverage {
            capability_id: "calls".into(),
            status: CapabilityCoverageStatus::NotApplicable,
            languages: Vec::new(),
        };
        assert_eq!(
            health_status(
                &not_applicable,
                CoverageTier::Unavailable,
                true,
                false,
                0,
                1,
            ),
            OverviewHealthStatus::Unavailable,
            "structural callables without semantic ownership are unknown, not authoritative-empty"
        );
    }

    #[test]
    fn aggregate_health_requires_authority_for_the_complete_callable_population() {
        let complete = CapabilityCoverage {
            capability_id: "calls".into(),
            status: CapabilityCoverageStatus::Complete,
            languages: Vec::new(),
        };
        assert_eq!(
            health_status(&complete, CoverageTier::Sufficient, true, false, 1, 2),
            OverviewHealthStatus::Partial,
            "one authoritative callable cannot authorize a two-callable aggregate"
        );
        assert_eq!(
            health_status(&complete, CoverageTier::Sufficient, true, false, 2, 2),
            OverviewHealthStatus::Complete,
            "the exact complete callable population remains authoritative"
        );
    }

    #[test]
    fn overview_adaptively_reduces_each_preview_without_hiding_totals() {
        let result = bound_overview_result(overview_with_units(100, 500), 100)
            .expect("large Overview must reduce to a useful bounded summary");
        let serialized = serde_json::to_string(&result).expect("bounded Overview JSON");
        assert!(
            serialized.chars().count() <= MAX_GENERATION_ENGINE_RESULT_CHARS,
            "bounded Overview exceeded the generation envelope"
        );
        assert!(result.projection.effective_limit < 100);
        assert_eq!(result.projection.project_units.total_items, 100);
        assert_eq!(
            result.projection.project_units.returned,
            result.project_units.len()
        );
        assert!(result.projection.project_units.truncated);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("bounded architecture summary"))
        );

        let small = bound_overview_result(overview_with_units(1, 8), 50)
            .expect("positive small Overview control");
        assert_eq!(small.project_units.len(), 1);
        assert!(!small.projection.project_units.truncated);
        assert_eq!(small.projection.effective_limit, 50);
    }

    #[test]
    fn overview_request_limit_is_transport_independent() {
        assert!(validate_overview_request(&OverviewRequest { limit: 1 }).is_ok());
        assert!(
            validate_overview_request(&OverviewRequest {
                limit: MAX_OVERVIEW_COLLECTION_LIMIT
            })
            .is_ok()
        );
        for limit in [0, MAX_OVERVIEW_COLLECTION_LIMIT + 1] {
            assert!(matches!(
                validate_overview_request(&OverviewRequest { limit }),
                Err(DomainError::InvalidRequest {
                    operation: "overview",
                    field: "limit",
                    ..
                })
            ));
        }
    }
}
