//! Scoped quality audit over one immutable semantic generation.
//!
//! Audit is a shared use case, not an adapter-side warning formatter. It keeps
//! observed provider calls, structural call hints, field coupling, and source
//! scopes distinct; ranks and pages symbol hotspots deterministically; and
//! withholds reachability-derived health when the generation cannot authorize
//! it. CLI and MCP serialize this same result.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::code_intel_calls::assess_calls_capability;
use crate::code_intel_cursor::{page_window, request_digest};
use crate::code_intel_dead::{
    CallableRootSets, ProjectUnitCallableLivenessResolver, ProjectUnitCallableVerdict,
    callable_root_sets,
};
use crate::code_intel_domain::{
    CapabilityCoverage, DomainError, GenerationId, LIVE_INPUT_RESULT_RESERVE_CHARS, LanguageId,
    Page, ProjectInventoryCoverage, ProjectUnitId, RepositoryBinding, UnitGraph,
    assess_structural_graph_capability,
};
use crate::code_intel_inventory::project_unit_graph;
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{language_id_for_path, repository_binding};
use crate::code_intel_symbol::exact_symbol_id;
use crate::graph::{EdgeKind, EdgeScope, EdgeSource, GraphEdge, GraphNode, KnowledgeGraph};
use crate::graph_overview::project_unit_label;
use crate::graph_stats::dead_code_unknown_guidance;
use crate::project_binding::ProjectBinding;
use crate::reachability::ReachabilityEvidence;
use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

#[cfg(test)]
use crate::reachability::ReachabilityClass;

pub const AUDIT_SCHEMA_VERSION: &str = "h00/code-intel/audit/v2";
pub const DEFAULT_AUDIT_FAN_IN_THRESHOLD: usize = 20;
pub const DEFAULT_AUDIT_DEAD_RATIO_PERCENT: usize = 10;
pub const DEFAULT_AUDIT_PAGE_SIZE: usize = 20;
pub const MAX_AUDIT_PAGE_SIZE: usize = 100;
pub const MAX_AUDIT_CURSOR_BYTES: usize = 8_192;
pub const MAX_AUDIT_RESULT_CHARS: usize = 28_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    #[default]
    Production,
    Conditional,
    Tests,
    All,
}

impl AuditScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Conditional => "conditional",
            Self::Tests => "tests",
            Self::All => "all",
        }
    }
}

pub fn parse_audit_scope(value: &str) -> Result<AuditScope, DomainError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "production" => Ok(AuditScope::Production),
        "conditional" => Ok(AuditScope::Conditional),
        "tests" => Ok(AuditScope::Tests),
        "all" => Ok(AuditScope::All),
        _ => Err(invalid_request(
            "scope",
            "must be one of: production, conditional, tests, all",
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRequest {
    pub scope: AuditScope,
    pub min_fan_in: usize,
    pub min_dead_ratio_percent: usize,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl Default for AuditRequest {
    fn default() -> Self {
        Self {
            scope: AuditScope::Production,
            min_fan_in: DEFAULT_AUDIT_FAN_IN_THRESHOLD,
            min_dead_ratio_percent: DEFAULT_AUDIT_DEAD_RATIO_PERCENT,
            limit: DEFAULT_AUDIT_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditQuery {
    pub scope: AuditScope,
    pub min_fan_in: usize,
    pub min_dead_ratio_percent: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditGraphSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditAuthority {
    /// These are observed incoming relationships. Provider and structural
    /// completeness are reported separately and never inferred from counts.
    pub population: String,
    pub calls: CapabilityCoverage,
    pub structural_graph: CapabilityCoverage,
    pub project_inventory_coverage: ProjectInventoryCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDeadCodeStatus {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditDeadFile {
    pub document_path: String,
    /// Provider-reconciled source-owned callables with no retained-root path.
    pub dead_symbols: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditProjectUnitDeadRatio {
    pub project_unit_id: ProjectUnitId,
    pub label: String,
    pub language_id: LanguageId,
    /// Source-owned callable population reconciled against provider Calls.
    /// The field name is retained for the current adapter shape; this is not
    /// an all-symbol structural denominator.
    pub total_symbols: usize,
    /// Callables with complete negative authority and no retained-root path.
    pub dead_symbols: usize,
    pub ratio_basis_points: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditProjectUnitAuthority {
    pub language_id: LanguageId,
    pub status: AuditDeadCodeStatus,
    pub authoritative_project_units: usize,
    pub withheld_project_units: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditDeadCode {
    pub status: AuditDeadCodeStatus,
    /// Exact source-owned unreached-callable total. `None` means at least one
    /// source-owning project unit lacks the authority needed for aggregation.
    pub total: Option<usize>,
    /// Non-empty source-owner units whose callable liveness is fully resolved
    /// by retained roots and scoped provider Calls (or has no callables).
    pub authoritative_project_units: usize,
    /// Non-empty source-owner units omitted from unreached-callable
    /// observations because their roots, Calls, or topology is incomplete.
    pub withheld_project_units: usize,
    /// Deterministic reconciliation of the aggregate unit counts by source
    /// language. This stays bounded by the indexed language population instead
    /// of serializing an arbitrary monorepo-sized unit-ID list.
    pub project_unit_authority: Vec<AuditProjectUnitAuthority>,
    /// In a partial result these files come only from authoritative project
    /// units; they never masquerade as a whole-repository ranking.
    pub top_files: Vec<AuditDeadFile>,
    /// All authoritative project units above the requested unreached-callable
    /// threshold, deterministically ranked.
    pub high_ratio_project_units: Vec<AuditProjectUnitDeadRatio>,
    pub min_ratio_percent: usize,
    pub action_needed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AuditCouplingCounts {
    /// Calls observed in the selected semantic provider population.
    pub provider_calls: usize,
    /// Calls inferred by structural extraction rather than a semantic provider.
    pub structural_call_hints: usize,
    /// Structural type coupling from `FieldOf` edges.
    pub field_uses: usize,
    pub total: usize,
}

impl AuditCouplingCounts {
    const fn record(&mut self, edge: &GraphEdge) {
        match edge.kind {
            EdgeKind::Calls => match edge.source {
                EdgeSource::Scip | EdgeSource::Both => self.provider_calls += 1,
                EdgeSource::TreeSitter => self.structural_call_hints += 1,
            },
            EdgeKind::FieldOf => self.field_uses += 1,
            _ => return,
        }
        self.total += 1;
    }

    const fn add_assign(&mut self, other: &Self) {
        self.provider_calls += other.provider_calls;
        self.structural_call_hints += other.structural_call_hints;
        self.field_uses += other.field_uses;
        self.total += other.total;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AuditCouplingBreakdown {
    pub production: AuditCouplingCounts,
    pub conditional: AuditCouplingCounts,
    pub tests: AuditCouplingCounts,
    pub all: AuditCouplingCounts,
}

impl AuditCouplingBreakdown {
    #[must_use]
    pub const fn selected(&self, scope: AuditScope) -> &AuditCouplingCounts {
        match scope {
            AuditScope::Production => &self.production,
            AuditScope::Conditional => &self.conditional,
            AuditScope::Tests => &self.tests,
            AuditScope::All => &self.all,
        }
    }

    fn record(&mut self, scope: RelationshipScope, edge: &GraphEdge) {
        let selected = match scope {
            RelationshipScope::Production => &mut self.production,
            RelationshipScope::Conditional => &mut self.conditional,
            RelationshipScope::Tests => &mut self.tests,
        };
        selected.record(edge);
        self.all = AuditCouplingCounts::default();
        self.all.add_assign(&self.production);
        self.all.add_assign(&self.conditional);
        self.all.add_assign(&self.tests);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditHotspot {
    pub symbol_id: String,
    pub name: String,
    pub kind: String,
    pub document_path: String,
    pub language_id: crate::code_intel_domain::LanguageId,
    pub start_line: Option<usize>,
    pub end_line: Option<usize>,
    pub test_only: Option<bool>,
    pub selected_fan_in: usize,
    pub fan_in: AuditCouplingBreakdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditHotspotPopulation {
    pub considered_symbols: usize,
    pub qualifying_symbols: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactAuditResult {
    pub schema_version: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub unit_graph: UnitGraph,
    pub query: AuditQuery,
    pub graph: AuditGraphSummary,
    pub authority: AuditAuthority,
    pub dead_code: AuditDeadCode,
    pub hotspot_population: AuditHotspotPopulation,
    pub hotspots: Vec<AuditHotspot>,
    pub page: Page,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn validate_audit_request(request: &AuditRequest) -> Result<(), DomainError> {
    if request.min_fan_in == 0 {
        return Err(invalid_request("min_fan_in", "must be at least 1"));
    }
    if !(1..=100).contains(&request.min_dead_ratio_percent) {
        return Err(invalid_request(
            "min_dead_ratio_percent",
            "must be between 1 and 100",
        ));
    }
    if !(1..=MAX_AUDIT_PAGE_SIZE).contains(&request.limit) {
        return Err(invalid_request(
            "limit",
            format!("must be between 1 and {MAX_AUDIT_PAGE_SIZE}"),
        ));
    }
    if request
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_AUDIT_CURSOR_BYTES)
    {
        return Err(invalid_request(
            "cursor",
            format!("must be at most {MAX_AUDIT_CURSOR_BYTES} UTF-8 bytes"),
        ));
    }
    Ok(())
}

pub fn query_published_audit(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    reachability: Option<&ReachabilityEvidence>,
    request: &AuditRequest,
) -> Result<ExactAuditResult, DomainError> {
    validate_audit_request(request)?;

    let calls = assess_calls_capability(
        graph,
        &generation.manifest.receipts,
        &generation.provider_payloads,
        &generation.project_inventory,
    );
    let structural_graph = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let authority = AuditAuthority {
        population: "observed incoming provider Calls, structural call hints, and FieldOf relationships, partitioned by persisted source scope"
            .into(),
        calls: calls.clone(),
        structural_graph,
        project_inventory_coverage: generation.project_inventory.coverage,
    };
    let roots = reachability
        .map(|evidence| callable_root_sets(graph, evidence))
        .transpose()?;
    let dead_code = dead_code_summary(
        graph,
        generation,
        &calls,
        roots.as_ref(),
        request.min_dead_ratio_percent,
    )?;
    let (hotspot_population, hotspots) = collect_hotspots(
        graph,
        &generation.manifest.repository_id,
        &generation.manifest.generation_id,
        request.scope,
        request.min_fan_in,
    );
    let digest = request_digest(
        "audit",
        &[
            request.scope.as_str(),
            &request.min_fan_in.to_string(),
            &request.min_dead_ratio_percent.to_string(),
        ],
    );

    let mut smallest_result_chars = 0;
    for effective_limit in (1..=request.limit).rev() {
        let window = page_window(
            "audit",
            &generation.manifest.generation_id,
            &digest,
            request.cursor.as_deref(),
            effective_limit,
            hotspots.len(),
        )?;
        let page_hotspots = hotspots[window.range.clone()].to_vec();
        let mut warnings = Vec::new();
        if generation.project_inventory.coverage
            == ProjectInventoryCoverage::IndexedSourcePopulationPartial
        {
            warnings.push(format!(
                "project inventory is partial and reports {} issue(s)",
                generation.project_inventory.issues.len()
            ));
        }
        if effective_limit < request.limit {
            warnings.push(format!(
                "page reduced from requested limit {} to {} to preserve the product result bound",
                request.limit, effective_limit
            ));
        }
        if window.page.has_more {
            warnings.push(format!(
                "showing {} of {} hotspots in this page; continue with next_cursor",
                window.page.returned, window.page.total_items
            ));
        }
        let result = ExactAuditResult {
            schema_version: AUDIT_SCHEMA_VERSION.into(),
            generation_id: generation.manifest.generation_id.clone(),
            repository: repository_binding(binding, generation),
            unit_graph: project_unit_graph(
                &generation.project_inventory,
                page_hotspots
                    .iter()
                    .map(|hotspot| hotspot.document_path.as_str()),
            ),
            query: AuditQuery {
                scope: request.scope,
                min_fan_in: request.min_fan_in,
                min_dead_ratio_percent: request.min_dead_ratio_percent,
                limit: request.limit,
            },
            graph: AuditGraphSummary {
                total_nodes: graph.node_count(),
                total_edges: graph.edge_count(),
            },
            authority: authority.clone(),
            dead_code: dead_code.clone(),
            hotspot_population: hotspot_population.clone(),
            hotspots: page_hotspots,
            page: window.page,
            warnings,
        };
        let result_chars = serde_json::to_string(&result)
            .map_err(|error| invalid_generation(format!("serialize Audit result: {error}")))?
            .chars()
            .count();
        smallest_result_chars = result_chars;
        if result_chars <= MAX_AUDIT_RESULT_CHARS - LIVE_INPUT_RESULT_RESERVE_CHARS {
            return Ok(result);
        }
    }

    Err(invalid_request(
        "limit",
        format!(
            "even a one-hotspot Audit page would contain {smallest_result_chars} serialized characters and cannot leave room for required live-input evidence within the {MAX_AUDIT_RESULT_CHARS}-character product bound"
        ),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelationshipScope {
    Production,
    Conditional,
    Tests,
}

fn relationship_scope(edge: &GraphEdge, source: Option<&GraphNode>) -> RelationshipScope {
    if edge.scope == EdgeScope::Test || source.is_some_and(|node| node.is_test_only == Some(true)) {
        RelationshipScope::Tests
    } else if edge.scope == EdgeScope::CfgGated {
        RelationshipScope::Conditional
    } else {
        RelationshipScope::Production
    }
}

fn collect_hotspots(
    graph: &KnowledgeGraph,
    repository_id: &crate::code_intel_domain::RepositoryId,
    generation_id: &GenerationId,
    scope: AuditScope,
    min_fan_in: usize,
) -> (AuditHotspotPopulation, Vec<AuditHotspot>) {
    let mut fan_in = HashMap::<Uuid, AuditCouplingBreakdown>::new();
    for (from_id, to_id, edge) in graph.all_edges() {
        if !edge.kind.is_observed_coupling() {
            continue;
        }
        fan_in
            .entry(to_id)
            .or_default()
            .record(relationship_scope(edge, graph.node(&from_id)), edge);
    }

    let mut considered_symbols = 0;
    let mut hotspots = Vec::new();
    for node in graph.all_nodes() {
        if scope == AuditScope::Production && node.is_test_only == Some(true) {
            continue;
        }
        considered_symbols += 1;
        let breakdown = fan_in.remove(&node.memory_id).unwrap_or_default();
        let selected_fan_in = breakdown.selected(scope).total;
        if selected_fan_in < min_fan_in {
            continue;
        }
        hotspots.push(AuditHotspot {
            symbol_id: exact_symbol_id(repository_id, generation_id, node.memory_id),
            name: node.symbol_name.clone(),
            kind: node.kind.clone(),
            document_path: node.file_path.clone(),
            language_id: language_id_for_path(&node.file_path),
            start_line: node.line_start,
            end_line: node.line_end,
            test_only: node.is_test_only,
            selected_fan_in,
            fan_in: breakdown,
        });
    }
    hotspots.sort_by(|left, right| {
        right
            .selected_fan_in
            .cmp(&left.selected_fan_in)
            .then_with(|| left.document_path.cmp(&right.document_path))
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.symbol_id.cmp(&right.symbol_id))
    });
    (
        AuditHotspotPopulation {
            considered_symbols,
            qualifying_symbols: hotspots.len(),
        },
        hotspots,
    )
}

fn dead_code_summary(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    calls: &CapabilityCoverage,
    roots: Option<&CallableRootSets>,
    min_dead_ratio_percent: usize,
) -> Result<AuditDeadCode, DomainError> {
    let nodes = graph.all_nodes();
    let owners = generation
        .project_inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            generation
                .project_inventory
                .is_semantic_source_owner(membership)
        })
        .map(|membership| {
            (
                membership.document_path.as_str(),
                &membership.project_unit_id,
            )
        })
        .collect::<BTreeMap<_, _>>();
    // (owned symbols, callable symbols), keyed by exact generation-local
    // source owner. Path-context units never authorize health.
    let mut unit_populations = BTreeMap::<ProjectUnitId, (usize, usize)>::new();
    for node in &nodes {
        let Some(unit_id) = owners.get(node.file_path.as_str()) else {
            continue;
        };
        let counts = unit_populations.entry((*unit_id).clone()).or_default();
        counts.0 += 1;
        if symbol_kind_has_role(&node.kind, SymbolRole::Callable) {
            counts.1 += 1;
        }
    }
    let units = generation
        .project_inventory
        .project_topology
        .units
        .iter()
        .map(|unit| (&unit.project_unit_id, unit))
        .collect::<BTreeMap<_, _>>();

    // (total callables, unreached callables), populated only for units whose
    // complete shared liveness result authorizes negative claims.
    let mut unit_counts = BTreeMap::<ProjectUnitId, (usize, usize)>::new();
    let mut authoritative_unit_ids = BTreeSet::new();
    let mut unreached_node_ids = BTreeSet::new();
    let mut liveness_resolver =
        roots.map(|roots| ProjectUnitCallableLivenessResolver::new(graph, generation, roots));
    for (project_unit_id, (_, callable_symbols)) in &unit_populations {
        if !units.contains_key(project_unit_id) {
            return Err(DomainError::ProjectInventoryMismatch {
                document_path: format!("<project unit {project_unit_id}>"),
                reason: "source-owner project unit is missing from the persisted unit population"
                    .into(),
            });
        }
        if *callable_symbols == 0 {
            authoritative_unit_ids.insert(project_unit_id.clone());
            unit_counts.insert(project_unit_id.clone(), (0, 0));
            continue;
        }
        let Some(resolver) = liveness_resolver.as_mut() else {
            continue;
        };
        let liveness = resolver.resolve(project_unit_id)?;
        if liveness.items.len() != *callable_symbols {
            return Err(DomainError::ProjectInventoryMismatch {
                document_path: format!("<project unit {project_unit_id}>"),
                reason: format!(
                    "shared callable liveness returned {} item(s) for a {}-callable source-owner population",
                    liveness.items.len(),
                    callable_symbols
                ),
            });
        }
        if liveness.is_complete() {
            let unreached = liveness.count(ProjectUnitCallableVerdict::Unreached);
            unreached_node_ids.extend(
                liveness
                    .items
                    .iter()
                    .filter(|item| item.verdict == ProjectUnitCallableVerdict::Unreached)
                    .map(|item| item.memory_id),
            );
            authoritative_unit_ids.insert(project_unit_id.clone());
            unit_counts.insert(project_unit_id.clone(), (*callable_symbols, unreached));
        }
    }
    let authoritative_project_units = authoritative_unit_ids.len();
    let withheld_project_units = unit_populations
        .len()
        .saturating_sub(authoritative_project_units);
    let mut authority_by_language = BTreeMap::<LanguageId, (usize, usize)>::new();
    for project_unit_id in unit_populations.keys() {
        let language_id = units.get(project_unit_id).map_or_else(
            || LanguageId::new("unknown"),
            |unit| unit.language_id.clone(),
        );
        let counts = authority_by_language.entry(language_id).or_default();
        if authoritative_unit_ids.contains(project_unit_id) {
            counts.0 += 1;
        } else {
            counts.1 += 1;
        }
    }
    let project_unit_authority = authority_by_language
        .into_iter()
        .map(
            |(language_id, (authoritative_project_units, withheld_project_units))| {
                AuditProjectUnitAuthority {
                    language_id,
                    status: project_unit_authority_status(
                        authoritative_project_units,
                        withheld_project_units,
                    ),
                    authoritative_project_units,
                    withheld_project_units,
                }
            },
        )
        .collect::<Vec<_>>();
    let aggregate_authoritative = withheld_project_units == 0;
    let status = if aggregate_authoritative {
        AuditDeadCodeStatus::Complete
    } else if authoritative_project_units > 0 {
        AuditDeadCodeStatus::Partial
    } else {
        AuditDeadCodeStatus::Unavailable
    };

    let total_dead = unreached_node_ids.len();
    let mut dead_by_file = BTreeMap::<String, usize>::new();
    if status != AuditDeadCodeStatus::Unavailable {
        for node_id in &unreached_node_ids {
            if let Some(node) = graph.node(node_id) {
                *dead_by_file.entry(node.file_path.clone()).or_default() += 1;
            }
        }
    }
    let mut top_files = dead_by_file
        .into_iter()
        .map(|(document_path, dead_symbols)| AuditDeadFile {
            document_path,
            dead_symbols,
        })
        .collect::<Vec<_>>();
    top_files.sort_by(|left, right| {
        right
            .dead_symbols
            .cmp(&left.dead_symbols)
            .then_with(|| left.document_path.cmp(&right.document_path))
    });
    top_files.truncate(10);

    let mut high_ratio_project_units = unit_counts
        .into_iter()
        .filter(|(project_unit_id, (total, dead))| {
            authoritative_unit_ids.contains(project_unit_id)
                && *total > 0
                && dead_ratio_meets_threshold(*total, *dead, min_dead_ratio_percent)
        })
        .map(|(project_unit_id, (total_symbols, dead_symbols))| {
            let unit = units.get(&project_unit_id);
            let label = unit.map_or_else(
                || project_unit_id.to_string(),
                |unit| project_unit_label(unit),
            );
            AuditProjectUnitDeadRatio {
                project_unit_id,
                label,
                language_id: unit.map_or_else(
                    || LanguageId::new("unknown"),
                    |unit| unit.language_id.clone(),
                ),
                total_symbols,
                dead_symbols,
                ratio_basis_points: (((dead_symbols as u128) * 10_000) / (total_symbols as u128))
                    as usize,
            }
        })
        .collect::<Vec<_>>();
    high_ratio_project_units.sort_by(|left, right| {
        right
            .ratio_basis_points
            .cmp(&left.ratio_basis_points)
            .then_with(|| right.dead_symbols.cmp(&left.dead_symbols))
            .then_with(|| left.project_unit_id.cmp(&right.project_unit_id))
    });

    let guidance = (status != AuditDeadCodeStatus::Complete)
        .then(|| dead_code_unknown_guidance(calls, roots.is_some(), graph.node_count() > 0));
    Ok(AuditDeadCode {
        status,
        total: aggregate_authoritative.then_some(total_dead),
        authoritative_project_units,
        withheld_project_units,
        project_unit_authority,
        top_files,
        high_ratio_project_units,
        min_ratio_percent: min_dead_ratio_percent,
        action_needed: guidance
            .as_ref()
            .is_some_and(|guidance| guidance.action_needed),
        guidance: guidance.map(|guidance| guidance.message),
    })
}

const fn project_unit_authority_status(
    authoritative_project_units: usize,
    withheld_project_units: usize,
) -> AuditDeadCodeStatus {
    if withheld_project_units == 0 {
        AuditDeadCodeStatus::Complete
    } else if authoritative_project_units > 0 {
        AuditDeadCodeStatus::Partial
    } else {
        AuditDeadCodeStatus::Unavailable
    }
}

const fn dead_ratio_meets_threshold(total: usize, dead: usize, minimum_percent: usize) -> bool {
    (dead as u128) * 100 >= (minimum_percent as u128) * (total as u128)
}

fn invalid_request(field: &'static str, reason: impl Into<String>) -> DomainError {
    DomainError::InvalidRequest {
        operation: "audit",
        field,
        reason: reason.into(),
    }
}

const fn invalid_generation(reason: String) -> DomainError {
    DomainError::PublishedGenerationInvalid { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_intel_domain::{GenerationId, RepositoryId};
    use crate::graph::{GraphEdge, GraphNode};

    fn node(name: &str, test_only: bool) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: "function".into(),
            file_path: if test_only {
                "src/lib_tests.rs".into()
            } else {
                "src/lib.rs".into()
            },
            content_hash: "fixture".into(),
            signature: String::new(),
            reachability_class: if test_only {
                ReachabilityClass::TestOnly
            } else {
                ReachabilityClass::Wired
            },
            line_start: Some(0),
            line_end: Some(0),
            has_body: Some(true),
            visibility: "private".into(),
            is_test_only: Some(test_only),
            is_test_root: test_only,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    fn hotspots(graph: &KnowledgeGraph, scope: AuditScope, threshold: usize) -> Vec<AuditHotspot> {
        collect_hotspots(
            graph,
            &RepositoryId::new("fixture-repository"),
            &GenerationId::new("fixture-generation"),
            scope,
            threshold,
        )
        .1
    }

    #[test]
    fn production_fan_in_excludes_test_callers_and_other_scopes_recover_them() {
        let target = node("target", false);
        let production_caller = node("production_caller", false);
        let conditional_caller = node("conditional_caller", false);
        let test_caller = node("test_caller", true);
        let target_id = target.memory_id;
        let production_caller_id = production_caller.memory_id;
        let conditional_caller_id = conditional_caller.memory_id;
        let test_caller_id = test_caller.memory_id;
        let mut graph = KnowledgeGraph::new();
        graph.add_node(target).unwrap();
        graph.add_node(production_caller).unwrap();
        graph.add_node(conditional_caller).unwrap();
        graph.add_node(test_caller).unwrap();
        graph
            .add_edge(
                production_caller_id,
                target_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    scope: EdgeScope::Production,
                    source: EdgeSource::Scip,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        graph
            .add_edge(
                conditional_caller_id,
                target_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    scope: EdgeScope::CfgGated,
                    source: EdgeSource::Scip,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        graph
            .add_edge(
                test_caller_id,
                target_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    scope: EdgeScope::Test,
                    source: EdgeSource::TreeSitter,
                    ..GraphEdge::default()
                },
            )
            .unwrap();

        assert!(
            hotspots(&graph, AuditScope::Production, 2).is_empty(),
            "a test caller must not manufacture a production hotspot"
        );
        let production = hotspots(&graph, AuditScope::Production, 1);
        assert_eq!(
            production.len(),
            1,
            "real production caller must still fire"
        );
        assert_eq!(production[0].fan_in.production.provider_calls, 1);
        assert_eq!(production[0].fan_in.production.structural_call_hints, 0);

        let conditional = hotspots(&graph, AuditScope::Conditional, 1);
        assert_eq!(conditional.len(), 1, "cfg-gated coupling has its own scope");
        assert_eq!(conditional[0].fan_in.conditional.provider_calls, 1);

        let tests = hotspots(&graph, AuditScope::Tests, 1);
        assert_eq!(tests.len(), 1, "test scope preserves test coupling");
        assert_eq!(tests[0].fan_in.tests.structural_call_hints, 1);

        let all = hotspots(&graph, AuditScope::All, 3);
        assert_eq!(all.len(), 1, "all scope preserves the combined capability");
        assert_eq!(all[0].selected_fan_in, 3);
    }

    #[test]
    fn coupling_breakdown_keeps_provider_hints_and_fields_distinct() {
        let target = node("target", false);
        let provider_caller = node("provider_caller", false);
        let structural_caller = node("structural_caller", false);
        let field_owner = node("field_owner", false);
        let target_id = target.memory_id;
        let provider_caller_id = provider_caller.memory_id;
        let structural_caller_id = structural_caller.memory_id;
        let field_owner_id = field_owner.memory_id;
        let mut graph = KnowledgeGraph::new();
        graph.add_node(target).unwrap();
        graph.add_node(provider_caller).unwrap();
        graph.add_node(structural_caller).unwrap();
        graph.add_node(field_owner).unwrap();
        for (caller_id, source) in [
            (provider_caller_id, EdgeSource::Scip),
            (structural_caller_id, EdgeSource::TreeSitter),
        ] {
            graph
                .add_edge(
                    caller_id,
                    target_id,
                    GraphEdge {
                        kind: EdgeKind::Calls,
                        source,
                        ..GraphEdge::default()
                    },
                )
                .unwrap();
        }
        graph
            .add_edge(
                field_owner_id,
                target_id,
                GraphEdge {
                    kind: EdgeKind::FieldOf,
                    ..GraphEdge::default()
                },
            )
            .unwrap();

        let results = hotspots(&graph, AuditScope::Production, 3);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fan_in.production.provider_calls, 1);
        assert_eq!(results[0].fan_in.production.structural_call_hints, 1);
        assert_eq!(results[0].fan_in.production.field_uses, 1);
        assert_eq!(results[0].fan_in.production.total, 3);
    }

    #[test]
    fn production_scope_excludes_test_only_targets_without_hiding_other_scopes() {
        let target = node("test_target", true);
        let production_caller = node("production_caller", false);
        let test_caller = node("test_caller", true);
        let target_id = target.memory_id;
        let production_caller_id = production_caller.memory_id;
        let test_caller_id = test_caller.memory_id;
        let mut graph = KnowledgeGraph::new();
        graph.add_node(target).unwrap();
        graph.add_node(production_caller).unwrap();
        graph.add_node(test_caller).unwrap();
        graph
            .add_edge(
                production_caller_id,
                target_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    scope: EdgeScope::Production,
                    source: EdgeSource::Scip,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        graph
            .add_edge(
                test_caller_id,
                target_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    scope: EdgeScope::Test,
                    source: EdgeSource::Scip,
                    ..GraphEdge::default()
                },
            )
            .unwrap();

        assert!(
            hotspots(&graph, AuditScope::Production, 1).is_empty(),
            "a test-only target must not become a production hotspot even when persisted input is inconsistent"
        );
        assert_eq!(hotspots(&graph, AuditScope::Tests, 1).len(), 1);
        assert_eq!(hotspots(&graph, AuditScope::All, 2).len(), 1);
    }

    #[test]
    fn request_validation_rejects_every_unbounded_or_ambiguous_input() {
        for (field, request) in [
            (
                "min_fan_in",
                AuditRequest {
                    min_fan_in: 0,
                    ..AuditRequest::default()
                },
            ),
            (
                "min_dead_ratio_percent",
                AuditRequest {
                    min_dead_ratio_percent: 0,
                    ..AuditRequest::default()
                },
            ),
            (
                "min_dead_ratio_percent",
                AuditRequest {
                    min_dead_ratio_percent: 101,
                    ..AuditRequest::default()
                },
            ),
            (
                "limit",
                AuditRequest {
                    limit: 0,
                    ..AuditRequest::default()
                },
            ),
            (
                "limit",
                AuditRequest {
                    limit: MAX_AUDIT_PAGE_SIZE + 1,
                    ..AuditRequest::default()
                },
            ),
            (
                "cursor",
                AuditRequest {
                    cursor: Some("x".repeat(MAX_AUDIT_CURSOR_BYTES + 1)),
                    ..AuditRequest::default()
                },
            ),
        ] {
            let error = validate_audit_request(&request)
                .expect_err("invalid Audit request must be rejected");
            assert!(
                matches!(
                    &error,
                    DomainError::InvalidRequest {
                        operation: "audit",
                        field: actual,
                        ..
                    } if *actual == field
                ),
                "{field} must fail as a typed Audit request error"
            );
            let envelope = error.envelope();
            assert_eq!(envelope.error.operation.as_deref(), Some("audit"));
            assert_eq!(envelope.error.field.as_deref(), Some(field));
        }
        assert!(matches!(
            parse_audit_scope("some"),
            Err(DomainError::InvalidRequest {
                operation: "audit",
                field: "scope",
                ..
            })
        ));
    }

    #[test]
    fn exact_dead_ratio_threshold_is_inclusive() {
        assert!(
            dead_ratio_meets_threshold(10, 1, 10),
            "a minimum threshold includes a unit exactly on the boundary"
        );
        assert!(!dead_ratio_meets_threshold(11, 1, 10));
    }

    #[test]
    fn project_unit_authority_status_distinguishes_complete_partial_and_unavailable() {
        assert_eq!(
            project_unit_authority_status(2, 0),
            AuditDeadCodeStatus::Complete
        );
        assert_eq!(
            project_unit_authority_status(1, 1),
            AuditDeadCodeStatus::Partial
        );
        assert_eq!(
            project_unit_authority_status(0, 2),
            AuditDeadCodeStatus::Unavailable
        );
    }
}
