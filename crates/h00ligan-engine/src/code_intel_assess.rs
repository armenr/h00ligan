//! Authority-qualified change-impact assessment over one immutable generation.
//!
//! `assess` keeps exact provider call paths separate from structural dependency
//! evidence. It never promotes navigation-only graph edges into causal impact,
//! and it reports objective review signals rather than an invented risk tier.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::code_intel_calls::{
    CallablePathStep, ExactCallReference, ExactCapabilityAuthority, PublishedCallsGraph,
    assess_calls_capability, filter_admits, published_node_is_invocation_target,
    published_node_is_invocation_target_indexed,
};
use crate::code_intel_cursor::{page_window, request_digest};
use crate::code_intel_domain::{
    AuthorityStatus, CallerFilter, CapabilityCoverage, CapabilityCoverageStatus, DomainError,
    GenerationId, LIVE_INPUT_RESULT_RESERVE_CHARS, Page, ProjectInventoryCoverage,
    RepositoryBinding, SymbolIdentity, UnitGraph, assess_structural_graph_capability,
};
use crate::code_intel_inventory::project_unit_graph;
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{generation_file_context, language_id_for_path, repository_binding};
use crate::code_intel_query_index::GenerationQueryIndex;
use crate::code_intel_symbol::{NameFileSelection, resolve_symbol_selector};
use crate::code_intel_tests::{
    ExactTestReference, TestsAuthority, TestsRequest, query_published_tests,
    query_published_tests_indexed,
};
use crate::code_intel_type::{StructuralSymbol, structural_symbol};
use crate::graph::{EdgeKind, GraphNode, KnowledgeGraph};
use crate::project_binding::ProjectBinding;
use crate::reachability::ReachabilityClass;

pub const ASSESS_SCHEMA_VERSION: &str = "h00/code-intel/assess/v2";
pub const DEFAULT_ASSESS_DEPTH: usize = 3;
pub const MAX_ASSESS_DEPTH: usize = 10;
pub const DEFAULT_ASSESS_PAGE_SIZE: usize = 50;
pub const MAX_ASSESS_PAGE_SIZE: usize = 100;
pub const MAX_ASSESS_SYMBOL_BYTES: usize = 4_096;
pub const MAX_ASSESS_FILE_BYTES: usize = 4_096;
pub const MAX_ASSESS_CURSOR_BYTES: usize = 8_192;
pub const MAX_ASSESS_RESULT_CHARS: usize = 28_000;
const MAX_ASSESS_FACET_PREVIEW: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessSection {
    BlastRadius,
    Callers,
    Tests,
    Risk,
}

impl AssessSection {
    pub const ALL: [Self; 4] = [Self::BlastRadius, Self::Callers, Self::Tests, Self::Risk];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlastRadius => "blast_radius",
            Self::Callers => "callers",
            Self::Tests => "tests",
            Self::Risk => "risk",
        }
    }
}

impl FromStr for AssessSection {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "blast_radius" => Ok(Self::BlastRadius),
            "callers" => Ok(Self::Callers),
            "tests" => Ok(Self::Tests),
            "risk" => Ok(Self::Risk),
            _ => Err(format!(
                "unknown Assess section '{value}', expected blast_radius, callers, tests, or risk"
            )),
        }
    }
}

pub fn parse_assess_section(value: &str) -> Result<AssessSection, DomainError> {
    value
        .parse()
        .map_err(|reason| invalid_request("sections", reason))
}

pub fn parse_assess_filter(value: &str) -> Result<CallerFilter, DomainError> {
    value
        .parse()
        .map_err(|reason| invalid_request("filter", reason))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessRequest {
    pub symbol: String,
    pub file: Option<String>,
    pub sections: BTreeSet<AssessSection>,
    pub max_depth: usize,
    pub filter: CallerFilter,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl AssessRequest {
    #[must_use]
    pub fn new(symbol: impl Into<String>) -> Self {
        Self {
            symbol: symbol.into(),
            file: None,
            sections: AssessSection::ALL.into_iter().collect(),
            max_depth: DEFAULT_ASSESS_DEPTH,
            filter: CallerFilter::Live,
            limit: DEFAULT_ASSESS_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssessQuery {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub sections: Vec<AssessSection>,
    pub max_depth: usize,
    pub filter: CallerFilter,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssessTarget {
    pub structural: StructuralSymbol,
    pub callable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_identity: Option<SymbolIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralImpactKind {
    Reference,
    TypeUse,
    Implementation,
    Inheritance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralImpactStep {
    pub dependent: StructuralSymbol,
    pub dependency: StructuralSymbol,
    pub relation: StructuralImpactKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImpactedSymbol {
    pub symbol: StructuralSymbol,
    pub reachability: ReachabilityClass,
    pub minimum_depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_path: Option<Vec<CallablePathStep>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structural_path: Option<Vec<StructuralImpactStep>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssessBlastRadius {
    pub population_complete: bool,
    pub observed_affected_symbols: usize,
    pub observed_execution_affected_symbols: usize,
    pub observed_exact_only_affected_symbols: usize,
    pub observed_qualified_binding_affected_symbols: usize,
    pub observed_structural_affected_symbols: usize,
    pub observed_affected_files: usize,
    pub filtered_out_symbols: usize,
    pub execution_depth_cutoff_nodes: usize,
    pub structural_depth_cutoff_nodes: usize,
    pub page: Page,
    pub items: Vec<ImpactedSymbol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessApplicability {
    Applicable,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssessCallers {
    pub applicability: AssessApplicability,
    pub observed_direct_callers: Option<usize>,
    pub observed_call_sites: Option<usize>,
    pub population_complete: Option<bool>,
    pub items_complete: bool,
    pub items: Vec<ExactCallReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssessTests {
    pub applicability: AssessApplicability,
    pub observed_runnable_test_roots: Option<usize>,
    pub population_complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<TestsAuthority>,
    pub items_complete: bool,
    pub items: Vec<ExactTestReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssessReviewSignals {
    pub observed_affected_symbols: usize,
    pub observed_affected_files: usize,
    pub observed_direct_callers: Option<usize>,
    pub observed_transitive_execution_dependents: Option<usize>,
    pub observed_qualified_binding_dependents: Option<usize>,
    pub observed_structural_dependents: usize,
    pub observed_runnable_test_roots: Option<usize>,
    pub maximum_observed_depth: usize,
    pub depth_boundary_reached: bool,
    pub crosses_project_units: bool,
    pub population_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssessAuthority {
    pub status: AuthorityStatus,
    pub population: String,
    pub structural_graph: CapabilityCoverage,
    pub calls: CapabilityCoverage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_calls: Option<ExactCapabilityAuthority>,
    pub project_inventory_coverage: ProjectInventoryCoverage,
    pub execution_traversal_complete: bool,
    pub structural_traversal_complete: bool,
    pub population_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactAssessResult {
    pub schema_version: String,
    pub capability: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub unit_graph: UnitGraph,
    pub query: AssessQuery,
    pub resolved_symbol: AssessTarget,
    pub authority: AssessAuthority,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blast_radius: Option<AssessBlastRadius>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers: Option<AssessCallers>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tests: Option<AssessTests>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<AssessReviewSignals>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

struct ImpactAccumulator {
    symbol: StructuralSymbol,
    reachability: ReachabilityClass,
    execution_path: Option<Vec<CallablePathStep>>,
    structural_path: Option<Vec<StructuralImpactStep>>,
}

struct StructuralTraversal {
    paths: BTreeMap<Uuid, Vec<(Uuid, Uuid, StructuralImpactKind)>>,
    depth_cutoff_nodes: usize,
}

struct ExecutionEvidence {
    resolved_symbol: SymbolIdentity,
    authority: ExactCapabilityAuthority,
    paths: Vec<(Uuid, usize, Vec<CallablePathStep>)>,
    direct_references: Vec<ExactCallReference>,
    depth_cutoff_nodes: usize,
    warning: Option<String>,
}

pub fn validate_assess_request(request: &AssessRequest) -> Result<(), DomainError> {
    if request.symbol.trim().is_empty() {
        return Err(invalid_request("symbol", "must not be empty"));
    }
    if request.symbol.len() > MAX_ASSESS_SYMBOL_BYTES {
        return Err(invalid_request(
            "symbol",
            format!("must be at most {MAX_ASSESS_SYMBOL_BYTES} UTF-8 bytes"),
        ));
    }
    if let Some(file) = request.file.as_deref() {
        if file.trim().is_empty() {
            return Err(invalid_request("file", "must not be empty"));
        }
        if file.len() > MAX_ASSESS_FILE_BYTES {
            return Err(invalid_request(
                "file",
                format!("must be at most {MAX_ASSESS_FILE_BYTES} UTF-8 bytes"),
            ));
        }
    }
    if request.sections.is_empty() {
        return Err(invalid_request(
            "sections",
            "must contain at least one section",
        ));
    }
    if !(1..=MAX_ASSESS_DEPTH).contains(&request.max_depth) {
        return Err(invalid_request(
            "depth",
            format!("must be between 1 and {MAX_ASSESS_DEPTH}"),
        ));
    }
    if !(1..=MAX_ASSESS_PAGE_SIZE).contains(&request.limit) {
        return Err(invalid_request(
            "limit",
            format!("must be between 1 and {MAX_ASSESS_PAGE_SIZE}"),
        ));
    }
    if request
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_ASSESS_CURSOR_BYTES)
    {
        return Err(invalid_request(
            "cursor",
            format!("must be at most {MAX_ASSESS_CURSOR_BYTES} UTF-8 bytes"),
        ));
    }
    if request.cursor.is_some() && !request.sections.contains(&AssessSection::BlastRadius) {
        return Err(invalid_request(
            "cursor",
            "requires the blast_radius section because it pages that population",
        ));
    }
    Ok(())
}

pub fn query_published_assess(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &AssessRequest,
) -> Result<ExactAssessResult, DomainError> {
    query_published_assess_with_index(None, graph, generation, binding, request)
}

pub fn query_published_assess_indexed(
    index: &GenerationQueryIndex,
    binding: &ProjectBinding,
    request: &AssessRequest,
) -> Result<ExactAssessResult, DomainError> {
    query_published_assess_with_index(
        Some(index),
        index.graph(),
        index.generation(),
        binding,
        request,
    )
}

fn query_published_assess_with_index(
    index: Option<&GenerationQueryIndex>,
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &AssessRequest,
) -> Result<ExactAssessResult, DomainError> {
    validate_assess_request(request)?;
    let file = request
        .file
        .as_deref()
        .map(|file| generation_file_context(binding, file))
        .transpose()?;
    let normalized_file = file.as_ref().map(|context| context.file_path().to_owned());
    let target = resolve_target(graph, generation, &request.symbol, file)?;
    let target_structural = structural_symbol(graph, target, generation)?;
    if !target_structural.source_backed {
        return Err(invalid_generation(format!(
            "resolved Assess target {} is not backed by an indexed source document",
            target.symbol_name
        )));
    }
    let target_language = language_id_for_path(&target.file_path);
    let structural_coverage = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let calls_coverage = assess_calls_capability(
        graph,
        &generation.manifest.receipts,
        &generation.provider_payloads,
        &generation.project_inventory,
    );
    let callable = match index {
        Some(index) => published_node_is_invocation_target_indexed(index, target)?,
        None => published_node_is_invocation_target(graph, generation, target)?,
    };
    let calls_applicable = callable
        && !generation
            .project_inventory
            .is_structural_only_source_document(&target.file_path, &target_language);
    let calls_applicability = callable.then_some(if calls_applicable {
        AssessApplicability::Applicable
    } else {
        AssessApplicability::NotApplicable
    });
    let calls_usable = calls_coverage.language_is_usable(&target_language.0);
    let execution_evidence = (calls_applicable && calls_usable)
        .then(|| collect_execution_evidence(index, graph, generation, target, request))
        .transpose()?;
    let structural = collect_structural_impact(graph, target, request.max_depth)?;

    let mut identity_cache = BTreeMap::new();
    identity_cache.insert(target.memory_id, target_structural.clone());
    let mut impacts = BTreeMap::<Uuid, ImpactAccumulator>::new();
    let mut execution_impacted = BTreeSet::new();
    let mut exact_invocation_impacted = BTreeSet::new();
    let mut qualified_binding_impacted = BTreeSet::new();
    let mut structural_impacted = BTreeSet::new();
    let mut filtered_out = BTreeSet::new();
    if let Some(evidence) = &execution_evidence {
        for (node_id, _depth, path) in &evidence.paths {
            let node = graph.node(node_id).ok_or_else(|| {
                invalid_generation(format!("call-impact node {node_id} disappeared"))
            })?;
            if !filter_admits(request.filter, node.reachability_class) {
                filtered_out.insert(*node_id);
                continue;
            }
            execution_impacted.insert(*node_id);
            if path.iter().any(CallablePathStep::is_qualified) {
                qualified_binding_impacted.insert(*node_id);
            } else {
                exact_invocation_impacted.insert(*node_id);
            }
            let symbol = cached_structural_symbol(&mut identity_cache, graph, node, generation)?;
            impacts
                .entry(*node_id)
                .or_insert_with(|| ImpactAccumulator {
                    symbol,
                    reachability: node.reachability_class,
                    execution_path: None,
                    structural_path: None,
                })
                .execution_path = Some(path.clone());
        }
    }
    for (node_id, raw_path) in &structural.paths {
        let node = graph.node(node_id).ok_or_else(|| {
            invalid_generation(format!("structural-impact node {node_id} disappeared"))
        })?;
        if !filter_admits(request.filter, node.reachability_class) {
            filtered_out.insert(*node_id);
            continue;
        }
        let path = materialize_structural_path(raw_path, &mut identity_cache, graph, generation)?;
        structural_impacted.insert(*node_id);
        let symbol = cached_structural_symbol(&mut identity_cache, graph, node, generation)?;
        impacts
            .entry(*node_id)
            .or_insert_with(|| ImpactAccumulator {
                symbol,
                reachability: node.reachability_class,
                execution_path: None,
                structural_path: None,
            })
            .structural_path = Some(path);
    }
    let mut all_items = impacts
        .into_values()
        .map(|impact| ImpactedSymbol {
            minimum_depth: minimum_depth(&impact),
            symbol: impact.symbol,
            reachability: impact.reachability,
            execution_path: impact.execution_path,
            structural_path: impact.structural_path,
        })
        .collect::<Vec<_>>();
    all_items.sort_by(|left, right| {
        (
            left.minimum_depth,
            left.symbol.document_path.as_str(),
            left.symbol.name.as_str(),
            left.symbol.symbol_id.as_str(),
        )
            .cmp(&(
                right.minimum_depth,
                right.symbol.document_path.as_str(),
                right.symbol.name.as_str(),
                right.symbol.symbol_id.as_str(),
            ))
    });

    let inventory_complete = generation.project_inventory.coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationComplete;
    let structural_complete = structural_coverage.language_status(&target_language.0)
        == Some(CapabilityCoverageStatus::Complete);
    let execution_complete = execution_evidence.as_ref().is_some_and(|evidence| {
        evidence.authority.status == AuthorityStatus::Complete && evidence.depth_cutoff_nodes == 0
    });
    // Calls authority covers callable invocations and callable-value bindings,
    // but h00ligan does not yet publish an equivalent provider-backed reference
    // census for non-callable symbols. Structural edges remain useful observed
    // evidence for those targets, but they cannot prove that every type/value
    // use site has been enumerated.
    let reference_population_complete = calls_applicable && execution_evidence.is_some();
    let structural_traversal_complete = structural.depth_cutoff_nodes == 0;
    let population_complete = inventory_complete
        && structural_complete
        && execution_complete
        && reference_population_complete
        && structural_traversal_complete;
    let affected_files = all_items
        .iter()
        .map(|item| item.symbol.document_path.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let maximum_observed_depth = all_items
        .iter()
        .map(|item| item.minimum_depth)
        .max()
        .unwrap_or(0);
    let exact_calls = execution_evidence
        .as_ref()
        .map(|evidence| evidence.authority.clone());
    let call_identity = execution_evidence
        .as_ref()
        .map(|evidence| evidence.resolved_symbol.clone());
    let direct_references = execution_evidence
        .as_ref()
        .map_or_else(Vec::new, |evidence| evidence.direct_references.clone());
    let direct_callers = direct_references
        .iter()
        .map(|reference| reference.caller.symbol_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let call_sites = direct_references.len();

    let tests_result = if execution_evidence.is_some()
        && (request.sections.contains(&AssessSection::Tests)
            || request.sections.contains(&AssessSection::Risk))
    {
        let mut tests_request = TestsRequest::new(request.symbol.clone());
        tests_request.file = request.file.clone();
        tests_request.limit = MAX_ASSESS_FACET_PREVIEW;
        Some(match index {
            Some(index) => query_published_tests_indexed(index, binding, &tests_request)?,
            None => query_published_tests(graph, generation, binding, &tests_request)?,
        })
    } else {
        None
    };
    let test_count = tests_result.as_ref().map(|result| result.page.total_items);
    let test_complete = tests_result
        .as_ref()
        .map(|result| result.authority.population_complete);
    let crosses_project_units = crosses_project_units(&target_structural, &all_items);
    let digest = assess_request_digest(
        request,
        &target_structural.symbol_id,
        normalized_file.clone(),
    );
    let base_warnings = assess_warnings(
        generation,
        structural_complete,
        calls_applicability,
        execution_evidence.as_ref(),
        structural.depth_cutoff_nodes,
        filtered_out.len(),
        qualified_binding_impacted.len(),
    );
    let sections = request.sections.iter().copied().collect::<Vec<_>>();

    let mut smallest_result_chars = 0;
    for effective_limit in (1..=request.limit).rev() {
        let window = page_window(
            "assess",
            &generation.manifest.generation_id,
            &digest,
            request.cursor.as_deref(),
            effective_limit,
            all_items.len(),
        )?;
        let page_items = all_items[window.range.clone()].to_vec();
        let preview_limit = effective_limit.min(MAX_ASSESS_FACET_PREVIEW);
        let caller_items = direct_references
            .iter()
            .take(preview_limit)
            .cloned()
            .collect::<Vec<_>>();
        let test_items = tests_result
            .as_ref()
            .map(|result| {
                result
                    .items
                    .iter()
                    .take(preview_limit)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut warnings = base_warnings.clone();
        if effective_limit < request.limit {
            warnings.push(format!(
                "serialized-result bounds reduced this page from the requested ceiling of {} to {effective_limit} affected symbols",
                request.limit
            ));
        }
        if window.page.has_more && request.sections.contains(&AssessSection::BlastRadius) {
            warnings.push(format!(
                "showing {} of {} observed affected symbols in this page; continue with next_cursor",
                window.page.returned, window.page.total_items
            ));
        }
        if direct_references.len() > caller_items.len()
            && request.sections.contains(&AssessSection::Callers)
        {
            warnings.push(
                "the callers section is a bounded preview; use Calls for every exact call occurrence"
                    .into(),
            );
        }
        if tests_result
            .as_ref()
            .is_some_and(|result| result.page.total_items > test_items.len())
            && request.sections.contains(&AssessSection::Tests)
        {
            warnings.push(
                "the tests section is a bounded preview; use Tests for every runnable test root and continuation"
                    .into(),
            );
        }
        let mut projected_documents = page_items
            .iter()
            .map(|item| item.symbol.document_path.as_str())
            .collect::<Vec<_>>();
        projected_documents.extend(
            caller_items
                .iter()
                .map(|item| item.caller.document_path.as_str()),
        );
        projected_documents.extend(
            test_items
                .iter()
                .map(|item| item.test.document_path.as_str()),
        );
        projected_documents.push(&target_structural.document_path);
        let result = ExactAssessResult {
            schema_version: ASSESS_SCHEMA_VERSION.into(),
            capability: "assess".into(),
            generation_id: generation.manifest.generation_id.clone(),
            repository: repository_binding(binding, generation),
            unit_graph: project_unit_graph(&generation.project_inventory, projected_documents),
            query: AssessQuery {
                symbol: request.symbol.clone(),
                file: normalized_file.clone(),
                sections: sections.clone(),
                max_depth: request.max_depth,
                filter: request.filter,
                limit: request.limit,
            },
            resolved_symbol: AssessTarget {
                structural: target_structural.clone(),
                callable,
                call_identity: call_identity.clone(),
            },
            authority: AssessAuthority {
                status: if population_complete && qualified_binding_impacted.is_empty() {
                    AuthorityStatus::Complete
                } else {
                    AuthorityStatus::Qualified
                },
                population: "provider_execution_dependents_plus_forward_structural_dependents"
                    .into(),
                structural_graph: structural_coverage.clone(),
                calls: calls_coverage.clone(),
                exact_calls: exact_calls.clone(),
                project_inventory_coverage: generation.project_inventory.coverage,
                execution_traversal_complete: !calls_applicable
                    || execution_evidence
                        .as_ref()
                        .is_some_and(|evidence| evidence.depth_cutoff_nodes == 0),
                structural_traversal_complete,
                population_complete,
            },
            blast_radius: request
                .sections
                .contains(&AssessSection::BlastRadius)
                .then(|| AssessBlastRadius {
                    population_complete,
                    observed_affected_symbols: all_items.len(),
                    observed_execution_affected_symbols: execution_impacted.len(),
                    observed_exact_only_affected_symbols: exact_invocation_impacted.len(),
                    observed_qualified_binding_affected_symbols: qualified_binding_impacted.len(),
                    observed_structural_affected_symbols: structural_impacted.len(),
                    observed_affected_files: affected_files,
                    filtered_out_symbols: filtered_out.len(),
                    execution_depth_cutoff_nodes: execution_evidence
                        .as_ref()
                        .map_or(0, |evidence| evidence.depth_cutoff_nodes),
                    structural_depth_cutoff_nodes: structural.depth_cutoff_nodes,
                    page: window.page,
                    items: page_items,
                }),
            callers: request
                .sections
                .contains(&AssessSection::Callers)
                .then(|| AssessCallers {
                    applicability: calls_applicability
                        .unwrap_or(AssessApplicability::NotApplicable),
                    observed_direct_callers: execution_evidence.as_ref().map(|_| direct_callers),
                    observed_call_sites: execution_evidence.as_ref().map(|_| call_sites),
                    population_complete: execution_evidence.as_ref().map(|_| execution_complete),
                    items_complete: direct_references.len() == caller_items.len(),
                    items: caller_items,
                }),
            tests: request
                .sections
                .contains(&AssessSection::Tests)
                .then(|| AssessTests {
                    applicability: calls_applicability
                        .unwrap_or(AssessApplicability::NotApplicable),
                    observed_runnable_test_roots: test_count,
                    population_complete: test_complete,
                    authority: tests_result.as_ref().map(|result| result.authority.clone()),
                    items_complete: tests_result
                        .as_ref()
                        .is_none_or(|result| result.page.total_items == test_items.len()),
                    items: test_items,
                }),
            risk: request
                .sections
                .contains(&AssessSection::Risk)
                .then(|| AssessReviewSignals {
                    observed_affected_symbols: all_items.len(),
                    observed_affected_files: affected_files,
                    observed_direct_callers: execution_evidence.as_ref().map(|_| direct_callers),
                    observed_transitive_execution_dependents: execution_evidence
                        .as_ref()
                        .map(|_| execution_impacted.len()),
                    observed_qualified_binding_dependents: execution_evidence
                        .as_ref()
                        .map(|_| qualified_binding_impacted.len()),
                    observed_structural_dependents: structural_impacted.len(),
                    observed_runnable_test_roots: test_count,
                    maximum_observed_depth,
                    depth_boundary_reached: !execution_evidence
                        .as_ref()
                        .is_none_or(|evidence| evidence.depth_cutoff_nodes == 0)
                        || !structural_traversal_complete,
                    crosses_project_units,
                    population_complete: population_complete && test_complete.unwrap_or(true),
                }),
            warnings,
        };
        let result_chars = serde_json::to_string(&result)
            .map_err(|error| {
                invalid_generation(format!(
                    "serialize Assess result for size validation: {error}"
                ))
            })?
            .chars()
            .count();
        smallest_result_chars = result_chars;
        if result_chars <= MAX_ASSESS_RESULT_CHARS - LIVE_INPUT_RESULT_RESERVE_CHARS {
            return Ok(result);
        }
    }
    Err(invalid_request(
        "symbol",
        format!(
            "even a one-item Assess page would contain {smallest_result_chars} serialized characters and cannot leave room for required live-input evidence within the {MAX_ASSESS_RESULT_CHARS}-character product bound"
        ),
    ))
}

pub(crate) fn resolve_target<'a>(
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    symbol: &str,
    file: Option<crate::graph_query::FileContext>,
) -> Result<&'a GraphNode, DomainError> {
    resolve_symbol_selector(
        graph,
        generation,
        symbol,
        file.as_ref()
            .map(crate::graph_query::FileContext::file_path),
        NameFileSelection::Locality,
    )
}

fn collect_execution_evidence(
    index: Option<&GenerationQueryIndex>,
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    target: &GraphNode,
    request: &AssessRequest,
) -> Result<ExecutionEvidence, DomainError> {
    let language = language_id_for_path(&target.file_path);
    let calls = match index {
        Some(index) => index.calls_for_target(&language, target)?,
        None => std::sync::Arc::new(PublishedCallsGraph::build_for_target(
            graph, generation, &language, target,
        )?),
    };
    let resolved_symbol = calls.node(graph, target)?.identity.clone();
    let traversal = calls.reverse_reachable(graph, target, request.max_depth)?;
    let paths = traversal
        .paths
        .iter()
        .map(|path| (path.caller_id, path.depth, path.chain.clone()))
        .collect();
    let direct_references = calls
        .incoming(target.memory_id)
        .iter()
        .filter(|incoming| filter_admits(request.filter, incoming.caller_reachability))
        .map(|incoming| ExactCallReference {
            caller: incoming.caller.clone(),
            call_span: incoming.call_span.clone(),
            context: "exact provider-resolved direct call occurrence".into(),
        })
        .collect();
    Ok(ExecutionEvidence {
        resolved_symbol,
        authority: calls.authority(),
        paths,
        direct_references,
        depth_cutoff_nodes: traversal.depth_cutoff_nodes,
        warning: calls.coverage_warning(),
    })
}

fn collect_structural_impact(
    graph: &KnowledgeGraph,
    target: &GraphNode,
    max_depth: usize,
) -> Result<StructuralTraversal, DomainError> {
    let mut queue = VecDeque::from([(target.memory_id, 0usize, Vec::new())]);
    let mut visited = BTreeSet::from([target.memory_id]);
    let mut paths = BTreeMap::new();
    let mut depth_cutoffs = BTreeSet::new();
    while let Some((dependency_id, depth, path_to_target)) = queue.pop_front() {
        let mut incoming = graph
            .incoming_neighbors(&dependency_id)
            .into_iter()
            .filter_map(|(dependent_id, edge)| {
                structural_impact_kind(edge.kind).map(|kind| (dependent_id, kind))
            })
            .collect::<Vec<_>>();
        incoming.sort_by(|(left_id, left_kind), (right_id, right_kind)| {
            let left = graph.node(left_id);
            let right = graph.node(right_id);
            (
                left.map_or("", |node| node.file_path.as_str()),
                left.map_or("", |node| node.symbol_name.as_str()),
                *left_kind,
                left_id,
            )
                .cmp(&(
                    right.map_or("", |node| node.file_path.as_str()),
                    right.map_or("", |node| node.symbol_name.as_str()),
                    *right_kind,
                    right_id,
                ))
        });
        for (dependent_id, kind) in incoming {
            let next_depth = depth + 1;
            if next_depth > max_depth {
                if !visited.contains(&dependent_id) {
                    depth_cutoffs.insert(dependent_id);
                }
                continue;
            }
            if graph.node(&dependent_id).is_none() {
                return Err(invalid_generation(format!(
                    "structural impact references missing node {dependent_id}"
                )));
            }
            if visited.insert(dependent_id) {
                let mut next_path = Vec::with_capacity(path_to_target.len() + 1);
                next_path.push((dependent_id, dependency_id, kind));
                next_path.extend(path_to_target.iter().copied());
                paths.insert(dependent_id, next_path.clone());
                queue.push_back((dependent_id, next_depth, next_path));
            }
        }
    }
    Ok(StructuralTraversal {
        paths,
        depth_cutoff_nodes: depth_cutoffs.len(),
    })
}

pub(crate) const fn structural_impact_kind(kind: EdgeKind) -> Option<StructuralImpactKind> {
    match kind {
        EdgeKind::References => Some(StructuralImpactKind::Reference),
        EdgeKind::TypeOf | EdgeKind::FieldOf => Some(StructuralImpactKind::TypeUse),
        EdgeKind::Implements => Some(StructuralImpactKind::Implementation),
        EdgeKind::Extends => Some(StructuralImpactKind::Inheritance),
        EdgeKind::Calls
        | EdgeKind::Contains
        | EdgeKind::DependsOn
        | EdgeKind::HasImpl
        | EdgeKind::RelatedTo => None,
    }
}

fn cached_structural_symbol(
    cache: &mut BTreeMap<Uuid, StructuralSymbol>,
    graph: &KnowledgeGraph,
    node: &GraphNode,
    generation: &ResolvedGeneration,
) -> Result<StructuralSymbol, DomainError> {
    if let Some(symbol) = cache.get(&node.memory_id) {
        return Ok(symbol.clone());
    }
    let symbol = structural_symbol(graph, node, generation)?;
    cache.insert(node.memory_id, symbol.clone());
    Ok(symbol)
}

fn materialize_structural_path(
    path: &[(Uuid, Uuid, StructuralImpactKind)],
    cache: &mut BTreeMap<Uuid, StructuralSymbol>,
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
) -> Result<Vec<StructuralImpactStep>, DomainError> {
    path.iter()
        .map(|(dependent_id, dependency_id, relation)| {
            let dependent = graph.node(dependent_id).ok_or_else(|| {
                invalid_generation(format!("structural dependent {dependent_id} disappeared"))
            })?;
            let dependency = graph.node(dependency_id).ok_or_else(|| {
                invalid_generation(format!("structural dependency {dependency_id} disappeared"))
            })?;
            Ok(StructuralImpactStep {
                dependent: cached_structural_symbol(cache, graph, dependent, generation)?,
                dependency: cached_structural_symbol(cache, graph, dependency, generation)?,
                relation: *relation,
            })
        })
        .collect()
}

fn minimum_depth(impact: &ImpactAccumulator) -> usize {
    impact
        .execution_path
        .as_ref()
        .map(Vec::len)
        .into_iter()
        .chain(impact.structural_path.as_ref().map(Vec::len))
        .min()
        .unwrap_or(0)
}

fn crosses_project_units(target: &StructuralSymbol, items: &[ImpactedSymbol]) -> bool {
    let target_units = target.project_unit_ids.iter().collect::<BTreeSet<_>>();
    items.iter().any(|item| {
        item.symbol
            .project_unit_ids
            .iter()
            .any(|unit| !target_units.contains(unit))
    })
}

fn assess_request_digest(
    request: &AssessRequest,
    resolved_symbol_id: &str,
    file: Option<String>,
) -> String {
    let sections = request
        .sections
        .iter()
        .map(|section| section.as_str())
        .collect::<Vec<_>>()
        .join(",");
    request_digest(
        "assess",
        &[
            resolved_symbol_id,
            file.as_deref().unwrap_or_default(),
            sections.as_str(),
            &request.max_depth.to_string(),
            &format!("{:?}", request.filter),
        ],
    )
}

fn assess_warnings(
    generation: &ResolvedGeneration,
    structural_complete: bool,
    calls_applicability: Option<AssessApplicability>,
    execution: Option<&ExecutionEvidence>,
    structural_depth_cutoff_nodes: usize,
    filtered_out_symbols: usize,
    qualified_binding_symbols: usize,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if generation.project_inventory.coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationPartial
    {
        warnings.push(format!(
            "project inventory is partial and reports {} issue(s); impact is limited to the published source-owner population",
            generation.project_inventory.issues.len()
        ));
    }
    if !structural_complete {
        warnings.push(
            "structural authority is incomplete for the target language; structural zeroes and totals are qualified"
                .into(),
        );
    }
    match calls_applicability {
        None => warnings.push(
            "non-callable impact is limited to observed structural edges; provider-backed reference authority is unavailable for this symbol class, so zeroes and totals are qualified"
                .into(),
        ),
        Some(AssessApplicability::NotApplicable) => warnings.push(
            "the callable is structurally indexed source data without a semantic project execution unit, so Calls-backed callers, execution impact, and runnable-test discovery do not apply; structural impact remains available"
                .into(),
        ),
        Some(AssessApplicability::Applicable) if execution.is_none() => warnings.push(
            "Calls evidence is unavailable for the target language; structural impact remains available, while callers, execution impact, runnable tests, and semantic risk populations are unknown"
                .into(),
        ),
        Some(AssessApplicability::Applicable) => {}
    }
    if let Some(warning) = execution.and_then(|execution| execution.warning.clone()) {
        warnings.push(warning);
    }
    if let Some(execution) = execution
        && execution.depth_cutoff_nodes > 0
    {
        warnings.push(format!(
            "{} provider execution-path node(s) exist beyond the requested depth boundary",
            execution.depth_cutoff_nodes
        ));
    }
    if qualified_binding_symbols > 0 {
        warnings.push(format!(
            "{qualified_binding_symbols} affected symbol(s) are connected through provider-resolved callable-value assignments; those are qualified possible-dispatch paths, not exact invocation records"
        ));
    }
    if structural_depth_cutoff_nodes > 0 {
        warnings.push(format!(
            "{structural_depth_cutoff_nodes} structural dependent node(s) exist beyond the requested depth boundary"
        ));
    }
    if filtered_out_symbols > 0 {
        warnings.push(format!(
            "the reachability filter excluded {filtered_out_symbols} observed affected symbol(s)"
        ));
    }
    warnings
}

fn invalid_request(field: &'static str, reason: impl Into<String>) -> DomainError {
    DomainError::InvalidRequest {
        operation: "assess",
        field,
        reason: reason.into(),
    }
}

const fn invalid_generation(reason: String) -> DomainError {
    DomainError::PublishedGenerationInvalid { reason }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::code_intel_domain::{
        CapabilityReceipt, CapabilityScope, ConfigurationId, DocumentMembership,
        DocumentMembershipKind, EcosystemId, ProjectInventory, ProjectUnit, ProjectUnitId,
        ProjectUnitKind, RepositoryId, STRUCTURAL_GRAPH_CONFIGURATION_ID,
    };
    use crate::code_intel_publication::{GenerationManifest, PublicationHead, PublicationHeadBody};
    use crate::graph::{GraphEdge, SourceSpan};
    use crate::project_binding::ProjectBindingOptions;

    struct StructuralFixture {
        _temporary: TempDir,
        binding: ProjectBinding,
        graph: KnowledgeGraph,
        generation: ResolvedGeneration,
    }

    fn structural_node(name: &str, kind: &str, line: usize) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: kind.into(),
            file_path: "src/lib.rs".into(),
            content_hash: format!("hash-{name}"),
            signature: format!("{kind} {name}"),
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
        }
    }

    fn structural_fixture() -> StructuralFixture {
        let temporary = TempDir::new().expect("temporary directory");
        let root = temporary.path().join("repo");
        let graph_dir = temporary.path().join("bundle");
        std::fs::create_dir_all(root.join("src")).expect("source root");
        std::fs::create_dir_all(&graph_dir).expect("graph directory");
        std::fs::write(root.join("src/lib.rs"), b"fixture source").expect("source fixture");
        let binding = ProjectBinding::resolve(
            ProjectBindingOptions::new(&root)
                .explicit_root(&root)
                .global_graph_dir(&graph_dir),
        )
        .expect("project binding");

        let mut graph = KnowledgeGraph::new();
        let target = structural_node("Target", "struct", 0);
        let target_id = target.memory_id;
        let direct = structural_node("use_target", "function", 1);
        let direct_id = direct.memory_id;
        let transitive = structural_node("outer", "function", 2);
        let transitive_id = transitive.memory_id;
        let navigation_only = structural_node("TargetTrait", "trait", 3);
        let navigation_only_id = navigation_only.memory_id;
        for (node, start) in [
            (target, 0),
            (direct, 20),
            (transitive, 40),
            (navigation_only, 60),
        ] {
            let id = node.memory_id;
            graph.add_node(node).expect("structural node");
            graph
                .set_source_span(
                    id,
                    SourceSpan {
                        start_byte: start,
                        end_byte: start + 10,
                    },
                )
                .expect("source span");
        }
        graph
            .add_edge(
                direct_id,
                target_id,
                GraphEdge {
                    kind: EdgeKind::References,
                    ..GraphEdge::default()
                },
            )
            .expect("direct structural dependency");
        graph
            .add_edge(
                transitive_id,
                direct_id,
                GraphEdge {
                    kind: EdgeKind::References,
                    ..GraphEdge::default()
                },
            )
            .expect("transitive structural dependency");
        graph
            .add_edge(
                navigation_only_id,
                target_id,
                GraphEdge {
                    kind: EdgeKind::HasImpl,
                    ..GraphEdge::default()
                },
            )
            .expect("navigation-only inverse");

        let project_unit_id = ProjectUnitId::new("rust:fixture");
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: crate::code_intel_domain::ProjectTopology {
                units: vec![ProjectUnit {
                    project_unit_id: project_unit_id.clone(),
                    language_id: crate::code_intel_domain::LanguageId::new("rust"),
                    ecosystem_id: EcosystemId::new("cargo"),
                    kind: ProjectUnitKind::Package,
                    root_path: String::new(),
                    manifest_path: None,
                    compilation_root_paths: Vec::new(),
                }],
                memberships: vec![DocumentMembership {
                    document_path: "src/lib.rs".into(),
                    language_id: crate::code_intel_domain::LanguageId::new("rust"),
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
        };
        let structural_receipt = CapabilityReceipt::complete(
            "structural_graph",
            "fixture-structural",
            "1.0.0",
            CapabilityScope::Repository {
                configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
            },
            "a".repeat(64),
        );
        let repository_id = RepositoryId::new("repository-fixture");
        let generation_id = GenerationId::new("generation-a");
        let generation = ResolvedGeneration {
            slot: 0,
            head: PublicationHead {
                body: PublicationHeadBody {
                    schema_version: "h00/code-intel/head/v4".into(),
                    sequence: 1,
                    repository_id: repository_id.clone(),
                    generation_id: generation_id.clone(),
                    database_blake3: "1".repeat(64),
                    manifest_sha256: "2".repeat(64),
                    receipt_set_sha256: "3".repeat(64),
                    provider_payload_set_sha256: "4".repeat(64),
                    previous_generation_id: None,
                },
                digest: "5".repeat(64),
            },
            manifest: GenerationManifest {
                schema_version: "h00/code-intel/generation/v6".into(),
                generation_id,
                repository_id,
                parent_generation_id: None,
                source_revision: Some("fixture".into()),
                payload_blake3: "6".repeat(64),
                graph_publication_proof: crate::graph_store::GraphPublicationProof::test_fixture(),
                index_state_publication_proof:
                    crate::index_state::IndexStatePublicationProof::test_fixture(),
                project_inventory_sha256: "7".repeat(64),
                receipts: vec![structural_receipt],
                provider_payloads: Vec::new(),
            },
            project_inventory: inventory.into(),
            provider_payloads: Vec::new(),
            database_path: PathBuf::from("generation.redb"),
        };
        StructuralFixture {
            _temporary: temporary,
            binding,
            graph,
            generation,
        }
    }

    #[test]
    fn structural_impact_projection_classifies_every_edge_kind_without_navigation_inverses() {
        assert_eq!(
            structural_impact_kind(EdgeKind::References),
            Some(StructuralImpactKind::Reference)
        );
        assert_eq!(
            structural_impact_kind(EdgeKind::TypeOf),
            Some(StructuralImpactKind::TypeUse)
        );
        assert_eq!(
            structural_impact_kind(EdgeKind::FieldOf),
            Some(StructuralImpactKind::TypeUse)
        );
        assert_eq!(
            structural_impact_kind(EdgeKind::Implements),
            Some(StructuralImpactKind::Implementation)
        );
        assert_eq!(
            structural_impact_kind(EdgeKind::Extends),
            Some(StructuralImpactKind::Inheritance)
        );
        assert_eq!(structural_impact_kind(EdgeKind::Calls), None);
        assert_eq!(structural_impact_kind(EdgeKind::Contains), None);
        assert_eq!(structural_impact_kind(EdgeKind::DependsOn), None);
        assert_eq!(structural_impact_kind(EdgeKind::HasImpl), None);
        assert_eq!(structural_impact_kind(EdgeKind::RelatedTo), None);
    }

    #[test]
    fn request_validation_rejects_silent_clamps_empty_sections_and_unpaged_cursors() {
        let mut request = AssessRequest::new("target");
        request.max_depth = MAX_ASSESS_DEPTH + 1;
        assert!(matches!(
            validate_assess_request(&request),
            Err(DomainError::InvalidRequest { field: "depth", .. })
        ));

        request.max_depth = DEFAULT_ASSESS_DEPTH;
        request.sections.clear();
        assert!(matches!(
            validate_assess_request(&request),
            Err(DomainError::InvalidRequest {
                field: "sections",
                ..
            })
        ));

        request.sections.insert(AssessSection::Risk);
        request.cursor = Some("opaque".into());
        assert!(matches!(
            validate_assess_request(&request),
            Err(DomainError::InvalidRequest {
                field: "cursor",
                ..
            })
        ));
        assert!(matches!(
            parse_assess_filter("maybe"),
            Err(DomainError::InvalidRequest {
                field: "filter",
                ..
            })
        ));
        assert!(matches!(
            parse_assess_section("everything"),
            Err(DomainError::InvalidRequest {
                field: "sections",
                ..
            })
        ));
    }

    #[test]
    fn non_callable_targets_report_transitive_structural_impact_without_inventing_callers() {
        let fixture = structural_fixture();
        let mut request = AssessRequest::new("Target");
        request.filter = CallerFilter::All;
        let result = query_published_assess(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &request,
        )
        .expect("structural Assess query");

        assert!(!result.resolved_symbol.callable);
        assert!(result.resolved_symbol.call_identity.is_none());
        assert_eq!(result.authority.status, AuthorityStatus::Qualified);
        assert!(!result.authority.population_complete);
        assert!(result.authority.exact_calls.is_none());
        let blast = result.blast_radius.expect("blast radius");
        assert!(!blast.population_complete);
        assert_eq!(blast.observed_affected_symbols, 2);
        assert_eq!(blast.observed_execution_affected_symbols, 0);
        assert_eq!(blast.observed_structural_affected_symbols, 2);
        assert_eq!(
            blast
                .items
                .iter()
                .map(|item| (item.symbol.name.as_str(), item.minimum_depth))
                .collect::<Vec<_>>(),
            vec![("use_target", 1), ("outer", 2)]
        );
        assert!(
            blast
                .items
                .iter()
                .all(|item| item.execution_path.is_none() && item.structural_path.is_some())
        );
        let callers = result.callers.expect("callers section");
        assert_eq!(callers.applicability, AssessApplicability::NotApplicable);
        assert_eq!(callers.observed_direct_callers, None);
        let tests = result.tests.expect("tests section");
        assert_eq!(tests.applicability, AssessApplicability::NotApplicable);
        assert_eq!(tests.observed_runnable_test_roots, None);
        let signals = result.risk.expect("review signals");
        assert_eq!(signals.observed_structural_dependents, 2);
        assert_eq!(signals.observed_direct_callers, None);
        assert!(!signals.population_complete);
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("non-callable") && warning.contains("reference authority")
        }));
    }

    #[test]
    fn auxiliary_callable_retains_structural_assess_without_inventing_calls() {
        let mut fixture = structural_fixture();
        let target_id = fixture
            .graph
            .node_by_name("Target")
            .expect("target node")
            .memory_id;
        let target = fixture.graph.node_mut(&target_id).expect("mutable target");
        target.kind = "function".into();
        target.signature = "fn Target()".into();
        std::sync::Arc::make_mut(&mut fixture.generation.project_inventory)
            .project_topology
            .units[0]
            .kind = ProjectUnitKind::AuxiliarySources;

        let mut request = AssessRequest::new("Target");
        request.filter = CallerFilter::All;
        let result = query_published_assess(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &request,
        )
        .expect("auxiliary callable keeps structural Assess evidence");

        assert!(result.resolved_symbol.callable);
        assert!(result.resolved_symbol.call_identity.is_none());
        assert_eq!(
            result.authority.calls.status,
            CapabilityCoverageStatus::NotApplicable
        );
        assert_eq!(result.authority.status, AuthorityStatus::Qualified);
        let blast = result.blast_radius.expect("blast radius");
        assert_eq!(blast.observed_execution_affected_symbols, 0);
        assert_eq!(blast.observed_structural_affected_symbols, 2);
        assert!(!blast.population_complete);
        assert_eq!(
            result.callers.expect("callers facet").applicability,
            AssessApplicability::NotApplicable
        );
        assert_eq!(
            result.tests.expect("tests facet").applicability,
            AssessApplicability::NotApplicable
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("without a semantic project execution unit"))
        );
    }

    #[test]
    fn structural_depth_boundary_qualifies_the_population_instead_of_hiding_dependents() {
        let fixture = structural_fixture();
        let mut request = AssessRequest::new("Target");
        request.filter = CallerFilter::All;
        request.max_depth = 1;
        let result = query_published_assess(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &request,
        )
        .expect("depth-bounded structural Assess query");
        let blast = result.blast_radius.expect("blast radius");
        assert_eq!(blast.observed_affected_symbols, 1);
        assert_eq!(blast.items[0].symbol.name, "use_target");
        assert_eq!(blast.structural_depth_cutoff_nodes, 1);
        assert!(!blast.population_complete);
        assert_eq!(result.authority.status, AuthorityStatus::Qualified);
        assert!(result.risk.expect("review signals").depth_boundary_reached);
    }
}
