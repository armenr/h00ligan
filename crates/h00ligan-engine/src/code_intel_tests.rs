//! Exact test-root reachability over one immutable provider-backed Calls graph.
//!
//! `tests` answers which runnable test entries reach a callable through exact
//! provider-resolved invocations and explicitly qualified callable-value
//! assignments. It does not consult the legacy graph relationship population,
//! treat every test-only helper as a runnable test, or let CLI and MCP invent
//! independent truncation and authority semantics.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::code_intel_calls::{
    CallablePathStep, ExactCapabilityAuthority, PublishedCallsGraph, resolve_invocation_target,
    resolve_invocation_target_indexed,
};
use crate::code_intel_cursor::{page_window, request_digest};
use crate::code_intel_domain::{
    AuthorityStatus, CapabilityCoverage, CapabilityCoverageStatus, DomainError, GenerationId,
    LIVE_INPUT_RESULT_RESERVE_CHARS, Page, ProjectInventoryCoverage, RepositoryBinding,
    SymbolIdentity, UnitGraph, assess_structural_graph_capability,
};
use crate::code_intel_inventory::project_unit_graph;
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{
    generation_scope_selector, language_id_for_path, repository_binding,
};
use crate::code_intel_query_index::GenerationQueryIndex;
use crate::graph::KnowledgeGraph;
use crate::project_binding::ProjectBinding;

pub const TESTS_SCHEMA_VERSION: &str = "h00/code-intel/tests/v2";
pub const DEFAULT_TESTS_PAGE_SIZE: usize = 50;
pub const MAX_TESTS_PAGE_SIZE: usize = 100;
pub const MAX_TESTS_SYMBOL_BYTES: usize = 4_096;
pub const MAX_TESTS_FILE_BYTES: usize = 4_096;
pub const MAX_TESTS_CURSOR_BYTES: usize = 8_192;
pub const MAX_TESTS_RESULT_CHARS: usize = 28_000;
pub const MAX_TESTS_CALL_DEPTH: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestsRequest {
    pub symbol: String,
    pub file: Option<String>,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl TestsRequest {
    #[must_use]
    pub fn new(symbol: impl Into<String>) -> Self {
        Self {
            symbol: symbol.into(),
            file: None,
            limit: DEFAULT_TESTS_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestsQuery {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub limit: usize,
    pub max_call_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestRootPopulation {
    PersistedStructuralTestRootsReachableThroughProviderExecutionPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestsAuthority {
    pub status: AuthorityStatus,
    pub population: TestRootPopulation,
    pub calls: ExactCapabilityAuthority,
    pub structural_graph: CapabilityCoverage,
    pub project_inventory_coverage: ProjectInventoryCoverage,
    pub max_call_depth: usize,
    pub traversal_complete: bool,
    pub population_complete: bool,
    pub qualified_path_count: usize,
    pub depth_cutoff_nodes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactTestReference {
    pub test: SymbolIdentity,
    /// Ordered from the runnable test entry toward the queried target.
    pub chain: Vec<CallablePathStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactTestsResult {
    pub schema_version: String,
    pub capability: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub unit_graph: UnitGraph,
    pub query: TestsQuery,
    pub resolved_symbol: SymbolIdentity,
    pub authority: TestsAuthority,
    pub items: Vec<ExactTestReference>,
    pub page: Page,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn validate_tests_request(request: &TestsRequest) -> Result<(), DomainError> {
    if request.symbol.trim().is_empty() {
        return Err(invalid_request("symbol", "must not be empty"));
    }
    if request.symbol.len() > MAX_TESTS_SYMBOL_BYTES {
        return Err(invalid_request(
            "symbol",
            format!("must be at most {MAX_TESTS_SYMBOL_BYTES} UTF-8 bytes"),
        ));
    }
    if let Some(file) = request.file.as_deref() {
        if file.trim().is_empty() {
            return Err(invalid_request("file", "must not be empty"));
        }
        if file.len() > MAX_TESTS_FILE_BYTES {
            return Err(invalid_request(
                "file",
                format!("must be at most {MAX_TESTS_FILE_BYTES} UTF-8 bytes"),
            ));
        }
    }
    if !(1..=MAX_TESTS_PAGE_SIZE).contains(&request.limit) {
        return Err(invalid_request(
            "limit",
            format!("must be between 1 and {MAX_TESTS_PAGE_SIZE}"),
        ));
    }
    if request
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_TESTS_CURSOR_BYTES)
    {
        return Err(invalid_request(
            "cursor",
            format!("must be at most {MAX_TESTS_CURSOR_BYTES} UTF-8 bytes"),
        ));
    }
    Ok(())
}

pub fn query_published_tests(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &TestsRequest,
) -> Result<ExactTestsResult, DomainError> {
    query_published_tests_with_index(None, graph, generation, binding, request)
}

pub fn query_published_tests_indexed(
    index: &GenerationQueryIndex,
    binding: &ProjectBinding,
    request: &TestsRequest,
) -> Result<ExactTestsResult, DomainError> {
    query_published_tests_with_index(
        Some(index),
        index.graph(),
        index.generation(),
        binding,
        request,
    )
}

fn query_published_tests_with_index(
    index: Option<&GenerationQueryIndex>,
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &TestsRequest,
) -> Result<ExactTestsResult, DomainError> {
    validate_tests_request(request)?;
    let file = request
        .file
        .as_deref()
        .map(|file| generation_scope_selector(binding, file))
        .transpose()?;
    if let Some(file) = file.as_deref()
        && !graph.all_nodes().iter().any(|node| node.file_path == file)
    {
        return Err(DomainError::SourcePath(format!(
            "{} is not an indexed source file in this generation",
            request.file.as_deref().unwrap_or(file)
        )));
    }
    let target = match index {
        Some(index) => {
            resolve_invocation_target_indexed(index, binding, &request.symbol, file.as_deref())?
        }
        None => {
            resolve_invocation_target(graph, generation, binding, &request.symbol, file.as_deref())?
        }
    };
    let target_language = language_id_for_path(&target.file_path);
    let calls = match index {
        Some(index) => index.calls_for_target(&target_language, target)?,
        None => std::sync::Arc::new(PublishedCallsGraph::build_for_target(
            graph,
            generation,
            &target_language,
            target,
        )?),
    };
    let resolved_symbol = calls.node(graph, target)?.identity.clone();

    let mut tests = BTreeMap::<String, ExactTestReference>::new();
    let traversal = calls.reverse_reachable(graph, target, MAX_TESTS_CALL_DEPTH)?;
    for path in &traversal.paths {
        if path.caller_is_test_root {
            tests.insert(
                path.caller.symbol_id.clone(),
                ExactTestReference {
                    test: path.caller.clone(),
                    chain: path.chain.clone(),
                },
            );
        }
    }

    let all_items = tests.into_values().collect::<Vec<_>>();
    let qualified_path_count = all_items
        .iter()
        .filter(|item| item.chain.iter().any(CallablePathStep::is_qualified))
        .count();
    let calls_authority = calls.authority();
    let structural_graph = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let structural_classification_complete = structural_graph.language_status(&target_language.0)
        == Some(CapabilityCoverageStatus::Complete);
    let inventory_complete = generation.project_inventory.coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationComplete;
    let traversal_complete = traversal.depth_cutoff_nodes == 0;
    let population_complete = calls_authority.status == AuthorityStatus::Complete
        && structural_classification_complete
        && inventory_complete
        && traversal_complete;
    let authority_status = if population_complete && qualified_path_count == 0 {
        AuthorityStatus::Complete
    } else {
        AuthorityStatus::Qualified
    };
    let digest = tests_request_digest(&resolved_symbol.symbol_id);
    let base_warnings = {
        let mut warnings = Vec::new();
        if let Some(warning) = calls.coverage_warning() {
            warnings.push(warning);
        }
        if !structural_classification_complete {
            warnings.push(format!(
                "structural authority for {} is incomplete; persisted test-root classifications cannot support a complete zero",
                target_language.0
            ));
        }
        if !inventory_complete {
            warnings.push(
                "project inventory is partial; test-root totals are limited to the published source-owner population"
                    .into(),
            );
        }
        if !traversal_complete {
            warnings.push(format!(
                "{} non-test execution-path node(s) reached the maximum provider execution-path depth of {}; additional test roots may exist beyond this boundary",
                traversal.depth_cutoff_nodes,
                MAX_TESTS_CALL_DEPTH
            ));
        }
        if qualified_path_count > 0 {
            warnings.push(format!(
                "{qualified_path_count} runnable test path(s) include provider-resolved callable-value assignments; those paths are qualified possible dispatch, not exact invocation-only chains"
            ));
        }
        warnings
    };

    let mut smallest_result_chars = 0;
    for effective_limit in (1..=request.limit).rev() {
        let window = page_window(
            "tests",
            &generation.manifest.generation_id,
            &digest,
            request.cursor.as_deref(),
            effective_limit,
            all_items.len(),
        )?;
        let items = all_items[window.range.clone()].to_vec();
        let mut warnings = base_warnings.clone();
        if effective_limit < request.limit && window.page.returned == effective_limit {
            warnings.push(format!(
                "serialized-result bounds reduced this page from the requested ceiling of {} to {} test roots",
                request.limit, effective_limit
            ));
        }
        if window.page.has_more {
            warnings.push(format!(
                "showing {} of {} test roots in this page; continue with next_cursor",
                window.page.returned, window.page.total_items
            ));
        }
        let mut projected_documents = Vec::new();
        for item in &items {
            projected_documents.push(item.test.document_path.as_str());
            for step in &item.chain {
                projected_documents.push(step.source().document_path.as_str());
                projected_documents.push(step.target().document_path.as_str());
            }
        }
        projected_documents.push(&resolved_symbol.document_path);
        let result = ExactTestsResult {
            schema_version: TESTS_SCHEMA_VERSION.into(),
            capability: "tests".into(),
            generation_id: generation.manifest.generation_id.clone(),
            repository: repository_binding(binding, generation),
            unit_graph: project_unit_graph(&generation.project_inventory, projected_documents),
            query: TestsQuery {
                symbol: request.symbol.clone(),
                file: file.clone(),
                limit: request.limit,
                max_call_depth: MAX_TESTS_CALL_DEPTH,
            },
            resolved_symbol: resolved_symbol.clone(),
            authority: TestsAuthority {
                status: authority_status.clone(),
                population:
                    TestRootPopulation::PersistedStructuralTestRootsReachableThroughProviderExecutionPaths,
                calls: calls_authority.clone(),
                structural_graph: structural_graph.clone(),
                project_inventory_coverage: generation.project_inventory.coverage,
                max_call_depth: MAX_TESTS_CALL_DEPTH,
                traversal_complete,
                population_complete,
                qualified_path_count,
                depth_cutoff_nodes: traversal.depth_cutoff_nodes,
            },
            items,
            page: window.page,
            warnings,
        };
        let result_chars = serde_json::to_string(&result)
            .map_err(|error| {
                invalid_generation(format!(
                    "serialize Tests result for size validation: {error}"
                ))
            })?
            .chars()
            .count();
        smallest_result_chars = result_chars;
        if result_chars <= MAX_TESTS_RESULT_CHARS - LIVE_INPUT_RESULT_RESERVE_CHARS {
            return Ok(result);
        }
    }
    Err(invalid_request(
        "symbol",
        format!(
            "even a one-item Tests page would contain {smallest_result_chars} serialized characters and cannot leave room for required live-input evidence within the {MAX_TESTS_RESULT_CHARS}-character product bound; query a closer target or reduce call-chain depth"
        ),
    ))
}

pub(crate) fn tests_request_digest(resolved_symbol_id: &str) -> String {
    request_digest(
        "tests",
        &[
            resolved_symbol_id,
            "persisted_structural_test_roots",
            &MAX_TESTS_CALL_DEPTH.to_string(),
        ],
    )
}

fn invalid_request(field: &'static str, reason: impl Into<String>) -> DomainError {
    DomainError::InvalidRequest {
        operation: "tests",
        field,
        reason: reason.into(),
    }
}

const fn invalid_generation(reason: String) -> DomainError {
    DomainError::PublishedGenerationInvalid { reason }
}
