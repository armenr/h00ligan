//! Generation-bound structural symbol discovery shared by CLI and MCP.
//!
//! Find searches one immutable graph population. It does not infer semantic
//! liveness, consult live source bytes, or let either transport invent its own
//! mode detection, truncation, or authority claim.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::code_intel_cursor::{page_window, request_digest};
use crate::code_intel_domain::{
    AuthorityStatus, CapabilityCoverage, CapabilityCoverageStatus, DomainError, GenerationId,
    LanguageId, MAX_GENERATION_ENGINE_RESULT_CHARS, Page, ProjectInventoryCoverage,
    RepositoryBinding, assess_structural_graph_capability,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{
    generation_scope_selector, language_id_for_path, repository_binding,
};
use crate::code_intel_type::{StructuralSymbol, structural_symbol};
use crate::graph::KnowledgeGraph;
use crate::graph_query::symbol_not_found_candidates;
use crate::graph_search::{is_path_query, search_by_name, search_by_path};
use crate::project_binding::ProjectBinding;

pub const FIND_SCHEMA_VERSION: &str = "h00/code-intel/find/v1";
pub const DEFAULT_FIND_PAGE_SIZE: usize = 20;
pub const MAX_FIND_PAGE_SIZE: usize = 100;
pub const MAX_FIND_QUERY_BYTES: usize = 4_096;
pub const MAX_FIND_KIND_BYTES: usize = 256;
pub const MAX_FIND_CURSOR_BYTES: usize = 8_192;
/// Leaves headroom below the MCP adapter's final 30,000-character ceiling.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindMode {
    Auto,
    Name,
    Path,
}

impl FindMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Name => "name",
            Self::Path => "path",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindRequest {
    pub query: String,
    pub mode: FindMode,
    pub kind: Option<String>,
    pub definitions_only: bool,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl FindRequest {
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            mode: FindMode::Auto,
            kind: None,
            definitions_only: false,
            limit: DEFAULT_FIND_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindQuery {
    pub value: String,
    pub mode: FindMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub definitions_only: bool,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindPopulation {
    PublishedStructuralGraphSymbols,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindAuthority {
    pub status: AuthorityStatus,
    pub population: FindPopulation,
    pub structural_graph: CapabilityCoverage,
    pub project_inventory_coverage: ProjectInventoryCoverage,
    pub selected_language_ids: Vec<LanguageId>,
    pub selected_file_count: usize,
    pub population_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindSuggestion {
    pub name: String,
    pub distance: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactFindResult {
    pub schema_version: String,
    pub capability: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub query: FindQuery,
    pub authority: FindAuthority,
    pub items: Vec<StructuralSymbol>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<FindSuggestion>,
    pub page: Page,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn validate_find_request(request: &FindRequest) -> Result<(), DomainError> {
    if request.query.trim().is_empty() {
        return Err(invalid_request("query", "must not be empty"));
    }
    if request.query.len() > MAX_FIND_QUERY_BYTES {
        return Err(invalid_request(
            "query",
            format!("must be at most {MAX_FIND_QUERY_BYTES} UTF-8 bytes"),
        ));
    }
    if let Some(kind) = request.kind.as_deref() {
        if kind.trim().is_empty() {
            return Err(invalid_request("kind", "must not be empty"));
        }
        if kind.len() > MAX_FIND_KIND_BYTES {
            return Err(invalid_request(
                "kind",
                format!("must be at most {MAX_FIND_KIND_BYTES} UTF-8 bytes"),
            ));
        }
    }
    if !(1..=MAX_FIND_PAGE_SIZE).contains(&request.limit) {
        return Err(invalid_request(
            "limit",
            format!("must be between 1 and {MAX_FIND_PAGE_SIZE}"),
        ));
    }
    if request
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_FIND_CURSOR_BYTES)
    {
        return Err(invalid_request(
            "cursor",
            format!("must be at most {MAX_FIND_CURSOR_BYTES} UTF-8 bytes"),
        ));
    }
    Ok(())
}

pub fn query_published_find(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &FindRequest,
) -> Result<ExactFindResult, DomainError> {
    validate_find_request(request)?;
    let mode = match request.mode {
        FindMode::Auto if is_path_query(&request.query) => FindMode::Path,
        FindMode::Auto => FindMode::Name,
        explicit => explicit,
    };
    let query = match mode {
        FindMode::Path => generation_scope_selector(binding, &request.query)?,
        FindMode::Name | FindMode::Auto => request.query.clone(),
    };

    let indexed_files = indexed_source_files(graph, generation);
    let selected_files = match mode {
        FindMode::Name => indexed_files,
        FindMode::Path => resolve_path_scope(&indexed_files, &query).ok_or_else(|| {
            DomainError::SourcePath(format!(
                "{} is not an indexed source file or directory in this generation",
                request.query
            ))
        })?,
        FindMode::Auto => unreachable!("auto mode is resolved before querying"),
    };

    let matches = match mode {
        FindMode::Name => search_by_name(
            graph,
            &query,
            request.kind.as_deref(),
            request.definitions_only,
            usize::MAX,
        ),
        FindMode::Path => search_by_path(
            graph,
            &query,
            request.kind.as_deref(),
            request.definitions_only,
            usize::MAX,
        ),
        FindMode::Auto => unreachable!("auto mode is resolved before querying"),
    };
    let items = matches
        .iter()
        .map(|found| {
            graph
                .node(&found.memory_id)
                .ok_or_else(|| DomainError::PublishedGenerationInvalid {
                    reason: format!(
                        "Find match {} is absent from its immutable graph",
                        found.memory_id
                    ),
                })
        })
        .map(|node| node.and_then(|node| structural_symbol(graph, node, generation)))
        .collect::<Result<Vec<_>, _>>()?;

    let request_digest = request_digest(
        "find",
        &[
            query.as_str(),
            mode.as_str(),
            request.kind.as_deref().unwrap_or_default(),
            if request.definitions_only {
                "definitions_only"
            } else {
                "all_structural_rows"
            },
        ],
    );
    let structural_graph = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let selected_language_ids = selected_files
        .iter()
        .map(|path| language_id_for_path(path))
        .filter(|language| language.0 != "unknown")
        .collect::<BTreeSet<_>>();
    let inventory_coverage = generation
        .project_inventory
        .coverage_for_languages(&selected_language_ids);
    let population_complete = inventory_coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationComplete
        && selected_language_ids.iter().all(|language| {
            structural_graph.language_status(&language.0)
                == Some(CapabilityCoverageStatus::Complete)
        });
    let status = if population_complete {
        AuthorityStatus::Complete
    } else {
        AuthorityStatus::Qualified
    };
    let selected_language_ids = selected_language_ids.into_iter().collect::<Vec<_>>();

    let suggestions = if items.is_empty() && mode == FindMode::Name {
        symbol_not_found_candidates(graph, &query)
            .into_iter()
            .map(|(name, distance)| FindSuggestion { name, distance })
            .collect()
    } else {
        Vec::new()
    };
    let mut base_warnings = Vec::new();
    if !population_complete {
        base_warnings.push(
            "Find results are exact within the published graph, but zeroes and totals are not complete for every selected source population"
                .into(),
        );
    }

    // `limit` is a caller-supplied ceiling, not permission to cross the
    // product's serialized-result bound. Select the largest deterministic page
    // at or below that ceiling and make the cursor advance by the exact number
    // actually returned. No row or field is silently truncated.
    let mut smallest_result_chars = 0;
    for effective_limit in (1..=request.limit).rev() {
        let window = page_window(
            "find",
            &generation.manifest.generation_id,
            &request_digest,
            request.cursor.as_deref(),
            effective_limit,
            items.len(),
        )?;
        let mut warnings = base_warnings.clone();
        if effective_limit < request.limit && window.page.returned == effective_limit {
            warnings.push(format!(
                "serialized-result bounds reduced this page from the requested ceiling of {} to {} structural matches",
                request.limit, effective_limit
            ));
        }
        if window.page.has_more {
            warnings.push(format!(
                "showing {} of {} structural matches in this page; continue with next_cursor",
                window.page.returned, window.page.total_items
            ));
        }
        let result = ExactFindResult {
            schema_version: FIND_SCHEMA_VERSION.into(),
            capability: "structural_graph".into(),
            generation_id: generation.manifest.generation_id.clone(),
            repository: repository_binding(binding, generation),
            query: FindQuery {
                value: if query.is_empty() {
                    ".".into()
                } else {
                    query.clone()
                },
                mode,
                kind: request.kind.clone(),
                definitions_only: request.definitions_only,
                limit: request.limit,
            },
            authority: FindAuthority {
                status: status.clone(),
                population: FindPopulation::PublishedStructuralGraphSymbols,
                structural_graph: structural_graph.clone(),
                project_inventory_coverage: inventory_coverage,
                selected_language_ids: selected_language_ids.clone(),
                selected_file_count: selected_files.len(),
                population_complete,
            },
            items: items[window.range.clone()].to_vec(),
            suggestions: suggestions.clone(),
            page: window.page,
            warnings,
        };
        let result_chars = serde_json::to_string(&result)
            .map_err(|error| DomainError::PublishedGenerationInvalid {
                reason: format!("serialize Find result for size validation: {error}"),
            })?
            .chars()
            .count();
        smallest_result_chars = result_chars;
        if result_chars <= MAX_GENERATION_ENGINE_RESULT_CHARS {
            return Ok(result);
        }
    }
    Err(DomainError::result_too_large(
        "find",
        smallest_result_chars,
        MAX_GENERATION_ENGINE_RESULT_CHARS,
        "Narrow the query, kind, or file scope; required Find identity, authority, and unit metadata do not fit even when the page limit is one",
    ))
}

fn indexed_source_files(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
) -> BTreeSet<String> {
    let mut files = generation
        .project_inventory
        .project_topology
        .memberships
        .iter()
        .map(|membership| membership.document_path.clone())
        .collect::<BTreeSet<_>>();
    files.extend(
        graph
            .all_nodes()
            .into_iter()
            .filter(|node| crate::graph_stats::node_language(node).is_some())
            .map(|node| node.file_path.clone()),
    );
    files
}

fn resolve_path_scope(
    indexed_files: &BTreeSet<String>,
    selector: &str,
) -> Option<BTreeSet<String>> {
    if !selector.is_empty() && indexed_files.contains(selector) {
        return Some(std::iter::once(selector.to_owned()).collect());
    }
    let prefix = if selector.is_empty() {
        String::new()
    } else {
        format!("{selector}/")
    };
    let files = indexed_files
        .iter()
        .filter(|file| file.starts_with(&prefix))
        .cloned()
        .collect::<BTreeSet<_>>();
    (!files.is_empty()).then_some(files)
}

fn invalid_request(field: &'static str, reason: impl Into<String>) -> DomainError {
    DomainError::InvalidRequest {
        operation: "find",
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_bounds_are_transport_independent() {
        assert!(validate_find_request(&FindRequest::new("target")).is_ok());

        let mut invalid = FindRequest::new("target");
        invalid.limit = 0;
        assert!(matches!(
            validate_find_request(&invalid),
            Err(DomainError::InvalidRequest { field: "limit", .. })
        ));

        let mut invalid = FindRequest::new(" ");
        invalid.limit = MAX_FIND_PAGE_SIZE;
        assert!(matches!(
            validate_find_request(&invalid),
            Err(DomainError::InvalidRequest { field: "query", .. })
        ));
    }
}
