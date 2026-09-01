//! Bounded multi-facet inspection over one immutable semantic generation.
//!
//! Inspect is a composition surface, not a second implementation of Read,
//! Type, Calls, or Tests. Each requested facet invokes the canonical use case
//! and embeds its typed result. Facets that do not apply or lack authority are
//! explicit, so one useful structural result can never turn an unavailable
//! Calls population into a confident zero.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use regex::Regex;
use serde::Serialize;

use crate::code_intel_assess::{resolve_target, structural_impact_kind};
use crate::code_intel_calls::{
    ExactCallsResult, calls_request_digest, published_node_is_invocation_target,
    published_node_is_invocation_target_indexed,
};
use crate::code_intel_cursor::page_window;
use crate::code_intel_domain::{
    AuthorityStatus, CallerFilter, CallsRequest, CapabilityCoverage, CapabilityCoverageStatus,
    DomainError, GenerationId, MAX_GENERATION_ENGINE_RESULT_CHARS, ProjectInventoryCoverage,
    RepositoryBinding, TypeRequest, UnitGraph, assess_structural_graph_capability,
};
use crate::code_intel_inventory::project_unit_graph;
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{generation_file_context, language_id_for_path, repository_binding};
use crate::code_intel_query_index::GenerationQueryIndex;
use crate::code_intel_read::{
    ExactReadResult, ReadRequest, query_published_read, read_request_digest,
};
use crate::code_intel_tests::{
    ExactTestsResult, TestsRequest, query_published_tests, query_published_tests_indexed,
    tests_request_digest,
};
use crate::code_intel_type::{
    ExactTypeResult, StructuralSymbol, query_published_type, structural_symbol, type_request_digest,
};
use crate::graph::{GraphNode, KnowledgeGraph};
use crate::graph_query::{
    collect_type_children, field_usage_regex_pattern, short_name, strip_comments_and_strings,
};
use crate::index_state::FileRecord;
use crate::project_binding::ProjectBinding;
use crate::reachability::ReachabilityClass;
use crate::source_materialization::materialize_source;
use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

pub const INSPECT_SCHEMA_VERSION: &str = "h00/code-intel/inspect/v3";
pub const MAX_INSPECT_SYMBOL_BYTES: usize = 4_096;
pub const MAX_INSPECT_FILE_BYTES: usize = 4_096;
pub const DEFAULT_INSPECT_PREVIEW_ITEMS: usize = 20;
pub const DEFAULT_INSPECT_SOURCE_CHARACTERS: usize = 4_000;
const MAX_FIELD_USAGE_CANDIDATES_SCANNED: usize = 100;

#[cfg(test)]
std::thread_local! {
    static INSPECT_RESULT_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_inspect_result_builds() {
    INSPECT_RESULT_BUILDS.set(0);
}

#[cfg(test)]
fn inspect_result_builds() -> usize {
    INSPECT_RESULT_BUILDS.get()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectSection {
    Source,
    Structure,
    Callers,
    FieldUsage,
    Tests,
    Warnings,
}

impl InspectSection {
    pub const ALL: [Self; 6] = [
        Self::Source,
        Self::Structure,
        Self::Callers,
        Self::FieldUsage,
        Self::Tests,
        Self::Warnings,
    ];
}

impl FromStr for InspectSection {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "source" => Ok(Self::Source),
            "structure" => Ok(Self::Structure),
            "callers" => Ok(Self::Callers),
            "field_usage" => Ok(Self::FieldUsage),
            "tests" => Ok(Self::Tests),
            "warnings" => Ok(Self::Warnings),
            _ => Err(format!(
                "unknown Inspect section '{value}', expected source, structure, callers, field_usage, tests, or warnings"
            )),
        }
    }
}

pub fn parse_inspect_section(value: &str) -> Result<InspectSection, DomainError> {
    value
        .parse()
        .map_err(|reason| invalid_request("sections", reason))
}

pub fn parse_inspect_sections<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<InspectSection>, DomainError> {
    let mut sections = BTreeSet::new();
    for value in values {
        let section = parse_inspect_section(value)?;
        if !sections.insert(section) {
            return Err(invalid_request(
                "sections",
                format!("duplicate Inspect section '{value}'"),
            ));
        }
    }
    if sections.is_empty() {
        return Err(invalid_request(
            "sections",
            "must contain at least one section",
        ));
    }
    Ok(sections)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectRequest {
    pub symbol: String,
    pub file: Option<String>,
    pub sections: BTreeSet<InspectSection>,
}

impl InspectRequest {
    #[must_use]
    pub fn new(symbol: impl Into<String>) -> Self {
        Self {
            symbol: symbol.into(),
            file: None,
            sections: InspectSection::ALL.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectQuery {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub sections: Vec<InspectSection>,
    pub preview_item_limit: usize,
    pub source_character_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectFacetIssue {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InspectFacet<T> {
    Available { result: T },
    Qualified { result: T },
    NotApplicable { issue: InspectFacetIssue },
    Unavailable { issue: InspectFacetIssue },
}

impl<T> InspectFacet<T> {
    const fn population_complete(&self) -> bool {
        matches!(self, Self::Available { .. } | Self::NotApplicable { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldUsageEvidenceKind {
    LanguagePatternHeuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldUsageAuthority {
    pub status: AuthorityStatus,
    pub evidence_kind: FieldUsageEvidenceKind,
    pub language_id: crate::code_intel_domain::LanguageId,
    pub candidate_population: String,
    pub candidate_dependents: usize,
    pub scanned_dependents: usize,
    pub excluded_dependents: usize,
    pub population_complete: bool,
    pub false_positives_possible: bool,
    pub false_negatives_possible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldUsageObservation {
    pub field: StructuralSymbol,
    pub observed_dependents: usize,
    pub dependents: Vec<StructuralSymbol>,
    pub dependents_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactFieldUsageResult {
    pub authority: FieldUsageAuthority,
    pub total_fields: usize,
    pub returned_fields: usize,
    pub fields_truncated: bool,
    pub items: Vec<FieldUsageObservation>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectReviewSignal {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectReviewResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<ReachabilityClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_tier: Option<String>,
    pub signals: Vec<InspectReviewSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectAuthority {
    pub status: AuthorityStatus,
    pub structural_graph: CapabilityCoverage,
    pub project_inventory_coverage: ProjectInventoryCoverage,
    pub requested_facets_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactInspectResult {
    pub schema_version: String,
    pub capability: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub unit_graph: UnitGraph,
    pub query: InspectQuery,
    pub resolved_symbol: StructuralSymbol,
    pub authority: InspectAuthority,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<InspectFacet<ExactReadResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structure: Option<InspectFacet<ExactTypeResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers: Option<InspectFacet<ExactCallsResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_usage: Option<InspectFacet<ExactFieldUsageResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tests: Option<InspectFacet<ExactTestsResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<InspectFacet<InspectReviewResult>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<String>,
}

pub fn validate_inspect_request(request: &InspectRequest) -> Result<(), DomainError> {
    if request.symbol.trim().is_empty() {
        return Err(invalid_request("symbol", "must not be empty"));
    }
    if request.symbol.len() > MAX_INSPECT_SYMBOL_BYTES {
        return Err(invalid_request(
            "symbol",
            format!("must be at most {MAX_INSPECT_SYMBOL_BYTES} UTF-8 bytes"),
        ));
    }
    if let Some(file) = request.file.as_deref() {
        if file.trim().is_empty() {
            return Err(invalid_request("file", "must not be empty"));
        }
        if file.len() > MAX_INSPECT_FILE_BYTES {
            return Err(invalid_request(
                "file",
                format!("must be at most {MAX_INSPECT_FILE_BYTES} UTF-8 bytes"),
            ));
        }
    }
    if request.sections.is_empty() {
        return Err(invalid_request(
            "sections",
            "must contain at least one section",
        ));
    }
    Ok(())
}

/// Compose a bounded dossier from the canonical per-capability use cases.
pub async fn query_published_inspect(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    indexed_sources: Result<&[(String, FileRecord)], &str>,
    request: &InspectRequest,
) -> Result<ExactInspectResult, DomainError> {
    query_published_inspect_with_index(None, graph, generation, binding, indexed_sources, request)
        .await
}

pub async fn query_published_inspect_indexed(
    index: &GenerationQueryIndex,
    binding: &ProjectBinding,
    indexed_sources: Result<&[(String, FileRecord)], &str>,
    request: &InspectRequest,
) -> Result<ExactInspectResult, DomainError> {
    query_published_inspect_with_index(
        Some(index),
        index.graph(),
        index.generation(),
        binding,
        indexed_sources,
        request,
    )
    .await
}

async fn query_published_inspect_with_index(
    index: Option<&GenerationQueryIndex>,
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    indexed_sources: Result<&[(String, FileRecord)], &str>,
    request: &InspectRequest,
) -> Result<ExactInspectResult, DomainError> {
    validate_inspect_request(request)?;
    let file = request
        .file
        .as_deref()
        .map(|file| generation_file_context(binding, file))
        .transpose()?;
    let normalized_file = file.as_ref().map(|context| context.file_path().to_owned());
    let target = resolve_target(graph, generation, &request.symbol, file)?;
    let resolved_symbol = structural_symbol(graph, target, generation)?;
    if !resolved_symbol.source_backed {
        return Err(invalid_generation(format!(
            "resolved Inspect target {} is not backed by an indexed source document",
            target.symbol_name
        )));
    }

    let full_result = build_inspect_result(
        index,
        graph,
        generation,
        binding,
        indexed_sources,
        request,
        normalized_file.as_deref(),
        target,
        &resolved_symbol,
        DEFAULT_INSPECT_PREVIEW_ITEMS,
        DEFAULT_INSPECT_SOURCE_CHARACTERS,
    )
    .await?;
    let full_result_chars = serialized_inspect_chars(&full_result)?;
    if full_result_chars <= MAX_GENERATION_ENGINE_RESULT_CHARS {
        return Ok(full_result);
    }

    let mut preview_item_limit = DEFAULT_INSPECT_PREVIEW_ITEMS;
    let mut source_character_limit = DEFAULT_INSPECT_SOURCE_CHARACTERS;
    let smallest_result_chars = loop {
        if preview_item_limit > 1 {
            preview_item_limit = (preview_item_limit / 2).max(1);
        } else if source_character_limit > 1 {
            source_character_limit = (source_character_limit / 2).max(1);
        } else {
            break full_result_chars;
        }
        let result = compact_inspect_result(
            &full_result,
            generation,
            preview_item_limit,
            source_character_limit,
        )?;
        let result_chars = serialized_inspect_chars(&result)?;
        if result_chars <= MAX_GENERATION_ENGINE_RESULT_CHARS {
            return Ok(result);
        }
        if preview_item_limit == 1 && source_character_limit == 1 {
            break result_chars;
        }
    };
    Err(DomainError::result_too_large(
        "inspect",
        smallest_result_chars,
        MAX_GENERATION_ENGINE_RESULT_CHARS,
        "Request fewer sections or narrow the symbol/file scope; the minimum Inspect dossier does not fit after every optional preview is reduced",
    ))
}

fn serialized_inspect_chars(result: &ExactInspectResult) -> Result<usize, DomainError> {
    serde_json::to_string(result)
        .map_err(|error| invalid_generation(format!("serialize Inspect result: {error}")))
        .map(|serialized| serialized.chars().count())
}

/// Derive a smaller first-page rendering from one canonical semantic dossier.
///
/// Inspect never exposes an independent nested paging contract. Every nested
/// cursor must remain consumable by its owning Read, Type, Calls, or Tests use
/// case, so compacting regenerates pages under those exact request identities
/// instead of merely truncating serialized vectors.
fn compact_inspect_result(
    full_result: &ExactInspectResult,
    generation: &ResolvedGeneration,
    preview_item_limit: usize,
    source_character_limit: usize,
) -> Result<ExactInspectResult, DomainError> {
    let mut result = full_result.clone();
    result.query.preview_item_limit = preview_item_limit;
    result.query.source_character_limit = source_character_limit;

    if let Some(source) = facet_result_mut(result.source.as_mut()) {
        compact_read_facet(source, source_character_limit)?;
    }
    if let Some(structure) = facet_result_mut(result.structure.as_mut()) {
        compact_type_facet(
            structure,
            generation,
            &result.query.symbol,
            result.query.file.as_deref(),
            preview_item_limit,
        )?;
    }
    if let Some(callers) = facet_result_mut(result.callers.as_mut()) {
        compact_calls_facet(
            callers,
            generation,
            &result.query.symbol,
            result.query.file.as_deref(),
            preview_item_limit,
        )?;
    }
    if let Some(tests) = facet_result_mut(result.tests.as_mut()) {
        compact_tests_facet(tests, generation, preview_item_limit)?;
    }
    if let Some(field_usage) = facet_result_mut(result.field_usage.as_mut()) {
        compact_field_usage_facet(field_usage, preview_item_limit);
    }

    result
        .notices
        .retain(|notice| !notice.starts_with("serialized-result bounds reduced this dossier"));
    result.notices.push(format!(
        "serialized-result bounds reduced this dossier to {preview_item_limit} preview items per collection and {source_character_limit} source characters"
    ));
    Ok(result)
}

const fn facet_result_mut<T>(facet: Option<&mut InspectFacet<T>>) -> Option<&mut T> {
    match facet {
        Some(InspectFacet::Available { result } | InspectFacet::Qualified { result }) => {
            Some(result)
        }
        Some(InspectFacet::NotApplicable { .. } | InspectFacet::Unavailable { .. }) | None => None,
    }
}

fn compact_read_facet(
    result: &mut ExactReadResult,
    requested_limit: usize,
) -> Result<(), DomainError> {
    require_first_page("Read", &result.page)?;
    let effective_limit = requested_limit.min(result.page.limit);
    let digest = read_request_digest(&result.query.symbol, result.query.file.as_deref());
    let window = page_window(
        "read",
        &result.generation_id,
        &digest,
        None,
        effective_limit,
        result.page.total_items,
    )?;
    let end_byte = byte_offset_for_character(&result.source, window.range.end);
    if end_byte > result.source.len() {
        return Err(invalid_generation(
            "Inspect Read preview does not contain its advertised first-page population".into(),
        ));
    }
    result.source.truncate(end_byte);
    result.source_span.end_byte = result.source_span.start_byte + end_byte;
    let newline_count = result.source.bytes().filter(|byte| *byte == b'\n').count();
    result.source_span.end_line = result.source_span.start_line + newline_count;
    result.source_span.end_column = result
        .source
        .as_bytes()
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(result.source_span.start_column + end_byte, |newline| {
            end_byte - newline - 1
        });
    result.query.limit = requested_limit;
    result.page = window.page;
    Ok(())
}

fn compact_type_facet(
    result: &mut ExactTypeResult,
    generation: &ResolvedGeneration,
    symbol: &str,
    file: Option<&str>,
    requested_limit: usize,
) -> Result<(), DomainError> {
    require_first_page("Type", &result.page)?;
    let effective_limit = requested_limit.min(result.page.limit);
    let mut request = TypeRequest::new(symbol);
    request.file = file.map(str::to_owned);
    request.limit = requested_limit;
    let digest = type_request_digest(&request);
    let window = page_window(
        "type",
        &result.generation_id,
        &digest,
        None,
        effective_limit,
        result.page.total_items,
    )?;
    truncate_first_page("Type", &mut result.items, window.range.end)?;
    let mut projected_documents = result
        .items
        .iter()
        .filter(|item| item.symbol.source_backed)
        .map(|item| item.symbol.document_path.as_str())
        .collect::<Vec<_>>();
    projected_documents.push(&result.resolved_type.document_path);
    result.unit_graph = project_unit_graph(&generation.project_inventory, projected_documents);
    result.page = window.page;
    Ok(())
}

fn compact_calls_facet(
    result: &mut ExactCallsResult,
    generation: &ResolvedGeneration,
    symbol: &str,
    file: Option<&str>,
    requested_limit: usize,
) -> Result<(), DomainError> {
    require_first_page("Calls", &result.page)?;
    let effective_limit = requested_limit.min(result.page.limit);
    let mut request = CallsRequest::new(symbol);
    request.file = file.map(str::to_owned);
    request.filter = CallerFilter::All;
    request.limit = requested_limit;
    let digest = calls_request_digest(&request);
    let window = page_window(
        "calls",
        &result.generation_id,
        &digest,
        None,
        effective_limit,
        result.page.total_items,
    )?;
    truncate_first_page("Calls", &mut result.items, window.range.end)?;
    let mut projected_documents = result
        .items
        .iter()
        .map(|item| item.origin.document_path())
        .collect::<Vec<_>>();
    projected_documents.push(&result.resolved_symbol.document_path);
    result.unit_graph = project_unit_graph(&generation.project_inventory, projected_documents);
    result.page = window.page;
    Ok(())
}

fn compact_tests_facet(
    result: &mut ExactTestsResult,
    generation: &ResolvedGeneration,
    requested_limit: usize,
) -> Result<(), DomainError> {
    require_first_page("Tests", &result.page)?;
    let effective_limit = requested_limit.min(result.page.limit);
    let digest = tests_request_digest(&result.resolved_symbol.symbol_id);
    let window = page_window(
        "tests",
        &result.generation_id,
        &digest,
        None,
        effective_limit,
        result.page.total_items,
    )?;
    truncate_first_page("Tests", &mut result.items, window.range.end)?;
    let mut projected_documents = Vec::new();
    for item in &result.items {
        projected_documents.push(item.test.document_path.as_str());
        for step in &item.chain {
            projected_documents.push(step.source_document());
            projected_documents.push(step.target().document_path.as_str());
        }
    }
    projected_documents.push(&result.resolved_symbol.document_path);
    result.unit_graph = project_unit_graph(&generation.project_inventory, projected_documents);
    result.query.limit = requested_limit;
    result.warnings.retain(|warning| {
        !warning.starts_with("serialized-result bounds reduced this page")
            && !(warning.starts_with("showing ")
                && warning.ends_with("test roots in this page; continue with next_cursor"))
    });
    if effective_limit < requested_limit && window.page.returned == effective_limit {
        result.warnings.push(format!(
            "serialized-result bounds reduced this page from the requested ceiling of {requested_limit} to {effective_limit} test roots"
        ));
    }
    if window.page.has_more {
        result.warnings.push(format!(
            "showing {} of {} test roots in this page; continue with next_cursor",
            window.page.returned, window.page.total_items
        ));
    }
    result.page = window.page;
    Ok(())
}

fn compact_field_usage_facet(result: &mut ExactFieldUsageResult, preview_item_limit: usize) {
    result.items.truncate(preview_item_limit);
    for item in &mut result.items {
        item.dependents.truncate(preview_item_limit);
        item.dependents_truncated = item.observed_dependents > item.dependents.len();
    }
    result.returned_fields = result.items.len();
    result.fields_truncated = result.total_fields > result.returned_fields;
}

fn require_first_page(
    operation: &str,
    page: &crate::code_intel_domain::Page,
) -> Result<(), DomainError> {
    if page.offset == 0 {
        Ok(())
    } else {
        Err(invalid_generation(format!(
            "Inspect {operation} facet unexpectedly started at page offset {}",
            page.offset
        )))
    }
}

fn truncate_first_page<T>(
    operation: &str,
    items: &mut Vec<T>,
    new_len: usize,
) -> Result<(), DomainError> {
    if new_len > items.len() {
        return Err(invalid_generation(format!(
            "Inspect {operation} preview contains {} items but its compact page requires {new_len}",
            items.len()
        )));
    }
    items.truncate(new_len);
    Ok(())
}

fn byte_offset_for_character(source: &str, character: usize) -> usize {
    if character == 0 {
        return 0;
    }
    source
        .char_indices()
        .nth(character)
        .map_or(source.len(), |(offset, _)| offset)
}

#[allow(clippy::too_many_arguments)]
async fn build_inspect_result(
    index: Option<&GenerationQueryIndex>,
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    indexed_sources: Result<&[(String, FileRecord)], &str>,
    request: &InspectRequest,
    normalized_file: Option<&str>,
    target: &GraphNode,
    resolved_symbol: &StructuralSymbol,
    preview_item_limit: usize,
    source_character_limit: usize,
) -> Result<ExactInspectResult, DomainError> {
    #[cfg(test)]
    INSPECT_RESULT_BUILDS.set(INSPECT_RESULT_BUILDS.get() + 1);

    let callable = match index {
        Some(index) => published_node_is_invocation_target_indexed(index, target)?,
        None => published_node_is_invocation_target(graph, generation, target)?,
    };
    let source = if request.sections.contains(&InspectSection::Source) {
        let mut read = ReadRequest::new(&request.symbol);
        read.file = normalized_file.map(str::to_owned);
        read.limit = source_character_limit;
        Some(
            match query_published_read(graph, generation, binding, indexed_sources, &read).await {
                Ok(result) => authority_facet(result.authority.status.clone(), result),
                Err(error) => facet_error_or_propagate(error)?,
            },
        )
    } else {
        None
    };

    let structure = if request.sections.contains(&InspectSection::Structure) {
        if structural_node_is_type(target) {
            let mut type_request = TypeRequest::new(&request.symbol);
            type_request.file = normalized_file.map(str::to_owned);
            type_request.limit = preview_item_limit;
            Some(
                match query_published_type(graph, generation, binding, &type_request) {
                    Ok(result) => authority_facet(result.authority.status.clone(), result),
                    Err(error) => facet_error_or_propagate(error)?,
                },
            )
        } else {
            Some(not_applicable_facet(
                "symbol_not_type",
                format!(
                    "{} is a structural {}, so the Type member facet does not apply",
                    target.symbol_name, target.kind
                ),
            ))
        }
    } else {
        None
    };

    let callers = if request.sections.contains(&InspectSection::Callers) {
        if callable {
            let mut calls = CallsRequest::new(&request.symbol);
            calls.file = normalized_file.map(str::to_owned);
            calls.filter = CallerFilter::All;
            calls.limit = preview_item_limit;
            Some(
                match index.map_or_else(
                    || {
                        crate::code_intel_calls::query_published_calls(
                            graph, generation, binding, &calls,
                        )
                    },
                    |index| index.query_calls(binding, &calls),
                ) {
                    Ok(result) => authority_facet(result.authority.status.clone(), result),
                    Err(error) => facet_error_or_propagate(error)?,
                },
            )
        } else {
            Some(not_applicable_facet(
                "symbol_not_callable",
                format!(
                    "{} is a structural {}, so caller reachability does not apply",
                    target.symbol_name, target.kind
                ),
            ))
        }
    } else {
        None
    };

    let tests = if request.sections.contains(&InspectSection::Tests) {
        if callable {
            let mut tests = TestsRequest::new(&request.symbol);
            tests.file = normalized_file.map(str::to_owned);
            tests.limit = preview_item_limit;
            Some(
                match index.map_or_else(
                    || query_published_tests(graph, generation, binding, &tests),
                    |index| query_published_tests_indexed(index, binding, &tests),
                ) {
                    Ok(result) => authority_facet(result.authority.status.clone(), result),
                    Err(error) => facet_error_or_propagate(error)?,
                },
            )
        } else {
            Some(not_applicable_facet(
                "symbol_not_callable",
                format!(
                    "{} is a structural {}, so runnable-test call paths do not apply",
                    target.symbol_name, target.kind
                ),
            ))
        }
    } else {
        None
    };

    let field_usage = if request.sections.contains(&InspectSection::FieldUsage) {
        if symbol_kind_has_role(&target.kind, SymbolRole::FieldContainer) {
            Some(query_field_usage(graph, generation, binding, target, preview_item_limit).await?)
        } else {
            Some(not_applicable_facet(
                "symbol_not_field_container",
                format!(
                    "{} is a structural {}, so field-usage evidence does not apply",
                    target.symbol_name, target.kind
                ),
            ))
        }
    } else {
        None
    };

    let warnings = request
        .sections
        .contains(&InspectSection::Warnings)
        .then(|| review_facet(target, callable, callers.as_ref(), source.as_ref()));

    let structural_graph = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let requested_facets_complete = [
        source.as_ref().map(InspectFacet::population_complete),
        structure.as_ref().map(InspectFacet::population_complete),
        callers.as_ref().map(InspectFacet::population_complete),
        field_usage.as_ref().map(InspectFacet::population_complete),
        tests.as_ref().map(InspectFacet::population_complete),
        warnings.as_ref().map(InspectFacet::population_complete),
    ]
    .into_iter()
    .flatten()
    .all(|complete| complete);
    let target_language = language_id_for_path(&target.file_path);
    let target_structural_complete = structural_graph
        .language_status(&target_language.0)
        .is_some_and(|status| status == CapabilityCoverageStatus::Complete);
    let inventory_coverage = generation
        .project_inventory
        .coverage_for_language(&target_language);
    let inventory_complete =
        inventory_coverage == ProjectInventoryCoverage::IndexedSourcePopulationComplete;
    let status = if requested_facets_complete && target_structural_complete && inventory_complete {
        AuthorityStatus::Complete
    } else {
        AuthorityStatus::Qualified
    };
    let mut notices = Vec::new();
    if preview_item_limit < DEFAULT_INSPECT_PREVIEW_ITEMS
        || source_character_limit < DEFAULT_INSPECT_SOURCE_CHARACTERS
    {
        notices.push(format!(
            "serialized-result bounds reduced this dossier to {preview_item_limit} preview items per collection and {source_character_limit} source characters"
        ));
    }

    Ok(ExactInspectResult {
        schema_version: INSPECT_SCHEMA_VERSION.into(),
        capability: "inspect".into(),
        generation_id: generation.manifest.generation_id.clone(),
        repository: repository_binding(binding, generation),
        unit_graph: project_unit_graph(
            &generation.project_inventory,
            [resolved_symbol.document_path.as_str()],
        ),
        query: InspectQuery {
            symbol: request.symbol.clone(),
            file: normalized_file.map(str::to_owned),
            sections: request.sections.iter().copied().collect(),
            preview_item_limit,
            source_character_limit,
        },
        resolved_symbol: resolved_symbol.clone(),
        authority: InspectAuthority {
            status,
            structural_graph,
            project_inventory_coverage: inventory_coverage,
            requested_facets_complete,
        },
        source,
        structure,
        callers,
        field_usage,
        tests,
        warnings,
        notices,
    })
}

async fn query_field_usage(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    target: &GraphNode,
    preview_item_limit: usize,
) -> Result<InspectFacet<ExactFieldUsageResult>, DomainError> {
    let language_id = language_id_for_path(&target.file_path);
    if !matches!(language_id.0.as_str(), "rust" | "go") {
        return Ok(InspectFacet::Unavailable {
            issue: InspectFacetIssue {
                code: "field_usage_provider_unavailable".into(),
                message: format!(
                    "no bounded field-usage evidence provider is registered for {}",
                    language_id.0
                ),
            },
        });
    }

    let mut fields = collect_type_children(graph, &target.memory_id).fields;
    fields.sort_by(|left, right| {
        (&left.file_path, &left.symbol_name, left.memory_id).cmp(&(
            &right.file_path,
            &right.symbol_name,
            right.memory_id,
        ))
    });
    fields.dedup_by_key(|field| field.memory_id);
    let total_fields = fields.len();
    fields.truncate(preview_item_limit);

    let mut candidate_ids = graph
        .incoming_neighbors(&target.memory_id)
        .into_iter()
        .filter_map(|(node_id, edge)| structural_impact_kind(edge.kind).map(|_| node_id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    candidate_ids.sort_by(|left_id, right_id| {
        let left = graph.node(left_id);
        let right = graph.node(right_id);
        (
            left.map_or("", |node| node.file_path.as_str()),
            left.map_or("", |node| node.symbol_name.as_str()),
            left_id,
        )
            .cmp(&(
                right.map_or("", |node| node.file_path.as_str()),
                right.map_or("", |node| node.symbol_name.as_str()),
                right_id,
            ))
    });
    let candidate_dependents = candidate_ids.len();
    candidate_ids.truncate(MAX_FIELD_USAGE_CANDIDATES_SCANNED);

    let mut patterns = BTreeMap::<String, Regex>::new();
    for field in &fields {
        let name = short_name(&field.symbol_name).to_owned();
        let pattern = match language_id.0.as_str() {
            "rust" => field_usage_regex_pattern(&name),
            "go" => {
                let escaped = regex::escape(&name);
                format!(r"(\.{escaped}\b)|(\b{escaped}\s*:)")
            }
            _ => unreachable!("language was checked above"),
        };
        let regex = Regex::new(&pattern).map_err(|error| {
            invalid_generation(format!(
                "compile {language_id} field-usage pattern for {name}: {error}"
            ))
        })?;
        patterns.insert(name, regex);
    }

    let mut observed = BTreeMap::<String, BTreeMap<String, StructuralSymbol>>::new();
    for name in patterns.keys() {
        observed.insert(name.clone(), BTreeMap::new());
    }
    let mut scanned_dependents = 0usize;
    let mut excluded_dependents =
        candidate_dependents.saturating_sub(MAX_FIELD_USAGE_CANDIDATES_SCANNED);
    for candidate_id in candidate_ids {
        let Some(candidate) = graph.node(&candidate_id) else {
            return Err(invalid_generation(format!(
                "field-usage candidate {candidate_id} disappeared"
            )));
        };
        let materialized = match materialize_source(binding, graph, candidate).await {
            Ok(materialized) => materialized,
            Err(error) if error.project_path_error().is_some() => {
                return Err(invalid_generation(format!(
                    "field-usage candidate {} has an unsafe source path: {error}",
                    candidate.symbol_name
                )));
            }
            Err(_) => {
                excluded_dependents += 1;
                continue;
            }
        };
        scanned_dependents += 1;
        let cleaned = materialized
            .source
            .lines()
            .map(strip_comments_and_strings)
            .collect::<Vec<_>>()
            .join("\n");
        let symbol = structural_symbol(graph, candidate, generation)?;
        for (field_name, pattern) in &patterns {
            if pattern.is_match(&cleaned) {
                observed
                    .get_mut(field_name)
                    .expect("field population initialized")
                    .insert(symbol.symbol_id.clone(), symbol.clone());
            }
        }
    }

    let mut items = Vec::with_capacity(fields.len());
    for field in fields {
        let name = short_name(&field.symbol_name).to_owned();
        let users = observed.remove(&name).unwrap_or_default();
        let observed_dependents = users.len();
        let dependents = users
            .into_values()
            .take(preview_item_limit)
            .collect::<Vec<_>>();
        items.push(FieldUsageObservation {
            field: structural_symbol(graph, &field, generation)?,
            observed_dependents,
            dependents_truncated: observed_dependents > dependents.len(),
            dependents,
        });
    }

    Ok(InspectFacet::Qualified {
        result: ExactFieldUsageResult {
            authority: FieldUsageAuthority {
                status: AuthorityStatus::Qualified,
                evidence_kind: FieldUsageEvidenceKind::LanguagePatternHeuristic,
                language_id,
                candidate_population: "bounded source slices of persisted structural dependents"
                    .into(),
                candidate_dependents,
                scanned_dependents,
                excluded_dependents,
                population_complete: false,
                false_positives_possible: true,
                false_negatives_possible: true,
            },
            total_fields,
            returned_fields: items.len(),
            fields_truncated: total_fields > items.len(),
            items,
            warnings: vec![
                "Field usage is a bounded language-pattern heuristic over structural dependents, not an exact reference census; empty observations are not proof that a field is unused."
                    .into(),
            ],
        },
    })
}

fn review_facet(
    target: &GraphNode,
    callable: bool,
    callers: Option<&InspectFacet<ExactCallsResult>>,
    source: Option<&InspectFacet<ExactReadResult>>,
) -> InspectFacet<InspectReviewResult> {
    let calls_result = callers.and_then(|facet| match facet {
        InspectFacet::Available { result } | InspectFacet::Qualified { result } => Some(result),
        InspectFacet::NotApplicable { .. } | InspectFacet::Unavailable { .. } => None,
    });
    let calls_complete = matches!(
        callers,
        Some(InspectFacet::Available { result })
            if result.authority.status == AuthorityStatus::Complete
    );
    let reachability_observed = callable && calls_result.is_some();
    let has_qualified_binding = calls_result.is_some_and(|calls| calls.callable_value_bindings > 0);
    let reachability = reachability_observed.then_some(target.reachability_class);
    let action_tier =
        calls_complete.then(|| target.reachability_class.action_tier().label().to_owned());
    let mut signals = Vec::new();
    if let Some(reachability) = reachability
        && let Some(message) = crate::graph_query::reachability_warning(reachability)
    {
        signals.push(InspectReviewSignal {
            code: "reachability_review".into(),
            message: message.into(),
        });
    }
    if let Some(calls) = calls_result
        && calls.authority.status == AuthorityStatus::Complete
        && calls.total_callers == 0
    {
        signals.push(InspectReviewSignal {
            code: "no_exact_callers".into(),
            message:
                "No exact provider-resolved callers were observed in the authorized population"
                    .into(),
        });
    }
    if let Some(calls) = calls_result
        && calls.callable_value_bindings > 0
    {
        signals.push(InspectReviewSignal {
            code: "qualified_callable_value_binding".into(),
            message: format!(
                "{} provider-resolved callable-value assignment(s) target this symbol; they establish qualified possible dispatch and impact, not exact direct calls",
                calls.callable_value_bindings
            ),
        });
    }
    if callable && calls_result.is_some() && !calls_complete {
        signals.push(InspectReviewSignal {
            code: "calls_authority_qualified".into(),
            message: "Observed reachability is retained from qualified Calls evidence, but the action tier is withheld until Calls authority is complete".into(),
        });
    }
    if callable && calls_result.is_none() {
        signals.push(InspectReviewSignal {
            code: "reachability_evidence_unavailable".into(),
            message:
                "Reachability and action tier are withheld because exact Calls evidence is unavailable"
                    .into(),
        });
    } else if !callable {
        signals.push(InspectReviewSignal {
            code: "reachability_not_authorized".into(),
            message:
                "Reachability and action tier are withheld because Inspect has no exact reachability contract for non-callable symbols"
                    .into(),
        });
    }
    if target.signature.is_empty() && !matches!(target.kind.as_str(), "module" | "use") {
        signals.push(InspectReviewSignal {
            code: "signature_unavailable".into(),
            message: "No indexed signature is available for this symbol".into(),
        });
    }
    if target.line_start.is_none() {
        signals.push(InspectReviewSignal {
            code: "source_span_unavailable".into(),
            message: "No indexed source range is available for this symbol".into(),
        });
    }
    if matches!(source, Some(InspectFacet::Unavailable { .. })) {
        signals.push(InspectReviewSignal {
            code: "source_unavailable".into(),
            message: "The requested source preview could not be materialized from current bytes"
                .into(),
        });
    }
    let result = InspectReviewResult {
        reachability,
        action_tier,
        signals,
    };
    if reachability_observed && calls_complete && !has_qualified_binding {
        InspectFacet::Available { result }
    } else {
        InspectFacet::Qualified { result }
    }
}

const fn authority_facet<T>(status: AuthorityStatus, result: T) -> InspectFacet<T> {
    match status {
        AuthorityStatus::Complete => InspectFacet::Available { result },
        AuthorityStatus::Qualified => InspectFacet::Qualified { result },
    }
}

fn facet_error_or_propagate<T>(error: DomainError) -> Result<InspectFacet<T>, DomainError> {
    match error {
        error @ DomainError::CapabilityNotApplicable { .. } => {
            let envelope = error.envelope();
            Ok(InspectFacet::NotApplicable {
                issue: InspectFacetIssue {
                    code: envelope.error.code.into(),
                    message: envelope.error.message,
                },
            })
        }
        error @ (DomainError::CapabilityUnavailable { .. }
        | DomainError::CapabilityAmbiguous { .. }
        | DomainError::SymbolOutsideProviderCoverage { .. }
        | DomainError::SymbolOutsideProviderPopulation { .. }
        | DomainError::SourceAuthorityUnavailable { .. }
        | DomainError::SourceMaterialization {
            code: "source_read_failed",
            ..
        }) => {
            let envelope = error.envelope();
            Ok(InspectFacet::Unavailable {
                issue: InspectFacetIssue {
                    code: envelope.error.code.into(),
                    message: envelope.error.message,
                },
            })
        }
        integrity_or_request_error => Err(integrity_or_request_error),
    }
}

fn not_applicable_facet<T>(code: impl Into<String>, message: impl Into<String>) -> InspectFacet<T> {
    InspectFacet::NotApplicable {
        issue: InspectFacetIssue {
            code: code.into(),
            message: message.into(),
        },
    }
}

fn structural_node_is_type(node: &GraphNode) -> bool {
    symbol_kind_has_role(&node.kind, SymbolRole::Type)
}

fn invalid_request(field: &'static str, reason: impl Into<String>) -> DomainError {
    DomainError::InvalidRequest {
        operation: "inspect",
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

    #[test]
    fn section_parser_rejects_unknown_and_duplicate_values() {
        let sections =
            parse_inspect_sections(["source", "callers", "tests"]).expect("valid Inspect sections");
        assert_eq!(sections.len(), 3);
        assert!(sections.contains(&InspectSection::Source));
        assert!(sections.contains(&InspectSection::Callers));
        assert!(sections.contains(&InspectSection::Tests));

        for (values, expected) in [
            (vec!["source", "source"], "duplicate"),
            (vec!["source", "everything"], "unknown"),
        ] {
            let error = parse_inspect_sections(values).expect_err("invalid section population");
            assert!(matches!(
                error,
                DomainError::InvalidRequest {
                    operation: "inspect",
                    field: "sections",
                    ..
                }
            ));
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn request_validation_rejects_empty_identity_and_section_populations() {
        let mut request = InspectRequest::new("target");
        request.symbol.clear();
        assert!(matches!(
            validate_inspect_request(&request),
            Err(DomainError::InvalidRequest {
                operation: "inspect",
                field: "symbol",
                ..
            })
        ));

        request.symbol = "target".into();
        request.sections.clear();
        assert!(matches!(
            validate_inspect_request(&request),
            Err(DomainError::InvalidRequest {
                operation: "inspect",
                field: "sections",
                ..
            })
        ));
    }

    #[test]
    fn only_evidence_absence_can_degrade_one_inspect_facet() {
        let unavailable: InspectFacet<()> =
            facet_error_or_propagate(DomainError::CapabilityUnavailable {
                capability: "calls".into(),
                reason: "provider was not requested".into(),
                scopes: Vec::new(),
                evidence: Vec::new(),
            })
            .expect("missing capability evidence can be isolated to one facet");
        assert!(matches!(
            unavailable,
            InspectFacet::Unavailable {
                issue: InspectFacetIssue { ref code, .. }
            } if code == "capability_unavailable"
        ));
        let missing_source: InspectFacet<()> =
            facet_error_or_propagate(DomainError::SourceMaterialization {
                code: "source_read_failed",
                message: "source file is temporarily unavailable".into(),
            })
            .expect("an unreadable current source may leave structural facets useful");
        assert!(matches!(missing_source, InspectFacet::Unavailable { .. }));

        for error in [
            DomainError::PublishedGenerationInvalid {
                reason: "mismatched provider payload".into(),
            },
            DomainError::ProjectInventoryMismatch {
                document_path: "src/lib.rs".into(),
                reason: "document is absent from the sealed inventory".into(),
            },
            DomainError::SourceMaterialization {
                code: "source_changed_since_indexing",
                message: "source bytes no longer match the generation".into(),
            },
        ] {
            let result: Result<InspectFacet<()>, _> = facet_error_or_propagate(error);
            assert!(
                result.is_err(),
                "generation and inventory contradictions must abort the whole dossier"
            );
        }
    }

    /// RIGHT-REASON REGRESSION for B07: a qualified Calls facet can retain
    /// useful observed reachability, but it cannot authorize an unqualified
    /// review facet or a deletion-oriented action tier.
    #[test]
    fn review_inherits_calls_qualification_and_withholds_action_tier() {
        let fixture = crate::code_intel_calls::tests::fixture(&[]);
        let index = GenerationQueryIndex::new(
            std::sync::Arc::new(fixture.graph.clone()),
            std::sync::Arc::new(fixture.generation.clone()),
        );
        let calls = index
            .query_calls(&fixture.binding, &CallsRequest::new("target"))
            .expect("complete Calls positive control");
        assert_eq!(calls.authority.status, AuthorityStatus::Complete);
        let qualified_callers = InspectFacet::Qualified { result: calls };
        let target = fixture.graph.node_by_name("target").expect("target node");

        let review = review_facet(target, true, Some(&qualified_callers), None);
        let InspectFacet::Qualified { result } = review else {
            panic!("qualified Calls must produce a qualified review facet")
        };
        assert!(
            result.reachability.is_some(),
            "qualified positive evidence remains useful"
        );
        assert!(
            result.action_tier.is_none(),
            "qualified negative authority cannot authorize an action tier"
        );
        assert!(result.signals.iter().any(|signal| {
            signal.code == "calls_authority_qualified" && signal.message.contains("action tier")
        }));
    }

    /// Right-reason RED: serialized bounding may retry cheap rendering, but it
    /// must not rerun the semantic facet population. The fixture makes both
    /// Calls and Tests nonempty so the initial 20-item dossier crosses the
    /// bound; the current loop invokes `build_inspect_result` again.
    #[tokio::test]
    async fn bounded_inspect_executes_expensive_facets_once() {
        let caller_names = (0..40)
            .map(|index| {
                format!("caller_{index:02}_with_a_deliberately_verbose_symbol_name_for_bounds")
            })
            .collect::<Vec<_>>();
        let caller_refs = caller_names.iter().map(String::as_str).collect::<Vec<_>>();
        let mut fixture = crate::code_intel_calls::tests::fixture(&caller_refs);
        for caller_name in &caller_names {
            let caller_id = fixture
                .graph
                .node_by_name(caller_name)
                .expect("fixture caller")
                .memory_id;
            let caller = fixture.graph.node_mut(&caller_id).expect("mutable caller");
            caller.is_test_root = true;
            caller.is_test_only = Some(true);
        }
        let index = GenerationQueryIndex::new(
            std::sync::Arc::new(fixture.graph.clone()),
            std::sync::Arc::new(fixture.generation.clone()),
        );
        let mut request = InspectRequest::new("target");
        request.sections = [InspectSection::Callers, InspectSection::Tests]
            .into_iter()
            .collect();
        reset_inspect_result_builds();

        let result = query_published_inspect_indexed(
            &index,
            &fixture.binding,
            Err("source facet not requested"),
            &request,
        )
        .await
        .expect("bounded Inspect dossier");
        assert!(
            result.query.preview_item_limit < DEFAULT_INSPECT_PREVIEW_ITEMS,
            "positive oversized-dossier control: {result:?}"
        );
        assert!(
            serialized_inspect_chars(&result).expect("serialized bounded dossier")
                <= MAX_GENERATION_ENGINE_RESULT_CHARS,
            "successful Inspect output must satisfy its transport reserve"
        );
        assert_eq!(
            inspect_result_builds(),
            1,
            "Inspect must execute semantic facets once and bound an owned result afterward"
        );

        let (calls_cursor, calls_offset) = match result.callers.as_ref() {
            Some(InspectFacet::Available { result } | InspectFacet::Qualified { result }) => (
                result
                    .page
                    .next_cursor
                    .clone()
                    .expect("bounded Calls continuation"),
                result.page.returned,
            ),
            other => panic!("expected bounded Calls facet, got {other:?}"),
        };
        let mut calls_request = CallsRequest::new("target");
        calls_request.filter = CallerFilter::All;
        calls_request.limit = 3;
        calls_request.cursor = Some(calls_cursor);
        let calls_continuation = index
            .query_calls(&fixture.binding, &calls_request)
            .expect("Inspect Calls cursor must be owned by canonical Calls paging");
        assert_eq!(calls_continuation.page.offset, calls_offset);

        let (tests_cursor, tests_offset) = match result.tests.as_ref() {
            Some(InspectFacet::Available { result } | InspectFacet::Qualified { result }) => (
                result
                    .page
                    .next_cursor
                    .clone()
                    .expect("bounded Tests continuation"),
                result.page.returned,
            ),
            other => panic!("expected bounded Tests facet, got {other:?}"),
        };
        let mut tests_request = TestsRequest::new("target");
        tests_request.limit = 3;
        tests_request.cursor = Some(tests_cursor);
        let tests_continuation =
            query_published_tests_indexed(&index, &fixture.binding, &tests_request)
                .expect("Inspect Tests cursor must be owned by canonical Tests paging");
        assert_eq!(tests_continuation.page.offset, tests_offset);
    }
}
