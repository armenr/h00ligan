//! Bounded source materialization for one symbol in an immutable generation.
//!
//! The generation supplies symbol selection, source span, and indexed-source
//! authority. The live worktree supplies bytes only when the selected span's
//! BLAKE3 digest still matches the published definition. CLI and MCP adapters
//! serialize this same cursor-paged result.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::code_intel_cursor::{page_window, request_digest};
use crate::code_intel_domain::{
    AuthorityStatus, CapabilityCoverage, CapabilityCoverageStatus, ConfigurationId,
    DocumentMembershipKind, DomainError, GenerationId, LIVE_INPUT_RESULT_RESERVE_CHARS, LanguageId,
    Page, ProjectInventoryCoverage, ProjectUnitId, RepositoryBinding,
    STRUCTURAL_GRAPH_CONFIGURATION_ID, SourceSpan, assess_structural_graph_capability,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{generation_file_context, language_id_for_path, repository_binding};
use crate::code_intel_symbol::{
    NameFileSelection, exact_symbol_id, is_exact_symbol_selector, resolve_symbol_selector,
};
use crate::edge_builder::{qualified_name, source_symbol_ids};
use crate::extractor::extract_source;
use crate::graph::{GraphNode, KnowledgeGraph};
use crate::index_state::FileRecord;
use crate::indexed_source_authority::validate_indexed_source_records;
use crate::project_binding::{ProjectBinding, ProjectPathError};
use crate::source_materialization::{
    SourceMaterializationError, materialize_source_from_file, read_source_file,
};
use crate::structural_ir::CodeSymbol;

pub const READ_SCHEMA_VERSION: &str = "h00/code-intel/read/v1";
pub const DEFAULT_READ_PAGE_SIZE: usize = 8_000;
pub const MAX_READ_PAGE_SIZE: usize = 20_000;
pub const MAX_READ_SYMBOL_BYTES: usize = 4_096;
pub const MAX_READ_FILE_BYTES: usize = 4_096;
pub const MAX_READ_CURSOR_BYTES: usize = 8_192;
/// Leaves room below the MCP transport's final 30,000-character ceiling.
pub const MAX_READ_RESULT_CHARS: usize = 28_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub symbol: String,
    pub file: Option<String>,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl ReadRequest {
    pub fn new(symbol: impl Into<String>) -> Self {
        Self {
            symbol: symbol.into(),
            file: None,
            limit: DEFAULT_READ_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadPopulation {
    SelectedPublishedSymbolSourceCharacters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadSelectionScope {
    ExactSymbolId,
    RepositoryGraph,
    ExactFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadSourceConsistency {
    LiveDefinitionHashMatchesGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadIdentityEvidence {
    PublishedGraphPopulation,
    RevalidatedIndexedSourcePopulation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadQuery {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadResolvedSymbol {
    pub symbol_id: String,
    pub name: String,
    pub kind: String,
    pub document_path: String,
    pub language_id: LanguageId,
    pub project_unit_ids: Vec<ProjectUnitId>,
    pub configuration_id: ConfigurationId,
    pub signature: String,
    pub visibility: String,
    pub definition_span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadAuthority {
    pub status: AuthorityStatus,
    pub population: ReadPopulation,
    pub selection_scope: ReadSelectionScope,
    pub source_consistency: ReadSourceConsistency,
    pub structural_graph: CapabilityCoverage,
    pub project_inventory_coverage: ProjectInventoryCoverage,
    pub selected_file_population_complete: bool,
    pub selected_symbol_identity_complete: bool,
    pub identity_evidence: ReadIdentityEvidence,
    pub whole_file_matches_generation: bool,
    pub indexed_file_blake3: String,
    pub observed_file_blake3: String,
    pub published_definition_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactReadResult {
    pub schema_version: String,
    pub capability: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub query: ReadQuery,
    pub resolved_symbol: ReadResolvedSymbol,
    pub authority: ReadAuthority,
    pub source: String,
    pub source_span: SourceSpan,
    pub page: Page,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn validate_read_request(request: &ReadRequest) -> Result<(), DomainError> {
    if request.symbol.trim().is_empty() {
        return Err(invalid_request("symbol", "must not be empty"));
    }
    if request.symbol.len() > MAX_READ_SYMBOL_BYTES {
        return Err(invalid_request(
            "symbol",
            format!("must be at most {MAX_READ_SYMBOL_BYTES} UTF-8 bytes"),
        ));
    }
    if let Some(file) = request.file.as_deref() {
        if file.is_empty() {
            return Err(invalid_request("file", "must not be empty"));
        }
        if file.len() > MAX_READ_FILE_BYTES {
            return Err(invalid_request(
                "file",
                format!("must be at most {MAX_READ_FILE_BYTES} UTF-8 bytes"),
            ));
        }
    }
    if !(1..=MAX_READ_PAGE_SIZE).contains(&request.limit) {
        return Err(invalid_request(
            "limit",
            format!("must be between 1 and {MAX_READ_PAGE_SIZE}"),
        ));
    }
    if request
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_READ_CURSOR_BYTES)
    {
        return Err(invalid_request(
            "cursor",
            format!("must be at most {MAX_READ_CURSOR_BYTES} UTF-8 bytes"),
        ));
    }
    Ok(())
}

/// Resolve, verify, and page one exact symbol source slice.
pub async fn query_published_read(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    indexed_sources: Result<&[(String, FileRecord)], &str>,
    request: &ReadRequest,
) -> Result<ExactReadResult, DomainError> {
    validate_read_request(request)?;

    let normalized_file = request
        .file
        .as_deref()
        .map(|file| generation_file_context(binding, file))
        .transpose()?
        .map(|context| context.file_path().to_owned());
    let node = resolve_symbol_selector(
        graph,
        generation,
        &request.symbol,
        normalized_file.as_deref(),
        NameFileSelection::ExactFile,
    )?;
    let normalized_node_path = generation_file_context(binding, &node.file_path)?
        .file_path()
        .to_owned();
    if normalized_node_path != node.file_path {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!(
                "Read target '{}' carries non-canonical document path '{}'",
                node.symbol_name, node.file_path
            ),
        });
    }
    let language_id = language_id_for_path(&node.file_path);
    if language_id.0 == "unknown" {
        return Err(source_authority_unavailable(
            node,
            "target document does not use a registered source language",
        ));
    }

    let indexed_sources = indexed_sources.map_err(|reason| {
        source_authority_unavailable(
            node,
            format!("immutable indexed-source authority is unavailable: {reason}"),
        )
    })?;
    let indexed_sources = validate_indexed_source_records(indexed_sources)?;
    let indexed_file = indexed_sources.get(&node.file_path).ok_or_else(|| {
        source_authority_unavailable(node, "target document has no indexed-source record")
    })?;
    let project_unit_ids = source_owner_ids(generation, &node.file_path, &language_id)?;
    let structural_graph = target_structural_coverage(graph, generation, &language_id)?;
    let language_status = structural_graph
        .language_status(&language_id.0)
        .ok_or_else(|| {
            source_authority_unavailable(node, "target language has no structural receipt")
        })?;
    if language_status == CapabilityCoverageStatus::Unavailable {
        return Err(source_authority_unavailable(
            node,
            "target language has no usable structural evidence",
        ));
    }

    let source_file = read_source_file(binding, node)
        .await
        .map_err(materialization_domain_error)?;
    let observed_file_blake3 = blake3::hash(&source_file.bytes).to_hex().to_string();
    let whole_file_matches_generation = observed_file_blake3 == indexed_file.blake3_hash;
    let identity = validate_selected_identity(
        graph,
        node,
        indexed_file,
        &source_file.bytes,
        whole_file_matches_generation,
    )?;
    let materialized = materialize_source_from_file(graph, node, source_file)
        .map_err(materialization_domain_error)?;
    let total_characters = materialized.source.chars().count();
    let digest = read_request_digest(&request.symbol, normalized_file.as_deref());
    let window = page_window(
        "read",
        &generation.manifest.generation_id,
        &digest,
        request.cursor.as_deref(),
        request.limit,
        total_characters,
    )?;
    let relative_start = byte_offset_for_character(&materialized.source, window.range.start);
    let relative_end = byte_offset_for_character(&materialized.source, window.range.end);
    let source = materialized.source[relative_start..relative_end].to_owned();
    let absolute_start = materialized.span.start_byte + relative_start;
    let absolute_end = materialized.span.start_byte + relative_end;
    let definition_span = source_span(
        &materialized.file_bytes,
        materialized.span.start_byte,
        materialized.span.end_byte,
    )?;
    let source_span = source_span(&materialized.file_bytes, absolute_start, absolute_end)?;

    let selection_complete =
        normalized_file.is_some() || language_status == CapabilityCoverageStatus::Complete;
    let inventory_complete = generation.project_inventory.coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationComplete;
    let status = if selection_complete
        && identity.selected_file_population_complete
        && whole_file_matches_generation
        && (normalized_file.is_some() || inventory_complete)
    {
        AuthorityStatus::Complete
    } else {
        AuthorityStatus::Qualified
    };
    let mut warnings = Vec::new();
    if normalized_file.is_none() && language_status != CapabilityCoverageStatus::Complete {
        warnings.push(format!(
            "Bare-symbol selection is qualified because {language_id} structural coverage is not complete; pass the exact file selector shown by Find when identity matters."
        ));
    }
    if normalized_file.is_none() && !inventory_complete {
        warnings.push(
            "Bare-symbol selection is qualified because the indexed project inventory is partial."
                .into(),
        );
    }
    if !whole_file_matches_generation {
        warnings.push(
            "The selected definition bytes still match the generation, but other bytes in its live file changed; surrounding context and project semantics may differ."
                .into(),
        );
    }
    if !identity.selected_file_population_complete {
        warnings.push(
            "The selected source identity was revalidated against the exact indexed file bytes, but the published graph does not represent that file's complete extracted symbol population; unrelated identities were collapsed."
                .into(),
        );
    }

    let result = ExactReadResult {
        schema_version: READ_SCHEMA_VERSION.into(),
        capability: "structural_graph".into(),
        generation_id: generation.manifest.generation_id.clone(),
        repository: repository_binding(binding, generation),
        query: ReadQuery {
            symbol: request.symbol.clone(),
            file: normalized_file.clone(),
            limit: request.limit,
        },
        resolved_symbol: ReadResolvedSymbol {
            symbol_id: exact_symbol_id(
                &generation.manifest.repository_id,
                &generation.manifest.generation_id,
                node.memory_id,
            ),
            name: node.symbol_name.clone(),
            kind: node.kind.clone(),
            document_path: node.file_path.clone(),
            language_id,
            project_unit_ids,
            configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
            signature: node.signature.clone(),
            visibility: node.visibility.clone(),
            definition_span,
        },
        authority: ReadAuthority {
            status,
            population: ReadPopulation::SelectedPublishedSymbolSourceCharacters,
            selection_scope: if is_exact_symbol_selector(&request.symbol) {
                ReadSelectionScope::ExactSymbolId
            } else if normalized_file.is_some() {
                ReadSelectionScope::ExactFile
            } else {
                ReadSelectionScope::RepositoryGraph
            },
            source_consistency: ReadSourceConsistency::LiveDefinitionHashMatchesGeneration,
            structural_graph,
            project_inventory_coverage: generation.project_inventory.coverage,
            selected_file_population_complete: identity.selected_file_population_complete,
            selected_symbol_identity_complete: true,
            identity_evidence: identity.evidence,
            whole_file_matches_generation,
            indexed_file_blake3: indexed_file.blake3_hash.clone(),
            observed_file_blake3,
            published_definition_blake3: node.content_hash.clone(),
        },
        source,
        source_span,
        page: window.page,
        warnings,
    };
    let result_characters = serde_json::to_string(&result)
        .map_err(|error| DomainError::PublishedGenerationInvalid {
            reason: format!("Read result serialization failed: {error}"),
        })?
        .chars()
        .count();
    if result_characters > MAX_READ_RESULT_CHARS - LIVE_INPUT_RESULT_RESERVE_CHARS {
        return Err(invalid_request(
            "limit",
            format!(
                "result would contain {result_characters} serialized characters and cannot leave room for required live-input evidence within the {MAX_READ_RESULT_CHARS}-character product bound; lower limit"
            ),
        ));
    }
    Ok(result)
}

pub(crate) fn read_request_digest(symbol: &str, normalized_file: Option<&str>) -> String {
    request_digest("read", &[symbol, normalized_file.unwrap_or_default()])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedIdentityAuthority {
    selected_file_population_complete: bool,
    evidence: ReadIdentityEvidence,
}

fn validate_selected_identity(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    indexed_file: &FileRecord,
    file_bytes: &[u8],
    whole_file_matches_generation: bool,
) -> Result<SelectedIdentityAuthority, DomainError> {
    let graph_symbols = graph.nodes_for_file(&node.file_path).len();
    let extracted_symbols = usize::try_from(indexed_file.symbol_count).map_err(|_| {
        DomainError::PublishedGenerationInvalid {
            reason: format!(
                "indexed symbol count for '{}' does not fit this platform",
                node.file_path
            ),
        }
    })?;
    let selected_file_population_complete = graph_symbols == extracted_symbols;

    if selected_file_population_complete {
        return Ok(SelectedIdentityAuthority {
            selected_file_population_complete,
            evidence: ReadIdentityEvidence::PublishedGraphPopulation,
        });
    }
    if !whole_file_matches_generation {
        return Err(source_authority_unavailable(
            node,
            format!(
                "target document published {extracted_symbols} extracted symbols but the graph represents {graph_symbols}, and the live file no longer matches the indexed bytes needed to revalidate this target"
            ),
        ));
    }

    let source = std::str::from_utf8(file_bytes).map_err(|error| {
        DomainError::PublishedGenerationInvalid {
            reason: format!(
                "indexed source '{}' is not valid UTF-8 during Read identity validation: {error}",
                node.file_path
            ),
        }
    })?;
    let extracted = extract_source(source, &node.file_path).map_err(|error| {
        source_authority_unavailable(
            node,
            format!(
                "the current registered extractor cannot reproduce the exact indexed source population: {error}"
            ),
        )
    })?;
    if extracted.file_hash != indexed_file.blake3_hash
        || extracted.symbols.len() != extracted_symbols
    {
        return Err(source_authority_unavailable(
            node,
            format!(
                "the current registered extractor reproduced {} symbols from the exact indexed bytes, but the generation records {extracted_symbols}; publish a fresh generation",
                extracted.symbols.len()
            ),
        ));
    }

    let extracted_ids = source_symbol_ids(&node.file_path, &extracted.symbols);
    let matching = extracted
        .symbols
        .iter()
        .zip(extracted_ids)
        .filter_map(|(symbol, id)| (id == node.memory_id).then_some(symbol))
        .collect::<Vec<_>>();
    let selected = match matching.as_slice() {
        [selected] => *selected,
        [] => {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "selected graph occurrence '{}' in '{}' is absent from the exact indexed source population",
                    node.symbol_name, node.file_path
                ),
            });
        }
        duplicates => {
            return Err(DomainError::SymbolIdentityAmbiguous {
                symbol: node.symbol_name.clone(),
                document_path: node.file_path.clone(),
                candidates: duplicates
                    .iter()
                    .map(|symbol| occurrence_label(&node.file_path, symbol))
                    .collect(),
            });
        }
    };
    let span = graph.source_span(&node.memory_id).ok_or_else(|| {
        DomainError::PublishedGenerationInvalid {
            reason: format!(
                "selected graph symbol '{}' in '{}' has no source span",
                node.symbol_name, node.file_path
            ),
        }
    })?;
    if node.kind != selected.kind.to_string()
        || node.content_hash != selected.content_hash
        || node.signature != selected.signature
        || node.visibility != selected.visibility.to_string()
        || node.line_start != Some(selected.line_range.0)
        || node.line_end != Some(selected.line_range.1)
        || span.start_byte != selected.span.0
        || span.end_byte != selected.span.1
    {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!(
                "selected graph occurrence '{}' in '{}' does not match its exact indexed source occurrence",
                node.symbol_name, node.file_path
            ),
        });
    }

    Ok(SelectedIdentityAuthority {
        selected_file_population_complete,
        evidence: ReadIdentityEvidence::RevalidatedIndexedSourcePopulation,
    })
}

fn occurrence_label(document_path: &str, symbol: &CodeSymbol) -> String {
    format!(
        "{} ({document_path}:{}..{}, {})",
        qualified_name(symbol),
        symbol.span.0,
        symbol.span.1,
        symbol.kind
    )
}

fn source_owner_ids(
    generation: &ResolvedGeneration,
    document_path: &str,
    language_id: &LanguageId,
) -> Result<Vec<ProjectUnitId>, DomainError> {
    let ids = generation
        .project_inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.document_path == document_path
                && membership.language_id == *language_id
                && membership.kind == DocumentMembershipKind::SourceOwner
        })
        .map(|membership| membership.project_unit_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Err(DomainError::ProjectInventoryMismatch {
            document_path: document_path.into(),
            reason: format!("no source-owner membership exists for language {language_id}"),
        });
    }
    for id in &ids {
        if !generation
            .project_inventory
            .project_topology
            .units
            .iter()
            .any(|unit| unit.project_unit_id == *id && unit.language_id == *language_id)
        {
            return Err(DomainError::ProjectInventoryMismatch {
                document_path: document_path.into(),
                reason: format!("source-owner unit {id} is missing or has a different language"),
            });
        }
    }
    Ok(ids)
}

fn target_structural_coverage(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    language_id: &LanguageId,
) -> Result<CapabilityCoverage, DomainError> {
    let mut coverage = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    coverage
        .languages
        .retain(|language| language.language_id == *language_id);
    coverage.status = match coverage.languages.as_slice() {
        [] => CapabilityCoverageStatus::Unavailable,
        [language] => language.status,
        _ => {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "structural authority contains duplicate language rows for {language_id}"
                ),
            });
        }
    };
    Ok(coverage)
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

fn source_span(file_bytes: &[u8], start: usize, end: usize) -> Result<SourceSpan, DomainError> {
    if start > end || end > file_bytes.len() {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!(
                "Read source page span {start}..{end} is outside a {}-byte file",
                file_bytes.len()
            ),
        });
    }
    let (start_line, start_column) = byte_position(file_bytes, start);
    let (end_line, end_column) = byte_position(file_bytes, end);
    Ok(SourceSpan {
        start_byte: start,
        end_byte: end,
        start_line,
        start_column,
        end_line,
        end_column,
    })
}

fn byte_position(file_bytes: &[u8], offset: usize) -> (usize, usize) {
    let prefix = &file_bytes[..offset];
    let line = prefix.iter().filter(|byte| **byte == b'\n').count();
    let column = prefix
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(prefix.len(), |newline| prefix.len() - newline - 1);
    (line, column)
}

fn source_authority_unavailable(node: &GraphNode, reason: impl Into<String>) -> DomainError {
    DomainError::SourceAuthorityUnavailable {
        symbol: node.symbol_name.clone(),
        document_path: node.file_path.clone(),
        reason: reason.into(),
    }
}

fn materialization_domain_error(error: SourceMaterializationError) -> DomainError {
    let code = if matches!(
        error.project_path_error(),
        Some(ProjectPathError::ParentTraversal { .. } | ProjectPathError::Escape { .. })
    ) {
        "source_path_invalid"
    } else {
        error.code()
    };
    DomainError::SourceMaterialization {
        code,
        message: error.to_string(),
    }
}

fn invalid_request(field: &'static str, reason: impl Into<String>) -> DomainError {
    DomainError::InvalidRequest {
        operation: "read",
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_bounds_are_explicit_and_non_vacuous() {
        for limit in [0, MAX_READ_PAGE_SIZE + 1] {
            let mut request = ReadRequest::new("target");
            request.limit = limit;
            assert!(matches!(
                validate_read_request(&request),
                Err(DomainError::InvalidRequest { field: "limit", .. })
            ));
        }
        assert!(validate_read_request(&ReadRequest::new("target")).is_ok());
    }

    #[test]
    fn byte_positions_are_zero_based_utf8_byte_columns() {
        let source = "αβ\nxyz".as_bytes();
        assert_eq!(byte_position(source, 0), (0, 0));
        assert_eq!(byte_position(source, 4), (0, 4));
        assert_eq!(byte_position(source, 5), (1, 0));
        assert_eq!(byte_position(source, source.len()), (1, 3));
    }
}
