//! Honest live-worktree search with generation-bound structural context.
//!
//! Search results are observations of bytes read from the current worktree.
//! An immutable graph may annotate a result only when the persisted whole-file
//! digest for that generation exactly matches the bytes that were searched.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::code_intel_domain::{
    DomainError, GenerationId, LanguageId, MAX_CODE_INTEL_RESULT_CHARS, RepositoryBinding,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::repository_binding;
use crate::graph::KnowledgeGraph;
use crate::graph_query::short_name;
use crate::index_state::FileRecord;
use crate::indexed_source_authority::validate_indexed_source_records;
use crate::project_binding::ProjectBinding;

pub const SOURCE_SEARCH_SCHEMA_VERSION: &str = "h00/code-intel/source-search/v1";
pub const SOURCE_SEARCH_POPULATION: &str = "live_worktree_registered_source_files";
pub const DEFAULT_SOURCE_SEARCH_LIMIT: usize = 50;
pub const MAX_SOURCE_SEARCH_LIMIT: usize = 100;
pub const MAX_SOURCE_SEARCH_CONTEXT_LINES: usize = 10;
pub const MAX_SOURCE_SEARCH_PATTERN_BYTES: usize = 4_096;

/// Bounds and context controls consumed by the filesystem search kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSearchOptions {
    pub max_matches: usize,
    pub max_matches_per_file: usize,
    pub context_lines: usize,
}

impl Default for SourceSearchOptions {
    fn default() -> Self {
        Self {
            max_matches: DEFAULT_SOURCE_SEARCH_LIMIT,
            max_matches_per_file: DEFAULT_SOURCE_SEARCH_LIMIT,
            context_lines: 0,
        }
    }
}

/// One returned matching or context line from exact live file bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSearchRecord {
    pub file_path: String,
    pub line_number: usize,
    pub line_text: String,
    pub is_match: bool,
    pub content_truncated: bool,
}

/// Whole-file identity for bytes successfully searched by the live kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchedSourceFile {
    pub file_path: String,
    pub blake3_hash: String,
}

/// One registered-language file deliberately omitted from the live search.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SkippedSourceFile {
    pub file_path: String,
    pub reason: String,
}

/// Internal search observation. Adapters publish [`ExactSourceSearchResult`],
/// never this authority-free intermediate form.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceSearchReport {
    pub records: Vec<SourceSearchRecord>,
    pub matches_returned: usize,
    pub truncated: bool,
    pub searched_files: Vec<SearchedSourceFile>,
    pub skipped_file_count: usize,
    pub skipped_files: Vec<SkippedSourceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSearchRequest {
    pub pattern: String,
    /// Normalized repository-relative path, or `.` for the repository root.
    pub path: String,
    pub context_lines: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceSearchQuery {
    pub pattern: String,
    pub path: String,
    pub context_lines: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAuthorityKind {
    LiveWorktree,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceSearchAuthority {
    pub kind: SourceAuthorityKind,
    pub population: String,
    pub registered_languages: Vec<LanguageId>,
    /// True only when the walk completed without result truncation or skipped
    /// registered source files.
    pub population_complete: bool,
    pub searched_file_count: usize,
    pub skipped_file_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchGraphContextStatus {
    ExactGenerationMatch,
    SourceChangedSinceGeneration,
    NotIndexedInGeneration,
    IndexedSourceAuthorityUnavailable,
}

impl std::fmt::Display for SearchGraphContextStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ExactGenerationMatch => "exact_generation_match",
            Self::SourceChangedSinceGeneration => "source_changed_since_generation",
            Self::NotIndexedInGeneration => "not_indexed_in_generation",
            Self::IndexedSourceAuthorityUnavailable => "indexed_source_authority_unavailable",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchGraphContextCoverage {
    Complete,
    Qualified,
    Unavailable,
    NotApplicable,
}

impl std::fmt::Display for SearchGraphContextCoverage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Complete => "complete",
            Self::Qualified => "qualified",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not_applicable",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchGraphContextAuthority {
    pub generation_id: GenerationId,
    pub coverage: SearchGraphContextCoverage,
    pub exact_file_count: usize,
    pub changed_file_count: usize,
    pub not_indexed_file_count: usize,
    pub authority_unavailable_file_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactSourceSearchRecord {
    pub file_path: String,
    pub line_number: usize,
    pub line_text: String,
    pub is_match: bool,
    pub content_truncated: bool,
    pub graph_context_status: SearchGraphContextStatus,
    pub containing_symbol: Option<String>,
    pub symbol_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactSourceSearchResult {
    pub schema_version: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub query: SourceSearchQuery,
    pub source_authority: SourceSearchAuthority,
    pub graph_context: SearchGraphContextAuthority,
    /// Matches actually returned. When `truncated` is true, this is not a total.
    pub matches_returned: usize,
    pub records_returned: usize,
    pub truncated: bool,
    pub skipped_files: Vec<SkippedSourceFile>,
    pub results: Vec<ExactSourceSearchRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Reject unsafe work requests before either adapter touches publication state.
pub fn validate_source_search_request(request: &SourceSearchRequest) -> Result<(), DomainError> {
    if request.pattern.is_empty() {
        return Err(DomainError::InvalidRequest {
            operation: "source_search",
            field: "pattern",
            reason: "must not be empty".into(),
        });
    }
    if request.pattern.len() > MAX_SOURCE_SEARCH_PATTERN_BYTES {
        return Err(DomainError::InvalidRequest {
            operation: "source_search",
            field: "pattern",
            reason: format!("must be at most {MAX_SOURCE_SEARCH_PATTERN_BYTES} UTF-8 bytes"),
        });
    }
    regex::Regex::new(&request.pattern).map_err(|error| DomainError::InvalidRequest {
        operation: "source_search",
        field: "pattern",
        reason: format!("invalid regular expression: {error}"),
    })?;
    if !(1..=MAX_SOURCE_SEARCH_LIMIT).contains(&request.limit) {
        return Err(DomainError::InvalidRequest {
            operation: "source_search",
            field: "limit",
            reason: format!("must be between 1 and {MAX_SOURCE_SEARCH_LIMIT}"),
        });
    }
    if request.context_lines > MAX_SOURCE_SEARCH_CONTEXT_LINES {
        return Err(DomainError::InvalidRequest {
            operation: "source_search",
            field: "context_lines",
            reason: format!("must be at most {MAX_SOURCE_SEARCH_CONTEXT_LINES}"),
        });
    }
    Ok(())
}

/// Bind exact live search observations to one immutable graph generation.
pub fn bind_source_search_result(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    indexed_sources: Result<&[(String, FileRecord)], &str>,
    request: SourceSearchRequest,
    report: SourceSearchReport,
) -> Result<ExactSourceSearchResult, DomainError> {
    validate_source_search_request(&request)?;
    let indexed_hashes = match indexed_sources {
        Ok(records) => Some(
            validate_indexed_source_records(records)?
                .into_iter()
                .map(|(path, record)| (path, record.blake3_hash))
                .collect::<BTreeMap<_, _>>(),
        ),
        Err(_) => None,
    };

    let mut file_statuses = BTreeMap::new();
    for searched in &report.searched_files {
        validate_digest(
            "live source observation",
            &searched.file_path,
            &searched.blake3_hash,
        )?;
        if file_statuses.contains_key(&searched.file_path) {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "live source search reported duplicate file '{}'",
                    searched.file_path
                ),
            });
        }
        let status = indexed_hashes.as_ref().map_or(
            SearchGraphContextStatus::IndexedSourceAuthorityUnavailable,
            |indexed| match indexed.get(&searched.file_path) {
                Some(expected) if *expected == searched.blake3_hash => {
                    SearchGraphContextStatus::ExactGenerationMatch
                }
                Some(_) => SearchGraphContextStatus::SourceChangedSinceGeneration,
                None => SearchGraphContextStatus::NotIndexedInGeneration,
            },
        );
        file_statuses.insert(searched.file_path.clone(), status);
    }

    let mut results = Vec::with_capacity(report.records.len());
    for record in report.records {
        let status = file_statuses
            .get(&record.file_path)
            .copied()
            .ok_or_else(|| DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "live source search returned a record for unobserved file '{}'",
                    record.file_path
                ),
            })?;
        let (containing_symbol, symbol_kind) =
            if status == SearchGraphContextStatus::ExactGenerationMatch {
                find_containing_symbol(graph, &record.file_path, record.line_number)
            } else {
                (None, None)
            };
        results.push(ExactSourceSearchRecord {
            file_path: record.file_path,
            line_number: record.line_number,
            line_text: record.line_text,
            is_match: record.is_match,
            content_truncated: record.content_truncated,
            graph_context_status: status,
            containing_symbol,
            symbol_kind,
        });
    }

    let exact_file_count = count_status(
        &file_statuses,
        SearchGraphContextStatus::ExactGenerationMatch,
    );
    let changed_file_count = count_status(
        &file_statuses,
        SearchGraphContextStatus::SourceChangedSinceGeneration,
    );
    let not_indexed_file_count = count_status(
        &file_statuses,
        SearchGraphContextStatus::NotIndexedInGeneration,
    );
    let authority_unavailable_file_count = count_status(
        &file_statuses,
        SearchGraphContextStatus::IndexedSourceAuthorityUnavailable,
    );
    let graph_coverage = if file_statuses.is_empty() {
        SearchGraphContextCoverage::NotApplicable
    } else if exact_file_count == file_statuses.len() {
        SearchGraphContextCoverage::Complete
    } else if exact_file_count > 0 {
        SearchGraphContextCoverage::Qualified
    } else {
        SearchGraphContextCoverage::Unavailable
    };

    let mut warnings = Vec::new();
    if report.truncated {
        warnings.push(
            "search results are truncated; matches_returned is not a repository total".into(),
        );
    }
    if report.skipped_file_count > 0 {
        warnings.push(format!(
            "{} registered source file(s) were skipped; search population is incomplete",
            report.skipped_file_count
        ));
    }
    if matches!(
        graph_coverage,
        SearchGraphContextCoverage::Qualified | SearchGraphContextCoverage::Unavailable
    ) {
        warnings.push(
            "indexed symbol context is withheld for live files whose exact generation bytes cannot be proven"
                .into(),
        );
    }

    let searched_file_count = file_statuses.len();
    let skipped_file_count = report.skipped_file_count;
    let truncated = report.truncated;
    let matches_returned = report.matches_returned;
    let result = ExactSourceSearchResult {
        schema_version: SOURCE_SEARCH_SCHEMA_VERSION.into(),
        generation_id: generation.manifest.generation_id.clone(),
        repository: repository_binding(binding, generation),
        query: SourceSearchQuery {
            pattern: request.pattern,
            path: request.path,
            context_lines: request.context_lines,
            limit: request.limit,
        },
        source_authority: SourceSearchAuthority {
            kind: SourceAuthorityKind::LiveWorktree,
            population: SOURCE_SEARCH_POPULATION.into(),
            registered_languages: crate::language::registered_languages()
                .into_iter()
                .map(LanguageId::new)
                .collect(),
            population_complete: !truncated && skipped_file_count == 0,
            searched_file_count,
            skipped_file_count,
        },
        graph_context: SearchGraphContextAuthority {
            generation_id: generation.manifest.generation_id.clone(),
            coverage: graph_coverage,
            exact_file_count,
            changed_file_count,
            not_indexed_file_count,
            authority_unavailable_file_count,
        },
        matches_returned,
        records_returned: results.len(),
        truncated,
        skipped_files: report.skipped_files,
        results,
        warnings,
    };
    let result_chars = serde_json::to_string(&result)
        .map_err(|error| DomainError::PublishedGenerationInvalid {
            reason: format!("source-search result serialization failed: {error}"),
        })?
        .chars()
        .count();
    if result_chars > MAX_CODE_INTEL_RESULT_CHARS {
        return Err(DomainError::result_too_large(
            "source_search",
            result_chars,
            MAX_CODE_INTEL_RESULT_CHARS,
            "Lower the source-search limit or context_lines, narrow the path, or use a more selective pattern",
        ));
    }
    Ok(result)
}

fn validate_digest(label: &str, path: &str, digest: &str) -> Result<(), DomainError> {
    let path_valid = !path.is_empty()
        && !std::path::Path::new(path).is_absolute()
        && !std::path::Path::new(path)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir));
    let digest_valid = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if !path_valid || !digest_valid {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!("{label} for '{path}' has an invalid path or BLAKE3 digest"),
        });
    }
    Ok(())
}

fn count_status(
    statuses: &BTreeMap<String, SearchGraphContextStatus>,
    expected: SearchGraphContextStatus,
) -> usize {
    statuses
        .values()
        .filter(|status| **status == expected)
        .count()
}

fn find_containing_symbol(
    graph: &KnowledgeGraph,
    file_path: &str,
    line_number: usize,
) -> (Option<String>, Option<String>) {
    if line_number == 0 {
        return (None, None);
    }
    let line = line_number - 1;
    let best = graph
        .nodes_for_file(file_path)
        .into_iter()
        .filter_map(|node| {
            let (Some(start), Some(end)) = (node.line_start, node.line_end) else {
                return None;
            };
            (line >= start && line <= end).then_some((end - start, &node.symbol_name, node))
        })
        .min_by(|left, right| {
            (left.0, left.1, left.2.memory_id).cmp(&(right.0, right.1, right.2.memory_id))
        })
        .map(|(_, _, node)| node);
    best.map_or((None, None), |node| {
        (
            Some(short_name(&node.symbol_name).to_string()),
            Some(node.kind.clone()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn request_bounds_reject_false_empty_and_unbounded_work() {
        let valid = SourceSearchRequest {
            pattern: "needle".into(),
            path: ".".into(),
            context_lines: MAX_SOURCE_SEARCH_CONTEXT_LINES,
            limit: MAX_SOURCE_SEARCH_LIMIT,
        };
        validate_source_search_request(&valid).expect("maximum valid request");

        for invalid in [
            SourceSearchRequest {
                pattern: String::new(),
                ..valid.clone()
            },
            SourceSearchRequest {
                limit: 0,
                ..valid.clone()
            },
            SourceSearchRequest {
                limit: MAX_SOURCE_SEARCH_LIMIT + 1,
                ..valid.clone()
            },
            SourceSearchRequest {
                context_lines: MAX_SOURCE_SEARCH_CONTEXT_LINES + 1,
                ..valid.clone()
            },
            SourceSearchRequest {
                pattern: "x".repeat(MAX_SOURCE_SEARCH_PATTERN_BYTES + 1),
                ..valid
            },
        ] {
            assert!(
                validate_source_search_request(&invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn graph_context_status_order_is_total_for_deterministic_maps() {
        let population = BTreeSet::from([
            SearchGraphContextStatus::ExactGenerationMatch,
            SearchGraphContextStatus::SourceChangedSinceGeneration,
            SearchGraphContextStatus::NotIndexedInGeneration,
            SearchGraphContextStatus::IndexedSourceAuthorityUnavailable,
        ]);
        assert_eq!(population.len(), 4);
    }
}
