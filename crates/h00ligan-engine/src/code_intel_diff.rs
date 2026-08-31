//! Generation-bound symbol diff against a bounded live-worktree observation.
//!
//! The immutable generation is the baseline. Candidate source bytes are read
//! once per file from the current worktree; a repository-wide observation is
//! deliberately not presented as one atomic filesystem snapshot. This module
//! owns the versioned result and authority language shared by CLI and MCP.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::code_intel_domain::{
    CapabilityCoverage, CapabilityCoverageStatus, DocumentMembershipKind, DomainError,
    GenerationId, ProjectInventoryCoverage, RepositoryBinding, assess_structural_graph_capability,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::repository_binding;
use crate::diff::{
    DiffExclusionReason, DiffExclusionSummary, DiffObservation, FileDiff, SymbolDiff, diff_bound,
};
use crate::graph::KnowledgeGraph;
use crate::index_state::IndexedSourceSnapshot;
use crate::indexed_source_authority::validate_indexed_source_records;
use crate::project_binding::ProjectBinding;

pub const DIFF_SCHEMA_VERSION: &str = "h00/code-intel/diff/v1";
pub const DIFF_BASELINE_POPULATION: &str = "published_structural_symbols";
pub const DIFF_CANDIDATE_POPULATION: &str = "live_worktree_registered_source_files_in_scope";
pub const DEFAULT_DIFF_LIMIT: usize = 50;
pub const MAX_DIFF_LIMIT: usize = 100;
pub const MAX_DIFF_PATH_BYTES: usize = 4_096;
/// Keep successful results below the MCP adapter's final 30,000-character
/// ceiling so transport never replaces a valid diff with a generic cap error.
pub const MAX_DIFF_RESULT_CHARS: usize = 28_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRequest {
    pub path: Option<String>,
    pub limit: usize,
}

impl Default for DiffRequest {
    fn default() -> Self {
        Self {
            path: None,
            limit: DEFAULT_DIFF_LIMIT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffScopeKind {
    Repository,
    File,
}

impl std::fmt::Display for DiffScopeKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Repository => "repository",
            Self::File => "file",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffQuery {
    pub path: String,
    pub scope_kind: DiffScopeKind,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffAuthorityStatus {
    Complete,
    Qualified,
}

impl std::fmt::Display for DiffAuthorityStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Complete => "complete",
            Self::Qualified => "qualified",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffBaselineKind {
    ImmutableGenerationStructuralGraph,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffBaselineAuthority {
    pub kind: DiffBaselineKind,
    pub population: String,
    pub structural_graph: CapabilityCoverage,
    pub project_inventory_coverage: ProjectInventoryCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffCandidateKind {
    LiveWorktree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffCandidateConsistency {
    PerFileReadNonAtomic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffCandidateAuthority {
    pub kind: DiffCandidateKind,
    pub population: String,
    pub consistency: DiffCandidateConsistency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffComparisonAuthority {
    pub coverage_complete: bool,
    pub files_considered: usize,
    pub files_compared: usize,
    pub files_excluded: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<DiffExclusionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffAuthority {
    pub status: DiffAuthorityStatus,
    pub baseline: DiffBaselineAuthority,
    pub candidate: DiffCandidateAuthority,
    pub comparison: DiffComparisonAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffVerdict {
    SymbolDifferencesObserved,
    NoSymbolDifferences,
    Unknown,
}

impl std::fmt::Display for DiffVerdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SymbolDifferencesObserved => "symbol_differences_observed",
            Self::NoSymbolDifferences => "no_symbol_differences",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactDiffResult {
    pub schema_version: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub query: DiffQuery,
    pub authority: DiffAuthority,
    pub verdict: DiffVerdict,
    pub files_considered: usize,
    pub files_compared: usize,
    pub files_excluded: usize,
    pub files_with_symbol_changes: usize,
    pub total_added: usize,
    pub total_removed: usize,
    pub total_modified: usize,
    pub changes_total: usize,
    pub changes_returned: usize,
    pub truncated: bool,
    pub files: Vec<FileDiff>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Reject false-empty and unbounded requests before either adapter loads a
/// publication or starts filesystem work.
pub fn validate_diff_request(request: &DiffRequest) -> Result<(), DomainError> {
    if !(1..=MAX_DIFF_LIMIT).contains(&request.limit) {
        return Err(DomainError::InvalidRequest {
            operation: "diff",
            field: "limit",
            reason: format!("must be between 1 and {MAX_DIFF_LIMIT}"),
        });
    }
    if let Some(path) = request.path.as_deref() {
        if path.is_empty() {
            return Err(DomainError::InvalidRequest {
                operation: "diff",
                field: "path",
                reason: "must not be empty".into(),
            });
        }
        if path.len() > MAX_DIFF_PATH_BYTES {
            return Err(DomainError::InvalidRequest {
                operation: "diff",
                field: "path",
                reason: format!("must be at most {MAX_DIFF_PATH_BYTES} UTF-8 bytes"),
            });
        }
        let path_value = std::path::Path::new(path);
        if path_value.is_absolute()
            || !path_value
                .components()
                .any(|component| matches!(component, std::path::Component::Normal(_)))
            || path_value.components().any(|component| {
                !matches!(
                    component,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            })
        {
            return Err(DomainError::InvalidRequest {
                operation: "diff",
                field: "path",
                reason: "must be a project-relative file path without parent traversal".into(),
            });
        }
    }
    Ok(())
}

/// Execute the one live symbol-diff use case shared by CLI and MCP.
pub fn query_live_diff(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    indexed_sources: Result<&IndexedSourceSnapshot, &str>,
    request: DiffRequest,
) -> Result<ExactDiffResult, DomainError> {
    validate_diff_request(&request)?;
    let published_source_files = generation
        .project_inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
        .filter(|membership| {
            std::path::Path::new(&membership.document_path)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(crate::language::is_registered_extension)
        })
        .map(|membership| membership.document_path.clone())
        .collect::<BTreeSet<_>>();
    let indexed_source_authority = match indexed_sources {
        Ok(authority) => authority,
        Err(reason) => {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!("diff requires immutable indexed-source authority: {reason}"),
            });
        }
    };
    let indexed_sources = validate_indexed_source_records(indexed_source_authority.files())?;
    let indexed_paths = indexed_sources.keys().cloned().collect::<BTreeSet<_>>();
    let document_fact_paths = indexed_source_authority.document_fact_paths();
    for path in &published_source_files {
        validate_relative_path(path)?;
    }
    for path in document_fact_paths {
        validate_relative_path(path)?;
    }
    if let Some(path) = indexed_paths.difference(&published_source_files).next() {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!(
                "diff indexed source '{path}' is absent from the published project inventory"
            ),
        });
    }
    if let Some(path) = document_fact_paths
        .difference(&published_source_files)
        .next()
    {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!(
                "diff document facts source '{path}' is absent from the published project inventory"
            ),
        });
    }
    if let Some(path) = document_fact_paths.difference(&indexed_paths).next() {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!(
                "diff document facts source '{path}' is absent from indexed-source authority"
            ),
        });
    }
    let baseline_exclusions = published_source_files
        .difference(document_fact_paths)
        .map(|path| (path.clone(), DiffExclusionReason::BaselineSourceNotIndexed))
        .collect::<BTreeMap<_, _>>();
    if let Some(path) = graph
        .all_nodes()
        .into_iter()
        .map(|node| node.file_path.as_str())
        .filter(|path| {
            std::path::Path::new(path)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(crate::language::is_registered_extension)
        })
        .find(|path| !indexed_sources.contains_key(*path))
    {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!(
                "structural graph source '{path}' is absent from indexed-source authority"
            ),
        });
    }
    let observation = diff_bound(
        graph,
        binding,
        &indexed_sources,
        &baseline_exclusions,
        request.path.as_deref().map(std::path::Path::new),
    )
    .map_err(|error| DomainError::CandidateObservationFailed {
        operation: "diff",
        reason: error.to_string(),
    })?;
    bind_diff_result(graph, generation, binding, request, observation)
}

fn bind_diff_result(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: DiffRequest,
    observation: DiffObservation,
) -> Result<ExactDiffResult, DomainError> {
    validate_diff_request(&request)?;
    validate_observation(&observation)?;

    let structural_graph = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let comparison_coverage_complete = observation.exclusions.is_empty()
        && observation.files_compared == observation.files_considered;
    let baseline_complete = matches!(
        structural_graph.status,
        CapabilityCoverageStatus::Complete | CapabilityCoverageStatus::NotApplicable
    ) && generation.project_inventory.coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationComplete;
    let authority_status = if baseline_complete && comparison_coverage_complete {
        DiffAuthorityStatus::Complete
    } else {
        DiffAuthorityStatus::Qualified
    };

    let total_added = observation
        .files
        .iter()
        .map(|file| file.diff.added.len())
        .sum();
    let total_removed = observation
        .files
        .iter()
        .map(|file| file.diff.removed.len())
        .sum();
    let total_modified = observation
        .files
        .iter()
        .map(|file| file.diff.modified.len())
        .sum();
    let changes_total = total_added + total_removed + total_modified;
    let (files, changes_returned) = bound_files(&observation.files, request.limit);
    let truncated = changes_returned < changes_total;
    let verdict = if changes_total > 0 {
        DiffVerdict::SymbolDifferencesObserved
    } else if authority_status == DiffAuthorityStatus::Complete {
        DiffVerdict::NoSymbolDifferences
    } else {
        DiffVerdict::Unknown
    };
    let mut warnings = Vec::new();
    if !baseline_complete {
        warnings.push(
            "the immutable structural baseline is incomplete; observed differences remain useful, but an empty observation cannot prove that live source matches the generation"
                .into(),
        );
    }
    if !comparison_coverage_complete {
        warnings.push(format!(
            "{} of {} source files were excluded from comparison; inspect authority.comparison.exclusions for the bounded reason census",
            observation.files_considered - observation.files_compared,
            observation.files_considered
        ));
    }

    let files_excluded = observation.files_considered - observation.files_compared;

    let result = ExactDiffResult {
        schema_version: DIFF_SCHEMA_VERSION.into(),
        generation_id: generation.manifest.generation_id.clone(),
        repository: repository_binding(binding, generation),
        query: DiffQuery {
            path: observation.scope_path,
            scope_kind: if request.path.is_some() {
                DiffScopeKind::File
            } else {
                DiffScopeKind::Repository
            },
            limit: request.limit,
        },
        authority: DiffAuthority {
            status: authority_status,
            baseline: DiffBaselineAuthority {
                kind: DiffBaselineKind::ImmutableGenerationStructuralGraph,
                population: DIFF_BASELINE_POPULATION.into(),
                structural_graph,
                project_inventory_coverage: generation.project_inventory.coverage,
            },
            candidate: DiffCandidateAuthority {
                kind: DiffCandidateKind::LiveWorktree,
                population: DIFF_CANDIDATE_POPULATION.into(),
                consistency: DiffCandidateConsistency::PerFileReadNonAtomic,
            },
            comparison: DiffComparisonAuthority {
                coverage_complete: comparison_coverage_complete,
                files_considered: observation.files_considered,
                files_compared: observation.files_compared,
                files_excluded,
                exclusions: observation.exclusions.clone(),
            },
        },
        verdict,
        files_considered: observation.files_considered,
        files_compared: observation.files_compared,
        files_excluded,
        files_with_symbol_changes: observation.files.len(),
        total_added,
        total_removed,
        total_modified,
        changes_total,
        changes_returned,
        truncated,
        files,
        warnings,
    };
    let result_chars = serde_json::to_string(&result)
        .map_err(|error| DomainError::PublishedGenerationInvalid {
            reason: format!("diff result serialization failed: {error}"),
        })?
        .chars()
        .count();
    if result_chars > MAX_DIFF_RESULT_CHARS {
        return Err(DomainError::InvalidRequest {
            operation: "diff",
            field: "limit",
            reason: format!(
                "result would contain {result_chars} serialized characters, above the {MAX_DIFF_RESULT_CHARS}-character product bound; lower limit or narrow path"
            ),
        });
    }
    Ok(result)
}

fn validate_observation(observation: &DiffObservation) -> Result<(), DomainError> {
    if observation.scope_path.is_empty() {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: "diff observation has an empty scope path".into(),
        });
    }
    if observation.files_compared > observation.files_considered {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: "diff observation compared-file count exceeds considered-file count".into(),
        });
    }
    let mut excluded_files = 0usize;
    let mut prior_reason = None;
    for exclusion in &observation.exclusions {
        if exclusion.files == 0 {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: "diff observation contains an empty exclusion summary".into(),
            });
        }
        if prior_reason.is_some_and(|prior| prior >= exclusion.reason_code) {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: "diff observation exclusion reasons are not strictly increasing".into(),
            });
        }
        prior_reason = Some(exclusion.reason_code);
        excluded_files = excluded_files.checked_add(exclusion.files).ok_or_else(|| {
            DomainError::PublishedGenerationInvalid {
                reason: "diff observation exclusion count overflowed".into(),
            }
        })?;
    }
    if observation.files_compared.checked_add(excluded_files) != Some(observation.files_considered)
    {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: "diff observation exclusions do not close the considered-file population"
                .into(),
        });
    }
    let mut prior_path: Option<&str> = None;
    let mut seen = BTreeSet::new();
    for file in &observation.files {
        if file.diff.is_empty() {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "diff observation contains an unchanged file row for '{}'",
                    file.file_path
                ),
            });
        }
        validate_relative_path(&file.file_path)?;
        if !seen.insert(file.file_path.as_str()) {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "diff observation contains duplicate file '{}'",
                    file.file_path
                ),
            });
        }
        if prior_path.is_some_and(|prior: &str| prior >= file.file_path.as_str()) {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: "diff observation file order is not strictly increasing".into(),
            });
        }
        prior_path = Some(file.file_path.as_str());
    }
    if observation.files.len() > observation.files_compared {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: "diff observation changed-file count exceeds compared-file count".into(),
        });
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), DomainError> {
    let path_value = std::path::Path::new(path);
    if path.is_empty()
        || path_value.is_absolute()
        || path_value.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!("diff observation contains unsafe file path '{path}'"),
        });
    }
    Ok(())
}

fn bound_files(files: &[FileDiff], limit: usize) -> (Vec<FileDiff>, usize) {
    let mut emitted = 0usize;
    let mut bounded = Vec::new();
    for file in files {
        if emitted >= limit {
            break;
        }
        let mut remaining = limit - emitted;
        let added = file
            .diff
            .added
            .iter()
            .take(remaining)
            .cloned()
            .collect::<Vec<_>>();
        emitted += added.len();
        remaining = limit.saturating_sub(emitted);
        let removed = file
            .diff
            .removed
            .iter()
            .take(remaining)
            .cloned()
            .collect::<Vec<_>>();
        emitted += removed.len();
        remaining = limit.saturating_sub(emitted);
        let modified = file
            .diff
            .modified
            .iter()
            .take(remaining)
            .cloned()
            .collect::<Vec<_>>();
        emitted += modified.len();
        let diff = SymbolDiff {
            added,
            removed,
            modified,
        };
        if !diff.is_empty() {
            bounded.push(FileDiff {
                file_path: file.file_path.clone(),
                diff,
            });
        }
    }
    (bounded, emitted)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::code_intel_domain::{ProjectInventory, RepositoryId};
    use crate::code_intel_publication::{GenerationManifest, PublicationHead, PublicationHeadBody};
    use crate::diff::{DiffExclusionReason, DiffExclusionSummary};

    fn generation_with_inventory_coverage(
        coverage: ProjectInventoryCoverage,
    ) -> ResolvedGeneration {
        let repository_id = RepositoryId::new("repository-fixture");
        let generation_id = GenerationId::new("generation-fixture");
        ResolvedGeneration {
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
                source_revision: None,
                payload_blake3: "6".repeat(64),
                graph_publication_proof: crate::graph_store::GraphPublicationProof::test_fixture(),
                index_state_publication_proof:
                    crate::index_state::IndexStatePublicationProof::test_fixture(),
                project_inventory_sha256: "7".repeat(64),
                receipts: Vec::new(),
                provider_payloads: Vec::new(),
            },
            project_inventory: ProjectInventory {
                coverage,
                project_topology: crate::code_intel_domain::ProjectTopology {
                    units: Vec::new(),
                    memberships: Vec::new(),
                    relationships: Vec::new(),
                    exact_workspace_member_sets: Vec::new(),
                    dependency_graphs: Vec::new(),
                },
                analysis_context_graphs: Vec::new(),
                inputs: Vec::new(),
                issues: Vec::new(),
            }
            .into(),
            provider_payloads: Vec::new(),
            database_path: PathBuf::from("generation.redb"),
        }
    }

    #[test]
    fn request_bounds_reject_false_empty_and_unbounded_work() {
        for limit in [0, MAX_DIFF_LIMIT + 1] {
            let error = validate_diff_request(&DiffRequest { path: None, limit })
                .expect_err("out-of-range limit");
            assert!(matches!(
                error,
                DomainError::InvalidRequest { field: "limit", .. }
            ));
        }
        let error = validate_diff_request(&DiffRequest {
            path: Some(String::new()),
            limit: DEFAULT_DIFF_LIMIT,
        })
        .expect_err("empty path");
        assert!(matches!(
            error,
            DomainError::InvalidRequest { field: "path", .. }
        ));
        for path in [".", "../src/lib.rs", "/tmp/src/lib.rs"] {
            let error = validate_diff_request(&DiffRequest {
                path: Some(path.into()),
                limit: DEFAULT_DIFF_LIMIT,
            })
            .expect_err("unsafe or non-file scope path");
            assert!(matches!(
                error,
                DomainError::InvalidRequest { field: "path", .. }
            ));
        }
        validate_diff_request(&DiffRequest {
            path: Some("./src/lib.rs".into()),
            limit: DEFAULT_DIFF_LIMIT,
        })
        .expect("a normalized project-relative file path remains valid");
    }

    #[test]
    fn empty_observation_is_unknown_without_complete_baseline_authority() {
        let temporary = tempfile::tempdir().expect("temporary project");
        let bundle = temporary.path().join("bundle");
        let binding = ProjectBinding::explicit(temporary.path(), &bundle).expect("binding");
        let graph = KnowledgeGraph::new();
        let observation = DiffObservation {
            scope_path: ".".into(),
            files_considered: 0,
            files_compared: 0,
            exclusions: Vec::new(),
            files: Vec::new(),
        };

        let qualified = bind_diff_result(
            &graph,
            &generation_with_inventory_coverage(
                ProjectInventoryCoverage::IndexedSourcePopulationPartial,
            ),
            &binding,
            DiffRequest::default(),
            observation.clone(),
        )
        .expect("qualified diff result");
        assert_eq!(qualified.authority.status, DiffAuthorityStatus::Qualified);
        assert_eq!(qualified.verdict, DiffVerdict::Unknown);
        assert!(!qualified.warnings.is_empty());

        let complete = bind_diff_result(
            &graph,
            &generation_with_inventory_coverage(
                ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            ),
            &binding,
            DiffRequest::default(),
            observation,
        )
        .expect("complete diff result");
        assert_eq!(complete.authority.status, DiffAuthorityStatus::Complete);
        assert_eq!(complete.verdict, DiffVerdict::NoSymbolDifferences);
        assert!(complete.warnings.is_empty());
    }

    #[test]
    fn excluded_files_make_comparison_authority_qualified_and_population_closed() {
        let temporary = tempfile::tempdir().expect("temporary project");
        let bundle = temporary.path().join("bundle");
        let binding = ProjectBinding::explicit(temporary.path(), &bundle).expect("binding");
        let graph = KnowledgeGraph::new();
        let excluded = DiffObservation {
            scope_path: ".".into(),
            files_considered: 2,
            files_compared: 1,
            exclusions: vec![DiffExclusionSummary {
                reason_code: DiffExclusionReason::BaselineSymbolIdentityCollision,
                files: 1,
            }],
            files: Vec::new(),
        };

        let result = bind_diff_result(
            &graph,
            &generation_with_inventory_coverage(
                ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            ),
            &binding,
            DiffRequest::default(),
            excluded.clone(),
        )
        .expect("closed qualified result");
        assert_eq!(result.authority.status, DiffAuthorityStatus::Qualified);
        assert_eq!(result.verdict, DiffVerdict::Unknown);
        assert!(!result.authority.comparison.coverage_complete);
        assert_eq!(result.files_considered, 2);
        assert_eq!(result.files_compared, 1);
        assert_eq!(result.files_excluded, 1);
        let serialized = serde_json::to_value(&result).expect("serialize diff result");
        assert!(
            serialized["authority"]["candidate"]
                .get("exclusions")
                .is_none(),
            "baseline and candidate comparison failures must not be mislabeled as candidate population authority: {serialized}"
        );
        assert_eq!(
            serialized["authority"]["comparison"]["exclusions"][0]["reason_code"],
            "baseline_symbol_identity_collision",
            "comparison coverage must own the aggregate exclusion census: {serialized}"
        );

        let malformed = DiffObservation {
            files_considered: 3,
            ..excluded
        };
        let error = bind_diff_result(
            &graph,
            &generation_with_inventory_coverage(
                ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            ),
            &binding,
            DiffRequest::default(),
            malformed,
        )
        .expect_err("exclusion counts must close the considered population");
        assert!(matches!(
            error,
            DomainError::PublishedGenerationInvalid { .. }
        ));
    }
}
