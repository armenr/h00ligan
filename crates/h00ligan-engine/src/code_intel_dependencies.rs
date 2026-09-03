//! Exact direct-dependency projection over one immutable generation.
//!
//! Graph storage contains both semantic facts and navigation indexes. This
//! module is the boundary that turns only forward semantic facts into a public
//! dependency result. In particular, `HasImpl` is the inverse navigation index
//! for `Implements`; exposing both would invent a dependency cycle.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::code_intel_calls::assess_calls_capability;
use crate::code_intel_domain::{
    CapabilityCoverage, CapabilityCoverageStatus, DomainError, GenerationId,
    MAX_GENERATION_ENGINE_RESULT_CHARS, Page, ProjectInventoryCoverage, RepositoryBinding,
    assess_project_dependencies_capability, assess_structural_graph_capability,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{
    generation_scope_selector, language_id_for_path, repository_binding,
};
use crate::graph::{EdgeKind, KnowledgeGraph};
use crate::project_binding::ProjectBinding;

pub const DEPENDENCIES_SCHEMA_VERSION: &str = "h00/code-intel/dependencies/v1";
pub const DEPENDENCIES_POPULATION: &str = "repository_local_direct_source_and_project_dependencies";
pub const DEFAULT_DEPENDENCIES_PAGE_SIZE: usize = 50;
pub const MAX_DEPENDENCIES_PAGE_SIZE: usize = 100;

/// Validate the shared CLI/MCP page-size contract before either adapter loads
/// a published generation.
pub fn validate_dependencies_limit(
    limit: usize,
) -> Result<usize, crate::code_intel_domain::DomainError> {
    if !(1..=MAX_DEPENDENCIES_PAGE_SIZE).contains(&limit) {
        return Err(crate::code_intel_domain::DomainError::InvalidRequest {
            operation: "dependencies",
            field: "limit",
            reason: format!("must be between 1 and {MAX_DEPENDENCIES_PAGE_SIZE}"),
        });
    }
    Ok(limit)
}

/// Reject an unsafe or empty file/directory selector before an adapter loads
/// publication state. Indexed-membership validation still belongs to the
/// immutable-generation query itself.
pub fn validate_dependencies_path(
    binding: &ProjectBinding,
    path: &str,
) -> Result<(), crate::code_intel_domain::DomainError> {
    generation_scope_selector(binding, path).map(drop)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependenciesRequest {
    pub path: String,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl DependenciesRequest {
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            limit: DEFAULT_DEPENDENCIES_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRelationKind {
    Call,
    Reference,
    TypeUse,
    Implementation,
    Inheritance,
    ProjectDependency,
}

impl DependencyRelationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Reference => "reference",
            Self::TypeUse => "type_use",
            Self::Implementation => "implementation",
            Self::Inheritance => "inheritance",
            Self::ProjectDependency => "project_dependency",
        }
    }
}

impl std::fmt::Display for DependencyRelationKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyAuthorityStatus {
    Complete,
    Qualified,
}

impl std::fmt::Display for DependencyAuthorityStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Complete => "complete",
            Self::Qualified => "qualified",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyAuthority {
    pub status: DependencyAuthorityStatus,
    pub population: String,
    pub structural_graph: CapabilityCoverage,
    pub calls: CapabilityCoverage,
    pub project_dependencies: CapabilityCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyScopeKind {
    File,
    Directory,
}

impl std::fmt::Display for DependencyScopeKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::File => "file",
            Self::Directory => "directory",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyScope {
    pub path: String,
    pub kind: DependencyScopeKind,
    pub indexed_files: usize,
    pub symbols: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyRelationCount {
    pub kind: DependencyRelationKind,
    pub evidence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyFileSummary {
    pub file: String,
    /// Forward evidence: the selected scope relies on this file.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<DependencyRelationCount>,
    /// Incoming evidence: this file relies on the selected scope.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependents: Vec<DependencyRelationCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactDependenciesResult {
    pub schema_version: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub scope: DependencyScope,
    pub authority: DependencyAuthority,
    /// Number of observed forward semantic edges from the scope to other files.
    pub dependency_evidence_count: usize,
    /// Number of observed forward semantic edges from other files into the scope.
    pub dependent_evidence_count: usize,
    pub page: Page,
    pub files: Vec<DependencyFileSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Default)]
struct FileBucket {
    dependencies: BTreeMap<DependencyRelationKind, usize>,
    dependents: BTreeMap<DependencyRelationKind, usize>,
}

/// Query direct, repository-local dependencies for one indexed file or
/// directory. The graph and generation must be the same coherent snapshot.
pub fn query_published_dependencies(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &DependenciesRequest,
) -> Result<ExactDependenciesResult, crate::code_intel_domain::DomainError> {
    let limit = validate_dependencies_limit(request.limit)?;
    let normalized_selector = generation_scope_selector(binding, &request.path)?;
    let indexed_files = indexed_source_files(graph, generation);
    let (scope_kind, scope_files) = resolve_scope(&indexed_files, &normalized_selector)
        .ok_or_else(|| {
            crate::code_intel_domain::DomainError::SourcePath(format!(
                "{} is not an indexed source file or directory in this generation",
                request.path
            ))
        })?;

    let scope_nodes = graph
        .all_nodes()
        .into_iter()
        .filter(|node| scope_files.contains(node.file_path.as_str()))
        .collect::<Vec<_>>();
    let mut per_file: BTreeMap<String, FileBucket> = BTreeMap::new();
    let mut dependency_evidence_count = 0usize;
    let mut dependent_evidence_count = 0usize;

    for node in &scope_nodes {
        for (target_id, edge) in graph.neighbors(&node.memory_id) {
            let Some(kind) = dependency_relation(edge.kind) else {
                continue;
            };
            let Some(target) = graph.node(&target_id) else {
                continue;
            };
            if scope_files.contains(target.file_path.as_str())
                || !indexed_files.contains(target.file_path.as_str())
            {
                continue;
            }
            *per_file
                .entry(target.file_path.clone())
                .or_default()
                .dependencies
                .entry(kind)
                .or_default() += 1;
            dependency_evidence_count += 1;
        }

        for (source_id, edge) in graph.incoming_neighbors(&node.memory_id) {
            let Some(kind) = dependency_relation(edge.kind) else {
                continue;
            };
            let Some(source) = graph.node(&source_id) else {
                continue;
            };
            if scope_files.contains(source.file_path.as_str())
                || !indexed_files.contains(source.file_path.as_str())
            {
                continue;
            }
            *per_file
                .entry(source.file_path.clone())
                .or_default()
                .dependents
                .entry(kind)
                .or_default() += 1;
            dependent_evidence_count += 1;
        }
    }

    let structural_graph = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let calls = assess_calls_capability(
        graph,
        &generation.manifest.receipts,
        &generation.provider_payloads,
        &generation.project_inventory,
    );
    let project_dependencies = assess_project_dependencies_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let selected_languages = scope_files
        .iter()
        .map(|path| language_id_for_path(path))
        .filter(|language| language.0 != "unknown")
        .collect::<BTreeSet<_>>();
    let inventory_coverage = generation
        .project_inventory
        .coverage_for_languages(&selected_languages);
    let authority_status = if inventory_coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationComplete
        && capability_complete(&structural_graph)
        && capability_complete(&calls)
        && capability_complete(&project_dependencies)
    {
        DependencyAuthorityStatus::Complete
    } else {
        DependencyAuthorityStatus::Qualified
    };

    let mut base_warnings = Vec::new();
    if authority_status == DependencyAuthorityStatus::Qualified {
        base_warnings.push(
            "dependency rows are observed evidence only; zeroes and totals are not complete while structural, Calls, or project-dependency coverage is incomplete"
                .into(),
        );
    }
    let inventory_issues = generation
        .project_inventory
        .issues_for_languages(&selected_languages);
    if !inventory_issues.is_empty() {
        base_warnings.push(format!(
            "project inventory is partial and reports {} issue(s)",
            inventory_issues.len()
        ));
    }

    let files_total = per_file.len();
    let files = per_file.into_iter().collect::<Vec<_>>();
    let request_digest =
        crate::code_intel_cursor::request_digest("dependencies", &[normalized_selector.as_str()]);
    let scope_path = if normalized_selector.is_empty() {
        ".".into()
    } else {
        normalized_selector
    };
    let mut smallest_result_chars = usize::MAX;
    for effective_limit in (1..=limit).rev() {
        let window = crate::code_intel_cursor::page_window(
            "dependencies",
            &generation.manifest.generation_id,
            &request_digest,
            request.cursor.as_deref(),
            effective_limit,
            files_total,
        )?;
        let page_files = files[window.range.clone()]
            .iter()
            .map(|(file, bucket)| DependencyFileSummary {
                file: file.clone(),
                dependencies: relation_counts(bucket.dependencies.clone()),
                dependents: relation_counts(bucket.dependents.clone()),
            })
            .collect::<Vec<_>>();
        let mut warnings = base_warnings.clone();
        if effective_limit < limit {
            warnings.push(format!(
                "serialized-result bounds reduced this page limit from {limit} to {effective_limit} related files"
            ));
        }
        if window.page.has_more {
            warnings.push(format!(
                "showing {} of {files_total} related files in this page; continue with next_cursor",
                window.page.returned
            ));
        }
        let result = ExactDependenciesResult {
            schema_version: DEPENDENCIES_SCHEMA_VERSION.into(),
            generation_id: generation.manifest.generation_id.clone(),
            repository: repository_binding(binding, generation),
            scope: DependencyScope {
                path: scope_path.clone(),
                kind: scope_kind,
                indexed_files: scope_files.len(),
                symbols: scope_nodes.len(),
            },
            authority: DependencyAuthority {
                status: authority_status,
                population: DEPENDENCIES_POPULATION.into(),
                structural_graph: structural_graph.clone(),
                calls: calls.clone(),
                project_dependencies: project_dependencies.clone(),
            },
            dependency_evidence_count,
            dependent_evidence_count,
            page: window.page,
            files: page_files,
            warnings,
        };
        let result_chars = serde_json::to_string(&result)
            .map_err(|error| DomainError::PublishedGenerationInvalid {
                reason: format!("serialize Dependencies result for size validation: {error}"),
            })?
            .chars()
            .count();
        smallest_result_chars = result_chars;
        if result_chars <= MAX_GENERATION_ENGINE_RESULT_CHARS {
            return Ok(result);
        }
    }
    Err(DomainError::result_too_large(
        "dependencies",
        smallest_result_chars,
        MAX_GENERATION_ENGINE_RESULT_CHARS,
        "Narrow the file or directory scope; required Dependencies identity, authority, and one related-file row do not fit",
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

fn resolve_scope(
    indexed_files: &BTreeSet<String>,
    selector: &str,
) -> Option<(DependencyScopeKind, BTreeSet<String>)> {
    if !selector.is_empty() && indexed_files.contains(selector) {
        return Some((
            DependencyScopeKind::File,
            std::iter::once(selector.to_owned()).collect(),
        ));
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
    (!files.is_empty()).then_some((DependencyScopeKind::Directory, files))
}

fn relation_counts(
    counts: BTreeMap<DependencyRelationKind, usize>,
) -> Vec<DependencyRelationCount> {
    counts
        .into_iter()
        .map(|(kind, evidence_count)| DependencyRelationCount {
            kind,
            evidence_count,
        })
        .collect()
}

const fn capability_complete(coverage: &CapabilityCoverage) -> bool {
    matches!(
        coverage.status,
        CapabilityCoverageStatus::NotApplicable | CapabilityCoverageStatus::Complete
    )
}

/// Map storage edges onto the public direction of dependency. Navigation-only
/// inverses and containment/similarity edges have no public dependency meaning.
const fn dependency_relation(kind: EdgeKind) -> Option<DependencyRelationKind> {
    match kind {
        EdgeKind::Calls => Some(DependencyRelationKind::Call),
        EdgeKind::References => Some(DependencyRelationKind::Reference),
        EdgeKind::TypeOf | EdgeKind::FieldOf => Some(DependencyRelationKind::TypeUse),
        EdgeKind::Implements => Some(DependencyRelationKind::Implementation),
        EdgeKind::Extends => Some(DependencyRelationKind::Inheritance),
        EdgeKind::DependsOn => Some(DependencyRelationKind::ProjectDependency),
        EdgeKind::Contains | EdgeKind::HasImpl | EdgeKind::RelatedTo => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;
    use crate::code_intel_domain::{ProjectInventory, RepositoryId};
    use crate::code_intel_publication::{GenerationManifest, PublicationHead, PublicationHeadBody};
    use crate::graph::{GraphEdge, GraphNode};
    use crate::reachability::ReachabilityClass;

    fn generation() -> ResolvedGeneration {
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
                schema_version: crate::code_intel_publication::GENERATION_SCHEMA_VERSION.into(),
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
                coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
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

    fn node(name: &str, path: String) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: "function".into(),
            file_path: path,
            content_hash: format!("hash-{name}"),
            signature: format!("pub fn {name}()"),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(0),
            line_end: Some(0),
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

    #[test]
    fn dependency_projection_is_forward_only_and_classifies_every_edge_kind() {
        assert_eq!(
            dependency_relation(EdgeKind::Calls),
            Some(DependencyRelationKind::Call)
        );
        assert_eq!(
            dependency_relation(EdgeKind::References),
            Some(DependencyRelationKind::Reference)
        );
        assert_eq!(
            dependency_relation(EdgeKind::TypeOf),
            Some(DependencyRelationKind::TypeUse)
        );
        assert_eq!(
            dependency_relation(EdgeKind::FieldOf),
            Some(DependencyRelationKind::TypeUse)
        );
        assert_eq!(
            dependency_relation(EdgeKind::Implements),
            Some(DependencyRelationKind::Implementation)
        );
        assert_eq!(
            dependency_relation(EdgeKind::Extends),
            Some(DependencyRelationKind::Inheritance)
        );
        assert_eq!(
            dependency_relation(EdgeKind::DependsOn),
            Some(DependencyRelationKind::ProjectDependency)
        );
        assert_eq!(dependency_relation(EdgeKind::Contains), None);
        assert_eq!(dependency_relation(EdgeKind::HasImpl), None);
        assert_eq!(dependency_relation(EdgeKind::RelatedTo), None);
    }

    #[test]
    fn root_and_directory_scope_resolution_is_deterministic() {
        let files = ["src/lib.rs".to_owned(), "src/nested/mod.rs".to_owned()]
            .into_iter()
            .collect();
        assert_eq!(
            resolve_scope(&files, "src/lib.rs"),
            Some((
                DependencyScopeKind::File,
                std::iter::once("src/lib.rs".to_owned()).collect()
            ))
        );
        assert_eq!(
            resolve_scope(&files, "src").map(|(kind, files)| (kind, files.len())),
            Some((DependencyScopeKind::Directory, 2))
        );
        assert_eq!(
            resolve_scope(&files, "").map(|(kind, files)| (kind, files.len())),
            Some((DependencyScopeKind::Directory, 2))
        );
        assert_eq!(resolve_scope(&files, "missing"), None);
    }

    #[test]
    fn page_size_contract_is_bounded() {
        assert_eq!(validate_dependencies_limit(1).expect("minimum"), 1);
        assert_eq!(
            validate_dependencies_limit(MAX_DEPENDENCIES_PAGE_SIZE).expect("maximum"),
            MAX_DEPENDENCIES_PAGE_SIZE
        );
        assert!(validate_dependencies_limit(0).is_err());
        assert!(validate_dependencies_limit(MAX_DEPENDENCIES_PAGE_SIZE + 1).is_err());
    }

    #[test]
    fn large_page_is_adaptively_reduced_without_losing_population_totals() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(&root).expect("fixture root");
        let binding = ProjectBinding::explicit(&root, &temporary.path().join("bundle"))
            .expect("fixture binding");
        let generation = generation();
        let mut graph = KnowledgeGraph::new();
        let source = node("source", "src/lib.rs".into());
        let source_id = source.memory_id;
        graph.add_node(source).expect("source node");

        let path_component = "x".repeat(100);
        let mut related_path_characters = 0usize;
        for index in 0..MAX_DEPENDENCIES_PAGE_SIZE {
            let path = format!(
                "src/{path_component}/{path_component}/{path_component}/dependency_{index}.rs"
            );
            related_path_characters += path.chars().count();
            let target = node(&format!("target_{index}"), path);
            let target_id = target.memory_id;
            graph.add_node(target).expect("target node");
            graph
                .add_edge(
                    source_id,
                    target_id,
                    GraphEdge {
                        kind: EdgeKind::References,
                        ..GraphEdge::default()
                    },
                )
                .expect("dependency edge");
        }
        assert!(
            related_path_characters > MAX_GENERATION_ENGINE_RESULT_CHARS,
            "positive control: file paths alone must exceed the result envelope"
        );

        let result = query_published_dependencies(
            &graph,
            &generation,
            &binding,
            &DependenciesRequest {
                path: "src/lib.rs".into(),
                limit: MAX_DEPENDENCIES_PAGE_SIZE,
                cursor: None,
            },
        )
        .expect("large Dependencies result must remain useful through page reduction");
        let serialized = serde_json::to_string(&result).expect("Dependencies JSON");

        assert!(serialized.chars().count() <= MAX_GENERATION_ENGINE_RESULT_CHARS);
        assert!(result.page.returned < MAX_DEPENDENCIES_PAGE_SIZE);
        assert_eq!(result.page.total_items, MAX_DEPENDENCIES_PAGE_SIZE);
        assert!(result.page.has_more);
        assert!(result.page.next_cursor.is_some());
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("serialized-result bounds reduced this page limit")
        }));
    }
}
