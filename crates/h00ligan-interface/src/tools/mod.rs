//! h00ligan code-intelligence handlers.

pub mod code_intel;
pub mod composite_intel;
pub mod composite_intel_query;

pub use crate::tool_api::ToolError;

#[cfg(test)]
fn retain_test_graph_directory() -> std::path::PathBuf {
    static GRAPH_DIRECTORIES: std::sync::OnceLock<std::sync::Mutex<Vec<tempfile::TempDir>>> =
        std::sync::OnceLock::new();

    let directory = tempfile::tempdir().expect("private code-intel graph directory");
    let graph_dir = directory.path().to_path_buf();
    GRAPH_DIRECTORIES
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(directory);
    graph_dir
}

#[cfg(test)]
pub(crate) fn test_code_intel_context(
    root: &std::path::Path,
    graph: Option<h00ligan_engine::graph::KnowledgeGraph>,
    oracle_ran_ok: Option<bool>,
) -> std::sync::Arc<crate::CodeIntelContext> {
    let graph_dir = retain_test_graph_directory();
    let binding = h00ligan_engine::project_binding::ProjectBinding::explicit(root, &graph_dir)
        .expect("test code-intel binding");
    let load_state = if graph.is_some() {
        crate::GraphLoadState::Loaded {
            origin: Some(binding.root().to_path_buf()),
        }
    } else {
        crate::GraphLoadState::Unindexed
    };
    let generation_metadata = graph.as_ref().map(|_| {
        h00ligan_engine::graph_store::GraphGenerationMetadata::now(oracle_ran_ok.unwrap_or(false))
    });
    let mut snapshot = crate::CodeIntelSnapshot::unindexed();
    snapshot.graph = graph.map(std::sync::Arc::new);
    snapshot.load_state = load_state;
    snapshot.generation_metadata = generation_metadata;
    std::sync::Arc::new(crate::CodeIntelContext::from_test_snapshot(
        binding,
        tokio_util::sync::CancellationToken::new(),
        std::sync::Arc::new(snapshot),
    ))
}

/// Build a test context through the same immutable publication loader used by
/// the product. Publication-backed tests must not fabricate authority
/// on an in-memory graph.
#[cfg(test)]
pub(crate) async fn test_published_code_intel_context(
    root: &std::path::Path,
    graph: h00ligan_engine::graph::KnowledgeGraph,
) -> std::sync::Arc<crate::CodeIntelContext> {
    test_published_code_intel_context_fixture(root, graph, None, false).await
}

/// Build a real immutable test publication carrying complete Rust Calls
/// authority. Capability receipts, not a mutable success bit, authorize a
/// handler.
#[cfg(test)]
pub(crate) async fn test_published_rust_calls_context_with_metadata(
    root: &std::path::Path,
    graph: h00ligan_engine::graph::KnowledgeGraph,
) -> std::sync::Arc<crate::CodeIntelContext> {
    test_published_code_intel_context_fixture(root, graph, Some(true), true).await
}

#[cfg(test)]
async fn test_published_code_intel_context_fixture(
    root: &std::path::Path,
    graph: h00ligan_engine::graph::KnowledgeGraph,
    oracle_ran_ok: Option<bool>,
    calls_authority: bool,
) -> std::sync::Arc<crate::CodeIntelContext> {
    use std::collections::BTreeSet;

    use h00ligan_engine::code_intel_domain::{
        CALLS_CONFIGURATION_ID, CapabilityReceipt, CapabilityScope, ConfigurationId,
        DocumentMembership, DocumentMembershipKind, EcosystemId, LanguageId, ProjectInventory,
        ProjectInventoryCoverage, ProjectUnit, ProjectUnitId, ProjectUnitKind,
        STRUCTURAL_GRAPH_CONFIGURATION_ID,
    };
    use h00ligan_engine::code_intel_payload::{
        CallsProviderPayload, ProviderDocument, ProviderPayload,
    };
    use h00ligan_engine::code_intel_publication::{GenerationDraft, SemanticPublisher};
    use h00ligan_engine::graph_store::GraphGenerationMetadata;

    let graph_dir = retain_test_graph_directory();
    let binding = h00ligan_engine::project_binding::ProjectBinding::explicit(root, &graph_dir)
        .expect("test published code-intel binding");
    let mut publisher =
        SemanticPublisher::acquire(binding.graph_dir(), binding.root()).expect("test publisher");
    let workspace = publisher
        .begin_generation()
        .expect("test generation workspace");
    let store = h00ligan_engine::graph_store::GraphStore::new(workspace.database());
    store
        .save_snapshot(&graph)
        .await
        .expect("test generation graph");
    store
        .set_origin(binding.root())
        .await
        .expect("test generation origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(oracle_ran_ok.unwrap_or(false)))
        .await
        .expect("test generation metadata");
    drop(store);

    let document_paths = graph
        .all_nodes()
        .iter()
        .filter_map(|node| {
            h00ligan_engine::graph_stats::node_language(node)
                .map(|language| (node.file_path.clone(), language.to_owned()))
        })
        .collect::<BTreeSet<_>>();
    let index_state = h00ligan_engine::index_state::IndexState::new(workspace.database())
        .expect("test generation indexed-source state");
    let mut document_facts = Vec::new();
    for (document_path, language) in &document_paths {
        let source_path = root.join(document_path);
        let source_hash = std::fs::read(&source_path).map_or_else(
            |_| "0".repeat(64),
            |bytes| blake3::hash(&bytes).to_hex().to_string(),
        );
        index_state
            .set_file(
                document_path,
                &h00ligan_engine::index_state::FileRecord {
                    blake3_hash: source_hash,
                    last_indexed: 0,
                    symbol_count: graph.nodes_for_file(document_path).len() as u32,
                    language: language.clone(),
                },
            )
            .expect("test generation indexed-source record");
        if source_path.is_file() {
            document_facts.push(
                h00ligan_engine::extractor::extract_file(&source_path, root)
                    .expect("test generation document facts"),
            );
        }
    }
    index_state
        .replace_document_facts(&document_facts)
        .expect("test generation document-facts population");
    drop(index_state);

    assert!(
        !calls_authority
            || document_paths
                .iter()
                .all(|(_, language)| language == "rust"),
        "the Rust Calls authority fixture cannot authorize non-Rust documents"
    );
    let languages = document_paths
        .iter()
        .map(|(_, language)| language.clone())
        .collect::<BTreeSet<_>>();
    let project_inventory = ProjectInventory {
        coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
        project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
            units: languages
                .iter()
                .map(|language| ProjectUnit {
                    project_unit_id: ProjectUnitId::new(format!("{language}:test:published")),
                    language_id: LanguageId::new(language),
                    ecosystem_id: EcosystemId::new("test"),
                    kind: ProjectUnitKind::Package,
                    root_path: String::new(),
                    manifest_path: None,
                    compilation_root_paths: Vec::new(),
                })
                .collect(),
            memberships: document_paths
                .iter()
                .map(|(document_path, language)| DocumentMembership {
                    document_path: document_path.clone(),
                    language_id: LanguageId::new(language),
                    project_unit_id: ProjectUnitId::new(format!("{language}:test:published")),
                    kind: DocumentMembershipKind::SourceOwner,
                })
                .collect(),
            relationships: Vec::new(),
            exact_workspace_member_sets: Vec::new(),
            dependency_graphs: Vec::new(),
        },
        analysis_context_graphs: Vec::new(),
        inputs: Vec::new(),
        issues: Vec::new(),
    };
    let mut receipts = languages
        .iter()
        .map(|language| {
            CapabilityReceipt::complete(
                "structural_graph",
                "handler-test-structural",
                "1.0.0",
                CapabilityScope::Language {
                    language_id: LanguageId::new(language),
                    configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
                },
                "c".repeat(64),
            )
        })
        .collect::<Vec<_>>();
    let provider_payloads = if calls_authority {
        let receipt = CapabilityReceipt::complete(
            "calls",
            "handler-test-provider",
            "1.0.0",
            CapabilityScope::Repository {
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            "a".repeat(64),
        );
        let mut payload = CallsProviderPayload::new(receipt.clone());
        payload.documents = document_paths
            .iter()
            .map(|(document_path, _)| ProviderDocument {
                document_path: document_path.clone(),
                language_id: LanguageId::new("rust"),
                content_sha256: "b".repeat(64),
                cross_document_surface_sha256: "c".repeat(64),
                byte_length: 0,
            })
            .collect();
        receipts.push(receipt);
        vec![ProviderPayload::Calls(payload)]
    } else {
        Vec::new()
    };
    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("source-mutation-test".into()),
                project_inventory,
                receipts,
                provider_payloads,
            },
        )
        .expect("publish test generation");
    drop(publisher);

    std::sync::Arc::new(
        crate::CodeIntelContext::load(binding, tokio_util::sync::CancellationToken::new())
            .await
            .expect("load published test generation"),
    )
}
