#![cfg(feature = "code-intel")]

use std::collections::BTreeSet;
use std::path::{Component, Path};

use h00ligan_engine::code_intel_domain::{
    CapabilityReceipt, CapabilityScope, ConfigurationId, DocumentMembership,
    DocumentMembershipKind, EcosystemId, LanguageId, ProjectInventory, ProjectInventoryCoverage,
    ProjectUnit, ProjectUnitId, ProjectUnitKind, STRUCTURAL_GRAPH_CONFIGURATION_ID,
};
use h00ligan_engine::code_intel_publication::{GenerationDraft, SemanticPublisher};
use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::extractor::extract_file;
use h00ligan_engine::graph::{GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_store::{GraphGenerationMetadata, GraphStore};
use h00ligan_engine::project_binding::ProjectBinding;
use h00ligan_engine::reachability::ReachabilityClass;
use h00ligan_interface::{CodeIntelContext, CodeIntelRegistry, ToolError};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn node(name: &str, kind: &str, file: &str, hash: String) -> GraphNode {
    GraphNode {
        memory_id: Uuid::new_v4(),
        symbol_name: name.into(),
        kind: kind.into(),
        file_path: file.into(),
        content_hash: hash,
        signature: format!("{kind} {name}"),
        reachability_class: ReachabilityClass::Wired,
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

async fn published_context(root: &Path, graph: KnowledgeGraph) -> CodeIntelContext {
    let graph_dir = root.join(".h00ligan/code-intel");
    let binding = ProjectBinding::explicit(root, &graph_dir).expect("published binding");
    binding
        .prepare_graph_directory_write()
        .expect("admit fixture publication directory write");
    let mut publisher =
        SemanticPublisher::acquire(binding.graph_dir(), binding.root()).expect("publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let database = workspace.database();
    let store = GraphStore::new(database.clone());
    store.save_snapshot(&graph).await.expect("generation graph");
    store
        .set_origin(binding.root())
        .await
        .expect("generation origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("complete generation metadata");
    drop(store);
    let source_documents = graph
        .all_nodes()
        .into_iter()
        .filter(|node| {
            let path = Path::new(&node.file_path);
            !path.is_absolute()
                && !path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
                && path.extension().is_some_and(|extension| extension == "rs")
        })
        .map(|node| node.file_path.clone())
        .collect::<BTreeSet<_>>();
    let index_state = h00ligan_engine::index_state::IndexState::new(database.clone())
        .expect("generation index state");
    for document_path in &source_documents {
        let path = root.join(document_path);
        if let Ok(bytes) = std::fs::read(&path) {
            index_state
                .set_file(
                    document_path,
                    &h00ligan_engine::index_state::FileRecord {
                        blake3_hash: blake3::hash(&bytes).to_hex().to_string(),
                        last_indexed: 1,
                        symbol_count: u32::try_from(graph.nodes_for_file(document_path).len())
                            .expect("fixture symbol count fits u32"),
                        language: "rust".into(),
                    },
                )
                .expect("indexed source record");
        }
    }
    drop(index_state);
    drop(database);
    let project_unit_id = ProjectUnitId::new("rust:behavior-fixture");
    let project_inventory = ProjectInventory {
        coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
        project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
            units: (!source_documents.is_empty())
                .then(|| ProjectUnit {
                    project_unit_id: project_unit_id.clone(),
                    language_id: LanguageId::new("rust"),
                    ecosystem_id: EcosystemId::new("rust"),
                    kind: ProjectUnitKind::LooseSources,
                    root_path: String::new(),
                    manifest_path: None,
                    compilation_root_paths: Vec::new(),
                })
                .into_iter()
                .collect(),
            memberships: source_documents
                .iter()
                .map(|document_path| DocumentMembership {
                    document_path: document_path.clone(),
                    language_id: LanguageId::new("rust"),
                    project_unit_id: project_unit_id.clone(),
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
    let receipts = (!source_documents.is_empty())
        .then(|| {
            CapabilityReceipt::complete(
                "structural_graph",
                "h00-structural",
                "behavior-fixture-v1",
                CapabilityScope::Language {
                    language_id: LanguageId::new("rust"),
                    configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
                },
                "a".repeat(64),
            )
        })
        .into_iter()
        .collect();
    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("replace-behavior-test".into()),
                project_inventory,
                receipts,
                provider_payloads: Vec::new(),
            },
        )
        .expect("publish generation");
    drop(publisher);

    CodeIntelContext::load(binding, CancellationToken::new())
        .await
        .expect("load published generation")
}

#[tokio::test]
async fn type_uses_graph_lines_without_a_memory_backend() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source root");
    let mut graph = KnowledgeGraph::new();
    let mut widget = node("Widget", "struct", "src/lib.rs", "hash".into());
    widget.line_start = Some(2);
    widget.line_end = Some(4);
    graph.add_node(widget).expect("add Widget");
    let ctx = published_context(&root, graph).await;

    let result = CodeIntelRegistry::default()
        .execute("type", serde_json::json!({"symbol": "Widget"}), &ctx)
        .await
        .expect("type result");
    assert_eq!(result["schema_version"], "h00/code-intel/type/v1");
    assert_eq!(result["resolved_type"]["document_path"], "src/lib.rs");
    assert_eq!(result["resolved_type"]["start_line"], 2);
    assert_eq!(result["resolved_type"]["end_line"], 4);
}

#[tokio::test]
async fn read_refuses_source_that_changed_after_its_generation_was_published() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let source = root.join("src/lib.rs");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
    std::fs::write(&source, "pub fn answer() -> u32 { 42 }\n").expect("indexed source");

    let output = extract_file(&source, &root).expect("extract indexed source");
    assert_eq!(
        output
            .symbols
            .iter()
            .filter(|symbol| symbol.name == "answer")
            .count(),
        1,
        "positive control: the extractor must find the symbol under test"
    );
    let mut graph = KnowledgeGraph::new();
    build_graph(&[output], &mut graph).expect("build indexed graph");
    let ctx = published_context(&root, graph).await;

    std::fs::write(&source, "pub fn answer() -> u32 { 43 }\n").expect("mutated source");
    let registry = CodeIntelRegistry::default();
    let error = registry
        .execute("read", serde_json::json!({"symbol": "answer"}), &ctx)
        .await
        .expect_err("a published generation must not authorize changed source bytes");

    let ToolError::Domain { message, envelope } = error else {
        panic!("stale source must return a machine-readable domain error")
    };
    assert!(message.contains("source changed since indexing"));
    assert_eq!(envelope["error"]["code"], "source_changed_since_indexing");

    let inspect = registry
        .execute(
            "inspect",
            serde_json::json!({"symbol": "answer", "sections": ["source"]}),
            &ctx,
        )
        .await
        .expect_err("inspect must use the same exact source authority");
    assert!(
        matches!(inspect, ToolError::Domain { ref envelope, .. } if envelope["error"]["code"] == "source_changed_since_indexing")
    );
}
