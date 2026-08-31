//! Integration tests for residual SCIP index loading and edge fusion.
//!
//! All tests build SCIP fixtures programmatically — no rust-analyzer required.

#![cfg(feature = "code-intel")]

use std::collections::HashSet;

use h00ligan_engine::graph::{
    EdgeKind, EdgeScope, EdgeSource, GraphEdge, GraphNode, KnowledgeGraph,
};
use h00ligan_engine::reachability::ReachabilityClass;
use h00ligan_engine::scip_loader::{ScipLoader, ScipStats};

use protobuf::{Enum as _, Message as _};
use scip::types::{Document, Index, Occurrence, Relationship, SymbolInformation, SymbolRole};
use uuid::Uuid;

/// Explicit package seed for narrow fixtures that intentionally predate the
/// `Document.symbols` locality contract. Production derives package authority
/// from repository-owned symbol information in the admitted SCIP index.
fn h00_local_packages() -> HashSet<String> {
    [
        "h00ligan_engine",
        "h00ligan_interface",
        "h00_cli",
        "h00_core",
        "h00_sdl",
        "h00ligan",
        "h00_bench",
        "h00ligan-engine",
        "h00ligan-interface",
        "h00-cli",
        "h00-core",
        "h00-sdl",
        "h00ligan",
        "h00-bench",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Build a minimal SCIP index with known symbols and relationships.
///
/// Creates 2 files with 4 symbols:
/// - `src/main.rs`: `main` (function), references `Greeter::greet()`
/// - `src/greeter.rs`: `Greeter` (struct), `Greeter::greet()` (method), `Message` (struct)
///
/// Produces at least 1 References edge (`main → greet`) and 1 TypeOf edge
/// (`greet → Message` via return type relationship). Raw SCIP references
/// deliberately cannot claim Calls authority because a function-shaped symbol
/// may be a value, callback, import, or invocation.
fn build_test_scip_index() -> Index {
    let mut index = Index::new();

    // Document 1: src/main.rs
    let mut main_doc = Document::new();
    main_doc.relative_path = "src/main.rs".to_string();

    // Definition of `main`
    let mut main_def = Occurrence::new();
    main_def.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 main().".to_string();
    main_def.symbol_roles = SymbolRole::Definition.value();
    main_def.range = vec![0, 0, 10]; // line 0, col 0..10
    main_def.enclosing_range = vec![0, 0, 10, 0];

    // Reference to `Greeter::greet()` inside `main`
    let mut greet_ref = Occurrence::new();
    greet_ref.symbol =
        "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Greeter#greet().".to_string();
    greet_ref.symbol_roles = 0; // pure reference
    greet_ref.range = vec![5, 4, 20]; // line 5, col 4..20

    // Reference to `Greeter` type inside `main`
    let mut greeter_type_ref = Occurrence::new();
    greeter_type_ref.symbol =
        "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Greeter#".to_string();
    greeter_type_ref.symbol_roles = 0;
    greeter_type_ref.range = vec![3, 8, 15]; // line 3

    // SymbolInformation for `main`
    let mut main_sym_info = SymbolInformation::new();
    main_sym_info.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 main().".to_string();

    main_doc.occurrences = vec![main_def, greet_ref, greeter_type_ref];
    main_doc.symbols = vec![main_sym_info];

    // Document 2: src/greeter.rs
    let mut greeter_doc = Document::new();
    greeter_doc.relative_path = "src/greeter.rs".to_string();

    // Definition of `Greeter` struct
    let mut greeter_def = Occurrence::new();
    greeter_def.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Greeter#".to_string();
    greeter_def.symbol_roles = SymbolRole::Definition.value();
    greeter_def.range = vec![0, 0, 15];

    // Definition of `Greeter::greet()` method
    let mut greet_def = Occurrence::new();
    greet_def.symbol =
        "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Greeter#greet().".to_string();
    greet_def.symbol_roles = SymbolRole::Definition.value();
    greet_def.range = vec![5, 4, 20];

    // Definition of `Message` struct
    let mut message_def = Occurrence::new();
    message_def.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Message#".to_string();
    message_def.symbol_roles = SymbolRole::Definition.value();
    message_def.range = vec![15, 0, 15];

    // SymbolInformation for `greet` with TypeOf relationship to `Message`
    let mut greet_sym_info = SymbolInformation::new();
    greet_sym_info.symbol =
        "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Greeter#greet().".to_string();

    let mut type_rel = Relationship::new();
    type_rel.symbol = "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Message#".to_string();
    type_rel.is_type_definition = true;
    greet_sym_info.relationships = vec![type_rel];

    // SymbolInformation for `Greeter`
    let mut greeter_sym_info = SymbolInformation::new();
    greeter_sym_info.symbol =
        "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Greeter#".to_string();

    // SymbolInformation for `Message`
    let mut message_sym_info = SymbolInformation::new();
    message_sym_info.symbol =
        "rust-analyzer cargo h00ligan_engine 0.1.0 greeter/Message#".to_string();

    greeter_doc.occurrences = vec![greeter_def, greet_def, message_def];
    greeter_doc.symbols = vec![greeter_sym_info, greet_sym_info, message_sym_info];

    index.documents = vec![main_doc, greeter_doc];
    index
}

/// Create a graph pre-populated with nodes matching the test SCIP index.
///
/// Uses `deterministic_id` from edge_builder so the UUIDs match what the
/// SCIP loader's `build_node_lookup` will find.
fn build_test_graph() -> KnowledgeGraph {
    let mut graph = KnowledgeGraph::new();

    // Nodes matching the SCIP fixture
    let nodes = vec![
        GraphNode {
            memory_id: deterministic_id("src/main.rs", "main"),
            symbol_name: "main".to_string(),
            kind: "function".to_string(),
            file_path: "src/main.rs".to_string(),
            content_hash: "abc123".to_string(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        },
        GraphNode {
            memory_id: deterministic_id("src/greeter.rs", "Greeter"),
            symbol_name: "Greeter".to_string(),
            kind: "struct".to_string(),
            file_path: "src/greeter.rs".to_string(),
            content_hash: "def456".to_string(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        },
        GraphNode {
            memory_id: deterministic_id("src/greeter.rs", "greet"),
            symbol_name: "greet".to_string(),
            kind: "function".to_string(),
            file_path: "src/greeter.rs".to_string(),
            content_hash: "ghi789".to_string(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        },
        GraphNode {
            memory_id: deterministic_id("src/greeter.rs", "Message"),
            symbol_name: "Message".to_string(),
            kind: "struct".to_string(),
            file_path: "src/greeter.rs".to_string(),
            content_hash: "jkl012".to_string(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        },
    ];

    for node in nodes {
        graph.add_node(node).expect("add node");
    }

    graph
}

/// Deterministic UUID from file_path + symbol_name (mirrors edge_builder).
fn deterministic_id(file_path: &str, symbol_name: &str) -> Uuid {
    h00ligan_engine::edge_builder::deterministic_id(file_path, symbol_name)
}

/// Serialize a SCIP Index to bytes.
fn serialize_index(index: &Index) -> Vec<u8> {
    index.write_to_bytes().expect("serialize SCIP index")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_scip_loader_parses_fixture() {
    let mut graph = build_test_graph();
    let index = build_test_scip_index();
    let bytes = serialize_index(&index);

    let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
    let stats = loader.load_scip_bytes(&bytes).expect("load SCIP index");

    // Should have found some symbols.
    assert!(
        stats.symbols_found > 0,
        "expected symbols_found > 0, got {}",
        stats.symbols_found
    );

    // Should have created at least one edge.
    let total_edges = stats.typeof_edges_added + stats.novel_edges + stats.merged_with_existing;
    assert!(
        total_edges > 0,
        "expected at least one edge, got total_edges = {total_edges}"
    );
}

#[test]
fn test_scip_typeof_edge_created() {
    let mut graph = build_test_graph();
    let index = build_test_scip_index();
    let bytes = serialize_index(&index);

    let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
    let stats = loader.load_scip_bytes(&bytes).expect("load SCIP index");

    assert!(
        stats.typeof_edges_added > 0,
        "expected TypeOf edges, got typeof_edges_added = {}",
        stats.typeof_edges_added
    );

    // Verify a TypeOf edge exists in the graph.
    let edges = graph.all_edges();
    let has_typeof = edges.iter().any(|(_, _, e)| e.kind == EdgeKind::TypeOf);
    assert!(has_typeof, "graph should contain at least one TypeOf edge");
}

#[test]
fn test_scip_function_reference_remains_a_residual_reference() {
    let mut graph = build_test_graph();
    let index = build_test_scip_index();
    let bytes = serialize_index(&index);

    let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
    loader.load_scip_bytes(&bytes).expect("load SCIP index");

    // Verify the exact residual reference survives in the graph.
    let edges = graph.all_edges();
    let has_reference = edges
        .iter()
        .any(|(_, _, edge)| edge.kind == EdgeKind::References);
    assert!(
        has_reference,
        "graph should contain the exact residual References edge"
    );
    assert!(
        edges
            .iter()
            .all(|(_, _, edge)| edge.kind != EdgeKind::Calls),
        "raw function-shaped references cannot establish Calls authority"
    );
}

#[test]
fn test_residual_scip_reference_fusion_increases_confidence() {
    let mut graph = build_test_graph();

    // Pre-populate with a tree-sitter edge matching one the residual SCIP
    // projection will produce. The raw index can establish only References.
    // Pre-add that same edge as tree-sitter.
    let main_id = deterministic_id("src/main.rs", "main");
    let greet_id = deterministic_id("src/greeter.rs", "greet");

    let ts_edge = GraphEdge {
        kind: EdgeKind::References,
        weight: 1.0,
        source: EdgeSource::TreeSitter,
        confidence: 0.7,
        ..Default::default()
    };
    graph
        .add_edge(main_id, greet_id, ts_edge)
        .expect("add tree-sitter edge");

    // Verify the tree-sitter edge.
    let edges_before = graph.all_edges();
    let reference_before = edges_before
        .iter()
        .find(|(src, tgt, edge)| {
            *src == main_id && *tgt == greet_id && edge.kind == EdgeKind::References
        })
        .expect("tree-sitter References edge should exist");
    assert_eq!(reference_before.2.source, EdgeSource::TreeSitter);
    assert!((reference_before.2.confidence - 0.7).abs() < f32::EPSILON);

    // Load SCIP index — should corroborate the residual References edge.
    let index = build_test_scip_index();
    let bytes = serialize_index(&index);

    let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
    let stats = loader.load_scip_bytes(&bytes).expect("load SCIP index");

    assert!(
        stats.merged_with_existing > 0,
        "expected merged_with_existing > 0, got {}",
        stats.merged_with_existing
    );

    // Verify the edge was upgraded to Both with confidence 0.95.
    let edges_after = graph.all_edges();
    let reference_after = edges_after
        .iter()
        .find(|(src, tgt, edge)| {
            *src == main_id && *tgt == greet_id && edge.kind == EdgeKind::References
        })
        .expect("References edge should still exist after fusion");

    assert_eq!(
        reference_after.2.source,
        EdgeSource::Both,
        "merged edge source should be Both"
    );
    assert!(
        (reference_after.2.confidence - 0.95).abs() < f32::EPSILON,
        "merged edge confidence should be 0.95, got {}",
        reference_after.2.confidence
    );
}

#[test]
fn test_scip_novel_edge_confidence() {
    let mut graph = build_test_graph();

    // Do NOT pre-populate any edges — all SCIP edges will be novel.
    let index = build_test_scip_index();
    let bytes = serialize_index(&index);

    let mut loader = ScipLoader::with_local_packages(&mut graph, h00_local_packages());
    let stats = loader.load_scip_bytes(&bytes).expect("load SCIP index");

    assert!(
        stats.novel_edges > 0,
        "expected novel_edges > 0, got {}",
        stats.novel_edges
    );

    // All SCIP-only edges should have source=Scip and confidence=0.9.
    let edges = graph.all_edges();
    for (_, _, edge) in &edges {
        if edge.source == EdgeSource::Scip {
            assert!(
                (edge.confidence - 0.9).abs() < f32::EPSILON,
                "SCIP-only edge should have confidence 0.9, got {}",
                edge.confidence
            );
        }
    }
}

#[test]
fn test_scip_graceful_on_corrupt_file() {
    let mut graph = KnowledgeGraph::new();
    let garbage = b"this is not valid protobuf data at all";

    let mut loader = ScipLoader::new(&mut graph);
    let result = loader.load_scip_bytes(garbage);

    assert!(
        result.is_err(),
        "corrupt data should produce an error, not panic"
    );

    match result.unwrap_err() {
        h00ligan_engine::scip_loader::ScipLoaderError::ProtobufParse(_) => {
            // Expected error variant.
        }
        other => panic!("expected ProtobufParse error, got: {other:?}"),
    }
}

#[test]
fn test_scip_empty_index() {
    let mut graph = build_test_graph();

    // Empty but valid SCIP index.
    let index = Index::new();
    let bytes = serialize_index(&index);

    let mut loader = ScipLoader::new(&mut graph);
    let stats = loader
        .load_scip_bytes(&bytes)
        .expect("empty index should not error");

    assert_eq!(
        stats,
        ScipStats::default(),
        "empty index should produce zero stats"
    );
}

#[test]
fn test_edge_source_serde_roundtrip_uses_the_complete_current_shape() {
    let edge = GraphEdge {
        kind: EdgeKind::Calls,
        weight: 0.8,
        access_count: 3,
        last_accessed_ms: Some(17),
        created_at_ms: Some(11),
        source: EdgeSource::Scip,
        confidence: 0.95,
        scope: EdgeScope::Production,
    };

    let json = serde_json::to_string(&edge).expect("serialize current edge");
    let decoded: GraphEdge = serde_json::from_str(&json).expect("deserialize current edge");
    assert_eq!(decoded.kind, EdgeKind::Calls);
    assert_eq!(decoded.source, EdgeSource::Scip);
    assert_eq!(decoded.access_count, 3);
    assert_eq!(decoded.last_accessed_ms, Some(17));
    assert_eq!(decoded.created_at_ms, Some(11));
    assert!((decoded.weight - 0.8).abs() < f32::EPSILON);
    assert!((decoded.confidence - 0.95).abs() < f32::EPSILON);
}

#[test]
fn incomplete_edge_json_is_rejected_instead_of_inventing_missing_state() {
    let error = serde_json::from_str::<GraphEdge>(r#"{"kind":"Calls","weight":0.8}"#)
        .expect_err("the current edge contract requires every persisted field");
    assert!(
        error.to_string().contains("missing field"),
        "rejection must identify an incomplete record: {error}"
    );
}

/// Build a single-document SCIP index for a NON-h00 package `acme_widget`
/// where `caller()` references `helper()` — both intra-crate.
fn build_nonh00_caller_helper_index() -> Index {
    let mut index = Index::new();

    let mut doc = Document::new();
    doc.relative_path = "src/work.rs".to_string();

    // Definition of `caller` (in package acme_widget).
    let mut def_occ = Occurrence::new();
    def_occ.symbol = "rust-analyzer cargo acme_widget 0.1.0 work/caller().".to_string();
    def_occ.symbol_roles = SymbolRole::Definition.value();
    def_occ.range = vec![10, 4, 10, 13];
    def_occ.enclosing_range = vec![10, 0, 20, 0];

    // Reference to `helper` from inside `caller` (also package acme_widget).
    let mut ref_occ = Occurrence::new();
    ref_occ.symbol = "rust-analyzer cargo acme_widget 0.1.0 helpers/helper().".to_string();
    ref_occ.symbol_roles = 0;
    ref_occ.range = vec![12, 8, 12, 17];

    doc.occurrences = vec![def_occ, ref_occ];
    let mut caller_info = SymbolInformation::new();
    caller_info.symbol = "rust-analyzer cargo acme_widget 0.1.0 work/caller().".to_string();
    doc.symbols = vec![caller_info];

    // ADR-0044: the `helper` TARGET must be an indexed DEFINITION for the exact
    // identity join to bind the edge (the deleted name heuristic no longer
    // conjures it). Same acme_widget package, so arm (b)'s EMPTY-set loader still
    // drops the edge — the helper def is not collected (packaged symbol not in
    // the set) → the ref's target is unindexed → fail-closed.
    let mut helper_doc = Document::new();
    helper_doc.relative_path = "src/helpers.rs".to_string();
    let mut helper_def = Occurrence::new();
    helper_def.symbol = "rust-analyzer cargo acme_widget 0.1.0 helpers/helper().".to_string();
    helper_def.symbol_roles = SymbolRole::Definition.value();
    helper_def.range = vec![1, 0, 1, 6];
    helper_doc.occurrences = vec![helper_def];
    let mut helper_info = SymbolInformation::new();
    helper_info.symbol = "rust-analyzer cargo acme_widget 0.1.0 helpers/helper().".to_string();
    helper_doc.symbols = vec![helper_info];

    index.documents = vec![doc, helper_doc];
    index
}

/// Build a graph with `caller` (src/work.rs) and `helper` (src/helpers.rs)
/// nodes for the non-h00 fixture above.
fn build_nonh00_caller_helper_graph() -> (KnowledgeGraph, Uuid, Uuid) {
    let mut graph = KnowledgeGraph::new();

    let caller_id = Uuid::new_v4();
    graph
        .add_node(GraphNode {
            memory_id: caller_id,
            symbol_name: "caller".to_string(),
            kind: "function".to_string(),
            file_path: "src/work.rs".to_string(),
            content_hash: "caller".to_string(),
            signature: "fn caller()".to_string(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(10),
            line_end: Some(20),
            has_body: Some(true),
            visibility: "pub".to_string(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        })
        .expect("add caller");

    let helper_id = Uuid::new_v4();
    graph
        .add_node(GraphNode {
            memory_id: helper_id,
            symbol_name: "helper".to_string(),
            kind: "function".to_string(),
            file_path: "src/helpers.rs".to_string(),
            content_hash: "helper".to_string(),
            signature: "fn helper()".to_string(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(1),
            line_end: Some(3),
            has_body: Some(true),
            visibility: "pub".to_string(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        })
        .expect("add helper");

    (graph, caller_id, helper_id)
}

/// A non-h00 package resolves from SCIP's repository-owned `Document.symbols`
/// population without a Cargo-specific metadata probe. Definition-shaped
/// occurrences alone cannot grant the same package authority.
#[test]
fn scip_derives_nonh00_locality_and_rejects_occurrence_only_claims() {
    let index = build_nonh00_caller_helper_index();

    // Positive: the package is declared by symbols owned by admitted
    // repository documents, so the exact cross-file reference resolves.
    {
        let (mut graph, caller_id, helper_id) = build_nonh00_caller_helper_graph();
        let mut loader = ScipLoader::new(&mut graph);
        let stats = loader
            .load_scip_bytes(&serialize_index(&index))
            .expect("load non-h00 SCIP index");
        assert!(
            stats.symbols_found > 0,
            "positive control: the repository symbol population must be admitted"
        );

        let neighbors = graph.neighbors(&caller_id);
        let has_reference = neighbors
            .iter()
            .any(|(id, edge)| *id == helper_id && edge.kind == EdgeKind::References);
        assert!(
            has_reference,
            "expected References edge caller -> helper for repository-owned acme_widget"
        );
        assert!(
            neighbors
                .iter()
                .all(|(_, edge)| edge.kind != EdgeKind::Calls),
            "a raw function-shaped reference cannot establish Calls authority"
        );
    }

    // Negative: preserve the exact same definition/reference occurrences but
    // remove SCIP's repository-ownership declarations. The package must no
    // longer resolve merely because an occurrence claimed Definition.
    {
        let mut occurrence_only = index;
        for document in &mut occurrence_only.documents {
            document.symbols.clear();
        }
        let (mut graph, caller_id, helper_id) = build_nonh00_caller_helper_graph();
        let mut loader = ScipLoader::new(&mut graph);
        let _stats = loader
            .load_scip_bytes(&serialize_index(&occurrence_only))
            .expect("load occurrence-only negative control");

        let neighbors = graph.neighbors(&caller_id);
        let has_reference = neighbors
            .iter()
            .any(|(id, edge)| *id == helper_id && edge.kind == EdgeKind::References);
        assert!(
            !has_reference,
            "definition-shaped occurrences without Document.symbols ownership must not grant package authority"
        );
    }
}
