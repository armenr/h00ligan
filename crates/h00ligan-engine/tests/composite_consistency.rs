//! Composite consistency tests for code intelligence graph operations.
//!
//! Tests cover:
//! - Category 2: Cross-command consistency (4 tests)
//! - Category 3: CLI/MCP consistency via shared functions (3 tests)
//! - Category 4: Stability / idempotency (3 tests)
//! - Category 5: Error handling (3 tests)
//! - Category 6: Architecture-differentiated (3 tests)
//! - Category 7: Output size guards (2 tests)

#![cfg(feature = "code-intel")]

use uuid::Uuid;

use h00ligan_engine::code_intel_domain::ProjectInventory;
use h00ligan_engine::code_intel_inventory::{InventorySource, build_project_inventory};
use h00ligan_engine::graph::{EdgeKind, GraphEdge, GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_overview::extract_overview_data;
use h00ligan_engine::graph_query::{
    FileContext, Match, ReachabilityFilter, Resolution, find_test_callers, is_dependency_edge,
    levenshtein_distance, resolve_unique, reverse_bfs, symbol_not_found_candidates,
};
use h00ligan_engine::graph_stats::{compute_graph_stats, compute_reachability_summary};
use h00ligan_engine::reachability::ReachabilityClass;

// ============================================================================
// Helpers
// ============================================================================

fn make_node(name: &str, kind: &str, file_path: &str) -> GraphNode {
    GraphNode {
        memory_id: Uuid::new_v4(),
        symbol_name: name.to_string(),
        kind: kind.to_string(),
        file_path: file_path.to_string(),
        content_hash: format!("hash_{name}"),
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
    }
}

fn make_wired_node(name: &str, kind: &str, file_path: &str) -> GraphNode {
    GraphNode {
        reachability_class: ReachabilityClass::Wired,
        ..make_node(name, kind, file_path)
    }
}

fn make_dead_node(name: &str, kind: &str, file_path: &str) -> GraphNode {
    GraphNode {
        reachability_class: ReachabilityClass::Dead,
        ..make_node(name, kind, file_path)
    }
}

fn make_test_node(name: &str, file_path: &str) -> GraphNode {
    GraphNode {
        reachability_class: ReachabilityClass::TestOnly,
        ..make_node(name, "function", file_path)
    }
}

fn inventory_for_graph(graph: &KnowledgeGraph) -> ProjectInventory {
    let root = tempfile::tempdir().expect("project-inventory root");
    let sources = graph
        .all_nodes()
        .into_iter()
        .map(|node| InventorySource::new(&node.file_path, "rust"))
        .collect::<Vec<_>>();
    build_project_inventory(root.path(), &sources)
}

fn calls_edge() -> GraphEdge {
    GraphEdge {
        kind: EdgeKind::Calls,
        confidence: 0.9,
        ..GraphEdge::default()
    }
}

fn contains_edge() -> GraphEdge {
    GraphEdge {
        kind: EdgeKind::Contains,
        confidence: 1.0,
        ..GraphEdge::default()
    }
}

/// Build a test graph with known structure for cross-command tests:
///
/// ```text
/// main (function, wired) -- calls --> handler (function, wired)
///   handler -- calls --> helper (function, wired)
///     helper -- calls --> util (function, wired)
///
/// test_helper (function in tests/) -- calls --> helper
/// test_handler (function in tests/) -- calls --> handler
///
/// dead_fn (function, dead) -- no incoming edges
/// orphan_fn (function, dead) -- no incoming edges
///
/// MyStruct (struct, wired)
///   contains --> MyStruct::new (function, wired)
///   contains --> MyStruct::process (function, wired)
/// ```
#[allow(dead_code)] // Fixture fields available for future test expansion
struct ConsistencyFixture {
    graph: KnowledgeGraph,
    main_id: Uuid,
    handler_id: Uuid,
    helper_id: Uuid,
    util_id: Uuid,
    test_helper_id: Uuid,
    test_handler_id: Uuid,
    dead_fn_id: Uuid,
    orphan_fn_id: Uuid,
    my_struct_id: Uuid,
    my_struct_new_id: Uuid,
    my_struct_process_id: Uuid,
}

fn build_consistency_fixture() -> ConsistencyFixture {
    let mut g = KnowledgeGraph::new();

    let main_n = make_wired_node("main", "function", "crates/app/src/main.rs");
    let handler_n = make_wired_node("handler", "function", "crates/app/src/handler.rs");
    let helper_n = make_wired_node("helper", "function", "crates/app/src/helper.rs");
    let util_n = make_wired_node("util", "function", "crates/app/src/util.rs");

    let test_helper_n = make_test_node("test_helper", "crates/app/tests/test_helper.rs");
    let test_handler_n = make_test_node("test_handler", "crates/app/tests/test_handler.rs");

    let dead_fn_n = make_dead_node("dead_fn", "function", "crates/app/src/dead.rs");
    let orphan_fn_n = make_dead_node("orphan_fn", "function", "crates/app/src/orphan.rs");

    let my_struct_n = make_wired_node("MyStruct", "struct", "crates/app/src/types.rs");
    let my_struct_new_n = make_wired_node("MyStruct::new", "function", "crates/app/src/types.rs");
    let my_struct_process_n =
        make_wired_node("MyStruct::process", "function", "crates/app/src/types.rs");

    let main_id = main_n.memory_id;
    let handler_id = handler_n.memory_id;
    let helper_id = helper_n.memory_id;
    let util_id = util_n.memory_id;
    let test_helper_id = test_helper_n.memory_id;
    let test_handler_id = test_handler_n.memory_id;
    let dead_fn_id = dead_fn_n.memory_id;
    let orphan_fn_id = orphan_fn_n.memory_id;
    let my_struct_id = my_struct_n.memory_id;
    let my_struct_new_id = my_struct_new_n.memory_id;
    let my_struct_process_id = my_struct_process_n.memory_id;

    // Add all nodes
    for node in [
        main_n,
        handler_n,
        helper_n,
        util_n,
        test_helper_n,
        test_handler_n,
        dead_fn_n,
        orphan_fn_n,
        my_struct_n,
        my_struct_new_n,
        my_struct_process_n,
    ] {
        g.add_node(node).unwrap();
    }

    // Call chain: main -> handler -> helper -> util
    g.add_edge(main_id, handler_id, calls_edge()).unwrap();
    g.add_edge(handler_id, helper_id, calls_edge()).unwrap();
    g.add_edge(helper_id, util_id, calls_edge()).unwrap();

    // Test edges: test_helper -> helper, test_handler -> handler
    g.add_edge(test_helper_id, helper_id, calls_edge()).unwrap();
    g.add_edge(test_handler_id, handler_id, calls_edge())
        .unwrap();

    // Struct containment: MyStruct -> new, MyStruct -> process
    g.add_edge(my_struct_id, my_struct_new_id, contains_edge())
        .unwrap();
    g.add_edge(my_struct_id, my_struct_process_id, contains_edge())
        .unwrap();

    // handler also calls MyStruct::new
    g.add_edge(handler_id, my_struct_new_id, calls_edge())
        .unwrap();

    ConsistencyFixture {
        graph: g,
        main_id,
        handler_id,
        helper_id,
        util_id,
        test_helper_id,
        test_handler_id,
        dead_fn_id,
        orphan_fn_id,
        my_struct_id,
        my_struct_new_id,
        my_struct_process_id,
    }
}

// ============================================================================
// Category 2: Cross-Command Consistency Tests
// ============================================================================

/// T-CC1: assess test count matches standalone find_test_callers count.
///
/// reverse_bfs collects test files in its `test_files` map during traversal.
/// find_test_callers specifically finds test functions that exercise a symbol.
/// Both should agree on the number of test files touching the target.
#[test]
fn t_cc1_assess_test_count_matches_standalone_tests_count() {
    let f = build_consistency_fixture();

    // reverse_bfs from `helper` — should find test_helper in test_files
    let helper_node = f.graph.node(&f.helper_id).unwrap();
    let bfs_result = reverse_bfs(&f.graph, helper_node, 3, None);

    // find_test_callers for the same symbol
    let test_callers = find_test_callers(&f.graph, f.helper_id);

    // reverse_bfs counts test FILES, find_test_callers counts test FUNCTIONS.
    // For our fixture, test_helper (in tests/) calls helper.
    let bfs_test_file_count: usize = bfs_result.test_files.values().sum();
    let test_caller_count = test_callers.len();

    // Both should be non-zero — both should detect the test coverage.
    assert!(
        bfs_test_file_count > 0,
        "reverse_bfs should find test files for helper"
    );
    assert!(
        test_caller_count > 0,
        "find_test_callers should find test callers for helper"
    );

    // The test caller count should be >= the test file count
    // (multiple test functions can be in one file).
    assert!(
        test_caller_count >= bfs_test_file_count,
        "test caller count ({test_caller_count}) should be >= test file count ({bfs_test_file_count})"
    );
}

/// T-CC2: inspect field_types matches type field_types.
///
/// Both inspect (via reverse_bfs + structure) and type (via graph queries)
/// should see the same contained methods for MyStruct.
#[test]
fn t_cc2_inspect_structure_matches_type_structure() {
    let f = build_consistency_fixture();

    // MyStruct contains MyStruct::new and MyStruct::process via Contains edges.
    // Verify that neighbors (outgoing) gives us the contained methods.
    let contained: Vec<_> = f
        .graph
        .neighbors(&f.my_struct_id)
        .into_iter()
        .filter(|(_, e)| e.kind == EdgeKind::Contains)
        .collect();

    assert_eq!(
        contained.len(),
        2,
        "MyStruct should have 2 contained methods (new, process)"
    );

    // EP1 (ADR-0027): 'MyStruct' is a lone exact match → Unique (the FIXED
    // behavior, not a first-match artifact).
    let found_id = resolve_unique(&f.graph, "MyStruct", None)
        .unique_or_report()
        .expect("MyStruct is a lone exact match → Unique");
    assert_eq!(found_id.uuid(), f.my_struct_id);

    // The same struct's methods should be discoverable via contained edges
    let contained_ids: std::collections::HashSet<Uuid> =
        contained.iter().map(|(id, _)| *id).collect();
    assert!(
        contained_ids.contains(&f.my_struct_new_id),
        "MyStruct should contain MyStruct::new"
    );
    assert!(
        contained_ids.contains(&f.my_struct_process_id),
        "MyStruct should contain MyStruct::process"
    );
}

/// T-CC3: assess blast_radius matches direct reverse_bfs call.
///
/// The assess handler internally calls reverse_bfs. Running reverse_bfs
/// independently with the same parameters should produce identical results.
#[test]
fn t_cc3_assess_blast_radius_matches_direct_reverse_bfs() {
    let f = build_consistency_fixture();

    let helper_node = f.graph.node(&f.helper_id).unwrap();

    // Call reverse_bfs twice with identical parameters
    let result1 = reverse_bfs(&f.graph, helper_node, 3, None);
    let result2 = reverse_bfs(&f.graph, helper_node, 3, None);

    // Dependent counts must be identical
    assert_eq!(
        result1.dependents.len(),
        result2.dependents.len(),
        "reverse_bfs dependent count should be identical across calls"
    );

    // File count maps must be identical
    assert_eq!(
        result1.file_counts, result2.file_counts,
        "reverse_bfs file_counts should be identical across calls"
    );

    // Test file maps must be identical
    assert_eq!(
        result1.test_files, result2.test_files,
        "reverse_bfs test_files should be identical across calls"
    );

    // Verify non-trivial results (helper has callers: handler, main, test_helper)
    assert!(
        !result1.dependents.is_empty(),
        "helper should have dependents"
    );
}

/// T-CC4: dead verdict matches resolver round-trip reachability.
///
/// resolve_unique → graph.node for a dead symbol shows it as dead, and for a
/// wired symbol shows it as wired (reachability preserved across the round-trip).
#[test]
fn t_cc4_dead_verdict_matches_find_reachability() {
    let f = build_consistency_fixture();

    // Dead function
    let dead_node = f.graph.node(&f.dead_fn_id).unwrap();
    assert_eq!(
        dead_node.reachability_class,
        ReachabilityClass::Dead,
        "dead_fn should have Dead reachability class"
    );

    // Wired function
    let wired_node = f.graph.node(&f.helper_id).unwrap();
    assert_eq!(
        wired_node.reachability_class,
        ReachabilityClass::Wired,
        "helper should have Wired reachability class"
    );

    // EP1 (ADR-0027): both are lone exact matches → Unique; the resolver
    // round-trip (resolve_unique → graph.node) preserves reachability_class.
    let dead_id = resolve_unique(&f.graph, "dead_fn", None)
        .unique_or_report()
        .expect("dead_fn is a lone exact match → Unique");
    assert_eq!(
        f.graph.node(&dead_id.uuid()).unwrap().reachability_class,
        ReachabilityClass::Dead,
        "resolver round-trip should preserve Dead reachability"
    );

    let wired_id = resolve_unique(&f.graph, "helper", None)
        .unique_or_report()
        .expect("helper is a lone exact match → Unique");
    assert_eq!(
        f.graph.node(&wired_id.uuid()).unwrap().reachability_class,
        ReachabilityClass::Wired,
        "resolver round-trip should preserve Wired reachability"
    );
}

// ============================================================================
// Category 3: CLI/MCP Consistency Tests (via shared functions)
// ============================================================================
//
// Since FIX-1 through FIX-4a ensured both CLI and MCP call the same shared
// engine functions, testing the shared functions IS testing consistency.

/// T-CM1: reverse_bfs used by both CLI assess and MCP assess produces
/// consistent blast_radius data.
///
/// We verify that the shared reverse_bfs function returns structured data
/// that both CLI and MCP handlers can consume: dependents, file_counts,
/// test_files, and isolation_note.
#[test]
fn t_cm1_shared_reverse_bfs_produces_complete_assess_data() {
    let f = build_consistency_fixture();

    let handler_node = f.graph.node(&f.handler_id).unwrap();
    let result = reverse_bfs(&f.graph, handler_node, 3, None);

    // Verify all fields are populated and structurally valid
    assert!(
        !result.dependents.is_empty(),
        "handler has callers (main) so dependents should be non-empty"
    );

    // Each dependent should have valid fields
    for dep in &result.dependents {
        assert!(dep.depth > 0, "dependent depth should be > 0");
        assert!(
            is_dependency_edge(dep.edge_kind),
            "dependent edge should be a dependency edge, got {:?}",
            dep.edge_kind
        );
        assert!(
            !dep.node.symbol_name.is_empty(),
            "symbol name should not be empty"
        );
    }

    // file_counts should reflect which files the dependents are in
    assert!(
        !result.file_counts.is_empty(),
        "file_counts should be non-empty for a symbol with callers"
    );

    // test_files should capture test coverage
    assert!(
        !result.test_files.is_empty(),
        "test_files should be non-empty (test_handler calls handler)"
    );
}

/// T-CM2 (RETARGETED, ADR-0027): the shared resolver `resolve_unique` (used by
/// both CLI and MCP find) enforces the FIXED tier semantics — qualified exact →
/// Unique, a genuine bare-name homonym → Ambiguous (F8), substring → NotFound.
///
/// This INVERTS the deleted first-match-blessing version, which asserted bare
/// 'new' and substring 'Struct' SILENTLY resolved to a single node.
#[test]
fn t_cm2_shared_find_enforces_fixed_tier_semantics() {
    let mut f = build_consistency_fixture();

    // Qualified exact name → Unique.
    let exact = resolve_unique(&f.graph, "MyStruct::new", None)
        .unique_or_report()
        .expect("qualified 'MyStruct::new' is an exact-tier singleton → Unique");
    assert_eq!(exact.uuid(), f.my_struct_new_id);

    // Substring-only 'Struct' → NotFound (Substring is NOT a resolution tier).
    assert_eq!(
        resolve_unique(&f.graph, "Struct", None),
        Resolution::NotFound,
        "substring-only 'Struct' must be NotFound, never a silent resolution"
    );

    // Bare 'new' is currently a lone ::new suffix-tier match → Unique.
    let bare_new = resolve_unique(&f.graph, "new", None)
        .unique_or_report()
        .expect("bare 'new' is the lone ::new suffix match → Unique");
    assert_eq!(bare_new.uuid(), f.my_struct_new_id);

    // Add a cross-file sibling so bare 'new' becomes a genuine homonym → it
    // must now fire Ambiguous (F8), NOT silently pick one.
    let sibling = make_node("OtherStruct::new", "function", "other.rs");
    let sibling_id = sibling.memory_id;
    f.graph.add_node(sibling).unwrap();
    match resolve_unique(&f.graph, "new", None) {
        Resolution::Ambiguous(candidates) => {
            let ids: Vec<Uuid> = candidates.iter().map(|c| c.id.uuid()).collect();
            assert!(
                ids.contains(&f.my_struct_new_id),
                "MyStruct::new in F8 list"
            );
            assert!(ids.contains(&sibling_id), "OtherStruct::new in F8 list");
        }
        other => panic!("bare 'new' with two siblings must be Ambiguous, got {other:?}"),
    }
}

/// T-CM3: compute_graph_stats and compute_reachability_summary used by both
/// CLI and MCP dead/status produce consistent shared data.
#[test]
fn t_cm3_shared_stats_produce_consistent_data() {
    let f = build_consistency_fixture();

    let stats = compute_graph_stats(&f.graph);
    let reachability = compute_reachability_summary(&f.graph);

    // 11 nodes total in fixture
    assert_eq!(stats.node_count, 11, "should have 11 nodes");

    // Edge count should be positive
    assert!(stats.edge_count > 0, "should have edges");

    // Edge kinds should include Calls and Contains
    assert!(
        stats.edge_kinds.contains_key("Calls"),
        "should have Calls edges"
    );
    assert!(
        stats.edge_kinds.contains_key("Contains"),
        "should have Contains edges"
    );

    // Reachability summary should account for all 11 nodes
    let total_classified = reachability.wired
        + reachability.dead
        + reachability.test_only
        + reachability.unclassified
        + reachability.public_api
        + reachability.structural
        + reachability.orphan;
    assert_eq!(
        total_classified, stats.node_count,
        "reachability total ({total_classified}) should equal node count ({})",
        stats.node_count
    );

    // Our fixture has 7 wired, 2 dead, 2 test_only
    assert_eq!(reachability.wired, 7, "should have 7 wired nodes");
    assert_eq!(reachability.dead, 2, "should have 2 dead nodes");
    assert_eq!(reachability.test_only, 2, "should have 2 test_only nodes");
}

// ============================================================================
// Category 4: Stability Tests
// ============================================================================

/// T-S1: Idempotency — call reverse_bfs twice with the same graph and params.
/// Results must be identical.
#[test]
fn t_s1_reverse_bfs_idempotent() {
    let f = build_consistency_fixture();

    let util_node = f.graph.node(&f.util_id).unwrap();

    let result1 = reverse_bfs(&f.graph, util_node, 3, None);
    let result2 = reverse_bfs(&f.graph, util_node, 3, None);

    assert_eq!(
        result1.dependents.len(),
        result2.dependents.len(),
        "dependent count must be stable"
    );

    // Verify dependent node IDs are identical (order may vary, so compare sets)
    let ids1: std::collections::HashSet<Uuid> = result1
        .dependents
        .iter()
        .map(|d| d.node.memory_id)
        .collect();
    let ids2: std::collections::HashSet<Uuid> = result2
        .dependents
        .iter()
        .map(|d| d.node.memory_id)
        .collect();
    assert_eq!(ids1, ids2, "dependent IDs must be identical across calls");

    assert_eq!(
        result1.file_counts, result2.file_counts,
        "file_counts must be stable"
    );
    assert_eq!(
        result1.test_files, result2.test_files,
        "test_files must be stable"
    );
}

/// T-S2: Reindex stability — construct a graph, compute stats. Construct the
/// same graph again. Stats must be identical.
#[test]
fn t_s2_reindex_stability() {
    // Build the same fixture twice
    let f1 = build_consistency_fixture();
    let f2 = build_consistency_fixture();

    let stats1 = compute_graph_stats(&f1.graph);
    let stats2 = compute_graph_stats(&f2.graph);

    assert_eq!(
        stats1.node_count, stats2.node_count,
        "node count must be stable across identical graph constructions"
    );
    assert_eq!(
        stats1.edge_count, stats2.edge_count,
        "edge count must be stable across identical graph constructions"
    );

    // Edge kind distribution must match
    for (kind, count1) in &stats1.edge_kinds {
        let count2 = stats2.edge_kinds.get(kind).copied().unwrap_or(0);
        assert_eq!(
            *count1, count2,
            "edge kind {kind} count must be stable: {count1} vs {count2}"
        );
    }

    let reach1 = compute_reachability_summary(&f1.graph);
    let reach2 = compute_reachability_summary(&f2.graph);

    assert_eq!(reach1.wired, reach2.wired, "wired count must be stable");
    assert_eq!(reach1.dead, reach2.dead, "dead count must be stable");
    assert_eq!(
        reach1.test_only, reach2.test_only,
        "test_only count must be stable"
    );
}

/// T-S3: Empty graph — all operations return safe defaults, no crashes.
#[test]
fn t_s3_empty_graph_no_crash() {
    let g = KnowledgeGraph::new();

    // EP1 (ADR-0027): resolution on an empty graph is NotFound, and the sole
    // id-extractor returns Err(Ambiguity{candidates: []}).
    assert_eq!(resolve_unique(&g, "anything", None), Resolution::NotFound);
    let amb = resolve_unique(&g, "anything", None)
        .unique_or_report()
        .expect_err("empty graph → NotFound → Err");
    assert!(amb.candidates.is_empty(), "NotFound carries no candidates");

    // compute_graph_stats returns zeros
    let stats = compute_graph_stats(&g);
    assert_eq!(stats.node_count, 0, "empty graph has 0 nodes");
    assert_eq!(stats.edge_count, 0, "empty graph has 0 edges");
    assert!(stats.edge_kinds.is_empty(), "empty graph has no edge kinds");

    // compute_reachability_summary returns zeros
    let reach = compute_reachability_summary(&g);
    assert_eq!(reach.wired, 0);
    assert_eq!(reach.dead, 0);
    assert_eq!(reach.test_only, 0);
    assert_eq!(reach.unclassified, 0);
    assert_eq!(reach.public_api, 0);
    assert_eq!(reach.structural, 0);
    assert_eq!(reach.orphan, 0);

    // symbol_not_found_candidates returns empty
    let candidates = symbol_not_found_candidates(&g, "anything");
    assert!(
        candidates.is_empty(),
        "empty graph should return no candidates"
    );

    // reverse_bfs on a synthetic node should return empty dependents.
    // We need a node reference — create one manually but don't add to graph.
    // Actually, reverse_bfs needs a node IN the graph. Since graph is empty,
    // we add a single node and verify reverse_bfs returns no dependents
    // (since there are no incoming edges).
    let mut g2 = KnowledgeGraph::new();
    let solo = make_node("solo", "function", "src/solo.rs");
    let solo_id = solo.memory_id;
    g2.add_node(solo).unwrap();

    let solo_ref = g2.node(&solo_id).unwrap();
    let bfs = reverse_bfs(&g2, solo_ref, 3, None);
    assert!(
        bfs.dependents.is_empty(),
        "solo node with no edges should have no dependents"
    );
    assert!(
        bfs.file_counts.is_empty(),
        "solo node should have no file counts"
    );
    assert!(
        bfs.test_files.is_empty(),
        "solo node should have no test files"
    );
}

// ============================================================================
// Category 5: Error Handling Tests
// ============================================================================

/// T-E1: Symbol not found — returns None for nonexistent symbol.
/// symbol_not_found_candidates returns empty for a completely unrelated query.
#[test]
fn t_e1_symbol_not_found_graceful() {
    let f = build_consistency_fixture();

    // EP1 (ADR-0027): a garbage name resolves to NotFound, never a panic or pick.
    assert_eq!(
        resolve_unique(&f.graph, "nonexistent_symbol_xyz_12345", None),
        Resolution::NotFound,
        "nonexistent symbol should be NotFound, not panic"
    );

    // symbol_not_found_candidates with garbage should return empty
    // (no symbol is within levenshtein distance 3 of this string)
    let candidates = symbol_not_found_candidates(&f.graph, "zzzzzzzzzzzzzzzzzzzzzzz");
    assert!(
        candidates.is_empty(),
        "completely unrelated query should return no candidates"
    );
}

/// T-E2: Levenshtein suggestions — off-by-one typo returns suggestions.
#[test]
fn t_e2_levenshtein_suggestions_for_typo() {
    let f = build_consistency_fixture();

    // Direct levenshtein_distance test
    assert_eq!(
        levenshtein_distance("handler", "handlr"),
        1,
        "handlr -> handler should be distance 1"
    );
    assert_eq!(
        levenshtein_distance("handler", "handler"),
        0,
        "identical strings should be distance 0"
    );
    assert_eq!(
        levenshtein_distance("", "abc"),
        3,
        "empty to abc should be distance 3"
    );
    assert_eq!(
        levenshtein_distance("abc", ""),
        3,
        "abc to empty should be distance 3"
    );

    // symbol_not_found_candidates should suggest "handler" for "handlr"
    let candidates = symbol_not_found_candidates(&f.graph, "handlr");
    assert!(
        !candidates.is_empty(),
        "typo 'handlr' should produce candidate suggestions"
    );
    // At least one candidate should be "handler"
    let has_handler = candidates.iter().any(|(name, _)| name == "handler");
    assert!(
        has_handler,
        "candidates for 'handlr' should include 'handler'. Got: {:?}",
        candidates
    );
    // The distance should be 1
    let handler_entry = candidates.iter().find(|(name, _)| name == "handler");
    assert_eq!(
        handler_entry.unwrap().1,
        1,
        "'handler' should be at distance 1 from 'handlr'"
    );
}

/// T-E3: Truncation — find_test_callers results can be safely truncated.
#[test]
fn t_e3_truncation_safety() {
    // Build a graph with many test callers for a single target
    let mut g = KnowledgeGraph::new();

    let target = make_wired_node("target_fn", "function", "crates/app/src/lib.rs");
    let target_id = target.memory_id;
    g.add_node(target).unwrap();

    // Create 100 test callers
    for i in 0..100 {
        let test_node = make_test_node(
            &format!("test_{i}"),
            &format!("crates/app/tests/test_{i}.rs"),
        );
        let test_id = test_node.memory_id;
        g.add_node(test_node).unwrap();
        g.add_edge(test_id, target_id, calls_edge()).unwrap();
    }

    let test_callers = find_test_callers(&g, target_id);

    // Should find all 100 test callers
    assert_eq!(test_callers.len(), 100, "should find all 100 test callers");

    // Apply truncation logic (cap at 50, as the handlers do)
    let truncated: Vec<_> = test_callers.into_iter().take(50).collect();
    assert_eq!(
        truncated.len(),
        50,
        "truncated results should have 50 entries"
    );

    // Each entry should have a valid call path
    for (node, path) in &truncated {
        assert!(
            !node.symbol_name.is_empty(),
            "test node name should not be empty"
        );
        assert!(!path.is_empty(), "call path should not be empty");
    }
}

// ============================================================================
// Category 6: Architecture-Differentiated Tests
// ============================================================================

/// T-A1: Compositional correctness — assess data contains all components
/// (blast_radius, test data, risk data) when the graph has relevant data.
#[test]
fn t_a1_compositional_correctness() {
    let f = build_consistency_fixture();

    let handler_node = f.graph.node(&f.handler_id).unwrap();
    let bfs_result = reverse_bfs(&f.graph, handler_node, 3, None);
    let test_callers = find_test_callers(&f.graph, f.handler_id);

    // Blast radius data should be populated
    assert!(
        !bfs_result.dependents.is_empty(),
        "handler has callers, blast radius should be non-empty"
    );

    // Test data should be populated
    assert!(
        !test_callers.is_empty(),
        "handler has test callers, test data should be non-empty"
    );

    // Test files from BFS should also be populated
    assert!(
        !bfs_result.test_files.is_empty(),
        "BFS test_files should capture test coverage"
    );

    // File counts should be populated (callers come from different files)
    assert!(
        !bfs_result.file_counts.is_empty(),
        "file_counts should be populated for handler with callers"
    );

    // Verify the dependents include expected symbols
    assert!(
        bfs_result
            .dependents
            .iter()
            .any(|d| d.node.symbol_name == "main"),
        "handler's dependents should include main"
    );
}

/// T-A2: Cross-command arithmetic — reachability summary totals equal node count.
#[test]
fn t_a2_cross_command_arithmetic() {
    let f = build_consistency_fixture();

    let stats = compute_graph_stats(&f.graph);
    let reachability = compute_reachability_summary(&f.graph);

    let total_reachability = reachability.wired
        + reachability.public_api
        + reachability.structural
        + reachability.test_only
        + reachability.dead
        + reachability.orphan
        + reachability.unclassified;

    assert_eq!(
        total_reachability,
        stats.node_count,
        "sum of all reachability classes ({total_reachability}) must equal \
         total node count ({node_count}). Breakdown: wired={w}, public_api={pa}, \
         structural={s}, test_only={to}, dead={d}, orphan={o}, unclassified={u}",
        node_count = stats.node_count,
        w = reachability.wired,
        pa = reachability.public_api,
        s = reachability.structural,
        to = reachability.test_only,
        d = reachability.dead,
        o = reachability.orphan,
        u = reachability.unclassified,
    );
}

/// T-A3: Filter composition — reverse_bfs with ReachabilityFilter::Wired
/// returns only wired/public_api/structural nodes.
#[test]
fn t_a3_filter_composition() {
    let f = build_consistency_fixture();

    let helper_node = f.graph.node(&f.helper_id).unwrap();

    // Unfiltered BFS should include test nodes
    let unfiltered = reverse_bfs(&f.graph, helper_node, 3, None);

    // Wired-filtered BFS should exclude test-only nodes
    let wired_only = reverse_bfs(&f.graph, helper_node, 3, Some(ReachabilityFilter::Wired));

    // Unfiltered should have more (or equal) dependents than wired-only
    assert!(
        unfiltered.dependents.len() >= wired_only.dependents.len(),
        "unfiltered ({}) should have >= dependents than wired-only ({})",
        unfiltered.dependents.len(),
        wired_only.dependents.len()
    );

    // All wired-only dependents must have wired-compatible reachability
    for dep in &wired_only.dependents {
        let rc = dep.node.reachability_class;
        let is_wired_compatible = matches!(
            rc,
            ReachabilityClass::Wired
                | ReachabilityClass::PublicApi
                | ReachabilityClass::Structural
                | ReachabilityClass::Unclassified // unclassified passes Wired filter
        );
        assert!(
            is_wired_compatible,
            "wired-filtered BFS should only return wired-compatible nodes, \
             got {:?} for {}",
            rc, dep.node.symbol_name
        );
    }

    // Verify that test-only nodes are excluded from wired filter
    let wired_names: std::collections::HashSet<&str> = wired_only
        .dependents
        .iter()
        .map(|d| d.node.symbol_name.as_str())
        .collect();
    assert!(
        !wired_names.contains("test_helper"),
        "test_helper (TestOnly) should be excluded from wired-only results"
    );
}

// ============================================================================
// Category 7: Output Size Guards
// ============================================================================

/// T-OS1: find_test_callers output stays manageable after truncation.
#[test]
fn t_os1_test_callers_output_bounded() {
    let mut g = KnowledgeGraph::new();

    let target = make_wired_node("popular_fn", "function", "crates/lib/src/lib.rs");
    let target_id = target.memory_id;
    g.add_node(target).unwrap();

    // Create 200 test callers with long names
    for i in 0..200 {
        let name = format!(
            "tests::integration::very_long_test_module_name::test_case_{i}_with_descriptive_name"
        );
        let test_node = make_test_node(&name, &format!("crates/lib/tests/integration/test_{i}.rs"));
        let test_id = test_node.memory_id;
        g.add_node(test_node).unwrap();
        g.add_edge(test_id, target_id, calls_edge()).unwrap();
    }

    let test_callers = find_test_callers(&g, target_id);
    assert_eq!(test_callers.len(), 200, "should find all 200 test callers");

    // Apply truncation (cap at 50)
    let truncated: Vec<_> = test_callers.into_iter().take(50).collect();

    // Serialize to check size
    let mut output = String::new();
    for (node, path) in &truncated {
        output.push_str(&format!("{}: {}\n", node.symbol_name, path.join(" -> ")));
    }

    // Output should be under 50KB for 50 entries
    assert!(
        output.len() < 50_000,
        "truncated test callers output should be under 50KB, got {} bytes",
        output.len()
    );
}

/// T-OS2: the raw Overview projection remains compact. Audit v1's exact
/// product bound is exercised through its real CLI/MCP boundary contract.
#[test]
fn t_os2_overview_output_bounded() {
    let f = build_consistency_fixture();

    let inventory = inventory_for_graph(&f.graph);
    let overview = extract_overview_data(&f.graph, &inventory);

    // Verify overview is populated from graph data
    assert_eq!(overview.total_nodes, 11, "overview should report 11 nodes");
    assert!(overview.total_edges > 0, "overview should report edges");
    assert!(
        overview.dead_code_count > 0,
        "overview should detect dead code"
    );

    // Serialize overview fields to check approximate size
    let overview_json = serde_json::json!({
        "total_nodes": overview.total_nodes,
        "total_edges": overview.total_edges,
        "project_units": overview.project_units.len(),
        "dead_code_count": overview.dead_code_count,
    });
    let overview_str = serde_json::to_string(&overview_json).unwrap();
    assert!(
        overview_str.len() < 100_000,
        "overview JSON should be under 100KB, got {} bytes",
        overview_str.len()
    );
}

// ============================================================================
// EP1 CLI≡MCP parity falsifiers (ADR-0027 / WU-0002 Wave 3)
//
// The CLI (`composite_cmd::ambiguous_symbol_error`) and MCP
// (`code_intel::resolve_unique_or_tool_err`) F8 renderers BOTH derive their
// per-candidate label from the single source of truth `Match::candidate_label`.
// Asserting that function's output here proves byte-for-byte parity by
// construction: there is no second label formatter to drift.
// ============================================================================

/// Two suffix-tier siblings sharing the bare name `store`, in different files,
/// with DIFFERING reachability. `foostore_dead` selects which sibling is Dead.
/// Returns `(graph, foostore_id, barstore_id)`.
fn parity_store_fixture(foostore_dead: bool) -> (KnowledgeGraph, Uuid, Uuid) {
    let mut g = KnowledgeGraph::new();
    let (foostore, barstore) = if foostore_dead {
        (
            make_dead_node("FooStore::store", "function", "crates/app/src/foo.rs"),
            make_wired_node("BarStore::store", "function", "crates/app/src/bar.rs"),
        )
    } else {
        (
            make_wired_node("FooStore::store", "function", "crates/app/src/foo.rs"),
            make_dead_node("BarStore::store", "function", "crates/app/src/bar.rs"),
        )
    };
    let foostore_id = foostore.memory_id;
    let barstore_id = barstore.memory_id;
    g.add_node(foostore).unwrap();
    g.add_node(barstore).unwrap();
    (g, foostore_id, barstore_id)
}

/// P-PARITY-1: a bare-name homonym with differing reachability fires Ambiguous
/// (F8) enumerating BOTH siblings with the canonical structured `symbol (file)`
/// label — never an is_dead/WIRED pick, never an alphabetical/insertion pick.
#[test]
fn p_parity_1_bare_homonym_fires_f8_with_structured_label() {
    let (g, foostore_id, barstore_id) = parity_store_fixture(true); // FooStore Dead, BarStore Wired

    let candidates = match resolve_unique(&g, "store", None) {
        Resolution::Ambiguous(c) => c,
        other => panic!("bare 'store' must be Ambiguous, got {other:?}"),
    };

    // (1)(4)(5) BOTH siblings enumerated; NEITHER picked as Unique.
    let ids: Vec<Uuid> = candidates.iter().map(|c| c.id.uuid()).collect();
    assert!(
        ids.contains(&foostore_id),
        "FooStore::store must be in the F8 list"
    );
    assert!(
        ids.contains(&barstore_id),
        "BarStore::store must be in the F8 list"
    );
    assert_eq!(candidates.len(), 2, "exactly the two siblings, no pick");

    // (3) The canonical structured label is `symbol (file_path)` — the single
    // source of truth BOTH CLI and MCP render, so their labels are identical.
    let labels: Vec<String> = candidates.iter().map(Match::candidate_label).collect();
    assert!(
        labels.contains(&"FooStore::store (crates/app/src/foo.rs)".to_string()),
        "structured label, got {labels:?}"
    );
    assert!(
        labels.contains(&"BarStore::store (crates/app/src/bar.rs)".to_string()),
        "structured label, got {labels:?}"
    );
    // Pre-fix MCP emitted `file::symbol` ('crates/app/src/foo.rs::FooStore::store');
    // assert that lossy form is NOT produced.
    assert!(
        !labels.iter().any(|l| l.contains("::FooStore::store")),
        "must NOT use the lossy file::symbol label, got {labels:?}"
    );
}

/// P-PARITY-2: REVERSE-INVERSION of P-PARITY-1 — swap which sibling is Dead.
/// The F8 diagnostic is reachability- and ordering-independent: an alphabetical
/// resolver would pick BarStore (< FooStore) in BOTH variants; F8 picks neither.
#[test]
fn p_parity_2_reverse_inversion_reachability_independent() {
    let (g, foostore_id, barstore_id) = parity_store_fixture(false); // BarStore Dead, FooStore Wired

    let candidates = match resolve_unique(&g, "store", None) {
        Resolution::Ambiguous(c) => c,
        other => panic!("bare 'store' must STILL be Ambiguous after swap, got {other:?}"),
    };
    let ids: Vec<Uuid> = candidates.iter().map(|c| c.id.uuid()).collect();
    assert!(
        ids.contains(&foostore_id) && ids.contains(&barstore_id),
        "both still enumerated"
    );
    assert_eq!(candidates.len(), 2, "still picks neither sibling");
}

/// F8-ROUNDTRIP: a candidate's structured `{file_path, symbol}` re-resolves to
/// EXACTLY that one node — the F8 label is an actionable round-trip key.
#[test]
fn f8_candidate_label_round_trips_to_one_node() {
    let (g, _foostore_id, _barstore_id) = parity_store_fixture(true);

    let candidates = match resolve_unique(&g, "store", None) {
        Resolution::Ambiguous(c) => c,
        other => panic!("expected Ambiguous, got {other:?}"),
    };

    // Pick a candidate and feed its qualified name + FileContext(file_path) back.
    let pick = &candidates[0];
    let resolved = resolve_unique(
        &g,
        &pick.symbol_name,
        Some(FileContext::from(pick.file_path.clone())),
    )
    .unique_or_report()
    .expect("a candidate's {symbol, file} must re-resolve to exactly one node");
    assert_eq!(
        resolved.uuid(),
        pick.id.uuid(),
        "round-trip resolves to exactly the node the candidate identified"
    );
}

// ============================================================================
// CL-REACH-08 — shared-signal anchor for the CLI≡MCP UNCLASSIFIED-banner
// parity falsifier (WU-0003 Leg C signal -> render wire).
//
// This is the THIRD co-located assertion over the one shared signal contract.
// It is the ONLY crate that can run `extract_overview_data` + the `make_node`
// Unclassified helper, so it anchors the REAL extraction route (R1): an
// all-Unclassified graph -> `unclassified_count > 0` /
// `needs_unclassified_banner() == true` / `dead_code_count == 0`. The two
// surface render tests (MCP `format_overview_json` in h00ligan-interface, CLI
// `render_overview_text` / `build_overview_json` in h00ligan) consume this
// same signal and assert byte-identical `unclassified_count` /
// `needs_unclassified` JSON keys — the cross-crate split is unavoidable (no
// single crate sees both real render fns), so parity is enforced by these
// three assertions against one contract, not one unified call site.
// ============================================================================

/// CL-REACH-08 (signal anchor): an all-Unclassified graph routes through
/// `extract_overview_data` to a NON-zero `unclassified_count`, fires the banner
/// signal, and — crucially — keeps `dead_code_count == 0`. The last assertion
/// IS the false-clean trap the banner guards: Unclassified nodes are NOT dead,
/// so a naive `dead=0` read would falsely report "clean".
#[test]
fn cl_reach_08_unclassified_graph_fires_banner_signal_not_false_clean() {
    let mut g = KnowledgeGraph::new();

    // `make_node` defaults to ReachabilityClass::Unclassified, so these nodes
    // are exactly the loaded-but-unindexed (never-classified) shape.
    g.add_node(make_node(
        "unindexed_fn",
        "function",
        "crates/app/src/lib.rs",
    ))
    .unwrap();
    g.add_node(make_node(
        "UnindexedStruct",
        "struct",
        "crates/app/src/types.rs",
    ))
    .unwrap();

    let inventory = inventory_for_graph(&g);
    let overview = extract_overview_data(&g, &inventory);

    // The signal layer (WU-0003 Leg C) is live: an all-Unclassified graph yields
    // a non-zero unclassified_count and fires the banner.
    assert!(
        overview.unclassified_count > 0,
        "all-Unclassified graph -> nonzero unclassified_count, got {}",
        overview.unclassified_count
    );
    assert!(
        overview.needs_unclassified_banner(),
        "the UNCLASSIFIED banner signal must fire on an unclassified graph"
    );

    // THE FALSE-CLEAN TRAP THE BANNER GUARDS: Unclassified nodes are routed to
    // the Unclassified bucket, NOT the dead bucket, so dead_code_count stays 0.
    // Without the banner, a `dead=0` read would falsely report a clean graph.
    assert_eq!(
        overview.dead_code_count, 0,
        "Unclassified nodes are NOT dead — dead=0 here is the false-clean the banner guards"
    );
}
