//! Integration tests for graph query helpers (code intelligence).
//!
//! Tests cover dependency impact, trait bridging, wide-graph regression,
//! and symbol-resolution consistency guards.

#![cfg(feature = "code-intel")]

use uuid::Uuid;

use h00ligan_engine::graph::{EdgeKind, GraphEdge, GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_query::{
    Resolution, find_impl_methods_for_trait, is_dependency_edge, resolve_unique,
};
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

fn edge_of(kind: EdgeKind) -> GraphEdge {
    GraphEdge {
        kind,
        ..GraphEdge::default()
    }
}

/// Build a realistic 20+ node graph fixture representing a small project:
///
/// ```text
/// main (function, src/main.rs)
///   ├─ Contains ─> run (function, src/main.rs)
///   │    └─ Calls ─> Engine::start (function, src/engine.rs)
///   │         └─ Calls ─> Storage::open (function, src/storage.rs)
///   │              └─ Calls ─> Storage::init (function, src/storage.rs)
///   ├─ Contains ─> cli_module (module, src/main.rs)
///   │    └─ Contains ─> parse_args (function, src/main.rs)
///
/// Engine (struct, src/engine.rs)
///   ├─ Contains ─> Engine::start
///   ├─ Contains ─> Engine::stop (function, src/engine.rs)
///   ├─ Implements ─> Backend (trait, src/backend.rs)
///   └─ Calls ─> Logger::log (function, src/logger.rs)
///
/// Backend (trait, src/backend.rs)
///   ├─ Contains ─> Backend::start (function, src/backend.rs)
///   └─ Contains ─> Backend::stop (function, src/backend.rs)
///
/// impl Backend for Engine::start — Implements edge to Backend::start
/// impl Backend for Engine::stop — Implements edge to Backend::stop
///
/// Storage (struct, src/storage.rs)
///   ├─ Contains ─> Storage::open
///   ├─ Contains ─> Storage::init
///   └─ Contains ─> Storage::close (function, src/storage.rs)
///
/// Logger (struct, src/logger.rs)
///   └─ Contains ─> Logger::log
///
/// util_module (module, src/util.rs)
///   └─ Contains ─> helper_fn (function, src/util.rs)
///
/// dead_fn (function, src/dead.rs)  -- no edges, dead code
/// orphan_fn (function, src/orphan.rs) -- no edges, dead code
///
/// main ── RelatedTo ──> dead_fn (should NOT make dead_fn reachable)
/// ```
#[allow(dead_code)] // Fixture fields are available for future test expansion
struct TestFixture {
    graph: KnowledgeGraph,
    main_id: Uuid,
    run_id: Uuid,
    engine_start_id: Uuid,
    engine_stop_id: Uuid,
    storage_open_id: Uuid,
    storage_init_id: Uuid,
    storage_close_id: Uuid,
    backend_trait_id: Uuid,
    backend_start_id: Uuid,
    backend_stop_id: Uuid,
    logger_log_id: Uuid,
    helper_fn_id: Uuid,
    dead_fn_id: Uuid,
    orphan_fn_id: Uuid,
    cli_module_id: Uuid,
    parse_args_id: Uuid,
    engine_id: Uuid,
    storage_id: Uuid,
    logger_id: Uuid,
    util_module_id: Uuid,
    impl_backend_engine_start_id: Uuid,
    impl_backend_engine_stop_id: Uuid,
}

fn build_fixture() -> TestFixture {
    let mut g = KnowledgeGraph::new();

    // Nodes
    let main_n = make_node("main", "function", "src/main.rs");
    let run_n = make_node("run", "function", "src/main.rs");
    let cli_module_n = make_node("cli_module", "module", "src/main.rs");
    let parse_args_n = make_node("parse_args", "function", "src/main.rs");

    let engine_n = make_node("Engine", "struct", "src/engine.rs");
    let engine_start_n = make_node("Engine::start", "function", "src/engine.rs");
    let engine_stop_n = make_node("Engine::stop", "function", "src/engine.rs");

    let backend_n = make_node("Backend", "trait", "src/backend.rs");
    let backend_start_n = make_node("Backend::start", "function", "src/backend.rs");
    let backend_stop_n = make_node("Backend::stop", "function", "src/backend.rs");

    let impl_start_n = make_node(
        "impl Backend for Engine::start",
        "function",
        "src/engine.rs",
    );
    let impl_stop_n = make_node("impl Backend for Engine::stop", "function", "src/engine.rs");

    let storage_n = make_node("Storage", "struct", "src/storage.rs");
    let storage_open_n = make_node("Storage::open", "function", "src/storage.rs");
    let storage_init_n = make_node("Storage::init", "function", "src/storage.rs");
    let storage_close_n = make_node("Storage::close", "function", "src/storage.rs");

    let logger_n = make_node("Logger", "struct", "src/logger.rs");
    let logger_log_n = make_node("Logger::log", "function", "src/logger.rs");

    let util_module_n = make_node("util_module", "module", "src/util.rs");
    let helper_fn_n = make_node("helper_fn", "function", "src/util.rs");

    let dead_fn_n = make_node("dead_fn", "function", "src/dead.rs");
    let orphan_fn_n = make_node("orphan_fn", "function", "src/orphan.rs");

    // Capture IDs
    let main_id = main_n.memory_id;
    let run_id = run_n.memory_id;
    let cli_module_id = cli_module_n.memory_id;
    let parse_args_id = parse_args_n.memory_id;
    let engine_id = engine_n.memory_id;
    let engine_start_id = engine_start_n.memory_id;
    let engine_stop_id = engine_stop_n.memory_id;
    let backend_trait_id = backend_n.memory_id;
    let backend_start_id = backend_start_n.memory_id;
    let backend_stop_id = backend_stop_n.memory_id;
    let impl_start_id = impl_start_n.memory_id;
    let impl_stop_id = impl_stop_n.memory_id;
    let storage_id = storage_n.memory_id;
    let storage_open_id = storage_open_n.memory_id;
    let storage_init_id = storage_init_n.memory_id;
    let storage_close_id = storage_close_n.memory_id;
    let logger_id = logger_n.memory_id;
    let logger_log_id = logger_log_n.memory_id;
    let util_module_id = util_module_n.memory_id;
    let helper_fn_id = helper_fn_n.memory_id;
    let dead_fn_id = dead_fn_n.memory_id;
    let orphan_fn_id = orphan_fn_n.memory_id;

    // Add all nodes
    g.add_node(main_n).unwrap();
    g.add_node(run_n).unwrap();
    g.add_node(cli_module_n).unwrap();
    g.add_node(parse_args_n).unwrap();
    g.add_node(engine_n).unwrap();
    g.add_node(engine_start_n).unwrap();
    g.add_node(engine_stop_n).unwrap();
    g.add_node(backend_n).unwrap();
    g.add_node(backend_start_n).unwrap();
    g.add_node(backend_stop_n).unwrap();
    g.add_node(impl_start_n).unwrap();
    g.add_node(impl_stop_n).unwrap();
    g.add_node(storage_n).unwrap();
    g.add_node(storage_open_n).unwrap();
    g.add_node(storage_init_n).unwrap();
    g.add_node(storage_close_n).unwrap();
    g.add_node(logger_n).unwrap();
    g.add_node(logger_log_n).unwrap();
    g.add_node(util_module_n).unwrap();
    g.add_node(helper_fn_n).unwrap();
    g.add_node(dead_fn_n).unwrap();
    g.add_node(orphan_fn_n).unwrap();

    // 22 nodes total

    // Edges: structural containment
    g.add_edge(main_id, run_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(main_id, cli_module_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(cli_module_id, parse_args_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(engine_id, engine_start_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(engine_id, engine_stop_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(
        backend_trait_id,
        backend_start_id,
        edge_of(EdgeKind::Contains),
    )
    .unwrap();
    g.add_edge(
        backend_trait_id,
        backend_stop_id,
        edge_of(EdgeKind::Contains),
    )
    .unwrap();
    g.add_edge(storage_id, storage_open_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(storage_id, storage_init_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(storage_id, storage_close_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(logger_id, logger_log_id, edge_of(EdgeKind::Contains))
        .unwrap();
    g.add_edge(util_module_id, helper_fn_id, edge_of(EdgeKind::Contains))
        .unwrap();

    // Edges: call graph
    g.add_edge(run_id, engine_start_id, edge_of(EdgeKind::Calls))
        .unwrap();
    g.add_edge(engine_start_id, storage_open_id, edge_of(EdgeKind::Calls))
        .unwrap();
    g.add_edge(storage_open_id, storage_init_id, edge_of(EdgeKind::Calls))
        .unwrap();
    g.add_edge(engine_id, logger_log_id, edge_of(EdgeKind::Calls))
        .unwrap();

    // Edges: trait implementation
    g.add_edge(engine_id, backend_trait_id, edge_of(EdgeKind::Implements))
        .unwrap();
    g.add_edge(
        impl_start_id,
        backend_start_id,
        edge_of(EdgeKind::Implements),
    )
    .unwrap();
    g.add_edge(impl_stop_id, backend_stop_id, edge_of(EdgeKind::Implements))
        .unwrap();

    // Edge: RelatedTo (should be excluded from reachability)
    g.add_edge(main_id, dead_fn_id, edge_of(EdgeKind::RelatedTo))
        .unwrap();

    TestFixture {
        graph: g,
        main_id,
        run_id,
        engine_start_id,
        engine_stop_id,
        storage_open_id,
        storage_init_id,
        storage_close_id,
        backend_trait_id,
        backend_start_id,
        backend_stop_id,
        logger_log_id,
        helper_fn_id,
        dead_fn_id,
        orphan_fn_id,
        cli_module_id,
        parse_args_id,
        engine_id,
        storage_id,
        logger_id,
        util_module_id,
        impl_backend_engine_start_id: impl_start_id,
        impl_backend_engine_stop_id: impl_stop_id,
    }
}

// ============================================================================
// R4: Integration tests on realistic graph fixture
// ============================================================================

/// Blast radius: Engine::start has callers (run) and is contained in Engine.
/// Via reverse trait bridging, Backend::start should also find
/// impl Backend for Engine::start.
#[test]
fn test_blast_radius_with_trait_bridging() {
    let f = build_fixture();

    // EP1 (ADR-0027): 'Backend::start' is a qualified exact-tier singleton →
    // Unique (the FIXED behavior). Round-trip to the node for trait bridging.
    let trait_method_id = resolve_unique(&f.graph, "Backend::start", None)
        .unique_or_report()
        .expect("qualified 'Backend::start' is an exact-tier singleton → Unique");
    assert_eq!(trait_method_id.uuid(), f.backend_start_id);
    let trait_method = f.graph.node(&trait_method_id.uuid()).unwrap();

    // Reverse bridging: find impl methods for this trait method
    let impls = find_impl_methods_for_trait(&f.graph, trait_method);
    assert_eq!(
        impls.len(),
        1,
        "should find exactly 1 impl of Backend::start"
    );
    assert_eq!(
        impls[0].symbol_name, "impl Backend for Engine::start",
        "should find the correct impl method"
    );

    // Also verify the dependency edge filter works for blast radius
    // Engine::start is called by run via Calls edge -- Calls is a dependency edge
    assert!(
        is_dependency_edge(EdgeKind::Calls),
        "Calls should be a dependency edge"
    );
    assert!(
        is_dependency_edge(EdgeKind::Contains),
        "Contains should be a dependency edge (structural containment for BFS escape)"
    );
    assert!(
        !is_dependency_edge(EdgeKind::RelatedTo),
        "RelatedTo should NOT be a dependency edge"
    );
}

/// Reachability via `KnowledgeGraph::reachable()` -- verify wired vs dead.
/// With the R5 edge filter, RelatedTo edges should NOT make dead_fn reachable.
#[test]
fn test_is_wired_integration() {
    let f = build_fixture();

    // From main, depth 10 should find run, cli_module, parse_args,
    // engine_start, storage_open, storage_init via call/contain edges.
    // But NOT dead_fn (only RelatedTo edge from main).
    let reachable = f.graph.reachable(&f.main_id, 10);
    let reachable_ids: std::collections::HashSet<Uuid> =
        reachable.iter().map(|(id, _)| *id).collect();

    // Wired nodes (reachable from main)
    assert!(
        reachable_ids.contains(&f.main_id),
        "main should be reachable from itself"
    );
    assert!(
        reachable_ids.contains(&f.run_id),
        "run should be reachable (Contains from main)"
    );
    assert!(
        reachable_ids.contains(&f.engine_start_id),
        "Engine::start should be reachable (Calls from run)"
    );
    assert!(
        reachable_ids.contains(&f.storage_open_id),
        "Storage::open should be reachable (Calls from Engine::start)"
    );

    // Dead nodes (NOT reachable -- only connected by RelatedTo or no edge)
    assert!(
        !reachable_ids.contains(&f.dead_fn_id),
        "dead_fn should NOT be reachable (only RelatedTo edge)"
    );
    assert!(
        !reachable_ids.contains(&f.orphan_fn_id),
        "orphan_fn should NOT be reachable (no edges at all)"
    );

    // helper_fn is NOT reachable from main (no edges from main's subtree
    // to util_module)
    assert!(
        !reachable_ids.contains(&f.helper_fn_id),
        "helper_fn is not connected to main's call chain"
    );
}

// ============================================================================
// R6: Wide-graph BFS regression tests
// ============================================================================

/// Function called by 30+ callers. Blast radius (via incoming_neighbors)
/// should find ALL callers.
#[test]
fn test_blast_radius_wide_graph() {
    let mut g = KnowledgeGraph::new();

    let target = make_node("utility_fn", "function", "src/util.rs");
    let target_id = target.memory_id;
    g.add_node(target).unwrap();

    let mut caller_ids = Vec::new();
    for i in 0..35 {
        let caller = make_node(
            &format!("caller_{i}"),
            "function",
            &format!("src/mod{i}.rs"),
        );
        let caller_id = caller.memory_id;
        caller_ids.push(caller_id);
        g.add_node(caller).unwrap();
        g.add_edge(caller_id, target_id, edge_of(EdgeKind::Calls))
            .unwrap();
    }

    // incoming_neighbors should find all 35 callers
    let incoming = g.incoming_neighbors(&target_id);
    assert_eq!(
        incoming.len(),
        35,
        "utility_fn should have exactly 35 incoming callers"
    );

    // Verify each caller is in the incoming set
    let incoming_ids: std::collections::HashSet<Uuid> =
        incoming.iter().map(|(id, _)| *id).collect();
    for caller_id in &caller_ids {
        assert!(
            incoming_ids.contains(caller_id),
            "caller should be in incoming neighbors"
        );
    }

    // All edges should be dependency edges (Calls)
    for (_, edge) in &incoming {
        assert!(
            is_dependency_edge(edge.kind),
            "all edges should be dependency edges"
        );
    }
}

// ============================================================================
// R8: CLI-vs-agent consistency regression guards
// ============================================================================

/// INVERTED (ADR-0027 / WU-0002 Wave 3): the former version blessed
/// "the first one found via suffix wins" for the ambiguous bare name 'start'.
/// The EP1 contract is the opposite — a qualified name resolves Unique, but a
/// bare suffix-tier homonym MUST fire Ambiguous (F8), never a silent pick.
#[test]
fn test_bare_homonym_is_ambiguous_qualified_is_unique() {
    let f = build_fixture();

    // Qualified exact name → Unique (stable across calls).
    let exact = resolve_unique(&f.graph, "Engine::start", None)
        .unique_or_report()
        .expect("qualified 'Engine::start' is an exact-tier singleton → Unique");
    assert_eq!(exact.uuid(), f.engine_start_id);
    let exact2 = resolve_unique(&f.graph, "Engine::start", None)
        .unique_or_report()
        .expect("repeated qualified lookup → Unique");
    assert_eq!(exact2.uuid(), exact.uuid(), "qualified lookup is stable");

    // Bare 'start' matches Engine::start, Backend::start, and
    // "impl Backend for Engine::start" at the suffix tier → MUST be Ambiguous.
    // (The deleted test asserted "returns a valid node" — the silent first-match
    // a reviewer must reject. A rename-only swap would still pass that line.)
    match resolve_unique(&f.graph, "start", None) {
        Resolution::Ambiguous(candidates) => {
            assert!(
                candidates.len() >= 2,
                "bare 'start' must enumerate the suffix siblings, got {}",
                candidates.len()
            );
            let ids: Vec<Uuid> = candidates.iter().map(|c| c.id.uuid()).collect();
            assert!(ids.contains(&f.engine_start_id), "Engine::start in F8 list");
            assert!(
                ids.contains(&f.backend_start_id),
                "Backend::start in F8 list"
            );
        }
        other => panic!("bare 'start' must be Ambiguous, got {other:?}"),
    }
}

/// Known dependents: Engine::start is called by run (via Calls edge).
/// Verify the blast radius count and IDs are consistent.
#[test]
fn test_blast_radius_consistency() {
    let f = build_fixture();

    // Engine::start has incoming_neighbors: run (Calls), Engine (Contains)
    let incoming = f.graph.incoming_neighbors(&f.engine_start_id);

    // Filter to dependency edges only (blast radius semantics)
    let dep_callers: Vec<_> = incoming
        .iter()
        .filter(|(_, e)| is_dependency_edge(e.kind))
        .collect();

    assert_eq!(
        dep_callers.len(),
        2,
        "Engine::start has 2 dependency callers (run via Calls, Engine via Contains)"
    );
    // Both run (Calls) and Engine (Contains) are now dependency edges
    let dep_caller_ids: std::collections::HashSet<_> =
        dep_callers.iter().map(|(id, _)| *id).collect();
    assert!(
        dep_caller_ids.contains(&f.run_id),
        "run should be a dependency caller (Calls edge)"
    );
    assert!(
        dep_caller_ids.contains(&f.engine_id),
        "Engine should be a dependency caller (Contains edge)"
    );

    // Run again to verify stability
    let incoming2 = f.graph.incoming_neighbors(&f.engine_start_id);
    let dep_callers2_count = incoming2
        .iter()
        .filter(|(_, e)| is_dependency_edge(e.kind))
        .count();
    assert_eq!(
        dep_callers2_count,
        dep_callers.len(),
        "blast radius count should be stable"
    );
}
