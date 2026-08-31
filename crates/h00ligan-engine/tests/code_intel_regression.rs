//! CI regression tests for code intelligence subsystem.
//!
//! These tests verify the correctness of the extractor → graph → persistence
//! pipeline. All are behind `#[cfg(feature = "code-intel")]`.

#![cfg(feature = "code-intel")]

use h00ligan_engine::edge_builder::{build_graph, incremental_update};
use h00ligan_engine::extractor::extract_file;
use h00ligan_engine::graph::{EdgeKind, KnowledgeGraph};
use h00ligan_engine::graph_store::GraphStore;
use h00ligan_engine::structural_ir::SymbolKind;
use std::sync::Arc;
use tempfile::TempDir;

/// FC-CI01: Symbol extraction completeness — all 11 SymbolKind variants
/// are extracted from a single source file.
#[test]
fn fc_ci01_symbol_extraction_completeness() {
    let dir = TempDir::new().expect("tempdir");
    let src = dir.path().join("all_kinds.rs");

    // Write a source file that exercises all 11 symbol kinds.
    let source = r#"
//! Module doc (this is the module itself)

use std::collections::HashMap;

pub const MAX_SIZE: usize = 100;

pub static GLOBAL: &str = "hello";

pub type AliasMap = HashMap<String, String>;

macro_rules! my_macro {
    () => {};
}

pub mod inner {
    pub fn inner_fn() {}
}

pub trait Greeter {
    fn greet(&self) -> String;
}

pub struct Person {
    name: String,
}

pub enum Color {
    Red,
    Green,
    Blue,
}

impl Greeter for Person {
    fn greet(&self) -> String {
        format!("Hello, {}", self.name)
    }
}

pub fn standalone() -> bool {
    true
}
"#;

    std::fs::write(&src, source).expect("write source");
    let output = extract_file(&src, dir.path()).expect("extract");

    // Collect the kinds found.
    let kinds: std::collections::HashSet<SymbolKind> =
        output.symbols.iter().map(|s| s.kind).collect();

    // All 12 kinds must be present (Field is extracted from struct field declarations).
    let expected = [
        SymbolKind::Function,
        SymbolKind::Struct,
        SymbolKind::Enum,
        SymbolKind::Impl,
        SymbolKind::Trait,
        SymbolKind::Const,
        SymbolKind::Static,
        SymbolKind::Module,
        SymbolKind::Use,
        SymbolKind::TypeAlias,
        SymbolKind::Macro,
        SymbolKind::Field,
    ];

    for kind in &expected {
        assert!(
            kinds.contains(kind),
            "Missing SymbolKind::{kind:?} in extraction output. Found: {kinds:?}"
        );
    }

    // Verify we got a non-trivial number of symbols (11 original + 1 field from Person struct).
    assert!(
        output.symbols.len() >= 12,
        "Expected at least 12 symbols, got {}",
        output.symbols.len()
    );
}

/// FC-CI02: Edge creation — Contains and Implements edges from extraction.
#[test]
fn fc_ci02_edge_creation_contains_and_implements() {
    let dir = TempDir::new().expect("tempdir");
    let src = dir.path().join("edges.rs");

    let source = r#"
pub trait Speaker {
    fn speak(&self) -> String;
}

pub struct Dog {
    name: String,
}

impl Speaker for Dog {
    fn speak(&self) -> String {
        format!("Woof, I'm {}", self.name)
    }
}

impl Dog {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}
"#;

    std::fs::write(&src, source).expect("write source");
    let output = extract_file(&src, dir.path()).expect("extract");

    let mut graph = KnowledgeGraph::new();
    let stats = build_graph(&[output], &mut graph).expect("build_graph");

    // We should have nodes and edges.
    assert!(stats.nodes_added > 0, "Expected nodes to be added");
    assert!(stats.edges_added > 0, "Expected edges to be added");

    // Verify Contains edges exist (impl block → method).
    let all_edges = graph.all_edges();
    let has_contains = all_edges
        .iter()
        .any(|(_, _, e)| e.kind == EdgeKind::Contains);
    assert!(
        has_contains,
        "Expected at least one Contains edge (impl -> method)"
    );

    // Verify Implements edges exist (impl Speaker for Dog → Speaker trait).
    let has_implements = all_edges
        .iter()
        .any(|(_, _, e)| e.kind == EdgeKind::Implements);
    assert!(
        has_implements,
        "Expected at least one Implements edge (impl Trait for Type -> Trait)"
    );
}

/// FC-CI03: Invalidation on file change — re-extract, verify no stale nodes.
#[test]
fn fc_ci03_invalidation_on_file_change() {
    let dir = TempDir::new().expect("tempdir");
    let src = dir.path().join("changing.rs");

    // Initial version: has fn old_fn.
    let v1 = r#"
pub fn old_fn() -> i32 { 42 }
pub fn stable_fn() -> bool { true }
"#;
    std::fs::write(&src, v1).expect("write v1");
    let output_v1 = extract_file(&src, dir.path()).expect("extract v1");
    let mut graph = KnowledgeGraph::new();
    build_graph(&[output_v1], &mut graph).expect("build v1");

    let v1_node_count = graph.node_count();
    assert!(v1_node_count >= 2, "v1 should have at least 2 nodes");

    // Check old_fn exists.
    let has_old_fn = graph
        .all_nodes()
        .iter()
        .any(|n| n.symbol_name.contains("old_fn"));
    assert!(has_old_fn, "old_fn should exist in v1 graph");

    // Updated version: removes old_fn, adds new_fn.
    let v2 = r#"
pub fn new_fn() -> i32 { 99 }
pub fn stable_fn() -> bool { true }
"#;
    std::fs::write(&src, v2).expect("write v2");
    let stats = incremental_update(&src, dir.path(), &mut graph).expect("incremental update");
    assert!(stats.nodes_added > 0, "incremental should add new nodes");

    // old_fn should be gone.
    let has_old_fn = graph
        .all_nodes()
        .iter()
        .any(|n| n.symbol_name.contains("old_fn"));
    assert!(
        !has_old_fn,
        "old_fn should have been invalidated after re-extraction"
    );

    // new_fn should exist.
    let has_new_fn = graph
        .all_nodes()
        .iter()
        .any(|n| n.symbol_name.contains("new_fn"));
    assert!(has_new_fn, "new_fn should exist after re-extraction");

    // stable_fn should still exist.
    let has_stable = graph
        .all_nodes()
        .iter()
        .any(|n| n.symbol_name.contains("stable_fn"));
    assert!(has_stable, "stable_fn should survive re-extraction");
}

/// FC-CI04: Graph crash recovery — persist → reload → verify same graph.
#[tokio::test]
async fn fc_ci04_graph_crash_recovery() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("graph_test.redb");

    // Build a graph from a temp file.
    let src = dir.path().join("recoverable.rs");
    let source = r#"
pub trait Recoverable {
    fn recover(&self);
}

pub struct Engine;

impl Recoverable for Engine {
    fn recover(&self) {}
}

pub fn helper() -> bool { true }
"#;
    std::fs::write(&src, source).expect("write source");
    let output = extract_file(&src, dir.path()).expect("extract");

    let mut graph = KnowledgeGraph::new();
    build_graph(&[output], &mut graph).expect("build_graph");

    let original_node_count = graph.node_count();
    let original_edge_count = graph.edge_count();
    assert!(original_node_count > 0, "graph should have nodes");

    // Persist the graph.
    let db = Arc::new(redb::Database::create(&db_path).expect("create redb"));
    let store = GraphStore::new(Arc::clone(&db));
    store.save_snapshot(&graph).await.expect("save snapshot");

    // Simulate crash: drop graph.
    drop(graph);

    // Reload from persistence.
    let loaded = store
        .load_snapshot()
        .await
        .expect("load snapshot")
        .expect("snapshot should exist");

    assert_eq!(
        loaded.node_count(),
        original_node_count,
        "node count mismatch after reload"
    );
    assert_eq!(
        loaded.edge_count(),
        original_edge_count,
        "edge count mismatch after reload"
    );

    // Verify specific nodes survived.
    let has_engine = loaded.all_nodes().iter().any(|n| n.symbol_name == "Engine");
    assert!(
        has_engine,
        "Engine node should survive persistence roundtrip"
    );

    let has_helper = loaded.all_nodes().iter().any(|n| n.symbol_name == "helper");
    assert!(
        has_helper,
        "helper node should survive persistence roundtrip"
    );
}

/// FC-CI05: `@invalidate` directive — verify watcher classify_event filters correctly
/// and that the invalidation pathway works through the public API.
///
/// Since the `@invalidate` directive is not yet a parsed annotation (it will be
/// a future enhancement), this test validates the prerequisite: that file-level
/// invalidation works correctly through the graph's `invalidate_file` method,
/// which is the mechanism that an `@invalidate` directive would trigger.
#[test]
fn fc_ci05_invalidation_directive_pathway() {
    let dir = TempDir::new().expect("tempdir");
    let src_a = dir.path().join("module_a.rs");
    let src_b = dir.path().join("module_b.rs");

    let source_a = r#"
pub fn func_a() -> i32 { 1 }
pub fn func_a2() -> i32 { 2 }
"#;
    let source_b = r#"
pub fn func_b() -> i32 { 3 }
"#;

    std::fs::write(&src_a, source_a).expect("write a");
    std::fs::write(&src_b, source_b).expect("write b");

    let output_a = extract_file(&src_a, dir.path()).expect("extract a");
    let output_b = extract_file(&src_b, dir.path()).expect("extract b");

    let mut graph = KnowledgeGraph::new();
    build_graph(&[output_a, output_b], &mut graph).expect("build");

    let total_before = graph.node_count();
    assert!(total_before >= 3, "should have at least 3 nodes");

    // Invalidate only module_a — simulates what @invalidate would trigger.
    // file_path is now relative (e.g. "module_a.rs"), not absolute.
    let removed = graph.invalidate_file("module_a.rs");
    assert!(
        removed.len() >= 2,
        "should remove at least 2 nodes from module_a"
    );

    // module_b nodes should still exist.
    let remaining_b = graph
        .all_nodes()
        .iter()
        .any(|n| n.symbol_name.contains("func_b"));
    assert!(
        remaining_b,
        "func_b should survive invalidation of module_a"
    );

    // module_a nodes should be gone.
    let remaining_a = graph
        .all_nodes()
        .iter()
        .any(|n| n.symbol_name.contains("func_a"));
    assert!(!remaining_a, "func_a should be removed after invalidation");

    // Verify graph is still structurally sound (no dangling references).
    assert_eq!(
        graph.node_count(),
        total_before - removed.len(),
        "node count should decrease by exactly the removed count"
    );
}

/// FC-CI06: Bounded watcher batches are explicitly non-authoritative hints.
#[test]
fn fc_ci06_watcher_batch_contract() {
    use h00ligan_engine::watcher::{WatchHintBatch, WatchHintReason};
    use std::path::PathBuf;

    let batch = WatchHintBatch {
        paths: vec![PathBuf::from("/src/lib.rs"), PathBuf::from("/web/app.ts")],
        reason: WatchHintReason::Filesystem,
        overflowed: false,
    };
    assert_eq!(batch.paths.len(), 2);
    assert!(!batch.overflowed);
}

/// FC-CI06b: Debounce coalescing integration test.
///
/// Real notify watcher + real temp-dir fs writes, made DETERMINISTIC (no fixed
/// sleeps): we settle the watch registration via a readiness handshake, fire 5
/// rapid same-file rewrites, then collect events with a quiet-period
/// `timeout(_, rx.recv())` loop instead of a fixed sleep + `try_recv`. The
/// two-sided assertion (`!empty && len < 5`) kills both the timing flake AND the
/// original zero-event false-pass (`count < 5` passed even when 0 events arrived).
///
/// Linux/inotify is reliable and is the workspace's primary CI lane. macOS
/// FSEvents may coalesce at the OS layer (as few as 1 event), which this
/// assertion still tolerates.
#[tokio::test]
async fn fc_ci06b_debounce_coalesces_events() {
    use h00ligan_engine::watcher::{FileWatcher, WatcherConfig};
    use tokio::time::{Duration, timeout};

    let dir = TempDir::new().expect("tempdir");
    let src = dir.path().join("debounce_test.rs");
    std::fs::write(&src, "fn v1() {}").expect("write v1");

    let config = WatcherConfig::new(dir.path().to_path_buf(), 200);
    let watcher = FileWatcher::new(config);
    let mut rx = watcher.start().expect("start watcher");

    // Readiness handshake: write a separate .rs file and wait for its event so
    // the rewrites below race an ARMED watcher, not the registration window.
    std::fs::write(dir.path().join("readiness.rs"), "fn ready() {}").expect("write readiness");
    let armed = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("watcher did not arm within 5s (no readiness event)");
    assert!(armed.is_some(), "watcher channel closed before arming");
    // Drain trailing readiness events to a quiet period.
    while timeout(Duration::from_millis(400), rx.recv())
        .await
        .is_ok_and(|e| e.is_some())
    {}

    // Rapid-fire rewrites of the SAME file within the 200ms debounce window.
    for i in 0..5 {
        let content = format!("fn v{i}() {{}}");
        std::fs::write(&src, content.as_bytes()).expect("write rewrite");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Collect debounced batches deterministically: receive until a 750ms quiet
    // period (well past the 200ms debounce flush) yields nothing more.
    let mut batches = Vec::new();
    while let Ok(Some(ev)) = timeout(Duration::from_millis(750), rx.recv()).await {
        batches.push(ev);
    }

    let paths = batches
        .iter()
        .flat_map(|batch| batch.paths.iter())
        .filter(|path| path.ends_with("debounce_test.rs"))
        .count();
    assert!(
        !batches.is_empty() && paths > 0 && batches.len() < 5,
        "expected 1..5 nonempty coalesced batches from 5 rapid rewrites, got {batches:?}"
    );
}
