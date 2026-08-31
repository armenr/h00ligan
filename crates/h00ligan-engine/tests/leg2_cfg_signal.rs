//! WU-0015 Leg 2 / ADR-0036 — platform-cfg SIGNAL end-to-end contract.
//!
//! Leg 2 CAPTURES a per-node `has_platform_cfg` signal at index time and exposes
//! two consumer helpers (`crate_name_of`, `cfg_touching_crates`) for the Leg-3
//! gate. It changes NO verdict: the delete-authority tier stays EMPTY. These
//! tests prove:
//!   1. the per-file scan actually reaches `GraphNode.has_platform_cfg` through
//!      the real producer (`extract_rust_symbols` → `build_graph` →
//!      `symbol_to_node`) — the IMPL→WIRED plumbing, not just the scanner unit;
//!   2. `cfg_touching_crates` rolls the signal up to the right crate set;
//!   3. the SAFETY control — a graph that CONTAINS a `has_platform_cfg` node
//!      alongside a private-unreachable fn STILL yields `count(Dead)==0 &&
//!      count(SafeDelete)==0` (the signal is present but wired into no verdict);
//!   4. (`#[ignore]`, drive-time) on the real reindexed-under-SCHEMA-4 graph the
//!      signal populates and rolls up to the ADR-0036 v4 measured crate set.
//!
//! Producer-driven (never a hand-fabricated graph) per the anti-green-by-
//! construction discipline; the real-graph checks mirror `step0_blast_radius.rs`.

use std::collections::HashSet;
use std::path::PathBuf;

use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::entry_points::{EntryPoint, EntryPointKind};
use h00ligan_engine::extractor::extract_rust_symbols;
use h00ligan_engine::graph::KnowledgeGraph;
use h00ligan_engine::graph_query::{DeadAction, cfg_touching_crates, classify_dead_action};
use h00ligan_engine::reachability::{ReachabilityAnalyzer, ReachabilityClass};
use h00ligan_engine::structural_ir::ExtractorOutput;

// ---------------------------------------------------------------------------
// Producer-driven fixture helpers (mirrors reachability_contract.rs).
// ---------------------------------------------------------------------------

fn build_from_sources(files: &[(&str, &str)]) -> KnowledgeGraph {
    let outputs: Vec<ExtractorOutput> = files
        .iter()
        .map(|(path, src)| {
            extract_rust_symbols(src, path).unwrap_or_else(|e| panic!("extract {path}: {e:?}"))
        })
        .collect();
    let mut graph = KnowledgeGraph::new();
    build_graph(&outputs, &mut graph).expect("build_graph");
    graph
}

fn binary_entry(file_path: &str) -> EntryPoint {
    EntryPoint {
        name: "test_bin".to_string(),
        kind: EntryPointKind::Binary,
        file_path: PathBuf::from(file_path),
        crate_name: "testcrate".to_string(),
    }
}

fn entry(kind: EntryPointKind, name: &str, file_path: &str) -> EntryPoint {
    EntryPoint {
        name: name.to_string(),
        kind,
        file_path: PathBuf::from(file_path),
        crate_name: "testcrate".to_string(),
    }
}

fn analyze_and_writeback(graph: &mut KnowledgeGraph, eps: Vec<EntryPoint>) {
    let report = ReachabilityAnalyzer::new(graph, eps).analyze();
    for cn in &report.classified {
        if let Some(n) = graph.node_mut(&cn.memory_id) {
            n.reachability_class = cn.classification;
        }
    }
}

fn node_named<'g>(graph: &'g KnowledgeGraph, name: &str) -> &'g h00ligan_engine::graph::GraphNode {
    graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == name)
        .unwrap_or_else(|| panic!("node {name:?} not in graph"))
}

// ---------------------------------------------------------------------------
// GREEN — the per-file scan reaches GraphNode through symbol_to_node.
// ---------------------------------------------------------------------------

#[test]
fn cfg_scan_wiring_end_to_end() {
    // Two files through the REAL producer: a.rs is platform-cfg-touching, b.rs
    // is clean. EVERY node from a.rs must carry has_platform_cfg==true; EVERY
    // node from b.rs must carry false. Guards against the scan being computed
    // but never plumbed onto nodes.
    let graph = build_from_sources(&[
        (
            "crates/x/src/a.rs",
            "#[cfg(target_os = \"windows\")]\nfn w() {}",
        ),
        ("crates/x/src/b.rs", "pub fn b() {}"),
    ]);

    let a_nodes: Vec<_> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.file_path == "crates/x/src/a.rs")
        .collect();
    assert!(!a_nodes.is_empty(), "a.rs must produce at least one node");
    assert!(
        a_nodes.iter().all(|n| n.has_platform_cfg),
        "every node from the platform-cfg file must have has_platform_cfg==true"
    );

    let b_nodes: Vec<_> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.file_path == "crates/x/src/b.rs")
        .collect();
    assert!(!b_nodes.is_empty(), "b.rs must produce at least one node");
    assert!(
        b_nodes.iter().all(|n| !n.has_platform_cfg),
        "every node from the clean file must have has_platform_cfg==false"
    );
}

// ---------------------------------------------------------------------------
// GREEN — cfg_touching_crates rolls the signal up by owning crate.
// ---------------------------------------------------------------------------

#[test]
fn cfg_touching_crates_t1_producer_graph() {
    // alpha (cfg attribute) + gamma (cfg!() in body) are cfg-touching; beta is
    // clean; a non-crates-path node must not crash and must not add a bucket.
    let graph = build_from_sources(&[
        (
            "crates/alpha/src/lib.rs",
            "#[cfg(target_os = \"linux\")]\npub fn a() {}",
        ),
        ("crates/beta/src/lib.rs", "pub fn b() {}"),
        (
            "crates/gamma/src/lib.rs",
            "pub fn g() { let _ = cfg!(unix); }",
        ),
        ("src/top.rs", "fn top() {}"),
    ]);

    let got = cfg_touching_crates(&graph);
    let want: HashSet<String> = ["alpha", "gamma"].iter().map(|s| s.to_string()).collect();
    assert_eq!(
        got, want,
        "cfg_touching_crates must be exactly {{alpha, gamma}} (beta clean, non-crates skipped)"
    );
    assert!(
        !got.contains("beta"),
        "the clean crate beta must be excluded"
    );
}

// ---------------------------------------------------------------------------
// INVARIANT (non-ignored) — the NON-VACUOUS Leg-2 safety control.
// ---------------------------------------------------------------------------

#[test]
fn leg2_safety_control_cfg_node_present_but_no_safedelete() {
    // A crate that BOTH contains a platform-cfg token AND a private call-
    // unreachable fn. After analyze (WU-0015 Leg-3b REBASELINE): (1) at least one
    // has_platform_cfg==true node EXISTS (else the control is vacuous);
    // (2) count(SafeDelete)==0 — the load-bearing check (Dead is now non-empty);
    // (3) private_unreached is class==Dead but action==SuspectedDelete because the
    // crate is cfg-touching AND the node is rustc-unflagged (TWO broken conjuncts).
    let mut graph = build_from_sources(&[
        (
            "crates/lib/src/lib.rs",
            "#[cfg(target_os = \"linux\")]\npub fn plat() {}\n\
             fn private_unreached() {}\n\
             pub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "lib", "crates/lib/src/lib.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);

    // (1) NON-VACUITY: the signal is actually present in the graph.
    let cfg_nodes = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.has_platform_cfg)
        .count();
    assert!(
        cfg_nodes > 0,
        "at least one has_platform_cfg node must exist (non-vacuous control)"
    );

    // (2) WU-0015 Leg-3b REBASELINE — SafeDelete count == 0 (was count(Dead)==0;
    // Dead is now legitimately non-empty). Meaningful because crate `lib` is
    // cfg-touching (the `plat` sibling) AND private_unreached is rustc-unflagged
    // — TWO conjuncts broken.
    let cfg_crates = cfg_touching_crates(&graph);
    let safe_delete: Vec<String> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| classify_dead_action(&graph, n, &cfg_crates) == DeadAction::SafeDelete)
        .map(|n| n.symbol_name.clone())
        .collect();
    assert!(
        safe_delete.is_empty(),
        "a cfg-touching + unflagged crate must yield NO SafeDelete; found {safe_delete:?}"
    );

    // (3) the private call-unreachable residual is now class==Dead (Leg-3b), but
    // action==SuspectedDelete (cfg-touching crate + unflagged → 2 conjuncts fail).
    let residual = node_named(&graph, "private_unreached").clone();
    assert_eq!(
        residual.reachability_class,
        ReachabilityClass::Dead,
        "the private call-unreachable fn promotes to Dead in Leg 3b"
    );
    assert_eq!(
        classify_dead_action(&graph, &residual, &cfg_crates),
        DeadAction::SuspectedDelete,
        "cfg-touching + unflagged → the non-delete SuspectedDelete recommendation"
    );
}
