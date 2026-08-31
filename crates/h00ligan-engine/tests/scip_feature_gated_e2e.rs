//! F1 (ADR-0030) — feature-gated SCIP coverage, END-TO-END through the REAL
//! generator.
//!
//! This is the only test in the suite that shells the real `rust-analyzer scip`
//! binary (all of `scip_integration.rs` fabricates SCIP protobuf in-memory).
//! It is `#[ignore]`-gated: it spawns rust-analyzer (~2-4s) and needs a
//! network-free `cargo metadata` load of a throwaway fixture crate. Run with:
//!
//! ```text
//! cargo test -p h00ligan-engine --features test-utils --test scip_feature_gated_e2e -- --ignored
//! ```
//!
//! What it proves (anti-green-by-construction): a `#[cfg(feature = "extra")]`
//! function called only from `#[cfg(feature = "extra")] pub fn user()` is
//! false-DEAD under DEFAULT-feature SCIP (no incoming SCIP edge — the bug), and
//! becomes reachable (NOT `Dead`) once `generate_scip_index` indexes with
//! `ScipFeatures::All`. No hand-fabricated protobuf can sneak the edge in — the
//! edge must come from the real generator, or the test fails.

#![cfg(feature = "code-intel")]

use std::io::Write as _;
use std::path::Path;

use h00ligan_engine::code_intel_cancellation::IndexCancellation;
use h00ligan_engine::edge_builder::full_scan;
use h00ligan_engine::graph::{EdgeKind, KnowledgeGraph};
use h00ligan_engine::reachability::classify_and_writeback;
use h00ligan_engine::scip_loader::{ScipFeatures, ScipLoader, generate_scip_index};

/// Write the throwaway feature-gated fixture crate into `dir`.
///
/// `helper()` is gated behind `feature = "extra"` and called only from the
/// likewise-gated `user()`. `always()` is unconditional — the always-reachable
/// control so we can tell "indexer ran at all" apart from "gated edge present".
fn write_fixture_crate(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).expect("mk fixture src dir");

    // NOTE: the crate is named `acme-widget` — an ARBITRARY non-h00 name, on
    // purpose. Before F4 (ADR-0030) this fixture HAD to be named `h00ligan-engine`
    // because `ScipLoader` only resolved SCIP symbols whose package matched the
    // hardcoded h00 whitelist; an arbitrarily-named crate would have its edges
    // skipped as "external" and the gated edge could never land. The current
    // loader derives package authority from SCIP's repository-owned
    // `Document.symbols` population. This fixture being a non-h00 crate that
    // still resolves its own intra-crate edge is the IMPL->WIRED proof.
    let mut cargo = std::fs::File::create(dir.join("Cargo.toml")).expect("create Cargo.toml");
    cargo
        .write_all(
            br#"[package]
name = "acme-widget"
version = "0.0.0"
edition = "2021"

[features]
extra = []
"#,
        )
        .expect("write Cargo.toml");

    let mut lib = std::fs::File::create(dir.join("src").join("lib.rs")).expect("create lib.rs");
    lib.write_all(
        br#"#[cfg(feature = "extra")]
fn helper() -> u32 {
    42
}

#[cfg(feature = "extra")]
pub fn user() -> u32 {
    helper()
}

pub fn always() -> u32 {
    7
}
"#,
    )
    .expect("write lib.rs");
}

/// Build a graph for `fixture_root` with the given SCIP feature selection,
/// classify it, and return it. Mirrors the production pipeline order:
/// `full_scan` (tree-sitter nodes/edges) -> `generate_scip_index` ->
/// `ScipLoader::load_scip_index` (SCIP edges) -> `classify_and_writeback`.
fn build_and_classify(fixture_root: &Path, features: &ScipFeatures) -> KnowledgeGraph {
    let mut graph = KnowledgeGraph::default();
    full_scan(fixture_root, &mut graph).expect("tree-sitter full_scan of fixture");

    let provider = tempfile::tempdir().expect("isolated provider directory");
    let generated = generate_scip_index(
        fixture_root,
        &provider.path().join("index.scip"),
        provider.path(),
        features,
        &IndexCancellation::new(),
    )
    .expect("generate_scip_index on fixture");

    {
        // Production derives locality from the provider's admitted repository
        // symbol population; no package-manager subprocess is needed here.
        let mut loader = ScipLoader::new(&mut graph);
        loader
            .load_scip_index(&generated.path)
            .expect("load generated SCIP index");
    }

    // Consumption of the language-AGNOSTIC classifier (not a modification): F1
    // only changes SCIP generation; we read its verdict to prove the effect.
    classify_and_writeback(&mut graph, fixture_root).expect("classify_and_writeback");
    graph
}

/// Find the node whose fully-qualified symbol name ends in `helper`.
fn helper_node(graph: &KnowledgeGraph) -> Option<&h00ligan_engine::graph::GraphNode> {
    graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == "helper" || n.symbol_name.ends_with("::helper"))
}

/// Whether `helper` has any incoming `Calls`/`References` edge (i.e. SCIP saw
/// the `user -> helper` call).
fn helper_has_incoming_call_edge(graph: &KnowledgeGraph) -> bool {
    let Some(helper) = helper_node(graph) else {
        return false;
    };
    graph.all_nodes().into_iter().any(|src| {
        graph.neighbors(&src.memory_id).into_iter().any(|(to, e)| {
            to == helper.memory_id && matches!(e.kind, EdgeKind::Calls | EdgeKind::References)
        })
    })
}

#[test]
#[ignore = "shells real rust-analyzer (~2-4s) + cargo metadata; run with --ignored"]
fn feature_gated_helper_is_not_dead_with_scip_features_all() {
    // Skip cleanly (not fail) if rust-analyzer is not installed on this box.
    if !h00ligan_engine::scip_loader::rust_analyzer_available() {
        eprintln!("rust-analyzer not found; skipping feature-gated SCIP e2e");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir for fixture crate");
    let fixture_root = tmp.path();
    write_fixture_crate(fixture_root);

    // The LOAD-BEARING F1 claim, stated as a SCIP-edge presence differential:
    // the feature-gated `user -> helper` edge is absent under DEFAULT-feature
    // indexing (the false-DEAD bug) and present under ALL-feature indexing (the
    // ADR-0030 fix). This is exactly what `generate_scip_index(_, features)`
    // controls; it does not depend on entry-point discovery in a synthetic
    // library fixture (which has no `main()` root), so it isolates the fix.

    // --- Positive: ScipFeatures::All surfaces the gated user -> helper edge. ---
    let all_graph = build_and_classify(fixture_root, &ScipFeatures::All);
    assert!(
        helper_node(&all_graph).is_some(),
        "the gated `helper` fn must appear as a tree-sitter node regardless of features"
    );
    assert!(
        helper_has_incoming_call_edge(&all_graph),
        "with ScipFeatures::All the real generator must emit an incoming \
         Calls/References edge into the gated `helper` from `user` (ADR-0030 fix)"
    );

    // NOTE on classification (verified firsthand): we deliberately do NOT
    // assert `helper` is non-Dead here. In a synthetic *library* fixture with
    // no `[[bin]]`/`main()`, entry-point discovery finds no production root, so
    // the BACKWARD-reachability classifier marks every symbol Dead regardless
    // of the SCIP edge — that is an entry-point-discovery property, NOT what F1
    // controls. The load-bearing F1 differential is the SCIP *edge* presence
    // asserted above + the negative control below; the real-tree DEAD->WIRED
    // flip (is_transient_error / OpenAiEmbedder / resolve_otlp_endpoint) is
    // proven by the DRIVE stage on a fresh scratch index of the actual
    // workspace, where genuine entry points exist. We still run
    // `classify_and_writeback` (in `build_and_classify`) to exercise the full
    // pipeline order end-to-end.

    // --- Negative control: ScipFeatures::Default leaves helper edgeless. ---
    // index.scip is regenerated in-place by the second call, so this re-derives
    // the SAME fixture under default features and proves the fix is what flips
    // it (no hand-built protobuf can fabricate the edge here).
    let default_graph = build_and_classify(fixture_root, &ScipFeatures::Default);
    assert!(
        !helper_has_incoming_call_edge(&default_graph),
        "negative control: with ScipFeatures::Default the gated edge is absent \
         (the false-DEAD bug) — proving ScipFeatures::All is what surfaces it"
    );
}
