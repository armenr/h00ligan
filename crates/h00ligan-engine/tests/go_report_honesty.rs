//! WU-0023 P3b — Go REPORT-ONLY honesty floor (Bundle 1) falsifiers.
//!
//! Each test is a falsifier proven RED on HEAD (before the Bundle-1 change) for
//! the right reason, then GREEN, with the non-vacuous negative control
//! (break-the-guard → watch the control fail → restore-in-assertion). The scope
//! is REPORTING honesty (false-DEAD / false-CLEAN) — NEVER delete authority: the
//! `SafeDelete` conjuncts stay fail-closed for Go for free, which the FENCE-HOLDS
//! test pins.
//!
//! Covers: FENCE-HOLDS (Go never SafeDelete), LEAK-1 (0-fn store split), DEC-R5a
//! (mixed-store per-language segmentation), RUST NO-REGRESSION, DEC-R8a
//! (unclassified → UNKNOWN), LEAK-3 (Path-A raw membership survives).

use h00ligan_engine::dead_pipeline::compute_dead_tiers;
use h00ligan_engine::graph::{EdgeKind, EdgeSource, GraphEdge, GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_query::{
    DeadAction, DeadReport, DeadSingleReport, GateSignals, classify_dead_action, dead_report_gated,
    dead_single_gated, graph_reachability_classified, suppresses,
};
use h00ligan_engine::graph_stats::{
    CoverageTier, call_edge_coverage, coverage_suppressed_languages, coverage_tier, node_language,
};
use h00ligan_engine::reachability::ReachabilityClass;
use std::collections::HashSet;
use uuid::Uuid;

// ── builders ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn mk_node(
    id: u128,
    name: &str,
    kind: &str,
    file_path: &str,
    class: ReachabilityClass,
    visibility: &str,
    rustc_flagged_dead: bool,
) -> GraphNode {
    GraphNode {
        memory_id: Uuid::from_u128(id),
        symbol_name: name.to_string(),
        kind: kind.to_string(),
        file_path: file_path.to_string(),
        content_hash: String::new(),
        signature: String::new(),
        reachability_class: class,
        line_start: None,
        line_end: None,
        has_body: Some(true),
        visibility: visibility.to_string(),
        is_test_only: None,
        is_test_root: false,
        has_platform_cfg: false,
        rustc_flagged_dead,
        entry_retain: Default::default(),
        has_uncaptured_items: false,
        oracle_receipt: None,
    }
}

fn scip_calls_edge() -> GraphEdge {
    GraphEdge {
        kind: EdgeKind::Calls,
        source: EdgeSource::Scip,
        ..GraphEdge::default()
    }
}

const fn healthy_signals() -> GateSignals {
    GateSignals {
        tier: CoverageTier::Sufficient,
        oracle_ran_ok: true,
        reachability_classified: true,
    }
}

fn dead_names(report: &DeadReport) -> Vec<String> {
    match report {
        DeadReport::Full(d) => d.entries.iter().map(|e| e.symbol_name.clone()).collect(),
        DeadReport::Unknown => Vec::new(),
    }
}

// ── FENCE-HOLDS — Go is never SafeDelete (conjunct 2 is the load-bearing guard) ──

/// An UNEXPORTED Go Dead node under `crates/<name>/` passes conjuncts 1
/// (Dead) + 3 (private → deletable) + 4 (crate_name_of → Some) + 5 (no retain),
/// so `rustc_flagged_dead` (conjunct 2 — NEVER set for Go) is the SOLE guard. The
/// fence holds: SuspectedDelete, never SafeDelete. NON-VACUOUS: flipping
/// `rustc_flagged_dead=true` (the one thing false) DOES grant SafeDelete —
/// proving conjunct 2 is exactly what holds the line for Go.
#[test]
fn fence_holds_unexported_go_node_never_safe_delete() {
    let mut graph = KnowledgeGraph::new();
    // Unexported ("private") Go node under crates/<name>/ so conjunct 4 passes.
    let go = mk_node(
        1,
        "helper",
        "function",
        "crates/gopkg/internal/util.go",
        ReachabilityClass::Dead,
        "private",
        false, // rustc_flagged_dead — NEVER set for Go
    );
    graph.add_node(go.clone()).unwrap();
    let cfg_crates: HashSet<String> = HashSet::new();

    // The fence: Go stays SuspectedDelete for free (conjunct 2 false).
    assert_eq!(
        classify_dead_action(&graph, &go, &cfg_crates),
        DeadAction::SuspectedDelete,
        "an unexported Go Dead node must NEVER be SafeDelete (conjunct 2 fail-closed)"
    );

    // NON-VACUOUS negative control: with the SAME node but conjunct 2 flipped
    // true, SafeDelete WOULD be granted — so conjunct 2 is the only thing holding
    // the line (the guard is not vacuously green).
    let mut go_flagged = go;
    go_flagged.rustc_flagged_dead = true;
    let mut graph2 = KnowledgeGraph::new();
    graph2.add_node(go_flagged.clone()).unwrap();
    assert_eq!(
        classify_dead_action(&graph2, &go_flagged, &cfg_crates),
        DeadAction::SafeDelete,
        "control: flipping rustc_flagged_dead grants SafeDelete → conjunct 2 is load-bearing"
    );
}

// ── LEAK-1 — a 0-fn Go store does NOT false-CLEAN ────────────────────────────

/// DEGENERATE-empty (`total_nodes == 0`): the coverage tier is `Degenerate` and
/// the dead verb SUPPRESSES to UNKNOWN — never a bare `dead_code:0`/`fresh`.
#[test]
fn leak1_degenerate_empty_store_suppresses_to_unknown() {
    let graph = KnowledgeGraph::new();
    let cov = call_edge_coverage(&graph, true);
    let tier = coverage_tier(&cov);
    assert_eq!(tier, CoverageTier::Degenerate, "0 nodes → Degenerate");
    assert!(
        suppresses(tier, true),
        "the Degenerate tier must suppress to UNKNOWN"
    );
    // The dead verb renders UNKNOWN on a degenerate store.
    assert!(matches!(
        dead_report_gated(&graph, tier, true),
        DeadReport::Unknown
    ));
}

/// AUTHORITATIVE-empty (`total_nodes > 0 && total_fn_nodes == 0`, e.g. a Go
/// type/const-only package): tier `NotApplicable`, does NOT suppress (so it does
/// not mask dead NON-function nodes), and is NOT `Degenerate`. NON-VACUOUS: were
/// the discriminator `total_fn_nodes`-primary, this would collapse into the
/// suppressing branch — the `total_nodes`-primary split keeps them distinct.
#[test]
fn leak1_authoritative_empty_is_not_applicable_not_suppressed() {
    let mut graph = KnowledgeGraph::new();
    // A dead non-function Go node (a struct) — no callable functions in scope.
    let go_type = mk_node(
        10,
        "Config",
        "struct",
        "pkg/cfg/config.go",
        ReachabilityClass::Dead,
        "private",
        false,
    );
    graph.add_node(go_type).unwrap();

    let cov = call_edge_coverage(&graph, true);
    assert_eq!(cov.total_fn_nodes, 0);
    assert!(cov.total_nodes > 0);
    let tier = coverage_tier(&cov);
    assert_eq!(tier, CoverageTier::NotApplicable);
    assert!(
        !suppresses(tier, true),
        "NotApplicable must NOT suppress (it must not mask dead non-function nodes)"
    );
    // The dead report is Full (not Unknown) and STILL surfaces the dead struct.
    let report = dead_report_gated(&graph, tier, true);
    assert!(
        dead_names(&report).contains(&"Config".to_string()),
        "authoritative-empty must not mask a dead non-function node"
    );
}

// ── DEC-R5a — mixed Rust+Go store segments per language ──────────────────────

/// A MIXED Rust+Go store: the Go function slice is coverage-uncovered (zero SCIP
/// Calls edges at the tags floor) → its Dead nodes render UNKNOWN (excluded from
/// the authoritative dead set), WHILE the Rust Dead node renders normally. No
/// blended Dead total ever includes the Go node. NON-VACUOUS: giving the Go slice
/// a SCIP Calls edge (simulating scip-go) flips it covered → the Go node appears.
#[test]
fn dec_r5a_mixed_store_go_unknown_rust_normal() {
    let mut graph = KnowledgeGraph::new();
    let rust_dead = mk_node(
        20,
        "rust_orphan",
        "function",
        "crates/rustcrate/src/lib.rs",
        ReachabilityClass::Dead,
        "private",
        false,
    );
    let go_dead = mk_node(
        21,
        "goHelper",
        "function",
        "internal/foo/bar.go",
        ReachabilityClass::Dead,
        "private",
        false,
    );
    graph.add_node(rust_dead).unwrap();
    graph.add_node(go_dead).unwrap();

    // Sanity: the partition helper sees Go present, Rust never suppressed.
    let suppressed = coverage_suppressed_languages(&graph, |lang| lang == "rust");
    assert!(
        suppressed.contains("go") && !suppressed.contains("rust"),
        "Go (no precise resolver) is suppressed; Rust never is"
    );

    let report = dead_report_gated(&graph, CoverageTier::Sufficient, true);
    let names = dead_names(&report);
    assert!(
        names.contains(&"rust_orphan".to_string()),
        "the Rust dead verdict must render normally on a mixed store"
    );
    assert!(
        !names.contains(&"goHelper".to_string()),
        "the Go slice (uncovered) must render UNKNOWN — never summed into the dead set"
    );

    // NON-VACUOUS: give Go a SCIP Calls edge → the slice is covered → Go appears.
    let go_callee = mk_node(
        22,
        "goCallee",
        "function",
        "internal/foo/baz.go",
        ReachabilityClass::Wired,
        "pub",
        false,
    );
    let callee_id = go_callee.memory_id;
    let helper_id = Uuid::from_u128(21);
    graph.add_node(go_callee).unwrap();
    graph
        .add_edge(helper_id, callee_id, scip_calls_edge())
        .unwrap();
    let report2 = dead_report_gated(&graph, CoverageTier::Sufficient, true);
    assert!(
        dead_names(&report2).contains(&"goHelper".to_string()),
        "control: once Go has a SCIP Calls edge, the slice is covered → the Go node renders"
    );
}

/// A Go symbol on a mixed store, queried single: UNKNOWN (withheld), never a
/// false-DEAD verdict.
#[test]
fn dec_r5a_single_go_symbol_is_unknown() {
    let mut graph = KnowledgeGraph::new();
    // A covered Rust node so the aggregate tier is Sufficient (mixed store).
    graph
        .add_node(mk_node(
            30,
            "rust_fn",
            "function",
            "crates/x/src/lib.rs",
            ReachabilityClass::Wired,
            "pub",
            false,
        ))
        .unwrap();
    let go_dead = mk_node(
        31,
        "goDead",
        "function",
        "svc/handler.go",
        ReachabilityClass::Dead,
        "private",
        false,
    );
    graph.add_node(go_dead.clone()).unwrap();
    assert!(matches!(
        dead_single_gated(&graph, &go_dead, CoverageTier::Sufficient, true,),
        DeadSingleReport::Unknown
    ));
}

// ── RUST NO-REGRESSION — a Rust-only store is unaffected by the Go path ───────

/// On a Rust-only store the per-language suppressed set is EMPTY and the dead
/// verdicts / SafeDelete authority are exactly what they were pre-WU: the
/// full-4-way Rust Dead node is SafeDelete, the report contains it unchanged.
#[test]
fn rust_no_regression_rust_only_store_unchanged() {
    let mut graph = KnowledgeGraph::new();
    // A Rust node satisfying the full 4-way SafeDelete conjunction.
    let rust_deletable = mk_node(
        40,
        "lonely",
        "function",
        "crates/x/src/util.rs",
        ReachabilityClass::Dead,
        "private",
        true, // rustc_flagged_dead
    );
    graph.add_node(rust_deletable.clone()).unwrap();

    // The Go path is inert for a Rust-only store: no suppressed languages.
    assert!(
        coverage_suppressed_languages(&graph, |lang| lang == "rust").is_empty(),
        "a Rust-only store must have an EMPTY suppressed-language set"
    );
    assert_eq!(node_language(&rust_deletable), Some("rust"));

    // The dead verdict + SafeDelete authority are unchanged.
    let cfg_crates: HashSet<String> = HashSet::new();
    assert_eq!(
        classify_dead_action(&graph, &rust_deletable, &cfg_crates),
        DeadAction::SafeDelete,
        "a full-4-way Rust Dead node stays SafeDelete (no Go-path regression)"
    );
    let report = dead_report_gated(&graph, CoverageTier::Sufficient, true);
    assert!(dead_names(&report).contains(&"lonely".to_string()));
}

// ── DEC-R8a — an unclassified graph renders UNKNOWN (both surfaces) ───────────

/// A graph carrying ANY `Unclassified` node → `graph_reachability_classified`
/// false → the dead verb (and, by the shared `suppresses` chokepoint, every
/// coverage-gated verb on BOTH surfaces) renders UNKNOWN even under Sufficient
/// coverage. NON-VACUOUS: classifying the node flips it back to a real verdict.
#[test]
fn dec_r8a_unclassified_graph_is_unknown() {
    // suppresses() folds the axis: unclassified always suppresses.
    assert!(suppresses(CoverageTier::Sufficient, false));
    assert!(!suppresses(CoverageTier::Sufficient, true));

    let mut graph = KnowledgeGraph::new();
    graph
        .add_node(mk_node(
            50,
            "unclassified_fn",
            "function",
            "crates/x/src/lib.rs",
            ReachabilityClass::Unclassified,
            "pub",
            false,
        ))
        .unwrap();
    assert!(!graph_reachability_classified(&graph));
    assert!(matches!(
        dead_report_gated(&graph, CoverageTier::Sufficient, true),
        DeadReport::Unknown
    ));

    // NON-VACUOUS: once classified, the same store yields a real (Full) verdict.
    let mut classified = KnowledgeGraph::new();
    classified
        .add_node(mk_node(
            50,
            "classified_fn",
            "function",
            "crates/x/src/lib.rs",
            ReachabilityClass::Dead,
            "private",
            false,
        ))
        .unwrap();
    assert!(graph_reachability_classified(&classified));
    assert!(matches!(
        dead_report_gated(&classified, CoverageTier::Sufficient, true),
        DeadReport::Full(_)
    ));
}

// ── LEAK-3 — Path A raw membership survives an unclassified graph ─────────────

/// Path A ([`compute_dead_tiers`], the `graph reachability` / `--fail-on-dead`
/// wiring surface) is IMMUNE to the reachability-classification axis: even with
/// `reachability_classified=false` in its signals, the RAW `{Dead,Suspected}`
/// membership is emitted (never emptied), so genuinely-unwired code cannot
/// silently PASS `--fail-on-dead`.
#[test]
fn leak3_path_a_raw_membership_survives_unclassified() {
    let mut graph = KnowledgeGraph::new();
    graph
        .add_node(mk_node(
            60,
            "raw_dead",
            "function",
            "crates/x/src/lib.rs",
            ReachabilityClass::Dead,
            "private",
            false,
        ))
        .unwrap();
    let signals = GateSignals {
        reachability_classified: false, // Path A must ignore this
        ..healthy_signals()
    };
    let tiers = compute_dead_tiers(&graph, signals);
    assert!(
        tiers.total() >= 1,
        "Path A must emit the raw Dead membership regardless of the classification axis"
    );
}

// ── Go entry-point discovery + pub-api seeding (manifest dispatch) ────────────

use h00ligan_engine::entry_points::{EntryPointError, EntryPointKind, discover_entry_points};
use h00ligan_engine::reachability::classify_and_writeback;
use std::fs;

/// Write a minimal Go module fixture: `go.mod`, an importable library package
/// `pkg/foo`, and a `cmd/app` binary. Returns the tempdir (keep it alive).
fn go_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("go.mod"),
        "module example.com/m\n\ngo 1.25\n",
    )
    .unwrap();
    let pkg_dir = dir.path().join("pkg/foo");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("lib.go"),
        "package foo\n\nfunc Exported() {}\nfunc unexported() {}\n",
    )
    .unwrap();
    let app = dir.path().join("cmd/app");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();
    dir
}

/// A pure-Go repo (go.mod, NO Cargo.toml) does NOT `NoSupportedManifest`; it yields a
/// `LibRoot` per importable package + a `Binary` for `package main`. A repo with
/// NEITHER manifest still errors (fail-closed contract preserved).
#[test]
fn go_entry_points_manifest_dispatch() {
    let dir = go_fixture();
    let eps = discover_entry_points(dir.path()).expect("pure-Go repo must NOT NoSupportedManifest");
    assert!(
        eps.iter().any(|e| matches!(e.kind, EntryPointKind::LibRoot)
            && e.file_path.to_string_lossy().ends_with("pkg/foo")),
        "importable package pkg/foo must emit a LibRoot, got {eps:?}"
    );
    assert!(
        eps.iter().any(|e| matches!(e.kind, EntryPointKind::Binary)
            && e.file_path.to_string_lossy().ends_with("main.go")),
        "package main must emit a Binary at main.go, got {eps:?}"
    );

    // NEITHER manifest → still NoSupportedManifest (unchanged fail-closed).
    let empty = tempfile::tempdir().expect("tempdir");
    assert!(matches!(
        discover_entry_points(empty.path()),
        Err(EntryPointError::NoSupportedManifest)
    ));
}

/// A MIXED repo (both Cargo.toml + go.mod) unions Rust + Go entries.
#[test]
fn go_entry_points_mixed_repo_unions() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"m\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    fs::write(
        dir.path().join("go.mod"),
        "module example.com/m\n\ngo 1.25\n",
    )
    .unwrap();
    let goc = dir.path().join("gopkg");
    fs::create_dir_all(&goc).unwrap();
    fs::write(goc.join("x.go"), "package gopkg\n\nfunc G() {}\n").unwrap();

    let eps = discover_entry_points(dir.path()).expect("mixed repo discovers");
    assert!(
        eps.iter()
            .any(|e| e.file_path.to_string_lossy().ends_with("src/lib.rs")),
        "the Rust lib root must be present in a mixed repo"
    );
    assert!(
        eps.iter()
            .any(|e| e.file_path.to_string_lossy().ends_with("gopkg")),
        "the Go package LibRoot must be present in a mixed repo"
    );
}

/// An EXPORTED Go symbol in an importable package seeds as a pub-api root — it is
/// NOT false-DEAD; an UNEXPORTED sibling with no caller stays Dead. Covers both
/// the importable-unit predicate (Go exact-package-dir branch) AND the Go-gated
/// `const|static` `is_api_kind` addition. RED on HEAD: the Rust `/src/` needle
/// rejects the Go path → nothing seeds → the exported symbols false-DEAD.
#[test]
fn go_pub_api_exported_symbols_seed_not_dead() {
    let dir = go_fixture();
    let mut graph = KnowledgeGraph::new();
    // Synthetic Go nodes matching the on-disk importable package pkg/foo.
    let exported_fn = mk_node(
        100,
        "Exported",
        "function",
        "pkg/foo/lib.go",
        ReachabilityClass::Unclassified,
        "pub",
        false,
    );
    let exported_const = mk_node(
        101,
        "MaxRetries",
        "const",
        "pkg/foo/lib.go",
        ReachabilityClass::Unclassified,
        "pub",
        false,
    );
    let exported_var = mk_node(
        102,
        "Registry",
        "static",
        "pkg/foo/lib.go",
        ReachabilityClass::Unclassified,
        "pub",
        false,
    );
    let unexported_fn = mk_node(
        103,
        "unexported",
        "function",
        "pkg/foo/lib.go",
        ReachabilityClass::Unclassified,
        "private",
        false,
    );
    for n in [&exported_fn, &exported_const, &exported_var, &unexported_fn] {
        graph.add_node(n.clone()).unwrap();
    }

    classify_and_writeback(&mut graph, dir.path()).expect("classify runs on a pure-Go repo");

    let class = |id: u128| graph.node(&Uuid::from_u128(id)).unwrap().reachability_class;
    let not_dead =
        |c: ReachabilityClass| !matches!(c, ReachabilityClass::Dead | ReachabilityClass::Orphan);
    assert!(
        not_dead(class(100)),
        "exported Go func must seed as a pub-api root (not false-DEAD)"
    );
    assert!(
        not_dead(class(101)),
        "exported Go const must seed (is_api_kind Go-gated const)"
    );
    assert!(
        not_dead(class(102)),
        "exported Go var must seed (is_api_kind Go-gated static)"
    );
    assert_eq!(
        class(103),
        ReachabilityClass::Dead,
        "an unexported, caller-less Go func is NOT seeded → Dead (distinguishes the seed)"
    );
}
