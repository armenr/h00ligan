//! WU-0015 Leg 3b / ADR-0036 §Decision v6 — the DEAD-authority tier: the leg
//! where `DeadAction::SafeDelete` first becomes reachable.
//!
//! Leg 3b emits `ReachabilityClass::Dead` for the private call-unreachable-no-guard
//! residual, and grants `SafeDelete` ONLY under a 4-way conjunction:
//!   (1) `reachability_class == Dead`
//!   (2) `rustc_flagged_dead` (Phase-8e rustc/clippy oracle corroboration)
//!   (3) delete-eligible visibility (private/pub(crate)/…, NOT `pub`, NOT "")
//!   (4) a cfg-CLEAN `crates/<name>` crate (`crate_name_of` is Some AND the crate
//!       carries no platform-cfg anywhere).
//! The delete-authority OUTPUT `classify_dead_action` (the action) is gated on
//! this conjunction. (WU-0016 / ADR-0039 superseded-for-cascade the parked
//! Leg-3b cascade HOLE FIX 1: the `find_cascade_deletable` payload was removed as
//! dead-weight under the delete-authority demote — see ADR-0036 provenance.)
//!
//! Every NEGATIVE control (`n*`) isolates ONE conjunct: break it → the node flips
//! to `SuspectedDelete`; restore it → `SafeDelete`, proving the conjunct
//! load-bearing. Producer-driven (real extractor line ranges) per the
//! anti-green-by-construction discipline; mirrors `leg3a_oracle.rs`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::entry_points::{EntryPoint, EntryPointKind};
use h00ligan_engine::extractor::extract_rust_symbols;
use h00ligan_engine::graph::{EdgeKind, EntryRetainFlags, GraphEdge, GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_query::{
    DeadAction, DeadReport, DeadSingleReport, cfg_touching_crates, classify_dead_action,
    classify_withhold_cause, crate_name_of, dead_report_gated, dead_single_gated,
    oracle_stale_downgrade_action,
};
use h00ligan_engine::reachability::{ReachabilityAnalyzer, ReachabilityClass};
use h00ligan_engine::rustc_oracle::{
    DeadDiag, OracleError, OracleOutcome, apply_oracle, clippy_build_succeeded,
    collect_dead_diagnostics,
};
use h00ligan_engine::structural_ir::ExtractorOutput;

// ---------------------------------------------------------------------------
// Producer-driven fixture helpers (mirror leg3a_oracle.rs).
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

fn node_id_named(graph: &KnowledgeGraph, name: &str) -> uuid::Uuid {
    graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == name)
        .unwrap_or_else(|| panic!("node {name:?} not found"))
        .memory_id
}

fn node_cloned(graph: &KnowledgeGraph, name: &str) -> GraphNode {
    graph.node(&node_id_named(graph, name)).unwrap().clone()
}

/// Manually set the rustc oracle bit on a producer node (simulates a Phase-8e
/// clippy flag — the ONLY signal a producer graph cannot synthesize itself).
fn flag_dead(graph: &mut KnowledgeGraph, name: &str) {
    let id = node_id_named(graph, name);
    if let Some(n) = graph.node_mut(&id) {
        n.rustc_flagged_dead = true;
    }
}

/// Build a graph whose `dead_fn` is a fully SafeDelete-eligible node: private,
/// call-unreachable → class==Dead (real analyze()), rustc-flagged, in the cfg-CLEAN
/// crate `x`. Returns the graph (the caller owns cfg_crates).
fn qualifying_graph() -> KnowledgeGraph {
    let mut graph = build_from_sources(&[
        ("crates/x/src/a.rs", "fn dead_fn() {}\npub fn api() {}\n"),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);
    flag_dead(&mut graph, "dead_fn");
    graph
}

// ===========================================================================
// R-1 — all-4 conjuncts satisfied → SafeDelete (the grant path).
// ===========================================================================

#[test]
fn r1_all_four_conjuncts_yield_safedelete() {
    let graph = qualifying_graph();
    let dead = node_cloned(&graph, "dead_fn");
    let cfg_crates = cfg_touching_crates(&graph); // empty: crate x is cfg-clean

    // Preconditions — the full 4-way profile, each asserted independently.
    assert_eq!(
        dead.reachability_class,
        ReachabilityClass::Dead,
        "private call-unreachable residual promotes to Dead"
    );
    assert!(dead.rustc_flagged_dead, "oracle-corroborated");
    assert!(
        dead.visibility != "pub" && !dead.visibility.is_empty(),
        "delete-eligible visibility (got {:?})",
        dead.visibility
    );
    assert_eq!(
        crate_name_of(&dead.file_path),
        Some("x"),
        "resolves to crate x"
    );
    assert!(!cfg_crates.contains("x"), "crate x is cfg-clean");

    assert_eq!(
        classify_dead_action(&graph, &dead, &cfg_crates),
        DeadAction::SafeDelete,
        "all 4 conjuncts satisfied → SafeDelete"
    );
}

// ===========================================================================
// N-1 — visibility conjunct (break → pub).
// ===========================================================================

#[test]
fn n1_break_visibility_pub_then_restore() {
    let graph = qualifying_graph();
    let base = node_cloned(&graph, "dead_fn");
    let empty = HashSet::new();

    // Baseline: SafeDelete.
    assert_eq!(
        classify_dead_action(&graph, &base, &empty),
        DeadAction::SafeDelete
    );

    // BREAK conjunct 3: pub visibility → SuspectedDelete (base is not needed after).
    let mut broken = base;
    broken.visibility = "pub".into();
    assert_eq!(
        classify_dead_action(&graph, &broken, &empty),
        DeadAction::SuspectedDelete,
        "a pub node is NEVER SafeDelete (conjunct 3 load-bearing)"
    );

    // RESTORE → SafeDelete.
    broken.visibility = "private".into();
    assert_eq!(
        classify_dead_action(&graph, &broken, &empty),
        DeadAction::SafeDelete
    );
}

#[test]
fn n1_producer_pub_body_residual_is_suspected_class() {
    // The residual-sweep effect (a): a PUB call-unreachable residual is downgraded
    // to Suspected (never Dead), so even with the oracle flag set it is
    // SuspectedDelete — the pub surface is never false-DEADed.
    let mut graph = build_from_sources(&[
        (
            "crates/x/src/a.rs",
            "pub fn dead_pub() {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);
    flag_dead(&mut graph, "dead_pub");

    let dead_pub = node_cloned(&graph, "dead_pub");
    assert_eq!(
        dead_pub.reachability_class,
        ReachabilityClass::Suspected,
        "a pub zero-caller residual is Suspected, never Dead"
    );
    assert_eq!(
        classify_dead_action(&graph, &dead_pub, &HashSet::new()),
        DeadAction::SuspectedDelete,
        "a flagged pub residual is still SuspectedDelete"
    );
}

// ===========================================================================
// N-2 — class conjunct (break → not Dead). has_platform_cfg is CRATE-level
// (conjunct 4 / N-3), never node-level, so conjunct 1 is isolated by class alone.
// ===========================================================================

#[test]
fn n2_break_class_not_dead_then_restore() {
    let graph = qualifying_graph();
    let base = node_cloned(&graph, "dead_fn");
    let empty = HashSet::new();

    assert_eq!(
        classify_dead_action(&graph, &base, &empty),
        DeadAction::SafeDelete
    );

    // BREAK conjunct 1: any non-Dead class → SuspectedDelete (Suspected and Orphan
    // both fail conjunct 1).
    let mut suspected = base.clone();
    suspected.reachability_class = ReachabilityClass::Suspected;
    assert_eq!(
        classify_dead_action(&graph, &suspected, &empty),
        DeadAction::SuspectedDelete,
        "a Suspected node is NEVER SafeDelete (conjunct 1 load-bearing)"
    );
    let mut orphan = base; // base is not needed after this move
    orphan.reachability_class = ReachabilityClass::Orphan;
    assert_eq!(
        classify_dead_action(&graph, &orphan, &empty),
        DeadAction::SuspectedDelete,
        "an Orphan node is NEVER SafeDelete (conjunct 1 load-bearing)"
    );

    // RESTORE → SafeDelete.
    orphan.reachability_class = ReachabilityClass::Dead;
    assert_eq!(
        classify_dead_action(&graph, &orphan, &empty),
        DeadAction::SafeDelete
    );
}

// ===========================================================================
// N-3 — cfg-clean-crate conjunct (break → cfg-touching crate). PRODUCER: a
// sibling in the SAME crate carries a platform-cfg guard.
// ===========================================================================

#[test]
fn n3_break_crate_cfg_touching_then_restore() {
    let mut graph = build_from_sources(&[
        ("crates/y/src/a.rs", "fn dead_fn() {}\npub fn api() {}\n"),
        (
            "crates/y/src/b.rs",
            "#[cfg(target_os = \"linux\")]\npub fn plat() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "y", "crates/y/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);
    flag_dead(&mut graph, "dead_fn");

    let dead = node_cloned(&graph, "dead_fn");
    assert_eq!(dead.reachability_class, ReachabilityClass::Dead);

    // cfg_crates computed ONCE (never per-node); the sibling `plat` puts crate `y`
    // into the set.
    let cfg_crates = cfg_touching_crates(&graph);
    assert!(
        cfg_crates.contains("y"),
        "crate y is cfg-touching via `plat`"
    );

    // BREAK conjunct 4: the whole crate is cfg-contaminated → SuspectedDelete.
    assert_eq!(
        classify_dead_action(&graph, &dead, &cfg_crates),
        DeadAction::SuspectedDelete,
        "a node in a cfg-touching crate is NEVER SafeDelete (conjunct 4 load-bearing)"
    );

    // RESTORE (no cfg sibling ⇒ y leaves the set) → SafeDelete.
    assert_eq!(
        classify_dead_action(&graph, &dead, &HashSet::new()),
        DeadAction::SafeDelete,
        "with the crate cfg-clean the same node → SafeDelete"
    );
}

// ===========================================================================
// N-4 — rustc_flagged_dead conjunct (break → false). Structurally impossible via
// real clippy (it always flags genuine dead), so producer + manual toggle.
// ===========================================================================

#[test]
fn n4_break_rustc_unflagged_then_restore() {
    let graph = qualifying_graph();
    let mut node = node_cloned(&graph, "dead_fn");
    let empty = HashSet::new();

    // BREAK conjunct 2: strip the oracle flag → SuspectedDelete (uncorroborated).
    node.rustc_flagged_dead = false;
    assert_eq!(
        classify_dead_action(&graph, &node, &empty),
        DeadAction::SuspectedDelete,
        "an uncorroborated Dead node is NEVER SafeDelete (conjunct 2 load-bearing)"
    );

    // RESTORE the flag → SafeDelete.
    node.rustc_flagged_dead = true;
    assert_eq!(
        classify_dead_action(&graph, &node, &empty),
        DeadAction::SafeDelete
    );
}

// ===========================================================================
// N-5 — visibility conjunct, exported-surface variant (pub zero-caller).
// ===========================================================================

#[test]
fn n5_producer_pub_zero_caller_is_suspected() {
    // A pub fn with ZERO callers in a lib crate: the V3-1 split classifies it
    // Suspected (the external-API-vs-wiring-gap review candidate), never Dead and
    // never SafeDelete — the crate's exported surface is never delete-authority.
    let mut graph = build_from_sources(&[(
        "crates/x/src/a.rs",
        "pub fn external_api() {}\npub fn used() {}\n",
    )]);
    let eps = vec![entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs")];
    analyze_and_writeback(&mut graph, eps);
    flag_dead(&mut graph, "external_api");

    let api = node_cloned(&graph, "external_api");
    assert_eq!(
        api.reachability_class,
        ReachabilityClass::Suspected,
        "a pub zero-caller exported fn is Suspected (never Dead)"
    );
    assert_eq!(
        classify_dead_action(&graph, &api, &HashSet::new()),
        DeadAction::SuspectedDelete,
        "the exported surface is never granted SafeDelete"
    );
}

// ===========================================================================
// WU-0016 / ADR-0039 (superseded-for-cascade): the parked Leg-3b HOLE FIX 1
// proof test `hole_cascade_collects_only_safedelete_corroborated` was REMOVED
// with the `find_cascade_deletable` machinery it exercised (dead-weight under
// the delete-authority demote). The surviving `classify_dead_action` 4-way
// conjunction coverage (the `n*` negative controls + the ceiling test below) is
// unchanged. ADR-0036 provenance: the cascade path was the SECOND
// delete-authority output; deleting it retires that surface.
// ===========================================================================

// ===========================================================================
// HOLE FIX 2 — crate_name_of == None must NOT be SafeDelete-eligible (the
// is_some() requirement, encoded by is_some_and).
// ===========================================================================

#[test]
fn hole_crate_name_none_is_not_safedelete() {
    // A BARE src/lib.rs (single-package repo): crate_name_of returns None. A private
    // flagged Dead fn here would, on a naive gate that omits is_some() (e.g.
    // map_or(true, …)), be granted SafeDelete WITHOUT any cfg-clean-crate
    // attribution — a latent false-SafeDelete. The is_some_and gate withholds it.
    let mut graph =
        build_from_sources(&[("src/lib.rs", "fn unused_private() {}\npub fn api() {}\n")]);
    let eps = vec![entry(EntryPointKind::LibRoot, "singlepkg", "src/lib.rs")];
    analyze_and_writeback(&mut graph, eps);
    flag_dead(&mut graph, "unused_private");

    let node = node_cloned(&graph, "unused_private");
    assert_eq!(
        crate_name_of(&node.file_path),
        None,
        "a bare src/lib.rs has no crates/<name> attribution"
    );
    assert_eq!(
        node.reachability_class,
        ReachabilityClass::Dead,
        "the private residual is Dead (HOLE FIX 2 is about the ACTION, not the class)"
    );
    assert!(node.rustc_flagged_dead, "and rustc-flagged");
    assert_eq!(
        classify_dead_action(&graph, &node, &HashSet::new()),
        DeadAction::SuspectedDelete,
        "a None-crate node is NOT SafeDelete-eligible (is_some() requirement)"
    );
}

// ===========================================================================
// OQ-ORACLE-COMPILE-SUCCESS-GATE — a completed-but-failed-compile clippy run must
// yield ZERO flags (absent oracle), never a partial-unsafe dead set.
// ===========================================================================

const DEAD_DIAG_LINE: &str = r#"{"reason":"compiler-message","message":{"code":{"code":"dead_code"},"spans":[{"file_name":"crates/x/src/a.rs","line_start":10,"is_primary":true}]}}"#;

#[test]
fn oracle_gate_failed_build_yields_empty() {
    // A diag-bearing stream WITHOUT `build-finished: success=true` (a compile error
    // stopped the build) → empty set, same downstream as a graceful-degrade absent
    // oracle.
    let json = format!("{DEAD_DIAG_LINE}\n{{\"reason\":\"build-finished\",\"success\":false}}");
    let runner = |_: &Path, _: Duration| Ok::<String, OracleError>(json.clone());
    let out =
        collect_dead_diagnostics(dummy_root(), Duration::from_secs(1), runner).expect("no error");
    // LEG E (part a1): a failed-compile stream is now signalled as `Degraded`
    // (was `Ok(Vec::new())`), so the caller can distinguish it from a clean-empty
    // run and PRESERVE existing flags instead of resetting them.
    assert!(
        matches!(out, OracleOutcome::Degraded),
        "a failed-compile clippy stream must be Degraded (no trustworthy info); got {out:?}"
    );
}

#[test]
fn oracle_gate_success_build_yields_diags() {
    // The same diag WITH `build-finished: success=true` → the diagnostic is kept.
    let json = format!("{DEAD_DIAG_LINE}\n{{\"reason\":\"build-finished\",\"success\":true}}");
    let runner = |_: &Path, _: Duration| Ok::<String, OracleError>(json.clone());
    let out =
        collect_dead_diagnostics(dummy_root(), Duration::from_secs(1), runner).expect("no error");
    // LEG E (part a1): a successful build is `Ran(diags)` — the AUTHORITATIVE
    // arm whose (here non-empty) set is the complete truth.
    let OracleOutcome::Ran(diags) = out else {
        panic!("a successful-build stream must be Ran(..); got {out:?}");
    };
    assert_eq!(
        diags.len(),
        1,
        "a successful-build stream keeps its diagnostics"
    );
}

#[test]
fn clippy_build_succeeded_unit() {
    assert!(clippy_build_succeeded(
        "{\"reason\":\"build-finished\",\"success\":true}"
    ));
    assert!(!clippy_build_succeeded(
        "{\"reason\":\"build-finished\",\"success\":false}"
    ));
    assert!(
        !clippy_build_succeeded(DEAD_DIAG_LINE),
        "a stream with NO build-finished marker is not a successful build"
    );
    assert!(!clippy_build_succeeded(""), "empty stream is not a success");
}

fn dummy_root() -> &'static Path {
    Path::new("/repo")
}

// ===========================================================================
// LEG E — OQ-ORACLE-INCREMENTAL-STALE: the oracle-stale backstop (part b2).
//   oracle_stale_downgrade_action strips SafeDelete when the last reindex's
//   oracle pass was NON-authoritative (oracle_ran_ok=false), TARGETED (fires
//   only on a degraded build), and is COMPOSED at both gate call sites.
// ===========================================================================

/// F2 (COMPILE-RED on HEAD: `oracle_stale_downgrade_action` does not exist) —
/// the pure-function contract: `(SafeDelete, false) → SuspectedDelete`; every
/// non-SafeDelete action passes through unchanged under `false`. The WIRED proof
/// is F2b.
#[test]
fn leg_e_f2_backstop_strips_safedelete_when_oracle_degraded() {
    assert_eq!(
        oracle_stale_downgrade_action(DeadAction::SafeDelete, false),
        DeadAction::SuspectedDelete,
        "oracle_ran_ok=false strips SafeDelete"
    );
    assert_eq!(
        oracle_stale_downgrade_action(DeadAction::SuspectedDelete, false),
        DeadAction::SuspectedDelete
    );
    assert_eq!(
        oracle_stale_downgrade_action(DeadAction::NeedsReview, false),
        DeadAction::NeedsReview
    );
}

/// F2b (COMPILE-RED on HEAD: `dead_report_gated` / `dead_single_gated` took no
/// `oracle_ran_ok` param) — the IMPL→WIRED proof for the backstop. A qualifying
/// SafeDelete node reported through the gated helpers with a non-suppressing tier
/// (Sufficient) + in-envelope disposition (Emit) is SafeDelete when
/// `oracle_ran_ok=true`, and downgraded to SuspectedDelete when
/// `oracle_ran_ok=false` — proving `oracle_stale_downgrade_action` is COMPOSED at
/// BOTH gate call sites (part b2), not merely defined. This is the WIRED bar the
/// pure F2 does NOT cover.
#[test]
fn leg_e_f2b_backstop_wired_into_gated_reports() {
    use h00ligan_engine::graph_stats::CoverageTier;
    let graph = qualifying_graph(); // dead_fn: Dead+flagged+private+cfg-clean crate x
    let node = node_cloned(&graph, "dead_fn");
    let tier = CoverageTier::Sufficient;

    // authoritative (true) → SafeDelete survives the full report.
    let DeadReport::Full(d) = dead_report_gated(&graph, tier, true) else {
        panic!("Sufficient must EMIT");
    };
    assert!(
        d.entries
            .iter()
            .any(|e| e.symbol_name.ends_with("dead_fn") && e.action == DeadAction::SafeDelete),
        "oracle_ran_ok=true keeps dead_fn SafeDelete in the full report"
    );

    // degraded (false) → stripped to SuspectedDelete in the full report.
    let DeadReport::Full(d) = dead_report_gated(&graph, tier, false) else {
        panic!("Sufficient must EMIT");
    };
    assert!(
        d.entries
            .iter()
            .any(|e| e.symbol_name.ends_with("dead_fn") && e.action == DeadAction::SuspectedDelete),
        "oracle_ran_ok=false strips dead_fn to SuspectedDelete in the full report"
    );

    // single-symbol path threads identically.
    let DeadSingleReport::Computed {
        is_dead, action, ..
    } = dead_single_gated(&graph, &node, tier, false)
    else {
        panic!("Sufficient must compute a single-symbol verdict");
    };
    assert!(is_dead, "dead_fn is dead");
    assert_eq!(
        action,
        Some(DeadAction::SuspectedDelete),
        "the single-symbol gate composes the oracle-stale downgrade too"
    );
}

/// N3 (negative control) — `(SafeDelete, true) → SafeDelete`: an AUTHORITATIVE
/// oracle pass does NOT downgrade a confirmed DEAD. Proves the backstop is
/// TARGETED (fires only on a degraded build), not the SUPERSEDED blanket
/// incremental_drift downgrade that would collapse the confirmed tier on every
/// incremental. The F2/N3 pair together prove the helper actually READS the bool
/// rather than being a constant.
#[test]
fn leg_e_n3_backstop_targeted_true_keeps_safedelete() {
    assert_eq!(
        oracle_stale_downgrade_action(DeadAction::SafeDelete, true),
        DeadAction::SafeDelete,
        "oracle_ran_ok=true (authoritative) does NOT downgrade — targeted, not blanket"
    );
}

// ===========================================================================
// LEG C — presence-based cfg detection (OQ-CFG-CLEAN-CONJUNCT-UNSOUND).
//
// Conjunct 4 (the cfg-clean-crate gate) was UNSOUND for the class of cfg
// predicates that SCIP silently STRIPS: SCIP is generated with `--all-features`
// on a normal (non-doc, non-sanitizer) build, so a symbol gated ONLY by
// `cfg(doc)` / `cfg(docsrs)` / `cfg(kani)` / `cfg(fuzzing)` / a custom build-script
// rustc-cfg / a NEGATED feature `cfg(not(feature = "x"))` / `cfg(not(test))` is
// compiled OUT of the SCIP graph. A caller hidden behind such a gate is invisible
// to BOTH the SCIP edge graph AND the cold rustc oracle → its callee looks
// call-unreachable → a FALSE `SafeDelete`. The old `has_platform_cfg` scan keyed
// only on `target_*` / `windows` / `unix` / `panic` / `debug_assertions`, so these
// crates were mis-classified cfg-CLEAN and reached delete-authority.
//
// Each `legc_red_*` isolates ONE such strippable kind: on the UNMODIFIED tree the
// sibling's cfg does NOT mark the crate cfg-touching → `dead_fn` → SafeDelete
// (the RED / false-authority state); presence-based detection marks the crate
// cfg-touching → SuspectedDelete. Each mirrors `n3_break_crate_cfg_touching_then_restore`
// through the REAL extractor (`build_from_sources`), varying ONLY the cfg guard.
//
// The two `legc_guard_*` pin the DELIBERATE exclusions (extractor doc invariant):
// a POSITIVE feature cfg (SCIP `--all-features` resolves it TRUE → kept, never
// hides a symbol) and a bare `cfg(test)` (test-only symbols are tracked by the
// separate test-scope machinery, not the platform-cfg delete-authority path) must
// STAY cfg-clean → SafeDelete, BEFORE and AFTER the fix. They must not regress.
// ===========================================================================

/// Build a producer graph whose crate `y` holds a private, oracle-flagged,
/// call-unreachable `dead_fn` (SafeDelete-eligible on all conjuncts except
/// possibly 4) plus a sibling `plat` fn carrying `guard_attr` as its cfg guard.
/// Returns `(graph, cfg_touching_crates(graph))`. Mirrors
/// `n3_break_crate_cfg_touching_then_restore` with the guard parameterized so each
/// strippable-cfg kind is isolated behind the SAME producer path.
fn cfg_guard_graph(guard_attr: &str) -> (KnowledgeGraph, HashSet<String>) {
    let b_src = format!("{guard_attr}\npub fn plat() {{}}\n");
    let mut graph = build_from_sources(&[
        ("crates/y/src/a.rs", "fn dead_fn() {}\npub fn api() {}\n"),
        ("crates/y/src/b.rs", b_src.as_str()),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "y", "crates/y/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);
    flag_dead(&mut graph, "dead_fn");
    let cfg_crates = cfg_touching_crates(&graph);
    (graph, cfg_crates)
}

/// Shared body for the six RED falsifiers: the `guard_attr` sibling MUST mark
/// crate `y` cfg-touching (RED on HEAD, GREEN after the fix), which withholds
/// `dead_fn` from SafeDelete via conjunct 4.
fn assert_strippable_cfg_withholds_authority(guard_attr: &str, why: &str) {
    let (graph, cfg_crates) = cfg_guard_graph(guard_attr);
    let dead = node_cloned(&graph, "dead_fn");
    assert_eq!(
        dead.reachability_class,
        ReachabilityClass::Dead,
        "dead_fn is a private call-unreachable residual regardless of the sibling's cfg"
    );
    assert!(
        cfg_crates.contains("y"),
        "{guard_attr} is SCIP-strippable ({why}) → crate y must be cfg-touching"
    );
    assert_eq!(
        classify_dead_action(&graph, &dead, &cfg_crates),
        DeadAction::SuspectedDelete,
        "a node in a cfg-touching crate is withheld from SafeDelete (conjunct 4); guard={guard_attr}"
    );
}

#[test]
fn legc_red_cfg_doc_marks_crate_touching() {
    // SCIP is not built with `--cfg doc`, so `cfg(doc)` code is stripped.
    assert_strippable_cfg_withholds_authority("#[cfg(doc)]", "SCIP builds without --cfg doc");
}

#[test]
fn legc_red_cfg_docsrs_marks_crate_touching() {
    // `docsrs` is a custom cfg set only by docs.rs; a normal SCIP build strips it.
    assert_strippable_cfg_withholds_authority("#[cfg(docsrs)]", "docs.rs-only custom cfg");
}

#[test]
fn legc_red_cfg_kani_marks_crate_touching() {
    // `kani` is set only under the Kani model checker; a normal SCIP build strips it.
    assert_strippable_cfg_withholds_authority("#[cfg(kani)]", "Kani-only sanitizer cfg");
}

#[test]
fn legc_red_cfg_fuzzing_marks_crate_touching() {
    // `fuzzing` is set only under a fuzz build; a normal SCIP build strips it.
    assert_strippable_cfg_withholds_authority("#[cfg(fuzzing)]", "fuzz-only sanitizer cfg");
}

#[test]
fn legc_red_cfg_not_feature_marks_crate_touching() {
    // `--all-features` makes `feature = "x"` TRUE, so `not(feature = "x")` is FALSE
    // → SCIP strips the negated arm (the mirror of the positive-feature exclusion).
    assert_strippable_cfg_withholds_authority(
        "#[cfg(not(feature = \"x\"))]",
        "--all-features strips the negated arm",
    );
}

#[test]
fn legc_red_cfg_not_test_marks_crate_touching() {
    // `not(test)` gates production-only code that a test-config SCIP build strips.
    assert_strippable_cfg_withholds_authority("#[cfg(not(test))]", "test-config strips not(test)");
}

#[test]
fn legc_guard_bare_cfg_test_stays_safedelete() {
    // DELIBERATE EXCLUSION (must NOT regress): a bare `cfg(test)` symbol is tracked
    // by the test-scope machinery, not the platform-cfg delete-authority path — it
    // must leave the crate cfg-CLEAN so `dead_fn` stays SafeDelete, before + after.
    let (graph, cfg_crates) = cfg_guard_graph("#[cfg(test)]");
    let dead = node_cloned(&graph, "dead_fn");
    assert!(
        !cfg_crates.contains("y"),
        "a bare cfg(test) sibling must NOT mark crate y cfg-touching"
    );
    assert_eq!(
        classify_dead_action(&graph, &dead, &cfg_crates),
        DeadAction::SafeDelete,
        "a bare-cfg(test) sibling leaves the crate cfg-clean → dead_fn stays SafeDelete"
    );
}

#[test]
fn legc_guard_positive_feature_stays_safedelete() {
    // DELIBERATE EXCLUSION (must NOT regress): a POSITIVE feature cfg is resolved
    // TRUE by SCIP's `--all-features`, so it never hides a symbol — it must leave
    // the crate cfg-CLEAN so `dead_fn` stays SafeDelete, before + after the fix.
    let (graph, cfg_crates) = cfg_guard_graph("#[cfg(feature = \"x\")]");
    let dead = node_cloned(&graph, "dead_fn");
    assert!(
        !cfg_crates.contains("y"),
        "a positive cfg(feature = \"x\") sibling must NOT mark crate y cfg-touching"
    );
    assert_eq!(
        classify_dead_action(&graph, &dead, &cfg_crates),
        DeadAction::SafeDelete,
        "a positive-feature sibling leaves the crate cfg-clean → dead_fn stays SafeDelete"
    );
}

// ===========================================================================
// LEG D — the trait-contract guard (OQ-TRAIT-CONTRACT-GUARD / WU-0015 Leg-D).
//
// A node that PASSES the 4-way conjunction is STILL withheld from SafeDelete when
// it has an incoming `Implements`/`HasImpl`/`Contains` edge whose COUNTERPART (the
// edge source) is not itself corroborated-deletable — deleting the node would
// dangle an edge-carried reference in a still-alive counterpart. Directions
// (edge_builder ground truth): `Implements` impl->trait, `HasImpl` trait->struct,
// `Contains` parent->child, so `incoming_neighbors` yields the trait's impls, the
// struct's owning trait, and the item's container respectively. The guard only ever
// DOWNGRADES SafeDelete->SuspectedDelete (safe-direction, same as conjuncts B+C).
//
// Companion MAJOR fix: `has_alive_dependent`/`has_test_dependent` now EXCLUDE
// `Contains` (parent->child is containment, not usage), so a dead item nested in an
// alive parent no longer mis-reads as "has an alive user" (NeedsReview); the LEG-D
// guard owns containment-breakage instead. Each fixture asserts the 4-way holds on
// the node fields (anti-green-by-construction: the ONLY reason it is not SafeDelete
// is the guard). cfg_crates is empty (hand-built nodes carry no platform-cfg).
//
// OUT OF SCOPE (edge-invisible; tracked in an OQ, NOT chased here): E0407 macro-emitted
// impls (macros produce no graph edge) and inherent-impl `impl T {}` E0412 (no
// struct<->impl edge) — the guard protects only edge-carried contracts.
// ===========================================================================

/// Hand-build a node with an explicit reachability class + oracle flag, for the
/// LEG-D direct-arm fixtures whose edge shapes the producer path does not
/// synthesize on demand.
fn dnode(
    name: &str,
    kind: &str,
    file: &str,
    vis: &str,
    class: ReachabilityClass,
    flagged: bool,
) -> GraphNode {
    GraphNode {
        memory_id: uuid::Uuid::new_v4(),
        symbol_name: name.to_string(),
        kind: kind.to_string(),
        file_path: file.to_string(),
        content_hash: format!("h_{name}"),
        signature: String::new(),
        reachability_class: class,
        line_start: None,
        line_end: None,
        has_body: None,
        visibility: vis.to_string(),
        is_test_only: None,
        is_test_root: false,
        has_platform_cfg: false,
        rustc_flagged_dead: flagged,
        entry_retain: Default::default(),
        has_uncaptured_items: false,
        oracle_receipt: None,
    }
}

fn edge(kind: EdgeKind) -> GraphEdge {
    GraphEdge {
        kind,
        ..Default::default()
    }
}

/// Assert the node satisfies all 4 SafeDelete conjuncts on its OWN fields, so the
/// ONLY thing that can withhold SafeDelete is the LEG-D guard (anti-green-by-
/// construction). cfg_crates is the (empty) hand-built set.
fn assert_four_way_holds(node: &GraphNode, cfg_crates: &HashSet<String>) {
    assert_eq!(
        node.reachability_class,
        ReachabilityClass::Dead,
        "precond conjunct 1: class==Dead"
    );
    assert!(node.rustc_flagged_dead, "precond conjunct 2: rustc-flagged");
    assert!(
        node.visibility != "pub" && !node.visibility.is_empty(),
        "precond conjunct 3: delete-eligible visibility (got {:?})",
        node.visibility
    );
    assert!(
        crate_name_of(&node.file_path).is_some_and(|c| !cfg_crates.contains(c)),
        "precond conjunct 4: cfg-clean crates/<name> crate (path {:?})",
        node.file_path
    );
}

// ---------------------------------------------------------------------------
// legd_e0412 — the LOAD-BEARING end-to-end falsifier through the REAL extractor.
// `trait Bar {} / struct Foo; / impl Bar for Foo {}`, wholly unused so all Dead;
// Foo+Bar oracle-flagged, the impl block UNFLAGGED. On HEAD Foo (and Bar) reach
// SafeDelete (the E0412 leak: deleting Foo dangles the live `impl Bar for Foo`);
// after the fix the guard withholds both -> SuspectedDelete. build_from_sources so
// the REAL Implements/HasImpl/Contains edges + the unflagged impl block are produced.
// ---------------------------------------------------------------------------

#[test]
fn legd_e0412_trait_impl_cluster_withholds_via_real_extractor() {
    let mut graph = build_from_sources(&[
        (
            "crates/x/src/a.rs",
            "trait Bar {}\nstruct Foo;\nimpl Bar for Foo {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);
    // Foo (struct) + Bar (trait) are oracle-flagged; the impl block stays UNFLAGGED.
    flag_dead(&mut graph, "Foo");
    flag_dead(&mut graph, "Bar");

    let cfg_crates = cfg_touching_crates(&graph); // empty: crate x is cfg-clean
    let foo = node_cloned(&graph, "Foo");
    let bar = node_cloned(&graph, "Bar");
    let impl_block = node_cloned(&graph, "impl Bar for Foo");

    // Anti-green-by-construction: Foo + Bar each pass the full 4-way, so on HEAD
    // (no guard) both are SafeDelete. The impl block is the WITHHOLDING CAUSE — it
    // is Dead but UNFLAGGED, so it is never SafeDelete itself.
    assert_four_way_holds(&foo, &cfg_crates);
    assert_four_way_holds(&bar, &cfg_crates);
    assert!(
        !impl_block.rustc_flagged_dead,
        "the impl block must stay UNFLAGGED (the uncorroborated counterpart)"
    );
    assert_eq!(
        classify_dead_action(&graph, &impl_block, &cfg_crates),
        DeadAction::SuspectedDelete,
        "the UNFLAGGED impl block is not itself SafeDelete (fails conjunct 2)"
    );

    // RED on HEAD: Foo -> SafeDelete (deleting Foo dangles the live impl -> E0412).
    // GREEN after the guard: the HasImpl->Implements chain reaches the unflagged
    // impl block, so both the struct and the trait are withheld.
    assert_eq!(
        classify_dead_action(&graph, &foo, &cfg_crates),
        DeadAction::SuspectedDelete,
        "E0412: a struct in a live `impl` must be withheld from SafeDelete"
    );
    assert_eq!(
        classify_dead_action(&graph, &bar, &cfg_crates),
        DeadAction::SuspectedDelete,
        "E0405: a trait with a live `impl` must be withheld from SafeDelete"
    );
}

// ---------------------------------------------------------------------------
// legd_codeletion — no-over-withhold invariant (GREEN before AND after). When the
// WHOLE cluster is corroborated-deletable (trait+struct+impl all Dead+flagged+
// private+cfg-clean), the members that pass the 4-way STILL reach SafeDelete: the
// visited-set base case lets the mutual-impl ring CO-DELETE. Proves the guard does
// not over-withhold a genuinely co-deletable cluster.
// ---------------------------------------------------------------------------

#[test]
fn legd_wholly_dead_cluster_still_codeletes() {
    let mut graph = build_from_sources(&[
        (
            "crates/x/src/a.rs",
            "trait Bar {}\nstruct Foo;\nimpl Bar for Foo {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);
    // Flag ALL THREE members: the whole ring is corroborated-deletable.
    flag_dead(&mut graph, "Foo");
    flag_dead(&mut graph, "Bar");
    flag_dead(&mut graph, "impl Bar for Foo");

    let cfg_crates = cfg_touching_crates(&graph);
    for name in ["Foo", "Bar", "impl Bar for Foo"] {
        let n = node_cloned(&graph, name);
        assert_eq!(
            classify_dead_action(&graph, &n, &cfg_crates),
            DeadAction::SafeDelete,
            "co-deletable cluster member {name:?} must still reach SafeDelete \
             (guard must not over-withhold; cycle base case closes the ring)"
        );
    }
}

// ---------------------------------------------------------------------------
// legd_e0405 — hand-built direct arm: a dead+flagged TRAIT with an incoming
// `Implements` from an uncorroborated (Dead+UNFLAGGED) impl. The impl being Dead
// keeps it out of `has_alive_dependent` on HEAD, so the trait reaches SafeDelete
// (RED); the guard withholds it post-fix. Pure `Implements` edge -> exercises the
// guard alone (unaffected by the Contains-exclusion).
// ---------------------------------------------------------------------------

#[test]
fn legd_e0405_dead_trait_with_uncorroborated_impl() {
    let mut graph = KnowledgeGraph::new();
    let t = dnode(
        "Tr",
        "trait",
        "crates/xd/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        true, // flagged: 4-way holds
    );
    let imp = dnode(
        "impl Tr for S",
        "impl",
        "crates/xd/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        false, // UNFLAGGED: uncorroborated counterpart
    );
    let t_id = t.memory_id;
    let imp_id = imp.memory_id;
    graph.add_node(t.clone()).unwrap();
    graph.add_node(imp.clone()).unwrap();
    // impl --Implements--> trait  (so the trait's incoming counterpart is the impl)
    graph
        .add_edge(imp_id, t_id, edge(EdgeKind::Implements))
        .unwrap();

    let cfg_crates = cfg_touching_crates(&graph);
    assert_four_way_holds(&t, &cfg_crates);
    assert_eq!(
        classify_dead_action(&graph, &imp, &cfg_crates),
        DeadAction::SuspectedDelete,
        "the uncorroborated (unflagged) impl is not itself SafeDelete"
    );
    assert_eq!(
        classify_dead_action(&graph, &t, &cfg_crates),
        DeadAction::SuspectedDelete,
        "E0405: a trait with an uncorroborated `impl` is withheld from SafeDelete"
    );
}

// ---------------------------------------------------------------------------
// legd_e0046 — hand-built direct arm through the CONTAINS edge: a dead+flagged
// required method with an incoming `Contains` from an ALIVE (Wired) impl block.
// On HEAD the alive container makes `has_alive_dependent` fire -> NeedsReview
// (the Contains-misattribution). The Contains-exclusion moves it off NeedsReview
// so it reaches the 4-way; the guard then withholds it (the live impl block is
// not deletable) -> SuspectedDelete. Exercises the Contains-fix AND the guard.
// ---------------------------------------------------------------------------

#[test]
fn legd_e0046_required_method_contained_by_live_impl() {
    let mut graph = KnowledgeGraph::new();
    let m = dnode(
        "S::m",
        "function",
        "crates/xe/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        true, // flagged: 4-way holds
    );
    let impl_block = dnode(
        "impl Tr for S",
        "impl",
        "crates/xe/src/a.rs",
        "private",
        ReachabilityClass::Wired, // ALIVE container
        false,
    );
    let m_id = m.memory_id;
    let ib_id = impl_block.memory_id;
    graph.add_node(m.clone()).unwrap();
    graph.add_node(impl_block.clone()).unwrap();
    // impl block --Contains--> method (parent->child)
    graph
        .add_edge(ib_id, m_id, edge(EdgeKind::Contains))
        .unwrap();

    let cfg_crates = cfg_touching_crates(&graph);
    assert_four_way_holds(&m, &cfg_crates);
    assert_ne!(
        classify_dead_action(&graph, &impl_block, &cfg_crates),
        DeadAction::SafeDelete,
        "the live impl block is not itself deletable"
    );
    // RED on HEAD: NeedsReview (Contains counted the alive impl as a usage-dependent);
    // GREEN after fix: SuspectedDelete (Contains no longer counted; guard withholds).
    assert_eq!(
        classify_dead_action(&graph, &m, &cfg_crates),
        DeadAction::SuspectedDelete,
        "E0046: a method contained by a live impl block is withheld from SafeDelete"
    );
}

// ---------------------------------------------------------------------------
// legd_misattribution — the Contains-exclusion regression: a dead+flagged private
// child fn with an incoming `Contains` from an ALIVE (Wired) parent module. On
// HEAD the alive parent mis-reads as an alive USER -> NeedsReview. Post-fix the
// child reaches the 4-way and the guard withholds it (alive container not
// deletable) -> SuspectedDelete. Confirms the relabel is NeedsReview->
// SuspectedDelete (BOTH withheld), NOT a new-SafeDelete unlock.
// ---------------------------------------------------------------------------

#[test]
fn legd_misattribution_contains_from_alive_parent() {
    let mut graph = KnowledgeGraph::new();
    let child = dnode(
        "nested_fn",
        "function",
        "crates/xf/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        true, // flagged: 4-way holds
    );
    let parent = dnode(
        "parent_mod",
        "module",
        "crates/xf/src/a.rs",
        "private",
        ReachabilityClass::Wired, // ALIVE parent
        false,
    );
    let child_id = child.memory_id;
    let parent_id = parent.memory_id;
    graph.add_node(child.clone()).unwrap();
    graph.add_node(parent).unwrap(); // parent not read after add
    // parent --Contains--> child (parent->child)
    graph
        .add_edge(parent_id, child_id, edge(EdgeKind::Contains))
        .unwrap();

    let cfg_crates = cfg_touching_crates(&graph);
    assert_four_way_holds(&child, &cfg_crates);
    // Not a new-SafeDelete unlock: the guard withholds because the alive container
    // is not deletable -> SuspectedDelete (RED on HEAD was NeedsReview).
    assert_eq!(
        classify_dead_action(&graph, &child, &cfg_crates),
        DeadAction::SuspectedDelete,
        "a child nested in an ALIVE parent is withheld (relabel, not a SafeDelete unlock)"
    );
}

// ===========================================================================
// LEG J — retain-attribute / entry-point blindness
// (OQ-RETAIN-ATTRIBUTE-ENTRYPOINT-BLINDNESS).
//
// Part (a): an ABI/linker retain attribute (`#[no_mangle]` / `#[export_name]` /
// `#[used]`) is a PRODUCTION reachability root — a private `#[no_mangle] fn` is
// reached from the linker, not from `main`, so it must classify Wired, NOT Dead.
// Part (b): an explicit `#[allow(dead_code)]` is the author's "keep this" and
// VETOES the SafeDelete delete-authority gate (downgrade to SuspectedDelete).
//
// The (a)/(b) falsifiers below use ONLY the existing public surface
// (build_from_sources + analyze_and_writeback + classify_dead_action) so they
// COMPILE + FAIL on HEAD (the RED capture). The mask/predicate unit tests and
// the file-surface (c) test reference the new `EntryRetainFlags` API and are
// GREEN-after signals.
// ===========================================================================

/// (a) A private `#[no_mangle] fn` is a linker entry point → Wired, not Dead.
/// RED-on-HEAD: no attr-root seeding → the private fn is call-unreachable → Dead.
#[test]
fn legj_no_mangle_private_fn_is_wired_via_real_extractor() {
    let mut graph = build_from_sources(&[
        (
            "crates/x/src/a.rs",
            "#[no_mangle]\nfn ffi_entry() {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);

    let ffi = node_cloned(&graph, "ffi_entry");
    assert_eq!(
        ffi.visibility, "private",
        "the fixture symbol must be private (no pub-api rescue)"
    );
    assert_eq!(
        ffi.reachability_class,
        ReachabilityClass::Wired,
        "a private #[no_mangle] fn is a production entry-point root → Wired"
    );
}

/// (a′) Edition-2024 `#[unsafe(no_mangle)]` is captured identically (fix #1: the
/// capture unwraps the leading `unsafe(` wrapper). RED-on-HEAD: Dead.
#[test]
fn legj_unsafe_no_mangle_edition2024_is_wired() {
    let mut graph = build_from_sources(&[
        (
            "crates/x/src/a.rs",
            "#[unsafe(no_mangle)]\nfn ffi_entry2() {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);

    let ffi = node_cloned(&graph, "ffi_entry2");
    assert_eq!(
        ffi.reachability_class,
        ReachabilityClass::Wired,
        "#[unsafe(no_mangle)] (edition 2024) is a production entry-point root → Wired"
    );
}

/// (b) A `#[allow(dead_code)]` retain attr VETOES SafeDelete even when the full
/// 4-way otherwise holds → SuspectedDelete. RED-on-HEAD: SafeDelete.
#[test]
fn legj_allow_dead_code_vetoes_safedelete_via_real_extractor() {
    let mut graph = build_from_sources(&[
        (
            "crates/x/src/a.rs",
            "#[allow(dead_code)]\nfn retained() {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);
    // Force the oracle bit the 4-way's conjunct-2 needs (a producer graph cannot
    // synthesize a clippy flag). `retained` is private + call-unreachable → Dead,
    // in the cfg-clean crate `x`: on HEAD the full 4-way holds → SafeDelete.
    flag_dead(&mut graph, "retained");

    let cfg_crates = cfg_touching_crates(&graph); // empty: crate x is cfg-clean
    let retained = node_cloned(&graph, "retained");
    // Anti-green-by-construction: the node passes every one of the 4 conjuncts,
    // so the ONLY thing that can withhold SafeDelete is the Leg-J retain veto.
    assert_four_way_holds(&retained, &cfg_crates);
    assert_eq!(
        classify_dead_action(&graph, &retained, &cfg_crates),
        DeadAction::SuspectedDelete,
        "an #[allow(dead_code)] retain attr must veto SafeDelete → SuspectedDelete"
    );
}

/// (b′) A grouped `#[allow(dead_code, unused)]` is captured too (fix #3: the
/// `allow(...)` arg list is token-scanned for `dead_code`). RED-on-HEAD: SafeDelete.
#[test]
fn legj_grouped_allow_dead_code_vetoes_safedelete() {
    let mut graph = build_from_sources(&[
        (
            "crates/x/src/a.rs",
            "#[allow(dead_code, unused)]\nfn retained2() {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "x", "crates/x/src/a.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);
    flag_dead(&mut graph, "retained2");

    let cfg_crates = cfg_touching_crates(&graph);
    let retained = node_cloned(&graph, "retained2");
    assert_four_way_holds(&retained, &cfg_crates);
    assert_eq!(
        classify_dead_action(&graph, &retained, &cfg_crates),
        DeadAction::SuspectedDelete,
        "a grouped #[allow(dead_code, unused)] must also veto SafeDelete"
    );
}

/// (c) File-surface (the load-bearing part-b consumer): a file whose ONLY Dead
/// symbol carries `#[allow(dead_code)]` is NOT "fully dead". Proves the retain
/// signal flows onto `ClassifiedNode.has_retain_attr` (which ligan's `graph_cmd`
/// reads) and that the `dead == total && !has_retain` fully-dead predicate
/// excludes it. Uses the REAL extractor + analyze(). (References the new
/// `has_retain_attr` field, so it is a GREEN-after signal, not RED-runnable.)
#[test]
fn legj_allow_dead_code_file_not_fully_dead_via_real_extractor() {
    // A single-symbol file, no entry points → the private fn is Dead. It carries
    // `#[allow(dead_code)]`, the author's "keep this".
    let graph = build_from_sources(&[(
        "crates/x/src/lonely.rs",
        "#[allow(dead_code)]\nfn only_symbol() {}\n",
    )]);
    let report = ReachabilityAnalyzer::new(&graph, vec![]).analyze();

    let only = report
        .classified
        .iter()
        .find(|n| n.symbol_name == "only_symbol")
        .expect("only_symbol is classified");
    assert_eq!(
        only.classification,
        ReachabilityClass::Dead,
        "the sole private fn is call-unreachable → Dead"
    );
    assert!(
        only.has_retain_attr,
        "the #[allow(dead_code)] retain attr must flow onto the ClassifiedNode (part-b data)"
    );

    // The ligan fully-dead FILE predicate (graph_cmd): dead == total && !has_retain.
    let file = &only.file_path;
    let file_nodes: Vec<_> = report
        .classified
        .iter()
        .filter(|n| &n.file_path == file)
        .collect();
    let dead = file_nodes
        .iter()
        .filter(|n| n.classification == ReachabilityClass::Dead)
        .count();
    let total = file_nodes.len();
    let has_retain = file_nodes.iter().any(|n| n.has_retain_attr);
    assert_eq!(
        dead, total,
        "every symbol in the file is Dead (all-dead numerator)"
    );
    // The ligan fully-dead FILE label predicate (graph_cmd): dead == total AND
    // no retain attr. The retain attr flips it false → NOT fully-dead.
    let labeled_fully_dead = dead == total && !has_retain;
    assert!(
        !labeled_fully_dead,
        "a file whose only Dead symbol is #[allow(dead_code)] is NOT fully-dead"
    );
}

// ---------------------------------------------------------------------------
// Mechanical unit tests for the EntryRetainFlags bitmask + its two orthogonal
// predicates (the type-level contract the two halves of Leg J depend on).
// ---------------------------------------------------------------------------

/// The four mask bits are distinct + stable, and `from_bits`/`bits`/`contains`
/// round-trip.
#[test]
fn legj_entry_retain_flag_masks() {
    assert_eq!(EntryRetainFlags::NO_MANGLE, 1);
    assert_eq!(EntryRetainFlags::EXPORT_NAME, 2);
    assert_eq!(EntryRetainFlags::USED, 4);
    assert_eq!(EntryRetainFlags::ALLOW_DEAD_CODE, 8);
    assert_eq!(EntryRetainFlags::default().bits(), 0);

    let f = EntryRetainFlags::from_bits(
        EntryRetainFlags::NO_MANGLE | EntryRetainFlags::ALLOW_DEAD_CODE,
    );
    assert_eq!(f.bits(), 1 | 8);
    assert!(f.contains(EntryRetainFlags::NO_MANGLE));
    assert!(f.contains(EntryRetainFlags::ALLOW_DEAD_CODE));
    assert!(!f.contains(EntryRetainFlags::USED));
    // `contains` is ANY-of.
    assert!(f.contains(EntryRetainFlags::NO_MANGLE | EntryRetainFlags::USED));
}

/// `is_entry_point` (NO_MANGLE | EXPORT_NAME | USED) and `has_retain_attr`
/// (ALLOW_DEAD_CODE) are ORTHOGONAL — no bit is read by both. `#[used]` is an
/// entry point ONLY (fix #2: never a retain attr — no double-classification).
#[test]
fn legj_entry_retain_predicates_are_orthogonal() {
    for m in [
        EntryRetainFlags::NO_MANGLE,
        EntryRetainFlags::EXPORT_NAME,
        EntryRetainFlags::USED,
    ] {
        let f = EntryRetainFlags::from_bits(m);
        assert!(f.is_entry_point(), "mask {m} is an entry-point root");
        assert!(
            !f.has_retain_attr(),
            "an entry-point bit ({m}) is NOT a retain attr"
        );
    }

    let retain = EntryRetainFlags::from_bits(EntryRetainFlags::ALLOW_DEAD_CODE);
    assert!(retain.has_retain_attr());
    assert!(
        !retain.is_entry_point(),
        "allow(dead_code) is a retain attr, NOT an entry point"
    );

    let empty = EntryRetainFlags::default();
    assert!(!empty.is_entry_point());
    assert!(!empty.has_retain_attr());
}

// ---------------------------------------------------------------------------
// WU-0016 Leg H — has_uncaptured_items capture-completeness scan (engine side)
// OQ-FILE-TIER-CAPTURE-COMPLETENESS. Companions to the ligan-side
// compute_file_tiers falsifiers/controls in composite_integration.rs: these
// assert the persisted signal FLOWS from the extractor scan onto every
// GraphNode the file produces (build_from_sources → all_nodes).
// ---------------------------------------------------------------------------

/// H-F1 (engine companion): a file holding an item-position `macro_invocation`
/// (`make_gen!{}`) — a construct `node_kind_to_symbol_kind` DROPS — stamps
/// has_uncaptured_items=true on every node it produces. The captured symbols
/// (the macro_definition + the plain fn) are all Dead, but the file is NOT
/// capture-complete, so the ligan tier must withhold `fully_dead`.
#[test]
fn has_uncaptured_items_true_for_item_position_macro_invocation() {
    let graph = build_from_sources(&[(
        "crates/x/src/gen.rs",
        "macro_rules! make_gen { () => { pub fn generated_used() -> u32 { 7 } } }\n\
         make_gen!{}\n\
         fn also_dead() {}\n",
    )]);
    let nodes: Vec<_> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.file_path.ends_with("gen.rs"))
        .collect();
    assert!(!nodes.is_empty(), "gen.rs produced captured nodes");
    assert!(
        nodes.iter().all(|n| n.has_uncaptured_items),
        "an item-position make_gen!{{}} is an uncaptured item → every node in the file is stamped true"
    );
}

/// H-N2 (engine companion / noise-allowlist): a file with ONLY benign non-item
/// extras — a `//!` inner doc comment (line_comment), a `#![allow(dead_code)]`
/// inner attribute (inner_attribute_item), a stray `;` (empty_statement), plus
/// one dead fn — has has_uncaptured_items=false. Without the noise-allowlist a
/// naive default-deny would flag each as uncaptured and false-withhold nearly
/// every documented / lint-annotated file. (`#![allow(dead_code)]` is an INNER
/// attr, distinct from the item-level `#[allow(dead_code)]` retain attr.)
#[test]
fn has_uncaptured_items_false_for_benign_noise_extras() {
    let graph = build_from_sources(&[(
        "crates/x/src/doc.rs",
        "//! module doc\n#![allow(dead_code)]\n;\nfn only_dead() {}\n",
    )]);
    let nodes: Vec<_> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.file_path.ends_with("doc.rs"))
        .collect();
    assert!(!nodes.is_empty(), "doc.rs produced a captured node");
    assert!(
        nodes.iter().all(|n| !n.has_uncaptured_items),
        "doc-comment / inner-attr / empty-stmt extras are NOT uncaptured items"
    );
}

/// H-N5 (engine companion / associated-type over-withhold guard): an all-dead
/// file defining a trait with a bare REQUIRED associated type (`type Item;`)
/// has has_uncaptured_items=false. In tree-sitter-rust a bare `type Item;` (no
/// `= …`) parses as `associated_type`, NOT `type_item` — a structural member of
/// the already-captured `trait_item`, never an independently-emittable item (no
/// E0425 risk on delete). Without `associated_type` in the noise allowlist the
/// default-deny scan would flag it and false-withhold every dead trait-defining
/// module. (Reviewer-caught over-withhold MAJOR, WU-0016 Leg H.)
#[test]
fn has_uncaptured_items_false_for_trait_required_associated_type() {
    let graph = build_from_sources(&[(
        "crates/x/src/store.rs",
        "pub trait Store {\n    type Handle;\n    fn open(&self) -> Self::Handle;\n}\n",
    )]);
    let nodes: Vec<_> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.file_path.ends_with("store.rs"))
        .collect();
    assert!(!nodes.is_empty(), "store.rs produced a captured trait node");
    assert!(
        nodes.iter().all(|n| !n.has_uncaptured_items),
        "a bare required associated type (`type Item;`) is a structural trait member, NOT an uncaptured item"
    );
}

/// H-N3 (engine companion / position-awareness): a file whose sole dead fn's
/// BODY contains an expression-position `macro_invocation` (`println!()`) has
/// has_uncaptured_items=false. The macro_invocation sits in expression position
/// inside a fn block, not item position — an all-descendants walk would count it
/// and catastrophically over-withhold nearly every real file (they almost all
/// carry expression macros). This is the single most load-bearing over-withhold
/// guard.
#[test]
fn has_uncaptured_items_false_for_expression_position_macro() {
    let graph = build_from_sources(&[(
        "crates/x/src/body.rs",
        "fn only_dead() { println!(\"x\"); }\n",
    )]);
    let nodes: Vec<_> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.file_path.ends_with("body.rs"))
        .collect();
    assert!(!nodes.is_empty(), "body.rs produced a captured node");
    assert!(
        nodes.iter().all(|n| !n.has_uncaptured_items),
        "an expression-position println!() is NOT an item-position uncaptured construct"
    );
}

// ===========================================================================
// WU-0016 Leg F — OQ-DELETE-REASON-PROVENANCE: cause-carrying withhold reason.
//   The tool must NAME the actual withhold cause instead of the overloaded
//   "un-indexable (ADR-0035)" const that HEAD printed for EVERY withheld symbol.
// ===========================================================================

use h00ligan_engine::graph_stats::CoverageTier as CT;

/// Pull the (Some) `withhold_reason` out of the WIRED gated single-symbol path.
fn cause_via_gate(graph: &KnowledgeGraph, node: &GraphNode, oracle_ran_ok: bool) -> String {
    let DeadSingleReport::Computed {
        withhold_reason: Some(reason),
        ..
    } = dead_single_gated(graph, node, CT::Sufficient, oracle_ran_ok)
    else {
        panic!("Sufficient tier + dead node must compute a Some(withhold_reason)");
    };
    reason
}

/// A hand-broken node that keeps EVERY 4-way conjunct EXCEPT `class` (Suspected).
fn reachability_broken_node() -> GraphNode {
    dnode(
        "susp_fn",
        "function",
        "crates/x/src/a.rs",
        "private",
        ReachabilityClass::Suspected,
        true,
    )
}
/// A hand-broken node that keeps every conjunct EXCEPT `visibility` (pub) — class
/// stays Dead so visibility is genuinely first-failing (risk note: NOT the
/// producer pub-residual, which downgrades to Suspected → cause #3 instead).
fn visibility_broken_node() -> GraphNode {
    dnode(
        "pub_fn",
        "function",
        "crates/x/src/a.rs",
        "pub",
        ReachabilityClass::Dead,
        true,
    )
}
/// A hand-broken node that keeps every conjunct EXCEPT `crate-cfg` (crate y is in
/// the cfg set the caller passes).
fn cfg_broken_node() -> GraphNode {
    dnode(
        "cfg_fn",
        "function",
        "crates/y/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        true,
    )
}
/// A node that passes all 4 conjuncts but carries a `#[allow(dead_code)]` retain
/// attr — the veto is the only failing gate.
fn retain_broken_node() -> GraphNode {
    let mut n = dnode(
        "kept_fn",
        "function",
        "crates/x/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        true,
    );
    n.entry_retain = EntryRetainFlags::from_bits(EntryRetainFlags::ALLOW_DEAD_CODE);
    n
}

/// F-F1 — the CORE LIE fix. An in-envelope, Dead+private+cfg-clean node that is
/// merely UNCORROBORATED (`!rustc_flagged_dead`, conjunct 2 broken) must yield a
/// withhold_reason naming the UNCORROBORATED cause — NOT the "un-indexable
/// (ADR-0035)" envelope lie. Envelope=Emit + oracle_ran_ok=true so neither
/// downgrade layer fires; the else branch must re-derive conjunct 2 as
/// first-failing.
#[test]
fn f_f1_the_lie_uncorroborated_not_unindexable() {
    let graph = qualifying_graph();
    let mut node = node_cloned(&graph, "dead_fn");
    node.rustc_flagged_dead = false; // in-envelope, uncorroborated

    let DeadSingleReport::Computed {
        withhold_reason: Some(reason),
        action,
        ..
    } = dead_single_gated(&graph, &node, CT::Sufficient, true)
    else {
        panic!("expected a Computed verdict with a withhold_reason");
    };
    assert_eq!(action, Some(DeadAction::SuspectedDelete));
    let lc = reason.to_lowercase();
    assert!(
        lc.contains("oracle") && reason.contains("verify before removing"),
        "must name the uncorroborated cause: {reason}"
    );
    assert!(
        !reason.contains("un-indexable") && !reason.contains("ADR-0035"),
        "must NOT print the envelope lie for an in-envelope uncorroborated node: {reason}"
    );
    // Pure-fn twin: `classify_withhold_cause` yields the SAME string.
    assert_eq!(
        classify_withhold_cause(&graph, &node, &HashSet::new(), true),
        reason,
        "the gated field must equal the pure-fn twin"
    );
}

/// F-F2 — the 7 OTHER disjoint withhold layers each yield their OWN named cause,
/// all mutually distinct (a HashSet of the 7 has len 7). Every fixture breaks
/// EXACTLY ONE conjunct/layer (anti-green-by-construction).
#[test]
fn f_f2_per_conjunct_seven_distinct_named_causes() {
    let empty = HashSet::new();
    let cfg_y: HashSet<String> = HashSet::from(["y".to_string()]);
    let g = KnowledgeGraph::new(); // hand nodes have no edges

    // #3 reachability, #5 visibility, #6 cfg, #7 retain — pure-fn (Emit/true so no
    // downgrade layer masks the conjunct break).
    let r_reach = classify_withhold_cause(&g, &reachability_broken_node(), &empty, true);
    let r_vis = classify_withhold_cause(&g, &visibility_broken_node(), &empty, true);
    let r_cfg = classify_withhold_cause(&g, &cfg_broken_node(), &cfg_y, true);
    let r_ret = classify_withhold_cause(&g, &retain_broken_node(), &empty, true);

    // #8 LEG-D counterpart — a dead trait Tr blocked by its UNFLAGGED impl.
    let mut gd = KnowledgeGraph::new();
    let tr = dnode(
        "Tr",
        "trait",
        "crates/xd/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        true,
    );
    let imp = dnode(
        "impl Tr for S",
        "impl",
        "crates/xd/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        false,
    );
    let (tr_id, imp_id) = (tr.memory_id, imp.memory_id);
    gd.add_node(tr.clone()).unwrap();
    gd.add_node(imp).unwrap();
    gd.add_edge(imp_id, tr_id, edge(EdgeKind::Implements))
        .unwrap();
    let r_legd = classify_withhold_cause(&gd, &tr, &cfg_touching_crates(&gd), true);
    assert!(
        r_legd.contains("impl Tr for S"),
        "LEG-D cause interpolates the blocking counterpart: {r_legd}"
    );

    // Oracle authority is the sole gate-layer downgrade.
    let graph = qualifying_graph();
    let dead = node_cloned(&graph, "dead_fn");
    let r_ora = cause_via_gate(&graph, &dead, false);
    assert!(
        r_ora.to_lowercase().contains("oracle") && r_ora.contains("degraded"),
        "oracle-degraded layer names the degraded build: {r_ora}"
    );

    // Cause-specific substrings (each names its own conjunct).
    assert!(
        r_reach.contains("Suspected/Orphan"),
        "reachability: {r_reach}"
    );
    assert!(r_vis.contains("public"), "visibility: {r_vis}");
    assert!(r_cfg.contains("platform-cfg"), "cfg: {r_cfg}");
    assert!(r_ret.contains("allow(dead_code)"), "retain: {r_ret}");

    let set: HashSet<String> = [r_reach, r_vis, r_cfg, r_ret, r_legd, r_ora]
        .into_iter()
        .collect();
    assert_eq!(set.len(), 6, "6 disjoint causes, all distinct");
}

/// Re-stamp `dead_fn`'s oracle receipt via the real `apply_oracle` path (the
/// qualifying graph's `flag_dead` only sets the bit, not the receipt).
fn qualifying_graph_with_receipt() -> KnowledgeGraph {
    let mut graph = qualifying_graph();
    let line1 = node_cloned(&graph, "dead_fn")
        .line_start
        .expect("dead_fn has a line")
        + 1;
    let diag = DeadDiag {
        file_name: "crates/x/src/a.rs".to_string(),
        line_start: line1, // 1-indexed
        code: "dead_code".to_string(),
        subject: Some("dead_fn".to_string()),
        manifest_path: None,
    };
    apply_oracle(&mut graph, &[diag], dummy_root());
    graph
}

/// F-N2 (negative control) — DEMOTE-safe: no cause string (the 8 withhold causes
/// plus the SafeDelete corroboration reason) carries a delete-authority verb, and
/// every one carries the demote-safe framing. Non-vacuous: iterates a concretely
/// enumerated, non-empty vector of REAL cause strings.
#[test]
fn f_n2_demote_safe_no_delete_authority_verb_in_any_cause() {
    let empty = HashSet::new();
    let cfg_y: HashSet<String> = HashSet::from(["y".to_string()]);
    let g = KnowledgeGraph::new();
    let graph = qualifying_graph();
    let dead = node_cloned(&graph, "dead_fn");
    let mut uncorroborated = dead.clone();
    uncorroborated.rustc_flagged_dead = false;

    // LEG-D graph for cause #8.
    let mut gd = KnowledgeGraph::new();
    let tr = dnode(
        "Tr",
        "trait",
        "crates/xd/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        true,
    );
    let imp = dnode(
        "impl Tr for S",
        "impl",
        "crates/xd/src/a.rs",
        "private",
        ReachabilityClass::Dead,
        false,
    );
    let (tr_id, imp_id) = (tr.memory_id, imp.memory_id);
    gd.add_node(tr.clone()).unwrap();
    gd.add_node(imp).unwrap();
    gd.add_edge(imp_id, tr_id, edge(EdgeKind::Implements))
        .unwrap();

    // The confirmed-DEAD corroboration reason (receipt-backed).
    let rg = qualifying_graph_with_receipt();
    let receipted = node_cloned(&rg, "dead_fn");
    let safe_delete_reason = classify_withhold_cause(&rg, &receipted, &empty, true);

    let causes: Vec<String> = vec![
        cause_via_gate(&graph, &dead, false), // oracle-degraded
        classify_withhold_cause(&g, &reachability_broken_node(), &empty, true),
        classify_withhold_cause(&graph, &uncorroborated, &empty, true),
        classify_withhold_cause(&g, &visibility_broken_node(), &empty, true),
        classify_withhold_cause(&g, &cfg_broken_node(), &cfg_y, true),
        classify_withhold_cause(&g, &retain_broken_node(), &empty, true),
        classify_withhold_cause(&gd, &tr, &cfg_touching_crates(&gd), true),
        safe_delete_reason,
    ];
    assert_eq!(causes.len(), 8, "7 withhold causes + the SafeDelete reason");
    for c in &causes {
        let lc = c.to_lowercase();
        assert!(
            !lc.contains("safe to delete")
                && !lc.contains("deletable")
                && !lc.contains("safe_delete"),
            "no delete-authority verb: {c}"
        );
        assert!(
            lc.contains("verify")
                || lc.contains("review")
                || lc.contains("remov")
                || lc.contains("keep"),
            "demote-safe framing present: {c}"
        );
    }
}

/// F-N3 (negative control) — a genuinely SafeDelete node (receipt stamped by
/// `apply_oracle`) surfaces a reason that NAMES the corroborating conjunct AND the
/// receipt contents (code / line / subject / private / cfg-clean). Proves the
/// receipt is SURFACED at render, not merely stored (distinct from F-F3 storage).
#[test]
fn f_n3_dead_confirmed_reason_surfaces_corroborating_receipt() {
    let graph = qualifying_graph_with_receipt();
    let node = node_cloned(&graph, "dead_fn");
    assert!(node.oracle_receipt.is_some(), "precond: receipt stamped");
    assert_eq!(
        classify_dead_action(&graph, &node, &HashSet::new()),
        DeadAction::SafeDelete,
        "precond: confirmed (SafeDelete) path"
    );
    let reason = classify_withhold_cause(&graph, &node, &HashSet::new(), true);
    let rl = node.oracle_receipt.as_ref().unwrap().line;
    assert!(
        reason.contains("dead_code")
            && reason.contains(&rl.to_string())
            && reason.contains("dead_fn"),
        "names the corroborating receipt (code/line/subject): {reason}"
    );
    assert!(
        reason.contains("private") && reason.contains("cfg-clean"),
        "names the corroborated conjuncts: {reason}"
    );
    assert!(
        !reason.to_lowercase().contains("safe to delete"),
        "demote-safe: {reason}"
    );
}
