//! WU-0022 S1 — the dead-verdict parity contract (PARITY-A … PARITY-J).
//!
//! Pins the REPORTING-vs-GATING split (D3/D4) that unifies the two dead-verdict
//! wrapper stacks onto one decision core: Path A
//! ([`h00ligan_engine::dead_pipeline::compute_dead_tiers`], the `graph reachability`
//! wiring surface) and Path B ([`h00ligan_engine::graph_query::dead_report_gated`], the
//! `dead` command + MCP report). See ADR-0034 L4 (§Decision-2/§Decision-10),
//! ADR-0038 §2 (the compiler-sound coverage-complete DEAD tier), and WU-0016 legs E
//! (`oracle_stale_downgrade_action`) + F (`classify_withhold_cause`).
//!
//! # The contract
//!
//! * **Membership / wiring gate (D2)** — Path A `total()`/`symbol_names()`/
//!   `is_empty()` are RAW `{Dead, Suspected}` population, IMMUNE to every gate
//!   signal (a wiring gate fires on unwired code under any coverage/oracle;
//!   `dead_pipeline` MAJOR-2).
//! * **Reported confidence LABELS (D3/D4)** — Path A's `dead_confirmed` bucket
//!   is computed over the SAME per-symbol downgrade Path B applies
//!   (`downgraded_action` ∘ `classify_dead_action`), so a degraded/absent oracle
//!   (WU-0016 E) strips a raw
//!   `SafeDelete` → `SuspectedDelete` and moves it `dead_confirmed → investigate`
//!   — while membership above is unchanged.
//! * **Coverage carve-out** — `CoverageTier` does NOT alter Path A (neither
//!   membership nor the confidence bucket): Path A never whole-verb-suppresses,
//!   and `dead_confirmed`'s corroborating conjuncts are coverage-independent.
//!
//! Fixtures are built via direct node construction (not `build_from_sources`):
//! this contract exercises the pipeline's bucketing/downgrade over CONTROLLED
//! node states (exact reachability class × the 4 SafeDelete conjuncts × gate
//! signals), which the producer-driven path cannot pin per-conjunct — the
//! reachability CLASSIFIER is exercised by `reachability_contract.rs`, the
//! per-conjunct authority gate by `leg3b_dead_authority.rs`. Same node-builder
//! shape those suites use.

use h00ligan_engine::dead_pipeline::compute_dead_tiers;
use h00ligan_engine::graph::{EdgeKind, GraphEdge, GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_query::{
    DeadAction, DeadReport, GateSignals, cfg_touching_crates, classify_dead_action,
    dead_report_gated,
};
use h00ligan_engine::graph_stats::CoverageTier;
use h00ligan_engine::reachability::ReachabilityClass;
use uuid::Uuid;

// ── shared builders ─────────────────────────────────────────────────────────

fn mk_node(
    id: u128,
    name: &str,
    file_path: &str,
    class: ReachabilityClass,
    visibility: &str,
    rustc_flagged_dead: bool,
) -> GraphNode {
    GraphNode {
        memory_id: Uuid::from_u128(id),
        symbol_name: name.to_string(),
        kind: "function".to_string(),
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

fn calls_edge() -> GraphEdge {
    GraphEdge {
        kind: EdgeKind::Calls,
        ..GraphEdge::default()
    }
}

const fn signals(tier: CoverageTier, oracle_ran_ok: bool) -> GateSignals {
    GateSignals {
        tier,
        oracle_ran_ok,
        // DEC-R8a (WU-0023 P3b): Path A (compute_dead_tiers) IGNORES this axis
        // (raw-membership gate — LEAK-3), so `true` keeps these parity pins
        // byte-identical.
        reachability_classified: true,
    }
}

const fn healthy() -> GateSignals {
    signals(CoverageTier::Sufficient, true)
}

/// The action Path B ([`dead_report_gated`]) reports for `name`, or `None` if the
/// report was whole-verb-suppressed / the symbol is absent.
fn path_b_action(report: &DeadReport, name: &str) -> Option<DeadAction> {
    match report {
        DeadReport::Full(data) => data
            .entries
            .iter()
            .find(|e| e.symbol_name == name)
            .map(|e| e.action.clone()),
        DeadReport::Unknown => None,
    }
}

/// Whether Path B's report contains an entry named `name`.
fn path_b_contains(report: &DeadReport, name: &str) -> bool {
    matches!(report, DeadReport::Full(data) if data.entries.iter().any(|e| e.symbol_name == name))
}

/// A one-node graph carrying the full `SafeDelete` conjunction (private +
/// rustc-flagged + cfg-clean + `Dead`), parameterised on `rustc_flagged` so a
/// negative-control sibling can break conjunct 2.
fn one_safe_delete_graph(name: &str, rustc_flagged: bool) -> KnowledgeGraph {
    let mut graph = KnowledgeGraph::new();
    graph
        .add_node(mk_node(
            1,
            name,
            "crates/x/src/a.rs",
            ReachabilityClass::Dead,
            "private",
            rustc_flagged,
        ))
        .unwrap();
    graph
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-A — healthy-regime agreement anchor (parity_pin_green_on_head)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wu0022_parity_a_healthy_regime_agreement_anchor() {
    let mut graph = KnowledgeGraph::new();
    // n1: private + rustc-flagged + cfg-clean Dead → SafeDelete.
    graph
        .add_node(mk_node(
            1,
            "n1_safe",
            "crates/x/src/a.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        ))
        .unwrap();
    // n2: pub Dead + rustc-flagged → SuspectedDelete (fails the visibility conjunct).
    graph
        .add_node(mk_node(
            2,
            "n2_pub",
            "crates/x/src/b.rs",
            ReachabilityClass::Dead,
            "pub",
            true,
        ))
        .unwrap();
    // n3: private Suspected → SuspectedDelete (fails the reachability conjunct).
    graph
        .add_node(mk_node(
            3,
            "n3_susp",
            "crates/x/src/c.rs",
            ReachabilityClass::Suspected,
            "private",
            false,
        ))
        .unwrap();
    // n4: private Dead with an alive Wired caller → NeedsReview.
    graph
        .add_node(mk_node(
            4,
            "n4_needs",
            "crates/x/src/d.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        ))
        .unwrap();
    graph
        .add_node(mk_node(
            10,
            "alive",
            "crates/x/src/alive.rs",
            ReachabilityClass::Wired,
            "pub",
            false,
        ))
        .unwrap();
    graph
        .add_edge(Uuid::from_u128(10), Uuid::from_u128(4), calls_edge())
        .unwrap();
    // n5: private Dead under a `tests/` path → TestOnly (path_under_test_dir).
    graph
        .add_node(mk_node(
            5,
            "n5_test",
            "crates/x/tests/only.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        ))
        .unwrap();

    let tiers = compute_dead_tiers(&graph, healthy());

    // Path A — the 3-bucket projection over the 5 verdicts.
    assert_eq!(
        tiers.action_tiers_json(),
        serde_json::json!({
            "dead_confirmed": { "files": 1, "symbols": 1 },
            "investigate":    { "files": 3, "symbols": 3 },
            "test_only":      { "files": 1, "symbols": 1 },
        }),
        "PARITY-A: healthy-regime action_tiers projection"
    );
    // Path A — the canonical 4-tally (store breakdown).
    assert_eq!(
        tiers.store_tier_breakdown(),
        serde_json::json!({
            "dead_confirmed": 1,
            "suspected": 2,
            "needs_review": 1,
            "test_only": 1,
        }),
        "PARITY-A: healthy-regime store breakdown"
    );
    // Non-vacuity: all three buckets non-empty (an accidental collapse/key-drop
    // is detectable).
    assert!(tiers.dead_confirmed().symbols >= 1);
    assert!(tiers.investigate().symbols >= 1);
    assert!(tiers.test_only().symbols >= 1);
    assert_eq!(tiers.total(), 5, "all five nodes are broad-set members");

    // Path B — the canonical 4-tally agrees (no Orphan here, so exact match modulo
    // the D1 population split; PARITY-E pins the Orphan divergence).
    let DeadReport::Full(data) = dead_report_gated(&graph, CoverageTier::Sufficient, true) else {
        panic!("PARITY-A: Path B must EMIT under healthy signals");
    };
    let counts = data.counts();
    assert_eq!(counts.safe_delete, 1);
    assert_eq!(counts.suspected_delete, 2);
    assert_eq!(counts.needs_review, 1);
    assert_eq!(counts.test_only, 1);
    // Per-node verdict lands in exactly its intended bucket on BOTH paths.
    assert_eq!(
        path_b_action(&DeadReport::Full(data), "n1_safe"),
        Some(DeadAction::SafeDelete)
    );
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-B — low-coverage designed divergence (parity_pin_green_on_head)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wu0022_parity_b_low_coverage_designed_divergence() {
    let mut graph = KnowledgeGraph::new();
    graph
        .add_node(mk_node(
            1,
            "raw_safe",
            "crates/x/src/a.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        ))
        .unwrap();
    graph
        .add_node(mk_node(
            2,
            "susp",
            "crates/x/src/b.rs",
            ReachabilityClass::Suspected,
            "private",
            false,
        ))
        .unwrap();

    // (a) Path A with Calls unavailable: the --fail-on-dead gate FIRES (total>0) and the
    // oracle-corroborated dead_confirmed bucket is NOT stripped — CoverageTier does
    // not touch Path A.
    let tiers_none = compute_dead_tiers(&graph, signals(CoverageTier::Unavailable, true));
    assert!(
        tiers_none.total() > 0,
        "PARITY-B: Path A gate fires under None"
    );
    assert!(
        tiers_none.dead_confirmed().symbols >= 1,
        "PARITY-B: CoverageTier does NOT strip the corroborated dead_confirmed bucket"
    );
    // Byte-stable vs tier=Sufficient (Path A ignores tier by contract).
    let tiers_suff = compute_dead_tiers(&graph, healthy());
    assert_eq!(
        tiers_none.action_tiers_json(),
        tiers_suff.action_tiers_json(),
        "PARITY-B: Path A output is byte-stable across coverage tiers"
    );
    assert_eq!(
        tiers_none.store_tier_breakdown(),
        tiers_suff.store_tier_breakdown()
    );

    // (b) Path B with Calls unavailable: the WHOLE verb is suppressed to Unknown.
    assert!(
        matches!(
            dead_report_gated(&graph, CoverageTier::Unavailable, true,),
            DeadReport::Unknown
        ),
        "PARITY-B: Path B whole-verb-suppresses under None"
    );
    // Non-vacuity: the SAME graph under tier=Sufficient yields a real Full report
    // with entries — so None→Unknown is a genuine suppression delta, not an
    // empty-graph artifact.
    let DeadReport::Full(data) = dead_report_gated(&graph, CoverageTier::Sufficient, true) else {
        panic!("PARITY-B: Path B EMITs under Sufficient");
    };
    assert!(
        !data.entries.is_empty(),
        "PARITY-B: the suppression is a real delta"
    );
}

// PARITY-C — the SafeDelete conjunction is non-vacuous.
#[test]
fn wu0022_parity_c_safe_delete_conjunction_keeps_dead_confirmed() {
    let graph = one_safe_delete_graph("raw_safe", true);

    let emit = compute_dead_tiers(&graph, healthy());
    assert_eq!(
        emit.dead_confirmed().symbols,
        1,
        "PARITY-C: a fully corroborated symbol stays dead-confirmed"
    );
    assert_eq!(emit.investigate().symbols, 0);

    // Own non-vacuity: the SafeDelete membership under Emit is REAL — flip
    // conjunct 2 (rustc_flagged=false) and it drops to investigate, proving the
    // conjunction is exercised (not accidentally-confirmed).
    let no_flag = compute_dead_tiers(&one_safe_delete_graph("raw_safe", false), healthy());
    assert_eq!(
        no_flag.dead_confirmed().symbols,
        0,
        "PARITY-C: breaking the rustc conjunct drops it from dead-confirmed"
    );
    assert_eq!(no_flag.investigate().symbols, 1);
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-D — degraded oracle strips dead_confirmed (falsifier_red_on_head)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wu0022_parity_d_degraded_oracle_strips_dead_confirmed() {
    let graph = one_safe_delete_graph("raw_safe", true);

    // oracle_ran_ok=false (degraded/absent clippy pass, WU-0016 E) strips SafeDelete.
    let tiers = compute_dead_tiers(&graph, signals(CoverageTier::Sufficient, false));
    assert_eq!(
        tiers.dead_confirmed().symbols,
        0,
        "PARITY-D: a degraded oracle strips the dead_confirmed LABEL"
    );
    assert_eq!(tiers.investigate().symbols, 1);
    assert_eq!(tiers.dead_confirmed_count(), 0);
    assert_eq!(tiers.suspected_count(), 1);
    assert_eq!(
        tiers.total(),
        1,
        "PARITY-D: RAW membership unchanged under !oracle_ran_ok"
    );

    // Cross-path: Path A verdict == Path B DeadEntry.action.
    let report_b = dead_report_gated(&graph, CoverageTier::Sufficient, false);
    assert_eq!(
        path_b_action(&report_b, "raw_safe"),
        Some(DeadAction::SuspectedDelete),
        "PARITY-D: Path B also downgrades on a degraded oracle"
    );

    // total() identical across oracle true/false.
    let total_ok = compute_dead_tiers(&graph, healthy()).total();
    assert_eq!(
        total_ok,
        tiers.total(),
        "PARITY-D: membership is oracle-immune"
    );
}

// PARITY-D-NC — authoritative oracle keeps dead_confirmed (negative_control)
#[test]
fn wu0022_parity_d_nc_authoritative_oracle_keeps_dead_confirmed() {
    let graph = one_safe_delete_graph("raw_safe", true);

    let ok = compute_dead_tiers(&graph, healthy());
    assert_eq!(
        ok.dead_confirmed().symbols,
        1,
        "PARITY-D-NC: authoritative oracle keeps dead_confirmed"
    );
    assert_eq!(ok.investigate().symbols, 0);

    let degraded = compute_dead_tiers(&graph, signals(CoverageTier::Sufficient, false));
    // Delta true→1 vs false→0 isolates oracle_stale_downgrade_action.
    assert_eq!(ok.dead_confirmed().symbols, 1);
    assert_eq!(degraded.dead_confirmed().symbols, 0);
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-E — Orphan population pin (parity_pin_green_on_head, D1)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wu0022_parity_e_orphan_population_pin() {
    let mut graph = KnowledgeGraph::new();
    // o1: a private Orphan-class node.
    graph
        .add_node(mk_node(
            1,
            "o1_orphan",
            "crates/x/src/orphan.rs",
            ReachabilityClass::Orphan,
            "private",
            true,
        ))
        .unwrap();
    // d1: a private + rustc-flagged + cfg-clean Dead node.
    graph
        .add_node(mk_node(
            2,
            "d1_dead",
            "crates/x/src/dead.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        ))
        .unwrap();

    // Path A population = {Dead, Suspected}: Orphan EXCLUDED (gated separately via
    // --fail-on-orphan).
    let tiers = compute_dead_tiers(&graph, healthy());
    assert_eq!(tiers.total(), 1, "PARITY-E: Path A excludes the Orphan");
    assert_eq!(tiers.symbol_names(), vec!["d1_dead".to_string()]);

    // Path B population = {Dead, Orphan, Suspected}: Orphan INCLUDED, as a
    // SuspectedDelete (Orphan fails the Dead-class conjunct → never dead_confirmed).
    let report_b = dead_report_gated(&graph, CoverageTier::Sufficient, true);
    assert!(
        path_b_contains(&report_b, "o1_orphan"),
        "PARITY-E: Path B INCLUDES the Orphan (non-vacuous — it would surface if the filter were wrong)"
    );
    assert!(
        !tiers.symbol_names().contains(&"o1_orphan".to_string()),
        "PARITY-E: the two populations legitimately differ"
    );
    assert_eq!(
        path_b_action(&report_b, "o1_orphan"),
        Some(DeadAction::SuspectedDelete),
        "PARITY-E: the Orphan is never dead_confirmed in Path B either"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-F — NeedsReview bucketing (parity_pin_green_on_head)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wu0022_parity_f_needs_review_bucketing() {
    let mut graph = KnowledgeGraph::new();
    // A private Dead node with an alive (Wired) dependent via an incoming Calls
    // edge → NeedsReview.
    graph
        .add_node(mk_node(
            1,
            "dead_fn",
            "crates/x/src/f.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        ))
        .unwrap();
    graph
        .add_node(mk_node(
            2,
            "alive_fn",
            "crates/x/src/g.rs",
            ReachabilityClass::Wired,
            "pub",
            false,
        ))
        .unwrap();
    graph
        .add_edge(Uuid::from_u128(2), Uuid::from_u128(1), calls_edge())
        .unwrap();

    let tiers = compute_dead_tiers(&graph, healthy());
    // NeedsReview folds into investigate but is a distinct 4-tally row.
    assert_eq!(tiers.needs_review_count(), 1);
    assert_eq!(tiers.investigate().symbols, 1);
    assert_eq!(tiers.dead_confirmed_count(), 0);
    assert_eq!(tiers.test_only_count(), 0);

    // Path B agrees: DeadEntry.action == NeedsReview.
    let report_b = dead_report_gated(&graph, CoverageTier::Sufficient, true);
    assert_eq!(
        path_b_action(&report_b, "dead_fn"),
        Some(DeadAction::NeedsReview)
    );

    // Non-vacuity: remove the alive dependent → the node flips to dead_confirmed,
    // proving the alive-dependent edge is what produced NeedsReview.
    let mut lone = KnowledgeGraph::new();
    lone.add_node(mk_node(
        1,
        "dead_fn",
        "crates/x/src/f.rs",
        ReachabilityClass::Dead,
        "private",
        true,
    ))
    .unwrap();
    let lone_tiers = compute_dead_tiers(&lone, healthy());
    assert_eq!(
        lone_tiers.dead_confirmed_count(),
        1,
        "PARITY-F: without the alive dependent the node is dead_confirmed"
    );
    assert_eq!(lone_tiers.needs_review_count(), 0);
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-G — Suspected: same verdict, different label (parity_pin_green_on_head)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wu0022_parity_g_suspected_same_verdict_different_label() {
    let mut graph = KnowledgeGraph::new();
    graph
        .add_node(mk_node(
            1,
            "susp_fn",
            "crates/x/src/b.rs",
            ReachabilityClass::Suspected,
            "private",
            false,
        ))
        .unwrap();

    // Underlying verdict is SuspectedDelete on BOTH the raw core and Path B…
    let node = graph.node(&Uuid::from_u128(1)).unwrap();
    let cfg_crates = cfg_touching_crates(&graph);
    assert_eq!(
        classify_dead_action(&graph, node, &cfg_crates),
        DeadAction::SuspectedDelete,
        "PARITY-G: the raw core verdict is SuspectedDelete"
    );
    let report_b = dead_report_gated(&graph, CoverageTier::Sufficient, true);
    assert_eq!(
        path_b_action(&report_b, "susp_fn"),
        Some(DeadAction::SuspectedDelete)
    );

    // …while Path A LABELS it investigate (the 3-bucket projection of the tally).
    let tiers = compute_dead_tiers(&graph, healthy());
    assert_eq!(tiers.investigate().symbols, 1);
    assert_eq!(tiers.suspected_count(), 1);
    assert_eq!(tiers.dead_confirmed().symbols, 0);
    assert_eq!(tiers.action_tiers_json()["investigate"]["symbols"], 1);
    assert_eq!(tiers.action_tiers_json()["dead_confirmed"]["symbols"], 0);
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-H — generated-glue exclusion by construction (parity_pin_green_on_head)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wu0022_parity_h_generated_glue_exclusion_by_construction() {
    // g1 would be SafeDelete but for its OUT_DIR path; r1 is a real dead symbol.
    let build = |glue_path: &str| {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(mk_node(
                1,
                "g1_glue",
                glue_path,
                ReachabilityClass::Dead,
                "private",
                true,
            ))
            .unwrap();
        graph
            .add_node(mk_node(
                2,
                "r1_real",
                "crates/x/src/a.rs",
                ReachabilityClass::Dead,
                "private",
                true,
            ))
            .unwrap();
        graph
    };

    let excluded = build("target/debug/build/pkg-abc/out/glue.rs");
    let tiers = compute_dead_tiers(&excluded, healthy());
    assert_eq!(
        tiers.total(),
        1,
        "PARITY-H: Path A excludes the OUT_DIR glue"
    );
    assert_eq!(tiers.symbol_names(), vec!["r1_real".to_string()]);

    let report_b = dead_report_gated(&excluded, CoverageTier::Sufficient, true);
    assert!(path_b_contains(&report_b, "r1_real"));
    assert!(
        !path_b_contains(&report_b, "g1_glue"),
        "PARITY-H: Path B excludes the OUT_DIR glue via the SAME is_generated_target_path"
    );

    // Non-vacuity: the SAME node relocated to a real src/ path WOULD be
    // dead_confirmed in BOTH surfaces — proving the exclusion (not another conjunct
    // failure) removed it, from BOTH paths identically.
    let relocated = build("crates/x/src/g.rs");
    let tiers2 = compute_dead_tiers(&relocated, healthy());
    assert_eq!(
        tiers2.total(),
        2,
        "PARITY-H: relocated glue is a real member"
    );
    assert_eq!(tiers2.dead_confirmed_count(), 2);
    let report_b2 = dead_report_gated(&relocated, CoverageTier::Sufficient, true);
    assert!(path_b_contains(&report_b2, "g1_glue"));
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-I — assess-is-coarser scope guard (parity_pin_green_on_head)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn wu0022_parity_i_assess_is_coarser_scope_guard() {
    // The suppress policy the assess/inspect/tests gates consume (`tier_suppresses`)
    // is UNCHANGED by the WU-0022 dead-pipeline consolidation.
    assert!(
        h00ligan_engine::graph_query::tier_suppresses(CoverageTier::Unavailable),
        "PARITY-I: assess/inspect/tests still suppress under None"
    );
    assert!(
        !h00ligan_engine::graph_query::tier_suppresses(CoverageTier::Sufficient),
        "PARITY-I: Sufficient does not suppress"
    );

    // Independence: on the SAME graph with Calls unavailable, Path B
    // whole-verb-suppresses (Unknown) while Path A does NOT (dead_confirmed stays
    // populated; --fail-on-dead still fires). The two surfaces are not coupled.
    let graph = one_safe_delete_graph("raw_safe", true);
    assert!(
        matches!(
            dead_report_gated(&graph, CoverageTier::Unavailable, true,),
            DeadReport::Unknown
        ),
        "PARITY-I: Path B suppresses under None"
    );
    let tiers_none = compute_dead_tiers(&graph, signals(CoverageTier::Unavailable, true));
    assert!(
        tiers_none.dead_confirmed().symbols >= 1 && tiers_none.total() >= 1,
        "PARITY-I: Path A does NOT suppress under None (independent, coarser assess surface)"
    );
    // And Path A is byte-stable across None/Sufficient (the consolidated
    // tier_suppresses site never reaches Path A).
    assert_eq!(
        tiers_none.action_tiers_json(),
        compute_dead_tiers(&graph, healthy()).action_tiers_json()
    );
}

// ════════════════════════════════════════════════════════════════════════════
// PARITY-J — CLI==MCP byte-identical regression lock (parity_pin_green_on_head)
// ════════════════════════════════════════════════════════════════════════════
//
// Cross-crate home note: h00ligan-engine cannot reach the h00ligan/h00ligan-interface render
// wrappers, so the true byte-level CLI==MCP JSON lock lives in the existing
// `composite_consistency.rs` (out of the WU-0022 fence, unchanged). This engine
// fixture locks the GUARANTEE that makes CLI==MCP hold: (1) the ONE shared
// `GateSignals::derive` loader is deterministic, so both surfaces feeding it the
// SAME raw bits get identical signals; (2) `dead_report_gated` — the shared core
// both wrappers render — is deterministic over those signals. Same signals →
// same report → byte-identical CLI/MCP.

#[test]
fn wu0022_parity_j_cli_mcp_byte_identical_regression_lock() {
    let mut graph = KnowledgeGraph::new();
    graph
        .add_node(mk_node(
            1,
            "safe",
            "crates/x/src/a.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        ))
        .unwrap();
    graph
        .add_node(mk_node(
            2,
            "susp",
            "crates/x/src/b.rs",
            ReachabilityClass::Suspected,
            "private",
            false,
        ))
        .unwrap();
    graph
        .add_node(mk_node(
            3,
            "needs",
            "crates/x/src/c.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        ))
        .unwrap();
    graph
        .add_node(mk_node(
            4,
            "alive",
            "crates/x/src/d.rs",
            ReachabilityClass::Wired,
            "pub",
            false,
        ))
        .unwrap();
    graph
        .add_edge(Uuid::from_u128(4), Uuid::from_u128(3), calls_edge())
        .unwrap();

    // A corroborated state, sourced through the unified loader. Both
    // surfaces build their GateSignals via THIS same call, so identical raw bits →
    // identical signals.
    let cov = h00ligan_engine::graph_stats::call_edge_coverage(&graph, true);
    let s1 = GateSignals::derive(&cov, Some(true));
    let s2 = GateSignals::derive(&cov, Some(true));
    assert_eq!(s1, s2, "PARITY-J: the shared loader is deterministic");

    // The shared core both wrappers render is byte-identical across two runs with
    // the SAME signals (a non-empty report).
    let render = |sig: GateSignals| {
        let DeadReport::Full(data) = dead_report_gated(&graph, sig.tier, sig.oracle_ran_ok) else {
            panic!("PARITY-J: expected a Full report");
        };
        assert!(
            !data.entries.is_empty(),
            "PARITY-J: report must be non-empty"
        );
        // Serialise the load-bearing per-symbol content (action + cause + name) —
        // the bytes the CLI + MCP renderers both project.
        let mut rows: Vec<String> = data
            .entries
            .iter()
            .map(|e| format!("{}|{:?}|{}", e.symbol_name, e.action, e.withhold_reason))
            .collect();
        rows.sort();
        rows.join("\n")
    };
    assert_eq!(
        render(s1),
        render(s2),
        "PARITY-J: CLI==MCP shared-core bytes are identical"
    );

    // Prove the lock BITES: source the oracle differently (Some(false)) and the
    // rendered content DIVERGES — so a real D7 signal-sourcing regression between
    // the surfaces would be caught by the byte-identical assertion.
    let s_emit_ok = GateSignals::derive(&cov, Some(true));
    let s_emit_degraded = GateSignals::derive(&cov, Some(false));
    assert_ne!(
        render(s_emit_ok),
        render(s_emit_degraded),
        "PARITY-J: differing oracle sourcing DIVERGES the report — the lock bites"
    );
}
