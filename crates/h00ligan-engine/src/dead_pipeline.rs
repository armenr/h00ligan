//! The `graph reachability` tiered production-unreachable (DEAD ∪ SUSPECTED)
//! projection — Path A of the WU-0022 S1 unified dead-verdict pipeline.
//!
//! HOISTED into `h00ligan-engine` (from `h00ligan/src/reachability_tiers.rs`) so it
//! shares ONE decision core + ONE downgrade application site with the `dead`
//! command / MCP report (Path B, [`crate::graph_query::dead_report_gated`]).
//! `h00ligan` keeps only the rendering; the classification + tiering lives here.
//!
//! WHAT THIS IS: a PROJECTION over the same per-symbol verdict Path B computes.
//! Every wiring surface of `graph reachability` (the `action_tiers` JSON block,
//! the default table's ACTION SUMMARY, the `--fail-on-dead` exit,
//! `--save-baseline`/`--diff`, and `--store`) is driven off this single source —
//! the broad non-live set `class ∈ {Dead, Suspected}` (generated `OUT_DIR` glue
//! excluded), bucketed by the shared engine oracle [`classify_dead_action`] AFTER
//! the shared per-symbol downgrade [`downgraded_action`].
//!
//! # WU-0022 S1 — the REPORTING-vs-GATING split (D3/D4)
//!
//! This module presents TWO distinct products that WU-0022 governs separately:
//!
//! 1. **The wiring gate / membership (RAW, signal-IMMUNE, byte-stable).**
//!    [`DeadTiers::total`], [`DeadTiers::is_empty`], [`DeadTiers::symbol_names`]
//!    — the RAW `{Dead, Suspected}` population count/names the `--fail-on-dead`
//!    exit, `--save-baseline`/`--diff`, and `--store` gate on. These are IMMUNE
//!    to [`CoverageTier`](crate::graph_stats::CoverageTier) or
//!    `oracle_ran_ok`: a wiring gate exists to fire on IMPL-not-WIRED code
//!    (MAJOR-2 below), so shrinking/suppressing it under degraded signals would
//!    let genuinely-unwired code silently PASS the check — the exact damaging
//!    mode ADR-0034 (poisoned-Dead-set) + ADR-0035 (ATTACK-1 fig-leaf) forbid.
//!    Over-reporting unwired-ness under degraded signals is the SAFE direction
//!    for a gate.
//!
//! 2. **The reported confidence LABELS (downgraded under `GateSignals`).**
//!    The `dead_confirmed` bucket ([`DeadTiers::dead_confirmed`],
//!    [`DeadTiers::dead_confirmed_count`], the `action_tiers`/`store`/`fail`
//!    projections) makes a POSITIVE SafeDelete-grade confidence claim, so its
//!    per-symbol action is the SAME downgraded action Path B computes
//!    ([`downgraded_action`]∘[`classify_dead_action`]). When `!oracle_ran_ok`, a
//!    would-be-`dead_confirmed` (SafeDelete)
//!    member is relabelled `SuspectedDelete` and moves `dead_confirmed →
//!    investigate` — while its RAW membership above is unchanged.
//!
//! ## Why `CoverageTier` does NOT touch this surface (the carve-out)
//!
//! Path A NEVER whole-verb-suppresses (unlike the `dead` command). `dead_confirmed`
//! is not the raw reachability-Dead set — it is the ORACLE-CORROBORATED subset,
//! whose corroborating conjuncts (rustc-flagged + private + cfg-clean) are
//! COVERAGE-INDEPENDENT (the compiler compiled the crate and saw real intra-crate
//! calls). It is the ADR-0038 §2 "compiler speaking on the tier where it is
//! complete" tier — coverage-robust by construction. Its ONE residual failure mode
//! is a STALE oracle bit, which `oracle_ran_ok`/[`downgraded_action`] handles. So
//! Path A's honesty comes from the coverage-independent oracle-stale signal;
//! adding coverage suppression here would break the
//! wiring gate AND over-suppress a compiler-sound tier (the ADR-0034
//! over-suppression-is-also-a-lie error, in the wiring direction). Hence
//! [`compute_dead_tiers`] consumes [`GateSignals`] but IGNORES its `tier` field.
//!
//! ## MAJOR-2 (widen, not narrow)
//!
//! The membership computation mirrors [`crate::graph_query::dead_report_gated`]'s
//! *enumeration* (raw `graph.all_nodes()`, the same `class ∈ {Dead, Suspected}`
//! filter, the same generated-glue exclusion, `cfg_touching_crates` computed ONCE)
//! but never short-circuits to `Unknown` under low coverage — the wiring gates
//! fire on the RAW membership so a low-SCIP repo cannot silently PASS a
//! `--fail-on-dead` check. Orphan is intentionally NOT in this set (D1): it is
//! gated separately by `--fail-on-orphan`, so Path A's population `{Dead,
//! Suspected}` legitimately differs from Path B's `{Dead, Orphan, Suspected}`.

use std::collections::HashSet;

use crate::graph::KnowledgeGraph;
use crate::graph_query::{
    DeadAction, GateSignals, cfg_touching_crates, classify_dead_action, downgraded_action,
    is_generated_target_path,
};
use crate::reachability::ReachabilityClass;

/// One production-unreachable symbol tagged with its honest cleanup tier.
#[derive(Debug, Clone)]
pub struct TieredSymbol {
    /// Fully-qualified symbol name.
    pub symbol_name: String,
    /// Source file path as stored on the node.
    pub file_path: String,
    /// The broad-set class that put it here (`Dead` or `Suspected`).
    pub reachability: ReachabilityClass,
    /// The shared [`classify_dead_action`] tier AFTER the per-symbol
    /// [`downgraded_action`] (oracle-stale). Under healthy signals this
    /// equals the raw classify verdict; under degraded signals a raw `SafeDelete`
    /// is stripped to `SuspectedDelete` here (the D3/D4 REPORTING downgrade).
    pub action: DeadAction,
}

/// A `{files, symbols}` count pair for one human-facing tier group.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TierGroup {
    /// Distinct source files contributing symbols to this group.
    pub files: usize,
    /// Symbols in this group.
    pub symbols: usize,
}

/// The tiered breakdown of the broad production-unreachable set — the single
/// source of truth for every `graph reachability` wiring surface (Path A).
#[derive(Debug, Clone, Default)]
pub struct DeadTiers {
    symbols: Vec<TieredSymbol>,
}

/// Compute the tiered production-unreachable set from a freshly-classified graph
/// (WU-0022 S1, Path A).
///
/// The graph must already carry reachability classes (i.e. after
/// [`crate::reachability::classify_and_writeback`]). Each member's `action` is the
/// shared per-symbol verdict [`downgraded_action`]∘[`classify_dead_action`], so the
/// reported confidence LABELS honour the ADR-0035/WU-0016-E downgrades while the
/// RAW membership ([`DeadTiers::total`]/[`DeadTiers::symbol_names`]) stays for the
/// `--fail-on-dead` exit. `signals.tier` is IGNORED by contract (the MAJOR-2
/// no-coverage-gate carve-out — see the module docs).
#[must_use]
pub fn compute_dead_tiers(graph: &KnowledgeGraph, signals: GateSignals) -> DeadTiers {
    // O(n^2) guard: compute the cfg-touching-crate set ONCE (`cfg_touching_crates`
    // is O(all_nodes)) and thread it into every per-node `classify_dead_action`.
    let cfg_crates = cfg_touching_crates(graph);
    let mut symbols: Vec<TieredSymbol> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| {
            matches!(
                n.reachability_class,
                ReachabilityClass::Dead | ReachabilityClass::Suspected
            ) && !is_generated_target_path(&n.file_path)
        })
        .map(|n| TieredSymbol {
            symbol_name: n.symbol_name.clone(),
            file_path: n.file_path.clone(),
            reachability: n.reachability_class,
            // WU-0022 S1: the SHARED per-symbol downgrade — Path A applies the
            // SAME oracle-stale strip Path B does, at the single
            // `downgraded_action` application site. RAW membership (below) is
            // unaffected: the downgrade only re-buckets, never drops a member.
            action: downgraded_action(classify_dead_action(graph, n, &cfg_crates), signals),
        })
        .collect();
    // Deterministic order for stable output + baselines.
    symbols.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.symbol_name.cmp(&b.symbol_name))
    });
    DeadTiers { symbols }
}

impl DeadTiers {
    // ── RAW wiring-gate accessors (D2) — signal-IMMUNE membership ─────────────
    // total()/is_empty()/symbol_names() are the EXPLICITLY-NAMED raw wiring-gate
    // accessors: they report the broad `{Dead, Suspected}` POPULATION, which the
    // per-symbol downgrade never shrinks (it only re-buckets `action`). The
    // `--fail-on-dead` exit, `--save-baseline`/`--diff`, and `--store` gate on
    // these — immune to CoverageTier / oracle_ran_ok
    // (MAJOR-2). See the module docs.

    /// RAW broad-set membership (the count the `--fail-on-dead` exit gates on).
    /// Signal-IMMUNE — the downgrade re-buckets labels, never drops a member.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the RAW broad set is empty (signal-IMMUNE — see [`Self::total`]).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// The RAW broad membership symbol names (for `--save-baseline` + `--store` +
    /// `--diff`). Signal-IMMUNE — see [`Self::total`].
    #[must_use]
    pub fn symbol_names(&self) -> Vec<String> {
        self.symbols.iter().map(|s| s.symbol_name.clone()).collect()
    }

    // ── Reported-confidence LABEL projections (D3/D4) — over the DOWNGRADED
    // action. A raw SafeDelete stripped to SuspectedDelete under degraded signals
    // moves dead_confirmed → investigate here, NEVER changing membership above. ─

    fn group<F: Fn(&DeadAction) -> bool>(&self, pred: F) -> TierGroup {
        let mut files: HashSet<&str> = HashSet::new();
        let mut symbols = 0usize;
        for s in &self.symbols {
            if pred(&s.action) {
                symbols += 1;
                files.insert(s.file_path.as_str());
            }
        }
        TierGroup {
            files: files.len(),
            symbols,
        }
    }

    /// `dead_confirmed` group — the 4-way `SafeDelete` conjunction (private +
    /// rustc-flagged + cfg-clean + `Dead`) that SURVIVED the per-symbol downgrade.
    /// A `pub` symbol never lands here (fails `visibility_is_deletable`); a
    /// `Suspected`-class symbol never lands here (fails conjunct 1); and under
    /// `!oracle_ran_ok` NO symbol lands here (all
    /// stripped to `SuspectedDelete` → investigate).
    #[must_use]
    pub fn dead_confirmed(&self) -> TierGroup {
        self.group(|a| matches!(a, DeadAction::SafeDelete))
    }

    /// `investigate` group — suspected-delete or has-alive-dependent
    /// (`SuspectedDelete` ∪ `NeedsReview`): needs human judgement before removal.
    /// Absorbs every symbol the downgrade stripped from `dead_confirmed`.
    #[must_use]
    pub fn investigate(&self) -> TierGroup {
        self.group(|a| matches!(a, DeadAction::SuspectedDelete | DeadAction::NeedsReview))
    }

    /// `test_only` group — the action oracle found only test-code dependents.
    /// Byte-stable under all `GateSignals` (TestOnly is never a downgrade target).
    #[must_use]
    pub fn test_only(&self) -> TierGroup {
        self.group(|a| matches!(a, DeadAction::TestOnly))
    }

    fn count_action(&self, want: &DeadAction) -> usize {
        self.symbols.iter().filter(|s| &s.action == want).count()
    }

    /// Count of `SafeDelete` (dead-confirmed) members that survived the downgrade.
    #[must_use]
    pub fn dead_confirmed_count(&self) -> usize {
        self.count_action(&DeadAction::SafeDelete)
    }

    /// Count of `SuspectedDelete` (suspected) members.
    #[must_use]
    pub fn suspected_count(&self) -> usize {
        self.count_action(&DeadAction::SuspectedDelete)
    }

    /// Count of `NeedsReview` members. Byte-stable under all `GateSignals`.
    #[must_use]
    pub fn needs_review_count(&self) -> usize {
        self.count_action(&DeadAction::NeedsReview)
    }

    /// Count of `TestOnly`-action members. Byte-stable under all `GateSignals`.
    #[must_use]
    pub fn test_only_count(&self) -> usize {
        self.count_action(&DeadAction::TestOnly)
    }

    /// The `action_tiers` JSON object for `--format json` (site 1). Three
    /// human-facing groups keyed by HONEST tier names — no "safe"/delete token —
    /// a PROJECTION of the canonical 4-tally over the DOWNGRADED action
    /// (`dead_confirmed` = SafeDelete; `investigate` = SuspectedDelete ∪
    /// NeedsReview; `test_only` = TestOnly). There is no `Unknown` bucket: Path A
    /// never whole-verb-suppresses, so `classify_dead_action` (verb-level `Unknown`
    /// never) leaves only the four per-symbol actions.
    #[must_use]
    pub fn action_tiers_json(&self) -> serde_json::Value {
        let dc = self.dead_confirmed();
        let inv = self.investigate();
        let to = self.test_only();
        serde_json::json!({
            "dead_confirmed": { "files": dc.files, "symbols": dc.symbols },
            "investigate": { "files": inv.files, "symbols": inv.symbols },
            "test_only": { "files": to.files, "symbols": to.symbols },
        })
    }

    /// The four-bucket action breakdown for the `--store` metadata (site 5) —
    /// over the DOWNGRADED action.
    #[must_use]
    pub fn store_tier_breakdown(&self) -> serde_json::Value {
        serde_json::json!({
            "dead_confirmed": self.dead_confirmed_count(),
            "suspected": self.suspected_count(),
            "needs_review": self.needs_review_count(),
            "test_only": self.test_only_count(),
        })
    }

    /// The honest tier breakdown appended to the `--fail-on-dead` failure message
    /// (site 3) — over the DOWNGRADED action. The four counts sum to
    /// [`Self::total`] (the downgrade re-buckets within the population).
    #[must_use]
    pub fn fail_summary(&self) -> String {
        format!(
            "{} dead-confirmed / {} suspected / {} needs-review / {} test-only",
            self.dead_confirmed_count(),
            self.suspected_count(),
            self.needs_review_count(),
            self.test_only_count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{EdgeKind, GraphEdge, GraphNode};
    use crate::graph_stats::CoverageTier;
    use uuid::Uuid;

    /// The healthy-regime signals — both downgrades are no-ops, so the hoisted
    /// projection equals the pre-WU-0022 raw bucketing byte-for-byte. Every pin
    /// below runs under these (the WU-0022 fixtures exercise the degraded signals).
    const fn healthy() -> GateSignals {
        GateSignals {
            tier: CoverageTier::Sufficient,
            oracle_ran_ok: true,
            // DEC-R8a (WU-0023 P3b): Path A (compute_dead_tiers) IGNORES this axis
            // (raw-membership gate — LEAK-3); `true` keeps these pins byte-identical.
            reachability_classified: true,
        }
    }

    /// Build a graph node with only the fields the tier oracle reads; the rest
    /// take inert defaults.
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

    // ── Falsifier F-A1: a `pub` Dead node in a fully-dead file is NOT
    // dead-confirmed (a `pub` symbol fails `visibility_is_deletable`). ──────────
    #[test]
    fn pub_dead_node_is_investigate_not_dead_confirmed() {
        let mut graph = KnowledgeGraph::new();
        let node = mk_node(
            1,
            "pub_dead_fn",
            "crates/x/src/orphan.rs",
            ReachabilityClass::Dead,
            "pub",
            true,
        );
        graph.add_node(node).unwrap();

        let tiers = compute_dead_tiers(&graph, healthy());
        assert_eq!(tiers.total(), 1, "the pub dead node is in the broad set");
        assert_eq!(
            tiers.dead_confirmed().symbols,
            0,
            "a pub symbol must never be dead_confirmed"
        );
        assert_eq!(
            tiers.investigate().symbols,
            1,
            "a pub dead node routes to investigate"
        );
    }

    // ── Falsifier F-A2: a private, rustc-flagged, cfg-clean Dead node IS
    // dead-confirmed (the SafeDelete conjunction holds). ────────────────────────
    #[test]
    fn private_flagged_dead_node_is_dead_confirmed() {
        let mut graph = KnowledgeGraph::new();
        let node = mk_node(
            1,
            "priv_dead_fn",
            "crates/x/src/a.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        );
        graph.add_node(node).unwrap();

        let tiers = compute_dead_tiers(&graph, healthy());
        assert_eq!(tiers.dead_confirmed().symbols, 1);
        assert_eq!(tiers.dead_confirmed_count(), 1);
        assert_eq!(tiers.investigate().symbols, 0);
    }

    // ── Falsifier F-A3 (THE widen): a Suspected-only node appears in the tiers,
    // routed to investigate. ────────────────────────────────────────────────────
    #[test]
    fn suspected_only_node_appears_in_investigate() {
        let mut graph = KnowledgeGraph::new();
        let node = mk_node(
            1,
            "suspected_fn",
            "crates/x/src/b.rs",
            ReachabilityClass::Suspected,
            "private",
            false,
        );
        graph.add_node(node).unwrap();

        let tiers = compute_dead_tiers(&graph, healthy());
        assert_eq!(
            tiers.total(),
            1,
            "a Suspected-only node is in the broad non-live set"
        );
        assert_eq!(tiers.dead_confirmed().symbols, 0);
        assert_eq!(tiers.investigate().symbols, 1);
        let json = tiers.action_tiers_json();
        assert_eq!(json["investigate"]["symbols"], 1);
        assert_eq!(json["dead_confirmed"]["symbols"], 0);
    }

    // ── Falsifier F-A4 (fail-on-dead widen + MAJOR-2): a Suspected-only repo with
    // zero call edges (low/no-SCIP shape) still counts toward the gate. ─────────
    #[test]
    fn fail_on_dead_counts_suspected_under_zero_coverage() {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(mk_node(
                1,
                "s1",
                "crates/x/src/c.rs",
                ReachabilityClass::Suspected,
                "private",
                false,
            ))
            .unwrap();
        graph
            .add_node(mk_node(
                2,
                "s2",
                "crates/x/src/c.rs",
                ReachabilityClass::Suspected,
                "pub",
                false,
            ))
            .unwrap();

        let tiers = compute_dead_tiers(&graph, healthy());
        assert_eq!(
            tiers.total(),
            2,
            "both Suspected symbols count toward the gate"
        );
        assert!(
            tiers.total() > 0,
            "the exit gate fires on a Suspected-only repo"
        );
        assert_eq!(
            tiers.suspected_count() + tiers.needs_review_count(),
            2,
            "Suspected-only members are suspected/needs-review, never dead-confirmed"
        );
        assert_eq!(tiers.dead_confirmed_count(), 0);
    }

    // ── Falsifier F-A5 (baseline widen): the broad membership names include
    // Suspected symbols. ────────────────────────────────────────────────────────
    #[test]
    fn symbol_names_include_suspected_members() {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(mk_node(
                1,
                "went_suspected",
                "crates/x/src/d.rs",
                ReachabilityClass::Suspected,
                "private",
                false,
            ))
            .unwrap();

        let tiers = compute_dead_tiers(&graph, healthy());
        let names = tiers.symbol_names();
        assert_eq!(names, vec!["went_suspected".to_string()]);
    }

    // ── Falsifier F-A6 (store widen): the `--store` tier breakdown enumerates a
    // Suspected-only repo. ──────────────────────────────────────────────────────
    #[test]
    fn store_breakdown_enumerates_suspected() {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(mk_node(
                1,
                "s",
                "crates/x/src/e.rs",
                ReachabilityClass::Suspected,
                "private",
                false,
            ))
            .unwrap();

        let tiers = compute_dead_tiers(&graph, healthy());
        let breakdown = tiers.store_tier_breakdown();
        assert_eq!(breakdown["suspected"], 1);
        assert_eq!(breakdown["dead_confirmed"], 0);
        assert_eq!(tiers.symbol_names().len(), 1);
    }

    // ── A Dead node with an alive dependent is NeedsReview → investigate. ───────
    #[test]
    fn dead_node_with_alive_dependent_is_investigate() {
        let mut graph = KnowledgeGraph::new();
        let dead = mk_node(
            1,
            "dead_fn",
            "crates/x/src/f.rs",
            ReachabilityClass::Dead,
            "private",
            true,
        );
        let alive = mk_node(
            2,
            "alive_fn",
            "crates/x/src/g.rs",
            ReachabilityClass::Wired,
            "pub",
            false,
        );
        let dead_id = dead.memory_id;
        let alive_id = alive.memory_id;
        graph.add_node(dead).unwrap();
        graph.add_node(alive).unwrap();
        graph.add_edge(alive_id, dead_id, calls_edge()).unwrap();

        let tiers = compute_dead_tiers(&graph, healthy());
        assert_eq!(tiers.needs_review_count(), 1);
        assert_eq!(tiers.dead_confirmed_count(), 0);
        assert_eq!(tiers.investigate().symbols, 1);
    }

    // ── Generated OUT_DIR glue is excluded from the broad set. ──────────────────
    #[test]
    fn generated_out_dir_glue_is_excluded() {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(mk_node(
                1,
                "generated_thing",
                "target/debug/build/somepkg-abc/out/glue.rs",
                ReachabilityClass::Dead,
                "private",
                true,
            ))
            .unwrap();
        graph
            .add_node(mk_node(
                2,
                "real_dead",
                "crates/x/src/target/thing.rs",
                ReachabilityClass::Suspected,
                "private",
                false,
            ))
            .unwrap();

        let tiers = compute_dead_tiers(&graph, healthy());
        assert_eq!(
            tiers.total(),
            1,
            "OUT_DIR glue excluded; the src/.../target/ user symbol kept"
        );
        assert_eq!(tiers.symbol_names(), vec!["real_dead".to_string()]);
    }

    // ── Orphan/TestOnly-class/live nodes are NOT in the broad set. ──────────────
    #[test]
    fn only_dead_and_suspected_are_members() {
        let mut graph = KnowledgeGraph::new();
        for (i, class) in [
            ReachabilityClass::Wired,
            ReachabilityClass::PublicApi,
            ReachabilityClass::Structural,
            ReachabilityClass::TestOnly,
            ReachabilityClass::Orphan,
            ReachabilityClass::Unclassified,
        ]
        .into_iter()
        .enumerate()
        {
            graph
                .add_node(mk_node(
                    (i as u128) + 1,
                    &format!("n{i}"),
                    &format!("crates/x/src/n{i}.rs"),
                    class,
                    "private",
                    false,
                ))
                .unwrap();
        }
        let tiers = compute_dead_tiers(&graph, healthy());
        assert_eq!(tiers.total(), 0, "no Dead/Suspected members present");
    }
}
