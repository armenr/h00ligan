//! WU-0015 Leg 3a / ADR-0036 §Decision v6 — the rustc/clippy dead-code oracle
//! SIGNAL, end-to-end contract.
//!
//! Leg 3a PRODUCES a per-node `rustc_flagged_dead` bit at index time and wires
//! it into NO verdict: the delete-authority tier stays EMPTY. These fixtures
//! prove the three load-bearing properties (ADR-0036 V3-3/V4-2/V6):
//!   * PARSE (`P*`) — the clippy-JSON parser retains the dead_code/unused_*
//!     family, drops style/clippy lints, keys on the PRIMARY span, and degrades
//!     on garbage without panicking;
//!   * SPAN-MAP (`SM*`) — the mapper is EXACT-line + span-based, NEVER name-based
//!     and NEVER an enclosing-definition heuristic; the 1→0 index normalization
//!     is load-bearing; ambiguous/no-match flags nothing;
//!   * DEGRADE (`GD*`) — clippy absent / non-compiling / timeout / non-cargo →
//!     oracle ABSENT → zero flags → zero crash → no over-flag;
//!   * SAFETY (`INV*`) — the signal is PRODUCED but consumed by NOBODY: even the
//!     single most Dead-eligible node stays Suspected/SuspectedDelete, and
//!     apply_oracle mutates NO verdict field.
//!
//! Producer-driven (real extractor line ranges, never a hand-set node) per the
//! anti-green-by-construction discipline; mirrors `leg2_cfg_signal.rs`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::entry_points::{EntryPoint, EntryPointKind};
use h00ligan_engine::extractor::extract_rust_symbols;
use h00ligan_engine::graph::{GraphNode, KnowledgeGraph, OracleReceipt};
use h00ligan_engine::graph_query::{DeadAction, cfg_touching_crates, classify_dead_action};
use h00ligan_engine::reachability::{ReachabilityAnalyzer, ReachabilityClass};
use h00ligan_engine::rustc_oracle::{
    DeadDiag, OracleError, OracleOutcome, apply_oracle, collect_dead_diagnostics,
    parse_clippy_dead_diagnostics, reaffirm_oracle,
};
use h00ligan_engine::structural_ir::ExtractorOutput;

// ---------------------------------------------------------------------------
// Producer-driven fixture helpers (mirror leg2_cfg_signal.rs).
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

/// The unique node with `symbol_name == name` in a given `file_path`
/// (disambiguates the same-named nodes across files that `SM2` plants).
fn node_in_file<'g>(graph: &'g KnowledgeGraph, file: &str, name: &str) -> &'g GraphNode {
    graph
        .all_nodes()
        .into_iter()
        .find(|n| n.file_path == file && n.symbol_name == name)
        .unwrap_or_else(|| panic!("node {name:?} not found in {file:?}"))
}

/// The 0-indexed graph `line_start` of a node, or panic if absent.
fn line0(node: &GraphNode) -> usize {
    node.line_start
        .unwrap_or_else(|| panic!("node {:?} has no line_start", node.symbol_name))
}

fn diag(file_name: &str, line_start_1indexed: usize, code: &str) -> DeadDiag {
    DeadDiag {
        file_name: file_name.to_string(),
        line_start: line_start_1indexed,
        code: code.to_string(),
        // Line-only helper: no parsed subject → apply_oracle's None fallback
        // flags the unique-line candidate (WU-0016 Class-B).
        subject: None,
        manifest_path: None,
    }
}

/// A one-line clippy `compiler-message` JSON for `code` at `file:line`
/// (1-indexed), with a single primary span and NO backtick `message` (so the
/// parsed `subject` is `None`).
fn clippy_line(file: &str, line_start_1indexed: usize, code: &str) -> String {
    format!(
        r#"{{"reason":"compiler-message","message":{{"code":{{"code":"{code}"}},"spans":[{{"file_name":"{file}","line_start":{line_start_1indexed},"is_primary":true}}]}}}}"#
    )
}

/// A dummy repo root — the SM*/INV* fixtures feed workspace-relative file names,
/// which `relativize` returns unchanged regardless of the root.
fn dummy_root() -> &'static Path {
    Path::new("/repo")
}

fn count_flagged(graph: &KnowledgeGraph) -> usize {
    graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.rustc_flagged_dead)
        .count()
}

// ===========================================================================
// PARSE — the clippy-JSON parser.
// ===========================================================================

/// P1: the parser retains `dead_code`, and drops the `unused_variables` diag
/// (WU-0016 Class-B narrowing), the clippy::* style lint, and the
/// compiler-artifact build noise; line_start is extracted VERBATIM (still
/// 1-indexed at parse time).
#[test]
fn p1_parse_retains_deadcode_family_drops_style() {
    let json = r#"{"reason":"compiler-message","message":{"code":{"code":"dead_code"},"spans":[{"file_name":"crates/x/src/a.rs","line_start":10,"is_primary":true}]}}
{"reason":"compiler-message","message":{"code":{"code":"unused_variables"},"spans":[{"file_name":"crates/x/src/b.rs","line_start":4,"is_primary":true}]}}
{"reason":"compiler-message","message":{"code":{"code":"clippy::needless_return"},"spans":[{"file_name":"crates/x/src/c.rs","line_start":7,"is_primary":true}]}}
{"reason":"compiler-artifact","target":{"name":"x"}}"#;

    let got = parse_clippy_dead_diagnostics(json);
    assert_eq!(
        got,
        vec![diag("crates/x/src/a.rs", 10, "dead_code")],
        "only the dead_code diagnostic survives; unused_variables (Class-B narrowing), clippy::* and compiler-artifact are dropped"
    );
}

/// P2: with a secondary + primary span (and a child-note span), the parser keys
/// on `is_primary:true` — never the first span and never a child span.
#[test]
fn p2_parse_extracts_primary_span_only() {
    let json = r#"{"reason":"compiler-message","message":{"code":{"code":"dead_code"},"spans":[{"file_name":"crates/x/src/a.rs","line_start":2,"is_primary":false},{"file_name":"crates/x/src/a.rs","line_start":10,"is_primary":true}],"children":[{"spans":[{"file_name":"crates/x/src/a.rs","line_start":99,"is_primary":true}]}]}}"#;

    let got = parse_clippy_dead_diagnostics(json);
    assert_eq!(got.len(), 1, "exactly one diagnostic");
    assert_eq!(
        got[0].line_start, 10,
        "line_start must be the is_primary:true span (10), not the secondary (2) or child (99)"
    );
}

/// P3: a stream mixing a valid dead_code line with an error-level message, a
/// build-finished line, a blank line, and a truncated half-JSON line yields ONLY
/// the valid diagnostic — the malformed lines are skipped without panic.
#[test]
fn p3_parse_degrades_on_noise_and_malformed() {
    let json = "{\"reason\":\"compiler-message\",\"message\":{\"code\":{\"code\":\"dead_code\"},\"spans\":[{\"file_name\":\"crates/x/src/a.rs\",\"line_start\":10,\"is_primary\":true}]}}\n\
{\"reason\":\"compiler-message\",\"message\":{\"code\":{\"code\":\"E0433\"},\"level\":\"error\",\"spans\":[{\"file_name\":\"crates/x/src/z.rs\",\"line_start\":1,\"is_primary\":true}]}}\n\
{\"reason\":\"build-finished\",\"success\":false}\n\
\n\
{\"reason\":\"compiler-message\",\"message\":{\"code\":{\"code\":\"dead_c";

    let got = parse_clippy_dead_diagnostics(json);
    assert_eq!(
        got.len(),
        1,
        "only the single valid dead_code diagnostic survives"
    );
    assert_eq!(got[0].code, "dead_code");
    assert_eq!(got[0].line_start, 10);
}

/// P4: pins the NARROWED retention boundary (WU-0016 Class-B). The thesis is
/// INVERTED from Leg-3a: ONLY `dead_code` is kept; the WHOLE `unused_*` family
/// (plus the bare `unused` group) now moves to the DROPPED set alongside
/// non_snake_case (style), clippy::* and unreachable_code. `unused_*` targets a
/// local binding/statement/import — never a definition item — so its only
/// matches on a definition NODE were line-collision spoofs.
#[test]
fn p4_parse_unused_family_boundary() {
    let mut lines = Vec::new();
    let mut push = |code: &str, line: usize| {
        lines.push(format!(
            r#"{{"reason":"compiler-message","message":{{"code":{{"code":"{code}"}},"spans":[{{"file_name":"crates/x/src/f.rs","line_start":{line},"is_primary":true}}]}}}}"#
        ));
    };
    // Retained — `dead_code` ONLY.
    push("dead_code", 1);
    // Dropped — the whole `unused_*` family + the bare `unused` group.
    push("unused", 2);
    push("unused_variables", 3);
    push("unused_imports", 4);
    push("unused_mut", 5);
    push("unused_assignments", 6);
    // Dropped — style / clippy / adjacent non-family.
    push("non_snake_case", 7);
    push("clippy::needless_return", 8);
    push("unreachable_code", 9);
    let json = lines.join("\n");

    let got = parse_clippy_dead_diagnostics(&json);
    let kept: Vec<&str> = got.iter().map(|d| d.code.as_str()).collect();
    assert_eq!(
        kept,
        vec!["dead_code"],
        "narrowed retention boundary = dead_code ONLY; the unused_* family + style/clippy/unreachable_code are all excluded"
    );
}

// ===========================================================================
// SPAN-MAP — the exact-line, span-based mapper.
// ===========================================================================

/// SM1: an exact 1→0 line match sets the bit; every other node stays false.
#[test]
fn sm1_span_exact_1to0_match_flags() {
    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn dead_fn() {}\n")]);
    let k = line0(node_in_file(&graph, "crates/x/src/a.rs", "dead_fn"));

    apply_oracle(
        &mut graph,
        &[diag("crates/x/src/a.rs", k + 1, "dead_code")],
        dummy_root(),
    );

    assert!(
        node_in_file(&graph, "crates/x/src/a.rs", "dead_fn").rustc_flagged_dead,
        "the exact-(file,line) node must be flagged (−1 normalization + exact match)"
    );
    assert_eq!(count_flagged(&graph), 1, "no other node may be flagged");
}

/// SM2 (RED for a name-based mapper): two identically-named private fns in
/// DIFFERENT files; clippy flags only a.rs's. A span-based mapper flags ONLY
/// a.rs's helper; a name-based mapper would false-flag the used twin in b.rs.
#[test]
fn sm2_name_collision_span_not_name() {
    let mut graph = build_from_sources(&[
        ("crates/x/src/a.rs", "fn helper() {}\n"),
        (
            "crates/x/src/b.rs",
            "pub fn use_it() { helper(); }\nfn helper() {}\n",
        ),
    ]);
    let k_a = line0(node_in_file(&graph, "crates/x/src/a.rs", "helper"));

    apply_oracle(
        &mut graph,
        &[diag("crates/x/src/a.rs", k_a + 1, "dead_code")],
        dummy_root(),
    );

    assert!(
        node_in_file(&graph, "crates/x/src/a.rs", "helper").rustc_flagged_dead,
        "the dead a.rs::helper (span match) must be flagged"
    );
    assert!(
        !node_in_file(&graph, "crates/x/src/b.rs", "helper").rustc_flagged_dead,
        "the used b.rs::helper twin must NOT be flagged — a name-based mapper would falsely flag it"
    );
    assert_eq!(count_flagged(&graph), 1);
}

/// SM3 (RED for a 1-vs-0 off-by-one): two adjacent fns; a no-subtract bug would
/// flag the NEIGHBOR planted at the mis-indexed line. Correct (−1) flags target.
#[test]
fn sm3_offbyone_adjacent_node_misflag() {
    let mut graph = build_from_sources(&[(
        "crates/x/src/a.rs",
        "fn target_fn() {}\nfn neighbor_fn() {}\n",
    )]);
    let g = line0(node_in_file(&graph, "crates/x/src/a.rs", "target_fn"));
    let g_neighbor = line0(node_in_file(&graph, "crates/x/src/a.rs", "neighbor_fn"));
    assert_eq!(
        g_neighbor,
        g + 1,
        "precondition: neighbor sits at g+1 so a no-subtract bug would mis-flag it (non-vacuous)"
    );

    // clippy reports target at its 1-indexed line (g+1).
    apply_oracle(
        &mut graph,
        &[diag("crates/x/src/a.rs", g + 1, "dead_code")],
        dummy_root(),
    );

    assert!(
        node_in_file(&graph, "crates/x/src/a.rs", "target_fn").rustc_flagged_dead,
        "the −1 normalization must flag target_fn (line_start==g)"
    );
    assert!(
        !node_in_file(&graph, "crates/x/src/a.rs", "neighbor_fn").rustc_flagged_dead,
        "a no-subtract bug would flag neighbor_fn (line_start==g+1) — it must stay false"
    );
}

/// SM4: two nodes share the SAME (file, line) → ambiguous → flag NEITHER.
#[test]
fn sm4_ambiguous_multinode_not_flagged() {
    // A single-line impl: the impl block node and its method both start at line 0.
    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "impl Foo { fn bar() {} }\n")]);

    // Precondition: at least two nodes at (crates/x/src/a.rs, line 0) — else the
    // ambiguity the rule guards against is not present (vacuity guard).
    let at_line0 = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.file_path == "crates/x/src/a.rs" && n.line_start == Some(0))
        .count();
    assert!(
        at_line0 >= 2,
        "precondition: the single-line impl must yield >=2 nodes at line 0 (got {at_line0})"
    );

    apply_oracle(
        &mut graph,
        &[diag("crates/x/src/a.rs", 1, "dead_code")],
        dummy_root(),
    );

    assert_eq!(
        count_flagged(&graph),
        0,
        "an ambiguous multi-node (file,line) match must flag NEITHER node"
    );
}

/// SM5: a diagnostic whose line has no node (interior body line) or whose file
/// is absent from the graph flags nothing and never panics.
#[test]
fn sm5_no_match_not_flagged() {
    let mut graph = build_from_sources(&[(
        "crates/x/src/a.rs",
        "pub fn f() {\n    let x = 1;\n    let _ = x;\n}\n",
    )]);

    apply_oracle(
        &mut graph,
        &[
            // (a) an interior body line (line 2, 1-indexed) — no node begins there.
            diag("crates/x/src/a.rs", 2, "dead_code"),
            // (b) a file entirely absent from the graph.
            diag("crates/x/src/absent.rs", 1, "dead_code"),
        ],
        dummy_root(),
    );

    assert_eq!(
        count_flagged(&graph),
        0,
        "no-match diagnostics must flag nothing (conservative)"
    );
}

/// SM6: the relativizer normalizes the absolute and package-relative clippy
/// emission forms to the graph's `crates/<crate>/src/...` convention.
#[test]
fn sm6_relativization_to_graph_convention() {
    // (a) ABSOLUTE form.
    {
        let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn a() {}\n")]);
        let k = line0(node_in_file(&graph, "crates/x/src/a.rs", "a"));
        let abs = DeadDiag {
            file_name: "/repo/crates/x/src/a.rs".to_string(),
            line_start: k + 1,
            code: "dead_code".to_string(),
            // Subject matches the lone node `a` → exercises the subject-match
            // path (WU-0016 Class-B), not just the None fallback.
            subject: Some("a".to_string()),
            manifest_path: None,
        };
        apply_oracle(&mut graph, &[abs], Path::new("/repo"));
        assert!(
            node_in_file(&graph, "crates/x/src/a.rs", "a").rustc_flagged_dead,
            "the absolute form must relativize+match"
        );
    }
    // (b) PACKAGE-RELATIVE form (resolved via manifest_path → package root).
    {
        let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn a() {}\n")]);
        let k = line0(node_in_file(&graph, "crates/x/src/a.rs", "a"));
        let pkg_rel = DeadDiag {
            file_name: "src/a.rs".to_string(),
            line_start: k + 1,
            code: "dead_code".to_string(),
            // Subject matches the lone node `a` (subject-match path).
            subject: Some("a".to_string()),
            manifest_path: Some("/repo/crates/x/Cargo.toml".to_string()),
        };
        apply_oracle(&mut graph, &[pkg_rel], Path::new("/repo"));
        assert!(
            node_in_file(&graph, "crates/x/src/a.rs", "a").rustc_flagged_dead,
            "the package-relative form must join the package root and match"
        );
    }
}

/// SM7 (RED for an enclosing-definition heuristic): a diagnostic pointing at an
/// interior body line must NOT resolve to the enclosing fn. Only an exact
/// def-line match flags. Directly forbids reusing find_enclosing_definition.
#[test]
fn sm7_forbid_enclosing_definition_heuristic() {
    let mut graph = build_from_sources(&[(
        "crates/x/src/a.rs",
        "pub fn wrapper() {\n    // body line\n    let x = 1;\n    let _ = x;\n}\n",
    )]);
    let w = line0(node_in_file(&graph, "crates/x/src/a.rs", "wrapper"));

    // Point at an interior line (w+2, 0-indexed → w+3 as a 1-indexed diag),
    // NOT the def line.
    apply_oracle(
        &mut graph,
        &[diag("crates/x/src/a.rs", w + 3, "dead_code")],
        dummy_root(),
    );

    assert!(
        !node_in_file(&graph, "crates/x/src/a.rs", "wrapper").rustc_flagged_dead,
        "an interior body line must resolve to NOTHING — never the enclosing definition"
    );
    assert_eq!(count_flagged(&graph), 0);
}

// ===========================================================================
// GRACEFUL DEGRADE — clippy absent / timeout / non-cargo → zero flags, no crash.
// ===========================================================================

/// GD1: a failing runner seam → collect returns Err WITHOUT panic; a no-Cargo.toml
/// tempdir does the same via the real runner; apply_oracle with an empty diag set
/// leaves every node false.
#[test]
fn gd1_clippy_absent_zero_flags_zero_crash() {
    // (a) injected failing runner → Err, no panic.
    let failing = |_: &Path, _: Duration| Err::<String, _>(OracleError::NotCargo);
    let collected = collect_dead_diagnostics(dummy_root(), Duration::from_secs(1), failing);
    assert!(matches!(collected, Err(OracleError::NotCargo)));

    // (b) real runner on a tempdir with no Cargo.toml → Err(NotCargo).
    let tmp = tempfile::tempdir().expect("tempdir");
    let real = collect_dead_diagnostics(
        tmp.path(),
        Duration::from_secs(1),
        h00ligan_engine::rustc_oracle::run_cargo_clippy,
    );
    assert!(
        matches!(real, Err(OracleError::NotCargo)),
        "a dir with no Cargo.toml degrades to NotCargo, not a crash"
    );

    // (c) absent oracle (empty diags) flags nothing.
    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn a() {}\n")]);
    apply_oracle(&mut graph, &[], dummy_root());
    assert_eq!(
        count_flagged(&graph),
        0,
        "an absent oracle over-flags nothing"
    );
}

/// GD2: a clippy stream that is all level==error with zero dead_code (a repo
/// that does not compile) yields zero diagnostics → zero flags, no over-flag.
#[test]
fn gd2_noncompiling_stream_no_overflag() {
    let json = r#"{"reason":"compiler-message","message":{"code":{"code":"E0432"},"level":"error","spans":[{"file_name":"crates/x/src/a.rs","line_start":1,"is_primary":true}]}}
{"reason":"compiler-message","message":{"code":null,"level":"error","spans":[{"file_name":"crates/x/src/a.rs","line_start":2,"is_primary":true}]}}
{"reason":"build-finished","success":false}"#;
    let diags = parse_clippy_dead_diagnostics(json);
    assert!(
        diags.is_empty(),
        "a non-compiling repo yields NO dead_code diagnostics"
    );

    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn a() {}\n")]);
    apply_oracle(&mut graph, &diags, dummy_root());
    assert_eq!(
        count_flagged(&graph),
        0,
        "a compile failure must never fabricate flags"
    );
}

/// GD3: a timeout (injected via the runner seam) degrades identically to
/// clippy-absent → collect Err, zero flags, no crash. Confirms the bounded cap.
#[test]
fn gd3_timeout_bounded_degrade() {
    let timing_out = |_: &Path, _: Duration| Err::<String, _>(OracleError::Timeout);
    let collected = collect_dead_diagnostics(dummy_root(), Duration::from_millis(1), timing_out);
    assert!(matches!(collected, Err(OracleError::Timeout)));

    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn a() {}\n")]);
    apply_oracle(&mut graph, &[], dummy_root());
    assert_eq!(
        count_flagged(&graph),
        0,
        "a timeout degrades to absent → zero flags"
    );
}

/// GD4: a non-cargo / non-Rust repo (tempdir with only a text file, no
/// Cargo.toml) → the real runner returns NotCargo → zero flags, no crash.
#[test]
fn gd4_non_cargo_non_rust_repo_degrade() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("README.txt"), "not a rust project").expect("write");

    let collected = collect_dead_diagnostics(
        tmp.path(),
        Duration::from_secs(1),
        h00ligan_engine::rustc_oracle::run_cargo_clippy,
    );
    assert!(
        matches!(collected, Err(OracleError::NotCargo)),
        "a non-cargo repo degrades to NotCargo"
    );

    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn a() {}\n")]);
    apply_oracle(&mut graph, &[], tmp.path());
    assert_eq!(count_flagged(&graph), 0);
}

// ===========================================================================
// SAFETY CONTROL — the signal is PRODUCED but consumed by NOBODY.
// ===========================================================================

/// INV1: with the signal actually present (non-vacuous), the delete-authority
/// tier stays EMPTY and the flagged private-unreachable fn is STILL
/// Suspected/SuspectedDelete — the signal is consumed by no verdict path.
#[test]
fn inv1_all_conjuncts_satisfied_yields_one_safedelete() {
    let mut graph = build_from_sources(&[
        (
            "crates/lib/src/lib.rs",
            "fn private_unreached() {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "lib", "crates/lib/src/lib.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);

    // Set the oracle bit on private_unreached (simulate clippy flagging it).
    let k = line0(node_in_file(
        &graph,
        "crates/lib/src/lib.rs",
        "private_unreached",
    ));
    apply_oracle(
        &mut graph,
        &[diag("crates/lib/src/lib.rs", k + 1, "dead_code")],
        dummy_root(),
    );

    // (1) NON-VACUITY — the signal is actually present.
    assert!(
        count_flagged(&graph) >= 1,
        "at least one node must carry rustc_flagged_dead==true (non-vacuous control)"
    );

    // (2) WU-0015 Leg-3b REBASELINE — private_unreached now promotes to Dead
    // (private, call-unreachable, no guard). Dead is legitimately non-empty.
    let residual = node_in_file(&graph, "crates/lib/src/lib.rs", "private_unreached").clone();
    assert!(
        residual.rustc_flagged_dead,
        "precondition: private_unreached carries the oracle flag"
    );
    assert_eq!(
        residual.reachability_class,
        ReachabilityClass::Dead,
        "a private call-unreachable residual promotes to Dead in Leg 3b"
    );

    // (3) WU-0015 Leg-3b REBASELINE — this is now a NON-VACUOUS SafeDelete
    // control: ALL 4 conjuncts hold (Dead + rustc-flagged + private + cfg-clean
    // crate `lib`), so EXACTLY ONE node yields SafeDelete, and it is
    // private_unreached.
    let cfg_crates = cfg_touching_crates(&graph);
    let safe_delete: Vec<String> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| classify_dead_action(&graph, n, &cfg_crates) == DeadAction::SafeDelete)
        .map(|n| n.symbol_name.clone())
        .collect();
    assert_eq!(
        safe_delete.len(),
        1,
        "exactly ONE SafeDelete (private_unreached); found {safe_delete:?}"
    );
    assert!(
        safe_delete[0].ends_with("private_unreached"),
        "the sole SafeDelete node is private_unreached; found {safe_delete:?}"
    );

    // (4) and private_unreached itself is SafeDelete.
    assert_eq!(
        classify_dead_action(&graph, &residual, &cfg_crates),
        DeadAction::SafeDelete,
        "all 4 conjuncts satisfied → SafeDelete"
    );
}

/// INV2: the EXACT profile Leg 3b would upgrade to Dead — private, call-
/// unreachable, cfg-clean, rustc_flagged_dead==true — STILL stays
/// Suspected/SuspectedDelete in Leg 3a, because no classifier consults the flag.
#[test]
fn inv2_most_eligible_dead_candidate_now_safedelete() {
    let mut graph = build_from_sources(&[
        // cfg-CLEAN crate (no platform-cfg token) with a private unreached fn.
        (
            "crates/lib/src/lib.rs",
            "fn most_dead() {}\npub fn api() {}\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "lib", "crates/lib/src/lib.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);

    let candidate = node_in_file(&graph, "crates/lib/src/lib.rs", "most_dead").clone();
    // Confirm the full Dead-eligible profile.
    assert!(!candidate.has_platform_cfg, "cfg-clean crate");
    assert_eq!(candidate.visibility, "private", "private symbol");
    assert_eq!(
        candidate.reachability_class,
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: a private call-unreachable residual is Dead before the oracle"
    );

    let k = line0(&candidate);
    apply_oracle(
        &mut graph,
        &[diag("crates/lib/src/lib.rs", k + 1, "dead_code")],
        dummy_root(),
    );

    let after = node_in_file(&graph, "crates/lib/src/lib.rs", "most_dead").clone();
    assert!(
        after.rustc_flagged_dead,
        "the most-eligible node IS oracle-flagged"
    );
    assert_eq!(
        after.reachability_class,
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: the class is Dead (apply_oracle changes no class)"
    );
    let cfg_crates = cfg_touching_crates(&graph);
    assert_eq!(
        classify_dead_action(&graph, &after, &cfg_crates),
        DeadAction::SafeDelete,
        "WU-0015 Leg-3b: the most-eligible node (Dead + flagged + private + cfg-clean) → SafeDelete"
    );
}

/// INV3: apply_oracle mutates ONLY rustc_flagged_dead — every node's
/// reachability_class is byte-identical before/after (structural proof that the
/// oracle pass changes no verdict field).
#[test]
fn inv3_pure_signal_no_reachability_class_consumer() {
    let mut graph = build_from_sources(&[
        (
            "crates/lib/src/lib.rs",
            "fn a() {}\nfn b() {}\npub fn api() { a(); }\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "lib", "crates/lib/src/lib.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);

    let snapshot = |g: &KnowledgeGraph| -> Vec<(uuid::Uuid, ReachabilityClass)> {
        let mut v: Vec<_> = g
            .all_nodes()
            .into_iter()
            .map(|n| (n.memory_id, n.reachability_class))
            .collect();
        v.sort_by_key(|(id, _)| *id);
        v
    };

    let before = snapshot(&graph);
    // Flag a subset (b is private-unreached).
    let k = line0(node_in_file(&graph, "crates/lib/src/lib.rs", "b"));
    apply_oracle(
        &mut graph,
        &[diag("crates/lib/src/lib.rs", k + 1, "dead_code")],
        dummy_root(),
    );
    let after = snapshot(&graph);

    assert_eq!(
        before, after,
        "apply_oracle must leave every node's reachability_class unchanged"
    );
    assert!(
        count_flagged(&graph) >= 1,
        "…while still having set the signal"
    );
}

// ===========================================================================
// WU-0016 Class-B — narrow the rustc dead-code oracle (conjunct-2 SOUND).
//   PART 1: retention narrowed to `dead_code`-only (the `unused_*` family, which
//           only ever def-line-collided, is dropped at parse time).
//   PART 2: apply_oracle gates the lone-candidate flag on subject identity, with
//           a None fallback for subject-less diagnostics.
// Both edits ONLY REDUCE the flagged set — the SAFE (under-flag) direction.
// ===========================================================================

/// PART1 (RED on HEAD): an `unused_*` diagnostic whose PRIMARY span lands on a
/// captured node's EXACT def line. The whole `unused_*` family targets local
/// bindings/statements/imports — never a definition item — so this is only ever
/// a line-collision spoof. After the Class-B narrowing it is DROPPED at parse
/// time, the node is NOT flagged, and it can never seed a SafeDelete. RED on
/// HEAD: `unused_variables` is in-family there → parsed → flags the lone node.
#[test]
fn part1_unused_family_on_defline_dropped() {
    // A cfg-clean crate with a private, call-unreachable fn — the profile that,
    // IF spuriously flagged, would satisfy the other 3 SafeDelete conjuncts.
    let mut graph = build_from_sources(&[
        ("crates/lib/src/lib.rs", "fn victim() {}\npub fn api() {}\n"),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "lib", "crates/lib/src/lib.rs"),
    ];
    analyze_and_writeback(&mut graph, eps);

    let one_indexed = line0(node_in_file(&graph, "crates/lib/src/lib.rs", "victim")) + 1;
    // Synthetic clippy JSON: unused_variables / unused_mut / unused_assignments
    // primary spans all landing on victim's EXACT def line.
    let json = [
        clippy_line("crates/lib/src/lib.rs", one_indexed, "unused_variables"),
        clippy_line("crates/lib/src/lib.rs", one_indexed, "unused_mut"),
        clippy_line("crates/lib/src/lib.rs", one_indexed, "unused_assignments"),
    ]
    .join("\n");

    // PART 1: the narrowed predicate DROPS the whole unused_* family.
    let diags = parse_clippy_dead_diagnostics(&json);
    assert!(
        diags.is_empty(),
        "the unused_* family is dropped at parse time (dead_code-only); got {diags:?}"
    );

    // …so apply_oracle flags nothing and the node cannot become SafeDelete.
    apply_oracle(&mut graph, &diags, dummy_root());
    let after = node_in_file(&graph, "crates/lib/src/lib.rs", "victim");
    assert!(
        !after.rustc_flagged_dead,
        "an unused_* def-line spoof must NOT flag the node"
    );
    let cfg_crates = cfg_touching_crates(&graph);
    assert_ne!(
        classify_dead_action(&graph, after, &cfg_crates),
        DeadAction::SafeDelete,
        "with no oracle flag the 4-way conjunction fails → never SafeDelete"
    );
}

/// PART2 (RED on HEAD): a lone captured node at the diagnostic's line, but the
/// diagnostic's parsed subject names a DIFFERENT symbol. The subject-identity
/// gate must refuse to flag it. RED on HEAD: no subject check → the unique-line
/// match flags `sibling` regardless of the subject.
#[test]
fn part2_subject_mismatch_not_flagged() {
    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn sibling() {}\n")]);
    let k = line0(node_in_file(&graph, "crates/x/src/a.rs", "sibling"));

    let d = DeadDiag {
        file_name: "crates/x/src/a.rs".to_string(),
        line_start: k + 1,
        code: "dead_code".to_string(),
        subject: Some("other".to_string()),
        manifest_path: None,
    };
    apply_oracle(&mut graph, &[d], dummy_root());

    assert!(
        !node_in_file(&graph, "crates/x/src/a.rs", "sibling").rustc_flagged_dead,
        "a dead_code diag whose subject ('other') != the lone node's name ('sibling') must NOT flag it"
    );
    assert_eq!(count_flagged(&graph), 0);
}

/// PART2 (GREEN, non-vacuity — guards against OVER-narrowing): (a) a dead_code
/// diag whose subject MATCHES the lone node's short name STILL flags it; (b) a
/// dead_code diag with `subject == None` FALLS BACK to the unique-line flag and
/// STILL flags it. Both must be GREEN after Class-B.
#[test]
fn part2_positive_control_and_none_fallback() {
    // (a) subject matches → flag.
    {
        let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn sibling() {}\n")]);
        let k = line0(node_in_file(&graph, "crates/x/src/a.rs", "sibling"));
        let d = DeadDiag {
            file_name: "crates/x/src/a.rs".to_string(),
            line_start: k + 1,
            code: "dead_code".to_string(),
            subject: Some("sibling".to_string()),
            manifest_path: None,
        };
        apply_oracle(&mut graph, &[d], dummy_root());
        assert!(
            node_in_file(&graph, "crates/x/src/a.rs", "sibling").rustc_flagged_dead,
            "a subject-matching dead_code diag must still flag the node"
        );
    }
    // (b) subject None → unique-line fallback → flag.
    {
        let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn sibling() {}\n")]);
        let k = line0(node_in_file(&graph, "crates/x/src/a.rs", "sibling"));
        let d = DeadDiag {
            file_name: "crates/x/src/a.rs".to_string(),
            line_start: k + 1,
            code: "dead_code".to_string(),
            subject: None,
            manifest_path: None,
        };
        apply_oracle(&mut graph, &[d], dummy_root());
        assert!(
            node_in_file(&graph, "crates/x/src/a.rs", "sibling").rustc_flagged_dead,
            "a subject-less (None) dead_code diag must fall back to the unique-line flag"
        );
    }
}

/// PART2 parse: the parser extracts the FIRST backtick-quoted token of
/// `message.message` as the `subject`; a message with no backticks → `None`.
/// RED on HEAD (the parser does not read `message.message` there).
#[test]
fn part2_parse_extracts_backtick_subject() {
    let json = concat!(
        r#"{"reason":"compiler-message","message":{"message":"function `foo` is never used","code":{"code":"dead_code"},"spans":[{"file_name":"crates/x/src/a.rs","line_start":10,"is_primary":true}]}}"#,
        "\n",
        r#"{"reason":"compiler-message","message":{"message":"multiple things are never used","code":{"code":"dead_code"},"spans":[{"file_name":"crates/x/src/b.rs","line_start":3,"is_primary":true}]}}"#
    );
    let got = parse_clippy_dead_diagnostics(json);
    assert_eq!(got.len(), 2, "both dead_code diagnostics survive");
    assert_eq!(
        got[0].subject.as_deref(),
        Some("foo"),
        "the first backtick-quoted token is the subject"
    );
    assert_eq!(
        got[1].subject, None,
        "a message with no backtick subject parses to None"
    );
}

// ===========================================================================
// LEG E — OQ-ORACLE-INCREMENTAL-STALE: reset-then-reaffirm (part a) unit surface.
//   reaffirm_oracle(Ran) RESETS all flags then re-applies the fresh diags, so a
//   stale carried-over flag (a symbol that gained a caller) CLEARS while a
//   still-dead node is RE-affirmed. reaffirm_oracle(Degraded) preserves flags.
// ===========================================================================

/// F1 (COMPILE-RED on HEAD: references `reaffirm_oracle` + `OracleOutcome::Ran`,
/// neither of which exists on HEAD). After a CLEAN reaffirm whose fresh diag set
/// OMITS a previously-flagged node (it gained a caller), that node's
/// `rustc_flagged_dead` flips true→false, while a still-genuinely-dead node in
/// the same set is RE-affirmed true. Mid-test the OLD additive `apply_oracle` is
/// shown to LEAVE the stale bit set (HEAD-baseline / non-vacuity anchor: the bug
/// is that `apply_oracle` is set-only/additive — rustc_oracle.rs only ever writes
/// `true`, so an unchanged-file carryover bit can never clear).
#[test]
fn leg_e_f1_reaffirm_clears_stale_carryover() {
    let mut graph =
        build_from_sources(&[("crates/x/src/a.rs", "fn victim() {}\nfn still_dead() {}\n")]);
    // Simulate an incremental carryover: both nodes carry a stale flag.
    for n in ["victim", "still_dead"] {
        let id = node_in_file(&graph, "crates/x/src/a.rs", n).memory_id;
        graph.node_mut(&id).unwrap().rustc_flagged_dead = true;
    }

    // HEAD-baseline / NON-VACUITY: the additive `apply_oracle` with a diag set
    // OMITTING victim LEAVES the stale bit set (this is the exact bug LEG E fixes).
    apply_oracle(&mut graph, &[], dummy_root());
    assert!(
        node_in_file(&graph, "crates/x/src/a.rs", "victim").rustc_flagged_dead,
        "apply_oracle is additive: a stale carryover flag survives an empty re-apply"
    );

    // THE FIX: a CLEAN reaffirm resets ALL flags, then re-applies the fresh diag
    // set (still_dead only) → victim clears, still_dead re-affirmed.
    let k = line0(node_in_file(&graph, "crates/x/src/a.rs", "still_dead"));
    reaffirm_oracle(
        &mut graph,
        &OracleOutcome::Ran(vec![diag("crates/x/src/a.rs", k + 1, "dead_code")]),
        dummy_root(),
    );
    assert!(
        !node_in_file(&graph, "crates/x/src/a.rs", "victim").rustc_flagged_dead,
        "a clean reaffirm OMITTING victim must CLEAR its stale carryover flag"
    );
    assert!(
        node_in_file(&graph, "crates/x/src/a.rs", "still_dead").rustc_flagged_dead,
        "a clean reaffirm must RE-AFFIRM a still-dead node present in the fresh set"
    );
}

/// N2 (negative control) — a DEGRADED oracle outcome (build failed) passed to
/// `reaffirm_oracle` leaves every existing `rustc_flagged_dead` bit UNCHANGED:
/// the reset is gated on build-success, preserving the graceful-degrade contract
/// (the degraded-corner soundness the store-level backstop then covers). Paired
/// with F1 (which shows `Ran` DOES clear) this proves the `Ran` vs `Degraded`
/// arms are genuinely distinct, not both no-ops or both resets.
#[test]
fn leg_e_n2_degraded_oracle_preserves_flags() {
    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn victim() {}\n")]);
    let id = node_in_file(&graph, "crates/x/src/a.rs", "victim").memory_id;
    graph.node_mut(&id).unwrap().rustc_flagged_dead = true; // carryover

    reaffirm_oracle(&mut graph, &OracleOutcome::Degraded, dummy_root());

    assert!(
        node_in_file(&graph, "crates/x/src/a.rs", "victim").rustc_flagged_dead,
        "a degraded oracle run must NOT wipe existing flags (reset gated on clean)"
    );
}

// ===========================================================================
// SCHEMA / real-clippy — #[ignore] (need a real compile / a persisted graph).
// ===========================================================================

/// E2E1: the ONLY path exercising REAL rustc output end-to-end. A fresh on-disk
/// cargo crate → real `cargo clippy` → parse → relativize → span-map. Guards the
/// whole chain against real clippy emission drift.
#[test]
#[ignore = "real clippy: writes a temp crate and shells to `cargo clippy`; run with --ignored"]
fn e2e1_real_clippy_dead_vs_used() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("src")).expect("mkdir src");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"leg3a_e2e_fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
    )
    .expect("write Cargo.toml");
    // 0-indexed: entry=0, used_helper=1, orphan_helper=2.
    let lib_src = "pub fn entry() { used_helper(); }\nfn used_helper() {}\nfn orphan_helper() {}\n";
    std::fs::write(root.join("src/lib.rs"), lib_src).expect("write lib.rs");

    // Build the graph from the same source (real extractor line ranges).
    let mut graph = build_from_sources(&[("src/lib.rs", lib_src)]);

    // Run the REAL clippy runner. If clippy is genuinely unavailable, skip.
    let diags = match collect_dead_diagnostics(
        root,
        Duration::from_secs(300),
        h00ligan_engine::rustc_oracle::run_cargo_clippy,
    ) {
        Ok(OracleOutcome::Ran(d)) => d,
        Ok(OracleOutcome::Degraded) => {
            eprintln!("[leg3a] real clippy build degraded — skipping E2E1");
            return;
        }
        Err(e) => {
            eprintln!("[leg3a] real clippy unavailable ({e}) — skipping E2E1");
            return;
        }
    };
    eprintln!("[leg3a] real clippy dead diags = {diags:?}");
    apply_oracle(&mut graph, &diags, root);

    assert!(
        node_in_file(&graph, "src/lib.rs", "orphan_helper").rustc_flagged_dead,
        "the uncalled orphan_helper must be flagged by REAL clippy dead_code"
    );
    assert!(
        !node_in_file(&graph, "src/lib.rs", "used_helper").rustc_flagged_dead,
        "the called used_helper must NOT be flagged"
    );
    assert!(
        !node_in_file(&graph, "src/lib.rs", "entry").rustc_flagged_dead,
        "the pub entry must NOT be flagged"
    );
}

// ===========================================================================
// WU-0016 Leg F — OQ-DELETE-REASON-PROVENANCE: the corroboration receipt.
//   apply_oracle stamps a companion OracleReceipt beside rustc_flagged_dead; the
//   leg-E reset-then-reaffirm clears BOTH together (no stale receipt survives).
// ===========================================================================

/// F-F3 — apply_oracle stamps `oracle_receipt` from the in-scope diag (code /
/// normalized 0-indexed def line == node.line_start / subject), and the receipt
/// survives a bincode GraphNode round-trip byte-identical. (SCHEMA_VERSION == 8
/// is pinned in graph_store's `schema_version_is_eight_after_oracle_receipt_field`.)
#[test]
fn f_f3_apply_oracle_stamps_receipt_roundtrips() {
    let mut graph = build_from_sources(&[("crates/x/src/a.rs", "fn dead_fn() {}\n")]);
    let k = line0(node_in_file(&graph, "crates/x/src/a.rs", "dead_fn"));
    let d = DeadDiag {
        file_name: "crates/x/src/a.rs".to_string(),
        line_start: k + 1, // rustc is 1-indexed
        code: "dead_code".to_string(),
        subject: Some("dead_fn".to_string()),
        manifest_path: None,
    };
    apply_oracle(&mut graph, &[d], dummy_root());

    let n = node_in_file(&graph, "crates/x/src/a.rs", "dead_fn");
    assert_eq!(
        n.oracle_receipt,
        Some(OracleReceipt {
            code: "dead_code".to_string(),
            line: k, // normalized 0-indexed == node.line_start
            subject: Some("dead_fn".to_string()),
        }),
        "apply_oracle stamps the receipt from the diag"
    );

    let bytes =
        bincode::serde::encode_to_vec(n, bincode::config::standard()).expect("encode GraphNode");
    let (back, _): (GraphNode, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .expect("decode GraphNode");
    assert_eq!(
        back.oracle_receipt, n.oracle_receipt,
        "the receipt survives a bincode round-trip byte-identical"
    );
}

/// F-F4 — the LOAD-BEARING leg-E lifecycle interaction. A node flagged+receipted
/// in run 1, then `reaffirm_oracle(Ran(fresh))` whose fresh set OMITS it, has
/// `rustc_flagged_dead == false` AND `oracle_receipt == None` (no stale receipt
/// survives the reset). Companion non-vacuity: a node PRESENT in the fresh set is
/// re-affirmed flagged AND carries a FRESH receipt. Extends
/// `leg_e_f1_reaffirm_clears_stale_carryover` to the receipt companion.
#[test]
fn f_f4_reaffirm_ran_clears_stale_receipt() {
    let mut graph =
        build_from_sources(&[("crates/x/src/a.rs", "fn victim() {}\nfn still_dead() {}\n")]);

    // Run 1: flag + receipt BOTH nodes via apply_oracle.
    let kv = line0(node_in_file(&graph, "crates/x/src/a.rs", "victim"));
    let ks = line0(node_in_file(&graph, "crates/x/src/a.rs", "still_dead"));
    apply_oracle(
        &mut graph,
        &[
            diag("crates/x/src/a.rs", kv + 1, "dead_code"),
            diag("crates/x/src/a.rs", ks + 1, "dead_code"),
        ],
        dummy_root(),
    );
    assert!(
        node_in_file(&graph, "crates/x/src/a.rs", "victim")
            .oracle_receipt
            .is_some(),
        "precond: victim receipted after run 1"
    );

    // A CLEAN reaffirm whose fresh set OMITS victim (it gained a caller).
    reaffirm_oracle(
        &mut graph,
        &OracleOutcome::Ran(vec![diag("crates/x/src/a.rs", ks + 1, "dead_code")]),
        dummy_root(),
    );

    let v = node_in_file(&graph, "crates/x/src/a.rs", "victim");
    assert!(
        !v.rustc_flagged_dead && v.oracle_receipt.is_none(),
        "an omitted node clears the flag AND the receipt (no stale carryover)"
    );
    let s = node_in_file(&graph, "crates/x/src/a.rs", "still_dead");
    assert!(
        s.rustc_flagged_dead && s.oracle_receipt.is_some(),
        "a node present in the fresh set is re-affirmed with a FRESH receipt"
    );
}
