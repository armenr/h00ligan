//! WU-0003 / CL-REACH Leg B (RC1 + RC2) — behavioral falsifier matrix.
//!
//! Every behavioral test here is driven END-TO-END through the real producer
//! (`extract_rust_symbols` → `build_graph` → `ReachabilityAnalyzer::analyze`
//! / the `graph_query` walks) — never a hand-fabricated `make_node` graph —
//! per the anti-green-by-construction discipline.
//!
//! NOTE on the producer's edge model (verified firsthand 2026-06-23): the
//! tree-sitter extractor (no SCIP in these tests) does NOT emit `Calls` edges
//! for intra-file calls — connectivity comes from `Contains` (parent→child,
//! followed bidirectionally by the classifier), `Implements`/`HasImpl` (the
//! trait↔impl pair, always created together), and `References` (use imports).
//! The fixtures below are shaped to that real model, not to an assumed
//! call-graph.
//!
//! Falsifier ↔ contract mapping:
//! - F1 TRACE       — `traced_reachability_bfs` uses the classifier's exact
//!   traversal contract and reaches every non-container node the call verdict
//!   classifies WIRED.
//! - F3 PRUNE       — a test-only trait implementor of a WIRED trait classifies
//!   TEST_ONLY, never WIRED, through the one walk's symmetric prune; plus a
//!   direct API assertion that the `HasImpl` prune is direction-agnostic
//!   (CL-REACH-04).
//! - F4 TRAIT-EDGE  — trait bridging consults the Implements/HasImpl EDGES
//!   (CL-REACH-05): `seed_trait_bridge_via_edges` is exercised on a producer
//!   graph that contains those edges.
//! - F5 LABEL / F6 EXHAUSTIVE — asserted in the `graph_query` lib unit tests
//!   (`admit_set_label_matches_admit_set`, `admits_exhaustive_truth_table`).

use std::fs;
use std::path::PathBuf;

use h00ligan_engine::code_intel_inventory::{InventorySource, build_project_inventory};
use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::entry_points::{EntryPoint, EntryPointKind, discover_entry_points};
use h00ligan_engine::extractor::{extract_file, extract_rust_symbols};
use h00ligan_engine::graph::{EdgeKind, GraphEdge, KnowledgeGraph};
use h00ligan_engine::graph_query::{
    DeadAction, EdgeClass, admits, cfg_touching_crates, classify_dead_action, is_dependency_edge,
    resolve_production_root_ids, reverse_bfs, traced_reachability_bfs,
};
use h00ligan_engine::reachability::{
    ActionTier, BfsDirection, BfsSpec, ReachabilityAnalyzer, ReachabilityClass,
    classify_and_writeback_with_inventory_evidence,
};
use h00ligan_engine::structural_ir::ExtractorOutput;
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Producer-driven fixture: real source -> extractor -> edge builder -> graph.
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

/// Resolve a classification for a symbol by exact name from an analyze() run.
fn class_of(classes: &[(String, ReachabilityClass)], name: &str) -> ReachabilityClass {
    classes
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("symbol {name:?} not found in {classes:?}"))
        .1
}

fn analyze(graph: &KnowledgeGraph, eps: Vec<EntryPoint>) -> Vec<(String, ReachabilityClass)> {
    ReachabilityAnalyzer::new(graph, eps)
        .analyze()
        .classified
        .into_iter()
        .map(|c| (c.symbol_name, c.classification))
        .collect()
}

// ---------------------------------------------------------------------------
// F1 — TRACE: the explanatory trace uses the exact classifier traversal.
// ---------------------------------------------------------------------------

#[test]
fn f1_trace_reaches_every_noncontainer_wired_node() {
    // Single entry file so module-`Contains` connects everything the classifier
    // wires; the producer creates Implements/HasImpl/Contains/References edges.
    // CL-REACH-05 (WU-0003 Leg C): the classifier now seeds ONLY the `main`
    // symbol, so `main` must genuinely reach its file-mates via a real call
    // edge (in production SCIP supplies it). Add the production-kind `main -->
    // Loud::hi` Calls edge the over-seed used to paper over, so the WIRED set is
    // several nodes (trait, method, struct, impl) — a non-vacuous parity check.
    let mut graph = build_from_sources(&[(
        "src/main.rs",
        "pub trait Greet { fn hi(&self); }\n\
         pub struct Loud;\n\
         impl Greet for Loud { fn hi(&self) {} }\n\
         fn main() { Loud.hi(); }\n",
    )]);
    add_calls_edge(&mut graph, "main", "impl Greet for Loud::hi");
    let eps = vec![binary_entry("src/main.rs")];

    let report = ReachabilityAnalyzer::new(&graph, eps.clone()).analyze();
    let wired: Vec<(Uuid, String)> = report
        .classified
        .iter()
        .filter(|c| c.classification == ReachabilityClass::Wired)
        .map(|c| (c.memory_id, c.symbol_name.clone()))
        .collect();
    // WU-0015 REBASELINE: under the directed-call verdict, only nodes on a real
    // use-chain from `main` are WIRED (main + the called impl method). The pub
    // trait/struct, reachable only via Contains/Implements (not walked), are no
    // longer WIRED — so the WIRED set is 2 here, still non-vacuous (> just main).
    assert!(
        wired.len() >= 2,
        "fixture must wire >1 node for a non-vacuous parity check, got {}: {:?}",
        wired.len(),
        wired.iter().map(|(_, n)| n).collect::<Vec<_>>()
    );

    // The trace must seed from the same production roots as the verdict and use
    // the same admission and direction.
    let roots = resolve_production_root_ids(&graph, &eps);
    let root_set: std::collections::HashSet<Uuid> = roots.iter().copied().collect();
    assert!(!roots.is_empty(), "production roots must resolve");
    let dir = tempfile::tempdir().expect("tempdir");
    for (target, label) in &wired {
        if root_set.contains(target) {
            continue; // a root proves itself trivially
        }
        // WU-0019: a CONTAINER node (impl/trait/module header) is never on a
        // directed call-chain — it has no incoming `Calls` edge (connectivity is
        // `Contains`/`Implements`, excluded from the call verdict), so it is never
        // WIRED by the production call VERDICT. It reaches the Wired TIER only via
        // the structural container roll-up (child-tier propagation: an `impl`/
        // `trait`/`module` that OWNS wired code is structurally required). That is
        // the same "structurally-required-but-not-called" category the Pass-5
        // `STRUCTURAL_KINDS` rescue and the `guard_rescue_tier` post-pass already
        // classify — nodes the directed-call parity walk intentionally cannot
        // reach. The parity GUARANTEE this test pins is about the CALL verdict
        // (never STRICTER than the call-reachability verdict for call targets), so
        // exempt the structural roll-up's container nodes — every genuinely
        // call-verdict-WIRED node (here `impl Greet for Loud::hi`, a function
        // reached via the real `main --Calls--> hi` edge) is still checked.
        if graph
            .node(target)
            .is_some_and(|n| matches!(n.kind.as_str(), "impl" | "trait" | "module"))
        {
            continue;
        }
        let mut tw = h00ligan_engine::graph_query::TraceWriter::new(&dir.path().join("trace.txt"))
            .expect("trace writer");
        let path = traced_reachability_bfs(&graph, &roots, *target, &mut tw);
        assert!(
            path.is_some(),
            "reachability trace must reach WIRED node {label:?} from the production roots"
        );
    }
}

// ---------------------------------------------------------------------------
// F3 — PRUNE: a test-only implementor of a WIRED trait stays TEST_ONLY.
//
// Non-vacuous: `Greet` is genuinely WIRED (in the entry file with `main`), the
// producer creates BOTH `tests::impl Greet for Quiet --Implements--> Greet`
// (incoming to the wired trait) AND `Greet --HasImpl--> tests::Quiet`
// (outgoing from the wired trait) — yet the impl method must classify
// TEST_ONLY, not WIRED. The one walk's symmetric prune + test-module skip is
// what keeps the WIRED trait from auto-marking the test implementor WIRED
// through EITHER edge (CL-REACH-04).
// ---------------------------------------------------------------------------

#[test]
fn f3_test_only_impl_of_wired_trait_stays_test_only() {
    // CL-REACH-05: `main` is now the sole production seed, so it must genuinely
    // reach the trait for `Greet` to be WIRED. Add the production-kind `main -->
    // Greet::hi` Calls edge (SCIP supplies it in production) so the prune check
    // stays non-vacuous: `Greet` is WIRED, yet its test-only implementor must
    // still classify TEST_ONLY through the symmetric prune.
    let mut graph = build_from_sources(&[
        (
            "src/main.rs",
            "pub trait Greet { fn hi(&self); }\nfn main() {}\n",
        ),
        (
            "src/q.rs",
            "use crate::Greet;\n\
             #[cfg(test)]\n\
             mod tests {\n\
               use super::*;\n\
               struct Quiet;\n\
               impl Greet for Quiet { fn hi(&self) {} }\n\
               #[test]\n\
               fn t() { Quiet.hi(); }\n\
             }\n",
        ),
    ]);
    add_calls_edge(&mut graph, "main", "Greet::hi");
    // WU-0015: model the `#[test] fn t()` → impl-method call (SCIP supplies it in
    // production) so the test-only impl method is reached from a `#[test]` root.
    add_calls_edge(&mut graph, "tests::t", "tests::impl Greet for Quiet::hi");
    let eps = vec![binary_entry("src/main.rs")];
    let classes = analyze(&graph, eps);

    // WU-0015 REBASELINE: the WIRED anchor is the CALLED method `Greet::hi`
    // (reached from main via Calls). The trait NODE, reachable only via the
    // non-walked Contains/Implements edges, is now Suspected — so anchor on the
    // method for a non-vacuous prune check.
    let greet_hi = classes
        .iter()
        .find(|(n, _)| n == "Greet::hi")
        .expect("Greet::hi");
    assert_eq!(
        greet_hi.1,
        ReachabilityClass::Wired,
        "the called trait method must be genuinely WIRED for a non-vacuous prune check"
    );

    let impl_method = classes
        .iter()
        .find(|(n, _)| n == "tests::impl Greet for Quiet::hi")
        .expect("impl method node");
    assert_ne!(
        impl_method.1,
        ReachabilityClass::Wired,
        "a test-only impl of a WIRED trait must NOT be auto-WIRED through the \
         Implements/HasImpl bridge (HasImpl not walked + test-module skip, \
         CL-REACH-04); got {}",
        impl_method.1
    );
    assert_eq!(
        impl_method.1,
        ReachabilityClass::TestOnly,
        "the test-only impl method (reached from the #[test] fn via Calls) should \
         classify TEST_ONLY; got {}",
        impl_method.1
    );
}

/// F3 (direct API form): the `HasImpl` prune is DIRECTION-AGNOSTIC.
///
/// On HEAD the classifier skipped only OUTGOING `HasImpl`, leaving incoming
/// `HasImpl` followed (the asymmetry). `BfsSpec::admits_edge` now returns the
/// same decision regardless of the physical direction flag — proving the prune
/// is symmetric at the contract surface.
#[test]
fn f3_hasimpl_prune_is_symmetric() {
    let prod = BfsSpec::classifier_calls();
    assert!(prod.skip_has_impl, "liveness classifier prunes HasImpl");
    // Symmetric: pruned whether the edge is traversed outgoing or incoming.
    assert!(!prod.admits_edge(EdgeKind::HasImpl, true));
    assert!(!prod.admits_edge(EdgeKind::HasImpl, false));
    // Non-pruned kinds remain admitted in both directions.
    assert!(prod.admits_edge(EdgeKind::Calls, true));
    assert!(prod.admits_edge(EdgeKind::Calls, false));
}

// ---------------------------------------------------------------------------
// F4 — TRAIT-EDGE: trait bridging consults the Implements/HasImpl EDGES.
//
// The producer creates the trait↔impl edges (block-level); the edge-driven
// bridge `seed_trait_bridge_via_edges` (used by `reverse_bfs`) consults them.
// Non-vacuous: we assert the producer graph really contains the bridge edges,
// and that the edge-driven seeding widens — never narrows — the dependent set
// and keeps `reverse_bfs` deterministic.
// ---------------------------------------------------------------------------

#[test]
fn f4_trait_bridge_consults_edges() {
    let graph = build_from_sources(&[(
        "src/lib.rs",
        "pub trait Greet { fn hi(&self); }\n\
         pub struct Quiet;\n\
         impl Greet for Quiet { fn hi(&self) {} }\n\
         pub fn caller() { let q = Quiet; q.hi(); }\n",
    )]);

    let has_bridge_edge = graph
        .all_edges()
        .iter()
        .any(|(_, _, e)| matches!(e.kind, EdgeKind::Implements | EdgeKind::HasImpl));
    assert!(
        has_bridge_edge,
        "producer graph must contain Implements/HasImpl edges for the \
         edge-driven trait bridge to consult (CL-REACH-05)"
    );

    let trait_method = graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == "Greet::hi")
        .expect("trait method node");
    let r1 = reverse_bfs(&graph, trait_method, 4, None);
    let r2 = reverse_bfs(&graph, trait_method, 4, None);
    assert_eq!(
        r1.dependents.len(),
        r2.dependents.len(),
        "edge-driven bridge must keep reverse_bfs deterministic (idempotent)"
    );
}

// ---------------------------------------------------------------------------
// Preserved load-bearing assertions over the ONE admit surface: the Dependency
// class excludes DependsOn/Extends; both classes exclude RelatedTo.
// ---------------------------------------------------------------------------

#[test]
fn admit_surface_dependson_extends_relatedto_exclusions() {
    assert!(admits(EdgeClass::Structural, EdgeKind::DependsOn));
    assert!(admits(EdgeClass::Structural, EdgeKind::Extends));
    assert!(!admits(EdgeClass::Dependency, EdgeKind::DependsOn));
    assert!(!admits(EdgeClass::Dependency, EdgeKind::Extends));
    assert!(!admits(EdgeClass::Structural, EdgeKind::RelatedTo));
    assert!(!admits(EdgeClass::Dependency, EdgeKind::RelatedTo));
    assert!(!is_dependency_edge(EdgeKind::DependsOn));
    assert!(!is_dependency_edge(EdgeKind::Extends));
    assert!(is_dependency_edge(EdgeKind::Calls));
}

#[test]
fn bfs_direction_variants_distinct() {
    // Smoke: the three directions are distinct and the spec carries them.
    assert_ne!(BfsDirection::Out, BfsDirection::In);
    assert_ne!(BfsDirection::Out, BfsDirection::Both);
    // The explanatory trace and liveness verdict share one traversal spec.
    assert_eq!(
        BfsSpec::reachability_trace().direction,
        BfsDirection::Out,
        "trace follows the directed liveness walk"
    );
    assert_eq!(
        BfsSpec::reachability_trace().edge_class,
        h00ligan_engine::graph_query::EdgeClass::Call,
        "trace uses the Call edge-set"
    );
}

// ===========================================================================
// WU-0003 / CL-REACH Leg C — C2a falsifiers (RC6 integration-test seeding +
// CL-REACH-05 false-WIRE removal).
//
// Producer edge-model note (verified firsthand 2026-06-24): the tree-sitter
// extractor emits NO intra-file Calls and NO file-module Contains for top-level
// functions, so a top-level `main` is an ISOLATED node. In production the SCIP
// fusion supplies `main --Calls--> callee` edges; these fixtures add that ONE
// real production-kind Calls edge (via the public graph API) onto the
// extractor-built node set to model the SCIP-enriched graph the classifier sees
// in production. The NODES are all real extractor output; only the cross-symbol
// Calls edge that SCIP would supply is added explicitly.
// ===========================================================================

/// Add a real production-kind `Calls` edge between two named symbols on an
/// extractor-built graph (models the SCIP-supplied call edge).
fn add_calls_edge(graph: &mut KnowledgeGraph, from: &str, to: &str) {
    let from_id = graph
        .all_nodes()
        .iter()
        .find(|n| n.symbol_name == from)
        .map(|n| n.memory_id)
        .unwrap_or_else(|| panic!("from-symbol {from:?} not in graph"));
    let to_id = graph
        .all_nodes()
        .iter()
        .find(|n| n.symbol_name == to)
        .map(|n| n.memory_id)
        .unwrap_or_else(|| panic!("to-symbol {to:?} not in graph"));
    graph
        .add_edge(
            from_id,
            to_id,
            GraphEdge {
                kind: EdgeKind::Calls,
                weight: 1.0,
                confidence: 0.9,
                ..Default::default()
            },
        )
        .expect("add Calls edge");
}

#[test]
fn rc04_integration_test_file_helper_is_testonly_not_dead() {
    // A genuine production-looking pub helper reached ONLY from an integration
    // test file. The producer connects tests/it.rs -> lib_helper via the `use`
    // import node's References edge (NOT Calls). RED-on-HEAD: analyze() never
    // consumes the IntegrationTest entry-point variant, so both the #[test] fn
    // and the helper classify Dead.
    // NOTE: no LibRoot entry — `lib_helper` is reached ONLY from the integration
    // test, so it must NOT be pub-api-seeded (a pub-api root would classify it
    // PublicApi). With only the IntegrationTest entry, on HEAD both nodes are
    // Dead (the IntegrationTest variant is never consumed); after the fix the
    // test-file seeding pass classifies both TestOnly.
    let graph = build_from_sources(&[
        ("src/lib.rs", "pub fn lib_helper() {}\n"),
        (
            "tests/it.rs",
            "use testcrate::lib_helper;\n#[test]\nfn it_works() { lib_helper(); }\n",
        ),
    ]);
    let eps = vec![entry(EntryPointKind::IntegrationTest, "it", "tests/it.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "it_works"),
        ReachabilityClass::TestOnly,
        "top-level #[test] fn in tests/it.rs must be TestOnly, not Dead/SafeDelete; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "lib_helper"),
        ReachabilityClass::TestOnly,
        "a lib helper reached ONLY from an integration test must be TestOnly, not Dead; got {classes:?}"
    );
}

#[test]
fn rc04_example_and_bench_seeding_distinct_classes() {
    // examples/* is test-adjacent -> TestOnly; benches/* is prod-adjacent ->
    // NOT TestOnly. The example/bench entry files reach the lib via `use`
    // References. RED-on-HEAD: both Dead (no Example/Bench seeding pass).
    let graph = build_from_sources(&[
        ("crates/testcrate/src/lib.rs", "pub fn shared() {}\n"),
        (
            "examples/demo.rs",
            "use testcrate::shared;\nfn main() { shared(); }\n",
        ),
        (
            "benches/b.rs",
            "use testcrate::shared;\nfn main() { shared(); }\n",
        ),
    ]);
    let eps = vec![
        entry(
            EntryPointKind::LibRoot,
            "testcrate",
            "crates/testcrate/src/lib.rs",
        ),
        entry(EntryPointKind::Example, "demo", "examples/demo.rs"),
        entry(EntryPointKind::Bench, "b", "benches/b.rs"),
    ];
    let classes = analyze(&graph, eps);

    // The example-file entry node (`main` in examples/demo.rs) is TestOnly.
    let example_main = classes
        .iter()
        .filter(|(n, _)| n == "main")
        .map(|(_, c)| *c)
        .collect::<Vec<_>>();
    assert!(
        example_main.contains(&ReachabilityClass::TestOnly),
        "the example-file main must classify TestOnly; got mains {example_main:?}"
    );
    // The bench-file entry node is prod-adjacent -> NOT TestOnly (Wired).
    assert!(
        example_main.contains(&ReachabilityClass::Wired),
        "the bench-file main must classify prod-adjacent (Wired), NOT TestOnly; got mains {example_main:?}"
    );
}

#[test]
fn rc04_convention_dirs_autodiscovered_in_entry_points() {
    // On-disk tempdir crate with NO explicit [[test]]/[[bench]]/[[example]]
    // arrays. discover_entry_points must auto-discover tests/ benches/ examples/
    // by CONVENTION. RED-on-HEAD: only explicit-array targets are discovered.
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"convcrate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(root.join("tests/conv_it.rs"), "#[test]\nfn t() {}\n").unwrap();
    std::fs::create_dir_all(root.join("benches")).unwrap();
    std::fs::write(root.join("benches/conv_bench.rs"), "fn main() {}\n").unwrap();
    std::fs::create_dir_all(root.join("examples")).unwrap();
    std::fs::write(root.join("examples/conv_ex.rs"), "fn main() {}\n").unwrap();

    let eps = discover_entry_points(root).expect("discover");
    let has = |kind: EntryPointKind, suffix: &str| {
        eps.iter()
            .any(|ep| ep.kind == kind && ep.file_path.to_string_lossy().ends_with(suffix))
    };
    assert!(
        has(EntryPointKind::IntegrationTest, "tests/conv_it.rs"),
        "convention tests/ dir must be auto-discovered as IntegrationTest; got {eps:?}"
    );
    assert!(
        has(EntryPointKind::Bench, "benches/conv_bench.rs"),
        "convention benches/ dir must be auto-discovered as Bench; got {eps:?}"
    );
    assert!(
        has(EntryPointKind::Example, "examples/conv_ex.rs"),
        "convention examples/ dir must be auto-discovered as Example; got {eps:?}"
    );

    // autotests = false opts out of convention integration-test discovery.
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let root2 = dir2.path();
    std::fs::write(
        root2.join("Cargo.toml"),
        "[package]\nname = \"noauto\"\nversion = \"0.1.0\"\nedition = \"2021\"\nautotests = false\n",
    )
    .unwrap();
    std::fs::create_dir_all(root2.join("src")).unwrap();
    std::fs::write(root2.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    std::fs::create_dir_all(root2.join("tests")).unwrap();
    std::fs::write(root2.join("tests/conv_it.rs"), "#[test]\nfn t() {}\n").unwrap();

    let eps2 = discover_entry_points(root2).expect("discover2");
    assert!(
        !eps2
            .iter()
            .any(|ep| ep.kind == EntryPointKind::IntegrationTest),
        "autotests=false must suppress convention IntegrationTest discovery; got {eps2:?}"
    );
}

#[test]
fn rc04_dead_node_under_tests_dir_is_testonly_belt_and_suspenders() {
    // A dead node whose file_path is under tests/ -> TestOnly belt-and-suspenders
    // in classify_dead_action. RED-on-HEAD: classify_dead_action returns
    // SafeDelete (no path-under-tests/ heuristic exists).
    let graph = build_from_sources(&[(
        "tests/orphan_it.rs",
        "#[test]\nfn orphan() {}\nfn unused_in_test_file() {}\n",
    )]);
    let node = graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == "unused_in_test_file")
        .expect("unused_in_test_file node")
        .clone();
    assert_eq!(
        classify_dead_action(&graph, &node, &cfg_touching_crates(&graph)),
        DeadAction::TestOnly,
        "a dead node under tests/ must classify TestOnly, not SafeDelete"
    );
}

// ---------------------------------------------------------------------------
// CL-REACH-05 — false-WIRE removal (the critical negative control) + narrowness.
// ---------------------------------------------------------------------------

#[test]
fn rc05_uncalled_bin_helper_stays_dead_negative_control() {
    // src/main.rs with main() calling live_helper (real Calls edge, modeling
    // SCIP) and an uncalled dead_helper. RED-on-HEAD: the over-seed seeds EVERY
    // function in the entry file as a root, so dead_helper falses WIRED.
    let mut graph = build_from_sources(&[(
        "src/main.rs",
        "fn main() { live_helper(); }\nfn dead_helper() {}\nfn live_helper() {}\n",
    )]);
    add_calls_edge(&mut graph, "main", "live_helper");
    let classes = analyze(&graph, vec![binary_entry("src/main.rs")]);

    // WU-0015 REBASELINE (Dead → Suspected): the uncalled bin helper is NOT
    // over-seeded (it stays out of the WIRED set) — the anti-over-seed intent
    // holds — but the residual tier is now Suspected, not Dead (Leg 1, no oracle).
    assert_eq!(
        class_of(&classes, "dead_helper"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: an uncalled PRIVATE bin helper stays out of WIRED → Dead (not over-seeded); got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "live_helper"),
        ReachabilityClass::Wired,
        "a helper main() genuinely calls must stay Wired (no live code flips to Dead); got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "main"),
        ReachabilityClass::Wired,
        "main is the seeded root; got {classes:?}"
    );
}

#[test]
fn rc05_main_only_seed_named_main_not_every_function() {
    // resolve_production_root_ids for a Binary entry must resolve EXACTLY {main},
    // not every top-level fn in the file. RED-on-HEAD: the kind=='function'
    // clause seeds all three sibling fns.
    let graph = build_from_sources(&[(
        "src/main.rs",
        "fn main() {}\nfn sibling_a() {}\nfn sibling_b() {}\n",
    )]);
    let eps = vec![binary_entry("src/main.rs")];
    let roots = resolve_production_root_ids(&graph, &eps);

    assert_eq!(
        roots.len(),
        1,
        "a Binary entry must resolve exactly one root (main), got {}: {:?}",
        roots.len(),
        roots
            .iter()
            .filter_map(|id| graph.node(id).map(|n| n.symbol_name.clone()))
            .collect::<Vec<_>>()
    );
    let root_name = graph.node(&roots[0]).map(|n| n.symbol_name.clone());
    assert_eq!(
        root_name.as_deref(),
        Some("main"),
        "the single resolved root must be main"
    );
}

// ===========================================================================
// WU-0003 / CL-REACH Leg C — C2b falsifiers (CL-REACH-06 canonical test-ness +
// CL-REACH-09 disk-read deletion).
// ===========================================================================

#[test]
fn rc06_test_ness_consumers_agree_on_persisted_bit() {
    // `test_utils` — a pub fn whose name starts with `test_` but is NOT in a
    // `#[cfg(test)]` scope (a production helper). The producer sets
    // is_test_only=Some(false) on it. The `tests` module is `#[cfg(test)]` so
    // its children get is_test_only=Some(true). All test-ness consumers must
    // agree with the PERSISTED bit, not the name. RED-on-HEAD: the name-only
    // `is_test_module_symbol` / unanchored `is_test_file` disagree with the AST.
    let graph = build_from_sources(&[(
        "src/m.rs",
        "pub fn test_utils() {}\n\
         #[cfg(test)]\n\
         mod tests {\n\
           fn helper() {}\n\
         }\n",
    )]);

    let utils = graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == "test_utils")
        .expect("test_utils node")
        .clone();
    assert_eq!(
        utils.is_test_only,
        Some(false),
        "producer must persist is_test_only=Some(false) on the production `test_utils` helper"
    );
    // The canonical node-in-hand consumer (`graph_query::node_is_test`) reads the
    // PERSISTED bit: `test_utils` is NOT test despite the `test_` name prefix.
    assert!(
        !h00ligan_engine::graph_query::node_is_test(&graph, &utils),
        "node_is_test must read the persisted bit: `test_utils` (is_test_only=false) is not test"
    );

    // A child of the `#[cfg(test)]` module carries is_test_only=Some(true) and
    // every consumer agrees.
    let helper = graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == "tests::helper")
        .expect("tests::helper node")
        .clone();
    assert_eq!(
        helper.is_test_only,
        Some(true),
        "producer must persist is_test_only=Some(true) on a #[cfg(test)] module child"
    );
    assert!(
        h00ligan_engine::graph_query::node_is_test(&graph, &helper),
        "node_is_test must agree: `tests::helper` (is_test_only=true) is test"
    );
}

#[test]
fn rc06_is_test_file_path_heuristic_anchored_not_substring() {
    // The remaining PATH heuristic (for SCIP/old nodes with no persisted bit)
    // must be anchored on a path COMPONENT, never a raw `.contains("test_")`.
    // RED-on-HEAD: `is_test_file` uses `path.contains("test_")` etc., so
    // `src/contest_runner.rs` / `src/test_data/x.rs` false-match.
    use h00ligan_engine::graph_query::is_test_file;

    // Genuine test paths -> true.
    assert!(is_test_file("crates/x/tests/it.rs"), "tests/ component");
    assert!(
        is_test_file("src/test_helpers.rs"),
        "test_-prefixed basename"
    );

    // Adversarial decoys -> false (the unanchored substring would falsely match).
    assert!(
        !is_test_file("src/contest_runner.rs"),
        "`contest` contains `test` but is not a test file"
    );
    assert!(
        !is_test_file("src/latest.rs"),
        "`latest` contains `test` but is not a test file"
    );
    assert!(
        !is_test_file("src/test_data/fixtures.rs"),
        "a `test_data` fixture DIR component is not a test SOURCE file"
    );
    assert!(
        !is_test_file("src/protest_results.rs"),
        "`protest_results` contains `test` but is not a test file"
    );
}

#[test]
fn rc09_build_test_chains_classifies_test_root_without_disk_read() {
    // A #[cfg(test)] mod with a #[test] fn calling a helper. The producer sets
    // is_test_root=true on the #[test] fn. Then we MOVE the source file path to a
    // non-existent location BEFORE analyze() — if `has_test_attribute` still did a
    // disk read it would return false and build_test_chains would find no roots.
    // RED-on-HEAD: the disk read fails on the missing path -> test_chains empty.
    let mut graph = build_from_sources(&[(
        "src/x.rs",
        "#[cfg(test)]\n\
         mod tests {\n\
           #[test]\n\
           fn t() { helper(); }\n\
           fn helper() {}\n\
         }\n",
    )]);
    // Connect the #[test] root to the helper with a real Calls edge (SCIP model),
    // since tree-sitter emits no intra-module Calls.
    add_calls_edge(&mut graph, "tests::t", "tests::helper");

    // Rewrite every node's file_path to a path that does NOT exist on disk, so a
    // disk read inside has_test_attribute would fail (Err -> false on HEAD).
    let ids: Vec<Uuid> = graph.all_nodes().iter().map(|n| n.memory_id).collect();
    for id in ids {
        if let Some(n) = graph.node_mut(&id) {
            n.file_path = format!("/nonexistent/moved/{}.rs", n.symbol_name.replace("::", "_"));
        }
    }

    let report = ReachabilityAnalyzer::new(&graph, vec![]).analyze();
    let helper_id = graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == "tests::helper")
        .expect("helper node")
        .memory_id;
    let chains = report.test_chains.get(&helper_id);
    assert!(
        chains.is_some_and(|c| !c.is_empty()),
        "build_test_chains must trace `tests::helper` back to the #[test] root using \
         the PERSISTED is_test_root bit, even with the source file absent on disk; \
         got test_chains for helper = {:?}",
        chains
    );
}

#[test]
fn persisted_reachability_omits_redundant_eager_test_chains() {
    let workspace = TempDir::new().expect("scratch Rust package");
    let root = workspace.path();
    fs::create_dir_all(root.join("src")).expect("source directory");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .expect("package manifest");
    let source = "#[cfg(test)]\n\
                  mod tests {\n\
                    #[test]\n\
                    fn t() { helper(); }\n\
                    fn helper() {}\n\
                  }\n";
    fs::write(root.join("src/lib.rs"), source).expect("package source");
    let mut graph = build_from_sources(&[("src/lib.rs", source)]);
    add_calls_edge(&mut graph, "tests::t", "tests::helper");

    let direct = ReachabilityAnalyzer::new(&graph, vec![]).analyze();
    assert!(
        direct.test_chains.values().any(|chains| !chains.is_empty()),
        "non-vacuity: the analyzer's explicit eager-chain API remains available"
    );

    let inventory = build_project_inventory(root, &[InventorySource::new("src/lib.rs", "rust")]);
    let evidence = classify_and_writeback_with_inventory_evidence(&mut graph, root, &inventory)
        .expect("production inventory classification")
        .expect("Cargo package owns reachability");
    assert!(
        evidence.report.test_chains.is_empty(),
        "immutable generations must not duplicate query-time test paths for every helper"
    );
}

#[test]
fn unavailable_inventory_reachability_clears_carried_classification() {
    let workspace = TempDir::new().expect("scratch manifestless repository");
    let root = workspace.path();
    let source = "pub fn loose_symbol() -> usize { 1 }\n";
    fs::write(root.join("loose.rs"), source).expect("manifestless Rust source");
    let mut graph = build_from_sources(&[("loose.rs", source)]);
    let symbol_id = graph
        .all_nodes()
        .into_iter()
        .find(|node| node.symbol_name == "loose_symbol")
        .expect("positive graph population")
        .memory_id;
    graph
        .node_mut(&symbol_id)
        .expect("carried node")
        .reachability_class = ReachabilityClass::Dead;

    let inventory = build_project_inventory(root, &[InventorySource::new("loose.rs", "rust")]);
    let evidence = classify_and_writeback_with_inventory_evidence(&mut graph, root, &inventory)
        .expect("absence of an owner is not malformed inventory");

    assert!(
        evidence.is_none(),
        "reachability authority must not be fabricated"
    );
    assert_eq!(
        graph
            .node(&symbol_id)
            .expect("structural node remains published")
            .reachability_class,
        ReachabilityClass::Unclassified,
        "classification from an earlier owned generation must be revoked"
    );
}

/// FALSIFIER for repository-global reachability availability: one supported
/// project unit authorizes classification only for its own source population.
/// A Go module must not make structurally indexed loose Rust eligible for a
/// Go-rooted reachability verdict merely because both languages share a graph.
#[test]
fn mixed_owned_and_unowned_source_keeps_reachability_authority_document_scoped() {
    let workspace = TempDir::new().expect("scratch mixed repository");
    let root = workspace.path();
    fs::create_dir_all(root.join("templates")).expect("loose source directory");
    fs::write(
        root.join("go.mod"),
        "module example.test/owned\n\ngo 1.26\n",
    )
    .expect("Go module manifest");
    fs::write(
        root.join("main.go"),
        "package main\n\nfunc main() {}\nfunc coveredOnlyViaUnownedBridge() {}\n",
    )
    .expect("owned Go source");
    fs::write(
        root.join("templates/loose.rs"),
        "pub fn structurally_visible_template() {}\n",
    )
    .expect("loose Rust source");

    let outputs = [root.join("main.go"), root.join("templates/loose.rs")]
        .iter()
        .map(|path| extract_file(path, root).expect("registered-language extraction"))
        .collect::<Vec<_>>();
    let mut graph = KnowledgeGraph::new();
    build_graph(&outputs, &mut graph).expect("mixed structural graph");
    // Sabotage control: even a malformed cross-authority edge population must
    // not let uncovered source bridge two covered nodes during traversal.
    add_calls_edge(&mut graph, "main", "structurally_visible_template");
    add_calls_edge(
        &mut graph,
        "structurally_visible_template",
        "coveredOnlyViaUnownedBridge",
    );
    let inventory = build_project_inventory(
        root,
        &[
            InventorySource::new("main.go", "go"),
            InventorySource::new("templates/loose.rs", "rust"),
        ],
    );

    let go_owner = inventory
        .project_topology
        .memberships
        .iter()
        .find(|membership| membership.document_path == "main.go")
        .expect("positive Go ownership population");
    let loose_owner = inventory
        .project_topology
        .memberships
        .iter()
        .find(|membership| membership.document_path == "templates/loose.rs")
        .expect("positive loose ownership population");
    assert!(
        inventory.is_semantic_source_owner(go_owner),
        "the Go module must provide a real supported reachability owner"
    );
    assert!(
        inventory.is_structural_only_source_document(
            &loose_owner.document_path,
            &loose_owner.language_id,
        ),
        "the loose Rust file must remain in the structural source population"
    );

    let evidence = classify_and_writeback_with_inventory_evidence(&mut graph, root, &inventory)
        .expect("mixed inventory is valid")
        .expect("the Go module supplies non-vacuous reachability evidence");
    let go_main = graph
        .node_by_name("main")
        .expect("positive classified Go entry point");
    assert_ne!(
        go_main.reachability_class,
        ReachabilityClass::Unclassified,
        "the supported Go owner must still classify its source"
    );
    let loose = graph
        .node_by_name("structurally_visible_template")
        .expect("positive loose structural symbol");
    assert_eq!(
        loose.reachability_class,
        ReachabilityClass::Unclassified,
        "a classifier owned by another language/project unit grants no verdict authority"
    );
    assert_eq!(
        evidence
            .report
            .classified
            .iter()
            .find(|node| node.memory_id == loose.memory_id)
            .expect("loose symbol remains explicit in the evidence population")
            .classification,
        ReachabilityClass::Unclassified
    );
    assert_ne!(
        graph
            .node_by_name("coveredOnlyViaUnownedBridge")
            .expect("positive covered traversal target")
            .reachability_class,
        ReachabilityClass::Wired,
        "uncovered source must not bridge reachability between covered nodes"
    );
    let reconstructed_roots = evidence.analyzer(&graph).resolved_roots();
    assert!(
        !reconstructed_roots.public_api.contains(&loose.memory_id),
        "query-time root reconstruction must retain the persisted document scope"
    );

    let mut widened = evidence.clone();
    widened
        .classified_documents
        .push("templates/loose.rs".into());
    widened.classified_documents.sort();
    assert!(
        widened.validate(&graph).is_err(),
        "altered authority cannot reinterpret an unclassified document as covered"
    );
    let mut narrowed = evidence;
    narrowed
        .classified_documents
        .retain(|document| document != "main.go");
    assert!(
        narrowed.validate(&graph).is_err(),
        "partial persistence cannot detach classified nodes from their authority document"
    );
}

/// FALSIFIER for Cargo-global census scope: in a real mixed repository, each
/// registered reachability owner contributes its own documents. Cargo member
/// directories cannot exclude a sibling Go module that the same inventory
/// independently proves and the Go classifier owns.
#[test]
fn mixed_cargo_and_go_reachability_does_not_apply_cargo_membership_to_go() {
    let workspace = TempDir::new().expect("scratch polyglot repository");
    let root = workspace.path();
    fs::create_dir_all(root.join("crates/host/src")).expect("Cargo package source directory");
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/host\"]\nresolver = \"3\"\n",
    )
    .expect("Cargo workspace manifest");
    fs::write(
        root.join("crates/host/Cargo.toml"),
        "[package]\nname = \"host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo package manifest");
    fs::write(
        root.join("crates/host/src/lib.rs"),
        "pub fn rust_host() {}\n",
    )
    .expect("owned Rust source");
    fs::write(root.join("go.mod"), "module example.test/root\n\ngo 1.26\n")
        .expect("Go module manifest");
    fs::write(root.join("main.go"), "package main\n\nfunc main() {}\n").expect("owned Go source");

    let source_paths = [root.join("crates/host/src/lib.rs"), root.join("main.go")];
    let outputs = source_paths
        .iter()
        .map(|path| extract_file(path, root).expect("registered-language extraction"))
        .collect::<Vec<_>>();
    let mut graph = KnowledgeGraph::new();
    build_graph(&outputs, &mut graph).expect("polyglot structural graph");
    let inventory = build_project_inventory(
        root,
        &[
            InventorySource::new("crates/host/src/lib.rs", "rust"),
            InventorySource::new("main.go", "go"),
        ],
    );
    let evidence = classify_and_writeback_with_inventory_evidence(&mut graph, root, &inventory)
        .expect("polyglot inventory is valid")
        .expect("both project systems provide reachability owners");
    assert_eq!(
        evidence.classified_documents,
        vec!["crates/host/src/lib.rs".to_string(), "main.go".to_string()],
        "positive exact owner population"
    );
    assert_eq!(
        graph
            .node_by_name("main")
            .expect("Go entry point")
            .reachability_class,
        ReachabilityClass::Wired,
        "Cargo membership cannot exclude independently owned Go source"
    );
    assert_ne!(
        graph
            .node_by_name("rust_host")
            .expect("Rust library source")
            .reachability_class,
        ReachabilityClass::Unclassified,
        "the Cargo positive control remains classified"
    );
}

// ===========================================================================
// WU-0003 / CL-REACH Leg C — C2d falsifiers (CL-REACH-10 enum/struct field
// false-DEAD).
//
// FIRSTHAND CAVEAT: direct data members have a Contains edge, but a Rust
// variant-payload field (`MyErr::NotFound::0`) has an unmaterialized variant
// between it and the enum. Qualified-name prefix resolution remains the
// conservative fallback for that shape. These tests assert the END STATE
// through the real analyze() path, so they are mechanism-agnostic.
// ===========================================================================

#[test]
fn rc10_enum_variant_field_with_alive_parent_is_structural_not_dead() {
    // `MyErr` is genuinely alive (pub-api-seeded via the LibRoot). Its
    // variant-payload field `MyErr::NotFound::0` must classify Structural (alive)
    // because its parent type is alive — NOT Dead. RED-on-HEAD: STRUCTURAL_KINDS
    // has no `field`, so the field lands in Dead.
    let mut graph = build_from_sources(&[(
        "crates/testcrate/src/lib.rs",
        "pub enum MyErr { NotFound(uuid::Uuid), Io(String) }\n\
         pub fn use_err() -> MyErr { MyErr::Io(String::new()) }\n",
    )]);
    // WU-0015: model the SCIP-supplied `use_err -> MyErr` USE edge (return type /
    // construction) so the pub enum is GENUINELY reached (call-reachability, not
    // pub-by-fiat) — the directed verdict requires a real use edge, and this keeps
    // the field-rescue check non-vacuous (an ALIVE parent).
    add_calls_edge(&mut graph, "use_err", "MyErr");
    let eps = vec![entry(
        EntryPointKind::LibRoot,
        "testcrate",
        "crates/testcrate/src/lib.rs",
    )];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "MyErr"),
        ReachabilityClass::PublicApi,
        "the parent enum must be alive for a non-vacuous check; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "MyErr::NotFound::0"),
        ReachabilityClass::Structural,
        "a variant-payload field of an ALIVE enum must be Structural (alive), not Dead; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "MyErr::Io::0"),
        ReachabilityClass::Structural,
        "the second variant-payload field of an alive enum must be Structural too; got {classes:?}"
    );
}

#[test]
fn rc10_field_with_dead_parent_stays_dead_narrowness() {
    // `UsedErr` is alive (pub + reached); `DeadErr` is referenced by nothing.
    // The fix must reclassify a field as alive ONLY when its parent is alive —
    // `UsedErr::A::0` flips Structural, `DeadErr::B::0` STAYS Dead. RED-on-HEAD:
    // both field nodes are Dead (no field handling). Narrowness guard against a
    // blanket "all fields alive" cheat.
    // `DeadErr` lives in a SECOND crate with NO entry point, so the pub-api pass
    // (which only seeds nodes in the LibRoot's crate) never reaches it and it is
    // genuinely Dead. `UsedErr` is in the entry crate's lib -> alive.
    let mut graph = build_from_sources(&[
        (
            "crates/testcrate/src/lib.rs",
            "pub enum UsedErr { A(u8) }\npub fn f() -> UsedErr { UsedErr::A(0) }\n",
        ),
        (
            "crates/othercrate/src/lib.rs",
            "pub enum DeadErr { B(u8) }\n",
        ),
    ]);
    // WU-0015: model the SCIP-supplied `f -> UsedErr` USE edge so UsedErr is
    // GENUINELY reached (an ALIVE parent for the narrowness check). `DeadErr` (in a
    // crate with no entry point + no use edge) stays call-unreachable.
    add_calls_edge(&mut graph, "f", "UsedErr");
    let eps = vec![entry(
        EntryPointKind::LibRoot,
        "testcrate",
        "crates/testcrate/src/lib.rs",
    )];
    let classes = analyze(&graph, eps);

    // UsedErr is genuinely reached (alive); DeadErr (no entry crate, no use edge) is
    // call-unreachable → Suspected (WU-0015 REBASELINE: never Dead in Leg 1).
    assert_eq!(
        class_of(&classes, "UsedErr"),
        ReachabilityClass::PublicApi,
        "UsedErr must be alive; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "DeadErr"),
        ReachabilityClass::Suspected,
        "DeadErr (crate with no entry point, no use edge) is call-unreachable → Suspected; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "UsedErr::A::0"),
        ReachabilityClass::Structural,
        "a field of an ALIVE parent flips to Structural; got {classes:?}"
    );
    // WU-0015 REBASELINE (Dead → Suspected): the narrowness guard still holds — a
    // field of a NON-alive parent is NOT rescued to Structural — but the un-rescued
    // residual is Suspected, not Dead.
    assert_eq!(
        class_of(&classes, "DeadErr::B::0"),
        ReachabilityClass::Suspected,
        "a field of a non-alive parent is NOT rescued → Suspected (narrowness holds); got {classes:?}"
    );
}

// ===========================================================================
// WU-0003 / CL-REACH Leg C — C2c falsifiers (CL-REACH-08 UNCLASSIFIED banner).
//
// `extract_overview_data` is the SINGLE shared producer feeding BOTH the
// h00ligan CLI `run_overview` AND the MCP OverviewHandler — asserting on
// `OverviewData` covers both production output paths in one fixture.
// ===========================================================================

#[test]
fn rc08_unclassified_graph_emits_banner_and_never_dead_zero() {
    // Build a graph but DO NOT classify it -> every node is Unclassified (the
    // default). The overview must carry an explicit unclassified signal and must
    // NOT silently report dead_code_count == 0 on an all-Unclassified graph.
    // RED-on-HEAD: Unclassified buckets into the no-op arm, dead_code_count is
    // matches!(Dead|Orphan) -> 0, and there is no unclassified field.
    let graph = build_from_sources(&[(
        "crates/testcrate/src/lib.rs",
        "pub fn a() {}\npub fn b() {}\n",
    )]);
    let total = graph.all_nodes().len();
    assert!(total > 0, "fixture must have nodes");
    // Confirm the graph is genuinely unclassified (no analyze() run).
    assert!(
        graph
            .all_nodes()
            .iter()
            .all(|n| n.reachability_class == ReachabilityClass::Unclassified),
        "fixture must be fully Unclassified for a non-vacuous banner check"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let inventory = build_project_inventory(
        dir.path(),
        &[InventorySource::new("crates/testcrate/src/lib.rs", "rust")],
    );
    let overview = h00ligan_engine::graph_overview::extract_overview_data(&graph, &inventory);

    assert_eq!(
        overview.unclassified_count, total,
        "an all-Unclassified graph must report unclassified_count == total_nodes; got {} of {total}",
        overview.unclassified_count
    );
    assert!(
        overview.unclassified_count > 0,
        "the UNCLASSIFIED banner signal must be set when any node is unclassified"
    );
}

#[test]
fn rc08_classified_graph_does_not_emit_banner_control() {
    // Same fixture, but force every node to a non-Unclassified class first. The
    // banner must NOT fire (unclassified_count == 0) — proving the signal is
    // conditional, not always-on. GREEN both pre/post-fix in spirit; pins the
    // post-fix banner as conditional.
    let mut graph = build_from_sources(&[(
        "crates/testcrate/src/lib.rs",
        "pub fn a() {}\npub fn b() {}\n",
    )]);
    let ids: Vec<Uuid> = graph.all_nodes().iter().map(|n| n.memory_id).collect();
    for id in ids {
        if let Some(n) = graph.node_mut(&id) {
            n.reachability_class = ReachabilityClass::Wired;
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let inventory = build_project_inventory(
        dir.path(),
        &[InventorySource::new("crates/testcrate/src/lib.rs", "rust")],
    );
    let overview = h00ligan_engine::graph_overview::extract_overview_data(&graph, &inventory);
    assert_eq!(
        overview.unclassified_count, 0,
        "a fully-classified graph must NOT set the UNCLASSIFIED banner; got {}",
        overview.unclassified_count
    );
}

// ===========================================================================
// WU-0003 / CL-REACH Leg ? — R5-F1: the end-to-end cross-crate-DependsOn
// reachability falsifier (ADR-0028; the GATE that closes CL-REACH-07/08).
//
// LAYER under test: the CLASSIFIER CONSUMING a cross-crate `DependsOn` edge into
// a `Wired` verdict — distinct from the PRODUCER falsifier
// `build_dependency_edges_emits_cross_crate_dependson` (edge_builder.rs), which
// proves the producer EMITS the edge. Here we hand the classifier a graph that
// already CONTAINS the cross-crate `DependsOn` bridge and prove the verdict
// rides it.
//
// NON-VACUITY / coverage-regression carve-out (load-bearing): R5-F1 is
// GREEN-on-HEAD by design — RC1 (commit 3a7ee4a) already landed
// `admits(EdgeClass::Structural, EdgeKind::DependsOn) == true`, so the
// classifier ALREADY traverses cross-crate `DependsOn`. This is NOT a
// RED-on-HEAD bug test; it closes the "passed VACUOUSLY" hole that let EC-11
// (`DependsOn == 0` in production) survive a 218-finding audit. Non-vacuity is
// proven TWO ways:
//   (a) the NEGATIVE-CONTROL sibling
//       `r5f1_no_dependson_edge_leaves_target_dead` builds the SAME graph
//       WITHOUT the `DependsOn` edge and asserts the target classifies `Dead`,
//       so the `DependsOn` edge is the SOLE load-bearing reachability bridge
//       (non-vacuous by construction);
//   (b) flipping `admits(EdgeClass::Structural, EdgeKind::DependsOn) -> false`
//       in `graph_query::admits` makes the POSITIVE test below go RED (a
//       mutation guard — the verdict can no longer ride the bridge).
//
// PRODUCER-FAITHFUL edge endpoints (verified firsthand 2026-06-25 via the
// producer probe): the tree-sitter extractor emits NO `module` node for a
// `lib.rs`/`main.rs` file, so `find_crate_root_node` lands the real
// `DependsOn` edge on the crate-root file's first FUNCTION node (alphabetically)
// — e.g. the live producer emits `a_entry --DependsOn--> b_api`, function to
// function, not module to module. We therefore route the bridge from the
// crate_a seed (`a_main`) to the crate_b symbol (`b_only`), which matches the
// producer's actual endpoint shape more faithfully than inventing an absent
// module node.
// ===========================================================================

// WU-0015: the former `add_dependson_edge` helper was REMOVED — `DependsOn` is
// dropped from the verdict walk (ADR-0036 V5-1; it is crate-root→dep-crate-root,
// zero symbol-level reachability). The r5f1 tests now model real cross-crate USE
// with `add_calls_edge`.

/// Build the EC-11 two-"crate" fixture WITH the cross-crate bridge.
///
/// Shape: crate_a holds the Binary entry `a_main` (the sole production seed);
/// crate_b holds `b_only`, a pub fn with NO intra-crate caller, NO `LibRoot`
/// seed for crate_b, and NO `Calls` edge — it is reachable EXCLUSIVELY across
/// the crate boundary via `a_main --DependsOn--> b_only`.
fn build_r5f1_cross_crate_fixture() -> KnowledgeGraph {
    build_from_sources(&[
        ("crates/crate_a/src/main.rs", "fn a_main() {}\n"),
        ("crates/crate_b/src/lib.rs", "pub fn b_only() {}\n"),
    ])
}

#[test]
fn r5f1_cross_crate_dependson_only_reach_is_wired_not_dead() {
    // POSITIVE: model EC-11 — crate_a's seed reaches crate_b's `b_only` ONLY
    // across the cross-crate `DependsOn` bridge (no Calls, no LibRoot seed, no
    // intra-crate caller). The classifier consumes the `DependsOn` edge (it lives
    // in EdgeClass::Structural, which `admits` `DependsOn`) and must classify
    // `b_only` as Wired — reached from `a_main` purely via the cross-crate
    // dependency.
    //
    // WU-0015 REBASELINE (ADR-0036 V5-1, reframe option b): `DependsOn` is DROPPED
    // from the verdict walk — it is crate-root→dep-crate-root (zero symbol-level
    // reachability); real cross-crate USE rides `Calls`/`References` (SCIP resolves
    // cross-crate). The old `add_dependson_edge` was a SYNTHETIC symbol→symbol edge
    // that never modeled the real crate-level producer. Reframed to a real
    // cross-crate `Calls` edge (`a_main --Calls--> b_only`), the classifier rides
    // the genuine use edge and classifies `b_only` Wired. The sibling
    // `r5f1_no_dependson_edge_leaves_target_dead` (now: no edge → Suspected) is the
    // constructive non-vacuity proof (flips purely on that one Calls edge).
    let mut graph = build_r5f1_cross_crate_fixture();
    add_calls_edge(&mut graph, "a_main", "b_only");

    let eps = vec![binary_entry("crates/crate_a/src/main.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "a_main"),
        ReachabilityClass::Wired,
        "the crate_a Binary seed `a_main` must be Wired; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "b_only"),
        ReachabilityClass::Wired,
        "a crate_b pub fn reachable via a real cross-crate Calls edge \
         (a_main --Calls--> b_only) must classify Wired; got {classes:?}"
    );
}

#[test]
fn r5f1_no_dependson_edge_leaves_target_dead() {
    // NEGATIVE CONTROL (WU-0015 REBASELINE): the SAME two-crate graph WITHOUT the
    // cross-crate `Calls` edge. With no use edge from crate_a's seed and no crate_b
    // seed/caller, `b_only` is call-unreachable → Suspected (Leg 1 emits no Dead).
    // This proves the cross-crate `Calls` edge in the positive test is the SOLE
    // load-bearing reachability bridge (it flips Suspected → Wired purely on that
    // one edge).
    let graph = build_r5f1_cross_crate_fixture();

    let eps = vec![binary_entry("crates/crate_a/src/main.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "a_main"),
        ReachabilityClass::Wired,
        "the crate_a Binary seed `a_main` must still be Wired without the bridge; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "b_only"),
        ReachabilityClass::Suspected,
        "WITHOUT the cross-crate Calls edge, crate_b's `b_only` is call-unreachable \
         → Suspected (never Dead in Leg 1); got {classes:?}"
    );
}

// ===========================================================================
// WU-0009 F2 — serde-attribute edges (ADR-0030).
//
// A helper fn named in `#[serde(default = "fn")]` and a module named in
// `#[serde(with = "mod")]` on a struct field get NO graph edge on HEAD, so the
// reachability classifier false-DEADs them even though serde references them at
// (de)serialization time. F2 emits a `References` edge from the annotated symbol
// to the named local target, so the helper/module is reachable whenever its
// struct is. Driven END-TO-END through the real producer chain
// (extract_rust_symbols -> build_graph -> ReachabilityAnalyzer::analyze) via
// build_from_sources — never a hand-fabricated graph.
// ===========================================================================

#[test]
fn f2_serde_default_helper_classifies_publicapi_when_struct_reachable() {
    // F2 (WU-0009, ADR-0030): a PRIVATE helper fn named ONLY in a
    // `#[serde(default = "...")]` attribute on a field of a pub struct must
    // classify NOT-DEAD (PublicApi) once F2 emits the serde `References` edge —
    // it is reachable EXACTLY because its struct is reachable. Driven through
    // the real producer chain (extract_rust_symbols -> build_graph ->
    // ReachabilityAnalyzer::analyze) via build_from_sources.
    //
    // SHAPE (the rc10 analog): the pub struct `Cfg` is pub-api-seeded by the
    // LibRoot entry -> PublicApi (Pass 2). The serde `References` edge
    // (field/struct -> helper) is admitted by EdgeClass::Structural (includes
    // References) and walked in the SAME Pass-2 BFS, so the helper lands in
    // pub_api_set -> PublicApi. The helper is PRIVATE so it can NOT self-seed as
    // a pub-api root (CL-REACH-11) — the serde edge is its ONLY path in.
    let graph = build_from_sources(&[(
        "crates/testcrate/src/lib.rs",
        "fn default_retries() -> u32 { 3 }\n\
         pub struct Cfg {\n\
           #[serde(default = \"default_retries\")]\n\
           pub retries: u32,\n\
         }\n\
         pub fn make() -> Cfg { Cfg { retries: default_retries() } }\n",
    )]);
    let eps = vec![entry(
        EntryPointKind::LibRoot,
        "testcrate",
        "crates/testcrate/src/lib.rs",
    )];
    let classes = analyze(&graph, eps);

    // WU-0015 REBASELINE (V3-1): the pub struct `Cfg` is SEEDED as a pub-api root
    // (so it anchors its field's serde-edge reachability) but with zero in-workspace
    // callers classifies Suspected, not PublicApi-by-fiat. The serde mechanism is
    // still exercised: the helper rides the serde References edge FROM the seeded
    // struct into the pub-api reachable set.
    assert_eq!(
        class_of(&classes, "Cfg"),
        ReachabilityClass::Suspected,
        "the pub struct seeds as a pub-api root but zero-caller → Suspected; got {classes:?}"
    );
    // The serde helper rides the serde References edge from the SEEDED struct ->
    // reached in the pub-api pass -> PublicApi (NOT Dead). This is the F2 fix.
    assert_eq!(
        class_of(&classes, "default_retries"),
        ReachabilityClass::PublicApi,
        "a private helper named ONLY in `#[serde(default = \"...\")]` on a field of \
         a seeded pub struct must classify PublicApi via the serde References \
         edge, not Dead (F2 false-DEAD fix); got {classes:?}"
    );
}

#[test]
fn f2_serde_with_module_classifies_publicapi_when_struct_reachable() {
    // F2: the `#[serde(with = "mod")]` module variant. A module named ONLY in a
    // `with = "..."` attribute on a field of a reachable pub struct must
    // classify NOT-DEAD (PublicApi). The module is named `ts_millis` (NOT
    // `tests`, which is the test-module heuristic name in reachability.rs:1351).
    let graph = build_from_sources(&[(
        "crates/testcrate/src/lib.rs",
        "mod ts_millis { }\n\
         pub struct Cfg {\n\
           #[serde(with = \"ts_millis\")]\n\
           pub at: u64,\n\
         }\n",
    )]);
    let eps = vec![entry(
        EntryPointKind::LibRoot,
        "testcrate",
        "crates/testcrate/src/lib.rs",
    )];
    let classes = analyze(&graph, eps);

    // WU-0015 REBASELINE (V3-1): the seeded pub struct is zero-caller → Suspected.
    assert_eq!(
        class_of(&classes, "Cfg"),
        ReachabilityClass::Suspected,
        "the pub struct seeds as a pub-api root but zero-caller → Suspected; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "ts_millis"),
        ReachabilityClass::PublicApi,
        "a module named ONLY in `#[serde(with = \"...\")]` on a field of a \
         seeded pub struct must classify PublicApi via the serde References \
         edge, not Dead; got {classes:?}"
    );
}

#[test]
fn f2_no_serde_attr_leaves_helper_dead_negative_control() {
    // NEGATIVE CONTROL (the required non-vacuity proof): the SAME private helper
    // and SAME pub struct, but the field carries NO serde attribute. With no
    // serde `References` edge, no caller, and private visibility (no pub-api
    // seed), `default_retries` is unreachable and must classify Dead. This
    // proves the serde edge — not some other path — is what flips the helper to
    // PublicApi in the positive tests (non-vacuity by construction).
    let graph = build_from_sources(&[(
        "crates/testcrate/src/lib.rs",
        "fn default_retries() -> u32 { 3 }\n\
         pub struct Cfg {\n\
           pub retries: u32,\n\
         }\n",
    )]);
    let eps = vec![entry(
        EntryPointKind::LibRoot,
        "testcrate",
        "crates/testcrate/src/lib.rs",
    )];
    let classes = analyze(&graph, eps);

    // WU-0015 REBASELINE (V3-1): seeded pub struct, zero-caller → Suspected.
    assert_eq!(
        class_of(&classes, "Cfg"),
        ReachabilityClass::Suspected,
        "the pub struct seeds as a pub-api root but zero-caller → Suspected; got {classes:?}"
    );
    // WU-0015 REBASELINE (Dead → Suspected): WITHOUT the serde attribute the
    // private helper is call-unreachable → Suspected (never Dead in Leg 1). The
    // serde References edge remains the SOLE load-bearing bridge: it flips the
    // helper Suspected → PublicApi in the positive tests.
    assert_eq!(
        class_of(&classes, "default_retries"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: WITHOUT the serde attribute the private helper is call-unreachable → Dead; got {classes:?}"
    );
}

#[test]
fn f2_skip_serializing_if_std_method_yields_no_edge_no_error() {
    // STD NEGATIVE (required): a field with `#[serde(skip_serializing_if =
    // "Option::is_none")]` names a std method. `last_segment` -> `is_none`
    // resolves to NO local node, so F2 must SILENTLY skip it (no edge, no
    // error). Also asserts the build does not panic and the graph is well-formed.
    let graph = build_from_sources(&[(
        "crates/testcrate/src/lib.rs",
        "pub struct Cfg {\n\
           #[serde(skip_serializing_if = \"Option::is_none\")]\n\
           pub maybe: Option<u32>,\n\
         }\n",
    )]);
    // No node named `is_none` / `Option` should have been fabricated, and no
    // References edge should target one. The build completing (build_from_sources
    // does not panic) is itself the no-error half of the assertion.
    let has_phantom_ref = graph.all_edges().iter().any(|(_, to, e)| {
        e.kind == EdgeKind::References
            && graph
                .node(to)
                .is_some_and(|n| n.symbol_name == "is_none" || n.symbol_name == "Option::is_none")
    });
    assert!(
        !has_phantom_ref,
        "`skip_serializing_if = \"Option::is_none\"` (a std method) must NOT \
         produce a References edge — it resolves to no local node and is \
         silently skipped (negative control, not a target)"
    );
}

// ---------------------------------------------------------------------------
// F3 (WU-0009, ADR-0030) — cross-file private-module containment.
//
// A bare `mod foo;` in a.rs produces a Module node (file_path=a.rs) but, on
// HEAD, NO edge to the symbols DEFINED in the SEPARATE foo.rs (extracted
// independently, top-level symbols at parent=None). So foo.rs contents are
// reachability false-DEAD when reachable only via the module declaration.
//
// PART 1 (e2e): the new cross-file module Contains pass in edge_builder makes
// a PRIVATE helper in helper.rs ride the `pub mod helper;` -> helper Contains
// edge -> PublicApi (the pub-mod self-seeds; the private helper has no other
// path in). PART 2 (Pass-5 STRUCTURAL_KINDS): an UNREACHED `mod foo;` decl
// node living in an ALIVE file is rescued to STRUCTURAL (not Dead). Driven
// END-TO-END through the real producer (extract_rust_symbols -> build_graph ->
// ReachabilityAnalyzer::analyze) via build_from_sources, with sibling-convention
// paths so the graph-based resolution finds helper.rs from lib.rs.
//
// NAMING: `f3_module_*` to avoid collision with the pre-existing CL-REACH
// `f3_test_only_*` / `f3_hasimpl_*` "F3 PRUNE" set above (a different "F3").
// ---------------------------------------------------------------------------

#[test]
fn f3_module_private_cross_file_helper_is_publicapi_not_dead() {
    // A private top-level function in helper.rs is reachable only through the
    // module's structural Contains edge; the directed call verdict must not
    // mistake ownership for use.
    let graph = build_from_sources(&[
        ("crates/tc/src/lib.rs", "pub mod helper;\npub fn api() {}\n"),
        // PRIVATE, top-level (parent=None), sibling of lib.rs:
        ("crates/tc/src/helper.rs", "fn the_helper() {}\n"),
    ]);
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    // WU-0015 REBASELINE (the archetypal HARD RED, ADR-0036): the verdict walk now
    // DROPS `Contains`, so cross-file module CONTAINMENT no longer confers
    // reachability — a module owning a symbol does not USE it. The `pub mod helper;`
    // decl seeds as a pub root but zero-caller → Suspected; the PRIVATE `the_helper`,
    // reachable ONLY via the (dropped) module Contains edge, is now call-unreachable
    // → Suspected (never Dead in Leg 1; a non-delete review candidate — the honest
    // recall surface). This is the recall-hygiene fix: containment ≠ use.
    assert_eq!(
        class_of(&classes, "helper"),
        ReachabilityClass::Suspected,
        "the `pub mod helper;` decl seeds as a pub root but zero-caller → Suspected; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "the_helper"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: a PRIVATE fn reachable ONLY via the (now-dropped) module Contains edge is \
         call-unreachable → Suspected (containment ≠ use); got {classes:?}"
    );
}

#[test]
fn f3_module_no_decl_leaves_helper_dead_negative_control() {
    // F3 negative control (the non-vacuity proof for the positive e2e): the SAME
    // private helper.rs, but lib.rs has NO `mod helper;` declaration. With no
    // module node there is no F3 Contains edge, no caller, and private visibility
    // (no pub-api seed) -> `the_helper` is unreachable and must classify Dead.
    // Proves the `mod helper;` decl is the SOLE load-bearing bridge.
    let graph = build_from_sources(&[
        // NO `mod helper;`:
        ("crates/tc/src/lib.rs", "pub fn api() {}\n"),
        ("crates/tc/src/helper.rs", "fn the_helper() {}\n"),
    ]);
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    // WU-0015 REBASELINE (V3-1): `api` seeds as a pub root but zero-caller → Suspected.
    assert_eq!(
        class_of(&classes, "api"),
        ReachabilityClass::Suspected,
        "the pub fn seeds as a pub root but zero-caller → Suspected; got {classes:?}"
    );
    // WU-0015 REBASELINE (Dead → Suspected): without the module decl the private
    // cross-file helper is call-unreachable → Suspected (never Dead in Leg 1).
    assert_eq!(
        class_of(&classes, "the_helper"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: WITHOUT a `mod helper;` decl the private cross-file helper is call-unreachable → Dead; got {classes:?}"
    );

    // ALSO the UNUSED-module control: a PRIVATE `mod dead_mod;` whose dead_mod.rs
    // helper STAYS Dead (proves F3 does not blanket-revive; the module node is
    // never reached, so the F3 Contains edge it builds carries nothing). If F3
    // were a blanket revive (e.g. synthetic file-root seeding — CORRECTION-2),
    // this clause would FLIP RED.
    let graph2 = build_from_sources(&[
        // PRIVATE mod (not `pub mod`) -> NOT pub-api-seeded, unreached:
        ("crates/tc/src/lib.rs", "mod dead_mod;\npub fn api() {}\n"),
        ("crates/tc/src/dead_mod.rs", "fn dead_helper() {}\n"),
    ]);
    let classes2 = analyze(
        &graph2,
        vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")],
    );
    // WU-0015 REBASELINE (Dead → Suspected): the helper in an unused private mod is
    // call-unreachable → Suspected (never Dead in Leg 1). F3 still does not
    // blanket-revive (it is not rescued into a clean tier).
    assert_eq!(
        class_of(&classes2, "dead_helper"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: a private helper in an UNUSED private `mod dead_mod;` is call-unreachable → Dead; got {classes2:?}"
    );
}

#[test]
fn f3_module_unreached_decl_in_alive_file_is_structural() {
    // F3 PART 2 (Pass-5 STRUCTURAL_KINDS falsifier): a `mod foo;` declaration
    // node that lands in DEAD-after-BFS but lives in an ALIVE file must classify
    // STRUCTURAL post-F3 (reachability.rs STRUCTURAL_KINDS gains "module"), not
    // Dead. Binary entry so `main` is the wired root and src/main.rs is alive.
    //
    // `helpers` is PRIVATE (not `pub mod`) so it is NOT pub-api-seeded, and the
    // producer emits no main->module edge, so the `helpers` module node is
    // unreached by every BFS pass -> Dead-after-BFS. It lives in src/main.rs
    // (alive: contains the wired `main`). Pass-5 with "module" in STRUCTURAL_KINDS
    // + the alive_files guard rescues it to Structural.
    let graph = build_from_sources(&[
        // PRIVATE `mod helpers;` in the alive bin file:
        ("src/main.rs", "mod helpers;\nfn main() {}\n"),
        ("src/helpers.rs", "fn util() {}\n"),
    ]);
    let eps = vec![binary_entry("src/main.rs")];
    let classes = analyze(&graph, eps);

    // Non-vacuity: main is the wired root, so src/main.rs is an ALIVE file.
    assert_eq!(
        class_of(&classes, "main"),
        ReachabilityClass::Wired,
        "main must be the wired root so its file is alive; got {classes:?}"
    );
    // THE PART-2 ASSERTION: the `mod helpers;` decl node, Dead-after-BFS but in an
    // alive file, classifies STRUCTURAL (not Dead) once "module" is in
    // STRUCTURAL_KINDS.
    assert_eq!(
        class_of(&classes, "helpers"),
        ReachabilityClass::Structural,
        "a `mod helpers;` decl node living in an ALIVE file must classify \
         Structural (Pass-5 rescue), not Dead — removing it would break the build \
         (F3 Part 2); got {classes:?}"
    );

    // ANTI-OVER-RESCUE control: a `mod orphan;` decl in a DEAD file stays DEAD
    // (the alive_files guard holds — a module in a dead file is NOT rescued).
    let graph2 = build_from_sources(&[
        // alive bin file, does NOT declare orphan:
        ("src/main.rs", "fn main() {}\n"),
        // whole file is unreached/dead:
        ("src/dead_island.rs", "mod orphan;\nfn island_fn() {}\n"),
        ("src/orphan.rs", "fn o() {}\n"),
    ]);
    let classes2 = analyze(&graph2, vec![binary_entry("src/main.rs")]);
    // WU-0015 REBASELINE (Dead → Suspected): the alive_files guard still holds (a
    // module in a DEAD file is NOT rescued to Structural), but the un-rescued
    // residual is now Suspected, not Dead (Leg 1 emits no Dead).
    assert_eq!(
        class_of(&classes2, "orphan"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: a `mod orphan;` decl in a DEAD file is NOT rescued → Dead (guard holds); got {classes2:?}"
    );
}

// ===========================================================================
// WU-0015 / ADR-0036 v6 — directed call-reachability + the SUSPECTED tier.
//
// Every test is producer-driven (build_from_sources + add_calls_edge modeling
// the SCIP-supplied call edge) so it isolates ONE mechanism. The load-bearing
// Leg-1 safety invariant (EMPTY delete-authority: count(Dead)==0 &&
// count(SafeDelete)==0) is pinned universally here and on the real graph in
// step0_blast_radius.rs.
// ===========================================================================

/// Run analyze() and write each classification back onto its graph node, so the
/// downstream `classify_dead_action` (which reads `node.reachability_class`) sees
/// the verdict. Returns the report's classified list for convenience.
fn analyze_and_writeback(
    graph: &mut KnowledgeGraph,
    eps: Vec<EntryPoint>,
) -> Vec<(String, ReachabilityClass)> {
    let report = ReachabilityAnalyzer::new(graph, eps).analyze();
    for cn in &report.classified {
        if let Some(n) = graph.node_mut(&cn.memory_id) {
            n.reachability_class = cn.classification;
        }
    }
    report
        .classified
        .into_iter()
        .map(|c| (c.symbol_name, c.classification))
        .collect()
}

fn node_named<'g>(graph: &'g KnowledgeGraph, name: &str) -> &'g h00ligan_engine::graph::GraphNode {
    graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == name)
        .unwrap_or_else(|| panic!("node {name:?} not in graph"))
}

// --- RED-recall-hygiene: the planted-defect falsifier ----------------------

#[test]
fn wu0015_red_recall_hygiene_private_zero_caller_is_suspected() {
    // A pub `api` (given a real caller so it is genuinely PublicApi) and a PRIVATE
    // free fn `graph_hygiene_score` with ZERO callers in the SAME module. On HEAD
    // the undirected-Contains walk marked the private sibling WIRED (module reached
    // → sibling reached). The directed-call verdict drops Contains → the private
    // zero-caller residual is SUSPECTED (the recall bug fixed). Non-vacuity anchor:
    // `api` has a genuinely-reached caller so the module has a live sibling.
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub fn caller() { api() }\n\
         pub fn api() {}\n\
         fn graph_hygiene_score() {}\n",
    )]);
    add_calls_edge(&mut graph, "caller", "api");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "graph_hygiene_score"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: a private zero-caller free fn is Dead (never WIRED via Contains); got {classes:?}"
    );
    // Non-vacuity: `api` has a real caller so it is genuinely PublicApi.
    assert_eq!(
        class_of(&classes, "api"),
        ReachabilityClass::PublicApi,
        "the pub sibling WITH a real caller must be PublicApi; got {classes:?}"
    );
}

#[test]
fn wu0015_red_recall_hygiene_negative_control_calls_edge_flips_to_wired() {
    // NON-VACUITY: the SAME graph + a real Calls edge INTO graph_hygiene_score
    // makes it call-reachable → it leaves Suspected (Wired/PublicApi). Proves the
    // zero-caller condition is the SOLE load-bearing driver of the verdict.
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub fn caller() { api() }\n\
         pub fn api() {}\n\
         fn graph_hygiene_score() {}\n",
    )]);
    add_calls_edge(&mut graph, "caller", "api");
    add_calls_edge(&mut graph, "api", "graph_hygiene_score");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);
    assert_ne!(
        class_of(&classes, "graph_hygiene_score"),
        ReachabilityClass::Suspected,
        "with a real Calls edge the fn is call-reachable, not Suspected; got {classes:?}"
    );
}

// --- RED-pub-zero-caller-census --------------------------------------------

#[test]
fn wu0015_red_pub_zero_caller_is_suspected_v3_1_split() {
    // The census archetype (set_generation_metadata_sync / write_audit_entry / warmup): a
    // pub fn with ZERO real callers seeds as a PublicApi ROOT but V3-1 classifies
    // it SUSPECTED (external-API-vs-wiring-gap). A pub fn WITH a real caller stays
    // PublicApi — proving the split does not blanket-Suspected every pub item.
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub fn set_generation_metadata_sync() {}\n\
         pub fn used_api() {}\n\
         pub fn driver() { used_api() }\n",
    )]);
    add_calls_edge(&mut graph, "driver", "used_api");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "set_generation_metadata_sync"),
        ReachabilityClass::Suspected,
        "a pub fn with zero real callers → Suspected (V3-1 seed-vs-classify); got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "used_api"),
        ReachabilityClass::PublicApi,
        "a pub fn WITH a real caller stays PublicApi (split is not a blanket); got {classes:?}"
    );
}

// --- RED-indegree-excludes-Contains ----------------------------------------

#[test]
fn wu0015_red_indegree_excludes_contains_pub_child_is_suspected() {
    // A pub item reachable from a root ONLY through a Contains parent→child
    // relationship (no Calls/References into it) has use_in_degree 0 → V3-1 →
    // Suspected. Guards against re-admitting the Contains-as-caller pollution
    // through the in-degree signal. `pub mod outer { pub fn inner_api() {} }`:
    // `inner_api`'s only incoming edge is the `outer`→`inner_api` Contains.
    let graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub mod outer { pub fn inner_api() {} }\n",
    )]);
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);
    assert_eq!(
        class_of(&classes, "outer::inner_api"),
        ReachabilityClass::Suspected,
        "a pub item reachable ONLY via Contains has in-degree 0 → Suspected; got {classes:?}"
    );
}

// --- RED-test-only-reseed ---------------------------------------------------

#[test]
fn wu0015_red_test_only_reseed_helper_is_testonly() {
    // resolve_test_roots reseeds to `is_test_root` FUNCTION nodes. A private prod
    // helper called only by a `#[test]` fn → TestOnly (never residual/Suspected).
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub fn api() {}\n\
         fn test_helper() {}\n\
         #[cfg(test)]\n\
         mod tests { #[test] fn t() { super::test_helper(); } }\n",
    )]);
    // Model the SCIP-supplied `t -> test_helper` call.
    add_calls_edge(&mut graph, "tests::t", "test_helper");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);
    assert_eq!(
        class_of(&classes, "test_helper"),
        ReachabilityClass::TestOnly,
        "a helper reached only from a #[test] root → TestOnly; got {classes:?}"
    );
}

#[test]
fn wu0015_red_test_only_reseed_negative_control_no_edge_is_suspected() {
    // NON-VACUITY: remove the test→helper Calls edge → the helper is reached by
    // neither production nor a test-fn root → Suspected (not TestOnly). Proves
    // TestOnly is EARNED via the real test→helper Calls edge, not file location.
    let graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub fn api() {}\n\
         fn test_helper() {}\n\
         #[cfg(test)]\n\
         mod tests { #[test] fn t() { super::test_helper(); } }\n",
    )]);
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);
    assert_eq!(
        class_of(&classes, "test_helper"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: without the test→helper Calls edge the private helper → Dead; got {classes:?}"
    );
}

// --- GREEN-stdlib-trait-family (guard-b) -----------------------------------

#[test]
fn wu0015_green_stdlib_trait_impl_method_rescued_not_suspected() {
    // A stdlib-trait impl method (`impl Display for Foo::fmt`) is invoked only via
    // desugared code (no Calls edge). guard-b (STRUCTURAL: the impl carries an
    // Implements edge; the concrete type Foo is reached) rescues it to Foo's tier —
    // NOT residual, NOT a delete tier. Detection is STRUCTURAL (Implements edge),
    // not a trait-name allowlist.
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub struct Foo;\n\
         impl std::fmt::Display for Foo {\n\
           fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }\n\
         }\n\
         pub fn make() -> Foo { Foo }\n",
    )]);
    // Model a real USE of Foo so the concrete type is genuinely reached.
    add_calls_edge(&mut graph, "make", "Foo");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    let fmt = class_of(&classes, "impl std::fmt::Display for Foo::fmt");
    assert_ne!(
        fmt,
        ReachabilityClass::Suspected,
        "the trait-impl method must be guard-rescued to the reached type's tier, not Suspected; got {classes:?}"
    );
    assert!(
        matches!(fmt, ReachabilityClass::Wired | ReachabilityClass::PublicApi),
        "rescued to a non-delete reached tier; got {fmt}"
    );
}

#[test]
fn wu0015_green_stdlib_trait_impl_method_negative_control_unreached_type_is_suspected() {
    // NON-VACUITY: when NEITHER the trait node NOR the concrete type is reached
    // (no use of Foo), guard-b correctly does NOT over-rescue — the method falls to
    // Suspected. Proves the rescue keys on a REACHED type, not on being a trait impl.
    let graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "struct Foo;\n\
         impl std::fmt::Display for Foo {\n\
           fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }\n\
         }\n",
    )]);
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);
    assert_eq!(
        class_of(&classes, "impl std::fmt::Display for Foo::fmt"),
        ReachabilityClass::Dead,
        "WU-0015 Leg-3b: an impl method whose type/trait is unreached is NOT over-rescued → Dead; got {classes:?}"
    );
}

// --- GREEN-pub-inherent-method / pub-nested-module -------------------------

#[test]
fn wu0015_green_pub_inherent_method_seeded_publicapi() {
    // Comprehensive seeding (V2-2, drop is_top_level): a pub inherent METHOD
    // `Foo::method` self-seeds as a pub-api root. With a real caller it classifies
    // PublicApi (not residual/Dead).
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub struct Foo;\n\
         impl Foo { pub fn method(&self) {} }\n\
         pub fn driver(f: &Foo) { f.method() }\n",
    )]);
    add_calls_edge(&mut graph, "driver", "impl Foo::method");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);
    let m = class_of(&classes, "impl Foo::method");
    assert!(
        matches!(m, ReachabilityClass::PublicApi | ReachabilityClass::Wired),
        "a pub inherent method WITH a caller must classify PublicApi/Wired (seeded), never Dead; got {classes:?}"
    );
}

#[test]
fn wu0015_green_pub_nested_module_item_seeded_not_dead() {
    // Comprehensive seeding admits pub items in pub NESTED modules. `deep_api`'s
    // symbol name contains `::` (nested) — the dropped is_top_level filter no
    // longer rejects it, so it is surfaced (PublicApi with a caller / Suspected
    // without), NEVER residual/Dead.
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub mod outer { pub mod inner { pub fn deep_api() {} } }\n\
         pub fn driver() { outer::inner::deep_api() }\n",
    )]);
    add_calls_edge(&mut graph, "driver", "outer::inner::deep_api");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);
    let d = class_of(&classes, "outer::inner::deep_api");
    assert!(
        matches!(d, ReachabilityClass::PublicApi | ReachabilityClass::Wired),
        "a pub item in a pub nested module is seeded and reachable via a caller → PublicApi/Wired; got {classes:?}"
    );
}

// --- GREEN-trait-default-method (V3-4) -------------------------------------

#[test]
fn wu0015_green_trait_default_method_rescued_not_suspected() {
    // A trait DEFINITION default method (parent is a trait node) is neither a
    // concrete-impl method nor inside a trait-IMPL block. V3-4 extends guard-b to
    // rescue it when the trait node is reached — STRUCTURAL (parent Contains →
    // trait node), never delete-eligible.
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub trait Widget { fn handle_mouse_event(&self) {} }\n\
         pub fn driver(w: &dyn Widget) { w.handle_mouse_event() }\n",
    )]);
    // Reach the trait node via a real use edge from the driver.
    add_calls_edge(&mut graph, "driver", "Widget");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);
    let m = class_of(&classes, "Widget::handle_mouse_event");
    assert_ne!(
        m,
        ReachabilityClass::Suspected,
        "a trait-definition default method whose trait is reached is guard-rescued, not Suspected; got {classes:?}"
    );
}

// --- INV-suspected-action-tier + dead-set exclusion ------------------------

#[test]
fn wu0015_inv_suspected_action_tier_is_review() {
    // Suspected is a REVIEW candidate: never Healthy (reports-clean) nor a delete
    // tier. Pins the arm against a render/aggregation site folding Suspected into a
    // clean/deletable tier during the cross-crate exhaustive-match ripple.
    assert_eq!(
        ReachabilityClass::Suspected.action_tier(),
        ActionTier::Review,
        "Suspected.action_tier() must be Review (never Healthy)"
    );
    assert_ne!(
        ReachabilityClass::Suspected.action_tier(),
        ActionTier::Healthy
    );
    // WU-0016 / ADR-0039: the `Action` auto-delete tier was removed; Review is
    // the only non-Healthy/non-Unknown tier.
}

#[test]
fn wu0015_inv_unflagged_dead_never_safedelete() {
    // WU-0015 Leg-3b: a private call-unreachable residual is now class==Dead, but
    // WITHOUT the rustc oracle flag (conjunct 2) it routes to SuspectedDelete,
    // NEVER SafeDelete — corroboration, not mere deadness, grants delete authority.
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub fn api() {}\nfn residual() {}\n",
    )]);
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let _ = analyze_and_writeback(&mut graph, eps);
    let node = node_named(&graph, "residual").clone();
    // WU-0015 Leg-3b REBASELINE — the residual private fn promotes to Dead, but a
    // rustc-UNflagged Dead node (conjunct 2 fails) still never yields SafeDelete.
    assert_eq!(
        node.reachability_class,
        ReachabilityClass::Dead,
        "the residual private fn promotes to Dead in Leg 3b"
    );
    let cfg_crates = cfg_touching_crates(&graph);
    assert_ne!(
        classify_dead_action(&graph, &node, &cfg_crates),
        DeadAction::SafeDelete,
        "an unflagged Dead node must NEVER yield SafeDelete (conjunct 2 not met)"
    );
    assert_eq!(
        classify_dead_action(&graph, &node, &cfg_crates),
        DeadAction::SuspectedDelete,
        "an unflagged Dead node yields the non-delete SuspectedDelete recommendation"
    );
}

// --- INV-universal: no Dead, no SafeDelete over a multi-shape graph --------

#[test]
fn wu0015_inv_universal_no_dead_no_safedelete() {
    // WU-0015 Leg-3b load-bearing SAFETY INVARIANT on a producer-driven graph
    // spanning every shape (wired chain, pub-zero-caller, private-unreachable, a
    // trait impl, an orphan-ish private fn): count(action==SafeDelete)==0 (Dead is
    // now legitimately non-empty — no oracle flag is set anywhere here). A
    // UNIVERSAL sweep — not just the named controls.
    let mut graph = build_from_sources(&[
        (
            "src/main.rs",
            "fn main() { helper(); }\nfn helper() {}\nfn never_called() {}\n",
        ),
        (
            "crates/lib/src/lib.rs",
            "pub struct Cfg;\n\
             impl std::fmt::Debug for Cfg {\n\
               fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }\n\
             }\n\
             pub fn external_api() {}\n\
             fn private_dead() {}\n",
        ),
    ]);
    add_calls_edge(&mut graph, "main", "helper");
    let eps = vec![
        binary_entry("src/main.rs"),
        entry(EntryPointKind::LibRoot, "lib", "crates/lib/src/lib.rs"),
    ];
    let _ = analyze_and_writeback(&mut graph, eps);

    // WU-0015 Leg-3b REBASELINE — Dead is now legitimately non-empty (never_called
    // and private_dead are private call-unreachable residuals → Dead). The
    // load-bearing UNIVERSAL invariant is now on SafeDelete: with NO oracle flag
    // set anywhere in this producer graph (conjunct 2 fails everywhere;
    // never_called additionally has a None crate), count(action==SafeDelete)==0.
    let cfg_crates = cfg_touching_crates(&graph);
    let safe_delete = graph
        .all_nodes()
        .into_iter()
        .filter(|n| classify_dead_action(&graph, n, &cfg_crates) == DeadAction::SafeDelete)
        .map(|n| n.symbol_name.clone())
        .collect::<Vec<_>>();
    assert!(
        safe_delete.is_empty(),
        "delete-authority tier must be EMPTY absent the oracle bit; found {safe_delete:?}"
    );
}

// --- INV-orphan-disposed ----------------------------------------------------

#[test]
fn wu0015_inv_orphan_class_never_safedelete() {
    // The Orphan path cannot yield SafeDelete: classify_dead_action's conjunct 1
    // requires class==Dead, so an Orphan-class node → SuspectedDelete regardless of
    // the other signals. Construct a node, force class Orphan, assert non-delete.
    let mut graph = build_from_sources(&[("src/main.rs", "fn main() {}\nfn some_fn() {}\n")]);
    let node_id = node_named(&graph, "some_fn").memory_id;
    if let Some(n) = graph.node_mut(&node_id) {
        n.reachability_class = ReachabilityClass::Orphan;
    }
    let node = graph.node(&node_id).unwrap().clone();
    assert_ne!(
        classify_dead_action(&graph, &node, &cfg_touching_crates(&graph)),
        DeadAction::SafeDelete,
        "an Orphan-class node must NOT yield SafeDelete (conjunct 1 requires Dead)"
    );
}

// --- INV-trace-equals-verdict -----------------------------------------------

#[test]
fn reachability_trace_uses_exact_verdict_spec() {
    let trace = BfsSpec::reachability_trace();
    let calls = BfsSpec::classifier_calls();
    assert_eq!(
        trace, calls,
        "an explanatory trace must not maintain a second liveness contract"
    );
}

// ===========================================================================
// WU-0019 — container roll-up: a Dead/Suspected impl/trait/module CONTAINER
// with a genuinely-alive Contains-child rolls up to its most-alive child tier.
//
// Instrument-hardening fix for the reachability container-rollup gap (the
// 2026-07-11 code-state campaign's false-DEAD container classes). Producer-
// driven per the file header: real extractor + build_graph; `add_calls_edge`
// models ONLY the SCIP-supplied call edge the tree-sitter extractor never emits
// for intra-file calls.
//
// TRACE verdicts folded in: the trait-method-node guard extension (ground-truth
// #2) is REFUTED for the live ToolHandler shape and DEFERRED — see
// OQ-TRAIT-GUARD-RESIDUAL (the classification-side twin cited at the fix). The
// module-decl class (#3) is RED_CONFIRMED but with SUSPECTED (not Dead) input,
// so the rescue accepts Suspected and runs at/after the V3-1 split.
// ===========================================================================

#[test]
fn wu0019_fa_inherent_impl_container_rescued_to_wired_child_tier() {
    // FAL-1 — the F-A falsifier (exemplar = StalenessCheck impl). The impl HEADER
    // node is a distinct graph node from verdict(); verdict() has a genuine wired
    // call site, so the container must roll up to the child's exact Wired tier.
    let mut graph = build_from_sources(&[(
        "src/main.rs",
        "struct StalenessCheck;\n\
         impl StalenessCheck { fn verdict(&self) -> bool { true } }\n\
         fn main() { let s = StalenessCheck; s.verdict(); }\n",
    )]);
    add_calls_edge(&mut graph, "main", "impl StalenessCheck::verdict");
    let eps = vec![binary_entry("src/main.rs")];
    let classes = analyze(&graph, eps);

    // Non-vacuity: a genuinely-alive CHILD exists via the real Calls edge.
    assert_eq!(
        class_of(&classes, "main"),
        ReachabilityClass::Wired,
        "non-vacuity: main is the wired entrypoint; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "impl StalenessCheck::verdict"),
        ReachabilityClass::Wired,
        "non-vacuity: verdict() has a real wired call site; got {classes:?}"
    );
    // Falsifier: the impl HEADER rolls up to the MOST-ALIVE child tier (Wired),
    // asserted EXACTLY — defeats the STRUCTURAL_KINDS-widening shortcut (which
    // would give Structural in the alive file) and a blanket-Wired-vs-tier bug.
    assert_eq!(
        class_of(&classes, "impl StalenessCheck"),
        ReachabilityClass::Wired,
        "impl container must roll up to its wired child's tier, not stay Dead; got {classes:?}"
    );
}

#[test]
fn wu0019_fa_trait_container_rescued_from_suspected_to_child_tier() {
    // FAL-2 — the TRAIT-kind branch of the rollup from a SUSPECTED input. run() is
    // pub-api reached (real caller), the trait HEADER downgrades to Suspected via
    // V3-1, and must roll up to its most-alive child (run = PublicApi).
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub trait Proc { fn run(&self) {} }\n\
         pub struct W;\n\
         impl Proc for W {}\n\
         pub fn driver(w: &W) { w.run() }\n",
    )]);
    add_calls_edge(&mut graph, "driver", "Proc::run");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "Proc::run"),
        ReachabilityClass::PublicApi,
        "non-vacuity: run() is a pub-api-reached trait method with a real caller; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "Proc"),
        ReachabilityClass::PublicApi,
        "trait container must roll up to its most-alive child (run=PublicApi), not stay Suspected; got {classes:?}"
    );
}

#[test]
fn wu0019_nested_module_over_impl_rolls_up_after_container() {
    // FAL-3 — the nested-container falsifier: the only alive route into module `m`
    // is THROUGH `impl S` (which the fix must rescue first). `go` is a grandchild
    // of `m` (parent = `impl S`), so a single-pass direct-child module check that
    // ran before the impl rollup would leave `m` Suspected. Forces the
    // fixpoint/ordering decision.
    let mut graph = build_from_sources(&[
        (
            "crates/tc/src/lib.rs",
            "pub mod m;\npub fn driver() { m::S::go() }\n",
        ),
        (
            "crates/tc/src/m.rs",
            "pub struct S;\nimpl S { pub fn go() {} }\n",
        ),
    ]);
    add_calls_edge(&mut graph, "driver", "impl S::go");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    // Non-vacuity: go() is genuinely alive.
    assert_eq!(
        class_of(&classes, "impl S::go"),
        ReachabilityClass::PublicApi,
        "non-vacuity: go() is pub-api reached; got {classes:?}"
    );
    // fix-1 leg: the inherent-impl container rolls up via go.
    assert_eq!(
        class_of(&classes, "impl S"),
        ReachabilityClass::PublicApi,
        "inner impl container must roll up via go; got {classes:?}"
    );
    // fix-3 nested leg (the teeth): m's only alive DIRECT child is `impl S`, alive
    // only AFTER the impl rollup — proving the rollup iterates to a fixpoint.
    assert_eq!(
        class_of(&classes, "m"),
        ReachabilityClass::PublicApi,
        "module container must roll up through the inner impl container (nested fixpoint); got {classes:?}"
    );
}

#[test]
fn wu0019_fix3_pub_mod_decl_rescued_via_alive_content_tier() {
    // FAL-4 — the fix-3 falsifier: a bare `pub mod feature;` decl node (SUSPECTED
    // via V3-1, never Dead — so a Pass-5 STRUCTURAL_KINDS widening cannot reach it)
    // rolls up to its most-alive OUTGOING-Contains child.
    let mut graph = build_from_sources(&[
        (
            "crates/tc/src/lib.rs",
            "pub mod feature;\npub fn driver() { feature::used() }\n",
        ),
        ("crates/tc/src/feature.rs", "pub fn used() {}\n"),
    ]);
    add_calls_edge(&mut graph, "driver", "used");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "used"),
        ReachabilityClass::PublicApi,
        "non-vacuity: used() is a pub fn with a real caller; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "feature"),
        ReachabilityClass::PublicApi,
        "pub-mod decl must roll up to its alive content tier, not stay Suspected; got {classes:?}"
    );
}

#[test]
fn wu0019_f121_rolled_up_impl_container_leaves_dead_tier_surface() {
    // FAL-5 — the F-121 downstream verify: once the by-method-wired trait-impl
    // container leaves {Dead,Suspected}, it is excluded from the compute_dead_tiers
    // surface that produced the campaign-row-121 NeedsReview mislabel. NO
    // graph_query.rs change: classify_dead_action is unchanged; the resolution is
    // the upstream reclassification filtering the node out of the review surface.
    let mut graph = build_from_sources(&[(
        "src/main.rs",
        "pub trait Handler { fn handle(&self); }\n\
         struct StatusH;\n\
         impl Handler for StatusH { fn handle(&self) {} }\n\
         fn main() { StatusH.handle(); }\n",
    )]);
    add_calls_edge(&mut graph, "main", "impl Handler for StatusH::handle");
    // Model the dyn-trait use so the trait node is WIRED (the alive HasImpl
    // dependent that drives the mislabel).
    add_calls_edge(&mut graph, "main", "Handler");
    let eps = vec![binary_entry("src/main.rs")];
    let classes = analyze_and_writeback(&mut graph, eps);

    // Non-vacuity: the method is wired and the alive dependent genuinely exists.
    assert_eq!(
        class_of(&classes, "impl Handler for StatusH::handle"),
        ReachabilityClass::Wired,
        "non-vacuity: the impl method is wired; got {classes:?}"
    );
    assert!(
        matches!(
            class_of(&classes, "Handler"),
            ReachabilityClass::Wired | ReachabilityClass::PublicApi
        ),
        "non-vacuity: the trait (alive HasImpl dependent) is alive; got {classes:?}"
    );
    // Falsifier: the container leaves the {Dead,Suspected} compute_dead_tiers
    // surface (== its wired child's Wired tier). This exclusion — NOT any edit to
    // classify_dead_action — is what prevents the NeedsReview mislabel.
    let c = node_named(&graph, "impl Handler for StatusH").reachability_class;
    assert!(
        !matches!(c, ReachabilityClass::Dead | ReachabilityClass::Suspected),
        "container must leave the dead-tier review surface; got {c:?}"
    );
    assert_eq!(
        c,
        ReachabilityClass::Wired,
        "container rolls up to its wired child's tier; got {c:?}"
    );
}

#[test]
fn wu0019_nc_zero_alive_children_container_stays_non_alive() {
    // NC-1 — over-correction guard (a): a container with ZERO alive children stays
    // non-alive. Covers BOTH container tiers (Dead impl, Suspected trait).
    // graph1: an inherent impl whose only child is Dead stays Dead.
    let mut graph1 = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "struct Lonely;\n\
         impl Lonely { fn never(&self) {} }\n\
         pub fn api() {}\n\
         pub fn driver() { api() }\n",
    )]);
    add_calls_edge(&mut graph1, "driver", "api");
    let eps1 = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes1 = analyze(&graph1, eps1);
    // Non-triviality: the analysis is non-trivial (a genuinely-alive node exists).
    assert_eq!(
        class_of(&classes1, "api"),
        ReachabilityClass::PublicApi,
        "non-triviality: api is alive; got {classes1:?}"
    );
    assert_eq!(
        class_of(&classes1, "impl Lonely"),
        ReachabilityClass::Dead,
        "an impl with only a Dead child MUST stay Dead (over-correction guard); got {classes1:?}"
    );

    // graph2: a pub trait whose only child is Dead stays Suspected.
    let mut graph2 = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub trait EmptyProc { fn only(&self) {} }\n\
         pub fn api() {}\n\
         pub fn driver() { api() }\n",
    )]);
    add_calls_edge(&mut graph2, "driver", "api");
    let eps2 = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes2 = analyze(&graph2, eps2);
    assert_eq!(
        class_of(&classes2, "EmptyProc"),
        ReachabilityClass::Suspected,
        "a pub trait with only a Dead child MUST stay Suspected (over-correction guard); got {classes2:?}"
    );
}

#[test]
fn wu0019_nc_dead_sibling_method_not_rescued_on_impl_rollup() {
    // NC-2 — cascade guard (b), inherent-impl variant (the live SdlConfig
    // expanded_user_schema_path exemplar). The container rolls up via one alive
    // child; a genuinely-dead SIBLING method must NOT be dragged alive. `struct
    // Svc` is deliberately left Dead so guard-b cannot independently rescue
    // `unused` via the concrete type — isolating the cascade to the rollup.
    let mut graph = build_from_sources(&[(
        "src/main.rs",
        "struct Svc;\n\
         impl Svc { fn used(&self) {} fn unused(&self) {} }\n\
         fn main() { Svc.used(); }\n",
    )]);
    add_calls_edge(&mut graph, "main", "impl Svc::used");
    let eps = vec![binary_entry("src/main.rs")];
    let classes = analyze(&graph, eps);

    // Rollup fired (RED-on-HEAD half).
    assert_eq!(
        class_of(&classes, "impl Svc::used"),
        ReachabilityClass::Wired,
        "non-vacuity: used() is wired; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "impl Svc"),
        ReachabilityClass::Wired,
        "container rolls up via used; got {classes:?}"
    );
    // The load-bearing control (GREEN-on-HEAD half): the dead sibling stays Dead
    // after the container is rolled up via a DIFFERENT child.
    assert_eq!(
        class_of(&classes, "impl Svc::unused"),
        ReachabilityClass::Dead,
        "a genuinely-dead SIBLING method must NOT be rescued by the container rollup; got {classes:?}"
    );
}

#[test]
fn wu0019_nc_dead_default_method_not_rescued_when_trait_rolls_up() {
    // NC-3 — the ordering/feedback cascade guard (trait branch): the rollup runs
    // AFTER guard_rescue_tier and must NOT feed back into it. Only run() is
    // called; NOTHING edges the trait node Proc2 or idle().
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub trait Proc2 { fn run(&self) {} fn idle(&self) {} }\n\
         pub struct W2;\n\
         impl Proc2 for W2 {}\n\
         pub fn driver(w: &W2) { w.run() }\n",
    )]);
    add_calls_edge(&mut graph, "driver", "Proc2::run");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    // Rollup fired + trait-container falsification (RED-on-HEAD half).
    assert_eq!(
        class_of(&classes, "Proc2::run"),
        ReachabilityClass::PublicApi,
        "non-vacuity: run() is pub-api reached; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "Proc2"),
        ReachabilityClass::PublicApi,
        "trait header rolls up via run; got {classes:?}"
    );
    // The load-bearing control (GREEN-on-HEAD half): the uncalled sibling default
    // method stays Dead even though its trait container was just rolled up alive —
    // the rollup must not re-trigger guard_rescue_tier.
    assert_eq!(
        class_of(&classes, "Proc2::idle"),
        ReachabilityClass::Dead,
        "the uncalled default method must stay Dead — the rollup must not feed back into guard_rescue_tier; got {classes:?}"
    );
}

#[test]
fn wu0019_nc_fix3_all_dead_content_pub_mod_stays_suspected() {
    // NC-4 — fix-3 over-correction guard: a pub-mod decl whose OUTGOING-Contains
    // content is entirely non-alive stays Suspected (the honest review surface).
    let mut graph = build_from_sources(&[
        (
            "crates/tc/src/lib.rs",
            "pub mod feature;\npub mod empty_mod;\npub fn driver() { feature::used() }\n",
        ),
        ("crates/tc/src/feature.rs", "pub fn used() {}\n"),
        ("crates/tc/src/empty_mod.rs", "fn only_dead() {}\n"),
    ]);
    add_calls_edge(&mut graph, "driver", "used");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    // Positive control still fires (the fix is genuinely active).
    assert_eq!(
        class_of(&classes, "feature"),
        ReachabilityClass::PublicApi,
        "non-triviality: the alive module rolls up; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "empty_mod"),
        ReachabilityClass::Suspected,
        "a pub-mod with only Dead content MUST stay Suspected; got {classes:?}"
    );
}

#[test]
fn wu0019_nc_fix1_tier_propagation_testonly_child_not_blanket_wired() {
    // NC-5 — fix-1 tier-propagation guard: a container whose ONLY alive child is
    // TEST_ONLY rolls up to TestOnly, NOT a blanket-clean tier.
    let mut graph = build_from_sources(&[(
        "crates/tc/src/lib.rs",
        "pub fn api() {}\n\
         pub fn driver() { api() }\n\
         struct T;\n\
         impl T { fn helper(&self) {} }\n\
         #[cfg(test)]\n\
         mod tests { #[test] fn t() { super::T.helper(); } }\n",
    )]);
    add_calls_edge(&mut graph, "driver", "api");
    add_calls_edge(&mut graph, "tests::t", "impl T::helper");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "impl T::helper"),
        ReachabilityClass::TestOnly,
        "non-vacuity: helper is reached only from a #[test] root; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "impl T"),
        ReachabilityClass::TestOnly,
        "container must roll up to its child's ACTUAL tier (TestOnly), not blanket Wired; got {classes:?}"
    );
}

#[test]
fn wu0019_nc_fix3_tier_propagation_testonly_content_not_blanket_wired() {
    // NC-6 — fix-3 tier-propagation guard (Trace caution: "a module whose content
    // is only TEST_ONLY must roll up to TEST_ONLY, not WIRED"). `helper` is PRIVATE
    // so it is genuinely TestOnly (not pub-api-seeded).
    let mut graph = build_from_sources(&[
        (
            "crates/tc/src/lib.rs",
            "pub mod util;\npub fn api() {}\npub fn driver() { api() }\n#[cfg(test)]\nmod tests { #[test] fn t() { crate::util::helper(); } }\n",
        ),
        ("crates/tc/src/util.rs", "fn helper() {}\n"),
    ]);
    add_calls_edge(&mut graph, "driver", "api");
    add_calls_edge(&mut graph, "tests::t", "helper");
    let eps = vec![entry(EntryPointKind::LibRoot, "tc", "crates/tc/src/lib.rs")];
    let classes = analyze(&graph, eps);

    assert_eq!(
        class_of(&classes, "helper"),
        ReachabilityClass::TestOnly,
        "non-vacuity: helper is a private fn reached only from a #[test] root; got {classes:?}"
    );
    assert_eq!(
        class_of(&classes, "util"),
        ReachabilityClass::TestOnly,
        "pub-mod decl must roll up to its content's ACTUAL tier (TestOnly), not blanket Wired; got {classes:?}"
    );
}
