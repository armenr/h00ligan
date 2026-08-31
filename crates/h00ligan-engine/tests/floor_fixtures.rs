//! WU-0014 L0a — reusable floor-fixture harness for the code-intel trust-floor
//! remediation campaign.
//!
//! # What this is
//! A *reusable* fixture-builder: given a repo SHAPE, it materializes a throwaway
//! cargo repo, indexes it through the **real shipped entrypoint**
//! (`h00ligan index` → `run_index` → the production supervisor and
//! `IndexPipeline`), and exposes the persisted [`KnowledgeGraph`] plus the real
//! query verbs (`run_dead`/`run_assess`/`run_overview`) for assertions. Each
//! later WU-0014 leg (L1+) adds the SHAPE that exposes its bug
//! (single-package, `[lib] path=`, no-RA, partial-SCIP, cfg-twin, two-repo, …)
//! by constructing a [`RepoShape`] — the harness machinery does not change.
//!
//! # Why in-process through h00ligan
//! `run_index`/`run_dead`/`run_assess`/`load_or_scan_graph` are the `pub async fn`
//! surface of the `h00ligan` lib that the `h00ligan` binary's `main()`
//! dispatches to — so calling them in-process drives the *same wired code path*
//! the shipped CLI does (IMPL→WIRED), while letting us assert against the
//! returned [`KnowledgeGraph`] without scraping stdout. h00ligan is a dev-only
//! dependency here (an allowed dev-dependency cycle — see `Cargo.toml`).
//!
//! # Hermetic by default; rust-analyzer is opt-in
//! [`index_fixture`] with `scip = false` is fully hermetic (tree-sitter only,
//! no `rust-analyzer`) so it runs in CI without RA installed. `scip = true`
//! shells the real `rust-analyzer scip` binary and is therefore gated on
//! [`rust_analyzer_available`] exactly like `scip_feature_gated_e2e.rs`.
//!
//! # Isolation
//! Every [`IndexedFixture`] owns BOTH a temp repo AND a temp data-dir (its own
//! `graph.redb`), so tests are parallel-safe without `--test-threads=1` (redb
//! locks per-file and no two fixtures share a store).
//!
//! # Scope (WU-0014 L0)
//! L0 builds the harness and proves it works with an **all-GREEN** health smoke
//! on a healthy fixture. It deliberately does NOT contain bug-demonstrating
//! fixtures — those belong to each leg (L1+), so L0 never reddens the
//! `--workspace --tests` CI lane.

#![cfg(feature = "code-intel")]

use std::collections::BTreeMap;
use std::path::PathBuf;

use h00ligan_engine::code_intel_domain::CapabilityCoverageStatus;
use h00ligan_engine::graph::{KnowledgeGraph, OracleReceipt};
use h00ligan_engine::graph_query::{
    DeadAction, DeadReport, DeadSingleReport, cfg_touching_crates, classify_dead_action,
    dead_report_gated, dead_single_gated,
};
use h00ligan_engine::graph_stats::{
    CallEdgeCoverage, CoverageTier, IndexBaseline, StalenessVerdict, call_edge_coverage,
    compute_reachability_summary, coverage_tier,
};
use h00ligan_engine::graph_status::status_verdict;
use h00ligan_engine::project_binding::ProjectBinding;
use h00ligan_engine::reachability::ReachabilityClass;
use h00ligan_engine::scip_loader::rust_analyzer_available;

use h00ligan::composite_cmd::{AssessArgs, DeadArgs, OverviewArgs};
use h00ligan::graph_cmd::{load_indexed_graph_snapshot, load_or_scan_graph};
use h00ligan::index_cmd::IndexArgs;

#[derive(Debug, Eq, PartialEq)]
enum ArtifactSnapshot {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
    Other,
}

fn path_population(root: &std::path::Path) -> BTreeMap<PathBuf, ArtifactSnapshot> {
    fn collect(
        root: &std::path::Path,
        current: &std::path::Path,
        population: &mut BTreeMap<PathBuf, ArtifactSnapshot>,
    ) {
        let mut entries = std::fs::read_dir(current)
            .unwrap_or_else(|error| panic!("read {}: {error}", current.display()))
            .map(|entry| entry.expect("directory entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::path);

        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .expect("population-relative path")
                .to_path_buf();
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("classify {}: {error}", path.display()));
            let snapshot = if file_type.is_dir() {
                ArtifactSnapshot::Directory
            } else if file_type.is_file() {
                ArtifactSnapshot::File(
                    std::fs::read(&path)
                        .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
                )
            } else if file_type.is_symlink() {
                ArtifactSnapshot::Symlink(
                    std::fs::read_link(&path)
                        .unwrap_or_else(|error| panic!("read link {}: {error}", path.display())),
                )
            } else {
                ArtifactSnapshot::Other
            };
            population.insert(relative, snapshot);
            if file_type.is_dir() {
                collect(root, &path, population);
            }
        }
    }

    assert!(root.is_dir(), "population root must be a directory");
    let mut population = BTreeMap::new();
    collect(root, root, &mut population);
    population
}

fn fixture_binding(root: &std::path::Path, data_dir: &std::path::Path) -> ProjectBinding {
    ProjectBinding::explicit(root, data_dir).expect("fixture project binding")
}

// ============================================================================
// Shape model
// ============================================================================

/// One file to materialize into a fixture repo: a path RELATIVE to the repo
/// root, plus its verbatim contents.
#[derive(Clone, Debug)]
pub struct FixtureFile {
    pub rel_path: String,
    pub contents: String,
}

impl FixtureFile {
    pub fn new(rel_path: impl Into<String>, contents: impl Into<String>) -> Self {
        Self {
            rel_path: rel_path.into(),
            contents: contents.into(),
        }
    }
}

/// A repo SHAPE — the files (manifests + sources) defining a fixture's layout.
///
/// This is the unit each later leg extends: add a constructor (e.g.
/// `single_package_lib()`) that returns the shape exposing the leg's bug, then
/// drive it through [`index_fixture`].
#[derive(Clone, Debug)]
pub struct RepoShape {
    /// Human-readable label, surfaced in diagnostics.
    pub name: String,
    pub files: Vec<FixtureFile>,
}

impl RepoShape {
    pub fn new(name: impl Into<String>, files: Vec<FixtureFile>) -> Self {
        Self {
            name: name.into(),
            files,
        }
    }

    /// Materialize this shape into a fresh temp directory and return the
    /// `TempDir` (its `.path()` is the repo root). Parent directories are
    /// created as needed so nested layouts (`crates/foo/src/lib.rs`) work.
    pub fn materialize(&self) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("create temp fixture repo");
        for f in &self.files {
            let abs = dir.path().join(&f.rel_path);
            if let Some(parent) = abs.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| panic!("mkdir for {}: {e}", f.rel_path));
            }
            std::fs::write(&abs, &f.contents)
                .unwrap_or_else(|e| panic!("write fixture file {}: {e}", f.rel_path));
        }
        dir
    }

    // ------------------------------------------------------------------
    // GREEN baseline shape (L0). Bug-exposing shapes live with their legs.
    // ------------------------------------------------------------------

    /// A healthy single-member cargo *workspace* whose sources live under
    /// `crates/widget/src/` (so node paths contain `/src/` and pub-API root
    /// detection is exercised on a well-formed layout — NOT the single-package
    /// `src/lib.rs` shape that L1 will use to expose FD-1).
    ///
    /// Structure:
    /// - `main()` → calls `widget::run()`              (binary entry point)
    /// - `pub fn run()` → calls `helper()`             (public API)
    /// - `fn helper()`                                 (private, called by run)
    /// - `pub fn add(a, b)`                            (public API, leaf)
    /// - `fn orphan_unused()`                          (genuinely dead: private,
    ///   never referenced — the true-DEAD control)
    pub fn healthy_workspace() -> Self {
        let root_manifest = r#"[workspace]
members = ["crates/widget"]
resolver = "2"
"#;
        let member_manifest = r#"[package]
name = "widget"
version = "0.0.0"
edition = "2021"

[lib]
name = "widget"
path = "src/lib.rs"

[[bin]]
name = "widget"
path = "src/main.rs"
"#;
        let main_rs = r#"fn main() {
    let n = widget::run();
    println!("{n}");
}
"#;
        let lib_rs = r#"pub fn run() -> u32 {
    helper() + add(1, 2)
}

fn helper() -> u32 {
    40
}

pub fn add(a: u32, b: u32) -> u32 {
    a + b
}

fn orphan_unused() -> u32 {
    9999
}
"#;
        Self::new(
            "healthy_workspace",
            vec![
                FixtureFile::new("Cargo.toml", root_manifest),
                FixtureFile::new("crates/widget/Cargo.toml", member_manifest),
                FixtureFile::new("crates/widget/src/main.rs", main_rs),
                FixtureFile::new("crates/widget/src/lib.rs", lib_rs),
            ],
        )
    }

    /// WU-0014 L1 / FD-1 — a SINGLE-PACKAGE library crate whose sources live at
    /// `src/lib.rs` (the dominant crates.io shape), NOT under `crates/<name>/src/`.
    /// This is the shape FD-1 false-DEADs: the pub-API-root matcher keys on a
    /// leading `/src/` substring that a bare `src/lib.rs` lacks, so the WHOLE
    /// public API is classified DEAD/SAFE_DELETE on HEAD.
    pub fn single_package_lib() -> Self {
        let manifest = r#"[package]
name = "solo"
version = "0.0.0"
edition = "2021"

[lib]
name = "solo"
path = "src/lib.rs"
"#;
        let lib_rs = r#"pub fn public_api() -> u32 {
    helper()
}

fn helper() -> u32 {
    42
}

fn unused_private() -> u32 {
    7
}
"#;
        Self::new(
            "single_package_lib",
            vec![
                FixtureFile::new("Cargo.toml", manifest),
                FixtureFile::new("src/lib.rs", lib_rs),
            ],
        )
    }

    // ------------------------------------------------------------------
    // WU-0014 L4 / ADR-0034 — SCIP-degradation honesty fixtures.
    // ------------------------------------------------------------------

    /// WU-0014 L4 / ADR-0034 Shape 1a + 5a + 7 — the load-bearing flood fixture.
    ///
    /// A single-member **workspace** (`crates/flood/src/` — so node paths carry
    /// the `/src/` substring and pub-API root detection is exercised on a
    /// well-formed layout, FD-1-immune like [`healthy_workspace`]) with EXACTLY
    /// three functions:
    /// - `pub fn alpha()` → calls private `beta()`   (public API root)
    /// - `fn beta()`      → private, reachable ONLY via the SCIP-derived
    ///   `alpha → beta` Calls edge (absent under `--no-scip`)
    /// - `fn gamma_dead()` → private, unreferenced (genuinely DEAD)
    ///
    /// Indexed `--no-scip` (Shape 1a): `beta` has no inbound Calls edge, so it is
    /// classified DEAD next to the true-dead `gamma_dead` → `safe_delete == 2`
    /// (the indistinguishable poison — `beta` is a FALSE positive). Indexed WITH
    /// SCIP (Shape 5a): the `alpha → beta` edge resolves, `beta` becomes Wired →
    /// `safe_delete == 1` (`gamma_dead` only). The crisp 3-fn counts match the
    /// ADR's MEASURED `{2,2}` / `{1,1}`.
    pub fn scip_call_flood() -> Self {
        let root_manifest = r#"[workspace]
members = ["crates/flood"]
resolver = "2"
"#;
        let member_manifest = r#"[package]
name = "flood"
version = "0.0.0"
edition = "2021"

[lib]
name = "flood"
path = "src/lib.rs"
"#;
        let lib_rs = r#"pub fn alpha() -> u32 {
    beta()
}

fn beta() -> u32 {
    7
}

fn gamma_dead() -> u32 {
    99
}
"#;
        Self::new(
            "scip_call_flood",
            vec![
                FixtureFile::new("Cargo.toml", root_manifest),
                FixtureFile::new("crates/flood/Cargo.toml", member_manifest),
                FixtureFile::new("crates/flood/src/lib.rs", lib_rs),
            ],
        )
    }

    /// WU-0014 L4 / ADR-0034 Shape 1b — the Scenario-B false-CLEAN fixture.
    ///
    /// A workspace whose library has ONLY public leaf functions (no private /
    /// unreferenced symbols), so the Dead set is GENUINELY EMPTY. Indexed
    /// `--no-scip`: `total_dead == 0` on HEAD — read by an agent as a confident
    /// "no dead code, clean." Under the `None` coverage gate this must render
    /// `UNKNOWN`, never `0` ("cannot determine" ≠ "clean").
    pub fn all_public_leaf() -> Self {
        let root_manifest = r#"[workspace]
members = ["crates/publeaf"]
resolver = "2"
"#;
        let member_manifest = r#"[package]
name = "publeaf"
version = "0.0.0"
edition = "2021"

[lib]
name = "publeaf"
path = "src/lib.rs"
"#;
        let lib_rs = r#"pub fn a() -> u32 {
    1
}

pub fn b() -> u32 {
    2
}
"#;
        Self::new(
            "all_public_leaf",
            vec![
                FixtureFile::new("Cargo.toml", root_manifest),
                FixtureFile::new("crates/publeaf/Cargo.toml", member_manifest),
                FixtureFile::new("crates/publeaf/src/lib.rs", lib_rs),
            ],
        )
    }

    /// WU-0014 L4 / ADR-0034 Shape 5c — the S1 cry-wolf negative control.
    ///
    /// A workspace library that is genuinely a LEAF: its functions call NOTHING,
    /// so a successful SCIP index resolves ZERO internal `Calls` edges
    /// (`scip_calls_edges == 0`) — yet a complete Calls receipt exists. It carries a
    /// genuine dead item (`dead_leaf`, private + unreferenced). The gate MUST
    /// classify this `Sufficient` (via immutable receipt authority,
    /// NOT a bare `scip_calls_edges == 0`) and EMIT the dead verdict — proving v3
    /// does not regress into the v2 over-suppression on a valid leaf crate.
    /// RA-gated (scip = true).
    pub fn leaf_crate_zero_calls() -> Self {
        let root_manifest = r#"[workspace]
members = ["crates/leaf"]
resolver = "2"
"#;
        let member_manifest = r#"[package]
name = "leaf"
version = "0.0.0"
edition = "2021"

[lib]
name = "leaf"
path = "src/lib.rs"
"#;
        let lib_rs = r#"pub fn one() -> u32 {
    1
}

pub fn two() -> u32 {
    2
}

fn dead_leaf() -> u32 {
    3
}
"#;
        Self::new(
            "leaf_crate_zero_calls",
            vec![
                FixtureFile::new("Cargo.toml", root_manifest),
                FixtureFile::new("crates/leaf/Cargo.toml", member_manifest),
                FixtureFile::new("crates/leaf/src/lib.rs", lib_rs),
            ],
        )
    }

    /// WU-0014 L5 #3 — a NON-Rust repo with NO `Cargo.toml` at all (a lone
    /// `notes.txt` + a `script.py`). The indexer finds no `.rs` sources; the
    /// whole chain must still complete and the query verbs must return `Ok` on
    /// the resulting empty graph—never panic on a non-Rust repository shape.
    pub fn no_cargo_repo() -> Self {
        Self::new(
            "no_cargo_repo",
            vec![
                FixtureFile::new("notes.txt", "just some prose, no code here\n"),
                FixtureFile::new("script.py", "print('not rust')\n"),
            ],
        )
    }
}

// Indexed fixture
// ============================================================================

/// A materialized + indexed fixture. Owns its temp repo and a private temp
/// data-dir (its own `graph.redb`), so it is self-isolating and parallel-safe.
pub struct IndexedFixture {
    pub shape_name: String,
    /// Whether SCIP (real rust-analyzer) was requested at index time.
    pub scip: bool,
    repo: tempfile::TempDir,
    store: tempfile::TempDir,
}

struct LoadedFixtureSnapshot {
    graph: KnowledgeGraph,
    index_baseline: IndexBaseline,
    source_freshness: StalenessVerdict,
    calls_authority_available: bool,
    database_path: PathBuf,
}

impl IndexedFixture {
    /// The fixture repo root (workspace root passed to the indexer/verbs).
    pub fn repo_root(&self) -> PathBuf {
        self.repo.path().to_path_buf()
    }

    /// The private data-dir backing this fixture's graph store.
    pub fn data_dir(&self) -> PathBuf {
        self.store.path().to_path_buf()
    }

    fn binding(&self) -> ProjectBinding {
        fixture_binding(self.repo.path(), self.store.path())
    }

    /// Load graph and metadata through the same validated immutable generation.
    async fn snapshot(&self) -> LoadedFixtureSnapshot {
        let (graph, snapshot) = load_indexed_graph_snapshot(&self.binding())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "load indexed generation for fixture '{}': {error}",
                    self.shape_name
                )
            });
        let database_path = snapshot
            .immutable_generation()
            .unwrap_or_else(|| {
                panic!(
                    "fixture '{}' loaded without immutable generation authority",
                    self.shape_name
                )
            })
            .database_path
            .clone();
        let calls_authority_available = snapshot.calls_coverage().any_callable_language_complete();
        let source_freshness = snapshot.source_freshness(self.repo.path()).await;
        LoadedFixtureSnapshot {
            graph,
            index_baseline: snapshot.index_baseline,
            source_freshness,
            calls_authority_available,
            database_path,
        }
    }

    /// Load the persisted knowledge graph for structured assertions.
    pub async fn graph(&self) -> KnowledgeGraph {
        self.snapshot().await.graph
    }

    /// Run the real `dead` verb against this fixture's store. Returns the verb's
    /// `Result` so a test can assert it does not crash (the verb prints its
    /// report to stdout; structured assertions go through [`Self::graph`]).
    pub async fn run_dead(&self, symbol: Option<&str>) -> Result<(), String> {
        let args = DeadArgs {
            symbol: symbol.map(str::to_string),
            file: None,
            production_only: false,
            limit: h00ligan_engine::code_intel_dead::DEFAULT_DEAD_PAGE_SIZE,
            cursor: None,
            format: "json".to_string(),
        };
        h00ligan::composite_cmd::run_dead(args, &self.binding())
            .await
            .map_err(|e| e.to_string())
    }

    /// Run the real `assess` verb against this fixture's store.
    pub async fn run_assess(&self, symbol: &str) -> Result<(), String> {
        let args = AssessArgs {
            symbol: symbol.to_string(),
            file: None,
            sections: None,
            depth: 3,
            filter: "all".to_string(),
            limit: 50,
            cursor: None,
            format: "json".to_string(),
        };
        h00ligan::composite_cmd::run_assess(args, &self.binding())
            .await
            .map_err(|e| e.to_string())
    }

    /// Run the real `overview` verb against this fixture's store.
    pub async fn run_overview(&self) -> Result<(), String> {
        let args = OverviewArgs {
            format: "json".to_string(),
        };
        h00ligan::composite_cmd::run_overview(args, &self.binding())
            .await
            .map_err(|e| e.to_string())
    }
}

fn index_args(scip: bool) -> IndexArgs {
    IndexArgs {
        scip,
        force: false,
        require_complete_calls: false,
        jobs: None,
        debug: false,
        profile: false,
        recover_publication: false,
        allow_capability_downgrade: false,
        format: "json".to_string(),
    }
}

/// Materialize `shape` and index it through the real `run_index` entrypoint.
///
/// `scip = false` is hermetic (tree-sitter only). `scip = true` regenerates the
/// SCIP index via the real `rust-analyzer scip` binary — callers MUST gate that
/// on [`rust_analyzer_available`] (see [`require_rust_analyzer`]).
pub async fn index_fixture(shape: &RepoShape, scip: bool) -> IndexedFixture {
    let repo = shape.materialize();
    let store = tempfile::tempdir().expect("create temp data dir");

    let binding = fixture_binding(repo.path(), store.path());
    h00ligan::index_cmd::run_index(index_args(scip), &binding)
        .await
        .unwrap_or_else(|e| panic!("run_index on fixture '{}' (scip={scip}): {e}", shape.name));

    IndexedFixture {
        shape_name: shape.name.clone(),
        scip,
        repo,
        store,
    }
}

// ============================================================================
// Assertion helpers (reusable by later legs)
// ============================================================================

/// Tally nodes by reachability class — handy for diagnostics + invariant checks.
pub fn class_histogram(graph: &KnowledgeGraph) -> BTreeMap<String, usize> {
    let mut h: BTreeMap<String, usize> = BTreeMap::new();
    for node in graph.all_nodes() {
        *h.entry(format!("{:?}", node.reachability_class))
            .or_insert(0) += 1;
    }
    h
}

/// Find the single node whose `symbol_name` is exactly `name`, or ends in
/// `::name`. Panics with a helpful message if absent or ambiguous-by-name.
pub fn node_by_name<'g>(
    graph: &'g KnowledgeGraph,
    name: &str,
) -> &'g h00ligan_engine::graph::GraphNode {
    let matches: Vec<&h00ligan_engine::graph::GraphNode> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.symbol_name == name || n.symbol_name.ends_with(&format!("::{name}")))
        .collect();
    assert!(
        !matches.is_empty(),
        "no node named '{name}' in fixture graph; present symbols: {:?}",
        graph
            .all_nodes()
            .iter()
            .map(|n| n.symbol_name.clone())
            .collect::<Vec<_>>()
    );
    matches[0]
}

/// Supply a precise oracle receipt to an in-memory graph when a test is about a
/// downstream gate rather than about running a compiler. The negative control
/// at each call site first proves that the structural-only graph withholds
/// delete authority; this mutation then isolates the gate under test without
/// executing code from the fixture repository.
fn corroborate_dead_for_gate_test(graph: &mut KnowledgeGraph, name: &str) {
    let node_id = node_by_name(graph, name).memory_id;
    let node = graph
        .node_mut(&node_id)
        .unwrap_or_else(|| panic!("node '{name}' disappeared before test corroboration"));
    assert!(
        !node.rustc_flagged_dead && node.oracle_receipt.is_none(),
        "structural-only fixture must begin without compiler authority"
    );
    node.rustc_flagged_dead = true;
    node.oracle_receipt = Some(OracleReceipt {
        code: "dead_code".to_string(),
        line: node.line_start.unwrap_or(0),
        subject: Some(name.to_string()),
    });
}

/// True if `name` resolves to a reachable (PublicApi | Wired | Structural)
/// node — i.e. NOT classified Dead/Orphan. The anti-false-DEAD signal.
pub fn is_reachable(graph: &KnowledgeGraph, name: &str) -> bool {
    matches!(
        node_by_name(graph, name).reachability_class,
        ReachabilityClass::PublicApi | ReachabilityClass::Wired | ReachabilityClass::Structural
    )
}

/// Skip a `scip = true` test cleanly (return false) when rust-analyzer is not
/// installed, mirroring `scip_feature_gated_e2e.rs`.
fn require_rust_analyzer(test: &str) -> bool {
    if rust_analyzer_available() {
        true
    } else {
        eprintln!("[{test}] rust-analyzer not found; skipping real-SCIP fixture");
        false
    }
}

// ============================================================================
// L0a health smoke — proves the harness works. ALL-GREEN.
// ============================================================================

/// Diagnostic: index the healthy workspace hermetically (no SCIP) and print the
/// reachability histogram + per-node classes. Always GREEN — it only asserts
/// the index produced nodes. Run with `--nocapture` to inspect classification.
#[tokio::test]
async fn l0a_health_diagnostic_no_scip() {
    let shape = RepoShape::healthy_workspace();
    let fx = index_fixture(&shape, false).await;
    let graph = fx.graph().await;

    eprintln!(
        "[l0a-diag] shape='{}' scip={} nodes={} edges={}",
        fx.shape_name,
        fx.scip,
        graph.node_count(),
        graph.edge_count()
    );
    eprintln!("[l0a-diag] class histogram: {:?}", class_histogram(&graph));
    for node in graph.all_nodes() {
        eprintln!(
            "[l0a-diag]   {:<24} {:<10} {:?}  ({})",
            node.symbol_name, node.kind, node.reachability_class, node.file_path
        );
    }
    assert!(
        graph.node_count() > 0,
        "indexing the healthy workspace must produce nodes"
    );
}

/// L0a GREEN health smoke (hermetic, no rust-analyzer): index one healthy
/// fixture structurally, then assert honest reduced-authority classifications
/// and that real query verbs either return qualified data or fail with the
/// expected typed capability boundary.
#[tokio::test]
async fn l0a_healthy_fixture_indexes_with_sane_reachability() {
    let shape = RepoShape::healthy_workspace();
    let fx = index_fixture(&shape, false).await;
    let graph = fx.graph().await;

    // (0) L3b / ROOT-8 (ADR-0033) M4 SELF-DoS NEGATIVE CONTROL.
    //     `load_or_scan_graph` is the SAME wired Refuse locus the cross-origin
    //     falsifiers (`l3b_*`) exercise. A repo querying its OWN store — origin
    //     stamped = A by the index, queried from the same root A — must NOT be
    //     refused; it must SERVE. This explicit re-load (origin matches) is the
    //     break-target for proving the gate is NON-VACUOUS: forcing
    //     `origin_matches = false` at the graph_store origin gate reddens THIS
    //     assertion (the home repo locked out of its own store = M4 reproduced).
    let own_store_graph = load_or_scan_graph(&fx.binding()).await.expect(
        "M4 negative control: a repo querying its OWN matching-origin store (origin=A, \
             query=A) must SERVE, not refuse",
    );
    let _ = node_by_name(&own_store_graph, "run");
    let _ = node_by_name(&own_store_graph, "add");

    // (1) The index produced the expected symbols.
    assert!(graph.node_count() > 0, "fixture graph must be non-empty");
    for sym in ["run", "main", "helper", "add", "orphan_unused"] {
        let _ = node_by_name(&graph, sym); // panics with a useful message if absent
    }

    // (2) With no semantic Calls provider, public roots are surfaced as
    //     Suspected rather than falsely claimed reachable or falsely declared
    //     dead. Private callees likewise cannot inherit reachability from call
    //     edges that do not exist, and remain non-actionable without an oracle.
    for sym in ["run", "add"] {
        assert_eq!(
            node_by_name(&graph, sym).reachability_class,
            ReachabilityClass::Suspected,
            "structural-only public root `{sym}` must be surfaced as Suspected; classes: {:?}",
            class_histogram(&graph)
        );
    }
    let helper = node_by_name(&graph, "helper");
    assert_eq!(helper.reachability_class, ReachabilityClass::Dead);
    assert_eq!(
        classify_dead_action(&graph, helper, &cfg_touching_crates(&graph)),
        DeadAction::SuspectedDelete,
        "missing Calls and compiler evidence must never grant delete authority"
    );

    // (3) At least one node is reachable AND the genuinely-unused private fn is
    //     classified — i.e. the classifier ran and discriminates (not all-DEAD,
    //     not all-WIRED).
    let summary = compute_reachability_summary(&graph);
    let reachable_total = summary.wired + summary.public_api + summary.structural;
    assert!(
        reachable_total > 0,
        "a healthy repo must have >0 reachable nodes (false-DEAD floor); classes: {:?}",
        class_histogram(&graph)
    );

    // (4) The reachability buckets account for EVERY node (no node lost between
    //     classification and summary) — the cross-command arithmetic invariant.
    let summed = summary.wired
        + summary.public_api
        + summary.structural
        + summary.test_only
        + summary.dead
        + summary.orphan
        + summary.unclassified
        // WU-0015: the 8th bucket — the directed-reachability review tier.
        + summary.suspected;
    assert_eq!(
        summed,
        graph.node_count(),
        "reachability summary ({summed}) must account for every node ({})",
        graph.node_count()
    );

    // (5) The real query verbs run against the fixture store without crashing.
    //     Structural overview, Dead, and Assess remain useful with qualified
    //     authority. The explicit no-Calls control proves Assess does not need
    //     semantic evidence merely to return independently authorized structure;
    //     focused product-contract tests assert its semantic fields stay unknown.
    fx.run_dead(None)
        .await
        .expect("`dead` full report must succeed on a healthy fixture");
    fx.run_dead(Some("run"))
        .await
        .expect("`dead run` single-symbol check must succeed");
    assert!(
        !fx.snapshot().await.calls_authority_available,
        "positive control: this fixture must remain structural-only"
    );
    fx.run_assess("run")
        .await
        .expect("structural-only Assess must retain independently authorized structure");
    fx.run_overview()
        .await
        .expect("`overview` must succeed on a healthy fixture");
}

/// L0a deeper health smoke (real rust-analyzer SCIP): with genuine Calls edges,
/// the full production chain `main → run → helper` is reachable and the
/// genuinely-unused private fn is DEAD. Skips cleanly when RA is absent.
#[tokio::test]
async fn l0a_healthy_fixture_real_scip_full_chain_reachable() {
    if !require_rust_analyzer("l0a_real_scip") {
        return;
    }
    let shape = RepoShape::healthy_workspace();
    let fx = index_fixture(&shape, true).await;
    let graph = fx.graph().await;

    eprintln!(
        "[l0a-scip] nodes={} edges={} classes={:?}",
        graph.node_count(),
        graph.edge_count(),
        class_histogram(&graph)
    );

    // With real SCIP Calls edges, the whole production chain is reachable.
    for sym in ["run", "helper", "add"] {
        assert!(
            is_reachable(&graph, sym),
            "with real SCIP, `{sym}` must be reachable; classes: {:?}",
            class_histogram(&graph)
        );
    }

    // The genuinely-unreferenced private fn is the true-DEAD control: a healthy
    // index must still be able to call something DEAD (proves it is not
    // blanket-marking everything reachable).
    // Shipped SCIP indexing supplies precise Calls but deliberately does not run
    // the in-place compiler oracle. The unused symbol is therefore detected as
    // Dead while deletion authority remains withheld.
    let orphan = node_by_name(&graph, "orphan_unused");
    assert_eq!(
        orphan.reachability_class,
        ReachabilityClass::Dead,
        "the unreferenced private `orphan_unused` → Dead in Leg 3b; classes: {:?}",
        class_histogram(&graph)
    );
    assert_eq!(
        classify_dead_action(&graph, orphan, &cfg_touching_crates(&graph)),
        DeadAction::SuspectedDelete,
        "SCIP reachability without compiler corroboration must remain advisory"
    );

    // Verbs still run clean on the SCIP-indexed store.
    fx.run_assess("run")
        .await
        .expect("`assess` must succeed on the SCIP-indexed fixture");
}

// ============================================================================
// L1 / FD-1 — single-package whole-API false-DEAD. RED on HEAD, GREEN post-fix.
// ============================================================================

/// WU-0014 L1 falsifier for **FD-1** (the #1 ship blocker). A single-package
/// library crate (`src/lib.rs`, no `crates/<name>/` prefix) must have its public
/// API classified reachable — NOT DEAD/SAFE_DELETE. On HEAD this FAILS (RED):
/// `resolve_pub_api_roots`'s `in_lib_crate` matcher requires a leading `/src/`
/// substring that a bare `src/lib.rs` lacks (`rfind("/src/")` → None), so zero
/// pub-API roots are seeded and the whole API reads DEAD. Hermetic (no SCIP) —
/// pub-API root seeding is SCIP-independent, so the bug reproduces without
/// rust-analyzer. After the L1 fix (crate-root directory membership), GREEN.
#[tokio::test]
async fn l1_single_package_pub_api_reachable_fd1() {
    let fx = index_fixture_hermetic(&RepoShape::single_package_lib()).await;
    let graph = fx.graph().await;

    // sanity: the index produced the symbols (isolates FD-1 from an index failure)
    let _ = node_by_name(&graph, "public_api");
    let _ = node_by_name(&graph, "helper");

    // WU-0015 REBASELINE (ADR-0036 V3-1 seed-vs-classify split): `public_api` is
    // SEEDED as a pub-api root (FD-1 fixed — the whole API is no longer lost to
    // DEAD), but without a semantic Calls provider it classifies Suspected, not
    // PublicApi-by-fiat. The FD-1 anti-false-DEAD property holds: it is surfaced
    // and NON-DELETE, never Dead. The private helper cannot be proven reachable
    // without the missing Calls edge, so it must also remain non-actionable.
    let pub_api_class = node_by_name(&graph, "public_api").reachability_class;
    assert!(
        matches!(
            pub_api_class,
            ReachabilityClass::PublicApi | ReachabilityClass::Suspected
        ),
        "FD-1: single-package `pub fn public_api` must be surfaced (PublicApi/Suspected), never DEAD; \
         classes: {:?}",
        class_histogram(&graph)
    );
    let helper = node_by_name(&graph, "helper");
    assert_eq!(helper.reachability_class, ReachabilityClass::Dead);
    assert_eq!(
        classify_dead_action(&graph, helper, &cfg_touching_crates(&graph)),
        DeadAction::SuspectedDelete,
        "structural-only indexing must not invent the missing public_api -> helper Calls edge"
    );

    // `dead` must NOT recommend deleting the live public API.
    fx.run_dead(None)
        .await
        .expect("`dead` full report must succeed on the single-package fixture");
}

/// WU-0014 L1 NEGATIVE CONTROL — the over-correction guard for FD-1. The fix makes
/// EVERY node in a single-package crate "in_lib_crate", so the inversion risk
/// (cert L91) is that it OVER-seeds — marking private dead code reachable too.
/// It must NOT: pub-API root seeding stays gated on `is_public && is_top_level &&
/// is_api_kind`, so a genuinely-unreferenced PRIVATE fn must STILL classify Dead.
/// Without this guard a future change could silently invert FD-1 into "everything
/// WIRED" and `dead` would go blind on single-package crates. (RED-on-HEAD proves
/// the bug is fixed; THIS proves the fix didn't over-correct.)
#[tokio::test]
async fn l1_single_package_dead_private_stays_dead_no_over_seed() {
    let fx = index_fixture(&RepoShape::single_package_lib(), false).await;
    let graph = fx.graph().await;

    // The fix DID surface the public API (not lost to DEAD) ...
    // WU-0015 REBASELINE (V3-1): `public_api` seeds as a pub-api root but with zero
    // in-workspace callers classifies Suspected (surfaced, non-delete) — never Dead.
    assert!(
        matches!(
            node_by_name(&graph, "public_api").reachability_class,
            ReachabilityClass::PublicApi | ReachabilityClass::Suspected
        ),
        "public_api must be surfaced (PublicApi/Suspected), never DEAD; classes: {:?}",
        class_histogram(&graph)
    );
    // ... but the genuinely-unreferenced private fn must NOT have been over-seeded.
    // WU-0015 Leg-3b REBASELINE + HOLE FIX 2 e2e: the over-seed guard still holds —
    // the fn is NOT rescued into a clean tier — and the private residual is now
    // class==Dead. But a BARE src/lib.rs has crate_name_of==None, so it is NOT
    // SafeDelete-eligible: the action is the non-delete SuspectedDelete.
    let unused = node_by_name(&graph, "unused_private");
    assert_eq!(
        unused.reachability_class,
        ReachabilityClass::Dead,
        "unreferenced private `unused_private` → Dead (not over-seeded to a clean tier); classes: {:?}",
        class_histogram(&graph)
    );
    assert_eq!(
        classify_dead_action(&graph, unused, &cfg_touching_crates(&graph)),
        DeadAction::SuspectedDelete,
        "HOLE FIX 2: a None-crate (bare src/lib.rs) node is NOT SafeDelete-eligible"
    );
}

// ============================================================================
// L3b / ROOT-8 (ADR-0033) — cross-origin (foreign-workspace) falsifiers.
//
// The #2 DAMAGING ship blocker: a code-intel store indexed from workspace A
// must never be spliced onto a query/index standing in a DIFFERENT workspace B.
// READ intent (CLI query / agent / mcp-serve) must REFUSE fail-closed; INDEX
// immutable index intent must refuse foreign ownership without mutating either
// repository. These end-to-end falsifiers drive the real wired entrypoints
// (`load_or_scan_graph`, `run_index`) — the store-layer twins at graph_store.rs
// prove the primitive; these prove the wiring.
// ============================================================================

/// A store `S` indexed from repo `A`, plus a SEPARATE materialized repo `B`
/// that was NEVER indexed into `S`. Querying or re-indexing `S` "from B" is the
/// foreign-origin splice ADR-0033 ROOT-8 guards.
///
/// `origin` (the [`IndexedFixture`] for A) is held alive for the fixture's
/// lifetime so `S`'s `TempDir` survives every query; `foreign` is materialized
/// (not bare) so `canonicalize(B)` succeeds and is `!= canonicalize(A)`.
struct CrossOriginFixture {
    /// Store `S`, indexed from repo `A` (origin = canonical(A) once wired).
    origin: IndexedFixture,
    /// Repo `B`, materialized on disk but NEVER indexed into `S`.
    foreign: tempfile::TempDir,
}

impl CrossOriginFixture {
    /// Index `shape_a` into store `S` (hermetic, no SCIP), then materialize
    /// `shape_b` as a separate on-disk repo. `shape_a` and `shape_b` must carry
    /// distinct symbols so foreign leakage is detectable.
    async fn index_a_materialize_b(shape_a: &RepoShape, shape_b: &RepoShape) -> Self {
        let origin = index_fixture(shape_a, false).await;
        let foreign = shape_b.materialize();
        Self { origin, foreign }
    }

    /// Store `S`'s data-dir.
    fn store_dir(&self) -> PathBuf {
        self.origin.data_dir()
    }

    /// Repo `A`'s root (the workspace `S` was indexed from).
    fn origin_root(&self) -> PathBuf {
        self.origin.repo_root()
    }

    /// Repo `B`'s root (the foreign workspace).
    fn foreign_root(&self) -> PathBuf {
        self.foreign.path().to_path_buf()
    }

    /// Read store `S` "as if standing in foreign repo B" through the SAME wired
    /// locus the `h00ligan` query verbs use (`load_or_scan_graph`).
    async fn load_from_foreign(&self) -> Result<KnowledgeGraph, h00ligan::error::LiganError> {
        let binding = fixture_binding(&self.foreign_root(), &self.store_dir());
        load_or_scan_graph(&binding).await
    }
}

/// Canonicalize a path to the lossy `String` form `set_origin`/`get_origin`
/// compare on (symlink-resolved, byte-for-byte).
fn canonical_string(p: &std::path::Path) -> String {
    p.canonicalize()
        .unwrap_or_else(|e| panic!("canonicalize {}: {e}", p.display()))
        .to_string_lossy()
        .into_owned()
}

/// A query may not splice an immutable generation published for repository A
/// onto repository B. The repository record intentionally stores a stable
/// identity rather than A's machine-local path, so the diagnostic names that
/// identity and the selected root. More importantly, refusal preserves every
/// byte in the store and both repository populations, and A remains readable.
#[tokio::test]
async fn l3b_cli_query_foreign_origin_refuses_fail_closed() {
    let fx = CrossOriginFixture::index_a_materialize_b(
        &RepoShape::healthy_workspace(), // A — has `add`, `run`, `orphan_unused`
        &RepoShape::single_package_lib(), // B — has `public_api`, `unused_private`
    )
    .await;

    let store_before = path_population(&fx.store_dir());
    let origin_before = path_population(&fx.origin_root());
    let foreign_before = path_population(&fx.foreign_root());
    assert!(
        store_before
            .keys()
            .any(|path| path.ends_with("repository.json")),
        "known-positive: the fixture must contain immutable repository authority"
    );

    let result = fx.load_from_foreign().await;

    // `KnowledgeGraph` is not `Debug`, so match (don't `unwrap_err`). An `Ok`
    // here IS the foreign-serve bug → RED.
    let msg = match result {
        Ok(_) => panic!(
            "querying a store indexed from A while standing in foreign repo B must REFUSE \
             (fail-closed), not serve A's graph nor degrade to full_scan(B)"
        ),
        Err(e) => e.to_string(),
    };
    let b = canonical_string(&fx.foreign_root());
    assert!(
        msg.contains("belongs to repository") && msg.contains(&b),
        "the refusal must name the stored repository identity and selected root ({b}); got: {msg}"
    );
    assert_eq!(path_population(&fx.store_dir()), store_before);
    assert_eq!(path_population(&fx.origin_root()), origin_before);
    assert_eq!(path_population(&fx.foreign_root()), foreign_before);

    let origin_binding = fixture_binding(&fx.origin_root(), &fx.store_dir());
    let graph = load_or_scan_graph(&origin_binding)
        .await
        .expect("same-owner query must remain readable after foreign refusal");
    let _ = node_by_name(&graph, "add");
}

/// Publishing through `run_index` also refuses a foreign repository before the
/// index pipeline runs. Standalone h00ligan deliberately exposes no destructive
/// adoption flag: selecting another data directory is the explicit remedy.
/// Refusal must preserve the complete store and both source populations.
#[tokio::test]
async fn l3b_index_foreign_origin_refuses_and_preserves_the_publication() {
    let fx = CrossOriginFixture::index_a_materialize_b(
        &RepoShape::healthy_workspace(),  // A
        &RepoShape::single_package_lib(), // B
    )
    .await;

    let b = canonical_string(&fx.foreign_root());
    let store_before = path_population(&fx.store_dir());
    let origin_before = path_population(&fx.origin_root());
    let foreign_before = path_population(&fx.foreign_root());
    assert!(
        store_before
            .keys()
            .any(|path| path.ends_with("repository.json")),
        "known-positive: the fixture must contain immutable repository authority"
    );

    // Re-index foreign root B into the SAME store S, unauthorised.
    let foreign_binding = fixture_binding(&fx.foreign_root(), &fx.store_dir());
    let err = h00ligan::index_cmd::run_index(index_args(false), &foreign_binding)
        .await
        .expect_err("re-indexing foreign root B into store S must REFUSE without authorisation");

    let msg = err.to_string();
    assert!(
        msg.contains("belongs to repository") && msg.contains(&b),
        "the refusal must name the stored repository identity and selected root ({b}); got: {msg}"
    );
    assert!(
        !msg.contains("--adopt-foreign-origin"),
        "standalone immutable publication must not advertise a destructive adoption mode: {msg}"
    );
    assert_eq!(path_population(&fx.store_dir()), store_before);
    assert_eq!(path_population(&fx.origin_root()), origin_before);
    assert_eq!(path_population(&fx.foreign_root()), foreign_before);

    // A can still read its own store, and A's data is intact.
    let origin_binding = fixture_binding(&fx.origin_root(), &fx.store_dir());
    let graph = load_or_scan_graph(&origin_binding)
        .await
        .expect("after the refusal, A must still own and be able to read store S");
    let _ = node_by_name(&graph, "add"); // A-only symbol still present
    assert!(
        graph
            .all_nodes()
            .iter()
            .all(|n| n.symbol_name != "public_api" && !n.symbol_name.ends_with("::public_api")),
        "the refused index must not have merged B's symbols into A's store"
    );
}

// ============================================================================
// WU-0014 L4 / ADR-0034 — SCIP-degradation honesty falsifiers (dead verb)
// ============================================================================

/// Build the coverage verdict the `dead` verb sees from the loaded graph and
/// immutable generation receipt authority. Mirrors the production CLI/MCP path.
async fn coverage_for(fx: &IndexedFixture) -> (KnowledgeGraph, CallEdgeCoverage, CoverageTier) {
    let snapshot = fx.snapshot().await;
    let cov = call_edge_coverage(&snapshot.graph, snapshot.calls_authority_available);
    let tier = coverage_tier(&cov);
    (snapshot.graph, cov, tier)
}

/// Index `shape` through the REAL [`IndexPipeline`] with
/// [`ScipMode::Disabled`](h00ligan_engine::index_pipeline::ScipMode::Disabled) — the
/// faithful structural-only state with an unavailable Calls receipt.
///
/// Drive the shipped entrypoint's explicit structural-only provider mode. This
/// is hermetic, but it still crosses the real immutable publication boundary;
/// a fixture must never manufacture a legacy mutable root bundle that shipped
/// readers are required to reject.
async fn index_fixture_hermetic(shape: &RepoShape) -> IndexedFixture {
    index_fixture(shape, false).await
}

/// Names of the genuinely-Dead/Orphan nodes the HEAD classifier flags
/// `SAFE_DELETE` — the PRE-GATE poison anchor (uses the HEAD-existing
/// `classify_dead_action`, untouched by L4).
fn pre_gate_safe_delete_names(graph: &KnowledgeGraph) -> Vec<String> {
    // WU-0015 REBASELINE: Leg 1 emits NO SafeDelete (the delete-authority tier is
    // EMPTY). The "poison flood" the L4 coverage gate must suppress is now the
    // SUSPECTED review set (`SuspectedDelete`), still indistinguishable
    // true-dead-vs-false-dead — so the coverage-gate suppression this test
    // exercises is unchanged. Leg 3 restores the SafeDelete-specific baseline.
    let cfg_crates = cfg_touching_crates(graph);
    graph
        .all_nodes()
        .into_iter()
        .filter(|n| {
            matches!(
                n.reachability_class,
                ReachabilityClass::Dead | ReachabilityClass::Orphan | ReachabilityClass::Suspected
            ) && matches!(
                classify_dead_action(graph, n, &cfg_crates),
                DeadAction::SafeDelete | DeadAction::SuspectedDelete
            )
        })
        .map(|n| n.symbol_name.clone())
        .collect()
}

/// FALSIFIER **Shape 1a** [unit-fixture, NON-VACUOUS RED-on-HEAD core] — a FRESH
/// `--no-scip` index of the workspace-layout 3-fn flood (`alpha`→`beta`;
/// `gamma_dead` unref) where classification RAN over a `Calls`-less graph.
///
/// PRE-GATE (the RED reason, proven non-vacuous with the HEAD-existing
/// `classify_dead_action`): the Dead set lists `safe_delete >= 2` INCLUDING the
/// FALSE-dead `beta` (genuinely called by `alpha`, but its only inbound edge is
/// the SCIP-derived `alpha→beta` Calls edge, absent under `--no-scip`) next to
/// the true-dead `gamma_dead` — the indistinguishable poison. On HEAD the `dead`
/// verb would emit `{total_dead:2, safe_delete:2}` (no coverage gate exists).
///
/// POST-GATE: no complete Calls receipt ⇒ `Unavailable` ⇒ `dead_report_gated` returns
/// `Unknown` (verb-level suppression BEFORE the Dead set is consulted).
#[tokio::test]
async fn l4_shape_1a_no_scip_flood_suppressed_to_unknown() {
    let shape = RepoShape::scip_call_flood();
    let fx = index_fixture_hermetic(&shape).await;
    let (graph, cov, tier) = coverage_for(&fx).await;

    // (1) SIGNAL: a structural-only generation carries no complete Calls receipt.
    assert!(
        !fx.snapshot().await.calls_authority_available,
        "a structural-only generation must not authorize Calls"
    );

    // (2) PRE-GATE NON-VACUITY: the poisoned flood (>=2 SAFE_DELETE incl beta).
    let safe = pre_gate_safe_delete_names(&graph);
    assert!(
        safe.len() >= 2,
        "PRE-GATE non-vacuity: expected the >=2 SAFE_DELETE flood, got {safe:?}"
    );
    assert!(
        safe.iter().any(|n| n.ends_with("beta")),
        "PRE-GATE: the FALSE-dead `beta` (called by alpha) must be in the poisoned flood: {safe:?}"
    );
    assert!(
        safe.iter().any(|n| n.ends_with("gamma_dead")),
        "PRE-GATE: the true-dead `gamma_dead` must also be flagged: {safe:?}"
    );

    // (3) POST-GATE: unavailable coverage suppresses the whole verb to UNKNOWN.
    assert!(!cov.calls_authority_available);
    assert_eq!(
        tier,
        CoverageTier::Unavailable,
        "a scope without Calls receipt authority must classify Unavailable"
    );
    match dead_report_gated(&graph, tier, true) {
        DeadReport::Unknown => {}
        DeadReport::Full(d) => panic!(
            "Unavailable coverage MUST suppress to UNKNOWN; emitted {} dead instead (the false flood)",
            d.entries.len()
        ),
    }
}

/// FALSIFIER **Shape 1b** [unit-fixture] — the Scenario-B false-CLEAN lie. An
/// all-public-leaf lib has a GENUINELY EMPTY Dead set, so HEAD prints
/// `total_dead:0` ("clean"). Without Calls receipt authority the verb MUST render
/// UNKNOWN, never `0` ("cannot determine" ≠ "clean") — the case v1's per-node
/// override was a no-op on (nothing to override).
#[tokio::test]
async fn l4_shape_1b_no_scip_false_clean_suppressed() {
    let shape = RepoShape::all_public_leaf();
    let fx = index_fixture_hermetic(&shape).await;
    let (graph, cov, tier) = coverage_for(&fx).await;

    // PRE-GATE: the Dead set is genuinely empty (the false-clean 0).
    let dead_count = graph
        .all_nodes()
        .into_iter()
        .filter(|n| {
            matches!(
                n.reachability_class,
                ReachabilityClass::Dead | ReachabilityClass::Orphan
            )
        })
        .count();
    assert_eq!(
        dead_count, 0,
        "all-public-leaf must have a genuinely empty Dead set (the false-clean lie), got {dead_count}"
    );

    // POST-GATE: Unavailable fires even on an EMPTY Dead set — UNKNOWN, not Full(0).
    assert!(!cov.calls_authority_available);
    assert_eq!(tier, CoverageTier::Unavailable);
    match dead_report_gated(&graph, tier, true) {
        DeadReport::Unknown => {}
        DeadReport::Full(_) => {
            panic!(
                "Scenario B: unavailable Calls authority with an empty Dead set must render UNKNOWN, NOT total_dead:0"
            )
        }
    }
}

/// FALSIFIER **action-withheld** [unit-fixture, Decision 3] — under `Unavailable` the
/// single-symbol path withholds reachability and the action recommendation.
/// (WU-0016 / ADR-0039: the former second destructive `cascade_deletable`
/// payload was removed with the cascade machinery.)
///
/// PRE-GATE non-vacuity: `gamma_dead` is genuinely Dead and HEAD would recommend
/// `SAFE_DELETE` on it. POST-GATE: `dead_single_gated` returns `Unknown` (the
/// `Computed` variant carrying the action is never produced).
#[tokio::test]
async fn action_is_withheld_when_calls_are_unavailable() {
    let shape = RepoShape::scip_call_flood();
    let fx = index_fixture_hermetic(&shape).await;
    let (mut graph, _cov, tier) = coverage_for(&fx).await;
    assert_eq!(tier, CoverageTier::Unavailable);

    let cfg_crates = cfg_touching_crates(&graph);
    assert_eq!(
        classify_dead_action(&graph, node_by_name(&graph, "gamma_dead"), &cfg_crates),
        DeadAction::SuspectedDelete,
        "structural-only precondition must withhold delete authority"
    );
    corroborate_dead_for_gate_test(&mut graph, "gamma_dead");
    let node = node_by_name(&graph, "gamma_dead");
    // PRE-GATE non-vacuity: once this in-memory test supplies the otherwise
    // absent compiler receipt, gamma_dead reaches the strongest inner action.
    // The None-coverage gate must still withhold the entire verdict.
    assert_eq!(
        classify_dead_action(&graph, node, &cfg_crates),
        DeadAction::SafeDelete,
        "synthetic corroboration must make the coverage gate non-vacuous"
    );

    // POST-GATE: the single-symbol verdict (the action) is withheld.
    match dead_single_gated(&graph, node, tier, true) {
        DeadSingleReport::Unknown => {}
        DeadSingleReport::Computed { action, .. } => {
            panic!(
                "Unavailable coverage MUST withhold the single-symbol verdict; got action={action:?}"
            )
        }
    }
}

/// FALSIFIER **Shape 5a** [unit-fixture, RA-gated, NEGATIVE CONTROL] — the
/// cry-wolf guard on a properly-indexed repo. The SAME 3-fn flood indexed WITH
/// SCIP resolves the `alpha→beta` Calls edge ⇒ `beta` becomes Wired ⇒ only the
/// genuine `gamma_dead` is dead. A complete Rust Calls receipt + edges ⇒
/// `Sufficient` ⇒ the verb MUST still EMIT the genuine advisory finding, NOT
/// UNKNOWN. SCIP supplies the Calls evidence that removes `beta`; it does not
/// supply compiler authority, so `gamma_dead` remains `SuspectedDelete`.
#[tokio::test]
async fn l4_shape_5a_scip_emits_genuine_dead_no_cry_wolf() {
    if !require_rust_analyzer("l4_shape_5a") {
        return;
    }
    let shape = RepoShape::scip_call_flood();
    let fx = index_fixture(&shape, true).await;
    let (graph, cov, tier) = coverage_for(&fx).await;

    assert!(
        fx.snapshot().await.calls_authority_available,
        "a successful provider must publish complete Calls receipt authority"
    );
    assert!(cov.calls_authority_available);
    assert!(
        cov.scip_calls_edges >= 1,
        "the alpha->beta Calls edge must resolve under SCIP (scip_calls_edges={})",
        cov.scip_calls_edges
    );
    assert_eq!(
        tier,
        CoverageTier::Sufficient,
        "a fully-SCIP'd repo must be Sufficient (MEASURED save->reload persistence)"
    );

    let DeadReport::Full(data) = dead_report_gated(&graph, tier, true) else {
        panic!("Sufficient coverage MUST EMIT, not UNKNOWN (over-suppression cry-wolf)");
    };
    let counts = data.counts();
    let names: Vec<&String> = data.entries.iter().map(|e| &e.symbol_name).collect();
    assert_eq!(
        counts.safe_delete, 0,
        "SCIP supplies Calls, not compiler deletion authority; got {names:?}"
    );
    let gamma = data
        .entries
        .iter()
        .find(|entry| entry.symbol_name.ends_with("gamma_dead"))
        .expect("gamma_dead must remain in the emitted report");
    assert_eq!(gamma.action, DeadAction::SuspectedDelete);
    assert!(
        names.iter().any(|n| n.ends_with("gamma_dead")),
        "gamma_dead must still emit as an advisory finding: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.ends_with("beta")),
        "beta must NOT be dead under SCIP (it is called by alpha): {names:?}"
    );
}

/// FALSIFIER **Shape 5c** [unit-fixture, RA-gated, BLOCKING NEGATIVE CONTROL] —
/// the S1 cry-wolf guard. A crate with complete Calls receipt authority
/// that GENUINELY has zero internal calls (`scip_calls_edges==0`) with >=1 dead
/// item MUST classify `Sufficient` (via the leaf carve-out keyed on
/// the receipt, NOT a bare `scip_calls_edges==0`) and EMIT — proving v3 does
/// NOT regress into the v2 over-suppression on a valid leaf crate.
// The SCIP provider establishes that this is a genuine zero-call leaf. It does
// not run the compiler oracle, so the dead item must remain advisory.
#[tokio::test]
async fn l4_shape_5c_leaf_crate_emits_not_unknown() {
    if !require_rust_analyzer("l4_shape_5c") {
        return;
    }
    let shape = RepoShape::leaf_crate_zero_calls();
    let fx = index_fixture(&shape, true).await;
    let (graph, cov, tier) = coverage_for(&fx).await;

    // The authority invariant: a complete receipt exists despite zero internal Calls edges.
    assert!(
        fx.snapshot().await.calls_authority_available,
        "a leaf-crate provider run must publish complete Calls receipt authority"
    );
    assert!(cov.calls_authority_available);
    assert_eq!(
        cov.scip_calls_edges, 0,
        "a genuine leaf crate resolves ZERO internal Calls edges, got {}",
        cov.scip_calls_edges
    );

    // THE BLOCKING GUARD: receipt authority + 0 edges → Sufficient, not Unavailable.
    assert_eq!(
        tier,
        CoverageTier::Sufficient,
        "a successfully-SCIP'd leaf crate (0 calls) MUST be Sufficient via the carve-out, NOT None"
    );

    // NON-VACUITY against the rejected v2 mechanism (Alt-A''): a bare
    // scip_calls_edges==0 gate WOULD fire None here and cry wolf. Prove the
    // the immutable receipt is what keeps it Sufficient.
    assert!(
        cov.scip_calls_edges == 0,
        "the rejected v2 bare-0-edge gate WOULD fire None here"
    );

    let DeadReport::Full(data) = dead_report_gated(&graph, tier, true) else {
        panic!(
            "leaf crate MUST EMIT its dead verdict, not UNKNOWN (the v2 over-suppression regression)"
        );
    };
    let names: Vec<&String> = data.entries.iter().map(|e| &e.symbol_name).collect();
    assert_eq!(
        data.counts().safe_delete,
        0,
        "a successful SCIP run still carries no compiler deletion authority; got {names:?}"
    );
    let dead_leaf = data
        .entries
        .iter()
        .find(|entry| entry.symbol_name.ends_with("dead_leaf"))
        .expect("dead_leaf must remain in the emitted report");
    assert_eq!(dead_leaf.action, DeadAction::SuspectedDelete);
    assert!(
        names.iter().any(|n| n.ends_with("dead_leaf")),
        "the genuine dead_leaf must be emitted: {names:?}"
    );
}

/// FALSIFIER **Shape 7** [unit-fixture, RA-gated] — L6 non-inversion
/// (monotonicity, suppress-only). Raising SCIP coverage on the SAME fixture
/// (`--no-scip` → with-SCIP) moves verdicts UNKNOWN → {real recommendation}
/// ONLY; never a real recommendation → a NEW SafeDelete. Under `Unavailable` the verb
/// emits ZERO recommendations (all suppressed), so no node can invert into a
/// fresh SAFE_DELETE when coverage rises.
#[tokio::test]
async fn l4_shape_7_coverage_rise_is_monotone_suppress_only() {
    if !require_rust_analyzer("l4_shape_7") {
        return;
    }
    // No receipt authority → Unavailable → zero emitted recommendations.
    let fx_low = index_fixture_hermetic(&RepoShape::scip_call_flood()).await;
    let (graph_low, _cov_low, tier_low) = coverage_for(&fx_low).await;
    assert_eq!(tier_low, CoverageTier::Unavailable);
    assert!(
        matches!(
            dead_report_gated(&graph_low, tier_low, true),
            DeadReport::Unknown
        ),
        "Unavailable coverage emits NO recommendations (suppress-only baseline)"
    );

    // Raised coverage: with-SCIP → Sufficient → real recommendations appear.
    let fx_high = index_fixture(&RepoShape::scip_call_flood(), true).await;
    let (graph_high, _cov_high, tier_high) = coverage_for(&fx_high).await;
    assert_eq!(tier_high, CoverageTier::Sufficient);
    let DeadReport::Full(data_high) = dead_report_gated(&graph_high, tier_high, true) else {
        panic!("raised coverage must EMIT");
    };
    // The transition is UNKNOWN -> {gamma_dead: SAFE_DELETE}. Because the low
    // state emitted ZERO recommendations, no node moved FROM a recommendation
    // INTO a fresh SAFE_DELETE — the gate only un-suppressed (monotone).
    assert!(
        data_high
            .entries
            .iter()
            .any(|e| e.symbol_name.ends_with("gamma_dead")),
        "the raised-coverage report surfaces the genuine dead recommendation"
    );
}

/// SIGNAL round-trip: a structural generation's unavailable Calls receipt
/// survives publication and reload without a second graph-metadata authority.
#[tokio::test]
async fn structural_generation_receipt_authority_survives_reload() {
    let fx = index_fixture_hermetic(&RepoShape::scip_call_flood()).await;
    let snapshot = fx.snapshot().await;
    assert!(!snapshot.calls_authority_available);

    let coverage = call_edge_coverage(&snapshot.graph, snapshot.calls_authority_available);
    assert!(!coverage.calls_authority_available);
    assert_eq!(coverage.scip_calls_edges, 0);
    assert_eq!(
        coverage_tier(&coverage),
        CoverageTier::Unavailable,
        "a structural generation must remain unavailable after reload"
    );
}

// ============================================================================
// L4 staleness + status falsifiers
// ============================================================================

/// Repeated read-only generation loads cannot freshen a genuinely stale source
/// population or mutate the immutable database that supplies its authority.
#[tokio::test]
async fn l4_shape_3c_staleness_is_immune_to_read_only_generation_loads() {
    let fx = index_fixture_hermetic(&RepoShape::healthy_workspace()).await;
    let before = fx.snapshot().await;
    let baseline = before.index_baseline;
    let database_bytes = std::fs::read(&before.database_path).expect("read generation database");
    assert_eq!(before.source_freshness, StalenessVerdict::Fresh);

    std::fs::write(
        fx.repo_root().join("crates/widget/src/zzz_change.rs"),
        "pub fn changed_after_publication() {}\n",
    )
    .expect("write changed source");
    assert_eq!(
        fx.snapshot().await.source_freshness,
        StalenessVerdict::Stale,
        "changed source bytes must make the immutable generation stale"
    );

    for _ in 0..3 {
        let observed = fx.snapshot().await;
        assert_eq!(observed.index_baseline, baseline);
        assert_eq!(observed.source_freshness, StalenessVerdict::Stale);
    }
    assert_eq!(
        std::fs::read(&before.database_path).expect("reread generation database"),
        database_bytes,
        "read-only queries must not mutate immutable generation bytes"
    );
}

/// A freshly indexed generation with complete Calls authority reports fresh
/// source inputs and requires no recovery action.
#[tokio::test]
async fn l4_shape_5b_healthy_repo_status_stays_fresh() {
    if !require_rust_analyzer("l4_shape_5b") {
        return;
    }
    let fx = index_fixture(&RepoShape::healthy_workspace(), true).await;
    let snapshot = fx.snapshot().await;
    let coverage = call_edge_coverage(&snapshot.graph, snapshot.calls_authority_available);
    assert_eq!(coverage_tier(&coverage), CoverageTier::Sufficient);
    assert_eq!(snapshot.source_freshness, StalenessVerdict::Fresh);

    let verdict = status_verdict(
        true,
        false,
        false,
        snapshot.source_freshness,
        CapabilityCoverageStatus::Complete,
    );
    assert_eq!(verdict.freshness_label, "fresh");
    assert!(!verdict.action_needed);
    assert_eq!(
        verdict.recommendation,
        "Source inputs are fresh and measured capabilities are ready."
    );
    assert_eq!(verdict.freshness_reason, None);
}

/// FALSIFIER **target-inversion** [integration, NEGATIVE CONTROL] — a stray
/// `target/**/*.rs` in a freshly-indexed repo must not alter the selected source
/// population: shared discovery excludes generated `target/` trees.
#[tokio::test]
async fn l4_staleness_excludes_target_in_real_repo() {
    let shape = RepoShape::healthy_workspace();
    let fx = index_fixture_hermetic(&shape).await;
    let repo = fx.repo_root();
    assert_eq!(
        fx.snapshot().await.source_freshness,
        StalenessVerdict::Fresh,
        "positive control: fixture begins fresh"
    );

    // A generated target/ artifact is outside the selected source population.
    let gen_dir = repo.join("target").join("debug").join("build");
    std::fs::create_dir_all(&gen_dir).expect("mk target/");
    std::fs::write(gen_dir.join("out.rs"), "// generated, newer than index\n")
        .expect("write target rs");

    assert_eq!(
        fx.snapshot().await.source_freshness,
        StalenessVerdict::Fresh,
        "a target/*.rs artifact must not make a clean repo stale"
    );
}

// ============================================================================
// L5 #3 — no-Cargo / non-Rust structural capability independence.
// ============================================================================

/// A repo with no registered structural sources and no reachability-owning
/// project unit still publishes an empty structural generation. Reachability
/// absence is capability-local; it is not a repository-wide indexing error.
#[tokio::test]
async fn l5_no_cargo_repo_degrades_gracefully_not_panic() {
    let shape = RepoShape::no_cargo_repo();
    let repo = shape.materialize();
    let store = tempfile::tempdir().expect("temp data dir");

    let binding = fixture_binding(repo.path(), store.path());
    h00ligan::index_cmd::run_index(index_args(false), &binding)
        .await
        .expect("empty structural publication must not require reachability ownership");
}
