//! CLI integration tests for h00ligan composite commands.
//!
//! Category 1: Regression tests (6 tests) — T-R1 through T-R6.
//!
//! These tests run the actual `h00ligan` binary with `--format json`
//! against the real workspace and parse the JSON output to verify
//! structural correctness.
//!
//! All tests share a single indexed graph via a static temp directory.
//! Tests MUST run with `--test-threads=1` because redb uses exclusive
//! file locking and each h00ligan invocation opens graph.redb.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Get the path to the h00ligan binary built by cargo.
fn h00ligan_bin() -> PathBuf {
    // cargo test builds the binary in the same target directory
    let mut path = std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("parent of test binary")
        .parent()
        .expect("parent of deps dir")
        .to_path_buf();
    path.push("h00ligan");
    path
}

/// Get the workspace root (the top-level directory containing the root Cargo.toml).
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // h00ligan is at crates/h00ligan, so workspace root is ../../
    manifest_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Create the process-local shared data directory with an indexed graph.
///
/// On first call, creates a unique temp directory, runs `h00ligan index`, and
/// returns the path. Subsequent calls in this test process return the same path.
///
/// We use a static `OnceLock` so the index only runs once across all tests while
/// preventing a crashed process from poisoning later runs with a stale bundle.
fn shared_data_dir() -> &'static Path {
    static DATA_DIR: OnceLock<TempDir> = OnceLock::new();
    DATA_DIR
        .get_or_init(|| {
            let data_dir = TempDir::new().expect("create isolated h00ligan data dir");
            let bin = h00ligan_bin();
            let root = workspace_root();
            let data_path = data_dir.path();

            // Index without SCIP for speed. Tests that depend on Calls edges
            // (T-R1 blast_radius, T-R5 field_types) document findings when
            // SCIP edges are missing rather than failing.
            eprintln!(
                "[composite_integration] Indexing workspace into {} (no SCIP)...",
                data_path.display()
            );
            let output = Command::new(&bin)
                .args([
                    "--root",
                    root.to_str().unwrap(),
                    "--data-dir",
                    data_path.to_str().unwrap(),
                    "index",
                ])
                .current_dir(&root)
                .output()
                .expect("failed to run h00ligan index");

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                panic!(
                    "h00ligan index failed with code {:?}:\n{stderr}",
                    output.status.code()
                );
            }
            eprintln!("[composite_integration] Index complete.");
            data_dir
        })
        .path()
}

/// Run h00ligan with args + shared data-dir, return (stdout, stderr, exit_code).
fn run_h00ligan(args: &[&str]) -> (String, String, i32) {
    let bin = h00ligan_bin();
    let root = workspace_root();
    let data_dir = shared_data_dir();

    let mut full_args: Vec<&str> = vec![
        "--root",
        root.to_str().unwrap(),
        "--data-dir",
        data_dir.to_str().unwrap(),
    ];
    full_args.extend_from_slice(args);

    let output = Command::new(&bin)
        .args(&full_args)
        .current_dir(&root)
        .output()
        .unwrap_or_else(|e| panic!("failed to run h00ligan at {}: {e}", bin.display()));

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    (stdout, stderr, code)
}

// ============================================================================
// Category 1: Regression Tests
// ============================================================================

/// T-R2: `find KnowledgeGraph` returns results (exact match works).
#[test]
fn t_r2_find_exact_match() {
    let (stdout, stderr, code) = run_h00ligan(&["find", "KnowledgeGraph", "--format", "json"]);

    assert_eq!(code, 0, "find should succeed. stderr: {stderr}");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse find JSON: {e}\nstdout: {stdout}"));

    assert_eq!(json["schema_version"], "h00/code-intel/find/v1");
    assert!(
        json["page"]["total_items"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "find KnowledgeGraph should return at least one structural match: {json}"
    );
    assert!(
        json["items"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["name"]
                .as_str()
                .is_some_and(|name| name.contains("KnowledgeGraph")))),
        "at least one Find item should contain KnowledgeGraph: {json}"
    );
}

/// T-R3: `find *Handler` glob returns multiple results.
#[test]
fn t_r3_find_glob_handler() {
    let (stdout, stderr, code) =
        run_h00ligan(&["find", "*Handler", "--format", "json", "--limit", "100"]);

    assert_eq!(code, 0, "find glob should succeed. stderr: {stderr}");

    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "failed to parse find glob JSON: {e}\nstdout first 500: {}",
            &stdout[..stdout.len().min(500)]
        )
    });

    let count = json["page"]["total_items"].as_u64().unwrap_or(0);

    assert!(
        count >= 5,
        "find *Handler should return >= 5 results (there are ~30 handlers), got {count}. \
         JSON keys: {:?}",
        json.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    let returned = json["page"]["returned"].as_u64().unwrap_or(0);
    assert!((5..=100).contains(&returned), "{json}");
    assert!(
        serde_json::to_string(&json)
            .expect("serialize Find result")
            .chars()
            .count()
            <= h00ligan_engine::code_intel_domain::MAX_CODE_INTEL_RESULT_CHARS,
        "Find must enforce its product bound before transport: {json}"
    );
    if returned < count {
        assert_eq!(json["page"]["has_more"], true);
        assert!(json["page"]["next_cursor"].is_string());
        assert!(
            json["warnings"]
                .as_array()
                .is_some_and(|warnings| warnings.iter().any(|warning| warning
                    .as_str()
                    .is_some_and(|warning| warning.contains("serialized-result bounds")))),
            "a size-reduced page must disclose why fewer than the requested ceiling were returned: {json}"
        );
    }
}

/// T-R4: `dead` full report produces results.
#[test]
fn t_r4_dead_full_report() {
    let (stdout, stderr, code) = run_h00ligan(&["dead", "--format", "json"]);

    assert_eq!(code, 0, "dead should succeed. stderr: {stderr}");

    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "failed to parse dead JSON: {e}\nstdout first 500: {}",
            &stdout[..stdout.len().min(500)]
        )
    });

    // Check a dead-symbols ARRAY exists (under any schema alias) and is non-empty.
    // NB: the `dead` full report's per-symbol entries live under `files[].symbols`;
    // the top-level `dead` key is the DEAD-tier COUNT (int, WU-0016 demote of the
    // former `safe_delete` count), so guard on `is_array` to avoid mistaking the
    // count for the array.
    let dead_symbols = json
        .get("dead_symbols")
        .or_else(|| json.get("dead"))
        .or_else(|| json.get("symbols"))
        .filter(|v| v.is_array());

    if let Some(arr_val) = dead_symbols {
        let arr = arr_val
            .as_array()
            .unwrap_or_else(|| panic!("dead_symbols should be an array, got: {arr_val}"));
        assert!(
            !arr.is_empty(),
            "dead code report should find at least some dead symbols"
        );

        // Verify at least one entry has an action field
        let has_action = arr.iter().any(|item| {
            item.get("action").is_some()
                || item.get("recommendation").is_some()
                || item.get("verdict").is_some()
        });
        if has_action {
            let first_action = arr.iter().find_map(|item| {
                item.get("action")
                    .or_else(|| item.get("recommendation"))
                    .or_else(|| item.get("verdict"))
                    .and_then(|v| v.as_str())
            });
            if let Some(action) = first_action {
                eprintln!("[T-R4] first action value: {action}");
            }
        }
    } else {
        // Maybe the JSON has a different top-level structure
        assert!(
            !stdout.trim().is_empty(),
            "dead command should produce output. JSON keys: {:?}",
            json.as_object().map(|o| o.keys().collect::<Vec<_>>())
        );
    }
}

/// T-R5: `inspect KnowledgeGraph` preserves useful structural evidence without
/// overstating a partial structural receipt.
#[test]
fn t_r5_inspect_structure() {
    let (stdout, stderr, code) = run_h00ligan(&["inspect", "KnowledgeGraph", "--format", "json"]);

    assert_eq!(
        code, 0,
        "inspect KnowledgeGraph should succeed. stderr: {stderr}"
    );

    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "failed to parse inspect JSON: {e}\nstdout first 500: {}",
            &stdout[..stdout.len().min(500)]
        )
    });

    assert_eq!(json["schema_version"], "h00/code-intel/inspect/v3");
    assert!(
        matches!(
            json["source"]["status"].as_str(),
            Some("available" | "qualified")
        ),
        "the selected source definition must remain useful: {json}"
    );
    match json["structure"]["status"].as_str() {
        Some("available" | "qualified") => assert!(
            json["structure"]["result"]["totals"]["fields"]
                .as_u64()
                .is_some_and(|fields| fields > 0),
            "an admitted Type facet must expose the known fields: {json}"
        ),
        Some("unavailable") => {
            assert_eq!(
                json["structure"]["issue"]["code"], "capability_unavailable",
                "a partial structural receipt must fail closed through the shared Type contract: {json}"
            );
            assert_eq!(json["field_usage"]["status"], "qualified");
            assert!(
                json["field_usage"]["result"]["total_fields"]
                    .as_u64()
                    .is_some_and(|fields| fields > 0),
                "qualified field evidence must remain useful without impersonating exact Type authority: {json}"
            );
        }
        other => panic!("unexpected Inspect structure facet status {other:?}: {json}"),
    }
}

/// T-R6: `overview` returns persisted project-unit data.
#[test]
fn t_r6_overview_returns_project_unit_data() {
    let (stdout, stderr, code) = run_h00ligan(&["overview", "--format", "json"]);

    assert_eq!(code, 0, "overview should succeed. stderr: {stderr}");

    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "failed to parse overview JSON: {e}\nstdout first 500: {}",
            &stdout[..stdout.len().min(500)]
        )
    });

    if let Some(project_units) = json.get("project_units") {
        let arr = project_units
            .as_array()
            .unwrap_or_else(|| panic!("project_units should be an array, got: {project_units}"));

        assert!(
            arr.len() >= 5,
            "overview should report >= 5 persisted project units. \
             Got {}: {:?}",
            arr.len(),
            arr.iter()
                .filter_map(|unit| unit.get("label").and_then(|label| label.as_str()))
                .collect::<Vec<_>>()
        );

        let labels: Vec<String> = arr
            .iter()
            .filter_map(|unit| {
                unit.get("label")
                    .and_then(|label| label.as_str())
                    .map(String::from)
            })
            .collect();

        for expected in &["h00ligan-engine", "h00ligan"] {
            assert!(
                labels.iter().any(|label| label == expected),
                "overview should include {expected}. Found: {labels:?}"
            );
        }
    } else {
        panic!(
            "overview JSON has no project_units field. Keys: {:?}",
            json.as_object().map(|o| o.keys().collect::<Vec<_>>())
        );
    }
}

// ============================================================================
// Category 2: unavailable call-authority suppression
// ============================================================================
//
// The shared index is built without semantic providers, so it has no Calls
// authority. Reachability-derived verbs must report that authority as
// `Unavailable` and render UNKNOWN rather than inventing DEAD / zero callers /
// low risk from structural-only evidence.

/// `assess` without provider Calls authority retains independently authorized
/// structural impact while making every unavailable semantic population
/// explicit. It must neither abort the dossier nor invent complete zeroes.
#[test]
fn assess_keeps_structural_truth_when_calls_authority_is_unavailable() {
    let (stdout, stderr, code) =
        run_h00ligan(&["assess", "query_published_overview", "--format", "json"]);
    assert_eq!(
        code, 0,
        "Assess should retain structural truth. stderr: {stderr}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse assess JSON: {e}\nstdout: {stdout}"));

    assert_eq!(
        json["authority"]["status"], "qualified",
        "the composed result cannot claim complete population authority: {json}"
    );
    assert!(
        matches!(
            json["authority"]["calls"]["status"].as_str(),
            Some("partial" | "unavailable")
        ),
        "Assess must retain the missing Calls authority: {json}"
    );
    assert_eq!(json["blast_radius"]["population_complete"], false);
    assert_eq!(json["callers"]["applicability"], "applicable");
    assert!(json["callers"]["observed_direct_callers"].is_null());
    assert!(json["callers"]["population_complete"].is_null());
    assert_eq!(json["risk"]["population_complete"], false);
    assert!(
        json["warnings"].as_array().is_some_and(|warnings| {
            warnings.iter().any(|warning| {
                warning
                    .as_str()
                    .is_some_and(|warning| warning.contains("Calls evidence is unavailable"))
            })
        }),
        "the useful structural dossier must explain its missing semantic facet: {json}"
    );
}

/// `inspect` with unavailable Calls authority keeps useful non-call evidence
/// but withholds reachability and action judgment.
#[test]
fn inspect_keeps_structure_when_calls_authority_is_unavailable() {
    let (stdout, stderr, code) = run_h00ligan(&["inspect", "KnowledgeGraph", "--format", "json"]);
    assert_eq!(code, 0, "inspect should succeed. stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse inspect JSON: {e}\nstdout: {stdout}"));

    assert!(
        matches!(
            json["source"]["status"].as_str(),
            Some("available" | "qualified")
        ),
        "Inspect must keep independently authorized source evidence: {json}"
    );
    assert_eq!(json["warnings"]["status"], "qualified");
    assert!(json["warnings"]["result"].get("reachability").is_none());
    assert!(json["warnings"]["result"].get("action_tier").is_none());
    assert!(
        json["warnings"]["result"]["signals"]
            .as_array()
            .is_some_and(|signals| signals
                .iter()
                .any(|signal| signal["code"] == "reachability_not_authorized")),
        "Inspect must explain why it withheld reachability judgment: {json}"
    );
    assert!(
        matches!(
            json["structure"]["status"].as_str(),
            Some("available" | "qualified" | "unavailable")
        ),
        "the structure facet must remain explicit under partial authority: {json}"
    );
}

/// `tests` with unavailable Calls authority fails closed without a false zero.
#[test]
fn tests_fail_closed_when_calls_authority_is_unavailable() {
    let (stdout, stderr, code) =
        run_h00ligan(&["tests", "query_published_overview", "--format", "json"]);
    assert_ne!(
        code, 0,
        "Tests must not manufacture authority. stderr: {stderr}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse tests JSON: {e}\nstdout: {stdout}"));

    assert_eq!(
        json["error"]["code"], "capability_unavailable",
        "Tests must explain the missing provider authority: {json}"
    );
    assert!(
        json.get("items").is_none() && json.get("page").is_none(),
        "a failed authority gate must expose no false zero-result population: {json}"
    );
}

// ============================================================================
// WU-0016 Leg H — file-tier delete-safety (compute_file_tiers) integration
// OQ-FILE-TIER-CAPTURE-COMPLETENESS + OQ-RETAIN-ATTR-RESIDUAL closure.
//
// These observe the REAL h00ligan::graph_cmd::compute_file_tiers — the ONE pure
// fn both CLI paths (JSON + human) now call — from an external test crate. That
// pub-and-observed-from-outside contract IS the OQ-RETAIN-ATTR-RESIDUAL closure:
// the fully_dead verdict is read, not hand-re-derived (as WU-0016 Leg J was
// forced to at leg3b_dead_authority.rs when the predicate was inline in the CLI
// handler). They build synthetic in-memory graphs and never touch the shared
// /tmp fixture, so they are order-independent, but stay in this serial binary.
// ============================================================================

use h00ligan::graph_cmd::{FileTier, compute_file_tiers};
use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::extractor::extract_rust_symbols;
use h00ligan_engine::graph::KnowledgeGraph;
use h00ligan_engine::reachability::{ReachabilityAnalyzer, ReachabilityReport};

/// Build an in-memory knowledge graph + reachability report from synthetic
/// sources, with NO entry points — so every captured symbol classifies Dead,
/// exactly the all-dead numerator the file tiers consume. All three engine APIs
/// are already `pub`; h00ligan depends on h00ligan-engine, so the test can call them
/// with zero writeback and no subprocess/binary dependency (the stale-binary
/// hazard does not apply). Fixtures need NOT compile — tree-sitter parses
/// `make_gen!{}` / `println!()` as `macro_invocation` nodes WITHOUT expansion,
/// and the contract is asserted structurally over the graph, never by compiling.
fn build_graph_and_report(files: &[(&str, &str)]) -> (KnowledgeGraph, ReachabilityReport) {
    let outputs: Vec<_> = files
        .iter()
        .map(|(path, src)| {
            extract_rust_symbols(src, path).unwrap_or_else(|e| panic!("extract {path}: {e:?}"))
        })
        .collect();
    let mut graph = KnowledgeGraph::new();
    build_graph(&outputs, &mut graph).expect("build_graph");
    let report = ReachabilityAnalyzer::new(&graph, Vec::new()).analyze();
    (graph, report)
}

fn tier_for<'a>(tiers: &'a [FileTier], suffix: &str) -> &'a FileTier {
    tiers
        .iter()
        .find(|t| t.path.ends_with(suffix))
        .unwrap_or_else(|| panic!("no FileTier for {suffix}: {:?}", tiers))
}

/// H-F1: a file whose only captured symbols are all Dead but which holds an
/// item-position `macro_invocation` (`make_gen!{}`) is NOT reported fully_dead.
/// On HEAD the whitelist mapped macro_invocation → None, dropping the generated
/// item, so the inline predicate `dead == total && !has_retain` yielded
/// fully_dead=true — a consumer deletes gen.rs → E0425 (missing generated item).
#[test]
fn h_f1_capture_incomplete_macro_invocation_file_not_fully_dead() {
    let (graph, report) = build_graph_and_report(&[(
        "crates/x/src/gen.rs",
        "macro_rules! make_gen { () => { pub fn generated_used() -> u32 { 7 } } }\n\
         make_gen!{}\n\
         fn also_dead() {}\n",
    )]);
    let tiers = compute_file_tiers(&report, &graph);
    let gen_t = tier_for(&tiers, "gen.rs");
    assert!(
        !gen_t.capture_complete,
        "item-position make_gen!{{}} is an uncaptured item"
    );
    assert!(
        !gen_t.fully_dead,
        "a file holding an uncaptured item-generating construct is NOT fully_dead"
    );
}

/// H-F2: a genuinely all-Dead-captured file (deadmod.rs) that is the target of a
/// `mod deadmod;` living in a DIFFERENT file (lib.rs) is NOT fully_dead —
/// deleting it would break the surviving `mod deadmod;` (E0583). The graph
/// already carries the datum (module node file=lib.rs --Contains--> dead_fn); on
/// HEAD the predicate never consulted it.
#[test]
fn h_f2_mod_linked_file_not_fully_dead() {
    let (graph, report) = build_graph_and_report(&[
        ("crates/x/src/lib.rs", "mod deadmod;\n"),
        ("crates/x/src/deadmod.rs", "fn dead_fn() {}\n"),
    ]);
    let tiers = compute_file_tiers(&report, &graph);
    let dm = tier_for(&tiers, "deadmod.rs");
    assert!(
        dm.mod_linked,
        "inbound Contains from a module node whose file != deadmod.rs"
    );
    assert_eq!(
        dm.mod_linked_from.as_deref(),
        Some("crates/x/src/lib.rs"),
        "the linking file is surfaced for the demote annotation"
    );
    assert!(
        !dm.fully_dead,
        "a mod-linked file is NOT delete-safe (E0583 guard)"
    );
}

/// H-F3: the verdict is read from the REAL extracted compute_file_tiers (not a
/// hand-re-derived predicate), AND the DEMOTE annotation is NOT silently
/// withheld — the demoted files still surface in the per-file tiers with the WHY
/// (capture_complete / mod_linked) carried, so a consumer understands "review
/// candidate, but: mod-linked from lib.rs / holds uncaptured item(s)". This is
/// the extraction + observability closure (OQ-RETAIN-ATTR-RESIDUAL): it cannot
/// compile on HEAD (no pub compute_file_tiers, no FileTier annotation fields).
#[test]
fn h_f3_compute_file_tiers_observable_and_demote_annotated() {
    let (g1, r1) = build_graph_and_report(&[(
        "crates/x/src/gen.rs",
        "macro_rules! make_gen { () => { pub fn generated_used() -> u32 { 7 } } }\n\
         make_gen!{}\n\
         fn also_dead() {}\n",
    )]);
    let tiers_f1 = compute_file_tiers(&r1, &g1);
    let gen_t = tier_for(&tiers_f1, "gen.rs");
    assert!(!gen_t.capture_complete && !gen_t.fully_dead);
    // demoted-but-present: gen.rs is absent from fully_dead yet present with WHY.
    assert!(
        !tiers_f1
            .iter()
            .any(|t| t.fully_dead && t.path.ends_with("gen.rs")),
        "capture-incomplete gen.rs must be absent from the fully_dead set"
    );

    let (g2, r2) = build_graph_and_report(&[
        ("crates/x/src/lib.rs", "mod deadmod;\n"),
        ("crates/x/src/deadmod.rs", "fn dead_fn() {}\n"),
    ]);
    let tiers_f2 = compute_file_tiers(&r2, &g2);
    let dm = tier_for(&tiers_f2, "deadmod.rs");
    assert!(dm.mod_linked && !dm.fully_dead);
    assert!(
        tiers_f2.iter().any(|t| t.path.ends_with("deadmod.rs")),
        "demoted file still present in dead_by_file with mod_linked=true"
    );
}

/// H-N1 (negative control): a standalone all-Dead file with only captured items
/// (two plain dead fns), no retain attr, targeted by no `mod` decl → fully_dead.
/// Bites if either guard mis-fires: over-withheld capture would flip
/// capture_complete; a false mod-linkage would flip mod_linked — either flips
/// fully_dead false. Proves the leg did not hard-code fully_dead=false.
#[test]
fn h_n1_genuinely_fully_dead_file_stays_fully_dead() {
    let (g, r) =
        build_graph_and_report(&[("crates/x/src/lone.rs", "fn dead1() {}\nfn dead2() {}\n")]);
    let t = compute_file_tiers(&r, &g);
    let lone = tier_for(&t, "lone.rs");
    assert!(
        lone.capture_complete && !lone.mod_linked && !lone.has_retain && lone.fully_dead,
        "a real fully-dead file must STAY fully_dead: {lone:?}"
    );
}

/// H-N2 (ligan side): the benign-noise file (H-N2 engine companion asserts the
/// scan) STAYS fully_dead. `#![allow(dead_code)]` is an INNER attr, so has_retain
/// stays false and does not confound the assertion.
#[test]
fn h_n2_benign_noise_extras_stay_fully_dead() {
    let (g, r) = build_graph_and_report(&[(
        "crates/x/src/doc.rs",
        "//! module doc\n#![allow(dead_code)]\n;\nfn only_dead() {}\n",
    )]);
    let t = compute_file_tiers(&r, &g);
    let doc = tier_for(&t, "doc.rs");
    assert!(
        doc.capture_complete && !doc.has_retain && doc.fully_dead,
        "benign doc/inner-attr/empty-stmt extras keep the file fully_dead: {doc:?}"
    );
}

/// H-N3 (ligan side): the expression-position-macro file STAYS fully_dead — the
/// position-awareness guard keeps `println!()` in a fn body from tripping
/// capture-completeness.
#[test]
fn h_n3_expression_position_macro_stays_fully_dead() {
    let (g, r) = build_graph_and_report(&[(
        "crates/x/src/body.rs",
        "fn only_dead() { println!(\"x\"); }\n",
    )]);
    let t = compute_file_tiers(&r, &g);
    let body = tier_for(&t, "body.rs");
    assert!(
        body.capture_complete && body.fully_dead,
        "an expression-position println!() keeps the file fully_dead: {body:?}"
    );
}

/// H-N4 (negative control): a file F with an inline `mod inner { fn x(){} }`
/// whose body lives IN F is NOT flagged mod_linked and STAYS fully_dead. Bites
/// the `!= F` guard in the mod-linkage check: without the source-file inequality
/// the inline mod's own same-file Contains edge would self-flag F. Also confirms
/// mod_item is whitelisted (capture_complete stays true).
#[test]
fn h_n4_inline_mod_not_self_flagged_stays_fully_dead() {
    let (g, r) = build_graph_and_report(&[(
        "crates/x/src/inl.rs",
        "mod inner { fn x() {} }\nfn top_dead() {}\n",
    )]);
    let t = compute_file_tiers(&r, &g);
    let inl = tier_for(&t, "inl.rs");
    assert!(
        !inl.mod_linked,
        "an inline mod whose body is in F must NOT self-flag F: {inl:?}"
    );
    assert!(
        inl.capture_complete && inl.fully_dead,
        "inline mod is captured; file STAYS fully_dead: {inl:?}"
    );
}
