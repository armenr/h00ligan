//! Structural indexing is a useful capability even when no project-system
//! reachability classifier owns the selected source population.
//!
//! Every command crosses the shipped `h00ligan` binary and writes only to one
//! temporary data directory. The fixture deliberately has registered Rust
//! syntax but no Cargo manifest: structural truth is exact, while reachability
//! authority is unavailable and must remain independently qualified.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn h00ligan(root: &Path, data_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir);
    command
}

fn rendered(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn registered_source_publishes_structural_truth_without_reachability_owner() {
    let temporary = TempDir::new().expect("scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(&root).expect("repository root");
    std::fs::write(
        root.join("loose.rs"),
        "pub fn structurally_visible() -> usize { 1 }\n",
    )
    .expect("manifestless registered source");

    let indexed = h00ligan(&root, &data_dir)
        .args(["index", "--format", "json"])
        .output()
        .expect("run shipped structural index");
    assert!(
        indexed.status.success(),
        "missing reachability ownership must not suppress exact structural publication\n{}",
        rendered(&indexed)
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&indexed.stdout).expect("index receipt JSON");
    assert_eq!(receipt["files_discovered"], 1, "positive source population");
    assert!(
        receipt["nodes"].as_u64().is_some_and(|nodes| nodes > 0),
        "structural publication must be nonempty: {receipt}"
    );

    let found = h00ligan(&root, &data_dir)
        .args([
            "find",
            "structurally_visible",
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .expect("query shipped structural Find");
    assert!(
        found.status.success(),
        "structural Find must remain available without reachability\n{}",
        rendered(&found)
    );
    let found: serde_json::Value = serde_json::from_slice(&found.stdout).expect("Find result JSON");
    assert_eq!(found["page"]["total_items"], 1, "{found}");
    assert_eq!(found["items"][0]["name"], "structurally_visible", "{found}");

    let dead = h00ligan(&root, &data_dir)
        .args(["dead", "structurally_visible", "--format", "json"])
        .output()
        .expect("query shipped reachability-dependent Dead");
    assert!(
        !dead.status.success(),
        "unavailable reachability must not be fabricated\n{}",
        rendered(&dead)
    );
    let dead_error = rendered(&dead);
    assert!(
        dead_error.contains("reachability") && !dead_error.contains("no supported manifest"),
        "the refusal must name the unavailable capability, not reject structural publication: {dead_error}"
    );
}

#[test]
fn mixed_reachability_scope_keeps_structural_only_source_visible_without_global_downgrade() {
    let temporary = TempDir::new().expect("scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(root.join("templates")).expect("repository source directories");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/owned\n\ngo 1.26\n",
    )
    .expect("Go module manifest");
    std::fs::write(root.join("main.go"), "package main\n\nfunc main() {}\n")
        .expect("owned Go source");
    std::fs::write(
        root.join("templates/loose.rs"),
        "pub fn structurally_visible_template() {}\n",
    )
    .expect("structural-only Rust source");

    let indexed = h00ligan(&root, &data_dir)
        .args(["index", "--format", "json"])
        .output()
        .expect("run shipped mixed structural index");
    assert!(indexed.status.success(), "{}", rendered(&indexed));

    let found = h00ligan(&root, &data_dir)
        .args([
            "find",
            "structurally_visible_template",
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .expect("query shipped structural Find");
    assert!(found.status.success(), "{}", rendered(&found));
    let found: serde_json::Value = serde_json::from_slice(&found.stdout).expect("Find JSON");
    assert_eq!(found["page"]["total_items"], 1, "{found}");

    let overview = h00ligan(&root, &data_dir)
        .args(["overview", "--format", "json"])
        .output()
        .expect("query shipped mixed overview");
    assert!(overview.status.success(), "{}", rendered(&overview));
    let overview: serde_json::Value =
        serde_json::from_slice(&overview.stdout).expect("Overview JSON");
    assert!(
        overview["unclassified_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "the structural-only document must remain explicitly unclassified: {overview}"
    );
    assert_eq!(
        overview["health_status"], "unavailable",
        "missing Calls authority may withhold health, but must not erase the independently classified Go unit: {overview}"
    );

    let status = h00ligan(&root, &data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("query shipped mixed status");
    assert!(status.status.success(), "{}", rendered(&status));
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).expect("Status JSON");
    assert!(
        status["reachability"]["unclassified"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "positive control: the mixed graph really contains source outside the classified scope: {status}"
    );
    assert_eq!(
        status["classification_currency"]["current"], true,
        "valid document-scoped reachability evidence is current even when other source remains explicitly unclassified: {status}"
    );

    let dead = h00ligan(&root, &data_dir)
        .args(["dead", "structurally_visible_template", "--format", "json"])
        .output()
        .expect("query structural-only symbol through shipped Dead");
    assert!(dead.status.success(), "{}", rendered(&dead));
    let dead: serde_json::Value = serde_json::from_slice(&dead.stdout).expect("Dead JSON");
    assert_eq!(dead["items"][0]["verdict"], "unknown", "{dead}");
    assert_eq!(dead["items"][0]["recommendation"], "withheld", "{dead}");
}
