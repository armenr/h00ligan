use std::process::Command;

use tempfile::TempDir;

#[cfg(unix)]
fn go_only_search_path(temporary: &TempDir) -> std::ffi::OsString {
    let current_path = std::env::var_os("PATH").unwrap_or_default();
    let real_go = std::env::split_paths(&current_path)
        .map(|directory| directory.join("go"))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| std::fs::canonicalize(candidate).ok())
        .expect("installed Go driver in PATH");
    let provider_bin = temporary.path().join("go-only-bin");
    std::fs::create_dir_all(&provider_bin).expect("isolated Go PATH directory");
    std::os::unix::fs::symlink(real_go, provider_bin.join("go"))
        .expect("link exact Go driver into isolated PATH");
    assert!(provider_bin.join("go").is_file(), "positive Go control");
    assert!(
        !provider_bin.join("scip-go").exists(),
        "installed concurrency boundary must not depend on external scip-go"
    );
    std::env::join_paths([provider_bin]).expect("isolated Go PATH")
}

#[cfg(unix)]
fn embedded_go_provider_executable_count(data_dir: &std::path::Path) -> usize {
    let executable_root = data_dir
        .join(h00ligan_engine::project_binding::PROVIDER_CACHE_DIRECTORY)
        .join("executables");
    std::fs::read_dir(executable_root)
        .expect("embedded Go executable cache")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("h00-go-semantic-provider").is_file())
        .count()
}

#[test]
fn repository_root_with_nested_go_modules_publishes_one_generation() {
    let workspace = TempDir::new().expect("scratch workspace");
    let root = workspace.path().join("repository");
    let data_dir = workspace.path().join("data");

    let core = root.join("core");
    std::fs::create_dir_all(core.join("cmd/app")).expect("core source directories");
    std::fs::write(core.join("go.mod"), "module example.test/core\n\ngo 1.24\n")
        .expect("core go.mod");
    std::fs::write(
        core.join("cmd/app/main.go"),
        "package main\n\nfunc main() { run() }\n\nfunc run() {}\n",
    )
    .expect("core main source");

    let helper = root.join("tools/helper");
    std::fs::create_dir_all(&helper).expect("helper source directory");
    std::fs::write(
        helper.join("go.mod"),
        "module example.test/helper\n\ngo 1.24\n",
    )
    .expect("helper go.mod");
    std::fs::write(
        helper.join("helper.go"),
        "package helper\n\nfunc Exported() {}\n",
    )
    .expect("helper source");

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args(["--data-dir", data_dir.to_str().expect("UTF-8 data dir")])
        .args(["index", "--format", "json"])
        .output()
        .expect("run shipped h00ligan index");

    assert!(
        output.status.success(),
        "a repository root may own multiple nested Go modules without a synthetic root manifest\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let receipt: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("index receipt JSON");
    assert_eq!(receipt["files_discovered"], 2);
    assert_eq!(receipt["files_changed"], 2);
    assert!(
        receipt["generation_id"]
            .as_str()
            .is_some_and(|generation| generation.starts_with("g-"))
    );

    let overview = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args(["--data-dir", data_dir.to_str().expect("UTF-8 data dir")])
        .args(["overview", "--format", "json"])
        .output()
        .expect("run shipped h00ligan overview");
    assert!(
        overview.status.success(),
        "overview failed: {}",
        String::from_utf8_lossy(&overview.stderr)
    );
    let overview: serde_json::Value =
        serde_json::from_slice(&overview.stdout).expect("overview JSON");
    let units = overview["project_units"]
        .as_array()
        .expect("project unit array");
    let roots = units
        .iter()
        .filter_map(|unit| unit["root_path"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(roots, ["core", "tools/helper"].into_iter().collect());
}

/// INSTALLED PRODUCT BOUNDARY: the portable h00ligan executable must own a
/// bounded persistent provider session population for independent Go roots.
/// The deterministic coordinator barrier lives in the engine test; this test
/// proves `--jobs 2` reaches that production scheduler, complete two-root
/// authority is published, and no adjacent/global `scip-go` is available.
#[cfg(unix)]
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and Go"]
fn installed_multiroot_go_index_overlaps_independent_provider_processes() {
    assert!(
        std::thread::available_parallelism().is_ok_and(|parallelism| parallelism.get() >= 2),
        "installed provider-concurrency acceptance requires at least two logical CPUs"
    );
    let binary = std::path::PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed concurrency acceptance"),
    );
    let temporary = TempDir::new().expect("multi-root provider workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    for module in ["alpha", "beta"] {
        let module_root = root.join(module);
        std::fs::create_dir_all(&module_root).expect("module directory");
        std::fs::write(
            module_root.join("go.mod"),
            format!("module example.test/{module}\n\ngo 1.27\n"),
        )
        .expect("module manifest");
        let module_source = format!(
            "package {module}\n\nimport \"sync\"\n\nvar guard sync.Mutex\n\nfunc Target() int {{ return 1 }}\nfunc Caller() int {{ guard.Lock(); defer guard.Unlock(); return Target() }}\n"
        );
        std::fs::write(module_root.join("module.go"), module_source).expect("module source");
    }
    let search_path = go_only_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");

    let mut command = Command::new(&binary);
    command
        .env_clear()
        .env("PATH", search_path)
        .env("TMPDIR", temporary.path())
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args(["--data-dir", data_dir.to_str().expect("UTF-8 data dir")])
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--jobs",
            "2",
            "--profile",
            "--format",
            "json",
        ]);
    let output = command
        .output()
        .expect("run installed concurrent provider index");
    assert!(
        output.status.success(),
        "independent provider roots did not overlap\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("index receipt JSON");
    assert_eq!(receipt["capabilities"]["calls"]["status"], "complete");
    assert_eq!(
        receipt["capabilities"]["calls"]["languages"][0]["provider_id"],
        "h00-gopls-scip"
    );
    let refreshes = receipt["semantic_provider_refreshes"]
        .as_array()
        .expect("typed persistent-provider refresh population");
    assert_eq!(refreshes.len(), 1, "one Go authority lane: {receipt}");
    assert_eq!(refreshes[0]["language"], "go");
    assert_eq!(refreshes[0]["lane"], "full");
    assert_eq!(refreshes[0]["operation"], "certify_full");
    assert_eq!(refreshes[0]["documents"], serde_json::json!([]));
    assert_eq!(refreshes[0]["session_open"]["execution_roots"], 2);
    assert_eq!(refreshes[0]["session_open"]["max_parallelism"], 2);
    assert!(
        refreshes[0]["session_open"]["duration_ms"]
            .as_u64()
            .is_some(),
        "session-pool wall timing must be present"
    );
    assert_eq!(
        embedded_go_provider_executable_count(&data_dir),
        1,
        "one content-addressed embedded provider executable serves both roots"
    );
}
