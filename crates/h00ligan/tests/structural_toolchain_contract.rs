//! Installed-shape contract for dependency-free structural indexing.
//!
//! Semantic enrichment may execute an explicitly requested language provider
//! and its project toolchain. Plain structural indexing must not probe one.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

#[test]
fn structural_index_does_not_execute_project_toolchains_or_selectors() {
    let workspace = TempDir::new().expect("scratch workspace");
    let root = workspace.path().join("project");
    let data_dir = workspace.path().join("data");
    let fake_bin = workspace.path().join("fake-bin");
    let fake_home = workspace.path().join("home");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::create_dir_all(&fake_bin).expect("fake bin directory");
    std::fs::create_dir_all(&fake_home).expect("fake home directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"structural-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n")
        .expect("Rust source");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/structural\n\ngo 1.27\n",
    )
    .expect("Go manifest");
    std::fs::write(
        root.join("main.go"),
        "package structural\nfunc Answer() int { return 42 }\n",
    )
    .expect("Go source");
    std::fs::write(root.join(".tool-versions"), "go 1.27.0\nrust 1.97.1\n").expect("asdf selector");
    std::fs::write(root.join(".go-version"), "1.27.0\n").expect("Go selector");
    std::fs::write(
        root.join("mise.toml"),
        "[tools]\ngo = \"1.27.0\"\nrust = \"1.97.1\"\n",
    )
    .expect("mise selector");

    let sentinel = workspace.path().join("toolchain-was-executed");
    let fake_tools = [
        "asdf", "cargo", "go", "gopls", "mise", "rustc", "rustup", "scip-go",
    ];
    for tool in fake_tools {
        let executable = fake_bin.join(tool);
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf '%s\\n' \"${0##*/}\" >> \"$H00_FAKE_TOOLCHAIN_SENTINEL\"\nexit 97\n",
        )
        .expect("fake toolchain executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("fake toolchain metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions)
            .expect("executable fake toolchain command");

        let control = Command::new(&executable)
            .env("H00_FAKE_TOOLCHAIN_SENTINEL", &sentinel)
            .status()
            .expect("execute positive-control fake toolchain command");
        assert_eq!(control.code(), Some(97));
    }
    let mut control_population = std::fs::read_to_string(&sentinel)
        .expect("positive-control sentinel")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    control_population.sort();
    assert_eq!(
        control_population, fake_tools,
        "positive control must prove every fake toolchain command can record execution"
    );
    std::fs::remove_file(&sentinel).expect("reset positive-control sentinel");

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args(["--data-dir", data_dir.to_str().expect("UTF-8 data dir")])
        .args(["index", "--format", "json"])
        .env_clear()
        .env("HOME", &fake_home)
        .env("PATH", &fake_bin)
        .env("H00_FAKE_TOOLCHAIN_SENTINEL", &sentinel)
        .output()
        .expect("run structural index boundary");

    assert!(
        output.status.success(),
        "structural indexing must work without a project toolchain: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !sentinel.exists(),
        "plain structural indexing executed a project toolchain even though semantic providers were not requested"
    );

    let receipt: Value = serde_json::from_slice(&output.stdout).expect("index JSON receipt");
    assert_eq!(receipt["files_discovered"], 2);
    let languages = receipt["capabilities"]["calls"]["languages"]
        .as_array()
        .expect("per-language Calls authority");
    assert_eq!(languages.len(), 2, "positive Rust and Go population");
    assert!(
        languages.iter().all(|language| {
            language["gaps"].as_array().is_some_and(|gaps| {
                gaps.iter()
                    .any(|gap| gap["reason_code"] == "provider_not_requested")
            })
        }),
        "the control must exercise structural-only authority for every detected language: {languages:?}"
    );
}

/// Product-boundary falsifier: changing a directory-sensitive version-manager
/// selector must make the immutable generation stale even before semantic
/// enrichment is requested. Otherwise a standalone Status call can preserve
/// old toolchain authority until WATCH's slow integrity fallback happens to
/// run.
#[test]
fn structural_publication_tracks_version_manager_toolchain_selectors() {
    let workspace = TempDir::new().expect("scratch workspace");
    let root = workspace.path().join("project");
    let data_dir = workspace.path().join("data");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"selector-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n")
        .expect("Rust source");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/selector\n\ngo 1.27\n",
    )
    .expect("Go manifest");
    std::fs::write(
        root.join("main.go"),
        "package selector\nfunc Answer() int { return 42 }\n",
    )
    .expect("Go source");
    let selectors = [
        (
            root.join(".tool-versions"),
            "rust 1.97.1\n",
            "rust 1.98.0\n",
        ),
        (root.join(".go-version"), "1.27.0\n", "1.28.0\n"),
    ];
    for (selector, original, _) in &selectors {
        std::fs::write(selector, original).expect("initial toolchain selector");
    }

    let invoke = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_h00ligan"))
            .args(["--root", root.to_str().expect("UTF-8 root")])
            .args(["--data-dir", data_dir.to_str().expect("UTF-8 data dir")])
            .args(arguments)
            .output()
            .expect("run h00ligan product boundary")
    };
    let index = invoke(&["index", "--format", "json"]);
    assert!(
        index.status.success(),
        "structural index failed: stdout={} stderr={}",
        String::from_utf8_lossy(&index.stdout),
        String::from_utf8_lossy(&index.stderr)
    );

    let status = || {
        let output = invoke(&["status", "--format", "json"]);
        assert!(
            output.status.success(),
            "Status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).expect("Status JSON")
    };
    assert_eq!(status()["freshness"], "fresh", "positive current control");

    for (selector, original, changed) in selectors {
        std::fs::write(&selector, changed).expect("change only toolchain selector");
        assert_eq!(
            status()["freshness"],
            "stale",
            "toolchain selector drift must qualify the published generation: {}",
            selector.display()
        );

        std::fs::write(&selector, original).expect("restore exact toolchain selector bytes");
        assert_eq!(
            status()["freshness"],
            "fresh",
            "byte-exact restoration must recover freshness without reindexing: {}",
            selector.display()
        );
    }
}
