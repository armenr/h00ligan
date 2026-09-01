//! Installed-product acceptance for the one-file semantic MCP boundary.
//!
//! Ordinary test builds deliberately do not embed the Rust semantic provider.
//! This ignored test receives the exact portable artifact through
//! `H00_TEST_H00LIGAN_BINARY` and proves that CLI publication, MCP reuse, and
//! MCP queries share one durable authority contract.

#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

fn call_mcp(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    id: u64,
    name: &str,
    arguments: Value,
) -> Value {
    writeln!(
        stdin,
        "{}",
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": h00ligan_interface::mcp::CURRENT_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            },
        })
    )
    .expect("write MCP request");
    stdin.flush().expect("flush MCP request");

    let mut line = String::new();
    stdout.read_line(&mut line).expect("read MCP response");
    assert!(!line.is_empty(), "MCP closed before response {id}");
    let response: Value = serde_json::from_str(&line).expect("JSON-RPC response");
    assert_eq!(response["jsonrpc"], "2.0", "{response}");
    assert_eq!(response["id"], id, "{response}");
    response
}

fn structured_content<'a>(response: &'a Value, operation: &str) -> &'a Value {
    assert_ne!(
        response["result"]["isError"], true,
        "{operation} returned an MCP tool error: {response}"
    );
    let payload = &response["result"]["structuredContent"];
    assert!(
        payload.is_object(),
        "{operation} has no structured content: {response}"
    );
    payload
}

fn reindex_terminal(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    id: &mut u64,
) -> Value {
    let started_response = call_mcp(
        stdin,
        stdout,
        *id,
        "reindex",
        json!({"scip": true, "require_complete_calls": true}),
    );
    *id += 1;
    let started = structured_content(&started_response, "reindex");
    assert_eq!(started["terminal"], false, "{started}");
    let operation_id = started["operation_id"]
        .as_str()
        .expect("operation ID")
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(60);

    loop {
        let response = call_mcp(
            stdin,
            stdout,
            *id,
            "reindex_status",
            json!({"operation_id": operation_id}),
        );
        *id += 1;
        let terminal = structured_content(&response, "reindex_status");
        assert_eq!(terminal["operation_id"], operation_id, "{terminal}");
        if terminal["terminal"] == true {
            assert_eq!(terminal["state"], "succeeded", "{terminal}");
            return terminal["result"].clone();
        }
        assert!(Instant::now() < deadline, "reindex timed out: {terminal}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stop_mcp(mut child: Child, stdin: ChildStdin) {
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("poll MCP child") {
            Some(status) => {
                assert!(
                    status.success(),
                    "MCP child exited unsuccessfully: {status}"
                );
                return;
            }
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => {
                child.kill().expect("kill stuck MCP child");
                let status = child.wait().expect("reap stuck MCP child");
                panic!("MCP child did not exit after stdin closed: {status}");
            }
        }
    }
}

fn index_with_semantics(binary: &Path, root: &Path, data_dir: &Path) -> Value {
    let output = Command::new(binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .output()
        .expect("run installed semantic index");
    assert!(
        output.status.success(),
        "installed semantic index failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("installed index JSON")
}

fn index_with_qualified_semantics(binary: &Path, root: &Path, data_dir: &Path) -> Value {
    let output = Command::new(binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args(["index", "--scip", "--format", "json"])
        .env("GOMODCACHE", data_dir.join("go-module-cache"))
        .output()
        .expect("run installed qualified semantic index");
    assert!(
        output.status.success(),
        "installed qualified semantic index failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("installed qualified index JSON")
}

fn run_json_query(binary: &Path, root: &Path, data_dir: &Path, args: &[&str]) -> Value {
    let output = Command::new(binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args(args)
        .output()
        .expect("run installed JSON query");
    assert!(
        output.status.success(),
        "installed JSON query failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("installed query JSON")
}

fn assert_one_private_embedded_provider(data_dir: &Path, executable_name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let executable_root = data_dir
        .join(h00ligan_engine::project_binding::PROVIDER_CACHE_DIRECTORY)
        .join("executables");
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(&executable_root)
        .unwrap_or_else(|error| panic!("read {}: {error}", executable_root.display()))
    {
        let entry = entry.expect("provider content-address entry");
        let digest = entry.file_name().to_string_lossy().into_owned();
        let candidate = entry.path().join(executable_name);
        if candidate.exists() {
            matches.push((digest, candidate));
        }
    }
    assert_eq!(
        matches.len(),
        1,
        "one installed product must materialize exactly one {executable_name}"
    );
    let (digest, binary) = matches.pop().expect("one provider match");
    assert_eq!(digest.len(), 64, "provider cache key must be SHA-256");
    assert!(
        digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "provider cache key must be hexadecimal: {digest}"
    );
    let metadata = std::fs::symlink_metadata(&binary).expect("materialized provider metadata");
    assert!(metadata.file_type().is_file());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    let observed = Sha256::digest(std::fs::read(&binary).expect("materialized provider bytes"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        observed, digest,
        "materialized provider bytes must match their content address"
    );
    binary
}

/// FALSIFIER: explicit Calls cannot prove negative callable liveness when Go
/// dispatches through a parameter. The shipped product must consume a
/// separately typed whole-program liveness result: it keeps the callback
/// target while still nominating a genuinely unreachable definition from the
/// same compiler-owned source population.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY"]
fn installed_go_callable_liveness_distinguishes_callback_dispatch_from_unreached_code() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed Go liveness acceptance"),
    );
    let temporary = TempDir::new().expect("installed Go liveness scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(&root).expect("Go source directory");
    std::fs::write(
        root.join("go.mod"),
        "module example.com/h00ligan-liveness\n\ngo 1.27\n",
    )
    .expect("Go manifest");
    std::fs::write(
        root.join("main.go"),
        concat!(
            "package main\n\n",
            "type callableContract interface { Contract() }\n",
            "var callableValue = func() {}\n",
            "func callbackOnlyTarget() {}\n",
            "func genuinelyUnreached() {}\n",
            "func invoke(callback func()) { callback() }\n",
            "func main() { invoke(callbackOnlyTarget); callableValue() }\n",
        ),
    )
    .expect("Go source");

    let indexed = index_with_qualified_semantics(&binary, &root, &data_dir);
    assert_eq!(
        indexed["capabilities"]["calls"]["status"], "qualified",
        "positive control: unresolved function-parameter dispatch must not be mislabeled as exact Calls: {indexed}"
    );
    assert_eq!(
        indexed["capabilities"]["callable_liveness"]["status"], "complete",
        "the same provider run must publish an independently complete callable-liveness capability: {indexed}"
    );

    let live = run_json_query(
        &binary,
        &root,
        &data_dir,
        &["dead", "callbackOnlyTarget", "--format", "json"],
    );
    assert_eq!(
        live["authority"]["callable_liveness"]["status"], "complete",
        "callback liveness authority must be explicit: {live}"
    );
    assert_eq!(live["items"][0]["verdict"], "live_production", "{live}");
    assert_eq!(live["items"][0]["recommendation"], "keep", "{live}");
    assert_eq!(
        live["items"][0]["evidence"]["basis"], "provider_callable_liveness",
        "{live}"
    );

    let unreached = run_json_query(
        &binary,
        &root,
        &data_dir,
        &["dead", "genuinelyUnreached", "--format", "json"],
    );
    assert_eq!(
        unreached["items"][0]["verdict"], "unreached_callable",
        "{unreached}"
    );
    assert_eq!(
        unreached["items"][0]["reachable_from_retained_root"], false,
        "{unreached}"
    );
    assert_eq!(
        unreached["items"][0]["recommendation"], "review",
        "{unreached}"
    );
    assert_eq!(
        unreached["items"][0]["evidence"]["status"], "complete",
        "{unreached}"
    );
    assert_eq!(
        unreached["items"][0]["evidence"]["basis"], "provider_callable_liveness",
        "{unreached}"
    );

    let contract = run_json_query(
        &binary,
        &root,
        &data_dir,
        &["dead", "Contract", "--file", "main.go", "--format", "json"],
    );
    assert_eq!(
        contract["items"][0]["verdict"], "retained_structural",
        "a bodyless interface contract is an invocation target, not independently dead executable code: {contract}"
    );
    assert_eq!(
        contract["items"][0]["evidence"]["reason_code"],
        "callable_contract_not_executable_declaration",
        "{contract}"
    );

    let callable_value = run_json_query(
        &binary,
        &root,
        &data_dir,
        &[
            "dead",
            "callableValue",
            "--file",
            "main.go",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        callable_value["items"][0]["verdict"], "retained_structural",
        "the reached binding is retained without manufacturing an RTA declaration record: {callable_value}"
    );
    assert_eq!(
        callable_value["items"][0]["evidence"]["reason_code"],
        "callable_value_not_executable_declaration",
        "{callable_value}"
    );

    let full = run_json_query(
        &binary,
        &root,
        &data_dir,
        &[
            "dead",
            "--production-only",
            "--limit",
            "100",
            "--format",
            "json",
        ],
    );
    let candidate_names = full["items"]
        .as_array()
        .expect("full Dead items")
        .iter()
        .filter_map(|item| item["symbol"]["name"].as_str())
        .collect::<Vec<_>>();
    assert!(
        candidate_names.contains(&"genuinelyUnreached"),
        "positive full-report candidate control: {full}"
    );
    assert!(
        !candidate_names.contains(&"callableContract::Contract")
            && !candidate_names.contains(&"callableValue"),
        "callable contracts and retained value bindings must not become false executable candidates: {full}"
    );
}

/// Provider-specific workspace-selection strings are not a public authority
/// taxonomy. The shipped executable must normalize a genuinely omitted Go
/// document to the stable product reason while withholding a negative claim
/// about the excluded declaration.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY"]
fn installed_go_callable_liveness_normalizes_build_exclusions() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed Go exclusion acceptance"),
    );
    let temporary = TempDir::new().expect("installed Go exclusion scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(&root).expect("Go source directory");
    std::fs::write(
        root.join("go.mod"),
        "module example.com/h00ligan-liveness-exclusion\n\ngo 1.27\n",
    )
    .expect("Go manifest");
    std::fs::write(root.join("main.go"), "package main\n\nfunc main() {}\n")
        .expect("active Go source");
    std::fs::write(
        root.join("excluded.go"),
        concat!(
            "//go:build h00_excluded_fixture\n\n",
            "package main\n\n",
            "func buildTaggedOnly() {}\n",
        ),
    )
    .expect("build-excluded Go source");

    let indexed = index_with_qualified_semantics(&binary, &root, &data_dir);
    assert_eq!(
        indexed["capabilities"]["callable_liveness"]["status"], "qualified",
        "an omitted source document must prevent false complete authority: {indexed}"
    );
    let qualifications =
        indexed["capabilities"]["callable_liveness"]["languages"][0]["qualifications"]
            .as_array()
            .expect("callable-liveness qualifications");
    assert_eq!(qualifications.len(), 1, "{indexed}");
    assert_eq!(
        qualifications[0]["reason_code"], "provider_document_omitted",
        "provider-internal workspace states must be normalized: {indexed}"
    );

    let excluded = run_json_query(
        &binary,
        &root,
        &data_dir,
        &[
            "dead",
            "buildTaggedOnly",
            "--file",
            "excluded.go",
            "--format",
            "json",
        ],
    );
    assert_eq!(excluded["items"][0]["verdict"], "unknown", "{excluded}");
    assert_eq!(
        excluded["items"][0]["recommendation"], "withheld",
        "{excluded}"
    );
    assert_eq!(
        excluded["items"][0]["evidence"]["reason_code"], "provider_coverage_exclusions",
        "{excluded}"
    );
    assert!(
        excluded["items"][0]["evidence"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("provider_document_omitted")),
        "the exact stable exclusion reason must remain inspectable: {excluded}"
    );
}

#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and an installed Rust toolchain"]
fn installed_one_file_cli_and_mcp_share_exact_semantic_authority() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed MCP acceptance"),
    );
    let temporary = TempDir::new().expect("installed semantic MCP scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"installed-mcp\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
    )
    .expect("source");

    let cli = index_with_semantics(&binary, &root, &data_dir);
    assert_eq!(
        cli["reused_generation"], false,
        "fresh scratch must build: {cli}"
    );
    assert_eq!(cli["capabilities"]["calls"]["status"], "complete", "{cli}");
    let generation = cli["generation_id"]
        .as_str()
        .expect("CLI generation ID")
        .to_owned();

    let mut child = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn installed MCP server");
    let mut stdin = child.stdin.take().expect("MCP stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
    let mut id = 1_u64;

    let first = reindex_terminal(&mut stdin, &mut stdout, &mut id);
    assert_eq!(
        first["reused_generation"], true,
        "fresh MCP process must reuse CLI authority: {first}"
    );
    assert_eq!(first["generation"]["id"], generation, "{first}");
    let second = reindex_terminal(&mut stdin, &mut stdout, &mut id);
    assert_eq!(
        second["reused_generation"], true,
        "same MCP process must reuse: {second}"
    );
    assert_eq!(second["generation"]["id"], generation, "{second}");

    let calls_response = call_mcp(
        &mut stdin,
        &mut stdout,
        id,
        "calls",
        json!({"symbol": "target"}),
    );
    let calls = structured_content(&calls_response, "calls");
    assert_eq!(
        calls["generation_id"], generation,
        "query/read generation split: {calls}"
    );
    assert_eq!(calls["authority"]["status"], "complete", "{calls}");
    assert!(
        calls["items"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["origin"]["identity"]["name"] == "caller")
        }),
        "MCP Calls omitted the known caller: {calls}"
    );

    stop_mcp(child, stdin);
    assert!(
        !root.join("Cargo.lock").exists(),
        "indexing mutated the project manifest state"
    );
    assert!(
        !root.join("target").exists(),
        "provider cache escaped into the project root"
    );
}

struct InstalledLinkedWorktreeFixture {
    root: PathBuf,
    data_dir: PathBuf,
}

fn installed_linked_worktree_fixture(
    temporary: &TempDir,
    reciprocal_gitdir: bool,
) -> InstalledLinkedWorktreeFixture {
    let root = temporary.path().join("worktree");
    let common_git = temporary.path().join("main/.git");
    let worktree_git = common_git.join("worktrees/fixture");
    let branch_ref = common_git.join("refs/heads/fixture");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::create_dir_all(branch_ref.parent().expect("branch-ref parent"))
        .expect("common refs directory");
    std::fs::create_dir_all(&worktree_git).expect("worktree git directory");
    std::fs::write(
        root.join(".git"),
        format!("gitdir: {}\n", worktree_git.display()),
    )
    .expect("linked-worktree marker");
    std::fs::write(worktree_git.join("commondir"), "../..\n").expect("common-dir pointer");
    if reciprocal_gitdir {
        std::fs::write(
            worktree_git.join("gitdir"),
            format!("{}\n", root.join(".git").display()),
        )
        .expect("reciprocal worktree pointer");
    }
    std::fs::write(worktree_git.join("HEAD"), "ref: refs/heads/fixture\n").expect("worktree HEAD");
    std::fs::write(&branch_ref, format!("{}\n", "1".repeat(40))).expect("shared branch ref");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"linked-worktree\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n[workspace]\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("build.rs"),
        format!(
            "fn main() {{\n    let branch_ref = std::path::Path::new({:?});\n    println!(\"cargo:rerun-if-changed={{}}\", branch_ref.display());\n}}\n",
            branch_ref.to_str().expect("UTF-8 branch ref")
        ),
    )
    .expect("build script");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
    )
    .expect("source");

    InstalledLinkedWorktreeFixture { root, data_dir }
}

/// FALSIFIER for linked Git worktrees: Cargo build scripts may legitimately
/// declare the worktree's per-checkout HEAD or the shared common ref as an
/// input. Those files live outside the checked-out source root. The installed
/// product must bind them through Git's own reciprocal `.git`/`gitdir` and
/// `commondir` control plane while refusing unrelated machine-external inputs.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and an installed Rust toolchain"]
fn installed_rust_linked_worktree_git_inputs_remain_complete() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for linked-worktree acceptance"),
    );
    let temporary = TempDir::new().expect("linked-worktree scratch workspace");
    let fixture = installed_linked_worktree_fixture(&temporary, true);

    let indexed = index_with_semantics(&binary, &fixture.root, &fixture.data_dir);
    assert_eq!(
        indexed["capabilities"]["calls"]["status"], "complete",
        "linked-worktree Git inputs must retain Complete Calls authority: {indexed}"
    );
    assert!(
        !fixture.root.join("Cargo.lock").exists(),
        "indexing wrote Cargo.lock"
    );
    assert!(
        !fixture.root.join("target").exists(),
        "provider cache escaped into the worktree"
    );
}

/// RIGHT-REASON REGRESSION: a repository-controlled `.git` file alone cannot
/// grant semantic-input authority over an arbitrary external directory. Git's
/// per-worktree `gitdir` file must point back to that exact repository marker.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and an installed Rust toolchain"]
fn installed_rust_linked_worktree_refuses_nonreciprocal_git_authority() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for linked-worktree refusal"),
    );
    let temporary = TempDir::new().expect("forged linked-worktree scratch workspace");
    let fixture = installed_linked_worktree_fixture(&temporary, false);
    let output = Command::new(&binary)
        .args(["--root", fixture.root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            fixture.data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .output()
        .expect("run installed semantic index against forged Git authority");
    let diagnostic = format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !output.status.success(),
        "a one-way linked-worktree pointer incorrectly earned Complete Calls authority: {diagnostic}"
    );
    assert!(
        diagnostic.contains("linked-worktree gitdir backpointer"),
        "refusal did not identify the missing reciprocal authority proof: {diagnostic}"
    );
    assert!(
        diagnostic.contains("required complete Calls authority was not produced"),
        "strict indexing did not preserve its typed terminal contract: {diagnostic}"
    );
    assert!(
        !fixture.root.join("Cargo.lock").exists(),
        "refusal wrote Cargo.lock"
    );
    assert!(
        !fixture.root.join("target").exists(),
        "refusal leaked provider state into the worktree"
    );
}

/// Installed-product acceptance for the native TypeScript lane. The process
/// receives no ambient PATH or JavaScript toolchain; all semantic authority
/// must come from bytes embedded in the one-file h00ligan product.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY"]
fn installed_typescript_cli_and_mcp_need_no_ambient_toolchain() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed TypeScript acceptance"),
    );
    let temporary = TempDir::new().expect("installed TypeScript MCP scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let process_tmp = temporary.path().join("tmp");
    std::fs::create_dir_all(root.join("src")).expect("TypeScript source directory");
    std::fs::create_dir_all(&process_tmp).expect("private process temporary directory");
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"installed-typescript","private":true,"type":"module"}"#,
    )
    .expect("package manifest");
    std::fs::write(
        root.join("tsconfig.json"),
        r#"{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true},"include":["src/**/*.ts"]}"#,
    )
    .expect("TypeScript configuration");
    std::fs::write(
        root.join("src/target.ts"),
        "export function target(value: number): number { return value + 1; }\n",
    )
    .expect("TypeScript target source");
    std::fs::write(
        root.join("src/caller.ts"),
        "import { target } from './target.js';\nexport function caller(): number { return target(41); }\n",
    )
    .expect("TypeScript caller source");
    let source_before = [
        (
            "package.json",
            std::fs::read(root.join("package.json")).unwrap(),
        ),
        (
            "tsconfig.json",
            std::fs::read(root.join("tsconfig.json")).unwrap(),
        ),
        (
            "src/target.ts",
            std::fs::read(root.join("src/target.ts")).unwrap(),
        ),
        (
            "src/caller.ts",
            std::fs::read(root.join("src/caller.ts")).unwrap(),
        ),
    ];

    let output = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", &process_tmp)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .output()
        .expect("run installed TypeScript semantic index");
    assert!(
        output.status.success(),
        "installed TypeScript index failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let cli: Value = serde_json::from_slice(&output.stdout).expect("TypeScript index JSON");
    assert_eq!(cli["reused_generation"], false, "{cli}");
    assert_eq!(cli["capabilities"]["calls"]["status"], "complete", "{cli}");
    let generation = cli["generation_id"]
        .as_str()
        .expect("TypeScript generation ID")
        .to_owned();
    assert_one_private_embedded_provider(&data_dir, "h00-typescript-semantic-provider");

    let mut child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", &process_tmp)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn installed TypeScript MCP server");
    let mut stdin = child.stdin.take().expect("MCP stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
    let mut id = 1_u64;
    let reused = reindex_terminal(&mut stdin, &mut stdout, &mut id);
    assert_eq!(reused["reused_generation"], true, "{reused}");
    assert_eq!(reused["generation"]["id"], generation, "{reused}");

    let calls_response = call_mcp(
        &mut stdin,
        &mut stdout,
        id,
        "calls",
        json!({"symbol": "target"}),
    );
    let calls = structured_content(&calls_response, "TypeScript calls");
    assert_eq!(calls["generation_id"], generation, "{calls}");
    assert_eq!(calls["authority"]["status"], "complete", "{calls}");
    assert!(
        calls["items"].as_array().is_some_and(|items| items
            .iter()
            .any(|item| item["origin"]["identity"]["name"] == "caller")),
        "TypeScript Calls omitted the cross-file caller: {calls}"
    );
    stop_mcp(child, stdin);

    for (relative, expected) in source_before {
        assert_eq!(
            std::fs::read(root.join(relative)).expect("source after indexing"),
            expected,
            "installed TypeScript indexing mutated {relative}"
        );
    }
    assert!(!root.join("node_modules").exists());
    assert!(!root.join("package-lock.json").exists());
}

/// Installed-product acceptance for the native Python lane. The process has
/// no ambient PATH, interpreter, virtual environment, or Pyrefly executable;
/// semantic authority must come from the provider embedded in h00ligan.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY"]
fn installed_python_cli_and_mcp_need_no_ambient_toolchain() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed Python acceptance"),
    );
    let temporary = TempDir::new().expect("installed Python MCP scratch workspace");
    let root = temporary.path().join("repo");
    let execution_root = root.join("apps/agents");
    let data_dir = temporary.path().join("data");
    let process_tmp = temporary.path().join("tmp");
    std::fs::create_dir_all(execution_root.join("src/fixture"))
        .expect("nested Python source directory");
    std::fs::create_dir_all(&process_tmp).expect("private process temporary directory");
    std::fs::write(
        execution_root.join("pyproject.toml"),
        r#"[project]
name = "installed-python"
version = "0.1.0"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/fixture"]
"#,
    )
    .expect("Python project manifest");
    std::fs::write(execution_root.join("src/fixture/__init__.py"), "")
        .expect("Python package marker");
    std::fs::write(
        execution_root.join("src/fixture/target.py"),
        concat!(
            "class Widget:\n",
            "    def __init__(self, value: int) -> None:\n",
            "        self.value = value\n",
            "\n",
            "def target(value: int) -> int:\n",
            "    return value + 1\n",
        ),
    )
    .expect("Python target source");
    std::fs::write(
        execution_root.join("src/fixture/dynamic_pb2.py"),
        "globals()[\"AuditRecord\"] = type(\"AuditRecord\", (), {})\n",
    )
    .expect("Python dynamic runtime module");
    std::fs::write(
        execution_root.join("src/fixture/dynamic_pb2.pyi"),
        concat!(
            "class AuditRecord:\n",
            "    def __init__(self, value: str = ...) -> None: ...\n",
        ),
    )
    .expect("Python adjacent stub declaration");
    std::fs::write(
        execution_root.join("src/fixture/caller.py"),
        concat!(
            "from fixture.target import Widget, target\n",
            "from fixture.dynamic_pb2 import AuditRecord\n",
            "\n",
            "def caller() -> tuple[int, object]:\n",
            "    return target(Widget(40).value), AuditRecord(value=\"ok\")\n",
        ),
    )
    .expect("Python caller source");
    let source_before = [
        (
            "apps/agents/pyproject.toml",
            std::fs::read(execution_root.join("pyproject.toml")).unwrap(),
        ),
        (
            "apps/agents/src/fixture/__init__.py",
            std::fs::read(execution_root.join("src/fixture/__init__.py")).unwrap(),
        ),
        (
            "apps/agents/src/fixture/target.py",
            std::fs::read(execution_root.join("src/fixture/target.py")).unwrap(),
        ),
        (
            "apps/agents/src/fixture/dynamic_pb2.py",
            std::fs::read(execution_root.join("src/fixture/dynamic_pb2.py")).unwrap(),
        ),
        (
            "apps/agents/src/fixture/dynamic_pb2.pyi",
            std::fs::read(execution_root.join("src/fixture/dynamic_pb2.pyi")).unwrap(),
        ),
        (
            "apps/agents/src/fixture/caller.py",
            std::fs::read(execution_root.join("src/fixture/caller.py")).unwrap(),
        ),
    ];

    let output = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", &process_tmp)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .output()
        .expect("run installed Python semantic index");
    assert!(
        output.status.success(),
        "installed Python index failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let cli: Value = serde_json::from_slice(&output.stdout).expect("Python index JSON");
    assert_eq!(cli["reused_generation"], false, "{cli}");
    assert_eq!(cli["capabilities"]["calls"]["status"], "complete", "{cli}");
    let generation = cli["generation_id"]
        .as_str()
        .expect("Python generation ID")
        .to_owned();
    assert_one_private_embedded_provider(&data_dir, "h00-pyrefly-semantic-provider");

    let mut child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", &process_tmp)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn installed Python MCP server");
    let mut stdin = child.stdin.take().expect("MCP stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
    let mut id = 1_u64;
    let reused = reindex_terminal(&mut stdin, &mut stdout, &mut id);
    assert_eq!(reused["reused_generation"], true, "{reused}");
    assert_eq!(reused["generation"]["id"], generation, "{reused}");

    let calls_response = call_mcp(
        &mut stdin,
        &mut stdout,
        id,
        "calls",
        json!({"symbol": "target"}),
    );
    let calls = structured_content(&calls_response, "Python calls");
    assert_eq!(calls["generation_id"], generation, "{calls}");
    assert_eq!(calls["authority"]["status"], "complete", "{calls}");
    assert!(
        calls["items"].as_array().is_some_and(|items| items
            .iter()
            .any(|item| item["origin"]["identity"]["name"] == "caller")),
        "Python Calls omitted the cross-file caller: {calls}"
    );

    id += 1;
    let construction_response = call_mcp(
        &mut stdin,
        &mut stdout,
        id,
        "calls",
        json!({"symbol": "Widget"}),
    );
    let construction = structured_content(&construction_response, "Python class construction");
    assert_eq!(construction["generation_id"], generation, "{construction}");
    assert_eq!(
        construction["authority"]["status"], "complete",
        "{construction}"
    );
    assert!(
        construction["items"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["origin"]["identity"]["name"] == "caller")
        }),
        "Python Calls omitted the cross-file class construction: {construction}"
    );

    id += 1;
    let stub_construction_response = call_mcp(
        &mut stdin,
        &mut stdout,
        id,
        "calls",
        json!({"symbol": "AuditRecord"}),
    );
    let stub_construction = structured_content(
        &stub_construction_response,
        "Python adjacent-stub class construction",
    );
    assert_eq!(stub_construction["generation_id"], generation);
    assert_eq!(stub_construction["authority"]["status"], "complete");
    assert!(
        stub_construction["items"]
            .as_array()
            .is_some_and(|items| items
                .iter()
                .any(|item| item["origin"]["identity"]["name"] == "caller")),
        "Python Calls omitted the adjacent-stub class construction: {stub_construction}"
    );
    stop_mcp(child, stdin);

    for (relative, expected) in source_before {
        assert_eq!(
            std::fs::read(root.join(relative)).expect("source after indexing"),
            expected,
            "installed Python indexing mutated {relative}"
        );
    }
    assert!(!root.join(".venv").exists());
    assert!(!execution_root.join(".venv").exists());
    assert!(!root.join("__pycache__").exists());
}

/// Installed-product acceptance for JavaScript/JSX discovery plus a
/// repository-contained pnpm-style package link. Reusing the CLI generation
/// through MCP also proves the Rust reader reproduces the Go provider's exact
/// symlink-aware semantic-input receipt.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY"]
fn installed_javascript_jsx_and_pnpm_share_exact_semantic_authority() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed JavaScript acceptance"),
    );
    let temporary = TempDir::new().expect("installed JavaScript MCP scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let process_tmp = temporary.path().join("tmp");
    std::fs::create_dir_all(root.join("src")).expect("JavaScript source directory");
    std::fs::create_dir_all(&process_tmp).expect("private process temporary directory");
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"installed-javascript","private":true,"type":"module"}"#,
    )
    .expect("package manifest");
    std::fs::write(
        root.join("tsconfig.json"),
        r#"{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","allowJs":true,"checkJs":true,"jsx":"preserve"},"include":["src/**/*.js","src/**/*.jsx"]}"#,
    )
    .expect("JavaScript configuration");
    let package_root = root.join(".pnpm/fixture-a/node_modules/fixture-dependency");
    std::fs::create_dir_all(&package_root).expect("pnpm package store");
    std::fs::write(
        package_root.join("package.json"),
        r#"{"name":"fixture-dependency","version":"1.0.0","type":"module","types":"index.d.ts"}"#,
    )
    .expect("dependency manifest");
    std::fs::write(
        package_root.join("index.d.ts"),
        "export declare function dependency(): number;\n",
    )
    .expect("dependency declaration");
    std::fs::create_dir(root.join("node_modules")).expect("node_modules");
    symlink(
        "../.pnpm/fixture-a/node_modules/fixture-dependency",
        root.join("node_modules/fixture-dependency"),
    )
    .expect("pnpm package link");
    let component = "/** @param {string} label */\nexport function Widget(label) { return <button>{label}</button>; }\n";
    let caller = "import { dependency } from 'fixture-dependency';\nimport { Widget } from './component.jsx';\nexport function render() { return Widget(String(dependency())); }\n";
    std::fs::write(root.join("src/component.jsx"), component).expect("JSX component");
    std::fs::write(root.join("src/caller.js"), caller).expect("JavaScript caller");

    let output = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", &process_tmp)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .output()
        .expect("run installed JavaScript semantic index");
    assert!(
        output.status.success(),
        "installed JavaScript index failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let cli: Value = serde_json::from_slice(&output.stdout).expect("JavaScript index JSON");
    assert_eq!(cli["capabilities"]["calls"]["status"], "complete", "{cli}");
    let generation = cli["generation_id"]
        .as_str()
        .expect("JavaScript generation ID")
        .to_owned();
    assert_one_private_embedded_provider(&data_dir, "h00-typescript-semantic-provider");

    let mut child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", &process_tmp)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn installed JavaScript MCP server");
    let mut stdin = child.stdin.take().expect("MCP stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
    let mut id = 1_u64;
    let reused = reindex_terminal(&mut stdin, &mut stdout, &mut id);
    assert_eq!(reused["reused_generation"], true, "{reused}");
    assert_eq!(reused["generation"]["id"], generation, "{reused}");
    let calls_response = call_mcp(
        &mut stdin,
        &mut stdout,
        id,
        "calls",
        json!({"symbol": "Widget"}),
    );
    let calls = structured_content(&calls_response, "JavaScript/JSX calls");
    assert_eq!(calls["authority"]["status"], "complete", "{calls}");
    assert!(
        calls["items"].as_array().is_some_and(|items| items
            .iter()
            .any(|item| item["origin"]["identity"]["name"] == "render")),
        "JavaScript Calls omitted the JSX definition's caller: {calls}"
    );
    stop_mcp(child, stdin);
    assert_eq!(
        std::fs::read(root.join("src/component.jsx")).unwrap(),
        component.as_bytes()
    );
    assert_eq!(
        std::fs::read(root.join("src/caller.js")).unwrap(),
        caller.as_bytes()
    );
}
