use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const EXPECTED_TOOLS: &[&str] = &[
    "reindex",
    "reindex_status",
    "reindex_cancel",
    "watch",
    "type",
    "read",
    "calls",
    "assess",
    "inspect",
    "dead_code",
    "status",
    "find",
    "tests",
    "overview",
    "audit",
    "deps",
    "grep_context",
    "diff",
];

/// Interactive real-process harness for lifecycle-sensitive MCP tests.
///
/// A batch of requests followed by EOF cannot prove that reindex is
/// nonblocking: EOF itself asks the server to shut down and cancel background
/// work. This harness keeps the production process alive, consumes one exact
/// response at a time, and drains stderr concurrently so provider logging
/// cannot deadlock a test.
struct McpSession {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    next_id: u64,
}

impl McpSession {
    fn spawn(command: &mut Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn MCP server");
        let stdin = child.stdin.take().expect("MCP stdin");
        let stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
        let mut stderr = child.stderr.take().expect("MCP stderr");
        let stderr = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).expect("read MCP stderr");
            bytes
        });
        Self {
            child: Some(child),
            stdin: Some(stdin),
            stdout,
            stderr: Some(stderr),
            next_id: 1,
        }
    }

    fn call(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        });
        let stdin = self.stdin.as_mut().expect("live MCP stdin");
        writeln!(stdin, "{request}").expect("write MCP request");
        stdin.flush().expect("flush MCP request");

        let mut line = String::new();
        let bytes = self.stdout.read_line(&mut line).expect("read MCP response");
        assert_ne!(bytes, 0, "MCP closed before responding to {name}");
        let response: serde_json::Value =
            serde_json::from_str(line.trim()).expect("JSON-RPC response");
        assert_eq!(response["id"], id, "response/request ID mismatch");
        response
    }

    fn finish(mut self) -> (ExitStatus, String) {
        drop(self.stdin.take());
        let status = self
            .child
            .as_mut()
            .expect("live MCP child")
            .wait()
            .expect("wait for MCP server");
        self.child.take();
        let stderr = self
            .stderr
            .take()
            .expect("stderr reader")
            .join()
            .expect("join MCP stderr reader");
        (status, String::from_utf8(stderr).expect("UTF-8 MCP stderr"))
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

fn mcp_tool_payload(response: &serde_json::Value) -> serde_json::Value {
    if let Some(payload) = response["result"].get("structuredContent") {
        return payload.clone();
    }
    serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("MCP tool result text"),
    )
    .expect("MCP tool result JSON")
}

fn start_reindex_and_wait(
    session: &mut McpSession,
    arguments: serde_json::Value,
) -> serde_json::Value {
    let started = session.call("reindex", arguments);
    assert_ne!(
        started["result"]["isError"], true,
        "reindex start must return an operation receipt: {started}"
    );
    let started = mcp_tool_payload(&started);
    assert_eq!(
        started["terminal"], false,
        "reindex must start asynchronously"
    );
    let operation_id = started["operation_id"]
        .as_str()
        .expect("reindex operation ID")
        .to_owned();
    wait_reindex_terminal(session, &operation_id)
}

fn wait_reindex_terminal(session: &mut McpSession, operation_id: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let response = session.call(
            "reindex_status",
            serde_json::json!({"operation_id": operation_id}),
        );
        assert_ne!(
            response["result"]["isError"], true,
            "owned reindex status must remain available: {response}"
        );
        let status = mcp_tool_payload(&response);
        if status["terminal"] == true {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "reindex operation did not become terminal: {status}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/h00ligan")
        .to_path_buf()
}

fn production_code(source: &str) -> String {
    let cutoff = source.find("\nmod tests {").map_or(source.len(), |module| {
        source[..module].rfind("\n#[cfg").unwrap_or(module)
    });
    source[..cutoff]
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

fn read_production_code(relative: &str) -> String {
    let path = workspace_root().join(relative);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    production_code(&source)
}

fn collect_rust_sources(directory: &Path, files: &mut Vec<PathBuf>) {
    let mut entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .collect::<Result<Vec<_>, _>>()
        .expect("read source entry");
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, files);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

fn compact_code(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn forbidden_handler_tokens(source: &str) -> Vec<&'static str> {
    const FORBIDDEN: &[&str] = &[
        "EngineConfig::load(",
        "apply_data_dir(",
        "expanded_path(",
        "LanceStore",
        "connect_or_open",
        "MemoryStore",
        "EventBus",
        "ToolContext",
    ];
    let compact = compact_code(source);
    FORBIDDEN
        .iter()
        .copied()
        .filter(|token| compact.contains(token))
        .collect()
}

fn is_forbidden_lean_package(package: &str) -> bool {
    let package = package.to_ascii_lowercase();
    package == "lancedb"
        || package.starts_with("lancedb-")
        || package == "h00-sdl"
        || package == "tarpc"
        || package == "tarpc-plugins"
        || package == "tiktoken-rs"
        || package == "arrow"
        || package.starts_with("arrow-")
        || package == "moka"
        || package.starts_with("moka-")
        || package == "fastembed"
        || package.starts_with("fastembed-")
        || package == "candle"
        || package.starts_with("candle-")
        || package == "ort"
        || package.starts_with("ort-")
        || package.contains("cuda")
        || package == "reqwest"
        || package == "portable-pty"
        || package == "shell-words"
}

fn forbidden_default_binary_symbols(symbols: &str) -> Vec<&'static str> {
    const FORBIDDEN: &[&str] = &[
        "h00ligan_engine::lance_store::LanceStore::open",
        "h00ligan::store_connect::connect_or_open",
        "h00ligan::store_connect::",
    ];
    FORBIDDEN
        .iter()
        .copied()
        .filter(|symbol| symbols.contains(symbol))
        .collect()
}

#[test]
fn help_names_the_repo_local_code_intelligence_data_default() {
    for args in [&["--help"][..], &["index", "--help"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
            .args(args)
            .output()
            .expect("run h00ligan help");
        assert!(output.status.success(), "help command failed for {args:?}");
        let help = String::from_utf8(output.stdout).expect("UTF-8 help output");
        assert!(
            help.contains(
                "Override code-intelligence data directory (default: <repo>/.h00ligan/code-intel)"
            ),
            "help must name the repo-local code-intelligence data default for {args:?}:\n{help}"
        );
        assert!(
            !help.contains("~/.h00"),
            "help must not advertise the old central substrate path for {args:?}:\n{help}"
        );
    }
}

#[test]
fn standalone_cli_has_one_root_authority_and_no_workspace_alias() {
    let temporary = tempfile::tempdir().expect("temporary roots");
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    let graph = temporary.path().join("graph");
    std::fs::create_dir_all(&first).expect("first root");
    std::fs::create_dir_all(&second).expect("second root");

    let help = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["status", "--help"])
        .output()
        .expect("read status help");
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).expect("UTF-8 status help");
    assert!(
        help.contains("Select a project root") && !help.contains("Workspace root"),
        "the global process selector must own status root help: {help}"
    );

    let workspace_alias = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&first)
        .arg("--data-dir")
        .arg(&graph)
        .arg("--workspace")
        .arg(&second)
        .arg("status")
        .output()
        .expect("run retired workspace alias");
    assert!(!workspace_alias.status.success());
    assert!(
        String::from_utf8_lossy(&workspace_alias.stderr)
            .contains("unexpected argument '--workspace'"),
        "standalone startup must not carry a second root alias: {}",
        String::from_utf8_lossy(&workspace_alias.stderr)
    );
}

#[test]
fn production_config_loads_are_exhaustively_classified() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rust_sources(&root.join("crates/h00ligan/src"), &mut files);
    assert!(
        !files.is_empty(),
        "source population control must enumerate a non-empty h00ligan crate"
    );
    assert!(
        files.contains(&root.join("crates/h00ligan/src/ligan_cmd.rs"))
            && files.contains(&root.join("crates/h00ligan/src/binding.rs"))
            && files.contains(&root.join("crates/h00ligan/src/bin/h00ligan.rs")),
        "source population control must include the binding, binary, and command implementation"
    );

    let mut observed = BTreeMap::new();
    for path in files {
        let relative = path
            .strip_prefix(&root)
            .expect("source below workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&path).expect("read h00ligan source");
        let count = compact_code(&production_code(&source))
            .matches("EngineConfig::load(None)")
            .count();
        if count > 0 {
            observed.insert(relative, count);
        }
    }

    assert_eq!(
        compact_code("fn control() { EngineConfig::load(None); }")
            .matches("EngineConfig::load(None)")
            .count(),
        1,
        "config-load absence probe must fire on a known positive"
    );
    let expected = BTreeMap::new();
    assert_eq!(
        observed, expected,
        "h00ligan production must not resolve project authority from memory configuration"
    );

    let binding = compact_code(&read_production_code("crates/h00ligan/src/binding.rs"));
    assert!(binding.contains("fnresolve_project_binding("));
    assert!(binding.contains("ProjectBinding::resolve("));
    assert!(!binding.contains("ProjectBinding::legacy_storage("));
}

#[test]
fn code_intel_handlers_cannot_resolve_config_or_open_the_substrate() {
    let control = forbidden_handler_tokens(
        "fn bypass() { EngineConfig::load(None); let _: &dyn MemoryStore; }",
    );
    assert!(control.contains(&"EngineConfig::load("));
    assert!(control.contains(&"MemoryStore"));

    let mut violations = Vec::new();
    for relative in [
        "crates/h00ligan-interface/src/tools/code_intel.rs",
        "crates/h00ligan-interface/src/tools/composite_intel.rs",
        "crates/h00ligan-interface/src/tools/composite_intel_query.rs",
    ] {
        let source = read_production_code(relative);
        assert!(
            compact_code(&source).contains("implCodeIntelHandler"),
            "handler population control did not fire for {relative}"
        );
        for token in forbidden_handler_tokens(&source) {
            violations.push(format!("{relative}: {token}"));
        }
    }
    assert!(
        violations.is_empty(),
        "store/config capability leaked into code-intel handlers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn standalone_dispatch_propagates_one_binding_to_every_command_arm() {
    let entrypoint = read_production_code("crates/h00ligan/src/bin/h00ligan.rs");
    assert!(
        entrypoint.contains("fn main()") && entrypoint.contains("h00ligan::product::run("),
        "the executable entrypoint must delegate to the reusable product-policy boundary"
    );
    assert!(
        !entrypoint.contains("resolve_project_binding") && !entrypoint.contains("LiganCommand::"),
        "the executable entrypoint must not duplicate binding or dispatch authority"
    );

    let source = read_production_code("crates/h00ligan/src/cli.rs");
    assert_eq!(
        source
            .matches("crate::binding::resolve_project_binding(")
            .count(),
        1,
        "the reusable product CLI boundary must resolve exactly one project binding"
    );
    assert!(!source.contains("EngineConfig::load"));
    assert!(!source.contains("apply_data_dir"));

    let (_, after_match) = source
        .split_once("let result = match cli.command {")
        .expect("standalone command dispatch match");
    let (dispatch, _) = after_match
        .split_once("\n    };\n\n    if let Err")
        .expect("end of standalone command dispatch match");
    let arms: Vec<_> = dispatch.split("LiganCommand::").skip(1).collect();
    let names: Vec<String> = arms
        .iter()
        .map(|arm| {
            arm.trim_start()
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect()
        })
        .collect();
    let expected = [
        "Index",
        "Watch",
        "Type",
        "Read",
        "Calls",
        "Assess",
        "Inspect",
        "Dead",
        "Status",
        "Find",
        "Tests",
        "Overview",
        "Audit",
        "Deps",
        "GrepContext",
        "Diff",
        "McpServe",
    ];
    assert_eq!(names, expected, "dispatch population changed");
    for (name, arm) in names.iter().zip(arms) {
        assert!(
            arm.contains("&binding"),
            "{name} bypasses the startup-resolved binding"
        );
    }
}

#[test]
fn default_dependency_graph_excludes_the_substrate_stack() {
    assert!(is_forbidden_lean_package("lancedb"));
    assert!(is_forbidden_lean_package("tarpc"));
    assert!(!is_forbidden_lean_package("redb"));

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let normal = Command::new(&cargo)
        .current_dir(workspace_root())
        .args([
            "tree",
            "--offline",
            "-p",
            "h00ligan",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .output()
        .expect("run cargo tree for h00ligan");
    assert!(
        normal.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&normal.stderr)
    );
    let packages: BTreeSet<String> = String::from_utf8(normal.stdout)
        .expect("UTF-8 cargo tree")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect();
    for required in ["h00ligan", "h00ligan-interface", "h00ligan-engine", "redb"] {
        assert!(
            packages.contains(required),
            "positive package control missing: {required}"
        );
    }
    let forbidden: Vec<_> = packages
        .iter()
        .filter(|package| is_forbidden_lean_package(package))
        .cloned()
        .collect();
    assert_eq!(forbidden, Vec::<String>::new());

    let agent_features = Command::new(&cargo)
        .current_dir(workspace_root())
        .args([
            "tree",
            "--offline",
            "-p",
            "h00ligan",
            "--edges",
            "features",
            "-i",
            "h00ligan-interface",
        ])
        .output()
        .expect("run h00ligan-interface feature tree");
    assert!(agent_features.status.success());
    let agent_features = String::from_utf8(agent_features.stdout).expect("UTF-8 feature tree");
    for required in ["code-intel", "mcp"] {
        assert!(agent_features.contains(&format!("h00ligan-interface feature \"{required}\"")));
    }
    for forbidden in ["full", "runtime", "memory", "embed-candle", "client-tools"] {
        assert!(
            !agent_features.contains(&format!("h00ligan-interface feature \"{forbidden}\"")),
            "unexpected h00ligan-interface feature enabled: {forbidden}"
        );
    }

    let engine_features = Command::new(&cargo)
        .current_dir(workspace_root())
        .args([
            "tree",
            "--offline",
            "-p",
            "h00ligan",
            "--edges",
            "features",
            "-i",
            "h00ligan-engine",
        ])
        .output()
        .expect("run h00ligan-engine feature tree");
    assert!(engine_features.status.success());
    let engine_features = String::from_utf8(engine_features.stdout).expect("UTF-8 feature tree");
    assert!(engine_features.contains("h00ligan-engine feature \"code-intel\""));
    assert!(!engine_features.contains("h00ligan-engine feature \"store\""));
    assert!(!engine_features.contains("h00ligan-engine feature \"embed-candle\""));
}

#[cfg(unix)]
#[test]
fn binary_excludes_memory_substrate_connection_symbols() {
    let synthetic = concat!(
        "h00ligan_engine::lance_store::LanceStore::open\n",
        "h00ligan::store_connect::connect_or_open\n",
    );
    assert_eq!(forbidden_default_binary_symbols(synthetic).len(), 3);

    let output = Command::new("nm")
        .args(["-C", env!("CARGO_BIN_EXE_h00ligan")])
        .output()
        .expect("run nm against the default h00ligan binary");
    assert!(
        output.status.success(),
        "nm failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let symbols = String::from_utf8(output.stdout).expect("UTF-8 demangled symbol table");
    assert!(
        symbols.contains("h00ligan_interface::mcp::run_stdio"),
        "positive MCP symbol control did not fire"
    );
    assert_eq!(
        forbidden_default_binary_symbols(&symbols),
        Vec::<&str>::new(),
        "default h00ligan linked store-connection code"
    );
}

#[test]
fn manifest_has_no_memory_substrate_escape_hatch() {
    let manifest_path = workspace_root().join("crates/h00ligan/Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display()));
    assert!(
        manifest.contains("features = [\"code-intel\", \"mcp\"]"),
        "known-positive: dependency feature probe must fire on h00ligan-interface"
    );
    for forbidden in ["h00ligan-engine/store", "h00-sdl", "[features]", "store ="] {
        assert!(
            !manifest.contains(forbidden),
            "h00ligan manifest retained substrate escape hatch {forbidden:?}"
        );
    }

    let source_directory = workspace_root().join("crates/h00ligan/src");
    let mut sources = Vec::new();
    collect_rust_sources(&source_directory, &mut sources);
    assert!(
        !sources.is_empty()
            && sources.contains(&source_directory.join("lib.rs"))
            && sources.contains(&source_directory.join("bin/h00ligan.rs")),
        "known-positive: production source population unexpectedly empty"
    );
    assert!(
        !source_directory.join("store_connect.rs").exists(),
        "the retired h00ligan substrate connector still exists"
    );
}

#[test]
fn fresh_server_lists_exact_tools_without_indexing_and_fails_queries_structurally() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let other_root = temporary.path().join("other-repo");
    std::fs::create_dir_all(root.join(".git")).expect("git marker");

    let mut child = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root"])
        .arg(&root)
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn h00ligan mcp-serve");
    let requests = [
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"status","arguments":{}}
        }),
        serde_json::json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"path","arguments":{"from":"a","to":"b"}}
        }),
        serde_json::json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"status","arguments":[]}
        }),
        serde_json::json!({
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{"name":"find","arguments":{"query":"target","limit":"twenty"}}
        }),
        serde_json::json!({
            "jsonrpc":"2.0","id":6,"method":"tools/call",
            "params":{"name":"status","arguments":{"workspace":other_root}}
        }),
        serde_json::json!({
            "jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{"name":"find","arguments":{"query":"target","limit":101}}
        }),
        serde_json::json!({
            "jsonrpc":"2.0","id":8,"method":"tools/call",
            "params":{"name":"deps","arguments":{"path":"src/lib.rs","detail":true}}
        }),
    ];
    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("write request");
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for server");
    assert!(
        output.status.success(),
        "server failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let responses: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .expect("UTF-8 stdout")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON-RPC response"))
        .collect();
    assert_eq!(responses.len(), 8);
    for (expected_id, response) in (1..=8).zip(&responses) {
        assert_eq!(response["id"], expected_id, "responses must stay ordered");
    }
    let tools = responses[0]["result"]["tools"]
        .as_array()
        .expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(names, EXPECTED_TOOLS);
    let reindex = tools
        .iter()
        .find(|tool| tool["name"] == "reindex")
        .expect("reindex definition");
    assert_eq!(
        reindex["inputSchema"]["properties"]["allow_capability_downgrade"]["type"], "boolean",
        "MCP must expose the same explicit capability-loss decision as the CLI"
    );
    assert_eq!(
        reindex["inputSchema"]["properties"]["require_complete_calls"]["type"], "boolean",
        "MCP must expose the same opt-in complete-Calls requirement as the CLI"
    );
    assert_eq!(
        reindex["inputSchema"]["properties"]["force"]["type"], "boolean",
        "MCP must expose the same explicit reuse bypass as the CLI"
    );

    let status_text = responses[1]["result"]["content"][0]["text"]
        .as_str()
        .expect("status text");
    let status: serde_json::Value = serde_json::from_str(status_text).expect("status JSON");
    assert_eq!(status["graph_loaded"], false);
    assert_eq!(
        status["root"],
        root.canonicalize().unwrap().to_string_lossy().as_ref()
    );

    assert_eq!(responses[2]["error"]["code"], -32602);
    assert!(
        responses[2]["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Unknown tool: path"))
    );

    for (response_index, expected_fragments) in [
        (3, &["arguments", "object"][..]),
        (4, &["arguments.limit", "integer"][..]),
        (5, &["workspace", "one project"][..]),
        (6, &["arguments.limit", "maximum", "100"][..]),
        (7, &["detail", "unadvertised"][..]),
    ] {
        let response = &responses[response_index];
        assert_eq!(response["error"]["code"], -32602);
        let message = response["error"]["message"]
            .as_str()
            .expect("invalid-params message");
        for expected in expected_fragments {
            assert!(
                message.contains(expected),
                "unexpected error for response {response_index}: {response}"
            );
        }
    }

    let graph_dir = root.join(".h00ligan/code-intel");
    assert!(
        !graph_dir.exists(),
        "read-only MCP startup must not create managed code-intelligence state"
    );
    assert!(!graph_dir.join("graph.redb").exists());
    assert!(!graph_dir.join("index.redb").exists());
    assert!(!graph_dir.join("reindex.incomplete").exists());
    assert!(!graph_dir.join("traces").exists());
    assert!(!graph_dir.join("profile").exists());
    assert!(!root.join("index.scip").exists());
}

#[test]
fn mcp_queries_fail_closed_when_the_published_head_population_becomes_invalid() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("bundle");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"mcp_head_failure\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn retained_answer_must_not_escape() {}\n",
    )
    .expect("source fixture");

    let indexed = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish initial generation");
    assert!(
        indexed.status.success(),
        "initial publication failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("mcp-serve");
    let mut session = McpSession::spawn(&mut command);

    let positive = session.call(
        "find",
        serde_json::json!({
            "query": "retained_answer_must_not_escape",
            "definitions_only": true
        }),
    );
    assert_ne!(
        positive["result"]["isError"], true,
        "positive control must prove the initial publication was queryable: {positive}"
    );
    let positive = mcp_tool_payload(&positive);
    assert_eq!(positive["page"]["total_items"], 1);

    let publication = data_dir.join("publication-v4");
    for slot in ["head-0.json", "head-1.json"] {
        std::fs::write(publication.join(slot), format!("invalid-{slot}"))
            .expect("invalidate published head control");
    }

    let status = session.call("status", serde_json::json!({}));
    assert_ne!(status["result"]["isError"], true, "{status}");
    let status = mcp_tool_payload(&status);
    assert_eq!(status["publication_state"], "invalid", "{status}");
    assert_eq!(status["availability"], "load_failed", "{status}");

    let refused = session.call(
        "find",
        serde_json::json!({
            "query": "retained_answer_must_not_escape",
            "definitions_only": true
        }),
    );
    assert_eq!(
        refused["result"]["isError"], true,
        "a process that cannot validate any published head must not serve its retained in-memory generation: {refused}"
    );
    assert!(
        refused["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|message| message.contains("refresh publication")),
        "the refusal must identify current publication validation as the failed authority: {refused}"
    );

    let (transport, stderr) = session.finish();
    assert!(transport.success(), "MCP transport failed: {stderr}");
}

#[test]
fn mcp_supports_current_stateless_discovery_and_tool_results() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join(".git")).expect("git marker");

    let mut child = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root"])
        .arg(&root)
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn current-protocol MCP server");
    let modern_meta = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "h00ligan-contract-test",
            "version": "1.0.0"
        },
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let requests = [
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": modern_meta}
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"_meta": modern_meta}
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "status",
                "arguments": {},
                "_meta": modern_meta
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "not_a_h00ligan_tool",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2099-01-01",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": 20260728,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "path",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }),
    ];
    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("write current-protocol request");
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for MCP server");
    assert!(
        output.status.success(),
        "current-protocol MCP server failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .expect("UTF-8 stdout")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON-RPC response"))
        .collect();
    assert_eq!(responses.len(), 7);

    let expected_identity = serde_json::json!({
        "name": "h00ligan",
        "version": env!("CARGO_PKG_VERSION")
    });
    let discover = &responses[0]["result"];
    assert_eq!(discover["resultType"], "complete");
    assert_eq!(discover["ttlMs"], 0);
    assert_eq!(discover["cacheScope"], "private");
    assert_eq!(discover["supportedVersions"][0], "2026-07-28");
    assert!(discover["capabilities"]["tools"].is_object());
    assert_eq!(
        discover["_meta"]["io.modelcontextprotocol/serverInfo"],
        expected_identity
    );

    let listed = &responses[1]["result"];
    assert_eq!(listed["resultType"], "complete");
    assert_eq!(listed["ttlMs"], 0);
    assert_eq!(listed["cacheScope"], "private");
    assert_eq!(
        listed["tools"].as_array().map(Vec::len),
        Some(EXPECTED_TOOLS.len())
    );
    assert_eq!(
        listed["_meta"]["io.modelcontextprotocol/serverInfo"],
        expected_identity
    );

    let called = &responses[2]["result"];
    assert_eq!(called["resultType"], "complete");
    assert_eq!(
        called["_meta"]["io.modelcontextprotocol/serverInfo"],
        expected_identity
    );
    assert!(called["content"].is_array());
    assert!(called["structuredContent"].is_object());
    assert_eq!(
        called["content"][0]["text"],
        "Full typed h00ligan result is available in structuredContent.",
        "current MCP must carry the full typed result once, not duplicate it as JSON text"
    );

    assert_eq!(responses[3]["error"]["code"], -32602);
    assert!(
        responses[3]["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Unknown tool"))
    );
    assert_eq!(responses[4]["error"]["code"], -32022);
    assert_eq!(responses[4]["error"]["data"]["requested"], "2099-01-01");
    assert!(
        responses[4]["error"]["data"]["supported"]
            .as_array()
            .is_some_and(|versions| versions.iter().any(|version| version == "2026-07-28"))
    );
    assert_eq!(responses[5]["error"]["code"], -32602);
    assert!(
        responses[5]["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("protocol version"))
    );
    assert_eq!(responses[6]["error"]["code"], -32602);
    assert!(
        responses[6]["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Unknown tool: path"))
    );
}

#[test]
fn mcp_latest_legacy_handshake_echoes_version_and_binary_identity() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join(".git")).expect("git marker");

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "h00ligan-contract-test", "version": "1.0.0"}
        }
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root"])
        .arg(&root)
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn legacy MCP server");
    writeln!(child.stdin.as_mut().expect("child stdin"), "{request}")
        .expect("write initialize request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for MCP server");
    assert!(
        output.status.success(),
        "legacy MCP server failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("initialize JSON-RPC response");
    assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(response["result"]["serverInfo"]["name"], "h00ligan");
    assert_eq!(
        response["result"]["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn mcp_watch_lifecycle_publishes_changes_and_stops_idempotently() {
    let temporary = tempfile::tempdir().expect("temporary MCP WATCH fixture");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let source = root.join("src/lib.rs");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"mcp-watch-boundary\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(&source, "pub fn mcp_watch_before() -> u8 { 1 }\n").expect("initial source");

    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command
        .args(["--root"])
        .arg(&root)
        .args(["--data-dir"])
        .arg(&data_dir)
        .arg("mcp-serve");
    let mut session = McpSession::spawn(&mut command);

    let started = session.call(
        "watch",
        serde_json::json!({
            "action": "start",
            "debounce_ms": 25,
            "publication_probe_ms": 10,
            "reconcile_secs": 60
        }),
    );
    assert!(
        started["result"].is_object(),
        "the shipped MCP registry must expose WATCH as a real tool: {started}"
    );
    assert_ne!(
        started["result"]["isError"], true,
        "WATCH start must be admitted: {started}"
    );
    let started = mcp_tool_payload(&started);
    assert_eq!(started["schema_version"], "h00/code-intel/watch/v2");
    assert_eq!(started["action"], "start");
    assert_eq!(started["watch"]["running"], true);

    let duplicate = session.call("watch", serde_json::json!({"action": "start"}));
    assert_eq!(
        duplicate["result"]["isError"], true,
        "a second start must not silently replace the active policy: {duplicate}"
    );

    let first_deadline = Instant::now() + Duration::from_secs(30);
    let first_epoch = loop {
        let response = session.call("watch", serde_json::json!({"action": "status"}));
        assert_ne!(
            response["result"]["isError"], true,
            "WATCH status: {response}"
        );
        let status = mcp_tool_payload(&response);
        if status["watch"]["published_epoch"].as_u64().unwrap_or(0) >= 1 {
            break status["watch"]["published_epoch"]
                .as_u64()
                .expect("published WATCH epoch");
        }
        assert!(
            Instant::now() < first_deadline,
            "initial MCP WATCH generation did not publish: {status}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let initial_generation =
        h00ligan_engine::code_intel_publication::resolve_generation(&data_dir, &root)
            .expect("initial MCP WATCH publication")
            .manifest
            .generation_id;

    std::fs::write(&source, "pub fn mcp_watch_after() -> u8 { 2 }\n").expect("changed source");
    let changed_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let response = session.call("watch", serde_json::json!({"action": "status"}));
        assert_ne!(
            response["result"]["isError"], true,
            "WATCH status: {response}"
        );
        let status = mcp_tool_payload(&response);
        if status["watch"]["published_epoch"].as_u64().unwrap_or(0) > first_epoch {
            break;
        }
        assert!(
            Instant::now() < changed_deadline,
            "changed MCP WATCH generation did not publish: {status}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let changed_generation =
        h00ligan_engine::code_intel_publication::resolve_generation(&data_dir, &root)
            .expect("changed MCP WATCH publication")
            .manifest
            .generation_id;
    assert_ne!(changed_generation, initial_generation);

    let query = session.call(
        "find",
        serde_json::json!({
            "query": "mcp_watch_after",
            "mode": "name",
            "definitions_only": true
        }),
    );
    assert_ne!(
        query["result"]["isError"], true,
        "WATCH query failed: {query}"
    );
    let query = mcp_tool_payload(&query);
    assert!(
        query["items"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["symbol"]["name"] == "mcp_watch_after" || item["name"] == "mcp_watch_after"
            })
        }),
        "same-session query must refresh to the watched generation: {query}"
    );

    let stopped = session.call("watch", serde_json::json!({"action": "stop"}));
    assert_ne!(stopped["result"]["isError"], true, "WATCH stop: {stopped}");
    let stopped = mcp_tool_payload(&stopped);
    assert_eq!(stopped["watch"]["running"], false);
    assert_eq!(stopped["changed"], true);
    assert!(
        stopped["watch"]["publication_probes"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "positive control: native MCP must execute bounded publication probes: {stopped}"
    );
    assert!(
        stopped["watch"]["publication_control_reads"]
            .as_u64()
            .zip(stopped["watch"]["publication_probes"].as_u64())
            .is_some_and(|(reads, probes)| reads > 0 && reads < probes),
        "native MCP heartbeat probes must sparsify validated control reads: {stopped}"
    );
    assert_eq!(
        stopped["watch"]["publication_drifts"], 0,
        "MCP WATCH must not treat its own publications as foreign drift"
    );

    let replay = session.call("watch", serde_json::json!({"action": "stop"}));
    assert_ne!(
        replay["result"]["isError"], true,
        "WATCH stop replay: {replay}"
    );
    let replay = mcp_tool_payload(&replay);
    assert_eq!(replay["watch"]["running"], false);
    assert_eq!(replay["changed"], false);

    let (status, stderr) = session.finish();
    assert!(status.success(), "MCP WATCH shutdown failed: {stderr}");
}

#[test]
fn graph_only_index_publishes_one_immutable_generation_and_not_storage_substrate() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    let git = Command::new("git")
        .args(["init", "-q"])
        .arg(&root)
        .status()
        .expect("run git init");
    assert!(git.success());
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn rust_target() -> u32 { 42 } // cross_language_marker\n",
    )
    .expect("Rust source");
    std::fs::write(
        root.join("main.go"),
        "package fixture\nfunc goReference() { println(\"rust_target cross_language_marker\") }\n",
    )
    .expect("Go source");

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root"])
        .arg(&root)
        .arg("index")
        .output()
        .expect("run graph-only index");
    assert!(
        output.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let graph_dir = root.join(".h00ligan/code-intel");
    let generation = h00ligan_engine::code_intel_publication::resolve_generation(&graph_dir, &root)
        .expect("normal indexing publishes a resolvable immutable generation");
    assert!(generation.database_path.is_file());
    for obsolete in [
        "graph.redb",
        "index.redb",
        "graph-write.lock",
        "reindex.incomplete",
    ] {
        assert!(
            !graph_dir.join(obsolete).exists(),
            "normal indexing must not dual-write obsolete {obsolete}"
        );
    }
    assert!(!root.join(".gitignore").exists());
    let ignored = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["check-ignore", "-q", ".h00ligan/code-intel/publication-v4"])
        .status()
        .expect("check internal ignore");
    assert!(
        ignored.success(),
        "internal .gitignore must hide immutable publication state"
    );

    // F11: once the graph exists, both source-search consumers must work with
    // no host `grep` (or any other PATH command) available. The executable path
    // is absolute; an empty PATH therefore specifically falsifies shell-outs.
    let mut child = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .env("PATH", "")
        .args(["--root"])
        .arg(&root)
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn graph-only MCP with empty PATH");
    let requests = [serde_json::json!({
        "jsonrpc":"2.0", "id":1, "method":"tools/call",
        "params":{"name":"grep_context","arguments":{"pattern":"cross_language_marker"}}
    })];
    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("write request");
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for MCP");
    assert!(
        output.status.success(),
        "empty-PATH MCP failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .expect("UTF-8 stdout")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON-RPC response"))
        .collect();
    assert_eq!(responses.len(), 1);

    let grep_text = responses[0]["result"]["content"][0]["text"]
        .as_str()
        .expect("grep content");
    let grep: serde_json::Value = serde_json::from_str(grep_text).expect("grep JSON");
    let paths: Vec<&str> = grep["results"]
        .as_array()
        .expect("grep results")
        .iter()
        .filter_map(|entry| entry["file_path"].as_str())
        .collect();
    assert!(paths.contains(&"src/lib.rs"), "Rust hit missing: {grep}");
    assert!(paths.contains(&"main.go"), "Go hit missing: {grep}");
}

#[cfg(unix)]
fn path_with_recording_rust_analyzer(temporary: &Path) -> std::ffi::OsString {
    use std::os::unix::fs::PermissionsExt as _;

    let fake_bin = temporary.join("fake-bin");
    std::fs::create_dir_all(&fake_bin).expect("fake executable directory");
    let fake_rust_analyzer = fake_bin.join("rust-analyzer");
    std::fs::write(
        &fake_rust_analyzer,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$H00_SCIP_INVOCATION_LOG\"\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'rust-analyzer 1.97.1-test'\nfi\nexit 0\n",
    )
    .expect("fake rust-analyzer");
    let mut permissions = std::fs::metadata(&fake_rust_analyzer)
        .expect("fake executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_rust_analyzer, permissions).expect("make fake executable");

    let mut search_path = vec![fake_bin];
    search_path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(search_path).expect("joined executable search path")
}

#[cfg(unix)]
fn path_with_slow_rust_analyzer(temporary: &Path) -> std::ffi::OsString {
    use std::os::unix::fs::PermissionsExt as _;

    let fake_bin = temporary.join("slow-provider-bin");
    std::fs::create_dir_all(&fake_bin).expect("slow provider executable directory");
    let fake_rust_analyzer = fake_bin.join("rust-analyzer");
    std::fs::write(
        &fake_rust_analyzer,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$H00_SCIP_INVOCATION_LOG\"\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'rust-analyzer 1.97.1-test'\n  exit 0\nfi\nprintf '%s\\n' \"$$\" > \"$H00_SCIP_PROVIDER_PID\"\nwhile :; do printf x >> \"$H00_SCIP_HEARTBEAT\"; sleep 0.05; done &\nprintf '%s\\n' \"$!\" > \"$H00_SCIP_DESCENDANT_PID\"\nwait\n",
    )
    .expect("slow fake rust-analyzer");
    let mut permissions = std::fs::metadata(&fake_rust_analyzer)
        .expect("slow fake executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_rust_analyzer, permissions).expect("make slow fake executable");

    let mut search_path = vec![fake_bin];
    search_path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(search_path).expect("joined slow-provider search path")
}

#[cfg(unix)]
fn wait_for_nonempty_file(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::fs::metadata(path).map_or(0, |metadata| metadata.len()) == 0 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {label}: {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn wait_for_file_growth(path: &Path, initial_len: u64, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let current_len = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
        if current_len > initial_len {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {label}: {} remained at {current_len} bytes",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn assert_cli_signal_cancels_and_reaps_provider(signal: libc::c_int, signal_name: &str) {
    use std::os::unix::process::ExitStatusExt as _;

    let temporary = tempfile::tempdir().expect("temporary CLI cancellation fixture");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"cli_cancellation\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn cancellation_target() {}\n").expect("source");

    let invocation_log = temporary.path().join("provider-invocations");
    let heartbeat = temporary.path().join("provider-heartbeat");
    let provider_pid_path = temporary.path().join("provider.pid");
    let descendant_pid = temporary.path().join("provider-descendant.pid");
    let child = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--force"])
        .env("PATH", path_with_slow_rust_analyzer(temporary.path()))
        .env("H00_SCIP_INVOCATION_LOG", &invocation_log)
        .env("H00_SCIP_HEARTBEAT", &heartbeat)
        .env("H00_SCIP_PROVIDER_PID", &provider_pid_path)
        .env("H00_SCIP_DESCENDANT_PID", &descendant_pid)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shipped CLI index");

    wait_for_nonempty_file(&heartbeat, "CLI provider heartbeat");
    wait_for_nonempty_file(&provider_pid_path, "CLI provider PID receipt");
    wait_for_nonempty_file(&descendant_pid, "CLI provider descendant PID receipt");
    // SAFETY: `child` is the exact test-owned h00ligan process. The signal is
    // sent to that PID only, never to an ambient process group.
    assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, signal) }, 0);
    let output = child.wait_with_output().expect("wait for interrupted CLI");

    let provider_pid = std::fs::read_to_string(&provider_pid_path)
        .expect("provider PID after CLI exit")
        .trim()
        .parse::<libc::pid_t>()
        .expect("numeric provider PID");
    let bytes_after_exit = std::fs::metadata(&heartbeat)
        .expect("heartbeat after CLI exit")
        .len();
    std::thread::sleep(Duration::from_millis(250));
    let bytes_after_grace = std::fs::metadata(&heartbeat)
        .expect("heartbeat after CLI cancellation grace")
        .len();

    // The unmodified CLI dies by the default signal disposition and leaks the
    // deliberately slow provider group. Always clean that RED control before
    // asserting so this regression can never leave a fixture process behind.
    if bytes_after_grace != bytes_after_exit {
        // SAFETY: the PID is a receipt written by the exact test-owned provider,
        // which the production launcher made leader of its private process group.
        unsafe {
            libc::killpg(provider_pid, libc::SIGKILL);
        }
    }

    assert_eq!(
        output.status.signal(),
        None,
        "the CLI must consume {signal_name} cooperatively instead of dying by default signal disposition"
    );
    assert!(
        !output.status.success(),
        "cancelled indexing must not succeed"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("indexing operation cancelled"),
        "the CLI must report the typed cancellation result: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        bytes_after_grace, bytes_after_exit,
        "CLI cancellation must kill the provider's complete process group"
    );
    assert!(
        h00ligan_engine::code_intel_publication::resolve_generation(&data_dir, &root).is_err(),
        "cancelled private work must not publish a generation"
    );
    assert!(
        std::fs::read_dir(&data_dir)
            .expect("data directory after cancellation")
            .all(|entry| !entry
                .expect("data directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".h00-provider-")),
        "CLI cancellation must reclaim the disposable provider workspace"
    );
    let generations = data_dir.join("publication-v4/generations");
    assert!(
        std::fs::read_dir(&generations)
            .expect("private generation population after cancellation")
            .all(|entry| !entry
                .expect("private generation entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-")),
        "cooperative CLI cancellation must reclaim its private generation staging directory"
    );
}

#[cfg(unix)]
#[test]
fn cli_sigint_cancels_and_reaps_an_active_provider_without_publication() {
    assert_cli_signal_cancels_and_reaps_provider(libc::SIGINT, "SIGINT");
}

#[cfg(unix)]
#[test]
fn cli_sigterm_cancels_and_reaps_an_active_provider_without_publication() {
    assert_cli_signal_cancels_and_reaps_provider(libc::SIGTERM, "SIGTERM");
}

#[cfg(unix)]
#[test]
fn index_defaults_to_structural_indexing_without_invoking_a_scip_provider() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("graph-bundle");
    let invocation_log = temporary.path().join("rust-analyzer-invoked");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"no_scip_init\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn indexed() {}\n").expect("source");

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--format", "json"])
        .env("PATH", path_with_recording_rust_analyzer(temporary.path()))
        .env("H00_SCIP_INVOCATION_LOG", &invocation_log)
        .output()
        .expect("run shipped index with default provider intent");

    assert!(
        output.status.success(),
        "default structural index failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !invocation_log.exists(),
        "default structural index must not even probe a SCIP provider; observed: {}",
        std::fs::read_to_string(&invocation_log).unwrap_or_default()
    );
    assert!(
        !root.join("index.scip").exists(),
        "default structural index must not create a root SCIP artifact"
    );
}

/// RIGHT-REASON FALSIFIER: the ordinary development product intentionally
/// wires only its system Rust and Go provider lanes. Requesting semantic
/// indexing for a valid Python project must therefore report that Python is
/// not configured in this product; it must not invent a provider execution
/// failure for a process that could never have been started.
#[test]
fn development_product_does_not_report_an_absent_python_provider_as_failed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("graph-bundle");
    std::fs::create_dir_all(root.join("src/example")).expect("source directory");
    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"provider-absence\"\nversion = \"0.1.0\"\n",
    )
    .expect("Python project manifest");
    std::fs::write(root.join("src/example/__init__.py"), "").expect("package marker");
    std::fs::write(
        root.join("src/example/service.py"),
        "def target() -> int:\n    return 42\n\ndef caller() -> int:\n    return target()\n",
    )
    .expect("Python source");

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .output()
        .expect("run development product against Python project");

    assert!(
        output.status.success(),
        "best-effort indexing must retain structural truth: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("best-effort index JSON");
    let python = &payload["capabilities"]["calls"]["languages"][0];
    assert_eq!(python["language_id"], "python", "positive language control");
    assert_eq!(python["status"], "unavailable");
    assert_eq!(
        python["gaps"][0]["reason_code"], "provider_not_configured",
        "an absent provider is product configuration evidence, not an execution failure: {payload}"
    );
}

#[cfg(unix)]
#[test]
fn index_scip_invokes_provider_and_reports_a_missing_artifact() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("graph-bundle");
    let invocation_log = temporary.path().join("rust-analyzer-invoked");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"explicit_scip_index\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn indexed() {}\n").expect("source");

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .env("PATH", path_with_recording_rust_analyzer(temporary.path()))
        .env("H00_SCIP_INVOCATION_LOG", &invocation_log)
        .output()
        .expect("run shipped index with explicit SCIP refresh");

    assert!(
        output.status.success(),
        "best-effort SCIP must publish structural authority with an honest provider gap: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let invocations = std::fs::read_to_string(&invocation_log).unwrap_or_default();
    assert!(
        invocations.lines().any(|line| line == "--version"),
        "explicit SCIP must probe the selected provider: {invocations}"
    );
    assert!(
        invocations.lines().any(|line| line.starts_with("scip ")),
        "explicit SCIP must invoke generation: {invocations}"
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("best-effort index JSON");
    assert_eq!(payload["capabilities"]["calls"]["status"], "unavailable");
    assert_eq!(
        payload["capabilities"]["calls"]["languages"][0]["gaps"][0]["reason_code"],
        "provider_failed_or_unavailable"
    );
    let published = h00ligan_engine::code_intel_publication::resolve_generation(&data_dir, &root)
        .expect("best-effort provider failure must publish honest structural authority");

    let strict = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--require-complete-calls"])
        .env("PATH", path_with_recording_rust_analyzer(temporary.path()))
        .env("H00_SCIP_INVOCATION_LOG", &invocation_log)
        .output()
        .expect("run strict shipped index with missing provider artifact");
    assert!(
        !strict.status.success(),
        "strict completeness must reject the same provider gap: stdout={} stderr={}",
        String::from_utf8_lossy(&strict.stdout),
        String::from_utf8_lossy(&strict.stderr)
    );
    assert!(
        String::from_utf8_lossy(&strict.stderr).contains("complete Calls authority"),
        "strict refusal must identify the unsatisfied semantic capability"
    );
    let preserved = h00ligan_engine::code_intel_publication::resolve_generation(&data_dir, &root)
        .expect("strict rejection must preserve the best-effort generation");
    assert_eq!(
        preserved.manifest.generation_id, published.manifest.generation_id,
        "strict rejection must not advance publication"
    );
}

#[cfg(unix)]
#[test]
fn mcp_reindex_provider_intent_is_explicit() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    for (name, arguments, expect_provider, expect_error) in [
        ("structural", serde_json::json!({}), false, false),
        (
            "explicit-scip",
            serde_json::json!({"scip": true}),
            true,
            false,
        ),
        (
            "strict-scip",
            serde_json::json!({"scip": true, "require_complete_calls": true}),
            true,
            true,
        ),
    ] {
        let lane = temporary.path().join(name);
        let root = lane.join("repo");
        let invocation_log = lane.join("rust-analyzer-invoked");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .expect("git init")
                .success()
        );
        std::fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"mcp_reindex_{}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                name.replace('-', "_")
            ),
        )
        .expect("manifest");
        std::fs::write(root.join("src/lib.rs"), "pub fn indexed() {}\n").expect("source");

        let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
        command
            .arg("--root")
            .arg(&root)
            .arg("mcp-serve")
            .env("PATH", path_with_recording_rust_analyzer(&lane))
            .env("H00_SCIP_INVOCATION_LOG", &invocation_log);
        let mut session = McpSession::spawn(&mut command);
        let terminal = start_reindex_and_wait(&mut session, arguments);
        let (status, stderr) = session.finish();
        assert!(status.success(), "{name} MCP transport failed: {stderr}");

        let invocations = std::fs::read_to_string(&invocation_log).unwrap_or_default();
        if expect_provider {
            assert!(
                invocations.lines().any(|line| line == "--version")
                    && invocations.lines().any(|line| line.starts_with("scip ")),
                "explicit MCP SCIP must probe and invoke its provider: {invocations}"
            );
            if expect_error {
                assert_eq!(
                    terminal["state"], "failed",
                    "strict MCP must reject a missing provider artifact: {terminal}"
                );
                assert_eq!(terminal["error"]["kind"], "tool_error");
                assert!(
                    terminal["error"]["message"]
                        .as_str()
                        .is_some_and(|error| error.contains("complete Calls authority"))
                );
            } else {
                assert_ne!(
                    terminal["state"], "failed",
                    "best-effort MCP must publish honest partial authority: {terminal}"
                );
                assert_eq!(
                    terminal["result"]["capabilities"]["calls"]["status"], "unavailable",
                    "best-effort MCP must publish and disclose the provider gap: {terminal}"
                );
            }
        } else {
            assert!(
                invocations.is_empty(),
                "default MCP reindex must remain structural: {invocations}"
            );
            assert_eq!(
                terminal["state"], "succeeded",
                "default structural MCP reindex must publish: {terminal}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn mcp_reindex_lifecycle_is_responsive_owned_cancellable_and_replay_safe() {
    let temporary = tempfile::tempdir().expect("temporary lifecycle fixture");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"mcp_lifecycle\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn last_good_symbol() {}\n")
        .expect("initial source");

    let indexed = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("index")
        .output()
        .expect("publish last-good fixture");
    assert!(
        indexed.status.success(),
        "initial publication failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    let graph_dir = root.join(".h00ligan/code-intel");
    let generation_before =
        h00ligan_engine::code_intel_publication::resolve_generation(&graph_dir, &root)
            .expect("last-good generation");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn last_good_symbol() {}\npub fn pending_symbol() {}\n",
    )
    .expect("stale source");

    let invocation_log = temporary.path().join("provider-invocations");
    let heartbeat = temporary.path().join("provider-heartbeat");
    let provider_pid = temporary.path().join("provider.pid");
    let descendant_pid = temporary.path().join("provider-descendant.pid");
    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command
        .arg("--root")
        .arg(&root)
        .arg("mcp-serve")
        .env("PATH", path_with_slow_rust_analyzer(temporary.path()))
        .env("H00_SCIP_INVOCATION_LOG", &invocation_log)
        .env("H00_SCIP_HEARTBEAT", &heartbeat)
        .env("H00_SCIP_PROVIDER_PID", &provider_pid)
        .env("H00_SCIP_DESCENDANT_PID", &descendant_pid);
    let mut session = McpSession::spawn(&mut command);

    let started_response =
        session.call("reindex", serde_json::json!({"scip": true, "force": true}));
    assert_ne!(started_response["result"]["isError"], true);
    let started = mcp_tool_payload(&started_response);
    assert_eq!(started["state"], "running");
    assert_eq!(started["terminal"], false);
    let operation_id = started["operation_id"]
        .as_str()
        .expect("operation ID")
        .to_owned();

    wait_for_nonempty_file(&heartbeat, "slow provider heartbeat");
    wait_for_nonempty_file(&provider_pid, "provider PID receipt");
    wait_for_nonempty_file(&descendant_pid, "provider descendant PID receipt");

    let old_query = session.call(
        "find",
        serde_json::json!({"query": "last_good_symbol", "definitions_only": true}),
    );
    assert_ne!(
        old_query["result"]["isError"], true,
        "last-good publication must remain queryable while a private generation builds: {old_query}"
    );

    let foreign_cancel = session.call(
        "reindex_cancel",
        serde_json::json!({
            "operation_id": "index-00000000000000000000000000000000-1"
        }),
    );
    assert_eq!(
        foreign_cancel["result"]["isError"], true,
        "a foreign operation ID must have no cancellation authority: {foreign_cancel}"
    );
    let second_writer = session.call("reindex", serde_json::json!({}));
    assert_eq!(
        second_writer["result"]["isError"], true,
        "one process must not admit a second concurrent writer"
    );
    let heartbeat_before = std::fs::metadata(&heartbeat)
        .expect("heartbeat before owned cancellation")
        .len();
    wait_for_file_growth(
        &heartbeat,
        heartbeat_before,
        "active provider progress after rejected foreign/busy controls",
    );

    let cancelled = session.call(
        "reindex_cancel",
        serde_json::json!({"operation_id": operation_id}),
    );
    let cancelled = mcp_tool_payload(&cancelled);
    assert_eq!(cancelled["cancellation"]["accepted"], true);
    let terminal = wait_reindex_terminal(&mut session, &operation_id);
    assert_eq!(terminal["state"], "cancelled", "{terminal}");
    assert_eq!(terminal["terminal"], true);
    assert!(terminal["result"].is_null());

    let bytes_after_cancel = std::fs::metadata(&heartbeat)
        .expect("heartbeat after terminal cancellation")
        .len();
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        std::fs::metadata(&heartbeat)
            .expect("heartbeat after cancellation grace")
            .len(),
        bytes_after_cancel,
        "no provider descendant may keep running after terminal cancellation"
    );
    let generation_after =
        h00ligan_engine::code_intel_publication::resolve_generation(&graph_dir, &root)
            .expect("last-good generation after cancellation");
    assert_eq!(
        generation_after.manifest.generation_id, generation_before.manifest.generation_id,
        "cancelled private work must not replace the last-good head"
    );

    let replay = session.call(
        "reindex_cancel",
        serde_json::json!({"operation_id": operation_id}),
    );
    let replay = mcp_tool_payload(&replay);
    assert_eq!(replay["cancellation"]["accepted"], false);
    assert_eq!(replay["cancellation"]["reason"], "already_terminal");
    std::thread::sleep(Duration::from_millis(20));
    let stable = mcp_tool_payload(&session.call(
        "reindex_status",
        serde_json::json!({"operation_id": operation_id}),
    ));
    assert_eq!(
        stable, terminal,
        "terminal operation receipt must be immutable"
    );

    let (status, stderr) = session.finish();
    assert!(status.success(), "MCP lifecycle server failed: {stderr}");
}

#[cfg(unix)]
#[test]
fn mcp_eof_cancels_and_reaps_an_active_provider_without_publication() {
    let temporary = tempfile::tempdir().expect("temporary shutdown fixture");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"mcp_shutdown\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn shutdown_target() {}\n").expect("source");

    let invocation_log = temporary.path().join("provider-invocations");
    let heartbeat = temporary.path().join("provider-heartbeat");
    let provider_pid = temporary.path().join("provider.pid");
    let descendant_pid = temporary.path().join("provider-descendant.pid");
    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command
        .arg("--root")
        .arg(&root)
        .arg("mcp-serve")
        .env("PATH", path_with_slow_rust_analyzer(temporary.path()))
        .env("H00_SCIP_INVOCATION_LOG", &invocation_log)
        .env("H00_SCIP_HEARTBEAT", &heartbeat)
        .env("H00_SCIP_PROVIDER_PID", &provider_pid)
        .env("H00_SCIP_DESCENDANT_PID", &descendant_pid);
    let mut session = McpSession::spawn(&mut command);
    let started = session.call("reindex", serde_json::json!({"scip": true, "force": true}));
    assert_ne!(started["result"]["isError"], true);
    wait_for_nonempty_file(&heartbeat, "shutdown provider heartbeat");

    let shutdown_started = Instant::now();
    let (status, stderr) = session.finish();
    assert!(status.success(), "MCP shutdown failed: {stderr}");
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(5),
        "EOF shutdown must cancel promptly, not wait for the provider timeout"
    );
    let bytes_after_shutdown = std::fs::metadata(&heartbeat)
        .expect("heartbeat after shutdown")
        .len();
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        std::fs::metadata(&heartbeat)
            .expect("heartbeat after shutdown grace")
            .len(),
        bytes_after_shutdown,
        "EOF shutdown must reap the provider process group"
    );
    assert!(
        h00ligan_engine::code_intel_publication::resolve_generation(
            &root.join(".h00ligan/code-intel"),
            &root,
        )
        .is_err(),
        "shutdown-cancelled private work must not publish a generation"
    );
    let generations = root.join(".h00ligan/code-intel/publication-v4/generations");
    assert!(
        std::fs::read_dir(&generations)
            .expect("MCP private generation population after shutdown")
            .all(|entry| !entry
                .expect("MCP private generation entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-")),
        "cooperative MCP shutdown must reclaim its private generation staging directory"
    );
}

#[cfg(unix)]
#[test]
fn index_default_ignores_a_force_tracked_existing_scip_artifact() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("graph-bundle");
    let invocation_log = temporary.path().join("rust-analyzer-invoked");
    let scip_path = root.join("index.scip");
    let sentinel: &[u8] = &[]; // An empty protobuf is a valid default SCIP Index.

    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"tracked_auto_scip_init\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn indexed() {}\n").expect("source");
    std::fs::write(&scip_path, sentinel).expect("SCIP sentinel");
    assert!(
        Command::new("git")
            .current_dir(&root)
            .args(["add", "-f", "--", "index.scip"])
            .status()
            .expect("force-track SCIP sentinel")
            .success()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--format", "json"])
        .env("PATH", path_with_recording_rust_analyzer(temporary.path()))
        .env("H00_SCIP_INVOCATION_LOG", &invocation_log)
        .output()
        .expect("run shipped structural index with an ambient SCIP artifact");

    assert!(
        output.status.success(),
        "structural index must ignore an ambient SCIP artifact: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !invocation_log.exists(),
        "structural index must not probe or invoke a provider because an artifact exists; observed: {}",
        std::fs::read_to_string(&invocation_log).unwrap_or_default()
    );
    assert_eq!(
        std::fs::read(&scip_path).expect("SCIP sentinel after init"),
        sentinel,
        "structural index must preserve an ambient tracked artifact byte-for-byte"
    );
}

#[cfg(unix)]
#[test]
fn index_scip_ignores_and_preserves_a_project_root_scip_symlink() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("graph-bundle");
    let external_scip = temporary.path().join("external-index.scip");
    let sentinel: &[u8] = &[]; // An empty protobuf is a valid default SCIP Index.

    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"symlinked_refresh_scip_init\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn indexed() {}\n").expect("source");
    std::fs::write(&external_scip, sentinel).expect("external SCIP sentinel");
    std::os::unix::fs::symlink(&external_scip, root.join("index.scip"))
        .expect("symlinked root SCIP input");

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .output()
        .expect("run shipped index with explicit SCIP refresh");

    assert!(
        output.status.success(),
        "project-root SCIP artifacts are not provider inputs or outputs: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&external_scip).expect("external sentinel after refusal"),
        sentinel
    );
    h00ligan_engine::code_intel_publication::resolve_generation(&data_dir, &root)
        .expect("indexing must publish while leaving the unrelated symlink untouched");
}

#[test]
fn index_scip_ignores_and_preserves_a_force_tracked_root_scip_artifact() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("graph-bundle");
    let scip_path = root.join("index.scip");
    let sentinel = b"force-tracked root SCIP sentinel\n";

    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"tracked_scip_init\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn indexed() {}\n").expect("source");
    std::fs::write(&scip_path, sentinel).expect("SCIP sentinel");
    assert!(
        Command::new("git")
            .current_dir(&root)
            .args(["add", "-f", "--", "index.scip"])
            .status()
            .expect("force-track SCIP sentinel")
            .success()
    );
    assert!(
        Command::new("git")
            .current_dir(&root)
            .args(["ls-files", "--error-unmatch", "--", "index.scip"])
            .stdout(Stdio::null())
            .status()
            .expect("verify tracked SCIP sentinel")
            .success(),
        "test precondition: index.scip must be tracked"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .output()
        .expect("run shipped index with explicit SCIP refresh");

    assert!(
        output.status.success(),
        "explicit provider execution must not claim the tracked project-root artifact: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&scip_path).expect("SCIP sentinel after init"),
        sentinel,
        "explicit provider execution must preserve the tracked artifact byte-for-byte"
    );
    h00ligan_engine::code_intel_publication::resolve_generation(&data_dir, &root)
        .expect("indexing must publish beside the unrelated tracked artifact");
}

#[test]
fn explicit_mcp_reindex_refreshes_the_same_server_snapshot_graph_only() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"refresh_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub struct Widget { pub value: u32 }\npub type WidgetValue = u32;\npub fn widget() -> Widget { Widget { value: 7 } }\n",
    )
    .expect("Rust source");

    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command
        .args(["--root"])
        .arg(&root)
        .arg("mcp-serve")
        .env("RUST_LOG", "h00ligan_engine=info");
    let mut session = McpSession::spawn(&mut command);
    let before = mcp_tool_payload(&session.call("status", serde_json::json!({})));
    let terminal = start_reindex_and_wait(&mut session, serde_json::json!({"scip": false}));
    let reindex = terminal["result"].clone();
    let after = mcp_tool_payload(&session.call("status", serde_json::json!({})));
    let type_result =
        mcp_tool_payload(&session.call("type", serde_json::json!({"symbol": "Widget"})));
    let diff_result =
        mcp_tool_payload(&session.call("diff", serde_json::json!({"path": "src/lib.rs"})));
    let (status, stderr) = session.finish();
    assert!(status.success(), "MCP server failed: {stderr}");
    assert!(
        stderr.contains("SCIP analysis disabled"),
        "the framing guard must exercise the real disabled-mode tracing path: {stderr}"
    );
    assert_eq!(before["graph_loaded"], false);
    assert_eq!(reindex["provider_requested"], false);
    assert_eq!(reindex["capability_downgrade_authorized"], false);
    assert_eq!(reindex["index_mode"], "fresh_generation");
    assert!(reindex["generation"]["id"].as_str().is_some());
    assert!(
        reindex["graph"]["nodes_total"]
            .as_u64()
            .is_some_and(|n| n > 0)
    );
    assert_eq!(after["graph_loaded"], true);
    assert_eq!(after["publication_state"], "published");
    assert!(after["stats"]["node_count"].as_u64().is_some_and(|n| n > 0));
    assert_eq!(type_result["schema_version"], "h00/code-intel/type/v2");
    assert_eq!(type_result["resolved_type"]["document_path"], "src/lib.rs");
    assert_eq!(type_result["resolved_type"]["start_line"], 0);
    assert_eq!(diff_result["total_added"], 0, "{diff_result}");
    assert_eq!(diff_result["total_removed"], 0, "{diff_result}");
    assert_eq!(diff_result["total_modified"], 0, "{diff_result}");

    let graph_dir = root.join(".h00ligan/code-intel");
    h00ligan_engine::code_intel_publication::resolve_generation(&graph_dir, &root)
        .expect("MCP publication must resolve as one immutable generation");
    assert!(!graph_dir.join("graph.redb").exists());
    assert!(!graph_dir.join("index.redb").exists());
    assert!(!graph_dir.join("reindex.incomplete").exists());
    assert!(!graph_dir.join("lance").exists());
    assert!(!graph_dir.join("journal.redb").exists());
}

#[test]
fn fresh_publication_ignores_an_obsolete_split_bundle_marker_without_mutating_it() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"recovery_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn recovered() -> bool { true }\n",
    )
    .expect("Rust source");
    let graph_dir = root.join(".h00ligan/code-intel");
    std::fs::create_dir_all(&graph_dir).expect("graph directory");
    std::fs::write(graph_dir.join(".gitignore"), "*\n!.gitignore\n").expect("internal ignore");
    std::fs::write(
        graph_dir.join("reindex.incomplete"),
        b"obsolete split-bundle marker bytes\n",
    )
    .expect("write obsolete marker fixture");
    let legacy_marker =
        std::fs::read(graph_dir.join("reindex.incomplete")).expect("legacy incomplete marker");

    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command.args(["--root"]).arg(&root).arg("mcp-serve");
    let mut session = McpSession::spawn(&mut command);
    let initial_status = mcp_tool_payload(&session.call("status", serde_json::json!({})));
    let blocked_response =
        session.call("grep_context", serde_json::json!({"pattern": "recovered"}));
    let blocked_query = mcp_tool_payload(&blocked_response);
    let terminal = start_reindex_and_wait(&mut session, serde_json::json!({"scip": false}));
    let publication = terminal["result"].clone();
    let final_status = mcp_tool_payload(&session.call("status", serde_json::json!({})));
    let recovered_response =
        session.call("grep_context", serde_json::json!({"pattern": "recovered"}));
    let recovered_query = mcp_tool_payload(&recovered_response);
    let (status, stderr) = session.finish();
    assert!(status.success(), "MCP recovery server failed: {stderr}");
    assert_eq!(initial_status["publication_state"], "unpublished");
    assert_eq!(initial_status["graph_loaded"], false);
    assert_eq!(blocked_response["result"]["isError"], true);
    assert_eq!(blocked_query["error"]["code"], "capability_unavailable");
    assert_eq!(blocked_query["error"]["capability"], "structural_graph");
    assert_eq!(
        blocked_query["error"]["evidence"][0]["reason_code"],
        "immutable_generation_unavailable"
    );
    assert_eq!(publication["index_mode"], "fresh_generation");
    assert_eq!(publication["provider_requested"], false);
    assert!(publication["generation"]["id"].as_str().is_some());
    assert_eq!(final_status["publication_state"], "published");
    assert_eq!(final_status["graph_loaded"], true);
    assert_ne!(recovered_response["result"]["isError"], true);
    assert!(
        recovered_query["matches_returned"]
            .as_u64()
            .is_some_and(|n| n > 0)
    );
    assert_eq!(
        std::fs::read(graph_dir.join("reindex.incomplete"))
            .expect("legacy marker after immutable publication"),
        legacy_marker,
        "the immutable publisher must not claim ownership of obsolete legacy control state"
    );
    h00ligan_engine::code_intel_publication::resolve_generation(&graph_dir, &root)
        .expect("fresh immutable generation resolves despite the obsolete marker");
}

#[test]
fn mcp_keeps_recovery_reachable_but_refuses_foreign_queries_and_strict_writes() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let repo_a = temporary.path().join("repo-a");
    let repo_b = temporary.path().join("repo-b");
    for (root, package, source) in [
        (&repo_a, "origin_a", "pub fn only_in_a() {}\n"),
        (&repo_b, "origin_b", "pub fn only_in_b() {}\n"),
    ] {
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(root)
                .status()
                .expect("git init")
                .success()
        );
        std::fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
        )
        .expect("manifest");
        std::fs::write(root.join("src/lib.rs"), source).expect("Rust source");
    }

    let index = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root"])
        .arg(&repo_a)
        .arg("index")
        .output()
        .expect("index repo A");
    assert!(
        index.status.success(),
        "repo A index failed: {}",
        String::from_utf8_lossy(&index.stderr)
    );
    let foreign_graph = repo_a.join(".h00ligan/code-intel");
    let publication =
        foreign_graph.join(h00ligan_engine::code_intel_publication::PUBLICATION_DIRECTORY);
    let repository_before = std::fs::read(publication.join("repository.json"))
        .expect("foreign repository identity before refusal");
    let heads_before =
        [0, 1].map(|slot| std::fs::read(publication.join(format!("head-{slot}.json"))).ok());

    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command
        .arg("--root")
        .arg(&repo_b)
        .arg("--data-dir")
        .arg(&foreign_graph)
        .arg("mcp-serve");
    let mut session = McpSession::spawn(&mut command);
    let query = session.call("find", serde_json::json!({"query": "only_in_a"}));
    let terminal = start_reindex_and_wait(&mut session, serde_json::json!({}));
    let (status, stderr) = session.finish();

    assert!(
        status.success(),
        "the process must remain available for an explicit recovery request: {stderr}"
    );
    assert_eq!(query["result"]["isError"], true);
    assert_eq!(terminal["state"], "failed");
    let response_errors = query["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let error = format!(
        "{stderr}\n{response_errors}\n{}",
        terminal["error"].as_str().unwrap_or_default()
    );
    let canonical_b = repo_b.canonicalize().expect("canonical repo B");
    assert!(
        error.contains(foreign_graph.to_string_lossy().as_ref())
            && error.contains(canonical_b.to_string_lossy().as_ref())
            && error.contains("repository"),
        "immutable-origin refusal must name the selected root, publication, and stored identity: {error}"
    );
    assert_eq!(
        std::fs::read(publication.join("repository.json"))
            .expect("foreign repository identity after refusal"),
        repository_before
    );
    for (slot, expected) in heads_before.iter().enumerate() {
        assert_eq!(
            std::fs::read(publication.join(format!("head-{slot}.json"))).ok(),
            *expected
        );
    }
    assert!(!repo_b.join(".h00ligan/code-intel/graph.redb").exists());
}

#[test]
fn live_cross_process_immutable_writer_lock_blocks_publication_until_release() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"lock_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn locked() {}\n").expect("source");
    let binding = h00ligan_engine::project_binding::ProjectBinding::resolve(
        h00ligan_engine::project_binding::ProjectBindingOptions::new(&root).explicit_root(&root),
    )
    .expect("resolve managed binding");
    binding
        .prepare_graph_directory_write()
        .expect("admit parent fixture writer");
    let writer = h00ligan_engine::code_intel_publication::SemanticPublisher::acquire(
        binding.graph_dir(),
        binding.root(),
    )
    .expect("parent process holds immutable publisher lock");

    let blocked = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("index")
        .output()
        .expect("run competing writer");
    assert!(!blocked.status.success(), "second writer must be refused");
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("another semantic publisher"),
        "writer refusal should name the live lock: {}",
        String::from_utf8_lossy(&blocked.stderr)
    );

    drop(writer);
    assert!(!binding.graph_dir().join("reindex.incomplete").exists());
    let published = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("index")
        .output()
        .expect("run publication after lock release");
    assert!(
        published.status.success(),
        "publication should enter after release: {}",
        String::from_utf8_lossy(&published.stderr)
    );
    h00ligan_engine::code_intel_publication::resolve_generation(
        binding.graph_dir(),
        binding.root(),
    )
    .expect("post-release publication resolves");
    assert!(!binding.graph_dir().join("reindex.incomplete").exists());
}

#[test]
fn cli_json_and_mcp_diff_share_one_bounded_result_contract() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"diff_parity\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn retained() {}\n\npub fn removed() {}\n\npub fn changed() -> u32 { 1 }\n",
    )
    .expect("original source");
    let index = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("index")
        .output()
        .expect("index diff fixture");
    assert!(
        index.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&index.stderr)
    );
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn retained() {}\n\npub fn changed() -> u32 { 2 }\n\npub fn added() {}\n",
    )
    .expect("changed source");

    let cli = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .args(["diff", "--format", "json", "--limit", "50"])
        .output()
        .expect("CLI diff");
    assert!(
        cli.status.success(),
        "CLI diff failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_result: serde_json::Value = serde_json::from_slice(&cli.stdout).expect("CLI diff JSON");

    let mut mcp = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn MCP diff server");
    writeln!(
        mcp.stdin.as_mut().expect("MCP stdin"),
        "{}",
        serde_json::json!({
            "jsonrpc":"2.0", "id":1, "method":"tools/call",
            "params":{"name":"diff","arguments":{"limit":50}}
        })
    )
    .expect("write MCP diff request");
    drop(mcp.stdin.take());
    let mcp_output = mcp.wait_with_output().expect("wait for MCP diff");
    assert!(
        mcp_output.status.success(),
        "MCP diff failed: {}",
        String::from_utf8_lossy(&mcp_output.stderr)
    );
    let outer: serde_json::Value =
        serde_json::from_slice(&mcp_output.stdout).expect("MCP JSON-RPC response");
    assert_ne!(outer["result"]["isError"], true, "{outer}");
    let mcp_result: serde_json::Value = serde_json::from_str(
        outer["result"]["content"][0]["text"]
            .as_str()
            .expect("MCP diff result text"),
    )
    .expect("MCP inner diff JSON");

    assert_eq!(cli_result, mcp_result);
    assert!(
        outer["result"].get("structuredContent").is_none(),
        "legacy MCP must carry the full typed value once in JSON text: {outer}"
    );
    assert_eq!(cli_result["schema_version"], "h00/code-intel/diff/v1");
    assert!(
        cli_result["generation_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "diff must identify its immutable baseline generation: {cli_result}"
    );
    assert!(cli_result["repository"].is_object(), "{cli_result}");
    assert_eq!(cli_result["query"]["path"], ".", "{cli_result}");
    assert_eq!(
        cli_result["authority"]["candidate"]["consistency"], "per_file_read_non_atomic",
        "repository-wide live source is not an atomic filesystem snapshot: {cli_result}"
    );
    assert_eq!(cli_result["verdict"], "symbol_differences_observed");
    assert_eq!(cli_result["total_added"], 1, "{cli_result}");
    assert_eq!(cli_result["total_removed"], 1, "{cli_result}");
    assert_eq!(cli_result["total_modified"], 1, "{cli_result}");
    assert_eq!(cli_result["changes_total"], 3, "{cli_result}");
    assert_eq!(cli_result["changes_returned"], 3, "{cli_result}");
    assert_eq!(cli_result["files_with_symbol_changes"], 1, "{cli_result}");
    assert_eq!(
        cli_result["files"][0]["removed"][0]["line"], 3,
        "removed symbol line must survive both adapters: {cli_result}"
    );
}

#[test]
fn tracked_obsolete_graph_output_is_preserved_and_not_part_of_immutable_indexing() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let tracked_path = ".h00ligan/code-intel/graph.redb";
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::create_dir_all(root.join(".h00ligan/code-intel")).expect("graph directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"tracked_graph\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn untouched() {}\n").expect("source");
    std::fs::write(
        root.join(".h00ligan/code-intel/.gitignore"),
        "*\n!.gitignore\n",
    )
    .expect("internal ignore");
    let sentinel = b"tracked graph sentinel bytes\n";
    std::fs::write(root.join(tracked_path), sentinel).expect("tracked generated artifact");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["add", "-f", "--", tracked_path])
            .status()
            .expect("stage generated artifact in scratch repo")
            .success()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("index")
        .output()
        .expect("run guarded index");
    assert!(
        output.status.success(),
        "an obsolete artifact the immutable writer never touches must not block indexing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(root.join(tracked_path)).expect("sentinel after refusal"),
        sentinel
    );
    h00ligan_engine::code_intel_publication::resolve_generation(
        &root.join(".h00ligan/code-intel"),
        &root,
    )
    .expect("immutable generation must publish beside the preserved obsolete file");
    assert!(
        !root
            .join(".h00ligan/code-intel/reindex.incomplete")
            .exists()
    );
}

#[test]
fn explicit_refresh_preserves_a_tracked_root_scip_artifact_and_publishes() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("graph-bundle");
    let scip_path = root.join("index.scip");
    let sentinel = b"tracked SCIP output sentinel bytes\n";
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"tracked_refresh_scip\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn untouched() {}\n").expect("source");
    std::fs::write(&scip_path, sentinel).expect("tracked SCIP artifact");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["add", "-f", "--", "index.scip"])
            .status()
            .expect("stage tracked SCIP artifact")
            .success()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .output()
        .expect("run explicit SCIP refresh");
    assert!(
        output.status.success(),
        "provider refresh must use its external workspace: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&scip_path).expect("SCIP sentinel after refusal"),
        sentinel
    );
    h00ligan_engine::code_intel_publication::resolve_generation(&data_dir, &root)
        .expect("refresh must publish beside the preserved tracked artifact");
}

/// The shipped MCP reindex path must share the same external provider-workspace
/// policy as the CLI. A tracked conventional artifact name in the project is
/// unrelated user data and must remain byte-identical.
#[test]
fn mcp_reindex_preserves_tracked_secondary_scip_across_best_effort_and_strict_failure() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"tracked_go_scip\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn untouched() {}\n").expect("source");
    let sentinel = b"tracked secondary SCIP sentinel\n";
    std::fs::write(root.join("index.go.scip"), sentinel).expect("secondary SCIP");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["add", "-f", "--", "index.go.scip"])
            .status()
            .expect("git add")
            .success()
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command
        .arg("--root")
        .arg(&root)
        .arg("mcp-serve")
        // Keep Git available but make optional providers unavailable so this
        // test measures artifact ownership rather than provider installation.
        .env("PATH", "/usr/bin:/bin");
    let mut session = McpSession::spawn(&mut command);
    let best_effort = start_reindex_and_wait(&mut session, serde_json::json!({"scip": true}));
    let strict = start_reindex_and_wait(
        &mut session,
        serde_json::json!({
            "scip": true,
            "require_complete_calls": true,
        }),
    );
    let (status, stderr) = session.finish();
    assert!(status.success(), "MCP transport failed: {stderr}");
    assert_eq!(
        best_effort["state"], "succeeded",
        "best-effort semantic refresh must publish honest structural authority: {best_effort}"
    );
    assert_eq!(
        best_effort["result"]["capabilities"]["calls"]["status"], "unavailable",
        "best-effort semantic refresh must disclose provider absence: {best_effort}"
    );
    assert_eq!(
        std::fs::read(root.join("index.go.scip")).expect("sentinel after refusal"),
        sentinel
    );
    let graph_dir = root.join(".h00ligan/code-intel");
    let published = h00ligan_engine::code_intel_publication::resolve_generation(&graph_dir, &root)
        .expect("best-effort MCP semantic refresh must publish a head");
    assert_eq!(
        strict["state"], "failed",
        "strict semantic refresh must reject provider absence: {strict}"
    );
    let preserved = h00ligan_engine::code_intel_publication::resolve_generation(&graph_dir, &root)
        .expect("strict rejection must preserve the best-effort head");
    assert_eq!(
        preserved.manifest.generation_id, published.manifest.generation_id,
        "strict rejection must not advance publication"
    );
}

/// A tracked legacy recovery marker is outside the immutable publisher's
/// namespace. It must neither block nor be deleted by a fresh publication.
#[test]
fn mcp_reindex_preserves_a_tracked_obsolete_legacy_marker() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let graph_dir = root.join(".h00ligan/code-intel");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::create_dir_all(&graph_dir).expect("graph directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"tracked_marker\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "pub fn untouched() {}\n").expect("source");
    std::fs::write(graph_dir.join(".gitignore"), "*\n!.gitignore\n").expect("internal ignore");
    let marker = b"tracked recovery marker\n";
    std::fs::write(graph_dir.join("reindex.incomplete"), marker).expect("marker");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["add", "-f", "--", ".h00ligan/code-intel/reindex.incomplete"])
            .status()
            .expect("git add marker")
            .success()
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_h00ligan"));
    command.arg("--root").arg(&root).arg("mcp-serve");
    let mut session = McpSession::spawn(&mut command);
    let terminal = start_reindex_and_wait(&mut session, serde_json::json!({"scip": false}));
    let publication = terminal["result"].clone();
    let publication_status = mcp_tool_payload(&session.call("status", serde_json::json!({})));
    let (status, stderr) = session.finish();
    assert!(status.success(), "MCP transport failed: {stderr}");
    assert_eq!(publication["index_mode"], "fresh_generation");
    assert_eq!(publication_status["publication_state"], "published");
    assert_eq!(publication_status["graph_loaded"], true);
    assert_eq!(
        std::fs::read(graph_dir.join("reindex.incomplete")).expect("marker after publication"),
        marker
    );
    assert!(!graph_dir.join("graph.redb").exists());
    assert!(!graph_dir.join("index.redb").exists());
    h00ligan_engine::code_intel_publication::resolve_generation(&graph_dir, &root)
        .expect("immutable generation resolves beside tracked legacy marker");
}
