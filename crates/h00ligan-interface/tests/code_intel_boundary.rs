#![cfg(all(feature = "code-intel", feature = "mcp"))]

use h00ligan_engine::project_binding::ProjectBinding;
use h00ligan_interface::mcp::{CodeIntelMcp, McpToolDispatcher};
use h00ligan_interface::{CodeIntelContext, CodeIntelRegistry, ToolError};
use tokio_util::sync::CancellationToken;

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

fn unindexed_dispatcher() -> (tempfile::TempDir, CodeIntelMcp) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let graph_dir = temporary.path().join("graph");
    std::fs::create_dir_all(&root).expect("create root");
    std::fs::create_dir_all(&graph_dir).expect("create graph directory");
    let binding = ProjectBinding::explicit(&root, &graph_dir).expect("explicit binding");
    let dispatcher = CodeIntelMcp::new(
        CodeIntelRegistry::default(),
        CodeIntelContext::unloaded(binding, CancellationToken::new()),
    );
    (temporary, dispatcher)
}

#[test]
fn lean_context_and_registry_are_store_free_and_exact() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let graph_dir = temporary.path().join("graph");
    std::fs::create_dir_all(&root).expect("create root");
    std::fs::create_dir_all(&graph_dir).expect("create graph directory");

    let binding = ProjectBinding::explicit(&root, &graph_dir).expect("explicit binding");
    let context = CodeIntelContext::unloaded(binding, CancellationToken::new());

    assert!(context.snapshot().graph.is_none());
    let registry = CodeIntelRegistry::default();
    let names: Vec<&str> = registry
        .definitions()
        .iter()
        .map(|definition| definition.name.as_str())
        .collect();
    assert_eq!(names, EXPECTED_TOOLS);
    assert_eq!(registry.handler_names(), EXPECTED_TOOLS);
}

#[tokio::test]
async fn mcp_dispatch_refuses_non_object_tool_arguments() {
    let (_temporary, dispatcher) = unindexed_dispatcher();

    let error = dispatcher
        .execute("status", serde_json::json!([]))
        .await
        .expect_err("non-object arguments must not reach a defaulting handler");

    assert!(matches!(error, ToolError::InvalidInput(_)));
}

#[tokio::test]
async fn mcp_dispatch_rejects_invalid_immutable_publication() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("repo");
    let graph_dir = temporary.path().join("graph");
    std::fs::create_dir_all(&root).expect("create root");
    std::fs::create_dir_all(&graph_dir).expect("create graph directory");
    std::fs::create_dir(
        graph_dir.join(h00ligan_engine::code_intel_publication::PUBLICATION_DIRECTORY),
    )
    .expect("create incomplete immutable publication directory");

    let binding = ProjectBinding::explicit(&root, &graph_dir).expect("explicit binding");
    let dispatcher = CodeIntelMcp::new(
        CodeIntelRegistry::default(),
        CodeIntelContext::unloaded(binding, CancellationToken::new()),
    );

    let error = dispatcher
        .execute("calls", serde_json::json!({"symbol": "target"}))
        .await
        .expect_err("an invalid immutable publication must be refused");

    assert!(
        matches!(&error, ToolError::ExecutionFailed(message) if message.contains("semantic publication")),
        "unexpected invalid-publication error: {error}"
    );
}

#[tokio::test]
async fn mcp_dispatch_enforces_the_advertised_tool_schema() {
    let (_temporary, dispatcher) = unindexed_dispatcher();

    let wrong_type = dispatcher
        .execute(
            "find",
            serde_json::json!({"query": "target", "limit": "twenty"}),
        )
        .await
        .expect_err("a string must not satisfy the advertised integer schema");
    assert!(
        matches!(&wrong_type, ToolError::InvalidInput(message) if message.contains("limit") && message.contains("integer")),
        "unexpected type error: {wrong_type}"
    );

    let extra_property = dispatcher
        .execute(
            "find",
            serde_json::json!({
                "query": "target",
                "unadvertised": true
            }),
        )
        .await
        .expect_err("additionalProperties=false must be enforced at dispatch");
    assert!(
        matches!(&extra_property, ToolError::InvalidInput(message) if message.contains("unadvertised")),
        "unexpected additional-property error: {extra_property}"
    );

    let zero_read_limit = dispatcher
        .execute("read", serde_json::json!({"symbol": "target", "limit": 0}))
        .await
        .expect_err("Read's advertised positive page bound must be enforced before execution");
    assert!(
        matches!(&zero_read_limit, ToolError::InvalidInput(message) if message.contains("limit") && message.contains("minimum")),
        "unexpected Read bound error: {zero_read_limit}"
    );

    let extra_read_property = dispatcher
        .execute(
            "read",
            serde_json::json!({"symbol": "target", "unadvertised": true}),
        )
        .await
        .expect_err("Read must reject properties outside its advertised contract");
    assert!(
        matches!(&extra_read_property, ToolError::InvalidInput(message) if message.contains("unadvertised")),
        "unexpected Read property error: {extra_read_property}"
    );
}

#[tokio::test]
async fn mcp_dispatch_refuses_every_project_switch_alias() {
    let (_temporary, dispatcher) = unindexed_dispatcher();

    for forbidden in ["root", "workspace", "project", "data_dir", "graph_dir"] {
        let mut input = serde_json::Map::new();
        input.insert(
            forbidden.to_owned(),
            serde_json::Value::String("/tmp/other-project".into()),
        );
        let error = dispatcher
            .execute("status", serde_json::Value::Object(input))
            .await
            .expect_err("a project-switch alias must not be silently ignored by MCP");

        assert!(
            matches!(&error, ToolError::InvalidInput(message) if message.contains(forbidden) && message.contains("one project")),
            "unexpected project-switch error for {forbidden}: {error}"
        );
    }
}
