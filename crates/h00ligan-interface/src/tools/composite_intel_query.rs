//! Composite code intelligence MCP tool handlers: `status`, `find`, `deps`,
//! `diff`, `grep_context`.
//!
//! Each handler composes existing engine functions into a single tool call.
//! No graph logic is duplicated — all heavy lifting delegates to
//! `h00ligan_engine` types.

use serde_json::{Value, json};

use h00ligan_engine::code_intel_diff::{
    DEFAULT_DIFF_LIMIT, DiffRequest, MAX_DIFF_LIMIT, validate_diff_request,
};
use h00ligan_engine::code_intel_find::{
    DEFAULT_FIND_PAGE_SIZE, FindMode, FindRequest, MAX_FIND_CURSOR_BYTES, MAX_FIND_KIND_BYTES,
    MAX_FIND_PAGE_SIZE, MAX_FIND_QUERY_BYTES,
};
use h00ligan_engine::code_intel_source_search::{
    DEFAULT_SOURCE_SEARCH_LIMIT, MAX_SOURCE_SEARCH_CONTEXT_LINES, MAX_SOURCE_SEARCH_LIMIT,
    SourceSearchRequest, validate_source_search_request,
};

use super::code_intel::{code_intel_domain_error, optional_usize};
use crate::tool_api::{CodeIntelAccess, CodeIntelHandler};
use crate::{CodeIntelContext, ToolDefinition, ToolError};

// ============================================================================
// StatusHandler
// ============================================================================

/// MCP tool: graph health check.
pub struct StatusHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for StatusHandler {
    async fn execute(&self, _input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }
        serde_json::to_value(
            ctx.status_snapshot()
                .await
                .status_result(ctx.binding())
                .await,
        )
        .map_err(|error| ToolError::ExecutionFailed(format!("serialize Status result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Status
    }

    fn name(&self) -> &str {
        "status"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "status".into(),
            description: "Quick health check of the code intelligence graph. Reports publication \
                availability, exact source/project-input freshness, per-language capability \
                coverage, graph statistics, reachability, and any required action."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": [],
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// FindHandler
// ============================================================================

/// MCP tool: unified symbol search.
pub struct FindHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for FindHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let snapshot = ctx.snapshot();

        let query = input
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing required field: query".into()))?;

        let definitions_only = input
            .get("definitions_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let kind = input
            .get("kind")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'kind' must be a string".into()))
            })
            .transpose()?;
        let mode = match input.get("mode").and_then(Value::as_str).unwrap_or("auto") {
            "auto" => FindMode::Auto,
            "name" => FindMode::Name,
            "path" => FindMode::Path,
            value => {
                return Err(ToolError::InvalidInput(format!(
                    "'mode' must be auto, name, or path (received {value:?})"
                )));
            }
        };
        let request = FindRequest {
            query: query.into(),
            mode,
            kind,
            definitions_only,
            limit: optional_usize(&input, "limit", DEFAULT_FIND_PAGE_SIZE)?,
            cursor: input
                .get("cursor")
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| ToolError::InvalidInput("'cursor' must be a string".into()))
                })
                .transpose()?,
        };
        serde_json::to_value(
            snapshot
                .query_find(ctx.binding(), &request)
                .await
                .map_err(code_intel_domain_error)?,
        )
        .map_err(|error| ToolError::ExecutionFailed(format!("serialize Find result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "find"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "find".into(),
            description: "Find symbols in one immutable structural generation by name, glob, \
                exact file, or directory. Mode defaults to auto and may be forced to name or path \
                exactly as on the CLI. Returns explicit structural authority and deterministic \
                cursor pages. Every result carries an exact repository- and generation-bound \
                symbol_id accepted by Type, Read, Calls, Assess, Inspect, Dead, and Tests; \
                semantic liveness belongs to dead_code and Calls-aware tools. \
                Check repository.live_inputs before applying generation evidence to the current \
                worktree; stale and unknown observations are explicitly qualified. \
                Follow page.next_cursor while page.has_more is true."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_FIND_QUERY_BYTES,
                        "description": "Symbol name, glob pattern (e.g. *Handler), or file path."
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["auto", "name", "path"],
                        "description": "Interpretation mode. auto detects path-shaped queries; name and path force an exact mode."
                    },
                    "kind": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_FIND_KIND_BYTES,
                        "description": "Case-insensitive structural kind filter. Values are provider vocabulary, not a closed language-specific enum."
                    },
                    "definitions_only": {
                        "type": "boolean",
                        "description": "When true, exclude `use` statements so only definitions are returned. Default: false."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_FIND_PAGE_SIZE,
                        "description": "Maximum structural matches in this page (default 20, max 100)."
                    },
                    "cursor": {
                        "type": "string",
                        "maxLength": MAX_FIND_CURSOR_BYTES,
                        "description": "Continuation from page.next_cursor; bound to the exact generation and normalized Find query."
                    }
                },
                "required": ["query"],
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// DepsHandler — Dependency Analysis
// ============================================================================

/// MCP tool: dependency analysis for a file or directory.
pub struct DepsHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for DepsHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let path = input
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing required field: path".into()))?;
        h00ligan_engine::code_intel_dependencies::validate_dependencies_path(ctx.binding(), path)
            .map_err(code_intel_domain_error)?;
        let mut request = h00ligan_engine::code_intel_dependencies::DependenciesRequest::new(path);
        request.limit = optional_usize(&input, "limit", request.limit)?;
        request.limit =
            h00ligan_engine::code_intel_dependencies::validate_dependencies_limit(request.limit)
                .map_err(code_intel_domain_error)?;
        request.cursor = input
            .get("cursor")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'cursor' must be a string".into()))
            })
            .transpose()?;

        let snapshot = ctx.snapshot();
        let result = snapshot
            .query_dependencies(ctx.binding(), &request)
            .await
            .map_err(code_intel_domain_error)?;
        serde_json::to_value(result).map_err(|error| {
            ToolError::ExecutionFailed(format!("serialize Dependencies result: {error}"))
        })
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "deps"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "deps".into(),
            description: "Direct repository-local dependencies crossing one indexed file or \
                directory boundary. Separates files the scope depends on from files that depend on \
                the scope, normalizes graph navigation indexes into forward semantic kinds, reports \
                structural, Calls, and project-dependency authority independently, and returns \
                deterministic cursor-paged per-file summaries. Check repository.live_inputs \
                before applying generation evidence to the current worktree. Follow \
                page.next_cursor while page.has_more is true."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Indexed file or directory boundary. Directory queries \
                            exclude edges whose endpoints are both inside the selection."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_dependencies::MAX_DEPENDENCIES_PAGE_SIZE,
                        "description": "Maximum related files in this page (default 50)."
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Opaque continuation cursor returned by an earlier Dependencies page."
                    }
                },
                "required": ["path"],
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// DiffHandler — Symbol-Level Change Detection
// ============================================================================

/// MCP tool: symbol-level diff between graph snapshot and current source.
pub struct DiffHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for DiffHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let path = input
            .get("path")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'path' must be a string".into()))
            })
            .transpose()?;
        let request = DiffRequest {
            path,
            limit: optional_usize(&input, "limit", DEFAULT_DIFF_LIMIT)?,
        };
        validate_diff_request(&request).map_err(code_intel_domain_error)?;

        let snapshot = ctx.snapshot();
        let result = snapshot
            .query_diff(ctx.binding(), &request)
            .await
            .map_err(code_intel_domain_error)?;

        serde_json::to_value(result)
            .map_err(|error| ToolError::ExecutionFailed(format!("serialize diff result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "diff"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "diff".into(),
            description: "Bounded symbol-level diff between the pinned immutable structural \
                generation and live worktree source. Reports baseline authority, the non-atomic \
                per-file candidate-read boundary, and added/removed/modified symbols. An empty \
                observation is `unknown` rather than `no_symbol_differences` when structural coverage \
                is incomplete. Omit path for the registered repository source population."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to diff (relative to workspace root). Omit to diff \
                            the entire workspace."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_DIFF_LIMIT,
                        "description": "Maximum changed symbols returned (default 50; range 1-100)."
                    }
                },
                "required": [],
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// GrepContextHandler — Live Source Search with Generation-Bound Context
// ============================================================================

/// MCP tool: search live source with generation-bound structural context.
pub struct GrepContextHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for GrepContextHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let pattern = input
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing required field: pattern".into()))?
            .to_string();

        let search_path = input.get("path").and_then(|v| v.as_str()).map(String::from);
        let limit = optional_usize(&input, "limit", DEFAULT_SOURCE_SEARCH_LIMIT)?;
        let context_lines = optional_usize(&input, "context_lines", 0)?;

        let request = SourceSearchRequest {
            pattern,
            path: search_path.unwrap_or_else(|| ".".into()),
            context_lines,
            limit,
        };
        validate_source_search_request(&request).map_err(code_intel_domain_error)?;
        let snapshot = ctx.snapshot();
        let result = snapshot
            .query_source_search(ctx.binding(), &request)
            .await
            .map_err(code_intel_domain_error)?;
        serde_json::to_value(result).map_err(|error| {
            ToolError::ExecutionFailed(format!("serialize source-search result: {error}"))
        })
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "grep_context"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "grep_context".into(),
            description: "Bounded regex search over the live, ignore-aware registered-source \
                worktree. Indexed symbol context is attached only when the searched file bytes \
                exactly match the pinned generation; every result reports that context status."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Regex pattern to search for."
                    },
                    "path": {
                        "type": "string",
                        "description": "File path or directory to search in (relative to workspace root). \
                            Omit to search the entire workspace."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_SOURCE_SEARCH_LIMIT,
                        "description": "Maximum matches to return (default 50, max 100)."
                    },
                    "context_lines": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAX_SOURCE_SEARCH_CONTEXT_LINES,
                        "description": "Context lines before and after each match (default 0, max 10)."
                    }
                },
                "required": ["pattern"],
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn status_reports_origin_mismatch_as_availability_not_load_failure() {
        let temporary = tempfile::tempdir().expect("temporary project");
        let root = temporary.path().join("repo");
        let foreign = temporary.path().join("foreign");
        let graph_dir = temporary.path().join("graph");
        std::fs::create_dir_all(&root).expect("project root");
        std::fs::create_dir_all(&foreign).expect("foreign root");
        std::fs::create_dir_all(&graph_dir).expect("graph directory");
        let binding = h00ligan_engine::project_binding::ProjectBinding::explicit(&root, &graph_dir)
            .expect("project binding");
        let mut snapshot = crate::CodeIntelSnapshot::unindexed();
        snapshot.load_state = crate::GraphLoadState::OriginMismatch {
            stored: foreign,
            bound: root,
        };
        let context = crate::CodeIntelContext::from_test_snapshot(
            binding,
            tokio_util::sync::CancellationToken::new(),
            std::sync::Arc::new(snapshot),
        );

        let result =
            serde_json::to_value(context.snapshot().status_result(context.binding()).await)
                .expect("status result");
        assert_eq!(result["availability"], "origin_mismatch", "{result}");
        assert_eq!(result["freshness"], "not_evaluated", "{result}");
        assert!(result.get("origin_mismatch").is_some(), "{result}");
    }

    #[tokio::test]
    async fn diff_handler_preserves_removed_symbol_line_from_shared_contract() {
        use h00ligan_engine::edge_builder::build_graph;
        use h00ligan_engine::extractor::extract_file;
        use h00ligan_engine::graph::KnowledgeGraph;

        let temporary = tempfile::tempdir().expect("temporary project");
        let relative = "src/lib.rs";
        let source_path = temporary.path().join(relative);
        std::fs::create_dir_all(source_path.parent().unwrap()).expect("source directory");
        std::fs::write(
            &source_path,
            "pub fn retained() {}\n\npub fn removed() {}\n",
        )
        .expect("original source");
        let extracted = extract_file(&source_path, temporary.path()).expect("extract source");
        let mut graph = KnowledgeGraph::new();
        build_graph(&[extracted], &mut graph).expect("build graph");
        let context =
            crate::tools::test_published_code_intel_context(temporary.path(), graph).await;
        std::fs::write(&source_path, "pub fn retained() {}\n").expect("remove symbol");

        let result = DiffHandler
            .execute(json!({"path": relative}), &context)
            .await
            .expect("diff handler");
        let removed = result["files"][0]["removed"]
            .as_array()
            .unwrap_or_else(|| panic!("removed symbols missing: {result}"));
        assert_eq!(removed.len(), 1, "{result}");
        assert_eq!(
            removed[0]["line"], 3,
            "MCP must preserve the same removed-symbol line emitted by CLI/engine: {result}"
        );
    }

    #[test]
    fn diff_definition_exposes_the_same_closed_bounds_as_the_engine() {
        let definition = DiffHandler.definition();
        assert_eq!(definition.input_schema["properties"]["limit"]["minimum"], 1);
        assert_eq!(
            definition.input_schema["properties"]["limit"]["maximum"],
            MAX_DIFF_LIMIT
        );
        assert_eq!(
            definition.input_schema["additionalProperties"],
            json!(false)
        );
    }

    #[test]
    fn deps_definition_has_no_unbounded_detail_escape_hatch() {
        let handler = DepsHandler;
        let definition = handler.definition();
        let properties = definition.input_schema["properties"]
            .as_object()
            .expect("deps properties");
        assert!(
            properties.contains_key("path"),
            "known-positive deps path property must remain"
        );
        assert!(
            !properties.contains_key("detail"),
            "unbounded legacy detail property must not be advertised"
        );
        assert_eq!(
            definition.input_schema["additionalProperties"],
            json!(false)
        );
    }
}
