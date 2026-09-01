//! Composite code intelligence tool handlers: `assess`, `inspect`, `dead_code`,
//! `tests`, `overview`, `audit`, `init`.
//!
//! Each handler composes multiple engine queries into a single MCP tool call.
//! All graph traversal uses shared engine functions from `h00ligan_engine::graph_query`
//! — no duplicate BFS logic.
//!
//! This module is gated by `#[cfg(feature = "code-intel")]` at the declaration
//! site in `mod.rs`; no additional per-item gates are needed.

use serde_json::{Value, json};
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
use h00ligan_engine::graph::KnowledgeGraph;
#[cfg(test)]
use h00ligan_engine::graph::{EdgeKind, GraphNode};
#[cfg(test)]
use h00ligan_engine::graph_query::reverse_bfs;
// WU-0016 / ADR-0039: `ReachabilityClass` is now referenced only from tests
// (the production action-tier map + inspect warnings moved to shared engine fns).
#[cfg(test)]
use h00ligan_engine::reachability::ReachabilityClass;

use super::code_intel::{code_intel_domain_error, optional_usize};
use crate::tool_api::{CodeIntelAccess, CodeIntelHandler};
use crate::{CodeIntelContext, ToolDefinition, ToolError};

// ============================================================================
// Shared helpers
// ============================================================================

// WU-0016 / ADR-0039 RC-B6: `classify_dead_reason` (FIX-16) was promoted to
// `h00ligan_engine::graph_query` so the CLI and MCP `dead` renderers share ONE
// implementation (closing the CLI≡MCP parity gap); the local copy was removed.

// ============================================================================
// AssessHandler — Change Impact Analysis
// ============================================================================

/// Authority-qualified change impact over one immutable generation. This is a
/// thin transport adapter; traversal, authority, paging, and review-signal
/// semantics live in `h00ligan-engine`.
pub struct AssessHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for AssessHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }
        let symbol = input
            .get("symbol")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::InvalidInput("missing required field: symbol".into()))?;
        let mut request = h00ligan_engine::code_intel_assess::AssessRequest::new(symbol);
        request.file = input
            .get("file")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'file' must be a string".into()))
            })
            .transpose()?;
        request.max_depth = optional_usize(&input, "depth", request.max_depth)?;
        request.limit = optional_usize(&input, "limit", request.limit)?;
        request.cursor = input
            .get("cursor")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'cursor' must be a string".into()))
            })
            .transpose()?;
        if let Some(filter) = input.get("filter") {
            let filter = filter
                .as_str()
                .ok_or_else(|| ToolError::InvalidInput("'filter' must be a string".into()))?;
            request.filter = h00ligan_engine::code_intel_assess::parse_assess_filter(filter)
                .map_err(code_intel_domain_error)?;
        }
        if let Some(sections) = input.get("sections") {
            let sections = sections
                .as_array()
                .ok_or_else(|| ToolError::InvalidInput("'sections' must be an array".into()))?;
            request.sections = sections
                .iter()
                .map(|value| {
                    let section = value.as_str().ok_or_else(|| {
                        ToolError::InvalidInput("every 'sections' item must be a string".into())
                    })?;
                    h00ligan_engine::code_intel_assess::parse_assess_section(section)
                        .map_err(code_intel_domain_error)
                })
                .collect::<Result<_, _>>()?;
        }

        let snapshot = ctx.snapshot();
        serde_json::to_value(
            snapshot
                .query_assess(ctx.binding(), &request)
                .await
                .map_err(code_intel_domain_error)?,
        )
        .map_err(|error| ToolError::ExecutionFailed(format!("serialize Assess result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "assess"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "assess".into(),
            description: "Before changing a symbol, inspect provider-backed call impact, separately \
                labeled structural dependents, exact direct call origins, runnable test roots, and objective \
                review signals. No HIGH/MEDIUM/LOW score is invented. The blast-radius population is \
                deterministic and cursor-paged. Check repository.live_inputs before applying \
                generation evidence to the current worktree; use page.next_cursor while \
                page.has_more is true."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": h00ligan_engine::code_intel_assess::MAX_ASSESS_SYMBOL_BYTES,
                        "description": "Symbol name, or an exact symbol_id returned by Find. Exact IDs are repository- and generation-bound; ambiguous names fail with candidates."
                    },
                    "file": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": h00ligan_engine::code_intel_assess::MAX_ASSESS_FILE_BYTES,
                        "description": "Optional exact repository-confined indexed file used to disambiguate a homonym."
                    },
                    "sections": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": ["blast_radius", "callers", "tests", "risk"]
                        },
                        "description": "Sections to include (omit for all)."
                    },
                    "depth": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_assess::MAX_ASSESS_DEPTH,
                        "description": "Maximum transitive call and structural impact depth (default 3, max 10)."
                    },
                    "filter": {
                        "type": "string",
                        "description": "Reachability filter for affected symbols (default live).",
                        "enum": ["live", "dead", "test_only", "all"]
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_assess::MAX_ASSESS_PAGE_SIZE,
                        "description": "Maximum affected symbols in this page (default 50, max 100)."
                    },
                    "cursor": {
                        "type": "string",
                        "maxLength": h00ligan_engine::code_intel_assess::MAX_ASSESS_CURSOR_BYTES,
                        "description": "Blast-radius continuation bound to this generation, target, filter, depth, and section set."
                    }
                },
                "required": ["symbol"],
                "additionalProperties": false
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// InspectHandler — bounded multi-facet symbol dossier
// ============================================================================

/// Thin transport adapter for the engine-owned Inspect composition contract.
pub struct InspectHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for InspectHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let symbol = input
            .get("symbol")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::InvalidInput("missing required field: symbol".into()))?;
        let mut request = h00ligan_engine::code_intel_inspect::InspectRequest::new(symbol);
        request.file = input
            .get("file")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'file' must be a string".into()))
            })
            .transpose()?;
        if let Some(sections) = input.get("sections") {
            let sections = sections
                .as_array()
                .ok_or_else(|| ToolError::InvalidInput("'sections' must be an array".into()))?;
            let sections = sections
                .iter()
                .map(|value| {
                    value.as_str().ok_or_else(|| {
                        ToolError::InvalidInput("every 'sections' item must be a string".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            request.sections =
                h00ligan_engine::code_intel_inspect::parse_inspect_sections(sections)
                    .map_err(code_intel_domain_error)?;
        }

        let snapshot = ctx.snapshot();
        serde_json::to_value(
            snapshot
                .query_inspect(ctx.binding(), &request)
                .await
                .map_err(code_intel_domain_error)?,
        )
        .map_err(|error| ToolError::ExecutionFailed(format!("serialize Inspect result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "inspect"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "inspect".into(),
            description:
                "Inspect one symbol through a bounded dossier composed from the canonical Read, Type, Calls, and Tests contracts. Each requested facet is independently marked available, qualified, not applicable, or unavailable; field usage remains explicitly heuristic rather than an exact census. Check repository.live_inputs before applying generation evidence to the current worktree."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": h00ligan_engine::code_intel_inspect::MAX_INSPECT_SYMBOL_BYTES,
                        "description": "Symbol name, or an exact symbol_id returned by Find. Exact IDs are repository- and generation-bound; ambiguous names fail with candidates."
                    },
                    "file": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": h00ligan_engine::code_intel_inspect::MAX_INSPECT_FILE_BYTES,
                        "description": "Optional exact repository-confined indexed file used to disambiguate a homonym."
                    },
                    "sections": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": ["source", "structure", "callers", "field_usage", "tests", "warnings"]
                        },
                        "description": "Dossier facets to include (omit for all)."
                    }
                },
                "required": ["symbol"],
                "additionalProperties": false
            }),
            server_tool_type: None,
        }
    }
}
// ============================================================================
// DeadCodeHandler — Dead Code Analysis
// ============================================================================

/// Thin MCP adapter for the engine-owned Dead v1 contract.
pub struct DeadCodeHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for DeadCodeHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let mut request = h00ligan_engine::code_intel_dead::DeadRequest::default();
        request.symbol = input
            .get("symbol")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'symbol' must be a string".into()))
            })
            .transpose()?;
        request.file = input
            .get("file")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'file' must be a string".into()))
            })
            .transpose()?;
        request.production_only = input
            .get("production_only")
            .map(|value| {
                value.as_bool().ok_or_else(|| {
                    ToolError::InvalidInput("'production_only' must be a boolean".into())
                })
            })
            .transpose()?
            .unwrap_or(false);
        request.limit = optional_usize(&input, "limit", request.limit)?;
        request.cursor = input
            .get("cursor")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'cursor' must be a string".into()))
            })
            .transpose()?;
        h00ligan_engine::code_intel_dead::validate_dead_request(&request)
            .map_err(code_intel_domain_error)?;

        let snapshot = ctx.snapshot();
        serde_json::to_value(
            snapshot
                .query_dead(ctx.binding(), &request)
                .await
                .map_err(code_intel_domain_error)?,
        )
        .map_err(|error| ToolError::ExecutionFailed(format!("serialize Dead result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "dead_code"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "dead_code".into(),
            description: "Find review candidates not reached from retained roots through the canonical provider Calls graph. Call with a symbol for one verdict or omit it for a cursor-paged report. Callable results distinguish live, test-reached, provider-unreached, and unknown; non-callable structural candidates remain explicitly qualified. Check repository.live_inputs before applying generation evidence to the current worktree. No result is an automatic deletion instruction."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": h00ligan_engine::code_intel_dead::MAX_DEAD_SYMBOL_BYTES,
                        "description": "Symbol name or exact symbol_id returned by Find (omit for a full report). Exact IDs are repository- and generation-bound."
                    },
                    "file": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": h00ligan_engine::code_intel_dead::MAX_DEAD_FILE_BYTES,
                        "description": "Optional exact repository-confined indexed file used to disambiguate a homonym on the single-symbol path."
                    },
                    "production_only": {
                        "type": "boolean",
                        "description": "When true, exclude structurally identified test populations from a full report. Default: false."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_dead::MAX_DEAD_PAGE_SIZE,
                        "description": "Maximum candidates in this page (default 50, max 100)."
                    },
                    "cursor": {
                        "type": "string",
                        "maxLength": h00ligan_engine::code_intel_dead::MAX_DEAD_CURSOR_BYTES,
                        "description": "Continuation from page.next_cursor, bound to this generation and full-report query."
                    }
                },
                "additionalProperties": false
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// TestsHandler — Test Coverage Mapping
// ============================================================================

/// Find test functions that transitively call a given symbol.
///
/// Maps a symbol to the `#[test]` and `#[tokio::test]` functions that
/// exercise it, with the call chain from test to target.
pub struct TestsHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for TestsHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }
        let symbol = input
            .get("symbol")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing required field 'symbol'".into()))?;
        let mut request = h00ligan_engine::code_intel_tests::TestsRequest::new(symbol);
        request.file = input
            .get("file")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'file' must be a string".into()))
            })
            .transpose()?;
        request.limit = optional_usize(&input, "limit", request.limit)?;
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
        serde_json::to_value(
            snapshot
                .query_tests(ctx.binding(), &request)
                .await
                .map_err(code_intel_domain_error)?,
        )
        .map_err(|error| ToolError::ExecutionFailed(format!("serialize Tests result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "tests"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "tests".into(),
            description: "Find runnable test entries that reach one callable through exact, \
                provider-resolved source invocations. Returns the same immutable-generation, \
                authority-qualified, cursor-paged result as h00ligan tests --format json. \
                Test-only helpers are traversed but are not misreported as runnable tests. \
                Exact test-source execution roots that cannot be tied to a named runnable test \
                remain positive evidence and explicitly qualify the runnable-test population. \
                Check repository.live_inputs before applying generation evidence to the current \
                worktree. \
                Follow page.next_cursor while page.has_more is true."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": h00ligan_engine::code_intel_tests::MAX_TESTS_SYMBOL_BYTES,
                        "description": "Symbol name, or an exact symbol_id returned by Find. Exact IDs are repository- and generation-bound."
                    },
                    "file": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": h00ligan_engine::code_intel_tests::MAX_TESTS_FILE_BYTES,
                        "description": "Optional exact repository-confined indexed file used to disambiguate a homonym."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_tests::MAX_TESTS_PAGE_SIZE,
                        "description": "Maximum runnable test entries in this page (default 50, max 100)."
                    },
                    "cursor": {
                        "type": "string",
                        "maxLength": h00ligan_engine::code_intel_tests::MAX_TESTS_CURSOR_BYTES,
                        "description": "Continuation from page.next_cursor, bound to this generation and resolved target."
                    }
                },
                "required": ["symbol"],
                "additionalProperties": false
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// OverviewHandler — Architecture Overview
// ============================================================================

/// Architecture overview from persisted project units and graph evidence.
pub struct OverviewHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for OverviewHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let mut request = h00ligan_engine::code_intel_overview::OverviewRequest::default();
        request.limit = optional_usize(&input, "limit", request.limit)?;
        h00ligan_engine::code_intel_overview::validate_overview_request(&request)
            .map_err(code_intel_domain_error)?;
        let snapshot = ctx.snapshot();
        let result = snapshot
            .query_overview(ctx.binding(), &request)
            .await
            .map_err(code_intel_domain_error)?;
        serde_json::to_value(result).map_err(|error| {
            ToolError::ExecutionFailed(format!("serialize Overview result: {error}"))
        })
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "overview"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "overview".into(),
            description: "Architecture overview from one immutable generation. Persisted polyglot \
                project units and dependencies remain structural; reachability health and mixed \
                Calls/FieldOf fan-in are null for every language unit without complete Calls authority. \
                Check repository.live_inputs before applying the snapshot to the current worktree."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_overview::MAX_OVERVIEW_COLLECTION_LIMIT,
                        "description": "Maximum preview rows returned per Overview collection (default 50, max 100)."
                    }
                },
                "additionalProperties": false
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// AuditHandler — Full Quality Audit
// ============================================================================

/// Scoped quality audit over one immutable generation.
pub struct AuditHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for AuditHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let mut request = h00ligan_engine::code_intel_audit::AuditRequest::default();
        if let Some(scope) = input.get("scope") {
            let scope = scope
                .as_str()
                .ok_or_else(|| ToolError::InvalidInput("'scope' must be a string".into()))?;
            request.scope = h00ligan_engine::code_intel_audit::parse_audit_scope(scope)
                .map_err(code_intel_domain_error)?;
        }
        request.min_fan_in = optional_usize(&input, "min_fan_in", request.min_fan_in)?;
        request.min_dead_ratio_percent = optional_usize(
            &input,
            "min_dead_ratio_percent",
            request.min_dead_ratio_percent,
        )?;
        request.limit = optional_usize(&input, "limit", request.limit)?;
        request.cursor = input
            .get("cursor")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'cursor' must be a string".into()))
            })
            .transpose()?;
        h00ligan_engine::code_intel_audit::validate_audit_request(&request)
            .map_err(code_intel_domain_error)?;

        let snapshot = ctx.snapshot();
        serde_json::to_value(
            snapshot
                .query_audit(ctx.binding(), &request)
                .await
                .map_err(code_intel_domain_error)?,
        )
        .map_err(|error| ToolError::ExecutionFailed(format!("serialize Audit result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "audit"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "audit".into(),
            description: "Audit one immutable generation for authority-qualified dead-code health \
                and ranked incoming-coupling hotspots. Provider calls, structural call hints, field \
                uses, production, cfg-gated, and test relationships remain separate. Results are \
                deterministic and cursor-paged; the global dead-code total is UNKNOWN when Calls or \
                classification authority is insufficient, while complete language-local project-unit \
                slices remain explicit. Check repository.live_inputs before \
                applying generation evidence to the current worktree."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "enum": ["production", "conditional", "tests", "all"],
                        "description": "Relationship population used for ranking (default: production)."
                    },
                    "min_fan_in": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Minimum observed incoming relationships for a hotspot (default: 20)."
                    },
                    "min_dead_ratio_percent": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Minimum per-project-unit dead-symbol ratio as a percentage (default: 10)."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_audit::MAX_AUDIT_PAGE_SIZE,
                        "description": "Maximum hotspots in this page (default: 20, max: 100)."
                    },
                    "cursor": {
                        "type": "string",
                        "maxLength": h00ligan_engine::code_intel_audit::MAX_AUDIT_CURSOR_BYTES,
                        "description": "Continuation bound to this generation, scope, and thresholds."
                    }
                },
                "additionalProperties": false
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
    use h00ligan_engine::graph::GraphEdge;

    /// Build a minimal test graph for composite handler tests.
    fn test_graph() -> KnowledgeGraph {
        let mut graph = KnowledgeGraph::new();

        let main_id = Uuid::new_v4();
        let handler_id = Uuid::new_v4();
        let helper_id = Uuid::new_v4();
        let dead_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();

        graph
            .add_node(GraphNode {
                memory_id: main_id,
                symbol_name: "main".into(),
                kind: "function".into(),
                file_path: "src/main.rs".into(),
                content_hash: "a".into(),
                signature: "fn main()".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(0),
                line_end: Some(10),
                has_body: Some(true),
                visibility: "pub".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: handler_id,
                symbol_name: "handler".into(),
                kind: "function".into(),
                file_path: "src/lib.rs".into(),
                content_hash: "b".into(),
                signature: "fn handler()".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(5),
                line_end: Some(20),
                has_body: Some(true),
                visibility: "pub".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: helper_id,
                symbol_name: "helper".into(),
                kind: "function".into(),
                file_path: "src/util.rs".into(),
                content_hash: "c".into(),
                signature: "fn helper() -> bool".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(0),
                line_end: Some(5),
                has_body: Some(true),
                visibility: "pub(crate)".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: dead_id,
                symbol_name: "unused_fn".into(),
                kind: "function".into(),
                // WU-0015 Leg-3b: a genuinely SafeDelete-eligible dead node — private,
                // rustc-flagged, in a cfg-clean `crates/<name>` crate — so the
                // dead-report surface still exercises the SAFE_DELETE path.
                file_path: "crates/util_crate/src/util.rs".into(),
                content_hash: "d".into(),
                signature: "fn unused_fn()".into(),
                reachability_class: ReachabilityClass::Dead,
                line_start: Some(10),
                line_end: Some(15),
                has_body: Some(true),
                visibility: "private".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: true,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: test_id,
                symbol_name: "test_handler".into(),
                kind: "function".into(),
                file_path: "src/tests/handler_test.rs".into(),
                content_hash: "e".into(),
                signature: "fn test_handler()".into(),
                reachability_class: ReachabilityClass::TestOnly,
                line_start: Some(0),
                line_end: Some(10),
                has_body: Some(true),
                visibility: "".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        // main --Calls--> handler --Calls--> helper
        graph
            .add_edge(
                main_id,
                handler_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    confidence: 0.9,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        graph
            .add_edge(
                handler_id,
                helper_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    confidence: 0.8,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        // test --Calls--> handler
        graph
            .add_edge(
                test_id,
                handler_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    confidence: 0.7,
                    ..GraphEdge::default()
                },
            )
            .unwrap();

        graph
    }

    #[test]
    fn test_reverse_bfs_finds_dependents() {
        let graph = test_graph();
        // 'helper' is a lone exact match → Unique (the FIXED EP1 behavior).
        let helper_id = graph
            .all_nodes()
            .into_iter()
            .find(|node| node.symbol_name == "helper")
            .expect("helper fixture")
            .memory_id;
        let helper = graph.node(&helper_id).unwrap();
        let result = reverse_bfs(&graph, helper, 3, None);

        // handler calls helper (depth 1)
        assert!(
            result
                .dependents
                .iter()
                .any(|e| e.node.symbol_name == "handler" && e.depth == 1),
            "handler should be at depth 1"
        );
        // main calls handler (depth 2)
        assert!(
            result
                .dependents
                .iter()
                .any(|e| e.node.symbol_name == "main" && e.depth == 2),
            "main should be at depth 2"
        );
        // test_handler also calls handler (depth 1 from handler, not from helper directly)
        assert!(
            result
                .dependents
                .iter()
                .any(|e| e.node.symbol_name == "test_handler"),
            "test_handler should be found"
        );
        assert!(!result.file_counts.is_empty());
        assert!(result.test_files.contains_key("src/tests/handler_test.rs"));
    }

    // ========================================================================
    // WU-0014 ITEM 1 — MCP assess/inspect/tests handlers suppress confident
    // reachability verdicts under unavailable Calls authority (CLI≡MCP parity).
    // ========================================================================

    /// Build a `CodeIntelContext` whose immutable receipts either authorize
    /// Calls or leave the capability unavailable.
    async fn ctx_with_calls_authority(
        graph: KnowledgeGraph,
        calls_authority_available: bool,
    ) -> std::sync::Arc<CodeIntelContext> {
        ctx_with_metadata(graph, calls_authority_available).await
    }

    async fn ctx_with_metadata(
        graph: KnowledgeGraph,
        calls_authority_available: bool,
    ) -> std::sync::Arc<CodeIntelContext> {
        if calls_authority_available {
            crate::tools::test_published_rust_calls_context_with_metadata(
                std::path::Path::new("."),
                graph,
            )
            .await
        } else {
            crate::tools::test_code_intel_context(std::path::Path::new("."), Some(graph), None)
        }
    }

    /// Tests v1 fails closed with the shared typed capability error when no
    /// immutable Calls authority exists. The real-process product contract
    /// supplies the provider-backed positive control and CLI/MCP parity proof.
    #[tokio::test]
    async fn mcp_tests_returns_typed_unavailable_without_an_immutable_generation() {
        let none_ctx = ctx_with_calls_authority(test_graph(), false).await;
        let error = TestsHandler
            .execute(json!({ "symbol": "handler" }), &none_ctx)
            .await
            .expect_err("Tests must not manufacture a graph-only result");
        let ToolError::Domain { envelope, .. } = error else {
            panic!("expected a typed domain refusal, got {error:?}");
        };
        assert_eq!(envelope["error"]["code"], "capability_unavailable");
        assert_eq!(envelope["error"]["capability"], "calls");
    }

    // ---- FRAGO 3 tests ----

    /// FIX-18: `find` with `definitions_only=true` excludes `use` statements.
    #[tokio::test]
    async fn find_definitions_only_excludes_use_statements() {
        use crate::tools::composite_intel_query::FindHandler;

        let mut graph = KnowledgeGraph::new();

        let store_def = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: store_def,
                symbol_name: "crate::MemoryStore".into(),
                kind: "trait".into(),
                file_path: "src/store.rs".into(),
                content_hash: "d".into(),
                signature: "pub trait MemoryStore".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(0),
                line_end: Some(5),
                has_body: Some(false),
                visibility: "pub".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        let store_use = Uuid::new_v4();
        graph
            .add_node(GraphNode {
                memory_id: store_use,
                symbol_name: "crate::uses::MemoryStore".into(),
                kind: "use".into(),
                file_path: "src/consumer.rs".into(),
                content_hash: "u".into(),
                signature: "use crate::MemoryStore".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(0),
                line_end: Some(0),
                has_body: Some(false),
                visibility: "".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        let ctx = ctx_with_calls_authority(graph, true).await;

        let handler = FindHandler;

        // Without the flag: both nodes returned
        let all = handler
            .execute(json!({ "query": "MemoryStore" }), &ctx)
            .await
            .unwrap();
        let all_results = all["items"].as_array().unwrap();
        let all_kinds: Vec<&str> = all_results
            .iter()
            .map(|r| r["kind"].as_str().unwrap())
            .collect();
        assert!(all_kinds.contains(&"trait"));
        assert!(all_kinds.contains(&"use"));

        // With definitions_only=true: only the trait definition remains.
        let def_only = handler
            .execute(
                json!({ "query": "MemoryStore", "definitions_only": true }),
                &ctx,
            )
            .await
            .unwrap();
        let def_results = def_only["items"].as_array().unwrap();
        assert_eq!(def_results.len(), 1);
        assert_eq!(def_results[0]["kind"].as_str(), Some("trait"));
    }

    // Overview's machine projection now lives entirely in h00ligan-engine. The
    // shipped CLI/stdio-MCP parity, unclassified false-clean, unavailable
    // per-unit health, and complete-Calls non-vacuity controls live together in
    // h00ligan's real-process product contract rather than testing a second
    // adapter serializer here.
}
