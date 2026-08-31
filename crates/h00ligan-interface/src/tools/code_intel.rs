//! Code intelligence tool handlers for the agent loop.
//!
//! Thin MCP adapters over the shared code-intelligence use cases and indexing
//! supervisor. Query handlers read one immutable generation; `reindex` and
//! `watch` publish through the same supervised lifecycle used by the CLI.
//!
//! All handlers return bounded JSON for inline agent consumption.
//! This module is gated by `#[cfg(feature = "code-intel")]` at the declaration
//! site in `mod.rs`; no additional per-item gates are needed.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use h00ligan_engine::graph::KnowledgeGraph;

use crate::tool_api::{CodeIntelAccess, CodeIntelHandler};
use crate::{CodeIntelContext, ToolDefinition, ToolError};

/// One coherent snapshot view. Deref keeps the query code compact while the
/// attached metadata guarantees coverage/envelope decisions come from the
/// same loaded generation as the graph.
pub(super) struct GraphView {
    graph: Arc<KnowledgeGraph>,
}

impl std::ops::Deref for GraphView {
    type Target = KnowledgeGraph;

    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

/// Clone one immutable generation and fail closed when the pinned snapshot is
/// absent or incomplete. An in-progress on-disk candidate does not revoke a
/// previously validated generation.
pub(super) fn require_graph(
    ctx: &CodeIntelContext,
    snapshot: &Arc<crate::CodeIntelSnapshot>,
) -> Result<GraphView, ToolError> {
    let graph = snapshot
        .graph
        .as_ref()
        .cloned()
        .ok_or_else(|| ToolError::Unindexed {
            root: ctx.binding().root().to_path_buf(),
            graph_dir: ctx.binding().graph_dir().to_path_buf(),
            remedy: format!(
                "call reindex/init or run `h00ligan --root {} index`",
                ctx.binding().root().display()
            ),
        })?;
    Ok(GraphView { graph })
}

// ============================================================================
// ReindexHandler
// ============================================================================

/// Start a cancellable code-knowledge publication operation.
///
/// The handler returns immediately. The background operation reuses an exactly
/// current generation or builds a complete fresh generation, then loads that
/// exact publication so subsequent requests cannot observe a split or partial
/// graph. Callers poll `reindex_status` with the returned exact operation ID.
pub struct ReindexHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for ReindexHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }
        let request = parse_reindex_operation_request(&input)?;
        let handle = ctx
            .index_supervisor()
            .start_manual(request)
            .map_err(crate::code_intel_operations::supervisor_error)?;
        let operation_id = handle.operation_id();
        // The supervisor owns the run and terminal receipt. Dropping this
        // one-use outcome receiver cannot cancel or detach the operation.
        drop(handle);
        let snapshot = ctx
            .index_supervisor()
            .snapshot(operation_id)
            .map_err(crate::code_intel_operations::supervisor_error)?;
        Ok(crate::code_intel_operations::operation_snapshot_json(
            &snapshot, None,
        ))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Publish
    }

    fn name(&self) -> &str {
        "reindex"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "reindex".into(),
            description: "Start a cancellable immutable reindex operation and return immediately with its operation_id. Poll reindex_status for bounded progress and the terminal receipt; use reindex_cancel with that exact ID to stop it. Exact current evidence is reused unless force=true. Set scip=true for external semantic enrichment; add require_complete_calls=true when every callable language must be complete.".into(),
            // DO NOT add "default" or "additionalProperties" — Anthropic API rejects them.
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scip": {
                        "type": "boolean",
                        "description": "Attempt best-effort SCIP provider enrichment and report exact per-scope coverage."
                    },
                    "force": {
                        "type": "boolean",
                        "description": "Build a fresh generation even when exact current evidence already satisfies this request."
                    },
                    "require_complete_calls": {
                        "type": "boolean",
                        "description": "Refuse publication unless every callable language has complete Calls authority. Requires scip=true."
                    },
                    "recover_publication": {
                        "type": "boolean",
                        "description": "Explicitly replace damaged, conflicting, missing-identity, or foreign publication controls only after a complete fresh generation validates."
                    },
                    "allow_capability_downgrade": {
                        "type": "boolean",
                        "description": "Allow a freshly built generation to replace stronger current capability authority. This permission does not bypass exact-current reuse; set force=true to request an intentional unchanged-input downgrade."
                    }
                }
            }),
            server_tool_type: None,
        }
    }
}

fn parse_reindex_operation_request(
    input: &Value,
) -> Result<h00ligan_engine::code_intel_supervisor::IndexSupervisorRequest, ToolError> {
    let providers = input.get("scip").and_then(Value::as_bool).unwrap_or(false);
    let require_complete_calls = input
        .get("require_complete_calls")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if require_complete_calls && !providers {
        return Err(ToolError::InvalidInput(
            "'require_complete_calls' requires 'scip' to be true".into(),
        ));
    }
    Ok(
        h00ligan_engine::code_intel_supervisor::IndexSupervisorRequest {
            providers: if providers {
                h00ligan_engine::code_intel_indexing::ProviderIntent::Refresh
            } else {
                h00ligan_engine::code_intel_indexing::ProviderIntent::StructuralOnly
            },
            force: input.get("force").and_then(Value::as_bool).unwrap_or(false),
            require_complete_calls,
            publication_recovery: if input
                .get("recover_publication")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                h00ligan_engine::code_intel_publication::PublicationRecovery::RecoverAndRebind
            } else {
                h00ligan_engine::code_intel_publication::PublicationRecovery::Strict
            },
            capability_floor: if input
                .get("allow_capability_downgrade")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                h00ligan_engine::code_intel_publication::CapabilityFloorPolicy::AllowDowngrade
            } else {
                h00ligan_engine::code_intel_publication::CapabilityFloorPolicy::Preserve
            },
            ..Default::default()
        },
    )
}

fn optional_string(input: &Value, name: &str) -> Result<Option<String>, ToolError> {
    input
        .get(name)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| ToolError::InvalidInput(format!("'{name}' must be a string")))
        })
        .transpose()
}

fn supervised_operation_json(
    ctx: &CodeIntelContext,
    snapshot: h00ligan_engine::code_intel_supervisor::IndexOperationSnapshot,
) -> Result<Value, ToolError> {
    let result = if snapshot.state
        == h00ligan_engine::code_intel_supervisor::IndexOperationState::Succeeded
    {
        let publication = snapshot.publication.as_ref().ok_or_else(|| {
            ToolError::ExecutionFailed(format!(
                "successful operation {} has no retained publication receipt",
                snapshot.operation_id
            ))
        })?;
        Some(crate::code_intel_operations::publication_result_json(
            publication,
            ctx.binding().graph_dir(),
            &snapshot,
        ))
    } else {
        None
    };
    Ok(crate::code_intel_operations::operation_snapshot_json(
        &snapshot, result,
    ))
}

pub struct ReindexStatusHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for ReindexStatusHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        let operation_id = optional_string(&input, "operation_id")?;
        let snapshot = if let Some(operation_id) = operation_id {
            let operation_id = crate::code_intel_operations::parse_operation_id(&operation_id)?;
            ctx.index_supervisor()
                .snapshot(operation_id)
                .map_err(crate::code_intel_operations::supervisor_error)?
        } else {
            ctx.index_supervisor()
                .latest_snapshot()
                .map_err(crate::code_intel_operations::supervisor_error)?
        };
        supervised_operation_json(ctx, snapshot)
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Status
    }

    fn name(&self) -> &str {
        "reindex_status"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "reindex_status".into(),
            description: "Return bounded progress or the immutable terminal receipt for this MCP process's latest reindex operation. Supply operation_id to pin the exact operation; an unknown or superseded ID fails closed.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "operation_id": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Exact operation_id returned by reindex. Omit only to inspect this process's latest operation."
                    }
                },
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}

pub struct ReindexCancelHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for ReindexCancelHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        let operation_id = input
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ToolError::InvalidInput("missing required field: operation_id".into())
            })?;
        let operation_id = crate::code_intel_operations::parse_operation_id(operation_id)?;
        let receipt = ctx
            .index_supervisor()
            .cancel(operation_id)
            .map_err(crate::code_intel_operations::supervisor_error)?;
        Ok(crate::code_intel_operations::cancellation_receipt_json(
            &receipt,
        ))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::OperationControl
    }

    fn name(&self) -> &str {
        "reindex_cancel"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "reindex_cancel".into(),
            description: "Request cancellation of one exact in-process reindex operation. Provider process groups are killed and reaped; a private partial generation never replaces the last good publication. Replaying cancellation after a terminal receipt is inert.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "operation_id": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Exact operation_id returned by reindex."
                    }
                },
                "required": ["operation_id"],
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// watch — long-lived supervised reconciliation lifecycle
// ============================================================================

pub struct WatchHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for WatchHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        let action = input
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::InvalidInput("missing required field: action".into()))?;
        match action {
            "start" => {
                let debounce_ms = bounded_u64(&input, "debounce_ms", 75, 1, 5_000)?;
                let publication_probe_ms =
                    bounded_u64(&input, "publication_probe_ms", 1_000, 10, 60_000)?;
                let reconcile_secs = bounded_u64(&input, "reconcile_secs", 60, 1, 3_600)?;
                let request = parse_reindex_operation_request(&input)?;
                let status = ctx
                    .start_index_watch(
                        request,
                        debounce_ms,
                        Duration::from_millis(publication_probe_ms),
                        Duration::from_secs(reconcile_secs),
                    )
                    .await
                    .map_err(watch_control_error)?;
                Ok(watch_status_json(ctx, "start", Some(&status), true))
            }
            "status" => {
                require_action_only(&input, action)?;
                let status = ctx.index_watch_status().await;
                Ok(watch_status_json(ctx, "status", status.as_ref(), false))
            }
            "stop" => {
                require_action_only(&input, action)?;
                let status = ctx.stop_index_watch().await.map_err(watch_control_error)?;
                let changed = status.is_some();
                Ok(watch_status_json(ctx, "stop", status.as_ref(), changed))
            }
            _ => Err(ToolError::InvalidInput(
                "'action' must be one of: start, status, stop".into(),
            )),
        }
    }

    fn access(&self, input: &Value) -> CodeIntelAccess {
        match input.get("action").and_then(Value::as_str) {
            Some("start") => CodeIntelAccess::Publish,
            Some("status") => CodeIntelAccess::Status,
            _ => CodeIntelAccess::OperationControl,
        }
    }

    fn name(&self) -> &str {
        "watch"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "watch".into(),
            description: "Control this MCP process's long-lived code-intelligence watcher. action=start begins native low-latency source observation, bounded publication-control probes, and slower byte-exact integrity reconciliation; action=status reports bounded epochs and operation state; action=stop disables future WATCH work and cancels/reaps any active WATCH candidate. With scip=true plus allow_capability_downgrade=true, a changed epoch publishes fresh structural truth first and then performs semantic enrichment as cancellable background work; strict complete-Calls requests remain atomic. Filesystem paths and control tokens are hints only—each publication performs authoritative discovery and hashing.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["start", "status", "stop"],
                        "description": "Lifecycle action for this process-bound project."
                    },
                    "scip": {
                        "type": "boolean",
                        "description": "On start, attempt semantic provider enrichment for each required reconciliation."
                    },
                    "require_complete_calls": {
                        "type": "boolean",
                        "description": "On start, refuse publication unless every callable language has complete Calls authority. Requires scip=true."
                    },
                    "debounce_ms": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5000,
                        "description": "On start, native-event quiet window in milliseconds (default 75)."
                    },
                    "publication_probe_ms": {
                        "type": "integer",
                        "minimum": 10,
                        "maximum": 60000,
                        "description": "On start, bounded publication-control drift probe interval in milliseconds (default 1000). This does not open or hash generation payloads."
                    },
                    "reconcile_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 3600,
                        "description": "On start, byte-exact full-discovery integrity reconciliation interval in seconds (default 60)."
                    },
                    "recover_publication": {
                        "type": "boolean",
                        "description": "On start, explicitly replace damaged, conflicting, missing-identity, or foreign publication controls only after a complete candidate validates."
                    },
                    "allow_capability_downgrade": {
                        "type": "boolean",
                        "description": "On start, permit a watched generation to lower previously complete capability authority. With scip=true, this also enables fast structural publication before background semantic enrichment."
                    }
                },
                "required": ["action"],
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}

fn bounded_u64(
    input: &Value,
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ToolError> {
    let Some(value) = input.get(name) else {
        return Ok(default);
    };
    let value = value
        .as_u64()
        .ok_or_else(|| ToolError::InvalidInput(format!("'{name}' must be an integer")))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ToolError::InvalidInput(format!(
            "'{name}' must be between {minimum} and {maximum}"
        )));
    }
    Ok(value)
}

fn require_action_only(input: &Value, action: &str) -> Result<(), ToolError> {
    let unexpected = input
        .as_object()
        .into_iter()
        .flat_map(serde_json::Map::keys)
        .find(|name| name.as_str() != "action");
    if let Some(name) = unexpected {
        return Err(ToolError::InvalidInput(format!(
            "'{name}' is only valid when action is 'start', not '{action}'"
        )));
    }
    Ok(())
}

fn watch_control_error(error: crate::code_intel_context::IndexWatchControlError) -> ToolError {
    let code = match error {
        crate::code_intel_context::IndexWatchControlError::AlreadyRunning => {
            "watch_already_running"
        }
        crate::code_intel_context::IndexWatchControlError::Stopping => {
            "watch_transition_in_progress"
        }
        crate::code_intel_context::IndexWatchControlError::Watcher(_) => "watch_failed",
        crate::code_intel_context::IndexWatchControlError::StopTask(_) => "watch_failed",
    };
    let message = error.to_string();
    ToolError::Domain {
        message: message.clone(),
        envelope: json!({
            "error": {
                "code": code,
                "message": message,
                "evidence": {},
            }
        }),
    }
}

fn watch_status_json(
    ctx: &CodeIntelContext,
    action: &str,
    status: Option<&h00ligan_engine::watcher::IndexWatchStatus>,
    changed: bool,
) -> Value {
    let schedule = ctx.index_supervisor().schedule_snapshot();
    let latest_operation = ctx
        .index_supervisor()
        .latest_snapshot()
        .ok()
        .map(|operation| crate::code_intel_operations::operation_snapshot_json(&operation, None));
    json!({
        "schema_version": "h00/code-intel/watch/v2",
        "action": action,
        "changed": changed,
        "root": ctx.binding().root(),
        "graph_directory": ctx.binding().graph_dir(),
        "watch": {
            "running": status.is_some_and(|status| status.running),
            "started_at_unix_ms": status.map(|status| status.started_at_unix_ms),
            "watched_directories": status.map_or(0, |status| status.watched_directories),
            "filesystem_batches": status.map_or(0, |status| status.filesystem_batches),
            "filesystem_paths": status.map_or(0, |status| status.filesystem_paths),
            "overflow_batches": status.map_or(0, |status| status.overflow_batches),
            "publication_probes": status.map_or(0, |status| status.publication_probes),
            "publication_control_reads": status.map_or(0, |status| status.publication_control_reads),
            "publication_probe_failures": status.map_or(0, |status| status.publication_probe_failures),
            "publication_drifts": status.map_or(0, |status| status.publication_drifts),
            "integrity_reconciliations": status.map_or(0, |status| status.integrity_reconciliations),
            "desired_epoch": status.map_or(schedule.desired_epoch, |status| status.desired_epoch),
            "published_epoch": status.map_or(schedule.published_epoch, |status| status.published_epoch),
            "active_trigger": status.and_then(|status| status.active_trigger).map(|trigger| match trigger {
                h00ligan_engine::code_intel_supervisor::IndexOperationTrigger::Manual => "manual",
                h00ligan_engine::code_intel_supervisor::IndexOperationTrigger::Watch => "watch",
            }),
            "last_error": status.and_then(|status| status.last_error.as_deref()),
        },
        "schedule": {
            "desired_epoch": schedule.desired_epoch,
            "published_epoch": schedule.published_epoch,
            "active_operation_id": schedule.active_operation.map(|operation| operation.to_string()),
            "active_trigger": schedule.active_trigger.map(|trigger| match trigger {
                h00ligan_engine::code_intel_supervisor::IndexOperationTrigger::Manual => "manual",
                h00ligan_engine::code_intel_supervisor::IndexOperationTrigger::Watch => "watch",
            }),
            "manual_queued": schedule.manual_queued,
            "watch_enabled": schedule.watch_enabled,
        },
        "latest_operation": latest_operation,
    })
}

// ============================================================================
// type_def — complete type structure with fields, methods, impls, and warnings
// ============================================================================

pub struct TypeDefHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for TypeDefHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let symbol = input
            .get("symbol")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::InvalidInput("missing required field: symbol".into()))?;
        let mut request = h00ligan_engine::code_intel_domain::TypeRequest::new(symbol);
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
        let result = snapshot
            .query_type(ctx.binding(), &request)
            .await
            .map_err(code_intel_domain_error)?;
        serde_json::to_value(result)
            .map_err(|error| ToolError::ExecutionFailed(format!("serialize Type result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "type"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "type".into(),
            description: "Return one immutable generation's exact structural members for a type. The typed, cursor-paged result is identical to h00ligan type --format json; authority.population names the bounded indexed population and incomplete structural evidence fails closed. Check repository.live_inputs before applying generation evidence to the current worktree."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Type name, or an exact symbol_id returned by Find. Exact IDs are repository- and generation-bound."
                    },
                    "file": {
                        "type": "string",
                        "description": "Optional repository-confined file path used to disambiguate a homonym."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_domain::MAX_TYPE_PAGE_SIZE,
                        "description": "Maximum structural members in this page (default 50)."
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Opaque continuation cursor returned by an earlier Type page."
                    }
                },
                "required": ["symbol"],
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}
// ============================================================================
// read_symbol — read a symbol's source code by name
// ============================================================================

/// Read a function or type body by name.
///
/// Resolves the symbol via the knowledge graph, reads its source line range
/// from the file system, and returns just that slice — avoiding the need to
/// read entire files.
pub struct ReadSymbolHandler;

#[async_trait::async_trait]
impl CodeIntelHandler for ReadSymbolHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }
        let symbol = input
            .get("symbol")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::InvalidInput("missing required field: symbol".into()))?;
        let file = input
            .get("file")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'file' must be a string".into()))
            })
            .transpose()?;
        let cursor = input
            .get("cursor")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ToolError::InvalidInput("'cursor' must be a string".into()))
            })
            .transpose()?;
        let request = h00ligan_engine::code_intel_read::ReadRequest {
            symbol: symbol.into(),
            file,
            limit: optional_usize(
                &input,
                "limit",
                h00ligan_engine::code_intel_read::DEFAULT_READ_PAGE_SIZE,
            )?,
            cursor,
        };
        h00ligan_engine::code_intel_read::validate_read_request(&request)
            .map_err(code_intel_domain_error)?;
        let snapshot = ctx.snapshot();
        let result = snapshot
            .query_read(ctx.binding(), &request)
            .await
            .map_err(code_intel_domain_error)?;
        serde_json::to_value(result)
            .map_err(|error| ToolError::ExecutionFailed(format!("serialize Read result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &'static str {
        "read"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "read".into(),
            description: "Read one immutable generation's selected symbol source through a bounded character page. Exact live definition bytes must match the published source hash. CLI JSON and MCP return the same typed result; repository.live_inputs discloses unrelated repository drift. Follow page.next_cursor while page.has_more is true.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Symbol name, or an exact symbol_id returned by Find. Exact IDs are repository- and generation-bound."
                    },
                    "file": {
                        "type": "string",
                        "description": "Optional exact repository-confined file selector. No cross-file or same-crate fallback is applied."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_read::MAX_READ_PAGE_SIZE,
                        "description": "Maximum Unicode source characters in this page (default 8000)."
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Opaque continuation cursor returned by an earlier Read page."
                    }
                },
                "required": ["symbol"],
                "additionalProperties": false,
            }),
            server_tool_type: None,
        }
    }
}

// ============================================================================
// CallSitesHandler — provider-neutral Calls query
// ============================================================================

/// Execute the same Calls use case used by CLI JSON and human CLI rendering.
pub struct CallSitesHandler;

pub(super) fn code_intel_domain_error(
    error: h00ligan_engine::code_intel_domain::DomainError,
) -> ToolError {
    let message = error.to_string();
    let envelope = serde_json::to_value(error.envelope()).unwrap_or_else(|serialize| {
        json!({
            "error": {
                "code": "domain_error_serialization",
                "message": serialize.to_string(),
            }
        })
    });
    ToolError::Domain { message, envelope }
}

pub(super) fn optional_usize(
    input: &Value,
    field: &'static str,
    default: usize,
) -> Result<usize, ToolError> {
    let Some(value) = input.get(field) else {
        return Ok(default);
    };
    let value = value.as_u64().ok_or_else(|| {
        ToolError::InvalidInput(format!("'{field}' must be a non-negative integer"))
    })?;
    usize::try_from(value)
        .map_err(|_| ToolError::InvalidInput(format!("'{field}' does not fit this platform")))
}

#[async_trait::async_trait]
impl CodeIntelHandler for CallSitesHandler {
    async fn execute(&self, input: Value, ctx: &CodeIntelContext) -> Result<Value, ToolError> {
        if ctx.cancel_token().is_cancelled() {
            return Err(ToolError::Cancelled);
        }

        let symbol = input
            .get("symbol")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::InvalidInput("missing required field: symbol".into()))?;
        let mut request = h00ligan_engine::code_intel_domain::CallsRequest::new(symbol);
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
        request.filter = input
            .get("filter")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidInput("'filter' must be a string".into()))?
                    .parse()
                    .map_err(ToolError::InvalidInput)
            })
            .transpose()?
            .unwrap_or_default();

        let snapshot = ctx.snapshot();
        let result = snapshot
            .query_calls(ctx.binding(), &request)
            .await
            .map_err(code_intel_domain_error)?;
        serde_json::to_value(result)
            .map_err(|error| ToolError::ExecutionFailed(format!("serialize Calls result: {error}")))
    }

    fn access(&self, _input: &Value) -> CodeIntelAccess {
        CodeIntelAccess::Query
    }

    fn name(&self) -> &str {
        "calls"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "calls".into(),
            description: "Find provider-resolved explicit source invocations of one symbol. The typed authority.population states the exact bounded population; it does not claim runtime dispatch or expanded-macro completeness. Exact call spans are present only when provider identity and source invocation syntax agree. Returns the same cursor-paged Calls result as h00ligan calls --format json. Check authority.status: complete has no exclusions within that population; qualified lists exact coverage_exclusions whose source regions may contain additional invocations. Check repository.live_inputs before applying generation evidence to the current worktree."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Symbol name, or an exact symbol_id returned by Find. Exact IDs are repository- and generation-bound."
                    },
                    "file": {
                        "type": "string",
                        "description": "Optional repository-confined file path used to disambiguate a homonym."
                    },
                    "filter": {
                        "type": "string",
                        "enum": ["live", "all", "dead", "test_only"],
                        "description": "Caller population (default live)."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": h00ligan_engine::code_intel_domain::MAX_CALLS_PAGE_SIZE,
                        "description": "Maximum call sites in this page (default 50)."
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Opaque continuation cursor returned by an earlier page."
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use parking_lot::RwLock;
    use serde_json::json;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use h00ligan_engine::code_intel_domain::{
        CALLS_CONFIGURATION_ID, CallsPopulation, CapabilityReceipt, CapabilityScope,
        ConfigurationId, DocumentMembership, DocumentMembershipKind, EcosystemId, LanguageId,
        ProjectInventory, ProjectInventoryCoverage, ProjectUnit, ProjectUnitId, ProjectUnitKind,
    };
    use h00ligan_engine::code_intel_payload::{
        CALLS_PROVIDER_PAYLOAD_SCHEMA, CallsProviderPayload, NormalizedSourceSpan, ProviderCall,
        ProviderDocument, ProviderLocation, ProviderPayload, ProviderSymbol, ProviderSymbolRole,
    };
    use h00ligan_engine::code_intel_publication::{GenerationDraft, SemanticPublisher};
    use h00ligan_engine::graph::{EdgeKind, GraphEdge, GraphNode, KnowledgeGraph};
    use h00ligan_engine::graph_store::{GraphGenerationMetadata, GraphStore};
    use h00ligan_engine::reachability::ReachabilityClass;

    fn make_test_ctx(graph: Option<Arc<RwLock<KnowledgeGraph>>>) -> Arc<CodeIntelContext> {
        let graph = graph.map(|graph| graph.read().clone());
        crate::tools::test_code_intel_context(std::path::Path::new("/tmp"), graph, None)
    }

    async fn make_calls_test_ctx(
        root: &std::path::Path,
        mut graph: KnowledgeGraph,
        exact_calls: &[(&str, &str, &str)],
    ) -> Arc<CodeIntelContext> {
        let graph_dir = root.join("calls-test-bundle");
        std::fs::create_dir_all(&graph_dir).expect("Calls test graph directory");
        let binding = h00ligan_engine::project_binding::ProjectBinding::explicit(root, &graph_dir)
            .expect("Calls test binding");

        let nodes = graph.all_nodes().into_iter().cloned().collect::<Vec<_>>();
        let document_paths = nodes
            .iter()
            .map(|node| node.file_path.clone())
            .collect::<BTreeSet<_>>();
        let project_unit_id = ProjectUnitId::new("rust:test:published-calls");
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
                units: (!document_paths.is_empty())
                    .then(|| ProjectUnit {
                        project_unit_id: project_unit_id.clone(),
                        language_id: LanguageId::new("rust"),
                        ecosystem_id: EcosystemId::new("test"),
                        kind: ProjectUnitKind::Package,
                        root_path: String::new(),
                        manifest_path: None,
                        compilation_root_paths: Vec::new(),
                    })
                    .into_iter()
                    .collect(),
                memberships: document_paths
                    .iter()
                    .map(|document_path| DocumentMembership {
                        document_path: document_path.clone(),
                        language_id: LanguageId::new("rust"),
                        project_unit_id: project_unit_id.clone(),
                        kind: DocumentMembershipKind::SourceOwner,
                    })
                    .collect(),
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };
        let receipt = CapabilityReceipt::complete(
            "calls",
            "handler-test-provider",
            "1.0.0",
            CapabilityScope::Repository {
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            "a".repeat(64),
        );
        let mut documents = Vec::new();
        for document_path in &document_paths {
            let byte_length = nodes
                .iter()
                .filter(|node| &node.file_path == document_path)
                .filter_map(|node| node.line_start)
                .map(|line| line as u64 * 100 + 100)
                .max()
                .unwrap_or(100);
            documents.push(ProviderDocument {
                document_path: document_path.clone(),
                language_id: LanguageId::new("rust"),
                content_sha256: "b".repeat(64),
                cross_document_surface_sha256: "c".repeat(64),
                byte_length,
            });
        }
        let mut provider_ids = BTreeMap::new();
        let mut symbols = Vec::new();
        for node in &nodes {
            let line = node
                .line_start
                .expect("exact Calls test nodes require a definition line");
            let base = line as u64 * 100;
            graph
                .set_source_span(
                    node.memory_id,
                    h00ligan_engine::graph::SourceSpan {
                        start_byte: base as usize,
                        end_byte: (base + 80) as usize,
                    },
                )
                .expect("co-published structural callable extent");
            let provider_symbol_id = format!("{}:{}:{}", node.file_path, line, node.symbol_name);
            provider_ids.insert(
                (node.file_path.clone(), node.symbol_name.clone()),
                provider_symbol_id.clone(),
            );
            let location = |span| ProviderLocation {
                document_path: node.file_path.clone(),
                span,
            };
            let structural_extent = NormalizedSourceSpan {
                start_byte: base,
                end_byte: base + 80,
                start_line: line as u32,
                start_utf8_byte_column: 0,
                end_line: line as u32,
                end_utf8_byte_column: 80,
            };
            symbols.push(ProviderSymbol {
                provider_symbol_id,
                name: node.symbol_name.clone(),
                provider_kind: node.kind.clone(),
                language_id: LanguageId::new("rust"),
                role: ProviderSymbolRole::SourceInvocationTarget,
                definition: Some(location(NormalizedSourceSpan {
                    start_byte: base + 4,
                    end_byte: base + 4 + node.symbol_name.len() as u64,
                    start_line: line as u32,
                    start_utf8_byte_column: 4,
                    end_line: line as u32,
                    end_utf8_byte_column: 4 + node.symbol_name.len() as u32,
                })),
                structural_extent: Some(location(structural_extent.clone())),
                call_owner_extent: Some(location(structural_extent)),
            });
        }
        let calls = exact_calls
            .iter()
            .map(|(caller, callee, document_path)| {
                let caller_id = provider_ids
                    .get(&(String::from(*document_path), String::from(*caller)))
                    .unwrap_or_else(|| panic!("missing exact caller {caller} in {document_path}"));
                let callee_id = provider_ids
                    .get(&(String::from(*document_path), String::from(*callee)))
                    .unwrap_or_else(|| panic!("missing exact callee {callee} in {document_path}"));
                let caller_line = nodes
                    .iter()
                    .find(|node| node.file_path == *document_path && node.symbol_name == *caller)
                    .and_then(|node| node.line_start)
                    .expect("exact caller line");
                let base = caller_line as u64 * 100;
                ProviderCall {
                    caller_symbol_id: caller_id.clone(),
                    callee_symbol_id: callee_id.clone(),
                    call_site: ProviderLocation {
                        document_path: String::from(*document_path),
                        span: NormalizedSourceSpan {
                            start_byte: base + 40,
                            end_byte: base + 46,
                            start_line: caller_line as u32,
                            start_utf8_byte_column: 40,
                            end_line: caller_line as u32,
                            end_utf8_byte_column: 46,
                        },
                    },
                }
            })
            .collect();
        let payload = ProviderPayload::Calls(CallsProviderPayload {
            schema_version: CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
            receipt: receipt.clone(),
            semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
            execution_authority:
                h00ligan_engine::code_intel_payload::ProviderExecutionAuthority::InvocationBound {
                    provider_configurations_sha256: std::collections::BTreeMap::new(),
                },
            canonical_snapshot_sha256: None,
            documents,
            symbols,
            calls,
            callable_bindings: Vec::new(),
            coverage_exclusions: Vec::new(),
        });

        let mut publisher =
            SemanticPublisher::acquire(binding.graph_dir(), binding.root()).expect("publisher");
        let workspace = publisher.begin_generation().expect("generation workspace");
        let store = GraphStore::new(workspace.database());
        store
            .save_snapshot(&graph)
            .await
            .expect("published handler graph");
        store
            .set_origin(binding.root())
            .await
            .expect("published handler origin");
        store
            .set_generation_metadata(GraphGenerationMetadata::now(false))
            .await
            .expect("published handler generation metadata");
        drop(store);
        publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("handler-test".into()),
                    project_inventory: inventory,
                    receipts: vec![receipt],
                    provider_payloads: vec![payload],
                },
            )
            .expect("published Calls handler generation");
        Arc::new(
            CodeIntelContext::load(binding, CancellationToken::new())
                .await
                .expect("published Calls handler context"),
        )
    }

    fn contains_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Contains,
            confidence: 1.0,
            ..GraphEdge::default()
        }
    }

    #[test]
    fn all_handlers_have_unique_names() {
        let handlers: Vec<Box<dyn CodeIntelHandler>> =
            vec![Box::new(ReindexHandler), Box::new(TypeDefHandler)];

        let names: Vec<&str> = handlers.iter().map(|h| h.name()).collect();
        let unique: std::collections::HashSet<&&str> = names.iter().collect();
        assert_eq!(names.len(), unique.len(), "duplicate tool names");
    }

    #[test]
    fn all_handlers_have_valid_definitions() {
        let handlers: Vec<Box<dyn CodeIntelHandler>> =
            vec![Box::new(ReindexHandler), Box::new(TypeDefHandler)];

        for handler in &handlers {
            let def = handler.definition();
            assert!(!def.name.is_empty(), "empty name");
            assert!(!def.description.is_empty(), "empty description");
            assert!(def.server_tool_type.is_none(), "should not be server tool");
            // Schema should be a valid JSON object
            assert!(def.input_schema.is_object(), "schema should be object");
        }
    }

    // Type semantics live in h00ligan-engine::code_intel_type. The real h00ligan
    // CLI/stdio-MCP parity test exercises this adapter without rebuilding a
    // second handler-local structural contract.
    // ====================================================================
    // CallSitesHandler tests
    // ====================================================================

    #[tokio::test]
    async fn call_sites_no_graph_returns_error() {
        let ctx = make_test_ctx(None);
        let handler = CallSitesHandler;
        let result = handler.execute(json!({"symbol": "foo"}), &ctx).await;
        let err = result.expect_err("an unindexed context must refuse calls");
        let ToolError::Domain { envelope, .. } = err else {
            panic!("expected a typed Calls domain error, got: {err}");
        };
        assert_eq!(envelope["error"]["code"], "capability_unavailable");
        assert_eq!(envelope["error"]["capability"], "calls");
        assert_eq!(
            envelope["error"]["evidence"][0]["reason_code"],
            "immutable_generation_unavailable"
        );
    }

    #[tokio::test]
    async fn call_sites_symbol_not_found() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let graph = KnowledgeGraph::new();
        let ctx = make_calls_test_ctx(temporary.path(), graph, &[]).await;
        let handler = CallSitesHandler;
        let result = handler
            .execute(json!({"symbol": "nonexistent"}), &ctx)
            .await;
        let err = result.expect_err("complete Calls coverage must report a missing symbol");
        let ToolError::Domain { envelope, .. } = err else {
            panic!("expected a typed Calls domain error, got: {err}");
        };
        assert_eq!(envelope["error"]["code"], "symbol_not_found");
    }

    #[tokio::test]
    async fn call_sites_finds_callers() {
        // The co-published graph supplies structural symbols but deliberately
        // has no Calls edge. Exact occurrence authority comes from the
        // provider payload built below.
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("src/lib.rs");
        std::fs::create_dir_all(file_path.parent().unwrap()).expect("mkdir");
        std::fs::write(
            &file_path,
            "fn target_fn() {\n    println!(\"hello\");\n}\n\nfn caller_fn() {\n    target_fn();\n    let x = 1;\n}\n",
        )
        .expect("write");

        let mut graph = KnowledgeGraph::new();
        let target = GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: "target_fn".into(),
            kind: "function".into(),
            file_path: "src/lib.rs".into(),
            content_hash: "abc".into(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Wired,
            line_start: Some(0),
            line_end: Some(2),
            has_body: Some(true),
            visibility: "pub".into(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        };
        let caller = GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: "caller_fn".into(),
            kind: "function".into(),
            file_path: "src/lib.rs".into(),
            content_hash: "def".into(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Wired,
            line_start: Some(4),
            line_end: Some(7),
            has_body: Some(true),
            visibility: "pub".into(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        };
        graph.add_node(target).unwrap();
        graph.add_node(caller).unwrap();

        let ctx = make_calls_test_ctx(
            dir.path(),
            graph,
            &[("caller_fn", "target_fn", "src/lib.rs")],
        )
        .await;

        let handler = CallSitesHandler;
        let result = handler
            .execute(json!({"symbol": "target_fn"}), &ctx)
            .await
            .expect("should succeed");

        assert_eq!(result["resolved_symbol"]["name"], "target_fn");
        assert_eq!(result["authority"]["status"], "complete");

        let sites = result["items"].as_array().expect("Calls items array");
        assert!(!sites.is_empty(), "should find at least one call site");

        let first = &sites[0];
        assert_eq!(first["caller"]["name"], "caller_fn");
        assert!(first.get("confidence").is_none());
        assert!(first.get("evidence").is_none());
        assert_eq!(first["call_span"]["start_line"], 4);
        assert_eq!(first["context"], "exact provider-resolved call occurrence");
        assert_eq!(result["page"]["returned"], sites.len());
        assert_eq!(result["page"]["total_items"], sites.len());
        assert_eq!(result["page"]["has_more"], false);
    }

    /// Drive the real MCP Calls request through the engine-owned exact-file
    /// resolver, including repository-confined absolute-path normalization.
    /// Two `process` homonyms each have one caller: selecting a.rs must return
    /// caller_a, while omitting the file selector remains ambiguous.
    #[tokio::test]
    async fn mcp_calls_handler_file_param_disambiguates_homonym_incl_abs_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("a.rs"),
            "fn process() {}\nfn caller_a() {\n    process();\n}\n",
        )
        .expect("write a.rs");
        std::fs::write(
            dir.path().join("b.rs"),
            "fn process() {}\nfn caller_b() {\n    process();\n}\n",
        )
        .expect("write b.rs");

        let mut graph = KnowledgeGraph::new();
        let mut node = |name: &str, file: &str, ls: usize, le: usize| {
            let n = GraphNode {
                memory_id: Uuid::new_v4(),
                symbol_name: name.into(),
                kind: "function".into(),
                file_path: file.into(),
                content_hash: format!("{file}:{name}"),
                signature: String::new(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(ls),
                line_end: Some(le),
                has_body: Some(true),
                visibility: "pub".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            };
            let id = n.memory_id;
            graph.add_node(n).unwrap();
            id
        };
        let process_a = node("process", "a.rs", 0, 0);
        let caller_a = node("caller_a", "a.rs", 1, 3);
        let process_b = node("process", "b.rs", 0, 0);
        let caller_b = node("caller_b", "b.rs", 1, 3);
        let _ = (caller_a, process_a, caller_b, process_b);
        let ctx = make_calls_test_ctx(
            dir.path(),
            graph,
            &[
                ("caller_a", "process", "a.rs"),
                ("caller_b", "process", "b.rs"),
            ],
        )
        .await;
        let handler = CallSitesHandler;

        // WITHOUT "file": homonym is F8 → Err.
        assert!(
            handler
                .execute(json!({"symbol": "process"}), &ctx)
                .await
                .is_err(),
            "bare 'process' must be F8-ambiguous on the MCP calls handler"
        );

        // WITH an ABSOLUTE "file" pointing at a.rs: the engine-owned exact-file
        // resolver selects a.rs's process and therefore caller_a, never caller_b.
        let abs_a = dir.path().join("a.rs");
        let result = handler
            .execute(
                json!({"symbol": "process", "file": abs_a.to_str().expect("utf8")}),
                &ctx,
            )
            .await
            .expect("absolute --file must resolve the homonym");
        let sites = result["items"].as_array().expect("Calls items array");
        assert!(
            sites.iter().any(|s| s["caller"]["name"] == "caller_a"),
            "must resolve to a.rs's process (caller_a), got: {sites:?}"
        );
        assert!(
            !sites.iter().any(|s| s["caller"]["name"] == "caller_b"),
            "must NOT resolve to b.rs's process (caller_b), got: {sites:?}"
        );
    }

    /// Structural containment is not semantic Calls evidence, even when the
    /// source text happens to contain a call-like token.
    #[tokio::test]
    async fn call_sites_rejects_contains_as_call_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("src/lib.rs");
        std::fs::create_dir_all(file_path.parent().unwrap()).expect("mkdir");
        std::fs::write(
            &file_path,
            "fn new() {\n    println!(\"hello\");\n}\n\nfn caller() {\n    new();\n}\n",
        )
        .expect("write");

        let mut graph = KnowledgeGraph::new();
        let target = GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: "new".into(),
            kind: "function".into(),
            file_path: "src/lib.rs".into(),
            content_hash: "abc".into(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Wired,
            line_start: Some(0),
            line_end: Some(2),
            has_body: Some(true),
            visibility: "pub".into(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        };
        let caller = GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: "caller".into(),
            kind: "function".into(),
            file_path: "src/lib.rs".into(),
            content_hash: "def".into(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Wired,
            line_start: Some(4),
            line_end: Some(6),
            has_body: Some(true),
            visibility: "pub".into(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        };
        let target_id = target.memory_id;
        let caller_id = caller.memory_id;
        graph.add_node(target).unwrap();
        graph.add_node(caller).unwrap();
        graph
            .add_edge(caller_id, target_id, contains_edge())
            .unwrap();

        let ctx = make_calls_test_ctx(dir.path(), graph, &[]).await;

        let handler = CallSitesHandler;
        let result = handler
            .execute(json!({"symbol": "new"}), &ctx)
            .await
            .expect("should succeed");

        assert_eq!(result["authority"]["status"], "complete");
        assert_eq!(result["items"], json!([]));
        assert_eq!(result["page"]["total_items"], 0);
        assert_eq!(
            result["repository"]["live_inputs"]["freshness"], "unknown",
            "the synthetic graph has complete generation-local Calls authority but its declared source is absent from the current worktree"
        );
        assert_eq!(
            result["repository"]["live_inputs"]["reason"],
            "no_source_found"
        );
        assert!(
            result["warnings"]
                .as_array()
                .is_some_and(|warnings| warnings.iter().any(|warning| warning
                    .as_str()
                    .is_some_and(|warning| warning.contains("current worktree")))),
            "generation-local zero must be qualified when live-input freshness is unknown: {result}"
        );
    }

    /// Complete Calls coverage distinguishes an authoritative empty answer
    /// from an unavailable capability without inventing a prose-only note.
    #[tokio::test]
    async fn call_sites_returns_authoritative_empty_result() {
        let temporary = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(temporary.path().join("src")).expect("source directory");
        std::fs::write(temporary.path().join("src/lib.rs"), "fn lonely_fn() {}\n")
            .expect("source fixture");
        let mut graph = KnowledgeGraph::new();
        let lonely = GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: "lonely_fn".into(),
            kind: "function".into(),
            file_path: "src/lib.rs".into(),
            content_hash: "abc".into(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Dead,
            line_start: Some(0),
            line_end: Some(2),
            has_body: Some(true),
            visibility: "pub".into(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        };
        graph.add_node(lonely).unwrap();
        // No edges — this node has zero callers.

        let ctx = make_calls_test_ctx(temporary.path(), graph, &[]).await;

        let handler = CallSitesHandler;
        let result = handler
            .execute(json!({"symbol": "lonely_fn"}), &ctx)
            .await
            .expect("should succeed");

        assert_eq!(result["authority"]["status"], "complete");
        assert_eq!(result["items"], json!([]));
        assert_eq!(result["page"]["returned"], 0);
        assert_eq!(result["page"]["total_items"], 0);
        assert_eq!(result["page"]["has_more"], false);
    }

    // Retired Type text/count/truncation tests moved to the shared engine
    // contract and real adapter-parity boundary.
}
