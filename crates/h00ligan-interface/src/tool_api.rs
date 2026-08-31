//! Small, substrate-free tool API shared by the full agent and lean MCP.

use serde::{Deserialize, Serialize};

/// Definition of a tool exposed to an LLM or MCP client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    /// Versioned server-tool identifier for provider-hosted tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_tool_type: Option<String>,
}

/// How a code-intelligence operation interacts with publication state.
///
/// This is deliberately required on every [`CodeIntelHandler`]. A newly
/// registered handler therefore cannot silently inherit read-only access to a
/// pinned generation or recovery access to an incomplete bundle.
#[cfg(feature = "code-intel")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeIntelAccess {
    /// Query one immutable snapshot. Publication resolution may select a
    /// previously validated generation, but an unresolved current control
    /// population cannot delegate authority to process memory.
    Query,
    /// Observe publication health. Refresh and inspection failures remain
    /// visible instead of being hidden by last-good fallback.
    Status,
    /// Publish a complete immutable generation. Admission belongs to the bound
    /// publication plan and does not inherit authority from legacy bundle state.
    Publish,
    /// Control one exact process-local publication operation. The operation
    /// identifier and engine writer lock—not a generic publish fallback—decide
    /// whether the request has authority.
    OperationControl,
}

/// Apply the publication-state contract shared by every code-intelligence
/// adapter before a handler executes.
#[cfg(feature = "code-intel")]
pub(crate) async fn admit_code_intel_access(
    context: &crate::CodeIntelContext,
    access: CodeIntelAccess,
) -> Result<(), ToolError> {
    match access {
        CodeIntelAccess::Query => {
            // Resolve one coherent publication for this request. The resolver
            // itself may choose an older validated head when a newer slot is
            // invalid, but a control/load failure means this process cannot
            // prove which generation is authoritative and must fail closed.
            context.refresh_if_changed().await.map_err(|error| {
                ToolError::ExecutionFailed(format!("refresh publication: {error}"))
            })?;
        }
        CodeIntelAccess::Status => {
            // Status owns refresh observation so it can report a failed current
            // candidate without replacing the pinned last-good query snapshot.
        }
        CodeIntelAccess::Publish => {
            // A publisher creates a complete replacement generation in private
            // state. BoundIndexPlan owns root, artifact, and writer admission;
            // stale or obsolete legacy bundle state conveys no authority here.
        }
        CodeIntelAccess::OperationControl => {
            // Exact operation ownership is enforced by the lifecycle manager.
            // This admission class intentionally performs no publication read
            // or refresh that could confuse control state with graph authority.
        }
    }
    Ok(())
}

/// Reject request-local attempts to replace a process-bound project.
///
/// Code-intelligence handlers receive one [`crate::CodeIntelContext`] selected
/// at process startup. Silently accepting another root or graph directory in
/// an individual tool call would misrepresent which repository authorized the
/// result. This guard is shared by lean MCP and every full-agent adapter.
#[cfg(feature = "code-intel")]
pub(crate) fn reject_bound_project_switch(input: &serde_json::Value) -> Result<(), ToolError> {
    let arguments = input
        .as_object()
        .ok_or_else(|| ToolError::InvalidInput("tool arguments must be a JSON object".into()))?;
    for forbidden in ["root", "workspace", "project", "data_dir", "graph_dir"] {
        if arguments.contains_key(forbidden) {
            return Err(ToolError::InvalidInput(format!(
                "'{forbidden}' is not accepted; this process is bound to one project"
            )));
        }
    }
    Ok(())
}

/// Errors from tool dispatch and execution.
#[derive(thiserror::Error, Debug)]
pub enum ToolError {
    #[error("Unknown tool: {0}")]
    UnknownTool(String),
    #[error("Tool execution failed: {0}")]
    ExecutionFailed(String),
    /// A write was refused by validation before either graph generation was
    /// mutated. The bundle guard may remove a marker it created for this
    /// attempt; ordinary execution failures must retain theirs.
    #[error("Tool execution refused before write: {0}")]
    PreWriteRefused(String),
    #[error("Path blocked by security policy: {0}")]
    PathBlocked(String),
    #[error("Command blocked by security policy: matches pattern '{0}'")]
    CommandBlocked(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// A provider-neutral domain error with a machine-readable envelope.
    #[error("{message}")]
    Domain {
        message: String,
        envelope: serde_json::Value,
    },
    #[error("Tool execution cancelled")]
    Cancelled,
    #[error(
        "code intelligence is unindexed for root {root} (graph directory {graph_dir}); {remedy}"
    )]
    Unindexed {
        root: std::path::PathBuf,
        graph_dir: std::path::PathBuf,
        remedy: String,
    },
}

impl ToolError {
    /// Preserve one machine-readable error shape across immediate MCP errors
    /// and asynchronous operation receipts. The caller supplies the rendered
    /// message because an adapter may append a recovery hint first.
    pub(crate) fn structured_error_details(&self, message: impl Into<String>) -> serde_json::Value {
        match self {
            Self::Unindexed {
                root,
                graph_dir,
                remedy,
            } => serde_json::json!({
                "kind": "unindexed",
                "root": root,
                "graph_directory": graph_dir,
                "remedy": remedy,
            }),
            Self::Domain { envelope, .. } => envelope.get("error").cloned().unwrap_or_else(|| {
                serde_json::json!({
                    "kind": "domain_error",
                    "message": message.into(),
                })
            }),
            _ => serde_json::json!({
                "kind": "tool_error",
                "message": message.into(),
            }),
        }
    }
}

/// A substrate-free code-intelligence handler.
#[cfg(feature = "code-intel")]
#[async_trait::async_trait]
pub trait CodeIntelHandler: Send + Sync + 'static {
    async fn execute(
        &self,
        input: serde_json::Value,
        ctx: &crate::CodeIntelContext,
    ) -> Result<serde_json::Value, ToolError>;

    fn access(&self, input: &serde_json::Value) -> CodeIntelAccess;

    fn name(&self) -> &str;

    fn definition(&self) -> ToolDefinition;

    fn recovery_hint(&self, _error: &ToolError) -> Option<String> {
        None
    }
}

#[cfg(feature = "code-intel")]
#[async_trait::async_trait]
impl<T> CodeIntelHandler for Box<T>
where
    T: CodeIntelHandler + ?Sized,
{
    async fn execute(
        &self,
        input: serde_json::Value,
        ctx: &crate::CodeIntelContext,
    ) -> Result<serde_json::Value, ToolError> {
        (**self).execute(input, ctx).await
    }

    fn access(&self, input: &serde_json::Value) -> CodeIntelAccess {
        (**self).access(input)
    }

    fn name(&self) -> &str {
        (**self).name()
    }

    fn definition(&self) -> ToolDefinition {
        (**self).definition()
    }

    fn recovery_hint(&self, error: &ToolError) -> Option<String> {
        (**self).recovery_hint(error)
    }
}
