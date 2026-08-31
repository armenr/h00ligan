//! Lean MCP and tool-contract adapter for h00ligan.

pub mod code_intel_context;
pub(crate) mod code_intel_operations;
pub mod code_intel_registry;
pub mod mcp;
pub mod tool_api;
pub mod tools;

pub use code_intel_context::{
    CodeIntelContext, CodeIntelLoadError, CodeIntelSnapshot, GraphLoadState, IndexedSourceState,
    ReachabilityEvidenceState,
};
pub use code_intel_registry::CodeIntelRegistry;
pub use tool_api::{ToolDefinition, ToolError};
