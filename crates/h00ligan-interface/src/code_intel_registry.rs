//! Exact, deterministic registry for the graph-only code-intelligence surface.

use crate::tool_api::{CodeIntelAccess, CodeIntelHandler};
use crate::tools::{code_intel, composite_intel, composite_intel_query};
use crate::{CodeIntelContext, ToolDefinition, ToolError};

pub(crate) fn handlers() -> Vec<Box<dyn CodeIntelHandler>> {
    vec![
        Box::new(code_intel::ReindexHandler),
        Box::new(code_intel::ReindexStatusHandler),
        Box::new(code_intel::ReindexCancelHandler),
        Box::new(code_intel::WatchHandler),
        Box::new(code_intel::TypeDefHandler),
        Box::new(code_intel::ReadSymbolHandler),
        Box::new(code_intel::CallSitesHandler),
        Box::new(composite_intel::AssessHandler),
        Box::new(composite_intel::InspectHandler),
        Box::new(composite_intel::DeadCodeHandler),
        Box::new(composite_intel_query::StatusHandler),
        Box::new(composite_intel_query::FindHandler),
        Box::new(composite_intel::TestsHandler),
        Box::new(composite_intel::OverviewHandler),
        Box::new(composite_intel::AuditHandler),
        Box::new(composite_intel_query::DepsHandler),
        Box::new(composite_intel_query::GrepContextHandler),
        Box::new(composite_intel_query::DiffHandler),
    ]
}

pub struct CodeIntelRegistry {
    handlers: Vec<Box<dyn CodeIntelHandler>>,
    definitions: Vec<ToolDefinition>,
}

impl CodeIntelRegistry {
    fn from_handlers(handlers: Vec<Box<dyn CodeIntelHandler>>) -> Self {
        let definitions = handlers
            .iter()
            .map(|handler| handler.definition())
            .collect();
        Self {
            handlers,
            definitions,
        }
    }

    pub fn new() -> Self {
        Self::from_handlers(handlers())
    }

    pub fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    pub fn handler_names(&self) -> Vec<&str> {
        self.handlers.iter().map(|handler| handler.name()).collect()
    }

    /// Resolve the explicit publication admission class for one registered
    /// operation. Unknown names never acquire a permissive fallback.
    pub fn access(
        &self,
        name: &str,
        input: &serde_json::Value,
    ) -> Result<CodeIntelAccess, ToolError> {
        self.handlers
            .iter()
            .find(|handler| handler.name() == name)
            .map(|handler| handler.access(input))
            .ok_or_else(|| ToolError::UnknownTool(name.into()))
    }

    pub async fn execute(
        &self,
        name: &str,
        input: serde_json::Value,
        context: &CodeIntelContext,
    ) -> Result<serde_json::Value, ToolError> {
        let handler = self
            .handlers
            .iter()
            .find(|handler| handler.name() == name)
            .ok_or_else(|| ToolError::UnknownTool(name.into()))?;
        handler.execute(input, context).await
    }

    pub fn recovery_hint(&self, name: &str, error: &ToolError) -> Option<String> {
        self.handlers
            .iter()
            .find(|handler| handler.name() == name)
            .and_then(|handler| handler.recovery_hint(error))
    }
}

impl Default for CodeIntelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_handler_has_an_explicit_admission_class() {
        let registry = CodeIntelRegistry::new();
        let expected = [
            ("reindex", CodeIntelAccess::Publish),
            ("reindex_status", CodeIntelAccess::Status),
            ("reindex_cancel", CodeIntelAccess::OperationControl),
            ("watch", CodeIntelAccess::OperationControl),
            ("type", CodeIntelAccess::Query),
            ("read", CodeIntelAccess::Query),
            ("calls", CodeIntelAccess::Query),
            ("assess", CodeIntelAccess::Query),
            ("inspect", CodeIntelAccess::Query),
            ("dead_code", CodeIntelAccess::Query),
            ("status", CodeIntelAccess::Status),
            ("find", CodeIntelAccess::Query),
            ("tests", CodeIntelAccess::Query),
            ("overview", CodeIntelAccess::Query),
            ("audit", CodeIntelAccess::Query),
            ("deps", CodeIntelAccess::Query),
            ("grep_context", CodeIntelAccess::Query),
            ("diff", CodeIntelAccess::Query),
        ];

        assert_eq!(
            registry.handler_names().as_slice(),
            expected.map(|(name, _)| name)
        );
        for (name, access) in expected {
            assert_eq!(
                registry.access(name, &serde_json::json!({})).unwrap(),
                access,
                "wrong admission class for {name}"
            );
        }
        assert_eq!(
            registry
                .access("watch", &serde_json::json!({"action": "start"}))
                .unwrap(),
            CodeIntelAccess::Publish
        );
        assert_eq!(
            registry
                .access("watch", &serde_json::json!({"action": "status"}))
                .unwrap(),
            CodeIntelAccess::Status
        );
        assert_eq!(
            registry
                .access("watch", &serde_json::json!({"action": "stop"}))
                .unwrap(),
            CodeIntelAccess::OperationControl
        );

        assert!(matches!(
            registry.access("future_unclassified_handler", &serde_json::json!({})),
            Err(ToolError::UnknownTool(_))
        ));
    }

    #[test]
    fn h00ligan_registry_exposes_nonblocking_indexing_lifecycles() {
        let registry = CodeIntelRegistry::default();
        let names = registry.handler_names();
        for required in ["reindex", "reindex_status", "reindex_cancel", "watch"] {
            assert!(
                names.contains(&required),
                "standalone h00ligan MCP is missing the {required} lifecycle operation: {names:?}"
            );
        }
    }
}
