//! Error types for h00ligan (code-intelligence only).
//!
//! `LiganError` covers graph operations, indexing, and code-intel
//! subcommands. It does NOT include agent or TUI errors.

/// Top-level error for the h00ligan code-intelligence layer.
#[derive(Debug, thiserror::Error)]
pub enum LiganError {
    /// IO error (file system, process spawning).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error (missing config, invalid values, bad paths).
    #[error("Config error: {0}")]
    Config(String),

    /// Project-root or code-intelligence data-directory binding error.
    #[error("Project binding error: {0}")]
    Project(#[from] h00ligan_engine::project_binding::ProjectRootError),

    /// A caller- or graph-supplied file path escaped the selected project.
    #[error("Project path error: {0}")]
    ProjectPath(#[from] h00ligan_engine::project_binding::ProjectPathError),

    /// Index pipeline error (code-intel feature).
    #[error("Index error: {0}")]
    Index(#[from] h00ligan_engine::index_pipeline::IndexPipelineError),

    /// Atomic immutable-generation build/publication error.
    #[error("Index publication error: {0}")]
    IndexPublication(
        #[from] h00ligan_engine::code_intel_publication::IndexGenerationPublicationError,
    ),

    /// Immutable indexing admission or destination-preparation error.
    #[error("Index plan error: {0}")]
    IndexPlan(#[from] h00ligan_engine::code_intel_indexing::BoundIndexPlanError),

    /// Index state error (code-intel feature).
    #[error("Index state error: {0}")]
    IndexState(#[from] h00ligan_engine::index_state::IndexStateError),

    /// Code-intel graph store error. Kept typed so a foreign-origin refusal
    /// propagates as a first-class error (its `Display` carries both the stored
    /// origin and the querying root) rather than a stringly-typed `Config`.
    #[error("Graph store error: {0}")]
    Graph(#[from] h00ligan_engine::graph_store::GraphStoreError),

    /// Provider-neutral code-intelligence query contract error.
    #[error("Code-intelligence query error: {0}")]
    Domain(#[from] h00ligan_engine::code_intel_domain::DomainError),

    /// Exact source bytes no longer match the selected immutable generation.
    #[error("Source materialization error: {0}")]
    SourceMaterialization(
        #[from] h00ligan_engine::source_materialization::SourceMaterializationError,
    ),

    /// A tokio task join error (panic in spawned task).
    #[error("Task join error: {0}")]
    Join(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn ligan_error_config() {
        let err = LiganError::Config("missing key".into());
        assert!(err.to_string().contains("missing key"));
    }

    #[test]
    fn ligan_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: LiganError = io_err.into();
        assert_matches!(err, LiganError::Io(_));
        assert!(err.to_string().contains("denied"));
    }
}
