//! Startup-only project binding helpers.

use std::path::Path;

use h00ligan_engine::project_binding::{ProjectBinding, ProjectBindingOptions};

use crate::error::LiganError;

/// Resolve the standalone `h00ligan` binding. Relative root and graph paths
/// are anchored by the engine resolver, so nested launches are deterministic.
pub fn resolve_project_binding(
    startup_dir: &Path,
    root: Option<&Path>,
    graph_dir: Option<&Path>,
) -> Result<ProjectBinding, LiganError> {
    let mut options = ProjectBindingOptions::new(startup_dir);
    if let Some(root) = root {
        options = options.explicit_root(root);
    }
    if let Some(path) = graph_dir {
        options = options.global_graph_dir(path);
    }
    ProjectBinding::resolve(options).map_err(LiganError::from)
}
