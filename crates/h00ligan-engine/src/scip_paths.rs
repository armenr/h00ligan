//! Shared path authority for provider-isolated SCIP artifacts.
//!
//! A semantic provider may execute below the repository root (for example in
//! a detached Cargo workspace). Its metadata and document paths are relative
//! to that execution root, while every persisted h00ligan path is relative to the
//! bound repository. Normalization and graph loading must use the same mapping
//! or they can certify one document population and merge another.

use std::path::{Component, Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ScipPathError {
    #[error("cannot resolve repository root: {0}")]
    RepositoryRoot(std::io::Error),
    #[error("cannot resolve SCIP execution root: {0}")]
    ExecutionRoot(std::io::Error),
    #[error("SCIP execution root is outside the bound repository")]
    ExecutionRootOutsideRepository,
    #[error("SCIP document path is not canonical and relative: {0:?}")]
    InvalidDocumentPath(String),
}

/// Canonical repository-relative prefix governed by one provider execution.
pub fn execution_prefix(
    repository_root: &Path,
    execution_root: &Path,
) -> Result<PathBuf, ScipPathError> {
    let repository_root =
        std::fs::canonicalize(repository_root).map_err(ScipPathError::RepositoryRoot)?;
    let execution_root =
        std::fs::canonicalize(execution_root).map_err(ScipPathError::ExecutionRoot)?;
    execution_root
        .strip_prefix(repository_root)
        .map(Path::to_path_buf)
        .map_err(|_| ScipPathError::ExecutionRootOutsideRepository)
}

/// Translate one provider-root-relative document path into the repository
/// vocabulary used by source inventory, payloads, and graph nodes.
pub fn repository_document_path(
    execution_prefix: &Path,
    provider_path: &str,
) -> Result<String, ScipPathError> {
    let provider_path = Path::new(provider_path);
    if provider_path.as_os_str().is_empty()
        || provider_path.is_absolute()
        || provider_path.as_os_str().to_string_lossy().contains('\\')
        || !provider_path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ScipPathError::InvalidDocumentPath(
            provider_path.to_string_lossy().into_owned(),
        ));
    }
    let rebased = execution_prefix.join(provider_path);
    if rebased
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ScipPathError::InvalidDocumentPath(
            provider_path.to_string_lossy().into_owned(),
        ));
    }
    Ok(rebased.to_string_lossy().replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn detached_provider_path_rebases_into_repository_vocabulary() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = temporary.path().join("repo");
        let execution = repository.join("detached");
        std::fs::create_dir_all(&execution).expect("execution root");

        let prefix = execution_prefix(&repository, &execution).expect("execution prefix");
        assert_eq!(prefix, Path::new("detached"));
        assert_eq!(
            repository_document_path(&prefix, "src/lib.rs").expect("rebased path"),
            "detached/src/lib.rs"
        );
    }

    #[test]
    fn document_traversal_is_rejected_before_rebasing() {
        let error = repository_document_path(Path::new("detached"), "../src/lib.rs")
            .expect_err("traversal must fail");
        assert!(matches!(error, ScipPathError::InvalidDocumentPath(_)));
    }
}
