//! Shared immutable-generation query helpers below CLI and MCP adapters.

use std::path::{Component, Path, PathBuf};

use crate::code_intel_domain::{DomainError, LanguageId, RepositoryBinding};
use crate::code_intel_publication::ResolvedGeneration;
use crate::graph_query::FileContext;
use crate::project_binding::ProjectBinding;

/// Normalize a selector against the bound repository without consulting live
/// source state. The selector addresses a document in the pinned generation;
/// requiring that document to still exist would make read-only results depend
/// on unrelated working-tree changes.
pub fn generation_file_context(
    binding: &ProjectBinding,
    file: &str,
) -> Result<FileContext, DomainError> {
    Ok(FileContext::from(normalize_generation_selector(
        binding, file, false,
    )?))
}

/// Normalize a file-or-directory selector against the immutable generation.
/// `.` and the bound repository path both select the generation root.
pub fn generation_scope_selector(
    binding: &ProjectBinding,
    selector: &str,
) -> Result<String, DomainError> {
    normalize_generation_selector(binding, selector, true)
}

fn normalize_generation_selector(
    binding: &ProjectBinding,
    selector: &str,
    allow_repository_root: bool,
) -> Result<String, DomainError> {
    if selector.is_empty() {
        return Err(DomainError::SourcePath(
            "source selector must not be empty".into(),
        ));
    }

    let raw = Path::new(selector);
    if raw
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(DomainError::SourcePath(format!(
            "{selector} contains a forbidden `..` component"
        )));
    }
    let relative = if raw.is_absolute() {
        raw.strip_prefix(binding.root())
            .map(Path::to_path_buf)
            .or_else(|_| absolute_alias_relative_to_root(binding.root(), raw))
            .map_err(|_| {
                DomainError::SourcePath(format!("{selector} is outside the bound repository"))
            })?
    } else {
        raw.to_path_buf()
    };

    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => normalized.push(name),
            Component::CurDir => {}
            Component::ParentDir => unreachable!("parent components were rejected above"),
            Component::RootDir | Component::Prefix(_) => {
                return Err(DomainError::SourcePath(format!(
                    "{selector} is outside the bound repository"
                )));
            }
        }
    }
    if normalized.as_os_str().is_empty() && !allow_repository_root {
        return Err(DomainError::SourcePath(
            "file selector must name a repository document".into(),
        ));
    }

    Ok(normalized.to_string_lossy().replace('\\', "/"))
}

/// Prove that an absolute filesystem alias resolves beneath the canonical
/// repository root without requiring the selected generation document to
/// still exist. The deepest existing ancestor supplies symlink authority; its
/// missing normal-component suffix remains a pinned-generation selector.
fn absolute_alias_relative_to_root(root: &Path, raw: &Path) -> Result<PathBuf, ()> {
    let mut existing = Some(raw);
    while let Some(candidate) = existing {
        match std::fs::canonicalize(candidate) {
            Ok(canonical) => {
                let suffix = raw.strip_prefix(candidate).map_err(|_| ())?;
                return canonical
                    .join(suffix)
                    .strip_prefix(root)
                    .map(Path::to_path_buf)
                    .map_err(|_| ());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing = candidate.parent();
            }
            Err(_) => return Err(()),
        }
    }
    Err(())
}

pub fn language_id_for_path(file_path: &str) -> LanguageId {
    let extension = Path::new(file_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    let language = crate::language::language_for_extension(extension).unwrap_or("unknown");
    LanguageId::new(language)
}

pub fn repository_binding(
    binding: &ProjectBinding,
    generation: &ResolvedGeneration,
) -> RepositoryBinding {
    RepositoryBinding {
        repository_id: generation.manifest.repository_id.clone(),
        root_label: binding
            .root()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("repository")
            .into(),
        live_inputs: None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn absolute_root_alias_preserves_a_missing_generation_document() {
        let temporary = TempDir::new().expect("selector scratch");
        let root = temporary.path().join("repository");
        let alias = temporary.path().join("repository-alias");
        std::fs::create_dir(&root).expect("canonical repository root");
        symlink(&root, &alias).expect("repository-root alias");
        let binding =
            ProjectBinding::explicit(&root, Path::new("graph")).expect("canonical project binding");
        let missing = alias.join("removed/module.rs");

        assert!(!missing.exists(), "missing-document control");
        assert_eq!(
            generation_file_context(&binding, missing.to_str().expect("UTF-8 alias"))
                .expect("filesystem alias remains confined")
                .file_path(),
            "removed/module.rs"
        );
    }

    #[test]
    fn absolute_alias_proof_rejects_a_missing_document_outside_the_repository() {
        let temporary = TempDir::new().expect("selector scratch");
        let root = temporary.path().join("repository");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&root).expect("canonical repository root");
        std::fs::create_dir(&outside).expect("outside directory");
        let binding =
            ProjectBinding::explicit(&root, Path::new("graph")).expect("canonical project binding");
        let missing = outside.join("removed/module.rs");

        assert!(!missing.exists(), "missing-document control");
        let error = generation_file_context(&binding, missing.to_str().expect("UTF-8 path"))
            .expect_err("an outside ancestor cannot authorize a generation selector");
        assert!(
            matches!(error, DomainError::SourcePath(ref message) if message.contains("outside the bound repository")),
            "outside-path rejection must retain the typed confinement reason: {error}"
        );
    }
}
