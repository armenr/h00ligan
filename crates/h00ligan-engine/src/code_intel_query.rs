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
    let relative = if raw.is_absolute() {
        raw.strip_prefix(binding.root()).map_err(|_| {
            DomainError::SourcePath(format!("{selector} is outside the bound repository"))
        })?
    } else {
        raw
    };

    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => normalized.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(DomainError::SourcePath(format!(
                    "{selector} contains a forbidden `..` component"
                )));
            }
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
