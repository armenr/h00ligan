//! Canonical repository-control inputs for project discovery and WATCH.
//!
//! Inventory owns the byte-authoritative current-language population. WATCH
//! consumes the same path vocabulary plus explicit future-language controls so
//! adapters do not grow independent Cargo/Go/Node/Python/PHP filename lists.

use std::path::{Path, PathBuf};

use crate::code_intel_domain::{LanguageId, ProjectInputRole};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectInputPathSpec {
    Exact(&'static str),
    FileNameFamily {
        prefix: &'static str,
        suffix: &'static str,
    },
}

impl ProjectInputPathSpec {
    fn matches(&self, path: &Path) -> bool {
        match self {
            Self::Exact(relative_path) => path.ends_with(relative_path),
            Self::FileNameFamily { prefix, suffix } => path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix) && name.ends_with(suffix)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SemanticProjectInputSpec {
    path: ProjectInputPathSpec,
    ecosystem: &'static str,
    role: ProjectInputRole,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectInputCandidatePath {
    Exact(PathBuf),
    FileNameFamily {
        directory: PathBuf,
        prefix: &'static str,
        suffix: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProjectInputCandidate {
    pub path: ProjectInputCandidatePath,
    pub language_id: LanguageId,
    pub ecosystem: &'static str,
    pub role: ProjectInputRole,
}

impl ProjectInputCandidate {
    #[cfg(test)]
    fn exact_path(&self) -> Option<&Path> {
        match &self.path {
            ProjectInputCandidatePath::Exact(path) => Some(path),
            ProjectInputCandidatePath::FileNameFamily { .. } => None,
        }
    }
}

const RUST_PROJECT_INPUTS: &[SemanticProjectInputSpec] = &[
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("Cargo.toml"),
        ecosystem: "cargo",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("Cargo.lock"),
        ecosystem: "cargo",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("rust-toolchain.toml"),
        ecosystem: "cargo",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("rust-toolchain"),
        ecosystem: "cargo",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".tool-versions"),
        ecosystem: "cargo",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".cargo/config.toml"),
        ecosystem: "cargo",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".cargo/config"),
        ecosystem: "cargo",
        role: ProjectInputRole::ToolConfiguration,
    },
];

const GO_PROJECT_INPUTS: &[SemanticProjectInputSpec] = &[
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("go.work"),
        ecosystem: "go",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("go.mod"),
        ecosystem: "go",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("go.sum"),
        ecosystem: "go",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("go.work.sum"),
        ecosystem: "go",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("vendor/modules.txt"),
        ecosystem: "go",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".tool-versions"),
        ecosystem: "go",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".go-version"),
        ecosystem: "go",
        role: ProjectInputRole::ToolConfiguration,
    },
];

const PYTHON_PROJECT_INPUTS: &[SemanticProjectInputSpec] = &[
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("pyproject.toml"),
        ecosystem: "python",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("setup.py"),
        ecosystem: "python",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("setup.cfg"),
        ecosystem: "python",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("Pipfile"),
        ecosystem: "python",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::FileNameFamily {
            prefix: "requirements",
            suffix: ".txt",
        },
        ecosystem: "python",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("uv.lock"),
        ecosystem: "python",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("poetry.lock"),
        ecosystem: "python",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("Pipfile.lock"),
        ecosystem: "python",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".python-version"),
        ecosystem: "python",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".tool-versions"),
        ecosystem: "python",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("pyrightconfig.json"),
        ecosystem: "python",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("mypy.ini"),
        ecosystem: "python",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".mypy.ini"),
        ecosystem: "python",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("pytest.ini"),
        ecosystem: "python",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("tox.ini"),
        ecosystem: "python",
        role: ProjectInputRole::ToolConfiguration,
    },
];

const TYPESCRIPT_PROJECT_INPUTS: &[SemanticProjectInputSpec] = &[
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("package.json"),
        ecosystem: "node",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("pnpm-workspace.yaml"),
        ecosystem: "node",
        role: ProjectInputRole::Manifest,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::FileNameFamily {
            prefix: "tsconfig",
            suffix: ".json",
        },
        ecosystem: "node",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::FileNameFamily {
            prefix: "jsconfig",
            suffix: ".json",
        },
        ecosystem: "node",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("package-lock.json"),
        ecosystem: "node",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("pnpm-lock.yaml"),
        ecosystem: "node",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("yarn.lock"),
        ecosystem: "node",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("bun.lock"),
        ecosystem: "node",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact("bun.lockb"),
        ecosystem: "node",
        role: ProjectInputRole::DependencyLock,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".node-version"),
        ecosystem: "node",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".nvmrc"),
        ecosystem: "node",
        role: ProjectInputRole::ToolConfiguration,
    },
    SemanticProjectInputSpec {
        path: ProjectInputPathSpec::Exact(".tool-versions"),
        ecosystem: "node",
        role: ProjectInputRole::ToolConfiguration,
    },
];

struct LanguageProjectInputSpec {
    language: &'static str,
    inputs: &'static [SemanticProjectInputSpec],
}

static PROJECT_INPUT_REGISTRY: &[LanguageProjectInputSpec] = &[
    LanguageProjectInputSpec {
        language: "rust",
        inputs: RUST_PROJECT_INPUTS,
    },
    LanguageProjectInputSpec {
        language: "go",
        inputs: GO_PROJECT_INPUTS,
    },
    LanguageProjectInputSpec {
        language: "python",
        inputs: PYTHON_PROJECT_INPUTS,
    },
    LanguageProjectInputSpec {
        language: "typescript",
        inputs: TYPESCRIPT_PROJECT_INPUTS,
    },
];

fn semantic_specs(language_id: &LanguageId) -> &'static [SemanticProjectInputSpec] {
    PROJECT_INPUT_REGISTRY
        .iter()
        .find(|entry| entry.language == language_id.0)
        .map_or(&[], |entry| entry.inputs)
}

pub fn semantic_project_input_candidates(
    directory: &Path,
    language_id: &LanguageId,
) -> Vec<ProjectInputCandidate> {
    semantic_specs(language_id)
        .iter()
        .map(|spec| ProjectInputCandidate {
            path: match spec.path {
                ProjectInputPathSpec::Exact(relative_path) => {
                    ProjectInputCandidatePath::Exact(directory.join(relative_path))
                }
                ProjectInputPathSpec::FileNameFamily { prefix, suffix } => {
                    ProjectInputCandidatePath::FileNameFamily {
                        directory: directory.to_path_buf(),
                        prefix,
                        suffix,
                    }
                }
            },
            language_id: language_id.clone(),
            ecosystem: spec.ecosystem,
            role: spec.role,
        })
        .collect()
}

/// Whether a repository path is a known source-population, dependency, or
/// toolchain control. Every registered project-input spec drives both
/// immutable inventory observation and native WATCH recognition; a language's
/// structural or semantic provider may still be unavailable independently.
pub fn is_project_control_path(path: &Path) -> bool {
    if PROJECT_INPUT_REGISTRY
        .iter()
        .flat_map(|entry| entry.inputs)
        .any(|spec| spec.path.matches(path))
    {
        return true;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == ".gitignore" || matches!(name, "composer.json" | "composer.lock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_inventory_candidates_and_watch_controls_share_one_vocabulary() {
        let rust = semantic_project_input_candidates(Path::new("crate"), &LanguageId::new("rust"));
        let go = semantic_project_input_candidates(Path::new("module"), &LanguageId::new("go"));
        assert_eq!(rust.len(), 7, "Rust control population");
        assert_eq!(go.len(), 7, "Go control population");
        for candidate in rust.iter().chain(&go) {
            let path = candidate
                .exact_path()
                .expect("current Rust/Go inputs use exact paths");
            assert!(
                is_project_control_path(path),
                "inventory input is invisible to WATCH: {}",
                path.display()
            );
        }

        for planned in [
            "pyproject.toml",
            "requirements-dev.txt",
            ".mypy.ini",
            "package.json",
            "tsconfig.build.json",
            "composer.json",
        ] {
            assert!(
                is_project_control_path(Path::new(planned)),
                "planned-language positive control: {planned}"
            );
        }
        for unrelated in ["README.md", "config.toml", ".codex/config.toml"] {
            assert!(
                !is_project_control_path(Path::new(unrelated)),
                "unrelated path entered project authority: {unrelated}"
            );
        }
    }

    /// FALSIFIER: directory-sensitive tool selectors participate in the
    /// effective compiler choice even though their conventional names begin
    /// with a dot. They must therefore be immutable inventory inputs and
    /// native WATCH controls for every language whose resolver observes them.
    #[test]
    fn version_manager_selectors_are_inventory_and_watch_inputs() {
        let rust = semantic_project_input_candidates(Path::new("crate"), &LanguageId::new("rust"));
        let go = semantic_project_input_candidates(Path::new("module"), &LanguageId::new("go"));

        for (population, selector) in [
            (&rust, "crate/.tool-versions"),
            (&go, "module/.tool-versions"),
            (&go, "module/.go-version"),
        ] {
            assert!(
                population.iter().any(|candidate| {
                    candidate.exact_path() == Some(Path::new(selector))
                        && candidate.role == ProjectInputRole::ToolConfiguration
                }),
                "toolchain selector is absent from immutable project inputs: {selector}"
            );
            assert!(
                is_project_control_path(Path::new(selector)),
                "hidden toolchain selector is invisible to native WATCH: {selector}"
            );
        }

        assert!(
            rust.iter().any(|candidate| candidate
                .exact_path()
                .is_some_and(|path| path.ends_with("rust-toolchain.toml")))
                && go.iter().any(|candidate| {
                    candidate
                        .exact_path()
                        .is_some_and(|path| path.ends_with("go.mod"))
                }),
            "known-positive native toolchain controls must remain populated"
        );
    }
}
