//! Immutable project/root and publication-data binding for code-intelligence work.
//!
//! Resolution happens before command dispatch. Downstream code receives this
//! value instead of independently consulting the process CWD or storage config.

use std::fs::{self, OpenOptions};
#[cfg(feature = "code-intel")]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::{ConfigError, ConfigSource, EngineConfig, expand_path};

/// Repo-managed directory containing immutable code-intelligence generations.
///
/// This lives in the ungated binding module so filesystem policy and the
/// code-intelligence publisher cannot drift on the owned path name.
pub const IMMUTABLE_PUBLICATION_DIRECTORY: &str = "publication-v4";

/// Non-authoritative provider caches retained across immutable publications.
/// Provider artifacts remain disposable; only rebuild/download acceleration
/// state lives here.
pub const PROVIDER_CACHE_DIRECTORY: &str = "provider-cache-v1";

/// Optional directory-shaped outputs owned by graph-query operations.
pub const GRAPH_AUXILIARY_DIRECTORIES: [&str; 2] = ["traces", PROVIDER_CACHE_DIRECTORY];

/// Admissible filesystem states for a generated artifact path.
///
/// Inspection never follows the final path component. A caller may create an
/// absent artifact or replace/read a regular file; every other shape is an
/// explicit refusal rather than something to skip or traverse implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedArtifactState {
    Absent,
    RegularFile,
}

/// Admissible filesystem states for an owned generated directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedDirectoryState {
    Absent,
    Directory,
}

/// Inspect a generated artifact without following its final path component.
pub fn inspect_generated_artifact(path: &Path) -> Result<GeneratedArtifactState, ProjectPathError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ProjectPathError::SymlinkedGenerated {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if metadata.file_type().is_file() => Ok(GeneratedArtifactState::RegularFile),
        Ok(_) => Err(ProjectPathError::NonRegularGenerated {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(GeneratedArtifactState::Absent)
        }
        Err(source) => Err(ProjectPathError::Io {
            operation: "inspect generated artifact",
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Inspect an owned generated directory without following its final path
/// component. Regular files and every other non-directory shape are refused.
pub fn inspect_generated_directory(
    path: &Path,
) -> Result<GeneratedDirectoryState, ProjectPathError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ProjectPathError::SymlinkedGenerated {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if metadata.file_type().is_dir() => Ok(GeneratedDirectoryState::Directory),
        Ok(_) => Err(ProjectPathError::NonDirectoryGenerated {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(GeneratedDirectoryState::Absent)
        }
        Err(source) => Err(ProjectPathError::Io {
            operation: "inspect generated directory",
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// How the project root was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSource {
    Explicit,
    Discovered,
}

/// How the code-intelligence data directory was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphSource {
    Cli,
    ProjectConfig,
    UserConfig,
    RepoDefault,
}

/// One process-wide root and code-intelligence data-directory decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectBinding {
    root: PathBuf,
    graph_dir: PathBuf,
    root_source: RootSource,
    graph_source: GraphSource,
}

impl ProjectBinding {
    /// Resolve an immutable binding from raw startup inputs.
    pub fn resolve(options: ProjectBindingOptions<'_>) -> Result<Self, ProjectRootError> {
        let startup_dir = canonical_directory(options.startup_dir, "startup directory")?;
        let (root, root_source) = if let Some(raw_root) = options.explicit_root {
            let selected = anchor_expanded_path(raw_root, &startup_dir);
            (
                canonical_directory(&selected, "explicit project root")?,
                RootSource::Explicit,
            )
        } else {
            (
                discover_repository_root(&startup_dir)?.ok_or_else(|| {
                    ProjectRootError::NoRepository {
                        startup_dir: startup_dir.clone(),
                    }
                })?,
                RootSource::Discovered,
            )
        };

        let loaded = EngineConfig::load_for_root(&root)?;
        let (raw_graph_dir, graph_source) = if let Some(path) = options.subcommand_graph_dir {
            (path.to_path_buf(), GraphSource::Cli)
        } else if let Some(path) = options.global_graph_dir {
            (path.to_path_buf(), GraphSource::Cli)
        } else if let Some(path) = loaded.value.graph.path.as_deref() {
            let source = match loaded.source {
                ConfigSource::Project => GraphSource::ProjectConfig,
                ConfigSource::User => GraphSource::UserConfig,
                ConfigSource::Defaults => GraphSource::RepoDefault,
            };
            (PathBuf::from(path), source)
        } else {
            (
                PathBuf::from(".h00ligan/code-intel"),
                GraphSource::RepoDefault,
            )
        };

        if raw_graph_dir.as_os_str().is_empty() {
            return Err(ProjectRootError::EmptyGraphPath);
        }
        let selected_graph_dir = anchor_expanded_path(&raw_graph_dir, &root);
        let graph_dir = select_graph_directory(&root, &selected_graph_dir, graph_source)?;

        Ok(Self {
            root,
            graph_dir,
            root_source,
            graph_source,
        })
    }

    /// Construct a binding from two caller-authorized paths.
    ///
    /// Unlike startup resolution, this does not discover Git, load project or
    /// user configuration, or consult the process working directory. It is
    /// primarily useful for deterministic embedded/test hosts that already
    /// own both decisions.
    pub fn explicit(root: &Path, graph_dir: &Path) -> Result<Self, ProjectRootError> {
        let root = canonical_directory(root, "explicit project root")?;
        let selected_graph_dir = anchor_expanded_path(graph_dir, &root);
        let graph_dir = select_graph_directory(&root, &selected_graph_dir, GraphSource::Cli)?;
        Ok(Self {
            root,
            graph_dir,
            root_source: RootSource::Explicit,
            graph_source: GraphSource::Cli,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn graph_dir(&self) -> &Path {
        &self.graph_dir
    }

    pub const fn root_source(&self) -> RootSource {
        self.root_source
    }

    pub const fn graph_source(&self) -> GraphSource {
        self.graph_source
    }

    /// Whether startup explicitly authorized a graph directory outside root.
    pub const fn graph_dir_may_be_external(&self) -> bool {
        matches!(
            self.graph_source,
            GraphSource::Cli | GraphSource::ProjectConfig | GraphSource::UserConfig
        )
    }

    /// Prepare the selected graph directory for an admitted writer.
    ///
    /// Binding construction is deliberately read-only. The immutable indexing
    /// plan calls this method only after its adapter has selected a write
    /// operation, keeping ordinary query/startup paths free of filesystem
    /// creation and managed-ignore updates.
    pub fn prepare_graph_directory_write(&self) -> Result<(), ProjectRootError> {
        if self.graph_source == GraphSource::RepoDefault {
            prepare_managed_graph_dir(&self.root, &self.graph_dir)?;
        } else {
            match inspect_generated_directory(&self.graph_dir)
                .map_err(ProjectRootError::UnsafeGraphDestination)?
            {
                GeneratedDirectoryState::Absent => {
                    fs::create_dir_all(&self.graph_dir).map_err(|source| ProjectRootError::Io {
                        operation: "create explicit graph directory",
                        path: self.graph_dir.clone(),
                        source,
                    })?;
                }
                GeneratedDirectoryState::Directory => {}
            }
            // Recheck after creation so a replaced final component is never
            // accepted merely because the caller explicitly selected it.
            inspect_generated_directory(&self.graph_dir)
                .map_err(ProjectRootError::UnsafeGraphDestination)?;
            canonical_directory(&self.graph_dir, "explicit graph directory")?;
        }
        Ok(())
    }

    /// Resolve an existing caller- or graph-supplied path beneath the project.
    pub fn resolve_existing_path(&self, raw: &Path) -> Result<PathBuf, ProjectPathError> {
        reject_parent_components(raw)?;
        let selected = anchor_expanded_path(raw, &self.root);
        let canonical = fs::canonicalize(&selected).map_err(|source| ProjectPathError::Io {
            operation: "canonicalize project path",
            path: selected,
            source,
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(ProjectPathError::Escape {
                root: self.root.clone(),
                path: canonical,
            });
        }
        Ok(canonical)
    }

    /// Read one existing project file through a root directory capability.
    ///
    /// The returned path is the canonical in-root path used for diagnostics.
    /// The actual open is descriptor-relative, so a symlink or ancestor swap
    /// cannot redirect the read beyond the bound project after validation.
    #[cfg(feature = "code-intel")]
    pub fn read_existing_file_bounded(
        &self,
        raw: &Path,
        max_bytes: u64,
    ) -> Result<(PathBuf, Vec<u8>), ProjectPathError> {
        let canonical = self.resolve_existing_path(raw)?;
        let relative =
            canonical
                .strip_prefix(&self.root)
                .map_err(|_| ProjectPathError::Escape {
                    root: self.root.clone(),
                    path: canonical.clone(),
                })?;
        let directory =
            cap_std::fs::Dir::open_ambient_dir(&self.root, cap_std::ambient_authority()).map_err(
                |source| ProjectPathError::Io {
                    operation: "open project root capability",
                    path: self.root.clone(),
                    source,
                },
            )?;
        let mut file = directory
            .open(relative)
            .map_err(|source| ProjectPathError::Io {
                operation: "open project file",
                path: canonical.clone(),
                source,
            })?;
        let metadata = file.metadata().map_err(|source| ProjectPathError::Io {
            operation: "inspect project file",
            path: canonical.clone(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(ProjectPathError::NonRegularSource { path: canonical });
        }
        if metadata.len() > max_bytes {
            return Err(ProjectPathError::SourceFileTooLarge {
                path: canonical,
                bytes: metadata.len(),
                max_bytes,
            });
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| ProjectPathError::Io {
                operation: "read project file",
                path: canonical.clone(),
                source,
            })?;
        if bytes.len() as u64 > max_bytes {
            return Err(ProjectPathError::SourceFileTooLarge {
                path: canonical,
                bytes: bytes.len() as u64,
                max_bytes,
            });
        }
        Ok((canonical, bytes))
    }

    /// Resolve a create/replace destination beneath the project. Existing
    /// symlinks are canonicalized; new files are authorized through their
    /// canonical parent plus a single normal final component.
    pub fn resolve_destination(&self, raw: &Path) -> Result<PathBuf, ProjectPathError> {
        reject_parent_components(raw)?;
        let selected = anchor_expanded_path(raw, &self.root);
        match fs::symlink_metadata(&selected) {
            Ok(_) => return self.resolve_existing_path(&selected),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ProjectPathError::Io {
                    operation: "inspect project destination",
                    path: selected,
                    source,
                });
            }
        }
        let name = selected
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ProjectPathError::InvalidDestination {
                path: selected.clone(),
            })?;
        let parent = selected
            .parent()
            .ok_or_else(|| ProjectPathError::InvalidDestination {
                path: selected.clone(),
            })?;
        let canonical_parent = fs::canonicalize(parent).map_err(|source| ProjectPathError::Io {
            operation: "canonicalize destination parent",
            path: parent.to_path_buf(),
            source,
        })?;
        if !canonical_parent.starts_with(&self.root) {
            return Err(ProjectPathError::Escape {
                root: self.root.clone(),
                path: canonical_parent.join(name),
            });
        }
        Ok(canonical_parent.join(name))
    }

    /// Refuse an unsafe or tracked generated graph directory. Existing
    /// directory-shaped outputs are admissible so repeated publication can
    /// advance the immutable head; files, symlinks, and other shapes are not.
    pub fn ensure_graph_directory_write(
        &self,
        directory_name: &str,
    ) -> Result<(), ProjectPathError> {
        inspect_generated_directory(&self.graph_dir)?;
        let path = self.graph_dir.join(directory_name);
        inspect_generated_directory(&path)?;
        if self.graph_source == GraphSource::RepoDefault {
            self.generated_directory_hygiene(&path)?;
        }
        Ok(())
    }

    fn checked_generated_directory_path(&self, path: &Path) -> Result<PathBuf, ProjectPathError> {
        reject_parent_components(path)?;
        let selected = anchor_expanded_path(path, &self.root);
        if !selected.starts_with(&self.root) {
            return Err(ProjectPathError::Escape {
                root: self.root.clone(),
                path: selected,
            });
        }
        inspect_generated_directory(&selected)?;
        Ok(selected)
    }

    /// Check whether an owned generated directory or any tracked descendant
    /// would be overwritten by a managed-default writer.
    pub fn generated_directory_hygiene(
        &self,
        path: &Path,
    ) -> Result<ArtifactHygiene, ProjectPathError> {
        let selected = self.checked_generated_directory_path(path)?;
        self.generated_path_hygiene(selected)
    }

    fn generated_path_hygiene(
        &self,
        selected: PathBuf,
    ) -> Result<ArtifactHygiene, ProjectPathError> {
        let relative = selected
            .strip_prefix(&self.root)
            .map_err(|_| ProjectPathError::Escape {
                root: self.root.clone(),
                path: selected.clone(),
            })?;

        let inside_repo = std::process::Command::new("git")
            .args(["-C"])
            .arg(&self.root)
            .args(["rev-parse", "--is-inside-work-tree"])
            .output();
        if !inside_repo.is_ok_and(|output| output.status.success()) {
            return Ok(ArtifactHygiene::NonGit);
        }

        let tracked = std::process::Command::new("git")
            .args(["-C"])
            .arg(&self.root)
            .args(["ls-files", "--error-unmatch", "--"])
            .arg(relative)
            .output()
            .map_err(|source| ProjectPathError::Io {
                operation: "check whether generated artifact is tracked",
                path: selected.clone(),
                source,
            })?;
        if tracked.status.success() {
            return Err(ProjectPathError::TrackedGenerated { path: selected });
        }

        let ignored = std::process::Command::new("git")
            .args(["-C"])
            .arg(&self.root)
            .args(["check-ignore", "-q", "--"])
            .arg(relative)
            .status()
            .map_err(|source| ProjectPathError::Io {
                operation: "check whether generated artifact is ignored",
                path: selected,
                source,
            })?;
        Ok(if ignored.success() {
            ArtifactHygiene::Ignored
        } else {
            ArtifactHygiene::Unignored
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactHygiene {
    Ignored,
    Unignored,
    NonGit,
}

/// Raw inputs accepted before the single binding decision.
#[derive(Debug, Clone, Copy)]
pub struct ProjectBindingOptions<'a> {
    startup_dir: &'a Path,
    explicit_root: Option<&'a Path>,
    subcommand_graph_dir: Option<&'a Path>,
    global_graph_dir: Option<&'a Path>,
}

impl<'a> ProjectBindingOptions<'a> {
    pub const fn new(startup_dir: &'a Path) -> Self {
        Self {
            startup_dir,
            explicit_root: None,
            subcommand_graph_dir: None,
            global_graph_dir: None,
        }
    }

    pub const fn explicit_root(mut self, root: &'a Path) -> Self {
        self.explicit_root = Some(root);
        self
    }

    pub const fn subcommand_graph_dir(mut self, path: &'a Path) -> Self {
        self.subcommand_graph_dir = Some(path);
        self
    }

    pub const fn global_graph_dir(mut self, path: &'a Path) -> Self {
        self.global_graph_dir = Some(path);
        self
    }
}

#[derive(Debug, Error)]
pub enum ProjectRootError {
    #[error(
        "no repository root found from {startup_dir}; pass --root <directory> to select a non-git workspace"
    )]
    NoRepository { startup_dir: PathBuf },

    #[error("{label} is not a directory: {path}")]
    NotDirectory { label: &'static str, path: PathBuf },

    #[error("graph.path may not be empty")]
    EmptyGraphPath,

    #[error(
        "managed graph directory escapes project root: root={root}, graph_dir={graph_dir}; use an explicit --data-dir if external placement is intentional"
    )]
    ManagedPathEscape { root: PathBuf, graph_dir: PathBuf },

    #[error("refusing symlinked managed graph artifact {path}")]
    SymlinkedManagedArtifact { path: PathBuf },

    #[error("managed graph artifact {path} must be a {expected}")]
    InvalidManagedArtifactShape {
        path: PathBuf,
        expected: &'static str,
    },

    #[error("unsafe graph directory destination: {0}")]
    UnsafeGraphDestination(#[source] ProjectPathError),

    #[error("managed ignore file {path} is not the safe tool-owned form; it was not overwritten")]
    InvalidManagedIgnore { path: PathBuf },

    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("project configuration failed: {0}")]
    Config(#[from] ConfigError),
}

#[derive(Debug, Error)]
pub enum ProjectPathError {
    #[error("project path contains a forbidden `..` component: {path}")]
    ParentTraversal { path: PathBuf },

    #[error("path escapes project root: root={root}, path={path}")]
    Escape { root: PathBuf, path: PathBuf },

    #[error("invalid project destination: {path}")]
    InvalidDestination { path: PathBuf },

    #[error(
        "refusing to overwrite tracked generated artifact {path}; untrack it or select an explicit graph directory"
    )]
    TrackedGenerated { path: PathBuf },

    #[error("refusing symlinked generated artifact {path}")]
    SymlinkedGenerated { path: PathBuf },

    #[error("refusing non-regular generated artifact {path}")]
    NonRegularGenerated { path: PathBuf },

    #[error("refusing non-directory generated artifact {path}")]
    NonDirectoryGenerated { path: PathBuf },

    #[error("refusing non-regular project source {path}")]
    NonRegularSource { path: PathBuf },

    #[error("project source {path} is {bytes} bytes, exceeding the {max_bytes}-byte read limit")]
    SourceFileTooLarge {
        path: PathBuf,
        bytes: u64,
        max_bytes: u64,
    },

    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Return the nearest ancestor containing `.git` as a directory or file.
pub fn discover_repository_root(startup_dir: &Path) -> Result<Option<PathBuf>, ProjectRootError> {
    let start = canonical_directory(startup_dir, "startup directory")?;
    for candidate in start.ancestors() {
        let marker = candidate.join(".git");
        match fs::metadata(&marker) {
            Ok(metadata) if metadata.is_dir() || metadata.is_file() => {
                return Ok(Some(candidate.to_path_buf()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ProjectRootError::Io {
                    operation: "inspect repository marker",
                    path: marker,
                    source,
                });
            }
        }
    }
    Ok(None)
}

fn anchor_expanded_path(raw: &Path, anchor: &Path) -> PathBuf {
    let expanded = PathBuf::from(expand_path(&raw.to_string_lossy()));
    if expanded.is_absolute() {
        expanded
    } else {
        anchor.join(expanded)
    }
}

fn reject_parent_components(path: &Path) -> Result<(), ProjectPathError> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(ProjectPathError::ParentTraversal {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn canonical_directory(path: &Path, label: &'static str) -> Result<PathBuf, ProjectRootError> {
    let canonical = fs::canonicalize(path).map_err(|source| ProjectRootError::Io {
        operation: "canonicalize path",
        path: path.to_path_buf(),
        source,
    })?;
    if !canonical.is_dir() {
        return Err(ProjectRootError::NotDirectory {
            label,
            path: canonical,
        });
    }
    Ok(canonical)
}

fn select_graph_directory(
    root: &Path,
    selected_graph_dir: &Path,
    graph_source: GraphSource,
) -> Result<PathBuf, ProjectRootError> {
    if graph_source == GraphSource::RepoDefault {
        validate_managed_graph_destination(root, selected_graph_dir)?;
    }

    match fs::symlink_metadata(selected_graph_dir) {
        Ok(metadata) if metadata.file_type().is_dir() || metadata.file_type().is_symlink() => {
            canonical_directory(selected_graph_dir, "graph directory")
        }
        Ok(_) => Err(ProjectRootError::NotDirectory {
            label: "graph directory",
            path: selected_graph_dir.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(selected_graph_dir.to_path_buf())
        }
        Err(source) => Err(ProjectRootError::Io {
            operation: "inspect graph directory",
            path: selected_graph_dir.to_path_buf(),
            source,
        }),
    }
}

fn validate_managed_graph_destination(
    root: &Path,
    selected_graph_dir: &Path,
) -> Result<(), ProjectRootError> {
    let relative =
        selected_graph_dir
            .strip_prefix(root)
            .map_err(|_| ProjectRootError::ManagedPathEscape {
                root: root.to_path_buf(),
                graph_dir: selected_graph_dir.to_path_buf(),
            })?;
    if relative
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(ProjectRootError::ManagedPathEscape {
            root: root.to_path_buf(),
            graph_dir: selected_graph_dir.to_path_buf(),
        });
    }

    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ProjectRootError::SymlinkedManagedArtifact { path: current });
            }
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(ProjectRootError::NotDirectory {
                    label: "managed graph path component",
                    path: current,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(ProjectRootError::Io {
                    operation: "inspect managed graph path component",
                    path: current,
                    source,
                });
            }
        }
    }

    if selected_graph_dir.is_dir() {
        ensure_managed_artifact_shapes(selected_graph_dir)?;
    }
    Ok(())
}

fn prepare_managed_graph_dir(
    root: &Path,
    selected_graph_dir: &Path,
) -> Result<PathBuf, ProjectRootError> {
    validate_managed_graph_destination(root, selected_graph_dir)?;
    // Validate every existing ancestor before creating children. This makes a
    // symlinked `.h00` escape fail before writing an ignore file outside root.
    let mut existing = selected_graph_dir;
    while !existing.exists() {
        existing = existing
            .parent()
            .ok_or_else(|| ProjectRootError::ManagedPathEscape {
                root: root.to_path_buf(),
                graph_dir: selected_graph_dir.to_path_buf(),
            })?;
    }
    let canonical_existing = fs::canonicalize(existing).map_err(|source| ProjectRootError::Io {
        operation: "canonicalize managed graph ancestor",
        path: existing.to_path_buf(),
        source,
    })?;
    if !canonical_existing.starts_with(root) {
        return Err(ProjectRootError::ManagedPathEscape {
            root: root.to_path_buf(),
            graph_dir: canonical_existing,
        });
    }

    fs::create_dir_all(selected_graph_dir).map_err(|source| ProjectRootError::Io {
        operation: "create managed graph directory",
        path: selected_graph_dir.to_path_buf(),
        source,
    })?;
    let graph_dir = canonical_directory(selected_graph_dir, "managed graph directory")?;
    if !graph_dir.starts_with(root) {
        return Err(ProjectRootError::ManagedPathEscape {
            root: root.to_path_buf(),
            graph_dir,
        });
    }

    // Refuse unsafe pre-existing output shapes before creating or rewriting
    // any managed control file in this directory.
    ensure_managed_artifact_shapes(&graph_dir)?;
    ensure_managed_ignore(&graph_dir)?;
    Ok(graph_dir)
}

fn ensure_managed_artifact_shapes(graph_dir: &Path) -> Result<(), ProjectRootError> {
    for child in GRAPH_AUXILIARY_DIRECTORIES
        .into_iter()
        .chain([IMMUTABLE_PUBLICATION_DIRECTORY])
    {
        let path = graph_dir.join(child);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ProjectRootError::SymlinkedManagedArtifact { path });
            }
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(ProjectRootError::InvalidManagedArtifactShape {
                    path,
                    expected: "directory",
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ProjectRootError::Io {
                    operation: "inspect managed graph directory",
                    path,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn ensure_managed_ignore(graph_dir: &Path) -> Result<(), ProjectRootError> {
    const CONTENTS: &str = "*\n!.gitignore\n";

    let path = graph_dir.join(".gitignore");
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(CONTENTS.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|source| ProjectRootError::Io {
                    operation: "write managed ignore file",
                    path: path.clone(),
                    source,
                })?;
            sync_directory(graph_dir)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&path).map_err(|source| ProjectRootError::Io {
                operation: "inspect managed ignore file",
                path: path.clone(),
                source,
            })?;
            if !metadata.file_type().is_file() {
                return Err(ProjectRootError::InvalidManagedIgnore { path });
            }
            let contents = fs::read_to_string(&path).map_err(|source| ProjectRootError::Io {
                operation: "read managed ignore file",
                path: path.clone(),
                source,
            })?;
            if contents != CONTENTS {
                return Err(ProjectRootError::InvalidManagedIgnore { path });
            }
        }
        Err(source) => {
            return Err(ProjectRootError::Io {
                operation: "create managed ignore file",
                path,
                source,
            });
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ProjectRootError> {
    let directory = fs::File::open(path).map_err(|source| ProjectRootError::Io {
        operation: "open directory for sync",
        path: path.to_path_buf(),
        source,
    })?;
    directory.sync_all().map_err(|source| ProjectRootError::Io {
        operation: "sync directory",
        path: path.to_path_buf(),
        source,
    })
}
