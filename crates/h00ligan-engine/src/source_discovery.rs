//! One deterministic repository source-population boundary.
//!
//! Indexing and workspace diff both consume this walk. A source path is
//! therefore either admitted by both operations or rejected by both; adapters
//! do not get to invent their own language, ignore, or symlink policy.

#[cfg(test)]
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SourceDiscoveryError {
    #[error("source discovery root {search_root} is outside workspace {workspace_root}")]
    EscapedSearchRoot {
        workspace_root: PathBuf,
        search_root: PathBuf,
    },

    #[error("invalid source exclusion pattern `{pattern}`: {source}")]
    InvalidExclusion {
        pattern: String,
        #[source]
        source: ignore::Error,
    },

    #[error("source discovery failed: {0}")]
    Walk(#[source] ignore::Error),

    #[error("refusing symlinked source file during repository discovery: {path}")]
    SymlinkedSource { path: PathBuf },
}

#[cfg(test)]
#[derive(Default)]
struct TestDiscoveryProbe {
    threads: usize,
    delay: bool,
    in_flight: usize,
    max_in_flight: usize,
}

#[cfg(test)]
fn test_discovery_probes() -> &'static Mutex<HashMap<PathBuf, TestDiscoveryProbe>> {
    static PROBES: OnceLock<Mutex<HashMap<PathBuf, TestDiscoveryProbe>>> = OnceLock::new();
    PROBES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
struct TestDiscoveryFlightGuard {
    root: Option<PathBuf>,
}

#[cfg(test)]
struct TestDiscoveryConfigGuard {
    root: PathBuf,
}

#[cfg(test)]
impl TestDiscoveryConfigGuard {
    fn parallel_probe(root: &Path) -> Self {
        let root = root.to_path_buf();
        let previous = test_discovery_probes()
            .lock()
            .expect("source-discovery probe state")
            .insert(
                root.clone(),
                TestDiscoveryProbe {
                    threads: 4,
                    delay: true,
                    ..TestDiscoveryProbe::default()
                },
            );
        assert!(previous.is_none(), "duplicate source-discovery probe root");
        Self { root }
    }
}

#[cfg(test)]
impl Drop for TestDiscoveryConfigGuard {
    fn drop(&mut self) {
        test_discovery_probes()
            .lock()
            .expect("source-discovery probe state")
            .remove(&self.root);
    }
}

#[cfg(test)]
impl TestDiscoveryFlightGuard {
    fn enter(root: &Path) -> Self {
        let delay = {
            let mut probes = test_discovery_probes()
                .lock()
                .expect("source-discovery probe state");
            let Some(probe) = probes.get_mut(root) else {
                return Self { root: None };
            };
            probe.in_flight = probe.in_flight.saturating_add(1);
            probe.max_in_flight = probe.max_in_flight.max(probe.in_flight);
            let delay = probe.delay;
            drop(probes);
            delay
        };
        if delay {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        Self {
            root: Some(root.to_path_buf()),
        }
    }
}

#[cfg(test)]
impl Drop for TestDiscoveryFlightGuard {
    fn drop(&mut self) {
        let Some(root) = &self.root else {
            return;
        };
        let mut probes = test_discovery_probes()
            .lock()
            .expect("source-discovery probe state");
        if let Some(probe) = probes.get_mut(root) {
            probe.in_flight = probe.in_flight.saturating_sub(1);
        }
        drop(probes);
    }
}

#[cfg(test)]
fn test_discovery_max_in_flight(root: &Path) -> usize {
    test_discovery_probes()
        .lock()
        .expect("source-discovery probe state")
        .get(root)
        .map_or(0, |probe| probe.max_in_flight)
}

/// Walk `root` using Git/hidden ignore policy and return supported regular
/// files in deterministic path order.
///
/// A symlink whose name has a supported extension is a hard error. Following
/// it would let repository coverage depend on bytes outside the selected root;
/// silently skipping it would falsely claim complete coverage.
pub fn discover_source_files(
    root: &Path,
    extensions: &HashSet<String>,
    exclusion_patterns: &[String],
) -> Result<Vec<PathBuf>, SourceDiscoveryError> {
    discover_source_files_beneath(root, root, extensions, exclusion_patterns)
}

/// Apply the workspace's discovery policy to one confined file or subtree.
pub fn discover_source_files_beneath(
    workspace_root: &Path,
    search_root: &Path,
    extensions: &HashSet<String>,
    exclusion_patterns: &[String],
) -> Result<Vec<PathBuf>, SourceDiscoveryError> {
    #[derive(Default)]
    struct Observations {
        paths: Vec<PathBuf>,
        symlinked_sources: Vec<PathBuf>,
        walk_errors: Vec<(String, ignore::Error)>,
    }

    let builder =
        configured_source_walk_builder(workspace_root, search_root, exclusion_patterns, &[])?;
    let observations = Arc::new(Mutex::new(Observations::default()));
    #[cfg(test)]
    let probe_root = Arc::new(workspace_root.to_path_buf());
    builder.build_parallel().run(|| {
        let observations = Arc::clone(&observations);
        #[cfg(test)]
        let probe_root = Arc::clone(&probe_root);
        Box::new(move |entry| {
            let mut observation = None;
            match entry {
                Err(error) => {
                    let label = error.to_string();
                    observations
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .walk_errors
                        .push((label, error));
                }
                Ok(entry) => {
                    let path = entry.path();
                    let supported = path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| extensions.contains(extension));
                    if supported {
                        #[cfg(test)]
                        let _flight = TestDiscoveryFlightGuard::enter(&probe_root);
                        if let Some(file_type) = entry.file_type() {
                            if file_type.is_symlink() {
                                observation = Some((path.to_path_buf(), true));
                            } else if file_type.is_file() {
                                observation = Some((path.to_path_buf(), false));
                            }
                        }
                    }
                }
            }
            if let Some((path, symlinked)) = observation {
                let mut observations = observations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if symlinked {
                    observations.symlinked_sources.push(path);
                } else {
                    observations.paths.push(path);
                }
            }
            ignore::WalkState::Continue
        })
    });
    let mut observations = std::mem::take(
        &mut *observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    observations
        .walk_errors
        .sort_by(|left, right| left.0.cmp(&right.0));
    if let Some((_, error)) = observations.walk_errors.into_iter().next() {
        return Err(SourceDiscoveryError::Walk(error));
    }
    observations.symlinked_sources.sort();
    if let Some(path) = observations.symlinked_sources.into_iter().next() {
        return Err(SourceDiscoveryError::SymlinkedSource { path });
    }
    observations.paths.sort();
    Ok(observations.paths)
}

/// Return the existing non-symlink directories admitted by source discovery.
///
/// WATCH registers these directories non-recursively so ignored build trees
/// never consume native watcher resources. `pruned_roots` additionally removes
/// selected generated state such as a custom code-intelligence data directory.
pub fn discover_source_directories(
    workspace_root: &Path,
    exclusion_patterns: &[String],
    pruned_roots: &[PathBuf],
) -> Result<Vec<PathBuf>, SourceDiscoveryError> {
    if pruned_roots
        .iter()
        .any(|pruned| workspace_root.starts_with(pruned))
    {
        return Ok(Vec::new());
    }
    let walker = configured_source_walk_builder(
        workspace_root,
        workspace_root,
        exclusion_patterns,
        pruned_roots,
    )?
    .build();
    let mut directories = Vec::new();
    for entry in walker {
        let entry = entry.map_err(SourceDiscoveryError::Walk)?;
        if entry
            .file_type()
            .is_some_and(|file_type| file_type.is_dir())
        {
            directories.push(entry.into_path());
        }
    }
    directories.sort();
    directories.dedup();
    Ok(directories)
}

fn configured_source_walk_builder(
    workspace_root: &Path,
    search_root: &Path,
    exclusion_patterns: &[String],
    pruned_roots: &[PathBuf],
) -> Result<ignore::WalkBuilder, SourceDiscoveryError> {
    if !search_root.starts_with(workspace_root) {
        return Err(SourceDiscoveryError::EscapedSearchRoot {
            workspace_root: workspace_root.to_path_buf(),
            search_root: search_root.to_path_buf(),
        });
    }
    let mut builder = ignore::WalkBuilder::new(search_root);
    #[cfg(test)]
    {
        let threads = test_discovery_probes()
            .lock()
            .expect("source-discovery probe state")
            .get(workspace_root)
            .map_or(0, |probe| probe.threads);
        if threads > 0 {
            builder.threads(threads);
        }
    }
    // Explicit project roots need not contain `.git` metadata (exported source,
    // fixtures, and detached package roots are all valid inputs). Still honor
    // the ignore policy selected with that root; otherwise generated source can
    // enter the indexed population merely because no VCS directory is present.
    builder
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .parents(true)
        .require_git(false)
        .follow_links(false);

    if !pruned_roots.is_empty() {
        let pruned_roots = pruned_roots.to_vec();
        builder.filter_entry(move |entry| {
            !pruned_roots
                .iter()
                .any(|pruned| entry.path().starts_with(pruned))
        });
    }

    let mut effective_exclusions = exclusion_patterns.to_vec();
    if workspace_root.join("Cargo.toml").is_file() {
        // Cargo owns the root-level `target/` tree even when an exported or
        // freshly-created project has no `.gitignore`. Keep this anchored to
        // the selected Cargo root: a user source directory merely named
        // `target` below `src/` is not build output.
        effective_exclusions.push("/target/**".to_string());
    }

    if !effective_exclusions.is_empty() {
        let mut overrides = ignore::overrides::OverrideBuilder::new(workspace_root);
        for pattern in &effective_exclusions {
            overrides.add(&format!("!{pattern}")).map_err(|source| {
                SourceDiscoveryError::InvalidExclusion {
                    pattern: pattern.clone(),
                    source,
                }
            })?;
        }
        let built = overrides.build().map_err(SourceDiscoveryError::Walk)?;
        builder.overrides(built);
    }
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FALSIFIER: repository traversal must retain deterministic output while
    /// allowing independent admitted source entries to be processed in
    /// parallel.
    #[test]
    #[serial_test::serial]
    fn source_discovery_processes_independent_entries_concurrently() {
        let temporary = tempfile::tempdir().expect("temporary repository");
        let source = temporary.path().join("src");
        std::fs::create_dir(&source).expect("source directory");
        for index in 0..24 {
            std::fs::write(
                source.join(format!("file_{index:02}.rs")),
                format!("pub fn item_{index:02}() {{}}\n"),
            )
            .expect("source fixture");
        }

        let _config = TestDiscoveryConfigGuard::parallel_probe(temporary.path());
        let discovered =
            discover_source_files(temporary.path(), &HashSet::from(["rs".to_string()]), &[])
                .expect("parallel source discovery");

        assert_eq!(discovered.len(), 24, "positive source-population control");
        assert!(
            test_discovery_max_in_flight(temporary.path()) > 1,
            "positive multi-thread control must observe overlapping source entries"
        );
    }

    #[test]
    fn ignored_generated_target_sources_are_excluded_at_the_shared_discovery_boundary() {
        let temporary = tempfile::tempdir().expect("temporary repository");
        std::fs::create_dir_all(temporary.path().join("src")).expect("source directory");
        std::fs::create_dir_all(temporary.path().join("target/generated"))
            .expect("generated directory");
        std::fs::write(temporary.path().join(".gitignore"), "/target/\n")
            .expect("repository ignore policy");
        let source = temporary.path().join("src/lib.rs");
        std::fs::write(&source, "pub fn source() {}\n").expect("source file");
        std::fs::write(
            temporary.path().join("target/generated/out.rs"),
            "pub fn generated() {}\n",
        )
        .expect("generated file");

        let discovered =
            discover_source_files(temporary.path(), &HashSet::from(["rs".to_string()]), &[])
                .expect("source discovery");
        assert_eq!(discovered, vec![source]);
    }

    #[test]
    fn a_source_directory_named_target_is_not_globally_treated_as_build_output() {
        let temporary = tempfile::tempdir().expect("temporary repository");
        std::fs::create_dir_all(temporary.path().join("src/domain/target"))
            .expect("nested source directory");
        std::fs::create_dir_all(temporary.path().join("target/generated"))
            .expect("Cargo build-output directory");
        std::fs::write(
            temporary.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo manifest");
        let control = temporary.path().join("src/lib.rs");
        let nested = temporary.path().join("src/domain/target/model.rs");
        std::fs::write(&control, "pub fn control() {}\n").expect("control source");
        std::fs::write(&nested, "pub fn model() {}\n").expect("nested source");
        std::fs::write(
            temporary.path().join("target/generated/out.rs"),
            "pub fn generated() {}\n",
        )
        .expect("generated source");

        let discovered =
            discover_source_files(temporary.path(), &HashSet::from(["rs".to_string()]), &[])
                .expect("source discovery");
        assert_eq!(
            discovered,
            vec![nested, control],
            "only Cargo's root-level build-output tree is excluded; a nested path component named `target` is not proof of generated output"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_discovery_still_rejects_supported_source_symlinks() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary repository");
        let outside = tempfile::tempdir().expect("outside directory");
        std::fs::create_dir_all(temporary.path().join("src")).expect("source directory");
        std::fs::write(
            temporary.path().join("src/lib.rs"),
            "pub fn positive_control() {}\n",
        )
        .expect("ordinary source positive control");
        let outside_source = outside.path().join("outside.rs");
        std::fs::write(&outside_source, "pub fn outside() {}\n").expect("outside source");
        let symlink_path = temporary.path().join("src/linked.rs");
        symlink(&outside_source, &symlink_path).expect("source symlink");

        let error =
            discover_source_files(temporary.path(), &HashSet::from(["rs".to_string()]), &[])
                .expect_err("source symlinks cannot enter complete repository authority");
        assert!(matches!(
            error,
            SourceDiscoveryError::SymlinkedSource { path } if path == symlink_path
        ));
    }

    #[test]
    fn scoped_discovery_retains_workspace_anchored_generated_output_policy() {
        let temporary = tempfile::tempdir().expect("temporary repository");
        std::fs::create_dir_all(temporary.path().join("src")).expect("source directory");
        std::fs::create_dir_all(temporary.path().join("target/generated"))
            .expect("generated directory");
        std::fs::write(
            temporary.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo manifest");
        std::fs::write(temporary.path().join("src/lib.rs"), "pub fn source() {}\n")
            .expect("source file");
        std::fs::write(
            temporary.path().join("target/generated/out.rs"),
            "pub fn generated() {}\n",
        )
        .expect("generated source");

        let discovered = discover_source_files_beneath(
            temporary.path(),
            &temporary.path().join("target"),
            &HashSet::from(["rs".to_string()]),
            &[],
        )
        .expect("scoped discovery");
        assert!(
            discovered.is_empty(),
            "a scoped walk must not bypass the workspace's root-level target exclusion: {discovered:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unrelated_symlinked_source_does_not_block_a_confined_scope() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary repository");
        let outside = tempfile::tempdir().expect("outside directory");
        std::fs::create_dir_all(temporary.path().join("src")).expect("source directory");
        std::fs::create_dir_all(temporary.path().join("other")).expect("other directory");
        let source = temporary.path().join("src/lib.rs");
        std::fs::write(&source, "pub fn source() {}\n").expect("source file");
        std::fs::write(outside.path().join("external.rs"), "pub fn external() {}\n")
            .expect("external source");
        symlink(
            outside.path().join("external.rs"),
            temporary.path().join("other/external.rs"),
        )
        .expect("unrelated source symlink");

        let discovered = discover_source_files_beneath(
            temporary.path(),
            &temporary.path().join("src"),
            &HashSet::from(["rs".to_string()]),
            &[],
        )
        .expect("confined source discovery");
        assert_eq!(discovered, vec![source]);
    }
}
