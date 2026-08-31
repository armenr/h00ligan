//! Repository-identity admission for immutable h00ligan publication.
//!
//! `h00ligan index` binds a selected data directory to one repository identity
//! and exposes no destructive adoption mode. Root-level SCIP artifacts and publications owned by another repository remain
//! outside the standalone contract and are never adopted implicitly.
//!
//! Every command crosses the shipped binary and uses a fresh project plus an
//! explicit scratch data directory. Nothing here can address the user store.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

#[derive(Debug, Eq, PartialEq)]
enum ArtifactSnapshot {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
    Other,
}

fn path_population(root: &Path) -> BTreeMap<PathBuf, ArtifactSnapshot> {
    fn collect(root: &Path, current: &Path, population: &mut BTreeMap<PathBuf, ArtifactSnapshot>) {
        let mut entries = std::fs::read_dir(current)
            .unwrap_or_else(|error| panic!("read {}: {error}", current.display()))
            .map(|entry| entry.expect("directory entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::path);

        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .expect("population-relative path")
                .to_path_buf();
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("classify {}: {error}", path.display()));
            let snapshot = if file_type.is_dir() {
                ArtifactSnapshot::Directory
            } else if file_type.is_file() {
                ArtifactSnapshot::File(
                    std::fs::read(&path)
                        .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
                )
            } else if file_type.is_symlink() {
                ArtifactSnapshot::Symlink(
                    std::fs::read_link(&path)
                        .unwrap_or_else(|error| panic!("read link {}: {error}", path.display())),
                )
            } else {
                ArtifactSnapshot::Other
            };
            population.insert(relative, snapshot);
            if file_type.is_dir() {
                collect(root, &path, population);
            }
        }
    }

    assert!(root.is_dir(), "population root must be a directory");
    let mut population = BTreeMap::new();
    collect(root, root, &mut population);
    population
}

fn make_repo(pkg: &str, unique_fn: &str) -> TempDir {
    let directory = TempDir::new().expect("temporary repository");
    std::fs::create_dir_all(directory.path().join("src")).expect("source directory");
    std::fs::write(
        directory.path().join("Cargo.toml"),
        format!("[package]\nname = \"{pkg}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
    )
    .expect("Cargo manifest");
    std::fs::write(
        directory.path().join("src/lib.rs"),
        format!("pub fn {unique_fn}() -> u32 {{ 1 }}\n"),
    )
    .expect("Rust source");
    directory
}

fn run_index(root: &Path, data_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("index")
        .output()
        .expect("spawn h00ligan index")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn immutable_index_refuses_a_different_root_without_mutating_either_population() {
    let store = TempDir::new().expect("scratch data directory");
    let repo_a = make_repo("repo_a", "alpha_only_fn");
    let repo_b = make_repo("repo_b", "beta_only_fn");

    let first = run_index(repo_a.path(), store.path());
    assert!(
        first.status.success(),
        "fresh immutable publication must succeed: {}",
        stderr_of(&first)
    );
    let publication = store
        .path()
        .join(h00ligan_engine::code_intel_publication::PUBLICATION_DIRECTORY);
    assert!(
        publication.join("repository.json").is_file(),
        "known-positive control must cross the shipped immutable writer"
    );
    for obsolete in [
        "graph.redb",
        "index.redb",
        "graph-write.lock",
        "reindex.incomplete",
    ] {
        assert!(
            !store.path().join(obsolete).exists(),
            "normal indexing must not recreate retired {obsolete}"
        );
    }

    let scip_sentinel = b"FOREIGN_REPOSITORY_REFUSAL_MUST_NOT_TOUCH_THIS\n";
    std::fs::write(repo_b.path().join("index.scip"), scip_sentinel)
        .expect("query-root SCIP sentinel");
    let store_before = path_population(store.path());
    let query_before = path_population(repo_b.path());
    assert!(
        !store_before.is_empty() && !query_before.is_empty(),
        "both compared populations must have known-positive entries"
    );

    let refused = run_index(repo_b.path(), store.path());
    let message = stderr_of(&refused);
    assert!(
        !refused.status.success()
            && message.contains("belongs to repository")
            && message.contains("not selected root")
            && message.contains(
                repo_b
                    .path()
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            )
            && message.contains(publication.to_string_lossy().as_ref()),
        "foreign immutable publication must fail through repository identity; \
         status={} stdout={} stderr={message}",
        refused.status,
        String::from_utf8_lossy(&refused.stdout),
    );
    assert!(
        !message.contains("--adopt-foreign-origin"),
        "normal immutable indexing must not advertise destructive adoption"
    );
    assert_eq!(
        path_population(store.path()),
        store_before,
        "foreign-root refusal must preserve every selected-data-dir entry and file byte"
    );
    assert_eq!(
        path_population(repo_b.path()),
        query_before,
        "foreign-root refusal must preserve every querying-root entry and file byte"
    );

    let same_owner = run_index(repo_a.path(), store.path());
    assert!(
        same_owner.status.success(),
        "same-root repeat is the non-vacuity control: {}",
        stderr_of(&same_owner)
    );
}
