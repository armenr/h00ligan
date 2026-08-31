#![cfg(feature = "code-intel")]

use std::fs;
use std::path::Path;
use std::process::Command;

use h00ligan_engine::project_binding::{
    GeneratedArtifactState, GeneratedDirectoryState, GraphSource, PROVIDER_CACHE_DIRECTORY,
    ProjectBinding, ProjectBindingOptions, ProjectPathError, ProjectRootError, RootSource,
    inspect_generated_artifact, inspect_generated_directory,
};
use tempfile::TempDir;

fn mkdir(path: &Path) {
    fs::create_dir_all(path).expect("create fixture directory");
}

#[test]
fn discovers_the_same_git_root_from_root_and_nested_startup_directories() {
    let repo = TempDir::new().expect("scratch repo");
    mkdir(&repo.path().join(".git"));
    let nested = repo.path().join("crates/example/src");
    mkdir(&nested);

    let from_root = ProjectBinding::resolve(ProjectBindingOptions::new(repo.path()))
        .expect("resolve from repository root");
    let from_nested = ProjectBinding::resolve(ProjectBindingOptions::new(&nested))
        .expect("resolve from nested directory");

    assert_eq!(from_root.root(), repo.path().canonicalize().unwrap());
    assert_eq!(from_nested.root(), from_root.root());
    assert_eq!(from_root.graph_dir(), from_nested.graph_dir());
    assert_eq!(from_nested.root_source(), RootSource::Discovered);
    assert_eq!(from_nested.graph_source(), GraphSource::RepoDefault);
}

#[test]
fn resolving_a_repo_default_binding_does_not_create_managed_state() {
    let repo = TempDir::new().expect("scratch repo");
    mkdir(&repo.path().join(".git"));

    let binding = ProjectBinding::resolve(ProjectBindingOptions::new(repo.path()))
        .expect("resolve read-only project binding");
    let canonical_repo = repo.path().canonicalize().expect("canonical scratch repo");

    assert_eq!(
        binding.graph_dir(),
        canonical_repo.join(".h00ligan/code-intel")
    );
    assert!(
        !repo.path().join(".h00ligan").exists(),
        "selecting read authority must not create managed project state"
    );
}

#[test]
fn discovers_a_worktree_git_file() {
    let repo = TempDir::new().expect("scratch worktree");
    fs::write(
        repo.path().join(".git"),
        "gitdir: /tmp/fixture.git/worktrees/wt\n",
    )
    .expect("write worktree marker");
    let nested = repo.path().join("src");
    mkdir(&nested);

    let binding = ProjectBinding::resolve(ProjectBindingOptions::new(&nested))
        .expect("worktree marker is a repository boundary");

    assert_eq!(binding.root(), repo.path().canonicalize().unwrap());
    assert_eq!(binding.root_source(), RootSource::Discovered);
}

#[test]
fn implicit_non_git_fails_before_creating_scaffolding_but_explicit_non_git_works() {
    let workspace = TempDir::new().expect("scratch workspace");

    // The managed test host exposes `/tmp/.git`, so a TempDir is intentionally
    // a discovered worktree. Filesystem root has no qualifying ancestor and is
    // the deterministic implicit-non-git fixture.
    let error = ProjectBinding::resolve(ProjectBindingOptions::new(Path::new("/")))
        .expect_err("implicit non-git startup must fail");
    assert!(matches!(error, ProjectRootError::NoRepository { .. }));
    assert!(!workspace.path().join(".h00ligan").exists());

    let binding = ProjectBinding::resolve(
        ProjectBindingOptions::new(workspace.path()).explicit_root(workspace.path()),
    )
    .expect("an explicitly selected non-git workspace is valid");
    let canonical_workspace = workspace
        .path()
        .canonicalize()
        .expect("canonical explicit workspace");
    assert_eq!(binding.root_source(), RootSource::Explicit);
    assert_eq!(
        binding.graph_dir(),
        canonical_workspace.join(".h00ligan/code-intel")
    );
    assert!(!binding.graph_dir().exists());
}

#[test]
fn explicit_paths_anchor_the_graph_to_the_supplied_root_without_discovery() {
    let temporary = TempDir::new().expect("temporary workspace");
    let root = temporary.path().join("workspace");
    mkdir(&root);

    let binding = ProjectBinding::explicit(&root, Path::new("semantic-data"))
        .expect("explicit project and graph binding");
    let canonical_root = root.canonicalize().expect("canonical explicit root");

    assert_eq!(binding.root(), canonical_root);
    assert_eq!(binding.graph_dir(), canonical_root.join("semantic-data"));
    assert_eq!(binding.root_source(), RootSource::Explicit);
    assert_eq!(binding.graph_source(), GraphSource::Cli);
}

#[test]
fn explicit_binding_does_not_create_the_graph_destination() {
    let temporary = TempDir::new().expect("temporary workspace");
    let root = temporary.path().join("workspace");
    let graph = root.join("semantic-data");
    mkdir(&root);

    let binding = ProjectBinding::explicit(&root, Path::new("semantic-data"))
        .expect("explicit read-only binding");
    let canonical_graph = root
        .canonicalize()
        .expect("canonical explicit root")
        .join("semantic-data");

    assert_eq!(binding.graph_dir(), canonical_graph);
    assert!(
        !graph.exists(),
        "explicit binding selection must not create the writer destination"
    );
}

#[test]
fn explicit_graph_directory_replaced_by_a_file_is_refused_before_write() {
    let temporary = TempDir::new().expect("temporary workspace");
    let root = temporary.path().join("workspace");
    let graph = temporary.path().join("semantic-data");
    let held_graph = temporary.path().join("held-semantic-data");
    mkdir(&root);
    mkdir(&graph);
    let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");

    fs::rename(&graph, &held_graph).expect("hold selected directory aside");
    let sentinel = b"not a directory";
    fs::write(&graph, sentinel).expect("replace selected directory with a file");

    let preflight = binding
        .ensure_graph_directory_write("publication-v4")
        .expect_err("a replaced graph root must fail preflight");
    assert!(matches!(
        preflight,
        ProjectPathError::NonDirectoryGenerated { .. }
    ));
    let preparation = binding
        .prepare_graph_directory_write()
        .expect_err("writer preparation must independently recheck the graph root");
    assert!(matches!(
        preparation,
        ProjectRootError::UnsafeGraphDestination(ProjectPathError::NonDirectoryGenerated { .. })
    ));
    assert_eq!(
        fs::read(&graph).expect("replacement sentinel remains readable"),
        sentinel
    );
    assert!(held_graph.is_dir(), "original directory remains untouched");
}

#[cfg(unix)]
#[test]
fn explicit_graph_directory_replaced_by_a_symlink_is_refused_before_write() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().expect("temporary workspace");
    let root = temporary.path().join("workspace");
    let graph = temporary.path().join("semantic-data");
    let held_graph = temporary.path().join("held-semantic-data");
    let outside = temporary.path().join("outside");
    mkdir(&root);
    mkdir(&graph);
    mkdir(&outside);
    let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");

    fs::rename(&graph, &held_graph).expect("hold selected directory aside");
    symlink(&outside, &graph).expect("replace selected directory with a symlink");

    let preflight = binding
        .ensure_graph_directory_write("publication-v4")
        .expect_err("a substituted graph-root symlink must fail preflight");
    assert!(matches!(
        preflight,
        ProjectPathError::SymlinkedGenerated { .. }
    ));
    let preparation = binding
        .prepare_graph_directory_write()
        .expect_err("writer preparation must independently reject the symlink");
    assert!(matches!(
        preparation,
        ProjectRootError::UnsafeGraphDestination(ProjectPathError::SymlinkedGenerated { .. })
    ));
    assert!(
        fs::read_dir(&outside)
            .expect("outside target remains readable")
            .next()
            .is_none(),
        "refusal must not create state through the symlink"
    );
    assert!(held_graph.is_dir(), "original directory remains untouched");
}

#[test]
fn unknown_config_sections_are_rejected_instead_of_aliasing_graph_path() {
    let repo = TempDir::new().expect("scratch repo");
    mkdir(&repo.path().join(".git"));
    mkdir(&repo.path().join(".h00ligan"));
    fs::write(
        repo.path().join(".h00ligan/config.toml"),
        "[storage]\npath = \"poisoned-substrate\"\n",
    )
    .unwrap();

    let error = ProjectBinding::resolve(ProjectBindingOptions::new(repo.path()))
        .expect_err("removed substrate configuration must fail closed");
    assert!(
        error.to_string().contains("unknown field `storage`"),
        "unexpected configuration error: {error}"
    );
    assert!(!repo.path().join("poisoned-substrate").exists());

    fs::write(
        repo.path().join(".h00ligan/config.toml"),
        "[graph]\npath = \".h00ligan/code-intel\"\n",
    )
    .unwrap();
    let configured = ProjectBinding::resolve(ProjectBindingOptions::new(repo.path()))
        .expect("explicit graph.path");
    assert_eq!(configured.graph_source(), GraphSource::ProjectConfig);
    assert!(configured.graph_dir().ends_with(".h00ligan/code-intel"));
}

#[test]
fn relative_cli_graph_paths_are_anchored_to_the_root_not_startup_cwd() {
    let repo = TempDir::new().expect("scratch repo");
    mkdir(&repo.path().join(".git"));
    let nested = repo.path().join("nested/deeper");
    mkdir(&nested);

    let binding = ProjectBinding::resolve(
        ProjectBindingOptions::new(&nested).global_graph_dir(Path::new("build/intel")),
    )
    .expect("resolve relative CLI graph path");
    let canonical_repo = repo.path().canonicalize().expect("canonical scratch repo");

    assert_eq!(binding.graph_source(), GraphSource::Cli);
    assert_eq!(binding.graph_dir(), canonical_repo.join("build/intel"));
    assert!(!binding.graph_dir().exists());
    assert!(!nested.join("build").exists());
}

#[test]
fn admitted_repo_default_writer_installs_a_self_contained_ignore_file() {
    let repo = TempDir::new().expect("scratch repo");
    mkdir(&repo.path().join(".git"));

    let binding = ProjectBinding::resolve(ProjectBindingOptions::new(repo.path()))
        .expect("resolve managed bundle");
    assert!(!binding.graph_dir().exists());
    binding
        .prepare_graph_directory_write()
        .expect("prepare admitted managed writer");
    let ignore =
        fs::read_to_string(binding.graph_dir().join(".gitignore")).expect("managed ignore file");

    assert!(ignore.lines().any(|line| line.trim() == "*"));
    assert!(ignore.lines().any(|line| line.trim() == "!.gitignore"));
}

#[test]
fn repo_default_refuses_safe_but_noncanonical_managed_ignore_without_overwrite() {
    let repo = TempDir::new().expect("scratch repo");
    let init = Command::new("git")
        .args(["init", "--quiet"])
        .arg(repo.path())
        .output()
        .expect("initialize scratch git repository");
    assert!(
        init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let graph_dir = repo.path().join(".h00ligan/code-intel");
    mkdir(&graph_dir);
    let ignore_path = graph_dir.join(".gitignore");
    let safe_but_noncanonical = "# operator note retained verbatim\n*\n!.gitignore\n";
    fs::write(&ignore_path, safe_but_noncanonical).expect("write safe noncanonical ignore file");

    for generated in [
        ".h00ligan/code-intel/graph.redb",
        ".h00ligan/code-intel/index.redb",
        ".h00ligan/code-intel/future-generated-child",
    ] {
        let ignored = Command::new("git")
            .args(["-C"])
            .arg(repo.path())
            .args(["check-ignore", "--quiet", "--", generated])
            .status()
            .expect("check generated artifact ignore behavior");
        assert!(ignored.success(), "fixture must ignore {generated}");
    }
    let managed_ignore_is_ignored = Command::new("git")
        .args(["-C"])
        .arg(repo.path())
        .args([
            "check-ignore",
            "--quiet",
            "--",
            ".h00ligan/code-intel/.gitignore",
        ])
        .status()
        .expect("check managed ignore visibility");
    assert!(
        !managed_ignore_is_ignored.success(),
        "fixture must keep its own .gitignore visible"
    );

    let binding = ProjectBinding::resolve(ProjectBindingOptions::new(repo.path()))
        .expect("read-only binding ignores writer control bytes");
    let error = binding
        .prepare_graph_directory_write()
        .expect_err("managed writer accepts only the canonical tool-owned bytes");
    assert!(matches!(
        error,
        ProjectRootError::InvalidManagedIgnore { .. }
    ));
    assert_eq!(
        fs::read_to_string(ignore_path).expect("managed ignore remains inspectable"),
        safe_but_noncanonical,
        "the safe operator-owned file must not be overwritten"
    );
}

#[test]
fn repo_default_refuses_managed_ignore_with_a_later_artifact_negation() {
    let repo = TempDir::new().expect("scratch repo");
    mkdir(&repo.path().join(".git"));
    let graph_dir = repo.path().join(".h00ligan/code-intel");
    mkdir(&graph_dir);
    let ignore_path = graph_dir.join(".gitignore");
    let unsafe_ignore = "*\n!.gitignore\n!graph.redb\n";
    fs::write(&ignore_path, unsafe_ignore).expect("write unsafe managed ignore file");

    let binding = ProjectBinding::resolve(ProjectBindingOptions::new(repo.path()))
        .expect("read-only binding ignores writer control bytes");
    let error = binding
        .prepare_graph_directory_write()
        .expect_err("managed ignore must not re-include a generated graph artifact");

    assert!(matches!(
        error,
        ProjectRootError::InvalidManagedIgnore { .. }
    ));
    assert_eq!(
        fs::read_to_string(ignore_path).expect("managed ignore remains inspectable"),
        unsafe_ignore,
        "an unsafe operator-owned ignore file must not be overwritten"
    );
}

#[cfg(unix)]
#[test]
fn repo_default_refuses_a_symlinked_managed_ignore() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().expect("scratch workspace");
    let repo = workspace.path().join("repo");
    let outside = workspace.path().join("outside");
    mkdir(&repo.join(".git"));
    let graph_dir = repo.join(".h00ligan/code-intel");
    mkdir(&graph_dir);
    mkdir(&outside);
    let outside_ignore = outside.join("shared-ignore");
    let canonical_ignore = "*\n!.gitignore\n";
    fs::write(&outside_ignore, canonical_ignore).expect("write outside ignore target");
    symlink(&outside_ignore, graph_dir.join(".gitignore")).expect("create managed ignore symlink");

    let binding = ProjectBinding::resolve(ProjectBindingOptions::new(&repo))
        .expect("read-only binding ignores writer control bytes");
    binding
        .prepare_graph_directory_write()
        .expect_err("the managed ignore must be a regular in-bundle file");
    assert_eq!(
        fs::read_to_string(outside_ignore).expect("outside ignore remains readable"),
        canonical_ignore,
        "managed-ignore validation must not alter the symlink target"
    );
}

#[cfg(unix)]
#[test]
fn destination_refuses_a_dangling_symlink_to_an_outside_target() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().expect("scratch workspace");
    let repo = workspace.path().join("repo");
    let outside = workspace.path().join("outside");
    mkdir(&repo);
    mkdir(&outside);
    let binding = ProjectBinding::resolve(ProjectBindingOptions::new(&repo).explicit_root(&repo))
        .expect("resolve explicit project root");

    let outside_target = outside.join("future.rs");
    let destination = repo.join("replacement.rs");
    symlink(&outside_target, &destination).expect("create dangling destination symlink");
    assert!(
        !outside_target.exists(),
        "outside target must remain absent"
    );
    assert!(
        fs::symlink_metadata(&destination)
            .expect("inspect destination symlink")
            .file_type()
            .is_symlink(),
        "the destination fixture must be a symlink"
    );

    binding
        .resolve_destination(Path::new("replacement.rs"))
        .expect_err("a dangling destination symlink must be refused");
}

#[test]
fn generated_artifact_classifier_accepts_only_absent_or_regular_files() {
    let workspace = TempDir::new().expect("scratch workspace");
    let absent = workspace.path().join("absent.scip");
    assert_eq!(
        inspect_generated_artifact(&absent).expect("absent artifact"),
        GeneratedArtifactState::Absent
    );

    let regular = workspace.path().join("regular.scip");
    fs::write(&regular, b"fixture").expect("regular artifact");
    assert_eq!(
        inspect_generated_artifact(&regular).expect("regular artifact"),
        GeneratedArtifactState::RegularFile
    );

    let directory = workspace.path().join("directory.scip");
    mkdir(&directory);
    assert!(matches!(
        inspect_generated_artifact(&directory).expect_err("directory must be refused"),
        ProjectPathError::NonRegularGenerated { .. }
    ));
}

#[test]
fn generated_directory_classifier_accepts_only_absent_or_directories() {
    let workspace = TempDir::new().expect("scratch workspace");
    let absent = workspace.path().join("absent-directory");
    assert_eq!(
        inspect_generated_directory(&absent).expect("absent generated directory"),
        GeneratedDirectoryState::Absent
    );

    let directory = workspace.path().join("publication-v4");
    mkdir(&directory);
    assert_eq!(
        inspect_generated_directory(&directory).expect("existing generated directory"),
        GeneratedDirectoryState::Directory
    );

    let regular = workspace.path().join("not-a-directory");
    fs::write(&regular, b"fixture").expect("regular-file fixture");
    assert!(matches!(
        inspect_generated_directory(&regular).expect_err("regular file must be refused"),
        ProjectPathError::NonDirectoryGenerated { .. }
    ));
}

#[cfg(unix)]
#[test]
fn generated_artifact_classifier_refuses_other_non_regular_entries() {
    use std::os::unix::net::UnixListener;

    let workspace = TempDir::new().expect("scratch workspace");
    let socket = workspace.path().join("socket.scip");
    let _listener = UnixListener::bind(&socket).expect("Unix socket fixture");
    assert!(matches!(
        inspect_generated_artifact(&socket).expect_err("socket must be refused"),
        ProjectPathError::NonRegularGenerated { .. }
    ));
}

#[cfg(unix)]
#[test]
fn managed_binding_refuses_a_symlinked_provider_cache_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().expect("scratch workspace");
    let repo = workspace.path().join("repo");
    let outside = workspace.path().join("outside-cache");
    mkdir(&repo.join(".git"));
    let graph_dir = repo.join(".h00ligan/code-intel");
    mkdir(&graph_dir);
    mkdir(&outside);
    fs::write(graph_dir.join(".gitignore"), "*\n!.gitignore\n")
        .expect("write canonical managed ignore");
    let sentinel = outside.join("sentinel");
    fs::write(&sentinel, b"outside cache target\n").expect("outside sentinel");
    symlink(&outside, graph_dir.join(PROVIDER_CACHE_DIRECTORY))
        .expect("symlink provider cache outside");

    let error = ProjectBinding::resolve(ProjectBindingOptions::new(&repo))
        .expect_err("managed provider cache symlinks must fail closed");
    assert!(matches!(
        error,
        ProjectRootError::SymlinkedManagedArtifact { .. }
    ));
    assert_eq!(
        fs::read(&sentinel).expect("outside sentinel remains readable"),
        b"outside cache target\n"
    );
    assert_eq!(
        fs::read_dir(&outside)
            .expect("outside target remains readable")
            .count(),
        1,
        "refusal must not create cache state through the symlink"
    );
}

#[cfg(unix)]
#[test]
fn repo_default_binding_ignores_an_obsolete_split_bundle_symlink() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().expect("scratch workspace");
    let repo = workspace.path().join("repo");
    let outside = workspace.path().join("outside");
    mkdir(&repo.join(".git"));
    let graph_dir = repo.join(".h00ligan/code-intel");
    mkdir(&graph_dir);
    mkdir(&outside);
    fs::write(graph_dir.join(".gitignore"), "*\n!.gitignore\n")
        .expect("write canonical managed ignore");
    let outside_target = outside.join("missing-graph.redb");
    symlink(&outside_target, graph_dir.join("graph.redb"))
        .expect("create dangling graph artifact symlink");

    let binding = ProjectBinding::resolve(ProjectBindingOptions::new(&repo))
        .expect("obsolete split-bundle paths are outside immutable publication authority");
    binding
        .prepare_graph_directory_write()
        .expect("immutable publication may proceed beside an untouched obsolete path");
    assert!(
        !outside_target.exists(),
        "binding and publication preparation must not follow or mutate the obsolete symlink"
    );
}

#[cfg(unix)]
#[test]
fn repo_default_refuses_a_symlink_escape() {
    use std::os::unix::fs::symlink;

    let repo = TempDir::new().expect("scratch repo");
    let outside = TempDir::new().expect("outside directory");
    mkdir(&repo.path().join(".git"));
    symlink(outside.path(), repo.path().join(".h00ligan")).expect("symlink .h00 outside");

    let error = ProjectBinding::resolve(ProjectBindingOptions::new(repo.path()))
        .expect_err("managed default must remain inside the repository");
    assert!(matches!(
        error,
        ProjectRootError::SymlinkedManagedArtifact { .. }
    ));
    assert!(!outside.path().join("code-intel/.gitignore").exists());
}
