use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use h00ligan_provider_protocol::{
    AdmittedProviderDocument, ExpectedAffectedRefresh, ExpectedFullCertification,
    ExpectedProviderAnalysis, ExpectedProviderDocument, H00_PYREFLY_IMPLEMENTATION_V1,
    H00_PYREFLY_LANGUAGE, H00_PYREFLY_PROVIDER_ID, H00_PYREFLY_UPSTREAM_COMMIT,
    H00_PYREFLY_UPSTREAM_VERSION, H00_RUST_ANALYZER_IMPLEMENTATION_V6,
    H00_RUST_ANALYZER_PROVIDER_ID, H00_SCIP_BINDINGS_UPSTREAM_COMMIT,
    H00_SCIP_BINDINGS_UPSTREAM_VERSION, H00_TYPESCRIPT_IMPLEMENTATION_V2, H00_TYPESCRIPT_LANGUAGE,
    H00_TYPESCRIPT_PROVIDER_ID, H00_TYPESCRIPT_UPSTREAM_COMMIT, H00_TYPESCRIPT_UPSTREAM_VERSION,
    ProviderAnalysisOutcome, ProviderAuthority, ProviderComponentHealth, ProviderDocumentOutcome,
    ProviderFrame, ProviderFrameLimits, ProviderHealthEvidence, ProviderIdentity,
    ProviderOperation, ProviderRequest, ProviderRequestBody, ProviderRequestClaims,
    ProviderResponse, ProviderResponseBody, ProviderRuntimeConfiguration,
    ProviderSemanticEnvironmentInput, ProviderSemanticInputCoverage, ProviderSemanticInputs,
    ProviderSemanticPathKind, ProviderSemanticPathRoot, ProviderSourceChange,
    ProviderSourceIdentity, RustCargoFeatures, RustSemanticProfile, SEMANTIC_PROVIDER_FRAME_MAGIC,
    SEMANTIC_PROVIDER_PROTOCOL, capture_provider_semantic_directory_listing,
    capture_provider_semantic_inputs, capture_provider_semantic_inputs_at_coordinates,
    classify_provider_semantic_input_path, decode_provider_frame, encode_provider_frame,
    provider_identity_sha256, provider_runtime_configuration,
    provider_semantic_file_identity_sha256, provider_semantic_inputs_are_current,
    provider_semantic_inputs_are_current_in_environment, provider_semantic_inputs_sha256,
    provider_semantic_paths_are_current, pyrefly_source_components, read_provider_frame,
    resolved_authority_configuration_sha256, rust_analyzer_runtime_configuration,
    rust_analyzer_source_components, sha256_hex, source_population_sha256,
    typescript_source_components, validate_affected_refresh, validate_full_certification,
    validate_provider_request, validate_runtime_configuration, write_provider_frame,
};

#[test]
fn protocol_v15_owns_v15_frame_magic() {
    assert_eq!(SEMANTIC_PROVIDER_PROTOCOL, "h00/semantic-provider/v15");
    assert_eq!(SEMANTIC_PROVIDER_FRAME_MAGIC, b"H00SP15\0");
}

fn sha(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

struct ScratchDirectory(std::path::PathBuf);

impl ScratchDirectory {
    fn new(label: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "h00-semantic-provider-{label}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create test-owned scratch directory");
        Self(path)
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// RIGHT-REASON REGRESSION: source documents and compiler-observed semantic
/// inputs are different bounded populations. A small source unit may resolve
/// more dependency/configuration files than it contains source documents.
#[test]
fn semantic_inputs_are_not_capped_by_the_source_document_limit() {
    let root = ScratchDirectory::new("independent-semantic-input-bound");
    std::fs::write(root.0.join("first.lock"), b"first\n").expect("first semantic input");
    std::fs::write(root.0.join("second.lock"), b"second\n").expect("second semantic input");
    let paths = BTreeSet::from(["first.lock".to_owned(), "second.lock".to_owned()]);
    let limits = ProviderFrameLimits {
        max_document_paths: 1,
        ..ProviderFrameLimits::default()
    };

    let captured = capture_provider_semantic_inputs(&root.0, &paths, &BTreeSet::new(), &limits)
        .expect("semantic inputs use their own negotiated population bound");
    assert_eq!(captured.paths.len(), 2, "populated semantic-input control");

    let sources = [
        ProviderSourceIdentity {
            document_path: "first.rs".into(),
            language: "rust".into(),
            content_identity: "first".into(),
            content_sha256: sha('a'),
        },
        ProviderSourceIdentity {
            document_path: "second.rs".into(),
            language: "rust".into(),
            content_identity: "second".into(),
            content_sha256: sha('b'),
        },
    ];
    assert!(
        source_population_sha256(&sources, &limits).is_err(),
        "positive control: the one-document source limit must still fire"
    );
}

#[test]
fn semantic_input_manifest_is_content_exact_bounded_and_non_vacuous() {
    let root = ScratchDirectory::new("semantic-inputs");
    std::fs::create_dir(root.0.join("assets")).expect("asset directory");
    std::fs::write(root.0.join("selector.txt"), b"alpha\n").expect("selector input");
    std::fs::write(root.0.join("assets/table.bin"), b"table-v1").expect("directory input");
    let paths = BTreeSet::from([
        "assets".to_owned(),
        "missing.txt".to_owned(),
        "selector.txt".to_owned(),
    ]);
    let limits = ProviderFrameLimits::default();
    let manifest = capture_provider_semantic_inputs(&root.0, &paths, &BTreeSet::new(), &limits)
        .expect("capture exact semantic inputs");
    assert_eq!(manifest.coverage, ProviderSemanticInputCoverage::Complete);
    assert_eq!(manifest.paths.len(), 3, "positive populated-path control");
    let encoded_manifest = serde_json::to_value(&manifest).expect("serialize semantic manifest");
    assert!(
        encoded_manifest["paths"]
            .as_array()
            .expect("semantic path population")
            .iter()
            .all(|input| input["root"] == "repository"),
        "every persisted semantic path must state its authority root explicitly"
    );
    let mut missing_root = encoded_manifest;
    missing_root["paths"][0]
        .as_object_mut()
        .expect("semantic path object")
        .remove("root");
    assert!(
        serde_json::from_value::<ProviderSemanticInputs>(missing_root).is_err(),
        "an omitted authority root must fail closed instead of defaulting to repository"
    );
    let selector = manifest
        .paths
        .iter()
        .find(|input| input.path == "selector.txt")
        .expect("selector semantic path");
    assert_eq!(
        selector.identity_sha256,
        provider_semantic_file_identity_sha256(&sha256_hex(b"alpha\n"))
            .expect("identity reconstructed from independently admitted bytes"),
        "inventory content authority must reproduce the exact captured file identity"
    );
    assert!(
        provider_semantic_file_identity_sha256(&"A".repeat(64)).is_err(),
        "noncanonical digest sabotage must fire"
    );
    assert!(
        provider_semantic_inputs_are_current(&root.0, &manifest, &limits)
            .expect("re-observe unchanged inputs"),
        "unchanged exact population must compare current"
    );
    assert!(
        provider_semantic_inputs_sha256(&manifest, &limits).is_ok(),
        "positive canonical digest control"
    );

    std::fs::create_dir(root.0.join("listing-assets")).expect("listing-only directory");
    std::fs::write(root.0.join("listing-assets/table.bin"), b"table-v1")
        .expect("listing-only member");
    let listing = capture_provider_semantic_directory_listing(&root.0, "listing-assets", &limits)
        .expect("capture compiler-style directory listing");
    assert_eq!(listing.kind, ProviderSemanticPathKind::DirectoryListing);
    assert_eq!(listing.entry_count, 2, "directory plus one known entry");
    let listing_manifest = ProviderSemanticInputs {
        schema_version: manifest.schema_version.clone(),
        coverage: ProviderSemanticInputCoverage::Complete,
        paths: vec![listing],
        environment: Vec::new(),
        issues: Vec::new(),
    };
    std::fs::write(root.0.join("listing-assets/table.bin"), b"table-v2")
        .expect("mutate descendant bytes");
    assert!(
        provider_semantic_paths_are_current(&root.0, &listing_manifest, &limits)
            .expect("re-observe unchanged directory membership"),
        "directory-listing authority must not recursively hash bytes owned by separate reads"
    );
    std::fs::write(root.0.join("listing-assets/second.bin"), b"new entry")
        .expect("add directory member");
    assert!(
        !provider_semantic_paths_are_current(&root.0, &listing_manifest, &limits)
            .expect("re-observe changed directory membership"),
        "directory membership drift must invalidate compiler resolution authority"
    );

    let mut explicit_environment_manifest = manifest.clone();
    explicit_environment_manifest
        .environment
        .push(ProviderSemanticEnvironmentInput {
            name: "H00_PROVIDER_ONLY_INPUT".into(),
            value_sha256: Some(sha256_hex(b"provider-only-value")),
        });
    let exact_provider_environment = BTreeMap::from([(
        OsString::from("H00_PROVIDER_ONLY_INPUT"),
        OsString::from("provider-only-value"),
    )]);
    assert!(
        provider_semantic_inputs_are_current_in_environment(
            &root.0,
            &explicit_environment_manifest,
            &exact_provider_environment,
            &limits,
        )
        .expect("re-observe exact provider environment"),
        "provider-input authority must use the post-env-clear child environment"
    );
    assert!(
        provider_semantic_paths_are_current(&root.0, &explicit_environment_manifest, &limits)
            .expect("re-observe repository paths only"),
        "query freshness must ignore an unrelated process environment"
    );
    assert!(
        !provider_semantic_inputs_are_current_in_environment(
            &root.0,
            &explicit_environment_manifest,
            &BTreeMap::new(),
            &limits,
        )
        .expect("observe explicit provider environment drift"),
        "provider reuse must still reject a different child environment"
    );

    std::fs::write(root.0.join("selector.txt"), b"bravo\n").expect("mutate selector bytes");
    assert!(
        !provider_semantic_inputs_are_current(&root.0, &manifest, &limits)
            .expect("observe ordinary content drift"),
        "same-length byte drift must fire independently of timestamps"
    );
    std::fs::write(root.0.join("selector.txt"), b"alpha\n").expect("restore selector");
    std::fs::write(root.0.join("missing.txt"), b"appeared").expect("materialize missing input");
    assert!(
        !provider_semantic_inputs_are_current(&root.0, &manifest, &limits)
            .expect("observe missing-to-present drift"),
        "missing-path state must be authoritative"
    );

    let mut duplicate = manifest;
    duplicate.paths.push(duplicate.paths[0].clone());
    assert!(
        provider_semantic_inputs_sha256(&duplicate, &limits).is_err(),
        "duplicate/noncanonical input sabotage must fail closed"
    );
}

/// RIGHT-REASON REGRESSION: linked worktrees relocate Git's per-worktree and
/// common control files, but the relocation does not grant arbitrary external
/// filesystem authority. Persisted inputs must retain only typed roots and
/// safe relative labels, then re-resolve those exact roots on freshness checks.
#[test]
fn semantic_inputs_bind_linked_worktree_git_roots_without_absolute_paths() {
    let scratch = ScratchDirectory::new("linked-worktree-semantic-inputs");
    let repository = scratch.0.join("worktree");
    let common_git = scratch.0.join("main/.git");
    let worktree_git = common_git.join("worktrees/fixture");
    let branch_ref = common_git.join("refs/heads/fixture");
    std::fs::create_dir_all(&repository).expect("worktree source root");
    std::fs::create_dir_all(branch_ref.parent().expect("branch-ref parent")).expect("common refs");
    std::fs::create_dir_all(&worktree_git).expect("worktree gitdir");
    std::fs::write(
        repository.join(".git"),
        format!("gitdir: {}\n", worktree_git.display()),
    )
    .expect("linked-worktree marker");
    std::fs::write(worktree_git.join("commondir"), "../..\n").expect("commondir");
    std::fs::write(worktree_git.join("HEAD"), "ref: refs/heads/fixture\n")
        .expect("per-worktree HEAD");
    std::fs::write(&branch_ref, format!("{}\n", "1".repeat(40))).expect("shared ref");

    let nonreciprocal_error = classify_provider_semantic_input_path(&repository, &branch_ref)
        .expect_err("a one-way repository gitfile must not grant external filesystem authority");
    assert!(
        nonreciprocal_error
            .to_string()
            .contains("linked-worktree gitdir backpointer"),
        "the refusal must identify the missing reciprocal proof: {nonreciprocal_error}"
    );
    std::fs::write(
        worktree_git.join("gitdir"),
        format!("{}\n", repository.join(".git").display()),
    )
    .expect("reciprocal worktree pointer");

    let coordinates = BTreeSet::from([
        classify_provider_semantic_input_path(&repository, &worktree_git.join("HEAD"))
            .expect("classify per-worktree control"),
        classify_provider_semantic_input_path(&repository, &branch_ref)
            .expect("classify shared control"),
    ]);
    assert_eq!(coordinates.len(), 2, "populated typed-root control");
    let outside = scratch.0.join("unrelated-machine-input");
    std::fs::write(&outside, "private\n").expect("outside negative fixture");
    assert!(
        classify_provider_semantic_input_path(&repository, &outside).is_err(),
        "the Git control plane must not authorize an unrelated sibling path"
    );

    let limits = ProviderFrameLimits::default();
    let manifest = capture_provider_semantic_inputs_at_coordinates(
        &repository,
        &coordinates,
        &BTreeSet::new(),
        &limits,
    )
    .expect("capture typed linked-worktree inputs");
    assert_eq!(
        manifest
            .paths
            .iter()
            .map(|input| (input.root, input.path.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (ProviderSemanticPathRoot::Repository, ".git"),
            (ProviderSemanticPathRoot::GitWorktree, "HEAD"),
            (ProviderSemanticPathRoot::GitWorktree, "commondir"),
            (ProviderSemanticPathRoot::GitWorktree, "gitdir"),
            (ProviderSemanticPathRoot::GitCommon, "refs/heads/fixture"),
        ],
        "addressing inputs and Git roots must form one canonical population"
    );
    let encoded = serde_json::to_string(&manifest).expect("serialize semantic inputs");
    assert!(!encoded.contains(scratch.0.to_str().expect("UTF-8 scratch")));
    assert!(
        provider_semantic_paths_are_current(&repository, &manifest, &limits)
            .expect("re-observe unchanged linked-worktree controls")
    );

    std::fs::write(&branch_ref, format!("{}\n", "2".repeat(40))).expect("move shared ref");
    assert!(
        !provider_semantic_paths_are_current(&repository, &manifest, &limits)
            .expect("re-observe shared-ref drift"),
        "same-shape Git ref byte drift must invalidate persisted authority"
    );

    let unrelated_common = scratch.0.join("unrelated-common");
    let unrelated_ref = unrelated_common.join("refs/heads/fixture");
    std::fs::create_dir_all(unrelated_ref.parent().expect("unrelated ref parent"))
        .expect("unrelated common directory");
    std::fs::write(&unrelated_ref, format!("{}\n", "3".repeat(40))).expect("unrelated common ref");
    std::fs::write(
        worktree_git.join("commondir"),
        unrelated_common.display().to_string(),
    )
    .expect("forged common-dir pointer");
    assert!(
        classify_provider_semantic_input_path(&repository, &unrelated_ref).is_err(),
        "commondir must not grant an unrelated directory without Git topology proof"
    );
}

/// RIGHT-REASON REGRESSION: Darwin commonly exposes a temporary directory
/// below `/var` while canonicalization resolves the same directory below
/// `/private/var`. Linked-worktree Git inputs must retain the mechanically
/// proven spelling from `.git`/`commondir` as well as the canonical root, so a
/// platform alias cannot make an owned control file look external.
#[cfg(unix)]
#[test]
fn linked_worktree_git_roots_accept_their_proven_parent_alias() {
    use std::os::unix::fs::symlink;

    let scratch = ScratchDirectory::new("linked-worktree-parent-alias");
    let physical = scratch.0.join("physical");
    let alias = scratch.0.join("alias");
    std::fs::create_dir(&physical).expect("physical fixture root");
    symlink(&physical, &alias).expect("fixture parent alias");
    let canonical_physical =
        std::fs::canonicalize(&physical).expect("canonical physical fixture root");

    let repository = alias.join("worktree");
    let common_git = alias.join("main/.git");
    let worktree_git = common_git.join("worktrees/fixture");
    let branch_ref = common_git.join("refs/heads/fixture");
    std::fs::create_dir_all(&repository).expect("worktree source root");
    std::fs::create_dir_all(&worktree_git).expect("worktree gitdir");
    std::fs::create_dir_all(branch_ref.parent().expect("branch-ref parent")).expect("common refs");
    std::fs::write(
        repository.join(".git"),
        format!("gitdir: {}\n", worktree_git.display()),
    )
    .expect("linked-worktree marker");
    std::fs::write(worktree_git.join("commondir"), "../..\n").expect("commondir");
    std::fs::write(worktree_git.join("HEAD"), "ref: refs/heads/fixture\n")
        .expect("per-worktree HEAD");
    std::fs::write(&branch_ref, format!("{}\n", "1".repeat(40))).expect("shared ref");
    std::fs::write(
        worktree_git.join("gitdir"),
        format!("{}\n", repository.join(".git").display()),
    )
    .expect("reciprocal worktree pointer");

    let worktree_coordinate =
        classify_provider_semantic_input_path(&repository, &worktree_git.join("HEAD"))
            .expect("a proven parent alias must retain Git-worktree authority");
    assert_eq!(
        worktree_coordinate,
        h00ligan_provider_protocol::ProviderSemanticPathCoordinate {
            root: ProviderSemanticPathRoot::GitWorktree,
            path: "HEAD".into(),
        }
    );
    let common_coordinate = classify_provider_semantic_input_path(&repository, &branch_ref)
        .expect("a proven parent alias must retain common-Git authority");
    assert_eq!(
        common_coordinate,
        h00ligan_provider_protocol::ProviderSemanticPathCoordinate {
            root: ProviderSemanticPathRoot::GitCommon,
            path: "refs/heads/fixture".into(),
        }
    );
    assert_eq!(
        classify_provider_semantic_input_path(
            &repository,
            &canonical_physical.join("main/.git/worktrees/fixture/HEAD"),
        )
        .expect("the canonical Git-worktree root remains authoritative"),
        worktree_coordinate
    );

    let unproven_alias = scratch.0.join("unproven-alias");
    symlink(&physical, &unproven_alias).expect("unproven parent alias");
    assert!(
        classify_provider_semantic_input_path(
            &repository,
            &unproven_alias.join("main/.git/worktrees/fixture/HEAD"),
        )
        .is_err(),
        "an equivalent target through an undeclared alias must not gain authority"
    );

    let manifest = capture_provider_semantic_inputs_at_coordinates(
        &repository,
        &BTreeSet::from([worktree_coordinate, common_coordinate]),
        &BTreeSet::new(),
        &ProviderFrameLimits::default(),
    )
    .expect("capture through canonical Git authority");
    assert!(
        provider_semantic_paths_are_current(
            &repository,
            &manifest,
            &ProviderFrameLimits::default(),
        )
        .expect("re-observe the aliased linked-worktree controls"),
        "the alias spelling and canonical Git location must identify one authority"
    );
}

/// FALSIFIER: the per-worktree `commondir` file participates in locating every
/// external Git root, even when the selected semantic input itself lives only
/// in the per-worktree directory. Its exact bytes must therefore be captured
/// and any representation drift must invalidate the old authority manifest.
#[test]
fn git_worktree_only_semantic_inputs_bind_commondir_addressing_bytes() {
    let scratch = ScratchDirectory::new("linked-worktree-only-semantic-inputs");
    let repository = scratch.0.join("worktree");
    let common_git = scratch.0.join("main/.git");
    let worktree_git = common_git.join("worktrees/fixture");
    std::fs::create_dir_all(&repository).expect("worktree source root");
    std::fs::create_dir_all(&worktree_git).expect("worktree gitdir");
    std::fs::write(
        repository.join(".git"),
        format!("gitdir: {}\n", worktree_git.display()),
    )
    .expect("linked-worktree marker");
    std::fs::write(worktree_git.join("commondir"), "../..\n").expect("commondir");
    std::fs::write(worktree_git.join("HEAD"), "ref: refs/heads/fixture\n")
        .expect("per-worktree HEAD");
    std::fs::write(
        worktree_git.join("gitdir"),
        format!("{}\n", repository.join(".git").display()),
    )
    .expect("reciprocal worktree pointer");

    let coordinates = BTreeSet::from([classify_provider_semantic_input_path(
        &repository,
        &worktree_git.join("HEAD"),
    )
    .expect("classify per-worktree control")]);
    assert_eq!(coordinates.len(), 1, "populated Git-worktree control");
    let limits = ProviderFrameLimits::default();
    let manifest = capture_provider_semantic_inputs_at_coordinates(
        &repository,
        &coordinates,
        &BTreeSet::new(),
        &limits,
    )
    .expect("capture typed linked-worktree input");
    assert_eq!(
        manifest
            .paths
            .iter()
            .map(|input| (input.root, input.path.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (ProviderSemanticPathRoot::Repository, ".git"),
            (ProviderSemanticPathRoot::GitWorktree, "HEAD"),
            (ProviderSemanticPathRoot::GitWorktree, "commondir"),
            (ProviderSemanticPathRoot::GitWorktree, "gitdir"),
        ],
        "every external Git manifest must bind its complete addressing population"
    );
    assert!(
        provider_semantic_paths_are_current(&repository, &manifest, &limits)
            .expect("unchanged addressing population")
    );

    std::fs::write(
        worktree_git.join("commondir"),
        format!("{}\n", common_git.display()),
    )
    .expect("same-target commondir representation drift");
    assert!(
        !provider_semantic_paths_are_current(&repository, &manifest, &limits)
            .expect("re-observe changed commondir bytes"),
        "same-target addressing-byte drift must invalidate persisted authority"
    );
}

/// RIGHT-REASON REGRESSION: a linked-worktree gitdir is a per-worktree entry
/// below the common repository and therefore has a `commondir` pointer. A
/// repository-local gitfile plus an arbitrary reciprocal external directory
/// is not enough to grant that directory semantic-input authority.
#[test]
fn gitfile_without_commondir_is_not_linked_worktree_authority() {
    let scratch = ScratchDirectory::new("forged-linked-worktree-without-commondir");
    let repository = scratch.0.join("repository");
    let external_gitdir = scratch.0.join("external-gitdir");
    std::fs::create_dir_all(&repository).expect("repository directory");
    std::fs::create_dir_all(&external_gitdir).expect("external gitdir directory");
    std::fs::write(
        repository.join(".git"),
        format!("gitdir: {}\n", external_gitdir.display()),
    )
    .expect("repository gitfile");
    std::fs::write(external_gitdir.join("HEAD"), "ref: refs/heads/main\n").expect("external HEAD");
    std::fs::write(
        external_gitdir.join("gitdir"),
        format!("{}\n", repository.join(".git").display()),
    )
    .expect("synthetic reciprocal pointer");

    let error = classify_provider_semantic_input_path(&repository, &external_gitdir.join("HEAD"))
        .expect_err("a non-worktree gitfile must not grant external authority");
    assert!(
        error.to_string().contains("commondir"),
        "the refusal must identify the missing linked-worktree control: {error}"
    );
}

#[test]
fn gitfile_with_self_commondir_is_not_linked_worktree_authority() {
    let scratch = ScratchDirectory::new("forged-linked-worktree-self-commondir");
    let repository = scratch.0.join("repository");
    let external_gitdir = scratch.0.join("external-gitdir");
    std::fs::create_dir_all(&repository).expect("repository directory");
    std::fs::create_dir_all(&external_gitdir).expect("external gitdir directory");
    std::fs::write(
        repository.join(".git"),
        format!("gitdir: {}\n", external_gitdir.display()),
    )
    .expect("repository gitfile");
    std::fs::write(external_gitdir.join("HEAD"), "ref: refs/heads/main\n").expect("external HEAD");
    std::fs::write(
        external_gitdir.join("gitdir"),
        format!("{}\n", repository.join(".git").display()),
    )
    .expect("synthetic reciprocal pointer");
    std::fs::write(external_gitdir.join("commondir"), ".\n").expect("synthetic self commondir");

    let error = classify_provider_semantic_input_path(&repository, &external_gitdir.join("HEAD"))
        .expect_err("a self-common gitfile must not grant external authority");
    assert!(
        error.to_string().contains("common Git directory"),
        "the refusal must identify the invalid common-directory topology: {error}"
    );
}

/// FALSIFIER: pnpm-style package links are ordinary repository-local project
/// inputs. Authority must follow them without allowing an escape, and a link
/// remap must invalidate freshness even when the two targets have identical
/// bytes and directory shape.
#[cfg(unix)]
#[test]
fn semantic_inputs_admit_repository_symlinks_and_bind_exact_targets() {
    use std::os::unix::fs::symlink;

    let root = ScratchDirectory::new("semantic-symlinks");
    for package in ["package-a", "package-b"] {
        std::fs::create_dir_all(root.0.join("store").join(package)).expect("package store");
        std::fs::write(
            root.0.join("store").join(package).join("package.json"),
            br#"{"name":"fixture","version":"1.0.0"}"#,
        )
        .expect("package manifest");
    }
    std::fs::create_dir(root.0.join("node_modules")).expect("node_modules");
    let link = root.0.join("node_modules/fixture");
    symlink("../store/package-a", &link).expect("repository-local package link");
    let limits = ProviderFrameLimits::default();
    let file_manifest = capture_provider_semantic_inputs(
        &root.0,
        &BTreeSet::from(["node_modules/fixture/package.json".to_owned()]),
        &BTreeSet::new(),
        &limits,
    )
    .expect("capture file through repository-contained package link");
    let mut paths = vec![
        capture_provider_semantic_directory_listing(&root.0, "node_modules", &limits)
            .expect("capture node_modules membership"),
        capture_provider_semantic_directory_listing(&root.0, "node_modules/fixture", &limits)
            .expect("capture linked package membership"),
        file_manifest.paths[0].clone(),
    ];
    paths.sort_by(|left, right| left.path.cmp(&right.path));
    let first = ProviderSemanticInputs {
        schema_version: file_manifest.schema_version,
        coverage: ProviderSemanticInputCoverage::Complete,
        paths,
        environment: Vec::new(),
        issues: Vec::new(),
    };
    assert_eq!(first.paths.len(), 3, "populated symlink authority control");
    assert_eq!(
        first.paths[0].kind,
        ProviderSemanticPathKind::DirectoryListing
    );
    assert_eq!(
        first.paths[1].kind,
        ProviderSemanticPathKind::DirectoryListing
    );
    assert_eq!(first.paths[2].kind, ProviderSemanticPathKind::File);
    assert!(
        provider_semantic_paths_are_current(&root.0, &first, &limits)
            .expect("re-observe unchanged package link")
    );

    std::fs::remove_file(&link).expect("remove test-owned package link");
    symlink("../store/package-b", &link).expect("remap package link");
    assert!(
        !provider_semantic_paths_are_current(&root.0, &first, &limits)
            .expect("re-observe remapped package link"),
        "a canonical package-target remap must invalidate authority"
    );

    let outside = ScratchDirectory::new("semantic-symlink-outside");
    std::fs::create_dir(outside.0.join("package")).expect("outside package");
    let escape = root.0.join("node_modules/escape");
    symlink(outside.0.join("package"), &escape).expect("escaping package link fixture");
    assert!(
        capture_provider_semantic_directory_listing(&root.0, "node_modules/escape", &limits)
            .is_err(),
        "a symlink target outside repository authority must fail closed"
    );
}

#[test]
fn rust_semantic_profiles_are_explicit_canonical_and_fail_closed() {
    let default = RustSemanticProfile::workspace_default();
    let encoded = default
        .to_environment_value()
        .expect("portable default profile");
    assert_eq!(
        encoded,
        r#"{"schema_version":"h00/rust-semantic-profile/v1","cargo_features":"workspace_default","target":null}"#
    );
    assert_eq!(
        RustSemanticProfile::from_environment_value(&encoded).expect("round-trip profile"),
        default
    );

    let selected = RustSemanticProfile::selected_features(
        [
            "z-feature".to_owned(),
            "a-feature".to_owned(),
            "a-feature".to_owned(),
        ],
        true,
    )
    .expect("canonical selected profile");
    assert!(matches!(
        selected.cargo_features,
        RustCargoFeatures::Selected {
            ref features,
            no_default_features: true,
        } if features == &["a-feature", "z-feature"]
    ));

    let attacks = [
        r#"{"schema_version":"h00/rust-semantic-profile/v0","cargo_features":"workspace_default","target":null}"#,
        r#"{"schema_version":"h00/rust-semantic-profile/v1","cargo_features":{"selected":{"features":[],"no_default_features":false}},"target":null}"#,
        r#"{"schema_version":"h00/rust-semantic-profile/v1","cargo_features":"workspace_default","target":"/tmp/target.json"}"#,
        r#"{"schema_version":"h00/rust-semantic-profile/v1","cargo_features":"workspace_default","target":null,"unknown":true}"#,
    ];
    assert_eq!(attacks.len(), 4, "non-vacuous profile sabotage population");
    for attack in attacks {
        assert!(
            RustSemanticProfile::from_environment_value(attack).is_err(),
            "invalid or noncanonical profile must fail closed: {attack}"
        );
    }
}

#[test]
fn runtime_configuration_binds_toolchain_reports_and_rejects_tampering() {
    let baseline = rust_analyzer_runtime_configuration(
        &sha('1'),
        b"rustc 1.97.1\ncommit-hash: exact\n",
        b"cargo 1.97.1\n",
        b"/exact/sysroot\n",
        b"exact-cleared-environment",
        b"exact-workspace-controls",
    )
    .expect("construct exact Rust runtime");
    validate_runtime_configuration(&baseline).expect("exact runtime configuration");
    for changed in [
        rust_analyzer_runtime_configuration(
            &sha('2'),
            b"rustc 1.97.1\ncommit-hash: exact\n",
            b"cargo 1.97.1\n",
            b"/exact/sysroot\n",
            b"exact-cleared-environment",
            b"exact-workspace-controls",
        )
        .expect("changed resolved toolchain"),
        rust_analyzer_runtime_configuration(
            &sha('1'),
            b"rustc 1.97.2\ncommit-hash: changed\n",
            b"cargo 1.97.1\n",
            b"/exact/sysroot\n",
            b"exact-cleared-environment",
            b"exact-workspace-controls",
        )
        .expect("changed rustc report"),
        rust_analyzer_runtime_configuration(
            &sha('1'),
            b"rustc 1.97.1\ncommit-hash: exact\n",
            b"cargo 1.97.2\n",
            b"/exact/sysroot\n",
            b"exact-cleared-environment",
            b"exact-workspace-controls",
        )
        .expect("changed Cargo report"),
        rust_analyzer_runtime_configuration(
            &sha('1'),
            b"rustc 1.97.1\ncommit-hash: exact\n",
            b"cargo 1.97.1\n",
            b"/different/sysroot\n",
            b"exact-cleared-environment",
            b"exact-workspace-controls",
        )
        .expect("changed sysroot report"),
        rust_analyzer_runtime_configuration(
            &sha('1'),
            b"rustc 1.97.1\ncommit-hash: exact\n",
            b"cargo 1.97.1\n",
            b"/exact/sysroot\n",
            b"changed-cleared-environment",
            b"exact-workspace-controls",
        )
        .expect("changed environment report"),
        rust_analyzer_runtime_configuration(
            &sha('1'),
            b"rustc 1.97.1\ncommit-hash: exact\n",
            b"cargo 1.97.1\n",
            b"/exact/sysroot\n",
            b"exact-cleared-environment",
            b"changed-workspace-controls",
        )
        .expect("changed workspace controls"),
    ] {
        assert_ne!(
            baseline.configuration_sha256, changed.configuration_sha256,
            "every runtime component must influence semantic authority"
        );
        validate_runtime_configuration(&changed).expect("changed but self-consistent runtime");
    }

    let mut tampered = baseline;
    tampered
        .component_sha256s
        .insert("rustc_verbose_version".into(), sha('0'));
    assert!(
        validate_runtime_configuration(&tampered).is_err(),
        "component substitution must not preserve the aggregate digest"
    );
}

#[test]
fn runtime_configuration_wire_is_language_neutral() {
    let runtime = provider_runtime_configuration(
        &sha('1'),
        &[
            ("go_version", b"go version go1.25.0"),
            ("gopls_version", b"golang.org/x/tools/gopls v0.23.0"),
        ],
        b"exact-cleared-go-environment",
        b"exact-go-workspace-controls",
    )
    .expect("construct exact Go runtime without Rust fields");
    validate_runtime_configuration(&runtime).expect("validate exact Go runtime");

    let encoded = serde_json::to_value(&runtime).expect("encode generic runtime");
    let decoded: ProviderRuntimeConfiguration =
        serde_json::from_value(encoded).expect("decode generic runtime");
    assert_eq!(decoded, runtime);
    assert_eq!(
        decoded
            .component_sha256s
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["go_version".to_owned(), "gopls_version".to_owned()],
        "BTreeMap serialization and authority hashing use one canonical component order"
    );
    assert!(
        provider_runtime_configuration(
            &sha('1'),
            &[("go_version", b"one"), ("go_version", b"two")],
            b"environment",
            b"workspace",
        )
        .is_err(),
        "duplicate components must not be silently overwritten"
    );
    assert!(
        provider_runtime_configuration(
            &sha('1'),
            &[("Go-Version", b"bad name")],
            b"environment",
            b"workspace",
        )
        .is_err(),
        "noncanonical component names must fail closed"
    );
    assert!(
        provider_runtime_configuration(&sha('1'), &[], b"environment", b"workspace").is_err(),
        "an empty runtime component population cannot carry semantic authority"
    );
}

fn sha_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn provider() -> ProviderIdentity {
    ProviderIdentity {
        protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
        provider_id: H00_RUST_ANALYZER_PROVIDER_ID.into(),
        language: "rust".into(),
        implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
        source_components: rust_analyzer_source_components(),
        patch_sha256: sha('a'),
        executable_sha256: sha('b'),
    }
}

#[test]
fn durable_provider_identity_binds_every_implementation_coordinate() {
    let baseline = provider();
    let baseline_digest = provider_identity_sha256(&baseline).expect("baseline provider identity");

    let mut wrong_protocol = baseline.clone();
    wrong_protocol.protocol.push_str("-changed");
    assert!(
        provider_identity_sha256(&wrong_protocol).is_err(),
        "a foreign protocol must be rejected rather than assigned durable authority"
    );

    let mut mutations = Vec::new();
    for field in 0..8 {
        let mut changed = baseline.clone();
        match field {
            0 => changed.provider_id.push_str("-changed"),
            1 => changed.language.push_str("-changed"),
            2 => changed.implementation_version.push_str("-changed"),
            3 => {
                changed
                    .source_components
                    .get_mut("rust_analyzer")
                    .expect("Rust source component")
                    .version
                    .push_str("-changed");
            }
            4 => {
                changed
                    .source_components
                    .get_mut("rust_analyzer")
                    .expect("Rust source component")
                    .revision
                    .push('0');
            }
            5 => {
                let component = changed
                    .source_components
                    .remove("rust_analyzer")
                    .expect("Rust source component");
                changed
                    .source_components
                    .insert("rust_analyzer_changed".into(), component);
            }
            6 => changed.patch_sha256 = sha('c'),
            7 => changed.executable_sha256 = sha('d'),
            _ => unreachable!(),
        }
        mutations
            .push(provider_identity_sha256(&changed).unwrap_or_else(|error| {
                panic!("valid changed provider identity {field}: {error}")
            }));
    }
    assert_eq!(
        mutations.len(),
        8,
        "non-vacuous mutable identity coordinate population"
    );
    assert!(
        mutations.iter().all(|digest| digest != &baseline_digest),
        "every provider implementation coordinate must change durable identity"
    );
    assert_eq!(mutations.iter().collect::<BTreeSet<_>>().len(), 8);
}

/// FALSIFIER: shipping one product artifact does not make Python or TypeScript
/// anonymous implementation details. Each embedded semantic engine needs its
/// own exact upstream coordinate and durable provider identity before any
/// result can carry authority.
#[test]
fn pinned_python_and_typescript_provider_identities_are_complete() {
    let fixtures = [
        (
            ProviderIdentity {
                protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
                provider_id: H00_PYREFLY_PROVIDER_ID.into(),
                language: H00_PYREFLY_LANGUAGE.into(),
                implementation_version: H00_PYREFLY_IMPLEMENTATION_V1.into(),
                source_components: pyrefly_source_components(),
                patch_sha256: sha('a'),
                executable_sha256: sha('b'),
            },
            &[(
                "pyrefly",
                H00_PYREFLY_UPSTREAM_VERSION,
                H00_PYREFLY_UPSTREAM_COMMIT,
            )][..],
        ),
        (
            ProviderIdentity {
                protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
                provider_id: H00_TYPESCRIPT_PROVIDER_ID.into(),
                language: H00_TYPESCRIPT_LANGUAGE.into(),
                implementation_version: H00_TYPESCRIPT_IMPLEMENTATION_V2.into(),
                source_components: typescript_source_components(),
                patch_sha256: sha('c'),
                executable_sha256: sha('d'),
            },
            &[
                (
                    "scip_bindings",
                    H00_SCIP_BINDINGS_UPSTREAM_VERSION,
                    H00_SCIP_BINDINGS_UPSTREAM_COMMIT,
                ),
                (
                    "typescript_native",
                    H00_TYPESCRIPT_UPSTREAM_VERSION,
                    H00_TYPESCRIPT_UPSTREAM_COMMIT,
                ),
            ][..],
        ),
    ];

    assert_eq!(fixtures.len(), 2, "positive provider population control");
    let mut provider_ids = BTreeSet::new();
    let mut languages = BTreeSet::new();
    for (identity, components) in fixtures {
        assert!(provider_identity_sha256(&identity).is_ok());
        assert_eq!(identity.source_components.len(), components.len());
        for (component_name, version, revision) in components {
            let component = identity
                .source_components
                .get(*component_name)
                .expect("named upstream source component");
            assert_eq!(&component.version, version);
            assert_eq!(&component.revision, revision);
        }
        provider_ids.insert(identity.provider_id);
        languages.insert(identity.language);
    }
    assert_eq!(provider_ids.len(), 2, "provider IDs must not alias");
    assert_eq!(languages.len(), 2, "language identities must not alias");
}

/// FALSIFIER: provider health is a cross-language authority contract. Go must
/// be able to report its real package/type-checking components without
/// fabricating Rust build-script or proc-macro state.
#[test]
fn provider_health_wire_is_language_neutral() {
    let encoded = serde_json::json!({
        "components": {
            "package_graph": "healthy",
            "type_checking": "healthy"
        },
        "diagnostics_complete": true,
        "degradation_reasons": []
    });
    let health: ProviderHealthEvidence =
        serde_json::from_value(encoded).expect("language-neutral provider health wire");
    assert!(health.admits_complete());
    let roundtrip = serde_json::to_value(&health).expect("serialize admitted health");
    assert_eq!(
        roundtrip["components"]
            .as_object()
            .expect("component map")
            .len(),
        2,
        "populated component control"
    );

    let rust_only_legacy = serde_json::json!({
        "workspace_model": "healthy",
        "build_scripts": "healthy",
        "proc_macros": "healthy",
        "diagnostics_complete": true,
        "degradation_reasons": []
    });
    assert!(
        serde_json::from_value::<ProviderHealthEvidence>(rust_only_legacy).is_err(),
        "the unreleased protocol must not retain a second Rust-only health wire"
    );

    let typed_incomplete = serde_json::json!({
        "components": {
            "module_resolution": "failed",
            "project_graph": "healthy",
            "type_checking": "healthy"
        },
        "diagnostics_complete": false,
        "degradation_reasons": ["unresolved_imports"]
    });
    let failed: ProviderHealthEvidence = serde_json::from_value(typed_incomplete.clone())
        .expect("failed is the protocol's typed incomplete component state");
    assert!(
        !failed.admits_complete(),
        "typed incomplete health must decode without authorizing semantic output"
    );

    let mut unknown_wire_state = typed_incomplete;
    unknown_wire_state["components"]["module_resolution"] = serde_json::json!("degraded");
    assert!(
        serde_json::from_value::<ProviderHealthEvidence>(unknown_wire_state).is_err(),
        "provider-specific code must not invent health states the shared decoder cannot name"
    );
}

/// FALSIFIER: one semantic provider may intentionally compose more than one
/// pinned upstream. Its executable identity must name every source component
/// instead of pretending the implementation has one privileged upstream.
#[test]
fn provider_identity_wire_admits_composite_implementations() {
    let encoded = serde_json::json!({
        "protocol": SEMANTIC_PROVIDER_PROTOCOL,
        "provider_id": "h00-gopls-scip",
        "language": "go",
        "implementation_version": "gopls-v0.23.0+scip-go-v0.2.7/project-input-reconfigure=discard-on-failure/snapshot-inputs=exact/h00-v3",
        "source_components": {
            "gopls": {
                "version": "v0.23.0",
                "revision": "014f87ff5c01915bc90f4f11a6bb8aea3e0edbd7"
            },
            "scip_go": {
                "version": "v0.2.7",
                "revision": "2e9ff3c2603a85daabe125c9f20075ec52df0731"
            }
        },
        "patch_sha256": sha('a'),
        "executable_sha256": sha('b')
    });
    let identity: ProviderIdentity =
        serde_json::from_value(encoded).expect("composite provider identity wire");
    assert!(provider_identity_sha256(&identity).is_ok());
    let roundtrip = serde_json::to_value(identity).expect("serialize provider identity");
    assert_eq!(
        roundtrip["source_components"]
            .as_object()
            .expect("source component map")
            .len(),
        2,
        "both independently pinned upstreams must be identity-bearing"
    );
}

fn authority() -> ProviderAuthority {
    ProviderAuthority {
        session_id: "session-7".into(),
        root_sha256: sha('c'),
        root_topology_sha256: sha('d'),
        configuration_sha256: sha('e'),
        workspace_resolution_sha256: Some(sha('1')),
        semantic_inputs_sha256: Some(sha('2')),
        population_sha256: sha('f'),
        source_epoch: 9,
    }
}

fn healthy() -> ProviderHealthEvidence {
    ProviderHealthEvidence {
        components: BTreeMap::from([
            ("build_scripts".into(), ProviderComponentHealth::Healthy),
            ("proc_macros".into(), ProviderComponentHealth::Healthy),
            ("workspace_model".into(), ProviderComponentHealth::Healthy),
        ]),
        diagnostics_complete: true,
        degradation_reasons: Vec::new(),
    }
}

fn expected_documents() -> BTreeMap<String, ExpectedProviderDocument> {
    BTreeMap::from([
        (
            "src/changed.rs".into(),
            ExpectedProviderDocument {
                language: "rust".into(),
                content_identity: "blake3:changed".into(),
            },
        ),
        (
            "src/empty.rs".into(),
            ExpectedProviderDocument {
                language: "rust".into(),
                content_identity: "blake3:empty".into(),
            },
        ),
    ])
}

fn affected_runtime_configuration() -> ProviderRuntimeConfiguration {
    provider_runtime_configuration(
        &sha('6'),
        &[("rustc", b"rustc 1.97.1"), ("cargo", b"cargo 1.97.1")],
        b"exact-environment",
        b"exact-workspace-controls",
    )
    .expect("terminal runtime witness")
}

fn expected(request_id: u64) -> ExpectedAffectedRefresh {
    ExpectedAffectedRefresh {
        request_id,
        provider: provider(),
        authority: authority(),
        parent_snapshot_sha256: sha('1'),
        documents: expected_documents(),
        analyses: BTreeMap::new(),
        terminal_runtime_configuration: affected_runtime_configuration(),
    }
}

fn expected_full(request_id: u64) -> ExpectedFullCertification {
    ExpectedFullCertification {
        request_id,
        provider: provider(),
        authority: authority(),
        documents: expected_documents(),
        analyses: BTreeMap::new(),
    }
}

fn valid_frame(request_id: u64) -> ProviderFrame<ProviderResponse> {
    let document = b"canonical SCIP document".to_vec();
    ProviderFrame {
        metadata: ProviderResponse {
            request_id,
            session_id: authority().session_id,
            provider: provider(),
            body: ProviderResponseBody::AffectedRefreshed {
                authority: authority(),
                parent_snapshot_sha256: sha('1'),
                health: healthy(),
                runtime_configuration: affected_runtime_configuration(),
                outcomes: vec![
                    ProviderDocumentOutcome::Present {
                        document_path: "src/changed.rs".into(),
                        language: "rust".into(),
                        content_identity: "blake3:changed".into(),
                        canonical_document_sha256:
                            "c64d0d6cab5a8ccd8e8a17c10d6845873e4f4cfb1fdc12534a5b412ad2241785"
                                .into(),
                        attachment_index: 0,
                    },
                    ProviderDocumentOutcome::Omitted {
                        document_path: "src/empty.rs".into(),
                        language: "rust".into(),
                        content_identity: "blake3:empty".into(),
                    },
                ],
                analyses: Vec::new(),
            },
        },
        attachments: vec![document],
    }
}

fn valid_full_frame(request_id: u64) -> ProviderFrame<ProviderResponse> {
    let mut frame = valid_frame(request_id);
    let ProviderResponseBody::AffectedRefreshed {
        authority,
        health,
        outcomes,
        analyses,
        ..
    } = frame.metadata.body
    else {
        unreachable!("affected fixture")
    };
    frame.metadata.body = ProviderResponseBody::FullCertification {
        authority,
        health,
        outcomes,
        analyses,
    };
    frame
}

#[test]
fn affected_refresh_is_bounded_exact_and_fail_closed() {
    let limits = ProviderFrameLimits::default();
    let request_id = 41;
    let frame = valid_frame(request_id);
    let encoded = encode_provider_frame(&frame, &limits).expect("encode bounded frame");
    let decoded: ProviderFrame<ProviderResponse> =
        decode_provider_frame(&encoded, &limits).expect("decode bounded frame");
    let admitted = validate_affected_refresh(decoded, &expected(request_id), &limits)
        .expect("admit exact response");
    assert_eq!(admitted.documents.len(), 2);
    assert!(admitted.analyses.is_empty());
    assert!(matches!(
        &admitted.documents[0],
        AdmittedProviderDocument::Present { document_path, .. }
            if document_path == "src/changed.rs"
    ));
    assert!(matches!(
        &admitted.documents[1],
        AdmittedProviderDocument::Omitted { document_path }
            if document_path == "src/empty.rs"
    ));

    let mut oversized_limits = limits;
    oversized_limits.max_frame_bytes = encoded.len() - 1;
    assert!(decode_provider_frame::<ProviderResponse>(&encoded, &oversized_limits).is_err());

    let mut attacks = Vec::new();
    let mut stale = valid_frame(request_id);
    if let ProviderResponseBody::AffectedRefreshed { authority, .. } = &mut stale.metadata.body {
        authority.source_epoch -= 1;
    }
    attacks.push(stale);

    let mut wrong_parent = valid_frame(request_id);
    if let ProviderResponseBody::AffectedRefreshed {
        parent_snapshot_sha256,
        ..
    } = &mut wrong_parent.metadata.body
    {
        *parent_snapshot_sha256 = sha('2');
    }
    attacks.push(wrong_parent);

    let mut unhealthy = valid_frame(request_id);
    if let ProviderResponseBody::AffectedRefreshed { health, .. } = &mut unhealthy.metadata.body {
        health
            .components
            .insert("build_scripts".into(), ProviderComponentHealth::Failed);
        health.degradation_reasons.push("build data failed".into());
    }
    attacks.push(unhealthy);

    let mut missing = valid_frame(request_id);
    if let ProviderResponseBody::AffectedRefreshed { outcomes, .. } = &mut missing.metadata.body {
        outcomes.pop();
    }
    attacks.push(missing);

    let mut duplicate = valid_frame(request_id);
    if let ProviderResponseBody::AffectedRefreshed { outcomes, .. } = &mut duplicate.metadata.body {
        outcomes.push(outcomes[0].clone());
    }
    attacks.push(duplicate);

    let mut foreign = valid_frame(request_id);
    foreign.metadata.provider.executable_sha256 = sha('9');
    attacks.push(foreign);

    let mut wrong_hash = valid_frame(request_id);
    if let ProviderResponseBody::AffectedRefreshed { outcomes, .. } = &mut wrong_hash.metadata.body
        && let ProviderDocumentOutcome::Present {
            canonical_document_sha256,
            ..
        } = &mut outcomes[0]
    {
        *canonical_document_sha256 = sha('0');
    }
    attacks.push(wrong_hash);

    let mut extra_attachment = valid_frame(request_id);
    extra_attachment.attachments.push(b"unclaimed".to_vec());
    attacks.push(extra_attachment);

    assert_eq!(attacks.len(), 8, "non-vacuous sabotage population");
    for attack in attacks {
        assert!(
            validate_affected_refresh(attack, &expected(request_id), &limits).is_err(),
            "every authority or coverage sabotage must fail closed"
        );
    }
}

#[test]
fn full_certification_uses_the_same_exact_fail_closed_admission() {
    let limits = ProviderFrameLimits::default();
    let request_id = 43;
    let admitted = validate_full_certification(
        valid_full_frame(request_id),
        &expected_full(request_id),
        &limits,
    )
    .expect("admit exact full certification");
    assert_eq!(
        admitted.documents.len(),
        2,
        "known-positive full population"
    );
    assert!(admitted.analyses.is_empty());

    let mut attacks = Vec::new();
    let mut stale = valid_full_frame(request_id);
    if let ProviderResponseBody::FullCertification { authority, .. } = &mut stale.metadata.body {
        authority.source_epoch -= 1;
    }
    attacks.push(stale);

    let mut unhealthy = valid_full_frame(request_id);
    if let ProviderResponseBody::FullCertification { health, .. } = &mut unhealthy.metadata.body {
        health.diagnostics_complete = false;
    }
    attacks.push(unhealthy);

    let mut missing = valid_full_frame(request_id);
    if let ProviderResponseBody::FullCertification { outcomes, .. } = &mut missing.metadata.body {
        outcomes.pop();
    }
    attacks.push(missing);

    let mut wrong_identity = valid_full_frame(request_id);
    wrong_identity.metadata.provider.patch_sha256 = sha('9');
    attacks.push(wrong_identity);

    let mut unclaimed = valid_full_frame(request_id);
    unclaimed.attachments.push(b"unclaimed".to_vec());
    attacks.push(unclaimed);

    assert_eq!(attacks.len(), 5, "non-vacuous full sabotage population");
    for attack in attacks {
        assert!(
            validate_full_certification(attack, &expected_full(request_id), &limits).is_err(),
            "every full-certification authority or coverage sabotage must fail closed"
        );
    }

    assert!(
        validate_full_certification(valid_frame(request_id), &expected_full(request_id), &limits)
            .is_err(),
        "an affected terminal cannot masquerade as full certification"
    );
}

#[test]
fn full_certification_admits_each_requested_analysis_once_and_fail_closed() {
    let limits = ProviderFrameLimits::default();
    let request_id = 44;
    let analysis = br#"{"schema_version":"fixture/liveness/v1","items":[]}"#.to_vec();
    let mut expected = expected_full(request_id);
    expected.analyses.insert(
        "callable_liveness".into(),
        ExpectedProviderAnalysis {
            schema_version: "fixture/liveness/v1".into(),
            configuration_id: "fixture-rta-v1".into(),
            language: "rust".into(),
        },
    );
    let mut valid = valid_full_frame(request_id);
    let ProviderResponseBody::FullCertification { analyses, .. } = &mut valid.metadata.body else {
        unreachable!("full fixture")
    };
    analyses.push(ProviderAnalysisOutcome {
        analysis_id: "callable_liveness".into(),
        schema_version: "fixture/liveness/v1".into(),
        configuration_id: "fixture-rta-v1".into(),
        language: "rust".into(),
        canonical_analysis_sha256: sha256_hex(&analysis),
        attachment_index: 1,
    });
    valid.attachments.push(analysis);

    let admitted = validate_full_certification(valid.clone(), &expected, &limits)
        .expect("admit document and typed analysis attachments");
    assert_eq!(admitted.documents.len(), 2, "populated document control");
    assert_eq!(admitted.analyses.len(), 1, "populated analysis control");
    assert_eq!(
        admitted.analyses[0].analysis_id, "callable_liveness",
        "the exact requested analysis must survive admission"
    );

    let mut attacks = Vec::new();
    let mut missing = valid.clone();
    if let ProviderResponseBody::FullCertification { analyses, .. } = &mut missing.metadata.body {
        analyses.clear();
    }
    attacks.push(missing);

    let mut wrong_configuration = valid.clone();
    if let ProviderResponseBody::FullCertification { analyses, .. } =
        &mut wrong_configuration.metadata.body
    {
        analyses[0].configuration_id = "different-rta".into();
    }
    attacks.push(wrong_configuration);

    let mut wrong_digest = valid.clone();
    if let ProviderResponseBody::FullCertification { analyses, .. } =
        &mut wrong_digest.metadata.body
    {
        analyses[0].canonical_analysis_sha256 = sha('0');
    }
    attacks.push(wrong_digest);

    let mut reused_attachment = valid;
    if let ProviderResponseBody::FullCertification { analyses, .. } =
        &mut reused_attachment.metadata.body
    {
        analyses[0].attachment_index = 0;
    }
    attacks.push(reused_attachment);

    assert_eq!(attacks.len(), 4, "non-vacuous analysis sabotage population");
    for attack in attacks {
        assert!(
            validate_full_certification(attack, &expected, &limits).is_err(),
            "missing, altered, corrupt, or multiply claimed analysis authority must fail closed"
        );
    }
}

#[test]
fn response_claims_are_session_owned_one_use_and_replay_resistant() {
    let mut claims = ProviderRequestClaims::new("session-7", 4).expect("claim ledger");
    let request_id = claims
        .issue(ProviderOperation::RefreshAffected)
        .expect("issue request");
    assert_eq!(claims.outstanding_ids(), BTreeSet::from([request_id]));

    assert!(
        claims
            .claim(
                "foreign-session",
                request_id,
                ProviderOperation::RefreshAffected
            )
            .is_err(),
        "a foreign process/session receives no authority"
    );
    assert_eq!(claims.outstanding_ids(), BTreeSet::from([request_id]));

    claims
        .claim("session-7", request_id, ProviderOperation::RefreshAffected)
        .expect("claim exact terminal response");
    assert!(claims.outstanding_ids().is_empty());
    assert!(
        claims
            .claim("session-7", request_id, ProviderOperation::RefreshAffected)
            .is_err(),
        "a terminal response cannot be replayed"
    );
}

#[test]
fn frame_decoder_rejects_length_magic_attachment_and_schema_sabotage() {
    let limits = ProviderFrameLimits::default();
    let valid = encode_provider_frame(&valid_frame(71), &limits).expect("valid encoded frame");
    let mut attacks = Vec::new();

    let mut bad_magic = valid.clone();
    bad_magic[0] ^= 0xff;
    attacks.push(bad_magic);

    let mut bad_total = valid.clone();
    bad_total[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    attacks.push(bad_total);

    attacks.push(valid[..valid.len() - 1].to_vec());

    let metadata_len = u32::from_be_bytes(valid[12..16].try_into().expect("metadata length"));
    let attachment_length_offset = 20 + metadata_len as usize;
    let mut bad_attachment = valid;
    bad_attachment[attachment_length_offset..attachment_length_offset + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    attacks.push(bad_attachment);

    assert_eq!(attacks.len(), 4, "non-vacuous malformed frame population");
    for attack in attacks {
        assert!(
            decode_provider_frame::<ProviderResponse>(&attack, &limits).is_err(),
            "malformed frame must fail before authority admission"
        );
    }

    let mut metadata = serde_json::to_value(valid_frame(71).metadata).expect("metadata value");
    metadata
        .as_object_mut()
        .expect("response object")
        .insert("unexpected_field".into(), serde_json::json!(true));
    let unknown_field = encode_provider_frame(
        &ProviderFrame {
            metadata,
            attachments: vec![b"canonical SCIP document".to_vec()],
        },
        &limits,
    )
    .expect("encode unknown-field sabotage");
    assert!(
        decode_provider_frame::<ProviderResponse>(&unknown_field, &limits).is_err(),
        "unknown metadata fields cannot silently change protocol meaning"
    );
}

#[test]
fn stream_transport_round_trips_and_refuses_oversized_or_partial_frames() {
    let limits = ProviderFrameLimits::default();
    let frame = valid_frame(93);
    let mut stream = Vec::new();
    write_provider_frame(&mut stream, &frame, &limits).expect("write complete frame");
    let decoded: ProviderFrame<ProviderResponse> =
        read_provider_frame(&mut std::io::Cursor::new(&stream), &limits)
            .expect("read complete frame");
    assert_eq!(decoded, frame);

    let mut partial = stream.clone();
    partial.pop();
    assert!(
        read_provider_frame::<_, ProviderResponse>(&mut std::io::Cursor::new(partial), &limits)
            .is_err(),
        "partial persistence must never become a decoded terminal"
    );

    let mut oversized_header = stream[..20].to_vec();
    oversized_header[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        read_provider_frame::<_, ProviderResponse>(
            &mut std::io::Cursor::new(oversized_header),
            &limits
        )
        .is_err(),
        "declared lengths are bounded before allocation"
    );
}

#[test]
fn provider_requests_bind_population_epoch_and_replacement_bytes() {
    let limits = ProviderFrameLimits::default();
    let before = b"fn changed() { before(); }".to_vec();
    let after = b"fn changed() { after(); }".to_vec();
    let mut sources = vec![
        ProviderSourceIdentity {
            document_path: "src/changed.rs".into(),
            language: "rust".into(),
            content_identity: "blake3:before".into(),
            content_sha256: sha_bytes(&before),
        },
        ProviderSourceIdentity {
            document_path: "src/stable.rs".into(),
            language: "rust".into(),
            content_identity: "blake3:stable".into(),
            content_sha256: sha_bytes(b"fn stable() {}"),
        },
    ];
    let mut base_authority = authority();
    base_authority.workspace_resolution_sha256 = None;
    base_authority.semantic_inputs_sha256 = None;
    base_authority.population_sha256 =
        source_population_sha256(&sources, &limits).expect("base population");

    let open = ProviderFrame {
        metadata: ProviderRequest {
            request_id: 1,
            session_id: base_authority.session_id.clone(),
            expected_provider: provider(),
            body: ProviderRequestBody::OpenSession {
                repository_root: "/scratch/repo".into(),
                execution_root: "/scratch/repo".into(),
                execution_prefix: String::new(),
                authority: base_authority.clone(),
                sources: sources.clone(),
                expected_semantic_inputs: None,
            },
        },
        attachments: Vec::new(),
    };
    validate_provider_request(&open, &limits).expect("exact open request");
    base_authority.workspace_resolution_sha256 = Some(sha('1'));
    base_authority.semantic_inputs_sha256 = Some(sha('2'));

    sources[0].content_identity = "blake3:after".into();
    sources[0].content_sha256 = sha_bytes(&after);
    let mut next_authority = base_authority.clone();
    next_authority.source_epoch += 1;
    next_authority.population_sha256 =
        source_population_sha256(&sources, &limits).expect("next population");
    let replace = ProviderSourceChange::Replace {
        document_path: "src/changed.rs".into(),
        language: "rust".into(),
        previous_content_identity: "blake3:before".into(),
        previous_content_sha256: sha_bytes(&before),
        content_identity: "blake3:after".into(),
        content_sha256: sha_bytes(&after),
        attachment_index: 0,
    };
    let apply = ProviderFrame {
        metadata: ProviderRequest {
            request_id: 2,
            session_id: base_authority.session_id.clone(),
            expected_provider: provider(),
            body: ProviderRequestBody::ApplyEpoch {
                previous_authority: base_authority,
                next_authority,
                changes: vec![replace],
            },
        },
        attachments: vec![after],
    };
    validate_provider_request(&apply, &limits).expect("exact epoch replacement");

    let mut attacks = Vec::new();
    let mut wrong_bytes = apply.clone();
    wrong_bytes.attachments[0][0] ^= 1;
    attacks.push(wrong_bytes);

    let mut duplicate = apply.clone();
    if let ProviderRequestBody::ApplyEpoch { changes, .. } = &mut duplicate.metadata.body {
        changes.push(changes[0].clone());
    }
    attacks.push(duplicate);

    let mut stale = apply.clone();
    if let ProviderRequestBody::ApplyEpoch {
        previous_authority,
        next_authority,
        ..
    } = &mut stale.metadata.body
    {
        next_authority.source_epoch = previous_authority.source_epoch;
    }
    attacks.push(stale);

    let mut skipped = apply.clone();
    if let ProviderRequestBody::ApplyEpoch {
        previous_authority,
        next_authority,
        ..
    } = &mut skipped.metadata.body
    {
        next_authority.source_epoch = previous_authority.source_epoch + 2;
    }
    attacks.push(skipped);

    let mut foreign = apply.clone();
    foreign.metadata.session_id = "foreign-session".into();
    attacks.push(foreign);

    let mut unclaimed = apply;
    unclaimed.attachments.push(b"unclaimed".to_vec());
    attacks.push(unclaimed);

    assert_eq!(attacks.len(), 6, "non-vacuous request sabotage population");
    for attack in attacks {
        assert!(
            validate_provider_request(&attack, &limits).is_err(),
            "mutative provider requests fail closed before host mutation"
        );
    }
}

/// FALSIFIER: one affected refresh is one provider-owned transaction. The
/// source-epoch mutation, compiler export, and post-work runtime witness must
/// not be split across independently admitted requests whose repeated runtime
/// observations dominate warm WATCH latency.
#[test]
fn affected_refresh_is_one_witnessed_protocol_transaction() {
    let limits = ProviderFrameLimits::default();
    let replacement_bytes = b"fn changed() { after(); }".to_vec();
    let previous_authority = authority();
    let mut next_authority = previous_authority.clone();
    next_authority.source_epoch += 1;
    next_authority.population_sha256 = sha('9');
    let request = serde_json::json!({
        "operation": "refresh_affected",
        "previous_authority": previous_authority,
        "next_authority": next_authority,
        "changes": [{
            "outcome": "replace",
            "document_path": "src/changed.rs",
            "language": "rust",
            "previous_content_identity": "blake3:before",
            "previous_content_sha256": sha('3'),
            "content_identity": "blake3:after",
            "content_sha256": sha_bytes(&replacement_bytes),
            "attachment_index": 0
        }],
        "parent_snapshot_sha256": sha('5'),
        "documents": ["src/changed.rs"],
        "analyses": []
    });
    let decoded: ProviderRequestBody = serde_json::from_value(request)
        .expect("one request must own mutation and affected refresh");
    assert_eq!(
        serde_json::to_value(&decoded).expect("encode affected refresh")["operation"],
        "refresh_affected",
        "known-positive operation discriminator"
    );
    let frame = ProviderFrame {
        metadata: ProviderRequest {
            request_id: 27,
            session_id: previous_authority.session_id,
            expected_provider: provider(),
            body: decoded,
        },
        attachments: vec![replacement_bytes],
    };
    validate_provider_request(&frame, &limits)
        .expect("one exact affected-refresh request must validate before provider mutation");
    let mut request_attacks = Vec::new();
    let mut missing_documents = frame.clone();
    if let ProviderRequestBody::RefreshAffected { documents, .. } =
        &mut missing_documents.metadata.body
    {
        documents.clear();
    }
    request_attacks.push(missing_documents);

    let mut changed_topology = frame.clone();
    if let ProviderRequestBody::RefreshAffected { next_authority, .. } =
        &mut changed_topology.metadata.body
    {
        next_authority.root_topology_sha256 = sha('0');
    }
    request_attacks.push(changed_topology);

    let mut stale = frame.clone();
    if let ProviderRequestBody::RefreshAffected {
        previous_authority,
        next_authority,
        ..
    } = &mut stale.metadata.body
    {
        next_authority.source_epoch = previous_authority.source_epoch;
    }
    request_attacks.push(stale);

    let mut skipped = frame.clone();
    if let ProviderRequestBody::RefreshAffected {
        previous_authority,
        next_authority,
        ..
    } = &mut skipped.metadata.body
    {
        next_authority.source_epoch = previous_authority.source_epoch + 2;
    }
    request_attacks.push(skipped);

    let mut wrapped = frame.clone();
    if let ProviderRequestBody::RefreshAffected {
        previous_authority,
        next_authority,
        ..
    } = &mut wrapped.metadata.body
    {
        previous_authority.source_epoch = u64::MAX;
        next_authority.source_epoch = 0;
    }
    request_attacks.push(wrapped);

    let mut changed_attachment = frame;
    changed_attachment.attachments[0][0] ^= 1;
    request_attacks.push(changed_attachment);
    assert_eq!(request_attacks.len(), 6, "request sabotage population");
    for attack in request_attacks {
        assert!(
            validate_provider_request(&attack, &limits).is_err(),
            "authority, coverage, or attachment sabotage must fail before provider mutation"
        );
    }

    let runtime_configuration = affected_runtime_configuration();
    let response = serde_json::json!({
        "result": "affected_refreshed",
        "authority": next_authority,
        "parent_snapshot_sha256": sha('5'),
        "health": healthy(),
        "runtime_configuration": runtime_configuration,
        "outcomes": [],
        "analyses": []
    });
    let decoded: ProviderResponseBody = serde_json::from_value(response.clone())
        .expect("one terminal must carry affected evidence and its post-work runtime witness");
    assert_eq!(
        serde_json::to_value(decoded).expect("encode affected terminal")["result"],
        "affected_refreshed",
        "known-positive terminal discriminator"
    );

    let mut missing_witness = response;
    missing_witness
        .as_object_mut()
        .expect("response object")
        .remove("runtime_configuration");
    assert!(
        serde_json::from_value::<ProviderResponseBody>(missing_witness).is_err(),
        "an affected terminal without its post-work runtime witness must fail closed"
    );

    let request_id = 28;
    let mut terminal = valid_frame(request_id);
    assert_eq!(
        validate_affected_refresh(terminal.clone(), &expected(request_id), &limits)
            .expect("admit exact witnessed affected terminal")
            .documents
            .len(),
        2,
        "populated affected-document control"
    );

    let ProviderResponseBody::AffectedRefreshed {
        runtime_configuration,
        ..
    } = &mut terminal.metadata.body
    else {
        unreachable!("witnessed terminal fixture")
    };
    *runtime_configuration = provider_runtime_configuration(
        &sha('7'),
        &[("rustc", b"rustc drifted")],
        b"drifted-environment",
        b"exact-workspace-controls",
    )
    .expect("self-consistent foreign runtime witness");
    assert!(
        validate_affected_refresh(terminal, &expected(request_id), &limits).is_err(),
        "a self-consistent but foreign terminal runtime witness must fail closed"
    );
}

#[test]
fn session_reconfiguration_binds_exact_prior_and_provider_observed_next_authority() {
    let limits = ProviderFrameLimits::default();
    let previous = authority();
    let mut next = previous.clone();
    next.root_topology_sha256 = sha('a');
    next.workspace_resolution_sha256 = None;
    next.semantic_inputs_sha256 = None;
    next.source_epoch += 1;
    let frame = ProviderFrame {
        metadata: ProviderRequest {
            request_id: 41,
            session_id: previous.session_id.clone(),
            expected_provider: provider(),
            body: ProviderRequestBody::ReconfigureSession {
                previous_authority: previous,
                next_authority: next,
                expected_semantic_inputs: ProviderSemanticInputs::empty(),
            },
        },
        attachments: Vec::new(),
    };
    validate_provider_request(&frame, &limits)
        .expect("exact project-input reconfiguration request");

    let mut attacks = Vec::new();
    let mut unchanged_topology = frame.clone();
    if let ProviderRequestBody::ReconfigureSession {
        previous_authority,
        next_authority,
        ..
    } = &mut unchanged_topology.metadata.body
    {
        next_authority.root_topology_sha256 = previous_authority.root_topology_sha256.clone();
    }
    attacks.push(unchanged_topology);

    let mut predeclared_workspace = frame.clone();
    if let ProviderRequestBody::ReconfigureSession { next_authority, .. } =
        &mut predeclared_workspace.metadata.body
    {
        next_authority.workspace_resolution_sha256 = Some(sha('b'));
    }
    attacks.push(predeclared_workspace);

    let mut predeclared_inputs = frame.clone();
    if let ProviderRequestBody::ReconfigureSession { next_authority, .. } =
        &mut predeclared_inputs.metadata.body
    {
        next_authority.semantic_inputs_sha256 = Some(sha('b'));
    }
    attacks.push(predeclared_inputs);

    let mut changed_population = frame.clone();
    if let ProviderRequestBody::ReconfigureSession { next_authority, .. } =
        &mut changed_population.metadata.body
    {
        next_authority.population_sha256 = sha('b');
    }
    attacks.push(changed_population);

    let mut changed_configuration = frame.clone();
    if let ProviderRequestBody::ReconfigureSession { next_authority, .. } =
        &mut changed_configuration.metadata.body
    {
        next_authority.configuration_sha256 = sha('b');
    }
    attacks.push(changed_configuration);

    let mut changed_root = frame.clone();
    if let ProviderRequestBody::ReconfigureSession { next_authority, .. } =
        &mut changed_root.metadata.body
    {
        next_authority.root_sha256 = sha('b');
    }
    attacks.push(changed_root);

    let mut stale_epoch = frame.clone();
    if let ProviderRequestBody::ReconfigureSession {
        previous_authority,
        next_authority,
        ..
    } = &mut stale_epoch.metadata.body
    {
        next_authority.source_epoch = previous_authority.source_epoch;
    }
    attacks.push(stale_epoch);

    let mut exhausted_epoch = frame.clone();
    if let ProviderRequestBody::ReconfigureSession {
        previous_authority,
        next_authority,
        ..
    } = &mut exhausted_epoch.metadata.body
    {
        previous_authority.source_epoch = u64::MAX;
        next_authority.source_epoch = u64::MAX;
    }
    attacks.push(exhausted_epoch);

    let mut foreign = frame.clone();
    foreign.metadata.session_id = "foreign-session".into();
    attacks.push(foreign);

    let mut attached = frame;
    attached.attachments.push(b"unclaimed".to_vec());
    attacks.push(attached);

    assert_eq!(attacks.len(), 10, "non-vacuous reconfiguration sabotage");
    for attack in attacks {
        assert!(
            validate_provider_request(&attack, &limits).is_err(),
            "project-input reconfiguration must fail before provider mutation"
        );
    }
}

#[test]
fn workspace_resolution_is_provider_observed_and_changes_effective_authority() {
    let limits = ProviderFrameLimits::default();
    let source = ProviderSourceIdentity {
        document_path: "src/lib.rs".into(),
        language: "rust".into(),
        content_identity: "blake3:source".into(),
        content_sha256: sha_bytes(b"pub fn source() {}\n"),
    };
    let mut pending = authority();
    pending.workspace_resolution_sha256 = None;
    pending.semantic_inputs_sha256 = None;
    pending.population_sha256 =
        source_population_sha256(std::slice::from_ref(&source), &limits).expect("population");
    let open = |authority: ProviderAuthority| ProviderFrame {
        metadata: ProviderRequest {
            request_id: 1,
            session_id: authority.session_id.clone(),
            expected_provider: provider(),
            body: ProviderRequestBody::OpenSession {
                repository_root: "/scratch/repo".into(),
                execution_root: "/scratch/repo".into(),
                execution_prefix: String::new(),
                authority,
                sources: vec![source.clone()],
                expected_semantic_inputs: None,
            },
        },
        attachments: Vec::new(),
    };
    validate_provider_request(&open(pending.clone()), &limits)
        .expect("open session begins without fabricated resolution");

    let mut predeclared = pending.clone();
    predeclared.workspace_resolution_sha256 = Some(sha('1'));
    predeclared.semantic_inputs_sha256 = Some(sha('2'));
    assert!(
        validate_provider_request(&open(predeclared.clone()), &limits).is_err(),
        "the client cannot fabricate provider-observed workspace resolution"
    );

    let first =
        resolved_authority_configuration_sha256(&predeclared).expect("first resolved authority");
    predeclared.workspace_resolution_sha256 = Some(sha('2'));
    let second =
        resolved_authority_configuration_sha256(&predeclared).expect("second resolved authority");
    assert_ne!(
        first, second,
        "dependency-resolution drift must change immutable authority even when runtime and sources match"
    );
    predeclared.semantic_inputs_sha256 = Some(sha('3'));
    let third = resolved_authority_configuration_sha256(&predeclared)
        .expect("semantic-input resolved authority");
    assert_ne!(
        second, third,
        "non-source semantic-input drift must change immutable authority independently of source bytes"
    );
    assert!(
        resolved_authority_configuration_sha256(&pending).is_err(),
        "unresolved authority cannot reach canonical publication"
    );
}

/// FALSIFIER: this transport owns exactly one request at a time. The parent
/// cancels an in-flight request by quarantining and reaping the disposable
/// provider process; a queued `cancel` frame cannot interrupt that request and
/// must not pretend otherwise in the protocol contract.
#[test]
fn serial_provider_protocol_does_not_claim_in_band_cancellation() {
    let hello = serde_json::from_str::<ProviderRequestBody>(r#"{"operation":"hello"}"#)
        .expect("known-positive provider request");
    assert!(matches!(hello, ProviderRequestBody::Hello));
    assert!(
        serde_json::from_str::<ProviderRequestBody>(
            r#"{"operation":"cancel","target_request_id":1}"#
        )
        .is_err(),
        "a serial provider must not acknowledge cancellation it cannot observe until work ends"
    );
}
