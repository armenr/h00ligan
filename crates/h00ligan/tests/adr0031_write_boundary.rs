//! Source-population controls for code-intelligence write chokepoints.
//!
//! Behavioral tests cover the real CLI/MCP refusals. These guards make the
//! negative claims exhaustive: every current adapter is enumerated, each probe
//! has a planted positive, and a reintroduced split-bundle writer or root-only
//! provider authority fails loudly.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_production_prefix(relative: &str) -> String {
    let source = read(relative);
    let marker = "\n#[cfg(test)]\nmod tests";
    let (production, tests) = source
        .split_once(marker)
        .unwrap_or_else(|| panic!("{relative} must expose a bounded cfg(test) module boundary"));
    assert!(
        !production.trim().is_empty() && !tests.trim().is_empty(),
        "{relative} production and test populations must both be nonempty"
    );
    production.to_owned()
}

#[test]
fn retired_split_bundle_api_is_absent_from_the_production_population() {
    let engine_lib = read("crates/h00ligan-engine/src/lib.rs");
    let graph_store = read("crates/h00ligan-engine/src/graph_store.rs");
    let index_state = read("crates/h00ligan-engine/src/index_state.rs");
    let project_binding = read("crates/h00ligan-engine/src/project_binding.rs");
    let ligan_binding = read("crates/h00ligan/src/binding.rs");
    let ligan_error = read("crates/h00ligan/src/error.rs");

    for (source, known_positive) in [
        (engine_lib.as_str(), "pub mod code_intel_publication"),
        (graph_store.as_str(), "pub async fn load_snapshot_checked"),
        (index_state.as_str(), "pub struct IndexState"),
        (project_binding.as_str(), "IMMUTABLE_PUBLICATION_DIRECTORY"),
        (ligan_binding.as_str(), "pub fn resolve_project_binding"),
        (ligan_error.as_str(), "IndexPublication("),
    ] {
        assert!(
            source.contains(known_positive),
            "known-positive control must prove each searched source was populated: {known_positive}"
        );
    }

    assert!(
        !repo_root()
            .join("crates/h00ligan-engine/src/graph_bundle.rs")
            .exists(),
        "the superseded in-place graph/index lock-and-marker subsystem must stay removed"
    );
    assert!(
        !repo_root()
            .join("crates/h00ligan-engine/tests/graph_bundle_guard.rs")
            .exists(),
        "tests for the superseded subsystem must not preserve it as a second architecture"
    );
    for (path, source, retired) in [
        (
            "crates/h00ligan-engine/src/lib.rs",
            engine_lib.as_str(),
            "pub mod graph_bundle",
        ),
        (
            "crates/h00ligan-engine/src/graph_store.rs",
            graph_store.as_str(),
            "preflight_write_origin",
        ),
        (
            "crates/h00ligan-engine/src/project_binding.rs",
            project_binding.as_str(),
            "GRAPH_BUNDLE_ARTIFACTS",
        ),
        (
            "crates/h00ligan-engine/src/project_binding.rs",
            project_binding.as_str(),
            "ensure_graph_artifact_write",
        ),
        (
            "crates/h00ligan/src/binding.rs",
            ligan_binding.as_str(),
            "guard_graph_bundle_write",
        ),
        (
            "crates/h00ligan/src/binding.rs",
            ligan_binding.as_str(),
            "preflight_graph_write_origin",
        ),
    ] {
        assert!(
            !source.contains(retired),
            "{path} retains superseded split-bundle authority: {retired}"
        );
    }
    for retired_variant in ["Bundle(", "Store(", "Embed("] {
        assert!(
            !ligan_error.contains(retired_variant),
            "LiganError retains an unreachable legacy conversion: {retired_variant}"
        );
    }
    for retired_index_authority in [
        "pub fn open(dir:",
        "pub fn open_existing",
        "directory: PathBuf",
        "pub fn directory(&self)",
    ] {
        assert!(
            !index_state.contains(retired_index_authority),
            "IndexState retains standalone filesystem authority: {retired_index_authority}"
        );
    }
    for retired_read_choice in ["pub enum OnOriginMismatch", "on_mismatch: OnOriginMismatch"] {
        assert!(
            !graph_store.contains(retired_read_choice),
            "the read path retains write-side adoption authority: {retired_read_choice}"
        );
    }
}

#[test]
fn immutable_adapters_do_not_reenter_legacy_split_bundle_writers() {
    fn contains_abort(source: &str) -> bool {
        source.contains("abort_unmodified")
    }
    assert!(
        contains_abort("synthetic positive: abort_unmodified"),
        "planted positive must prove the absence probe can fire"
    );

    let retired_scip = repo_root().join("crates/h00ligan/src/scip_cmd.rs");
    assert!(
        !retired_scip.exists(),
        "the split-bundle SCIP writer module must stay removed"
    );
    for (path, source) in [
        (
            "crates/h00ligan-interface/src/tools/code_intel.rs",
            read("crates/h00ligan-interface/src/tools/code_intel.rs"),
        ),
        (
            "crates/h00ligan/src/graph_cmd.rs",
            read("crates/h00ligan/src/graph_cmd.rs"),
        ),
        (
            "crates/h00ligan/src/composite_cmd.rs",
            read("crates/h00ligan/src/composite_cmd.rs"),
        ),
    ] {
        assert_eq!(
            source.matches("BundleWriteLock::acquire").count(),
            0,
            "{path} must not reenter the legacy split-bundle writer"
        );
        assert!(
            !contains_abort(&source),
            "{path} reintroduced post-marker abort authority"
        );
    }
    let supervised_adapters = [
        (
            "crates/h00ligan/src/index_cmd.rs",
            "supervisor.start_manual_with_progress(request, progress)",
        ),
        (
            "crates/h00ligan-interface/src/tools/code_intel.rs",
            ".start_manual(request)",
        ),
    ];
    assert!(
        "synthetic BoundIndexPlan::prepare".contains("BoundIndexPlan::prepare"),
        "planted positive must prove the immutable-writer probe can fire"
    );
    for (path, supervisor_seam) in supervised_adapters {
        let source = read(path);
        assert_eq!(
            source.matches("BoundIndexPlan::prepare").count(),
            0,
            "{path} must not duplicate engine-owned indexing admission"
        );
        assert!(
            source.contains(supervisor_seam),
            "{path} must submit through the shared supervisor seam {supervisor_seam}"
        );
    }
    let composite_adapter = read("crates/h00ligan/src/composite_cmd.rs");
    assert!(
        composite_adapter.contains("pub async fn run_overview"),
        "known-positive: the composite read-adapter population must be nonempty"
    );
    assert_eq!(
        composite_adapter.matches("start_manual(").count()
            + composite_adapter
                .matches("start_manual_with_progress(")
                .count(),
        0,
        "composite reads must not retain a hidden indexing/writer entrypoint"
    );
    let supervisor = read_production_prefix("crates/h00ligan-engine/src/code_intel_supervisor.rs");
    assert_eq!(
        supervisor.matches("BoundIndexPlan::prepare").count(),
        1,
        "the engine supervisor must own exactly one immutable-plan admission"
    );
    let probe_reuse = supervisor
        .find(".probe_reuse(")
        .expect("shared immutable-reuse probe");
    let live_basis_transfer = supervisor
        .find("let live_basis = self.live_basis.lock().take()")
        .expect("unique live-basis transfer");
    let fresh_publication = supervisor
        .find(".publish_with_live_basis(")
        .expect("shared fresh-publication seam");
    assert_eq!(supervisor.matches(".probe_reuse(").count(), 1);
    assert_eq!(supervisor.matches(".publish_with_live_basis(").count(), 1);
    assert!(
        probe_reuse < live_basis_transfer && live_basis_transfer < fresh_publication,
        "the engine supervisor must probe immutable reuse before transferring the live basis into fresh publication"
    );
    let cli_adapter = read("crates/h00ligan/src/index_cmd.rs");
    assert!(
        cli_adapter.contains("signal = wait_for_cli_index_signal()")
            && cli_adapter.contains("supervisor.cancel(operation_id)")
            && cli_adapter.contains("map_supervised_outcome(outcome.await)"),
        "the CLI must route signal cancellation and reaping through the shared supervisor"
    );

    for (path, dispatch) in [
        (
            "crates/h00ligan/src/bin/h00ligan.rs",
            "h00ligan::product::run(",
        ),
        (
            "crates/h00ligan/src/cli.rs",
            "index_cmd::run_index_with_runtime(",
        ),
    ] {
        let source = read(path);
        assert!(
            source.contains(dispatch),
            "{path} must dispatch through the product-owned runtime and shared immutable CLI adapter"
        );
        assert_eq!(
            source.matches("BoundIndexPlan::prepare").count(),
            0,
            "{path} must not duplicate the shared indexing admission"
        );
    }

    let cli = read("crates/h00ligan/src/cli.rs");
    assert!(
        cli.contains("run_with_runtime_factory(||")
            && cli.contains("const fn requires_semantic_runtime(&self) -> bool")
            && cli.contains("runtime_for_command(&cli.command, runtime_factory)"),
        "CLI dispatch must classify semantic effects before initializing product runtime"
    );
    assert!(
        cli.contains("Self::Index(_) | Self::Watch(_) | Self::McpServe => true")
            && cli.contains("| Self::Diff(_) => false"),
        "the semantic-runtime partition must explicitly cover both mutating and read-only commands"
    );

    let installed_entrypoint = read("providers/rust-analyzer/h00ligan_embedded_main.rs");
    assert!(
        installed_entrypoint.contains("h00ligan::product::run(")
            && installed_entrypoint.contains("H00_GO_PROVIDER_BINARY_SHA256"),
        "the installed one-file adapter must enter shared product policy and use its build-bound digest"
    );
    assert!(
        !installed_entrypoint.contains("let runtime = match")
            && !installed_entrypoint.contains("sha256_hex(EMBEDDED_GO_PROVIDER)"),
        "the installed entrypoint must not attest semantic providers before command dispatch"
    );
}

#[test]
fn provider_generation_is_owned_by_the_bound_plan_and_disposable_artifact_policy() {
    let loader = read("crates/h00ligan-engine/src/scip_loader.rs");
    let agent = read("crates/h00ligan-interface/src/tools/code_intel.rs");
    let supervisor = read("crates/h00ligan-engine/src/code_intel_supervisor.rs");
    let indexing = read("crates/h00ligan-engine/src/code_intel_indexing.rs");
    let pipeline = read("crates/h00ligan-engine/src/index_pipeline.rs");
    let binding = read("crates/h00ligan-engine/src/project_binding.rs");
    let engine_lib = read("crates/h00ligan-engine/src/lib.rs");
    let ligan_lib = read("crates/h00ligan/src/lib.rs");

    assert!(
        "synthetic BoundIndexPlan::prepare".contains("BoundIndexPlan::prepare"),
        "planted positive must prove the provider-owner probe can fire"
    );
    assert!(
        !repo_root().join("crates/h00ligan/src/extract.rs").exists(),
        "the retired live-source extraction adapter must stay removed"
    );
    assert_eq!(
        engine_lib.matches("pub mod scip_auto").count(),
        0,
        "the retired provider runner must not remain as a second publication path"
    );
    assert!(
        !ligan_lib.contains("pub mod watch;") && !ligan_lib.contains("pub mod scip_cmd;"),
        "retired nonpublishing WATCH and split SCIP writer adapters must not remain exported"
    );
    assert!(
        ligan_lib.contains("pub mod watch_cmd;"),
        "known-positive: the supervised immutable WATCH adapter must remain exported"
    );
    assert!(
        agent.contains("IndexSupervisorRequest")
            && !agent.contains("BoundIndexPlan::prepare")
            && supervisor.contains("BoundIndexPlan::prepare"),
        "MCP provider intent must flow through the supervisor-owned bound plan"
    );
    assert!(
        indexing.contains("provider_data_root: Some(binding.graph_dir().to_path_buf())"),
        "the bound indexing use case must confine disposable provider work and reusable caches to the selected data directory"
    );
    assert!(
        indexing.contains("ensure_graph_directory_write(PROVIDER_CACHE_DIRECTORY)")
            && pipeline.contains("builder.tempdir_in(parent)")
            && pipeline.contains("data_root.join(PROVIDER_CACHE_DIRECTORY)"),
        "provider scratch and cache paths must remain admitted and derived from the selected data directory"
    );

    // The loader owns the disposable provider-artifact population. Project
    // root files with the same conventional names are neither inputs nor
    // outputs and therefore need no preflight/reset policy.
    for symbol in ["GeneratedScipArtifact", "provider_version"] {
        assert!(
            loader.contains(symbol),
            "the shared SCIP execution receipt is missing {symbol}"
        );
    }
    assert!(
        pipeline.contains("builder.prefix(\".h00-provider-\")"),
        "index_pipeline must allocate an invocation-scoped provider workspace"
    );
    assert!(
        pipeline.contains("GeneratedProviderArtifact")
            && pipeline.contains("normalize_scip_artifact_set_for_inventory_coverage")
            && pipeline.contains("execution_root"),
        "index_pipeline must carry every invocation root and executable identity into set normalization"
    );
    assert!(
        pipeline.contains("canonical_snapshot")
            && pipeline
                .contains("loader.load_scip_documents_in_memory(canonical_snapshot.documents())")
            && !pipeline.contains("load_scip_index_in_memory")
            && !pipeline.contains("load_scip_index_set_rebased")
            && loader.contains("load_scip_documents_in_memory"),
        "normalized and residual projections must share the admitted canonical SCIP document shards instead of materializing a second monolithic index or reopening provider artifacts"
    );
    for obsolete in [
        "ROOT_SCIP_ARTIFACTS",
        "preflight_root_scip_artifacts",
        "reset_root_scip_artifacts",
        "checked_generated_artifact_path",
        "pub fn generated_artifact_hygiene",
    ] {
        assert!(
            !loader.contains(obsolete)
                && !pipeline.contains(obsolete)
                && !binding.contains(obsolete),
            "project-root SCIP ownership must stay removed: {obsolete}"
        );
    }
}

#[test]
fn managed_writer_hygiene_is_owned_by_the_immutable_publication_plan() {
    let binding = read("crates/h00ligan-engine/src/project_binding.rs");
    let publication = read("crates/h00ligan-engine/src/code_intel_publication.rs");
    let standalone = read("crates/h00ligan/src/binding.rs");
    let cli_index = read("crates/h00ligan/src/index_cmd.rs");
    let mcp = read("crates/h00ligan-interface/src/tools/code_intel.rs");
    let indexing = read("crates/h00ligan-engine/src/code_intel_indexing.rs");

    assert!(
        mcp.contains(".index_supervisor()") && !mcp.contains("BoundIndexPlan::prepare"),
        "MCP must submit to the engine supervisor without duplicating publication admission"
    );

    assert_eq!(
        format!("{binding}\n{publication}")
            .matches("\"publication-v4\"")
            .count(),
        1,
        "filesystem policy and publisher must share one publication-directory spelling"
    );
    for (path, source, symbol) in [
        (
            "crates/h00ligan-engine/src/project_binding.rs",
            binding.as_str(),
            "IMMUTABLE_PUBLICATION_DIRECTORY",
        ),
        (
            "crates/h00ligan-engine/src/code_intel_publication.rs",
            publication.as_str(),
            "IMMUTABLE_PUBLICATION_DIRECTORY as PUBLICATION_DIRECTORY",
        ),
        (
            "crates/h00ligan-engine/src/code_intel_indexing.rs",
            indexing.as_str(),
            "ensure_graph_directory_write(IMMUTABLE_PUBLICATION_DIRECTORY)",
        ),
    ] {
        assert!(
            format!("synthetic positive: {symbol}").contains(symbol),
            "planted positive must prove the directory-policy probe can fire"
        );
        assert!(source.contains(symbol), "{path} is missing {symbol}");
    }
    assert!(
        binding.contains("inspect_generated_directory")
            && standalone.contains("resolve_project_binding")
            && !standalone.contains("ensure_graph_directory_write"),
        "the engine must own directory-output admission instead of a standalone adapter"
    );
    assert!(
        cli_index.contains(".supervisor(binding)")
            && cli_index.contains("start_manual_with_progress")
            && !cli_index.contains("BoundIndexPlan::prepare")
            && !cli_index.contains("IndexSupervisor::new")
            && !cli_index.contains("guard_immutable_index_write"),
        "the CLI adapter must receive product runtime policy and rely on its engine supervisor instead of duplicating admission"
    );
}
