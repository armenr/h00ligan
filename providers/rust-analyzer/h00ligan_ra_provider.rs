//! Exact-version rust-analyzer semantic provider for h00ligan.
//!
//! This file is compiled inside the pinned Rust source workspace after h00ligan's
//! narrow upstream patch exposes exact-file `StaticIndex` computation and the
//! same canonical SCIP emitter used by `rust-analyzer scip`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, bail};
use h00ligan_provider_protocol::{
    H00_RUST_ANALYZER_IMPLEMENTATION_V5, H00_RUST_ANALYZER_LANGUAGE,
    H00_RUST_ANALYZER_PROVIDER_ID, ProviderAuthority, ProviderComponentHealth,
    ProviderDocumentOutcome, ProviderFrame, ProviderFrameLimits, ProviderHealthEvidence,
    ProviderIdentity, ProviderRequest, ProviderRequestBody, ProviderResponse, ProviderResponseBody,
    ProviderRuntimeConfiguration, ProviderSemanticInputCoverage, ProviderSemanticInputIssue,
    ProviderSemanticInputs, ProviderSourceChange, ProviderSourceIdentity,
    PROVIDER_PARENT_PID_ENV, RESOLVED_CARGO_SHA256_ENV, RESOLVED_RUSTC_SHA256_ENV,
    RESOLVED_TOOLCHAIN_SHA256_ENV, RUST_SEMANTIC_PROFILE_ENV, RustCargoFeatures,
    RustSemanticProfile, SEMANTIC_PROVIDER_PROTOCOL, capture_provider_semantic_inputs,
    provider_semantic_inputs_sha256, read_provider_frame, rust_analyzer_runtime_configuration,
    rust_analyzer_source_components, sha256_hex, source_population_sha256,
    validate_provider_request, validate_runtime_configuration, write_provider_frame,
};
use hir::ChangeWithProcMacros;
use ide::{AnalysisHost, StaticIndex};
use load_cargo::{LoadCargoConfig, ProcMacroServerChoice, load_workspace};
use project_model::{
    CargoWorkspace, ProjectManifest, ProjectWorkspace, ProjectWorkspaceKind, WorkspaceBuildScripts,
};
use protobuf::Message as _;
use rust_analyzer::{
    cli::scip::h00_emit_static_index,
    config::{Config, ConfigChange},
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use vfs::{AbsPathBuf, FileExcluded, VfsPath};

const PATCH_SHA256: &str = env!("H00_RA_PATCH_SHA256");

struct RootSession {
    execution_root: AbsPathBuf,
    execution_prefix: String,
    host: AnalysisHost,
    vfs: vfs::Vfs,
    authority: ProviderAuthority,
    sources: BTreeMap<String, ProviderSourceIdentity>,
    health: ProviderHealthEvidence,
    workspace_inputs: WorkspaceInputPlan,
}

/// Exact filesystem and environment population Cargo used to produce the
/// build-script outputs and proc-macro executables loaded by this session.
/// Paths never cross the wire; only their digest enters provider authority.
#[derive(Debug)]
struct WorkspaceInputPlan {
    paths: BTreeSet<PathBuf>,
    environment: BTreeMap<String, Option<String>>,
    admitted_sha256: String,
    semantic_inputs: ProviderSemanticInputs,
}

struct ProviderTerminal {
    body: ProviderResponseBody,
    attachments: Vec<Vec<u8>>,
}

impl ProviderTerminal {
    const fn empty(body: ProviderResponseBody) -> Self {
        Self {
            body,
            attachments: Vec::new(),
        }
    }
}

// Holding the stdin lock for the process lifetime is intentional: this is a
// single-owner framed stdio server, and releasing it between frames would let
// another reader steal bytes from the protocol stream.
#[allow(clippy::significant_drop_tightening)]
pub fn run_stdio() -> anyhow::Result<()> {
    arm_parent_liveness_guard()?;
    let limits = ProviderFrameLimits::default();
    let identity = executable_identity()?;
    let semantic_profile = RustSemanticProfile::from_environment_value(
        &std::env::var(RUST_SEMANTIC_PROFILE_ENV)
            .with_context(|| format!("read required {RUST_SEMANTIC_PROFILE_ENV}"))?,
    )
    .context("validate requested Rust semantic profile")?;
    let runtime_configuration = observe_runtime_configuration()?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = BufWriter::new(stdout.lock());
    let mut session = None::<RootSession>;
    let mut last_request_id = 0_u64;

    loop {
        let frame = read_provider_frame::<_, ProviderRequest>(&mut input, &limits)
            .context("read semantic-provider request")?;
        let request_id = frame.metadata.request_id;
        let session_id = frame.metadata.session_id.clone();
        let terminal = match validate_provider_request(&frame, &limits) {
            Ok(()) if request_id > last_request_id => {
                last_request_id = request_id;
                match handle_request(
                    &identity,
                    &semantic_profile,
                    &runtime_configuration,
                    &limits,
                    &mut session,
                    frame,
                ) {
                    Ok(terminal) => terminal,
                    Err(error) => ProviderTerminal::empty(ProviderResponseBody::Error {
                        code: "request_failed".into(),
                        message: bounded_error(&error),
                        retryable: false,
                    }),
                }
            }
            Ok(()) => ProviderTerminal::empty(ProviderResponseBody::Error {
                code: "replayed_request".into(),
                message: "request ID is not strictly monotonic for this process".into(),
                retryable: false,
            }),
            Err(error) => ProviderTerminal::empty(ProviderResponseBody::Error {
                code: "invalid_request".into(),
                message: bounded_text(&error.to_string(), 1024),
                retryable: false,
            }),
        };
        let close = matches!(&terminal.body, ProviderResponseBody::SessionClosed);
        write_provider_frame(
            &mut output,
            &ProviderFrame {
                metadata: ProviderResponse {
                    request_id,
                    session_id,
                    provider: identity.clone(),
                    body: terminal.body,
                },
                attachments: terminal.attachments,
            },
            &limits,
        )
        .context("write semantic-provider response")?;
        if close {
            return Ok(());
        }
    }
}

/// A provider is disposable acceleration owned by one h00ligan process. The
/// manager normally closes and reaps the whole provider process group, but a
/// SIGKILLed parent cannot execute that cleanup. This process-local thread
/// detects exact-parent loss and kills only the provider-owned process group;
/// it installs no service and creates no persistent machine state.
fn arm_parent_liveness_guard() -> anyhow::Result<()> {
    // SAFETY: these calls only observe the current process relationship.
    let process = unsafe { libc::getpid() };
    // SAFETY: see above.
    let process_group = unsafe { libc::getpgrp() };
    if process_group != process {
        bail!("semantic provider must own its process group");
    }
    let expected_parent = std::env::var(PROVIDER_PARENT_PID_ENV)
        .with_context(|| format!("read required {PROVIDER_PARENT_PID_ENV}"))?
        .parse::<libc::pid_t>()
        .with_context(|| format!("parse required {PROVIDER_PARENT_PID_ENV}"))?;
    // SAFETY: see above.
    let observed_parent = unsafe { libc::getppid() };
    if expected_parent <= 1 || observed_parent != expected_parent {
        bail!("semantic provider owning parent changed before liveness guard armed");
    }
    std::thread::Builder::new()
        .name("h00-provider-parent-guard".into())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
                // SAFETY: getppid only observes the current parent relationship.
                let current_parent = unsafe { libc::getppid() };
                if current_parent == expected_parent {
                    continue;
                }
                // SAFETY: group zero targets only the caller's process group. The
                // precondition above proves this provider is that group's leader.
                unsafe {
                    libc::kill(0, libc::SIGKILL);
                }
                return;
            }
        })
        .context("start semantic-provider parent-liveness guard")?;
    Ok(())
}

fn handle_request(
    identity: &ProviderIdentity,
    semantic_profile: &RustSemanticProfile,
    runtime_configuration: &ProviderRuntimeConfiguration,
    limits: &ProviderFrameLimits,
    session: &mut Option<RootSession>,
    frame: ProviderFrame<ProviderRequest>,
) -> anyhow::Result<ProviderTerminal> {
    let ProviderFrame {
        metadata: request,
        attachments,
    } = frame;
    if request.expected_provider != *identity {
        bail!("requested provider build identity differs from this executable");
    }
    if matches!(
        &request.body,
        ProviderRequestBody::Hello
            | ProviderRequestBody::OpenSession { .. }
            | ProviderRequestBody::ReconfigureSession { .. }
            | ProviderRequestBody::ApplyEpoch { .. }
            | ProviderRequestBody::RefreshAffected { .. }
            | ProviderRequestBody::CertifyFull { .. }
    ) && observe_runtime_configuration()? != *runtime_configuration
    {
        bail!("provider toolchain or workspace configuration changed after process admission");
    }
    if matches!(
        &request.body,
        ProviderRequestBody::Hello
            | ProviderRequestBody::ApplyEpoch { .. }
            | ProviderRequestBody::RefreshAffected { .. }
            | ProviderRequestBody::CertifyFull { .. }
    ) && let Some(active) = session.as_ref()
    {
        active.workspace_inputs.verify_unchanged()?;
    }
    match request.body {
        ProviderRequestBody::Hello => Ok(ProviderTerminal::empty(ProviderResponseBody::Hello {
            limits: *limits,
            runtime_configuration: runtime_configuration.clone(),
        })),
        ProviderRequestBody::OpenSession {
            repository_root,
            execution_root,
            execution_prefix,
            authority,
            sources,
            expected_semantic_inputs,
        } => {
            if session.is_some() {
                bail!("one provider process owns exactly one root session");
            }
            let repository_root = canonical_root(Path::new(&repository_root))?;
            let execution_root = canonical_root(Path::new(&execution_root))?;
            if !execution_root.starts_with(&repository_root) {
                bail!("provider execution root escapes the repository root");
            }
            let actual_prefix = execution_root
                .strip_prefix(&repository_root)
                .context("derive provider execution prefix")?
                .as_str()
                .replace('\\', "/");
            if actual_prefix != execution_prefix {
                bail!("provider execution prefix differs from canonical roots");
            }
            if sha256_hex(repository_root.as_str().as_bytes()) != authority.root_sha256 {
                bail!("repository root identity mismatch");
            }
            if runtime_configuration.configuration_sha256 != authority.configuration_sha256 {
                bail!("provider configuration identity mismatch");
            }
            if authority.workspace_resolution_sha256.is_some()
                || authority.semantic_inputs_sha256.is_some()
            {
                bail!(
                    "open-session authority predeclares provider-observed workspace resolution or semantic inputs"
                );
            }
            if expected_semantic_inputs.is_some() {
                bail!("Rust provider does not accept a client-owned semantic-input manifest");
            }
            let (host, vfs, health, workspace_resolution_sha256, workspace_inputs) =
                load_root(&repository_root, &execution_root, semantic_profile, limits)?;
            let mut resolved_authority = authority;
            resolved_authority.workspace_resolution_sha256 = Some(workspace_resolution_sha256);
            resolved_authority.semantic_inputs_sha256 = Some(provider_semantic_inputs_sha256(
                &workspace_inputs.semantic_inputs,
                limits,
            )?);
            let sources = validate_loaded_sources(
                &host,
                &vfs,
                &execution_root,
                &execution_prefix,
                sources,
                limits,
                &resolved_authority,
            )?;
            *session = Some(RootSession {
                execution_root,
                execution_prefix,
                host,
                vfs,
                authority: resolved_authority.clone(),
                sources,
                health: health.clone(),
                workspace_inputs,
            });
            Ok(ProviderTerminal::empty(
                ProviderResponseBody::SessionOpened {
                    authority: resolved_authority,
                    health,
                    semantic_inputs: session
                        .as_ref()
                        .expect("session was installed before its terminal")
                        .workspace_inputs
                        .semantic_inputs
                        .clone(),
                },
            ))
        }
        ProviderRequestBody::ReconfigureSession { .. } => {
            bail!("Rust provider sessions do not support project-input reconfiguration")
        }
        ProviderRequestBody::ApplyEpoch {
            previous_authority,
            next_authority,
            changes,
        } => {
            let active = exact_session(session, &request.session_id, &previous_authority)?;
            apply_epoch(active, &next_authority, changes, &attachments, limits)?;
            Ok(ProviderTerminal::empty(
                ProviderResponseBody::EpochApplied {
                    authority: next_authority,
                    health: active.health.clone(),
                },
            ))
        }
        ProviderRequestBody::RefreshAffected {
            previous_authority,
            next_authority,
            changes,
            parent_snapshot_sha256,
            documents,
            analyses,
        } => {
            if !analyses.is_empty() {
                bail!("Rust provider does not implement requested semantic analyses");
            }
            let active = exact_session(session, &request.session_id, &previous_authority)?;
            apply_epoch(active, &next_authority, changes, &attachments, limits)?;
            let (outcomes, attachments) = export_documents(active, documents)?;
            active.workspace_inputs.verify_unchanged()?;
            let terminal_runtime_configuration = observe_runtime_configuration()?;
            if terminal_runtime_configuration != *runtime_configuration {
                bail!("provider toolchain or workspace configuration changed during affected refresh");
            }
            Ok(ProviderTerminal {
                body: ProviderResponseBody::AffectedRefreshed {
                    authority: next_authority,
                    parent_snapshot_sha256,
                    health: active.health.clone(),
                    runtime_configuration: terminal_runtime_configuration,
                    outcomes,
                    analyses: Vec::new(),
                },
                attachments,
            })
        }
        ProviderRequestBody::CertifyFull {
            authority,
            analyses,
        } => {
            if !analyses.is_empty() {
                bail!("Rust provider does not implement requested semantic analyses");
            }
            let active = exact_session(session, &request.session_id, &authority)?;
            let documents = active.sources.keys().cloned().collect::<Vec<_>>();
            let (outcomes, attachments) = export_documents(active, documents)?;
            Ok(ProviderTerminal {
                body: ProviderResponseBody::FullCertification {
                    authority,
                    health: active.health.clone(),
                    outcomes,
                    analyses: Vec::new(),
                },
                attachments,
            })
        }
        ProviderRequestBody::CloseSession => {
            // Acknowledge before Rust drops rust-analyzer's workspace graph.
            // The parent owns final process-group termination after this
            // terminal, so teardown cost cannot strand CLI/MCP/WATCH exit.
            Ok(ProviderTerminal::empty(ProviderResponseBody::SessionClosed))
        }
    }
}

fn provider_worker_threads() -> usize {
    num_cpus::get_physical().max(1)
}

fn load_root(
    repository_root: &AbsPathBuf,
    root: &AbsPathBuf,
    semantic_profile: &RustSemanticProfile,
    limits: &ProviderFrameLimits,
) -> anyhow::Result<(
    AnalysisHost,
    vfs::Vfs,
    ProviderHealthEvidence,
    String,
    WorkspaceInputPlan,
)> {
    let config = Config::new(
        root.clone(),
        lsp_types::ClientCapabilities::default(),
        vec![],
        None,
    );
    // rust-analyzer redirects Cargo metadata and build-script resolution to a
    // private lockfile. Supplying `--locked` here contradicts that isolation:
    // an ordinary Cargo library without a checked-in lockfile then cannot
    // create the private lock and silently loses the persistent provider.
    let mut cargo = serde_json::Map::new();
    match &semantic_profile.cargo_features {
        RustCargoFeatures::WorkspaceDefault => {}
        RustCargoFeatures::All => {
            cargo.insert("features".into(), json!("all"));
        }
        RustCargoFeatures::Selected {
            features,
            no_default_features,
        } => {
            cargo.insert("features".into(), json!(features));
            cargo.insert("noDefaultFeatures".into(), json!(no_default_features));
        }
    }
    if let Some(target) = &semantic_profile.target {
        cargo.insert("target".into(), json!(target));
    }
    let mut change = ConfigChange::default();
    change.change_client_config(json!({"cargo": cargo}));
    let (config, errors, _) = config.apply_change(change);
    if !errors.is_empty() {
        bail!("provider configuration rejected: {errors}");
    }
    let load_config = LoadCargoConfig {
        load_out_dirs_from_check: true,
        with_proc_macro_server: ProcMacroServerChoice::Sysroot,
        prefill_caches: true,
        num_worker_threads: provider_worker_threads(),
        proc_macro_processes: config.proc_macro_num_processes(),
    };
    let cargo = config.cargo(None);
    let manifest = ProjectManifest::discover_single(root)?;
    let mut workspace = ProjectWorkspace::load(manifest, &cargo, &|_| {})?;
    let workspace_resolution_sha256 = workspace_resolution_sha256(&workspace)?;
    let build_scripts = workspace.run_build_scripts(&cargo, &|_| {})?;
    let workspace_inputs =
        WorkspaceInputPlan::capture(repository_root, root, &workspace, &build_scripts, limits)?;
    let workspace_resolution_sha256 = resolved_workspace_authority_sha256(
        &workspace_resolution_sha256,
        &workspace_inputs.admitted_sha256,
    );
    let build_script_error = build_scripts.error().map(str::to_owned);
    workspace.set_build_scripts(build_scripts);
    let (database, vfs, proc_macro_client) =
        load_workspace(workspace, &cargo.extra_env, &load_config)?;

    let mut degradation_reasons = Vec::new();
    let build_scripts = build_script_error.map_or(ProviderComponentHealth::Healthy, |error| {
        degradation_reasons.push(bounded_text(&format!("build scripts: {error}"), 1024));
        ProviderComponentHealth::Failed
    });
    let proc_macros = if proc_macro_client.is_some() {
        ProviderComponentHealth::Healthy
    } else {
        degradation_reasons.push("proc-macro server unavailable".into());
        ProviderComponentHealth::Unknown
    };
    let health = ProviderHealthEvidence {
        components: BTreeMap::from([
            ("build_scripts".into(), build_scripts),
            ("proc_macros".into(), proc_macros),
            (
                "workspace_model".into(),
                ProviderComponentHealth::Healthy,
            ),
        ]),
        diagnostics_complete: degradation_reasons.is_empty(),
        degradation_reasons,
    };
    Ok((
        AnalysisHost::with_database(database),
        vfs,
        health,
        workspace_resolution_sha256,
        workspace_inputs,
    ))
}

/// Fingerprint the exact dependency/workspace graph selected by Cargo before
/// it can become semantic authority. This deliberately hashes the resolved
/// package IDs, active features, dependency edges, and target population—not
/// merely Cargo.toml bytes—so lockfile-free resolution cannot masquerade as
/// the same provider configuration after selecting a different graph.
fn workspace_resolution_sha256(workspace: &ProjectWorkspace) -> anyhow::Result<String> {
    let ProjectWorkspaceKind::Cargo { cargo, rustc, .. } = &workspace.kind else {
        bail!("Rust semantic provider execution root did not load a Cargo workspace");
    };
    let mut report = b"h00/rust-analyzer-workspace-resolution/v1\0".to_vec();
    append_cargo_workspace_resolution(&mut report, b"workspace", cargo);
    if let Ok(rustc) = rustc {
        append_cargo_workspace_resolution(&mut report, b"rustc-workspace", &rustc.0);
    }
    Ok(sha256_hex(&report))
}

fn append_cargo_workspace_resolution(report: &mut Vec<u8>, label: &[u8], cargo: &CargoWorkspace) {
    append_resolution_field(report, label);
    append_resolution_field(report, cargo.workspace_root().as_str().as_bytes());
    append_resolution_field(report, cargo.manifest_path().to_string().as_bytes());

    let mut packages = cargo.packages().collect::<Vec<_>>();
    packages.sort_by(|left, right| cargo[*left].id.repr.cmp(&cargo[*right].id.repr));
    append_resolution_field(report, &(packages.len() as u64).to_be_bytes());
    for package_id in packages {
        let package = &cargo[package_id];
        append_resolution_field(report, package.id.repr.as_bytes());
        append_resolution_field(report, package.name.as_bytes());
        append_resolution_field(report, package.version.to_string().as_bytes());
        append_resolution_field(report, package.manifest.to_string().as_bytes());
        append_resolution_field(report, &[package.is_local as u8, package.is_member as u8]);

        let mut features = package.active_features.clone();
        features.sort();
        append_resolution_field(report, &(features.len() as u64).to_be_bytes());
        for feature in features {
            append_resolution_field(report, feature.as_bytes());
        }

        let mut dependencies = package
            .dependencies
            .iter()
            .map(|dependency| {
                format!(
                    "{}\0{}\0{:?}",
                    dependency.name, cargo[dependency.pkg].id.repr, dependency.kind
                )
            })
            .collect::<Vec<_>>();
        dependencies.sort();
        append_resolution_field(report, &(dependencies.len() as u64).to_be_bytes());
        for dependency in dependencies {
            append_resolution_field(report, dependency.as_bytes());
        }

        let mut targets = package
            .targets
            .iter()
            .map(|target_id| {
                let target = &cargo[*target_id];
                let mut required_features = target.required_features.clone();
                required_features.sort();
                format!(
                    "{}\0{}\0{:?}\0{}",
                    target.name,
                    target.root.as_str(),
                    target.kind,
                    required_features.join("\0")
                )
            })
            .collect::<Vec<_>>();
        targets.sort();
        append_resolution_field(report, &(targets.len() as u64).to_be_bytes());
        for target in targets {
            append_resolution_field(report, target.as_bytes());
        }
    }
}

fn append_resolution_field(report: &mut Vec<u8>, value: &[u8]) {
    report.extend_from_slice(&(value.len() as u64).to_be_bytes());
    report.extend_from_slice(value);
}

const WORKSPACE_INPUT_SCHEMA: &[u8] = b"h00/rust-workspace-inputs/v1\0";
const RESOLVED_WORKSPACE_AUTHORITY_SCHEMA: &[u8] = b"h00/rust-resolved-workspace-authority/v1\0";
const MAX_WORKSPACE_INPUT_ENTRIES: u64 = 2_000_000;
const MAX_WORKSPACE_INPUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

impl WorkspaceInputPlan {
    fn capture(
        repository_root: &AbsPathBuf,
        execution_root: &AbsPathBuf,
        workspace: &ProjectWorkspace,
        build_scripts: &WorkspaceBuildScripts,
        limits: &ProviderFrameLimits,
    ) -> anyhow::Result<Self> {
        let ProjectWorkspaceKind::Cargo { cargo, .. } = &workspace.kind else {
            bail!("Rust semantic provider execution root did not load a Cargo workspace");
        };
        let mut paths = BTreeSet::new();
        let mut environment = BTreeMap::new();
        let mut durable_paths = BTreeSet::new();
        let mut durable_environment = BTreeSet::new();
        let mut durable_issues = BTreeSet::new();

        for package_id in cargo.packages() {
            let package = &cargo[package_id];
            let package_root = PathBuf::from(package.manifest.parent().as_str());
            if package.is_local && !package_root.starts_with(repository_root.as_str()) {
                bail!(
                    "editable Cargo package escapes repository root: {}",
                    package_root.display()
                );
            }

            // A local path dependency outside this execution root is loaded by
            // rust-analyzer but absent from this root's ordinary source
            // overlay. It must remain inside the selected repository so the
            // immutable generation can re-observe it without persisting a
            // machine-local absolute path.
            if package.is_local && !package_root.starts_with(execution_root.as_str()) {
                paths.insert(package_root.clone());
                durable_paths.insert(repository_relative_input(
                    repository_root.as_ref(),
                    &package_root,
                )?);
            }

            if let Some(out_dir) = build_scripts.h00_output_directory(package_id) {
                let out_dir = PathBuf::from(out_dir.as_str());
                paths.insert(out_dir.clone());
                let build_instance = out_dir.parent().with_context(|| {
                    format!("build output has no parent: {}", out_dir.display())
                })?;
                let output = build_instance.join("output");
                paths.insert(output);
                let fingerprint = build_script_fingerprint_path(&out_dir)?;
                let mut rerun_paths = BTreeSet::new();
                let mut rerun_environment = BTreeMap::new();
                collect_cargo_rerun_inputs(
                    &fingerprint,
                    &package_root,
                    &mut rerun_paths,
                    &mut rerun_environment,
                )?;
                paths.extend(rerun_paths.iter().cloned());
                merge_cargo_environment(&mut environment, &rerun_environment)?;
                durable_environment.extend(rerun_environment.keys().cloned());
                if package.is_local {
                    if rerun_paths.is_empty() {
                        durable_issues.insert(ProviderSemanticInputIssue {
                            code: "implicit_cargo_package_rerun_population".into(),
                            path: repository_relative_input(
                                repository_root.as_ref(),
                                Path::new(package.manifest.as_str()),
                            )?,
                            detail: "local build script emitted no rerun-if-changed path, so Cargo's implicit package-file population cannot be reproduced without rerunning Cargo"
                                .into(),
                        });
                    }
                    for path in rerun_paths {
                        durable_paths
                            .insert(repository_relative_input(repository_root.as_ref(), &path)?);
                    }
                }
                paths.insert(fingerprint);
            }

            if let Some(dylib) = build_scripts.h00_proc_macro_dylib_path(package_id) {
                paths.insert(PathBuf::from(dylib.as_str()));
            }
        }

        let paths = coalesce_workspace_input_paths(paths);
        let mut semantic_inputs = capture_provider_semantic_inputs(
            repository_root.as_ref(),
            &durable_paths,
            &durable_environment,
            limits,
        )?;
        if !durable_issues.is_empty() {
            semantic_inputs.coverage = ProviderSemanticInputCoverage::Unverifiable;
            semantic_inputs.issues = durable_issues.into_iter().collect();
        }
        let mut plan = Self {
            paths,
            environment,
            admitted_sha256: String::new(),
            semantic_inputs,
        };
        plan.admitted_sha256 = plan.observe_sha256()?;
        Ok(plan)
    }

    fn verify_unchanged(&self) -> anyhow::Result<()> {
        let observed = self.observe_sha256()?;
        if observed != self.admitted_sha256 {
            bail!("Cargo workspace build inputs changed after provider admission");
        }
        Ok(())
    }

    fn observe_sha256(&self) -> anyhow::Result<String> {
        let mut hasher = Sha256::new();
        hash_workspace_field(&mut hasher, WORKSPACE_INPUT_SCHEMA);
        hash_workspace_field(&mut hasher, &(self.paths.len() as u64).to_be_bytes());
        let mut budget = WorkspaceInputBudget::default();
        for path in &self.paths {
            hash_workspace_field(&mut hasher, path.as_os_str().as_bytes());
            hash_workspace_path(&mut hasher, path, path, &mut budget)?;
        }
        hash_workspace_field(&mut hasher, &(self.environment.len() as u64).to_be_bytes());
        for (name, cargo_value) in &self.environment {
            let current = std::env::var_os(name);
            let current_text = current
                .as_ref()
                .map(|value| value.to_string_lossy().into_owned());
            if current_text.as_ref() != cargo_value.as_ref() {
                bail!("Cargo rerun environment changed after provider admission: {name}");
            }
            hash_workspace_field(&mut hasher, name.as_bytes());
            match current {
                Some(value) => {
                    hash_workspace_field(&mut hasher, b"present");
                    hash_workspace_field(&mut hasher, value.as_os_str().as_bytes());
                }
                None => hash_workspace_field(&mut hasher, b"missing"),
            }
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

fn repository_relative_input(repository_root: &Path, path: &Path) -> anyhow::Result<String> {
    let path = normalize_absolute_input(path)?;
    let relative = path.strip_prefix(repository_root).with_context(|| {
        format!(
            "editable Cargo semantic input escapes repository root: {}",
            path.display()
        )
    })?;
    if relative.as_os_str().is_empty() {
        bail!("Cargo semantic input cannot claim the entire repository root");
    }
    let relative = relative
        .to_str()
        .with_context(|| format!("Cargo semantic input is not UTF-8: {}", path.display()))?
        .replace('\\', "/");
    if relative
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("Cargo semantic input is not a safe repository-relative path: {relative}");
    }
    Ok(relative)
}

fn normalize_absolute_input(path: &Path) -> anyhow::Result<PathBuf> {
    if !path.is_absolute() {
        bail!("Cargo semantic input is not absolute: {}", path.display());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!(
                        "Cargo semantic input escapes filesystem root: {}",
                        path.display()
                    );
                }
            }
            Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn merge_cargo_environment(
    target: &mut BTreeMap<String, Option<String>>,
    additions: &BTreeMap<String, Option<String>>,
) -> anyhow::Result<()> {
    for (name, value) in additions {
        if target
            .insert(name.clone(), value.clone())
            .is_some_and(|previous| previous != *value)
        {
            bail!("Cargo reported conflicting rerun values for environment {name}");
        }
    }
    Ok(())
}

fn resolved_workspace_authority_sha256(
    resolution_sha256: &str,
    workspace_inputs_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hash_workspace_field(&mut hasher, RESOLVED_WORKSPACE_AUTHORITY_SCHEMA);
    hash_workspace_field(&mut hasher, resolution_sha256.as_bytes());
    hash_workspace_field(&mut hasher, workspace_inputs_sha256.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn build_script_fingerprint_path(out_dir: &Path) -> anyhow::Result<PathBuf> {
    let build_instance = out_dir
        .parent()
        .with_context(|| format!("build output has no instance: {}", out_dir.display()))?;
    let instance_name = build_instance
        .file_name()
        .with_context(|| format!("build output has no instance name: {}", out_dir.display()))?;
    let profile = build_instance
        .parent()
        .and_then(Path::parent)
        .with_context(|| format!("build output has no Cargo profile: {}", out_dir.display()))?;
    let fingerprint_dir = profile.join(".fingerprint").join(instance_name);
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(&fingerprint_dir).with_context(|| {
        format!(
            "read Cargo build-script fingerprint directory {}",
            fingerprint_dir.display()
        )
    })? {
        let entry =
            entry.with_context(|| format!("read entry in {}", fingerprint_dir.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("run-build-script-")
            && name.ends_with(".json")
            && entry.file_type()?.is_file()
        {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    if candidates.len() != 1 {
        bail!(
            "expected exactly one Cargo build-script fingerprint in {}, found {}",
            fingerprint_dir.display(),
            candidates.len()
        );
    }
    Ok(candidates.remove(0))
}

fn collect_cargo_rerun_inputs(
    fingerprint: &Path,
    package_root: &Path,
    paths: &mut BTreeSet<PathBuf>,
    environment: &mut BTreeMap<String, Option<String>>,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(fingerprint)
        .with_context(|| format!("read Cargo fingerprint {}", fingerprint.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse Cargo fingerprint {}", fingerprint.display()))?;
    let local = value
        .get("local")
        .and_then(serde_json::Value::as_array)
        .with_context(|| {
            format!(
                "Cargo fingerprint has no local inputs: {}",
                fingerprint.display()
            )
        })?;
    for input in local {
        if let Some(changed) = input.get("RerunIfChanged") {
            let changed_paths = changed
                .get("paths")
                .and_then(serde_json::Value::as_array)
                .with_context(|| {
                    format!(
                        "Cargo rerun fingerprint has no path list: {}",
                        fingerprint.display()
                    )
                })?;
            for value in changed_paths {
                let value = value.as_str().with_context(|| {
                    format!("Cargo rerun path is not UTF-8: {}", fingerprint.display())
                })?;
                let path = PathBuf::from(value);
                paths.insert(if path.is_absolute() {
                    path
                } else {
                    package_root.join(path)
                });
            }
        }
        if let Some(changed) = input.get("RerunIfEnvChanged") {
            let name = changed
                .get("var")
                .and_then(serde_json::Value::as_str)
                .with_context(|| {
                    format!(
                        "Cargo rerun environment has no name: {}",
                        fingerprint.display()
                    )
                })?
                .to_owned();
            let value = match changed.get("val") {
                None | Some(serde_json::Value::Null) => None,
                Some(value) => Some(
                    value
                        .as_str()
                        .with_context(|| {
                            format!(
                                "Cargo rerun environment is not UTF-8: {}",
                                fingerprint.display()
                            )
                        })?
                        .to_owned(),
                ),
            };
            if environment
                .insert(name.clone(), value.clone())
                .is_some_and(|previous| previous != value)
            {
                bail!("Cargo reported conflicting rerun values for environment {name}");
            }
        }
    }
    Ok(())
}

fn coalesce_workspace_input_paths(paths: BTreeSet<PathBuf>) -> BTreeSet<PathBuf> {
    paths
        .iter()
        .filter(|path| {
            let mut parent = path.parent();
            while let Some(candidate) = parent {
                if paths.contains(candidate)
                    && std::fs::symlink_metadata(candidate)
                        .is_ok_and(|metadata| metadata.file_type().is_dir())
                {
                    return false;
                }
                parent = candidate.parent();
            }
            true
        })
        .cloned()
        .collect()
}

#[derive(Default)]
struct WorkspaceInputBudget {
    entries: u64,
    bytes: u64,
}

impl WorkspaceInputBudget {
    fn observe_entry(&mut self) -> anyhow::Result<()> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > MAX_WORKSPACE_INPUT_ENTRIES {
            bail!(
                "Cargo workspace input population exceeds {} entries",
                MAX_WORKSPACE_INPUT_ENTRIES
            );
        }
        Ok(())
    }

    fn observe_bytes(&mut self, bytes: usize) -> anyhow::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes as u64)
            .context("Cargo workspace input byte population overflowed")?;
        if self.bytes > MAX_WORKSPACE_INPUT_BYTES {
            bail!(
                "Cargo workspace input population exceeds {} bytes",
                MAX_WORKSPACE_INPUT_BYTES
            );
        }
        Ok(())
    }
}

fn hash_workspace_path(
    hasher: &mut Sha256,
    root: &Path,
    path: &Path,
    budget: &mut WorkspaceInputBudget,
) -> anyhow::Result<()> {
    budget.observe_entry()?;
    let relative = path.strip_prefix(root).unwrap_or(path);
    hash_workspace_field(hasher, relative.as_os_str().as_bytes());
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hash_workspace_field(hasher, b"missing");
            return Ok(());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect Cargo input {}", path.display()));
        }
    };
    let before_stamp = metadata_stamp(&before);
    let file_type = before.file_type();
    if file_type.is_symlink() {
        hash_workspace_field(hasher, b"symlink");
        let target = std::fs::read_link(path)
            .with_context(|| format!("read Cargo input symlink {}", path.display()))?;
        hash_workspace_field(hasher, target.as_os_str().as_bytes());
    } else if file_type.is_file() {
        hash_workspace_field(hasher, b"file");
        let mut file =
            File::open(path).with_context(|| format!("open Cargo input {}", path.display()))?;
        let mut file_hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .with_context(|| format!("read Cargo input {}", path.display()))?;
            if read == 0 {
                break;
            }
            budget.observe_bytes(read)?;
            file_hasher.update(&buffer[..read]);
        }
        hash_workspace_field(hasher, &file_hasher.finalize());
    } else if file_type.is_dir() {
        hash_workspace_field(hasher, b"directory");
        let mut entries = std::fs::read_dir(path)
            .with_context(|| format!("read Cargo input directory {}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("read Cargo input entries {}", path.display()))?;
        entries.sort_by(|left, right| {
            left.file_name()
                .as_bytes()
                .cmp(right.file_name().as_bytes())
        });
        hash_workspace_field(hasher, &(entries.len() as u64).to_be_bytes());
        for entry in entries {
            hash_workspace_path(hasher, root, &entry.path(), budget)?;
        }
    } else {
        bail!(
            "Cargo workspace input has unsupported file type: {}",
            path.display()
        );
    }
    let after = std::fs::symlink_metadata(path)
        .with_context(|| format!("reinspect Cargo input {}", path.display()))?;
    if metadata_stamp(&after) != before_stamp {
        bail!(
            "Cargo workspace input changed while hashing: {}",
            path.display()
        );
    }
    Ok(())
}

fn metadata_stamp(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn hash_workspace_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_loaded_sources(
    host: &AnalysisHost,
    vfs: &vfs::Vfs,
    execution_root: &AbsPathBuf,
    execution_prefix: &str,
    sources: Vec<ProviderSourceIdentity>,
    limits: &ProviderFrameLimits,
    authority: &ProviderAuthority,
) -> anyhow::Result<BTreeMap<String, ProviderSourceIdentity>> {
    if source_population_sha256(&sources, limits)? != authority.population_sha256 {
        bail!("source population does not match open-session authority");
    }
    let mut by_path = BTreeMap::new();
    for source in sources {
        if source.language != H00_RUST_ANALYZER_LANGUAGE {
            bail!("non-Rust source entered the Rust provider session");
        }
        let relative = execution_relative_path(execution_prefix, &source.document_path)?;
        let absolute = execution_root.join(relative.as_str());
        let file_id = match vfs.file_id(&VfsPath::from(absolute)) {
            Some((file_id, FileExcluded::No)) => file_id,
            Some((_, FileExcluded::Yes)) => {
                bail!(
                    "source is excluded from provider VFS: {}",
                    source.document_path
                )
            }
            None => bail!(
                "source is absent from provider VFS: {}",
                source.document_path
            ),
        };
        let text = host
            .analysis()
            .file_text(file_id)
            .with_context(|| format!("read provider source {}", source.document_path))?;
        if sha256_hex(text.as_bytes()) != source.content_sha256 {
            bail!("loaded source digest mismatch for {}", source.document_path);
        }
        let path = source.document_path.clone();
        if by_path.insert(path.clone(), source).is_some() {
            bail!("duplicate provider source path {path}");
        }
    }
    Ok(by_path)
}

fn exact_session<'a>(
    session: &'a mut Option<RootSession>,
    session_id: &str,
    authority: &ProviderAuthority,
) -> anyhow::Result<&'a mut RootSession> {
    let active = session
        .as_mut()
        .context("no provider root session is open")?;
    if active.authority != *authority || active.authority.session_id != session_id {
        bail!("session or source authority mismatch");
    }
    Ok(active)
}

fn exact_file_id(session: &RootSession, repository_path: &str) -> anyhow::Result<vfs::FileId> {
    let relative = execution_relative_path(&session.execution_prefix, repository_path)?;
    let absolute = session.execution_root.join(relative.as_str());
    match session.vfs.file_id(&VfsPath::from(absolute)) {
        Some((file_id, FileExcluded::No)) => Ok(file_id),
        Some((_, FileExcluded::Yes)) => {
            bail!("source is excluded from provider: {repository_path}")
        }
        None => bail!("source is absent from provider VFS: {repository_path}"),
    }
}

fn apply_epoch(
    session: &mut RootSession,
    next_authority: &ProviderAuthority,
    changes: Vec<ProviderSourceChange>,
    attachments: &[Vec<u8>],
    limits: &ProviderFrameLimits,
) -> anyhow::Result<()> {
    let mut next_sources = session.sources.clone();
    let mut replacements = Vec::with_capacity(changes.len());
    for change in changes {
        let ProviderSourceChange::Replace {
            document_path,
            language,
            previous_content_identity,
            previous_content_sha256,
            content_identity,
            content_sha256,
            attachment_index,
        } = change;
        if language != H00_RUST_ANALYZER_LANGUAGE {
            bail!("non-Rust source entered the Rust provider session");
        }
        let prior = session
            .sources
            .get(&document_path)
            .with_context(|| format!("replacement path is not in session: {document_path}"))?;
        if prior.content_identity != previous_content_identity
            || prior.content_sha256 != previous_content_sha256
        {
            bail!("replacement prior identity mismatch for {document_path}");
        }
        let bytes = attachments
            .get(attachment_index as usize)
            .with_context(|| format!("replacement attachment missing for {document_path}"))?;
        let text = std::str::from_utf8(bytes)
            .with_context(|| format!("replacement is not UTF-8: {document_path}"))?;
        let file_id = exact_file_id(session, &document_path)?;
        let current = session
            .host
            .analysis()
            .file_text(file_id)
            .with_context(|| format!("read current provider source {document_path}"))?;
        if sha256_hex(current.as_bytes()) != previous_content_sha256 {
            bail!("provider host drifted before replacement: {document_path}");
        }
        replacements.push((file_id, text.to_owned()));
        next_sources.insert(
            document_path.clone(),
            ProviderSourceIdentity {
                document_path,
                language,
                content_identity,
                content_sha256,
            },
        );
    }
    let population = next_sources.values().cloned().collect::<Vec<_>>();
    if source_population_sha256(&population, limits)? != next_authority.population_sha256 {
        bail!("replacement population does not match next authority");
    }
    let mut update = ChangeWithProcMacros::default();
    for (file_id, text) in replacements {
        update.change_file(file_id, Some(text));
    }
    session.host.apply_change(update);
    session.sources = next_sources;
    session.authority = next_authority.clone();
    Ok(())
}

fn export_documents(
    session: &RootSession,
    requested: Vec<String>,
) -> anyhow::Result<(Vec<ProviderDocumentOutcome>, Vec<Vec<u8>>)> {
    let requested = requested.into_iter().collect::<BTreeSet<_>>();
    if requested.is_empty() {
        bail!("provider export population is empty");
    }
    let file_ids = requested
        .iter()
        .map(|path| {
            session
                .sources
                .get(path)
                .with_context(|| format!("export path is outside session population: {path}"))?;
            exact_file_id(session, path)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let analysis = session.host.analysis();
    let static_index = StaticIndex::compute_files(&analysis, file_ids, provider_worker_threads());
    let emission = h00_emit_static_index(
        &session.execution_root,
        &session.vfs,
        session.host.raw_database(),
        static_index,
        false,
    );
    let mut documents = BTreeMap::new();
    for mut document in emission.documents {
        document.relative_path =
            repository_path(&session.execution_prefix, document.relative_path.as_str());
        if !requested.contains(&document.relative_path)
            || documents
                .insert(document.relative_path.clone(), document)
                .is_some()
        {
            bail!("provider emitted an unexpected or duplicate document");
        }
    }

    let mut attachments = Vec::new();
    let mut outcomes = Vec::with_capacity(requested.len());
    for path in requested {
        let source = session
            .sources
            .get(&path)
            .context("requested source identity disappeared")?;
        if let Some(document) = documents.remove(&path) {
            let bytes = document
                .write_to_bytes()
                .with_context(|| format!("serialize canonical provider document {path}"))?;
            let attachment_index = attachments.len() as u32;
            let canonical_document_sha256 = sha256_hex(&bytes);
            attachments.push(bytes);
            outcomes.push(ProviderDocumentOutcome::Present {
                document_path: path,
                language: H00_RUST_ANALYZER_LANGUAGE.into(),
                content_identity: source.content_identity.clone(),
                canonical_document_sha256,
                attachment_index,
            });
        } else {
            outcomes.push(ProviderDocumentOutcome::Omitted {
                document_path: path,
                language: H00_RUST_ANALYZER_LANGUAGE.into(),
                content_identity: source.content_identity.clone(),
            });
        }
    }
    Ok((outcomes, attachments))
}

fn execution_relative_path(prefix: &str, repository_path: &str) -> anyhow::Result<String> {
    if prefix.is_empty() {
        return Ok(repository_path.into());
    }
    repository_path
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .filter(|suffix| !suffix.is_empty())
        .map(ToOwned::to_owned)
        .with_context(|| format!("source path is outside execution prefix {prefix:?}"))
}

fn repository_path(prefix: &str, execution_path: &str) -> String {
    if prefix.is_empty() {
        execution_path.into()
    } else {
        format!("{prefix}/{execution_path}")
    }
}

fn canonical_root(path: &Path) -> anyhow::Result<AbsPathBuf> {
    let path = std::fs::canonicalize(path).context("canonicalize provider root")?;
    Ok(AbsPathBuf::assert_utf8(path))
}

pub fn executable_identity() -> anyhow::Result<ProviderIdentity> {
    let executable = std::env::current_exe().context("resolve provider executable")?;
    let bytes = std::fs::read(&executable).context("hash provider executable")?;
    Ok(ProviderIdentity {
        protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
        provider_id: H00_RUST_ANALYZER_PROVIDER_ID.into(),
        language: H00_RUST_ANALYZER_LANGUAGE.into(),
        implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V5.into(),
        source_components: rust_analyzer_source_components(),
        patch_sha256: PATCH_SHA256.into(),
        executable_sha256: sha256_hex(&bytes),
    })
}

fn observe_runtime_configuration() -> anyhow::Result<ProviderRuntimeConfiguration> {
    let resolved_toolchain_sha256 =
        std::env::var(RESOLVED_TOOLCHAIN_SHA256_ENV).with_context(|| {
            format!("read required {RESOLVED_TOOLCHAIN_SHA256_ENV} provider environment")
        })?;
    let rustc_path = required_runtime_executable("RUSTC", RESOLVED_RUSTC_SHA256_ENV)?;
    let cargo_path = required_runtime_executable("CARGO", RESOLVED_CARGO_SHA256_ENV)?;
    let rustc = command_report(&rustc_path, &["-vV"])?;
    let cargo = command_report(&cargo_path, &["-V"])?;
    let sysroot = command_report(&rustc_path, &["--print", "sysroot"])?;
    let environment = environment_report();
    let workspace_configuration = workspace_configuration_report()?;
    let configuration = rust_analyzer_runtime_configuration(
        &resolved_toolchain_sha256,
        &rustc,
        &cargo,
        &sysroot,
        &environment,
        &workspace_configuration,
    )
    .context("construct observed provider runtime configuration")?;
    validate_runtime_configuration(&configuration)
        .context("validate observed provider runtime configuration")?;
    Ok(configuration)
}

fn environment_report() -> Vec<u8> {
    let mut entries = std::env::vars_os()
        .filter(|(name, _)| name != std::ffi::OsStr::new(PROVIDER_PARENT_PID_ENV))
        .map(|(name, value)| {
            (
                name.as_os_str().as_bytes().to_vec(),
                value.as_os_str().as_bytes().to_vec(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    let mut report = b"h00/rust-analyzer-environment/v1\0".to_vec();
    for (name, value) in entries {
        append_report_field(&mut report, &name);
        append_report_field(&mut report, &value);
    }
    report
}

fn workspace_configuration_report() -> anyhow::Result<Vec<u8>> {
    const MAX_CONTROL_FILE_BYTES: u64 = 4 * 1024 * 1024;

    let current = std::fs::canonicalize(std::env::current_dir()?)
        .context("canonicalize provider working directory")?;
    let mut candidates = BTreeSet::<PathBuf>::new();
    for ancestor in current.ancestors() {
        for relative in [
            ".cargo/config.toml",
            ".cargo/config",
            "rust-toolchain.toml",
            "rust-toolchain",
        ] {
            candidates.insert(ancestor.join(relative));
        }
    }
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
    {
        candidates.insert(cargo_home.join("config.toml"));
        candidates.insert(cargo_home.join("config"));
    }
    if let Some(rustup_home) = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
    {
        candidates.insert(rustup_home.join("settings.toml"));
    }

    let mut report = b"h00/rust-analyzer-workspace-configuration/v1\0".to_vec();
    for path in candidates {
        append_report_field(&mut report, path.as_os_str().as_bytes());
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                append_report_field(&mut report, b"missing");
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect provider control file {}", path.display()));
            }
            Ok(metadata) if metadata.file_type().is_file() => {
                if metadata.len() > MAX_CONTROL_FILE_BYTES {
                    bail!(
                        "provider control file exceeds size bound: {}",
                        path.display()
                    );
                }
                append_report_field(&mut report, b"file");
                append_report_field(
                    &mut report,
                    &std::fs::read(&path).with_context(|| {
                        format!("read provider control file {}", path.display())
                    })?,
                );
            }
            Ok(metadata) if metadata.file_type().is_symlink() => {
                append_report_field(&mut report, b"symlink");
                let target = std::fs::read_link(&path)
                    .with_context(|| format!("read provider control symlink {}", path.display()))?;
                append_report_field(&mut report, target.as_os_str().as_bytes());
                let bytes = std::fs::read(&path).with_context(|| {
                    format!("read provider control symlink target {}", path.display())
                })?;
                if bytes.len() as u64 > MAX_CONTROL_FILE_BYTES {
                    bail!(
                        "provider control file exceeds size bound: {}",
                        path.display()
                    );
                }
                append_report_field(&mut report, &bytes);
            }
            Ok(_) => bail!(
                "provider control path is not a file or symlink: {}",
                path.display()
            ),
        }
    }
    Ok(report)
}

fn append_report_field(report: &mut Vec<u8>, value: &[u8]) {
    report.extend_from_slice(&(value.len() as u64).to_be_bytes());
    report.extend_from_slice(value);
}

fn required_runtime_executable(path_name: &str, sha256_name: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os(path_name)
            .with_context(|| format!("read required {path_name} provider environment"))?,
    );
    if !path.is_absolute() {
        bail!("provider runtime executable {path_name} is not absolute");
    }
    let expected = std::env::var(sha256_name)
        .with_context(|| format!("read required {sha256_name} provider environment"))?;
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read provider runtime executable {}", path.display()))?;
    let actual = sha256_hex(&bytes);
    if actual != expected {
        bail!("provider runtime executable {path_name} changed after product resolution");
    }
    Ok(path)
}

fn command_report(program: &Path, arguments: &[&str]) -> anyhow::Result<Vec<u8>> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| {
            format!(
                "execute provider runtime identity command {}",
                program.display()
            )
        })?;
    if !output.status.success() || output.stdout.is_empty() {
        bail!(
            "provider runtime identity command {} failed with {}",
            program.display(),
            output.status
        );
    }
    Ok(output.stdout)
}

fn bounded_error(error: &anyhow::Error) -> String {
    bounded_text(&format!("{error:#}"), 1024)
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}
