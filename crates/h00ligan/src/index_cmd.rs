//! Immutable indexing adapter for the standalone `h00ligan` CLI.
//!
//! Both binaries select a [`ProjectBinding`] before entering this module. The
//! indexing effect therefore has one contract: build a fresh semantic
//! generation, publish it atomically, and never connect to the memory
//! substrate or create mutable root-level graph/index state.

use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use clap::Args;

use h00ligan_engine::code_intel_indexing::ProviderIntent;
use h00ligan_engine::code_intel_publication::{CapabilityFloorPolicy, PublicationRecovery};
use h00ligan_engine::code_intel_supervisor::{
    IndexOperationHandle, IndexOperationOutcome, IndexSupervisor, IndexSupervisorRequest,
};
use h00ligan_engine::index_pipeline::{IndexProgressEvent, IndexProgressState};
use h00ligan_engine::project_binding::ProjectBinding;

use crate::error::LiganError;
use crate::ligan_cmd::OutputFormat;

const PROGRESS_HEARTBEAT: Duration = Duration::from_secs(10);

#[cfg(unix)]
static CLI_TERMINATION_SIGNAL: AtomicU8 = AtomicU8::new(0);

#[cfg(unix)]
extern "C" fn record_cli_termination_signal(signal: libc::c_int) {
    CLI_TERMINATION_SIGNAL.store(signal as u8, Ordering::Release);
}

#[cfg(unix)]
fn install_cli_termination_handlers() -> std::io::Result<()> {
    // SAFETY: the handler performs only one lock-free atomic store. The
    // zeroed sigaction is fully initialized before either registration, and
    // both signals are process-level CLI termination inputs.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_cli_termination_signal as *const () as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) async fn wait_for_cli_index_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        CLI_TERMINATION_SIGNAL.store(0, Ordering::Release);
        install_cli_termination_handlers()?;
        loop {
            if CLI_TERMINATION_SIGNAL.load(Ordering::Acquire) != 0 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

/// Publish one CLI-owned generation while translating process shutdown signals
/// into the same cooperative cancellation contract used by managed MCP.
///
/// The signal branch always awaits the publication future after cancelling so
/// provider process groups are killed and reaped before the CLI can exit.
pub(crate) async fn wait_for_supervised_cli_publication(
    supervisor: &IndexSupervisor,
    operation: IndexOperationHandle,
) -> Result<Arc<h00ligan_engine::code_intel_publication::PublishedIndexGeneration>, LiganError> {
    let operation_id = operation.operation_id();
    let outcome = operation.wait();
    tokio::pin!(outcome);
    tokio::select! {
        result = &mut outcome => map_supervised_outcome(result),
        signal = wait_for_cli_index_signal() => {
            let _ = supervisor.cancel(operation_id);
            let publish_result = map_supervised_outcome(outcome.await);
            match signal {
                Ok(()) => publish_result,
                Err(error) => {
                    let _ = publish_result;
                    Err(LiganError::Io(error))
                }
            }
        }
    }
}

fn map_supervised_outcome(
    outcome: Result<
        IndexOperationOutcome,
        h00ligan_engine::code_intel_supervisor::IndexSupervisorError,
    >,
) -> Result<Arc<h00ligan_engine::code_intel_publication::PublishedIndexGeneration>, LiganError> {
    match outcome.map_err(|error| LiganError::Config(error.to_string()))? {
        IndexOperationOutcome::Published(published) => Ok(published),
        IndexOperationOutcome::Failed(failure) => Err(LiganError::Config(failure.message)),
        IndexOperationOutcome::Cancelled { .. } => {
            Err(h00ligan_engine::index_pipeline::IndexPipelineError::Cancelled.into())
        }
    }
}

pub(crate) fn start_human_index_progress(
    enabled: bool,
) -> (
    Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
    Option<tokio::task::JoinHandle<()>>,
) {
    if !enabled {
        return (None, None);
    }
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(render_index_progress(receiver, PROGRESS_HEARTBEAT));
    (Some(sender), Some(task))
}

pub(crate) async fn finish_human_index_progress(
    task: Option<tokio::task::JoinHandle<()>>,
) -> Result<(), LiganError> {
    if let Some(task) = task {
        task.await
            .map_err(|error| LiganError::Join(error.to_string()))?;
    }
    Ok(())
}

async fn render_index_progress(
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<IndexProgressEvent>,
    heartbeat: Duration,
) {
    let operation_start = Instant::now();
    let mut active: Option<(String, String, Instant)> = None;
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + heartbeat, heartbeat);

    loop {
        tokio::select! {
            event = receiver.recv() => {
                let Some(event) = event else {
                    break;
                };
                let total = operation_start.elapsed().as_secs_f64();
                let detail = if event.detail.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", event.detail)
                };
                match event.state {
                    IndexProgressState::Started => {
                        eprintln!("  [{total:>6.1}s] {} started{detail}", event.label);
                        active = Some((event.phase.label().into(), event.label, Instant::now()));
                    }
                    IndexProgressState::Completed => {
                        let phase_elapsed = event.elapsed.unwrap_or_default().as_secs_f64();
                        eprintln!(
                            "  [{total:>6.1}s] {} complete ({phase_elapsed:.1}s){detail}",
                            event.label,
                        );
                        active = None;
                    }
                    IndexProgressState::Skipped => {
                        eprintln!("  [{total:>6.1}s] {} skipped{detail}", event.label);
                    }
                    IndexProgressState::Failed => {
                        let phase_elapsed = event.elapsed.unwrap_or_default().as_secs_f64();
                        eprintln!(
                            "  [{total:>6.1}s] {} failed ({phase_elapsed:.1}s){detail}",
                            event.label,
                        );
                        active = None;
                    }
                }
            }
            _ = ticker.tick() => {
                if let Some((phase, label, started)) = &active {
                    eprintln!(
                        "  [{:>6.1}s] still running: {} ({phase}, {:.1}s in this phase)",
                        operation_start.elapsed().as_secs_f64(),
                        label,
                        started.elapsed().as_secs_f64(),
                    );
                }
            }
        }
    }
}

fn capability_scope_label(scope: &h00ligan_engine::code_intel_domain::CapabilityScope) -> String {
    use h00ligan_engine::code_intel_domain::CapabilityScope;
    match scope {
        CapabilityScope::Repository { .. } => "repository".into(),
        CapabilityScope::Language { language_id, .. } => language_id.0.clone(),
        CapabilityScope::ProjectUnit {
            language_id,
            project_unit_id,
            ..
        } => format!("{} · {}", language_id.0, project_unit_id.0),
        CapabilityScope::ProjectUnits {
            language_id,
            project_unit_ids,
            ..
        } => format!(
            "{} · {} project units",
            language_id.0,
            project_unit_ids.len()
        ),
    }
}

/// Arguments for `h00ligan index`.
#[derive(Args, Debug, Clone)]
pub struct IndexArgs {
    /// Attempt best-effort semantic enrichment using eligible SCIP providers.
    #[arg(long)]
    pub scip: bool,

    /// Build a fresh generation even when exact current evidence already
    /// satisfies this request.
    #[arg(long)]
    pub force: bool,

    /// Refuse publication unless every callable language has complete Calls
    /// authority. Requires explicit semantic provider execution.
    #[arg(long, requires = "scip")]
    pub require_complete_calls: bool,

    /// Number of parallel indexing workers.
    #[arg(long, short = 'j')]
    pub jobs: Option<usize>,

    /// Show detailed indexing progress and diagnostics.
    #[arg(long)]
    pub debug: bool,

    /// Print detailed per-phase timing diagnostics.
    #[arg(long)]
    pub profile: bool,

    /// Replace damaged, conflicting, missing-identity, or foreign publication
    /// controls only after a complete fresh generation validates.
    #[arg(long)]
    pub recover_publication: bool,

    /// Allow a freshly built generation to replace stronger current capability
    /// authority. This permission does not bypass exact-current reuse; combine
    /// it with --force to request an intentional unchanged-input downgrade.
    #[arg(long)]
    pub allow_capability_downgrade: bool,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Reuse exact current authority or build and atomically publish a generation.
pub async fn run_index(args: IndexArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    run_index_with_runtime(args, binding, &crate::runtime::LiganRuntime::default()).await
}

pub async fn run_index_with_runtime(
    args: IndexArgs,
    binding: &ProjectBinding,
    runtime: &crate::runtime::LiganRuntime,
) -> Result<(), LiganError> {
    let format = args
        .format
        .parse::<OutputFormat>()
        .map_err(LiganError::Config)?;
    let root = binding.root().to_path_buf();
    let providers = if args.scip {
        ProviderIntent::Refresh
    } else {
        ProviderIntent::StructuralOnly
    };
    let human_output = format == OutputFormat::Text;
    if human_output {
        eprintln!("Ensuring a current index for {} ...", root.display());
    }
    let (progress, progress_task) = start_human_index_progress(human_output);
    let supervisor = runtime
        .supervisor(binding)
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let request = IndexSupervisorRequest {
        providers,
        force: args.force,
        require_complete_calls: args.require_complete_calls,
        jobs: args.jobs,
        debug: args.debug,
        profile: args.profile,
        publication_recovery: if args.recover_publication {
            PublicationRecovery::RecoverAndRebind
        } else {
            PublicationRecovery::Strict
        },
        capability_floor: if args.allow_capability_downgrade {
            CapabilityFloorPolicy::AllowDowngrade
        } else {
            CapabilityFloorPolicy::Preserve
        },
        ..Default::default()
    };
    let operation = match progress {
        Some(progress) => supervisor.start_manual_with_progress(request, progress),
        None => supervisor.start_manual(request),
    }
    .map_err(|error| LiganError::Config(error.to_string()))?;
    let publish_result = wait_for_supervised_cli_publication(&supervisor, operation).await;
    finish_human_index_progress(progress_task).await?;
    supervisor.shutdown_and_wait().await;
    let published = publish_result?;

    let report = &published.telemetry;
    let manifest = &published.publication.manifest;
    let calls_authority = &published.calls_authority;
    let callable_liveness_authority = &published.callable_liveness_authority;
    if format == OutputFormat::Json {
        let result = serde_json::json!({
            "root": root,
            "graph_directory": binding.graph_dir(),
            "generation_id": manifest.generation_id,
            "repository_id": manifest.repository_id,
            "reused_generation": report.reused_generation,
            "files_discovered": report.files_discovered,
            "files_changed": report.files_changed,
            "symbols_extracted": report.symbols_extracted,
            "nodes": report.nodes_total,
            "edges": report.edges_total,
            "duration_ms": report.duration.as_millis(),
            "phase_timings": report.phase_timings.iter().map(|timing| serde_json::json!({
                "phase": timing.phase.label(),
                "label": timing.label,
                "duration_ms": crate::duration_milliseconds(timing.duration),
                "aggregation": timing.aggregation.label(),
            })).collect::<Vec<_>>(),
            "semantic_provider_refreshes": if args.profile {
                report.semantic_provider_refreshes.iter()
                    .map(h00ligan_engine::index_pipeline::SemanticProviderActivityTelemetry::json_value)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            },
            "publication_timings": if args.profile {
                published.publication_timings.iter().map(|timing| serde_json::json!({
                    "label": timing.label,
                    "duration_ms": crate::duration_milliseconds(timing.duration),
                    "aggregation": "exclusive",
                    "work_items": timing.work_items,
                    "work_unit": timing.work_unit,
                })).collect::<Vec<_>>()
            } else {
                Vec::new()
            },
            "capabilities": {
                "calls": &calls_authority,
                "callable_liveness": &callable_liveness_authority,
                "receipts": &manifest.receipts,
            },
            "maintenance": published.publication.maintenance,
        });
        println!(
            "{}",
            serde_json::to_string(&result)
                .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        if report.reused_generation {
            eprintln!("Index current (reused immutable generation):");
        } else {
            eprintln!("Index complete (new immutable generation):");
        }
        eprintln!("  Files changed:        {}", report.files_changed);
        eprintln!("  Symbols extracted:    {}", report.symbols_extracted);
        eprintln!("  Graph nodes:          {}", report.nodes_total);
        eprintln!("  Graph edges:          {}", report.edges_total);
        eprintln!("  Duration:             {:?}", report.duration);
        eprintln!("  Timing:");
        for timing in &report.phase_timings {
            eprintln!(
                "    {:<28} {:>8.3}s  [{}]",
                timing.label,
                timing.duration.as_secs_f64(),
                timing.aggregation.label(),
            );
        }
        if args.profile && !published.publication_timings.is_empty() {
            eprintln!("  Publication detail:");
            for timing in &published.publication_timings {
                eprintln!(
                    "    {:<33} {:>8.3}ms    {} {}  [exclusive]",
                    timing.label,
                    timing.duration.as_secs_f64() * 1_000.0,
                    timing.work_items,
                    timing.work_unit,
                );
            }
        }
        eprintln!("  Generation:           {}", manifest.generation_id);
        eprintln!("  Repository:           {}", manifest.repository_id);
        eprintln!("  Calls authority:       {:?}", calls_authority.status);
        for language in &calls_authority.languages {
            eprintln!(
                "    {:<12} {:?}{}",
                language.language_id,
                language.status,
                language
                    .provider_id
                    .as_ref()
                    .map_or_else(String::new, |provider| format!(" via {provider}")),
            );
            for gap in &language.gaps {
                eprintln!("      {}: {}", gap.reason_code, gap.reason);
            }
        }
        eprintln!(
            "  Callable liveness:     {:?}",
            callable_liveness_authority.status
        );
        for language in &callable_liveness_authority.languages {
            eprintln!(
                "    {:<12} {:?}{}",
                language.language_id,
                language.status,
                language
                    .provider_id
                    .as_ref()
                    .map_or_else(String::new, |provider| format!(" via {provider}")),
            );
            for gap in &language.gaps {
                eprintln!("      {}: {}", gap.reason_code, gap.reason);
            }
            for qualification in &language.qualifications {
                eprintln!(
                    "      {}: {}",
                    qualification.reason_code, qualification.reason
                );
            }
        }
        for receipt in &manifest.receipts {
            eprintln!(
                "  Capability {:<10} [{:<12}] {:?} via {} ({})",
                format!("{}:", receipt.capability_id),
                capability_scope_label(&receipt.scope),
                receipt.status,
                receipt.provider_id,
                receipt.scope.configuration_id(),
            );
            if let (Some(reason_code), Some(reason)) = (&receipt.reason_code, &receipt.reason) {
                eprintln!("    {reason_code}: {reason}");
            }
        }
        for warning in &published.publication.maintenance.warnings {
            eprintln!("  Maintenance warning: {warning}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(name = "test")]
    struct TestCli {
        #[command(flatten)]
        index: IndexArgs,
    }

    #[test]
    fn defaults_are_structural_full_publication() {
        let cli = TestCli::parse_from(["test"]);
        assert!(!cli.index.scip);
        assert!(!cli.index.force);
        assert!(!cli.index.require_complete_calls);
        assert_eq!(cli.index.jobs, None);
        assert!(!cli.index.debug);
        assert!(!cli.index.profile);
        assert!(!cli.index.allow_capability_downgrade);
        assert_eq!(cli.index.format, "text");
    }

    #[test]
    fn explicit_inputs_parse_once_for_both_cli_surfaces() {
        let cli = TestCli::parse_from([
            "test",
            "--scip",
            "--force",
            "--require-complete-calls",
            "-j",
            "4",
            "--debug",
            "--profile",
            "--allow-capability-downgrade",
            "--format",
            "json",
        ]);
        assert!(cli.index.scip);
        assert!(cli.index.force);
        assert!(cli.index.require_complete_calls);
        assert_eq!(cli.index.jobs, Some(4));
        assert!(cli.index.debug);
        assert!(cli.index.profile);
        assert!(cli.index.allow_capability_downgrade);
        assert_eq!(cli.index.format, "json");
    }

    #[test]
    fn complete_calls_requirement_needs_provider_execution() {
        let error = TestCli::try_parse_from(["test", "--require-complete-calls"])
            .expect_err("strict Calls cannot silently run a structural-only index");
        let rendered = error.to_string();
        assert!(rendered.contains("--scip"), "{rendered}");
    }
}
