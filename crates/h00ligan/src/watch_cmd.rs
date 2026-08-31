//! Long-lived CLI adapter for supervised code-intelligence reconciliation.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use clap::Args;
use h00ligan_engine::code_intel_indexing::ProviderIntent;
use h00ligan_engine::code_intel_publication::{CapabilityFloorPolicy, PublicationRecovery};
use h00ligan_engine::code_intel_supervisor::{
    IndexOperationId, IndexOperationSnapshot, IndexOperationState, IndexOperationTrigger,
    IndexSupervisor, IndexSupervisorRequest,
};
use h00ligan_engine::project_binding::ProjectBinding;
use h00ligan_engine::watcher::{IndexWatchService, WatchCadence, WatcherConfig};

use crate::error::LiganError;
use crate::ligan_cmd::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct WatchArgs {
    /// Attempt best-effort semantic provider enrichment on each reconciliation.
    #[arg(long)]
    pub scip: bool,

    /// Require complete Calls authority for every callable language.
    #[arg(long, requires = "scip")]
    pub require_complete_calls: bool,

    /// Native-event quiet window before requesting reconciliation.
    #[arg(long, default_value_t = 75)]
    pub debounce_ms: u64,

    /// Bounded publication-control drift probe interval.
    #[arg(long, default_value_t = 1_000)]
    pub publication_probe_ms: u64,

    /// Byte-exact full-discovery integrity reconciliation interval.
    #[arg(long, default_value_t = 60)]
    pub reconcile_secs: u64,

    /// Number of parallel indexing workers.
    #[arg(long, short = 'j')]
    pub jobs: Option<usize>,

    /// Show detailed indexing diagnostics.
    #[arg(long)]
    pub debug: bool,

    /// Retain detailed per-phase timing diagnostics.
    #[arg(long)]
    pub profile: bool,

    /// Repair and rebind damaged or foreign publication controls.
    #[arg(long)]
    pub recover_publication: bool,

    /// Permit capability downgrade and publish changed structural truth before
    /// slower semantic enrichment.
    #[arg(long)]
    pub allow_capability_downgrade: bool,

    /// Output format: text or json (one JSON object per event line).
    #[arg(long, default_value = "text")]
    pub format: String,
}

pub async fn run_watch(args: WatchArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    run_watch_with_runtime(args, binding, &crate::runtime::LiganRuntime::default()).await
}

pub async fn run_watch_with_runtime(
    args: WatchArgs,
    binding: &ProjectBinding,
    runtime: &crate::runtime::LiganRuntime,
) -> Result<(), LiganError> {
    if args.debounce_ms == 0 {
        return Err(LiganError::Config(
            "--debounce-ms must be at least 1".into(),
        ));
    }
    if args.reconcile_secs == 0 {
        return Err(LiganError::Config(
            "--reconcile-secs must be at least 1".into(),
        ));
    }
    if args.publication_probe_ms == 0 {
        return Err(LiganError::Config(
            "--publication-probe-ms must be at least 1".into(),
        ));
    }
    let format = args
        .format
        .parse::<OutputFormat>()
        .map_err(LiganError::Config)?;
    let supervisor = runtime
        .supervisor(binding)
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let request = IndexSupervisorRequest {
        providers: if args.scip {
            ProviderIntent::Refresh
        } else {
            ProviderIntent::StructuralOnly
        },
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
    let watcher = WatcherConfig::new(binding.root().to_path_buf(), args.debounce_ms)
        .exclude_root(binding.graph_dir().to_path_buf());
    let service = IndexWatchService::start(
        supervisor.as_ref().clone(),
        watcher,
        request,
        WatchCadence::new(
            Duration::from_millis(args.publication_probe_ms),
            Duration::from_secs(args.reconcile_secs),
        ),
    )
    .map_err(|error| LiganError::Config(error.to_string()))?;

    emit_started(
        format,
        binding,
        args.debounce_ms,
        args.publication_probe_ms,
        args.reconcile_secs,
    )?;
    let signal = crate::index_cmd::wait_for_cli_index_signal();
    tokio::pin!(signal);
    let mut poll = tokio::time::interval(Duration::from_millis(100));
    let mut event_cursor = WatchOperationCursor::default();
    let loop_result = loop {
        tokio::select! {
            signal = &mut signal => break signal.map_err(LiganError::Io),
            _ = poll.tick() => {
                let status = service.status();
                if !status.running {
                    break Err(LiganError::Config(
                        status.last_error.unwrap_or_else(|| "native watcher stopped unexpectedly".into())
                    ));
                }
                emit_operation_updates(format, args.profile, &mut event_cursor, &supervisor)?;
            }
        }
    };
    let stopped = service
        .stop()
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    supervisor.shutdown_and_wait().await;
    // Shutdown may terminally cancel an operation after the signal ended the
    // polling loop. Drain the retained population once so every announced
    // start receives its exact terminal receipt before `watch_stopped`.
    emit_operation_updates(format, args.profile, &mut event_cursor, &supervisor)?;
    loop_result?;
    emit_stopped(format, &stopped)?;
    Ok(())
}

fn emit_started(
    format: OutputFormat,
    binding: &ProjectBinding,
    debounce_ms: u64,
    publication_probe_ms: u64,
    reconcile_secs: u64,
) -> Result<(), LiganError> {
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "watch_started",
                "root": binding.root(),
                "graph_directory": binding.graph_dir(),
                "debounce_ms": debounce_ms,
                "publication_probe_ms": publication_probe_ms,
                "reconcile_secs": reconcile_secs,
            }))
            .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        eprintln!("Watching {} for code changes ...", binding.root().display());
        eprintln!(
            "  Debounce: {debounce_ms}ms · publication probe: {publication_probe_ms}ms · integrity reconciliation: {reconcile_secs}s · Ctrl-C to stop"
        );
    }
    Ok(())
}

fn emit_operation_started(
    format: OutputFormat,
    snapshot: &IndexOperationSnapshot,
) -> Result<(), LiganError> {
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "reconciliation_started",
                "operation_id": snapshot.operation_id.to_string(),
                "covered_epoch": snapshot.covered_epoch,
                "trigger": match snapshot.trigger {
                    IndexOperationTrigger::Manual => "manual",
                    IndexOperationTrigger::Watch => "watch",
                },
                "dirty_hint_count": snapshot.dirty_hint_count,
                "dirty_hints_overflowed": snapshot.dirty_hints_overflowed,
            }))
            .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        eprintln!(
            "  Reconciling epoch {} ({}) ...",
            snapshot.covered_epoch, snapshot.operation_id
        );
    }
    Ok(())
}

fn emit_terminal(
    format: OutputFormat,
    profile: bool,
    snapshot: &h00ligan_engine::code_intel_supervisor::IndexOperationSnapshot,
) -> Result<(), LiganError> {
    if format == OutputFormat::Json {
        let phase_timings = snapshot
            .publication
            .as_ref()
            .filter(|_| profile)
            .map(|publication| {
                publication
                    .phase_timings
                    .iter()
                    .map(|timing| {
                        serde_json::json!({
                            "phase": timing.phase.label(),
                            "label": timing.label,
                            "duration_ms": crate::duration_milliseconds(timing.duration),
                            "aggregation": timing.aggregation.label(),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let publication_timings = snapshot
            .publication
            .as_ref()
            .filter(|_| profile)
            .map(|publication| {
                publication
                    .publication_timings
                    .iter()
                    .map(|timing| {
                        serde_json::json!({
                            "label": timing.label,
                            "duration_ms": crate::duration_milliseconds(timing.duration),
                            "aggregation": "exclusive",
                            "work_items": timing.work_items,
                            "work_unit": timing.work_unit,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let semantic_provider_refreshes = snapshot
            .publication
            .as_ref()
            .filter(|_| profile)
            .map(|publication| {
                publication
                    .semantic_provider_refreshes
                    .iter()
                    .map(h00ligan_engine::index_pipeline::SemanticProviderActivityTelemetry::json_value)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "reconciliation_terminal",
                "operation_id": snapshot.operation_id.to_string(),
                "covered_epoch": snapshot.covered_epoch,
                "state": snapshot.state.label(),
                "generation": snapshot.publication.as_ref().map(|publication| &publication.generation_id),
                "reused_generation": snapshot.publication.as_ref().map(|publication| publication.reused_generation),
                "files_discovered": snapshot.publication.as_ref().map(|publication| publication.files_discovered),
                "files_changed": snapshot.publication.as_ref().map(|publication| publication.files_changed),
                "nodes_added": snapshot.publication.as_ref().map(|publication| publication.nodes_added),
                "live_structural_basis_reused": snapshot.publication.as_ref().map(|publication| publication.live_structural_basis_reused),
                "dirty_hint_count": snapshot.dirty_hint_count,
                "dirty_hints_overflowed": snapshot.dirty_hints_overflowed,
                "duration_ms": snapshot.elapsed.as_millis() as u64,
                "phase_timings": phase_timings,
                "publication_timings": publication_timings,
                "semantic_provider_refreshes": semantic_provider_refreshes,
                "error": snapshot.failure.as_ref().map(|failure| &failure.message),
            }))
            .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        match snapshot.state {
            IndexOperationState::Succeeded => {
                let publication = snapshot.publication.as_ref().ok_or_else(|| {
                    LiganError::Config("successful WATCH receipt has no publication".into())
                })?;
                eprintln!(
                    "  Current at epoch {}: {} files changed · {} nodes · {:.3}s",
                    snapshot.covered_epoch,
                    publication.files_changed,
                    publication.nodes_total,
                    snapshot.elapsed.as_secs_f64(),
                );
                if profile {
                    for timing in &publication.phase_timings {
                        eprintln!(
                            "    {:<28} {:>8.3}s  [{}]",
                            timing.label,
                            timing.duration.as_secs_f64(),
                            timing.aggregation.label(),
                        );
                    }
                    if !publication.publication_timings.is_empty() {
                        eprintln!("    Publication detail:");
                        for timing in &publication.publication_timings {
                            eprintln!(
                                "      {:<31} {:>8.3}ms    {} {}  [exclusive]",
                                timing.label,
                                timing.duration.as_secs_f64() * 1_000.0,
                                timing.work_items,
                                timing.work_unit,
                            );
                        }
                    }
                }
            }
            IndexOperationState::Superseded => {
                eprintln!("  Superseded by a newer source epoch");
            }
            IndexOperationState::Cancelled => eprintln!("  Reconciliation cancelled"),
            IndexOperationState::Failed => {
                let message = snapshot
                    .failure
                    .as_ref()
                    .map_or("unknown failure", |failure| failure.message.as_str());
                eprintln!("  Reconciliation failed: {message}");
            }
            _ => {}
        }
    }
    Ok(())
}

fn emit_structural_publication(
    format: OutputFormat,
    snapshot: &IndexOperationSnapshot,
) -> Result<(), LiganError> {
    let publication = snapshot.structural_publication.as_ref().ok_or_else(|| {
        LiganError::Config("structural WATCH event has no publication receipt".into())
    })?;
    let enrichment = snapshot.semantic_enrichment_state().ok_or_else(|| {
        LiganError::Config("structural WATCH event has no enrichment lifecycle".into())
    })?;
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "structural_publication",
                "operation_id": snapshot.operation_id.to_string(),
                "covered_epoch": snapshot.covered_epoch,
                "generation": publication.generation_id,
                "files_changed": publication.files_changed,
                "nodes_total": publication.nodes_total,
                "edges_total": publication.edges_total,
                "duration_ms": publication.duration.as_millis() as u64,
                // These are intentionally two coordinates. The structural
                // receipt proves enrichment was pending when this generation
                // became visible; a slow adapter poll may first observe that
                // milestone after the same operation is already terminal.
                "semantic_enrichment_pending_at_publication": true,
                "semantic_enrichment_state": enrichment.label(),
                "semantic_enrichment_pending": enrichment.is_pending(),
            }))
            .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        if enrichment.is_pending() {
            eprintln!(
                "  Structural current at epoch {}: {} files changed · {} nodes · {:.3}s; semantic enrichment continues ...",
                snapshot.covered_epoch,
                publication.files_changed,
                publication.nodes_total,
                publication.duration.as_secs_f64(),
            );
        } else {
            eprintln!(
                "  Structural current at epoch {}: {} files changed · {} nodes · {:.3}s; semantic enrichment is {}",
                snapshot.covered_epoch,
                publication.files_changed,
                publication.nodes_total,
                publication.duration.as_secs_f64(),
                enrichment.label(),
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WatchOperationEvent {
    Started(IndexOperationSnapshot),
    StructuralPublished(IndexOperationSnapshot),
    Terminal(IndexOperationSnapshot),
}

#[derive(Default)]
struct WatchOperationCursor {
    observed_states: HashMap<IndexOperationId, IndexOperationState>,
    observed_structural: HashSet<IndexOperationId>,
}

impl WatchOperationCursor {
    fn advance(&mut self, snapshots: &[IndexOperationSnapshot]) -> Vec<WatchOperationEvent> {
        let retained = snapshots
            .iter()
            .map(|snapshot| snapshot.operation_id)
            .collect::<HashSet<_>>();
        self.observed_states
            .retain(|operation_id, _| retained.contains(operation_id));
        self.observed_structural
            .retain(|operation_id| retained.contains(operation_id));

        let mut events = Vec::new();
        for snapshot in snapshots {
            let previous = self
                .observed_states
                .insert(snapshot.operation_id, snapshot.state);
            if previous.is_none() {
                events.push(WatchOperationEvent::Started(snapshot.clone()));
            }
            if snapshot.structural_publication.is_some()
                && self.observed_structural.insert(snapshot.operation_id)
            {
                events.push(WatchOperationEvent::StructuralPublished(snapshot.clone()));
            }
            if snapshot.state.is_terminal()
                && previous.is_none_or(|previous| !previous.is_terminal())
            {
                events.push(WatchOperationEvent::Terminal(snapshot.clone()));
            }
        }
        events
    }
}

fn emit_operation_updates(
    format: OutputFormat,
    profile: bool,
    cursor: &mut WatchOperationCursor,
    supervisor: &IndexSupervisor,
) -> Result<(), LiganError> {
    for event in cursor.advance(&supervisor.retained_snapshots()) {
        match event {
            WatchOperationEvent::Started(snapshot) => emit_operation_started(format, &snapshot)?,
            WatchOperationEvent::StructuralPublished(snapshot) => {
                emit_structural_publication(format, &snapshot)?;
            }
            WatchOperationEvent::Terminal(snapshot) => emit_terminal(format, profile, &snapshot)?,
        }
    }
    Ok(())
}

fn emit_stopped(
    format: OutputFormat,
    status: &h00ligan_engine::watcher::IndexWatchStatus,
) -> Result<(), LiganError> {
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "watch_stopped",
                "watched_directories": status.watched_directories,
                "filesystem_batches": status.filesystem_batches,
                "publication_probes": status.publication_probes,
                "publication_control_reads": status.publication_control_reads,
                "publication_probe_failures": status.publication_probe_failures,
                "publication_drifts": status.publication_drifts,
                "integrity_reconciliations": status.integrity_reconciliations,
                "published_epoch": status.published_epoch,
            }))
            .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        eprintln!("Watch stopped cleanly at epoch {}.", status.published_epoch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::str::FromStr as _;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        watch: WatchArgs,
    }

    #[test]
    fn watch_defaults_prioritize_native_events_and_bound_deep_integrity_audits() {
        let cli = TestCli::parse_from(["test"]);
        assert!(!cli.watch.scip);
        assert_eq!(cli.watch.debounce_ms, 75);
        assert_eq!(cli.watch.publication_probe_ms, 1_000);
        assert_eq!(
            cli.watch.reconcile_secs, 60,
            "the byte-exact whole-repository audit is a missed-event safety net, not an idle heartbeat"
        );
        assert_eq!(cli.watch.format, "text");
    }

    fn operation_snapshot(sequence: u64, state: IndexOperationState) -> IndexOperationSnapshot {
        IndexOperationSnapshot {
            operation_id: IndexOperationId::from_str(&format!(
                "index-00000000000000000000000000000001-{sequence}"
            ))
            .expect("operation ID"),
            trigger: IndexOperationTrigger::Watch,
            covered_epoch: sequence,
            state,
            request: IndexSupervisorRequest::default(),
            created_at_unix_ms: sequence,
            started_at_unix_ms: Some(sequence),
            finished_at_unix_ms: state.is_terminal().then_some(sequence + 1),
            elapsed: Duration::from_millis(1),
            progress: Vec::new(),
            cancellation_reason: None,
            dirty_hint_count: usize::from(sequence > 1),
            dirty_hints_overflowed: false,
            structural_publication: None,
            publication: None,
            failure: None,
        }
    }

    fn structural_receipt() -> h00ligan_engine::code_intel_supervisor::IndexPublicationReceipt {
        h00ligan_engine::code_intel_supervisor::IndexPublicationReceipt {
            generation_id: "g-structural".into(),
            repository_id: "repo-watch".into(),
            sequence: 2,
            reused_generation: false,
            files_discovered: 1,
            files_changed: 1,
            symbols_extracted: 1,
            nodes_added: 1,
            nodes_total: 1,
            edges_added: 0,
            edges_total: 0,
            live_structural_basis_reused: true,
            reachability: None,
            calls_authority: h00ligan_engine::code_intel_domain::CapabilityCoverage {
                capability_id: "calls".into(),
                status: h00ligan_engine::code_intel_domain::CapabilityCoverageStatus::NotApplicable,
                languages: Vec::new(),
            },
            callable_liveness_authority: h00ligan_engine::code_intel_domain::CapabilityCoverage {
                capability_id: "callable_liveness".into(),
                status: h00ligan_engine::code_intel_domain::CapabilityCoverageStatus::NotApplicable,
                languages: Vec::new(),
            },
            capability_receipts: Vec::new(),
            maintenance: h00ligan_engine::code_intel_publication::PublicationMaintenance::default(),
            duration: Duration::from_millis(25),
            phase_timings: Vec::new(),
            publication_timings: Vec::new(),
            semantic_provider_refreshes: Vec::new(),
        }
    }

    #[test]
    fn operation_cursor_does_not_lose_a_terminal_when_a_successor_is_already_running() {
        let mut cursor = WatchOperationCursor::default();
        let first_running = operation_snapshot(1, IndexOperationState::Running);
        assert!(matches!(
            cursor.advance(std::slice::from_ref(&first_running)).as_slice(),
            [WatchOperationEvent::Started(snapshot)] if snapshot.operation_id == first_running.operation_id
        ));

        let first_terminal = operation_snapshot(1, IndexOperationState::Succeeded);
        let second_running = operation_snapshot(2, IndexOperationState::Running);
        let events = cursor.advance(&[first_terminal.clone(), second_running.clone()]);
        assert!(matches!(
            events.as_slice(),
            [WatchOperationEvent::Terminal(first), WatchOperationEvent::Started(second)]
                if first.operation_id == first_terminal.operation_id
                    && second.operation_id == second_running.operation_id
        ));
        assert!(
            cursor
                .advance(&[first_terminal.clone(), second_running])
                .is_empty(),
            "unchanged retained states must not replay lifecycle events"
        );

        let second_terminal = operation_snapshot(2, IndexOperationState::Superseded);
        assert!(matches!(
            cursor.advance(&[first_terminal, second_terminal.clone()]).as_slice(),
            [WatchOperationEvent::Terminal(snapshot)]
                if snapshot.operation_id == second_terminal.operation_id
        ));
    }

    #[test]
    fn operation_cursor_emits_one_structural_publication_before_terminal_enrichment() {
        let mut cursor = WatchOperationCursor::default();
        let running = operation_snapshot(1, IndexOperationState::Running);
        assert!(matches!(
            cursor.advance(std::slice::from_ref(&running)).as_slice(),
            [WatchOperationEvent::Started(_)]
        ));

        let mut structural = running.clone();
        structural.structural_publication = Some(structural_receipt());
        assert!(matches!(
            cursor.advance(std::slice::from_ref(&structural)).as_slice(),
            [WatchOperationEvent::StructuralPublished(snapshot)]
                if snapshot.structural_publication.is_some()
        ));
        assert!(
            cursor.advance(std::slice::from_ref(&structural)).is_empty(),
            "an unchanged staged publication must not replay"
        );

        let mut terminal = structural;
        terminal.state = IndexOperationState::Succeeded;
        terminal.publication = Some(structural_receipt());
        assert!(matches!(
            cursor.advance(std::slice::from_ref(&terminal)).as_slice(),
            [WatchOperationEvent::Terminal(_)]
        ));
    }

    /// FALSIFIER for adapter polling races: the supervisor may publish the
    /// structural stage and reach a terminal semantic outcome between two CLI
    /// polls. The cursor must retain both milestones in order, while the
    /// shared enrichment state reports what is true at observation time.
    #[test]
    fn late_first_poll_keeps_structural_history_and_terminal_state_distinct() {
        let mut terminal = operation_snapshot(1, IndexOperationState::Cancelled);
        terminal.structural_publication = Some(structural_receipt());
        let mut cursor = WatchOperationCursor::default();
        let events = cursor.advance(std::slice::from_ref(&terminal));
        assert!(matches!(
            events.as_slice(),
            [
                WatchOperationEvent::Started(started),
                WatchOperationEvent::StructuralPublished(structural),
                WatchOperationEvent::Terminal(finished),
            ] if started.operation_id == terminal.operation_id
                && structural.semantic_enrichment_state()
                    == Some(h00ligan_engine::code_intel_supervisor::SemanticEnrichmentState::Cancelled)
                && finished.state == IndexOperationState::Cancelled
        ));
    }
}
