//! MCP rendering for the engine-owned indexing supervisor.
//!
//! Scheduling, cancellation authority, epochs, and terminal retention belong
//! to `h00ligan-engine`. This adapter translates typed receipts into the stable MCP
//! JSON shape without maintaining a second lifecycle state machine.

use std::path::Path;

use h00ligan_engine::code_intel_supervisor::{
    IndexCancellationReason, IndexCancellationReceipt, IndexOperationFailureKind, IndexOperationId,
    IndexOperationSnapshot, IndexOperationState, IndexOperationTrigger, IndexPublicationReceipt,
    IndexSupervisorError,
};
use serde_json::{Value, json};

use crate::ToolError;

pub fn parse_operation_id(value: &str) -> Result<IndexOperationId, ToolError> {
    value.parse().map_err(|_| {
        let message = "the requested index operation does not belong to this MCP process";
        ToolError::Domain {
            message: message.into(),
            envelope: json!({
                "error": {
                    "code": "reindex_operation_not_found",
                    "message": message,
                    "evidence": {"requested_operation_id": value},
                }
            }),
        }
    })
}

pub fn supervisor_error(error: IndexSupervisorError) -> ToolError {
    let code = match error {
        IndexSupervisorError::ManualBusy => "reindex_busy",
        IndexSupervisorError::OperationNotFound { .. } | IndexSupervisorError::NoOperations => {
            "reindex_operation_not_found"
        }
        IndexSupervisorError::ShuttingDown => "reindex_supervisor_shutting_down",
        IndexSupervisorError::RuntimeUnavailable => "reindex_runtime_unavailable",
        IndexSupervisorError::ResultChannelClosed { .. } => "reindex_result_channel_closed",
    };
    let message = error.to_string();
    ToolError::Domain {
        message: message.clone(),
        envelope: json!({
            "error": {
                "code": code,
                "message": message,
                "evidence": {},
            }
        }),
    }
}

pub fn operation_snapshot_json(snapshot: &IndexOperationSnapshot, result: Option<Value>) -> Value {
    let request = &snapshot.request;
    let semantic_enrichment = snapshot.semantic_enrichment_state();
    let progress = snapshot
        .progress
        .iter()
        .map(|event| {
            json!({
                "phase": event.phase.label(),
                "state": match event.state {
                    h00ligan_engine::index_pipeline::IndexProgressState::Started => "started",
                    h00ligan_engine::index_pipeline::IndexProgressState::Completed => "completed",
                    h00ligan_engine::index_pipeline::IndexProgressState::Skipped => "skipped",
                    h00ligan_engine::index_pipeline::IndexProgressState::Failed => "failed",
                },
                "label": event.label,
                "detail": event.detail,
                "elapsed_ms": event.elapsed.map(|elapsed| elapsed.as_millis() as u64),
            })
        })
        .collect::<Vec<_>>();
    let error = match snapshot.state {
        IndexOperationState::Failed => snapshot.failure.as_ref().map(|failure| {
            json!({
                "kind": "tool_error",
                "category": failure_kind_label(failure.kind),
                "code": failure.code.label(),
                "message": failure.message,
            })
        }),
        IndexOperationState::Cancelled => Some(json!({
            "kind": "cancelled",
            "message": "indexing operation cancelled before publication",
        })),
        IndexOperationState::Superseded => Some(json!({
            "kind": "superseded",
            "message": "a newer source epoch superseded this private candidate",
        })),
        _ => None,
    };
    json!({
        "schema_version": "h00/code-intel/index-operation/v2",
        "operation_id": snapshot.operation_id.to_string(),
        "trigger": match snapshot.trigger {
            IndexOperationTrigger::Manual => "manual",
            IndexOperationTrigger::Watch => "watch",
        },
        "covered_epoch": snapshot.covered_epoch,
        "state": snapshot.state.label(),
        "terminal": snapshot.state.is_terminal(),
        "cancel_requested": snapshot.cancellation_reason.is_some(),
        "cancellation_reason": snapshot.cancellation_reason.map(cancellation_reason_label),
        "request": {
            "scip": request.providers == h00ligan_engine::code_intel_indexing::ProviderIntent::Refresh,
            "force": request.force,
            "require_complete_calls": request.require_complete_calls,
            "recover_publication": request.publication_recovery == h00ligan_engine::code_intel_publication::PublicationRecovery::RecoverAndRebind,
            "allow_capability_downgrade": request.capability_floor == h00ligan_engine::code_intel_publication::CapabilityFloorPolicy::AllowDowngrade,
        },
        "created_at_unix_ms": snapshot.created_at_unix_ms,
        "started_at_unix_ms": snapshot.started_at_unix_ms,
        "finished_at_unix_ms": snapshot.finished_at_unix_ms,
        "elapsed_ms": snapshot.elapsed.as_millis() as u64,
        "progress": progress,
        "dirty_hints": {
            "retained": snapshot.dirty_hint_count,
            "overflowed": snapshot.dirty_hints_overflowed,
            "authoritative": false,
        },
        "structural_publication": snapshot.structural_publication.as_ref().map(|publication| json!({
            "generation_id": publication.generation_id,
            "repository_id": publication.repository_id,
            "sequence": publication.sequence,
            "reused_generation": publication.reused_generation,
            "files_changed": publication.files_changed,
            "nodes_total": publication.nodes_total,
            "edges_total": publication.edges_total,
            "duration_ms": publication.duration.as_millis() as u64,
            "semantic_enrichment_pending_at_publication": true,
            "semantic_enrichment_state": semantic_enrichment.map(|state| state.label()),
            "semantic_enrichment_pending": semantic_enrichment.is_some_and(|state| state.is_pending()),
        })),
        "result": result,
        "error": error,
    })
}

pub fn cancellation_receipt_json(receipt: &IndexCancellationReceipt) -> Value {
    let mut rendered = operation_snapshot_json(&receipt.operation, None);
    rendered["cancellation"] = json!({
        "accepted": receipt.accepted,
        "reason": if receipt.accepted {
            "requested"
        } else {
            "already_terminal"
        },
    });
    rendered
}

pub fn publication_result_json(
    publication: &IndexPublicationReceipt,
    graph_directory: &Path,
    operation: &IndexOperationSnapshot,
) -> Value {
    let request = &operation.request;
    json!({
        "generation": {
            "id": publication.generation_id,
            "sequence": publication.sequence,
            "repository_id": publication.repository_id,
        },
        "reused_generation": publication.reused_generation,
        "files_changed": publication.files_changed,
        "symbols_extracted": publication.symbols_extracted,
        "graph": {
            "nodes_total": publication.nodes_total,
            "nodes_added": publication.nodes_added,
            "edges_total": publication.edges_total,
            "edges_added": publication.edges_added,
            "live_structural_basis_reused": publication.live_structural_basis_reused,
        },
        "reachability": publication.reachability.as_ref().map(|reachability| json!({
            "wired": reachability.wired + reachability.public_api,
            "dead": reachability.dead,
            "test_only": reachability.test_only,
            "orphan": reachability.orphan,
            "structural": reachability.structural,
        })),
        "capabilities": {
            "calls": &publication.calls_authority,
            "callable_liveness": &publication.callable_liveness_authority,
            "receipts": &publication.capability_receipts,
        },
        "maintenance": &publication.maintenance,
        "duration_ms": publication.duration.as_millis() as u64,
        "phase_timings": publication.phase_timings.iter().map(|timing| json!({
            "phase": timing.phase.label(),
            "label": timing.label,
            "duration_ms": timing.duration.as_millis() as u64,
            "aggregation": timing.aggregation.label(),
        })).collect::<Vec<_>>(),
        "semantic_provider_refreshes": if request.profile {
            publication.semantic_provider_refreshes.iter()
                .map(h00ligan_engine::index_pipeline::SemanticProviderActivityTelemetry::json_value)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        },
        "provider_requested": request.providers == h00ligan_engine::code_intel_indexing::ProviderIntent::Refresh,
        "force_requested": request.force,
        "complete_calls_required": request.require_complete_calls,
        "publication_recovery_requested": request.publication_recovery == h00ligan_engine::code_intel_publication::PublicationRecovery::RecoverAndRebind,
        "capability_downgrade_authorized": request.capability_floor == h00ligan_engine::code_intel_publication::CapabilityFloorPolicy::AllowDowngrade,
        "index_mode": if publication.reused_generation {
            "reused_generation"
        } else {
            "fresh_generation"
        },
        "graph_directory": graph_directory,
    })
}

const fn failure_kind_label(kind: IndexOperationFailureKind) -> &'static str {
    match kind {
        IndexOperationFailureKind::Preparation => "preparation",
        IndexOperationFailureKind::Publication => "publication",
        IndexOperationFailureKind::BackgroundTask => "background_task",
    }
}

const fn cancellation_reason_label(reason: IndexCancellationReason) -> &'static str {
    match reason {
        IndexCancellationReason::Superseded => "superseded",
        IndexCancellationReason::ManualPriority => "manual_priority",
        IndexCancellationReason::Requested => "requested",
        IndexCancellationReason::Shutdown => "shutdown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use h00ligan_engine::code_intel_supervisor::{
        IndexOperationSnapshot, IndexPublicationReceipt, IndexSupervisorRequest,
    };
    use std::str::FromStr as _;
    use std::time::Duration;

    fn staged_snapshot(state: IndexOperationState) -> IndexOperationSnapshot {
        IndexOperationSnapshot {
            operation_id: IndexOperationId::from_str("index-00000000000000000000000000000001-1")
                .expect("operation ID"),
            trigger: IndexOperationTrigger::Watch,
            covered_epoch: 3,
            state,
            request: IndexSupervisorRequest {
                providers: h00ligan_engine::code_intel_indexing::ProviderIntent::Refresh,
                capability_floor:
                    h00ligan_engine::code_intel_publication::CapabilityFloorPolicy::AllowDowngrade,
                ..IndexSupervisorRequest::default()
            },
            created_at_unix_ms: 1,
            started_at_unix_ms: Some(1),
            finished_at_unix_ms: state.is_terminal().then_some(2),
            elapsed: Duration::from_millis(25),
            progress: Vec::new(),
            cancellation_reason: None,
            dirty_hint_count: 1,
            dirty_hints_overflowed: false,
            structural_publication: Some(IndexPublicationReceipt {
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
                    status:
                        h00ligan_engine::code_intel_domain::CapabilityCoverageStatus::NotApplicable,
                    languages: Vec::new(),
                },
                callable_liveness_authority: h00ligan_engine::code_intel_domain::CapabilityCoverage {
                    capability_id: "callable_liveness".into(),
                    status: h00ligan_engine::code_intel_domain::CapabilityCoverageStatus::NotApplicable,
                    languages: Vec::new(),
                },
                capability_receipts: Vec::new(),
                maintenance:
                    h00ligan_engine::code_intel_publication::PublicationMaintenance::default(),
                duration: Duration::from_millis(20),
                phase_timings: Vec::new(),
                publication_timings: Vec::new(),
                semantic_provider_refreshes: Vec::new(),
            }),
            publication: None,
            failure: None,
        }
    }

    #[test]
    fn operation_json_exposes_source_current_structural_stage_while_semantics_run() {
        let running = operation_snapshot_json(&staged_snapshot(IndexOperationState::Running), None);
        assert_eq!(
            running["structural_publication"]["generation_id"],
            "g-structural"
        );
        assert_eq!(
            running["structural_publication"]["semantic_enrichment_pending"],
            true
        );
        assert_eq!(
            running["structural_publication"]["semantic_enrichment_state"],
            "pending"
        );
        assert_eq!(
            running["structural_publication"]["semantic_enrichment_pending_at_publication"],
            true
        );
        assert_eq!(running["request"]["allow_capability_downgrade"], true);

        let terminal =
            operation_snapshot_json(&staged_snapshot(IndexOperationState::Cancelled), None);
        assert_eq!(
            terminal["structural_publication"]["semantic_enrichment_pending"], false,
            "the terminal receipt must not claim background work still exists"
        );
        assert_eq!(
            terminal["structural_publication"]["semantic_enrichment_state"], "cancelled",
            "terminal staged truth must distinguish cancellation from successful enrichment"
        );
        assert_eq!(
            terminal["structural_publication"]["semantic_enrichment_pending_at_publication"], true,
            "terminal observation must not erase the stage's historical lifecycle coordinate"
        );
    }

    #[test]
    fn terminal_result_is_rendered_from_the_self_contained_publication_receipt() {
        let mut operation = staged_snapshot(IndexOperationState::Succeeded);
        let mut publication = operation
            .structural_publication
            .take()
            .expect("publication fixture");
        publication.reachability = Some(h00ligan_engine::graph_stats::ReachabilitySummary {
            wired: 2,
            public_api: 1,
            structural: 3,
            test_only: 4,
            dead: 5,
            orphan: 6,
            ..h00ligan_engine::graph_stats::ReachabilitySummary::default()
        });
        operation.publication = Some(publication.clone());

        let result =
            publication_result_json(&publication, Path::new(".h00ligan/code-intel"), &operation);
        assert_eq!(result["generation"]["id"], "g-structural");
        assert_eq!(result["graph"]["nodes_total"], 1);
        assert_eq!(result["reachability"]["wired"], 3);
        assert_eq!(result["reachability"]["dead"], 5);
        assert_eq!(result["capabilities"]["calls"]["status"], "not_applicable");
        assert_eq!(result["capabilities"]["receipts"], json!([]));
        assert_eq!(result["maintenance"]["removed"], json!([]));
        assert_eq!(result["graph_directory"], ".h00ligan/code-intel");
    }
}
