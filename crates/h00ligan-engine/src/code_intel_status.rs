//! Exact Status projection shared by every h00ligan adapter.
//!
//! Loading and live freshness observation remain outside this pure module.
//! Once one coherent snapshot has supplied those inputs, this module owns the
//! result shape, verdict, graph summaries, and deterministic serialization.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::code_intel_domain::{CapabilityCoverage, GenerationId, RepositoryId};
use crate::graph::KnowledgeGraph;
use crate::graph_stats::{StalenessVerdict, compute_graph_stats, compute_reachability_summary};
use crate::graph_status::{
    ClassificationCurrencyStatus, ClassificationProvenance, classification_currency_status,
    status_verdict_with_calls_actionability,
};
use crate::graph_store::ClassifiedBy;

pub const STATUS_SCHEMA_VERSION: &str = "h00/code-intel/status/v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    Unpublished,
    Published,
    Invalid,
}

impl std::fmt::Display for PublicationState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unpublished => "unpublished",
            Self::Published => "published",
            Self::Invalid => "invalid",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityStatus {
    Unindexed,
    LoadFailed,
    OriginMismatch,
    Available,
}

impl std::fmt::Display for AvailabilityStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unindexed => "unindexed",
            Self::LoadFailed => "load_failed",
            Self::OriginMismatch => "origin_mismatch",
            Self::Available => "available",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    NotEvaluated,
    Unknown,
    Stale,
    Fresh,
}

impl std::fmt::Display for FreshnessStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotEvaluated => "not_evaluated",
            Self::Unknown => "unknown",
            Self::Stale => "stale",
            Self::Fresh => "fresh",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusCapabilities {
    pub calls: CapabilityCoverage,
    pub callable_liveness: CapabilityCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusGraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub edge_kinds: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReachability {
    pub wired: usize,
    pub public_api: usize,
    pub structural: usize,
    pub test_only: usize,
    pub dead: usize,
    pub orphan: usize,
    pub unclassified: usize,
    pub suspected: usize,
    pub excluded: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusOriginMismatch {
    pub stored: PathBuf,
    pub bound: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactStatusResult {
    pub schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_id: Option<GenerationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<RepositoryId>,
    pub publication_state: PublicationState,
    pub graph_exists: bool,
    pub graph_loaded: bool,
    pub root: PathBuf,
    pub graph_directory: PathBuf,
    pub root_source: String,
    pub graph_source: String,
    pub availability: AvailabilityStatus,
    pub freshness: FreshnessStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness_files_checked: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_at_unix_seconds: Option<u64>,
    pub action_needed: bool,
    pub recommendation: String,
    pub capabilities: StatusCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classified_by: Option<ClassificationProvenance>,
    pub classification_currency: ClassificationCurrencyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<StatusGraphStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<StatusReachability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authoritative_dead_requires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_mismatch: Option<StatusOriginMismatch>,
}

pub struct StatusObservation<'a> {
    pub root: &'a Path,
    pub graph_directory: &'a Path,
    pub root_source: &'static str,
    pub graph_source: &'static str,
    pub generation_id: Option<GenerationId>,
    pub repository_id: Option<RepositoryId>,
    pub graph: Option<&'a KnowledgeGraph>,
    pub graph_exists: bool,
    pub load_error: Option<String>,
    pub origin_mismatch: Option<StatusOriginMismatch>,
    pub freshness: StalenessVerdict,
    pub indexed_at: Option<SystemTime>,
    pub incremental_drift: bool,
    pub calls: CapabilityCoverage,
    pub callable_liveness: CapabilityCoverage,
    pub classified_by: Option<&'a ClassifiedBy>,
    /// Whether validated reachability evidence proves the exact document scope
    /// classified in this immutable generation.
    pub classification_authority_available: bool,
}

#[must_use]
pub fn status_result(observation: StatusObservation<'_>) -> ExactStatusResult {
    let graph_loaded = observation.graph.is_some();
    let load_failed = observation.load_error.is_some();
    let origin_mismatch = observation.origin_mismatch.is_some();
    let calls_gap_is_actionable = !observation.calls.satisfies_best_effort_provider_intent();
    let verdict = status_verdict_with_calls_actionability(
        observation.graph_exists,
        load_failed,
        origin_mismatch,
        observation.freshness,
        observation.calls.status,
        calls_gap_is_actionable,
    );
    let availability = if !observation.graph_exists {
        AvailabilityStatus::Unindexed
    } else if load_failed {
        AvailabilityStatus::LoadFailed
    } else if origin_mismatch {
        AvailabilityStatus::OriginMismatch
    } else {
        AvailabilityStatus::Available
    };
    let freshness = match verdict.freshness_label {
        "not-evaluated" => FreshnessStatus::NotEvaluated,
        "unknown" => FreshnessStatus::Unknown,
        "stale" => FreshnessStatus::Stale,
        "fresh" => FreshnessStatus::Fresh,
        _ => FreshnessStatus::Unknown,
    };
    let freshness_files_checked = match observation.freshness {
        StalenessVerdict::Unknown { files_checked, .. } => Some(files_checked),
        StalenessVerdict::Fresh | StalenessVerdict::Stale => None,
    };
    let reachability = observation.graph.map(compute_reachability_summary);
    let classification_currency = classification_currency_status(
        observation.graph_exists,
        graph_loaded,
        observation.freshness,
        observation.classification_authority_available,
        observation.classified_by,
    );
    let stats = observation.graph.map(|graph| {
        let stats = compute_graph_stats(graph);
        StatusGraphStats {
            node_count: stats.node_count,
            edge_count: stats.edge_count,
            edge_kinds: stats.edge_kinds.into_iter().collect(),
        }
    });
    let reachability = reachability.map(|summary| StatusReachability {
        wired: summary.wired,
        public_api: summary.public_api,
        structural: summary.structural,
        test_only: summary.test_only,
        dead: summary.dead,
        orphan: summary.orphan,
        unclassified: summary.unclassified,
        suspected: summary.suspected,
        excluded: summary.excluded,
    });
    let publication_state = if load_failed || origin_mismatch {
        PublicationState::Invalid
    } else if observation.generation_id.is_some() {
        PublicationState::Published
    } else {
        PublicationState::Unpublished
    };

    ExactStatusResult {
        schema_version: STATUS_SCHEMA_VERSION.into(),
        generation_id: observation.generation_id,
        repository_id: observation.repository_id,
        publication_state,
        graph_exists: observation.graph_exists,
        graph_loaded,
        root: observation.root.to_path_buf(),
        graph_directory: observation.graph_directory.to_path_buf(),
        root_source: observation.root_source.into(),
        graph_source: observation.graph_source.into(),
        availability,
        freshness,
        freshness_reason: verdict.freshness_reason.map(str::to_string),
        freshness_files_checked,
        indexed_at_unix_seconds: observation
            .indexed_at
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs()),
        action_needed: verdict.action_needed,
        recommendation: verdict.recommendation,
        capabilities: StatusCapabilities {
            calls: observation.calls,
            callable_liveness: observation.callable_liveness,
        },
        classified_by: observation
            .classified_by
            .map(ClassificationProvenance::from),
        classification_currency,
        stats,
        reachability,
        index_mode: observation.incremental_drift.then(|| "incremental".into()),
        authoritative_dead_requires: observation
            .incremental_drift
            .then(|| "publish a fresh immutable generation".into()),
        load_error: observation.load_error,
        origin_mismatch: observation.origin_mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_intel_domain::{
        CapabilityCoverageStatus, CapabilityEvidenceGap, CapabilityStatus,
        LanguageCapabilityCoverage, LanguageId,
    };

    #[test]
    fn unavailable_loose_source_language_is_informational_after_best_effort_indexing() {
        let graph = KnowledgeGraph::new();
        let result = status_result(StatusObservation {
            root: Path::new("repo"),
            graph_directory: Path::new("bundle"),
            root_source: "explicit",
            graph_source: "cli",
            generation_id: Some(GenerationId::new("generation")),
            repository_id: Some(RepositoryId::new("repository")),
            graph: Some(&graph),
            graph_exists: true,
            load_error: None,
            origin_mismatch: None,
            freshness: StalenessVerdict::Fresh,
            indexed_at: None,
            incremental_drift: false,
            calls: CapabilityCoverage {
                capability_id: "calls".into(),
                status: CapabilityCoverageStatus::Partial,
                languages: vec![
                    LanguageCapabilityCoverage {
                        language_id: LanguageId::new("rust"),
                        status: CapabilityCoverageStatus::Complete,
                        provider_id: None,
                        gaps: Vec::new(),
                        qualifications: Vec::new(),
                    },
                    LanguageCapabilityCoverage {
                        language_id: LanguageId::new("go"),
                        status: CapabilityCoverageStatus::Unavailable,
                        provider_id: None,
                        gaps: vec![CapabilityEvidenceGap {
                            provider_id: None,
                            status: CapabilityStatus::Unavailable,
                            reason_code: "provider_execution_root_unavailable".into(),
                            reason: "no go.mod or go.work owns the loose source".into(),
                        }],
                        qualifications: Vec::new(),
                    },
                ],
            },
            callable_liveness: CapabilityCoverage {
                capability_id: "callable_liveness".into(),
                status: CapabilityCoverageStatus::NotApplicable,
                languages: Vec::new(),
            },
            classified_by: None,
            classification_authority_available: false,
        });

        assert_eq!(result.freshness, FreshnessStatus::Fresh);
        assert_eq!(
            result.capabilities.calls.status,
            CapabilityCoverageStatus::Partial
        );
        assert!(
            !result.action_needed,
            "best-effort indexing already satisfied the only available project units"
        );
        assert!(
            result
                .recommendation
                .contains("reported per-language scope")
        );
        assert!(
            !result
                .recommendation
                .contains("run `h00ligan index --scip`")
        );
    }
}
