//! Shared code-intelligence availability and freshness verdict.
//!
//! [`status_verdict`] is the SINGLE source of the `status` health verdict, shared
//! by the CLI `run_status` (`h00ligan`) and the MCP `StatusHandler`
//! (`h00ligan-interface`) so the projection is parity-by-construction. Availability,
//! source freshness, and capability coverage are independent axes: a missing
//! Calls provider may degrade capability health, but it must never relabel
//! content-verified source freshness.

use serde::Serialize;

use crate::code_intel_domain::CapabilityCoverageStatus;
use crate::graph_stats::{MAX_STALENESS_FILES, StalenessReason, StalenessVerdict};
use crate::graph_store::{ClassifiedBy, CurrencyInputs, evaluate_classification_currency};

/// Stable status projection of the persisted reachability-classification stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassificationProvenance {
    pub build_identity: String,
    pub indexer_identity: String,
    pub prover_config: String,
    pub timestamp: String,
    pub build_provenance_approximate: bool,
}

impl From<&ClassifiedBy> for ClassificationProvenance {
    fn from(stamp: &ClassifiedBy) -> Self {
        Self {
            build_identity: stamp.build_identity.clone(),
            indexer_identity: stamp.indexer_identity.clone(),
            prover_config: stamp.prover_config.clone(),
            timestamp: stamp.timestamp.clone(),
            build_provenance_approximate: stamp.approximation().is_some(),
        }
    }
}

/// Machine-readable result of evaluating classification provenance.
///
/// `current` is `None` when no graph loaded, so an unevaluated store cannot be
/// mistaken for a clean one. The same value is serialized by CLI and MCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassificationCurrencyStatus {
    pub current: Option<bool>,
    pub not_evaluated_reason: Option<&'static str>,
    pub failures: Vec<String>,
}

/// Evaluate reachability-classification provenance from one coherent snapshot.
#[must_use]
pub fn classification_currency_status(
    graph_exists: bool,
    graph_loaded: bool,
    staleness: StalenessVerdict,
    classification_authority_available: bool,
    stamp: Option<&ClassifiedBy>,
) -> ClassificationCurrencyStatus {
    if !graph_exists {
        return ClassificationCurrencyStatus {
            current: None,
            not_evaluated_reason: Some("no graph in this data dir"),
            failures: Vec::new(),
        };
    }
    if !graph_loaded {
        return ClassificationCurrencyStatus {
            current: None,
            not_evaluated_reason: Some("graph present but did not load"),
            failures: Vec::new(),
        };
    }

    let index_stale = match staleness {
        StalenessVerdict::Fresh => Some(false),
        StalenessVerdict::Stale => Some(true),
        StalenessVerdict::Unknown { .. } => None,
    };
    let current = ClassifiedBy::now();
    let failures = evaluate_classification_currency(CurrencyInputs {
        stamp,
        current: &current,
        classification_authority_available,
        index_stale,
    })
    .iter()
    .map(crate::graph_store::CurrencyFailure::describe)
    .collect::<Vec<_>>();
    ClassificationCurrencyStatus {
        current: Some(failures.is_empty()),
        not_evaluated_reason: None,
        failures,
    }
}

/// Shared status projection. Availability, freshness, and capability coverage
/// remain distinct even though `action_needed` and `recommendation` summarize
/// whether any axis needs attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusVerdict {
    /// Machine label: `unindexed` | `load-failed` | `origin-mismatch` |
    /// `available`.
    pub availability_label: &'static str,
    /// Machine label: `not-evaluated` | `unknown` | `stale` | `fresh`.
    pub freshness_label: &'static str,
    /// Whether any measured axis needs attention.
    pub action_needed: bool,
    /// Human-readable remediation. `String` (not `&'static str`) because the
    /// truncation path carries the dynamic "scanned N files" disclosure.
    pub recommendation: String,
    /// Machine-readable reason for a fail-closed freshness verdict; `None`
    /// otherwise. This distinguishes a bounded scan, missing source snapshot,
    /// incomplete indexed population, and verification I/O failure.
    pub freshness_reason: Option<&'static str>,
}

/// Compute status from already-probed inputs. PURE — by-construction parity
/// across the CLI + MCP surfaces.
///
/// - `graph_exists` — an immutable generation was resolved for this project.
/// - `load_failed` — present but the snapshot did not load (corrupt / stale
///   schema / unreadable).
/// - `origin_mismatch` — a loadable store stamped with a different workspace
///   origin (ADR-0033 ROOT-8; observational — report, never refuse here).
/// - `freshness` — exact source/project-input byte verdict.
/// - `calls_status` — independently reported Calls capability coverage.
#[must_use]
pub fn status_verdict(
    graph_exists: bool,
    load_failed: bool,
    origin_mismatch: bool,
    freshness: StalenessVerdict,
    calls_status: CapabilityCoverageStatus,
) -> StatusVerdict {
    status_verdict_with_calls_actionability(
        graph_exists,
        load_failed,
        origin_mismatch,
        freshness,
        calls_status,
        true,
    )
}

/// Compute status while preserving the distinction between a capability gap
/// an operator can repair and an informational gap that already satisfies a
/// best-effort provider request.
#[must_use]
pub fn status_verdict_with_calls_actionability(
    graph_exists: bool,
    load_failed: bool,
    origin_mismatch: bool,
    freshness: StalenessVerdict,
    calls_status: CapabilityCoverageStatus,
    calls_gap_is_actionable: bool,
) -> StatusVerdict {
    let calls_have_gap = matches!(
        calls_status,
        CapabilityCoverageStatus::Qualified
            | CapabilityCoverageStatus::Partial
            | CapabilityCoverageStatus::Unavailable
    );
    let calls_need_action = calls_have_gap && calls_gap_is_actionable;
    let (freshness_unknown_reason, freshness_files, stale) = match freshness {
        StalenessVerdict::Unknown {
            reason,
            files_checked,
        } => (Some(reason), files_checked, false),
        StalenessVerdict::Stale => (None, 0, true),
        StalenessVerdict::Fresh => (None, 0, false),
    };

    if !graph_exists {
        return action_verdict(
            "unindexed",
            "not-evaluated",
            "Run `h00ligan index` to publish the first generation.".to_string(),
            None,
        );
    }
    if load_failed {
        return action_verdict(
            "load-failed",
            "not-evaluated",
            "The publication is invalid and strict indexing will refuse it. Run `h00ligan index \
             --recover-publication`, or call MCP `reindex` with \
             `recover_publication=true`, to authorize a complete fresh replacement."
                .to_string(),
            None,
        );
    }
    if origin_mismatch {
        return action_verdict(
            "origin-mismatch",
            "not-evaluated",
            "The publication belongs to a different workspace. Verify the bound root, then run \
             `h00ligan index --recover-publication`, or call MCP `reindex` with \
             `recover_publication=true`, only if this data directory should be rebound to the \
             current workspace."
                .to_string(),
            None,
        );
    }

    if let Some(reason) = freshness_unknown_reason {
        let recommendation = match reason {
            StalenessReason::Truncated => format!(
                "Freshness verification is bounded to {MAX_STALENESS_FILES} files and stopped at \
                 {freshness_files}; this repository exceeds that bound, so this build cannot assert \
                 freshness."
            ),
            StalenessReason::NoSourceFound => {
                "No source files found to verify freshness — run `h00ligan index` (check the \
                 workspace root)."
                    .to_string()
            }
            StalenessReason::IndexedSourceSnapshotUnavailable => {
                "The published generation has no readable indexed-source snapshot — run \
                 `h00ligan index` to publish content-verifiable authority."
                    .to_string()
            }
            StalenessReason::SourceVerificationFailed => {
                "Source discovery or content hashing failed — freshness is unknown; resolve the \
                 filesystem error and retry `h00ligan status`."
                    .to_string()
            }
            StalenessReason::ProviderSemanticInputsUnverifiable => {
                "A semantic provider could not publish a fully reproducible non-source input \
                 population — freshness is unknown; add explicit build-input declarations or \
                 run provider-backed indexing again."
                    .to_string()
            }
        };
        return action_verdict(
            "available",
            "unknown",
            append_calls_guidance(recommendation, calls_status),
            Some(reason_str(reason)),
        );
    }
    if stale {
        let recommendation = calls_gap_label(calls_status).map_or_else(
            || "Run `h00ligan index` to refresh the stale generation.".to_string(),
            |calls_gap| {
                format!(
                    "Source inputs are stale and Calls coverage is {calls_gap}; run `h00ligan index --scip` once to refresh both source and available provider evidence, then inspect the reported per-language scope. Use `--require-complete-calls` when incomplete Calls must refuse publication."
                )
            },
        );
        return action_verdict("available", "stale", recommendation, None);
    }
    if calls_need_action {
        return action_verdict(
            "available",
            "fresh",
            append_calls_guidance("Source inputs are fresh.".to_string(), calls_status),
            None,
        );
    }
    if calls_have_gap {
        return StatusVerdict {
            availability_label: "available",
            freshness_label: "fresh",
            action_needed: false,
            recommendation: informational_calls_guidance(calls_status),
            freshness_reason: None,
        };
    }
    StatusVerdict {
        availability_label: "available",
        freshness_label: "fresh",
        action_needed: false,
        recommendation: "Source inputs are fresh and measured capabilities are ready.".to_string(),
        freshness_reason: None,
    }
}

fn informational_calls_guidance(calls_status: CapabilityCoverageStatus) -> String {
    if calls_status == CapabilityCoverageStatus::Qualified {
        return "Source inputs are fresh. Calls authority is qualified: provider results are exact within covered source, while the reported source regions remain explicitly excluded. Inspect those qualifications before relying on negative results.".into();
    }
    let calls_gap = calls_gap_label(calls_status).unwrap_or("limited");
    format!(
        "Source inputs are fresh. Calls coverage is {calls_gap}; the reported per-language scope includes source without a provider execution root, and this best-effort generation already covers every available project unit."
    )
}

fn append_calls_guidance(
    mut recommendation: String,
    calls_status: CapabilityCoverageStatus,
) -> String {
    if let Some(calls_gap) = calls_gap_label(calls_status) {
        recommendation.push(' ');
        recommendation.push_str(&format!(
            "Calls coverage is {calls_gap}; inspect the reported per-language scope before changing provider or project configuration. Use `h00ligan index --scip --require-complete-calls` when incomplete Calls must refuse publication."
        ));
    }
    recommendation
}

const fn calls_gap_label(calls_status: CapabilityCoverageStatus) -> Option<&'static str> {
    match calls_status {
        CapabilityCoverageStatus::Partial => Some("partial"),
        CapabilityCoverageStatus::Qualified => Some("qualified"),
        CapabilityCoverageStatus::Unavailable => Some("unavailable"),
        CapabilityCoverageStatus::NotApplicable | CapabilityCoverageStatus::Complete => None,
    }
}

/// Build an action-needed verdict without coupling its independent axes.
const fn action_verdict(
    availability_label: &'static str,
    freshness_label: &'static str,
    recommendation: String,
    freshness_reason: Option<&'static str>,
) -> StatusVerdict {
    StatusVerdict {
        availability_label,
        freshness_label,
        action_needed: true,
        recommendation,
        freshness_reason,
    }
}

/// Machine-readable label for a [`StalenessReason`] (the JSON `freshness_reason`).
const fn reason_str(reason: StalenessReason) -> &'static str {
    match reason {
        StalenessReason::Truncated => "truncated",
        StalenessReason::NoSourceFound => "no_source",
        StalenessReason::IndexedSourceSnapshotUnavailable => "indexed_source_snapshot_unavailable",
        StalenessReason::SourceVerificationFailed => "source_verification_failed",
        StalenessReason::ProviderSemanticInputsUnverifiable => {
            "provider_semantic_inputs_unverifiable"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRESH: StalenessVerdict = StalenessVerdict::Fresh;
    const STALE: StalenessVerdict = StalenessVerdict::Stale;
    const TRUNCATED: StalenessVerdict = StalenessVerdict::Unknown {
        reason: StalenessReason::Truncated,
        files_checked: 50_000,
    };

    /// A content-verified generation with complete Calls coverage is available,
    /// fresh, and needs no action.
    #[test]
    fn fresh_complete_stays_ready_no_cry_wolf() {
        let v = status_verdict(
            true,
            false,
            false,
            FRESH,
            CapabilityCoverageStatus::Complete,
        );
        assert_eq!(v.availability_label, "available");
        assert_eq!(v.freshness_label, "fresh");
        assert!(!v.action_needed);
        assert_eq!(v.freshness_reason, None);
    }

    /// No callable functions means Calls is not applicable, not degraded.
    #[test]
    fn fresh_not_applicable_stays_fresh() {
        let v = status_verdict(
            true,
            false,
            false,
            FRESH,
            CapabilityCoverageStatus::NotApplicable,
        );
        assert_eq!(v.availability_label, "available");
        assert_eq!(v.freshness_label, "fresh");
        assert!(!v.action_needed);
    }

    /// Load failure prevents both query availability and freshness evaluation.
    #[test]
    fn load_failed_outranks_everything_below() {
        let v = status_verdict(
            true,
            true,
            true,
            TRUNCATED,
            CapabilityCoverageStatus::Unavailable,
        );
        assert_eq!(v.availability_label, "load-failed");
        assert_eq!(v.freshness_label, "not-evaluated");
        assert!(v.action_needed);
        assert!(v.recommendation.contains("strict indexing will refuse"));
        assert!(v.recommendation.contains("--recover-publication"));
        assert!(v.recommendation.contains("recover_publication=true"));
    }

    /// A foreign publication is not query authority for the bound root.
    #[test]
    fn origin_mismatch_prevents_freshness_evaluation() {
        let v = status_verdict(
            true,
            false,
            true,
            TRUNCATED,
            CapabilityCoverageStatus::Unavailable,
        );
        assert_eq!(v.availability_label, "origin-mismatch");
        assert_eq!(v.freshness_label, "not-evaluated");
        assert!(v.action_needed);
        assert!(v.recommendation.contains("different workspace"));
        assert!(v.recommendation.contains("--recover-publication"));
        assert!(v.recommendation.contains("recover_publication=true"));
    }

    /// An absent publication is unindexed, not a freshness result.
    #[test]
    fn unindexed_when_graph_absent() {
        let v = status_verdict(
            false,
            false,
            false,
            FRESH,
            CapabilityCoverageStatus::Complete,
        );
        assert_eq!(v.availability_label, "unindexed");
        assert_eq!(v.freshness_label, "not-evaluated");
        assert!(v.action_needed);
    }

    /// Bounded verification fails closed without revoking a loaded generation.
    #[test]
    fn freshness_unknown_truncated_needs_action() {
        let v = status_verdict(
            true,
            false,
            false,
            TRUNCATED,
            CapabilityCoverageStatus::Complete,
        );
        assert_eq!(v.availability_label, "available");
        assert_eq!(v.freshness_label, "unknown");
        assert!(v.action_needed);
        assert_eq!(v.freshness_reason, Some("truncated"));
        assert!(v.recommendation.contains("50000"));
        assert!(!v.recommendation.contains("h00ligan index"));
    }

    /// Calls capability health remains separate from exact source freshness.
    #[test]
    fn calls_unavailable_needs_action() {
        let v = status_verdict(
            true,
            false,
            false,
            FRESH,
            CapabilityCoverageStatus::Unavailable,
        );
        assert_eq!(v.availability_label, "available");
        assert_eq!(v.freshness_label, "fresh");
        assert!(v.action_needed);
        assert!(v.recommendation.contains("Calls coverage is unavailable"));
    }

    #[test]
    fn calls_gap_does_not_relabel_verified_source_freshness() {
        let v = status_verdict(true, false, false, FRESH, CapabilityCoverageStatus::Partial);
        assert_eq!(
            v.freshness_label, "fresh",
            "Calls capability health is independent from exact source freshness"
        );
        assert!(
            v.action_needed,
            "the independent capability gap can still require action"
        );
    }

    /// Simultaneous unknown freshness and missing Calls authority report both
    /// without recommending a removed legacy flag.
    #[test]
    fn simultaneous_unknown_freshness_and_calls_gap_joint_remediation() {
        let v = status_verdict(
            true,
            false,
            false,
            TRUNCATED,
            CapabilityCoverageStatus::Unavailable,
        );
        assert_eq!(v.freshness_label, "unknown");
        assert!(v.action_needed);
        assert!(!v.recommendation.contains("install rust-analyzer"));
        assert!(!v.recommendation.contains("--full"));
        assert!(v.recommendation.contains("reported per-language scope"));
        assert!(v.recommendation.contains("--require-complete-calls"));
        assert_eq!(v.freshness_reason, Some("truncated"));
    }

    /// A stale generation stays available for immutable queries but needs refresh.
    #[test]
    fn stale_reports_stale() {
        let v = status_verdict(
            true,
            false,
            false,
            STALE,
            CapabilityCoverageStatus::Complete,
        );
        assert_eq!(v.availability_label, "available");
        assert_eq!(v.freshness_label, "stale");
        assert!(v.action_needed);
        assert!(v.recommendation.contains("refresh"));
    }

    /// One semantic refresh can repair both stale sources and Calls coverage;
    /// status must not prescribe two sequential indexing passes.
    #[test]
    fn stale_with_calls_gap_recommends_one_combined_refresh() {
        let v = status_verdict(true, false, false, STALE, CapabilityCoverageStatus::Partial);
        assert_eq!(v.freshness_label, "stale");
        assert!(v.recommendation.contains("refresh both"));
        assert!(v.recommendation.contains("reported per-language scope"));
        assert!(v.recommendation.contains("--require-complete-calls"));
        assert_eq!(v.recommendation.matches("h00ligan index").count(), 1);
    }

    /// Improving capability coverage removes its action without changing freshness.
    #[test]
    fn capability_improvement_does_not_change_freshness() {
        let partial = status_verdict(true, false, false, FRESH, CapabilityCoverageStatus::Partial);
        let complete = status_verdict(
            true,
            false,
            false,
            FRESH,
            CapabilityCoverageStatus::Complete,
        );
        assert_eq!(partial.freshness_label, "fresh");
        assert!(partial.action_needed);
        assert_eq!(complete.freshness_label, "fresh");
        assert!(!complete.action_needed);
    }

    #[test]
    fn classification_currency_distinguishes_unindexed_from_unloaded() {
        let unindexed = classification_currency_status(false, false, FRESH, false, None);
        assert_eq!(unindexed.current, None);
        assert_eq!(
            unindexed.not_evaluated_reason,
            Some("no graph in this data dir")
        );
        assert!(unindexed.failures.is_empty());

        let unloaded = classification_currency_status(true, false, FRESH, false, None);
        assert_eq!(unloaded.current, None);
        assert_eq!(
            unloaded.not_evaluated_reason,
            Some("graph present but did not load")
        );
        assert!(unloaded.failures.is_empty());
    }

    #[test]
    fn loaded_unstamped_classification_is_evaluated_and_not_current() {
        let status = classification_currency_status(true, true, FRESH, true, None);
        assert_eq!(status.current, Some(false));
        assert_eq!(status.not_evaluated_reason, None);
        assert!(
            status
                .failures
                .iter()
                .any(|failure| failure.contains("provenance stamp ABSENT"))
        );
    }

    #[test]
    fn classification_provenance_is_a_lossless_status_projection() {
        let stamp = ClassifiedBy {
            build_identity: "0.1.0+h00ligan-test+dirty".into(),
            indexer_identity: format!("sha256:{}", "a".repeat(64)),
            prover_config: "code-intel=1".into(),
            timestamp: "2026-08-16T00:00:00Z".into(),
        };
        let projected = ClassificationProvenance::from(&stamp);
        assert_eq!(projected.build_identity, stamp.build_identity);
        assert_eq!(projected.indexer_identity, stamp.indexer_identity);
        assert_eq!(projected.prover_config, stamp.prover_config);
        assert_eq!(projected.timestamp, stamp.timestamp);
        assert!(projected.build_provenance_approximate);
    }
}
