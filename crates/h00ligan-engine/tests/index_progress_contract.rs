//! Production-boundary indexing progress and timing contracts.

#![cfg(feature = "code-intel")]

use h00ligan_engine::code_intel_indexing::{BoundIndexPlan, BoundIndexRequest};
use h00ligan_engine::index_pipeline::IndexTimingAggregation;
use h00ligan_engine::project_binding::ProjectBinding;
use tempfile::TempDir;

#[tokio::test]
async fn fresh_generation_accounts_for_private_candidate_preparation() {
    let temporary = TempDir::new().expect("temporary workspace");
    let root = temporary.path().join("repo");
    let graph = temporary.path().join("graph");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"progress-contract\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("source fixture");

    let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
    let plan = BoundIndexPlan::prepare(
        &binding,
        BoundIndexRequest {
            profile: true,
            progress: Some(progress_tx),
            ..BoundIndexRequest::default()
        },
    )
    .expect("prepare index plan");
    let published = plan.publish().await.expect("publish generation");
    let mut progress = Vec::new();
    while let Ok(event) = progress_rx.try_recv() {
        progress.push(event);
    }

    assert!(
        progress
            .iter()
            .any(|event| event.label == "preparing private generation"),
        "candidate acquisition, reusable-fact import, and private database setup must not disappear into unaccounted latency"
    );
    assert!(
        published
            .telemetry
            .phase_timings
            .iter()
            .any(|timing| timing.label == "preparing private generation"),
        "the terminal receipt must retain the preparation duration"
    );

    let detailed = published
        .telemetry
        .phase_timings
        .iter()
        .filter(|timing| timing.label.starts_with("profile: "))
        .collect::<Vec<_>>();
    for expected in [
        "profile: prepare / acquire publication authority",
        "profile: prepare / assemble incremental basis",
        "profile: graph build / source occurrence identities",
        "profile: reachability",
    ] {
        assert!(
            detailed.iter().any(|timing| {
                timing.label == expected
                    && timing.duration.as_nanos() > 0
                    && timing.aggregation == IndexTimingAggregation::ConcurrentSpan
            }),
            "profiled production indexing must retain nested machine timing {expected}; population: {detailed:?}"
        );
    }
    assert!(
        detailed.len() > 4,
        "non-vacuity: profiling must expose a populated internal timing census"
    );

    // Non-vacuity: this is the complete shipped publication path, not a
    // synthetic event emitter that can satisfy only the new assertion.
    for expected in [
        "structural scan",
        "finalizing generation",
        "publishing generation",
    ] {
        assert!(
            published
                .telemetry
                .phase_timings
                .iter()
                .any(|timing| timing.label == expected),
            "missing positive-control phase {expected}"
        );
    }

    let publication_labels = published
        .publication_timings
        .iter()
        .map(|timing| timing.label)
        .collect::<Vec<_>>();
    assert_eq!(
        publication_labels,
        [
            "candidate graph validation",
            "candidate receipt validation",
            "candidate inventory validation",
            "candidate payload receipt-scope validation",
            "candidate payload normalization",
            "candidate payload serialization",
            "candidate payload descriptor binding",
            "candidate payload inventory coverage validation",
            "candidate payload descriptor linkage validation",
            "candidate payload structural join validation",
            "candidate payload result materialization",
            "current authority validation",
            "authority table writes",
            "candidate close and sync",
            "candidate payload digest",
            "manifest seal and sync",
            "sealed database digest",
            "immutable generation promotion",
            "head commit",
            "bounded generation cleanup",
        ],
        "the opaque publication phase must retain one ordered, non-overlapping timing population"
    );
    assert!(
        published
            .publication_timings
            .iter()
            .find(|timing| timing.label == "candidate payload digest")
            .is_some_and(|timing| timing.work_items > 0 && timing.work_unit == "database bytes"),
        "positive control: publication timing must carry the hashed database population"
    );
    let detailed_duration = published
        .publication_timings
        .iter()
        .map(|timing| timing.duration)
        .sum::<std::time::Duration>();
    let publish_duration = published
        .telemetry
        .phase_timings
        .iter()
        .find(|timing| timing.label == "publishing generation")
        .expect("coarse publication duration")
        .duration;
    assert!(
        detailed_duration <= publish_duration,
        "nested publication timings must not double-count the coarse phase"
    );
}

#[tokio::test]
async fn reusable_basis_is_not_persisted_twice_before_publication() {
    let temporary = TempDir::new().expect("temporary workspace");
    let root = temporary.path().join("repo");
    let graph = temporary.path().join("graph");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"basis-transfer-contract\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("src/main.rs"),
        "fn main() { helper(); }\nfn helper() {}\n",
    )
    .expect("source fixture");

    let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
    BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
        .expect("prepare initial index")
        .publish()
        .await
        .expect("publish initial generation");

    let refreshed = BoundIndexPlan::prepare(
        &binding,
        BoundIndexRequest {
            force: true,
            ..BoundIndexRequest::default()
        },
    )
    .expect("prepare forced generation")
    .publish()
    .await
    .expect("publish forced generation");

    assert!(
        refreshed.telemetry.reusable_file_records > 0
            && refreshed.telemetry.reusable_document_fact_sets > 0,
        "positive control: the second generation must actually admit a reusable basis"
    );
    assert_eq!(
        refreshed.telemetry.preindex_basis_rows_persisted, 0,
        "validated reusable facts must flow directly into indexing instead of being serialized into the candidate, read back, and serialized again"
    );
}

#[tokio::test]
async fn deletion_progress_reports_delta_and_candidate_totals_without_conflating_them() {
    let temporary = TempDir::new().expect("temporary workspace");
    let root = temporary.path().join("repo");
    let graph = temporary.path().join("graph");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"deletion-progress-contract\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("manifest");
    std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("retained source");
    let removed_path = root.join("src/removed.rs");
    std::fs::write(&removed_path, "pub fn removed_symbol() {}\n").expect("removable source");

    let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
    BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
        .expect("prepare initial index")
        .publish()
        .await
        .expect("publish initial generation");
    std::fs::remove_file(&removed_path).expect("remove source fixture");

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
    let published = BoundIndexPlan::prepare(
        &binding,
        BoundIndexRequest {
            progress: Some(progress_tx),
            ..BoundIndexRequest::default()
        },
    )
    .expect("prepare deletion generation")
    .publish()
    .await
    .expect("publish deletion generation");
    let mut progress = Vec::new();
    while let Ok(event) = progress_rx.try_recv() {
        progress.push(event);
    }
    let detail = &progress
        .iter()
        .rev()
        .find(|event| event.label == "structural scan")
        .expect("completed structural progress")
        .detail;

    assert_eq!(
        published.telemetry.files_changed, 0,
        "deletion-only control"
    );
    assert_eq!(
        published.telemetry.files_deleted, 1,
        "deletion event control"
    );
    assert!(
        published.telemetry.nodes_total > 0,
        "positive control: the retained main symbol keeps the candidate non-empty"
    );
    assert!(
        detail.contains("1 deleted"),
        "deletion delta missing: {detail}"
    );
    assert!(
        detail.contains(&format!("{} nodes", published.telemetry.nodes_total)),
        "candidate node total missing: {detail}"
    );
    assert!(
        detail.contains(&format!("{} edges", published.telemetry.edges_total)),
        "candidate edge total missing: {detail}"
    );
}
