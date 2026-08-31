//! Real filesystem-boundary regressions for prepared immutable index writes.

#![cfg(all(feature = "code-intel", unix))]

use std::os::unix::fs::symlink;

use h00ligan_engine::code_intel_indexing::{BoundIndexPlan, BoundIndexRequest};
use h00ligan_engine::project_binding::ProjectBinding;
use tempfile::TempDir;

#[tokio::test]
async fn prepared_plan_refuses_graph_directory_replacement_without_touching_the_target() {
    let temporary = TempDir::new().expect("temporary workspace");
    let root = temporary.path().join("repo");
    let graph = temporary.path().join("graph");
    let original_graph = temporary.path().join("prepared-graph");
    let redirect_target = temporary.path().join("redirect-target");
    std::fs::create_dir(&root).expect("project root");
    std::fs::write(root.join("README.md"), "path-authority fixture\n")
        .expect("non-provider fixture file");
    std::fs::create_dir(&redirect_target).expect("redirect target");

    let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
    let plan = BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
        .expect("prepare bound index plan");
    assert!(
        graph.is_dir(),
        "prepare must create the selected graph directory"
    );

    std::fs::rename(&graph, &original_graph).expect("move prepared graph directory");
    symlink(&redirect_target, &graph).expect("substitute graph path with symlink");
    assert_eq!(
        std::fs::canonicalize(&graph).expect("resolve substitution"),
        std::fs::canonicalize(&redirect_target).expect("resolve target"),
        "known-positive control: the lexical graph path now resolves to the redirect target"
    );
    assert_eq!(
        std::fs::read_dir(&redirect_target)
            .expect("read empty target")
            .count(),
        0,
        "redirect target must start empty"
    );

    let error = plan
        .publish()
        .await
        .expect_err("a prepared writer must not follow a replaced graph path");
    assert!(
        error
            .to_string()
            .contains("graph directory changed after indexing was prepared"),
        "refusal must identify the lost path authority: {error}"
    );
    assert_eq!(
        std::fs::read_dir(&redirect_target)
            .expect("read redirect target after refusal")
            .count(),
        0,
        "refusal must occur before the substituted target is touched"
    );
    assert!(
        original_graph.is_dir(),
        "the directory admitted during preparation must remain intact"
    );
}
