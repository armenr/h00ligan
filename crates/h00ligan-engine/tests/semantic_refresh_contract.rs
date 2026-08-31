use std::collections::BTreeSet;

use h00ligan_engine::code_intel_domain::LanguageId;
use h00ligan_engine::code_intel_semantic_refresh::{
    AffectedCandidateEvidence, FullCertificationReason, SemanticDocumentChange,
    SemanticDocumentVersion, SemanticRefreshInput, SemanticRefreshPlan, SemanticTargetDivergence,
    plan_semantic_refresh, validate_affected_candidate,
};

fn version(path: &str, content: &str, surface: Option<&str>) -> SemanticDocumentVersion {
    SemanticDocumentVersion {
        document_path: path.into(),
        language_id: LanguageId::new("rust"),
        content_identity: content.into(),
        cross_document_surface_identity: surface.map(str::to_owned),
    }
}

fn exact_input(changes: Vec<SemanticDocumentChange>) -> SemanticRefreshInput {
    SemanticRefreshInput {
        exact_prior_authority: true,
        provider_identity_unchanged: true,
        provider_configuration_unchanged: true,
        affected_document_languages: BTreeSet::from([LanguageId::new("rust")]),
        changes,
    }
}

#[test]
fn body_only_edits_coalesce_without_weakening_full_certification_triggers() {
    let safe_changes = (0..100)
        .map(|index| SemanticDocumentChange::Modified {
            before: version(
                &format!("src/module_{index}.rs"),
                &format!("content-before-{index}"),
                Some(&format!("surface-{index}")),
            ),
            after: version(
                &format!("src/module_{index}.rs"),
                &format!("content-after-{index}"),
                Some(&format!("surface-{index}")),
            ),
        })
        .collect::<Vec<_>>();

    let plan = plan_semantic_refresh(&exact_input(safe_changes));
    let SemanticRefreshPlan::AffectedDocuments { documents } = plan else {
        panic!("body-local edits must use the bounded affected-document lane: {plan:?}");
    };
    assert_eq!(
        documents.len(),
        100,
        "every changed document remains covered"
    );

    let unsafe_plan = plan_semantic_refresh(&exact_input(vec![
        SemanticDocumentChange::Modified {
            before: version("src/lib.rs", "before", Some("old-surface")),
            after: version("src/lib.rs", "after", Some("new-surface")),
        },
        SemanticDocumentChange::Modified {
            before: version("src/body.rs", "before", Some("same-surface")),
            after: version("src/body.rs", "after", Some("same-surface")),
        },
    ]));
    assert!(matches!(
        unsafe_plan,
        SemanticRefreshPlan::FullCertification { ref reasons }
            if reasons.contains(&FullCertificationReason::CrossDocumentSurfaceChanged {
                document_path: "src/lib.rs".into(),
            })
    ));
}

#[test]
fn affected_candidate_fails_closed_on_target_drift() {
    let plan = plan_semantic_refresh(&exact_input(vec![SemanticDocumentChange::Modified {
        before: version("src/lib.rs", "before", Some("surface")),
        after: version("src/lib.rs", "after", Some("surface")),
    }]));
    let validated = validate_affected_candidate(
        plan,
        &AffectedCandidateEvidence {
            exact_source_epoch: true,
            exact_provider_identity: true,
            provider_healthy: true,
            covered_documents: BTreeSet::from(["src/lib.rs".into()]),
            target_divergences: vec![SemanticTargetDivergence {
                document_path: "src/lib.rs".into(),
                call_site_identity: "42:51".into(),
            }],
        },
    );
    assert!(matches!(
        validated,
        SemanticRefreshPlan::FullCertification { ref reasons }
            if reasons.contains(&FullCertificationReason::CandidateTargetDiverged {
                document_path: "src/lib.rs".into(),
                call_site_identity: "42:51".into(),
            })
    ));
}

#[test]
fn missing_authority_population_changes_and_uncertainty_require_full_certification() {
    let mut no_prior = exact_input(Vec::new());
    no_prior.exact_prior_authority = false;
    assert_full_reason(
        plan_semantic_refresh(&no_prior),
        FullCertificationReason::MissingPriorAuthority,
    );

    assert_full_reason(
        plan_semantic_refresh(&exact_input(vec![SemanticDocumentChange::Added {
            current: version("src/new.rs", "new", Some("surface")),
        }])),
        FullCertificationReason::DocumentAdded {
            document_path: "src/new.rs".into(),
        },
    );
    assert_full_reason(
        plan_semantic_refresh(&exact_input(vec![SemanticDocumentChange::Deleted {
            previous: version("src/old.rs", "old", Some("surface")),
        }])),
        FullCertificationReason::DocumentDeleted {
            document_path: "src/old.rs".into(),
        },
    );
    assert_full_reason(
        plan_semantic_refresh(&exact_input(vec![
            SemanticDocumentChange::ProjectInputChanged {
                path: "Cargo.toml".into(),
            },
        ])),
        FullCertificationReason::ProjectInputChanged {
            path: "Cargo.toml".into(),
        },
    );

    assert_full_reason(
        plan_semantic_refresh(&exact_input(vec![SemanticDocumentChange::Uncertain {
            path: Some("src/broken.rs".into()),
            reason: "syntax_incomplete".into(),
        }])),
        FullCertificationReason::UncertainChange {
            path: Some("src/broken.rs".into()),
            reason: "syntax_incomplete".into(),
        },
    );
}

fn assert_full_reason(plan: SemanticRefreshPlan, expected: FullCertificationReason) {
    let SemanticRefreshPlan::FullCertification { reasons } = plan else {
        panic!("expected full certification, found {plan:?}");
    };
    assert!(
        reasons.contains(&expected),
        "missing reason {expected:?}: {reasons:?}"
    );
}
