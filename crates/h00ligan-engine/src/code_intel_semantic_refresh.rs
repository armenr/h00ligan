//! Conservative planning for incremental semantic-provider refreshes.
//!
//! Filesystem events are only hints. The planner consumes exact source and
//! provider identities from an authoritative reconciliation and admits the
//! affected-document lane only when a language-specific cross-document
//! surface is unchanged. Anything uncertain falls back to full certification.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use tree_sitter::Node;

use crate::{code_intel_domain::LanguageId, language::LanguageExtractor};

const SEMANTIC_SURFACE_SCHEMA: &[u8] = b"h00/code-intel/cross-document-surface/v2\0";

/// One exact version of a source document at the semantic refresh boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticDocumentVersion {
    pub document_path: String,
    pub language_id: LanguageId,
    /// Exact full-content identity. The digest algorithm is selected by the
    /// source-authority layer and is opaque to this planner.
    pub content_identity: String,
    /// Language-specific identity of syntax that can affect other documents.
    /// Absence is uncertainty and therefore cannot enter the fast lane.
    pub cross_document_surface_identity: Option<String>,
}

/// One authoritative source-population change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticDocumentChange {
    Modified {
        before: SemanticDocumentVersion,
        after: SemanticDocumentVersion,
    },
    Added {
        current: SemanticDocumentVersion,
    },
    Deleted {
        previous: SemanticDocumentVersion,
    },
    /// Manifests, lockfiles, toolchains, build scripts, workspace topology,
    /// provider configuration, and equivalent non-source semantic inputs.
    ProjectInputChanged {
        path: String,
    },
    /// A watcher overflow, unreadable path, parse failure, unsupported event,
    /// or any other change whose exact semantic extent is not proven.
    Uncertain {
        path: Option<String>,
        reason: String,
    },
}

/// Exact evidence used to choose a semantic refresh lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticRefreshInput {
    pub exact_prior_authority: bool,
    pub provider_identity_unchanged: bool,
    pub provider_configuration_unchanged: bool,
    /// Languages whose affected-document implementation has independently
    /// passed parity and health gates. Fingerprint support alone does not admit
    /// a language here.
    pub affected_document_languages: BTreeSet<LanguageId>,
    pub changes: Vec<SemanticDocumentChange>,
}

/// Why an exact full-provider certification is mandatory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FullCertificationReason {
    MissingPriorAuthority,
    ProviderIdentityChanged,
    ProviderConfigurationChanged,
    InconsistentDocumentIdentity {
        document_path: String,
    },
    LanguageNotAdmitted {
        document_path: String,
        language_id: LanguageId,
    },
    MissingSurfaceIdentity {
        document_path: String,
    },
    CrossDocumentSurfaceChanged {
        document_path: String,
    },
    DocumentAdded {
        document_path: String,
    },
    DocumentDeleted {
        document_path: String,
    },
    ProjectInputChanged {
        path: String,
    },
    UncertainChange {
        path: Option<String>,
        reason: String,
    },
    CandidateSourceEpochMismatch,
    CandidateProviderIdentityMismatch,
    CandidateProviderUnhealthy,
    CandidateCoverageMissing {
        document_path: String,
    },
    CandidateCoverageUnexpected {
        document_path: String,
    },
    CandidateTargetDiverged {
        document_path: String,
        call_site_identity: String,
    },
}

/// Deterministic semantic work selected for one reconciled source epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticRefreshPlan {
    /// Source, provider, and configuration identities are unchanged.
    ReuseExactPrior,
    /// Recompute these exact documents, then pass the candidate validation
    /// boundary before publication can retain Complete authority.
    AffectedDocuments { documents: BTreeSet<String> },
    /// Run the provider's complete certification path.
    FullCertification {
        reasons: BTreeSet<FullCertificationReason>,
    },
}

/// Plan semantic work without trusting raw watcher paths as authority.
#[must_use]
pub fn plan_semantic_refresh(input: &SemanticRefreshInput) -> SemanticRefreshPlan {
    let mut reasons = BTreeSet::new();
    let mut affected_documents = BTreeSet::new();

    if !input.exact_prior_authority {
        reasons.insert(FullCertificationReason::MissingPriorAuthority);
    }
    if !input.provider_identity_unchanged {
        reasons.insert(FullCertificationReason::ProviderIdentityChanged);
    }
    if !input.provider_configuration_unchanged {
        reasons.insert(FullCertificationReason::ProviderConfigurationChanged);
    }
    for change in &input.changes {
        match change {
            SemanticDocumentChange::Modified { before, after } => {
                let path = after.document_path.clone();
                if before.document_path != after.document_path
                    || before.language_id != after.language_id
                    || before.content_identity.is_empty()
                    || after.content_identity.is_empty()
                {
                    reasons.insert(FullCertificationReason::InconsistentDocumentIdentity {
                        document_path: path,
                    });
                    continue;
                }
                if before.content_identity == after.content_identity {
                    if before.cross_document_surface_identity
                        != after.cross_document_surface_identity
                    {
                        reasons.insert(FullCertificationReason::InconsistentDocumentIdentity {
                            document_path: path,
                        });
                    }
                    continue;
                }
                if !input
                    .affected_document_languages
                    .contains(&after.language_id)
                {
                    reasons.insert(FullCertificationReason::LanguageNotAdmitted {
                        document_path: path,
                        language_id: after.language_id.clone(),
                    });
                    continue;
                }
                match (
                    &before.cross_document_surface_identity,
                    &after.cross_document_surface_identity,
                ) {
                    (Some(previous), Some(current)) if previous == current => {
                        affected_documents.insert(after.document_path.clone());
                    }
                    (Some(_), Some(_)) => {
                        reasons.insert(FullCertificationReason::CrossDocumentSurfaceChanged {
                            document_path: path,
                        });
                    }
                    _ => {
                        reasons.insert(FullCertificationReason::MissingSurfaceIdentity {
                            document_path: path,
                        });
                    }
                }
            }
            SemanticDocumentChange::Added { current } => {
                reasons.insert(FullCertificationReason::DocumentAdded {
                    document_path: current.document_path.clone(),
                });
            }
            SemanticDocumentChange::Deleted { previous } => {
                reasons.insert(FullCertificationReason::DocumentDeleted {
                    document_path: previous.document_path.clone(),
                });
            }
            SemanticDocumentChange::ProjectInputChanged { path } => {
                reasons.insert(FullCertificationReason::ProjectInputChanged { path: path.clone() });
            }
            SemanticDocumentChange::Uncertain { path, reason } => {
                reasons.insert(FullCertificationReason::UncertainChange {
                    path: path.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }

    if !reasons.is_empty() {
        SemanticRefreshPlan::FullCertification { reasons }
    } else if affected_documents.is_empty() {
        SemanticRefreshPlan::ReuseExactPrior
    } else {
        SemanticRefreshPlan::AffectedDocuments {
            documents: affected_documents,
        }
    }
}

/// One prior-canonical target that an affected-document candidate resolved to
/// a different provider identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticTargetDivergence {
    pub document_path: String,
    pub call_site_identity: String,
}

/// Evidence required after the fast provider lane runs and before its result
/// can retain Complete authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedCandidateEvidence {
    pub exact_source_epoch: bool,
    pub exact_provider_identity: bool,
    pub provider_healthy: bool,
    pub covered_documents: BTreeSet<String>,
    pub target_divergences: Vec<SemanticTargetDivergence>,
}

/// Fail an affected-document candidate closed. A full plan is never weakened,
/// and a reuse plan cannot be upgraded by candidate evidence that should not
/// exist for it.
#[must_use]
pub fn validate_affected_candidate(
    plan: SemanticRefreshPlan,
    evidence: &AffectedCandidateEvidence,
) -> SemanticRefreshPlan {
    let SemanticRefreshPlan::AffectedDocuments { documents } = plan else {
        return plan;
    };
    let mut reasons = BTreeSet::new();
    if !evidence.exact_source_epoch {
        reasons.insert(FullCertificationReason::CandidateSourceEpochMismatch);
    }
    if !evidence.exact_provider_identity {
        reasons.insert(FullCertificationReason::CandidateProviderIdentityMismatch);
    }
    if !evidence.provider_healthy {
        reasons.insert(FullCertificationReason::CandidateProviderUnhealthy);
    }
    for missing in documents.difference(&evidence.covered_documents) {
        reasons.insert(FullCertificationReason::CandidateCoverageMissing {
            document_path: missing.clone(),
        });
    }
    for unexpected in evidence.covered_documents.difference(&documents) {
        reasons.insert(FullCertificationReason::CandidateCoverageUnexpected {
            document_path: unexpected.clone(),
        });
    }
    for divergence in &evidence.target_divergences {
        reasons.insert(FullCertificationReason::CandidateTargetDiverged {
            document_path: divergence.document_path.clone(),
            call_site_identity: divergence.call_site_identity.clone(),
        });
    }
    if reasons.is_empty() {
        SemanticRefreshPlan::AffectedDocuments { documents }
    } else {
        SemanticRefreshPlan::FullCertification { reasons }
    }
}

/// Hash syntax that can change semantic resolution in another document while
/// eliding only proven executable bodies. The language adapter owns syntax
/// admission and supplies the tree it has already admitted; this function
/// neither creates another parser nor re-litigates that decision.
pub(crate) fn cross_document_surface_sha256(
    extractor: &dyn LanguageExtractor,
    source: &str,
    root: Node<'_>,
) -> String {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, SEMANTIC_SURFACE_SCHEMA);
    hash_frame(&mut hasher, extractor.language().as_bytes());
    hash_surface_node(&mut hasher, extractor, source, root);
    hex_digest(hasher.finalize().as_slice())
}

fn hash_surface_node(
    hasher: &mut Sha256,
    extractor: &dyn LanguageExtractor,
    source: &str,
    node: Node<'_>,
) {
    if matches!(node.kind(), "line_comment" | "block_comment" | "comment") {
        return;
    }
    hash_frame(hasher, b"node");
    hash_frame(hasher, node.kind().as_bytes());

    let elided_body = extractor.cross_document_surface_elidable_body(node, source);
    if node.child_count() == 0 {
        let token = source
            .as_bytes()
            .get(node.start_byte()..node.end_byte())
            .unwrap_or_default();
        hash_frame(hasher, token);
    } else {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if elided_body.is_some_and(|body| same_node(body, child)) {
                hash_frame(hasher, b"executable-body-elided");
            } else {
                hash_surface_node(hasher, extractor, source, child);
            }
        }
    }
    hash_frame(hasher, b"end");
}

fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.kind() == right.kind()
        && left.start_byte() == right.start_byte()
        && left.end_byte() == right.end_byte()
}

fn hash_frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(language: &str, source: &str) -> Result<String, String> {
        let extension = match language {
            "rust" => "rs",
            "go" => "go",
            "python" => "py",
            "typescript" => "ts",
            other => return Err(format!("unregistered test language `{other}`")),
        };
        let file_path = format!("surface.{extension}");
        let extractor = crate::language::extractor_for_extension(extension)
            .expect("registered semantic-surface grammar");
        let tree = extractor
            .parse_admitted_tree(source, &file_path)
            .expect("test syntax admission");
        Ok(cross_document_surface_sha256(
            extractor,
            source,
            tree.root_node(),
        ))
    }

    /// RIGHT-REASON REGRESSION: the native Pyrefly provider now has an exact
    /// affected-document export and parity boundary. A module function whose
    /// complete callable signature is annotated cannot change another
    /// document's type surface merely by changing its executable body. Inferred
    /// signatures, methods (whose bodies can declare instance shape), and
    /// module-global writes remain deliberately conservative.
    #[test]
    fn python_fully_typed_module_function_body_edits_are_stable_but_escapes_are_not() {
        let baseline = surface(
            "python",
            "def caller(value: int) -> int:\n    return target_a(value)\n",
        )
        .expect("fully typed baseline surface");
        assert_eq!(
            baseline,
            surface(
                "python",
                "def caller(value: int) -> int:\n    return target_b(value)\n",
            )
            .expect("fully typed body edit"),
            "a fully typed module-function body must use affected-document refresh"
        );
        assert_ne!(
            baseline,
            surface(
                "python",
                "def caller(value: str) -> int:\n    return target_b(value)\n",
            )
            .expect("changed parameter annotation"),
            "a changed Python signature must force full certification"
        );
        assert_ne!(
            surface("python", "def inferred(value):\n    return 1\n").expect("inferred baseline"),
            surface("python", "def inferred(value):\n    return 'changed'\n")
                .expect("inferred body edit"),
            "an inferred Python signature remains body-dependent"
        );
        assert_ne!(
            surface(
                "python",
                "class Owner:\n    def update(self, value: int) -> int:\n        self.value = value\n        return value\n",
            )
            .expect("method baseline"),
            surface(
                "python",
                "class Owner:\n    def update(self, value: int) -> int:\n        self.other = value\n        return value\n",
            )
            .expect("method body edit"),
            "Python method bodies can alter externally visible instance shape"
        );
        assert_ne!(
            surface(
                "python",
                "published = 0\ndef update() -> None:\n    global published\n    published = 1\n",
            )
            .expect("global baseline"),
            surface(
                "python",
                "published = 0\ndef update() -> None:\n    global published\n    published = 'changed'\n",
            )
            .expect("global body edit"),
            "Python module-global writes can alter another document's inferred surface"
        );
    }

    /// RIGHT-REASON REGRESSION: the native TypeScript provider has an exact
    /// affected-document export and parity boundary. A function declaration
    /// with an explicit return type fixes its cross-document type surface, so
    /// hashing its executable body forces every ordinary call-site edit back
    /// through a full workspace certification. Inferred return types remain
    /// body-dependent and must not enter that fast lane.
    #[test]
    fn typescript_explicit_return_body_edits_are_stable_but_inferred_returns_are_not() {
        let baseline = surface(
            "typescript",
            "export function caller(): number { return targetA(); }",
        )
        .expect("explicit-return baseline surface");
        assert_eq!(
            baseline,
            surface(
                "typescript",
                "export function caller(): number { return targetB(); }",
            )
            .expect("explicit-return body edit"),
            "an explicitly typed TypeScript function body must use affected-document refresh"
        );
        assert_ne!(
            baseline,
            surface(
                "typescript",
                "export function caller(): string { return targetB(); }",
            )
            .expect("changed explicit return type"),
            "a changed TypeScript signature must force full certification"
        );
        assert_ne!(
            surface("typescript", "export function inferred() { return 1; }",)
                .expect("inferred-return baseline"),
            surface(
                "typescript",
                "export function inferred() { return 'changed'; }",
            )
            .expect("inferred-return body edit"),
            "an inferred TypeScript return type remains body-dependent"
        );
    }

    #[test]
    fn rust_body_edits_are_stable_but_interface_edits_are_not() {
        let baseline = surface("rust", "pub fn answer(value: u32) -> u32 { value + 1 }")
            .expect("baseline surface");
        assert_eq!(
            baseline,
            surface(
                "rust",
                "// formatting and comments are not semantic\npub fn answer(value: u32) -> u32 { helper(value) }",
            )
            .expect("body-only surface")
        );
        for changed in [
            "fn answer(value: u32) -> u32 { value + 1 }",
            "pub fn renamed(value: u32) -> u32 { value + 1 }",
            "pub fn answer(value: u64) -> u32 { value as u32 }",
        ] {
            assert_ne!(baseline, surface("rust", changed).expect("changed surface"));
        }
    }

    #[test]
    fn rust_trait_impl_cfg_and_macro_surfaces_force_a_new_identity() {
        for (before, after) in [
            (
                "trait Run { fn run(&self); }",
                "trait Run { fn run(&mut self); }",
            ),
            (
                "impl Run for Job { fn run(&self) {} }",
                "impl Other for Job { fn run(&self) {} }",
            ),
            (
                "#[cfg(unix)] pub fn platform() {}",
                "#[cfg(windows)] pub fn platform() {}",
            ),
            (
                "macro_rules! make { () => { fn alpha() {} } }",
                "macro_rules! make { () => { fn beta() {} } }",
            ),
        ] {
            assert_ne!(
                surface("rust", before).expect("before surface"),
                surface("rust", after).expect("after surface")
            );
        }
    }

    #[test]
    fn body_dependent_rust_signatures_retain_their_bodies() {
        for (before, after) in [
            (
                "pub async fn work() { alpha().await; }",
                "pub async fn work() { beta().await; }",
            ),
            (
                "pub const fn value() -> usize { 1 }",
                "pub const fn value() -> usize { 2 }",
            ),
            (
                "pub fn make() -> impl Clone { Alpha }",
                "pub fn make() -> impl Clone { Beta }",
            ),
        ] {
            assert_ne!(
                surface("rust", before).expect("before surface"),
                surface("rust", after).expect("after surface")
            );
        }
    }

    #[test]
    fn syntax_admission_owner_refuses_incomplete_source_before_surface_hashing() {
        let error = crate::extractor::extract_source("pub fn broken(", "broken.rs")
            .expect_err("incomplete syntax must not reach surface hashing");
        assert!(matches!(
            error,
            crate::structural_ir::ExtractorError::IncompleteSyntax { .. }
        ));
    }

    #[test]
    fn go_body_edits_are_stable_but_package_and_signature_edits_are_not() {
        let baseline = surface(
            "go",
            "package worker\n\nfunc Run(value int) int { return value + 1 }\n",
        )
        .expect("baseline surface");
        assert_eq!(
            baseline,
            surface(
                "go",
                "package worker\n\n// comment-only drift\nfunc Run(value int) int { return helper(value) }\n",
            )
            .expect("body-only surface")
        );
        assert_ne!(
            baseline,
            surface(
                "go",
                "package renamed\n\nfunc Run(value int) int { return value + 1 }\n",
            )
            .expect("package surface")
        );
        assert_ne!(
            baseline,
            surface(
                "go",
                "package worker\n\nfunc Run(value int64) int { return int(value) }\n",
            )
            .expect("signature surface")
        );
    }
}
