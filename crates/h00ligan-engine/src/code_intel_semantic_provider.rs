//! Engine bridge from bounded provider output to canonical SCIP authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use protobuf::Message as _;
use scip::types::Document;
use serde::{Deserialize, Serialize};

pub use h00ligan_provider_protocol::*;

pub use crate::scip_normalizer::{
    CanonicalScipDocumentUpdate, CanonicalScipSnapshot, IndexedSourceEvidence,
    ScipArtifactEvidence, ScipArtifactSetNormalization,
};
use crate::{
    code_intel_domain::{
        CALLABLE_LIVENESS_CONFIGURATION_ID, CapabilityReceipt, CapabilityScope, ConfigurationId,
        LanguageId, ProjectInventory,
    },
    code_intel_payload::{
        CALLABLE_LIVENESS_PROVIDER_PAYLOAD_SCHEMA, CallableLivenessPopulation,
        CallableLivenessProviderPayload, CallsProviderPayload, NormalizedSourceSpan,
        ProviderCallableLiveness, ProviderCallableLivenessExclusion, ProviderDocument,
        ProviderLocation, ProviderPayload, normalize_provider_payload_typed,
    },
    scip_normalizer::{
        CanonicalSourceSyntaxCache, ScipProviderSpec,
        canonical_scip_snapshot_from_provider_document_sets_with_identity,
        normalize_canonical_scip_snapshot_for_inventory_coverage,
        normalize_canonical_scip_snapshot_with_affected_calls_reuse,
        normalize_canonical_scip_snapshot_with_source_syntax_cache,
    },
};

#[cfg(test)]
use crate::scip_normalizer::canonical_scip_snapshot_from_provider_document_sets;

/// A wire-valid provider document failed canonical SCIP admission.
#[derive(Debug, thiserror::Error)]
pub enum SemanticProviderBridgeError {
    #[error(transparent)]
    Protocol(#[from] SemanticProviderProtocolError),
    #[error("canonical provider document protobuf is invalid: {0}")]
    CanonicalDocumentDecode(String),
    #[error("canonical provider analysis is invalid: {0}")]
    CanonicalAnalysis(String),
    #[error("canonical provider snapshot overlay is invalid: {0}")]
    CanonicalSnapshot(String),
    #[error("canonical provider parent snapshot differs from the admitted prior snapshot")]
    ParentSnapshotMismatch,
    #[error("canonical provider snapshot belongs to a different provider lineage")]
    ProviderLineageMismatch,
    #[error("persistent provider certification population is empty")]
    EmptyCertificationPopulation,
    #[error("persistent provider certification document populations overlap")]
    OverlappingCertificationPopulation,
    #[error("persistent provider certification execution roots overlap")]
    OverlappingCertificationRoots,
}

#[derive(Debug)]
struct AdmittedAnalysisPartition {
    execution_root: PathBuf,
    analysis: AdmittedProviderAnalysis,
}

struct AdmittedCanonicalSnapshot {
    snapshot: CanonicalScipSnapshot,
    analyses: Vec<AdmittedAnalysisPartition>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallableLivenessAnalysisSpan {
    start_byte: u64,
    end_byte: u64,
    start_line: u32,
    start_utf8_byte_column: u32,
    end_line: u32,
    end_utf8_byte_column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallableLivenessAnalysisLocation {
    document_path: String,
    span: CallableLivenessAnalysisSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallableLivenessAnalysisDocument {
    document_path: String,
    content_sha256: String,
    included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    omission_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallableLivenessAnalysisRecord {
    name: String,
    definition: CallableLivenessAnalysisLocation,
    structural_extent: CallableLivenessAnalysisLocation,
    production_reachable: bool,
    test_reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallableLivenessAnalysisArtifact {
    schema_version: String,
    configuration_id: String,
    language: String,
    documents: Vec<CallableLivenessAnalysisDocument>,
    callables: Vec<CallableLivenessAnalysisRecord>,
}

const CALLABLE_LIVENESS_DOCUMENT_OMITTED_REASON_CODE: &str = "provider_document_omitted";

/// One independently supervised root terminal entering repository-wide full
/// certification composition.
pub struct ProviderFullCertification {
    pub execution_root: PathBuf,
    pub frame: ProviderFrame<ProviderResponse>,
    pub expected: ExpectedFullCertification,
}

/// One independently supervised root terminal entering a single canonical
/// affected-document overlay.
pub struct ProviderAffectedRefresh {
    pub execution_root: PathBuf,
    pub frame: ProviderFrame<ProviderResponse>,
    pub expected: ExpectedAffectedRefresh,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct AffectedNormalizationBasis<'a> {
    pub source_syntax_cache: Option<&'a CanonicalSourceSyntaxCache>,
    pub prior_payload: Option<&'a CallsProviderPayload>,
    pub prior_supplemental_evidence: &'a [ScipArtifactEvidence],
}

#[derive(Clone, Copy)]
pub(crate) struct ExecutionRootRecertificationBasis<'a> {
    pub snapshot: &'a CanonicalScipSnapshot,
    pub source_syntax_cache: Option<&'a CanonicalSourceSyntaxCache>,
    pub supplemental_evidence: &'a [ScipArtifactEvidence],
}

/// Admit one full persistent-provider certification and construct its
/// canonical baseline without a temporary artifact.
///
/// The baseline runs through the same global normalizer as one-shot SCIP. Its
/// distinct provider identity prevents affected refreshes from extending a
/// stock baseline.
pub fn normalize_admitted_full_certification(
    root: &Path,
    execution_root: &Path,
    frame: ProviderFrame<ProviderResponse>,
    expected: &ExpectedFullCertification,
    limits: &ProviderFrameLimits,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> Result<ScipArtifactSetNormalization, SemanticProviderBridgeError> {
    normalize_admitted_full_certifications(
        root,
        vec![ProviderFullCertification {
            execution_root: execution_root.to_path_buf(),
            frame,
            expected: expected.clone(),
        }],
        limits,
        indexed_sources,
        inventory,
    )
}

/// Admit every execution root from one exact persistent provider lineage,
/// compose one canonical snapshot, and only then run the repository-wide
/// normalizer.
pub fn normalize_admitted_full_certifications(
    root: &Path,
    certifications: Vec<ProviderFullCertification>,
    limits: &ProviderFrameLimits,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> Result<ScipArtifactSetNormalization, SemanticProviderBridgeError> {
    normalize_admitted_full_certifications_with_source_syntax_cache(
        root,
        certifications,
        limits,
        indexed_sources,
        inventory,
        None,
    )
}

pub(crate) fn normalize_admitted_full_certifications_with_source_syntax_cache(
    root: &Path,
    certifications: Vec<ProviderFullCertification>,
    limits: &ProviderFrameLimits,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
    prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
) -> Result<ScipArtifactSetNormalization, SemanticProviderBridgeError> {
    let admitted = canonical_snapshot_from_admitted_full_certifications(
        root,
        certifications,
        limits,
        inventory,
    )?;
    let mut normalization = match prior_source_syntax_cache {
        Some(cache) => normalize_canonical_scip_snapshot_with_source_syntax_cache(
            root,
            admitted.snapshot,
            indexed_sources,
            inventory,
            Some(cache),
        ),
        None => normalize_canonical_scip_snapshot_for_inventory_coverage(
            root,
            admitted.snapshot,
            indexed_sources,
            inventory,
        ),
    };
    attach_callable_liveness_analysis(&mut normalization, admitted.analyses, None, root)?;
    Ok(normalization)
}

/// Admit complete certifications for a strict subset of persistent-provider
/// execution roots, replace those canonical partitions, and then rerun the
/// ordinary repository-wide normalizer over the recomposed snapshot.
pub(crate) fn normalize_admitted_execution_root_recertifications_with_source_syntax_cache(
    root: &Path,
    prior: ExecutionRootRecertificationBasis<'_>,
    certifications: Vec<ProviderFullCertification>,
    limits: &ProviderFrameLimits,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> Result<ScipArtifactSetNormalization, SemanticProviderBridgeError> {
    let admitted = canonical_snapshot_from_admitted_full_certifications(
        root,
        certifications,
        limits,
        inventory,
    )?;
    let snapshot = prior
        .snapshot
        .replace_execution_root_partitions(&admitted.snapshot)
        .map_err(|error| SemanticProviderBridgeError::CanonicalSnapshot(error.to_string()))?;
    let mut normalization = normalize_canonical_scip_snapshot_with_source_syntax_cache(
        root,
        snapshot,
        indexed_sources,
        inventory,
        prior.source_syntax_cache,
    );
    // Execution-root recertification replaces complete provider partitions,
    // so its analysis population composes against the prior supplemental
    // evidence exactly like an affected refresh.
    attach_callable_liveness_analysis(
        &mut normalization,
        admitted.analyses,
        Some(prior.supplemental_evidence),
        root,
    )?;
    Ok(normalization)
}

fn canonical_snapshot_from_admitted_full_certifications(
    root: &Path,
    certifications: Vec<ProviderFullCertification>,
    limits: &ProviderFrameLimits,
    inventory: &ProjectInventory,
) -> Result<AdmittedCanonicalSnapshot, SemanticProviderBridgeError> {
    if certifications.is_empty() {
        return Err(SemanticProviderBridgeError::EmptyCertificationPopulation);
    }
    let first_provider = &certifications
        .first()
        .expect("nonempty certification population")
        .expected
        .provider;
    let spec = ScipProviderSpec::persistent_from_lineage(
        &first_provider.provider_id,
        &first_provider.language,
    )
    .ok_or(SemanticProviderBridgeError::ProviderLineageMismatch)?;
    let mut documents = Vec::new();
    let mut provider_configurations_by_execution_root = BTreeMap::new();
    let mut expected_paths = BTreeSet::new();
    let mut provider_version = None::<String>;
    let mut provider_implementation_sha256 = None::<String>;
    let mut analyses = Vec::new();
    for certification in certifications {
        let expected = &certification.expected;
        let implementation_sha256 = provider_identity_sha256(&expected.provider)?;
        if expected.provider.provider_id != spec.provider_id
            || expected.provider.language != spec.language
            || provider_version
                .as_deref()
                .is_some_and(|version| version != expected.provider.implementation_version)
            || provider_implementation_sha256
                .as_deref()
                .is_some_and(|identity| identity != implementation_sha256)
        {
            return Err(SemanticProviderBridgeError::ProviderLineageMismatch);
        }
        provider_version.get_or_insert_with(|| expected.provider.implementation_version.clone());
        provider_implementation_sha256.get_or_insert(implementation_sha256);
        if provider_configurations_by_execution_root
            .insert(
                certification.execution_root.clone(),
                resolved_authority_configuration_sha256(&expected.authority)?,
            )
            .is_some()
        {
            return Err(SemanticProviderBridgeError::OverlappingCertificationRoots);
        }
        if expected
            .documents
            .keys()
            .any(|path| !expected_paths.insert(path.clone()))
        {
            return Err(SemanticProviderBridgeError::OverlappingCertificationPopulation);
        }
        let admitted = validate_full_certification(certification.frame, expected, limits)?;
        analyses.extend(
            admitted
                .analyses
                .into_iter()
                .map(|analysis| AdmittedAnalysisPartition {
                    execution_root: certification.execution_root.clone(),
                    analysis,
                }),
        );
        for document in admitted.documents {
            let AdmittedProviderDocument::Present {
                document_path,
                canonical_document,
            } = document
            else {
                continue;
            };
            let document = Document::parse_from_bytes(&canonical_document).map_err(|error| {
                SemanticProviderBridgeError::CanonicalDocumentDecode(error.to_string())
            })?;
            if document.relative_path != document_path {
                return Err(SemanticProviderBridgeError::CanonicalSnapshot(format!(
                    "provider outcome path {document_path:?} differs from canonical SCIP path {:?}",
                    document.relative_path
                )));
            }
            documents.push(document);
        }
    }
    let snapshot = canonical_scip_snapshot_from_provider_document_sets_with_identity(
        root,
        spec,
        provider_version
            .as_deref()
            .ok_or(SemanticProviderBridgeError::EmptyCertificationPopulation)?,
        provider_implementation_sha256.as_deref(),
        &provider_configurations_by_execution_root,
        documents,
        inventory,
    )
    .map_err(|error| SemanticProviderBridgeError::CanonicalSnapshot(error.to_string()))?;
    Ok(AdmittedCanonicalSnapshot { snapshot, analyses })
}

/// Admit affected terminals from every touched provider root and apply their
/// exact union as one overlay on the common parent snapshot.
pub fn normalize_admitted_affected_refreshes(
    root: &Path,
    prior_snapshot: CanonicalScipSnapshot,
    exports: Vec<ProviderAffectedRefresh>,
    limits: &ProviderFrameLimits,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> Result<ScipArtifactSetNormalization, SemanticProviderBridgeError> {
    normalize_admitted_affected_refreshes_with_source_syntax_cache(
        root,
        &prior_snapshot,
        exports,
        limits,
        indexed_sources,
        inventory,
        AffectedNormalizationBasis::default(),
    )
}

pub(crate) fn normalize_admitted_affected_refreshes_with_source_syntax_cache(
    root: &Path,
    prior_snapshot: &CanonicalScipSnapshot,
    exports: Vec<ProviderAffectedRefresh>,
    limits: &ProviderFrameLimits,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
    prior_basis: AffectedNormalizationBasis<'_>,
) -> Result<ScipArtifactSetNormalization, SemanticProviderBridgeError> {
    if exports.is_empty() {
        return Err(SemanticProviderBridgeError::EmptyCertificationPopulation);
    }
    let parent_snapshot_sha256 = prior_snapshot.identity_sha256();
    let mut requested = BTreeSet::new();
    let mut updates = Vec::new();
    let mut analyses = Vec::new();
    for export in exports {
        let expected = &export.expected;
        if parent_snapshot_sha256 != expected.parent_snapshot_sha256 {
            return Err(SemanticProviderBridgeError::ParentSnapshotMismatch);
        }
        let expected_configuration = prior_snapshot
            .provider_configuration_sha256_for_execution_root(&export.execution_root)
            .map_err(|error| SemanticProviderBridgeError::CanonicalSnapshot(error.to_string()))?;
        let resolved_configuration = resolved_authority_configuration_sha256(&expected.authority)?;
        let expected_provider_implementation = provider_identity_sha256(&expected.provider)?;
        if prior_snapshot.provider_id() != expected.provider.provider_id
            || prior_snapshot.executed_provider_version()
                != expected.provider.implementation_version
            || prior_snapshot.provider_implementation_sha256()
                != Some(expected_provider_implementation.as_str())
            || expected_configuration != Some(resolved_configuration.as_str())
        {
            return Err(SemanticProviderBridgeError::ProviderLineageMismatch);
        }
        if expected
            .documents
            .keys()
            .any(|path| !requested.insert(path.clone()))
        {
            return Err(SemanticProviderBridgeError::OverlappingCertificationPopulation);
        }
        let admitted = validate_affected_refresh(export.frame, expected, limits)?;
        analyses.extend(
            admitted
                .analyses
                .into_iter()
                .map(|analysis| AdmittedAnalysisPartition {
                    execution_root: export.execution_root.clone(),
                    analysis,
                }),
        );
        for document in admitted.documents {
            match document {
                AdmittedProviderDocument::Present {
                    document_path,
                    canonical_document,
                } => {
                    let document =
                        Document::parse_from_bytes(&canonical_document).map_err(|error| {
                            SemanticProviderBridgeError::CanonicalDocumentDecode(error.to_string())
                        })?;
                    updates.push(CanonicalScipDocumentUpdate::Present {
                        document_path,
                        document,
                    });
                }
                AdmittedProviderDocument::Omitted { document_path } => {
                    updates.push(CanonicalScipDocumentUpdate::Omitted { document_path });
                }
            }
        }
    }
    let snapshot = prior_snapshot
        .overlay_affected_documents(&requested, updates)
        .map_err(|error| SemanticProviderBridgeError::CanonicalSnapshot(error.to_string()))?;
    let mut normalization = match prior_basis.prior_payload {
        Some(prior_payload) => {
            if prior_payload.canonical_snapshot_sha256.as_deref()
                != Some(parent_snapshot_sha256.as_str())
            {
                return Err(SemanticProviderBridgeError::ParentSnapshotMismatch);
            }
            normalize_canonical_scip_snapshot_with_affected_calls_reuse(
                root,
                snapshot,
                indexed_sources,
                inventory,
                prior_basis.source_syntax_cache,
                &requested,
                prior_payload,
            )
        }
        None => normalize_canonical_scip_snapshot_with_source_syntax_cache(
            root,
            snapshot,
            indexed_sources,
            inventory,
            prior_basis.source_syntax_cache,
        ),
    };
    attach_callable_liveness_analysis(
        &mut normalization,
        analyses,
        Some(prior_basis.prior_supplemental_evidence),
        root,
    )?;
    Ok(normalization)
}

fn attach_callable_liveness_analysis(
    normalization: &mut ScipArtifactSetNormalization,
    analyses: Vec<AdmittedAnalysisPartition>,
    prior_supplemental_evidence: Option<&[ScipArtifactEvidence]>,
    repository_root: &Path,
) -> Result<(), SemanticProviderBridgeError> {
    if analyses.is_empty() {
        if prior_supplemental_evidence.is_some_and(|prior| !prior.is_empty()) {
            return Err(SemanticProviderBridgeError::CanonicalAnalysis(
                "an affected provider refresh omitted its previously published analysis capability"
                    .into(),
            ));
        }
        return Ok(());
    }

    let calls = match normalization
        .evidence
        .payload
        .as_ref()
        .map(|payload| payload.payload())
    {
        Some(ProviderPayload::Calls(calls)) => calls.clone(),
        _ => {
            return Err(SemanticProviderBridgeError::CanonicalAnalysis(
                "callable-liveness analysis has no complete primary Calls payload".into(),
            ));
        }
    };
    let expected_documents = calls
        .documents
        .iter()
        .map(|document| (document.document_path.clone(), document.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut documents = BTreeMap::<String, ProviderDocument>::new();
    let mut callables = BTreeMap::<(String, u64, u64), ProviderCallableLiveness>::new();
    let mut exclusions = BTreeMap::<String, ProviderCallableLivenessExclusion>::new();
    if let Some(prior) = prior_supplemental_evidence {
        if prior.len() != 1 {
            return Err(SemanticProviderBridgeError::CanonicalAnalysis(
                "affected callable-liveness refresh requires exactly one prior supplemental capability"
                    .into(),
            ));
        }
        let prior_payload = match prior[0].payload.as_ref().map(|payload| payload.payload()) {
            Some(ProviderPayload::CallableLiveness(payload))
                if payload.receipt.provider_id == calls.receipt.provider_id
                    && payload.receipt.provider_version == calls.receipt.provider_version
                    && payload.receipt.scope.language_id() == calls.receipt.scope.language_id() =>
            {
                payload
            }
            _ => {
                return Err(SemanticProviderBridgeError::CanonicalAnalysis(
                    "prior supplemental evidence is not the matching callable-liveness capability"
                        .into(),
                ));
            }
        };
        documents.extend(
            prior_payload
                .documents
                .iter()
                .cloned()
                .map(|document| (document.document_path.clone(), document)),
        );
        callables.extend(prior_payload.callables.iter().cloned().map(|callable| {
            (
                (
                    callable.structural_extent.document_path.clone(),
                    callable.structural_extent.span.start_byte,
                    callable.structural_extent.span.end_byte,
                ),
                callable,
            )
        }));
        exclusions.extend(
            prior_payload
                .coverage_exclusions
                .iter()
                .cloned()
                .map(|exclusion| (exclusion.document_path.clone(), exclusion)),
        );
    }

    let mut replaced_documents = BTreeSet::new();
    let mut decoded = Vec::with_capacity(analyses.len());
    for partition in analyses {
        if partition.analysis.analysis_id != CALLABLE_LIVENESS_ANALYSIS_ID
            || partition.analysis.schema_version != CALLABLE_LIVENESS_ANALYSIS_SCHEMA_V1
            || partition.analysis.configuration_id != GO_CALLABLE_LIVENESS_CONFIGURATION_V1
            || partition.analysis.language != H00_GO_LANGUAGE
        {
            return Err(SemanticProviderBridgeError::CanonicalAnalysis(
                "provider returned an unsupported semantic analysis identity".into(),
            ));
        }
        let mut artifact: CallableLivenessAnalysisArtifact =
            serde_json::from_slice(&partition.analysis.canonical_analysis).map_err(|error| {
                SemanticProviderBridgeError::CanonicalAnalysis(format!(
                    "cannot decode callable-liveness payload: {error}"
                ))
            })?;
        if artifact.schema_version != CALLABLE_LIVENESS_ANALYSIS_SCHEMA_V1
            || artifact.configuration_id != GO_CALLABLE_LIVENESS_CONFIGURATION_V1
            || artifact.language != H00_GO_LANGUAGE
        {
            return Err(SemanticProviderBridgeError::CanonicalAnalysis(
                "callable-liveness attachment identity differs from its admitted outcome".into(),
            ));
        }
        let prefix = execution_root_prefix(repository_root, &partition.execution_root)?;
        for document in &mut artifact.documents {
            if !document_path_is_in_execution_prefix(&document.document_path, &prefix) {
                return Err(SemanticProviderBridgeError::CanonicalAnalysis(format!(
                    "callable-liveness document {} escapes its execution root",
                    document.document_path
                )));
            }
            let expected = expected_documents
                .get(&document.document_path)
                .ok_or_else(|| {
                    SemanticProviderBridgeError::CanonicalAnalysis(format!(
                        "callable-liveness document {} is outside the normalized Calls population",
                        document.document_path
                    ))
                })?;
            if document.content_sha256 != expected.content_sha256
                || !replaced_documents.insert(document.document_path.clone())
            {
                return Err(SemanticProviderBridgeError::CanonicalAnalysis(format!(
                    "callable-liveness document {} has inconsistent identity, selection, or ownership",
                    document.document_path
                )));
            }
            document.omission_reason = match (
                document.included,
                document.omission_reason.as_deref(),
            ) {
                (true, None) => None,
                (false, Some(reason)) => {
                    Some(normalize_callable_liveness_omission_reason(reason)?.into())
                }
                (true, Some(_)) | (false, None) => {
                    return Err(SemanticProviderBridgeError::CanonicalAnalysis(format!(
                        "callable-liveness document {} has inconsistent identity, selection, or ownership",
                        document.document_path
                    )));
                }
            };
        }
        decoded.push(artifact);
    }

    for path in &replaced_documents {
        documents.remove(path);
        exclusions.remove(path);
    }
    callables.retain(|(path, _, _), _| !replaced_documents.contains(path));

    for artifact in decoded {
        let selections = artifact
            .documents
            .iter()
            .map(|document| (document.document_path.clone(), document.included))
            .collect::<BTreeMap<_, _>>();
        for document in artifact.documents {
            let expected = expected_documents
                .get(&document.document_path)
                .expect("analysis documents were validated against Calls");
            documents.insert(document.document_path.clone(), expected.clone());
            if let Some(reason_code) = document.omission_reason {
                exclusions.insert(
                    document.document_path.clone(),
                    ProviderCallableLivenessExclusion {
                        document_path: document.document_path,
                        reason_code,
                    },
                );
            }
        }
        for callable in artifact.callables {
            let document_path = callable.structural_extent.document_path.as_str();
            if !selections
                .get(document_path)
                .is_some_and(|included| *included)
                || callable.definition.document_path != document_path
            {
                return Err(SemanticProviderBridgeError::CanonicalAnalysis(format!(
                    "callable-liveness record {} is outside its included analysis partition",
                    callable.name
                )));
            }
            let callable = ProviderCallableLiveness {
                name: callable.name,
                definition: convert_analysis_location(callable.definition),
                structural_extent: convert_analysis_location(callable.structural_extent),
                production_reachable: callable.production_reachable,
                test_reachable: callable.test_reachable,
            };
            let key = (
                callable.structural_extent.document_path.clone(),
                callable.structural_extent.span.start_byte,
                callable.structural_extent.span.end_byte,
            );
            if callables.insert(key, callable).is_some() {
                return Err(SemanticProviderBridgeError::CanonicalAnalysis(
                    "callable-liveness partitions contain overlapping callable identities".into(),
                ));
            }
        }
    }

    if documents.keys().collect::<BTreeSet<_>>()
        != expected_documents.keys().collect::<BTreeSet<_>>()
    {
        return Err(SemanticProviderBridgeError::CanonicalAnalysis(
            "callable-liveness analysis does not cover the exact normalized Calls document population"
                .into(),
        ));
    }
    let provider_version = calls.receipt.provider_version.clone().ok_or_else(|| {
        SemanticProviderBridgeError::CanonicalAnalysis(
            "complete Calls receipt has no provider version".into(),
        )
    })?;
    let input_fingerprint = callable_liveness_input_fingerprint(&calls.receipt)?;
    let receipt = CapabilityReceipt::complete(
        "callable_liveness",
        calls.receipt.provider_id.0.clone(),
        provider_version,
        callable_liveness_scope(&calls.receipt.scope),
        input_fingerprint,
    );
    let payload = ProviderPayload::CallableLiveness(CallableLivenessProviderPayload {
        schema_version: CALLABLE_LIVENESS_PROVIDER_PAYLOAD_SCHEMA.into(),
        population: CallableLivenessPopulation::NamedFunctionAndMethodDeclarations,
        receipt: receipt.clone(),
        semantic_inputs: calls.semantic_inputs,
        execution_authority: calls.execution_authority,
        documents: documents.into_values().collect(),
        callables: callables.into_values().collect(),
        coverage_exclusions: exclusions.into_values().collect(),
    });
    let payload = normalize_provider_payload_typed(&payload)
        .map_err(|error| SemanticProviderBridgeError::CanonicalAnalysis(error.to_string()))?;
    normalization.supplemental_evidence = vec![ScipArtifactEvidence {
        language_id: LanguageId::new(H00_GO_LANGUAGE),
        receipt,
        payload: Some(payload),
    }];
    Ok(())
}

fn normalize_callable_liveness_omission_reason(
    provider_reason: &str,
) -> Result<&'static str, SemanticProviderBridgeError> {
    match provider_reason {
        "invalid-package-clause" | "no-metadata" | "outside-selected-build" => {
            Ok(CALLABLE_LIVENESS_DOCUMENT_OMITTED_REASON_CODE)
        }
        unsupported => Err(SemanticProviderBridgeError::CanonicalAnalysis(format!(
            "unsupported callable-liveness document omission reason {unsupported:?}"
        ))),
    }
}

fn convert_analysis_location(location: CallableLivenessAnalysisLocation) -> ProviderLocation {
    ProviderLocation {
        document_path: location.document_path,
        span: NormalizedSourceSpan {
            start_byte: location.span.start_byte,
            end_byte: location.span.end_byte,
            start_line: location.span.start_line,
            start_utf8_byte_column: location.span.start_utf8_byte_column,
            end_line: location.span.end_line,
            end_utf8_byte_column: location.span.end_utf8_byte_column,
        },
    }
}

fn execution_root_prefix(
    repository_root: &Path,
    execution_root: &Path,
) -> Result<String, SemanticProviderBridgeError> {
    let relative = execution_root.strip_prefix(repository_root).map_err(|_| {
        SemanticProviderBridgeError::CanonicalAnalysis(
            "semantic analysis execution root escapes repository root".into(),
        )
    })?;
    relative
        .to_str()
        .map(|prefix| prefix.replace('\\', "/").trim_matches('/').to_owned())
        .ok_or_else(|| {
            SemanticProviderBridgeError::CanonicalAnalysis(
                "semantic analysis execution root is not valid UTF-8".into(),
            )
        })
}

fn document_path_is_in_execution_prefix(document_path: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || document_path == prefix
        || document_path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn callable_liveness_scope(scope: &CapabilityScope) -> CapabilityScope {
    let configuration_id = ConfigurationId::new(CALLABLE_LIVENESS_CONFIGURATION_ID);
    match scope {
        CapabilityScope::Repository { .. } => CapabilityScope::Repository { configuration_id },
        CapabilityScope::Language { language_id, .. } => CapabilityScope::Language {
            language_id: language_id.clone(),
            configuration_id,
        },
        CapabilityScope::ProjectUnit {
            language_id,
            project_unit_id,
            ..
        } => CapabilityScope::ProjectUnit {
            language_id: language_id.clone(),
            project_unit_id: project_unit_id.clone(),
            configuration_id,
        },
        CapabilityScope::ProjectUnits {
            language_id,
            project_unit_ids,
            ..
        } => CapabilityScope::ProjectUnits {
            language_id: language_id.clone(),
            project_unit_ids: project_unit_ids.clone(),
            configuration_id,
        },
    }
}

fn callable_liveness_input_fingerprint(
    calls_receipt: &CapabilityReceipt,
) -> Result<String, SemanticProviderBridgeError> {
    let calls_fingerprint = calls_receipt.input_fingerprint.as_deref().ok_or_else(|| {
        SemanticProviderBridgeError::CanonicalAnalysis(
            "complete Calls receipt has no input fingerprint".into(),
        )
    })?;
    serde_json::to_vec(&(
        "h00/code-intel/callable-liveness-input/v1",
        CALLABLE_LIVENESS_ANALYSIS_SCHEMA_V1,
        GO_CALLABLE_LIVENESS_CONFIGURATION_V1,
        calls_fingerprint,
    ))
    .map(|material| sha256_hex(&material))
    .map_err(|error| SemanticProviderBridgeError::CanonicalAnalysis(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use protobuf::{EnumOrUnknown, Message as _};
    use scip::types::{Document, PositionEncoding};
    use tempfile::TempDir;

    use super::*;
    use crate::code_intel_domain::CapabilityStatus;
    use crate::code_intel_inventory::{InventorySource, build_project_inventory};
    use crate::extractor::extract_file;

    const SOURCE: &str = "pub fn example() {}\n";

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    #[test]
    fn callable_liveness_omission_reasons_are_bounded_and_normalized() {
        for provider_reason in [
            "invalid-package-clause",
            "no-metadata",
            "outside-selected-build",
        ] {
            assert_eq!(
                normalize_callable_liveness_omission_reason(provider_reason)
                    .expect("supported provider omission reason"),
                CALLABLE_LIVENESS_DOCUMENT_OMITTED_REASON_CODE,
                "provider internals must not become public capability reason codes"
            );
        }

        let error = normalize_callable_liveness_omission_reason("invented-provider-state")
            .expect_err("unknown provider reason must fail closed");
        assert!(
            matches!(
                &error,
                SemanticProviderBridgeError::CanonicalAnalysis(reason)
                    if reason.contains("unsupported callable-liveness document omission reason")
            ),
            "unexpected error: {error}"
        );
    }

    fn provider() -> ProviderIdentity {
        ProviderIdentity {
            protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
            provider_id: H00_RUST_ANALYZER_PROVIDER_ID.into(),
            language: H00_RUST_ANALYZER_LANGUAGE.into(),
            implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
            source_components: rust_analyzer_source_components(),
            patch_sha256: digest('a'),
            executable_sha256: digest('b'),
        }
    }

    fn authority() -> ProviderAuthority {
        ProviderAuthority {
            session_id: "session-bridge-1".into(),
            root_sha256: digest('c'),
            root_topology_sha256: digest('d'),
            configuration_sha256: digest('e'),
            workspace_resolution_sha256: Some(digest('1')),
            semantic_inputs_sha256: Some(digest('2')),
            population_sha256: digest('f'),
            source_epoch: 1,
        }
    }

    fn health() -> ProviderHealthEvidence {
        ProviderHealthEvidence {
            components: BTreeMap::from([
                ("build_scripts".into(), ProviderComponentHealth::Healthy),
                ("proc_macros".into(), ProviderComponentHealth::Healthy),
                ("workspace_model".into(), ProviderComponentHealth::Healthy),
            ]),
            diagnostics_complete: true,
            degradation_reasons: Vec::new(),
        }
    }

    fn runtime_configuration() -> ProviderRuntimeConfiguration {
        provider_runtime_configuration(
            &digest('9'),
            &[("rustc", b"rustc 1.97.1")],
            b"exact-environment",
            b"exact-workspace-controls",
        )
        .expect("affected-refresh runtime witness")
    }

    fn document() -> Document {
        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document
    }

    fn expected_documents() -> BTreeMap<String, ExpectedProviderDocument> {
        BTreeMap::from([(
            "src/lib.rs".into(),
            ExpectedProviderDocument {
                language: "rust".into(),
                content_identity: format!("blake3:{}", blake3::hash(SOURCE.as_bytes()).to_hex()),
            },
        )])
    }

    fn full_frame(request_id: u64) -> ProviderFrame<ProviderResponse> {
        let bytes = document().write_to_bytes().expect("canonical document");
        ProviderFrame {
            metadata: ProviderResponse {
                request_id,
                session_id: authority().session_id,
                provider: provider(),
                body: ProviderResponseBody::FullCertification {
                    authority: authority(),
                    health: health(),
                    analyses: Vec::new(),
                    outcomes: vec![ProviderDocumentOutcome::Present {
                        document_path: "src/lib.rs".into(),
                        language: "rust".into(),
                        content_identity: expected_documents()["src/lib.rs"]
                            .content_identity
                            .clone(),
                        canonical_document_sha256: sha256_hex(&bytes),
                        attachment_index: 0,
                    }],
                },
            },
            attachments: vec![bytes],
        }
    }

    fn full_certification_for(
        execution_root: &Path,
        document_path: &str,
        source: &str,
        request_id: u64,
        configuration_digest: char,
    ) -> ProviderFullCertification {
        let mut authority = authority();
        authority.session_id = format!("session-{request_id}");
        authority.configuration_sha256 = digest(configuration_digest);
        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = document_path.into();
        document.text = source.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        let canonical_document = document
            .write_to_bytes()
            .expect("canonical provider document");
        let content_identity = format!("blake3:{}", blake3::hash(source.as_bytes()).to_hex());
        let expected_documents = BTreeMap::from([(
            document_path.into(),
            ExpectedProviderDocument {
                language: "rust".into(),
                content_identity: content_identity.clone(),
            },
        )]);
        ProviderFullCertification {
            execution_root: execution_root.to_path_buf(),
            frame: ProviderFrame {
                metadata: ProviderResponse {
                    request_id,
                    session_id: authority.session_id.clone(),
                    provider: provider(),
                    body: ProviderResponseBody::FullCertification {
                        authority: authority.clone(),
                        health: health(),
                        analyses: Vec::new(),
                        outcomes: vec![ProviderDocumentOutcome::Present {
                            document_path: document_path.into(),
                            language: "rust".into(),
                            content_identity,
                            canonical_document_sha256: sha256_hex(&canonical_document),
                            attachment_index: 0,
                        }],
                    },
                },
                attachments: vec![canonical_document],
            },
            expected: ExpectedFullCertification {
                request_id,
                provider: provider(),
                authority,
                documents: expected_documents,
                analyses: BTreeMap::new(),
            },
        }
    }

    fn affected_refresh_for(
        document_path: &str,
        source: &str,
        request_id: u64,
        configuration_digest: char,
        parent_snapshot_sha256: &str,
    ) -> (ProviderFrame<ProviderResponse>, ExpectedAffectedRefresh) {
        let mut authority = authority();
        authority.session_id = format!("session-{request_id}");
        authority.configuration_sha256 = digest(configuration_digest);
        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = document_path.into();
        document.text = source.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        let canonical_document = document
            .write_to_bytes()
            .expect("canonical affected document");
        let content_identity = format!("blake3:{}", blake3::hash(source.as_bytes()).to_hex());
        let documents = BTreeMap::from([(
            document_path.into(),
            ExpectedProviderDocument {
                language: "rust".into(),
                content_identity: content_identity.clone(),
            },
        )]);
        let expected = ExpectedAffectedRefresh {
            request_id,
            provider: provider(),
            authority: authority.clone(),
            parent_snapshot_sha256: parent_snapshot_sha256.into(),
            documents,
            analyses: BTreeMap::new(),
            terminal_runtime_configuration: runtime_configuration(),
        };
        let frame = ProviderFrame {
            metadata: ProviderResponse {
                request_id,
                session_id: authority.session_id.clone(),
                provider: provider(),
                body: ProviderResponseBody::AffectedRefreshed {
                    authority,
                    parent_snapshot_sha256: parent_snapshot_sha256.into(),
                    health: health(),
                    runtime_configuration: runtime_configuration(),
                    analyses: Vec::new(),
                    outcomes: vec![ProviderDocumentOutcome::Present {
                        document_path: document_path.into(),
                        language: "rust".into(),
                        content_identity,
                        canonical_document_sha256: sha256_hex(&canonical_document),
                        attachment_index: 0,
                    }],
                },
            },
            attachments: vec![canonical_document],
        };
        (frame, expected)
    }

    fn affected_frame(
        request_id: u64,
        parent_snapshot_sha256: String,
    ) -> ProviderFrame<ProviderResponse> {
        let bytes = document().write_to_bytes().expect("canonical document");
        ProviderFrame {
            metadata: ProviderResponse {
                request_id,
                session_id: authority().session_id,
                provider: provider(),
                body: ProviderResponseBody::AffectedRefreshed {
                    authority: authority(),
                    parent_snapshot_sha256,
                    health: health(),
                    runtime_configuration: runtime_configuration(),
                    analyses: Vec::new(),
                    outcomes: vec![ProviderDocumentOutcome::Present {
                        document_path: "src/lib.rs".into(),
                        language: "rust".into(),
                        content_identity: expected_documents()["src/lib.rs"]
                            .content_identity
                            .clone(),
                        canonical_document_sha256: sha256_hex(&bytes),
                        attachment_index: 0,
                    }],
                },
            },
            attachments: vec![bytes],
        }
    }

    struct Fixture {
        _temporary: TempDir,
        root: std::path::PathBuf,
        inventory: ProjectInventory,
        indexed_sources: Vec<IndexedSourceEvidence>,
    }

    const ALPHA_SOURCE: &str = "pub fn alpha() {}\n";
    const BETA_SOURCE: &str = "pub fn beta() {}\n";

    struct MultiRootFixture {
        _temporary: TempDir,
        root: PathBuf,
        alpha_root: PathBuf,
        beta_root: PathBuf,
        inventory: ProjectInventory,
        indexed_sources: Vec<IndexedSourceEvidence>,
    }

    fn fixture() -> Fixture {
        let temporary = TempDir::new().expect("temporary project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"bridge-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(root.join("src/lib.rs"), SOURCE).expect("source");
        let inventory =
            build_project_inventory(&root, &[InventorySource::new("src/lib.rs", "rust")]);
        Fixture {
            _temporary: temporary,
            root,
            inventory,
            indexed_sources: vec![IndexedSourceEvidence {
                relative_path: "src/lib.rs".into(),
                language: "rust".into(),
                blake3_hash: blake3::hash(SOURCE.as_bytes()).to_hex().to_string(),
                cross_document_surface_sha256: Some(sha256_hex(SOURCE.as_bytes())),
            }],
        }
    }

    fn multi_root_fixture() -> MultiRootFixture {
        let temporary = TempDir::new().expect("multi-root provider project");
        let root = temporary.path().join("repo");
        let alpha_root = root.join("alpha");
        let beta_root = root.join("beta");
        for (name, execution_root, source) in [
            ("alpha", &alpha_root, ALPHA_SOURCE),
            ("beta", &beta_root, BETA_SOURCE),
        ] {
            fs::create_dir_all(execution_root.join("src")).expect("execution-root source");
            fs::write(
                execution_root.join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
            )
            .expect("execution-root manifest");
            fs::write(execution_root.join("src/lib.rs"), source).expect("source fixture");
        }
        let sources = [
            InventorySource::new("alpha/src/lib.rs", "rust"),
            InventorySource::new("beta/src/lib.rs", "rust"),
        ];
        let inventory = build_project_inventory(&root, &sources);
        let indexed_sources = sources
            .iter()
            .map(|source| {
                let extracted = extract_file(&root.join(&source.document_path), &root)
                    .expect("extract exact source evidence");
                IndexedSourceEvidence {
                    relative_path: source.document_path.clone(),
                    language: "rust".into(),
                    blake3_hash: extracted.file_hash,
                    cross_document_surface_sha256: Some(extracted.cross_document_surface_sha256),
                }
            })
            .collect();
        MultiRootFixture {
            _temporary: temporary,
            root,
            alpha_root,
            beta_root,
            inventory,
            indexed_sources,
        }
    }

    #[test]
    fn full_sidecar_certification_seeds_only_its_own_canonical_lineage() {
        let fixture = fixture();
        let request_id = 11;
        let expected = ExpectedFullCertification {
            request_id,
            provider: provider(),
            authority: authority(),
            documents: expected_documents(),
            analyses: BTreeMap::new(),
        };
        let normalization = normalize_admitted_full_certification(
            &fixture.root,
            &fixture.root,
            full_frame(request_id),
            &expected,
            &ProviderFrameLimits::default(),
            &fixture.indexed_sources,
            &fixture.inventory,
        )
        .expect("admit full sidecar baseline");
        assert_eq!(
            normalization.evidence.receipt.status,
            CapabilityStatus::Complete
        );
        let snapshot = normalization
            .canonical_snapshot
            .expect("complete certification retains canonical baseline");
        assert_eq!(snapshot.provider_id(), H00_RUST_ANALYZER_PROVIDER_ID);
        assert_eq!(
            snapshot.executed_provider_version(),
            H00_RUST_ANALYZER_IMPLEMENTATION_V6
        );
        assert_eq!(snapshot.identity_sha256().len(), 64);
    }

    /// RIGHT-REASON REGRESSION: a wire-valid TypeScript certification is not
    /// product functionality until the canonical SCIP bridge admits its exact
    /// provider lineage and repository source population.
    #[test]
    fn typescript_native_certification_reaches_canonical_calls_admission() {
        const TYPESCRIPT_SOURCE: &str = "export function example(): void {}\n";
        let temporary = TempDir::new().expect("temporary TypeScript project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("TypeScript source directory");
        fs::write(
            root.join("package.json"),
            r#"{"name":"bridge-fixture","version":"1.0.0","type":"module"}"#,
        )
        .expect("TypeScript package manifest");
        fs::write(
            root.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("TypeScript compiler configuration");
        fs::write(root.join("src/index.ts"), TYPESCRIPT_SOURCE).expect("TypeScript source");
        let inventory = build_project_inventory(
            &root,
            &[InventorySource::new(
                "src/index.ts",
                H00_TYPESCRIPT_LANGUAGE,
            )],
        );
        let extracted = extract_file(&root.join("src/index.ts"), &root)
            .expect("extract exact TypeScript source evidence");
        let indexed_sources = vec![IndexedSourceEvidence {
            relative_path: "src/index.ts".into(),
            language: H00_TYPESCRIPT_LANGUAGE.into(),
            blake3_hash: extracted.file_hash,
            cross_document_surface_sha256: Some(extracted.cross_document_surface_sha256),
        }];
        let provider = ProviderIdentity {
            protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
            provider_id: H00_TYPESCRIPT_PROVIDER_ID.into(),
            language: H00_TYPESCRIPT_LANGUAGE.into(),
            implementation_version: H00_TYPESCRIPT_IMPLEMENTATION_V2.into(),
            source_components: typescript_source_components(),
            patch_sha256: digest('7'),
            executable_sha256: digest('8'),
        };
        let mut document = Document::new();
        document.language = H00_TYPESCRIPT_LANGUAGE.into();
        document.relative_path = "src/index.ts".into();
        document.text = TYPESCRIPT_SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        let canonical = document
            .write_to_bytes()
            .expect("canonical TypeScript document");
        let content_identity = format!(
            "blake3:{}",
            blake3::hash(TYPESCRIPT_SOURCE.as_bytes()).to_hex()
        );
        let documents = BTreeMap::from([(
            "src/index.ts".into(),
            ExpectedProviderDocument {
                language: H00_TYPESCRIPT_LANGUAGE.into(),
                content_identity: content_identity.clone(),
            },
        )]);
        let expected = ExpectedFullCertification {
            request_id: 12,
            provider: provider.clone(),
            authority: authority(),
            documents,
            analyses: BTreeMap::new(),
        };
        let frame = ProviderFrame {
            metadata: ProviderResponse {
                request_id: 12,
                session_id: authority().session_id,
                provider,
                body: ProviderResponseBody::FullCertification {
                    authority: authority(),
                    health: health(),
                    analyses: Vec::new(),
                    outcomes: vec![ProviderDocumentOutcome::Present {
                        document_path: "src/index.ts".into(),
                        language: H00_TYPESCRIPT_LANGUAGE.into(),
                        content_identity,
                        canonical_document_sha256: sha256_hex(&canonical),
                        attachment_index: 0,
                    }],
                },
            },
            attachments: vec![canonical],
        };

        let normalization = normalize_admitted_full_certification(
            &root,
            &root,
            frame,
            &expected,
            &ProviderFrameLimits::default(),
            &indexed_sources,
            &inventory,
        )
        .expect("admit TypeScript native certification");
        assert_eq!(
            normalization.evidence.receipt.status,
            CapabilityStatus::Complete
        );
        assert_eq!(
            normalization
                .canonical_snapshot
                .expect("complete TypeScript authority retains its canonical snapshot")
                .provider_id(),
            H00_TYPESCRIPT_PROVIDER_ID
        );
    }

    #[test]
    fn full_certification_accepts_distinct_per_root_toolchains_and_binds_each_identity() {
        let fixture = multi_root_fixture();
        let normalize = |beta_configuration| {
            normalize_admitted_full_certifications(
                &fixture.root,
                vec![
                    full_certification_for(
                        &fixture.alpha_root,
                        "alpha/src/lib.rs",
                        ALPHA_SOURCE,
                        31,
                        '1',
                    ),
                    full_certification_for(
                        &fixture.beta_root,
                        "beta/src/lib.rs",
                        BETA_SOURCE,
                        32,
                        beta_configuration,
                    ),
                ],
                &ProviderFrameLimits::default(),
                &fixture.indexed_sources,
                &fixture.inventory,
            )
            .expect("independent roots may use independent exact toolchains")
            .canonical_snapshot
            .expect("complete multi-root certification retains its snapshot")
        };

        let baseline = normalize('2');
        let changed_beta_toolchain = normalize('3');
        assert_ne!(
            baseline.identity_sha256(),
            changed_beta_toolchain.identity_sha256(),
            "changing one execution root's toolchain must change generation authority"
        );
    }

    #[test]
    fn full_recertification_reuses_only_byte_identical_source_syntax() {
        let mut fixture = multi_root_fixture();
        let baseline = normalize_admitted_full_certifications(
            &fixture.root,
            vec![
                full_certification_for(
                    &fixture.alpha_root,
                    "alpha/src/lib.rs",
                    ALPHA_SOURCE,
                    51,
                    '1',
                ),
                full_certification_for(&fixture.beta_root, "beta/src/lib.rs", BETA_SOURCE, 52, '2'),
            ],
            &ProviderFrameLimits::default(),
            &fixture.indexed_sources,
            &fixture.inventory,
        )
        .expect("baseline full certification");
        let prior_cache = baseline
            .source_syntax_cache
            .expect("baseline retains disposable syntax cache");

        let changed_beta = "pub fn beta_changed() {}\n";
        fs::write(fixture.beta_root.join("src/lib.rs"), changed_beta)
            .expect("change one source document");
        fixture.indexed_sources = [
            ("alpha/src/lib.rs", ALPHA_SOURCE),
            ("beta/src/lib.rs", changed_beta),
        ]
        .into_iter()
        .map(|(path, source)| IndexedSourceEvidence {
            relative_path: path.into(),
            language: "rust".into(),
            blake3_hash: blake3::hash(source.as_bytes()).to_hex().to_string(),
            cross_document_surface_sha256: Some(sha256_hex(source.as_bytes())),
        })
        .collect();
        let certifications = || {
            vec![
                full_certification_for(
                    &fixture.alpha_root,
                    "alpha/src/lib.rs",
                    ALPHA_SOURCE,
                    53,
                    '1',
                ),
                full_certification_for(
                    &fixture.beta_root,
                    "beta/src/lib.rs",
                    changed_beta,
                    54,
                    '2',
                ),
            ]
        };

        let uncached = normalize_admitted_full_certifications_with_source_syntax_cache(
            &fixture.root,
            certifications(),
            &ProviderFrameLimits::default(),
            &fixture.indexed_sources,
            &fixture.inventory,
            None,
        )
        .expect("uncached recertification positive control");
        assert_eq!(uncached.timings.source_documents, 2);
        assert_eq!(uncached.timings.syntax_cache_hits, 0);

        let cached = normalize_admitted_full_certifications_with_source_syntax_cache(
            &fixture.root,
            certifications(),
            &ProviderFrameLimits::default(),
            &fixture.indexed_sources,
            &fixture.inventory,
            Some(&prior_cache),
        )
        .expect("cached full recertification");
        assert_eq!(cached.timings.source_documents, 2);
        assert_eq!(
            cached.timings.syntax_cache_hits, 1,
            "the unchanged alpha source may be reused, while changed beta must be reparsed"
        );
        assert_eq!(cached.evidence, uncached.evidence);
        assert_eq!(
            cached
                .canonical_snapshot
                .as_ref()
                .expect("cached snapshot")
                .identity_sha256(),
            uncached
                .canonical_snapshot
                .as_ref()
                .expect("uncached snapshot")
                .identity_sha256(),
            "syntax acceleration must not alter full provider authority"
        );
    }

    #[test]
    fn affected_refresh_matches_the_configuration_of_its_exact_execution_root() {
        let fixture = multi_root_fixture();
        let baseline = normalize_admitted_full_certifications(
            &fixture.root,
            vec![
                full_certification_for(
                    &fixture.alpha_root,
                    "alpha/src/lib.rs",
                    ALPHA_SOURCE,
                    41,
                    '1',
                ),
                full_certification_for(&fixture.beta_root, "beta/src/lib.rs", BETA_SOURCE, 42, '2'),
            ],
            &ProviderFrameLimits::default(),
            &fixture.indexed_sources,
            &fixture.inventory,
        )
        .expect("multi-root baseline")
        .canonical_snapshot
        .expect("complete baseline snapshot");
        let parent = baseline.identity_sha256();
        let (frame, expected) =
            affected_refresh_for("beta/src/lib.rs", BETA_SOURCE, 43, '2', &parent);
        normalize_admitted_affected_refreshes(
            &fixture.root,
            baseline.clone(),
            vec![ProviderAffectedRefresh {
                execution_root: fixture.beta_root.clone(),
                frame,
                expected,
            }],
            &ProviderFrameLimits::default(),
            &fixture.indexed_sources,
            &fixture.inventory,
        )
        .expect("beta export matches beta toolchain identity");

        let (frame, expected) =
            affected_refresh_for("beta/src/lib.rs", BETA_SOURCE, 44, '2', &parent);
        assert!(matches!(
            normalize_admitted_affected_refreshes(
                &fixture.root,
                baseline,
                vec![ProviderAffectedRefresh {
                    execution_root: fixture.alpha_root.clone(),
                    frame,
                    expected,
                }],
                &ProviderFrameLimits::default(),
                &fixture.indexed_sources,
                &fixture.inventory,
            ),
            Err(SemanticProviderBridgeError::ProviderLineageMismatch)
        ));
    }

    /// FALSIFIER: an affected refresh may extend only the exact provider build
    /// that certified its parent. A wire-valid response from another binary
    /// with the same public ID/version/configuration is a different lineage,
    /// not a compatible incremental update.
    #[test]
    fn affected_refresh_rejects_changed_provider_build_identity() {
        let fixture = fixture();
        let baseline_provider = provider();
        let baseline = normalize_admitted_full_certification(
            &fixture.root,
            &fixture.root,
            full_frame(45),
            &ExpectedFullCertification {
                request_id: 45,
                provider: baseline_provider,
                authority: authority(),
                documents: expected_documents(),
                analyses: BTreeMap::new(),
            },
            &ProviderFrameLimits::default(),
            &fixture.indexed_sources,
            &fixture.inventory,
        )
        .expect("exact provider baseline")
        .canonical_snapshot
        .expect("complete baseline snapshot");
        let parent = baseline.identity_sha256();
        let (mut frame, mut expected) =
            affected_refresh_for("src/lib.rs", SOURCE, 46, 'e', &parent);
        let mut changed_provider = provider();
        changed_provider.executable_sha256 = digest('9');
        frame.metadata.provider = changed_provider.clone();
        expected.provider = changed_provider;

        assert!(matches!(
            normalize_admitted_affected_refreshes(
                &fixture.root,
                baseline,
                vec![ProviderAffectedRefresh {
                    execution_root: fixture.root.clone(),
                    frame,
                    expected,
                }],
                &ProviderFrameLimits::default(),
                &fixture.indexed_sources,
                &fixture.inventory,
            ),
            Err(SemanticProviderBridgeError::ProviderLineageMismatch)
        ));
    }

    #[test]
    fn affected_reuse_rejects_payload_from_a_different_parent_snapshot() {
        let fixture = fixture();
        let request_id = 61;
        let expected = ExpectedFullCertification {
            request_id,
            provider: provider(),
            authority: authority(),
            documents: expected_documents(),
            analyses: BTreeMap::new(),
        };
        let baseline = normalize_admitted_full_certification(
            &fixture.root,
            &fixture.root,
            full_frame(request_id),
            &expected,
            &ProviderFrameLimits::default(),
            &fixture.indexed_sources,
            &fixture.inventory,
        )
        .expect("admit reusable full baseline");
        let snapshot = baseline
            .canonical_snapshot
            .as_ref()
            .expect("complete baseline snapshot")
            .clone();
        let source_syntax_cache = baseline
            .source_syntax_cache
            .as_ref()
            .expect("complete baseline acceleration");
        let mut prior_payload = match baseline
            .evidence
            .payload
            .as_ref()
            .map(|payload| payload.payload())
        {
            Some(crate::code_intel_payload::ProviderPayload::Calls(payload)) => payload.clone(),
            Some(crate::code_intel_payload::ProviderPayload::CallableLiveness(_)) | None => {
                panic!("complete baseline Calls payload")
            }
        };
        let parent = snapshot.identity_sha256();
        assert_eq!(
            prior_payload.canonical_snapshot_sha256.as_deref(),
            Some(parent.as_str()),
            "positive control: the admitted baseline payload names its exact parent"
        );
        prior_payload.canonical_snapshot_sha256 = Some(digest('9'));

        let (frame, expected) =
            affected_refresh_for("src/lib.rs", SOURCE, 62, 'e', parent.as_str());
        assert!(matches!(
            normalize_admitted_affected_refreshes_with_source_syntax_cache(
                &fixture.root,
                &snapshot,
                vec![ProviderAffectedRefresh {
                    execution_root: fixture.root.clone(),
                    frame,
                    expected,
                }],
                &ProviderFrameLimits::default(),
                &fixture.indexed_sources,
                &fixture.inventory,
                AffectedNormalizationBasis {
                    source_syntax_cache: Some(source_syntax_cache),
                    prior_payload: Some(&prior_payload),
                    prior_supplemental_evidence: &[],
                },
            ),
            Err(SemanticProviderBridgeError::ParentSnapshotMismatch)
        ));
    }

    #[test]
    fn affected_refresh_rejects_wrong_parent_and_stock_provider_baselines() {
        let fixture = fixture();
        let sidecar_snapshot = canonical_scip_snapshot_from_provider_document_sets(
            &fixture.root,
            ScipProviderSpec::rust_analyzer_sidecar(),
            "1.97.1",
            &BTreeMap::from([(fixture.root.clone(), authority().configuration_sha256)]),
            vec![document()],
            &fixture.inventory,
        )
        .expect("sidecar snapshot");
        let wrong_parent = digest('9');
        let request_id = 21;
        let expected = ExpectedAffectedRefresh {
            request_id,
            provider: provider(),
            authority: authority(),
            parent_snapshot_sha256: wrong_parent.clone(),
            documents: expected_documents(),
            analyses: BTreeMap::new(),
            terminal_runtime_configuration: runtime_configuration(),
        };
        assert!(matches!(
            normalize_admitted_affected_refreshes(
                &fixture.root,
                sidecar_snapshot,
                vec![ProviderAffectedRefresh {
                    execution_root: fixture.root.clone(),
                    frame: affected_frame(request_id, wrong_parent),
                    expected,
                }],
                &ProviderFrameLimits::default(),
                &fixture.indexed_sources,
                &fixture.inventory,
            ),
            Err(SemanticProviderBridgeError::ParentSnapshotMismatch)
        ));

        let stock_snapshot = canonical_scip_snapshot_from_provider_document_sets(
            &fixture.root,
            ScipProviderSpec::rust_analyzer(),
            "1.97.1",
            &BTreeMap::from([(fixture.root.clone(), authority().configuration_sha256)]),
            vec![document()],
            &fixture.inventory,
        )
        .expect("stock snapshot");
        let parent = stock_snapshot.identity_sha256();
        let expected = ExpectedAffectedRefresh {
            request_id,
            provider: provider(),
            authority: authority(),
            parent_snapshot_sha256: parent.clone(),
            documents: expected_documents(),
            analyses: BTreeMap::new(),
            terminal_runtime_configuration: runtime_configuration(),
        };
        assert!(matches!(
            normalize_admitted_affected_refreshes(
                &fixture.root,
                stock_snapshot,
                vec![ProviderAffectedRefresh {
                    execution_root: fixture.root.clone(),
                    frame: affected_frame(request_id, parent),
                    expected,
                }],
                &ProviderFrameLimits::default(),
                &fixture.indexed_sources,
                &fixture.inventory,
            ),
            Err(SemanticProviderBridgeError::ProviderLineageMismatch)
        ));
    }
}
