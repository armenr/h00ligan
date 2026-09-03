//! Disposable cross-process cache for canonical semantic-provider snapshots.
//!
//! Immutable generation payloads remain the sole authority. Cache bytes are
//! bounded, never followed through symlinks, reconstructed with payload-owned
//! metadata, and accepted only when the resulting canonical identity exactly
//! matches the immutable payload. Any uncertainty is a cache miss.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::code_intel_domain::{CapabilityStatus, LanguageId};
#[cfg(test)]
use crate::code_intel_payload::normalize_provider_payload_typed;
use crate::code_intel_payload::{
    CallsProviderPayload, NormalizedProviderPayload, ProviderExecutionAuthority, ProviderPayload,
};
use crate::project_binding::{
    GeneratedArtifactState, GeneratedDirectoryState, PROVIDER_CACHE_DIRECTORY,
    inspect_generated_artifact, inspect_generated_directory,
};
use crate::scip_normalizer::{
    CanonicalSemanticBasis, ScipArtifactEvidence, ScipProviderSpec, rehydrate_canonical_snapshot,
};

const CANONICAL_SCIP_CACHE_DIRECTORY: &str = "canonical-scip-v2";
const CANONICAL_SCIP_CACHE_SCHEMA: &str = "h00/canonical-scip-cache/v2";
const MAX_CANONICAL_SCIP_CACHE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct CanonicalScipCacheEnvelope {
    schema_version: String,
    provider_id: String,
    provider_configurations_sha256: BTreeMap<String, String>,
    encoded_index: Vec<u8>,
}

fn canonical_cache_directory(data_root: &Path) -> PathBuf {
    data_root
        .join(PROVIDER_CACHE_DIRECTORY)
        .join(CANONICAL_SCIP_CACHE_DIRECTORY)
}

fn canonical_cache_file(data_root: &Path, identity: &str) -> PathBuf {
    canonical_cache_directory(data_root).join(format!("{identity}.cache"))
}

fn ensure_cache_directory(path: &Path) -> Result<(), String> {
    match inspect_generated_directory(path).map_err(|error| error.to_string())? {
        GeneratedDirectoryState::Directory => return Ok(()),
        GeneratedDirectoryState::Absent => {}
    }
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("cannot create semantic cache directory: {error}")),
    }
    match inspect_generated_directory(path).map_err(|error| error.to_string())? {
        GeneratedDirectoryState::Directory => Ok(()),
        GeneratedDirectoryState::Absent => {
            Err("semantic cache directory remained absent after creation".into())
        }
    }
}

fn prepare_cache_directory(data_root: &Path) -> Result<PathBuf, String> {
    let provider_cache = data_root.join(PROVIDER_CACHE_DIRECTORY);
    ensure_cache_directory(&provider_cache)?;
    let canonical_cache = canonical_cache_directory(data_root);
    ensure_cache_directory(&canonical_cache)?;
    Ok(canonical_cache)
}

fn existing_cache_directory(data_root: &Path) -> Option<PathBuf> {
    let provider_cache = data_root.join(PROVIDER_CACHE_DIRECTORY);
    if inspect_generated_directory(&provider_cache).ok()? != GeneratedDirectoryState::Directory {
        return None;
    }
    let canonical_cache = canonical_cache_directory(data_root);
    (inspect_generated_directory(&canonical_cache).ok()? == GeneratedDirectoryState::Directory)
        .then_some(canonical_cache)
}

fn open_regular_without_following(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn read_bounded_regular_file(path: &Path) -> Option<Vec<u8>> {
    let before = std::fs::symlink_metadata(path).ok()?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() == 0
        || before.len() > MAX_CANONICAL_SCIP_CACHE_BYTES as u64
    {
        return None;
    }
    let file = open_regular_without_following(path).ok()?;
    let opened = file.metadata().ok()?;
    if !opened.file_type().is_file()
        || opened.len() == 0
        || opened.len() > MAX_CANONICAL_SCIP_CACHE_BYTES as u64
    {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return None;
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_CANONICAL_SCIP_CACHE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= MAX_CANONICAL_SCIP_CACHE_BYTES).then_some(bytes)
}

fn encode_cache_envelope(
    snapshot: &crate::scip_normalizer::CanonicalScipSnapshot,
) -> Result<Vec<u8>, String> {
    let encoded_index = snapshot
        .encoded_index()
        .map_err(|error| error.to_string())?;
    let envelope = CanonicalScipCacheEnvelope {
        schema_version: CANONICAL_SCIP_CACHE_SCHEMA.into(),
        provider_id: snapshot.provider_id().into(),
        provider_configurations_sha256: snapshot.provider_configurations_sha256().clone(),
        encoded_index,
    };
    serialize_cache_envelope(envelope)
}

fn serialize_cache_envelope(envelope: CanonicalScipCacheEnvelope) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(
        envelope,
        bincode::config::standard().with_limit::<MAX_CANONICAL_SCIP_CACHE_BYTES>(),
    )
    .map_err(|error| format!("cannot encode semantic cache envelope: {error}"))
}

fn decode_cache_envelope(bytes: &[u8]) -> Option<CanonicalScipCacheEnvelope> {
    let (envelope, consumed) = bincode::serde::decode_from_slice::<CanonicalScipCacheEnvelope, _>(
        bytes,
        bincode::config::standard().with_limit::<MAX_CANONICAL_SCIP_CACHE_BYTES>(),
    )
    .ok()?;
    (consumed == bytes.len()
        && envelope.schema_version == CANONICAL_SCIP_CACHE_SCHEMA
        && !envelope.provider_id.trim().is_empty()
        && !envelope.encoded_index.is_empty())
    .then_some(envelope)
}

fn payload_snapshot_spec(payload: &CallsProviderPayload) -> Option<ScipProviderSpec> {
    if payload.receipt.status != CapabilityStatus::Complete {
        return None;
    }
    let language = payload.receipt.scope.language_id()?.0.as_str();
    let ProviderExecutionAuthority::ToolchainBound { ecosystem_id, .. } =
        &payload.execution_authority
    else {
        return None;
    };
    ScipProviderSpec::cacheable_from_lineage(&payload.receipt.provider_id.0, language)
        .filter(|spec| ecosystem_id.0 == spec.ecosystem)
}

fn payload_snapshot_identity(payload: &CallsProviderPayload) -> Option<(ScipProviderSpec, &str)> {
    let spec = payload_snapshot_spec(payload)?;
    Some((spec, payload.canonical_snapshot_sha256.as_deref()?))
}

/// Recover disposable canonical provider bases for an already validated
/// immutable generation. A missing, altered, oversized, unsupported, or unsafe
/// cache entry contributes no basis; ordinary provider execution remains the
/// fail-safe path.
pub fn load_cached_canonical_semantic_bases(
    data_root: &Path,
    repository_root: &Path,
    payloads: &[NormalizedProviderPayload],
) -> Vec<CanonicalSemanticBasis> {
    let Some(_cache_directory) = existing_cache_directory(data_root) else {
        return Vec::new();
    };
    payloads
        .iter()
        .filter_map(|provider_payload| {
            let ProviderPayload::Calls(payload) = provider_payload.payload() else {
                return None;
            };
            let (spec, identity) = payload_snapshot_identity(payload)?;
            let bytes = read_bounded_regular_file(&canonical_cache_file(data_root, identity))?;
            let envelope = decode_cache_envelope(&bytes)?;
            if envelope.provider_id != spec.provider_id {
                return None;
            }
            let snapshot = rehydrate_canonical_snapshot(
                repository_root,
                spec,
                payload,
                envelope.provider_configurations_sha256,
                &envelope.encoded_index,
            )
            .ok()?;
            Some(CanonicalSemanticBasis {
                snapshot,
                evidence: ScipArtifactEvidence {
                    language_id: LanguageId::new(spec.language),
                    receipt: payload.receipt.clone(),
                    payload: Some(provider_payload.clone()),
                },
                supplemental_evidence: payloads
                    .iter()
                    .filter(|candidate| {
                        let receipt = candidate.payload().receipt();
                        receipt.capability_id != "calls"
                            && receipt.status == CapabilityStatus::Complete
                            && receipt.provider_id == payload.receipt.provider_id
                            && receipt.provider_version == payload.receipt.provider_version
                            && receipt.scope.language_id() == Some(&LanguageId::new(spec.language))
                    })
                    .map(|candidate| ScipArtifactEvidence {
                        language_id: LanguageId::new(spec.language),
                        receipt: candidate.payload().receipt().clone(),
                        payload: Some(candidate.clone()),
                    })
                    .collect(),
                source_syntax_cache: None,
            })
        })
        .collect()
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Atomically persist exact canonical provider snapshots after their immutable
/// generation has committed. Failure is intentionally non-authoritative: the
/// caller reports it as an acceleration miss and leaves publication intact.
pub fn persist_cached_canonical_semantic_bases(
    data_root: &Path,
    bases: &[CanonicalSemanticBasis],
) -> Result<usize, String> {
    let eligible = bases
        .iter()
        .filter_map(|basis| {
            let ProviderPayload::Calls(payload) = basis.evidence.payload.as_ref()?.payload() else {
                return None;
            };
            let (spec, identity) = payload_snapshot_identity(payload)?;
            (basis.evidence.receipt == payload.receipt
                && basis.evidence.language_id.0 == spec.language
                && basis.snapshot.provider_id() == spec.provider_id
                && basis.snapshot.identity_sha256() == identity)
                .then_some((basis, identity.to_owned()))
        })
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Ok(0);
    }
    let cache_directory = prepare_cache_directory(data_root)?;
    let mut persisted = 0;
    let retained_identities = eligible
        .iter()
        .map(|(_, identity)| identity.clone())
        .collect::<BTreeSet<_>>();
    for (basis, identity) in eligible {
        let bytes = encode_cache_envelope(&basis.snapshot)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_SCIP_CACHE_BYTES {
            continue;
        }
        let target = canonical_cache_file(data_root, &identity);
        match inspect_generated_artifact(&target).map_err(|error| error.to_string())? {
            GeneratedArtifactState::Absent | GeneratedArtifactState::RegularFile => {}
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&cache_directory)
            .map_err(|error| format!("cannot create semantic cache staging file: {error}"))?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| format!("cannot durably write semantic cache entry: {error}"))?;
        temporary
            .persist(&target)
            .map_err(|error| format!("cannot atomically publish semantic cache entry: {error}"))?;
        sync_directory(&cache_directory)
            .map_err(|error| format!("cannot sync semantic cache directory: {error}"))?;
        persisted += 1;
    }
    for entry in std::fs::read_dir(&cache_directory)
        .map_err(|error| format!("cannot enumerate semantic cache directory: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("cannot inspect semantic cache directory entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect semantic cache entry type: {error}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let retained = name
            .strip_suffix(".cache")
            .is_some_and(|identity| retained_identities.contains(identity));
        if file_type.is_file() && !file_type.is_symlink() && !retained {
            std::fs::remove_file(entry.path()).map_err(|error| {
                format!("cannot remove superseded semantic cache entry: {error}")
            })?;
        }
    }
    sync_directory(&cache_directory)
        .map_err(|error| format!("cannot sync pruned semantic cache directory: {error}"))?;
    Ok(persisted)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use protobuf::Message as _;
    use scip::types::{Document, Index};
    use tempfile::TempDir;

    use super::*;
    use crate::code_intel_domain::{
        CALLS_CONFIGURATION_ID, CallsPopulation, CapabilityReceipt, CapabilityScope,
        ConfigurationId, EcosystemId,
    };
    use crate::code_intel_inventory::{
        InventorySource, build_project_inventory, semantic_provider_unit_execution_roots,
    };
    use crate::code_intel_payload::{
        ProviderExecutionAuthority, ProviderExecutionRootAuthority,
        ProviderGenerationReconstruction,
    };
    use crate::scip_normalizer::{
        ScipProviderSpec, canonical_scip_snapshot_from_provider_document_sets_with_identity,
    };

    struct Fixture {
        _temporary: TempDir,
        root: PathBuf,
        data_root: PathBuf,
        basis: CanonicalSemanticBasis,
    }

    fn go_fixture(
        spec: ScipProviderSpec,
        provider_version: &str,
        reuse_contract_id: &str,
    ) -> Fixture {
        let temporary = TempDir::new().expect("semantic cache fixture");
        let root = temporary.path().join("repo");
        let data_root = temporary.path().join("data");
        std::fs::create_dir_all(&root).expect("repository root");
        std::fs::create_dir_all(&data_root).expect("data root");
        std::fs::write(
            root.join("go.mod"),
            "module example.test/cache\n\ngo 1.27\n",
        )
        .expect("Go manifest");
        std::fs::write(root.join("main.go"), "package cache\nfunc Target() {}\n")
            .expect("Go source");
        let inventory = build_project_inventory(&root, &[InventorySource::new("main.go", "go")]);
        let units = semantic_provider_unit_execution_roots(&inventory, "go", "go")
            .into_keys()
            .collect::<Vec<_>>();
        assert!(!units.is_empty(), "positive semantic project-unit control");
        let mut document = Document::new();
        document.relative_path = "main.go".into();
        document.language = "go".into();
        let provider_implementation_sha256 = "c".repeat(64);
        let snapshot = canonical_scip_snapshot_from_provider_document_sets_with_identity(
            &root,
            spec,
            provider_version,
            Some(&provider_implementation_sha256),
            &BTreeMap::from([(root.clone(), "a".repeat(64))]),
            vec![document],
            &inventory,
        )
        .expect("canonical Go snapshot");
        let receipt = CapabilityReceipt::complete(
            "calls",
            spec.provider_id,
            provider_version,
            CapabilityScope::ProjectUnits {
                language_id: LanguageId::new("go"),
                project_unit_ids: units.clone(),
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            "b".repeat(64),
        );
        let payload = ProviderPayload::Calls(CallsProviderPayload {
            schema_version: crate::code_intel_payload::CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
            receipt: receipt.clone(),
            semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
            execution_authority: ProviderExecutionAuthority::ToolchainBound {
                resolver_policy_id: "fixture-resolver".into(),
                ecosystem_id: EcosystemId::new("go"),
                reuse_contract_id: reuse_contract_id.into(),
                provider_implementation_sha256,
                provider_inventory_sha256: "d".repeat(64),
                roots: vec![ProviderExecutionRootAuthority {
                    execution_root: String::new(),
                    project_unit_ids: units,
                    toolchain_fingerprint_sha256: "e".repeat(64),
                    provider_configuration_sha256: "a".repeat(64),
                    generation_reconstruction:
                        ProviderGenerationReconstruction::DeterministicInvocation,
                }],
            },
            canonical_snapshot_sha256: Some(snapshot.identity_sha256()),
            documents: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
            root_invocations: Vec::new(),
            callable_bindings: Vec::new(),
            coverage_exclusions: Vec::new(),
        });
        Fixture {
            _temporary: temporary,
            root,
            data_root,
            basis: CanonicalSemanticBasis {
                snapshot,
                evidence: ScipArtifactEvidence {
                    language_id: LanguageId::new("go"),
                    receipt,
                    payload: Some(
                        normalize_provider_payload_typed(&payload)
                            .expect("fixture Go payload is normalized"),
                    ),
                },
                supplemental_evidence: Vec::new(),
                source_syntax_cache: None,
            },
        }
    }

    fn fixture() -> Fixture {
        go_fixture(
            ScipProviderSpec::scip_go(),
            "fixture-scip-go",
            "fixture-scip-go-reuse",
        )
    }

    fn gopls_fixture() -> Fixture {
        go_fixture(
            ScipProviderSpec::gopls_sidecar(),
            h00ligan_provider_protocol::H00_GO_IMPLEMENTATION_V4,
            crate::code_intel_go_semantic_provider::GO_OPEN_SESSION_REUSE_CONTRACT_ID,
        )
    }

    fn rust_fixture() -> Fixture {
        let temporary = TempDir::new().expect("semantic cache fixture");
        let root = temporary.path().join("repo");
        let data_root = temporary.path().join("data");
        std::fs::create_dir_all(root.join("src")).expect("repository source root");
        std::fs::create_dir_all(&data_root).expect("data root");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"cache-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("Rust manifest");
        std::fs::write(root.join("src/lib.rs"), "pub fn target() {}\n").expect("Rust source");
        let inventory =
            build_project_inventory(&root, &[InventorySource::new("src/lib.rs", "rust")]);
        let units = semantic_provider_unit_execution_roots(&inventory, "rust", "cargo")
            .into_keys()
            .collect::<Vec<_>>();
        assert!(!units.is_empty(), "positive semantic project-unit control");
        let mut document = Document::new();
        document.relative_path = "src/lib.rs".into();
        document.language = "rust".into();
        let provider_implementation_sha256 = "3".repeat(64);
        let snapshot = canonical_scip_snapshot_from_provider_document_sets_with_identity(
            &root,
            ScipProviderSpec::rust_analyzer_sidecar(),
            "fixture-rust-analyzer",
            Some(&provider_implementation_sha256),
            &BTreeMap::from([(root.clone(), "1".repeat(64))]),
            vec![document],
            &inventory,
        )
        .expect("canonical Rust snapshot");
        let receipt = CapabilityReceipt::complete(
            "calls",
            h00ligan_provider_protocol::H00_RUST_ANALYZER_PROVIDER_ID,
            "fixture-rust-analyzer",
            CapabilityScope::ProjectUnits {
                language_id: LanguageId::new("rust"),
                project_unit_ids: units.clone(),
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            "2".repeat(64),
        );
        let payload = ProviderPayload::Calls(CallsProviderPayload {
            schema_version: crate::code_intel_payload::CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
            receipt: receipt.clone(),
            semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
            execution_authority: ProviderExecutionAuthority::ToolchainBound {
                resolver_policy_id: "fixture-resolver".into(),
                ecosystem_id: EcosystemId::new("cargo"),
                reuse_contract_id: "fixture-reuse".into(),
                provider_implementation_sha256,
                provider_inventory_sha256: "4".repeat(64),
                roots: vec![ProviderExecutionRootAuthority {
                    execution_root: String::new(),
                    project_unit_ids: units,
                    toolchain_fingerprint_sha256: "5".repeat(64),
                    // Durable Rust execution authority intentionally binds a
                    // stronger invocation contract than the canonical
                    // snapshot's provider-resolved workspace configuration.
                    provider_configuration_sha256: "6".repeat(64),
                    generation_reconstruction:
                        ProviderGenerationReconstruction::DeterministicInvocation,
                }],
            },
            canonical_snapshot_sha256: Some(snapshot.identity_sha256()),
            documents: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
            root_invocations: Vec::new(),
            callable_bindings: Vec::new(),
            coverage_exclusions: Vec::new(),
        });
        Fixture {
            _temporary: temporary,
            root,
            data_root,
            basis: CanonicalSemanticBasis {
                snapshot,
                evidence: ScipArtifactEvidence {
                    language_id: LanguageId::new("rust"),
                    receipt,
                    payload: Some(
                        normalize_provider_payload_typed(&payload)
                            .expect("fixture Rust payload is normalized"),
                    ),
                },
                supplemental_evidence: Vec::new(),
                source_syntax_cache: None,
            },
        }
    }

    fn payloads(basis: &CanonicalSemanticBasis) -> Vec<NormalizedProviderPayload> {
        vec![
            basis
                .evidence
                .payload
                .clone()
                .expect("fixture provider payload"),
        ]
    }

    /// FALSIFIER: every shipped provider whose canonical snapshot can be
    /// reconstructed across operations must be admitted by the cache lineage
    /// registry. Omitting one language silently converts exact reuse into a
    /// full semantic rebuild even though the publication remains current.
    #[test]
    fn cache_lineage_registry_covers_every_shipped_reconstructable_provider() {
        let specs = [
            ScipProviderSpec::scip_go(),
            ScipProviderSpec::gopls_sidecar(),
            ScipProviderSpec::rust_analyzer_sidecar(),
            ScipProviderSpec::pyrefly_sidecar(),
            ScipProviderSpec::typescript_native_sidecar(),
        ];
        assert_eq!(specs.len(), 5, "positive provider-population control");

        for spec in specs {
            let mut payload = CallsProviderPayload::new(CapabilityReceipt::complete(
                "calls",
                spec.provider_id,
                "fixture-provider-version",
                CapabilityScope::Language {
                    language_id: LanguageId::new(spec.language),
                    configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
                },
                "a".repeat(64),
            ));
            payload.execution_authority = ProviderExecutionAuthority::ToolchainBound {
                resolver_policy_id: "fixture-resolver".into(),
                ecosystem_id: EcosystemId::new(spec.ecosystem),
                reuse_contract_id: "fixture-reuse".into(),
                provider_implementation_sha256: "b".repeat(64),
                provider_inventory_sha256: "c".repeat(64),
                roots: Vec::new(),
            };
            assert_eq!(
                payload_snapshot_spec(&payload),
                Some(spec),
                "cache lineage registry omitted {} / {}",
                spec.language,
                spec.provider_id,
            );
        }
    }

    #[test]
    fn exact_cache_round_trip_recovers_the_same_canonical_identity() {
        let fixture = fixture();
        assert_eq!(
            persist_cached_canonical_semantic_bases(
                &fixture.data_root,
                std::slice::from_ref(&fixture.basis),
            )
            .expect("persist canonical cache"),
            1
        );
        let loaded = load_cached_canonical_semantic_bases(
            &fixture.data_root,
            &fixture.root,
            &payloads(&fixture.basis),
        );
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].snapshot.identity_sha256(),
            fixture.basis.snapshot.identity_sha256()
        );

        let stale = canonical_cache_file(&fixture.data_root, &"f".repeat(64));
        std::fs::write(&stale, b"superseded cache entry").expect("stale cache fixture");
        persist_cached_canonical_semantic_bases(
            &fixture.data_root,
            std::slice::from_ref(&fixture.basis),
        )
        .expect("repersist canonical cache");
        assert!(
            !stale.exists(),
            "successful publication must bound the cache to current identities"
        );
    }

    #[test]
    fn exact_persistent_gopls_cache_round_trip_recovers_the_same_canonical_identity() {
        let fixture = gopls_fixture();
        assert_eq!(
            persist_cached_canonical_semantic_bases(
                &fixture.data_root,
                std::slice::from_ref(&fixture.basis),
            )
            .expect("persist canonical persistent-Go cache"),
            1,
            "the shipped h00-gopls-scip lineage must be cross-process reusable"
        );
        let loaded = load_cached_canonical_semantic_bases(
            &fixture.data_root,
            &fixture.root,
            &payloads(&fixture.basis),
        );
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].snapshot.identity_sha256(),
            fixture.basis.snapshot.identity_sha256()
        );
        assert_eq!(loaded[0].evidence.language_id.0, "go");
        assert_eq!(
            loaded[0].evidence.receipt.provider_id.0,
            h00ligan_provider_protocol::H00_GO_PROVIDER_ID
        );
    }

    #[test]
    fn exact_toolchain_bound_rust_cache_round_trip_recovers_the_same_canonical_identity() {
        let fixture = rust_fixture();
        assert_eq!(
            persist_cached_canonical_semantic_bases(
                &fixture.data_root,
                std::slice::from_ref(&fixture.basis),
            )
            .expect("persist canonical Rust cache"),
            1,
            "a complete toolchain-bound Rust snapshot must be available to a later process"
        );
        let loaded = load_cached_canonical_semantic_bases(
            &fixture.data_root,
            &fixture.root,
            &payloads(&fixture.basis),
        );
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].snapshot.identity_sha256(),
            fixture.basis.snapshot.identity_sha256()
        );
        assert_eq!(loaded[0].evidence.language_id.0, "rust");
    }

    #[test]
    fn missing_or_corrupt_cache_grants_no_semantic_basis() {
        let fixture = fixture();
        let payloads = payloads(&fixture.basis);
        assert!(
            load_cached_canonical_semantic_bases(&fixture.data_root, &fixture.root, &payloads)
                .is_empty(),
            "missing-cache control"
        );
        persist_cached_canonical_semantic_bases(
            &fixture.data_root,
            std::slice::from_ref(&fixture.basis),
        )
        .expect("persist canonical cache");
        let identity = fixture.basis.snapshot.identity_sha256();
        std::fs::write(
            canonical_cache_file(&fixture.data_root, &identity),
            b"not SCIP",
        )
        .expect("corrupt cache fixture");
        assert!(
            load_cached_canonical_semantic_bases(&fixture.data_root, &fixture.root, &payloads)
                .is_empty(),
            "corrupt cache cannot grant reuse"
        );
    }

    #[test]
    fn decodable_but_altered_cache_must_match_the_immutable_identity() {
        let fixture = fixture();
        persist_cached_canonical_semantic_bases(
            &fixture.data_root,
            std::slice::from_ref(&fixture.basis),
        )
        .expect("persist canonical cache");
        let identity = fixture.basis.snapshot.identity_sha256();
        let cache_file = canonical_cache_file(&fixture.data_root, &identity);
        let mut envelope = decode_cache_envelope(
            &std::fs::read(&cache_file).expect("read canonical cache fixture"),
        )
        .expect("decode canonical cache envelope");
        let mut index = Index::parse_from_bytes(&envelope.encoded_index)
            .expect("decode canonical SCIP fixture");
        index.documents[0].relative_path = "altered.go".into();
        envelope.encoded_index = index.write_to_bytes().expect("encode altered valid SCIP");
        std::fs::write(
            &cache_file,
            serialize_cache_envelope(envelope).expect("encode altered cache envelope"),
        )
        .expect("write altered valid cache fixture");

        assert!(
            load_cached_canonical_semantic_bases(
                &fixture.data_root,
                &fixture.root,
                &payloads(&fixture.basis),
            )
            .is_empty(),
            "decodable bytes with the wrong canonical identity cannot grant reuse"
        );
    }

    #[test]
    fn altered_cache_configuration_metadata_grants_no_semantic_basis() {
        let fixture = rust_fixture();
        persist_cached_canonical_semantic_bases(
            &fixture.data_root,
            std::slice::from_ref(&fixture.basis),
        )
        .expect("persist canonical Rust cache");
        let identity = fixture.basis.snapshot.identity_sha256();
        let cache_file = canonical_cache_file(&fixture.data_root, &identity);
        let mut envelope = decode_cache_envelope(
            &std::fs::read(&cache_file).expect("read canonical cache fixture"),
        )
        .expect("decode canonical cache envelope");
        let configuration = envelope
            .provider_configurations_sha256
            .values_mut()
            .next()
            .expect("positive configuration-metadata control");
        *configuration = "f".repeat(64);
        std::fs::write(
            &cache_file,
            serialize_cache_envelope(envelope).expect("encode altered cache envelope"),
        )
        .expect("write altered cache metadata fixture");

        assert!(
            load_cached_canonical_semantic_bases(
                &fixture.data_root,
                &fixture.root,
                &payloads(&fixture.basis),
            )
            .is_empty(),
            "untrusted cache metadata cannot override the immutable snapshot identity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cache_entry_is_never_followed() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        persist_cached_canonical_semantic_bases(
            &fixture.data_root,
            std::slice::from_ref(&fixture.basis),
        )
        .expect("persist canonical cache");
        let identity = fixture.basis.snapshot.identity_sha256();
        let cache_file = canonical_cache_file(&fixture.data_root, &identity);
        let bytes = std::fs::read(&cache_file).expect("canonical bytes");
        let sentinel = fixture.data_root.join("outside-cache.scip");
        std::fs::write(&sentinel, &bytes).expect("symlink sentinel");
        std::fs::remove_file(&cache_file).expect("remove owned cache fixture");
        symlink(&sentinel, &cache_file).expect("symlink cache fixture");

        assert!(
            load_cached_canonical_semantic_bases(
                &fixture.data_root,
                &fixture.root,
                &payloads(&fixture.basis),
            )
            .is_empty(),
            "symlinked cache cannot grant reuse"
        );
        assert_eq!(
            std::fs::read(&sentinel).expect("sentinel remains readable"),
            bytes
        );
    }
}
