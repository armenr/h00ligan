//! Persistent Pyrefly semantic provider for h00ligan.
//!
//! The provider is linked into the one-file h00ligan product and entered only
//! through its private same-executable dispatch argument. Pyrefly owns parsing,
//! module resolution, type solving, and incremental invalidation; this adapter
//! owns protocol authority and deterministic SCIP projection.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, BufWriter};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, bail};
use h00ligan_provider_protocol::{
    H00_PYREFLY_IMPLEMENTATION_V1, H00_PYREFLY_LANGUAGE, H00_PYREFLY_PROVIDER_ID,
    H00_PYREFLY_UPSTREAM_COMMIT, H00_PYREFLY_UPSTREAM_VERSION, ProviderAuthority,
    ProviderComponentHealth, ProviderDocumentOutcome, ProviderFrame, ProviderFrameLimits,
    ProviderHealthEvidence, ProviderIdentity, ProviderRequest, ProviderRequestBody,
    ProviderResponse, ProviderResponseBody, ProviderRuntimeConfiguration, ProviderSemanticInputs,
    ProviderSourceChange, ProviderSourceIdentity, PROVIDER_PARENT_PID_ENV,
    RESOLVED_TOOLCHAIN_SHA256_ENV, SEMANTIC_PROVIDER_PROTOCOL, capture_provider_semantic_inputs,
    provider_runtime_configuration, provider_semantic_inputs_sha256,
    provider_semantic_paths_are_current, pyrefly_source_components, read_provider_frame,
    sha256_hex, source_population_sha256, validate_provider_request,
    validate_runtime_configuration, write_provider_frame,
};
use protobuf::{Enum as _, EnumOrUnknown, Message as _, MessageField};
use pyrefly::h00_semantic::{
    H00AuthorityFacts, H00ByteSpan, H00ConfigurationBinding, H00DeclarationFact,
    H00DeclarationKind, H00SemanticFacts, H00SemanticSession,
};
use scip::symbol::format_symbol;
use scip::types::{
    Descriptor, Document, Occurrence, Package, PositionEncoding, Relationship, Symbol,
    SymbolInformation, SymbolRole, descriptor, symbol_information,
};

const PATCH_SHA256: &str = env!("H00_PYREFLY_PATCH_SHA256");
const CONFIG_CANDIDATE_NAMES: &[&str] = &[
    ".pyrefly.toml",
    "mypy.ini",
    "pyproject.toml",
    "pyrefly.toml",
    "pyrightconfig.json",
];

struct ProviderTerminal {
    body: ProviderResponseBody,
    attachments: Vec<Vec<u8>>,
}

impl ProviderTerminal {
    const fn empty(body: ProviderResponseBody) -> Self {
        Self {
            body,
            attachments: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct PythonSymbol {
    symbol: String,
    display_name: String,
    kind: symbol_information::Kind,
    relationships: Vec<Relationship>,
}

struct RootSession {
    repository_root: PathBuf,
    execution_prefix: String,
    semantic: H00SemanticSession,
    authority: ProviderAuthority,
    semantic_inputs: ProviderSemanticInputs,
    health: ProviderHealthEvidence,
    sources: BTreeMap<String, ProviderSourceIdentity>,
    source_bytes: BTreeMap<String, String>,
    absolute_paths: BTreeMap<String, PathBuf>,
    facts_by_document: BTreeMap<String, H00SemanticFacts>,
    symbols: BTreeMap<(PathBuf, String), PythonSymbol>,
    package_name: String,
}

/// Run one process-owned framed provider session.
#[allow(clippy::significant_drop_tightening)]
pub fn run_stdio() -> anyhow::Result<()> {
    arm_parent_liveness_guard()?;
    let limits = ProviderFrameLimits::default();
    let identity = executable_identity()?;
    let runtime_configuration = observe_runtime_configuration()?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = BufWriter::new(stdout.lock());
    let mut session = None::<RootSession>;
    let mut last_request_id = 0_u64;

    loop {
        let frame = read_provider_frame::<_, ProviderRequest>(&mut input, &limits)
            .context("read Pyrefly semantic-provider request")?;
        let request_id = frame.metadata.request_id;
        let session_id = frame.metadata.session_id.clone();
        let terminal = match validate_provider_request(&frame, &limits) {
            Ok(()) if request_id > last_request_id => {
                last_request_id = request_id;
                match handle_request(
                    &identity,
                    &runtime_configuration,
                    &limits,
                    &mut session,
                    frame,
                ) {
                    Ok(terminal) => terminal,
                    Err(error) => ProviderTerminal::empty(ProviderResponseBody::Error {
                        code: "request_failed".into(),
                        message: bounded_error(&error),
                        retryable: false,
                    }),
                }
            }
            Ok(()) => ProviderTerminal::empty(ProviderResponseBody::Error {
                code: "replayed_request".into(),
                message: "request ID is not strictly monotonic for this process".into(),
                retryable: false,
            }),
            Err(error) => ProviderTerminal::empty(ProviderResponseBody::Error {
                code: "invalid_request".into(),
                message: bounded_text(&error.to_string(), 1024),
                retryable: false,
            }),
        };
        let close = matches!(&terminal.body, ProviderResponseBody::SessionClosed);
        write_provider_frame(
            &mut output,
            &ProviderFrame {
                metadata: ProviderResponse {
                    request_id,
                    session_id,
                    provider: identity.clone(),
                    body: terminal.body,
                },
                attachments: terminal.attachments,
            },
            &limits,
        )
        .context("write Pyrefly semantic-provider response")?;
        if close {
            return Ok(());
        }
    }
}

fn handle_request(
    identity: &ProviderIdentity,
    runtime_configuration: &ProviderRuntimeConfiguration,
    limits: &ProviderFrameLimits,
    session: &mut Option<RootSession>,
    frame: ProviderFrame<ProviderRequest>,
) -> anyhow::Result<ProviderTerminal> {
    let ProviderFrame {
        metadata: request,
        attachments,
    } = frame;
    if request.expected_provider != *identity {
        bail!("requested provider build identity differs from this executable");
    }
    if !matches!(&request.body, ProviderRequestBody::CloseSession)
        && observe_runtime_configuration()? != *runtime_configuration
    {
        bail!("Pyrefly provider runtime changed after process admission");
    }
    if let Some(active) = session.as_ref()
        && !matches!(
            &request.body,
            ProviderRequestBody::OpenSession { .. }
                | ProviderRequestBody::ReconfigureSession { .. }
                | ProviderRequestBody::CloseSession
        )
    {
        active.verify_authority_inputs(limits)?;
    }

    match request.body {
        ProviderRequestBody::Hello => Ok(ProviderTerminal::empty(ProviderResponseBody::Hello {
            limits: *limits,
            runtime_configuration: runtime_configuration.clone(),
        })),
        ProviderRequestBody::OpenSession {
            repository_root,
            execution_root,
            execution_prefix,
            authority,
            sources,
            expected_semantic_inputs,
        } => {
            if session.is_some() || !attachments.is_empty() {
                bail!("one Pyrefly provider process owns exactly one root session");
            }
            let opened = RootSession::open(
                &request.session_id,
                runtime_configuration,
                limits,
                repository_root,
                execution_root,
                execution_prefix,
                authority,
                sources,
                expected_semantic_inputs,
            )?;
            let terminal = ProviderTerminal::empty(ProviderResponseBody::SessionOpened {
                authority: opened.authority.clone(),
                health: opened.health.clone(),
                semantic_inputs: opened.semantic_inputs.clone(),
            });
            *session = Some(opened);
            Ok(terminal)
        }
        ProviderRequestBody::ReconfigureSession { .. } => {
            bail!("Pyrefly project-input changes require a fresh provider session")
        }
        ProviderRequestBody::ApplyEpoch {
            previous_authority,
            next_authority,
            changes,
        } => {
            let active = exact_session(session, &request.session_id, &previous_authority)?;
            active.apply_epoch(next_authority, changes, attachments, limits)?;
            Ok(ProviderTerminal::empty(
                ProviderResponseBody::EpochApplied {
                    authority: active.authority.clone(),
                    health: active.health.clone(),
                },
            ))
        }
        ProviderRequestBody::RefreshAffected {
            previous_authority,
            next_authority,
            changes,
            parent_snapshot_sha256,
            documents,
            analyses,
        } => {
            if !analyses.is_empty() {
                bail!("Pyrefly provider does not implement requested semantic analyses");
            }
            let active = exact_session(session, &request.session_id, &previous_authority)?;
            active.apply_epoch(next_authority, changes, attachments, limits)?;
            let (outcomes, attachments) = active.export_documents(documents, limits)?;
            let terminal_runtime_configuration = observe_runtime_configuration()?;
            if terminal_runtime_configuration != *runtime_configuration {
                bail!("Pyrefly provider runtime changed during affected refresh");
            }
            Ok(ProviderTerminal {
                body: ProviderResponseBody::AffectedRefreshed {
                    authority: active.authority.clone(),
                    parent_snapshot_sha256,
                    health: active.health.clone(),
                    runtime_configuration: terminal_runtime_configuration,
                    outcomes,
                    analyses: Vec::new(),
                },
                attachments,
            })
        }
        ProviderRequestBody::CertifyFull {
            authority,
            analyses,
        } => {
            if !analyses.is_empty() {
                bail!("Pyrefly provider does not implement requested semantic analyses");
            }
            if !attachments.is_empty() {
                bail!("full certification carries unexpected attachments");
            }
            let active = exact_session(session, &request.session_id, &authority)?;
            let documents = active.sources.keys().cloned().collect::<Vec<_>>();
            let (outcomes, attachments) = active.export_documents(documents, limits)?;
            Ok(ProviderTerminal {
                body: ProviderResponseBody::FullCertification {
                    authority,
                    health: active.health.clone(),
                    outcomes,
                    analyses: Vec::new(),
                },
                attachments,
            })
        }
        ProviderRequestBody::CloseSession => {
            if !attachments.is_empty() {
                bail!("close-session carries unexpected attachments");
            }
            Ok(ProviderTerminal::empty(ProviderResponseBody::SessionClosed))
        }
    }
}

impl RootSession {
    #[allow(clippy::too_many_arguments)]
    fn open(
        session_id: &str,
        runtime_configuration: &ProviderRuntimeConfiguration,
        limits: &ProviderFrameLimits,
        repository_root: String,
        execution_root: String,
        execution_prefix: String,
        mut authority: ProviderAuthority,
        source_population: Vec<ProviderSourceIdentity>,
        expected_semantic_inputs: Option<ProviderSemanticInputs>,
    ) -> anyhow::Result<Self> {
        if expected_semantic_inputs.is_some() {
            bail!("Pyrefly semantic inputs are provider-observed");
        }
        let repository_root = canonical_directory(Path::new(&repository_root))?;
        let execution_root = canonical_directory(Path::new(&execution_root))?;
        if !execution_root.starts_with(&repository_root) {
            bail!("Pyrefly execution root escapes the repository root");
        }
        let actual_prefix = repository_prefix(&repository_root, &execution_root)?;
        if actual_prefix != execution_prefix {
            bail!("Pyrefly execution prefix differs from canonical roots");
        }
        let repository_text = path_text(&repository_root)?;
        if authority.session_id != session_id
            || authority.root_sha256 != sha256_hex(repository_text.as_bytes())
            || authority.configuration_sha256 != runtime_configuration.configuration_sha256
            || authority.workspace_resolution_sha256.is_some()
            || authority.semantic_inputs_sha256.is_some()
            || authority.source_epoch == 0
        {
            bail!("Pyrefly open-session authority differs from canonical roots or runtime");
        }
        if source_population_sha256(&source_population, limits)? != authority.population_sha256 {
            bail!("Pyrefly open-session source population mismatch");
        }

        let mut sources = BTreeMap::new();
        let mut source_bytes = BTreeMap::new();
        let mut absolute_paths = BTreeMap::new();
        let mut admitted = Vec::with_capacity(source_population.len());
        for source in source_population {
            validate_source_identity(&source)?;
            if source.language != H00_PYREFLY_LANGUAGE {
                bail!("non-Python source entered the Pyrefly provider session");
            }
            if sources
                .insert(source.document_path.clone(), source.clone())
                .is_some()
            {
                bail!("duplicate Pyrefly source {}", source.document_path);
            }
            let absolute = canonical_source_path(&repository_root, &source.document_path)?;
            if !absolute.starts_with(&execution_root) {
                bail!("Pyrefly source is outside its execution root");
            }
            let bytes = std::fs::read(&absolute)
                .with_context(|| format!("read admitted Python source {}", source.document_path))?;
            if sha256_hex(&bytes) != source.content_sha256 {
                bail!("admitted Python source hash mismatch");
            }
            let text = String::from_utf8(bytes)
                .with_context(|| format!("Python source is not UTF-8: {}", source.document_path))?;
            absolute_paths.insert(source.document_path.clone(), absolute.clone());
            source_bytes.insert(source.document_path.clone(), text.clone());
            admitted.push((absolute, text));
        }
        if sources.is_empty() {
            bail!("Pyrefly source population is empty");
        }

        let candidate_paths = configuration_candidate_paths(
            &repository_root,
            absolute_paths.values().map(PathBuf::as_path),
            limits,
        )?;
        let before_candidates = capture_provider_semantic_inputs(
            &repository_root,
            &candidate_paths,
            &BTreeSet::new(),
            limits,
        )?;
        let semantic = H00SemanticSession::open(&repository_root, admitted)
            .context("open exact-byte Pyrefly solved state")?;
        let initial_authority = semantic.authority_facts()?;
        let semantic_paths = semantic_input_paths(
            &repository_root,
            &candidate_paths,
            &initial_authority,
            limits,
        )?;
        let semantic_inputs = capture_provider_semantic_inputs(
            &repository_root,
            &semantic_paths,
            &BTreeSet::new(),
            limits,
        )?;
        let after_candidates = capture_provider_semantic_inputs(
            &repository_root,
            &candidate_paths,
            &BTreeSet::new(),
            limits,
        )?;
        if before_candidates != after_candidates {
            bail!("Python configuration candidates changed during session admission");
        }
        semantic.refresh();
        let final_authority = semantic.authority_facts()?;
        let final_paths =
            semantic_input_paths(&repository_root, &candidate_paths, &final_authority, limits)?;
        let final_inputs = capture_provider_semantic_inputs(
            &repository_root,
            &final_paths,
            &BTreeSet::new(),
            limits,
        )?;
        if initial_authority != final_authority
            || semantic_paths != final_paths
            || semantic_inputs != final_inputs
        {
            bail!("Python workspace authority changed during session admission");
        }

        let facts_by_document = collect_facts(&semantic, &absolute_paths)?;
        let package_name = package_name(&execution_prefix);
        let symbols = build_symbol_catalog(&facts_by_document, &package_name)?;
        let workspace_resolution_sha256 =
            workspace_resolution_sha256(&execution_prefix, &package_name, &final_authority)?;
        let semantic_inputs_sha256 = provider_semantic_inputs_sha256(&semantic_inputs, limits)?;
        authority.workspace_resolution_sha256 = Some(workspace_resolution_sha256);
        authority.semantic_inputs_sha256 = Some(semantic_inputs_sha256);

        Ok(Self {
            repository_root,
            execution_prefix,
            semantic,
            authority,
            semantic_inputs,
            health: healthy_provider(),
            sources,
            source_bytes,
            absolute_paths,
            facts_by_document,
            symbols,
            package_name,
        })
    }

    fn verify_authority_inputs(&self, limits: &ProviderFrameLimits) -> anyhow::Result<()> {
        if !provider_semantic_paths_are_current(
            &self.repository_root,
            &self.semantic_inputs,
            limits,
        )? {
            bail!("Python project inputs changed after session admission");
        }
        let observed = self.semantic.authority_facts()?;
        if workspace_resolution_sha256(&self.execution_prefix, &self.package_name, &observed)?
            != self
                .authority
                .workspace_resolution_sha256
                .as_deref()
                .context("Pyrefly authority omitted workspace resolution")?
        {
            bail!("Pyrefly workspace resolution changed after session admission");
        }
        Ok(())
    }

    fn apply_epoch(
        &mut self,
        next_authority: ProviderAuthority,
        changes: Vec<ProviderSourceChange>,
        attachments: Vec<Vec<u8>>,
        limits: &ProviderFrameLimits,
    ) -> anyhow::Result<()> {
        if changes.is_empty() {
            bail!("Pyrefly source replacement population is empty");
        }
        let mut expected = self.authority.clone();
        expected.population_sha256 = next_authority.population_sha256.clone();
        expected.source_epoch = expected
            .source_epoch
            .checked_add(1)
            .context("Pyrefly source epoch overflow")?;
        if next_authority != expected {
            bail!("invalid Pyrefly provider authority transition");
        }

        let mut next_sources = self.sources.clone();
        let mut next_bytes = self.source_bytes.clone();
        let mut replacements = Vec::with_capacity(changes.len());
        let mut changed_documents = BTreeSet::new();
        let mut claimed_attachments = BTreeSet::new();
        for change in changes {
            let ProviderSourceChange::Replace {
                document_path,
                language,
                previous_content_identity,
                previous_content_sha256,
                content_identity,
                content_sha256,
                attachment_index,
            } = change;
            if language != H00_PYREFLY_LANGUAGE || !changed_documents.insert(document_path.clone())
            {
                bail!("invalid or duplicate Pyrefly source replacement");
            }
            let prior = self
                .sources
                .get(&document_path)
                .with_context(|| format!("replacement is outside session: {document_path}"))?;
            if prior.content_identity != previous_content_identity
                || prior.content_sha256 != previous_content_sha256
            {
                bail!("Pyrefly replacement prior identity mismatch");
            }
            if !claimed_attachments.insert(attachment_index) {
                bail!("Pyrefly replacement attachment is reused");
            }
            let bytes = attachments
                .get(attachment_index as usize)
                .with_context(|| format!("replacement attachment missing for {document_path}"))?;
            if sha256_hex(bytes) != content_sha256
                || content_identity == previous_content_identity
                || content_sha256 == previous_content_sha256
            {
                bail!("Pyrefly replacement content identity mismatch");
            }
            let text = std::str::from_utf8(bytes)
                .with_context(|| format!("replacement is not UTF-8: {document_path}"))?
                .to_owned();
            let absolute = self
                .absolute_paths
                .get(&document_path)
                .context("replacement source path disappeared")?
                .clone();
            replacements.push((absolute, text.clone()));
            next_bytes.insert(document_path.clone(), text);
            next_sources.insert(
                document_path.clone(),
                ProviderSourceIdentity {
                    document_path,
                    language,
                    content_identity,
                    content_sha256,
                },
            );
        }
        if claimed_attachments.len() != attachments.len() {
            bail!("Pyrefly replacement frame contains unclaimed attachments");
        }
        if source_population_sha256(&next_sources.values().cloned().collect::<Vec<_>>(), limits)?
            != next_authority.population_sha256
        {
            bail!("Pyrefly replacement population differs from next authority");
        }

        self.semantic.apply(replacements)?;
        self.sources = next_sources;
        self.source_bytes = next_bytes;
        for document_path in changed_documents {
            let absolute = self
                .absolute_paths
                .get(&document_path)
                .context("changed Pyrefly path disappeared")?;
            self.facts_by_document
                .insert(document_path, self.semantic.facts(absolute)?);
        }
        self.symbols = build_symbol_catalog(&self.facts_by_document, &self.package_name)?;
        self.authority = next_authority;
        self.verify_authority_inputs(limits)
    }

    fn export_documents(
        &self,
        requested: Vec<String>,
        limits: &ProviderFrameLimits,
    ) -> anyhow::Result<(Vec<ProviderDocumentOutcome>, Vec<Vec<u8>>)> {
        let requested = requested.into_iter().collect::<BTreeSet<_>>();
        if requested.is_empty() || requested.len() > limits.max_document_paths {
            bail!("Pyrefly export population is empty or oversized");
        }
        let mut attachments = Vec::with_capacity(requested.len());
        let mut outcomes = Vec::with_capacity(requested.len());
        for document_path in requested {
            let source = self.sources.get(&document_path).with_context(|| {
                format!("export path is outside Pyrefly session: {document_path}")
            })?;
            let absolute = self
                .absolute_paths
                .get(&document_path)
                .context("export source path disappeared")?;
            let facts = self.semantic.facts(absolute)?;
            let document = build_document(
                &document_path,
                self.source_bytes
                    .get(&document_path)
                    .context("export source bytes disappeared")?,
                &facts,
                &self.symbols,
            )?;
            let bytes = document
                .write_to_bytes()
                .with_context(|| format!("serialize canonical Pyrefly document {document_path}"))?;
            if bytes.is_empty() {
                bail!("canonical Pyrefly document is empty");
            }
            let attachment_index = attachments.len() as u32;
            let canonical_document_sha256 = sha256_hex(&bytes);
            attachments.push(bytes);
            outcomes.push(ProviderDocumentOutcome::Present {
                document_path,
                language: H00_PYREFLY_LANGUAGE.into(),
                content_identity: source.content_identity.clone(),
                canonical_document_sha256,
                attachment_index,
            });
        }
        self.verify_authority_inputs(limits)?;
        Ok((outcomes, attachments))
    }
}

fn collect_facts(
    semantic: &H00SemanticSession,
    paths: &BTreeMap<String, PathBuf>,
) -> anyhow::Result<BTreeMap<String, H00SemanticFacts>> {
    paths
        .iter()
        .map(|(document_path, absolute)| Ok((document_path.clone(), semantic.facts(absolute)?)))
        .collect()
}

fn build_symbol_catalog(
    facts_by_document: &BTreeMap<String, H00SemanticFacts>,
    package_name: &str,
) -> anyhow::Result<BTreeMap<(PathBuf, String), PythonSymbol>> {
    let mut declaration_kinds = BTreeMap::<String, H00DeclarationKind>::new();
    for facts in facts_by_document.values() {
        for declaration in &facts.declarations {
            if !supported_declaration(&declaration.kind) {
                continue;
            }
            if declaration_kinds
                .insert(declaration.name.clone(), declaration.kind.clone())
                .is_some()
            {
                bail!("Pyrefly emitted a duplicate qualified declaration name");
            }
        }
    }

    let mut catalog = BTreeMap::new();
    let mut declarations = BTreeMap::<String, H00DeclarationFact>::new();
    for facts in facts_by_document.values() {
        let file = PathBuf::from(&facts.file);
        for declaration in &facts.declarations {
            if !supported_declaration(&declaration.kind) {
                continue;
            }
            let symbol = python_symbol(package_name, declaration, &declaration_kinds)?;
            let display_name = declaration
                .name
                .rsplit('.')
                .next()
                .context("empty Pyrefly declaration name")?
                .to_owned();
            let kind = scip_kind(&declaration.kind);
            let key = (file.clone(), declaration.name.clone());
            if catalog
                .insert(
                    key,
                    PythonSymbol {
                        symbol,
                        display_name,
                        kind,
                        relationships: Vec::new(),
                    },
                )
                .is_some()
                || declarations
                    .insert(declaration.name.clone(), declaration.clone())
                    .is_some()
            {
                bail!("Pyrefly emitted a duplicate repository declaration");
            }
        }
    }

    let by_name = catalog
        .iter()
        .map(|((_, name), symbol)| (name.clone(), symbol.symbol.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut relationship_targets = BTreeMap::<String, BTreeSet<String>>::new();
    for (name, declaration) in &declarations {
        if declaration.kind == H00DeclarationKind::Class {
            for base in &declaration.bases {
                if let Some(target) = by_name.get(base) {
                    relationship_targets
                        .entry(name.clone())
                        .or_default()
                        .insert(target.clone());
                }
            }
            continue;
        }
        if !matches!(
            declaration.kind,
            H00DeclarationKind::Method | H00DeclarationKind::Constructor
        ) {
            continue;
        }
        let Some((owner, method)) = name.rsplit_once('.') else {
            continue;
        };
        let Some(owner_declaration) = declarations.get(owner) else {
            continue;
        };
        for base in &owner_declaration.bases {
            let inherited = format!("{base}.{method}");
            if let Some(target) = by_name.get(&inherited) {
                relationship_targets
                    .entry(name.clone())
                    .or_default()
                    .insert(target.clone());
            }
        }
    }
    for ((_, name), symbol) in &mut catalog {
        symbol.relationships = relationship_targets
            .get(name)
            .into_iter()
            .flatten()
            .map(|target| {
                let mut relationship = Relationship::new();
                relationship.symbol = target.clone();
                relationship.is_implementation = true;
                relationship
            })
            .collect();
    }
    Ok(catalog)
}

fn build_document(
    document_path: &str,
    source: &str,
    facts: &H00SemanticFacts,
    symbols: &BTreeMap<(PathBuf, String), PythonSymbol>,
) -> anyhow::Result<Document> {
    let fact_path = PathBuf::from(&facts.file);
    let mut occurrences = Vec::new();
    let mut information = Vec::new();
    for declaration in &facts.declarations {
        let Some(symbol) = symbols.get(&(fact_path.clone(), declaration.name.clone())) else {
            continue;
        };
        let mut occurrence = Occurrence::new();
        occurrence.range = scip_range(source, &declaration.name_span)?;
        occurrence.symbol = symbol.symbol.clone();
        occurrence.symbol_roles = SymbolRole::Definition.value();
        occurrence.enclosing_range = scip_range(source, &declaration.extent_span)?;
        occurrences.push(occurrence);

        let mut details = SymbolInformation::new();
        details.symbol = symbol.symbol.clone();
        details.display_name = symbol.display_name.clone();
        details.kind = EnumOrUnknown::new(symbol.kind);
        details.relationships = symbol.relationships.clone();
        information.push(details);
    }

    let mut references = BTreeSet::new();
    for reference in &facts.references {
        let Some(target_file) = reference.target_file.as_ref() else {
            continue;
        };
        let Some(target) =
            symbols.get(&(PathBuf::from(target_file), reference.target_name.clone()))
        else {
            continue;
        };
        let range = scip_range(source, &reference.source_span)?;
        if !references.insert((range.clone(), target.symbol.clone())) {
            continue;
        }
        let mut occurrence = Occurrence::new();
        occurrence.range = range;
        occurrence.symbol = target.symbol.clone();
        occurrence.symbol_roles = SymbolRole::ReadAccess.value();
        occurrences.push(occurrence);
    }
    occurrences.sort_by(|left, right| {
        left.range
            .cmp(&right.range)
            .then_with(|| left.symbol.cmp(&right.symbol))
            .then_with(|| left.symbol_roles.cmp(&right.symbol_roles))
    });
    information.sort_by(|left, right| left.symbol.cmp(&right.symbol));

    let mut document = Document::new();
    document.language = H00_PYREFLY_LANGUAGE.into();
    document.relative_path = document_path.into();
    document.text = source.into();
    document.position_encoding =
        EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
    document.occurrences = occurrences;
    document.symbols = information;
    Ok(document)
}

fn supported_declaration(kind: &H00DeclarationKind) -> bool {
    matches!(
        kind,
        H00DeclarationKind::Class
            | H00DeclarationKind::Function
            | H00DeclarationKind::Method
            | H00DeclarationKind::Constructor
    )
}

fn scip_kind(kind: &H00DeclarationKind) -> symbol_information::Kind {
    match kind {
        H00DeclarationKind::Class => symbol_information::Kind::Class,
        H00DeclarationKind::Function => symbol_information::Kind::Function,
        H00DeclarationKind::Method => symbol_information::Kind::Method,
        H00DeclarationKind::Constructor => symbol_information::Kind::Constructor,
        H00DeclarationKind::Variable => symbol_information::Kind::Variable,
    }
}

fn python_symbol(
    package_name: &str,
    declaration: &H00DeclarationFact,
    declaration_kinds: &BTreeMap<String, H00DeclarationKind>,
) -> anyhow::Result<String> {
    let names = declaration.name.split('.').collect::<Vec<_>>();
    if names.iter().any(|name| name.is_empty()) {
        bail!("Pyrefly emitted an empty qualified-name component");
    }
    let mut descriptors = Vec::with_capacity(names.len());
    let mut qualified = String::new();
    for (index, name) in names.iter().enumerate() {
        if !qualified.is_empty() {
            qualified.push('.');
        }
        qualified.push_str(name);
        let suffix = if index + 1 == names.len() {
            descriptor_suffix(&declaration.kind)
        } else {
            declaration_kinds
                .get(&qualified)
                .map_or(descriptor::Suffix::Namespace, descriptor_suffix)
        };
        let mut descriptor = Descriptor::new();
        descriptor.name = (*name).into();
        descriptor.suffix = EnumOrUnknown::new(suffix);
        descriptors.push(descriptor);
    }
    let mut package = Package::new();
    package.manager = "python".into();
    package.name = package_name.into();
    let mut symbol = Symbol::new();
    symbol.scheme = "pyrefly".into();
    symbol.package = MessageField::some(package);
    symbol.descriptors = descriptors;
    Ok(format_symbol(symbol))
}

fn descriptor_suffix(kind: &H00DeclarationKind) -> descriptor::Suffix {
    match kind {
        H00DeclarationKind::Class => descriptor::Suffix::Type,
        H00DeclarationKind::Function
        | H00DeclarationKind::Method
        | H00DeclarationKind::Constructor => descriptor::Suffix::Method,
        H00DeclarationKind::Variable => descriptor::Suffix::Term,
    }
}

fn scip_range(source: &str, span: &H00ByteSpan) -> anyhow::Result<Vec<i32>> {
    let start = usize::try_from(span.start).context("Pyrefly span start exceeds usize")?;
    let length = usize::try_from(span.length).context("Pyrefly span length exceeds usize")?;
    let end = start
        .checked_add(length)
        .context("Pyrefly span end overflow")?;
    if start >= end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        bail!("Pyrefly span is outside exact UTF-8 source bytes");
    }
    let line_starts = source
        .bytes()
        .enumerate()
        .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1))
        .fold(vec![0_usize], |mut starts, next| {
            starts.push(next);
            starts
        });
    let position = |byte: usize| -> anyhow::Result<(i32, i32)> {
        let line = match line_starts.binary_search(&byte) {
            Ok(line) => line,
            Err(next) => next.saturating_sub(1),
        };
        Ok((
            i32::try_from(line).context("Pyrefly line exceeds SCIP range")?,
            i32::try_from(byte - line_starts[line]).context("Pyrefly column exceeds SCIP range")?,
        ))
    };
    let (start_line, start_column) = position(start)?;
    let (end_line, end_column) = position(end)?;
    if start_line == end_line {
        Ok(vec![start_line, start_column, end_column])
    } else {
        Ok(vec![start_line, start_column, end_line, end_column])
    }
}

fn semantic_input_paths(
    repository_root: &Path,
    candidate_paths: &BTreeSet<String>,
    authority: &H00AuthorityFacts,
    limits: &ProviderFrameLimits,
) -> anyhow::Result<BTreeSet<String>> {
    let mut paths = candidate_paths.clone();
    for config in &authority.configurations {
        add_configuration_paths(repository_root, config, &mut paths)?;
    }
    if paths.len() > limits.max_document_paths {
        bail!("Python semantic-input population exceeds negotiated path bounds");
    }
    Ok(paths)
}

fn add_configuration_paths(
    repository_root: &Path,
    config: &H00ConfigurationBinding,
    paths: &mut BTreeSet<String>,
) -> anyhow::Result<()> {
    if config.source_database_enabled
        || config.build_system_enabled
        || config.fallback_search_path_enabled
    {
        bail!("Pyrefly build-system or fallback source databases are not yet authority-bound");
    }
    if let Some(path) = &config.source_path {
        paths.insert(
            repository_relative(repository_root, path)
                .context("normalize Pyrefly configuration source path")?,
        );
    }
    if let Some(root) = &config.root {
        ensure_repository_path(repository_root, root)
            .context("validate Pyrefly configuration root")?;
    }
    for path in &config.heuristic_search_paths {
        ensure_repository_path(repository_root, path)
            .context("validate Pyrefly heuristic search path")?;
    }
    for (kind, path) in config
        .explicit_search_paths
        .iter()
        .map(|path| ("explicit", path))
        .chain(
            config
                .site_package_paths
                .iter()
                .map(|path| ("site-package", path)),
        )
        .chain(
            config
                .custom_typeshed_path
                .iter()
                .map(|path| ("custom-typeshed", path)),
        )
    {
        ensure_repository_path(repository_root, path).with_context(|| {
            format!("validate Pyrefly {kind} dependency path {}", path.display())
        })?;
        if !path.exists() {
            bail!("configured Python dependency path does not exist");
        }
        paths.insert(
            repository_relative(repository_root, path)
                .context("normalize Pyrefly configured dependency path")?,
        );
    }
    Ok(())
}

fn configuration_candidate_paths<'a>(
    repository_root: &Path,
    sources: impl Iterator<Item = &'a Path>,
    limits: &ProviderFrameLimits,
) -> anyhow::Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for source in sources {
        let parent = source.parent().context("Python source has no parent")?;
        for ancestor in parent
            .ancestors()
            .take_while(|path| path.starts_with(repository_root))
        {
            for name in CONFIG_CANDIDATE_NAMES {
                paths.insert(repository_relative(repository_root, &ancestor.join(name))?);
            }
        }
    }
    if paths.is_empty() || paths.len() > limits.max_document_paths {
        bail!("Python configuration-candidate population is empty or oversized");
    }
    Ok(paths)
}

fn workspace_resolution_sha256(
    execution_prefix: &str,
    package_name: &str,
    authority: &H00AuthorityFacts,
) -> anyhow::Result<String> {
    let mut material = b"h00/pyrefly/workspace-resolution/v1\0".to_vec();
    append_field(&mut material, execution_prefix.as_bytes());
    append_field(&mut material, package_name.as_bytes());
    for module in &authority.modules {
        append_field(&mut material, path_text(&module.path)?.as_bytes());
        append_field(&mut material, module.module_name.as_bytes());
        append_field(&mut material, &[u8::from(module.fallback_name)]);
        append_field(&mut material, module.python_version.as_bytes());
        append_field(&mut material, module.python_platform.as_bytes());
        append_field(&mut material, &[u8::from(module.type_checking)]);
    }
    for config in &authority.configurations {
        append_optional_path(&mut material, config.source_path.as_deref())?;
        append_optional_path(&mut material, config.root.as_deref())?;
        for population in [
            &config.explicit_search_paths,
            &config.heuristic_search_paths,
            &config.site_package_paths,
        ] {
            append_field(&mut material, &(population.len() as u64).to_be_bytes());
            for path in population {
                append_field(&mut material, path_text(path)?.as_bytes());
            }
        }
        append_optional_path(&mut material, config.custom_typeshed_path.as_deref())?;
        append_field(
            &mut material,
            &[
                u8::from(config.source_database_enabled),
                u8::from(config.build_system_enabled),
                u8::from(config.fallback_search_path_enabled),
            ],
        );
    }
    Ok(sha256_hex(&material))
}

fn append_optional_path(material: &mut Vec<u8>, path: Option<&Path>) -> anyhow::Result<()> {
    match path {
        Some(path) => {
            append_field(material, b"present");
            append_field(material, path_text(path)?.as_bytes());
        }
        None => append_field(material, b"missing"),
    }
    Ok(())
}

fn append_field(material: &mut Vec<u8>, value: &[u8]) {
    material.extend_from_slice(&(value.len() as u64).to_be_bytes());
    material.extend_from_slice(value);
}

fn healthy_provider() -> ProviderHealthEvidence {
    ProviderHealthEvidence {
        components: BTreeMap::from([
            (
                "ambient_interpreter".into(),
                ProviderComponentHealth::NotApplicable,
            ),
            ("bundled_typeshed".into(), ProviderComponentHealth::Healthy),
            ("pyrefly_solver".into(), ProviderComponentHealth::Healthy),
        ]),
        diagnostics_complete: true,
        degradation_reasons: Vec::new(),
    }
}

fn exact_session<'a>(
    session: &'a mut Option<RootSession>,
    session_id: &str,
    authority: &ProviderAuthority,
) -> anyhow::Result<&'a mut RootSession> {
    let active = session
        .as_mut()
        .context("Pyrefly provider session is not open")?;
    if active.authority.session_id != session_id || active.authority != *authority {
        bail!("request authority differs from the process-owned Pyrefly session");
    }
    Ok(active)
}

fn package_name(execution_prefix: &str) -> String {
    let digest = sha256_hex(execution_prefix.as_bytes());
    format!("root-{}", &digest[..16])
}

fn validate_source_identity(source: &ProviderSourceIdentity) -> anyhow::Result<()> {
    if !safe_document_path(&source.document_path)
        || source.content_identity.is_empty()
        || !is_sha256(&source.content_sha256)
    {
        bail!("invalid Pyrefly source identity");
    }
    Ok(())
}

fn safe_document_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn canonical_directory(path: &Path) -> anyhow::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize provider directory {}", path.display()))?;
    if !std::fs::metadata(&canonical)?.is_dir() {
        bail!("provider root is not a directory");
    }
    path_text(&canonical)?;
    Ok(canonical)
}

fn canonical_source_path(repository_root: &Path, document_path: &str) -> anyhow::Result<PathBuf> {
    if !safe_document_path(document_path) {
        bail!("invalid repository document path");
    }
    let canonical = std::fs::canonicalize(repository_root.join(document_path))
        .with_context(|| format!("canonicalize Python source {document_path}"))?;
    if !canonical.starts_with(repository_root) || !std::fs::metadata(&canonical)?.is_file() {
        bail!("Python source escapes the repository or is not a regular file");
    }
    Ok(canonical)
}

fn ensure_repository_path(repository_root: &Path, path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() || !path.starts_with(repository_root) {
        bail!("Pyrefly resolved a semantic path outside the repository");
    }
    path_text(path)?;
    Ok(())
}

fn repository_relative(repository_root: &Path, path: &Path) -> anyhow::Result<String> {
    let text = repository_prefix(repository_root, path)?;
    if text.is_empty() {
        bail!("Pyrefly semantic path resolves to the repository root");
    }
    Ok(text)
}

fn repository_prefix(repository_root: &Path, path: &Path) -> anyhow::Result<String> {
    let relative = path
        .strip_prefix(repository_root)
        .context("Pyrefly path escapes the repository")?;
    let text = path_text(relative)?.replace('\\', "/");
    if !text.is_empty() && !safe_document_path(&text) {
        bail!("Pyrefly path is not a safe repository-relative path");
    }
    Ok(text)
}

fn path_text(path: &Path) -> anyhow::Result<&str> {
    path.to_str().context("Pyrefly provider path is not UTF-8")
}

pub fn executable_identity() -> anyhow::Result<ProviderIdentity> {
    if !is_sha256(PATCH_SHA256) {
        bail!("Pyrefly provider patch identity is not configured");
    }
    let executable = std::env::current_exe().context("resolve provider executable")?;
    let bytes = std::fs::read(executable).context("hash provider executable")?;
    Ok(ProviderIdentity {
        protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
        provider_id: H00_PYREFLY_PROVIDER_ID.into(),
        language: H00_PYREFLY_LANGUAGE.into(),
        implementation_version: H00_PYREFLY_IMPLEMENTATION_V1.into(),
        source_components: pyrefly_source_components(),
        patch_sha256: PATCH_SHA256.into(),
        executable_sha256: sha256_hex(&bytes),
    })
}

fn observe_runtime_configuration() -> anyhow::Result<ProviderRuntimeConfiguration> {
    let resolved_toolchain_sha256 = std::env::var(RESOLVED_TOOLCHAIN_SHA256_ENV)
        .with_context(|| format!("read required {RESOLVED_TOOLCHAIN_SHA256_ENV}"))?;
    if !is_sha256(&resolved_toolchain_sha256) || !is_sha256(PATCH_SHA256) {
        bail!("required resolved Pyrefly runtime identity is absent");
    }
    let version = format!("{H00_PYREFLY_UPSTREAM_VERSION}@{H00_PYREFLY_UPSTREAM_COMMIT}");
    let workspace = b"interpreter-query=disabled\0typeshed=bundled\0source-overlay=exact\0position-encoding=utf8";
    let configuration = provider_runtime_configuration(
        &resolved_toolchain_sha256,
        &[
            ("provider_patch", PATCH_SHA256.as_bytes()),
            ("pyrefly", version.as_bytes()),
        ],
        b"",
        workspace,
    )?;
    validate_runtime_configuration(&configuration)?;
    Ok(configuration)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn bounded_error(error: &anyhow::Error) -> String {
    bounded_text(&format!("{error:#}"), 1024)
}

fn bounded_text(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

fn arm_parent_liveness_guard() -> anyhow::Result<()> {
    // SAFETY: these calls only observe the current process relationship.
    let process = unsafe { libc::getpid() };
    // SAFETY: see above.
    let process_group = unsafe { libc::getpgrp() };
    if process_group != process {
        bail!("semantic provider must own its process group");
    }
    let expected_parent = std::env::var(PROVIDER_PARENT_PID_ENV)
        .with_context(|| format!("read required {PROVIDER_PARENT_PID_ENV}"))?
        .parse::<libc::pid_t>()
        .with_context(|| format!("parse required {PROVIDER_PARENT_PID_ENV}"))?;
    // SAFETY: see above.
    let observed_parent = unsafe { libc::getppid() };
    if expected_parent <= 1 || observed_parent != expected_parent {
        bail!("semantic provider owning parent changed before liveness guard armed");
    }
    std::thread::Builder::new()
        .name("h00-pyrefly-parent-guard".into())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
                // SAFETY: getppid only observes the current parent relationship.
                if unsafe { libc::getppid() } == expected_parent {
                    continue;
                }
                // SAFETY: group zero targets only this provider-owned process group.
                unsafe {
                    libc::kill(0, libc::SIGKILL);
                }
                return;
            }
        })
        .context("start Pyrefly provider parent-liveness guard")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_symbols_preserve_module_class_and_callable_ownership() {
        let kinds = BTreeMap::from([
            ("pkg.Base".into(), H00DeclarationKind::Class),
            ("pkg.Base.method".into(), H00DeclarationKind::Method),
        ]);
        let symbol = python_symbol(
            "root-fixture",
            &H00DeclarationFact {
                name: "pkg.Base.method".into(),
                kind: H00DeclarationKind::Method,
                name_span: H00ByteSpan {
                    start: 0,
                    length: 6,
                },
                extent_span: H00ByteSpan {
                    start: 0,
                    length: 6,
                },
                bases: Vec::new(),
            },
            &kinds,
        )
        .expect("canonical SCIP symbol");
        assert_eq!(symbol, "pyrefly python root-fixture . pkg/Base#method().");
    }

    #[test]
    fn byte_spans_become_exact_utf8_scip_ranges() {
        let source = "π = 1\ndef café():\n    return π\n";
        let start = source.find("café").unwrap();
        assert_eq!(
            scip_range(
                source,
                &H00ByteSpan {
                    start: start as u64,
                    length: "café".len() as u64,
                },
            )
            .unwrap(),
            vec![1, 4, 9],
            "SCIP UTF-8 columns count bytes, not Unicode scalar values"
        );
    }

    #[test]
    fn repository_root_is_a_valid_empty_execution_prefix_but_not_a_semantic_path() {
        let root = Path::new("/repository");
        assert_eq!(repository_prefix(root, root).unwrap(), "");
        assert!(
            repository_relative(root, root)
                .unwrap_err()
                .to_string()
                .contains("repository root")
        );
        assert_eq!(
            repository_relative(root, &root.join("pyproject.toml")).unwrap(),
            "pyproject.toml"
        );
    }
}
