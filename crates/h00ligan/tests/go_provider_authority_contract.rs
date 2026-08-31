//! Source-boundary falsifiers for the embedded gopls authority seam.
//!
//! The Go provider is compiled from a pinned upstream gopls tree plus these
//! small repository-owned patches. These assertions keep authority coupled to
//! the exact requested document population and initialized snapshot that emit
//! the SCIP documents, rather than to the timing-dependent ambient gopls cache.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn bounded_slice<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("start marker");
    let remainder = &source[start..];
    let end = remainder.find(end).expect("end marker");
    &remainder[..end]
}

#[test]
fn go_export_seals_resolution_from_the_same_initialized_snapshot() {
    let workspace = workspace_root();
    let server_source = std::fs::read_to_string(workspace.join("providers/go/gopls/h00_scip.go"))
        .expect("gopls server patch");
    let provider_source =
        std::fs::read_to_string(workspace.join("providers/go/gopls/h00_semantic_provider.go"))
            .expect("Go provider patch");

    assert_eq!(
        server_source.matches("server.session.SnapshotOf(").count(),
        2,
        "known-positive control: admission and export must each acquire one gopls snapshot"
    );
    assert!(
        server_source.contains("func H00InspectWorkspaceResolutionAndInputs("),
        "known-positive control: the input-bound admission entrypoint must exist"
    );
    assert!(
        provider_source.contains("goplsserver.H00ExportScipDocuments("),
        "known-positive control: the shipped provider must call the export bridge"
    );
    assert!(
        provider_source.contains("ctx, semanticServer, sourceURIs, sourceSHA256s")
            && provider_source.contains("session.workspaceWitness")
            && provider_source.contains("expectedSourceSHA256s"),
        "admission and export must carry exact source bytes as well as the document-population witness"
    );

    let export_bridge = bounded_slice(
        &server_source,
        "func H00ExportScipDocuments(",
        "// H00InspectWorkspaceResolutionAndInputs",
    );
    assert!(
        export_bridge.contains("snapshot.AwaitInitialized(ctx)"),
        "export must wait for the selected snapshot's initial workspace load"
    );
    assert!(
        export_bridge
            .matches("h00ObserveWorkspace(ctx, snapshot, observedURIs)")
            .count()
            == 2,
        "export must compare the selected closure before and after type checking"
    );
    assert!(
        export_bridge.contains("observedURIs := requested")
            && export_bridge.contains("if includeCallableLiveness {")
            && export_bridge.contains(
                "observedURIs = make([]protocol.DocumentURI, 0, len(expectedSourceSHA256s))",
            )
            && export_bridge.contains("for uri := range expectedSourceSHA256s")
            && export_bridge.contains("observedURIs = append(observedURIs, uri)"),
        "ordinary SCIP export may project requested documents, but whole-program callable liveness must seal the entire admitted source population"
    );
    assert!(
        export_bridge.contains("expectedWorkspace H00WorkspaceWitness")
            && export_bridge.contains("expectedSourceSHA256s map[protocol.DocumentURI]string",)
            && export_bridge.contains("snapshot.TypeCheck(ctx, ids...)")
            && export_bridge.contains("([]*scip.Document, []byte, error)"),
        "export must type-check only the admitted source and selected package population, returning callable liveness separately from SCIP documents"
    );
    assert_eq!(
        export_bridge
            .matches("h00VerifySnapshotSources(ctx, snapshot, expectedSourceSHA256s)")
            .count(),
        2,
        "exact gopls source bytes must bracket the type-check that emits SCIP documents"
    );
    assert!(
        export_bridge.contains("if meta == nil || meta.ID != id {")
            && export_bridge.contains("selected Go package identity changed before export")
            && export_bridge.contains("h00BoundedPackageIDs(group.files)"),
        "the typed package must still be the selected package, with bounded evidence on mismatch"
    );
    assert!(
        export_bridge.contains("if meta.Module == nil {")
            && export_bridge.contains("has no module authority for documents"),
        "a selected project package without a module identity must fail before SCIP adaptation"
    );
    let initial_observation = export_bridge
        .find("initial, err := h00ObserveWorkspace")
        .expect("initial observation");
    let initial_source_verification = export_bridge
        .find("h00VerifySnapshotSources(ctx, snapshot, expectedSourceSHA256s)")
        .expect("initial source verification");
    let type_check = export_bridge
        .find("snapshot.TypeCheck(ctx, ids...)")
        .expect("selected type check");
    let final_observation = export_bridge
        .find("final, err := h00ObserveWorkspace")
        .expect("final observation");
    let final_source_verification = export_bridge
        .rfind("h00VerifySnapshotSources(ctx, snapshot, expectedSourceSHA256s)")
        .expect("final source verification");
    assert!(
        initial_source_verification < initial_observation
            && initial_observation < type_check
            && type_check < final_observation
            && final_observation < final_source_verification,
        "source and workspace authority must bracket the type-check that supplies exported documents"
    );

    let verification = bounded_slice(
        &provider_source,
        "func (session *h00GoSession) verifyAuthorityInputs() error {",
        "func (session *h00GoSession) applyEpoch(",
    );
    assert!(
        !verification.contains("H00InspectWorkspaceResolution("),
        "a separate pre-export snapshot check creates a time-of-check/time-of-use race"
    );

    let export = bounded_slice(
        &provider_source,
        "func (session *h00GoSession) exportDocuments(",
        "func h00CanonicalizeScipDocument(",
    );
    assert!(
        export.contains("session.workspaceWitness")
            && export.contains("expectedSourceSHA256s")
            && export.contains("make(map[protocol.DocumentURI]string, len(session.sources))")
            && export.contains("for path, source := range session.sources")
            && export.contains("expectedSourceSHA256s[uri] = source.ContentSHA256"),
        "the export snapshot must join the entire admitted root-session source population, not only requested documents whose package analysis can consume siblings"
    );
    assert!(
        !export.contains("observedWorkspaceResolution"),
        "the gopls export boundary itself must fail closed before returning documents"
    );

    let resolution = bounded_slice(
        &server_source,
        "func h00ObserveWorkspace(",
        "func h00LoadedPackage(",
    );
    assert!(
        resolution.contains("h00SelectDocuments(ctx, snapshot, uris)")
            && resolution.contains("maps.Equal(documentSelections, nextSelections)")
            && resolution.contains("const maxConvergencePasses = 4")
            && resolution.contains("snapshot.MetadataForFile(ctx, uri, true)")
            && resolution.contains("meta.Standalone")
            && resolution.contains("metadata.IsCommandLineArguments(meta.ID)"),
        "every requested document must converge to a selected package or explicit omission"
    );
    assert!(
        resolution.contains("h00DocumentPackageName(ctx, snapshot, uri)")
            && resolution.contains("string(meta.Name) != packageName")
            && resolution.contains("if meta.Module == nil {")
            && resolution.contains("h00MetadataContainsURI(meta, uri)")
            && resolution.contains("h00BoundedMetadataCandidates(metas)"),
        "package selection must match the exact source package clause, document ownership, and module authority instead of trusting gopls candidate position"
    );
    assert!(
        !resolution.contains("id := metas[0].ID"),
        "the first gopls candidate is not independently authoritative"
    );
    assert!(
        resolution.contains("graph.ForwardReflexiveTransitiveClosure(rootID)")
            && resolution.contains("workspace-resolution/v3")
            && resolution.contains("RootClosurePackageIDs")
            && export_bridge
                .contains("h00ProjectWorkspaceWitness(expectedWorkspace, observedURIs)"),
        "authority must project the selected analysis population onto its admitted per-root dependency closure"
    );
    assert!(
        !server_source.contains(".AllMetadata("),
        "ambient gopls cache population is timing-dependent and cannot grant authority"
    );
    assert!(
        resolution.contains("h00WorkspaceResolutionDifference")
            && resolution.contains("const limit = 4"),
        "workspace drift must retain a bounded package-level diagnostic witness"
    );
    let observation = bounded_slice(
        &server_source,
        "func h00ObserveWorkspace(",
        "func h00ProjectWorkspaceWitness(",
    );
    assert_eq!(
        observation
            .matches("snapshot.LoadMetadataGraph(ctx)")
            .count(),
        2,
        "workspace convergence must load before comparison and after a pass, but must not immediately reload the identical terminal graph"
    );
    assert!(
        observation.contains("graph = nextGraph"),
        "the converged pass must retain the exact metadata graph produced at its authority boundary"
    );

    let open_session = bounded_slice(
        &provider_source,
        "func h00OpenGoSession(",
        "func (session *h00GoSession) close()",
    );
    assert!(
        open_session.contains("os.ReadFile(absolute)")
            && open_session.contains("h00SHA256(contents) != source.ContentSHA256"),
        "known-positive control: session admission must verify every source byte before gopls authority"
    );
    assert!(
        open_session.contains("sourceSHA256s[uri] = source.ContentSHA256")
            && open_session.contains("sourceURIs, sourceSHA256s,")
            && !open_session.contains("semanticServer.DidOpen("),
        "disk-backed admission is valid only when the exact initialized gopls snapshot is joined to every admitted source digest"
    );
    assert!(
        open_session.find("os.ReadFile(absolute)") < open_session.find("app := New()"),
        "cheap exact source admission must complete before gopls can begin workspace work"
    );
    let apply_epoch = bounded_slice(
        &provider_source,
        "func (session *h00GoSession) applyEpoch(",
        "func (session *h00GoSession) exportDocuments(",
    );
    assert!(
        apply_epoch.contains("session.server.DidOpen(")
            && apply_epoch.contains("session.server.DidChange("),
        "the first changed epoch must lazily open its exact replacement and later epochs must version that overlay"
    );

    let snapshot_verifier = bounded_slice(
        &server_source,
        "func h00VerifySnapshotSources(",
        "func h00ObserveSemanticInputs(",
    );
    assert!(
        snapshot_verifier.contains("snapshot.ReadFile(ctx, uri)")
            && snapshot_verifier.contains("fh.Identity().Hash.String()")
            && snapshot_verifier.contains("observedSHA256 != expectedSHA256"),
        "same-snapshot authority must compare gopls's immutable SHA-256 file identity, not re-read ambient disk bytes"
    );
}

/// FALSIFIER: Go's unsigned arithmetic wraps, so `current + 1` alone admits
/// epoch zero after `u64::MAX`. Both Go-native providers must delegate the
/// authority transition to one shared, non-wrapping exact-successor rule.
#[test]
fn go_native_providers_share_one_non_wrapping_epoch_successor_contract() {
    let workspace = workspace_root();
    let shared =
        std::fs::read_to_string(workspace.join("providers/go/shared/h00provider/protocol.go"))
            .expect("shared Go-native provider protocol");
    let go = std::fs::read_to_string(workspace.join("providers/go/gopls/h00_semantic_provider.go"))
        .expect("gopls provider patch");
    let typescript =
        std::fs::read_to_string(workspace.join("providers/typescript/h00_semantic_provider.go"))
            .expect("TypeScript provider patch");

    assert!(
        shared.contains("func IsExactSuccessorEpoch(previous, next uint64) bool"),
        "shared protocol must own the non-wrapping source-epoch transition"
    );
    assert!(
        go.matches("h00IsExactSuccessorEpoch(").count() == 2,
        "gopls reconfiguration and source replacement must use the shared rule"
    );
    assert!(
        typescript.matches("h00IsExactSuccessorEpoch(").count() == 1,
        "TypeScript source replacement must use the shared rule"
    );
    assert!(
        go.matches("SourceEpoch").count() >= 2 && typescript.matches("SourceEpoch").count() >= 2,
        "known-positive: both populated provider authority implementations were inspected"
    );
}

#[test]
fn unresolved_gopls_imports_degrade_locally_instead_of_aborting_go_authority() {
    let workspace = workspace_root();
    let server_source = std::fs::read_to_string(workspace.join("providers/go/gopls/h00_scip.go"))
        .expect("gopls server patch");
    let adapter = bounded_slice(
        &server_source,
        "func h00LoadedPackage(",
        "func h00CloneModule(",
    );

    assert_eq!(
        adapter
            .matches("for importPath, dependencyID := range meta.DepsByImpPath")
            .count(),
        1,
        "known-positive control: the packages.Package import adapter must be populated"
    );
    assert!(
        adapter.contains("if dependencyID == \"\" {")
            && adapter.contains("continue")
            && adapter.contains("if dependencyMeta == nil {")
            && adapter.contains("references missing metadata"),
        "gopls documents empty dependency IDs as missing imports: skip only that explicit state, while a non-empty dangling identity must still fail closed"
    );
}

#[test]
fn semantic_input_freshness_brackets_provider_work_and_every_reproducible_terminal() {
    let workspace = workspace_root();
    let provider =
        std::fs::read_to_string(workspace.join("providers/go/gopls/h00_semantic_provider.go"))
            .expect("Go provider patch");
    let coordinator = std::fs::read_to_string(
        workspace.join("crates/h00ligan-engine/src/code_intel_semantic_provider_coordinator.rs"),
    )
    .expect("shared semantic-provider coordinator");

    let dispatch = bounded_slice(
        &provider,
        "func h00HandleRequest(",
        "func h00OpenGoSession(",
    );
    assert!(
        dispatch.contains("(*session).verifyAuthorityInputs()"),
        "known-positive control: every admitted Go operation has a semantic-input preflight"
    );

    let apply_epoch = bounded_slice(
        &provider,
        "func (session *h00GoSession) applyEpoch(",
        "func (session *h00GoSession) exportDocuments(",
    );
    let committed_epoch = apply_epoch
        .find("session.authority = body.NextAuthority")
        .expect("epoch authority commit");
    let terminal_epoch_check = apply_epoch
        .rfind("session.verifyAuthorityInputs()")
        .expect("terminal epoch semantic-input check");
    assert!(
        committed_epoch < terminal_epoch_check,
        "source-epoch application must re-observe semantic inputs after gopls mutation"
    );

    let export = bounded_slice(
        &provider,
        "func (session *h00GoSession) exportDocuments(",
        "func h00CanonicalizeScipDocument(",
    );
    let provider_work = export
        .find("goplsserver.H00ExportScipDocuments(")
        .expect("gopls export work");
    let terminal_export_check = export
        .rfind("session.verifyAuthorityInputs()")
        .expect("terminal export semantic-input check");
    assert!(
        provider_work < terminal_export_check,
        "full certification and affected refresh must re-observe semantic inputs after gopls work"
    );

    let refresh = bounded_slice(
        &coordinator,
        "    pub async fn refresh(",
        "    /// Close every owned child",
    );
    let terminal_input_stage = refresh
        .find("terminal semantic-input authority")
        .expect("common terminal semantic-input stage");
    assert!(
        !refresh[..terminal_input_stage].contains("PendingProviderActivity::Reused"),
        "fresh full and affected results must not bypass the common terminal input check"
    );

    let terminal_checker = bounded_slice(
        &coordinator,
        "    fn session_semantic_inputs_are_current(",
        "    async fn probe_session_runtime_authority(",
    );
    assert!(
        terminal_checker.contains("ProviderSemanticInputCoverage::Complete")
            && terminal_checker.contains("ProviderSemanticInputCoverage::Unverifiable"),
        "the common owner must check every reproducible manifest while retaining an explicit unverifiable-provider boundary"
    );
}

#[test]
fn affected_provider_work_is_one_witnessed_transaction_with_real_terminal_boundaries() {
    let workspace = workspace_root();
    let coordinator = std::fs::read_to_string(
        workspace.join("crates/h00ligan-engine/src/code_intel_semantic_provider_coordinator.rs"),
    )
    .expect("shared semantic-provider coordinator");
    let protocol =
        std::fs::read_to_string(workspace.join("crates/h00ligan-provider-protocol/src/lib.rs"))
            .expect("semantic-provider protocol");
    let pipeline =
        std::fs::read_to_string(workspace.join("crates/h00ligan-engine/src/index_pipeline.rs"))
            .expect("index pipeline");

    assert!(
        coordinator.contains("ProviderRequestBody::RefreshAffected")
            && protocol.contains("AffectedRefreshed {")
            && protocol.contains("terminal_runtime_configuration"),
        "known-positive control: one affected request and its terminal runtime witness must exist"
    );
    let affected_lane = bounded_slice(
        &coordinator,
        "            SemanticRefreshPlan::AffectedDocuments { documents } => {",
        "    #[allow(clippy::too_many_arguments)]\n    async fn refresh_affected_execution_roots(",
    );
    assert_eq!(
        affected_lane.matches(".refresh_affected(").count(),
        1,
        "one logical source edit must enter one provider-owned affected-refresh transaction"
    );
    assert!(
        !affected_lane.contains(".apply_replacements(")
            && !affected_lane.contains(".export_affected("),
        "the production affected lane must not retain the old two-request sequence"
    );
    assert!(
        coordinator.contains("pub async fn refresh(")
            && pipeline.contains("persistent gopls execution and cache work"),
        "known-positive control: the persistent provider timing boundary must be populated"
    );
    for stage in [
        "affected refresh transaction RPC",
        "affected refresh admission and snapshot overlay",
        "affected refresh authority binding",
        "admit affected candidate",
        "terminal toolchain authority",
        "terminal semantic-input authority",
    ] {
        assert!(
            coordinator.contains(stage),
            "affected semantic refresh must measure the real {stage} boundary"
        );
    }
    assert!(
        coordinator.contains("refresh: SemanticProviderAdmittedRefreshKind::Affected { .. }")
            && coordinator.contains("terminal runtime authority"),
        "the witnessed affected lane must skip only its redundant Hello while other lanes retain the terminal runtime probe"
    );
    assert!(
        coordinator.contains("take_last_activity")
            && pipeline.contains("record_semantic_provider_execution_timings"),
        "the shared coordinator's measured stages must reach product WATCH telemetry"
    );
    assert!(
        pipeline.contains("IndexTimingAggregation::ConcurrentSpan")
            && pipeline.contains("semantic provider coordination remainder"),
        "the old aggregate must become a nested summary so component timings remain non-overlapping"
    );
}

#[test]
fn affected_refresh_snapshot_overlay_shares_unchanged_document_shards_until_serialization() {
    let workspace = workspace_root();
    let bridge = std::fs::read_to_string(
        workspace.join("crates/h00ligan-engine/src/code_intel_semantic_provider.rs"),
    )
    .expect("semantic-provider bridge");
    let normalizer =
        std::fs::read_to_string(workspace.join("crates/h00ligan-engine/src/scip_normalizer.rs"))
            .expect("canonical SCIP normalizer");

    assert!(
        bridge.contains("normalize_admitted_affected_refreshes_with_source_syntax_cache")
            && normalizer.contains("pub fn overlay_affected_documents("),
        "known-positive control: the affected canonical overlay boundary must be populated"
    );
    assert!(
        normalizer.contains("index_envelope: Arc<Index>")
            && normalizer.contains("documents_by_path: Arc<BTreeMap<String, Arc<Document>>>")
            && normalizer.contains("std::mem::take(&mut index.documents)"),
        "immutable canonical snapshots must separate their empty shared envelope from independently shared document shards"
    );
    let affected_bridge = bounded_slice(
        &bridge,
        "pub(crate) fn normalize_admitted_affected_refreshes_with_source_syntax_cache(",
        "#[cfg(test)]",
    );
    assert!(
        affected_bridge.contains("prior_snapshot: &CanonicalScipSnapshot"),
        "one-document refresh must borrow its immutable parent instead of deep-cloning it before overlay"
    );

    let overlay = bounded_slice(
        &normalizer,
        "    pub fn overlay_affected_documents(",
        "/// Reconstruct one disposable canonical provider snapshot",
    );
    let serialization_boundary = bounded_slice(
        &normalizer,
        "    pub(crate) fn encoded_index(&self)",
        "    pub(crate) fn documents(&self)",
    );
    assert!(
        overlay.contains("Arc::clone(document)")
            && overlay.contains("self.with_shared_documents(")
            && !overlay.contains("document.as_ref().clone()")
            && !overlay.contains("write_to_bytes"),
        "the affected overlay must retain unchanged immutable document storage without assembling a repository-sized protobuf index"
    );
    assert!(
        serialization_boundary.contains("self.index_envelope.as_ref().clone()")
            && serialization_boundary.contains("document.as_ref().clone()")
            && serialization_boundary.contains("index.write_to_bytes()"),
        "full protobuf assembly must remain confined to the cache-persistence serialization boundary"
    );
}

#[test]
fn incremental_definition_cache_uses_copy_on_write_without_a_second_repository_clone() {
    let workspace = workspace_root();
    let normalizer =
        std::fs::read_to_string(workspace.join("crates/h00ligan-engine/src/scip_normalizer.rs"))
            .expect("canonical SCIP normalizer");
    assert!(
        normalizer.contains("struct CachedCanonicalDefinitionGroups")
            && normalizer.contains("definition_canonicalization_started"),
        "known-positive control: the persistent canonical-definition cache must be populated"
    );

    let canonicalization = bounded_slice(
        &normalizer,
        "    let definition_canonicalization_started = Instant::now();",
        "    let binding_and_lookup_indexing_started = Instant::now();",
    );
    assert!(
        canonicalization.contains("Arc::make_mut(&mut definitions)")
            && canonicalization.contains("Arc::make_mut(&mut aliases)"),
        "incremental replacement must copy retained canonical maps only when their affected subset is mutated"
    );
    assert!(
        canonicalization.contains("definitions: Arc::clone(&definitions)")
            && canonicalization.contains("aliases: Arc::clone(&definition_aliases)"),
        "the next exact cache epoch must share the admitted canonical maps instead of cloning every record again"
    );
    assert!(
        !canonicalization.contains("Arc::new(definitions.clone())")
            && !canonicalization.contains("Arc::new(definition_aliases.clone())"),
        "caching an immutable epoch must not perform a second repository-sized clone"
    );
}
