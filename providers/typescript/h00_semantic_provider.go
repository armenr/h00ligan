package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/scip-code/scip/bindings/go/scip"
	"google.golang.org/protobuf/proto"
)

type h00OpenSessionBody struct {
	Operation              string              `json:"operation"`
	RepositoryRoot         string              `json:"repository_root"`
	ExecutionRoot          string              `json:"execution_root"`
	ExecutionPrefix        string              `json:"execution_prefix"`
	Authority              h00Authority        `json:"authority"`
	Sources                []h00SourceIdentity `json:"sources"`
	ExpectedSemanticInputs *h00SemanticInputs  `json:"expected_semantic_inputs"`
}

type h00SourceChange struct {
	Outcome                 string `json:"outcome"`
	DocumentPath            string `json:"document_path"`
	Language                string `json:"language"`
	PreviousContentIdentity string `json:"previous_content_identity"`
	PreviousContentSHA256   string `json:"previous_content_sha256"`
	ContentIdentity         string `json:"content_identity"`
	ContentSHA256           string `json:"content_sha256"`
	AttachmentIndex         uint32 `json:"attachment_index"`
}

type h00ApplyEpochBody struct {
	Operation         string            `json:"operation"`
	PreviousAuthority h00Authority      `json:"previous_authority"`
	NextAuthority     h00Authority      `json:"next_authority"`
	Changes           []h00SourceChange `json:"changes"`
}

type h00ReconfigureSessionBody struct {
	Operation              string            `json:"operation"`
	PreviousAuthority      h00Authority      `json:"previous_authority"`
	NextAuthority          h00Authority      `json:"next_authority"`
	ExpectedSemanticInputs h00SemanticInputs `json:"expected_semantic_inputs"`
}

type h00RefreshAffectedBody struct {
	Operation            string               `json:"operation"`
	PreviousAuthority    h00Authority         `json:"previous_authority"`
	NextAuthority        h00Authority         `json:"next_authority"`
	Changes              []h00SourceChange    `json:"changes"`
	ParentSnapshotSHA256 string               `json:"parent_snapshot_sha256"`
	Documents            []string             `json:"documents"`
	Analyses             []h00AnalysisRequest `json:"analyses"`
}

type h00CertifyFullBody struct {
	Operation string               `json:"operation"`
	Authority h00Authority         `json:"authority"`
	Analyses  []h00AnalysisRequest `json:"analyses"`
}

type h00DocumentOutcome struct {
	Outcome                 string  `json:"outcome"`
	DocumentPath            string  `json:"document_path"`
	Language                string  `json:"language"`
	ContentIdentity         string  `json:"content_identity"`
	CanonicalDocumentSHA256 string  `json:"canonical_document_sha256,omitempty"`
	AttachmentIndex         *uint32 `json:"attachment_index,omitempty"`
}

type h00TypeScriptProviderSession struct {
	engine         *h00TypeScriptEngine
	authority      h00Authority
	semanticInputs h00SemanticInputs
	health         h00Health
}

func H00SemanticProvider(ctx context.Context) error {
	if err := h00ArmParentLivenessGuard(); err != nil {
		return err
	}
	identity, err := h00ProviderExecutableIdentity()
	if err != nil {
		return err
	}
	runtimeConfiguration, err := h00ObserveRuntimeConfiguration()
	if err != nil {
		return err
	}
	input := bufio.NewReader(os.Stdin)
	output := bufio.NewWriter(os.Stdout)
	var session *h00TypeScriptProviderSession
	var lastRequestID uint64
	for {
		frame, err := h00ReadFrame(input)
		if err != nil {
			if session != nil {
				session.close()
			}
			return err
		}
		request := frame.Metadata
		body, attachments, closeProvider := h00HandleTypeScriptRequest(
			ctx,
			identity,
			runtimeConfiguration,
			&session,
			&lastRequestID,
			frame,
		)
		response := h00ResponseFrame{
			Metadata: h00Response{
				RequestID: request.RequestID,
				SessionID: request.SessionID,
				Provider:  identity,
				Body:      body,
			},
			Attachments: attachments,
		}
		if err := h00WriteFrame(output, response); err != nil {
			if session != nil {
				session.close()
			}
			return err
		}
		if closeProvider {
			if session != nil {
				session.close()
			}
			return nil
		}
	}
}

func h00HandleTypeScriptRequest(
	ctx context.Context,
	identity h00ProviderIdentity,
	runtimeConfiguration h00RuntimeConfiguration,
	session **h00TypeScriptProviderSession,
	lastRequestID *uint64,
	frame h00Frame,
) (any, [][]byte, bool) {
	request := frame.Metadata
	errorBody := func(code string, err error, terminal bool) (any, [][]byte, bool) {
		message := []rune(err.Error())
		if len(message) > 1024 {
			message = message[:1024]
		}
		return map[string]any{
			"result": "error", "code": code, "message": string(message), "retryable": false,
		}, nil, terminal
	}
	if request.RequestID == 0 || request.RequestID <= *lastRequestID {
		return errorBody("replayed_request", fmt.Errorf("request ID is not strictly monotonic"), false)
	}
	*lastRequestID = request.RequestID
	if request.SessionID == "" || !h00IdentityEqual(request.ExpectedProvider, identity) {
		return errorBody("invalid_request", fmt.Errorf("request identity differs from this provider"), false)
	}
	operation, err := h00DecodeOperation(request.Body)
	if err != nil {
		return errorBody("invalid_request", err, false)
	}
	if *session != nil && request.SessionID != (*session).authority.SessionID {
		return errorBody(
			"invalid_request",
			fmt.Errorf("request session differs from the process-owned TypeScript session"),
			true,
		)
	}
	if operation.Operation != "close_session" {
		current, observeErr := h00ObserveRuntimeConfiguration()
		if observeErr != nil || !reflect.DeepEqual(current, runtimeConfiguration) {
			if observeErr == nil {
				observeErr = fmt.Errorf("provider runtime changed after process admission")
			}
			return errorBody("request_failed", observeErr, true)
		}
	}
	if *session != nil && operation.Operation != "hello" && operation.Operation != "reconfigure_session" &&
		operation.Operation != "close_session" {
		if err := (*session).verifyAuthorityInputs(ctx); err != nil {
			return errorBody("request_failed", err, true)
		}
	}

	switch operation.Operation {
	case "hello":
		if len(frame.Attachments) != 0 {
			return errorBody("invalid_request", fmt.Errorf("hello carries attachments"), false)
		}
		if _, err := h00DecodeBody[h00RequestOperation](request.Body); err != nil {
			return errorBody("invalid_request", err, false)
		}
		return map[string]any{
			"result": "hello", "limits": h00Limits(), "runtime_configuration": runtimeConfiguration,
		}, nil, false
	case "open_session":
		if *session != nil || len(frame.Attachments) != 0 {
			return errorBody("request_failed", fmt.Errorf("one process owns exactly one root session"), true)
		}
		body, err := h00DecodeBody[h00OpenSessionBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err, false)
		}
		opened, err := h00OpenTypeScriptSession(ctx, request.SessionID, runtimeConfiguration, body)
		if err != nil {
			return errorBody("request_failed", err, true)
		}
		*session = opened
		return map[string]any{
			"result": "session_opened", "authority": opened.authority,
			"health": opened.health, "semantic_inputs": opened.semanticInputs,
		}, nil, false
	case "reconfigure_session":
		if _, err := h00DecodeBody[h00ReconfigureSessionBody](request.Body); err != nil {
			return errorBody("invalid_request", err, false)
		}
		return errorBody(
			"request_failed",
			fmt.Errorf("TypeScript project-input changes require a fresh compiler session"),
			true,
		)
	case "apply_epoch":
		if *session == nil {
			return errorBody("request_failed", fmt.Errorf("provider session is not open"), true)
		}
		body, err := h00DecodeBody[h00ApplyEpochBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err, false)
		}
		if err := (*session).applyEpoch(ctx, body, frame.Attachments); err != nil {
			return errorBody("request_failed", err, true)
		}
		return map[string]any{
			"result": "epoch_applied", "authority": (*session).authority, "health": (*session).health,
		}, nil, false
	case "refresh_affected":
		if *session == nil {
			return errorBody("request_failed", fmt.Errorf("provider session is not open"), true)
		}
		body, err := h00DecodeBody[h00RefreshAffectedBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err, false)
		}
		if len(body.Analyses) != 0 {
			return errorBody("invalid_request", fmt.Errorf("TypeScript provider does not implement requested semantic analyses"), false)
		}
		if err := (*session).applyEpoch(ctx, h00ApplyEpochBody{
			Operation: body.Operation, PreviousAuthority: body.PreviousAuthority,
			NextAuthority: body.NextAuthority, Changes: body.Changes,
		}, frame.Attachments); err != nil {
			return errorBody("request_failed", err, true)
		}
		outcomes, attachments, err := (*session).exportDocuments(ctx, body.NextAuthority, body.Documents)
		if err != nil {
			return errorBody("request_failed", err, true)
		}
		terminalRuntime, err := h00ObserveRuntimeConfiguration()
		if err != nil || !reflect.DeepEqual(terminalRuntime, runtimeConfiguration) {
			if err == nil {
				err = fmt.Errorf("provider runtime changed during affected refresh")
			}
			return errorBody("request_failed", err, true)
		}
		return map[string]any{
			"result": "affected_refreshed", "authority": (*session).authority,
			"parent_snapshot_sha256": body.ParentSnapshotSHA256,
			"health":                 (*session).health,
			"runtime_configuration":  terminalRuntime,
			"outcomes":               outcomes,
			"analyses":               []any{},
		}, attachments, false
	case "certify_full":
		if *session == nil || len(frame.Attachments) != 0 {
			return errorBody("request_failed", fmt.Errorf("invalid full-certification session"), true)
		}
		body, err := h00DecodeBody[h00CertifyFullBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err, false)
		}
		if len(body.Analyses) != 0 {
			return errorBody("invalid_request", fmt.Errorf("TypeScript provider does not implement requested semantic analyses"), false)
		}
		documents := make([]string, 0, len((*session).engine.sources))
		for path := range (*session).engine.sources {
			documents = append(documents, path)
		}
		outcomes, attachments, err := (*session).exportDocuments(ctx, body.Authority, documents)
		if err != nil {
			return errorBody("request_failed", err, true)
		}
		return map[string]any{
			"result": "full_certification", "authority": (*session).authority,
			"health": (*session).health, "outcomes": outcomes, "analyses": []any{},
		}, attachments, false
	case "close_session":
		if len(frame.Attachments) != 0 {
			return errorBody("invalid_request", fmt.Errorf("close carries attachments"), false)
		}
		body, err := h00DecodeBody[h00RequestOperation](request.Body)
		if err != nil || body.Operation != "close_session" {
			if err == nil {
				err = fmt.Errorf("close body operation is %q", body.Operation)
			}
			return errorBody("invalid_request", err, false)
		}
		return map[string]any{"result": "session_closed"}, nil, true
	default:
		return errorBody("invalid_request", fmt.Errorf("unsupported provider operation %q", operation.Operation), false)
	}
}

func h00OpenTypeScriptSession(
	ctx context.Context,
	sessionID string,
	runtimeConfiguration h00RuntimeConfiguration,
	body h00OpenSessionBody,
) (*h00TypeScriptProviderSession, error) {
	if body.ExpectedSemanticInputs != nil {
		return nil, fmt.Errorf("TypeScript semantic inputs are provider-observed")
	}
	repositoryRoot, err := h00CanonicalDirectory(body.RepositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("repository root: %w", err)
	}
	executionRoot, err := h00CanonicalDirectory(body.ExecutionRoot)
	if err != nil {
		return nil, fmt.Errorf("execution root: %w", err)
	}
	if body.Authority.SessionID != sessionID ||
		body.Authority.RootSHA256 != h00SHA256([]byte(repositoryRoot)) ||
		body.Authority.ConfigurationSHA256 != runtimeConfiguration.ConfigurationSHA256 ||
		body.Authority.WorkspaceResolutionSHA256 != nil || body.Authority.SemanticInputsSHA256 != nil ||
		!h00IsSHA256(body.Authority.RootTopologySHA256) || body.Authority.SourceEpoch == 0 {
		return nil, fmt.Errorf("open-session authority differs from canonical roots or runtime")
	}
	populationSHA, err := h00SourcePopulationSHA256(body.Sources)
	if err != nil || populationSHA != body.Authority.PopulationSHA256 {
		return nil, fmt.Errorf("open-session source population mismatch")
	}
	sources := make(map[string]h00SourceIdentity, len(body.Sources))
	for _, source := range body.Sources {
		if _, duplicate := sources[source.DocumentPath]; duplicate {
			return nil, fmt.Errorf("duplicate TypeScript provider source %q", source.DocumentPath)
		}
		sources[source.DocumentPath] = source
	}
	engine, err := h00StartTypeScriptEngine(
		ctx,
		repositoryRoot,
		executionRoot,
		body.ExecutionPrefix,
		sources,
	)
	if err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			engine.close()
		}
	}()
	workspaceSHA, semanticInputs, health, err := engine.authorityEvidence(ctx)
	if err != nil {
		return nil, err
	}
	terminalWorkspace, terminalInputs, terminalHealth, err := engine.authorityEvidence(ctx)
	if err != nil || workspaceSHA != terminalWorkspace ||
		!reflect.DeepEqual(semanticInputs, terminalInputs) || !reflect.DeepEqual(health, terminalHealth) {
		return nil, fmt.Errorf("TypeScript project authority changed during session admission")
	}
	semanticSHA, err := h00SemanticInputsSHA256(semanticInputs)
	if err != nil {
		return nil, err
	}
	body.Authority.WorkspaceResolutionSHA256 = &workspaceSHA
	body.Authority.SemanticInputsSHA256 = &semanticSHA
	opened = true
	return &h00TypeScriptProviderSession{
		engine: engine, authority: body.Authority,
		semanticInputs: semanticInputs, health: health,
	}, nil
}

func (session *h00TypeScriptProviderSession) close() {
	if session.engine != nil {
		session.engine.close()
		session.engine = nil
	}
}

func (session *h00TypeScriptProviderSession) verifyAuthorityInputs(ctx context.Context) error {
	if session.engine == nil {
		return fmt.Errorf("TypeScript provider session is closed")
	}
	workspaceSHA, semanticInputs, health, err := session.engine.authorityEvidence(ctx)
	if err != nil {
		return err
	}
	if session.authority.WorkspaceResolutionSHA256 == nil ||
		*session.authority.WorkspaceResolutionSHA256 != workspaceSHA ||
		!reflect.DeepEqual(session.semanticInputs, semanticInputs) ||
		!reflect.DeepEqual(session.health, health) {
		return fmt.Errorf("TypeScript project authority changed after session admission")
	}
	return nil
}

func (session *h00TypeScriptProviderSession) applyEpoch(
	ctx context.Context,
	body h00ApplyEpochBody,
	attachments [][]byte,
) error {
	if !h00AuthorityEqual(body.PreviousAuthority, session.authority) ||
		body.NextAuthority.SessionID != session.authority.SessionID ||
		body.NextAuthority.RootSHA256 != session.authority.RootSHA256 ||
		body.NextAuthority.RootTopologySHA256 != session.authority.RootTopologySHA256 ||
		body.NextAuthority.ConfigurationSHA256 != session.authority.ConfigurationSHA256 ||
		!h00OptionalStringEqual(body.NextAuthority.WorkspaceResolutionSHA256, session.authority.WorkspaceResolutionSHA256) ||
		!h00OptionalStringEqual(body.NextAuthority.SemanticInputsSHA256, session.authority.SemanticInputsSHA256) ||
		!h00IsExactSuccessorEpoch(session.authority.SourceEpoch, body.NextAuthority.SourceEpoch) || len(body.Changes) == 0 {
		return fmt.Errorf("invalid TypeScript provider authority transition")
	}
	nextSources := make(map[string]h00SourceIdentity, len(session.engine.sources))
	for path, source := range session.engine.sources {
		nextSources[path] = source
	}
	claimed := make(map[uint32]struct{}, len(attachments))
	replacements := make([]h00TypeScriptReplacement, 0, len(body.Changes))
	for _, change := range body.Changes {
		prior, ok := session.engine.sources[change.DocumentPath]
		if !ok || change.Outcome != "replace" || change.Language != h00ProviderLanguage ||
			prior.ContentIdentity != change.PreviousContentIdentity ||
			prior.ContentSHA256 != change.PreviousContentSHA256 ||
			int(change.AttachmentIndex) >= len(attachments) {
			return fmt.Errorf("invalid TypeScript source replacement for %q", change.DocumentPath)
		}
		if _, duplicate := claimed[change.AttachmentIndex]; duplicate {
			return fmt.Errorf("replacement attachment is reused")
		}
		claimed[change.AttachmentIndex] = struct{}{}
		contents := attachments[change.AttachmentIndex]
		if h00SHA256(contents) != change.ContentSHA256 ||
			change.ContentIdentity == change.PreviousContentIdentity ||
			change.ContentSHA256 == change.PreviousContentSHA256 {
			return fmt.Errorf("replacement content identity mismatch for %q", change.DocumentPath)
		}
		next := h00SourceIdentity{
			DocumentPath:    change.DocumentPath,
			Language:        change.Language,
			ContentIdentity: change.ContentIdentity,
			ContentSHA256:   change.ContentSHA256,
		}
		nextSources[change.DocumentPath] = next
		replacements = append(replacements, h00TypeScriptReplacement{
			path:    change.DocumentPath,
			bytes:   contents,
			version: session.engine.versions[change.DocumentPath] + 1,
			next:    next,
		})
	}
	if len(claimed) != len(attachments) {
		return fmt.Errorf("replacement frame contains unclaimed attachments")
	}
	population := make([]h00SourceIdentity, 0, len(nextSources))
	for _, source := range nextSources {
		population = append(population, source)
	}
	populationSHA, err := h00SourcePopulationSHA256(population)
	if err != nil || populationSHA != body.NextAuthority.PopulationSHA256 {
		return fmt.Errorf("replacement population differs from next authority")
	}
	if err := session.engine.applyReplacements(ctx, replacements); err != nil {
		return err
	}
	workspaceSHA, semanticInputs, health, err := session.engine.authorityEvidence(ctx)
	if err != nil || session.authority.WorkspaceResolutionSHA256 == nil ||
		*session.authority.WorkspaceResolutionSHA256 != workspaceSHA ||
		!reflect.DeepEqual(session.semanticInputs, semanticInputs) ||
		!reflect.DeepEqual(session.health, health) {
		return fmt.Errorf("TypeScript project authority changed during source epoch application")
	}
	session.authority = body.NextAuthority
	return nil
}

func (session *h00TypeScriptProviderSession) exportDocuments(
	ctx context.Context,
	authority h00Authority,
	documents []string,
) ([]h00DocumentOutcome, [][]byte, error) {
	if !h00AuthorityEqual(authority, session.authority) || len(documents) == 0 ||
		len(documents) > h00MaxDocumentPaths {
		return nil, nil, fmt.Errorf("export authority or document population mismatch")
	}
	paths := append([]string(nil), documents...)
	sort.Strings(paths)
	for index, path := range paths {
		if _, ok := session.engine.sources[path]; !ok || !h00SafeDocumentPath(path) {
			return nil, nil, fmt.Errorf("export path is outside TypeScript session population: %q", path)
		}
		if index > 0 && paths[index-1] == path {
			return nil, nil, fmt.Errorf("duplicate TypeScript export path %q", path)
		}
	}
	exported, err := session.engine.exportDocuments(ctx, paths)
	if err != nil {
		return nil, nil, err
	}
	byPath := make(map[string]*scip.Document, len(exported))
	for _, document := range exported {
		if _, duplicate := byPath[document.RelativePath]; duplicate {
			return nil, nil, fmt.Errorf("duplicate exported SCIP document %q", document.RelativePath)
		}
		byPath[document.RelativePath] = document
	}
	outcomes := make([]h00DocumentOutcome, 0, len(paths))
	attachments := make([][]byte, 0, len(paths))
	for _, path := range paths {
		source := session.engine.sources[path]
		document := byPath[path]
		if document == nil {
			outcomes = append(outcomes, h00DocumentOutcome{
				Outcome: "omitted", DocumentPath: path, Language: h00ProviderLanguage,
				ContentIdentity: source.ContentIdentity,
			})
			continue
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(document)
		if err != nil || len(encoded) == 0 {
			return nil, nil, fmt.Errorf("serialize canonical TypeScript document %q: %w", path, err)
		}
		index := uint32(len(attachments))
		attachments = append(attachments, encoded)
		outcomes = append(outcomes, h00DocumentOutcome{
			Outcome: "present", DocumentPath: path, Language: h00ProviderLanguage,
			ContentIdentity:         source.ContentIdentity,
			CanonicalDocumentSHA256: h00SHA256(encoded), AttachmentIndex: &index,
		})
	}
	if err := session.verifyAuthorityInputs(ctx); err != nil {
		return nil, nil, err
	}
	return outcomes, attachments, nil
}

func h00ObserveRuntimeConfiguration() (h00RuntimeConfiguration, error) {
	resolved := os.Getenv(h00ResolvedToolchainSHA256Env)
	if !h00IsSHA256(resolved) || !h00IsSHA256(h00ProviderPatchSHA256) {
		return h00RuntimeConfiguration{}, fmt.Errorf("required resolved TypeScript runtime identity is absent")
	}
	workspace := strings.Join([]string{
		"typescript-native=" + h00TypescriptVersion,
		"typescript-revision=" + h00TypescriptRevision,
		"scip-bindings=" + h00ScipBindingsVersion,
		"position-encoding=utf8",
		"automatic-type-acquisition=disabled",
		"watch-service=disabled",
	}, "\x00")
	return h00BuildRuntimeConfiguration(
		resolved,
		map[string][]byte{
			"provider_patch":    []byte(h00ProviderPatchSHA256),
			"scip_bindings":     []byte(h00ScipBindingsVersion + "@" + h00ScipBindingsRevision),
			"typescript_native": []byte(h00TypescriptVersion + "@" + h00TypescriptRevision),
		},
		nil,
		[]byte(workspace),
	)
}

func h00AuthorityEqual(left, right h00Authority) bool {
	return left.SessionID == right.SessionID && left.RootSHA256 == right.RootSHA256 &&
		left.RootTopologySHA256 == right.RootTopologySHA256 &&
		left.ConfigurationSHA256 == right.ConfigurationSHA256 &&
		h00OptionalStringEqual(left.WorkspaceResolutionSHA256, right.WorkspaceResolutionSHA256) &&
		h00OptionalStringEqual(left.SemanticInputsSHA256, right.SemanticInputsSHA256) &&
		left.PopulationSHA256 == right.PopulationSHA256 && left.SourceEpoch == right.SourceEpoch
}

func h00OptionalStringEqual(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
