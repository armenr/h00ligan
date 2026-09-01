package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scip-code/scip/bindings/go/scip"
	"golang.org/x/tools/gopls/internal/cache"
	"golang.org/x/tools/gopls/internal/protocol"
	goplsserver "golang.org/x/tools/gopls/internal/server"
	"golang.org/x/tools/gopls/internal/settings"
	"google.golang.org/protobuf/proto"
)

type h00OpenSessionBody struct {
	Operation              string              `json:"operation"`
	RepositoryRoot         string              `json:"repository_root"`
	ExecutionRoot          string              `json:"execution_root"`
	ExecutionPrefix        string              `json:"execution_prefix"`
	Authority              h00Authority        `json:"authority"`
	Sources                []h00SourceIdentity `json:"sources"`
	ExpectedSemanticInputs h00SemanticInputs   `json:"expected_semantic_inputs"`
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
	Outcome                 string `json:"outcome"`
	DocumentPath            string `json:"document_path"`
	Language                string `json:"language"`
	ContentIdentity         string `json:"content_identity"`
	CanonicalDocumentSHA256 string `json:"canonical_document_sha256,omitempty"`
	// A pointer distinguishes a Present document's valid attachment zero from
	// an Omitted document, for which this deny-unknown-fields protocol member
	// must be absent entirely.
	AttachmentIndex *uint32 `json:"attachment_index,omitempty"`
}

const (
	h00CallableLivenessAnalysisID      = "callable_liveness"
	h00CallableLivenessAnalysisSchema  = "h00/semantic-provider/callable-liveness/v1"
	h00CallableLivenessConfigurationID = "go-rta-v1/production=main+public-api/tests=go-test-roots"
)

type h00AnalysisOutcome struct {
	AnalysisID              string `json:"analysis_id"`
	SchemaVersion           string `json:"schema_version"`
	ConfigurationID         string `json:"configuration_id"`
	Language                string `json:"language"`
	CanonicalAnalysisSHA256 string `json:"canonical_analysis_sha256"`
	AttachmentIndex         uint32 `json:"attachment_index"`
}

type h00GoSession struct {
	ctx              context.Context
	client           *client
	server           protocol.Server
	repositoryRoot   string
	executionRoot    string
	executionPrefix  string
	authority        h00Authority
	sources          map[string]h00SourceIdentity
	overlayVersions  map[string]int32
	semanticInputs   h00SemanticInputs
	workspaceWitness goplsserver.H00WorkspaceWitness
	goStdlibVersion  string
	health           h00Health
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
	var session *h00GoSession
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
		body, attachments, closeProvider := h00HandleRequest(
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

func h00HandleRequest(
	ctx context.Context,
	identity h00ProviderIdentity,
	runtimeConfiguration h00RuntimeConfiguration,
	session **h00GoSession,
	lastRequestID *uint64,
	frame h00Frame,
) (any, [][]byte, bool) {
	request := frame.Metadata
	errorBody := func(code string, err error) (any, [][]byte, bool) {
		message := err.Error()
		if len(message) > 1024 {
			message = message[:1024]
		}
		return map[string]any{
			"result": "error", "code": code, "message": message, "retryable": false,
		}, nil, false
	}
	if request.RequestID == 0 || request.RequestID <= *lastRequestID {
		return errorBody("replayed_request", fmt.Errorf("request ID is not strictly monotonic"))
	}
	*lastRequestID = request.RequestID
	if request.SessionID == "" || !h00IdentityEqual(request.ExpectedProvider, identity) {
		return errorBody("invalid_request", fmt.Errorf("request identity differs from this provider"))
	}
	operation, err := h00DecodeOperation(request.Body)
	if err != nil {
		return errorBody("invalid_request", err)
	}
	if *session != nil && request.SessionID != (*session).authority.SessionID {
		body, attachments, _ := errorBody(
			"invalid_request",
			fmt.Errorf("request session differs from the process-owned Go session"),
		)
		return body, attachments, true
	}
	if operation.Operation != "close_session" {
		current, err := h00ObserveRuntimeConfiguration()
		if err != nil || current.ConfigurationSHA256 != runtimeConfiguration.ConfigurationSHA256 {
			if err == nil {
				err = fmt.Errorf("provider runtime changed after process admission")
			}
			return errorBody("request_failed", err)
		}
	}
	if *session != nil && operation.Operation != "hello" && operation.Operation != "reconfigure_session" &&
		operation.Operation != "close_session" {
		if err := (*session).verifyAuthorityInputs(); err != nil {
			return errorBody("request_failed", err)
		}
	}

	switch operation.Operation {
	case "hello":
		if len(frame.Attachments) != 0 {
			return errorBody("invalid_request", fmt.Errorf("hello carries attachments"))
		}
		if _, err := h00DecodeBody[h00RequestOperation](request.Body); err != nil {
			return errorBody("invalid_request", err)
		}
		return map[string]any{
			"result": "hello", "limits": h00Limits(), "runtime_configuration": runtimeConfiguration,
		}, nil, false
	case "open_session":
		if *session != nil || len(frame.Attachments) != 0 {
			return errorBody("request_failed", fmt.Errorf("one process owns exactly one root session"))
		}
		body, err := h00DecodeBody[h00OpenSessionBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err)
		}
		opened, err := h00OpenGoSession(ctx, request.SessionID, runtimeConfiguration, body)
		if err != nil {
			return errorBody("request_failed", err)
		}
		*session = opened
		return map[string]any{
			"result":          "session_opened",
			"authority":       opened.authority,
			"health":          opened.health,
			"semantic_inputs": opened.semanticInputs,
		}, nil, false
	case "reconfigure_session":
		if *session == nil || len(frame.Attachments) != 0 {
			return errorBody("request_failed", fmt.Errorf("invalid session reconfiguration"))
		}
		body, err := h00DecodeBody[h00ReconfigureSessionBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err)
		}
		authority, semanticInputs, err := (*session).reconfigureProjectInputs(body)
		if err != nil {
			return errorBody("request_failed", err)
		}
		return map[string]any{
			"result": "session_reconfigured", "authority": authority,
			"health": (*session).health, "semantic_inputs": semanticInputs,
		}, nil, false
	case "apply_epoch":
		if *session == nil {
			return errorBody("request_failed", fmt.Errorf("provider session is not open"))
		}
		body, err := h00DecodeBody[h00ApplyEpochBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err)
		}
		if err := (*session).applyEpoch(body, frame.Attachments); err != nil {
			return errorBody("request_failed", err)
		}
		return map[string]any{
			"result": "epoch_applied", "authority": (*session).authority, "health": (*session).health,
		}, nil, false
	case "refresh_affected":
		if *session == nil {
			return errorBody("request_failed", fmt.Errorf("provider session is not open"))
		}
		body, err := h00DecodeBody[h00RefreshAffectedBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err)
		}
		includeCallableLiveness, err := h00RequestsCallableLiveness(body.Analyses)
		if err != nil {
			return errorBody("invalid_request", err)
		}
		if err := (*session).applyEpoch(h00ApplyEpochBody{
			Operation: body.Operation, PreviousAuthority: body.PreviousAuthority,
			NextAuthority: body.NextAuthority, Changes: body.Changes,
		}, frame.Attachments); err != nil {
			return errorBody("request_failed", err)
		}
		outcomes, attachments, callableLiveness, err := (*session).exportDocuments(
			body.NextAuthority,
			body.Documents,
			includeCallableLiveness,
		)
		if err != nil {
			return errorBody("request_failed", err)
		}
		analysisOutcomes := make([]h00AnalysisOutcome, 0, 1)
		if includeCallableLiveness {
			attachmentIndex := uint32(len(attachments))
			attachments = append(attachments, callableLiveness)
			analysisOutcomes = append(analysisOutcomes, h00AnalysisOutcome{
				AnalysisID: h00CallableLivenessAnalysisID, SchemaVersion: h00CallableLivenessAnalysisSchema,
				ConfigurationID: h00CallableLivenessConfigurationID, Language: h00ProviderLanguage,
				CanonicalAnalysisSHA256: h00SHA256(callableLiveness), AttachmentIndex: attachmentIndex,
			})
		}
		terminalRuntime, err := h00ObserveRuntimeConfiguration()
		if err != nil || terminalRuntime.ConfigurationSHA256 != runtimeConfiguration.ConfigurationSHA256 {
			if err == nil {
				err = fmt.Errorf("provider runtime changed during affected refresh")
			}
			return errorBody("request_failed", err)
		}
		return map[string]any{
			"result": "affected_refreshed", "authority": (*session).authority,
			"parent_snapshot_sha256": body.ParentSnapshotSHA256,
			"health":                 (*session).health,
			"runtime_configuration":  terminalRuntime,
			"outcomes":               outcomes,
			"analyses":               analysisOutcomes,
		}, attachments, false
	case "certify_full":
		if *session == nil || len(frame.Attachments) != 0 {
			return errorBody("request_failed", fmt.Errorf("invalid full-certification session"))
		}
		body, err := h00DecodeBody[h00CertifyFullBody](request.Body)
		if err != nil {
			return errorBody("invalid_request", err)
		}
		includeCallableLiveness, err := h00RequestsCallableLiveness(body.Analyses)
		if err != nil {
			return errorBody("invalid_request", err)
		}
		documents := make([]string, 0, len((*session).sources))
		for path := range (*session).sources {
			documents = append(documents, path)
		}
		sort.Strings(documents)
		outcomes, attachments, callableLiveness, err := (*session).exportDocuments(
			body.Authority,
			documents,
			includeCallableLiveness,
		)
		if err != nil {
			return errorBody("request_failed", err)
		}
		analysisOutcomes := make([]h00AnalysisOutcome, 0, 1)
		if includeCallableLiveness {
			attachmentIndex := uint32(len(attachments))
			attachments = append(attachments, callableLiveness)
			analysisOutcomes = append(analysisOutcomes, h00AnalysisOutcome{
				AnalysisID: h00CallableLivenessAnalysisID, SchemaVersion: h00CallableLivenessAnalysisSchema,
				ConfigurationID: h00CallableLivenessConfigurationID, Language: h00ProviderLanguage,
				CanonicalAnalysisSHA256: h00SHA256(callableLiveness), AttachmentIndex: attachmentIndex,
			})
		}
		return map[string]any{
			"result": "full_certification", "authority": (*session).authority,
			"health": (*session).health, "outcomes": outcomes, "analyses": analysisOutcomes,
		}, attachments, false
	case "close_session":
		if len(frame.Attachments) != 0 {
			return errorBody("invalid_request", fmt.Errorf("close carries attachments"))
		}
		body, err := h00DecodeBody[h00RequestOperation](request.Body)
		if err != nil || body.Operation != "close_session" {
			if err == nil {
				err = fmt.Errorf("close body operation is %q", body.Operation)
			}
			return errorBody("invalid_request", err)
		}
		return map[string]any{"result": "session_closed"}, nil, true
	default:
		return errorBody("invalid_request", fmt.Errorf("unsupported provider operation %q", operation.Operation))
	}
}

func h00OpenGoSession(
	ctx context.Context,
	sessionID string,
	runtimeConfiguration h00RuntimeConfiguration,
	body h00OpenSessionBody,
) (*h00GoSession, error) {
	repositoryRoot, err := h00CanonicalDirectory(body.RepositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("repository root: %w", err)
	}
	executionRoot, err := h00CanonicalDirectory(body.ExecutionRoot)
	if err != nil {
		return nil, fmt.Errorf("execution root: %w", err)
	}
	if !h00PathWithin(executionRoot, repositoryRoot) {
		return nil, fmt.Errorf("execution root escapes repository root")
	}
	prefix, err := filepath.Rel(repositoryRoot, executionRoot)
	if err != nil {
		return nil, err
	}
	if prefix == "." {
		prefix = ""
	} else {
		prefix = filepath.ToSlash(prefix)
	}
	if prefix != body.ExecutionPrefix || body.Authority.SessionID != sessionID ||
		body.Authority.RootSHA256 != h00SHA256([]byte(repositoryRoot)) ||
		body.Authority.ConfigurationSHA256 != runtimeConfiguration.ConfigurationSHA256 ||
		body.Authority.WorkspaceResolutionSHA256 != nil || body.Authority.SemanticInputsSHA256 != nil {
		return nil, fmt.Errorf("open-session authority differs from canonical roots or runtime")
	}
	populationSHA, err := h00SourcePopulationSHA256(body.Sources)
	if err != nil || populationSHA != body.Authority.PopulationSHA256 {
		return nil, fmt.Errorf("open-session source population mismatch")
	}

	sources := make(map[string]h00SourceIdentity, len(body.Sources))
	overlayVersions := make(map[string]int32)
	sourceURIs := make([]protocol.DocumentURI, 0, len(body.Sources))
	sourceSHA256s := make(map[protocol.DocumentURI]string, len(body.Sources))
	// Validate the complete client-owned source population before starting
	// gopls. Unchanged files remain disk-backed for normal workspace loading,
	// but the initialized snapshot is joined below to these exact SHA-256
	// identities before it can grant authority. ApplyEpoch opens only an actual
	// replacement on its first change and versions that exact overlay thereafter.
	for _, source := range body.Sources {
		if source.Language != h00ProviderLanguage || !h00SafeDocumentPath(source.DocumentPath) {
			return nil, fmt.Errorf("non-Go or unsafe source entered Go provider: %q", source.DocumentPath)
		}
		if _, duplicate := sources[source.DocumentPath]; duplicate {
			return nil, fmt.Errorf("duplicate provider source %q", source.DocumentPath)
		}
		absolute := filepath.Join(repositoryRoot, filepath.FromSlash(source.DocumentPath))
		if !h00PathWithin(absolute, executionRoot) {
			return nil, fmt.Errorf("provider source escapes execution root: %q", source.DocumentPath)
		}
		contents, err := os.ReadFile(absolute)
		if err != nil || h00SHA256(contents) != source.ContentSHA256 {
			return nil, fmt.Errorf("provider source identity mismatch: %q", source.DocumentPath)
		}
		uri := protocol.URIFromPath(absolute)
		sourceURIs = append(sourceURIs, uri)
		sourceSHA256s[uri] = source.ContentSHA256
		sources[source.DocumentPath] = source
	}
	if len(sourceURIs) == 0 {
		return nil, fmt.Errorf("empty provider source population")
	}
	semanticInputs, err := h00CaptureGoSemanticInputs(repositoryRoot, body.ExpectedSemanticInputs)
	if err != nil {
		return nil, err
	}
	if !h00SemanticInputsEqual(semanticInputs, body.ExpectedSemanticInputs) {
		return nil, fmt.Errorf("open-session semantic inputs differ from the client-owned inventory")
	}

	app := New()
	client := newClient(app)
	options := settings.DefaultOptions(app.options)
	cacheSession := cache.NewSession(ctx, cache.New(nil))
	semanticServer := goplsserver.New(cacheSession, client, options)
	params := &protocol.ParamInitialize{}
	params.RootURI = protocol.URIFromPath(executionRoot)
	params.Capabilities.Workspace.Configuration = true
	if err := client.initialize(ctx, semanticServer, params); err != nil {
		return nil, fmt.Errorf("initialize gopls: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			client.terminate(ctx)
		}
	}()
	workspaceWitness, snapshotInputs, err := goplsserver.H00InspectWorkspaceResolutionAndInputs(
		ctx, semanticServer, sourceURIs, sourceSHA256s,
		h00SemanticInputURIs(repositoryRoot, semanticInputs),
	)
	if err != nil {
		return nil, err
	}
	if err := h00MatchSnapshotSemanticInputs(semanticInputs, snapshotInputs); err != nil {
		return nil, err
	}
	terminalInputs, err := h00CaptureGoSemanticInputs(repositoryRoot, body.ExpectedSemanticInputs)
	if err != nil || !h00SemanticInputsEqual(semanticInputs, terminalInputs) {
		return nil, fmt.Errorf("open-session semantic inputs changed during workspace observation")
	}
	semanticInputsSHA, err := h00SemanticInputsSHA256(semanticInputs)
	if err != nil {
		return nil, err
	}
	body.Authority.WorkspaceResolutionSHA256 = &workspaceWitness.SHA256
	body.Authority.SemanticInputsSHA256 = &semanticInputsSHA
	opened = true
	return &h00GoSession{
		ctx: ctx, client: client, server: semanticServer,
		repositoryRoot: repositoryRoot, executionRoot: executionRoot, executionPrefix: prefix,
		authority: body.Authority, sources: sources, overlayVersions: overlayVersions,
		semanticInputs:   semanticInputs,
		workspaceWitness: workspaceWitness,
		goStdlibVersion:  runtimeConfiguration.GoStdlibVersion,
		health: h00Health{
			Components: map[string]string{
				"package_graph": "healthy", "type_checking": "healthy",
			},
			DiagnosticsComplete: true, DegradationReasons: []string{},
		},
	}, nil
}

func (session *h00GoSession) close() {
	if session.client != nil {
		session.client.terminate(session.ctx)
		session.client = nil
	}
}

func (session *h00GoSession) verifyAuthorityInputs() error {
	observedInputs, err := h00CaptureGoSemanticInputs(session.repositoryRoot, session.semanticInputs)
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(session.semanticInputs)
	observed, _ := json.Marshal(observedInputs)
	if !bytes.Equal(expected, observed) {
		return fmt.Errorf("Go semantic inputs changed after session admission")
	}
	return nil
}

func (session *h00GoSession) reconfigureProjectInputs(body h00ReconfigureSessionBody) (h00Authority, h00SemanticInputs, error) {
	if !h00AuthorityEqual(body.PreviousAuthority, session.authority) ||
		body.NextAuthority.SessionID != session.authority.SessionID ||
		body.NextAuthority.RootSHA256 != session.authority.RootSHA256 ||
		body.NextAuthority.RootTopologySHA256 == session.authority.RootTopologySHA256 ||
		body.NextAuthority.ConfigurationSHA256 != session.authority.ConfigurationSHA256 ||
		body.NextAuthority.WorkspaceResolutionSHA256 != nil ||
		body.NextAuthority.SemanticInputsSHA256 != nil ||
		body.NextAuthority.PopulationSHA256 != session.authority.PopulationSHA256 ||
		!h00IsExactSuccessorEpoch(session.authority.SourceEpoch, body.NextAuthority.SourceEpoch) {
		return h00Authority{}, h00SemanticInputs{}, fmt.Errorf("invalid Go project-input authority transition")
	}

	nextInputs, err := h00CaptureGoSemanticInputs(session.repositoryRoot, body.ExpectedSemanticInputs)
	if err != nil {
		return h00Authority{}, h00SemanticInputs{}, err
	}
	if !h00SemanticInputsEqual(nextInputs, body.ExpectedSemanticInputs) {
		return h00Authority{}, h00SemanticInputs{}, fmt.Errorf("reconfigured semantic inputs differ from the client-owned inventory")
	}
	changes, err := h00ProjectInputEvents(session.repositoryRoot, session.semanticInputs, nextInputs)
	if err != nil {
		return h00Authority{}, h00SemanticInputs{}, err
	}
	if err := session.server.DidChangeWatchedFiles(session.ctx, &protocol.DidChangeWatchedFilesParams{Changes: changes}); err != nil {
		return h00Authority{}, h00SemanticInputs{}, fmt.Errorf("reconfigure gopls project inputs: %w", err)
	}

	openedURIs := make([]protocol.DocumentURI, 0, len(session.sources))
	sourceSHA256s := make(map[protocol.DocumentURI]string, len(session.sources))
	for path, source := range session.sources {
		uri := protocol.URIFromPath(filepath.Join(
			session.repositoryRoot,
			filepath.FromSlash(path),
		))
		openedURIs = append(openedURIs, uri)
		sourceSHA256s[uri] = source.ContentSHA256
	}
	sort.Slice(openedURIs, func(i, j int) bool { return openedURIs[i] < openedURIs[j] })
	workspaceWitness, snapshotInputs, err := goplsserver.H00InspectWorkspaceResolutionAndInputs(
		session.ctx, session.server, openedURIs, sourceSHA256s,
		h00SemanticInputURIs(session.repositoryRoot, nextInputs),
	)
	if err != nil {
		return h00Authority{}, h00SemanticInputs{}, err
	}
	if err := h00MatchSnapshotSemanticInputs(nextInputs, snapshotInputs); err != nil {
		return h00Authority{}, h00SemanticInputs{}, err
	}
	terminalInputs, err := h00CaptureGoSemanticInputs(session.repositoryRoot, body.ExpectedSemanticInputs)
	if err != nil || !h00SemanticInputsEqual(nextInputs, terminalInputs) {
		return h00Authority{}, h00SemanticInputs{}, fmt.Errorf("reconfigured semantic inputs changed during workspace observation")
	}
	semanticInputsSHA, err := h00SemanticInputsSHA256(nextInputs)
	if err != nil {
		return h00Authority{}, h00SemanticInputs{}, err
	}
	nextAuthority := body.NextAuthority
	nextAuthority.WorkspaceResolutionSHA256 = &workspaceWitness.SHA256
	nextAuthority.SemanticInputsSHA256 = &semanticInputsSHA
	session.authority = nextAuthority
	session.semanticInputs = nextInputs
	session.workspaceWitness = workspaceWitness
	return nextAuthority, nextInputs, nil
}

func h00ProjectInputEvents(repositoryRoot string, previous, next h00SemanticInputs) ([]protocol.FileEvent, error) {
	if previous.SchemaVersion != h00ProviderSemanticInputsSchema ||
		next.SchemaVersion != h00ProviderSemanticInputsSchema ||
		previous.Coverage != "complete" || next.Coverage != "complete" ||
		len(previous.Issues) != 0 || len(next.Issues) != 0 {
		return nil, fmt.Errorf("project-input reconfiguration requires complete semantic input evidence")
	}
	previousEnvironment, _ := json.Marshal(previous.Environment)
	nextEnvironment, _ := json.Marshal(next.Environment)
	if !bytes.Equal(previousEnvironment, nextEnvironment) {
		return nil, fmt.Errorf("project-input reconfiguration cannot change the provider environment")
	}
	priorPaths := make(map[string]h00SemanticPathInput, len(previous.Paths))
	for _, input := range previous.Paths {
		if _, duplicate := priorPaths[input.Path]; duplicate {
			return nil, fmt.Errorf("duplicate prior semantic input %q", input.Path)
		}
		priorPaths[input.Path] = input
	}
	if len(priorPaths) != len(next.Paths) {
		return nil, fmt.Errorf("project-input path population changed")
	}
	events := make([]protocol.FileEvent, 0, len(next.Paths))
	for _, input := range next.Paths {
		prior, ok := priorPaths[input.Path]
		if !ok {
			return nil, fmt.Errorf("project-input path population changed at %q", input.Path)
		}
		delete(priorPaths, input.Path)
		if prior == input {
			continue
		}
		var changeType protocol.FileChangeType
		switch {
		case prior.Kind == "missing" && input.Kind == "file":
			changeType = protocol.Created
		case prior.Kind == "file" && input.Kind == "missing":
			changeType = protocol.Deleted
		case prior.Kind == "file" && input.Kind == "file":
			changeType = protocol.Changed
		default:
			return nil, fmt.Errorf("unsupported project-input transition for %q", input.Path)
		}
		absolute := filepath.Join(repositoryRoot, filepath.FromSlash(input.Path))
		if !h00PathWithin(absolute, repositoryRoot) {
			return nil, fmt.Errorf("project input escapes repository root: %q", input.Path)
		}
		events = append(events, protocol.FileEvent{URI: protocol.URIFromPath(absolute), Type: changeType})
	}
	if len(priorPaths) != 0 || len(events) == 0 {
		return nil, fmt.Errorf("project-input reconfiguration has no exact path delta")
	}
	sort.Slice(events, func(i, j int) bool { return events[i].URI < events[j].URI })
	return events, nil
}

func (session *h00GoSession) applyEpoch(body h00ApplyEpochBody, attachments [][]byte) error {
	if !h00AuthorityEqual(body.PreviousAuthority, session.authority) ||
		body.NextAuthority.SessionID != session.authority.SessionID ||
		body.NextAuthority.RootSHA256 != session.authority.RootSHA256 ||
		body.NextAuthority.RootTopologySHA256 != session.authority.RootTopologySHA256 ||
		body.NextAuthority.ConfigurationSHA256 != session.authority.ConfigurationSHA256 ||
		!h00OptionalStringEqual(body.NextAuthority.WorkspaceResolutionSHA256, session.authority.WorkspaceResolutionSHA256) ||
		!h00OptionalStringEqual(body.NextAuthority.SemanticInputsSHA256, session.authority.SemanticInputsSHA256) ||
		!h00IsExactSuccessorEpoch(session.authority.SourceEpoch, body.NextAuthority.SourceEpoch) || len(body.Changes) == 0 {
		return fmt.Errorf("invalid Go provider authority transition")
	}
	nextSources := make(map[string]h00SourceIdentity, len(session.sources))
	for path, source := range session.sources {
		nextSources[path] = source
	}
	claimed := make(map[uint32]struct{}, len(attachments))
	type replacement struct {
		path        string
		bytes       []byte
		version     int32
		alreadyOpen bool
		next        h00SourceIdentity
	}
	replacements := make([]replacement, 0, len(body.Changes))
	for _, change := range body.Changes {
		prior, ok := session.sources[change.DocumentPath]
		if !ok || change.Outcome != "replace" || change.Language != h00ProviderLanguage ||
			prior.ContentIdentity != change.PreviousContentIdentity ||
			prior.ContentSHA256 != change.PreviousContentSHA256 ||
			int(change.AttachmentIndex) >= len(attachments) {
			return fmt.Errorf("invalid Go source replacement for %q", change.DocumentPath)
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
			DocumentPath: change.DocumentPath, Language: change.Language,
			ContentIdentity: change.ContentIdentity, ContentSHA256: change.ContentSHA256,
		}
		nextSources[change.DocumentPath] = next
		version, alreadyOpen := session.overlayVersions[change.DocumentPath]
		replacements = append(replacements, replacement{
			path: change.DocumentPath, bytes: contents, version: version + 1,
			alreadyOpen: alreadyOpen, next: next,
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
	for _, replacement := range replacements {
		uri := protocol.URIFromPath(filepath.Join(session.repositoryRoot, filepath.FromSlash(replacement.path)))
		if replacement.alreadyOpen {
			if err := session.server.DidChange(session.ctx, &protocol.DidChangeTextDocumentParams{
				TextDocument: protocol.VersionedTextDocumentIdentifier{
					TextDocumentIdentifier: protocol.TextDocumentIdentifier{URI: uri},
					Version:                replacement.version,
				},
				ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: string(replacement.bytes)}},
			}); err != nil {
				return fmt.Errorf("change Go provider source %q: %w", replacement.path, err)
			}
		} else if err := session.server.DidOpen(session.ctx, &protocol.DidOpenTextDocumentParams{
			TextDocument: protocol.TextDocumentItem{
				URI: uri, LanguageID: h00ProviderLanguage,
				Version: replacement.version, Text: string(replacement.bytes),
			},
		}); err != nil {
			return fmt.Errorf("open changed Go provider source %q: %w", replacement.path, err)
		}
		session.overlayVersions[replacement.path] = replacement.version
	}
	session.sources = nextSources
	session.authority = body.NextAuthority
	if err := session.verifyAuthorityInputs(); err != nil {
		return fmt.Errorf("verify Go semantic inputs after source-epoch application: %w", err)
	}
	return nil
}

func (session *h00GoSession) exportDocuments(
	authority h00Authority,
	documents []string,
	includeCallableLiveness bool,
) ([]h00DocumentOutcome, [][]byte, []byte, error) {
	if !h00AuthorityEqual(authority, session.authority) || len(documents) == 0 ||
		len(documents) > h00MaxDocumentPaths {
		return nil, nil, nil, fmt.Errorf("export authority or document population mismatch")
	}
	requested := make(map[string]protocol.DocumentURI, len(documents))
	for _, path := range documents {
		if _, ok := session.sources[path]; !ok || !h00SafeDocumentPath(path) {
			return nil, nil, nil, fmt.Errorf("export path is outside session population: %q", path)
		}
		if _, duplicate := requested[path]; duplicate {
			return nil, nil, nil, fmt.Errorf("duplicate export path %q", path)
		}
		requested[path] = protocol.URIFromPath(filepath.Join(session.repositoryRoot, filepath.FromSlash(path)))
	}
	paths := append([]string(nil), documents...)
	sort.Strings(paths)
	uris := make([]protocol.DocumentURI, 0, len(paths))
	for _, path := range paths {
		uris = append(uris, requested[path])
	}
	expectedSourceSHA256s := make(map[protocol.DocumentURI]string, len(session.sources))
	for path, source := range session.sources {
		uri := protocol.URIFromPath(filepath.Join(
			session.repositoryRoot,
			filepath.FromSlash(path),
		))
		expectedSourceSHA256s[uri] = source.ContentSHA256
	}
	exported, callableLiveness, err := goplsserver.H00ExportScipDocuments(
		session.ctx, session.server, session.executionRoot, ".", session.executionPrefix, uris,
		expectedSourceSHA256s, session.workspaceWitness, session.goStdlibVersion,
		includeCallableLiveness,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	byPath := make(map[string]*scip.Document, len(exported))
	for _, document := range exported {
		repositoryPath := document.RelativePath
		if session.executionPrefix != "" {
			repositoryPath = session.executionPrefix + "/" + repositoryPath
		}
		document.RelativePath = filepath.ToSlash(repositoryPath)
		if _, duplicate := byPath[document.RelativePath]; duplicate {
			return nil, nil, nil, fmt.Errorf("duplicate exported SCIP document %q", document.RelativePath)
		}
		byPath[document.RelativePath] = document
	}
	outcomes := make([]h00DocumentOutcome, 0, len(paths))
	attachments := make([][]byte, 0, len(paths))
	for _, path := range paths {
		source := session.sources[path]
		document := byPath[path]
		if document == nil {
			outcomes = append(outcomes, h00DocumentOutcome{
				Outcome: "omitted", DocumentPath: path, Language: h00ProviderLanguage,
				ContentIdentity: source.ContentIdentity,
			})
			continue
		}
		h00CanonicalizeScipDocument(document)
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(document)
		if err != nil || len(encoded) == 0 {
			return nil, nil, nil, fmt.Errorf("serialize canonical Go document %q: %w", path, err)
		}
		index := uint32(len(attachments))
		attachments = append(attachments, encoded)
		outcomes = append(outcomes, h00DocumentOutcome{
			Outcome: "present", DocumentPath: path, Language: h00ProviderLanguage,
			ContentIdentity: source.ContentIdentity, CanonicalDocumentSHA256: h00SHA256(encoded),
			AttachmentIndex: &index,
		})
	}
	if err := session.verifyAuthorityInputs(); err != nil {
		return nil, nil, nil, fmt.Errorf("verify Go semantic inputs after document export: %w", err)
	}
	return outcomes, attachments, callableLiveness, nil
}

func h00RequestsCallableLiveness(requests []h00AnalysisRequest) (bool, error) {
	if len(requests) == 0 {
		return false, nil
	}
	if len(requests) != 1 {
		return false, fmt.Errorf("Go provider accepts exactly one callable-liveness analysis")
	}
	request := requests[0]
	if request.AnalysisID != h00CallableLivenessAnalysisID ||
		request.SchemaVersion != h00CallableLivenessAnalysisSchema ||
		request.ConfigurationID != h00CallableLivenessConfigurationID {
		return false, fmt.Errorf("unsupported Go semantic analysis identity")
	}
	return true, nil
}

func h00CanonicalizeScipDocument(document *scip.Document) {
	// scip-go 0.2.7 emits Go token.Position byte columns but leaves this
	// protocol field unset. This h00ligan-owned boundary knows and binds that exact
	// upstream contract, so publish the encoding explicitly instead of asking
	// downstream consumers to infer it from provider identity.
	document.PositionEncoding = scip.PositionEncoding_UTF8CodeUnitOffsetFromLineStart
	for _, symbol := range document.Symbols {
		if symbol.SignatureDocumentation != nil {
			h00CanonicalizeScipDocument(symbol.SignatureDocumentation)
		}
		sort.SliceStable(symbol.Relationships, func(i, j int) bool {
			return bytes.Compare(h00CanonicalProto(symbol.Relationships[i]), h00CanonicalProto(symbol.Relationships[j])) < 0
		})
	}
	sort.SliceStable(document.Symbols, func(i, j int) bool {
		return bytes.Compare(h00CanonicalProto(document.Symbols[i]), h00CanonicalProto(document.Symbols[j])) < 0
	})
	sort.SliceStable(document.Occurrences, func(i, j int) bool {
		return bytes.Compare(h00CanonicalProto(document.Occurrences[i]), h00CanonicalProto(document.Occurrences[j])) < 0
	})
}

func h00CanonicalProto(message proto.Message) []byte {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		panic(fmt.Sprintf("canonical SCIP serialization failed: %v", err))
	}
	return encoded
}

func h00ObserveRuntimeConfiguration() (h00RuntimeConfiguration, error) {
	resolved := os.Getenv(h00ResolvedToolchainSHA256Env)
	goPath := os.Getenv("GO")
	expectedGoSHA := os.Getenv(h00ResolvedGoSHA256Env)
	if !h00IsSHA256(resolved) || goPath == "" || !h00IsSHA256(expectedGoSHA) {
		return h00RuntimeConfiguration{}, fmt.Errorf("required resolved Go toolchain environment is absent")
	}
	goBytes, err := os.ReadFile(goPath)
	if err != nil || h00SHA256(goBytes) != expectedGoSHA {
		return h00RuntimeConfiguration{}, fmt.Errorf("resolved Go executable changed")
	}
	command := exec.Command(goPath, "version")
	command.Env = os.Environ()
	report, err := command.CombinedOutput()
	if err != nil || len(report) == 0 || len(report) > 16*1024 {
		return h00RuntimeConfiguration{}, fmt.Errorf("observe Go runtime version: %w", err)
	}
	goStdlibVersion, err := h00ParseGoStdlibVersion(report)
	if err != nil {
		return h00RuntimeConfiguration{}, err
	}
	environment := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name != h00ProviderParentPIDEnv {
			environment = append(environment, entry)
		}
	}
	sort.Strings(environment)
	workspaceFields := make([]string, 0)
	for _, name := range []string{"GO111MODULE", "GOARCH", "GOENV", "GOFLAGS", "GOOS", "GOROOT", "GOTOOLCHAIN", "GOWORK"} {
		workspaceFields = append(workspaceFields, name+"="+os.Getenv(name))
	}
	configuration, err := h00BuildRuntimeConfiguration(
		resolved,
		map[string][]byte{
			"go_executable":   []byte(expectedGoSHA),
			"go_version":      report,
			"gopls_version":   []byte(h00GoplsVersion),
			"scip_go_version": []byte(h00ScipGoVersion),
		},
		[]byte(strings.Join(environment, "\x00")),
		[]byte(strings.Join(workspaceFields, "\x00")),
	)
	if err != nil {
		return h00RuntimeConfiguration{}, err
	}
	configuration.GoStdlibVersion = goStdlibVersion
	return configuration, nil
}

func h00ParseGoStdlibVersion(report []byte) (string, error) {
	for _, field := range strings.Fields(string(report)) {
		if strings.HasPrefix(field, "go1.") {
			return field, nil
		}
	}
	return "", fmt.Errorf("resolved Go version report has no standard-library identity")
}

func h00CaptureGoSemanticInputs(repositoryRoot string, expected h00SemanticInputs) (h00SemanticInputs, error) {
	if expected.SchemaVersion != h00ProviderSemanticInputsSchema || expected.Coverage != "complete" ||
		len(expected.Paths) == 0 || len(expected.Paths) > h00MaxSemanticInputPaths || len(expected.Issues) != 0 {
		return h00SemanticInputs{}, fmt.Errorf("invalid expected Go semantic-input population")
	}
	inputs := h00SemanticInputs{
		SchemaVersion: h00ProviderSemanticInputsSchema,
		Coverage:      "complete", Paths: make([]h00SemanticPathInput, 0, len(expected.Paths)),
		Environment: []h00SemanticEnvironmentInput{}, Issues: []h00SemanticInputIssue{},
	}
	previousPath := ""
	for _, input := range expected.Paths {
		if input.Root != "repository" || input.Path <= previousPath {
			return h00SemanticInputs{}, fmt.Errorf("expected Go semantic-input paths are not canonical")
		}
		previousPath = input.Path
		observed, err := h00HashSemanticFile(repositoryRoot, input.Path)
		if err != nil {
			return h00SemanticInputs{}, err
		}
		inputs.Paths = append(inputs.Paths, observed)
	}
	environmentNames := []string{
		"CGO_ENABLED", "GO111MODULE", "GOARCH", "GOCACHE", "GOENV", "GOEXPERIMENT", "GOFLAGS",
		"GOMODCACHE", "GOOS", "GOPRIVATE", "GOPROXY", "GOROOT", "GOSUMDB", "GOTOOLCHAIN", "GOWORK",
	}
	if len(expected.Environment) != len(environmentNames) {
		return h00SemanticInputs{}, fmt.Errorf("expected Go semantic-input environment population mismatch")
	}
	for index, name := range environmentNames {
		if expected.Environment[index].Name != name {
			return h00SemanticInputs{}, fmt.Errorf("expected Go semantic-input environment is not canonical")
		}
		var digest *string
		if value, present := os.LookupEnv(name); present {
			valueDigest := h00SHA256([]byte(value))
			digest = &valueDigest
		}
		inputs.Environment = append(inputs.Environment, h00SemanticEnvironmentInput{Name: name, ValueSHA256: digest})
	}
	return inputs, nil
}

func h00SemanticInputsEqual(left, right h00SemanticInputs) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func h00SemanticInputURIs(repositoryRoot string, inputs h00SemanticInputs) map[string]protocol.DocumentURI {
	result := make(map[string]protocol.DocumentURI, len(inputs.Paths))
	for _, input := range inputs.Paths {
		result[input.Path] = protocol.URIFromPath(filepath.Join(
			repositoryRoot, filepath.FromSlash(input.Path),
		))
	}
	return result
}

func h00MatchSnapshotSemanticInputs(
	expected h00SemanticInputs,
	observed map[string]goplsserver.H00SemanticPathWitness,
) error {
	if len(expected.Paths) != len(observed) {
		return fmt.Errorf("gopls semantic-input snapshot population mismatch")
	}
	for _, input := range expected.Paths {
		witness, ok := observed[input.Path]
		if !ok || witness.Kind != input.Kind || witness.IdentitySHA256 != input.IdentitySHA256 ||
			witness.EntryCount != input.EntryCount || witness.ByteLength != input.ByteLength {
			return fmt.Errorf("gopls semantic-input snapshot differs at %q", input.Path)
		}
	}
	return nil
}

func h00CanonicalDirectory(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("path is not absolute")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("path is not a directory")
	}
	if filepath.Clean(path) != canonical {
		return "", fmt.Errorf("path is not canonical")
	}
	return canonical, nil
}

func h00PathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func h00AuthorityEqual(left, right h00Authority) bool {
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	return bytes.Equal(leftBytes, rightBytes)
}

func h00OptionalStringEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
