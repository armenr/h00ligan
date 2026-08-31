package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/microsoft/typescript-go/internal/h00provider"
)

const (
	h00TypeScriptProviderHelperEnvironment = "H00_TYPESCRIPT_PROVIDER_TEST_HELPER"
	h00TypeScriptProviderTestPatchSHA256   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	h00TypeScriptProviderTestToolchain     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type h00ProviderTestProcess struct {
	command      *exec.Cmd
	processGroup int
	stdin        io.WriteCloser
	stdout       *bufio.Reader
	stderr       bytes.Buffer
	identity     h00ProviderIdentity
}

type h00TestHelloBody struct {
	Result               string                  `json:"result"`
	Limits               h00provider.FrameLimits `json:"limits"`
	RuntimeConfiguration h00RuntimeConfiguration `json:"runtime_configuration"`
}

type h00TestOpenedBody struct {
	Result         string            `json:"result"`
	Authority      h00Authority      `json:"authority"`
	Health         h00Health         `json:"health"`
	SemanticInputs h00SemanticInputs `json:"semantic_inputs"`
}

type h00TestExportBody struct {
	Result               string                   `json:"result"`
	Authority            h00Authority             `json:"authority"`
	ParentSnapshotSHA256 string                   `json:"parent_snapshot_sha256,omitempty"`
	Health               h00Health                `json:"health"`
	RuntimeConfiguration *h00RuntimeConfiguration `json:"runtime_configuration,omitempty"`
	Outcomes             []h00DocumentOutcome     `json:"outcomes"`
	Analyses             []json.RawMessage        `json:"analyses"`
}

type h00TestErrorBody struct {
	Result    string `json:"result"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// TestTypeScriptProviderSubprocessHelper is selected only by a child test
// binary. os.Exit prevents the Go test runner from appending output to the
// provider's framed stdout after the terminal receipt.
func TestTypeScriptProviderSubprocessHelper(t *testing.T) {
	if os.Getenv(h00TypeScriptProviderHelperEnvironment) != "1" {
		return
	}
	h00ProviderPatchSHA256 = h00TypeScriptProviderTestPatchSHA256
	if err := H00SemanticProvider(context.Background()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(31)
	}
	os.Exit(0)
}

func TestExactSuccessorEpochRejectsStaleSkippedAndWrappedAuthority(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		previous uint64
		next     uint64
		want     bool
	}{
		{name: "exact", previous: 7, next: 8, want: true},
		{name: "stale", previous: 7, next: 7, want: false},
		{name: "skipped", previous: 7, next: 9, want: false},
		{name: "wrapped", previous: ^uint64(0), next: 0, want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := h00IsExactSuccessorEpoch(testCase.previous, testCase.next); got != testCase.want {
				t.Fatalf("exact successor mismatch: got=%v want=%v", got, testCase.want)
			}
		})
	}
}

func TestFramedTypeScriptProviderLifecycleIsExactAndDeterministic(t *testing.T) {
	root, sources, before, after := h00TypeScriptProcessFixture(t)
	provider := h00StartProviderTestProcess(t, root)
	defer provider.terminate()

	helloResponse, _ := provider.call(t, 1, "typescript-lifecycle", map[string]any{"operation": "hello"}, nil, nil)
	var hello h00TestHelloBody
	h00DecodeTestBody(t, helloResponse.Body, &hello)
	if hello.Result != "hello" {
		t.Fatalf("provider did not complete Hello: %+v", hello)
	}

	replayResponse, replayAttachments := provider.call(t, 1, "typescript-lifecycle", map[string]any{"operation": "hello"}, nil, nil)
	h00RequireProviderError(t, replayResponse, replayAttachments, "replayed_request")
	wrongIdentity := provider.identity
	wrongIdentity.ExecutableSHA256 = strings.Repeat("0", 64)
	wrongResponse, wrongAttachments := provider.call(t, 2, "typescript-lifecycle", map[string]any{"operation": "hello"}, nil, &wrongIdentity)
	h00RequireProviderError(t, wrongResponse, wrongAttachments, "invalid_request")

	authority := h00InitialTypeScriptAuthority(t, root, "typescript-lifecycle", hello.RuntimeConfiguration, sources)
	openedResponse, openedAttachments := provider.call(t, 3, authority.SessionID, h00OpenSessionBody{
		Operation: "open_session", RepositoryRoot: root, ExecutionRoot: root,
		ExecutionPrefix: "", Authority: authority, Sources: sources,
	}, nil, nil)
	if len(openedAttachments) != 0 {
		t.Fatal("OpenSession returned unexpected attachments")
	}
	var opened h00TestOpenedBody
	h00DecodeTestBody(t, openedResponse.Body, &opened)
	if opened.Result != "session_opened" || opened.Authority.WorkspaceResolutionSHA256 == nil ||
		opened.Authority.SemanticInputsSHA256 == nil || !opened.Health.DiagnosticsComplete ||
		len(opened.Health.DegradationReasons) != 0 || opened.SemanticInputs.Coverage != "complete" {
		t.Fatalf("provider did not establish complete bound authority: %+v", opened)
	}
	authority = opened.Authority
	firstResponse, firstAttachments := provider.call(t, 4, authority.SessionID, h00CertifyFullBody{
		Operation: "certify_full", Authority: authority,
	}, nil, nil)
	var first h00TestExportBody
	h00DecodeTestBody(t, firstResponse.Body, &first)
	secondResponse, secondAttachments := provider.call(t, 5, authority.SessionID, h00CertifyFullBody{
		Operation: "certify_full", Authority: authority,
	}, nil, nil)
	var second h00TestExportBody
	h00DecodeTestBody(t, secondResponse.Body, &second)
	if first.Result != "full_certification" || second.Result != "full_certification" ||
		first.Analyses == nil || second.Analyses == nil || len(first.Analyses) != 0 ||
		len(second.Analyses) != 0 || len(firstAttachments) != len(sources) ||
		!reflect.DeepEqual(firstAttachments, secondAttachments) {
		t.Fatal("unchanged full certifications were not deterministic")
	}

	parentSnapshot := strings.Repeat("e", 64)
	updatedSource := testTypeScriptSource("src/usage.ts", after)
	nextSources := []h00SourceIdentity{sources[0], updatedSource}
	nextPopulation, err := h00SourcePopulationSHA256(nextSources)
	if err != nil {
		t.Fatalf("hash updated TypeScript population: %v", err)
	}
	nextAuthority := authority
	nextAuthority.PopulationSHA256 = nextPopulation
	nextAuthority.SourceEpoch++
	changedResponse, changedAttachments := provider.call(t, 6, authority.SessionID, h00RefreshAffectedBody{
		Operation: "refresh_affected", PreviousAuthority: authority, NextAuthority: nextAuthority,
		Changes: []h00SourceChange{{
			Outcome: "replace", DocumentPath: "src/usage.ts", Language: h00ProviderLanguage,
			PreviousContentIdentity: sources[1].ContentIdentity,
			PreviousContentSHA256:   sources[1].ContentSHA256,
			ContentIdentity:         updatedSource.ContentIdentity, ContentSHA256: updatedSource.ContentSHA256,
			AttachmentIndex: 0,
		}},
		ParentSnapshotSHA256: parentSnapshot, Documents: []string{"src/usage.ts"},
	}, [][]byte{[]byte(after)}, nil)
	var changed h00TestExportBody
	h00DecodeTestBody(t, changedResponse.Body, &changed)
	if changed.RuntimeConfiguration == nil ||
		!reflect.DeepEqual(*changed.RuntimeConfiguration, hello.RuntimeConfiguration) {
		t.Fatal("affected refresh omitted the exact post-work runtime witness")
	}
	fullResponse, fullAttachments := provider.call(t, 7, authority.SessionID, h00CertifyFullBody{
		Operation: "certify_full", Authority: nextAuthority,
	}, nil, nil)
	var full h00TestExportBody
	h00DecodeTestBody(t, fullResponse.Body, &full)
	if changed.Result != "affected_refreshed" || full.Result != "full_certification" ||
		changed.Analyses == nil || full.Analyses == nil || len(changed.Analyses) != 0 ||
		len(full.Analyses) != 0 || len(changedAttachments) != 1 ||
		bytes.Equal(firstAttachments[0], changedAttachments[0]) {
		t.Fatal("semantic source epoch did not change the framed canonical document")
	}
	fullUsage := h00AttachmentForDocument(t, full.Outcomes, fullAttachments, "src/usage.ts")
	if !bytes.Equal(changedAttachments[0], fullUsage) {
		t.Fatal("affected refresh differs from full certification at the same authority")
	}
	if contents, err := os.ReadFile(filepath.Join(root, "src/usage.ts")); err != nil || string(contents) != before {
		t.Fatalf("provider mutated repository source bytes: error=%v contents=%q", err, contents)
	}

	closedResponse, closedAttachments := provider.call(t, 8, authority.SessionID, map[string]any{"operation": "close_session"}, nil, nil)
	var closed struct {
		Result string `json:"result"`
	}
	h00DecodeTestBody(t, closedResponse.Body, &closed)
	if closed.Result != "session_closed" || len(closedAttachments) != 0 {
		t.Fatalf("provider did not return one clean terminal receipt: %+v", closed)
	}
	provider.finish(t, 0)
}

func TestFramedTypeScriptProviderRejectsForeignSessionAndPartialEpoch(t *testing.T) {
	for _, testCase := range []struct {
		name string
		run  func(*testing.T, *h00ProviderTestProcess, string, []h00SourceIdentity, h00Authority, string, string)
	}{
		{
			name: "foreign-session",
			run: func(t *testing.T, provider *h00ProviderTestProcess, _ string, _ []h00SourceIdentity, authority h00Authority, _, _ string) {
				response, attachments := provider.call(t, 3, "foreign-session", h00CertifyFullBody{
					Operation: "certify_full", Authority: authority,
				}, nil, nil)
				h00RequireProviderError(t, response, attachments, "invalid_request")
			},
		},
		{
			name: "partial-epoch",
			run: func(t *testing.T, provider *h00ProviderTestProcess, _ string, sources []h00SourceIdentity, authority h00Authority, _, after string) {
				updated := testTypeScriptSource("src/usage.ts", after)
				population, err := h00SourcePopulationSHA256([]h00SourceIdentity{sources[0], updated})
				if err != nil {
					t.Fatalf("hash partial next population: %v", err)
				}
				next := authority
				next.PopulationSHA256 = population
				next.SourceEpoch++
				response, attachments := provider.call(t, 3, authority.SessionID, h00ApplyEpochBody{
					Operation: "apply_epoch", PreviousAuthority: authority, NextAuthority: next,
					Changes: []h00SourceChange{{
						Outcome: "replace", DocumentPath: "src/usage.ts", Language: h00ProviderLanguage,
						PreviousContentIdentity: sources[1].ContentIdentity,
						PreviousContentSHA256:   sources[1].ContentSHA256,
						ContentIdentity:         updated.ContentIdentity, ContentSHA256: updated.ContentSHA256,
						AttachmentIndex: 0,
					}},
				}, nil, nil)
				h00RequireProviderError(t, response, attachments, "request_failed")
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root, sources, before, after := h00TypeScriptProcessFixture(t)
			provider := h00StartProviderTestProcess(t, root)
			defer provider.terminate()
			authority := h00OpenProviderTestSession(t, provider, root, "typescript-"+testCase.name, sources)
			testCase.run(t, provider, root, sources, authority, before, after)
			provider.finish(t, 0)
			contents, err := os.ReadFile(filepath.Join(root, "src/usage.ts"))
			if err != nil || string(contents) != before {
				t.Fatalf("failed request changed repository source: error=%v contents=%q", err, contents)
			}
		})
	}
}

func TestFramedTypeScriptProviderRejectsSemanticDriftAndOversizedFrames(t *testing.T) {
	t.Run("semantic-drift", func(t *testing.T) {
		root, sources, _, _ := h00TypeScriptProcessFixture(t)
		provider := h00StartProviderTestProcess(t, root)
		defer provider.terminate()
		authority := h00OpenProviderTestSession(t, provider, root, "typescript-semantic-drift", sources)
		writeTypeScriptFixture(t, root, "tsconfig.json", `{"compilerOptions":{"strict":false},"include":["src/**/*.ts"]}`)
		response, attachments := provider.call(t, 3, authority.SessionID, h00CertifyFullBody{
			Operation: "certify_full", Authority: authority,
		}, nil, nil)
		h00RequireProviderError(t, response, attachments, "request_failed")
		provider.finish(t, 0)
	})

	t.Run("oversized-frame", func(t *testing.T) {
		provider := h00StartProviderTestProcess(t, t.TempDir())
		defer provider.terminate()
		header := make([]byte, 20)
		copy(header[:8], h00provider.ProviderFrameMagic[:])
		binary.BigEndian.PutUint32(header[8:12], uint32(h00provider.MaxFrameBytes))
		if _, err := provider.stdin.Write(header); err != nil {
			t.Fatalf("write oversized frame declaration: %v", err)
		}
		_ = provider.stdin.Close()
		provider.finish(t, 31)
		if !strings.Contains(strings.ToLower(provider.stderr.String()), "frame") {
			t.Fatalf("oversized frame did not fail at the framed boundary: %q", provider.stderr.String())
		}
	})
}

// RIGHT-REASON REGRESSION: the Go-native decoder is the framed admission
// boundary shared by the embedded Go and TypeScript providers. One valid JSON
// value followed by another must not be accepted as the first value alone.
func TestSharedProviderProtocolRequiresExactlyOneJSONValue(t *testing.T) {
	request := h00provider.Request{
		RequestID: 1,
		SessionID: "exact-json",
		Body:      json.RawMessage(`{"operation":"hello"}`),
	}
	metadata, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode request metadata: %v", err)
	}
	metadata = append(metadata, []byte(`{}`)...)
	header := make([]byte, 20)
	copy(header[:8], h00provider.ProviderFrameMagic[:])
	binary.BigEndian.PutUint32(header[8:12], uint32(len(metadata)))
	binary.BigEndian.PutUint32(header[12:16], uint32(len(metadata)))
	framed := append(header, metadata...)
	if _, err := h00provider.ReadFrame(bufio.NewReader(bytes.NewReader(framed))); err == nil {
		t.Fatal("request metadata with a trailing JSON value reached provider dispatch")
	}

	type helloBody struct {
		Operation string `json:"operation"`
	}
	if _, err := h00provider.DecodeBody[helloBody](
		json.RawMessage(`{"operation":"hello"}{}`),
	); err == nil {
		t.Fatal("operation body with a trailing JSON value reached provider dispatch")
	}
}

// RIGHT-REASON REGRESSION: CloseSession has no extensible payload. Unknown
// fields must not bypass the typed body decoder merely because the operation
// discriminator was already read.
func TestFramedTypeScriptProviderRejectsUnknownCloseSessionFields(t *testing.T) {
	root, sources, _, _ := h00TypeScriptProcessFixture(t)
	provider := h00StartProviderTestProcess(t, root)
	defer provider.terminate()
	authority := h00OpenProviderTestSession(t, provider, root, "typescript-close-shape", sources)
	response, attachments := provider.call(t, 3, authority.SessionID, map[string]any{
		"operation":  "close_session",
		"unexpected": true,
	}, nil, nil)
	h00RequireProviderError(t, response, attachments, "invalid_request")
	closed, _ := provider.call(t, 4, authority.SessionID, map[string]any{
		"operation": "close_session",
	}, nil, nil)
	var body struct {
		Result string `json:"result"`
	}
	h00DecodeTestBody(t, closed.Body, &body)
	if body.Result != "session_closed" {
		t.Fatalf("valid close-session did not remain reachable: %+v", body)
	}
	provider.finish(t, 0)
}

func TestFramedTypeScriptProviderReportsTypedUnresolvedImportHealth(t *testing.T) {
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@h00/unresolved-health","version":"1.0.0","type":"module"}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true},"include":["src/**/*.ts"]}`)
	sourceText := "import { missing } from \"./does-not-exist.js\";\nexport const result = missing;\n"
	writeTypeScriptFixture(t, root, "src/usage.ts", sourceText)
	sources := []h00SourceIdentity{testTypeScriptSource("src/usage.ts", sourceText)}
	provider := h00StartProviderTestProcess(t, root)
	defer provider.terminate()

	helloResponse, _ := provider.call(t, 1, "typescript-unresolved-health", map[string]any{"operation": "hello"}, nil, nil)
	var hello h00TestHelloBody
	h00DecodeTestBody(t, helloResponse.Body, &hello)
	authority := h00InitialTypeScriptAuthority(
		t, root, "typescript-unresolved-health", hello.RuntimeConfiguration, sources,
	)
	openedResponse, attachments := provider.call(t, 2, authority.SessionID, h00OpenSessionBody{
		Operation: "open_session", RepositoryRoot: root, ExecutionRoot: root,
		ExecutionPrefix: "", Authority: authority, Sources: sources,
	}, nil, nil)
	if len(attachments) != 0 {
		t.Fatal("unresolved-import OpenSession returned attachments")
	}
	var opened h00TestOpenedBody
	h00DecodeTestBody(t, openedResponse.Body, &opened)
	if opened.Result != "session_opened" || opened.Health.DiagnosticsComplete ||
		!reflect.DeepEqual(opened.Health.DegradationReasons, []string{"unresolved_imports"}) ||
		opened.Health.Components["module_resolution"] != "failed" {
		t.Fatalf("unresolved imports did not produce typed incomplete health: %+v", opened)
	}

	closedResponse, _ := provider.call(t, 3, authority.SessionID, map[string]any{"operation": "close_session"}, nil, nil)
	var closed struct {
		Result string `json:"result"`
	}
	h00DecodeTestBody(t, closedResponse.Body, &closed)
	if closed.Result != "session_closed" {
		t.Fatalf("provider did not close after typed incomplete health: %+v", closed)
	}
	provider.finish(t, 0)
}

func TestSharedGoHealthWireRejectsUnknownVocabulary(t *testing.T) {
	valid := h00Health{
		Components:          map[string]string{"module_resolution": "failed"},
		DiagnosticsComplete: false,
		DegradationReasons:  []string{"unresolved_imports"},
	}
	if _, err := json.Marshal(valid); err != nil {
		t.Fatalf("known typed incomplete health must serialize: %v", err)
	}
	invalid := valid
	invalid.Components = map[string]string{"module_resolution": "degraded"}
	if encoded, err := json.Marshal(invalid); err == nil {
		t.Fatalf("unknown health vocabulary reached the wire: %s", encoded)
	}
}

func h00TypeScriptProcessFixture(t *testing.T) (string, []h00SourceIdentity, string, string) {
	t.Helper()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@h00/process-fixture","version":"1.0.0","type":"module"}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true},"include":["src/**/*.ts"]}`)
	definitions := "export function stable(value: number): number { return value + 1 }\n"
	before := "import { stable } from \"./definitions.js\";\nexport const result = stable(1);\n"
	after := "import { stable } from \"./definitions.js\";\nexport const updated = stable(stable(2));\n"
	writeTypeScriptFixture(t, root, "src/definitions.ts", definitions)
	writeTypeScriptFixture(t, root, "src/usage.ts", before)
	return root, []h00SourceIdentity{
		testTypeScriptSource("src/definitions.ts", definitions),
		testTypeScriptSource("src/usage.ts", before),
	}, before, after
}

func h00StartProviderTestProcess(t *testing.T, workingDirectory string) *h00ProviderTestProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve provider test executable: %v", err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatalf("hash provider test executable: %v", err)
	}
	identity := h00ProviderIdentity{
		Protocol: h00ProviderProtocol, ProviderID: h00ProviderID, Language: h00ProviderLanguage,
		ImplementationVersion: h00ProviderImplementationVersion,
		SourceComponents: map[string]h00SourceComponent{
			"scip_bindings":     {Version: h00ScipBindingsVersion, Revision: h00ScipBindingsRevision},
			"typescript_native": {Version: h00TypescriptVersion, Revision: h00TypescriptRevision},
		},
		PatchSHA256: h00TypeScriptProviderTestPatchSHA256, ExecutableSHA256: h00SHA256(executableBytes),
	}
	command := exec.Command(executable, "-test.run=^TestTypeScriptProviderSubprocessHelper$")
	command.Dir = workingDirectory
	command.Env = h00ProviderTestEnvironment(os.Environ())
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("open provider stdin: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open provider stdout: %v", err)
	}
	provider := &h00ProviderTestProcess{
		command: command, stdin: stdin, stdout: bufio.NewReader(stdout), identity: identity,
	}
	command.Stderr = &provider.stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start provider child: %v", err)
	}
	provider.processGroup = command.Process.Pid
	return provider
}

func h00ProviderTestEnvironment(current []string) []string {
	filtered := make([]string, 0, len(current)+2)
	for _, entry := range current {
		if strings.HasPrefix(entry, h00TypeScriptProviderHelperEnvironment+"=") ||
			strings.HasPrefix(entry, h00ResolvedToolchainSHA256Env+"=") ||
			strings.HasPrefix(entry, h00provider.ProviderParentPIDEnv+"=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered,
		h00TypeScriptProviderHelperEnvironment+"=1",
		h00ResolvedToolchainSHA256Env+"="+h00TypeScriptProviderTestToolchain,
		h00provider.ProviderParentPIDEnv+"="+strconv.Itoa(os.Getpid()),
	)
}

func (provider *h00ProviderTestProcess) call(
	t *testing.T,
	requestID uint64,
	sessionID string,
	body any,
	attachments [][]byte,
	expectedIdentity *h00ProviderIdentity,
) (h00Response, [][]byte) {
	t.Helper()
	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode provider request body: %v", err)
	}
	identity := provider.identity
	if expectedIdentity != nil {
		identity = *expectedIdentity
	}
	request := h00provider.Request{
		RequestID: requestID, SessionID: sessionID, ExpectedProvider: identity, Body: rawBody,
	}
	if err := h00WriteTestRequest(provider.stdin, request, attachments); err != nil {
		t.Fatalf("write provider request %d: %v", requestID, err)
	}
	type result struct {
		response    h00Response
		attachments [][]byte
		err         error
	}
	resultChannel := make(chan result, 1)
	go func() {
		response, responseAttachments, readErr := h00ReadTestResponse(provider.stdout)
		resultChannel <- result{response: response, attachments: responseAttachments, err: readErr}
	}()
	select {
	case observed := <-resultChannel:
		if observed.err != nil {
			t.Fatalf("read provider response %d: %v; stderr=%q", requestID, observed.err, provider.stderr.String())
		}
		if observed.response.RequestID != requestID || observed.response.SessionID != sessionID ||
			!h00IdentityEqual(observed.response.Provider, provider.identity) {
			t.Fatalf("provider response identity mismatch: %+v", observed.response)
		}
		return observed.response, observed.attachments
	case <-time.After(10 * time.Second):
		provider.terminate()
		t.Fatalf("provider response %d timed out", requestID)
		return h00Response{}, nil
	}
}

func (provider *h00ProviderTestProcess) finish(t *testing.T, expectedCode int) {
	t.Helper()
	_ = provider.stdin.Close()
	wait := make(chan error, 1)
	go func() { wait <- provider.command.Wait() }()
	select {
	case err := <-wait:
		code := 0
		if err != nil {
			if typed, ok := err.(*exec.ExitError); ok {
				code = typed.ExitCode()
			} else {
				t.Fatalf("wait for provider child: %v", err)
			}
		}
		if code != expectedCode {
			t.Fatalf("provider exit mismatch: expected=%d observed=%d stderr=%q", expectedCode, code, provider.stderr.String())
		}
		provider.command = nil
		h00RequireProcessGroupGone(t, provider)
	case <-time.After(10 * time.Second):
		provider.terminate()
		t.Fatal("provider child did not terminate")
	}
}

func (provider *h00ProviderTestProcess) terminate() {
	if provider == nil || provider.command == nil || provider.command.Process == nil {
		return
	}
	_ = syscall.Kill(-provider.command.Process.Pid, syscall.SIGKILL)
	_, _ = provider.command.Process.Wait()
	provider.command = nil
}

func h00RequireProcessGroupGone(t *testing.T, provider *h00ProviderTestProcess) {
	t.Helper()
	if provider.command != nil {
		t.Fatal("process group checked before provider wait completed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(-provider.processGroup, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			t.Fatalf("inspect provider process group: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("provider process group %d survived terminal completion", provider.processGroup)
}

func h00OpenProviderTestSession(
	t *testing.T,
	provider *h00ProviderTestProcess,
	root string,
	sessionID string,
	sources []h00SourceIdentity,
) h00Authority {
	t.Helper()
	helloResponse, _ := provider.call(t, 1, sessionID, map[string]any{"operation": "hello"}, nil, nil)
	var hello h00TestHelloBody
	h00DecodeTestBody(t, helloResponse.Body, &hello)
	authority := h00InitialTypeScriptAuthority(t, root, sessionID, hello.RuntimeConfiguration, sources)
	openedResponse, _ := provider.call(t, 2, sessionID, h00OpenSessionBody{
		Operation: "open_session", RepositoryRoot: root, ExecutionRoot: root,
		ExecutionPrefix: "", Authority: authority, Sources: sources,
	}, nil, nil)
	var opened h00TestOpenedBody
	h00DecodeTestBody(t, openedResponse.Body, &opened)
	if opened.Result != "session_opened" {
		t.Fatalf("provider session did not open: %+v", opened)
	}
	return opened.Authority
}

func h00InitialTypeScriptAuthority(
	t *testing.T,
	root string,
	sessionID string,
	runtime h00RuntimeConfiguration,
	sources []h00SourceIdentity,
) h00Authority {
	t.Helper()
	population, err := h00SourcePopulationSHA256(sources)
	if err != nil {
		t.Fatalf("hash initial TypeScript population: %v", err)
	}
	return h00Authority{
		SessionID: sessionID, RootSHA256: h00SHA256([]byte(root)),
		RootTopologySHA256:  strings.Repeat("b", 64),
		ConfigurationSHA256: runtime.ConfigurationSHA256,
		PopulationSHA256:    population, SourceEpoch: 1,
	}
}

func h00WriteTestRequest(writer io.Writer, request h00provider.Request, attachments [][]byte) error {
	metadata, err := json.Marshal(request)
	if err != nil {
		return err
	}
	payloadLength := len(metadata)
	for _, attachment := range attachments {
		payloadLength += 4 + len(attachment)
	}
	header := make([]byte, 20)
	copy(header[:8], h00provider.ProviderFrameMagic[:])
	binary.BigEndian.PutUint32(header[8:12], uint32(payloadLength))
	binary.BigEndian.PutUint32(header[12:16], uint32(len(metadata)))
	binary.BigEndian.PutUint32(header[16:20], uint32(len(attachments)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(metadata); err != nil {
		return err
	}
	var length [4]byte
	for _, attachment := range attachments {
		binary.BigEndian.PutUint32(length[:], uint32(len(attachment)))
		if _, err := writer.Write(length[:]); err != nil {
			return err
		}
		if _, err := writer.Write(attachment); err != nil {
			return err
		}
	}
	return nil
}

func h00ReadTestResponse(reader io.Reader) (h00Response, [][]byte, error) {
	header := make([]byte, 20)
	if _, err := io.ReadFull(reader, header); err != nil {
		return h00Response{}, nil, err
	}
	if !bytes.Equal(header[:8], h00provider.ProviderFrameMagic[:]) {
		return h00Response{}, nil, fmt.Errorf("response frame magic mismatch")
	}
	payloadLength := int(binary.BigEndian.Uint32(header[8:12]))
	metadataLength := int(binary.BigEndian.Uint32(header[12:16]))
	attachmentCount := int(binary.BigEndian.Uint32(header[16:20]))
	if payloadLength < metadataLength || payloadLength+20 > h00provider.MaxFrameBytes ||
		metadataLength > h00provider.MaxMetadataBytes || attachmentCount > h00provider.MaxAttachments {
		return h00Response{}, nil, fmt.Errorf("response frame exceeds bounds")
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return h00Response{}, nil, err
	}
	var response h00Response
	if err := json.Unmarshal(payload[:metadataLength], &response); err != nil {
		return h00Response{}, nil, err
	}
	cursor := metadataLength
	attachments := make([][]byte, 0, attachmentCount)
	for range attachmentCount {
		if cursor+4 > len(payload) {
			return h00Response{}, nil, fmt.Errorf("truncated response attachment")
		}
		length := int(binary.BigEndian.Uint32(payload[cursor : cursor+4]))
		cursor += 4
		if cursor+length > len(payload) {
			return h00Response{}, nil, fmt.Errorf("truncated response attachment bytes")
		}
		attachments = append(attachments, append([]byte(nil), payload[cursor:cursor+length]...))
		cursor += length
	}
	if cursor != len(payload) {
		return h00Response{}, nil, fmt.Errorf("response frame contains trailing bytes")
	}
	return response, attachments, nil
}

func h00DecodeTestBody(t *testing.T, body any, destination any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-encode provider response body: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode provider response body: %v; body=%s", err, encoded)
	}
}

func h00RequireProviderError(t *testing.T, response h00Response, attachments [][]byte, code string) {
	t.Helper()
	var body h00TestErrorBody
	h00DecodeTestBody(t, response.Body, &body)
	if body.Result != "error" || body.Code != code || len(attachments) != 0 {
		t.Fatalf("provider did not fail closed with %q: body=%+v attachments=%d", code, body, len(attachments))
	}
}

func h00AttachmentForDocument(
	t *testing.T,
	outcomes []h00DocumentOutcome,
	attachments [][]byte,
	document string,
) []byte {
	t.Helper()
	for _, outcome := range outcomes {
		if outcome.DocumentPath == document && outcome.Outcome == "present" &&
			outcome.AttachmentIndex != nil && int(*outcome.AttachmentIndex) < len(attachments) {
			return attachments[*outcome.AttachmentIndex]
		}
	}
	t.Fatalf("full certification omitted %q", document)
	return nil
}
