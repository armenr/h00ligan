// Package h00provider owns the bounded wire, canonical hashing, and process-liveness contract shared by Go-native semantic providers embedded in h00ligan.
package h00provider

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	Protocol                = "h00/semantic-provider/v13"
	SemanticInputsSchema    = "h00/semantic-provider/semantic-inputs/v3"
	MaxFrameBytes           = 128 * 1024 * 1024
	MaxMetadataBytes        = 1024 * 1024
	MaxAttachments          = 4096
	MaxAttachmentBytes      = 64 * 1024 * 1024
	MaxTotalAttachmentBytes = 120 * 1024 * 1024
	MaxDocumentPaths        = 4096
	MaxOutstandingRequests  = 64
	ProviderParentPIDEnv    = "H00_PROVIDER_PARENT_PID"
	maxSemanticInputEntries = 2_000_000
	maxSemanticInputBytes   = 64 * 1024 * 1024 * 1024
)

var (
	ProviderFrameMagic             = [8]byte{'H', '0', '0', 'S', 'P', '1', '3', 0}
	providerRuntimeConfigurationID = []byte("h00/semantic-provider/runtime-configuration/v1\x00")
	providerSourcePopulationID     = []byte("h00/semantic-provider/source-population/v1\x00")
	providerSemanticPathID         = []byte("h00/semantic-provider/semantic-path/v2\x00")
	providerSemanticInputsDigestID = []byte("h00/semantic-provider/semantic-inputs-digest/v3\x00")
)

type SourceComponent struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

type ProviderIdentity struct {
	Protocol              string                     `json:"protocol"`
	ProviderID            string                     `json:"provider_id"`
	Language              string                     `json:"language"`
	ImplementationVersion string                     `json:"implementation_version"`
	SourceComponents      map[string]SourceComponent `json:"source_components"`
	PatchSHA256           string                     `json:"patch_sha256"`
	ExecutableSHA256      string                     `json:"executable_sha256"`
}

type FrameLimits struct {
	MaxFrameBytes           int `json:"max_frame_bytes"`
	MaxMetadataBytes        int `json:"max_metadata_bytes"`
	MaxAttachments          int `json:"max_attachments"`
	MaxAttachmentBytes      int `json:"max_attachment_bytes"`
	MaxTotalAttachmentBytes int `json:"max_total_attachment_bytes"`
	MaxDocumentPaths        int `json:"max_document_paths"`
	MaxOutstandingRequests  int `json:"max_outstanding_requests"`
}

func Limits() FrameLimits {
	return FrameLimits{
		MaxFrameBytes:           MaxFrameBytes,
		MaxMetadataBytes:        MaxMetadataBytes,
		MaxAttachments:          MaxAttachments,
		MaxAttachmentBytes:      MaxAttachmentBytes,
		MaxTotalAttachmentBytes: MaxTotalAttachmentBytes,
		MaxDocumentPaths:        MaxDocumentPaths,
		MaxOutstandingRequests:  MaxOutstandingRequests,
	}
}

type RuntimeConfiguration struct {
	ConfigurationSHA256          string            `json:"configuration_sha256"`
	ResolvedToolchainSHA256      string            `json:"resolved_toolchain_sha256"`
	ComponentSHA256s             map[string]string `json:"component_sha256s"`
	EnvironmentSHA256            string            `json:"environment_sha256"`
	WorkspaceConfigurationSHA256 string            `json:"workspace_configuration_sha256"`
}

type Authority struct {
	SessionID                 string  `json:"session_id"`
	RootSHA256                string  `json:"root_sha256"`
	RootTopologySHA256        string  `json:"root_topology_sha256"`
	ConfigurationSHA256       string  `json:"configuration_sha256"`
	WorkspaceResolutionSHA256 *string `json:"workspace_resolution_sha256"`
	SemanticInputsSHA256      *string `json:"semantic_inputs_sha256"`
	PopulationSHA256          string  `json:"population_sha256"`
	SourceEpoch               uint64  `json:"source_epoch"`
}

type SourceIdentity struct {
	DocumentPath    string `json:"document_path"`
	Language        string `json:"language"`
	ContentIdentity string `json:"content_identity"`
	ContentSHA256   string `json:"content_sha256"`
}

type SemanticPathInput struct {
	Path           string `json:"path"`
	Kind           string `json:"kind"`
	IdentitySHA256 string `json:"identity_sha256"`
	EntryCount     uint64 `json:"entry_count"`
	ByteLength     uint64 `json:"byte_length"`
}

type SemanticEnvironmentInput struct {
	Name        string  `json:"name"`
	ValueSHA256 *string `json:"value_sha256"`
}

type SemanticInputIssue struct {
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

type SemanticInputs struct {
	SchemaVersion string                     `json:"schema_version"`
	Coverage      string                     `json:"coverage"`
	Paths         []SemanticPathInput        `json:"paths"`
	Environment   []SemanticEnvironmentInput `json:"environment"`
	Issues        []SemanticInputIssue       `json:"issues"`
}

type Health struct {
	Components          map[string]string `json:"components"`
	DiagnosticsComplete bool              `json:"diagnostics_complete"`
	DegradationReasons  []string          `json:"degradation_reasons"`
}

// MarshalJSON keeps the shared Go wire vocabulary locked to the Rust protocol
// decoder. Provider-specific health labels are intentionally open, but their
// states are not: inventing a sixth state turns a typed incomplete result into
// an undecodable protocol failure at the coordinator boundary.
func (health Health) MarshalJSON() ([]byte, error) {
	if len(health.Components) == 0 || len(health.Components) > 64 {
		return nil, fmt.Errorf("invalid provider health component population")
	}
	for name, state := range health.Components {
		if !ValidComponentName(name) {
			return nil, fmt.Errorf("invalid provider health component %q", name)
		}
		switch state {
		case "healthy", "not_applicable", "disabled", "failed", "unknown":
		default:
			return nil, fmt.Errorf("invalid provider health state %q for %q", state, name)
		}
	}
	if health.DegradationReasons == nil {
		return nil, fmt.Errorf("provider health degradation reasons must be an array")
	}
	type wireHealth Health
	return json.Marshal(wireHealth(health))
}

type Request struct {
	RequestID        uint64           `json:"request_id"`
	SessionID        string           `json:"session_id"`
	ExpectedProvider ProviderIdentity `json:"expected_provider"`
	Body             json.RawMessage  `json:"body"`
}

type RequestOperation struct {
	Operation string `json:"operation"`
}

type AnalysisRequest struct {
	AnalysisID      string `json:"analysis_id"`
	SchemaVersion   string `json:"schema_version"`
	ConfigurationID string `json:"configuration_id"`
}

type Response struct {
	RequestID uint64           `json:"request_id"`
	SessionID string           `json:"session_id"`
	Provider  ProviderIdentity `json:"provider"`
	Body      any              `json:"body"`
}

type Frame struct {
	Metadata    Request
	Attachments [][]byte
}

type ResponseFrame struct {
	Metadata    Response
	Attachments [][]byte
}

func IdentityEqual(left, right ProviderIdentity) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func decodeExactJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON input contains a trailing value")
		}
		return fmt.Errorf("JSON input contains trailing data: %w", err)
	}
	return nil
}

func ReadFrame(reader *bufio.Reader) (Frame, error) {
	header := make([]byte, 20)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Frame{}, fmt.Errorf("read provider frame header: %w", err)
	}
	if !bytes.Equal(header[:8], ProviderFrameMagic[:]) {
		return Frame{}, fmt.Errorf("provider frame magic mismatch")
	}
	payloadLength := int(binary.BigEndian.Uint32(header[8:12]))
	metadataLength := int(binary.BigEndian.Uint32(header[12:16]))
	attachmentCount := int(binary.BigEndian.Uint32(header[16:20]))
	if payloadLength < metadataLength || payloadLength+20 > MaxFrameBytes ||
		metadataLength > MaxMetadataBytes || attachmentCount > MaxAttachments {
		return Frame{}, fmt.Errorf("provider frame exceeds negotiated bounds")
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Frame{}, fmt.Errorf("read provider frame payload: %w", err)
	}
	var request Request
	if err := decodeExactJSON(payload[:metadataLength], &request); err != nil {
		return Frame{}, fmt.Errorf("decode provider request: %w", err)
	}
	cursor := metadataLength
	attachments := make([][]byte, 0, attachmentCount)
	totalAttachments := 0
	for range attachmentCount {
		if cursor+4 > len(payload) {
			return Frame{}, fmt.Errorf("provider attachment length is truncated")
		}
		length := int(binary.BigEndian.Uint32(payload[cursor : cursor+4]))
		cursor += 4
		totalAttachments += length
		if length > MaxAttachmentBytes || totalAttachments > MaxTotalAttachmentBytes ||
			cursor+length > len(payload) {
			return Frame{}, fmt.Errorf("provider attachment exceeds negotiated bounds")
		}
		attachment := make([]byte, length)
		copy(attachment, payload[cursor:cursor+length])
		attachments = append(attachments, attachment)
		cursor += length
	}
	if cursor != len(payload) {
		return Frame{}, fmt.Errorf("provider frame contains trailing bytes")
	}
	return Frame{Metadata: request, Attachments: attachments}, nil
}

func WriteFrame(writer *bufio.Writer, frame ResponseFrame) error {
	metadata, err := json.Marshal(frame.Metadata)
	if err != nil {
		return fmt.Errorf("serialize provider response: %w", err)
	}
	if len(metadata) > MaxMetadataBytes || len(frame.Attachments) > MaxAttachments {
		return fmt.Errorf("provider response metadata exceeds negotiated bounds")
	}
	payloadLength := len(metadata)
	totalAttachments := 0
	for _, attachment := range frame.Attachments {
		if len(attachment) > MaxAttachmentBytes {
			return fmt.Errorf("provider response attachment exceeds negotiated bound")
		}
		totalAttachments += len(attachment)
		payloadLength += 4 + len(attachment)
	}
	if totalAttachments > MaxTotalAttachmentBytes || payloadLength+20 > MaxFrameBytes {
		return fmt.Errorf("provider response frame exceeds negotiated bound")
	}
	header := make([]byte, 20)
	copy(header[:8], ProviderFrameMagic[:])
	binary.BigEndian.PutUint32(header[8:12], uint32(payloadLength))
	binary.BigEndian.PutUint32(header[12:16], uint32(len(metadata)))
	binary.BigEndian.PutUint32(header[16:20], uint32(len(frame.Attachments)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(metadata); err != nil {
		return err
	}
	var length [4]byte
	for _, attachment := range frame.Attachments {
		binary.BigEndian.PutUint32(length[:], uint32(len(attachment)))
		if _, err := writer.Write(length[:]); err != nil {
			return err
		}
		if _, err := writer.Write(attachment); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func DecodeBody[T any](raw json.RawMessage) (T, error) {
	var value T
	if err := decodeExactJSON(raw, &value); err != nil {
		return value, err
	}
	return value, nil
}

func DecodeOperation(raw json.RawMessage) (RequestOperation, error) {
	var operation RequestOperation
	if err := json.Unmarshal(raw, &operation); err != nil {
		return operation, err
	}
	if operation.Operation == "" {
		return operation, fmt.Errorf("provider request operation is empty")
	}
	return operation, nil
}

func BuildRuntimeConfiguration(
	resolvedToolchain string,
	components map[string][]byte,
	environmentReport, workspaceReport []byte,
) (RuntimeConfiguration, error) {
	if !IsSHA256(resolvedToolchain) || len(components) == 0 || len(components) > 64 {
		return RuntimeConfiguration{}, fmt.Errorf("invalid resolved runtime population")
	}
	digests := make(map[string]string, len(components))
	names := make([]string, 0, len(components))
	for name, report := range components {
		if !ValidComponentName(name) {
			return RuntimeConfiguration{}, fmt.Errorf("invalid runtime component %q", name)
		}
		names = append(names, name)
		digests[name] = SHA256(report)
	}
	sort.Strings(names)
	environmentSHA := SHA256(environmentReport)
	workspaceSHA := SHA256(workspaceReport)
	hasher := sha256.New()
	HashField(hasher, providerRuntimeConfigurationID)
	HashField(hasher, []byte(resolvedToolchain))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(names)))
	HashField(hasher, count[:])
	for _, name := range names {
		HashField(hasher, []byte(name))
		HashField(hasher, []byte(digests[name]))
	}
	HashField(hasher, []byte(environmentSHA))
	HashField(hasher, []byte(workspaceSHA))
	return RuntimeConfiguration{
		ConfigurationSHA256:          hex.EncodeToString(hasher.Sum(nil)),
		ResolvedToolchainSHA256:      resolvedToolchain,
		ComponentSHA256s:             digests,
		EnvironmentSHA256:            environmentSHA,
		WorkspaceConfigurationSHA256: workspaceSHA,
	}, nil
}

func SourcePopulationSHA256(sources []SourceIdentity) (string, error) {
	if len(sources) == 0 || len(sources) > MaxDocumentPaths {
		return "", fmt.Errorf("invalid source population size")
	}
	ordered := append([]SourceIdentity(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].DocumentPath < ordered[j].DocumentPath })
	hasher := sha256.New()
	HashField(hasher, providerSourcePopulationID)
	previous := ""
	for _, source := range ordered {
		if !SafeDocumentPath(source.DocumentPath) || source.DocumentPath == previous ||
			source.Language == "" || source.ContentIdentity == "" || !IsSHA256(source.ContentSHA256) {
			return "", fmt.Errorf("invalid source identity for %q", source.DocumentPath)
		}
		previous = source.DocumentPath
		for _, field := range []string{
			source.DocumentPath, source.Language, source.ContentIdentity, source.ContentSHA256,
		} {
			HashField(hasher, []byte(field))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func SemanticInputsSHA256(inputs SemanticInputs) (string, error) {
	if inputs.SchemaVersion != SemanticInputsSchema || inputs.Coverage != "complete" ||
		len(inputs.Issues) != 0 || len(inputs.Paths) > MaxDocumentPaths ||
		len(inputs.Environment) > MaxDocumentPaths {
		return "", fmt.Errorf("semantic input manifest is not complete")
	}
	hasher := sha256.New()
	HashField(hasher, providerSemanticInputsDigestID)
	HashField(hasher, []byte("complete"))
	previousPath := ""
	var totalEntries uint64
	var totalBytes uint64
	for _, input := range inputs.Paths {
		if input.Path <= previousPath || !SafeSemanticPath(input.Path) ||
			!IsSHA256(input.IdentitySHA256) || !validSemanticPathInput(input) {
			return "", fmt.Errorf("semantic input paths are not canonical")
		}
		if input.EntryCount > maxSemanticInputEntries-totalEntries ||
			input.ByteLength > maxSemanticInputBytes-totalBytes {
			return "", fmt.Errorf("semantic input population exceeds its bound")
		}
		totalEntries += input.EntryCount
		totalBytes += input.ByteLength
		previousPath = input.Path
		HashField(hasher, []byte(input.Path))
		HashField(hasher, []byte(input.Kind))
		HashField(hasher, []byte(input.IdentitySHA256))
		var integer [8]byte
		binary.BigEndian.PutUint64(integer[:], input.EntryCount)
		HashField(hasher, integer[:])
		binary.BigEndian.PutUint64(integer[:], input.ByteLength)
		HashField(hasher, integer[:])
	}
	previousName := ""
	for _, input := range inputs.Environment {
		if input.Name <= previousName || !safeEnvironmentName(input.Name) {
			return "", fmt.Errorf("semantic environment inputs are not canonical")
		}
		previousName = input.Name
		HashField(hasher, []byte(input.Name))
		if input.ValueSHA256 == nil {
			HashField(hasher, []byte("missing"))
		} else {
			if !IsSHA256(*input.ValueSHA256) {
				return "", fmt.Errorf("semantic environment digest is invalid")
			}
			HashField(hasher, []byte("present"))
			HashField(hasher, []byte(*input.ValueSHA256))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func validSemanticPathInput(input SemanticPathInput) bool {
	switch input.Kind {
	case "missing":
		return input.EntryCount == 0 && input.ByteLength == 0
	case "file", "directory", "directory_listing":
		return input.EntryCount > 0 && input.EntryCount <= maxSemanticInputEntries &&
			input.ByteLength <= maxSemanticInputBytes
	default:
		return false
	}
}

func safeEnvironmentName(value string) bool {
	if value == "" || len(value) > 1024 || strings.Contains(value, "=") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func HashSemanticFile(repositoryRoot, relative string) (SemanticPathInput, error) {
	input, err := HashSemanticPath(repositoryRoot, relative)
	if err != nil {
		return SemanticPathInput{}, err
	}
	if input.Kind == "directory_listing" {
		return SemanticPathInput{}, fmt.Errorf("semantic input is not a regular file: %s", relative)
	}
	return input, nil
}

// HashSemanticPath captures one compiler-observed repository path. Files and
// failed candidates are exact; directories bind only their immediate entry
// names and kinds so a compiler resolution trace does not recursively rehash
// every byte below each visited node_modules directory.
func HashSemanticPath(repositoryRoot, relative string) (SemanticPathInput, error) {
	if !SafeSemanticPath(relative) {
		return SemanticPathInput{}, fmt.Errorf("unsafe semantic input path %q", relative)
	}
	absolute := repositoryRoot
	if relative != "." {
		absolute = filepath.Join(repositoryRoot, filepath.FromSlash(relative))
	}
	hasher := sha256.New()
	HashField(hasher, providerSemanticPathID)
	HashField(hasher, nil)
	resolution, err := resolveSemanticPath(repositoryRoot, absolute)
	if err != nil {
		return SemanticPathInput{}, err
	}
	HashField(hasher, []byte(resolution.canonicalDelta))
	if !resolution.exists {
		HashField(hasher, []byte("missing"))
		current, currentErr := resolveSemanticPath(repositoryRoot, absolute)
		if currentErr != nil || current != resolution {
			return SemanticPathInput{}, fmt.Errorf("semantic input changed while hashing: %s", relative)
		}
		return SemanticPathInput{Path: relative, Kind: "missing", IdentitySHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
	}
	before, err := os.Stat(absolute)
	if err != nil {
		return SemanticPathInput{}, err
	}
	stamp := semanticMetadataStamp(before)
	var input SemanticPathInput
	input.Path = relative
	switch {
	case before.Mode().IsRegular():
		bytes, err := os.ReadFile(absolute)
		if err != nil {
			return SemanticPathInput{}, err
		}
		if uint64(len(bytes)) > maxSemanticInputBytes {
			return SemanticPathInput{}, fmt.Errorf("semantic input bytes exceed their bound")
		}
		HashField(hasher, []byte("file"))
		content := sha256.Sum256(bytes)
		HashField(hasher, content[:])
		input.Kind = "file"
		input.EntryCount = 1
		input.ByteLength = uint64(len(bytes))
	case before.IsDir():
		entries, entryBytes, err := semanticDirectoryListing(repositoryRoot, absolute)
		if err != nil {
			return SemanticPathInput{}, err
		}
		if uint64(len(entries))+1 > maxSemanticInputEntries || entryBytes > maxSemanticInputBytes {
			return SemanticPathInput{}, fmt.Errorf("semantic directory listing exceeds its bound")
		}
		HashField(hasher, []byte("directory_listing"))
		var count [8]byte
		binary.BigEndian.PutUint64(count[:], uint64(len(entries)))
		HashField(hasher, count[:])
		for _, entry := range entries {
			HashField(hasher, []byte(entry.name))
			HashField(hasher, []byte(entry.kind))
			HashField(hasher, []byte(entry.canonicalDelta))
		}
		afterEntries, _, err := semanticDirectoryListing(repositoryRoot, absolute)
		if err != nil {
			return SemanticPathInput{}, err
		}
		if !equalSemanticDirectoryListings(entries, afterEntries) {
			return SemanticPathInput{}, fmt.Errorf("semantic directory listing changed while hashing: %s", relative)
		}
		input.Kind = "directory_listing"
		input.EntryCount = uint64(len(entries)) + 1
		input.ByteLength = entryBytes
	default:
		return SemanticPathInput{}, fmt.Errorf("semantic input has unsupported file type: %s", relative)
	}
	after, err := os.Stat(absolute)
	current, currentErr := resolveSemanticPath(repositoryRoot, absolute)
	if err != nil || currentErr != nil || semanticMetadataStamp(after) != stamp || current != resolution {
		return SemanticPathInput{}, fmt.Errorf("semantic input changed while hashing: %s", relative)
	}
	input.IdentitySHA256 = hex.EncodeToString(hasher.Sum(nil))
	return input, nil
}

type semanticDirectoryEntry struct {
	name           string
	kind           string
	canonicalDelta string
}

func semanticDirectoryListing(repositoryRoot, path string) ([]semanticDirectoryEntry, uint64, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, 0, err
	}
	observed := make([]semanticDirectoryEntry, 0, len(entries))
	var bytes uint64
	for _, entry := range entries {
		name := entry.Name()
		if !utf8.ValidString(name) {
			return nil, 0, fmt.Errorf("semantic directory listing contains a non-UTF-8 name")
		}
		entryPath := filepath.Join(path, name)
		resolution, err := resolveSemanticPath(repositoryRoot, entryPath)
		if err != nil || !resolution.exists {
			return nil, 0, fmt.Errorf("resolve semantic directory entry %s: %w", name, err)
		}
		info, err := os.Stat(entryPath)
		if err != nil {
			return nil, 0, err
		}
		var kind string
		switch {
		case info.Mode().IsRegular():
			kind = "file"
		case info.IsDir():
			kind = "directory"
		default:
			return nil, 0, fmt.Errorf("semantic directory listing contains an unsupported entry: %s", entry.Name())
		}
		entryBytes := uint64(len(name) + len(resolution.canonicalDelta))
		if entryBytes > maxSemanticInputBytes-bytes {
			return nil, 0, fmt.Errorf("semantic directory listing bytes exceed their bound")
		}
		bytes += entryBytes
		observed = append(observed, semanticDirectoryEntry{
			name: name, kind: kind, canonicalDelta: resolution.canonicalDelta,
		})
	}
	sort.Slice(observed, func(i, j int) bool { return observed[i].name < observed[j].name })
	return observed, bytes, nil
}

type semanticPathResolution struct {
	exists         bool
	canonicalPath  string
	canonicalDelta string
}

func resolveSemanticPath(repositoryRoot, path string) (semanticPathResolution, error) {
	repositoryRoot = filepath.Clean(repositoryRoot)
	path = filepath.Clean(path)
	logicalRelative, err := semanticRelativeLabel(repositoryRoot, path)
	if err != nil {
		return semanticPathResolution{}, err
	}
	canonicalRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return semanticPathResolution{}, err
	}
	canonicalRoot, err = filepath.Abs(canonicalRoot)
	if err != nil {
		return semanticPathResolution{}, err
	}
	candidate := path
	missingSuffix := make([]string, 0)
	var canonicalPath string
	for {
		_, lstatErr := os.Lstat(candidate)
		switch {
		case lstatErr == nil:
			canonicalPath, err = filepath.EvalSymlinks(candidate)
			if err != nil {
				return semanticPathResolution{}, fmt.Errorf("semantic input contains an unresolved symlink: %s: %w", candidate, err)
			}
			for index := len(missingSuffix) - 1; index >= 0; index-- {
				canonicalPath = filepath.Join(canonicalPath, missingSuffix[index])
			}
			goto resolved
		case os.IsNotExist(lstatErr):
			if candidate == repositoryRoot {
				return semanticPathResolution{}, fmt.Errorf("semantic input repository root disappeared during observation")
			}
			missingSuffix = append(missingSuffix, filepath.Base(candidate))
			candidate = filepath.Dir(candidate)
			if _, parentErr := semanticRelativeLabel(repositoryRoot, candidate); parentErr != nil {
				return semanticPathResolution{}, parentErr
			}
		default:
			return semanticPathResolution{}, lstatErr
		}
	}

resolved:
	canonicalPath, err = filepath.Abs(filepath.Clean(canonicalPath))
	if err != nil {
		return semanticPathResolution{}, err
	}
	canonicalRelative, err := semanticRelativeLabel(canonicalRoot, canonicalPath)
	if err != nil {
		return semanticPathResolution{}, fmt.Errorf("semantic input symlink escapes repository authority: %s", path)
	}
	delta := ""
	if canonicalRelative != logicalRelative {
		delta = "target:" + canonicalRelative
	}
	return semanticPathResolution{
		exists: len(missingSuffix) == 0, canonicalPath: canonicalPath, canonicalDelta: delta,
	}, nil
}

func semanticRelativeLabel(repositoryRoot, path string) (string, error) {
	relative, err := filepath.Rel(repositoryRoot, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("semantic input path escapes repository authority")
	}
	if relative == "." {
		return "", nil
	}
	if !utf8.ValidString(relative) {
		return "", fmt.Errorf("semantic input path is not UTF-8")
	}
	return filepath.ToSlash(relative), nil
}

func equalSemanticDirectoryListings(left, right []semanticDirectoryEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type semanticMetadata struct {
	regular bool
	dir     bool
	size    int64
	modTime time.Time
}

func semanticMetadataStamp(info os.FileInfo) semanticMetadata {
	return semanticMetadata{
		regular: info.Mode().IsRegular(),
		dir:     info.IsDir(),
		size:    info.Size(),
		modTime: info.ModTime(),
	}
}

func HashField(writer io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func SHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func IsSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// IsExactSuccessorEpoch admits one and only one non-wrapping authority step.
func IsExactSuccessorEpoch(previous, next uint64) bool {
	return next != 0 && next-1 == previous
}

func ValidComponentName(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '_' {
			return false
		}
	}
	return true
}

func SafeDocumentPath(value string) bool {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return false
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// SafeSemanticPath admits the repository root itself for a compiler-observed
// directory listing while preserving the stricter document-path contract for
// sources and protocol attachments.
func SafeSemanticPath(value string) bool {
	return value == "." || SafeDocumentPath(value)
}

func ArmParentLivenessGuard() error {
	process := os.Getpid()
	if syscall.Getpgrp() != process {
		return fmt.Errorf("semantic provider must own its process group")
	}
	expectedParent, err := strconv.Atoi(os.Getenv(ProviderParentPIDEnv))
	if err != nil {
		return fmt.Errorf("semantic provider requires valid %s", ProviderParentPIDEnv)
	}
	if expectedParent <= 1 || os.Getppid() != expectedParent {
		return fmt.Errorf("semantic provider owning parent changed before liveness guard armed")
	}
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)
			if os.Getppid() != expectedParent {
				_ = syscall.Kill(0, syscall.SIGKILL)
				return
			}
		}
	}()
	return nil
}
