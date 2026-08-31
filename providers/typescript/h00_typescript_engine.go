package main

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/microsoft/typescript-go/internal/bundled"
	"github.com/microsoft/typescript-go/internal/diagnostics"
	"github.com/microsoft/typescript-go/internal/lsp/lsproto"
	"github.com/microsoft/typescript-go/internal/project"
	"github.com/microsoft/typescript-go/internal/vfs"
	"github.com/microsoft/typescript-go/internal/vfs/osvfs"
	"github.com/microsoft/typescript-go/internal/vfs/trackingvfs"
	"github.com/scip-code/scip/bindings/go/scip"
)

const h00TypeScriptWorkspaceResolutionSchema = "h00/typescript-native/workspace-resolution/v2"

var h00TypeScriptSemanticFileNames = []string{
	"package.json",
	"package-lock.json",
	"npm-shrinkwrap.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"bun.lock",
	"bun.lockb",
	".pnp.cjs",
	".pnp.data.json",
}

type h00TypeScriptEngine struct {
	mu               sync.Mutex
	session          *project.Session
	trackedFS        *trackingvfs.FS
	repositoryFS     *h00RepositoryFS
	repositoryRoot   string
	executionRoot    string
	executionPrefix  string
	sources          map[string]h00SourceIdentity
	sourceBytes      map[string][]byte
	versions         map[string]int32
	localPackages    map[string]h00TypeScriptPackageCoordinate
	externalPackages map[string]h00TypeScriptPackageCoordinate
}

type h00TypeScriptClient struct{}

// h00RepositoryFS makes the repository boundary an input to resolution rather
// than an after-the-fact reporting convention. TypeScript may probe ancestor
// package.json and node_modules paths, but those ambient machine paths cannot
// influence a portable repository-scoped provider session.
type h00RepositoryFS struct {
	inner            vfs.FS
	repositoryRoot   string
	currentDirectory string
}

var _ vfs.FS = (*h00RepositoryFS)(nil)

func (fs *h00RepositoryFS) UseCaseSensitiveFileNames() bool {
	return fs.inner.UseCaseSensitiveFileNames()
}

func (fs *h00RepositoryFS) FileExists(path string) bool {
	path, ok := fs.admittedPath(path)
	return ok && fs.inner.FileExists(path)
}

func (fs *h00RepositoryFS) ReadFile(path string) (string, bool) {
	path, ok := fs.admittedPath(path)
	if !ok {
		return "", false
	}
	return fs.inner.ReadFile(path)
}

func (*h00RepositoryFS) WriteFile(string, string) error  { return vfs.ErrPermission }
func (*h00RepositoryFS) AppendFile(string, string) error { return vfs.ErrPermission }
func (*h00RepositoryFS) Remove(string) error             { return vfs.ErrPermission }
func (*h00RepositoryFS) Chtimes(string, time.Time, time.Time) error {
	return vfs.ErrPermission
}

func (fs *h00RepositoryFS) DirectoryExists(path string) bool {
	path, ok := fs.admittedPath(path)
	return ok && fs.inner.DirectoryExists(path)
}

func (fs *h00RepositoryFS) GetAccessibleEntries(path string) vfs.Entries {
	path, ok := fs.admittedPath(path)
	if !ok {
		return vfs.Entries{}
	}
	return fs.inner.GetAccessibleEntries(path)
}

func (fs *h00RepositoryFS) Stat(path string) vfs.FileInfo {
	path, ok := fs.admittedPath(path)
	if !ok {
		return nil
	}
	return fs.inner.Stat(path)
}

func (fs *h00RepositoryFS) WalkDir(root string, walkFn vfs.WalkDirFunc) error {
	root, ok := fs.admittedPath(root)
	if !ok {
		return nil
	}
	return fs.inner.WalkDir(root, walkFn)
}

func (fs *h00RepositoryFS) Realpath(path string) string {
	admitted, ok := fs.admittedPath(path)
	if !ok {
		return path
	}
	return fs.inner.Realpath(admitted)
}

func (fs *h00RepositoryFS) admittedPath(path string) (string, bool) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(fs.currentDirectory, path)
	}
	path = filepath.Clean(path)
	if !h00PathWithin(path, fs.repositoryRoot) {
		return "", false
	}
	// An in-root lexical path can still escape through a symlinked ancestor.
	// Resolve the nearest existing ancestor so missing module candidates remain
	// admissible without letting an existing link import ambient machine state.
	for candidate := path; ; candidate = filepath.Dir(candidate) {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			return path, h00PathWithin(resolved, fs.repositoryRoot)
		}
		if !os.IsNotExist(err) || candidate == fs.repositoryRoot {
			return "", false
		}
		parent := filepath.Dir(candidate)
		if parent == candidate || !h00PathWithin(parent, fs.repositoryRoot) {
			return "", false
		}
	}
}

func (*h00TypeScriptClient) WatchFiles(context.Context, project.WatcherID, []*lsproto.FileSystemWatcher) error {
	return nil
}
func (*h00TypeScriptClient) UnwatchFiles(context.Context, project.WatcherID) error { return nil }
func (*h00TypeScriptClient) RefreshDiagnostics(context.Context) error              { return nil }
func (*h00TypeScriptClient) PublishDiagnostics(context.Context, *lsproto.PublishDiagnosticsParams) error {
	return nil
}
func (*h00TypeScriptClient) RefreshInlayHints(context.Context) error     { return nil }
func (*h00TypeScriptClient) RefreshCodeLens(context.Context) error       { return nil }
func (*h00TypeScriptClient) ProgressStart(*diagnostics.Message, ...any)  {}
func (*h00TypeScriptClient) ProgressFinish(*diagnostics.Message, ...any) {}
func (*h00TypeScriptClient) SendTelemetry(context.Context, lsproto.TelemetryEvent) error {
	return nil
}
func (*h00TypeScriptClient) IsActive() bool { return true }

func h00StartTypeScriptEngine(
	ctx context.Context,
	repositoryRoot string,
	executionRoot string,
	executionPrefix string,
	sources map[string]h00SourceIdentity,
) (*h00TypeScriptEngine, error) {
	canonicalRepository, err := h00CanonicalDirectory(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("repository root: %w", err)
	}
	canonicalExecution, err := h00CanonicalDirectory(executionRoot)
	if err != nil {
		return nil, fmt.Errorf("execution root: %w", err)
	}
	if !h00PathWithin(canonicalExecution, canonicalRepository) {
		return nil, fmt.Errorf("execution root escapes repository root")
	}
	prefix, err := filepath.Rel(canonicalRepository, canonicalExecution)
	if err != nil {
		return nil, fmt.Errorf("derive execution prefix: %w", err)
	}
	if prefix == "." {
		prefix = ""
	} else {
		prefix = filepath.ToSlash(prefix)
	}
	if prefix != executionPrefix {
		return nil, fmt.Errorf("execution prefix differs from canonical roots")
	}
	if len(sources) == 0 || len(sources) > h00MaxDocumentPaths {
		return nil, fmt.Errorf("invalid TypeScript source population")
	}

	ownedSources := make(map[string]h00SourceIdentity, len(sources))
	sourceBytes := make(map[string][]byte, len(sources))
	paths := make([]string, 0, len(sources))
	for path, source := range sources {
		if path != source.DocumentPath || source.Language != h00ProviderLanguage ||
			!h00SafeDocumentPath(path) || !h00IsSHA256(source.ContentSHA256) {
			return nil, fmt.Errorf("invalid TypeScript source identity for %q", path)
		}
		absolute := filepath.Join(canonicalRepository, filepath.FromSlash(path))
		if !h00PathWithin(absolute, canonicalExecution) {
			return nil, fmt.Errorf("TypeScript source escapes execution root: %q", path)
		}
		contents, err := os.ReadFile(absolute)
		if err != nil || h00SHA256(contents) != source.ContentSHA256 {
			return nil, fmt.Errorf("TypeScript source identity mismatch: %q", path)
		}
		ownedSources[path] = source
		sourceBytes[path] = contents
		paths = append(paths, path)
	}
	sort.Strings(paths)

	trackedFS := &trackingvfs.FS{Inner: osvfs.FS()}
	repositoryFS := &h00RepositoryFS{
		inner: trackedFS, repositoryRoot: canonicalRepository,
		currentDirectory: canonicalExecution,
	}
	compilerSession := project.NewSession(&project.SessionInit{
		BackgroundCtx: ctx,
		FS:            bundled.WrapFS(repositoryFS),
		Client:        &h00TypeScriptClient{},
		Options: &project.SessionOptions{
			CurrentDirectory:   canonicalExecution,
			DefaultLibraryPath: bundled.LibPath(),
			PositionEncoding:   lsproto.PositionEncodingKindUTF8,
			WatchEnabled:       false,
			LoggingEnabled:     false,
		},
	})
	opened := false
	defer func() {
		if !opened {
			compilerSession.Close()
		}
	}()
	versions := make(map[string]int32, len(paths))
	for _, path := range paths {
		compilerSession.DidOpenFile(
			ctx,
			h00TypeScriptURI(filepath.Join(canonicalRepository, filepath.FromSlash(path))),
			1,
			string(sourceBytes[path]),
			h00TypeScriptLanguageKind(path),
		)
		versions[path] = 1
	}
	// Force one compiler-backed project admission while every source byte is
	// still bound to the caller's population. Later exports reuse this session.
	externalSourceFiles := make(map[string]struct{})
	for _, path := range paths {
		languageService, err := compilerSession.GetLanguageService(
			ctx,
			h00TypeScriptURI(filepath.Join(canonicalRepository, filepath.FromSlash(path))),
		)
		if err != nil {
			return nil, fmt.Errorf("load TypeScript project for %q: %w", path, err)
		}
		program := languageService.GetProgram()
		if program == nil {
			return nil, fmt.Errorf("TypeScript project has no program for %q", path)
		}
		for _, sourceFile := range program.GetSourceFiles() {
			externalSourceFiles[sourceFile.FileName()] = struct{}{}
		}
	}
	localPackages := make(map[string]h00TypeScriptPackageCoordinate, len(paths))
	for _, path := range paths {
		localPackages[path] = h00ResolveTypeScriptPackageCoordinate(
			repositoryFS,
			filepath.Dir(filepath.Join(canonicalRepository, filepath.FromSlash(path))),
			canonicalRepository,
		)
	}
	externalPackages := h00ObservedTypeScriptExternalPackages(
		repositoryFS,
		externalSourceFiles,
	)
	opened = true
	return &h00TypeScriptEngine{
		session: compilerSession, trackedFS: trackedFS, repositoryFS: repositoryFS,
		repositoryRoot: canonicalRepository,
		executionRoot:  canonicalExecution, executionPrefix: prefix,
		sources: ownedSources, sourceBytes: sourceBytes, versions: versions,
		localPackages: localPackages, externalPackages: externalPackages,
	}, nil
}

func (engine *h00TypeScriptEngine) close() {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.session != nil {
		engine.session.Close()
		engine.session = nil
	}
}

func (engine *h00TypeScriptEngine) exportDocuments(
	ctx context.Context,
	documents []string,
) ([]*scip.Document, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.session == nil || len(documents) == 0 || len(documents) > h00MaxDocumentPaths {
		return nil, fmt.Errorf("invalid TypeScript export session or population")
	}
	paths := append([]string(nil), documents...)
	sort.Strings(paths)
	for index, path := range paths {
		if _, ok := engine.sources[path]; !ok || !h00SafeDocumentPath(path) {
			return nil, fmt.Errorf("TypeScript export path is outside the session population: %q", path)
		}
		if index > 0 && paths[index-1] == path {
			return nil, fmt.Errorf("duplicate TypeScript export path %q", path)
		}
	}
	exported := make([]*scip.Document, 0, len(paths))
	for _, path := range paths {
		document, err := engine.exportDocument(ctx, path)
		if err != nil {
			return nil, err
		}
		exported = append(exported, document)
	}
	return exported, nil
}

func (engine *h00TypeScriptEngine) authorityEvidence(
	ctx context.Context,
) (string, h00SemanticInputs, h00Health, error) {
	if engine.session == nil {
		return "", h00SemanticInputs{}, h00Health{}, fmt.Errorf("TypeScript compiler session is closed")
	}
	paths := make([]string, 0, len(engine.sources))
	for path := range engine.sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	workspacePaths := make(map[string]struct{})
	semanticPaths := make(map[string]struct{})
	unresolved := make(map[string]struct{})
	for _, path := range paths {
		absolute := filepath.Join(engine.repositoryRoot, filepath.FromSlash(path))
		languageService, err := engine.session.GetLanguageService(ctx, h00TypeScriptURI(absolute))
		if err != nil {
			return "", h00SemanticInputs{}, h00Health{}, fmt.Errorf("observe TypeScript project for %q: %w", path, err)
		}
		program := languageService.GetProgram()
		if program == nil {
			return "", h00SemanticInputs{}, h00Health{}, fmt.Errorf("TypeScript project has no program for %q", path)
		}
		if commandLine := program.CommandLine(); commandLine != nil {
			if len(commandLine.GetConfigFileParsingDiagnostics()) != 0 {
				return "", h00SemanticInputs{}, h00Health{}, fmt.Errorf("TypeScript configuration diagnostics prevent complete project authority")
			}
			for _, configPath := range append(
				append([]string{commandLine.ConfigName()}, commandLine.ExtendedSourceFiles()...),
				commandLine.ResolvedProjectReferencePaths()...,
			) {
				if err := engine.observeTypeScriptPath(configPath, workspacePaths, semanticPaths); err != nil {
					return "", h00SemanticInputs{}, h00Health{}, err
				}
			}
		}
		for _, sourceFile := range program.GetSourceFiles() {
			if err := engine.observeTypeScriptPath(sourceFile.FileName(), workspacePaths, semanticPaths); err != nil {
				return "", h00SemanticInputs{}, h00Health{}, err
			}
		}
		// GetUnresolvedImports exists for automatic type acquisition and
		// deliberately omits unresolved relative imports. Health authority must
		// instead inspect the compiler's complete per-file resolution cache so a
		// missing local module cannot be certified as a healthy project graph.
		for _, resolutions := range program.GetResolvedModules() {
			for key, resolution := range resolutions {
				if !resolution.IsResolved() {
					unresolved[key.Name] = struct{}{}
				}
			}
		}
	}
	for _, directory := range h00AncestorDirectories(engine.executionRoot, engine.repositoryRoot) {
		for _, name := range h00TypeScriptSemanticFileNames {
			path := filepath.Join(directory, name)
			relative, ok := engine.repositoryDocumentPath(path)
			if ok {
				semanticPaths[relative] = struct{}{}
			}
		}
	}
	if engine.trackedFS == nil {
		return "", h00SemanticInputs{}, h00Health{}, fmt.Errorf("TypeScript compiler access trace is unavailable")
	}
	for _, path := range engine.trackedFS.SeenFiles.ToSlice() {
		if err := engine.observeTrackedTypeScriptPath(path, semanticPaths); err != nil {
			return "", h00SemanticInputs{}, h00Health{}, err
		}
	}
	for path := range semanticPaths {
		if _, source := engine.sources[path]; source {
			delete(semanticPaths, path)
		}
	}
	workspaceLabels := make([]string, 0, len(workspacePaths)+len(unresolved))
	for path := range workspacePaths {
		workspaceLabels = append(workspaceLabels, "source\x00"+path)
	}
	for name := range unresolved {
		workspaceLabels = append(workspaceLabels, "unresolved\x00"+name)
	}
	sort.Strings(workspaceLabels)
	var workspace bytes.Buffer
	h00HashField(&workspace, []byte(h00TypeScriptWorkspaceResolutionSchema))
	h00HashField(&workspace, []byte(engine.executionPrefix))
	for _, path := range paths {
		coordinate, ok := engine.localPackages[path]
		if !ok {
			return "", h00SemanticInputs{}, h00Health{}, fmt.Errorf("TypeScript source has no package coordinate: %q", path)
		}
		h00HashField(&workspace, []byte("package\x00"+path+"\x00"+coordinate.Name+"\x00"+coordinate.Version))
	}
	for _, label := range workspaceLabels {
		h00HashField(&workspace, []byte(label))
	}
	semanticLabels := make([]string, 0, len(semanticPaths))
	for path := range semanticPaths {
		semanticLabels = append(semanticLabels, path)
	}
	sort.Strings(semanticLabels)
	if len(semanticLabels) > h00MaxDocumentPaths {
		return "", h00SemanticInputs{}, h00Health{}, fmt.Errorf("TypeScript semantic-input population exceeds the provider bound")
	}
	inputs := h00SemanticInputs{
		SchemaVersion: h00ProviderSemanticInputsSchema,
		Coverage:      "complete",
		Paths:         make([]h00SemanticPathInput, 0, len(semanticLabels)),
		Environment:   []h00SemanticEnvironmentInput{},
		Issues:        []h00SemanticInputIssue{},
	}
	for _, path := range semanticLabels {
		input, err := h00HashSemanticPath(engine.repositoryRoot, path)
		if err != nil {
			return "", h00SemanticInputs{}, h00Health{}, fmt.Errorf("observe TypeScript semantic input %q: %w", path, err)
		}
		inputs.Paths = append(inputs.Paths, input)
	}
	if _, err := h00SemanticInputsSHA256(inputs); err != nil {
		return "", h00SemanticInputs{}, h00Health{}, err
	}
	health := h00Health{
		Components: map[string]string{
			"project_graph": "healthy",
			"type_checking": "healthy",
		},
		DiagnosticsComplete: true,
		DegradationReasons:  []string{},
	}
	if len(unresolved) != 0 {
		health.Components["module_resolution"] = "failed"
		health.DiagnosticsComplete = false
		health.DegradationReasons = []string{"unresolved_imports"}
	} else {
		health.Components["module_resolution"] = "healthy"
	}
	return h00SHA256(workspace.Bytes()), inputs, health, nil
}

func (engine *h00TypeScriptEngine) observeTrackedTypeScriptPath(
	path string,
	semanticPaths map[string]struct{},
) error {
	if path == "" || strings.HasPrefix(filepath.ToSlash(path), "bundled:") {
		return nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(engine.executionRoot, path)
	}
	path = filepath.Clean(path)
	if !h00PathWithin(path, engine.repositoryRoot) {
		return fmt.Errorf("TypeScript compiler observed a path outside repository authority: %q", path)
	}
	// A missing candidate is fully witnessed by the immediate membership of
	// its nearest existing ancestor. This collapses thousands of redundant
	// Node-style probes without losing the transition that could make any of
	// them resolvable. Existing files and directories remain exact paths.
	for {
		_, err := os.Lstat(path)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("observe TypeScript compiler path %q: %w", path, err)
		}
		if path == engine.repositoryRoot {
			return fmt.Errorf("TypeScript repository root disappeared during compiler observation")
		}
		parent := filepath.Dir(path)
		if parent == path || !h00PathWithin(parent, engine.repositoryRoot) {
			return fmt.Errorf("TypeScript compiler path lost its repository-local membership owner: %q", path)
		}
		path = parent
	}
	relative, err := filepath.Rel(engine.repositoryRoot, path)
	if err != nil {
		return fmt.Errorf("derive TypeScript compiler path authority: %w", err)
	}
	relative = filepath.ToSlash(relative)
	if !h00SafeSemanticPath(relative) {
		return fmt.Errorf("TypeScript compiler observed an unsafe semantic path: %q", path)
	}
	if _, source := engine.sources[relative]; !source {
		semanticPaths[relative] = struct{}{}
	}
	return nil
}

type h00TypeScriptReplacement struct {
	path    string
	bytes   []byte
	version int32
	next    h00SourceIdentity
}

func (engine *h00TypeScriptEngine) applyReplacements(
	ctx context.Context,
	replacements []h00TypeScriptReplacement,
) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.session == nil || len(replacements) == 0 {
		return fmt.Errorf("invalid TypeScript replacement session")
	}
	for _, replacement := range replacements {
		if !utf8.Valid(replacement.bytes) {
			return fmt.Errorf("TypeScript replacement is not UTF-8: %q", replacement.path)
		}
		engine.session.DidChangeFile(
			ctx,
			h00TypeScriptURI(filepath.Join(engine.repositoryRoot, filepath.FromSlash(replacement.path))),
			replacement.version,
			[]lsproto.TextDocumentContentChangePartialOrWholeDocument{{
				WholeDocument: &lsproto.TextDocumentContentChangeWholeDocument{Text: string(replacement.bytes)},
			}},
		)
	}
	for _, replacement := range replacements {
		engine.sources[replacement.path] = replacement.next
		engine.sourceBytes[replacement.path] = append([]byte(nil), replacement.bytes...)
		engine.versions[replacement.path] = replacement.version
		if _, err := engine.session.GetLanguageService(
			ctx,
			h00TypeScriptURI(filepath.Join(engine.repositoryRoot, filepath.FromSlash(replacement.path))),
		); err != nil {
			return fmt.Errorf("refresh TypeScript project for %q: %w", replacement.path, err)
		}
	}
	return nil
}

func (engine *h00TypeScriptEngine) observeTypeScriptPath(
	path string,
	workspacePaths map[string]struct{},
	semanticPaths map[string]struct{},
) error {
	if path == "" {
		return nil
	}
	normalized := filepath.ToSlash(path)
	if strings.HasPrefix(normalized, "bundled:") || strings.Contains(normalized, "/internal/bundled/libs/") {
		workspacePaths["@typescript/lib/"+filepath.Base(normalized)] = struct{}{}
		return nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(engine.executionRoot, path)
	}
	if relative, ok := engine.repositoryDocumentPath(filepath.Clean(path)); ok {
		workspacePaths[relative] = struct{}{}
		if _, source := engine.sources[relative]; !source {
			semanticPaths[relative] = struct{}{}
		}
		return nil
	}
	return fmt.Errorf("TypeScript project input escapes repository authority: %q", path)
}

func h00AncestorDirectories(path, inclusiveRoot string) []string {
	var reversed []string
	for current := path; ; current = filepath.Dir(current) {
		reversed = append(reversed, current)
		if current == inclusiveRoot {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	directories := make([]string, 0, len(reversed))
	for index := len(reversed) - 1; index >= 0; index-- {
		directories = append(directories, reversed[index])
	}
	return directories
}

func h00TypeScriptURI(path string) lsproto.DocumentUri {
	clean := filepath.ToSlash(filepath.Clean(path))
	return lsproto.DocumentUri((&url.URL{Scheme: "file", Path: clean}).String())
}

func h00TypeScriptLanguageKind(path string) lsproto.LanguageKind {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".mjs", ".cjs":
		return lsproto.LanguageKindJavaScript
	case ".jsx":
		return lsproto.LanguageKindJavaScriptReact
	case ".tsx":
		return lsproto.LanguageKindTypeScriptReact
	default:
		return lsproto.LanguageKindTypeScript
	}
}

func h00CanonicalDirectory(path string) (string, error) {
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
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
