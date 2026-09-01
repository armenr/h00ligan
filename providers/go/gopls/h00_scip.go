package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/scip-code/scip-go/h00scip"
	"github.com/scip-code/scip/bindings/go/scip"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/gopls/internal/cache"
	"golang.org/x/tools/gopls/internal/cache/metadata"
	"golang.org/x/tools/gopls/internal/protocol"
	"golang.org/x/tools/gopls/internal/util/tokeninternal"
)

// H00WorkspaceWitness binds one provider session to the selected package
// closure of its exact requested source population. The maps are retained
// only in the private provider process so a failed comparison can name a
// bounded package/document delta instead of exposing an opaque digest race.
type H00WorkspaceWitness struct {
	SHA256                string
	PackageSHA256s        map[string]string
	DocumentSelections    map[string]string
	RootClosurePackageIDs map[string][]string
}

// H00SemanticPathWitness is the exact project-input identity read through the
// same immutable gopls snapshot that produced a workspace witness.
type H00SemanticPathWitness struct {
	Kind           string
	IdentitySHA256 string
	EntryCount     uint64
	ByteLength     uint64
}

type h00WorkspaceObservation struct {
	witness  H00WorkspaceWitness
	selected map[protocol.DocumentURI]cache.PackageID
}

// H00ExportScipDocuments emits scip-go documents from gopls's already
// type-checked snapshot without another packages.Load invocation.
func H00ExportScipDocuments(
	ctx context.Context,
	semanticServer protocol.Server,
	moduleRoot string,
	moduleVersion string,
	repositoryPrefix string,
	requested []protocol.DocumentURI,
	expectedSourceSHA256s map[protocol.DocumentURI]string,
	expectedWorkspace H00WorkspaceWitness,
	goStdlibVersion string,
	includeCallableLiveness bool,
) ([]*scip.Document, []byte, error) {
	server, ok := semanticServer.(*server)
	if !ok {
		return nil, nil, fmt.Errorf("h00ligan SCIP export requires the local gopls server")
	}
	if len(requested) == 0 || len(expectedSourceSHA256s) == 0 {
		return nil, nil, fmt.Errorf("empty requested or admitted source population")
	}
	requestedSet := make(map[protocol.DocumentURI]struct{}, len(requested))
	for _, uri := range requested {
		if _, admitted := expectedSourceSHA256s[uri]; !admitted {
			return nil, nil, fmt.Errorf("requested Go source is absent from admitted snapshot: %s", uri)
		}
		if _, duplicate := requestedSet[uri]; duplicate {
			return nil, nil, fmt.Errorf("duplicate requested Go source: %s", uri)
		}
		requestedSet[uri] = struct{}{}
	}
	snapshot, release, err := server.session.SnapshotOf(ctx, requested[0])
	if err != nil {
		return nil, nil, fmt.Errorf("resolve gopls snapshot: %w", err)
	}
	defer release()
	snapshot.AwaitInitialized(ctx)
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("await gopls snapshot initialization: %w", err)
	}
	observedURIs := requested
	if includeCallableLiveness {
		observedURIs = make([]protocol.DocumentURI, 0, len(expectedSourceSHA256s))
		for uri := range expectedSourceSHA256s {
			observedURIs = append(observedURIs, uri)
		}
		sort.Slice(observedURIs, func(i, j int) bool { return observedURIs[i].Path() < observedURIs[j].Path() })
	}
	expected, err := h00ProjectWorkspaceWitness(expectedWorkspace, observedURIs)
	if err != nil {
		return nil, nil, fmt.Errorf("project admitted Go workspace resolution: %w", err)
	}
	if err := h00VerifySnapshotSources(ctx, snapshot, expectedSourceSHA256s); err != nil {
		return nil, nil, err
	}
	initial, err := h00ObserveWorkspace(ctx, snapshot, observedURIs)
	if err != nil {
		return nil, nil, err
	}
	if initial.witness.SHA256 != expected.SHA256 {
		return nil, nil, fmt.Errorf(
			"Go workspace resolution changed after session admission: admitted=%s observed=%s %s",
			expected.SHA256,
			initial.witness.SHA256,
			h00WorkspaceResolutionDifference(expected, initial.witness),
		)
	}

	type packageGroup struct {
		pkg   *cache.Package
		files []string
	}
	ids := make([]cache.PackageID, 0, len(initial.selected))
	seenIDs := make(map[cache.PackageID]struct{}, len(initial.selected))
	for _, id := range initial.selected {
		if _, seen := seenIDs[id]; seen {
			continue
		}
		seenIDs[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	typed, err := snapshot.TypeCheck(ctx, ids...)
	if err != nil {
		return nil, nil, fmt.Errorf("type-check selected Go package population: %w", err)
	}
	typedByID := make(map[cache.PackageID]*cache.Package, len(ids))
	for index, id := range ids {
		if typed[index] == nil {
			return nil, nil, fmt.Errorf("type-check returned no package for %s", id)
		}
		typedByID[id] = typed[index]
	}
	final, err := h00ObserveWorkspace(ctx, snapshot, observedURIs)
	if err != nil {
		return nil, nil, err
	}
	if final.witness.SHA256 != expected.SHA256 {
		return nil, nil, fmt.Errorf(
			"Go workspace resolution changed during full certification: admitted=%s observed=%s %s",
			expected.SHA256,
			final.witness.SHA256,
			h00WorkspaceResolutionDifference(expected, final.witness),
		)
	}
	if err := h00VerifySnapshotSources(ctx, snapshot, expectedSourceSHA256s); err != nil {
		return nil, nil, err
	}
	groups := make(map[cache.PackageID]*packageGroup, len(ids))
	for uri, id := range final.selected {
		if _, requested := requestedSet[uri]; !requested {
			continue
		}
		group := groups[id]
		if group == nil {
			group = &packageGroup{pkg: typedByID[id]}
			groups[id] = group
		}
		group.files = append(group.files, uri.Path())
	}
	documentIDs := make([]cache.PackageID, 0, len(groups))
	for id := range groups {
		documentIDs = append(documentIDs, id)
	}
	sort.Slice(documentIDs, func(i, j int) bool { return documentIDs[i] < documentIDs[j] })
	var documents []*scip.Document
	for _, id := range documentIDs {
		group := groups[id]
		sort.Strings(group.files)
		if group.pkg == nil {
			return nil, nil, fmt.Errorf(
				"selected Go package %s has no type-checked package for documents %s",
				id, h00BoundedPackageIDs(group.files),
			)
		}
		meta := group.pkg.Metadata()
		if meta == nil || meta.ID != id {
			actualID := cache.PackageID("<nil>")
			if meta != nil {
				actualID = meta.ID
			}
			return nil, nil, fmt.Errorf(
				"selected Go package identity changed before export: selected=%s typed=%s documents=%s",
				id, actualID, h00BoundedPackageIDs(group.files),
			)
		}
		if meta.Module == nil {
			return nil, nil, fmt.Errorf(
				"selected Go package %s has no module authority for documents %s",
				id, h00BoundedPackageIDs(group.files),
			)
		}
		loaded, dependencies, err := h00LoadedPackage(snapshot, group.pkg, goStdlibVersion)
		if err != nil {
			return nil, nil, err
		}
		exported, err := h00scip.ExportDocuments(
			moduleRoot,
			moduleVersion,
			loaded,
			dependencies,
			group.files,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("export package %s: %w", id, err)
		}
		documents = append(documents, exported...)
	}
	sort.Slice(documents, func(i, j int) bool {
		return documents[i].RelativePath < documents[j].RelativePath
	})
	var callableLiveness []byte
	if includeCallableLiveness {
		callableLiveness, err = h00ExportCallableLiveness(
			ctx,
			moduleRoot,
			repositoryPrefix,
			snapshot,
			ids,
			typedByID,
			final,
			expectedSourceSHA256s,
			goStdlibVersion,
		)
		if err != nil {
			return nil, nil, err
		}
	}
	return documents, callableLiveness, nil
}

type h00CallableLivenessSpan struct {
	StartByte           uint64 `json:"start_byte"`
	EndByte             uint64 `json:"end_byte"`
	StartLine           uint32 `json:"start_line"`
	StartUTF8ByteColumn uint32 `json:"start_utf8_byte_column"`
	EndLine             uint32 `json:"end_line"`
	EndUTF8ByteColumn   uint32 `json:"end_utf8_byte_column"`
}

type h00CallableLivenessLocation struct {
	DocumentPath string                  `json:"document_path"`
	Span         h00CallableLivenessSpan `json:"span"`
}

type h00CallableLivenessDocument struct {
	DocumentPath   string `json:"document_path"`
	ContentSHA256  string `json:"content_sha256"`
	Included       bool   `json:"included"`
	OmissionReason string `json:"omission_reason,omitempty"`
}

type h00CallableLivenessRecord struct {
	Name                string                      `json:"name"`
	Definition          h00CallableLivenessLocation `json:"definition"`
	StructuralExtent    h00CallableLivenessLocation `json:"structural_extent"`
	ProductionReachable bool                        `json:"production_reachable"`
	TestReachable       bool                        `json:"test_reachable"`
}

type h00CallableLivenessArtifact struct {
	SchemaVersion   string                        `json:"schema_version"`
	ConfigurationID string                        `json:"configuration_id"`
	Language        string                        `json:"language"`
	Documents       []h00CallableLivenessDocument `json:"documents"`
	Callables       []h00CallableLivenessRecord   `json:"callables"`
}

type h00CallablePosition struct {
	Filename string
	Line     int
	Column   int
}

func h00ExportCallableLiveness(
	ctx context.Context,
	moduleRoot string,
	repositoryPrefix string,
	snapshot *cache.Snapshot,
	ids []cache.PackageID,
	typedByID map[cache.PackageID]*cache.Package,
	workspace h00WorkspaceObservation,
	expectedSourceSHA256s map[protocol.DocumentURI]string,
	goStdlibVersion string,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("build Go callable liveness: %w", err)
	}
	initial := make([]*packages.Package, 0, len(ids))
	loadedByTypes := make(map[*types.Package]*packages.Package)
	cacheByLoaded := make(map[*packages.Package]*cache.Package, len(ids))
	for _, id := range ids {
		pkg := typedByID[id]
		if pkg == nil {
			return nil, fmt.Errorf("callable liveness has no type-checked package for %s", id)
		}
		loaded, dependencies, err := h00LoadedPackage(snapshot, pkg, goStdlibVersion)
		if err != nil {
			return nil, err
		}
		if loaded.Types == nil || loaded.Fset == nil || loaded.TypesInfo == nil || len(loaded.Syntax) == 0 {
			return nil, fmt.Errorf("callable liveness package %s lacks typed source", id)
		}
		initial = append(initial, loaded)
		loadedByTypes[loaded.Types] = loaded
		cacheByLoaded[loaded] = pkg
		for _, dependency := range dependencies {
			if dependency.Types != nil {
				if _, exists := loadedByTypes[dependency.Types]; !exists {
					loadedByTypes[dependency.Types] = dependency
				}
			}
		}
	}
	for index, loaded := range initial {
		pkg := typedByID[ids[index]]
		meta := pkg.Metadata()
		for importPath, dependencyID := range meta.DepsByImpPath {
			if dependencyID == "" {
				continue
			}
			dependencyMeta := snapshot.Metadata(dependencyID)
			if dependencyMeta == nil {
				return nil, fmt.Errorf("callable liveness package %s has missing dependency metadata for %s", meta.ID, dependencyID)
			}
			dependencyTypes := pkg.DependencyTypes(dependencyMeta.PkgPath)
			if dependencyTypes == nil {
				continue
			}
			dependency := loadedByTypes[dependencyTypes]
			if dependency == nil {
				return nil, fmt.Errorf("callable liveness package %s has no adapter for import %s", meta.ID, importPath)
			}
			loaded.Imports[string(importPath)] = dependency
		}
	}
	fileSet, err := h00UnifiedFileSet(initial)
	if err != nil {
		return nil, err
	}
	for _, loaded := range initial {
		loaded.Fset = fileSet
	}
	program, ssaPackages := ssautil.Packages(initial, ssa.InstantiateGenerics)
	program.Build()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("build Go callable liveness SSA: %w", err)
	}

	allowedPaths := make(map[string]protocol.DocumentURI, len(expectedSourceSHA256s))
	for uri := range expectedSourceSHA256s {
		allowedPaths[filepath.Clean(uri.Path())] = uri
	}
	type sourceCallable struct {
		function *ssa.Function
		record   h00CallableLivenessRecord
		position h00CallablePosition
	}
	callables := make([]sourceCallable, 0)
	productionRoots := make(map[*ssa.Function]struct{})
	testRoots := make(map[*ssa.Function]struct{})
	addRoot := func(set map[*ssa.Function]struct{}, function *ssa.Function) {
		if function != nil {
			set[function] = struct{}{}
		}
	}
	for index, loaded := range initial {
		ssaPackage := ssaPackages[index]
		if ssaPackage == nil {
			return nil, fmt.Errorf("callable liveness could not build SSA package %s", loaded.ID)
		}
		pkg := cacheByLoaded[loaded]
		isTestVariant := pkg.Metadata().ForTest != ""
		if isTestVariant {
			addRoot(testRoots, ssaPackage.Func("init"))
		} else {
			addRoot(productionRoots, ssaPackage.Func("init"))
			if loaded.Name == "main" {
				addRoot(productionRoots, ssaPackage.Func("main"))
			}
		}
		for _, file := range loaded.Syntax {
			filename := filepath.Clean(loaded.Fset.PositionFor(file.Pos(), false).Filename)
			uri, admitted := allowedPaths[filename]
			if !admitted {
				continue
			}
			documentPath, err := h00RepositoryDocumentPath(moduleRoot, repositoryPrefix, uri.Path())
			if err != nil {
				return nil, err
			}
			isTestFile := strings.HasSuffix(filename, "_test.go")
			for _, declaration := range file.Decls {
				functionDeclaration, ok := declaration.(*ast.FuncDecl)
				if !ok || functionDeclaration.Name == nil {
					continue
				}
				object, ok := loaded.TypesInfo.Defs[functionDeclaration.Name].(*types.Func)
				if !ok || object == nil {
					return nil, fmt.Errorf("callable liveness declaration %s has no type identity", functionDeclaration.Name.Name)
				}
				function := program.FuncValue(object)
				if function == nil {
					return nil, fmt.Errorf("callable liveness declaration %s has no SSA identity", functionDeclaration.Name.Name)
				}
				definition, err := h00BuildCallableLivenessLocation(loaded.Fset, documentPath, functionDeclaration.Name.Pos(), functionDeclaration.Name.End())
				if err != nil {
					return nil, err
				}
				extent, err := h00BuildCallableLivenessLocation(loaded.Fset, documentPath, functionDeclaration.Pos(), functionDeclaration.End())
				if err != nil {
					return nil, err
				}
				position := loaded.Fset.PositionFor(function.Pos(), false)
				callables = append(callables, sourceCallable{
					function: function,
					position: h00CallablePosition{Filename: filepath.Clean(position.Filename), Line: position.Line, Column: position.Column},
					record:   h00CallableLivenessRecord{Name: functionDeclaration.Name.Name, Definition: definition, StructuralExtent: extent},
				})
				if !isTestVariant && (object.Exported() || h00ExternallyRootedGoDeclaration(functionDeclaration)) {
					addRoot(productionRoots, function)
				}
				if isTestFile && h00GoTestRootName(functionDeclaration.Name.Name) {
					addRoot(testRoots, function)
				}
			}
		}
	}
	if len(productionRoots) == 0 {
		return nil, fmt.Errorf("callable liveness found no production or public API roots")
	}
	production := h00SortedFunctions(productionRoots)
	productionResult := rta.Analyze(production, false)
	allRoots := make(map[*ssa.Function]struct{}, len(productionRoots)+len(testRoots))
	for function := range productionRoots {
		allRoots[function] = struct{}{}
	}
	for function := range testRoots {
		allRoots[function] = struct{}{}
	}
	testResult := rta.Analyze(h00SortedFunctions(allRoots), false)
	productionPositions := h00ReachablePositions(program.Fset, productionResult)
	testPositions := h00ReachablePositions(program.Fset, testResult)

	recordsByIdentity := make(map[string]h00CallableLivenessRecord, len(callables))
	for _, callable := range callables {
		record := callable.record
		_, record.ProductionReachable = productionPositions[callable.position]
		_, record.TestReachable = testPositions[callable.position]
		key := fmt.Sprintf("%s\x00%020d\x00%020d", record.StructuralExtent.DocumentPath, record.StructuralExtent.Span.StartByte, record.StructuralExtent.Span.EndByte)
		if prior, duplicate := recordsByIdentity[key]; duplicate {
			prior.ProductionReachable = prior.ProductionReachable || record.ProductionReachable
			prior.TestReachable = prior.TestReachable || record.TestReachable
			recordsByIdentity[key] = prior
		} else {
			recordsByIdentity[key] = record
		}
	}
	records := make([]h00CallableLivenessRecord, 0, len(recordsByIdentity))
	for _, record := range recordsByIdentity {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		left, right := records[i], records[j]
		if left.StructuralExtent.DocumentPath != right.StructuralExtent.DocumentPath {
			return left.StructuralExtent.DocumentPath < right.StructuralExtent.DocumentPath
		}
		if left.StructuralExtent.Span.StartByte != right.StructuralExtent.Span.StartByte {
			return left.StructuralExtent.Span.StartByte < right.StructuralExtent.Span.StartByte
		}
		return left.Name < right.Name
	})
	documents := make([]h00CallableLivenessDocument, 0, len(expectedSourceSHA256s))
	for uri, contentSHA256 := range expectedSourceSHA256s {
		documentPath, err := h00RepositoryDocumentPath(moduleRoot, repositoryPrefix, uri.Path())
		if err != nil {
			return nil, err
		}
		selection, ok := workspace.witness.DocumentSelections[uri.Path()]
		if !ok {
			return nil, fmt.Errorf("callable liveness workspace omitted source identity %s", uri)
		}
		document := h00CallableLivenessDocument{DocumentPath: documentPath, ContentSHA256: contentSHA256}
		if strings.HasPrefix(selection, "package:") {
			document.Included = true
		} else if strings.HasPrefix(selection, "omitted:") {
			document.OmissionReason = strings.TrimPrefix(selection, "omitted:")
		} else {
			return nil, fmt.Errorf("callable liveness workspace has unknown source selection %q", selection)
		}
		documents = append(documents, document)
	}
	sort.Slice(documents, func(i, j int) bool { return documents[i].DocumentPath < documents[j].DocumentPath })
	artifact := h00CallableLivenessArtifact{
		SchemaVersion:   "h00/semantic-provider/callable-liveness/v1",
		ConfigurationID: "go-rta-v1/production=main+public-api/tests=go-test-roots",
		Language:        "go",
		Documents:       documents,
		Callables:       records,
	}
	encoded, err := json.Marshal(artifact)
	if err != nil || len(encoded) == 0 {
		return nil, fmt.Errorf("serialize canonical Go callable liveness: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("complete Go callable liveness: %w", err)
	}
	return encoded, nil
}

// h00UnifiedFileSet joins the exact token files that back the current typed
// package population. gopls may reuse an unchanged package while rechecking a
// changed dependent package; those packages can then expose distinct FileSet
// containers even though every syntax tree belongs to the same admitted
// snapshot. SSA needs one FileSet that maps all of their positions, not
// pointer identity between the containers.
func h00UnifiedFileSet(initial []*packages.Package) (*token.FileSet, error) {
	filesByBase := make(map[int]*token.File)
	for _, loaded := range initial {
		if loaded == nil || loaded.Fset == nil {
			return nil, fmt.Errorf("callable liveness package has no admitted gopls file set")
		}
		for file := range loaded.Fset.Iterate {
			prior := filesByBase[file.Base()]
			if prior == nil {
				filesByBase[file.Base()] = file
				continue
			}
			if prior.Name() != file.Name() || prior.Size() != file.Size() ||
				!slices.Equal(prior.Lines(), file.Lines()) {
				return nil, fmt.Errorf(
					"callable liveness has conflicting gopls token files at base %d",
					file.Base(),
				)
			}
		}
	}
	files := make([]*token.File, 0, len(filesByBase))
	for _, file := range filesByBase {
		files = append(files, file)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Base() < files[j].Base() })
	for index := 1; index < len(files); index++ {
		prior := files[index-1]
		current := files[index]
		if prior.Base()+prior.Size() >= current.Base() {
			return nil, fmt.Errorf(
				"callable liveness has overlapping gopls token files %q and %q",
				prior.Name(), current.Name(),
			)
		}
	}
	fileSet := tokeninternal.FileSetFor(files...)
	for _, loaded := range initial {
		for _, syntax := range loaded.Syntax {
			if syntax == nil || fileSet.File(syntax.Pos()) == nil {
				return nil, fmt.Errorf(
					"callable liveness package %s has syntax outside the unified gopls file set",
					loaded.ID,
				)
			}
		}
	}
	return fileSet, nil
}

func h00RepositoryDocumentPath(moduleRoot, repositoryPrefix, filename string) (string, error) {
	relative, err := filepath.Rel(moduleRoot, filename)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("callable liveness source escapes execution root: %s", filename)
	}
	relative = filepath.ToSlash(relative)
	if repositoryPrefix != "" {
		relative = strings.TrimSuffix(repositoryPrefix, "/") + "/" + relative
	}
	return relative, nil
}

func h00BuildCallableLivenessLocation(fset *token.FileSet, documentPath string, start, end token.Pos) (h00CallableLivenessLocation, error) {
	file := fset.File(start)
	if file == nil || fset.File(end) != file || start > end {
		return h00CallableLivenessLocation{}, fmt.Errorf("callable liveness declaration has an invalid source span")
	}
	startPosition := fset.PositionFor(start, false)
	endPosition := fset.PositionFor(end, false)
	if startPosition.Line <= 0 || startPosition.Column <= 0 || endPosition.Line <= 0 || endPosition.Column <= 0 {
		return h00CallableLivenessLocation{}, fmt.Errorf("callable liveness declaration has an invalid source position")
	}
	return h00CallableLivenessLocation{
		DocumentPath: documentPath,
		Span: h00CallableLivenessSpan{
			StartByte: uint64(file.Offset(start)), EndByte: uint64(file.Offset(end)),
			StartLine: uint32(startPosition.Line - 1), StartUTF8ByteColumn: uint32(startPosition.Column - 1),
			EndLine: uint32(endPosition.Line - 1), EndUTF8ByteColumn: uint32(endPosition.Column - 1),
		},
	}, nil
}

func h00ExternallyRootedGoDeclaration(declaration *ast.FuncDecl) bool {
	if declaration.Doc == nil || declaration.Name == nil {
		return false
	}
	for _, comment := range declaration.Doc.List {
		text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
		if strings.HasPrefix(text, "go:linkname "+declaration.Name.Name) || text == "export "+declaration.Name.Name {
			return true
		}
	}
	return false
}

func h00GoTestRootName(name string) bool {
	return name == "TestMain" || strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Benchmark") || strings.HasPrefix(name, "Fuzz") || strings.HasPrefix(name, "Example")
}

func h00SortedFunctions(population map[*ssa.Function]struct{}) []*ssa.Function {
	functions := make([]*ssa.Function, 0, len(population))
	for function := range population {
		functions = append(functions, function)
	}
	sort.Slice(functions, func(i, j int) bool {
		left, right := functions[i], functions[j]
		if left.String() != right.String() {
			return left.String() < right.String()
		}
		return left.Pos() < right.Pos()
	})
	return functions
}

func h00ReachablePositions(fset *token.FileSet, result *rta.Result) map[h00CallablePosition]struct{} {
	positions := make(map[h00CallablePosition]struct{}, len(result.Reachable))
	for function := range result.Reachable {
		if !function.Pos().IsValid() {
			continue
		}
		position := fset.PositionFor(function.Pos(), false)
		positions[h00CallablePosition{Filename: filepath.Clean(position.Filename), Line: position.Line, Column: position.Column}] = struct{}{}
	}
	return positions
}

// H00InspectWorkspaceResolutionAndInputs binds project-input bytes and package
// resolution to one gopls snapshot lease. Callers still re-read the operating
// system manifest afterward; disagreement at either boundary discards the
// provider process rather than pretending gopls mutation can roll back.
func H00InspectWorkspaceResolutionAndInputs(
	ctx context.Context,
	semanticServer protocol.Server,
	requested []protocol.DocumentURI,
	expectedSourceSHA256s map[protocol.DocumentURI]string,
	semanticInputURIs map[string]protocol.DocumentURI,
) (H00WorkspaceWitness, map[string]H00SemanticPathWitness, error) {
	server, ok := semanticServer.(*server)
	if !ok {
		return H00WorkspaceWitness{}, nil, fmt.Errorf("workspace resolution requires the local gopls server")
	}
	if len(requested) == 0 || len(expectedSourceSHA256s) != len(requested) || len(semanticInputURIs) == 0 {
		return H00WorkspaceWitness{}, nil, fmt.Errorf("empty or mismatched workspace or semantic-input population")
	}
	snapshot, release, err := server.session.SnapshotOf(ctx, requested[0])
	if err != nil {
		return H00WorkspaceWitness{}, nil, fmt.Errorf("resolve gopls snapshot: %w", err)
	}
	defer release()
	snapshot.AwaitInitialized(ctx)
	if err := ctx.Err(); err != nil {
		return H00WorkspaceWitness{}, nil, fmt.Errorf("await gopls snapshot initialization: %w", err)
	}
	if err := h00VerifySnapshotSources(ctx, snapshot, expectedSourceSHA256s); err != nil {
		return H00WorkspaceWitness{}, nil, err
	}
	before, err := h00ObserveSemanticInputs(ctx, snapshot, semanticInputURIs)
	if err != nil {
		return H00WorkspaceWitness{}, nil, err
	}
	observed, err := h00ObserveWorkspace(ctx, snapshot, requested)
	if err != nil {
		return H00WorkspaceWitness{}, nil, err
	}
	after, err := h00ObserveSemanticInputs(ctx, snapshot, semanticInputURIs)
	if err != nil {
		return H00WorkspaceWitness{}, nil, err
	}
	if !maps.Equal(before, after) {
		return H00WorkspaceWitness{}, nil, fmt.Errorf("gopls semantic-input snapshot changed during workspace observation")
	}
	if err := h00VerifySnapshotSources(ctx, snapshot, expectedSourceSHA256s); err != nil {
		return H00WorkspaceWitness{}, nil, err
	}
	return observed.witness, after, nil
}

// h00VerifySnapshotSources joins every h00ligan-admitted source identity to the
// exact immutable file handle owned by the gopls snapshot that performs
// workspace resolution and type checking. File identities are already
// SHA-256 content digests inside gopls, so this neither re-reads ambient disk
// nor creates one editor overlay per unchanged source.
func h00VerifySnapshotSources(
	ctx context.Context,
	snapshot *cache.Snapshot,
	expectedSourceSHA256s map[protocol.DocumentURI]string,
) error {
	if len(expectedSourceSHA256s) == 0 {
		return fmt.Errorf("empty expected Go source snapshot")
	}
	requested := make([]protocol.DocumentURI, 0, len(expectedSourceSHA256s))
	for uri := range expectedSourceSHA256s {
		requested = append(requested, uri)
	}
	sort.Slice(requested, func(i, j int) bool { return requested[i] < requested[j] })
	for _, uri := range requested {
		expectedSHA256 := expectedSourceSHA256s[uri]
		if len(expectedSHA256) != sha256.Size*2 {
			return fmt.Errorf("invalid expected Go source identity for %s", uri)
		}
		fh, err := snapshot.ReadFile(ctx, uri)
		if err != nil {
			return fmt.Errorf("read gopls source snapshot %s: %w", uri, err)
		}
		if _, err := fh.Content(); err != nil {
			return fmt.Errorf("read gopls source contents %s: %w", uri, err)
		}
		observedSHA256 := fh.Identity().Hash.String()
		if fh.URI() != uri || observedSHA256 != expectedSHA256 {
			return fmt.Errorf(
				"gopls source snapshot differs from admitted bytes for %s: admitted=%s observed=%s",
				uri, expectedSHA256, observedSHA256,
			)
		}
	}
	return nil
}

func h00ObserveSemanticInputs(
	ctx context.Context,
	snapshot *cache.Snapshot,
	semanticInputURIs map[string]protocol.DocumentURI,
) (map[string]H00SemanticPathWitness, error) {
	paths := make([]string, 0, len(semanticInputURIs))
	for path := range semanticInputURIs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	observed := make(map[string]H00SemanticPathWitness, len(paths))
	for _, path := range paths {
		uri := semanticInputURIs[path]
		fh, err := snapshot.ReadFile(ctx, uri)
		if err != nil {
			return nil, fmt.Errorf("read gopls semantic input %s: %w", path, err)
		}
		contents, err := fh.Content()
		hasher := sha256.New()
		h00ServerHashField(hasher, []byte("h00/semantic-provider/semantic-path/v3\x00"))
		h00ServerHashField(hasher, []byte("repository"))
		h00ServerHashField(hasher, nil)
		h00ServerHashField(hasher, nil)
		if errors.Is(err, fs.ErrNotExist) {
			h00ServerHashField(hasher, []byte("missing"))
			observed[path] = H00SemanticPathWitness{
				Kind: "missing", IdentitySHA256: hex.EncodeToString(hasher.Sum(nil)),
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read gopls semantic input contents %s: %w", path, err)
		}
		if !fh.SameContentsOnDisk() {
			return nil, fmt.Errorf("gopls semantic input is not an exact on-disk file: %s", path)
		}
		h00ServerHashField(hasher, []byte("file"))
		contentSHA := sha256.Sum256(contents)
		h00ServerHashField(hasher, contentSHA[:])
		observed[path] = H00SemanticPathWitness{
			Kind: "file", IdentitySHA256: hex.EncodeToString(hasher.Sum(nil)),
			EntryCount: 1, ByteLength: uint64(len(contents)),
		}
	}
	return observed, nil
}

func h00ObserveWorkspace(
	ctx context.Context,
	snapshot *cache.Snapshot,
	requested []protocol.DocumentURI,
) (h00WorkspaceObservation, error) {
	if len(requested) == 0 {
		return h00WorkspaceObservation{}, fmt.Errorf("empty workspace-resolution source population")
	}
	uris := append([]protocol.DocumentURI(nil), requested...)
	sort.Slice(uris, func(i, j int) bool { return uris[i] < uris[j] })
	for index, uri := range uris {
		if index > 0 && uri == uris[index-1] {
			return h00WorkspaceObservation{}, fmt.Errorf("duplicate workspace-resolution source %s", uri)
		}
	}

	// MetadataForFile is deliberately lazy: resolving a later source may replace
	// an earlier source's temporary command-line-arguments association with its
	// real selected package. Drive the exact requested population to a fixed
	// point, and grant no authority until two consecutive readbacks agree. This
	// is bounded semantic convergence, not a timing retry or an ambient cache
	// census.
	selected, documentSelections, err := h00SelectDocuments(ctx, snapshot, uris)
	if err != nil {
		return h00WorkspaceObservation{}, err
	}
	var graph *metadata.Graph
	if _, err := snapshot.LoadMetadataGraph(ctx); err != nil {
		return h00WorkspaceObservation{}, fmt.Errorf("load gopls metadata graph: %w", err)
	}
	const maxConvergencePasses = 4
	converged := false
	for pass := 0; pass < maxConvergencePasses; pass++ {
		nextSelected, nextSelections, err := h00SelectDocuments(ctx, snapshot, uris)
		if err != nil {
			return h00WorkspaceObservation{}, err
		}
		nextGraph, err := snapshot.LoadMetadataGraph(ctx)
		if err != nil {
			return h00WorkspaceObservation{}, fmt.Errorf("load gopls metadata graph: %w", err)
		}
		if maps.Equal(documentSelections, nextSelections) {
			selected = nextSelected
			documentSelections = nextSelections
			graph = nextGraph
			converged = true
			break
		}
		selected = nextSelected
		documentSelections = nextSelections
	}
	if !converged {
		return h00WorkspaceObservation{}, fmt.Errorf(
			"requested Go document population did not reach a stable package selection after %d passes",
			maxConvergencePasses+1,
		)
	}

	rootIDs := make([]cache.PackageID, 0, len(selected))
	rootSet := make(map[cache.PackageID]struct{}, len(selected))
	for _, id := range selected {
		if _, seen := rootSet[id]; !seen {
			rootSet[id] = struct{}{}
			rootIDs = append(rootIDs, id)
		}
	}
	sort.Slice(rootIDs, func(i, j int) bool { return rootIDs[i] < rootIDs[j] })
	packageByID := make(map[cache.PackageID]*metadata.Package)
	rootClosurePackageIDs := make(map[string][]string, len(rootIDs))
	for _, rootID := range rootIDs {
		closure := make([]string, 0)
		for pkg := range graph.ForwardReflexiveTransitiveClosure(rootID) {
			packageByID[pkg.ID] = pkg
			closure = append(closure, string(pkg.ID))
		}
		sort.Strings(closure)
		rootClosurePackageIDs[string(rootID)] = closure
	}
	packages := make([]*metadata.Package, 0, len(packageByID))
	for _, pkg := range packageByID {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].ID < packages[j].ID })
	packageSHA256s := make(map[string]string, len(packages))
	for _, pkg := range packages {
		packageHasher := sha256.New()
		h00ServerHashField(packageHasher, []byte("h00/go-provider/workspace-package/v1\x00"))
		h00HashWorkspacePackage(packageHasher, pkg)
		packageSHA256s[string(pkg.ID)] = hex.EncodeToString(packageHasher.Sum(nil))
	}
	witness := H00WorkspaceWitness{
		PackageSHA256s:        packageSHA256s,
		DocumentSelections:    documentSelections,
		RootClosurePackageIDs: rootClosurePackageIDs,
	}
	witness.SHA256, err = h00WorkspaceWitnessSHA256(witness)
	if err != nil {
		return h00WorkspaceObservation{}, err
	}
	return h00WorkspaceObservation{
		witness:  witness,
		selected: selected,
	}, nil
}

func h00ProjectWorkspaceWitness(
	admitted H00WorkspaceWitness,
	requested []protocol.DocumentURI,
) (H00WorkspaceWitness, error) {
	projected := H00WorkspaceWitness{
		PackageSHA256s:        make(map[string]string),
		DocumentSelections:    make(map[string]string, len(requested)),
		RootClosurePackageIDs: make(map[string][]string),
	}
	for _, uri := range requested {
		path := uri.Path()
		selection, ok := admitted.DocumentSelections[path]
		if !ok {
			return H00WorkspaceWitness{}, fmt.Errorf("requested document was not admitted: %s", path)
		}
		if _, duplicate := projected.DocumentSelections[path]; duplicate {
			return H00WorkspaceWitness{}, fmt.Errorf("duplicate projected document: %s", path)
		}
		projected.DocumentSelections[path] = selection
		const packagePrefix = "package:"
		if !strings.HasPrefix(selection, packagePrefix) {
			continue
		}
		rootID := strings.TrimPrefix(selection, packagePrefix)
		closure, ok := admitted.RootClosurePackageIDs[rootID]
		if !ok {
			return H00WorkspaceWitness{}, fmt.Errorf("admitted package root has no closure: %s", rootID)
		}
		projected.RootClosurePackageIDs[rootID] = append([]string(nil), closure...)
		for _, packageID := range closure {
			digest, ok := admitted.PackageSHA256s[packageID]
			if !ok {
				return H00WorkspaceWitness{}, fmt.Errorf(
					"admitted root %s references unknown package %s", rootID, packageID,
				)
			}
			projected.PackageSHA256s[packageID] = digest
		}
	}
	var err error
	projected.SHA256, err = h00WorkspaceWitnessSHA256(projected)
	if err != nil {
		return H00WorkspaceWitness{}, err
	}
	return projected, nil
}

func h00WorkspaceWitnessSHA256(witness H00WorkspaceWitness) (string, error) {
	hasher := sha256.New()
	h00ServerHashField(hasher, []byte("h00/go-provider/workspace-resolution/v3\x00"))
	documentPaths := make([]string, 0, len(witness.DocumentSelections))
	for path := range witness.DocumentSelections {
		documentPaths = append(documentPaths, path)
	}
	sort.Strings(documentPaths)
	for _, path := range documentPaths {
		h00ServerHashField(hasher, []byte(path))
		h00ServerHashField(hasher, []byte(witness.DocumentSelections[path]))
	}
	packageIDs := make([]string, 0, len(witness.PackageSHA256s))
	for packageID := range witness.PackageSHA256s {
		packageIDs = append(packageIDs, packageID)
	}
	sort.Strings(packageIDs)
	for _, packageID := range packageIDs {
		digest := witness.PackageSHA256s[packageID]
		if len(digest) != sha256.Size*2 {
			return "", fmt.Errorf("invalid admitted package digest for %s", packageID)
		}
		h00ServerHashField(hasher, []byte(packageID))
		h00ServerHashField(hasher, []byte(digest))
	}
	rootIDs := make([]string, 0, len(witness.RootClosurePackageIDs))
	for rootID := range witness.RootClosurePackageIDs {
		rootIDs = append(rootIDs, rootID)
	}
	sort.Strings(rootIDs)
	for _, rootID := range rootIDs {
		h00ServerHashField(hasher, []byte(rootID))
		for _, packageID := range witness.RootClosurePackageIDs[rootID] {
			if _, ok := witness.PackageSHA256s[packageID]; !ok {
				return "", fmt.Errorf("package root %s references unknown package %s", rootID, packageID)
			}
			h00ServerHashField(hasher, []byte(packageID))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func h00SelectDocuments(
	ctx context.Context,
	snapshot *cache.Snapshot,
	uris []protocol.DocumentURI,
) (map[protocol.DocumentURI]cache.PackageID, map[string]string, error) {
	selected := make(map[protocol.DocumentURI]cache.PackageID, len(uris))
	documentSelections := make(map[string]string, len(uris))
	for _, uri := range uris {
		packageName, err := h00DocumentPackageName(ctx, snapshot, uri)
		if err != nil {
			return nil, nil, err
		}
		key := uri.Path()
		if packageName == "" {
			documentSelections[key] = "omitted:invalid-package-clause"
			continue
		}
		metas, err := snapshot.MetadataForFile(ctx, uri, true)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve package metadata for %s: %w", uri, err)
		}
		if len(metas) == 0 {
			documentSelections[key] = "omitted:no-metadata"
			continue
		}

		outsideSelectedBuild := true
		matchedPackageNameWithoutModule := false
		var chosen *metadata.Package
		for _, meta := range metas {
			if meta.Standalone || metadata.IsCommandLineArguments(meta.ID) {
				continue
			}
			outsideSelectedBuild = false
			if string(meta.Name) != packageName {
				continue
			}
			if !h00MetadataContainsURI(meta, uri) {
				return nil, nil, fmt.Errorf(
					"gopls returned package %s for %s without owning that document",
					meta.ID, uri,
				)
			}
			if meta.Module == nil {
				matchedPackageNameWithoutModule = true
				continue
			}
			chosen = meta
			break
		}
		switch {
		case chosen != nil:
			selected[uri] = chosen.ID
			documentSelections[key] = "package:" + string(chosen.ID)
		case outsideSelectedBuild:
			documentSelections[key] = "omitted:outside-selected-build"
		case matchedPackageNameWithoutModule:
			return nil, nil, fmt.Errorf(
				"Go document %s matched package %s without module authority; candidates=%s",
				uri, packageName, h00BoundedMetadataCandidates(metas),
			)
		default:
			return nil, nil, fmt.Errorf(
				"Go document %s declares package %s but gopls returned no matching package metadata; candidates=%s",
				uri, packageName, h00BoundedMetadataCandidates(metas),
			)
		}
	}
	return selected, documentSelections, nil
}

func h00DocumentPackageName(
	ctx context.Context,
	snapshot *cache.Snapshot,
	uri protocol.DocumentURI,
) (string, error) {
	fh, err := snapshot.ReadFile(ctx, uri)
	if err != nil {
		return "", fmt.Errorf("read Go package clause %s: %w", uri, err)
	}
	contents, err := fh.Content()
	if err != nil {
		return "", fmt.Errorf("read Go package-clause contents %s: %w", uri, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), uri.Path(), contents, parser.PackageClauseOnly)
	if err != nil || file == nil || file.Name == nil {
		return "", nil
	}
	return file.Name.Name, nil
}

func h00MetadataContainsURI(meta *metadata.Package, uri protocol.DocumentURI) bool {
	for _, candidate := range meta.CompiledGoFiles {
		if candidate == uri {
			return true
		}
	}
	for _, candidate := range meta.GoFiles {
		if candidate == uri {
			return true
		}
	}
	return false
}

func h00BoundedMetadataCandidates(metas []*metadata.Package) string {
	const limit = 4
	values := make([]string, 0, min(len(metas), limit))
	for _, meta := range metas[:min(len(metas), limit)] {
		module := "missing-module"
		if meta.Module != nil {
			module = "module:" + meta.Module.Path
		}
		values = append(values, fmt.Sprintf("%s(name=%s,%s)", meta.ID, meta.Name, module))
	}
	if len(metas) > limit {
		return fmt.Sprintf("%q+%d-more", values, len(metas)-limit)
	}
	return fmt.Sprintf("%q", values)
}

func h00HashWorkspacePackage(hasher io.Writer, pkg *metadata.Package) {
	for _, value := range []string{
		string(pkg.ID), string(pkg.PkgPath), string(pkg.Name), string(pkg.ForTest),
	} {
		h00ServerHashField(hasher, []byte(value))
	}
	if pkg.Module == nil {
		h00ServerHashField(hasher, []byte("no-module"))
	} else {
		module := pkg.Module
		for _, value := range []string{module.Path, module.Version, module.GoVersion} {
			h00ServerHashField(hasher, []byte(value))
		}
		if module.Replace == nil {
			h00ServerHashField(hasher, []byte("no-replacement"))
		} else {
			for _, value := range []string{
				module.Replace.Path, module.Replace.Version, module.Replace.GoVersion,
			} {
				h00ServerHashField(hasher, []byte(value))
			}
		}
	}
	dependencyPaths := make([]string, 0, len(pkg.DepsByImpPath))
	for path := range pkg.DepsByImpPath {
		dependencyPaths = append(dependencyPaths, string(path))
	}
	sort.Strings(dependencyPaths)
	for _, path := range dependencyPaths {
		h00ServerHashField(hasher, []byte(path))
		h00ServerHashField(hasher, []byte(pkg.DepsByImpPath[metadata.ImportPath(path)]))
	}
}

func h00WorkspaceResolutionDifference(expected, observed H00WorkspaceWitness) string {
	return fmt.Sprintf(
		"packages(%s) documents(%s) roots(%s)",
		h00StringMapDifference(expected.PackageSHA256s, observed.PackageSHA256s),
		h00StringMapDifference(expected.DocumentSelections, observed.DocumentSelections),
		h00RootClosureDifference(expected.RootClosurePackageIDs, observed.RootClosurePackageIDs),
	)
}

func h00RootClosureDifference(expected, observed map[string][]string) string {
	expectedDigests := make(map[string]string, len(expected))
	for rootID, packageIDs := range expected {
		expectedDigests[rootID] = strings.Join(packageIDs, "\x00")
	}
	observedDigests := make(map[string]string, len(observed))
	for rootID, packageIDs := range observed {
		observedDigests[rootID] = strings.Join(packageIDs, "\x00")
	}
	return h00StringMapDifference(expectedDigests, observedDigests)
}

func h00StringMapDifference(expected, observed map[string]string) string {
	added := make([]string, 0)
	removed := make([]string, 0)
	changed := make([]string, 0)
	for id, digest := range observed {
		expectedDigest, ok := expected[id]
		if !ok {
			added = append(added, id)
		} else if expectedDigest != digest {
			changed = append(changed, id)
		}
	}
	for id := range expected {
		if _, ok := observed[id]; !ok {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return fmt.Sprintf(
		"admitted=%d observed=%d added=%s removed=%s changed=%s",
		len(expected), len(observed), h00BoundedPackageIDs(added),
		h00BoundedPackageIDs(removed), h00BoundedPackageIDs(changed),
	)
}

func h00BoundedPackageIDs(ids []string) string {
	const limit = 4
	if len(ids) <= limit {
		return fmt.Sprintf("%q", ids)
	}
	return fmt.Sprintf("%q+%d-more", ids[:limit], len(ids)-limit)
}

func h00LoadedPackage(
	snapshot *cache.Snapshot,
	pkg *cache.Package,
	goStdlibVersion string,
) (*packages.Package, []*packages.Package, error) {
	meta := pkg.Metadata()
	projectModule := h00CloneModule(meta.Module)
	if projectModule == nil {
		return nil, nil, fmt.Errorf("project package %s has no module authority", meta.ID)
	}
	loaded := &packages.Package{
		ID:              string(meta.ID),
		Name:            string(meta.Name),
		PkgPath:         string(meta.PkgPath),
		Fset:            pkg.FileSet(),
		Syntax:          pkg.Syntax(),
		Types:           pkg.Types(),
		TypesInfo:       pkg.TypesInfo(),
		TypesSizes:      pkg.TypesSizes(),
		Module:          projectModule,
		Imports:         make(map[string]*packages.Package),
		CompiledGoFiles: make([]string, 0, len(pkg.CompiledGoFiles())),
	}
	for _, file := range pkg.CompiledGoFiles() {
		loaded.CompiledGoFiles = append(loaded.CompiledGoFiles, file.URI.Path())
	}

	dependenciesByPath := make(map[string]*packages.Package)
	for packagePath, dependencyID := range meta.DepsByPkgPath {
		dependencyMeta := snapshot.Metadata(dependencyID)
		if dependencyMeta == nil {
			return nil, nil, fmt.Errorf("package %s is missing dependency metadata for %s", meta.ID, dependencyID)
		}
		dependencyTypes := pkg.DependencyTypes(packagePath)
		if dependencyTypes == nil {
			continue
		}
		dependencyModule := h00CloneModule(dependencyMeta.Module)
		if dependencyModule == nil {
			if goStdlibVersion == "" {
				return nil, nil, fmt.Errorf("standard-library package %s has no Go version authority", dependencyMeta.ID)
			}
			dependencyModule = &packages.Module{
				Path:    "github.com/golang/go/src",
				Version: goStdlibVersion,
			}
		}
		dependenciesByPath[string(packagePath)] = &packages.Package{
			ID: string(dependencyMeta.ID), Name: string(dependencyMeta.Name),
			PkgPath: string(dependencyMeta.PkgPath), Types: dependencyTypes,
			Module: dependencyModule, Imports: make(map[string]*packages.Package),
		}
	}
	for importPath, dependencyID := range meta.DepsByImpPath {
		// gopls explicitly uses an empty package ID for an import that did not
		// resolve. There is no dependency package we can truthfully adapt in
		// that case. Leave the import absent so scip-go omits its references;
		// h00ligan's source/provider coverage check will then qualify any affected
		// repository-local call syntax instead of losing all Go authority.
		if dependencyID == "" {
			continue
		}
		dependencyMeta := snapshot.Metadata(dependencyID)
		if dependencyMeta == nil {
			return nil, nil, fmt.Errorf(
				"package %s import %s references missing metadata for %s",
				meta.ID, importPath, dependencyID,
			)
		}
		if dependency := dependenciesByPath[string(dependencyMeta.PkgPath)]; dependency != nil {
			loaded.Imports[string(importPath)] = dependency
		}
	}
	paths := make([]string, 0, len(dependenciesByPath))
	for packagePath := range dependenciesByPath {
		paths = append(paths, packagePath)
	}
	sort.Strings(paths)
	dependencies := make([]*packages.Package, 0, len(paths))
	for _, packagePath := range paths {
		dependencies = append(dependencies, dependenciesByPath[packagePath])
	}
	return loaded, dependencies, nil
}

func h00CloneModule(module *packages.Module) *packages.Module {
	if module == nil {
		return nil
	}
	clone := *module
	if module.Replace != nil {
		replacement := *module.Replace
		clone.Replace = &replacement
	}
	return &clone
}

func h00ServerHashField(writer io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

var _ metadata.Source = (*cache.Snapshot)(nil)
