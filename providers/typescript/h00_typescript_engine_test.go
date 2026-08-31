package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/microsoft/typescript-go/internal/lsp/lsproto"
	"github.com/microsoft/typescript-go/internal/vfs/osvfs"
	"github.com/scip-code/scip/bindings/go/scip"
	"google.golang.org/protobuf/proto"
)

// The compiler is allowed to probe Node-style ancestor paths, but those paths
// must be mechanically invisible to a portable repository-scoped session.
func TestRepositoryFilesystemHidesAmbientAndSymlinkedInputs(t *testing.T) {
	t.Parallel()
	scratch := t.TempDir()
	root := filepath.Join(scratch, "repo")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("create repository root: %v", err)
	}
	writeTypeScriptFixture(t, root, "inside.txt", "inside\n")
	outside := filepath.Join(scratch, "package.json")
	if err := os.WriteFile(outside, []byte("ambient\n"), 0o644); err != nil {
		t.Fatalf("write ambient fixture: %v", err)
	}
	filesystem := &h00RepositoryFS{
		inner: osvfs.FS(), repositoryRoot: root, currentDirectory: root,
	}
	if contents, ok := filesystem.ReadFile("inside.txt"); !ok || contents != "inside\n" {
		t.Fatalf("positive control: repository file was not readable: %q, %t", contents, ok)
	}
	if filesystem.FileExists(outside) {
		t.Fatal("an ambient ancestor input crossed the repository filesystem boundary")
	}
	link := filepath.Join(root, "linked-package.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink control is unavailable: %v", err)
	}
	if filesystem.FileExists(link) {
		t.Fatal("a repository-local symlink imported ambient filesystem authority")
	}
}

// RIGHT-REASON REGRESSION: native module resolution may probe thousands of
// missing candidates beneath the same directory. Persisting every absent name
// exhausts the wire bound without adding authority: one shallow listing of the
// nearest existing directory detects every possible candidate transition.
func TestCompilerTraceCoalescesMissingCandidatesAtMembershipOwner(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@fixture/trace"}`)
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatalf("create trace directory: %v", err)
	}
	engine := &h00TypeScriptEngine{
		repositoryRoot: root,
		executionRoot:  root,
		sources:        map[string]h00SourceIdentity{},
	}
	semanticPaths := map[string]struct{}{}
	for index := range h00MaxDocumentPaths + 257 {
		candidate := filepath.Join(root, "node_modules", fmt.Sprintf("missing-%05d", index), "package.json")
		if err := engine.observeTrackedTypeScriptPath(candidate, semanticPaths); err != nil {
			t.Fatalf("normalize missing compiler candidate %d: %v", index, err)
		}
	}
	if err := engine.observeTrackedTypeScriptPath(filepath.Join(root, "package.json"), semanticPaths); err != nil {
		t.Fatalf("normalize existing compiler input: %v", err)
	}
	if !reflect.DeepEqual(semanticPaths, map[string]struct{}{
		"node_modules": {},
		"package.json": {},
	}) {
		t.Fatalf("redundant compiler candidates were not coalesced: population=%d", len(semanticPaths))
	}
}

// RIGHT-REASON REGRESSION: the TypeScript provider must derive cross-file
// identity from the native compiler graph. Text matching cannot distinguish a
// local Unicode declaration from the same spelling in an external library,
// and UTF-16 columns would corrupt the byte-based h00ligan materialization seam.
func TestNativeCompilerExportsCanonicalCrossFileSymbols(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@h00/fixture","version":"1.0.0","type":"module"}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true
  },
  "include": ["src/**/*.ts"]
}`)
	definitions := "export function café(value: number): number { return value + 1 }\n"
	usage := "import { café } from \"./definitions.js\";\nexport const result = café(Math.max(1, 2));\n"
	writeTypeScriptFixture(t, root, "src/definitions.ts", definitions)
	writeTypeScriptFixture(t, root, "src/usage.ts", usage)

	sources := map[string]h00SourceIdentity{
		"src/definitions.ts": testTypeScriptSource("src/definitions.ts", definitions),
		"src/usage.ts":       testTypeScriptSource("src/usage.ts", usage),
	}
	engine, err := h00StartTypeScriptEngine(ctx, root, root, "", sources)
	if err != nil {
		t.Fatalf("start native TypeScript compiler: %v", err)
	}
	t.Cleanup(engine.close)

	documents, err := engine.exportDocuments(ctx, []string{"src/usage.ts", "src/definitions.ts"})
	if err != nil {
		t.Fatalf("export native TypeScript SCIP documents: %v", err)
	}
	if len(documents) != 2 {
		t.Fatalf("expected two exact documents, got %d", len(documents))
	}
	sort.Slice(documents, func(i, j int) bool { return documents[i].RelativePath < documents[j].RelativePath })
	definitionsDocument := documents[0]
	usageDocument := documents[1]
	if definitionsDocument.RelativePath != "src/definitions.ts" || usageDocument.RelativePath != "src/usage.ts" {
		t.Fatalf("unexpected document population: %q, %q", definitionsDocument.RelativePath, usageDocument.RelativePath)
	}
	for _, document := range documents {
		if document.Language != "typescript" {
			t.Fatalf("unexpected document language %q", document.Language)
		}
		if document.PositionEncoding != scip.PositionEncoding_UTF8CodeUnitOffsetFromLineStart {
			t.Fatalf("document %q did not declare UTF-8 byte columns", document.RelativePath)
		}
	}

	definition := uniqueOccurrence(t, definitionsDocument, definitions, "café", true)
	references := matchingOccurrences(usageDocument, usage, "café", false)
	if len(references) != 2 {
		t.Fatalf("expected import and call references for café, got %d", len(references))
	}
	for _, reference := range references {
		if definition.Symbol == "" || definition.Symbol != reference.Symbol {
			t.Fatalf("cross-file symbol identity differs: definition=%q reference=%q", definition.Symbol, reference.Symbol)
		}
	}
	if !documentDefines(definitionsDocument, definition.Symbol) {
		t.Fatalf("definition symbol %q is absent from Document.symbols", definition.Symbol)
	}
	if documentDefines(usageDocument, references[0].Symbol) {
		t.Fatalf("reference-only document falsely claims local definition authority for %q", references[0].Symbol)
	}

	maxReference := uniqueOccurrence(t, usageDocument, usage, "max", false)
	if maxReference.Symbol == "" || maxReference.Symbol == definition.Symbol {
		t.Fatalf("external library reference has invalid identity %q", maxReference.Symbol)
	}
	for _, document := range documents {
		if documentDefines(document, maxReference.Symbol) {
			t.Fatalf("external library symbol %q entered repository definition authority", maxReference.Symbol)
		}
	}

	first := canonicalTypeScriptDocument(t, definitionsDocument)
	second := canonicalTypeScriptDocument(t, definitionsDocument)
	if string(first) != string(second) {
		t.Fatal("deterministic SCIP serialization changed without an input change")
	}

	workspace, semanticInputs, health, err := engine.authorityEvidence(ctx)
	if err != nil {
		t.Fatalf("observe TypeScript authority: %v", err)
	}
	if !health.DiagnosticsComplete || len(health.DegradationReasons) != 0 {
		t.Fatalf("fully resolved fixture was degraded: %+v", health)
	}
	semanticByPath := make(map[string]h00SemanticPathInput, len(semanticInputs.Paths))
	for _, input := range semanticInputs.Paths {
		semanticByPath[input.Path] = input
	}
	for _, path := range []string{"package.json", "tsconfig.json", "package-lock.json", "pnpm-lock.yaml"} {
		if _, ok := semanticByPath[path]; !ok {
			t.Fatalf("provider-observed semantic input is missing %q", path)
		}
	}
	writeTypeScriptFixture(t, root, "src/usage.ts", usage+"// unsent disk edit\n")
	workspaceAfterSourceEdit, inputsAfterSourceEdit, _, err := engine.authorityEvidence(ctx)
	if err != nil {
		t.Fatalf("re-observe authority after source-only disk edit: %v", err)
	}
	if workspaceAfterSourceEdit != workspace || !reflect.DeepEqual(inputsAfterSourceEdit, semanticInputs) {
		t.Fatal("source content leaked into project-input authority instead of the source population")
	}
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@h00/fixture","version":"2.0.0","type":"module"}`)
	_, inputsAfterPackageEdit, _, err := engine.authorityEvidence(ctx)
	if err != nil {
		t.Fatalf("re-observe authority after package edit: %v", err)
	}
	if reflect.DeepEqual(inputsAfterPackageEdit, semanticInputs) {
		t.Fatal("package.json drift did not invalidate provider-observed semantic inputs")
	}
}

// RIGHT-REASON REGRESSION: allowJs makes JavaScript and JSX first-class
// compiler inputs. Opening those documents as TypeScript/TypeScriptReact can
// change parser and checker semantics even when the filename remains correct,
// while omitting them from structural discovery makes the semantic provider
// unreachable for the same files.
func TestNativeCompilerUsesJavaScriptLanguageKindsAndExportsAllowJS(t *testing.T) {
	t.Parallel()
	for path, expected := range map[string]lsproto.LanguageKind{
		"src/plain.js":      lsproto.LanguageKindJavaScript,
		"src/component.jsx": lsproto.LanguageKindJavaScriptReact,
		"src/module.mjs":    lsproto.LanguageKindJavaScript,
		"src/common.cjs":    lsproto.LanguageKindJavaScript,
		"src/typed.ts":      lsproto.LanguageKindTypeScript,
		"src/view.tsx":      lsproto.LanguageKindTypeScriptReact,
		"src/module.mts":    lsproto.LanguageKindTypeScript,
		"src/common.cts":    lsproto.LanguageKindTypeScript,
	} {
		if actual := h00TypeScriptLanguageKind(path); actual != expected {
			t.Fatalf("language kind for %q: got %q, want %q", path, actual, expected)
		}
	}

	ctx := context.Background()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@fixture/allow-js","version":"1.0.0","type":"module"}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "allowJs": true,
    "checkJs": true,
    "jsx": "preserve"
  },
  "include": ["src/**/*.js", "src/**/*.jsx"]
}`)
	component := "/** @param {string} label */\nexport function Widget(label) { return <button>{label}</button>; }\n"
	usage := "import { Widget } from './component.jsx';\nexport function render() { return Widget('ok'); }\n"
	writeTypeScriptFixture(t, root, "src/component.jsx", component)
	writeTypeScriptFixture(t, root, "src/usage.js", usage)
	engine, err := h00StartTypeScriptEngine(ctx, root, root, "", map[string]h00SourceIdentity{
		"src/component.jsx": testTypeScriptSource("src/component.jsx", component),
		"src/usage.js":      testTypeScriptSource("src/usage.js", usage),
	})
	if err != nil {
		t.Fatalf("start allowJs compiler fixture: %v", err)
	}
	t.Cleanup(engine.close)
	documents, err := engine.exportDocuments(ctx, []string{"src/component.jsx", "src/usage.js"})
	if err != nil || len(documents) != 2 {
		t.Fatalf("export allowJs fixture: documents=%d error=%v", len(documents), err)
	}
	byPath := map[string]*scip.Document{}
	for _, document := range documents {
		byPath[document.RelativePath] = document
	}
	definition := uniqueOccurrence(t, byPath["src/component.jsx"], component, "Widget", true)
	references := matchingOccurrences(byPath["src/usage.js"], usage, "Widget", false)
	if len(references) != 2 {
		t.Fatalf("expected import and call references for Widget, got %d", len(references))
	}
	for _, reference := range references {
		if reference.Symbol != definition.Symbol {
			t.Fatalf("allowJs cross-file identity differs: %q != %q", reference.Symbol, definition.Symbol)
		}
	}
}

// RIGHT-REASON REGRESSION: native NodeNext resolution reads a dependency's
// package.json to select its declaration entrypoint. The selected .d.ts file
// is a useful positive control, but hashing only final Program source files
// misses the manifest that chose it and lets a warm session retain stale
// Complete authority after the package mapping changes.
func TestNativeCompilerAuthorityIncludesObservedPackageResolutionInputs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@h00/package-input-fixture","private":true,"type":"module"}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true
  },
  "include": ["src/**/*.ts"]
}`)
	dependencyManifest := `{"name":"fixture-dependency","version":"1.0.0","type":"module","types":"types-a.d.ts"}`
	writeTypeScriptFixture(t, root, "node_modules/fixture-dependency/package.json", dependencyManifest)
	writeTypeScriptFixture(t, root, "node_modules/fixture-dependency/types-a.d.ts", "export declare function dependency(): number;\n")
	writeTypeScriptFixture(t, root, "node_modules/fixture-dependency/types-b.d.ts", "export declare function dependency(): string;\n")
	source := "import { dependency } from 'fixture-dependency';\nexport function caller(): number { return dependency(); }\n"
	writeTypeScriptFixture(t, root, "src/index.ts", source)

	engine, err := h00StartTypeScriptEngine(ctx, root, root, "", map[string]h00SourceIdentity{
		"src/index.ts": testTypeScriptSource("src/index.ts", source),
	})
	if err != nil {
		t.Fatalf("start package-resolution fixture: %v", err)
	}
	t.Cleanup(engine.close)
	documents, err := engine.exportDocuments(ctx, []string{"src/index.ts"})
	if err != nil || len(documents) != 1 {
		t.Fatalf("export package-resolution fixture: documents=%d error=%v", len(documents), err)
	}
	foundVersionedDependency := false
	for _, occurrence := range documents[0].Occurrences {
		if strings.Contains(occurrence.Symbol, "npm fixture-dependency 1.0.0") {
			foundVersionedDependency = true
			break
		}
	}
	if !foundVersionedDependency {
		t.Fatal("resolved dependency symbols omitted the package.json version coordinate")
	}

	_, semanticInputs, health, err := engine.authorityEvidence(ctx)
	if err != nil {
		t.Fatalf("observe package-resolution authority: %v", err)
	}
	if !health.DiagnosticsComplete || len(health.DegradationReasons) != 0 {
		t.Fatalf("resolved package fixture was degraded: %+v", health)
	}
	semanticByPath := make(map[string]h00SemanticPathInput, len(semanticInputs.Paths))
	for _, input := range semanticInputs.Paths {
		semanticByPath[input.Path] = input
	}
	if input, ok := semanticByPath["node_modules/fixture-dependency/types-a.d.ts"]; !ok || input.Kind != "file" {
		t.Fatal("positive control: selected dependency declaration was not observed")
	}
	if input, ok := semanticByPath["node_modules/fixture-dependency/package.json"]; !ok || input.Kind != "file" {
		t.Fatal("package-resolution manifest was omitted from semantic authority")
	}
	for _, path := range []string{"node_modules", "node_modules/fixture-dependency"} {
		if input, ok := semanticByPath[path]; !ok || input.Kind != "directory_listing" {
			t.Fatalf("compiler-observed resolution directory was not captured shallowly: %q: %+v", path, input)
		}
	}

	writeTypeScriptFixture(
		t,
		root,
		"node_modules/fixture-dependency/package.json",
		`{"name":"fixture-dependency","version":"1.0.0","type":"module","types":"types-b.d.ts"}`,
	)
	_, changedInputs, _, err := engine.authorityEvidence(ctx)
	if err != nil {
		t.Fatalf("re-observe changed package-resolution authority: %v", err)
	}
	if reflect.DeepEqual(changedInputs, semanticInputs) {
		t.Fatal("dependency package.json drift did not invalidate provider-observed semantic inputs")
	}
}

// pnpm presents dependencies through repository-contained node_modules
// symlinks. Those links must remain usable by the bounded compiler while the
// semantic-input receipt binds their exact target and rejects stale warm
// authority after a remap.
func TestNativeCompilerSupportsRepositoryContainedPnpmPackageLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@h00/pnpm-fixture","private":true,"type":"module"}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true},"include":["src/**/*.ts"]}`)
	for _, store := range []string{"fixture-a", "fixture-b"} {
		writeTypeScriptFixture(t, root, ".pnpm/"+store+"/node_modules/fixture-dependency/package.json", `{"name":"fixture-dependency","version":"1.0.0","type":"module","types":"index.d.ts"}`)
		writeTypeScriptFixture(t, root, ".pnpm/"+store+"/node_modules/fixture-dependency/index.d.ts", "export declare function dependency(): number;\n")
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatalf("create node_modules: %v", err)
	}
	link := filepath.Join(root, "node_modules/fixture-dependency")
	if err := os.Symlink(filepath.FromSlash("../.pnpm/fixture-a/node_modules/fixture-dependency"), link); err != nil {
		t.Skipf("symlink control is unavailable: %v", err)
	}
	source := "import { dependency } from 'fixture-dependency';\nexport function caller(): number { return dependency(); }\n"
	writeTypeScriptFixture(t, root, "src/index.ts", source)
	engine, err := h00StartTypeScriptEngine(ctx, root, root, "", map[string]h00SourceIdentity{
		"src/index.ts": testTypeScriptSource("src/index.ts", source),
	})
	if err != nil {
		t.Fatalf("start pnpm package-link fixture: %v", err)
	}
	t.Cleanup(engine.close)
	documents, err := engine.exportDocuments(ctx, []string{"src/index.ts"})
	if err != nil || len(documents) != 1 {
		t.Fatalf("export pnpm package-link fixture: documents=%d error=%v", len(documents), err)
	}
	dependencies := matchingOccurrences(documents[0], source, "dependency", false)
	if len(dependencies) != 2 {
		t.Fatalf("expected import and call references for pnpm dependency, got %d", len(dependencies))
	}
	if !strings.Contains(dependencies[0].Symbol, "npm fixture-dependency 1.0.0") ||
		dependencies[1].Symbol != dependencies[0].Symbol {
		t.Fatalf("pnpm dependency has the wrong package identity: %q", dependencies[0].Symbol)
	}
	_, firstInputs, health, err := engine.authorityEvidence(ctx)
	if err != nil {
		t.Fatalf("observe pnpm semantic authority: %v", err)
	}
	if !health.DiagnosticsComplete || len(health.DegradationReasons) != 0 {
		t.Fatalf("resolved pnpm fixture was degraded: %+v", health)
	}
	byPath := make(map[string]h00SemanticPathInput, len(firstInputs.Paths))
	for _, input := range firstInputs.Paths {
		byPath[input.Path] = input
	}
	for _, path := range []string{"node_modules", "node_modules/fixture-dependency"} {
		if input, ok := byPath[path]; !ok || input.Kind != "directory_listing" {
			t.Fatalf("pnpm resolution directory lacks exact authority: %q: %+v", path, input)
		}
	}
	if input, ok := byPath["node_modules/fixture-dependency/package.json"]; !ok || input.Kind != "file" {
		t.Fatal("pnpm package manifest lacks exact authority")
	}

	if err := os.Remove(link); err != nil {
		t.Fatalf("remove test-owned pnpm link: %v", err)
	}
	if err := os.Symlink(filepath.FromSlash("../.pnpm/fixture-b/node_modules/fixture-dependency"), link); err != nil {
		t.Fatalf("remap test-owned pnpm link: %v", err)
	}
	_, remappedInputs, _, err := engine.authorityEvidence(ctx)
	if err != nil {
		t.Fatalf("re-observe remapped pnpm authority: %v", err)
	}
	if reflect.DeepEqual(remappedInputs, firstInputs) {
		t.Fatal("pnpm package-link remap retained stale semantic authority")
	}
}

// One workspace-level compiler session may own several npm packages. Symbol
// identity must follow each declaration's nearest bounded package manifest;
// assigning the workspace root coordinate to every source collapses distinct
// packages and makes cross-package references lie about their owner.
func TestNativeCompilerPreservesPerPackageIdentityInOneWorkspaceSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"private":true,"workspaces":["packages/*"]}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true
  },
  "include": ["packages/**/*.ts"]
}`)
	writeTypeScriptFixture(t, root, "packages/alpha/package.json", `{"name":"@fixture/alpha","version":"1.2.3","type":"module"}`)
	writeTypeScriptFixture(t, root, "packages/beta/package.json", `{"name":"@fixture/beta","version":"4.5.6","type":"module"}`)
	alpha := "export function alphaValue(): number { return 7; }\n"
	beta := "import { alphaValue } from '../../alpha/src/index.js';\nexport function betaCaller(): number { return alphaValue(); }\n"
	writeTypeScriptFixture(t, root, "packages/alpha/src/index.ts", alpha)
	writeTypeScriptFixture(t, root, "packages/beta/src/index.ts", beta)

	engine, err := h00StartTypeScriptEngine(ctx, root, root, "", map[string]h00SourceIdentity{
		"packages/alpha/src/index.ts": testTypeScriptSource("packages/alpha/src/index.ts", alpha),
		"packages/beta/src/index.ts":  testTypeScriptSource("packages/beta/src/index.ts", beta),
	})
	if err != nil {
		t.Fatalf("start poly-package workspace fixture: %v", err)
	}
	t.Cleanup(engine.close)
	documents, err := engine.exportDocuments(ctx, []string{
		"packages/alpha/src/index.ts",
		"packages/beta/src/index.ts",
	})
	if err != nil || len(documents) != 2 {
		t.Fatalf("export poly-package workspace: documents=%d error=%v", len(documents), err)
	}
	byPath := map[string]*scip.Document{}
	for _, document := range documents {
		byPath[document.RelativePath] = document
	}
	alphaDefinition := uniqueOccurrence(
		t, byPath["packages/alpha/src/index.ts"], alpha, "alphaValue", true,
	)
	betaDefinition := uniqueOccurrence(
		t, byPath["packages/beta/src/index.ts"], beta, "betaCaller", true,
	)
	if !strings.Contains(alphaDefinition.Symbol, "npm @fixture/alpha 1.2.3") {
		t.Fatalf("alpha symbol has the wrong package owner: %q", alphaDefinition.Symbol)
	}
	if !strings.Contains(betaDefinition.Symbol, "npm @fixture/beta 4.5.6") {
		t.Fatalf("beta symbol has the wrong package owner: %q", betaDefinition.Symbol)
	}
	references := matchingOccurrences(
		byPath["packages/beta/src/index.ts"], beta, "alphaValue", false,
	)
	if len(references) != 2 {
		t.Fatalf("positive control: expected import and call references, got %d", len(references))
	}
	for _, reference := range references {
		if reference.Symbol != alphaDefinition.Symbol {
			t.Fatalf("cross-package reference lost alpha ownership: %q != %q", reference.Symbol, alphaDefinition.Symbol)
		}
	}
}

// TypeScript's checker already knows both type inheritance and member
// overrides. Omitting that graph from SCIP makes impact analysis silently
// weaker than the compiler model even when every symbol identity is exact.
func TestNativeCompilerExportsInheritanceAndOverrideRelationships(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@fixture/relationships","version":"1.0.0","type":"module"}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true,"noImplicitOverride":true},"include":["src/**/*.ts"]}`)
	contract := "export interface ParentContract { validate(): boolean; }\nexport interface Contract extends ParentContract { run(): number; }\n"
	base := "export class Base { static create(): Base { return new Base(); } run(): number { return 1; } }\n"
	derived := "import { Base } from './base.js';\nimport type { Contract } from './contract.js';\nexport class Derived extends Base implements Contract { static override create(): Derived { return new Derived(); } override run(): number { return super.run() + 1; } validate(): boolean { return true; } }\n"
	writeTypeScriptFixture(t, root, "src/contract.ts", contract)
	writeTypeScriptFixture(t, root, "src/base.ts", base)
	writeTypeScriptFixture(t, root, "src/derived.ts", derived)
	engine, err := h00StartTypeScriptEngine(ctx, root, root, "", map[string]h00SourceIdentity{
		"src/contract.ts": testTypeScriptSource("src/contract.ts", contract),
		"src/base.ts":     testTypeScriptSource("src/base.ts", base),
		"src/derived.ts":  testTypeScriptSource("src/derived.ts", derived),
	})
	if err != nil {
		t.Fatalf("start relationship fixture: %v", err)
	}
	t.Cleanup(engine.close)
	documents, err := engine.exportDocuments(ctx, []string{"src/contract.ts", "src/base.ts", "src/derived.ts"})
	if err != nil || len(documents) != 3 {
		t.Fatalf("export relationship fixture: documents=%d error=%v", len(documents), err)
	}
	byPath := map[string]*scip.Document{}
	for _, document := range documents {
		byPath[document.RelativePath] = document
	}
	parentType := uniqueOccurrence(t, byPath["src/contract.ts"], contract, "ParentContract", true)
	parentValidate := uniqueOccurrence(t, byPath["src/contract.ts"], contract, "validate", true)
	contractType := uniqueOccurrence(t, byPath["src/contract.ts"], contract, "Contract", true)
	contractRun := uniqueOccurrence(t, byPath["src/contract.ts"], contract, "run", true)
	baseType := uniqueOccurrence(t, byPath["src/base.ts"], base, "Base", true)
	baseCreate := uniqueOccurrence(t, byPath["src/base.ts"], base, "create", true)
	baseRun := uniqueOccurrence(t, byPath["src/base.ts"], base, "run", true)
	derivedType := uniqueOccurrence(t, byPath["src/derived.ts"], derived, "Derived", true)
	derivedCreate := uniqueOccurrence(t, byPath["src/derived.ts"], derived, "create", true)
	derivedRun := uniqueOccurrence(t, byPath["src/derived.ts"], derived, "run", true)
	derivedValidate := uniqueOccurrence(t, byPath["src/derived.ts"], derived, "validate", true)
	relationshipTargets := func(documentPath, symbol string) map[string]bool {
		for _, information := range byPath[documentPath].Symbols {
			if information.Symbol == symbol {
				targets := map[string]bool{}
				for _, relationship := range information.Relationships {
					if relationship.IsImplementation {
						targets[relationship.Symbol] = true
					}
				}
				return targets
			}
		}
		return nil
	}
	if !relationshipTargets("src/contract.ts", contractType.Symbol)[parentType.Symbol] {
		t.Fatalf("extended interface omitted compiler-known relationship to %q", parentType.Symbol)
	}
	for _, target := range []string{baseType.Symbol, contractType.Symbol} {
		if !relationshipTargets("src/derived.ts", derivedType.Symbol)[target] {
			t.Fatalf("derived type omitted compiler-known relationship to %q", target)
		}
	}
	for _, target := range []string{baseRun.Symbol, contractRun.Symbol} {
		if !relationshipTargets("src/derived.ts", derivedRun.Symbol)[target] {
			t.Fatalf("derived method omitted compiler-known override relationship to %q", target)
		}
	}
	if !relationshipTargets("src/derived.ts", derivedCreate.Symbol)[baseCreate.Symbol] {
		t.Fatalf("derived static method omitted compiler-known override relationship to %q", baseCreate.Symbol)
	}
	if !relationshipTargets("src/derived.ts", derivedValidate.Symbol)[parentValidate.Symbol] {
		t.Fatalf("derived implementation omitted inherited interface relationship to %q", parentValidate.Symbol)
	}
}

func TestProviderSessionAppliesOneExactSourceEpoch(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	writeTypeScriptFixture(t, root, "package.json", `{"name":"@h00/watch-fixture","version":"1.0.0","type":"module"}`)
	writeTypeScriptFixture(t, root, "tsconfig.json", `{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}`)
	definitions := "export function stable(value: number): number { return value + 1 }\n"
	before := "import { stable } from \"./definitions.js\";\nexport const result = stable(1);\n"
	after := "import { stable } from \"./definitions.js\";\nexport const updated = stable(stable(2));\n"
	writeTypeScriptFixture(t, root, "src/definitions.ts", definitions)
	writeTypeScriptFixture(t, root, "src/usage.ts", before)
	sources := []h00SourceIdentity{
		testTypeScriptSource("src/definitions.ts", definitions),
		testTypeScriptSource("src/usage.ts", before),
	}
	population, err := h00SourcePopulationSHA256(sources)
	if err != nil {
		t.Fatalf("hash initial source population: %v", err)
	}
	previousPatchSHA256 := h00ProviderPatchSHA256
	h00ProviderPatchSHA256 = strings.Repeat("c", 64)
	t.Cleanup(func() { h00ProviderPatchSHA256 = previousPatchSHA256 })
	t.Setenv(h00ResolvedToolchainSHA256Env, strings.Repeat("a", 64))
	runtime, err := h00ObserveRuntimeConfiguration()
	if err != nil {
		t.Fatalf("build test runtime: %v", err)
	}
	authority := h00Authority{
		SessionID:           "typescript-watch-fixture",
		RootSHA256:          h00SHA256([]byte(root)),
		RootTopologySHA256:  strings.Repeat("b", 64),
		ConfigurationSHA256: runtime.ConfigurationSHA256,
		PopulationSHA256:    population,
		SourceEpoch:         1,
	}
	session, err := h00OpenTypeScriptSession(ctx, authority.SessionID, runtime, h00OpenSessionBody{
		Operation: "open_session", RepositoryRoot: root, ExecutionRoot: root,
		ExecutionPrefix: "", Authority: authority, Sources: sources,
	})
	if err != nil {
		t.Fatalf("open TypeScript provider session: %v", err)
	}
	t.Cleanup(session.close)
	if session.authority.WorkspaceResolutionSHA256 == nil || session.authority.SemanticInputsSHA256 == nil {
		t.Fatal("provider did not resolve both authority coordinates")
	}
	_, initialAttachments, err := session.exportDocuments(ctx, session.authority, []string{"src/usage.ts"})
	if err != nil || len(initialAttachments) != 1 {
		t.Fatalf("export initial document: attachments=%d error=%v", len(initialAttachments), err)
	}

	nextSource := testTypeScriptSource("src/usage.ts", after)
	nextPopulation, err := h00SourcePopulationSHA256([]h00SourceIdentity{sources[0], nextSource})
	if err != nil {
		t.Fatalf("hash next source population: %v", err)
	}
	nextAuthority := session.authority
	nextAuthority.PopulationSHA256 = nextPopulation
	nextAuthority.SourceEpoch++
	if err := session.applyEpoch(ctx, h00ApplyEpochBody{
		Operation: "apply_epoch", PreviousAuthority: session.authority,
		NextAuthority: nextAuthority,
		Changes: []h00SourceChange{{
			Outcome: "replace", DocumentPath: "src/usage.ts", Language: h00ProviderLanguage,
			PreviousContentIdentity: sources[1].ContentIdentity,
			PreviousContentSHA256:   sources[1].ContentSHA256,
			ContentIdentity:         nextSource.ContentIdentity,
			ContentSHA256:           nextSource.ContentSHA256,
			AttachmentIndex:         0,
		}},
	}, [][]byte{[]byte(after)}); err != nil {
		t.Fatalf("apply exact TypeScript source epoch: %v", err)
	}
	if !h00AuthorityEqual(session.authority, nextAuthority) {
		t.Fatal("provider did not advance to the exact next authority")
	}
	_, nextAttachments, err := session.exportDocuments(ctx, nextAuthority, []string{"src/usage.ts"})
	if err != nil || len(nextAttachments) != 1 {
		t.Fatalf("export changed document: attachments=%d error=%v", len(nextAttachments), err)
	}
	if string(initialAttachments[0]) == string(nextAttachments[0]) {
		t.Fatal("changed source epoch reused stale canonical SCIP bytes")
	}

	// The frame envelope is part of authority: a foreign caller cannot reuse
	// the correctly bound inner authority from this process-owned session.
	identity := h00ProviderIdentity{
		Protocol: h00ProviderProtocol, ProviderID: h00ProviderID,
		Language: h00ProviderLanguage, ImplementationVersion: h00ProviderImplementationVersion,
		SourceComponents: map[string]h00SourceComponent{},
		PatchSHA256:      strings.Repeat("c", 64), ExecutableSHA256: strings.Repeat("d", 64),
	}
	foreignBody, err := json.Marshal(h00CertifyFullBody{
		Operation: "certify_full", Authority: nextAuthority,
	})
	if err != nil {
		t.Fatalf("encode foreign-session request: %v", err)
	}
	frame := h00Frame{}
	frame.Metadata.RequestID = 41
	frame.Metadata.SessionID = "foreign-session"
	frame.Metadata.ExpectedProvider = identity
	frame.Metadata.Body = foreignBody
	providerSession := session
	lastRequestID := uint64(40)
	response, responseAttachments, terminal := h00HandleTypeScriptRequest(
		ctx, identity, runtime, &providerSession, &lastRequestID, frame,
	)
	responseBody, ok := response.(map[string]any)
	if !ok || responseBody["result"] != "error" || responseBody["code"] != "invalid_request" ||
		!terminal || len(responseAttachments) != 0 {
		t.Fatalf("foreign envelope received session authority: body=%#v attachments=%d terminal=%v", response, len(responseAttachments), terminal)
	}

	writeTypeScriptFixture(t, root, "tsconfig.json", `{"compilerOptions":{"strict":false},"include":["src/**/*.ts"]}`)
	if err := session.verifyAuthorityInputs(ctx); err == nil {
		t.Fatal("configuration drift retained stale provider authority")
	}
}

func writeTypeScriptFixture(t *testing.T, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", relative, err)
	}
}

func testTypeScriptSource(path, contents string) h00SourceIdentity {
	return h00SourceIdentity{
		DocumentPath:    path,
		Language:        h00ProviderLanguage,
		ContentIdentity: "fixture:" + h00SHA256([]byte(contents)),
		ContentSHA256:   h00SHA256([]byte(contents)),
	}
}

func uniqueOccurrence(t *testing.T, document *scip.Document, source, spelling string, definition bool) *scip.Occurrence {
	t.Helper()
	matches := matchingOccurrences(document, source, spelling, definition)
	if len(matches) != 1 {
		observed := make([]string, 0, len(document.Occurrences))
		for _, occurrence := range document.Occurrences {
			observed = append(observed, occurrenceText(source, occurrence.Range)+":"+occurrence.Symbol)
			if len(observed) == 16 {
				break
			}
		}
		t.Fatalf("expected one %s occurrence of %q in %s, got %d; observed=%q", map[bool]string{true: "definition", false: "reference"}[definition], spelling, document.RelativePath, len(matches), observed)
	}
	return matches[0]
}

func matchingOccurrences(document *scip.Document, source, spelling string, definition bool) []*scip.Occurrence {
	var matches []*scip.Occurrence
	for _, occurrence := range document.Occurrences {
		isDefinition := occurrence.SymbolRoles&int32(scip.SymbolRole_Definition) != 0
		if isDefinition != definition || len(occurrence.Range) != 3 {
			continue
		}
		if occurrenceText(source, occurrence.Range) == spelling {
			matches = append(matches, occurrence)
		}
	}
	return matches
}

func occurrenceText(source string, sourceRange []int32) string {
	if len(sourceRange) != 3 || sourceRange[0] < 0 || sourceRange[1] < 0 || sourceRange[2] < sourceRange[1] {
		return ""
	}
	line := int(sourceRange[0])
	startColumn := int(sourceRange[1])
	endColumn := int(sourceRange[2])
	lineStart := 0
	for current := 0; current < line; current++ {
		next := lineStart
		for next < len(source) && source[next] != '\n' {
			next++
		}
		if next == len(source) {
			return ""
		}
		lineStart = next + 1
	}
	start := lineStart + startColumn
	end := lineStart + endColumn
	if start < lineStart || end < start || end > len(source) {
		return ""
	}
	return source[start:end]
}

func documentDefines(document *scip.Document, symbol string) bool {
	for _, information := range document.Symbols {
		if information.Symbol == symbol {
			return true
		}
	}
	return false
}

func canonicalTypeScriptDocument(t *testing.T, document *scip.Document) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(document)
	if err != nil {
		t.Fatalf("marshal canonical SCIP document: %v", err)
	}
	return encoded
}
