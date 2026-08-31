// Package h00scip exposes scip-go's document visitor over an already
// type-checked package. It deliberately does not package-load or recompute
// whole-program implementation relationships.
package h00scip

import (
	"fmt"
	"go/ast"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scip-code/scip-go/internal/document"
	"github.com/scip-code/scip-go/internal/lookup"
	"github.com/scip-code/scip-go/internal/symbols"
	"github.com/scip-code/scip-go/internal/visitors"
	"github.com/scip-code/scip/bindings/go/scip"
	"golang.org/x/tools/go/packages"
)

// ExportDocuments renders exactly the requested files from one already
// type-checked project package. Dependencies supply stable package/module
// identities for on-demand external symbol composition.
func ExportDocuments(
	moduleRoot string,
	moduleVersion string,
	pkg *packages.Package,
	dependencies []*packages.Package,
	requestedFiles []string,
) (documents []*scip.Document, err error) {
	defer func() {
		if failure := recover(); failure != nil {
			documents = nil
			err = fmt.Errorf("scip-go projection panic: %v", failure)
		}
	}()
	return exportDocuments(moduleRoot, moduleVersion, pkg, dependencies, requestedFiles)
}

func exportDocuments(
	moduleRoot string,
	moduleVersion string,
	pkg *packages.Package,
	dependencies []*packages.Package,
	requestedFiles []string,
) ([]*scip.Document, error) {
	if moduleRoot == "" || pkg == nil || pkg.Fset == nil || pkg.Types == nil || pkg.TypesInfo == nil || pkg.Module == nil {
		return nil, fmt.Errorf("incomplete loaded package")
	}
	if moduleVersion == "" {
		moduleVersion = "."
	}
	requested := make(map[string]struct{}, len(requestedFiles))
	for _, requestedPath := range requestedFiles {
		absolute, err := filepath.Abs(requestedPath)
		if err != nil {
			return nil, fmt.Errorf("resolve requested document %q: %w", requestedPath, err)
		}
		requested[filepath.Clean(absolute)] = struct{}{}
	}
	if len(requested) == 0 {
		return nil, fmt.Errorf("empty requested document population")
	}

	composer := symbols.NewComposer(moduleRoot, moduleVersion)
	globalSymbols := lookup.NewGlobalSymbols(composer)
	for _, dependency := range dependencies {
		if dependency == nil || dependency.PkgPath == "" {
			continue
		}
		if dependency.Module == nil {
			return nil, fmt.Errorf("dependency package %q has no module authority", dependency.PkgPath)
		}
		globalSymbols.SetPkgSymbol(dependency)
	}
	globalSymbols.SetPkgSymbol(pkg)

	pathToDocuments := map[string]*document.Document{}
	visitors.VisitPackageSyntax(moduleRoot, pkg, pathToDocuments, globalSymbols)
	if len(pkg.Syntax) == 0 {
		return nil, fmt.Errorf("loaded package %q has no syntax", pkg.PkgPath)
	}
	pkgSymbol, ok := globalSymbols.GetPkgSymbol(pkg)
	if !ok {
		return nil, fmt.Errorf("loaded package %q has no package symbol", pkg.PkgPath)
	}
	firstFile := pkg.Syntax[0]
	firstTokenFile := pkg.Fset.File(firstFile.Package)
	if firstTokenFile == nil {
		return nil, fmt.Errorf("loaded package %q has an unmapped first file", pkg.PkgPath)
	}
	firstDocument := pathToDocuments[firstTokenFile.Name()]
	if firstDocument == nil {
		return nil, fmt.Errorf("loaded package %q has no first document", pkg.PkgPath)
	}
	firstDocument.SetSymbolInformation(firstFile.Name.NamePos, &scip.SymbolInformation{
		Symbol: pkgSymbol, Kind: scip.SymbolInformation_Package, DisplayName: pkg.Name,
		Documentation:          packageDocs(pkg),
		SignatureDocumentation: &scip.Document{Language: "go", Text: "package " + pkg.Name},
	})
	for _, file := range pkg.Syntax {
		tokenFile := pkg.Fset.File(file.Package)
		if tokenFile == nil {
			return nil, fmt.Errorf("loaded package %q contains unmapped syntax", pkg.PkgPath)
		}
		doc := pathToDocuments[tokenFile.Name()]
		if doc == nil {
			return nil, fmt.Errorf("loaded package %q is missing %q", pkg.PkgPath, tokenFile.Name())
		}
		doc.PackageOccurrence = &scip.Occurrence{
			Range:  symbols.RangeFromName(pkg.Fset.Position(file.Name.NamePos), file.Name.Name, false),
			Symbol: pkgSymbol, SymbolRoles: int32(scip.SymbolRole_Definition),
		}
	}

	pkgSymbols := globalSymbols.GetPackage(pkg)
	if pkgSymbols == nil {
		return nil, fmt.Errorf("loaded package %q has no symbol census", pkg.PkgPath)
	}
	var documents []*scip.Document
	covered := make(map[string]struct{}, len(requested))
	for _, file := range pkg.Syntax {
		tokenFile := pkg.Fset.File(file.Package)
		absolute, err := filepath.Abs(tokenFile.Name())
		if err != nil {
			return nil, fmt.Errorf("resolve loaded document %q: %w", tokenFile.Name(), err)
		}
		absolute = filepath.Clean(absolute)
		if _, ok := requested[absolute]; !ok {
			continue
		}
		doc := pathToDocuments[tokenFile.Name()]
		visitor := visitors.NewFileVisitor(doc, pkg, file, pkgSymbols, globalSymbols)
		ast.Walk(visitor, file)
		documents = append(documents, visitor.ToScipDocument())
		covered[absolute] = struct{}{}
	}
	if len(covered) != len(requested) {
		return nil, fmt.Errorf("requested %d documents but loaded package covered %d", len(requested), len(covered))
	}
	sort.Slice(documents, func(i, j int) bool {
		return documents[i].RelativePath < documents[j].RelativePath
	})
	return documents, nil
}

func packageDocs(pkg *packages.Package) []string {
	var files []*ast.File
	for _, file := range pkg.Syntax {
		if file.Doc != nil {
			files = append(files, file)
		}
	}
	sort.SliceStable(files, func(i, j int) bool {
		left := pkg.Fset.Position(files[i].Pos()).Filename
		right := pkg.Fset.Position(files[j].Pos()).Filename
		return fileRelevance(pkg.Name, left) < fileRelevance(pkg.Name, right)
	})
	var docs []string
	for _, file := range files {
		docs = append(docs, file.Doc.Text())
	}
	return docs
}

func fileRelevance(packageName, filename string) int {
	switch {
	case path.Base(filename) == "doc.go":
		return 0
	case strings.TrimSuffix(path.Base(filename), path.Ext(filename)) == packageName:
		return 1
	case !strings.HasSuffix(filename, "_test.go"):
		return 2
	default:
		return 3
	}
}
