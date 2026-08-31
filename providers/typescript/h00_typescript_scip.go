package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/microsoft/typescript-go/internal/ast"
	"github.com/microsoft/typescript-go/internal/astnav"
	"github.com/microsoft/typescript-go/internal/checker"
	"github.com/microsoft/typescript-go/internal/scanner"
	"github.com/scip-code/scip/bindings/go/scip"
)

func (engine *h00TypeScriptEngine) exportDocument(
	ctx context.Context,
	documentPath string,
) (*scip.Document, error) {
	absolute := filepath.Join(engine.repositoryRoot, filepath.FromSlash(documentPath))
	languageService, err := engine.session.GetLanguageService(ctx, h00TypeScriptURI(absolute))
	if err != nil {
		return nil, fmt.Errorf("resolve TypeScript language service for %q: %w", documentPath, err)
	}
	program := languageService.GetProgram()
	if program == nil {
		return nil, fmt.Errorf("TypeScript project has no program for %q", documentPath)
	}
	file := program.GetSourceFile(absolute)
	if file == nil {
		return nil, fmt.Errorf("TypeScript program omitted admitted source %q", documentPath)
	}
	if file.Text() != string(engine.sourceBytes[documentPath]) {
		return nil, fmt.Errorf("TypeScript program source differs from admitted bytes for %q", documentPath)
	}
	typeChecker, done := program.GetTypeCheckerForFileExclusive(ctx, file)
	defer done()

	document := &scip.Document{
		Language:         h00ProviderLanguage,
		RelativePath:     documentPath,
		PositionEncoding: scip.PositionEncoding_UTF8CodeUnitOffsetFromLineStart,
	}
	definitions := make(map[string]*scip.SymbolInformation)
	var visit func(*ast.Node) bool
	visit = func(node *ast.Node) bool {
		if ast.IsIdentifier(node) || ast.IsPrivateIdentifier(node) ||
			(ast.IsStringOrNumericLiteralLike(node) && ast.IsDeclarationName(node)) {
			resolved := h00ResolveTypeScriptSymbol(typeChecker, node)
			if resolved != nil {
				symbol, localDefinition := engine.typeScriptSymbol(resolved)
				if symbol != "" {
					isDefinition := h00TypeScriptNodeDefinesSymbol(node, resolved)
					occurrence := &scip.Occurrence{
						Range:       h00TypeScriptRange(file, astnav.GetStartOfNode(node, file, false), node.End()),
						Symbol:      symbol,
						SymbolRoles: int32(scip.SymbolRole_ReadAccess),
					}
					if isDefinition {
						occurrence.SymbolRoles = int32(scip.SymbolRole_Definition)
						if enclosing := h00TypeScriptDefinitionRange(file, node, resolved); len(enclosing) != 0 {
							occurrence.EnclosingRange = enclosing
						}
						if localDefinition == documentPath {
							definitions[symbol] = &scip.SymbolInformation{
								Symbol: symbol, Kind: h00TypeScriptSymbolKind(resolved),
								DisplayName: h00TypeScriptDisplayName(resolved, node),
								Relationships: engine.typeScriptImplementationRelationships(
									typeChecker,
									resolved,
								),
							}
						}
					} else if h00TypeScriptImportReference(node) {
						occurrence.SymbolRoles |= int32(scip.SymbolRole_Import)
					}
					document.Occurrences = append(document.Occurrences, occurrence)
				}
			}
		}
		node.ForEachChild(visit)
		return false
	}
	file.ForEachChild(visit)
	for _, information := range definitions {
		document.Symbols = append(document.Symbols, information)
	}
	scip.CanonicalizeDocument(document)
	return document, nil
}

func h00ResolveTypeScriptSymbol(typeChecker *checker.Checker, node *ast.Node) *ast.Symbol {
	symbol := typeChecker.GetSymbolAtLocation(node)
	if symbol == nil {
		return nil
	}
	if symbol.Flags&ast.SymbolFlagsAlias != 0 {
		if target := typeChecker.GetAliasedSymbol(symbol); target != nil {
			symbol = target
		}
	}
	if target := typeChecker.GetExportSymbolOfSymbol(symbol); target != nil {
		symbol = target
	}
	return symbol
}

func (engine *h00TypeScriptEngine) typeScriptImplementationRelationships(
	typeChecker *checker.Checker,
	symbol *ast.Symbol,
) []*scip.Relationship {
	targets := make(map[string]struct{})
	addTarget := func(target *ast.Symbol) {
		if target == nil || target == symbol {
			return
		}
		formatted, _ := engine.typeScriptSymbol(target)
		if formatted != "" {
			targets[formatted] = struct{}{}
		}
	}
	if symbol.Flags&(ast.SymbolFlagsClass|ast.SymbolFlagsInterface) != 0 {
		for _, ancestor := range h00TypeScriptAncestorTypes(typeChecker, symbol) {
			addTarget(ancestor.Symbol())
		}
	}
	if parent := symbol.Parent; parent != nil &&
		parent.Flags&(ast.SymbolFlagsClass|ast.SymbolFlagsInterface) != 0 {
		staticMember := h00TypeScriptStaticMember(symbol)
		for _, ancestor := range h00TypeScriptAncestorTypes(typeChecker, parent) {
			memberOwner := ancestor
			if staticMember {
				memberOwner = typeChecker.GetTypeOfSymbol(ancestor.Symbol())
			}
			if memberOwner != nil {
				addTarget(typeChecker.GetPropertyOfType(memberOwner, symbol.Name))
			}
		}
	}
	ordered := make([]string, 0, len(targets))
	for target := range targets {
		ordered = append(ordered, target)
	}
	sort.Strings(ordered)
	relationships := make([]*scip.Relationship, 0, len(ordered))
	for _, target := range ordered {
		relationships = append(relationships, &scip.Relationship{
			Symbol: target, IsImplementation: true,
		})
	}
	return relationships
}

func h00TypeScriptStaticMember(symbol *ast.Symbol) bool {
	for _, declaration := range symbol.Declarations {
		if ast.IsClassElement(declaration) && ast.HasStaticModifier(declaration) {
			return true
		}
	}
	return false
}

func h00TypeScriptAncestorTypes(
	typeChecker *checker.Checker,
	symbol *ast.Symbol,
) []*checker.Type {
	declared := typeChecker.GetDeclaredTypeOfSymbol(symbol)
	if declared == nil {
		return nil
	}
	bySymbol := make(map[*ast.Symbol]*checker.Type)
	for _, base := range typeChecker.GetBaseTypes(declared) {
		if base != nil && base.Symbol() != nil {
			bySymbol[base.Symbol()] = base
		}
	}
	for _, declaration := range symbol.Declarations {
		for _, clause := range h00TypeScriptHeritageClauses(declaration) {
			for _, heritageType := range clause.AsHeritageClause().Types.Nodes {
				expression := heritageType.AsExpressionWithTypeArguments().Expression
				target := h00ResolveTypeScriptSymbol(typeChecker, expression)
				if target == nil {
					continue
				}
				ancestor := typeChecker.GetDeclaredTypeOfSymbol(target)
				if ancestor != nil {
					bySymbol[target] = ancestor
				}
			}
		}
	}
	orderedSymbols := make([]*ast.Symbol, 0, len(bySymbol))
	for ancestor := range bySymbol {
		orderedSymbols = append(orderedSymbols, ancestor)
	}
	sort.Slice(orderedSymbols, func(i, j int) bool {
		return ast.SymbolName(orderedSymbols[i]) < ast.SymbolName(orderedSymbols[j])
	})
	ancestors := make([]*checker.Type, 0, len(orderedSymbols))
	for _, ancestor := range orderedSymbols {
		ancestors = append(ancestors, bySymbol[ancestor])
	}
	return ancestors
}

func h00TypeScriptHeritageClauses(declaration *ast.Node) []*ast.Node {
	if declaration == nil {
		return nil
	}
	var clauses *ast.NodeList
	switch declaration.Kind {
	case ast.KindClassDeclaration:
		clauses = declaration.AsClassDeclaration().HeritageClauses
	case ast.KindClassExpression:
		clauses = declaration.AsClassExpression().HeritageClauses
	case ast.KindInterfaceDeclaration:
		clauses = declaration.AsInterfaceDeclaration().HeritageClauses
	}
	if clauses == nil {
		return nil
	}
	return clauses.Nodes
}

func h00TypeScriptNodeDefinesSymbol(node *ast.Node, symbol *ast.Symbol) bool {
	if !ast.IsDeclarationName(node) && !ast.IsLiteralComputedPropertyDeclarationName(node) {
		return false
	}
	for _, declaration := range symbol.Declarations {
		name := ast.GetNameOfDeclaration(declaration)
		if name == node || name != nil && name.Contains(node) {
			return true
		}
	}
	return false
}

func h00TypeScriptImportReference(node *ast.Node) bool {
	for parent := node.Parent; parent != nil && !ast.IsSourceFile(parent); parent = parent.Parent {
		if ast.IsImportOrExportSpecifier(parent) {
			return true
		}
		if ast.IsDeclaration(parent) && parent != node.Parent {
			break
		}
	}
	return false
}

func (engine *h00TypeScriptEngine) typeScriptSymbol(symbol *ast.Symbol) (string, string) {
	declaration := h00CanonicalTypeScriptDeclaration(symbol)
	if declaration == nil {
		return "", ""
	}
	file := ast.GetSourceFileOfNode(declaration)
	if file == nil {
		return "", ""
	}
	fileName := filepath.Clean(file.FileName())
	if localPath, ok := engine.repositoryDocumentPath(fileName); ok {
		if _, admitted := engine.sources[localPath]; admitted {
			coordinate, known := engine.localPackages[localPath]
			if !known {
				return "", ""
			}
			return h00TypeScriptRepositorySymbol(
				coordinate,
				localPath,
				declaration,
				symbol,
			), localPath
		}
	}
	return engine.typeScriptExternalSymbol(fileName, declaration, symbol), ""
}

func h00CanonicalTypeScriptDeclaration(symbol *ast.Symbol) *ast.Node {
	declarations := append([]*ast.Node(nil), symbol.Declarations...)
	if len(declarations) == 0 && symbol.ValueDeclaration != nil {
		declarations = append(declarations, symbol.ValueDeclaration)
	}
	sort.Slice(declarations, func(i, j int) bool {
		leftFile := ast.GetSourceFileOfNode(declarations[i])
		rightFile := ast.GetSourceFileOfNode(declarations[j])
		leftName, rightName := "", ""
		if leftFile != nil {
			leftName = leftFile.FileName()
		}
		if rightFile != nil {
			rightName = rightFile.FileName()
		}
		if leftName != rightName {
			return leftName < rightName
		}
		if declarations[i].Pos() != declarations[j].Pos() {
			return declarations[i].Pos() < declarations[j].Pos()
		}
		return declarations[i].End() < declarations[j].End()
	})
	if len(declarations) == 0 {
		return nil
	}
	return declarations[0]
}

func (engine *h00TypeScriptEngine) repositoryDocumentPath(fileName string) (string, bool) {
	if !filepath.IsAbs(fileName) {
		return "", false
	}
	relative, err := filepath.Rel(engine.repositoryRoot, fileName)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	path := filepath.ToSlash(relative)
	return path, h00SafeDocumentPath(path)
}

func h00TypeScriptRepositorySymbol(
	coordinate h00TypeScriptPackageCoordinate,
	documentPath string,
	declaration *ast.Node,
	symbol *ast.Symbol,
) string {
	if h00TypeScriptFunctionLocal(declaration) {
		local := h00SHA256([]byte(strings.Join([]string{
			documentPath,
			strconv.Itoa(declaration.Pos()),
			strconv.Itoa(declaration.End()),
			ast.SymbolName(symbol),
		}, "\x00")))
		return "local " + local[:24]
	}
	descriptors := []*scip.Descriptor{{Name: documentPath, Suffix: scip.Descriptor_Namespace}}
	for _, container := range h00TypeScriptNamedContainers(declaration) {
		descriptors = append(descriptors, container)
	}
	descriptors = append(descriptors, &scip.Descriptor{
		Name: ast.SymbolName(symbol), Suffix: h00TypeScriptDescriptorSuffix(symbol),
	})
	return scip.VerboseSymbolFormatter.FormatSymbol(&scip.Symbol{
		Scheme:      "typescript",
		Package:     &scip.Package{Manager: coordinate.Manager, Name: coordinate.Name, Version: coordinate.Version},
		Descriptors: descriptors,
	})
}

func (engine *h00TypeScriptEngine) typeScriptExternalSymbol(
	fileName string,
	declaration *ast.Node,
	symbol *ast.Symbol,
) string {
	coordinate, modulePath := engine.typeScriptExternalCoordinate(fileName)
	descriptors := []*scip.Descriptor{{Name: modulePath, Suffix: scip.Descriptor_Namespace}}
	for _, container := range h00TypeScriptNamedContainers(declaration) {
		descriptors = append(descriptors, container)
	}
	descriptors = append(descriptors, &scip.Descriptor{
		Name: ast.SymbolName(symbol), Suffix: h00TypeScriptDescriptorSuffix(symbol),
	})
	return scip.VerboseSymbolFormatter.FormatSymbol(&scip.Symbol{
		Scheme:      "typescript",
		Package:     &scip.Package{Manager: coordinate.Manager, Name: coordinate.Name, Version: coordinate.Version},
		Descriptors: descriptors,
	})
}

func h00TypeScriptNamedContainers(declaration *ast.Node) []*scip.Descriptor {
	var reversed []*scip.Descriptor
	for parent := declaration.Parent; parent != nil && !ast.IsSourceFile(parent); parent = parent.Parent {
		name := ast.GetNameOfDeclaration(parent)
		if name == nil || name.Text() == "" {
			continue
		}
		suffix := scip.Descriptor_Term
		if ast.IsClassLike(parent) || ast.IsInterfaceDeclaration(parent) || ast.IsTypeAliasDeclaration(parent) {
			suffix = scip.Descriptor_Type
		} else if ast.IsModuleDeclaration(parent) {
			suffix = scip.Descriptor_Namespace
		}
		reversed = append(reversed, &scip.Descriptor{Name: name.Text(), Suffix: suffix})
	}
	containers := make([]*scip.Descriptor, 0, len(reversed))
	for index := len(reversed) - 1; index >= 0; index-- {
		containers = append(containers, reversed[index])
	}
	return containers
}

func h00TypeScriptFunctionLocal(declaration *ast.Node) bool {
	for parent := declaration.Parent; parent != nil && !ast.IsSourceFile(parent); parent = parent.Parent {
		if ast.IsFunctionLike(parent) {
			return true
		}
	}
	return declaration.Kind == ast.KindParameter || declaration.Kind == ast.KindTypeParameter
}

func h00TypeScriptDescriptorSuffix(symbol *ast.Symbol) scip.Descriptor_Suffix {
	switch {
	case symbol.Flags&ast.SymbolFlagsModule != 0:
		return scip.Descriptor_Namespace
	case symbol.Flags&(ast.SymbolFlagsClass|ast.SymbolFlagsInterface|ast.SymbolFlagsEnum|ast.SymbolFlagsTypeAlias|ast.SymbolFlagsTypeParameter) != 0:
		return scip.Descriptor_Type
	case symbol.Flags&(ast.SymbolFlagsMethod|ast.SymbolFlagsConstructor|ast.SymbolFlagsGetAccessor|ast.SymbolFlagsSetAccessor|ast.SymbolFlagsSignature) != 0:
		return scip.Descriptor_Method
	default:
		return scip.Descriptor_Term
	}
}

func h00TypeScriptSymbolKind(symbol *ast.Symbol) scip.SymbolInformation_Kind {
	switch {
	case symbol.Flags&ast.SymbolFlagsClass != 0:
		return scip.SymbolInformation_Class
	case symbol.Flags&ast.SymbolFlagsInterface != 0:
		return scip.SymbolInformation_Interface
	case symbol.Flags&ast.SymbolFlagsEnum != 0:
		return scip.SymbolInformation_Enum
	case symbol.Flags&ast.SymbolFlagsEnumMember != 0:
		return scip.SymbolInformation_EnumMember
	case symbol.Flags&ast.SymbolFlagsTypeAlias != 0:
		return scip.SymbolInformation_TypeAlias
	case symbol.Flags&ast.SymbolFlagsTypeParameter != 0:
		return scip.SymbolInformation_TypeParameter
	case symbol.Flags&ast.SymbolFlagsConstructor != 0:
		return scip.SymbolInformation_Constructor
	case symbol.Flags&ast.SymbolFlagsGetAccessor != 0:
		return scip.SymbolInformation_Getter
	case symbol.Flags&ast.SymbolFlagsSetAccessor != 0:
		return scip.SymbolInformation_Setter
	case symbol.Flags&ast.SymbolFlagsMethod != 0:
		return scip.SymbolInformation_Method
	case symbol.Flags&ast.SymbolFlagsFunction != 0:
		return scip.SymbolInformation_Function
	case symbol.Flags&ast.SymbolFlagsProperty != 0:
		return scip.SymbolInformation_Property
	case symbol.Flags&ast.SymbolFlagsModule != 0:
		return scip.SymbolInformation_Namespace
	case symbol.Flags&ast.SymbolFlagsBlockScopedVariable != 0:
		return scip.SymbolInformation_Constant
	default:
		return scip.SymbolInformation_Variable
	}
}

func h00TypeScriptDisplayName(symbol *ast.Symbol, node *ast.Node) string {
	name := ast.SymbolName(symbol)
	if name == "" || strings.HasPrefix(name, ast.InternalSymbolNamePrefix) {
		return node.Text()
	}
	return name
}

func h00TypeScriptRange(file *ast.SourceFile, start, end int) []int32 {
	startLine, startColumn := scanner.GetECMALineAndByteOffsetOfPosition(file, start)
	endLine, endColumn := scanner.GetECMALineAndByteOffsetOfPosition(file, end)
	if startLine == endLine {
		return []int32{int32(startLine), int32(startColumn), int32(endColumn)}
	}
	return []int32{int32(startLine), int32(startColumn), int32(endLine), int32(endColumn)}
}

func h00TypeScriptDefinitionRange(file *ast.SourceFile, node *ast.Node, symbol *ast.Symbol) []int32 {
	for _, declaration := range symbol.Declarations {
		name := ast.GetNameOfDeclaration(declaration)
		if name == node || name != nil && name.Contains(node) {
			return h00TypeScriptRange(file, astnav.GetStartOfNode(declaration, file, true), declaration.End())
		}
	}
	return nil
}

type h00TypeScriptPackageManifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type h00TypeScriptPackageCoordinate struct {
	Manager string
	Name    string
	Version string
}

func h00ResolveTypeScriptPackageCoordinate(
	filesystem *h00RepositoryFS,
	startDirectory string,
	repositoryRoot string,
) h00TypeScriptPackageCoordinate {
	current := startDirectory
	for {
		path := filepath.Join(current, "package.json")
		if contents, ok := filesystem.ReadFile(path); ok {
			var manifest h00TypeScriptPackageManifest
			if json.Unmarshal([]byte(contents), &manifest) == nil && manifest.Name != "" {
				if manifest.Version == "" {
					manifest.Version = "."
				}
				return h00TypeScriptPackageCoordinate{
					Manager: "npm", Name: manifest.Name, Version: manifest.Version,
				}
			}
		}
		if current == repositoryRoot {
			break
		}
		parent := filepath.Dir(current)
		if parent == current || !h00PathWithin(parent, repositoryRoot) {
			break
		}
		current = parent
	}
	return h00TypeScriptPackageCoordinate{Manager: "npm", Name: "workspace", Version: "."}
}

func (engine *h00TypeScriptEngine) typeScriptExternalCoordinate(
	fileName string,
) (h00TypeScriptPackageCoordinate, string) {
	normalized := filepath.ToSlash(fileName)
	if strings.HasPrefix(normalized, "bundled:") || strings.Contains(normalized, "/internal/bundled/libs/") {
		return h00TypeScriptPackageCoordinate{
			Manager: "typescript", Name: "stdlib", Version: h00TypescriptVersion,
		}, filepath.Base(normalized)
	}
	if packageRoot, fallbackName, modulePath, ok := h00TypeScriptNodePackageLocation(normalized); ok {
		coordinate, known := engine.externalPackages[packageRoot]
		if !known {
			coordinate = h00TypeScriptPackageCoordinate{
				Manager: "npm", Name: fallbackName, Version: ".",
			}
		}
		if modulePath == "" {
			modulePath = coordinate.Name
		}
		return coordinate, modulePath
	}
	return h00TypeScriptPackageCoordinate{
		Manager: "typescript", Name: "external", Version: h00TypescriptVersion,
	}, normalized
}

func h00ObservedTypeScriptExternalPackages(
	filesystem *h00RepositoryFS,
	sourceFiles map[string]struct{},
) map[string]h00TypeScriptPackageCoordinate {
	paths := make([]string, 0, len(sourceFiles))
	for path := range sourceFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	coordinates := make(map[string]h00TypeScriptPackageCoordinate)
	for _, path := range paths {
		packageRoot, fallbackName, _, ok := h00TypeScriptNodePackageLocation(filepath.ToSlash(path))
		if !ok {
			continue
		}
		if _, known := coordinates[packageRoot]; known {
			continue
		}
		coordinate := h00TypeScriptPackageCoordinate{
			Manager: "npm", Name: fallbackName, Version: ".",
		}
		if contents, readable := filesystem.ReadFile(
			filepath.FromSlash(packageRoot + "/package.json"),
		); readable {
			var manifest h00TypeScriptPackageManifest
			if json.Unmarshal([]byte(contents), &manifest) == nil {
				if manifest.Name != "" {
					coordinate.Name = manifest.Name
				}
				if manifest.Version != "" {
					coordinate.Version = manifest.Version
				}
			}
		}
		coordinates[packageRoot] = coordinate
	}
	return coordinates
}

func h00TypeScriptNodePackageLocation(normalized string) (string, string, string, bool) {
	const marker = "/node_modules/"
	index := strings.LastIndex(normalized, marker)
	if index < 0 {
		return "", "", "", false
	}
	remainder := normalized[index+len(marker):]
	parts := strings.Split(remainder, "/")
	count := 1
	if len(parts) > 1 && strings.HasPrefix(parts[0], "@") {
		count = 2
	}
	if len(parts) < count {
		return "", "", "", false
	}
	name := strings.Join(parts[:count], "/")
	return normalized[:index+len(marker)] + name, name, strings.Join(parts[count:], "/"), true
}
