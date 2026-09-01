// Package main adapts the pinned TypeScript native engine identity to
// h00ligan's shared Go-native semantic-provider wire and runtime contract.
package main

import (
	"fmt"
	"os"

	"github.com/microsoft/typescript-go/internal/h00provider"
)

const (
	h00ProviderProtocol              = h00provider.Protocol
	h00ProviderID                    = "h00-typescript-native-scip"
	h00ProviderLanguage              = "typescript"
	h00ProviderImplementationVersion = "typescript-native-7.0.2+scip-v0.9.0/independent-semantic-input-bound/h00-semantic-provider-v2"
	h00TypescriptVersion             = "7.0.2"
	h00TypescriptRevision            = "2bd066d87f5bafd315be9f40889d0a60b9e58e0b"
	h00ScipBindingsVersion           = "v0.9.0"
	h00ScipBindingsRevision          = "e8ee0ae6038f8298e2195812eea9d7b1196748ae"
	h00ResolvedToolchainSHA256Env    = "H00_RESOLVED_TOOLCHAIN_SHA256"
	h00ProviderSemanticInputsSchema  = h00provider.SemanticInputsSchema
	h00MaxDocumentPaths              = h00provider.MaxDocumentPaths
	h00MaxSemanticInputPaths         = h00provider.MaxSemanticInputPaths
)

var h00ProviderPatchSHA256 string

type h00SourceComponent = h00provider.SourceComponent
type h00ProviderIdentity = h00provider.ProviderIdentity
type h00Authority = h00provider.Authority
type h00SourceIdentity = h00provider.SourceIdentity
type h00SemanticPathInput = h00provider.SemanticPathInput
type h00SemanticEnvironmentInput = h00provider.SemanticEnvironmentInput
type h00SemanticInputIssue = h00provider.SemanticInputIssue
type h00SemanticInputs = h00provider.SemanticInputs
type h00Health = h00provider.Health
type h00RequestOperation = h00provider.RequestOperation
type h00AnalysisRequest = h00provider.AnalysisRequest
type h00Response = h00provider.Response
type h00Frame = h00provider.Frame
type h00ResponseFrame = h00provider.ResponseFrame
type h00RuntimeConfiguration = h00provider.RuntimeConfiguration

func h00ProviderExecutableIdentity() (h00ProviderIdentity, error) {
	if !h00IsSHA256(h00ProviderPatchSHA256) {
		return h00ProviderIdentity{}, fmt.Errorf("provider patch identity is not configured")
	}
	executable, err := os.Executable()
	if err != nil {
		return h00ProviderIdentity{}, fmt.Errorf("resolve provider executable: %w", err)
	}
	bytes, err := os.ReadFile(executable)
	if err != nil {
		return h00ProviderIdentity{}, fmt.Errorf("hash provider executable: %w", err)
	}
	return h00ProviderIdentity{
		Protocol:              h00ProviderProtocol,
		ProviderID:            h00ProviderID,
		Language:              h00ProviderLanguage,
		ImplementationVersion: h00ProviderImplementationVersion,
		SourceComponents: map[string]h00SourceComponent{
			"scip_bindings": {
				Version:  h00ScipBindingsVersion,
				Revision: h00ScipBindingsRevision,
			},
			"typescript_native": {
				Version:  h00TypescriptVersion,
				Revision: h00TypescriptRevision,
			},
		},
		PatchSHA256:      h00ProviderPatchSHA256,
		ExecutableSHA256: h00SHA256(bytes),
	}, nil
}

func h00DecodeBody[T any](raw []byte) (T, error) {
	return h00provider.DecodeBody[T](raw)
}

var (
	h00ArmParentLivenessGuard    = h00provider.ArmParentLivenessGuard
	h00BuildRuntimeConfiguration = h00provider.BuildRuntimeConfiguration
	h00DecodeOperation           = h00provider.DecodeOperation
	h00HashField                 = h00provider.HashField
	h00HashSemanticFile          = h00provider.HashSemanticFile
	h00HashSemanticPath          = h00provider.HashSemanticPath
	h00IdentityEqual             = h00provider.IdentityEqual
	h00IsExactSuccessorEpoch     = h00provider.IsExactSuccessorEpoch
	h00IsSHA256                  = h00provider.IsSHA256
	h00Limits                    = h00provider.Limits
	h00ReadFrame                 = h00provider.ReadFrame
	h00SafeDocumentPath          = h00provider.SafeDocumentPath
	h00SafeSemanticPath          = h00provider.SafeSemanticPath
	h00SemanticInputsSHA256      = h00provider.SemanticInputsSHA256
	h00SHA256                    = h00provider.SHA256
	h00SourcePopulationSHA256    = h00provider.SourcePopulationSHA256
	h00WriteFrame                = h00provider.WriteFrame
)
