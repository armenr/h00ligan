// Package cmd adapts gopls identity to h00ligan's shared Go-native
// semantic-provider wire and runtime contract.
package cmd

import (
	"fmt"
	"os"

	"golang.org/x/tools/gopls/internal/h00provider"
)

const (
	h00ProviderProtocol              = h00provider.Protocol
	h00ProviderID                    = "h00-gopls-scip"
	h00ProviderLanguage              = "go"
	h00ProviderImplementationVersion = "gopls-v0.23.0+scip-go-v0.2.7/project-input-reconfigure=discard-on-failure/snapshot-inputs=exact/callable-liveness=go-rta-v1/h00ligan-v4"
	h00GoplsVersion                  = "v0.23.0"
	h00GoplsRevision                 = "014f87ff5c01915bc90f4f11a6bb8aea3e0edbd7"
	h00ScipGoVersion                 = "v0.2.7"
	h00ScipGoRevision                = "2e9ff3c2603a85daabe125c9f20075ec52df0731"
	h00ResolvedToolchainSHA256Env    = "H00_RESOLVED_TOOLCHAIN_SHA256"
	h00ResolvedGoSHA256Env           = "H00_RESOLVED_GO_SHA256"
	h00ProviderParentPIDEnv          = h00provider.ProviderParentPIDEnv
	h00ProviderSemanticInputsSchema  = h00provider.SemanticInputsSchema
	h00MaxFrameBytes                 = h00provider.MaxFrameBytes
	h00MaxMetadataBytes              = h00provider.MaxMetadataBytes
	h00MaxAttachments                = h00provider.MaxAttachments
	h00MaxAttachmentBytes            = h00provider.MaxAttachmentBytes
	h00MaxTotalAttachmentBytes       = h00provider.MaxTotalAttachmentBytes
	h00MaxDocumentPaths              = h00provider.MaxDocumentPaths
	h00MaxSemanticInputPaths         = h00provider.MaxSemanticInputPaths
	h00MaxOutstandingRequests        = h00provider.MaxOutstandingRequests
)

var (
	h00ProviderPatchSHA256 string
	h00ProviderFrameMagic  = h00provider.ProviderFrameMagic
)

type h00SourceComponent = h00provider.SourceComponent
type h00ProviderIdentity = h00provider.ProviderIdentity
type h00FrameLimits = h00provider.FrameLimits
type h00Authority = h00provider.Authority
type h00SourceIdentity = h00provider.SourceIdentity
type h00SemanticPathInput = h00provider.SemanticPathInput
type h00SemanticEnvironmentInput = h00provider.SemanticEnvironmentInput
type h00SemanticInputIssue = h00provider.SemanticInputIssue
type h00SemanticInputs = h00provider.SemanticInputs
type h00Health = h00provider.Health
type h00Request = h00provider.Request
type h00RequestOperation = h00provider.RequestOperation
type h00AnalysisRequest = h00provider.AnalysisRequest
type h00Response = h00provider.Response
type h00Frame = h00provider.Frame
type h00ResponseFrame = h00provider.ResponseFrame

type h00RuntimeConfiguration struct {
	h00provider.RuntimeConfiguration
	GoStdlibVersion string `json:"-"`
}

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
			"gopls":   {Version: h00GoplsVersion, Revision: h00GoplsRevision},
			"scip_go": {Version: h00ScipGoVersion, Revision: h00ScipGoRevision},
		},
		PatchSHA256:      h00ProviderPatchSHA256,
		ExecutableSHA256: h00SHA256(bytes),
	}, nil
}

func h00BuildRuntimeConfiguration(
	resolvedToolchain string,
	components map[string][]byte,
	environmentReport, workspaceReport []byte,
) (h00RuntimeConfiguration, error) {
	runtime, err := h00provider.BuildRuntimeConfiguration(
		resolvedToolchain,
		components,
		environmentReport,
		workspaceReport,
	)
	return h00RuntimeConfiguration{RuntimeConfiguration: runtime}, err
}

func h00DecodeBody[T any](raw []byte) (T, error) {
	return h00provider.DecodeBody[T](raw)
}

var (
	h00ArmParentLivenessGuard = h00provider.ArmParentLivenessGuard
	h00DecodeOperation        = h00provider.DecodeOperation
	h00HashField              = h00provider.HashField
	h00HashSemanticFile       = h00provider.HashSemanticFile
	h00IdentityEqual          = h00provider.IdentityEqual
	h00IsExactSuccessorEpoch  = h00provider.IsExactSuccessorEpoch
	h00IsSHA256               = h00provider.IsSHA256
	h00Limits                 = h00provider.Limits
	h00ReadFrame              = h00provider.ReadFrame
	h00SafeDocumentPath       = h00provider.SafeDocumentPath
	h00SemanticInputsSHA256   = h00provider.SemanticInputsSHA256
	h00SHA256                 = h00provider.SHA256
	h00SourcePopulationSHA256 = h00provider.SourcePopulationSHA256
	h00ValidComponentName     = h00provider.ValidComponentName
	h00WriteFrame             = h00provider.WriteFrame
)
