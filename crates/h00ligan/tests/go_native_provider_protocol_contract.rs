//! Source contract for Go-native semantic providers embedded by h00ligan.
//!
//! gopls and TypeScript-native have different semantic engines but the same
//! bounded process protocol. The transport, canonical hashing, bounds, and
//! parent-liveness rules must have one implementation; each engine owns only
//! its pinned identity and semantic session adapter.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn go_native_providers_share_one_wire_and_runtime_contract() {
    let workspace = workspace_root();
    let shared =
        std::fs::read_to_string(workspace.join("providers/go/shared/h00provider/protocol.go"))
            .expect("shared Go semantic-provider protocol implementation");
    let gopls =
        std::fs::read_to_string(workspace.join("providers/go/gopls/h00_provider_protocol.go"))
            .expect("gopls protocol identity adapter");
    let typescript =
        std::fs::read_to_string(workspace.join("providers/typescript/h00_provider_protocol.go"))
            .expect("TypeScript protocol identity adapter");
    let gopls_session =
        std::fs::read_to_string(workspace.join("providers/go/gopls/h00_semantic_provider.go"))
            .expect("gopls semantic-provider session adapter");
    let typescript_session =
        std::fs::read_to_string(workspace.join("providers/typescript/h00_semantic_provider.go"))
            .expect("TypeScript semantic-provider session adapter");

    for positive in [
        "package h00provider",
        "func ReadFrame(",
        "func WriteFrame(",
        "func BuildRuntimeConfiguration(",
        "func SourcePopulationSHA256(",
        "func SemanticInputsSHA256(",
        "func HashSemanticFile(",
        "func HashSemanticPath(",
        "func ArmParentLivenessGuard(",
    ] {
        assert!(
            shared.contains(positive),
            "known-positive shared protocol member is absent: {positive}"
        );
    }
    assert_eq!(
        shared.matches("func ReadFrame(").count(),
        1,
        "one shared frame reader must own request admission"
    );
    assert_eq!(
        shared.matches("func WriteFrame(").count(),
        1,
        "one shared frame writer must own response bounds"
    );

    for (engine, source, import) in [
        (
            "gopls",
            gopls.as_str(),
            "golang.org/x/tools/gopls/internal/h00provider",
        ),
        (
            "typescript",
            typescript.as_str(),
            "github.com/microsoft/typescript-go/internal/h00provider",
        ),
    ] {
        assert!(
            source.contains(import),
            "{engine} identity adapter must import the shared injected package"
        );
        assert!(
            source.contains("ProviderIdentity") && source.contains("ProviderExecutableIdentity"),
            "{engine} adapter must still own and verify its exact executable identity"
        );
        for duplicate in [
            "func h00ReadFrame(",
            "func h00WriteFrame(",
            "encoding/binary",
        ] {
            assert!(
                !source.contains(duplicate),
                "{engine} duplicated shared protocol machinery: {duplicate}"
            );
        }
    }

    let binding = "request.SessionID != (*session).authority.SessionID";
    for (engine, source) in [
        ("gopls", gopls_session.as_str()),
        ("typescript", typescript_session.as_str()),
    ] {
        assert!(
            source.contains(binding),
            "{engine} must bind every post-open request envelope to the exact process-owned session"
        );
        let mutant = source.replacen(
            binding,
            "request.SessionID == (*session).authority.SessionID",
            1,
        );
        assert!(
            !mutant.contains(binding),
            "{engine} session-binding check is vacuous against the reversed-comparison mutant"
        );
    }
}
