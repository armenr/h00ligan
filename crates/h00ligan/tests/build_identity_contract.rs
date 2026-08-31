//! Shipped-boundary contract for the standalone component build identity.

use std::process::Command;

use h00ligan_engine::graph_store::{
    ClassifiedBy, CurrencyInputs, evaluate_classification_currency,
};

#[test]
fn version_reports_the_ligan_component_build_identity() {
    let output = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--version")
        .output()
        .expect("run h00ligan --version");

    assert!(output.status.success());
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(printed.contains('+'), "missing build provenance: {printed}");
    assert!(
        printed.contains(h00ligan::build_identity()),
        "expected component identity {:?}, got {printed:?}",
        h00ligan::build_identity()
    );
}

#[test]
fn exact_classifier_content_not_git_cleanliness_decides_currency() {
    let stamped = ClassifiedBy {
        build_identity: "0.1.0+abc1234+dirty".into(),
        indexer_identity: format!("sha256:{}", "a".repeat(64)),
        prover_config: "code-intel=1".into(),
        timestamp: "2026-08-20T00:00:00Z".into(),
    };
    let same_content = stamped.clone();
    let failures = evaluate_classification_currency(CurrencyInputs {
        stamp: Some(&stamped),
        current: &same_content,
        classification_authority_available: true,
        index_stale: Some(false),
    });
    assert!(
        failures.is_empty(),
        "an exact classifier-content match must certify even when the informational build provenance is dirty: {failures:?}"
    );

    let different_content = ClassifiedBy {
        indexer_identity: format!("sha256:{}", "b".repeat(64)),
        ..same_content
    };
    let failures = evaluate_classification_currency(CurrencyInputs {
        stamp: Some(&stamped),
        current: &different_content,
        classification_authority_available: true,
        index_stale: Some(false),
    });
    assert!(
        failures
            .iter()
            .any(|failure| failure.describe().contains("CLASSIFIER")),
        "a changed classifier-content identity must fail the machine-authority axis: {failures:?}"
    );
}

#[test]
fn production_classifier_identity_is_canonical_sha256() {
    let identity = h00ligan_engine::INDEXER_IDENTITY;
    let digest = identity
        .strip_prefix("sha256:")
        .unwrap_or_else(|| panic!("classifier identity is not algorithm-tagged: {identity}"));
    assert_eq!(digest.len(), 64, "unexpected SHA-256 length: {identity}");
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "classifier identity must be canonical lowercase hex: {identity}"
    );
}

#[test]
fn shipped_index_and_status_roundtrip_exact_classifier_currency() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repository");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(root.join("src")).expect("repository source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"identity-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest fixture");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn exact_identity_probe() {}\n",
    )
    .expect("source fixture");

    let index = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root", root.to_str().expect("utf-8 root")])
        .args(["--data-dir", data_dir.to_str().expect("utf-8 data dir")])
        .arg("index")
        .output()
        .expect("run shipped index");
    assert!(
        index.status.success(),
        "index failed: stdout={} stderr={}",
        String::from_utf8_lossy(&index.stdout),
        String::from_utf8_lossy(&index.stderr)
    );

    let status = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["--root", root.to_str().expect("utf-8 root")])
        .args(["--data-dir", data_dir.to_str().expect("utf-8 data dir")])
        .args(["status", "--format", "json"])
        .output()
        .expect("run shipped status");
    assert!(
        status.status.success(),
        "status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    let provenance = &status["classified_by"];
    assert_eq!(status["schema_version"], "h00/code-intel/status/v3");
    assert_eq!(
        provenance["build_identity"],
        h00ligan_engine::BUILD_IDENTITY
    );
    assert_eq!(
        provenance["indexer_identity"],
        h00ligan_engine::INDEXER_IDENTITY
    );
    assert_eq!(
        provenance["build_provenance_approximate"],
        h00ligan_engine::BUILD_IDENTITY.ends_with("+dirty")
            || h00ligan_engine::BUILD_IDENTITY.ends_with("+nogit")
    );
    assert_eq!(status["classification_currency"]["current"], true);
    assert_eq!(
        status["classification_currency"]["failures"],
        serde_json::json!([])
    );
}
