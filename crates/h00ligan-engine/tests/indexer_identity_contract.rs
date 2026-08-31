#[path = "../build_support/indexer_identity.rs"]
mod indexer_identity;

use std::path::PathBuf;

fn inputs() -> Vec<(PathBuf, Vec<u8>)> {
    vec![
        (PathBuf::from("Cargo.lock"), b"lock-v1".to_vec()),
        (
            PathBuf::from("crates/h00ligan-engine/src/extractor.rs"),
            b"extractor-v1".to_vec(),
        ),
    ]
}

#[test]
fn digest_is_deterministic_and_order_independent() {
    let features = vec![
        ("CARGO_FEATURE_CODE_INTEL".into(), "1".into()),
        ("CARGO_FEATURE_TEST_UTILS".into(), "1".into()),
    ];
    let expected = indexer_identity::calculate("x86_64-unknown-linux-musl", &features, &inputs());

    let mut reversed_features = features;
    reversed_features.reverse();
    let mut reversed_inputs = inputs();
    reversed_inputs.reverse();
    let observed = indexer_identity::calculate(
        "x86_64-unknown-linux-musl",
        &reversed_features,
        &reversed_inputs,
    );

    assert_eq!(observed, expected);
    assert_eq!(expected.len(), "sha256:".len() + 64);
}

#[test]
fn every_authority_input_can_change_the_digest() {
    let target = "x86_64-unknown-linux-musl";
    let features = vec![("CARGO_FEATURE_CODE_INTEL".into(), "1".into())];
    let baseline = indexer_identity::calculate(target, &features, &inputs());

    let mut changed_source = inputs();
    changed_source[1].1.push(b'!');
    assert_ne!(
        indexer_identity::calculate(target, &features, &changed_source),
        baseline,
        "source bytes must be authority-bearing"
    );

    let mut changed_path = inputs();
    changed_path[1].0 = PathBuf::from("crates/h00ligan-engine/src/renamed.rs");
    assert_ne!(
        indexer_identity::calculate(target, &features, &changed_path),
        baseline,
        "source identity/path must be authority-bearing"
    );

    let changed_features = vec![("CARGO_FEATURE_CODE_INTEL".into(), "0".into())];
    assert_ne!(
        indexer_identity::calculate(target, &changed_features, &inputs()),
        baseline,
        "classifier feature configuration must be authority-bearing"
    );

    assert_ne!(
        indexer_identity::calculate("aarch64-apple-darwin", &features, &inputs()),
        baseline,
        "compiled target must be authority-bearing"
    );
}
