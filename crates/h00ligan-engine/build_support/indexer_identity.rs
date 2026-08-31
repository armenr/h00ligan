use std::path::PathBuf;

use sha2::{Digest as _, Sha256};

pub fn calculate(
    target: &str,
    features: &[(String, String)],
    files: &[(PathBuf, Vec<u8>)],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"h00/indexer-identity/v1\0");
    hash_field(&mut hasher, b"TARGET", target.as_bytes());

    let mut features = features.iter().collect::<Vec<_>>();
    features.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    for (key, value) in features {
        hash_field(&mut hasher, key.as_bytes(), value.as_bytes());
    }

    let mut files = files.iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    for (relative_path, bytes) in files {
        hash_field(
            &mut hasher,
            relative_path.as_os_str().as_encoded_bytes(),
            bytes,
        );
    }

    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

fn hash_field(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}
