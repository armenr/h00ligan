//! Validation for immutable per-file index-state authority.
//!
//! Consumers must not independently trust paths, language labels, or hashes
//! loaded from a generation database. This one validator returns a canonical
//! path-keyed population for source search, diff, and future live-source
//! comparisons.

use std::collections::BTreeMap;
use std::path::Path;

use crate::code_intel_domain::DomainError;
use crate::index_state::FileRecord;

pub fn validate_indexed_source_records(
    records: &[(String, FileRecord)],
) -> Result<BTreeMap<String, FileRecord>, DomainError> {
    let mut indexed = BTreeMap::new();
    for (path, record) in records {
        let path_value = Path::new(path);
        let safe_path = !path.is_empty()
            && !path_value.is_absolute()
            && path_value
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)));
        let expected_language = path_value
            .extension()
            .and_then(|extension| extension.to_str())
            .and_then(crate::language::language_for_extension);
        let digest_valid = record.blake3_hash.len() == 64
            && record
                .blake3_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if !safe_path || !digest_valid || expected_language != Some(record.language.as_str()) {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "indexed source authority for '{path}' has an invalid path, language, or BLAKE3 digest"
                ),
            });
        }
        if indexed.insert(path.clone(), record.clone()).is_some() {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!("indexed source authority contains duplicate path '{path}'"),
            });
        }
    }
    Ok(indexed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(language: &str) -> FileRecord {
        FileRecord {
            blake3_hash: "a".repeat(64),
            last_indexed: 1,
            symbol_count: 1,
            language: language.into(),
        }
    }

    #[test]
    fn indexed_source_authority_is_closed_and_canonical() {
        let valid = vec![("src/lib.rs".into(), record("rust"))];
        let indexed = validate_indexed_source_records(&valid).expect("valid authority");
        assert_eq!(indexed.len(), 1);

        for invalid in [
            vec![("../src/lib.rs".into(), record("rust"))],
            vec![("src/lib.rs".into(), record("go"))],
            vec![(
                "src/lib.rs".into(),
                FileRecord {
                    blake3_hash: "not-a-digest".into(),
                    ..record("rust")
                },
            )],
            vec![
                ("src/lib.rs".into(), record("rust")),
                ("src/lib.rs".into(), record("rust")),
            ],
        ] {
            let error = validate_indexed_source_records(&invalid)
                .expect_err("invalid authority must fail closed");
            assert!(matches!(
                error,
                DomainError::PublishedGenerationInvalid { .. }
            ));
        }
    }
}
