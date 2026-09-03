//! Shared, store-free source search for code-intelligence surfaces.
//!
//! This is deliberately narrower than the full agent's generic grep tool:
//! it searches only extensions owned by the engine language registry, honours
//! repository ignore files with the `ignore` crate's Git-aware defaults, never
//! invokes a host command, and reports files it refuses because they are binary,
//! unreadable, or over the source-size caps.

use std::path::Path;

use crate::code_intel_source_search::{
    SearchedSourceFile, SkippedSourceFile, SourceSearchOptions, SourceSearchRecord,
    SourceSearchReport,
};
use crate::project_binding::ProjectBinding;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{SearcherBuilder, Sink, SinkContext, SinkContextKind, SinkMatch};

/// Files larger than this are not materialized by the multi-line searcher.
pub const MAX_SOURCE_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// A source file with a line longer than this is treated as minified/generated.
pub const MAX_SOURCE_LINE_BYTES: usize = 256 * 1024;
/// Maximum text returned for one match or context record.
pub const MAX_RETURNED_LINE_CHARS: usize = 2_000;
/// Bound diagnostics independently of the number of unsuitable files.
const MAX_SKIP_DETAILS: usize = 100;

/// Whether the caller supplied a literal string or a regular expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourcePattern<'a> {
    Literal(&'a str),
    Regex(&'a str),
}

enum Suitability {
    Search,
    Skip(String),
}

/// Search registered-language source beneath `search_root`.
///
/// Both roots are canonicalized here even when the caller already used a
/// [`h00ligan_engine::project_binding::ProjectBinding`]. Keeping the confinement at
/// the I/O primitive means a future caller cannot accidentally reintroduce a
/// `root.join(user_input)` traversal or symlink escape.
pub fn search_registered_source(
    binding: &ProjectBinding,
    search_root: &Path,
    pattern: SourcePattern<'_>,
    options: SourceSearchOptions,
) -> Result<SourceSearchReport, String> {
    let workspace_root = binding.root().to_path_buf();
    let search_root = search_root
        .canonicalize()
        .map_err(|e| format!("cannot resolve search root {}: {e}", search_root.display()))?;
    if !search_root.starts_with(&workspace_root) {
        return Err(format!(
            "search root {} escapes project root {}",
            search_root.display(),
            workspace_root.display()
        ));
    }

    let expression = match pattern {
        SourcePattern::Literal(value) => regex::escape(value),
        SourcePattern::Regex(value) => value.to_string(),
    };
    let matcher = RegexMatcherBuilder::new()
        .multi_line(true)
        .dot_matches_new_line(true)
        .build(&expression)
        .map_err(|e| format!("invalid regex: {e}"))?;

    if options.max_matches == 0 || options.max_matches_per_file == 0 {
        return Err("source search limits must be positive".into());
    }

    let extensions = crate::language::extensions_for_languages(&[]);
    let source_files = crate::source_discovery::discover_source_files_beneath(
        &workspace_root,
        &search_root,
        &extensions,
        &[],
    )
    .map_err(|error| error.to_string())?;

    let mut report = SourceSearchReport::default();
    let mut searcher = SearcherBuilder::new()
        .line_number(true)
        .multi_line(true)
        .before_context(options.context_lines)
        .after_context(options.context_lines)
        .build();

    for path in source_files {
        let relative = relative_display(&workspace_root, &path);
        let bytes =
            match binding.read_existing_file_bounded(Path::new(&relative), MAX_SOURCE_FILE_BYTES) {
                Ok((_canonical, bytes)) => bytes,
                Err(error) => {
                    record_skip(&mut report, relative, format!("read_refused: {error}"));
                    continue;
                }
            };
        match inspect_source_bytes(&bytes) {
            Suitability::Search => {}
            Suitability::Skip(reason) => {
                record_skip(&mut report, relative, reason);
                continue;
            }
        }

        let mut file_match_count = 0usize;
        let records_before = report.records.len();
        let matches_before = report.matches_returned;
        let truncated_before = report.truncated;
        let mut sink = SourceSink {
            relative_path: &relative,
            records: &mut report.records,
            total_match_count: &mut report.matches_returned,
            file_match_count: &mut file_match_count,
            max_matches: options.max_matches,
            max_matches_per_file: options.max_matches_per_file,
            truncated: &mut report.truncated,
            pending_before: Vec::new(),
            accept_after_context: false,
        };
        if let Err(error) = searcher.search_slice(&matcher, &bytes, &mut sink) {
            report.records.truncate(records_before);
            report.matches_returned = matches_before;
            report.truncated = truncated_before;
            record_skip(&mut report, relative, format!("search_error: {error}"));
            continue;
        }
        report.searched_files.push(SearchedSourceFile {
            file_path: relative,
            blake3_hash: blake3::hash(&bytes).to_hex().to_string(),
        });

        if report.truncated && report.matches_returned >= options.max_matches {
            break;
        }
    }

    Ok(report)
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn inspect_source_bytes(bytes: &[u8]) -> Suitability {
    let mut line_bytes = 0usize;
    for byte in bytes {
        if *byte == 0 {
            return Suitability::Skip("binary_nul_byte".to_string());
        }
        if *byte == b'\n' {
            line_bytes = 0;
        } else {
            line_bytes += 1;
            if line_bytes > MAX_SOURCE_LINE_BYTES {
                return Suitability::Skip(format!(
                    "minified_line_over_cap: > {MAX_SOURCE_LINE_BYTES} bytes"
                ));
            }
        }
    }
    Suitability::Search
}

fn record_skip(report: &mut SourceSearchReport, file_path: String, reason: impl Into<String>) {
    report.skipped_file_count += 1;
    if report.skipped_files.len() < MAX_SKIP_DETAILS {
        report.skipped_files.push(SkippedSourceFile {
            file_path,
            reason: reason.into(),
        });
    }
}

struct SourceSink<'a> {
    relative_path: &'a str,
    records: &'a mut Vec<SourceSearchRecord>,
    total_match_count: &'a mut usize,
    file_match_count: &'a mut usize,
    max_matches: usize,
    max_matches_per_file: usize,
    truncated: &'a mut bool,
    pending_before: Vec<SourceSearchRecord>,
    accept_after_context: bool,
}

impl Sink for SourceSink<'_> {
    type Error = std::io::Error;

    fn matched(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        matched: &SinkMatch<'_>,
    ) -> Result<bool, Self::Error> {
        if *self.total_match_count >= self.max_matches
            || *self.file_match_count >= self.max_matches_per_file
        {
            *self.truncated = true;
            self.pending_before.clear();
            self.accept_after_context = false;
            return Ok(false);
        }

        self.records.append(&mut self.pending_before);
        self.records.push(record_from_bytes(
            self.relative_path,
            matched.line_number(),
            matched.bytes(),
            true,
        ));
        *self.total_match_count += 1;
        *self.file_match_count += 1;
        self.accept_after_context = true;
        // Continue once the cap is reached so one additional match can prove
        // truncation. Returning false here would recreate the exact-fit lie.
        Ok(true)
    }

    fn context(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        context: &SinkContext<'_>,
    ) -> Result<bool, Self::Error> {
        let record = record_from_bytes(
            self.relative_path,
            context.line_number(),
            context.bytes(),
            false,
        );
        match context.kind() {
            SinkContextKind::Before => self.pending_before.push(record),
            SinkContextKind::After if self.accept_after_context => self.records.push(record),
            SinkContextKind::Other => self.records.push(record),
            SinkContextKind::After => {}
        }
        Ok(true)
    }
}

fn record_from_bytes(
    relative_path: &str,
    line_number: Option<u64>,
    bytes: &[u8],
    is_match: bool,
) -> SourceSearchRecord {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_end_matches(['\r', '\n']);
    let content_truncated = text.chars().count() > MAX_RETURNED_LINE_CHARS;
    let line_text = if content_truncated {
        text.chars().take(MAX_RETURNED_LINE_CHARS).collect()
    } else {
        text.to_string()
    };
    SourceSearchRecord {
        file_path: relative_path.to_string(),
        line_number: line_number.unwrap_or(0) as usize,
        line_text,
        is_match,
        content_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(root: &Path) -> ProjectBinding {
        ProjectBinding::explicit(root, &root.join(".test-graph")).expect("test binding")
    }

    #[test]
    fn searches_every_registered_language_without_searching_unregistered_text() {
        let root = tempfile::tempdir().expect("temp root");
        std::fs::write(root.path().join("lib.rs"), "fn shared_marker() {}\n").unwrap();
        std::fs::write(root.path().join("main.go"), "func shared_marker() {}\n").unwrap();
        std::fs::write(
            root.path().join("service.py"),
            "def shared_marker(): pass\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("service.ts"),
            "function shared_marker() {}\n",
        )
        .unwrap();
        std::fs::write(root.path().join("notes.txt"), "shared_marker\n").unwrap();

        let report = search_registered_source(
            &binding(root.path()),
            root.path(),
            SourcePattern::Literal("shared_marker"),
            SourceSearchOptions::default(),
        )
        .unwrap();

        assert_eq!(report.matches_returned, 4);
        assert!(
            report
                .records
                .iter()
                .any(|record| record.file_path == "lib.rs")
        );
        assert!(
            report
                .records
                .iter()
                .any(|record| record.file_path == "main.go")
        );
        assert!(
            report
                .records
                .iter()
                .any(|record| record.file_path == "service.py")
        );
        assert!(
            report
                .records
                .iter()
                .any(|record| record.file_path == "service.ts")
        );
        assert!(
            !report
                .records
                .iter()
                .any(|record| record.file_path == "notes.txt")
        );
    }

    #[test]
    fn honours_ignore_files_and_reports_unsuitable_registered_sources() {
        let root = tempfile::tempdir().expect("temp root");
        // `ignore::WalkBuilder` deliberately follows ripgrep semantics: a
        // `.gitignore` is repository metadata and requires a detected Git
        // worktree. Keep that production contract and make the fixture a real
        // repository instead of depending on an ambient ancestor `.git`.
        std::fs::create_dir(root.path().join(".git")).unwrap();
        std::fs::write(root.path().join(".gitignore"), "ignored.go\n").unwrap();
        std::fs::write(root.path().join("ignored.go"), "func marker() {}\n").unwrap();
        std::fs::write(root.path().join("binary.rs"), b"marker\0binary\n").unwrap();
        let giant = format!("marker{}", "x".repeat(MAX_SOURCE_LINE_BYTES));
        std::fs::write(root.path().join("minified.go"), giant).unwrap();

        let report = search_registered_source(
            &binding(root.path()),
            root.path(),
            SourcePattern::Literal("marker"),
            SourceSearchOptions::default(),
        )
        .unwrap();

        assert_eq!(report.matches_returned, 0);
        assert_eq!(report.skipped_file_count, 2);
        assert!(
            report
                .skipped_files
                .iter()
                .any(|file| { file.file_path == "binary.rs" && file.reason == "binary_nul_byte" })
        );
        assert!(report.skipped_files.iter().any(|file| {
            file.file_path == "minified.go" && file.reason.starts_with("minified_line_over_cap")
        }));
    }

    #[test]
    fn rejects_a_symlink_escape_search_root() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let root = tempfile::tempdir().expect("temp root");
            let outside = tempfile::tempdir().expect("outside");
            std::fs::write(outside.path().join("outside.rs"), "fn marker() {}\n").unwrap();
            symlink(outside.path(), root.path().join("escape")).unwrap();

            let error = search_registered_source(
                &binding(root.path()),
                &root.path().join("escape"),
                SourcePattern::Literal("marker"),
                SourceSearchOptions::default(),
            )
            .unwrap_err();
            assert!(error.contains("escapes project root"));
        }
    }

    #[test]
    fn returns_requested_context_lines() {
        let root = tempfile::tempdir().expect("temp root");
        std::fs::write(
            root.path().join("multi.rs"),
            "line_one_before\nTARGET_MATCH_HERE\nline_three_after\n",
        )
        .unwrap();

        let report = search_registered_source(
            &binding(root.path()),
            root.path(),
            SourcePattern::Regex("TARGET_MATCH_HERE"),
            SourceSearchOptions {
                max_matches: 50,
                max_matches_per_file: 50,
                context_lines: 1,
            },
        )
        .unwrap();

        let joined = report
            .records
            .iter()
            .map(|record| record.line_text.as_str())
            .collect::<Vec<_>>()
            .join("");
        assert!(joined.contains("line_one_before"));
        assert!(joined.contains("TARGET_MATCH_HERE"));
        assert!(joined.contains("line_three_after"));
    }

    #[test]
    fn supports_multiline_patterns() {
        let root = tempfile::tempdir().expect("temp root");
        std::fs::write(
            root.path().join("span.rs"),
            "fn start_marker() {\n    end_marker();\n}\n",
        )
        .unwrap();

        let report = search_registered_source(
            &binding(root.path()),
            root.path(),
            SourcePattern::Regex("(?s)start_marker.*end_marker"),
            SourceSearchOptions {
                max_matches: 50,
                max_matches_per_file: 50,
                context_lines: 0,
            },
        )
        .unwrap();

        assert!(report.matches_returned > 0);
    }

    #[test]
    fn exact_match_limit_is_not_reported_as_truncated() {
        let root = tempfile::tempdir().expect("temp root");
        std::fs::write(root.path().join("lib.rs"), "marker\nmarker\n").unwrap();

        let report = search_registered_source(
            &binding(root.path()),
            root.path(),
            SourcePattern::Literal("marker"),
            SourceSearchOptions {
                max_matches: 2,
                max_matches_per_file: 10,
                context_lines: 0,
            },
        )
        .unwrap();

        assert_eq!(report.matches_returned, 2);
        assert!(!report.truncated);
    }
}
