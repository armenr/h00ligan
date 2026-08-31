//! WU-0015 Leg 3a / ADR-0036 §Decision v6 — the rustc/clippy dead-code oracle
//! SIGNAL.
//!
//! This module runs `cargo clippy --message-format=json` over the indexed repo,
//! extracts the `dead_code` diagnostics (WU-0016 Class-B narrowed the retained
//! family to `dead_code`-only), and stamps a per-node
//! [`GraphNode::rustc_flagged_dead`](crate::graph::GraphNode::rustc_flagged_dead)
//! bit on the EXACT, UNAMBIGUOUS symbol whose definition line matches a
//! diagnostic's primary span. It is the corroboration the Leg-3b DEAD-authority
//! gate will require.
//!
//! # The oracle bit is CONSUMED (it once changed no verdict — no longer)
//!
//! Leg 3a PRODUCES `rustc_flagged_dead`; it is now READ by several consumers, so
//! it is no longer an inert signal: `graph_query::classify_dead_action` reads it
//! as conjunct 2 of the 4-way `SafeDelete` gate (Leg 3b); the leg-E
//! [`reaffirm_oracle`] reset-then-reaffirm keys the incremental-staleness fix on
//! it; and WU-0016 Leg F stamps a companion [`OracleReceipt`] beside it (cleared
//! in lockstep by the same reset) which the DEAD-tier corroboration reason
//! surfaces. (`reachability::analyze()` and `ReachabilityClass` remain untouched
//! by the oracle pass itself — it still writes no reachability class.)
//!
//! # Correctness: span-based, never name-based
//!
//! The mapper (`apply_oracle`) matches on `(file_path, line_start)` and sets the
//! bit ONLY on an exact single-node match (ADR-0036 V3-3/V4-2). It NEVER:
//!   * matches on symbol name (two same-named private fns in different files
//!     would collide — the `SM2` falsifier);
//!   * reuses [`scip_loader::find_enclosing_definition`](crate::scip_loader) or
//!     any closest-preceding-def heuristic (an interior body line must resolve
//!     to NOTHING — the `SM7` falsifier);
//!   * flags on an off-by-one line (rustc is 1-indexed, the graph is 0-indexed;
//!     the `-1` normalization is the load-bearing arithmetic — the `SM3`
//!     falsifier).
//!
//! On 0 or >1 candidate matches it flags NEITHER (conservative — `SM4`/`SM5`).
//!
//! # Graceful degrade (non-negotiable)
//!
//! A missing/failed/timed-out clippy, a non-compiling repo, or a non-cargo /
//! non-Rust repo yields an ABSENT oracle: [`collect_dead_diagnostics`] returns
//! `Err` (or an empty set) WITHOUT panic, and the index pipeline treats that as
//! "no diagnostics" — every node keeps `rustc_flagged_dead == false`. Absence
//! can never over-flag (an empty diag set matches nothing) and can never crash
//! indexing (the collect path holds no `unwrap`/`expect`; the pipeline wraps the
//! pass non-fatally). The impure collector is split from the pure applier so the
//! degrade paths are unit-testable via an injectable `runner` seam without a
//! real clippy.

use std::path::Path;
use std::time::Duration;

use uuid::Uuid;

use crate::graph::{KnowledgeGraph, OracleReceipt};

/// A generous upper bound on how long the oracle waits for `cargo clippy`.
///
/// On expiry the child is killed and the oracle degrades to ABSENT (identical
/// to clippy being missing). Prevents a hung clippy from wedging indexing.
pub const DEFAULT_ORACLE_TIMEOUT: Duration = Duration::from_secs(300);

/// A retained dead-code family diagnostic extracted from the clippy JSON stream.
///
/// `line_start` is kept VERBATIM (still 1-INDEXED, as rustc emits it) — the
/// `-1` normalization to the graph's 0-indexed convention is the mapper's job
/// ([`apply_oracle`]), not the parser's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadDiag {
    /// The primary span's `file_name`, verbatim from clippy (may be absolute,
    /// workspace-relative, or package-relative — normalized at map time).
    pub file_name: String,
    /// The primary span's `line_start`, 1-INDEXED (verbatim from rustc).
    pub line_start: usize,
    /// The lint code. After the WU-0016 Class-B narrowing the parser only ever
    /// retains `"dead_code"` (the `unused_*` family is dropped at parse time),
    /// so in practice this is always `"dead_code"`.
    pub code: String,
    /// The short symbol name parsed best-effort from the diagnostic message —
    /// the FIRST backtick-quoted token of `message.message` (e.g. "function
    /// `foo` is never used" → `foo`). `None` when unparseable: the message is
    /// absent, or it is a plural / aggregated form with no single backtick
    /// subject. Consumed by [`apply_oracle`] as a subject-identity gate on the
    /// lone-candidate flag (WU-0016 Class-B). WU-0016 Leg F: it is ALSO persisted
    /// — [`apply_oracle`] copies it into the flagged node's
    /// [`OracleReceipt::subject`](crate::graph::OracleReceipt::subject) so the
    /// DEAD-tier corroboration reason can name the corroborated symbol.
    pub subject: Option<String>,
    /// The owning package's `manifest_path` (absolute), verbatim from the cargo
    /// `compiler-message`, when present. Used to resolve a package-relative
    /// `file_name` to the workspace-relative graph convention. `None` for a
    /// hand-fed JSON snippet without it (unit tests) or an absolute/workspace-
    /// relative `file_name` that needs no package context.
    pub manifest_path: Option<String>,
}

/// The outcome of an oracle collection pass — the AUTHORITATIVE-vs-DEGRADED
/// discriminator (OQ-ORACLE-INCREMENTAL-STALE, part a1).
///
/// [`collect_dead_diagnostics`] returned `Ok(Vec::new())` for BOTH a genuinely
/// clean run (build succeeded, nothing dead) AND a degraded run (a compile
/// error stopped analysis before any use was seen), so the caller could not
/// tell "the fresh truth is empty" from "we learned nothing." This enum makes
/// the two distinguishable:
///   * [`Ran`](Self::Ran) — the clippy build SUCCEEDED; the carried diagnostics
///     (possibly empty) are the COMPLETE, current dead-code truth. The
///     [`reaffirm_oracle`] reset-then-reaffirm keys on this: a node absent from
///     a `Ran` set is genuinely-not-dead-anymore and its stale flag must clear.
///   * [`Degraded`](Self::Degraded) — the build did NOT report success (compile
///     error, aborted run, empty stream); the dead-set is untrustworthy and
///     carries NO information. Existing flags are preserved unchanged (the
///     graceful-degrade contract); the store-level `oracle_ran_ok` backstop
///     then covers the resulting stale-flag corner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleOutcome {
    /// The clippy build succeeded — these diagnostics are the complete truth
    /// (an empty Vec means "genuinely nothing dead this run").
    Ran(Vec<DeadDiag>),
    /// The clippy build did not report success — no trustworthy information.
    Degraded,
}

/// Why the oracle could not produce diagnostics. Every variant degrades to an
/// ABSENT oracle (empty signal) at the pipeline boundary — none propagate to
/// crash indexing.
#[derive(Debug, thiserror::Error)]
pub enum OracleError {
    /// The repo root has no `Cargo.toml` — not a cargo project (covers the
    /// non-cargo / non-Rust index case).
    #[error("not a cargo project: no Cargo.toml at repo root")]
    NotCargo,
    /// `cargo clippy` could not be spawned (binary absent, PATH issue, …).
    #[error("failed to spawn cargo clippy: {0}")]
    Spawn(String),
    /// `cargo clippy` exceeded [`DEFAULT_ORACLE_TIMEOUT`] and was killed.
    #[error("cargo clippy timed out")]
    Timeout,
    /// Any other runner-side failure (I/O reading output, reaper channel, …).
    #[error("cargo clippy runner error: {0}")]
    Runner(String),
}

/// Parse a `cargo clippy --message-format=json` stream, retaining ONLY the
/// dead-code family diagnostics.
///
/// Best-effort and line-by-line: each line is an independent JSON object; a line
/// that fails to parse (blank, truncated, `build-finished`, `compiler-artifact`,
/// …) is SKIPPED without aborting the stream. Never panics on garbage input.
///
/// Retention predicate (the exact boundary — see the `P4` fixture):
/// `code == "dead_code"` ONLY (WU-0016 Class-B). Everything else is dropped —
/// the whole `unused_*` family (it fires on local bindings/statements/imports,
/// never a definition item, so its only matches on a definition NODE were
/// line-collision spoofs), style lints (`non_snake_case`), the entire `clippy::*`
/// group (`clippy::needless_return`), and adjacent non-family lints
/// (`unreachable_code`). See [`is_dead_code_family`].
///
/// The extracted `line_start` is taken from the PRIMARY span (`is_primary ==
/// true`) only — never a secondary span or a child-note span (the `P2`
/// fixture) — because a wrong span choice mis-maps to a different node. Each
/// retained diagnostic also carries a best-effort [`DeadDiag::subject`] (the
/// first backtick-quoted token of the human `message`), the subject-identity
/// gate [`apply_oracle`] uses to refuse a lone-candidate flag whose name does
/// not match.
pub fn parse_clippy_dead_diagnostics(json: &str) -> Vec<DeadDiag> {
    let mut out = Vec::new();
    for line in json.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Best-effort: a malformed / non-JSON line is skipped, never fatal.
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        if value.get("reason").and_then(|r| r.as_str()) != Some("compiler-message") {
            continue;
        }
        let Some(message) = value.get("message") else {
            continue;
        };
        // The lint code; many messages (notes, errors without a code) carry a
        // null `code`, which filters out here.
        let Some(code) = message
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|c| c.as_str())
        else {
            continue;
        };
        if !is_dead_code_family(code) {
            continue;
        }
        // Extract the PRIMARY span's 1-indexed line_start.
        let Some(spans) = message.get("spans").and_then(|s| s.as_array()) else {
            continue;
        };
        let Some(primary) = spans
            .iter()
            .find(|s| s.get("is_primary").and_then(|p| p.as_bool()) == Some(true))
        else {
            continue;
        };
        let Some(file_name) = primary.get("file_name").and_then(|f| f.as_str()) else {
            continue;
        };
        let Some(line_start) = primary
            .get("line_start")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        let manifest_path = value
            .get("manifest_path")
            .and_then(|m| m.as_str())
            .map(str::to_string);
        // Best-effort subject: the FIRST backtick-quoted token of the human
        // `message` (e.g. "function `foo` is never used" → "foo"). `None` when
        // the message is absent or carries no single backtick subject (a
        // plural/aggregated form). Consumed by `apply_oracle` as a subject-
        // identity gate on the lone-candidate flag (WU-0016 Class-B).
        let subject = message
            .get("message")
            .and_then(|m| m.as_str())
            .and_then(first_backtick_token);
        out.push(DeadDiag {
            file_name: file_name.to_string(),
            line_start: line_start as usize,
            code: code.to_string(),
            subject,
            manifest_path,
        });
    }
    out
}

/// The dead-code retention predicate — keeps `dead_code` ONLY (WU-0016
/// Class-B), drops everything else.
///
/// The WHOLE `unused_*` family is deliberately excluded. `unused_variables`,
/// `unused_mut`, `unused_assignments`, `unused_imports`, `unused_parens`, … all
/// fire on a local binding / statement / import / expression — NEVER on a
/// definition item — so an `unused_*` primary span could only ever land on a
/// definition NODE's line by COLLISION (a spoof), never as a genuine "this
/// definition is dead" signal. The sole practically-inert casualty is
/// `unused_macros` (a dead `macro_rules!`), which ~never satisfies the SafeDelete
/// visibility + reachability conjuncts anyway. `dead_code` is the only lint that
/// actually fires on an unused DEFINITION item, so narrowing to it makes the
/// SafeDelete conjunct-2 SOUND (the flagged set can only shrink — the safe,
/// under-flag direction).
fn is_dead_code_family(code: &str) -> bool {
    code == "dead_code"
}

/// Extract the substring between the FIRST pair of backticks in `s`
/// (best-effort). Returns `None` when there is no opening backtick, or no
/// closing backtick after it. Backticks are ASCII, so every index used here is
/// a char boundary — the slicing never panics.
fn first_backtick_token(s: &str) -> Option<String> {
    let start = s.find('`')? + 1;
    let rest = &s[start..];
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

/// Normalize a clippy `file_name` to the graph's `file_path` convention
/// (`crates/<crate>/src/...`, forward slashes).
///
/// Handles the emission forms the impl targets:
///   * ABSOLUTE (`<repo_root>/crates/x/src/a.rs`) — strip the `repo_root` prefix.
///   * workspace-relative (`crates/x/src/a.rs`) — used as-is.
///   * package-relative (`src/a.rs`, package root `crates/x`) — joined to the
///     `package_root` (resolved from the diagnostic's `manifest_path`).
///
/// Returns `None` only for a degenerate input (the file_name IS the repo root).
/// The EXACT real clippy form is pinned empirically by the `E2E1` real-clippy
/// fixture; if it reveals a third form, extend here.
pub fn relativize(file_name: &str, repo_root: &Path, package_root: Option<&str>) -> Option<String> {
    let fwd = file_name.replace('\\', "/");
    let root = repo_root.to_string_lossy().replace('\\', "/");
    let root = root.trim_end_matches('/');

    // 1. Absolute under repo_root → strip to workspace-relative.
    let stripped = if !root.is_empty() {
        if let Some(rest) = fwd.strip_prefix(&format!("{root}/")) {
            rest.to_string()
        } else if fwd == root {
            return None;
        } else {
            fwd
        }
    } else {
        fwd
    };

    // 2. Already workspace-relative (starts with `crates/`) → use as-is; this
    //    also catches the absolute form after stripping.
    if stripped.starts_with("crates/") {
        return Some(stripped);
    }

    // 3. Package-relative → join to the resolved package root, when known.
    if let Some(pkg) = package_root {
        let pkg = pkg.trim_end_matches('/');
        if !pkg.is_empty() {
            if stripped == pkg || stripped.starts_with(&format!("{pkg}/")) {
                return Some(stripped);
            }
            return Some(format!("{pkg}/{stripped}"));
        }
    }

    // 4. No package context (e.g. a top-level `src/...` or an unrecognized
    //    form) → return the forward-slash-normalized, repo-root-stripped path.
    Some(stripped)
}

/// Resolve a package's `manifest_path` (absolute `.../crates/x/Cargo.toml`) to
/// the workspace-relative package root (`crates/x`), forward slashes. Returns
/// `None` when the manifest is not under `repo_root`.
fn manifest_to_package_root(manifest_path: &str, repo_root: &Path) -> Option<String> {
    let dir = Path::new(manifest_path).parent()?;
    let rel = dir.strip_prefix(repo_root).ok()?;
    Some(rel.to_string_lossy().replace('\\', "/"))
}

/// Apply the parsed diagnostics to the graph — the PURE mapper.
///
/// For each [`DeadDiag`]: relativize its `file_name`, normalize its 1-indexed
/// `line_start` to the graph's 0-indexed convention (`line_start - 1`), and
/// collect nodes at EXACTLY that `(file_path, line_start)`. On a UNIQUE
/// candidate, apply the subject-identity gate (WU-0016 Class-B): if the
/// diagnostic parsed a `subject`, set `rustc_flagged_dead = true` ONLY when the
/// candidate's short OR full symbol name matches it; a subject-less diagnostic
/// (`subject == None`) FALLS BACK to flagging the unique candidate. (Real clippy
/// `dead_code` always carries a backtick subject, so the `None` fallback is
/// real-path-inert — it only arises for subject-less test fixtures or a rare
/// opaque-plural form, whose container node is already redundant-or-defanged by
/// the visibility/reachability conjuncts.) A diagnostic with 0 or >1 line
/// matches, or a unique match whose subject mismatches, sets nothing
/// (conservative). A `line_start == 0` is malformed (rustc is 1-indexed) and is
/// skipped.
///
/// Mutates ONLY `rustc_flagged_dead` and its WU-0016 Leg F companion
/// `oracle_receipt` (stamped together on a flag). No reachability class, no
/// action, no other field is touched — the oracle pass still changes no verdict
/// (the `INV3` guard); the receipt is pure evidence the DEAD-tier reason surfaces.
pub fn apply_oracle(graph: &mut KnowledgeGraph, diags: &[DeadDiag], repo_root: &Path) {
    for diag in diags {
        // rustc line numbers are 1-indexed; 0 is malformed → skip (never
        // underflow the -1 normalization).
        if diag.line_start == 0 {
            continue;
        }
        let package_root = diag
            .manifest_path
            .as_deref()
            .and_then(|m| manifest_to_package_root(m, repo_root));
        let Some(rel) = relativize(&diag.file_name, repo_root, package_root.as_deref()) else {
            continue;
        };
        let normalized_line = diag.line_start - 1;

        // Collect exact-(file, line) matches. Read-only borrow first, then
        // mutate — only a single unambiguous match sets the bit.
        let candidates: Vec<Uuid> = graph
            .all_nodes()
            .into_iter()
            .filter(|n| n.file_path == rel && n.line_start == Some(normalized_line))
            .map(|n| n.memory_id)
            .collect();

        if candidates.len() == 1
            && let Some(node) = graph.node_mut(&candidates[0])
        {
            // Subject-identity gate (WU-0016 Class-B): a UNIQUE line match is
            // still only trustworthy if the diagnostic's parsed subject names
            // THIS node. When `subject` is `Some`, flag ONLY when it matches the
            // candidate's short OR full symbol name (clippy emits the short
            // name; `short_name` handles a fully-qualified node name). When
            // `subject` is `None`, FALL BACK to the unique-line flag — real
            // clippy `dead_code` always carries a backtick subject, so `None`
            // only arises for subject-less test fixtures or a rare opaque-plural
            // form (whose container node is already redundant-or-defanged by the
            // visibility/reachability conjuncts).
            let subject_ok = match diag.subject.as_deref() {
                Some(s) => {
                    crate::graph_query::short_name(&node.symbol_name) == s || node.symbol_name == s
                }
                None => true,
            };
            if subject_ok {
                node.rustc_flagged_dead = true;
                // WU-0016 Leg F (OQ-DELETE-REASON-PROVENANCE): stamp the
                // corroborating receipt BESIDE the flag, from the in-scope diag —
                // the code, the normalized 0-indexed def line (== the node's
                // `line_start`), and the parsed subject. The receipt is a
                // COMPANION to `rustc_flagged_dead`: set together here, and cleared
                // together by the leg-E `reaffirm_oracle` reset — so a node that is
                // no longer flagged never carries a stale receipt.
                node.oracle_receipt = Some(OracleReceipt {
                    code: diag.code.clone(),
                    line: normalized_line,
                    subject: diag.subject.clone(),
                });
            }
        }
        // 0 or >1 line matches, or a unique match with a mismatched subject →
        // flag NOTHING (conservative: only an exact, subject-consistent, single
        // match is trustworthy — SM4 / SM5 / SM7 + the Class-B subject gate).
    }
}

/// RESET-then-REAFFIRM the per-node `rustc_flagged_dead` bits from a fresh
/// oracle outcome — the INCREMENTAL-staleness fix (OQ-ORACLE-INCREMENTAL-STALE,
/// part a2).
///
/// [`apply_oracle`] alone is SET-ONLY / additive: it only ever writes `true`, so
/// a stale flag carried over on an unchanged-file node (a symbol that has SINCE
/// gained a caller) can never clear on an incremental reindex — the false
/// `SafeDelete` this leg closes. This entry is the reset-gated reaffirm:
///   * [`OracleOutcome::Ran`] — the clippy build SUCCEEDED, so the diag set is
///     the complete current truth. RESET every node's `rustc_flagged_dead` to
///     `false`, THEN re-apply the fresh diags via the existing set-only
///     [`apply_oracle`]. A node absent from the fresh set is correctly cleared;
///     a still-genuinely-dead node is re-affirmed `true`.
///   * [`OracleOutcome::Degraded`] — the build did NOT succeed; the set is
///     untrustworthy. Leave EVERY bit UNCHANGED (preserve the graceful-degrade
///     contract). The store-level `oracle_ran_ok` backstop then downgrades any
///     surviving stale `SafeDelete` on a degraded incremental.
///
/// # Reset scope
/// The reset is WHOLE-GRAPH because the Phase-8e clippy run is WHOLE-WORKSPACE
/// (`cargo clippy --all-targets --all-features` in the repo root, NO `-p`
/// scoping — see [`run_cargo_clippy`]), so the `Ran` diag set covers every
/// crate: a genuinely-dead symbol in ANY crate is re-affirmed. If the runner
/// were ever scoped to changed crates, this reset MUST scope to match, else it
/// would wipe unchanged-crate flags absent from a scoped diag set.
///
/// # Full vs incremental
/// On a `--full` index every node is freshly extracted with
/// `rustc_flagged_dead == false`, so the reset is a no-op and the behavior is
/// byte-identical to the prior additive apply — the fix is inert on the shielded
/// full path and only changes the incremental carryover case.
pub fn reaffirm_oracle(graph: &mut KnowledgeGraph, outcome: &OracleOutcome, repo_root: &Path) {
    match outcome {
        OracleOutcome::Ran(diags) => {
            // Reset every flag FIRST (collect ids to avoid a borrow conflict with
            // the mutable per-node write), then re-affirm from the fresh set.
            let ids: Vec<Uuid> = graph.all_nodes().into_iter().map(|n| n.memory_id).collect();
            for id in ids {
                if let Some(node) = graph.node_mut(&id) {
                    node.rustc_flagged_dead = false;
                    // WU-0016 Leg F: the receipt is a COMPANION to the flag — clear
                    // it wherever the flag is cleared, else a re-affirm that OMITS a
                    // node (it gained a caller) would leave a stale receipt behind.
                    // `apply_oracle` below re-stamps a FRESH receipt for every node
                    // still in the fresh diag set.
                    node.oracle_receipt = None;
                }
            }
            apply_oracle(graph, diags, repo_root);
        }
        // Degraded → preserve every existing bit (graceful-degrade contract).
        OracleOutcome::Degraded => {}
    }
}

/// Collect dead-code diagnostics for a repo via an injectable `runner`.
///
/// The IMPURE half of the oracle: it drives the (possibly real) clippy runner
/// and parses its output. The `runner` seam lets tests feed `Err(Timeout)`,
/// `Err(NotCargo)`, or an empty/degenerate stream WITHOUT a real clippy, so the
/// graceful-degrade contract (`GD1`/`GD3`) is unit-testable. A runner `Err`
/// propagates here; the caller (the index pipeline) treats ANY `Err` as an
/// absent oracle (log + empty), never a crash.
pub fn collect_dead_diagnostics<R>(
    repo_root: &Path,
    timeout: Duration,
    runner: R,
) -> Result<OracleOutcome, OracleError>
where
    R: Fn(&Path, Duration) -> Result<String, OracleError>,
{
    let json = runner(repo_root, timeout)?;
    // WU-0015 Leg-3b (OQ-ORACLE-COMPILE-SUCCESS-GATE): a clippy run that
    // COMPLETED but did NOT report a successful build (a compile error, an
    // aborted run) yields a PARTIAL / untrustworthy dead-set — a symbol may look
    // "unused" only because a compile error stopped analysis before its use was
    // seen. Signal it as [`OracleOutcome::Degraded`] (part a1) so the caller can
    // distinguish it from an AUTHORITATIVE clean-empty run: a degraded pass
    // PRESERVES existing flags (graceful degrade) and never seeds the Leg-3b
    // SafeDelete conjunction, while a clean run's (possibly empty) set is the
    // complete truth that RESETS-then-reaffirms the flags.
    if !clippy_build_succeeded(&json) {
        return Ok(OracleOutcome::Degraded);
    }
    Ok(OracleOutcome::Ran(parse_clippy_dead_diagnostics(&json)))
}

/// Whether the cargo/clippy `--message-format=json` stream reported a SUCCESSFUL
/// build.
///
/// Line-by-line best-effort (like [`parse_clippy_dead_diagnostics`]): returns
/// `true` IFF some line is a `{"reason":"build-finished","success":true}` object.
/// A malformed / non-JSON line is skipped, never fatal; an absent marker (compile
/// error, aborted, empty stream) returns `false`. Never panics.
pub fn clippy_build_succeeded(json: &str) -> bool {
    for line in json.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        if value.get("reason").and_then(|r| r.as_str()) == Some("build-finished")
            && value.get("success").and_then(serde_json::Value::as_bool) == Some(true)
        {
            return true;
        }
    }
    false
}

/// Collect dead-code diagnostics using the real `cargo clippy` runner
/// ([`run_cargo_clippy`]). Used by the index pipeline (Phase 8e).
pub fn collect_with_default_runner(
    repo_root: &Path,
    timeout: Duration,
) -> Result<OracleOutcome, OracleError> {
    collect_dead_diagnostics(repo_root, timeout, run_cargo_clippy)
}

/// The real runner: spawn `cargo clippy`, capture stdout, and return it.
///
/// Runs `cargo clippy --all-targets --all-features --message-format=json` in
/// `repo_root`. Bounded by `timeout` (a reaper thread + `recv_timeout`; on expiry
/// the child is killed and [`OracleError::Timeout`] is returned). `stderr` is
/// discarded so a full stderr pipe can never deadlock the child.
///
/// Pre-checks for a `Cargo.toml` at the root so a non-cargo repo degrades to
/// [`OracleError::NotCargo`] without even spawning a process. Holds no
/// `unwrap`/`expect` — every failure is a typed `Err`.
pub fn run_cargo_clippy(repo_root: &Path, timeout: Duration) -> Result<String, OracleError> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    if !repo_root.join("Cargo.toml").exists() {
        return Err(OracleError::NotCargo);
    }

    let mut child = Command::new("cargo")
        .args([
            "clippy",
            "--all-targets",
            "--all-features",
            "--message-format=json",
        ])
        .current_dir(repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| OracleError::Spawn(e.to_string()))?;

    let Some(stdout) = child.stdout.take() else {
        // Could not capture stdout — kill and degrade.
        let _ = child.kill();
        let _ = child.wait();
        return Err(OracleError::Runner("clippy stdout pipe unavailable".into()));
    };

    // Drain stdout on a reaper thread so we can bound the wait with recv_timeout.
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut handle = stdout;
        let _ = handle.read_to_string(&mut buf);
        // Receiver may be gone on timeout; ignore send error.
        let _ = tx.send(buf);
    });

    match rx.recv_timeout(timeout) {
        Ok(output) => {
            let _ = child.wait();
            let _ = reader.join();
            Ok(output)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            Err(OracleError::Timeout)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            Err(OracleError::Runner(
                "clippy reader channel disconnected".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_code_family_predicate_boundary() {
        // Retained — `dead_code` ONLY (WU-0016 Class-B narrowing).
        assert!(is_dead_code_family("dead_code"));
        // Dropped — the WHOLE `unused_*` family + the bare `unused` group. These
        // lints fire on local bindings/statements/imports, never a definition
        // item, so a def-line match was only ever a line-collision spoof.
        assert!(!is_dead_code_family("unused"));
        assert!(!is_dead_code_family("unused_variables"));
        assert!(!is_dead_code_family("unused_imports"));
        assert!(!is_dead_code_family("unused_mut"));
        assert!(!is_dead_code_family("unused_assignments"));
        // Dropped — style / clippy / adjacent non-family.
        assert!(!is_dead_code_family("non_snake_case"));
        assert!(!is_dead_code_family("clippy::needless_return"));
        assert!(!is_dead_code_family("unreachable_code"));
    }

    #[test]
    fn relativize_absolute_and_workspace_relative() {
        let root = Path::new("/home/u/repo");
        assert_eq!(
            relativize("/home/u/repo/crates/x/src/a.rs", root, None).as_deref(),
            Some("crates/x/src/a.rs")
        );
        assert_eq!(
            relativize("crates/x/src/a.rs", root, None).as_deref(),
            Some("crates/x/src/a.rs")
        );
    }

    #[test]
    fn relativize_package_relative_joins_package_root() {
        let root = Path::new("/home/u/repo");
        assert_eq!(
            relativize("src/a.rs", root, Some("crates/x")).as_deref(),
            Some("crates/x/src/a.rs")
        );
        // An absolute form with a package_root must not double-prefix.
        assert_eq!(
            relativize("/home/u/repo/crates/x/src/a.rs", root, Some("crates/x")).as_deref(),
            Some("crates/x/src/a.rs")
        );
    }

    #[test]
    fn manifest_to_package_root_resolves_under_repo() {
        let root = Path::new("/home/u/repo");
        assert_eq!(
            manifest_to_package_root("/home/u/repo/crates/x/Cargo.toml", root).as_deref(),
            Some("crates/x")
        );
        // Manifest outside the repo → None.
        assert_eq!(
            manifest_to_package_root("/elsewhere/crates/x/Cargo.toml", root),
            None
        );
    }
}
