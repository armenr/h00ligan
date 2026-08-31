//! Build-time provenance and exact classifier-content identity.
//!
//! # Why this exists (ADR-0046 D2)
//!
//! The classification stamp has to answer "which binary produced these
//! reachability classes?". `CARGO_PKG_VERSION` cannot answer it: every crate in
//! this workspace is pinned `0.1.0` statically, so a version-only identity could
//! not have distinguished the pre-/post-FMG-1 binaries in the very incident that
//! motivated the stamp. A provenance stamp that cannot fire is vacuous by
//! construction, so the identity carries the git commit as well.
//!
//! Emits `H00_BUILD_IDENTITY` in the form:
//!
//! ```text
//! 0.1.0+a1b2c3d          clean build at commit a1b2c3d
//! 0.1.0+a1b2c3d+dirty    uncommitted changes present at build time
//! 0.1.0+nogit            git unavailable / not a repository
//! ```
//!
//! # Build provenance and machine authority are separate
//!
//! Two of the three build-provenance forms cannot pin a source tree:
//!
//! - `+dirty` is a BOOLEAN, not a content hash: two different uncommitted trees
//!   at the same base commit stamp identically.
//! - `+nogit` degenerates to `CARGO_PKG_VERSION`, which is statically `0.1.0`
//!   for every crate here — so EVERY git-less build of EVERY revision stamps the
//!   same string. That is verbatim the version-only identity ADR-0046 rejected
//!   as "vacuous by construction".
//!
//! They remain useful, honest human provenance, but they do not decide whether
//! persisted classifications are current. `H00_INDEXER_IDENTITY` separately
//! hashes the exact source/configuration closure that changes structural
//! extraction and reachability classification. Machine currency compares that
//! digest; a dirty tree can therefore certify its own exact indexed content
//! without pretending the word `dirty` is an identity.
//!
//! # Re-run granularity — it UNDER-fires AND it OVER-fires (disclosed, not hidden)
//!
//! This script watches `.git/HEAD` and the packed/loose ref files below, in
//! addition to Cargo's default (re-run whenever any `h00ligan-engine` file changes).
//! Both known inaccuracies are stated, because the second one is the more
//! dangerous and the first cut of this comment omitted it entirely:
//!
//! **UNDER-fire.** A commit touching no `h00ligan-engine` file and no watched ref
//! leaves the embedded SHA lagging. Benign in direction: writer and reader read
//! the same embedded constant, so a lagging SHA makes two binaries SHARE one
//! identity rather than manufacturing a false mismatch.
//!
//! **OVER-fire.** The dirty flag is sampled at build time. Build with a dirty
//! tree, commit, then rebuild without touching `h00ligan-engine`: Cargo could retain
//! stale human provenance. The `rerun-if-changed` entries on `.git/HEAD` and
//! its ref cut that case. This no longer affects classification currency, but
//! `--version` should still describe the artifact honestly.
//!
//! What that still does not catch: an unstaged edit to a tracked file (no ref
//! moves, so a clean-built binary keeps reading clean until something in this
//! crate changes). That residual is the UNDER-fire direction — the safe one.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "build_support/indexer_identity.rs"]
mod indexer_identity_digest;

fn main() {
    watch_git_refs();
    println!("cargo:rerun-if-env-changed=H00_BUILD_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=H00_BUILD_SOURCE_DIRTY");
    println!(
        "cargo:rustc-env=H00_BUILD_IDENTITY={}",
        build_identity(env!("CARGO_PKG_VERSION"))
    );
    println!(
        "cargo:rustc-env=H00_INDEXER_IDENTITY={}",
        indexer_identity().unwrap_or_else(|| "unavailable".into())
    );
}

/// Deterministic digest of the Rust source/configuration closure that can
/// change structural extraction or reachability classification.
///
/// This is deliberately separate from `H00_BUILD_IDENTITY`: Git provenance is
/// useful to a human, but `dirty` is not a machine identity. Classification
/// currency and structural-provider reuse key on this exact content digest.
fn indexer_identity() -> Option<String> {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    let root = manifest.parent()?.parent()?;
    let mut files = Vec::new();
    for relative in [
        "Cargo.lock",
        "Cargo.toml",
        "rust-toolchain.toml",
        "crates/h00ligan-engine/Cargo.toml",
        "crates/h00ligan-engine/build.rs",
        "crates/h00ligan-engine/build_support",
        "crates/h00ligan-engine/src",
    ] {
        collect_files(&root.join(relative), &mut files)?;
    }
    files.sort();
    files.dedup();

    println!("cargo:rerun-if-env-changed=TARGET");
    let target = std::env::var("TARGET").unwrap_or_default();
    let mut features = std::env::vars()
        .filter(|(key, _)| key.starts_with("CARGO_FEATURE_"))
        .collect::<Vec<_>>();
    features.sort();
    let mut inputs = Vec::with_capacity(files.len());
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let relative = path.strip_prefix(root).ok()?.to_path_buf();
        let bytes = std::fs::read(&path).ok()?;
        inputs.push((relative, bytes));
    }
    Some(indexer_identity_digest::calculate(
        &target, &features, &inputs,
    ))
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> Option<()> {
    if path.is_file() {
        files.push(path.to_path_buf());
        return Some(());
    }
    let mut entries = std::fs::read_dir(path)
        .ok()?
        .map(|entry| entry.ok())
        .collect::<Option<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        if entry.file_type().ok()?.is_dir() {
            collect_files(&path, files)?;
        } else if entry.file_type().ok()?.is_file() {
            files.push(path);
        }
    }
    Some(())
}

/// Ask Cargo to re-run this script when the checked-out commit moves.
///
/// The point is the OVER-fire cut documented above: without it, a binary built
/// from a dirty tree keeps stamping `+dirty` after you commit, and the currency
/// gate exits UNKNOWN indefinitely on a clean tree. Committing writes `.git/HEAD`
/// (or the ref it points at, or `packed-refs`), so watching those re-runs this
/// script and clears the flag.
///
/// Best-effort by design: a missing `.git` (tarball build) simply registers
/// nothing extra and falls back to Cargo's default granularity. Registering a
/// nonexistent path is also fine — Cargo re-runs if it later appears.
fn watch_git_refs() {
    let Some((git_dir, common_dir)) = locate_git_dirs() else {
        return;
    };

    // HEAD is PER-WORKTREE — it lives in the worktree's own gitdir.
    let head_path = git_dir.join("HEAD");
    watch_if_present(&head_path);
    // Refs and packed-refs live in the COMMON dir and are SHARED across
    // worktrees. Watching them under the worktree gitdir was wrong: MEASURED in
    // this repo's own worktree, 2 of 3 such paths do not exist there
    // (`refs/heads/<branch>` and `packed-refs` resolve into `.git/`, not
    // `.git/worktrees/<name>/`), so the commit this exists to notice would have
    // moved a file nobody was watching — and the missing paths would have made
    // Cargo re-run the script on every single build for good measure.
    watch_if_present(&common_dir.join("packed-refs"));
    if let Ok(head) = std::fs::read_to_string(&head_path)
        && let Some(rel) = head.trim().strip_prefix("ref: ")
    {
        watch_if_present(&common_dir.join(rel));
    }
}

/// Register a `rerun-if-changed` only for a path that EXISTS.
///
/// Cargo treats a registered path that is absent as perpetually changed, which
/// re-runs the build script on every build. That is not a correctness problem
/// here (this script only shells out to git twice) but it is a silent,
/// unexplained rebuild cost, and it hides the fact that the path was wrong.
fn watch_if_present(p: &std::path::Path) {
    if p.exists() {
        println!("cargo:rerun-if-changed={}", p.display());
    }
}

/// Resolve `(gitdir, commondir)` for this crate.
///
/// They are the SAME directory in an ordinary checkout and DIFFERENT in a linked
/// worktree, where `.git` is a FILE containing `gitdir: <path>` and that
/// directory holds a `commondir` pointer to the shared `.git`. Release gates
/// exercise both ordinary checkouts and linked worktrees, so both paths are live
/// product build-authority requirements.
fn locate_git_dirs() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    // crates/h00ligan-engine -> crates -> repo root
    let root = manifest.parent()?.parent()?;
    let dot_git = root.join(".git");

    if dot_git.is_dir() {
        return Some((dot_git.clone(), dot_git));
    }
    if dot_git.is_file() {
        let contents = std::fs::read_to_string(&dot_git).ok()?;
        let git_dir = root.join(contents.trim().strip_prefix("gitdir:")?.trim());
        // `commondir` is relative to the worktree gitdir (typically `../..`).
        let common_dir = std::fs::read_to_string(git_dir.join("commondir"))
            .ok()
            .map_or_else(
                || git_dir.clone(),
                |c| {
                    let p = git_dir.join(c.trim());
                    p.canonicalize().unwrap_or(p)
                },
            );
        return Some((git_dir, common_dir));
    }
    None
}

/// Compose `{version}+{short-sha}[+dirty]`, degrading to `{version}+nogit` when
/// git cannot answer.
fn build_identity(version: &str) -> String {
    if let Some(identity) = supplied_build_identity(version) {
        return identity;
    }
    git_short_sha().map_or_else(
        // Graceful fallback: a source tarball, a vendored build, or no git on
        // PATH. `nogit` is a legible marker that the CONSUMER treats as
        // APPROXIMATE (never a clean match) — NOT an empty string that would
        // read as "no provenance recorded", and NOT a self-matching identity.
        //
        // An earlier version of this comment claimed `nogit` was "deliberately
        // non-matching" while nothing enforced that: `0.1.0+nogit` matched
        // itself, so a nogit-stamped store read by a nogit binary CERTIFIED.
        // The non-matching property lives in `ClassifiedBy::approximation` and
        // is proven by
        // `currency_form7_nogit_never_certifies_even_when_strings_are_equal`.
        || format!("{version}+nogit"),
        |sha| {
            let suffix = if git_tree_is_dirty() { "+dirty" } else { "" };
            format!("{version}+{sha}{suffix}")
        },
    )
}

/// Accept typed source provenance from the product builder when the compiled
/// crates live in a verified, self-contained source snapshot rather than a Git
/// worktree. A Git checkout reports `git:<commit>` plus its dirty bit; a
/// Git-less source distribution reports `tree:<sha256>` and therefore needs no
/// lossy dirty approximation.
fn supplied_build_identity(version: &str) -> Option<String> {
    let revision = match std::env::var("H00_BUILD_SOURCE_REVISION") {
        Ok(revision) => revision,
        Err(std::env::VarError::NotPresent) => {
            assert!(
                std::env::var_os("H00_BUILD_SOURCE_DIRTY").is_none(),
                "H00_BUILD_SOURCE_DIRTY requires H00_BUILD_SOURCE_REVISION"
            );
            return None;
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("H00_BUILD_SOURCE_REVISION must be UTF-8")
        }
    };
    let dirty = std::env::var("H00_BUILD_SOURCE_DIRTY")
        .expect("H00_BUILD_SOURCE_DIRTY must accompany H00_BUILD_SOURCE_REVISION");
    let lowercase_hex = |value: &str| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if let Some(commit) = revision.strip_prefix("git:") {
        assert!(
            commit.len() == 40 && lowercase_hex(commit),
            "git source revision must contain 40 lowercase hexadecimal characters"
        );
        let suffix = match dirty.as_str() {
            "0" => "",
            "1" => "+dirty",
            _ => panic!("H00_BUILD_SOURCE_DIRTY must be exactly 0 or 1"),
        };
        return Some(format!("{version}+{}{suffix}", &commit[..7]));
    }
    if let Some(tree) = revision.strip_prefix("tree:") {
        assert!(
            tree.len() == 64 && lowercase_hex(tree),
            "tree source revision must contain 64 lowercase hexadecimal characters"
        );
        assert_eq!(
            dirty, "0",
            "an exact source-tree revision cannot also carry a dirty approximation"
        );
        return Some(format!("{version}+tree.{}", &tree[..7]));
    }
    panic!("H00_BUILD_SOURCE_REVISION must be git:<commit> or tree:<sha256>")
}

fn git_short_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if sha.is_empty() { None } else { Some(sha) }
}

/// True when the working tree has ANY uncommitted change (tracked modifications
/// OR untracked files).
///
/// Untracked files count deliberately: a new, uncommitted source file changes
/// what the classifier sees, so treating the tree as clean would be the unsafe
/// direction. A git failure reports `false` here, but that branch is only
/// reachable when `git_short_sha` already succeeded — i.e. git works — so it is
/// not a silent clean-claim over a broken git.
fn git_tree_is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|out| out.status.success() && !out.stdout.is_empty())
        .unwrap_or(false)
}
