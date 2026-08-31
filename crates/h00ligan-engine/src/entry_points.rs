//! Entry point discovery, dispatched by the workspace's manifest(s).
//!
//! **Rust** (`Cargo.toml` present): parses the workspace + member manifests to
//! discover binary, library, example, bench, integration test, and build script
//! entry points. **Go** (`go.mod` present): walks the module for package
//! directories — `package main` → `Binary`, every other importable package →
//! `LibRoot` (WU-0023 P3b). A repo carrying BOTH yields the union.
//!
//! This is a pure synchronous function — it reads the filesystem directly and is
//! intended to be called from a `spawn_blocking` context.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::code_intel_cargo::{CargoTargetKind, cargo_package_layout};
use crate::code_intel_domain::{
    DocumentMembershipKind, ProjectInventory, ProjectUnit, ProjectUnitId, ProjectUnitKind,
};

/// The kind of entry point discovered from Cargo.toml configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EntryPointKind {
    /// A `[[bin]]` target or default `src/main.rs`.
    Binary,
    /// The `[lib]` target or default `src/lib.rs`.
    LibRoot,
    /// A `[[example]]` target.
    Example,
    /// A `build.rs` build script.
    BuildScript,
    /// A `[[test]]` integration test target.
    IntegrationTest,
    /// A `[[bench]]` benchmark target.
    Bench,
}

impl std::fmt::Display for EntryPointKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binary => write!(f, "bin"),
            Self::LibRoot => write!(f, "lib"),
            Self::Example => write!(f, "example"),
            Self::BuildScript => write!(f, "build"),
            Self::IntegrationTest => write!(f, "test"),
            Self::Bench => write!(f, "bench"),
        }
    }
}

/// A discovered entry point in the workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    /// Target name (e.g. `h00ligan`, `cargo-helper`).
    pub name: String,
    /// What kind of entry point this is.
    pub kind: EntryPointKind,
    /// Absolute path to the source file.
    pub file_path: PathBuf,
    /// The crate this entry point belongs to.
    pub crate_name: String,
}

/// Errors that can occur during entry point discovery.
#[derive(Debug, thiserror::Error)]
pub enum EntryPointError {
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    ParseToml {
        path: String,
        source: toml::de::Error,
    },
    /// The workspace root carries NO manifest this tool can dispatch on.
    ///
    /// Renamed from `NoCargoToml` (2026-07-25): WU-0023 P3b widened the
    /// condition to `Cargo.toml` **OR** `go.mod`, but the variant name and its
    /// message still said "Cargo.toml" only — a surface that reads as
    /// "Rust-only" and demonstrably sent an external consumer to a wrong model
    /// of our capability. The name and the message now state BOTH manifests.
    #[error(
        "workspace root has no supported manifest (need `Cargo.toml` for Rust or `go.mod` for Go)"
    )]
    NoSupportedManifest,
    #[error("project inventory cannot supply reachability entry points: {0}")]
    InvalidProjectInventory(String),
}

/// Result of asking the indexed project inventory for reachability roots.
///
/// An inventory with no project unit owned by a registered reachability
/// classifier is not malformed: its structural source population can still be
/// indexed and queried exactly. `Available` means at least one classifier owns
/// a project unit; its entry-point vector may legitimately be empty.
#[derive(Debug)]
pub struct InventoryReachabilityPlan {
    /// Entry points supplied only by registered reachability-owning units.
    pub entry_points: Vec<EntryPoint>,
    /// Exact indexed documents those units authorize the classifier to judge.
    /// Other registered source remains structural and explicitly unclassified.
    pub classified_documents: Vec<String>,
}

#[derive(Debug)]
pub enum InventoryEntryPointDiscovery {
    Available(InventoryReachabilityPlan),
    Unavailable,
}

/// Discover all entry points in a workspace, dispatched by the manifest(s) it
/// carries (WU-0023 P3b — polyglot entry-point discovery).
///
/// - `Cargo.toml` present → Rust entry points (the existing per-crate walk).
/// - `go.mod` present → Go entry points (`func main` in `package main` → Binary;
///   every other importable package directory → LibRoot).
/// - BOTH present → the UNION (a mixed Rust+Go repo).
/// - NEITHER present → `NoSupportedManifest` (the pre-existing fail-closed
///   contract — the RC4 chokepoint still refuses a manifest-less repo).
///
/// Canonicalizes `workspace_root` so Rust `file_path` values are absolute (they
/// match the absolute paths the Rust extractor once stored). Go `file_path`
/// values are workspace-RELATIVE (matching the relative paths Go nodes carry) —
/// the two branches key on their own paths, so the mixed field is consumed
/// consistently per language.
pub fn discover_entry_points(workspace_root: &Path) -> Result<Vec<EntryPoint>, EntryPointError> {
    let workspace_root = workspace_root
        .canonicalize()
        .map_err(|_| EntryPointError::NoSupportedManifest)?;
    let has_cargo = workspace_root.join("Cargo.toml").exists();
    let has_gomod = workspace_root.join("go.mod").exists();

    // NEITHER manifest → the fail-closed contract holds (unchanged).
    if !has_cargo && !has_gomod {
        return Err(EntryPointError::NoSupportedManifest);
    }

    let mut entry_points = Vec::new();

    if has_cargo {
        discover_rust_entry_points(&workspace_root, &mut entry_points)?;
    }
    if has_gomod {
        discover_go_entry_points(&workspace_root, &mut entry_points);
    }

    Ok(entry_points)
}

/// Discover entry points from the exact project-unit inventory already built
/// for the indexed source population.
///
/// This is the production indexing authority. A repository root does not need
/// to be a language project itself: independent Cargo packages and Go modules
/// may live below it. Only source-owning units represented in `inventory` are
/// considered, so hidden caches, vendored trees, nested modules, and other
/// source-shaped data cannot be pulled into reachability by a second filesystem
/// walk with different exclusion rules.
pub fn discover_entry_points_from_inventory(
    workspace_root: &Path,
    inventory: &ProjectInventory,
) -> Result<InventoryEntryPointDiscovery, EntryPointError> {
    let workspace_root = workspace_root
        .canonicalize()
        .map_err(|_| EntryPointError::NoSupportedManifest)?;
    let mut entry_points = Vec::new();
    let mut supported_units = BTreeSet::<ProjectUnitId>::new();

    for unit in &inventory.project_topology.units {
        match (unit.language_id.0.as_str(), unit.kind) {
            ("rust", ProjectUnitKind::Package) => {
                supported_units.insert(unit.project_unit_id.clone());
                discover_inventory_rust_package(&workspace_root, unit, &mut entry_points)?;
            }
            ("go", ProjectUnitKind::Module) => {
                supported_units.insert(unit.project_unit_id.clone());
                discover_inventory_go_module(&workspace_root, inventory, unit, &mut entry_points)?;
            }
            _ => {}
        }
    }

    if supported_units.is_empty() {
        return Ok(InventoryEntryPointDiscovery::Unavailable);
    }

    let classified_documents = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.kind == DocumentMembershipKind::SourceOwner
                && supported_units.contains(&membership.project_unit_id)
        })
        .map(|membership| membership.document_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    entry_points.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.crate_name.cmp(&right.crate_name))
    });
    entry_points.dedup_by(|left, right| {
        left.kind == right.kind
            && left.file_path == right.file_path
            && left.name == right.name
            && left.crate_name == right.crate_name
    });
    Ok(InventoryEntryPointDiscovery::Available(
        InventoryReachabilityPlan {
            entry_points,
            classified_documents,
        },
    ))
}

fn discover_inventory_rust_package(
    workspace_root: &Path,
    unit: &ProjectUnit,
    entry_points: &mut Vec<EntryPoint>,
) -> Result<(), EntryPointError> {
    let manifest_path = unit.manifest_path.as_deref().ok_or_else(|| {
        EntryPointError::InvalidProjectInventory(format!(
            "Rust package {} has no manifest path",
            unit.project_unit_id
        ))
    })?;
    let manifest_path = workspace_root.join(manifest_path);
    let contents = read_toml(&manifest_path)?;
    let manifest: toml::Value = parse_toml(&manifest_path, &contents)?;
    let crate_name = manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            EntryPointError::InvalidProjectInventory(format!(
                "Rust package manifest {} has no [package].name",
                manifest_path.display()
            ))
        })?;
    let crate_dir = workspace_root.join(&unit.root_path);
    discover_crate_entry_points(&crate_dir, crate_name, &manifest, entry_points);
    Ok(())
}

fn discover_inventory_go_module(
    workspace_root: &Path,
    inventory: &ProjectInventory,
    unit: &ProjectUnit,
    entry_points: &mut Vec<EntryPoint>,
) -> Result<(), EntryPointError> {
    let manifest_path = unit.manifest_path.as_deref().ok_or_else(|| {
        EntryPointError::InvalidProjectInventory(format!(
            "Go module {} has no manifest path",
            unit.project_unit_id
        ))
    })?;
    let module_root = workspace_root.join(&unit.root_path);
    let module = read_go_module_path(&module_root).ok_or_else(|| {
        EntryPointError::InvalidProjectInventory(format!(
            "Go module manifest {} has no module directive",
            workspace_root.join(manifest_path).display()
        ))
    })?;

    let mut by_dir = std::collections::BTreeMap::<PathBuf, Vec<PathBuf>>::new();
    for membership in &inventory.project_topology.memberships {
        if membership.project_unit_id != unit.project_unit_id
            || membership.language_id.0 != "go"
            || membership.kind != DocumentMembershipKind::SourceOwner
            || Path::new(&membership.document_path)
                .extension()
                .is_none_or(|extension| extension != "go")
        {
            continue;
        }
        let relative = PathBuf::from(&membership.document_path);
        let Some(parent) = relative.parent() else {
            continue;
        };
        by_dir
            .entry(parent.to_path_buf())
            .or_default()
            .push(relative);
    }

    for files in by_dir.values_mut() {
        files.sort();
    }
    for (relative_dir, files) in by_dir {
        let representative = files
            .iter()
            .find(|file| !is_go_test_file(file))
            .or_else(|| files.first());
        let Some(representative) = representative else {
            continue;
        };
        let representative_absolute = workspace_root.join(representative);
        let Some(package) = go_package_clause(&representative_absolute) else {
            continue;
        };

        if package == "main" {
            let main_file = files
                .iter()
                .filter(|file| !is_go_test_file(file))
                .find(|file| go_file_has_func_main(&workspace_root.join(file)))
                .unwrap_or(representative);
            entry_points.push(EntryPoint {
                name: "main".into(),
                kind: EntryPointKind::Binary,
                file_path: main_file.clone(),
                crate_name: module.clone(),
            });
        } else {
            entry_points.push(EntryPoint {
                name: package,
                kind: EntryPointKind::LibRoot,
                file_path: relative_dir,
                crate_name: module.clone(),
            });
        }
    }
    Ok(())
}

/// Discover Rust entry points from the workspace `Cargo.toml` + each member's
/// manifest (the pre-WU-0023 body, extracted behind the manifest dispatch).
fn discover_rust_entry_points(
    workspace_root: &Path,
    entry_points: &mut Vec<EntryPoint>,
) -> Result<(), EntryPointError> {
    let ws_toml_path = workspace_root.join("Cargo.toml");
    let ws_contents = read_toml(&ws_toml_path)?;
    let ws_value: toml::Value = parse_toml(&ws_toml_path, &ws_contents)?;

    let member_dirs = resolve_workspace_members(workspace_root, &ws_value);

    for member_dir in &member_dirs {
        let crate_toml_path = member_dir.join("Cargo.toml");
        if !crate_toml_path.exists() {
            continue;
        }

        let crate_contents = read_toml(&crate_toml_path)?;
        let crate_value: toml::Value = parse_toml(&crate_toml_path, &crate_contents)?;

        let crate_name = crate_value
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_string();

        discover_crate_entry_points(member_dir, &crate_name, &crate_value, entry_points);
    }

    Ok(())
}

/// Discover Go entry points from a `go.mod` module tree (WU-0023 P3b).
///
/// Walks the module for package directories (`.go` files), reads each dir's
/// package clause, and emits:
/// - a `Binary` (pointing at the `.go` FILE that declares `func main`, so
///   [`resolve_production_roots`](crate::reachability) seeds `main` — FMG-1;
///   falls back to a representative file when none declares it) for a
///   `package main` directory;
/// - a `LibRoot` (pointing at the package DIRECTORY, workspace-relative, so
///   [`resolve_pub_api_roots`](crate::reachability) exact-package-dir-matches its
///   exported symbols) for every OTHER importable package directory.
///
/// Skips `vendor/`, `testdata/`, and hidden directories (not first-party API).
/// The importability decision is made HERE, at entry-point time, because the Go
/// package clause is NOT persisted on the node (INDEX-time schema work deferred
/// to the Stage-2 delete WU).
fn discover_go_entry_points(workspace_root: &Path, entry_points: &mut Vec<EntryPoint>) {
    let module = read_go_module_path(workspace_root).unwrap_or_else(|| "go-module".to_string());

    // Group .go files by directory (deterministic order).
    let mut by_dir: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> =
        std::collections::BTreeMap::new();
    collect_go_files(workspace_root, &mut by_dir);

    for (dir, files) in &by_dir {
        // The package clause comes from a representative NON-test .go file (all
        // files in a Go dir share one package). Fall back to any file.
        let repr = files
            .iter()
            .find(|f| !is_go_test_file(f))
            .or_else(|| files.first());
        let Some(repr) = repr else { continue };
        let Some(pkg) = go_package_clause(repr) else {
            continue;
        };

        let rel_dir = dir
            .strip_prefix(workspace_root)
            .unwrap_or(dir)
            .to_path_buf();

        if pkg == "main" {
            // FMG-1 (WU-0024): a `package main` directory can span multiple files
            // (e.g. `main.go` alongside helper files), and the representative
            // above is merely the FIRST non-test file in read-dir order — which
            // may not be the one declaring `func main`. `resolve_production_roots`
            // (reachability.rs) seeds the entry symbol `main` from the SYMBOLS of
            // the file this entry points at; if that file has no `main`, the
            // symbol never resolves and the narrow fallback seeds the wrong
            // file's helpers — leaving the real `main` (and everything only it
            // reaches) false-classified Dead. So seed the Binary from the file
            // that actually declares `func main`, independent of read-dir order.
            // Fall back to `repr` when no non-test file declares `func main`
            // (build-tag-split mains, or a degenerate package) to preserve the
            // prior behavior for that case with no regression.
            let main_file: &Path = files
                .iter()
                .filter(|f| !is_go_test_file(f))
                .find(|f| go_file_has_func_main(f))
                .map(PathBuf::as_path)
                .unwrap_or(repr);
            // A binary: seed the entry symbol (`main`) from the func-main-bearing
            // file (relative path → matches the workspace-relative Go node path).
            let rel_file = main_file
                .strip_prefix(workspace_root)
                .unwrap_or(main_file)
                .to_path_buf();
            entry_points.push(EntryPoint {
                name: "main".to_string(),
                kind: EntryPointKind::Binary,
                file_path: rel_file,
                crate_name: module.clone(),
            });
        } else {
            // An importable library package: its exported top-level identifiers
            // self-seed as PublicApi roots (resolve_pub_api_roots Go branch).
            entry_points.push(EntryPoint {
                name: pkg,
                kind: EntryPointKind::LibRoot,
                file_path: rel_dir,
                crate_name: module.clone(),
            });
        }
    }
}

/// Recursively collect `.go` files under `dir`, grouped by their parent
/// directory. Skips `vendor/`, `testdata/`, and hidden (`.`-prefixed) dirs.
fn collect_go_files(dir: &Path, by_dir: &mut std::collections::BTreeMap<PathBuf, Vec<PathBuf>>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let skip = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "vendor" || n == "testdata" || n.starts_with('.'));
            if !skip {
                collect_go_files(&path, by_dir);
            }
        } else if path.extension().is_some_and(|e| e == "go")
            && let Some(parent) = path.parent()
        {
            by_dir.entry(parent.to_path_buf()).or_default().push(path);
        }
    }
}

/// Read the `module <path>` line from a `go.mod`, if present.
fn read_go_module_path(workspace_root: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(workspace_root.join("go.mod")).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("module ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Parse the `package <name>` clause from a `.go` file (the first non-comment,
/// non-blank `package` line). Robust to leading blank/comment/`//go:build` lines.
fn go_package_clause(file: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(file).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with("/*") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("package ") {
            // `package main // comment` → take the first token.
            return rest.split_whitespace().next().map(str::to_string);
        }
        // The first non-comment line that is NOT a package clause means the file
        // is malformed for our purposes — stop scanning.
        break;
    }
    None
}

/// Return `true` if `file` is a Go test file (`*_test.go`). Test files carry the
/// package's clause but the Go toolchain compiles them only under `go test`, so
/// they are excluded from both package-clause and entry-seed selection.
fn is_go_test_file(file: &Path) -> bool {
    file.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with("_test.go"))
}

/// Return `true` if a `.go` file declares a top-level `func main` (FMG-1 — the
/// func-main-bearing file is the correct `Binary` entry seed for a multi-file
/// `package main`; see [`discover_go_entry_points`]).
///
/// A line-anchored text scan that does NOT parse Go, mirroring the precision of
/// [`go_package_clause`]: a line whose first non-whitespace run is `func main(`.
/// `func mainHelper(` is rejected because the trailing `(` disambiguates `main`
/// from `main`-prefixed identifiers. Robust to leading whitespace, though a
/// package-level `func main` is conventionally unindented. HONEST LIMIT (review
/// NB2): a line INSIDE a `/* … */` block comment or a raw-string literal whose
/// text begins `func main(` DOES match — the scan tracks no comment/string
/// context. Bounded by construction: a false positive can only mis-pick WITHIN
/// the package dir, which is never worse than HEAD's arbitrary read-dir-order
/// pick; a false negative falls back to the representative (HEAD behavior). An
/// unreadable file yields `false` (same fallback).
fn go_file_has_func_main(file: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(file) else {
        return false;
    };
    contents
        .lines()
        .any(|line| line.trim_start().starts_with("func main("))
}

/// Resolve the census member-crate directory set for the root build unit
/// (ADR-0045 D1), canonicalized.
///
/// Returns `Some(dirs)` — the absolute, canonicalized directories of every member
/// crate of the root Cargo workspace, or, for a single-crate / no-`[workspace]`
/// repo, the sole crate root (the **no-workspace fallback**: the containing crate
/// IS the census, so nothing is D1-excluded on the member-boundary ground). A dir
/// that fails to canonicalize (should not happen for a real member) is dropped.
///
/// Returns `None` when the root has no `Cargo.toml` (e.g. a Go-only repo) — D1 is
/// Cargo-workspace-scoped, so the caller disables member-boundary exclusion
/// entirely rather than excluding everything.
///
/// Reads the filesystem (parses `Cargo.toml`, resolves globs), so — like the rest
/// of entry-point discovery — it is FS-coupled and intended to run at INDEX time
/// with the workspace present.
pub fn resolve_census_members(workspace_root: &Path) -> Option<Vec<PathBuf>> {
    let workspace_root = workspace_root.canonicalize().ok()?;
    let ws_toml_path = workspace_root.join("Cargo.toml");
    if !ws_toml_path.exists() {
        return None;
    }
    let ws_contents = read_toml(&ws_toml_path).ok()?;
    let ws_value: toml::Value = parse_toml(&ws_toml_path, &ws_contents).ok()?;
    let members = resolve_workspace_members(&workspace_root, &ws_value);
    // Canonicalize each member dir so a D1 `starts_with` prefix test compares
    // like-for-like against a canonicalized node path.
    Some(
        members
            .iter()
            .filter_map(|m| m.canonicalize().ok())
            .collect(),
    )
}

/// Resolve workspace member directories from the workspace Cargo.toml.
///
/// Handles both explicit member lists and glob patterns like `crates/*`.
fn resolve_workspace_members(workspace_root: &Path, ws_value: &toml::Value) -> Vec<PathBuf> {
    let members = ws_value
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array());

    let Some(members) = members else {
        // Not a workspace — treat the root itself as the single crate.
        return vec![workspace_root.to_path_buf()];
    };

    let mut dirs = Vec::new();

    for member in members {
        let Some(pattern) = member.as_str() else {
            continue;
        };

        if pattern.contains('*') {
            // Simple glob: support `dir/*` by listing the parent directory.
            // This covers the common `members = ["crates/*"]` pattern.
            let base = pattern.trim_end_matches("/*").trim_end_matches("/*");
            let parent = workspace_root.join(base);
            if let Ok(entries) = std::fs::read_dir(&parent) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.join("Cargo.toml").exists() {
                        dirs.push(path);
                    }
                }
            }
        } else {
            let dir = workspace_root.join(pattern);
            if dir.is_dir() {
                dirs.push(dir);
            }
        }
    }

    dirs
}

/// Discover entry points within a single crate.
fn discover_crate_entry_points(
    crate_dir: &Path,
    crate_name: &str,
    crate_value: &toml::Value,
    entry_points: &mut Vec<EntryPoint>,
) {
    entry_points.extend(
        cargo_package_layout(crate_dir, crate_value)
            .targets()
            .iter()
            .map(|target| EntryPoint {
                name: target.name.clone(),
                kind: match target.kind {
                    CargoTargetKind::Library => EntryPointKind::LibRoot,
                    CargoTargetKind::Binary => EntryPointKind::Binary,
                    CargoTargetKind::Example => EntryPointKind::Example,
                    CargoTargetKind::IntegrationTest => EntryPointKind::IntegrationTest,
                    CargoTargetKind::Bench => EntryPointKind::Bench,
                    CargoTargetKind::BuildScript => EntryPointKind::BuildScript,
                },
                file_path: target.source_path.clone(),
                crate_name: crate_name.to_owned(),
            }),
    );
}

fn read_toml(path: &Path) -> Result<String, EntryPointError> {
    std::fs::read_to_string(path).map_err(|e| EntryPointError::ReadFile {
        path: path.display().to_string(),
        source: e,
    })
}

fn parse_toml(path: &Path, contents: &str) -> Result<toml::Value, EntryPointError> {
    toml::from_str(contents).map_err(|e| EntryPointError::ParseToml {
        path: path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_standalone_h00ligan_workspace_entry_points() {
        // Find the workspace root by walking up from the current file.
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let eps = discover_entry_points(&workspace_root).expect("should discover entry points");

        // The standalone workspace must expose the product binary and engine
        // library without relying on any external workspace member.
        assert!(!eps.is_empty(), "should find entry points");

        let binary_names: Vec<&str> = eps
            .iter()
            .filter(|ep| ep.kind == EntryPointKind::Binary)
            .map(|ep| ep.name.as_str())
            .collect();

        assert!(
            binary_names.contains(&"h00ligan"),
            "should find h00ligan binary, found: {binary_names:?}"
        );

        let lib_names: Vec<&str> = eps
            .iter()
            .filter(|ep| ep.kind == EntryPointKind::LibRoot)
            .map(|ep| ep.name.as_str())
            .collect();

        assert!(
            lib_names.contains(&"h00ligan_engine"),
            "should find h00ligan-engine lib, found: {lib_names:?}"
        );
    }

    #[test]
    fn no_cargo_toml_returns_error() {
        let result = discover_entry_points(Path::new("/tmp/nonexistent_h00_test_dir"));
        assert!(result.is_err());
    }

    #[test]
    fn entry_point_kind_serialization_roundtrip() {
        let ep = EntryPoint {
            name: "test_bin".to_string(),
            kind: EntryPointKind::Binary,
            file_path: PathBuf::from("src/main.rs"),
            crate_name: "test_crate".to_string(),
        };
        let json = serde_json::to_string(&ep).expect("serialize");
        let deser: EntryPoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.name, "test_bin");
        assert_eq!(deser.kind, EntryPointKind::Binary);
    }

    /// FMG-1 fixture: a Go module with ONE `package main` directory that spans
    /// two non-test files — `main.go` (declares `func main`) and `format.go`
    /// (helpers only). Files are written main-first / format-last so that on a
    /// reverse-insertion tmpfs `read_dir` yields `format.go` FIRST; `format.go`
    /// also sorts before `main.go` alphabetically, so a name-ordered filesystem
    /// likewise makes `format.go` the read-dir-order representative. Either way
    /// the pre-fix "first non-test file" heuristic picks `format.go` — the file
    /// WITHOUT `func main` — which is the bug.
    fn write_go_main_multifile_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("create temp go module");
        let root = dir.path();
        std::fs::write(root.join("go.mod"), "module example.com/app\n\ngo 1.22\n")
            .expect("write go.mod");
        let pkg = root.join("cmd/app");
        std::fs::create_dir_all(&pkg).expect("mkdir cmd/app");
        // main.go FIRST so reverse-insertion read_dir reads it LAST.
        std::fs::write(
            pkg.join("main.go"),
            "package main\n\nfunc main() {\n\tformat()\n}\n",
        )
        .expect("write main.go");
        // format.go LAST → read FIRST → the arbitrary representative on HEAD.
        std::fs::write(
            pkg.join("format.go"),
            "package main\n\nfunc format() string {\n\treturn \"x\"\n}\n",
        )
        .expect("write format.go");
        // Review NB2 hardening (order-determinism of the RED-on-HEAD power): the
        // pre-fix pick is "first non-test file in read-dir order", an order this
        // test cannot control. Bracket main.go from BOTH ends — helpers that sort
        // alphabetically FIRST (aaa_) and LAST (zzz_), written around it so
        // insertion-order filesystems in either direction ALSO front a helper.
        // With 3 helper files to 1 main.go, every common read_dir order
        // (alphabetical, insertion, reverse-insertion) yields a helper first, so
        // the HEAD heuristic deterministically mis-picks and the falsifier's red
        // is order-independent in practice (a hash-ordered fs retains a 1-in-4
        // residual — recorded, not hidden).
        std::fs::write(
            pkg.join("aaa_helpers.go"),
            "package main\n\nfunc aaaHelper() string {\n\treturn \"a\"\n}\n",
        )
        .expect("write aaa_helpers.go");
        std::fs::write(
            pkg.join("zzz_helpers.go"),
            "package main\n\nfunc zzzHelper() string {\n\treturn \"z\"\n}\n",
        )
        .expect("write zzz_helpers.go");
        dir
    }

    /// FMG-1 falsifier: for a multi-file `package main`, the discovered `Binary`
    /// entry must point at the file that declares `func main` (`main.go`), NOT the
    /// arbitrary read-dir-order representative. RED on HEAD (pre-fix): discovery
    /// seeds the Binary from `format.go` (the first non-test file in read-dir
    /// order), whose symbols contain no `main`, so `resolve_production_roots`
    /// (reachability.rs) fails to seed the real entry and the whole
    /// main-reachable subgraph false-classifies Dead. GREEN after: the func-main
    /// text-scan selects `main.go` regardless of read-dir order.
    #[test]
    fn go_multifile_main_seeds_func_main_file() {
        let dir = write_go_main_multifile_fixture();
        let eps = discover_entry_points(dir.path()).expect("discover go entry points");

        let bins: Vec<&EntryPoint> = eps
            .iter()
            .filter(|ep| ep.kind == EntryPointKind::Binary)
            .collect();
        assert_eq!(
            bins.len(),
            1,
            "exactly one Go binary entry expected, got: {bins:?}"
        );
        assert_eq!(
            bins[0].file_path.file_name().and_then(|n| n.to_str()),
            Some("main.go"),
            "Binary entry must point at the func-main-bearing file, got: {:?}",
            bins[0].file_path
        );
    }

    /// FMG-1 ablation fixture: a `package main` directory whose ONLY non-test
    /// file declares NO `func main` (`helpers.go`). The func-main scan finds
    /// nothing and MUST fall back to the read-dir representative — preserving the
    /// pre-fix behavior for this degenerate case (build-tag-split mains, or a
    /// package with no compilable main) with no regression.
    fn write_go_main_no_func_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("create temp go module");
        let root = dir.path();
        std::fs::write(
            root.join("go.mod"),
            "module example.com/nomain\n\ngo 1.22\n",
        )
        .expect("write go.mod");
        let pkg = root.join("cmd/tool");
        std::fs::create_dir_all(&pkg).expect("mkdir cmd/tool");
        // Single non-test file, so the representative is unambiguous.
        std::fs::write(
            pkg.join("helpers.go"),
            "package main\n\nfunc helper() int {\n\treturn 0\n}\n",
        )
        .expect("write helpers.go");
        dir
    }

    /// FMG-1 regression guard (declared-green on HEAD and after): when no
    /// non-test file declares `func main`, the func-main scan yields nothing and
    /// the Binary must still be emitted at the representative file — the fix must
    /// not drop or mis-seed the degenerate no-`main` package.
    #[test]
    fn go_main_no_func_falls_back_to_representative() {
        let dir = write_go_main_no_func_fixture();
        let eps = discover_entry_points(dir.path()).expect("discover go entry points");

        let bins: Vec<&EntryPoint> = eps
            .iter()
            .filter(|ep| ep.kind == EntryPointKind::Binary)
            .collect();
        assert_eq!(
            bins.len(),
            1,
            "exactly one Go binary entry expected, got: {bins:?}"
        );
        assert_eq!(
            bins[0].file_path.file_name().and_then(|n| n.to_str()),
            Some("helpers.go"),
            "fallback must point at the representative file, got: {:?}",
            bins[0].file_path
        );
    }
}
