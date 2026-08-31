//! Cargo package topology shared by code-intelligence inventory and reachability.
//!
//! Cargo manifests, not ancestor-directory containment, define compilable Rust
//! targets.  Keeping that interpretation here prevents semantic-provider scope
//! and reachability entry points from drifting into two subtly different models.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CargoTargetKind {
    Library,
    Binary,
    Example,
    IntegrationTest,
    Bench,
    BuildScript,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CargoTarget {
    pub name: String,
    pub kind: CargoTargetKind,
    pub source_path: PathBuf,
}

/// The target roots and conservative source domains of one Cargo package.
///
/// `owned_source_domains` contains only Cargo's standard auto-discovery trees.
/// Explicit non-standard target paths are admitted exactly, but do not claim
/// every sibling merely because Rust permits `#[path]` or `include!` to reach
/// arbitrary files.  Those dynamic edges require compiler/provider evidence;
/// false-negative structural ownership is safer than granting false semantic
/// authority.
#[derive(Debug, Clone)]
pub struct CargoPackageLayout {
    targets: Vec<CargoTarget>,
    exact_sources: BTreeSet<PathBuf>,
    owned_source_domains: BTreeSet<PathBuf>,
}

impl CargoPackageLayout {
    #[must_use]
    pub fn targets(&self) -> &[CargoTarget] {
        &self.targets
    }

    #[must_use]
    pub fn owns_document(&self, document: &Path) -> bool {
        self.exact_sources.contains(document)
            || self
                .owned_source_domains
                .iter()
                .any(|domain| document.starts_with(domain))
    }
}

/// Interpret one `[package]` manifest using Cargo's target-discovery rules.
///
/// Paths are absolute or caller-rooted according to `package_root`; no path is
/// canonicalized, so this function neither follows symlinks nor loses the
/// repository-relative identity used by the inventory layer.
#[must_use]
pub fn cargo_package_layout(package_root: &Path, manifest: &toml::Value) -> CargoPackageLayout {
    let package = manifest.get("package").and_then(toml::Value::as_table);
    let package_name = package
        .and_then(|table| table.get("name"))
        .and_then(toml::Value::as_str)
        .unwrap_or("unknown");
    let manual_target_defined = manifest.get("lib").is_some()
        || ["bin", "example", "test", "bench"]
            .into_iter()
            .any(|section| {
                manifest
                    .get(section)
                    .and_then(toml::Value::as_array)
                    .is_some_and(|targets| !targets.is_empty())
            });
    let edition_has_modern_auto_discovery =
        effective_package_edition(package_root, manifest).is_some_and(|edition| edition >= 2018);
    let auto_default = edition_has_modern_auto_discovery || !manual_target_defined;
    let auto_enabled = |key: &str| {
        package
            .and_then(|table| table.get(key))
            .and_then(toml::Value::as_bool)
            .unwrap_or(auto_default)
    };

    let mut targets = BTreeSet::new();
    let mut owned_source_domains = BTreeSet::new();

    if let Some(lib) = manifest.get("lib") {
        let name = lib
            .get("name")
            .and_then(toml::Value::as_str)
            .map_or_else(|| package_name.replace('-', "_"), str::to_owned);
        let source = lib.get("path").and_then(toml::Value::as_str).map_or_else(
            || package_root.join("src/lib.rs"),
            |path| package_root.join(path),
        );
        let conventional_source_domain =
            (source == package_root.join("src/lib.rs")).then_some("src");
        insert_existing_target(
            &mut targets,
            &mut owned_source_domains,
            package_root,
            CargoTarget {
                name,
                kind: CargoTargetKind::Library,
                source_path: source,
            },
            conventional_source_domain,
        );
    } else if auto_enabled("autolib") {
        insert_existing_target(
            &mut targets,
            &mut owned_source_domains,
            package_root,
            CargoTarget {
                name: package_name.replace('-', "_"),
                kind: CargoTargetKind::Library,
                source_path: package_root.join("src/lib.rs"),
            },
            Some("src"),
        );
    }

    insert_array_targets(
        package_root,
        manifest,
        "bin",
        CargoTargetKind::Binary,
        "src/bin",
        package_name,
        &mut targets,
        &mut owned_source_domains,
    );
    insert_array_targets(
        package_root,
        manifest,
        "example",
        CargoTargetKind::Example,
        "examples",
        package_name,
        &mut targets,
        &mut owned_source_domains,
    );
    insert_array_targets(
        package_root,
        manifest,
        "test",
        CargoTargetKind::IntegrationTest,
        "tests",
        package_name,
        &mut targets,
        &mut owned_source_domains,
    );
    insert_array_targets(
        package_root,
        manifest,
        "bench",
        CargoTargetKind::Bench,
        "benches",
        package_name,
        &mut targets,
        &mut owned_source_domains,
    );

    if auto_enabled("autobins") {
        insert_existing_target(
            &mut targets,
            &mut owned_source_domains,
            package_root,
            CargoTarget {
                name: package_name.to_owned(),
                kind: CargoTargetKind::Binary,
                source_path: package_root.join("src/main.rs"),
            },
            Some("src"),
        );
        insert_convention_targets(
            package_root,
            "src/bin",
            CargoTargetKind::Binary,
            &mut targets,
            &mut owned_source_domains,
        );
    }
    for (key, directory, kind) in [
        ("autoexamples", "examples", CargoTargetKind::Example),
        ("autotests", "tests", CargoTargetKind::IntegrationTest),
        ("autobenches", "benches", CargoTargetKind::Bench),
    ] {
        if auto_enabled(key) {
            insert_convention_targets(
                package_root,
                directory,
                kind,
                &mut targets,
                &mut owned_source_domains,
            );
        }
    }

    let build_source = match package.and_then(|table| table.get("build")) {
        Some(value) if value.as_bool() == Some(false) => None,
        Some(value) if value.as_str().is_some() => {
            value.as_str().map(|path| package_root.join(path))
        }
        _ => Some(package_root.join("build.rs")),
    };
    if let Some(source_path) = build_source {
        // A build-script crate root can import package-root siblings.  Admit
        // the root exactly; compiler/provider evidence must establish any such
        // non-standard module edges instead of claiming the whole package.
        insert_existing_target(
            &mut targets,
            &mut owned_source_domains,
            package_root,
            CargoTarget {
                name: "build".into(),
                kind: CargoTargetKind::BuildScript,
                source_path,
            },
            None,
        );
    }

    CargoPackageLayout {
        exact_sources: targets
            .iter()
            .map(|target| target.source_path.clone())
            .collect(),
        targets: targets.into_iter().collect(),
        owned_source_domains,
    }
}

fn effective_package_edition(package_root: &Path, manifest: &toml::Value) -> Option<u16> {
    let edition = manifest
        .get("package")
        .and_then(|package| package.get("edition"))?;
    if let Some(edition) = edition.as_str() {
        return edition.parse().ok();
    }
    if !edition
        .as_table()
        .and_then(|table| table.get("workspace"))
        .and_then(toml::Value::as_bool)
        .is_some_and(|workspace| workspace)
    {
        return None;
    }

    let inherited_edition = |workspace: &toml::Value| {
        workspace
            .get("workspace")
            .and_then(|workspace| workspace.get("package"))
            .and_then(|package| package.get("edition"))
            .and_then(toml::Value::as_str)
            .and_then(|edition| edition.parse().ok())
    };
    if let Some(edition) = inherited_edition(manifest) {
        return Some(edition);
    }
    for ancestor in package_root.ancestors().skip(1) {
        let Ok(contents) = std::fs::read_to_string(ancestor.join("Cargo.toml")) else {
            continue;
        };
        let Ok(workspace) = toml::from_str::<toml::Value>(&contents) else {
            continue;
        };
        if let Some(edition) = inherited_edition(&workspace) {
            return Some(edition);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn insert_array_targets(
    package_root: &Path,
    manifest: &toml::Value,
    section: &str,
    kind: CargoTargetKind,
    conventional_directory: &str,
    package_name: &str,
    targets: &mut BTreeSet<CargoTarget>,
    owned_source_domains: &mut BTreeSet<PathBuf>,
) {
    let Some(configured) = manifest.get(section).and_then(toml::Value::as_array) else {
        return;
    };
    for target in configured {
        let name = target
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or(package_name);
        let source_path = target
            .get("path")
            .and_then(toml::Value::as_str)
            .map_or_else(
                || {
                    package_root
                        .join(conventional_directory)
                        .join(format!("{name}.rs"))
                },
                |path| package_root.join(path),
            );
        let standard_domain = source_path
            .strip_prefix(package_root)
            .ok()
            .and_then(standard_source_domain);
        insert_existing_target(
            targets,
            owned_source_domains,
            package_root,
            CargoTarget {
                name: name.to_owned(),
                kind,
                source_path,
            },
            standard_domain,
        );
    }
}

fn insert_convention_targets(
    package_root: &Path,
    directory: &str,
    kind: CargoTargetKind,
    targets: &mut BTreeSet<CargoTarget>,
    owned_source_domains: &mut BTreeSet<PathBuf>,
) {
    let scan_root = package_root.join(directory);
    let Ok(entries) = std::fs::read_dir(&scan_root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let target =
            if path.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
                let name = path
                    .file_stem()
                    .map(|name| name.to_string_lossy().into_owned());
                name.map(|name| (name, path))
            } else if path.is_dir() && path.join("main.rs").is_file() {
                path.file_name()
                    .map(|name| (name.to_string_lossy().into_owned(), path.join("main.rs")))
            } else {
                None
            };
        if let Some((name, source_path)) = target {
            insert_existing_target(
                targets,
                owned_source_domains,
                package_root,
                CargoTarget {
                    name,
                    kind,
                    source_path,
                },
                Some(directory),
            );
        }
    }
}

fn insert_existing_target(
    targets: &mut BTreeSet<CargoTarget>,
    owned_source_domains: &mut BTreeSet<PathBuf>,
    package_root: &Path,
    target: CargoTarget,
    standard_domain: Option<&str>,
) {
    if !target.source_path.is_file() {
        return;
    }
    if let Some(domain) = standard_domain {
        owned_source_domains.insert(package_root.join(domain));
    }
    targets.insert(target);
}

fn standard_source_domain(path: &Path) -> Option<&'static str> {
    if path.starts_with("src") {
        Some("src")
    } else if path.starts_with("examples") {
        Some("examples")
    } else if path.starts_with("tests") {
        Some("tests")
    } else if path.starts_with("benches") {
        Some("benches")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn standard_targets_own_standard_sources_but_not_arbitrary_package_siblings() {
        let temporary = TempDir::new().expect("temporary package");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(root.join("providers")).expect("provider directory");
        std::fs::write(root.join("src/lib.rs"), "mod child;\n").expect("library root");
        std::fs::write(root.join("src/child.rs"), "pub fn child() {}\n").expect("module");
        std::fs::write(root.join("providers/template.rs"), "pub fn template() {}\n")
            .expect("loose template");
        let manifest: toml::Value = toml::from_str(
            "[package]\nname = \"layout\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");

        let layout = cargo_package_layout(root, &manifest);
        assert!(layout.owns_document(&root.join("src/lib.rs")));
        assert!(layout.owns_document(&root.join("src/child.rs")));
        assert!(!layout.owns_document(&root.join("providers/template.rs")));
        assert_eq!(layout.targets().len(), 1, "positive target census control");
    }

    /// RIGHT-REASON REGRESSION: `[lib]` may add target metadata such as
    /// `proc-macro = true` without changing Cargo's conventional `src/lib.rs`
    /// module domain. Only an actually nonstandard `path` narrows ownership to
    /// the exact target file.
    #[test]
    fn explicit_standard_library_metadata_retains_the_src_module_domain() {
        let temporary = TempDir::new().expect("temporary package");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(root.join("src/lib.rs"), "mod helper;\n").expect("library root");
        std::fs::write(root.join("src/helper.rs"), "pub fn helper() {}\n").expect("library module");
        let manifest: toml::Value = toml::from_str(
            "[package]\nname = \"macros\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\nproc-macro = true\n",
        )
        .expect("manifest");

        let layout = cargo_package_layout(root, &manifest);
        assert!(layout.owns_document(&root.join("src/lib.rs")));
        assert!(
            layout.owns_document(&root.join("src/helper.rs")),
            "ordinary modules remain owned when `[lib]` only changes target metadata"
        );
    }

    #[test]
    fn auto_discovery_controls_and_custom_targets_are_respected() {
        let temporary = TempDir::new().expect("temporary package");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src/bin/tool")).expect("binary directories");
        std::fs::create_dir_all(root.join("custom")).expect("custom target directory");
        std::fs::write(root.join("src/lib.rs"), "pub fn disabled() {}\n")
            .expect("disabled auto lib");
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("disabled auto bin");
        std::fs::write(root.join("src/bin/tool/main.rs"), "fn main() {}\n")
            .expect("disabled nested auto bin");
        std::fs::write(root.join("custom/entry.rs"), "fn main() {}\n").expect("explicit target");
        std::fs::write(root.join("custom/template.rs"), "fn template() {}\n")
            .expect("custom sibling");
        std::fs::write(root.join("build.rs"), "fn main() {}\n").expect("disabled build");
        let manifest: toml::Value = toml::from_str(
            r#"
                [package]
                name = "layout"
                version = "0.1.0"
                edition = "2024"
                autolib = false
                autobins = false
                build = false

                [[bin]]
                name = "explicit"
                path = "custom/entry.rs"
            "#,
        )
        .expect("manifest");

        let layout = cargo_package_layout(root, &manifest);
        assert_eq!(
            layout
                .targets()
                .iter()
                .map(|target| (target.kind, target.name.as_str()))
                .collect::<Vec<_>>(),
            vec![(CargoTargetKind::Binary, "explicit")]
        );
        assert!(layout.owns_document(&root.join("custom/entry.rs")));
        for loose in [
            "src/lib.rs",
            "src/main.rs",
            "src/bin/tool/main.rs",
            "custom/template.rs",
            "build.rs",
        ] {
            assert!(!layout.owns_document(&root.join(loose)), "{loose}");
        }
    }

    #[test]
    fn workspace_inherited_edition_preserves_modern_auto_discovery() {
        let temporary = TempDir::new().expect("temporary workspace");
        let root = temporary.path();
        let member = root.join("member");
        std::fs::create_dir_all(member.join("src")).expect("member source directory");
        std::fs::create_dir_all(member.join("tools")).expect("manual target directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n\n[workspace.package]\nedition = \"2024\"\n",
        )
        .expect("workspace manifest");
        std::fs::write(member.join("src/lib.rs"), "pub fn library() {}\n").expect("auto library");
        std::fs::write(member.join("tools/manual.rs"), "fn main() {}\n").expect("manual binary");
        let manifest: toml::Value = toml::from_str(
            r#"
                [package]
                name = "member"
                version = "0.1.0"
                edition.workspace = true

                [[bin]]
                name = "manual"
                path = "tools/manual.rs"
            "#,
        )
        .expect("member manifest");

        let layout = cargo_package_layout(&member, &manifest);
        assert_eq!(
            layout
                .targets()
                .iter()
                .map(|target| target.kind)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([CargoTargetKind::Library, CargoTargetKind::Binary])
        );
    }
}
