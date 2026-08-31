/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, bail};
use pyrefly_build::handle::Handle;
use pyrefly_config::args::ConfigOverrideArgs;
use pyrefly_config::config::ConfigSource;
use pyrefly_config::finder::ConfigError;
use pyrefly_python::module_path::ModulePath;
use pyrefly_util::thread_pool::ThreadCount;

use crate::commands::check::Handles;
use crate::commands::config_finder::default_config_finder_with_overrides_bounded;
use crate::report::glean::convert::h00_semantic_facts;
pub use crate::report::glean::convert::{
    H00ByteSpan, H00DeclarationFact, H00DeclarationKind, H00ReferenceFact, H00SemanticFacts,
};
use crate::state::load::FileContents;
use crate::state::require::Require;
use crate::state::state::State;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct H00ModuleBinding {
    pub path: PathBuf,
    pub module_name: String,
    pub fallback_name: bool,
    pub python_version: String,
    pub python_platform: String,
    pub type_checking: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct H00ConfigurationBinding {
    pub source_path: Option<PathBuf>,
    pub root: Option<PathBuf>,
    pub explicit_search_paths: Vec<PathBuf>,
    pub heuristic_search_paths: Vec<PathBuf>,
    pub site_package_paths: Vec<PathBuf>,
    pub custom_typeshed_path: Option<PathBuf>,
    pub source_database_enabled: bool,
    pub build_system_enabled: bool,
    pub fallback_search_path_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H00AuthorityFacts {
    pub modules: Vec<H00ModuleBinding>,
    pub configurations: Vec<H00ConfigurationBinding>,
}

/// Persistent solved Pyrefly state owned by one h00ligan provider root session.
pub struct H00SemanticSession {
    state: State,
    handles: BTreeMap<PathBuf, Handle>,
}

impl H00SemanticSession {
    pub fn open(
        repository_root: &Path,
        files: impl IntoIterator<Item = (PathBuf, String)>,
    ) -> anyhow::Result<Self> {
        let repository_root = std::fs::canonicalize(repository_root).with_context(|| {
            format!(
                "canonicalize Pyrefly repository root {}",
                repository_root.display()
            )
        })?;
        let files = files
            .into_iter()
            .map(|(path, source)| {
                let canonical = std::fs::canonicalize(&path).with_context(|| {
                    format!("canonicalize admitted Python source {}", path.display())
                })?;
                if !canonical.starts_with(&repository_root) {
                    bail!("admitted Python source escapes the repository root");
                }
                Ok((canonical, source))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if files.is_empty() {
            bail!("Pyrefly session source population is empty");
        }
        let config_finder = default_config_finder_with_overrides_bounded(
            ConfigOverrideArgs::without_interpreter_query(),
            false,
            None,
            repository_root,
        );
        let state = State::new(config_finder, ThreadCount::AllThreads);
        let source_handles = Handles::new(files.iter().map(|(path, _)| path.clone()));
        let (filesystem_handles, reloaded_configs, config_errors) =
            source_handles.all(state.config_finder());
        if !config_errors.is_empty() {
            let messages = config_errors
                .iter()
                .map(ConfigError::get_message)
                .collect::<Vec<_>>()
                .join("; ");
            bail!("Pyrefly source database configuration failed: {messages}");
        }
        if filesystem_handles.len() != files.len() {
            bail!(
                "Pyrefly loaded {} handles for {} admitted sources",
                filesystem_handles.len(),
                files.len()
            );
        }
        // h00ligan owns source bytes without mutating the user's worktree. Pyrefly's
        // memory overlay invalidates only `ModulePath::Memory` handles; keeping
        // the discovery-time filesystem handles would make later epochs reread
        // unchanged disk bytes and silently retain stale semantic facts.
        let loaded = filesystem_handles
            .into_iter()
            .map(|handle| {
                Handle::from_with_module_name_kind(
                    handle.module_kind(),
                    ModulePath::memory(handle.path().as_path().to_path_buf()),
                    handle.sys_info().clone(),
                )
            })
            .collect::<Vec<_>>();

        let mut transaction = state.new_committable_transaction(Require::Everything, None);
        transaction
            .as_mut()
            .invalidate_find_for_configs(reloaded_configs);
        transaction.as_mut().set_memory(
            files
                .iter()
                .map(|(path, source)| {
                    (
                        path.clone(),
                        Some(Arc::new(FileContents::from_source(source.clone()))),
                    )
                })
                .collect(),
        );
        transaction.as_mut().run(&loaded, Require::Everything, None);
        state.commit_transaction(transaction, None);

        let mut handles = BTreeMap::new();
        for handle in loaded {
            let path = handle.path().as_path().to_path_buf();
            if handles.insert(path.clone(), handle).is_some() {
                bail!("Pyrefly produced a duplicate handle for {}", path.display());
            }
        }
        for (file, _) in files {
            if !handles.contains_key(&file) {
                bail!("Pyrefly omitted admitted source {}", file.display());
            }
        }
        Ok(Self { state, handles })
    }

    pub fn refresh(&self) {
        let handles = self.handles.values().cloned().collect::<Vec<_>>();
        let mut transaction = self
            .state
            .new_committable_transaction(Require::Everything, None);
        transaction
            .as_mut()
            .run(&handles, Require::Everything, None);
        self.state.commit_transaction(transaction, None);
    }

    pub fn apply(&self, replacements: Vec<(PathBuf, String)>) -> anyhow::Result<()> {
        if replacements.is_empty() {
            bail!("Pyrefly source replacement population is empty");
        }
        let mut memory = Vec::with_capacity(replacements.len());
        for (path, source) in replacements {
            let path = std::fs::canonicalize(&path).with_context(|| {
                format!("canonicalize replaced Python source {}", path.display())
            })?;
            if !self.handles.contains_key(&path) {
                bail!("replacement is outside the admitted Pyrefly source population");
            }
            memory.push((path, Some(Arc::new(FileContents::from_source(source)))));
        }

        let handles = self.handles.values().cloned().collect::<Vec<_>>();
        let mut transaction = self
            .state
            .new_committable_transaction(Require::Everything, None);
        transaction.as_mut().set_memory(memory);
        transaction
            .as_mut()
            .run(&handles, Require::Everything, None);
        self.state.commit_transaction(transaction, None);
        Ok(())
    }

    pub fn facts(&self, file: &Path) -> anyhow::Result<H00SemanticFacts> {
        let file = std::fs::canonicalize(file)
            .with_context(|| format!("canonicalize exported Python source {}", file.display()))?;
        let handle = self.handles.get(&file).with_context(|| {
            format!(
                "source is outside the admitted Pyrefly population: {}",
                file.display()
            )
        })?;
        let transaction = self.state.new_transaction(Require::Everything, None);
        if transaction.get_ast(handle).is_none() {
            bail!("Pyrefly has no solved AST for {}", file.display());
        }
        Ok(h00_semantic_facts(&transaction, handle))
    }

    pub fn authority_facts(&self) -> anyhow::Result<H00AuthorityFacts> {
        let transaction = self.state.new_transaction(Require::Everything, None);
        let mut modules = Vec::with_capacity(self.handles.len());
        let mut configurations = Vec::new();
        for (path, handle) in &self.handles {
            modules.push(H00ModuleBinding {
                path: path.clone(),
                module_name: handle.module().to_string(),
                fallback_name: handle.is_fallback(),
                python_version: handle.sys_info().version().to_string(),
                python_platform: handle.sys_info().platform().to_string(),
                type_checking: handle.sys_info().type_checking(),
            });
            let config = transaction.get_config(handle).with_context(|| {
                format!("Pyrefly has no solved configuration for {}", path.display())
            })?;
            let source_path = match &config.source {
                ConfigSource::File(path)
                | ConfigSource::PythonToolMarker(path)
                | ConfigSource::Marker(path)
                | ConfigSource::FailedParse(path) => Some(path.clone()),
                ConfigSource::Synthetic => None,
            };
            let mut explicit_search_paths =
                config.explicit_search_path().cloned().collect::<Vec<_>>();
            explicit_search_paths.sort();
            explicit_search_paths.dedup();
            let mut heuristic_search_paths =
                config.heuristic_search_path().cloned().collect::<Vec<_>>();
            heuristic_search_paths.sort();
            heuristic_search_paths.dedup();
            let mut site_package_paths = config.site_package_path().cloned().collect::<Vec<_>>();
            site_package_paths.sort();
            site_package_paths.dedup();
            configurations.push(H00ConfigurationBinding {
                source_path,
                root: config.source.root().map(Path::to_path_buf),
                explicit_search_paths,
                heuristic_search_paths,
                site_package_paths,
                custom_typeshed_path: config.typeshed_path.clone(),
                source_database_enabled: config.source_db.is_some(),
                build_system_enabled: config.build_system.is_some(),
                fallback_search_path_enabled: config.enable_fallback_search_path,
            });
        }
        modules.sort();
        configurations.sort();
        configurations.dedup();
        Ok(H00AuthorityFacts {
            modules,
            configurations,
        })
    }

    pub fn source_paths(&self) -> impl Iterator<Item = &Path> {
        self.handles.keys().map(PathBuf::as_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::glean::convert::H00DeclarationKind;

    fn span_text<'a>(
        source: &'a str,
        span: &crate::report::glean::convert::H00ByteSpan,
    ) -> &'a str {
        &source[span.start as usize..(span.start + span.length) as usize]
    }

    #[test]
    fn solved_session_exports_exact_cross_file_facts_and_reuses_state_after_edit() {
        let temporary = tempfile::tempdir().expect("temporary repository");
        let root = temporary.path();
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"h00-pyrefly-proof\"\nversion = \"0.0.0\"\n\n[tool.pyrefly]\n",
        )
        .expect("project configuration");
        let target_path = root.join("target.py");
        let caller_path = root.join("caller.py");
        let target_source = "class Base:\n    def method(self) -> int:\n        return 1\n\ndef target() -> int:\n    return 2\n";
        let caller_source = "from target import Base, target\n\nclass Child(Base):\n    def method(self) -> int:\n        return target()\n\ndef caller() -> int:\n    return target()\n";
        std::fs::write(&target_path, target_source).expect("target source");
        std::fs::write(&caller_path, caller_source).expect("caller source");

        let session = H00SemanticSession::open(
            root,
            [
                (target_path.clone(), target_source.to_owned()),
                (caller_path.clone(), caller_source.to_owned()),
            ],
        )
        .expect("open solved session");
        let target_facts = session.facts(&target_path).expect("target facts");
        let caller_facts = session.facts(&caller_path).expect("caller facts");

        for declaration in target_facts
            .declarations
            .iter()
            .chain(caller_facts.declarations.iter())
        {
            let source = if target_facts.declarations.contains(declaration) {
                target_source
            } else {
                caller_source
            };
            let leaf_name = declaration.name.rsplit('.').next().unwrap();
            assert_eq!(span_text(source, &declaration.name_span), leaf_name);
        }
        let child = caller_facts
            .declarations
            .iter()
            .find(|declaration| declaration.name.ends_with(".Child"))
            .expect("child declaration");
        assert_eq!(child.kind, H00DeclarationKind::Class);
        assert!(child.bases.iter().any(|base| base.ends_with(".Base")));
        assert!(caller_facts.references.iter().any(|reference| {
            reference.target_name.ends_with(".target")
                && span_text(caller_source, &reference.source_span) == "target"
        }));
        let authority = session.authority_facts().expect("authority facts");
        assert_eq!(authority.modules.len(), 2);
        assert!(authority.modules.iter().any(|module| {
            module.module_name == "target"
                && !module.fallback_name
                && module.python_version == "3.13.0"
        }));
        assert_eq!(authority.configurations.len(), 1);
        assert_eq!(
            authority.configurations[0].source_path.as_deref(),
            Some(root.join("pyproject.toml").as_path())
        );
        assert!(authority.configurations[0].site_package_paths.is_empty());

        let edited = caller_source.replace(
            "return target()\n\ndef caller",
            "return target() + 1\n\ndef caller",
        );
        session
            .apply(vec![(caller_path.clone(), edited.clone())])
            .expect("incremental body edit");
        let edited_facts = session.facts(&caller_path).expect("edited caller facts");
        assert!(edited_facts.references.iter().any(|reference| {
            reference.target_name.ends_with(".target")
                && span_text(&edited, &reference.source_span) == "target"
        }));
        assert_eq!(
            session.source_paths().count(),
            2,
            "the edit must reuse the admitted two-file session"
        );
    }

    /// RIGHT-REASON REGRESSION: an h00ligan epoch supplies replacement bytes while
    /// the user's source file remains untouched. The retained Pyrefly session
    /// must therefore solve from its memory-backed handle, remove the old call
    /// target, and expose the new target from the same process.
    #[test]
    fn memory_backed_session_replaces_call_truth_without_mutating_disk() {
        let temporary = tempfile::tempdir().expect("temporary repository");
        let root = temporary.path();
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"h00-pyrefly-memory-proof\"\nversion = \"0.0.0\"\n\n[tool.pyrefly]\n",
        )
        .expect("project configuration");
        let target_path = root.join("target.py");
        let caller_path = root.join("caller.py");
        let target_source =
            "def targetA() -> int:\n    return 1\n\ndef targetB() -> int:\n    return 2\n";
        let caller_before = "from target import targetA, targetB\n\ndef caller() -> int:\n    return targetA()\n";
        let caller_after = caller_before.replace("return targetA()", "return targetB()");
        std::fs::write(&target_path, target_source).expect("target source");
        std::fs::write(&caller_path, caller_before).expect("caller source");

        let session = H00SemanticSession::open(
            root,
            [
                (target_path.clone(), target_source.to_owned()),
                (caller_path.clone(), caller_before.to_owned()),
            ],
        )
        .expect("open memory-backed session");
        let before = session.facts(&caller_path).expect("initial caller facts");
        assert_eq!(
            before
                .references
                .iter()
                .filter(|reference| reference.target_name.ends_with(".targetA"))
                .count(),
            2,
            "initial targetA import plus call positive control"
        );
        assert_eq!(
            before
                .references
                .iter()
                .filter(|reference| reference.target_name.ends_with(".targetB"))
                .count(),
            1,
            "initial targetB import control"
        );

        session
            .apply(vec![(caller_path.clone(), caller_after.clone())])
            .expect("apply in-memory body edit");
        let after = session.facts(&caller_path).expect("changed caller facts");
        assert_eq!(
            after
                .references
                .iter()
                .filter(|reference| reference.target_name.ends_with(".targetA"))
                .count(),
            1,
            "stale targetA call survived the memory epoch"
        );
        assert_eq!(
            after
                .references
                .iter()
                .filter(|reference| reference.target_name.ends_with(".targetB"))
                .count(),
            2,
            "fresh targetB call was not solved"
        );
        assert_eq!(
            std::fs::read_to_string(&caller_path).expect("caller disk bytes"),
            caller_before,
            "Pyrefly session mutated the user's source file"
        );
    }

    #[test]
    fn repository_boundary_excludes_parent_machine_configuration() {
        let temporary = tempfile::tempdir().expect("temporary workspace");
        std::fs::write(
            temporary.path().join("pyrefly.toml"),
            "python-version = \"3.8\"\n",
        )
        .expect("outside configuration");
        let root = temporary.path().join("repo");
        let source_path = root.join("src/main.py");
        std::fs::create_dir_all(source_path.parent().unwrap()).expect("source directory");
        std::fs::write(&source_path, "def current() -> int:\n    return 1\n")
            .expect("source fixture");

        let session = H00SemanticSession::open(
            &root,
            [(source_path, "def current() -> int:\n    return 1\n".into())],
        )
        .expect("bounded session");
        let authority = session.authority_facts().expect("bounded authority");
        assert_eq!(authority.modules.len(), 1, "positive source population");
        assert_ne!(
            authority.modules[0].python_version, "3.8.0",
            "the parent configuration must not select the session Python version"
        );
        assert_eq!(authority.configurations.len(), 1);
        assert_eq!(authority.configurations[0].source_path, None);
    }
}
