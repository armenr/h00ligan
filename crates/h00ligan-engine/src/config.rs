//! Standalone h00ligan project-configuration resolution.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Replace a leading `~/` (or bare `~`) with the current user's home.
pub fn expand_path(path: &str) -> String {
    if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.to_string_lossy().into_owned();
        }
    } else if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest).to_string_lossy().into_owned();
    }
    path.to_owned()
}

/// Code-intelligence publication-data configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GraphConfig {
    /// Directory containing immutable generations and provider caches.
    pub path: Option<String>,
}

/// The complete standalone configuration surface consumed by h00ligan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    pub graph: GraphConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    Project,
    User,
    Defaults,
}

#[derive(Debug, Clone)]
pub struct LoadedEngineConfig {
    pub value: EngineConfig,
    pub source: ConfigSource,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse configuration {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

impl EngineConfig {
    pub fn load_for_root(root: &Path) -> Result<LoadedEngineConfig, ConfigError> {
        let project = root.join(".h00ligan/config.toml");
        if project.exists() {
            return Self::load_path(&project, ConfigSource::Project);
        }
        if let Some(home) = dirs::home_dir() {
            let user = home.join(".h00ligan/config.toml");
            if user.exists() {
                return Self::load_path(&user, ConfigSource::User);
            }
        }
        Ok(LoadedEngineConfig {
            value: Self::default(),
            source: ConfigSource::Defaults,
        })
    }

    fn load_path(path: &Path, source: ConfigSource) -> Result<LoadedEngineConfig, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let value = toml::from_str(&contents).map_err(|error| ConfigError::Parse {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        Ok(LoadedEngineConfig { value, source })
    }
}
