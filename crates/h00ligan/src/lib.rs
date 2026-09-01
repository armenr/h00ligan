//! h00ligan: standalone code-intelligence CLI and MCP server.
//!
//! Provides code-intelligence commands (graph inspection, symbol analysis,
//! immutable indexing, and impact analysis) without
//! requiring a running daemon, database service, or embedding model.

use std::{sync::OnceLock, time::Duration};

/// Serialize telemetry durations without discarding sub-millisecond work.
pub(crate) fn duration_milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

/// This h00ligan package's version plus the engine build's Git provenance.
///
/// The engine owns the revision/dirty-state probe because that identity is
/// also persisted with graph classifications. Its SemVer prefix is not the
/// h00ligan component version, though: component releases can advance without
/// publishing every workspace crate. Replacing only that prefix keeps the
/// provenance suffix while making `h00ligan --version`, release tags, and the
/// package manifest agree.
pub fn build_identity() -> &'static str {
    static IDENTITY: OnceLock<String> = OnceLock::new();
    IDENTITY
        .get_or_init(|| {
            compose_build_identity(env!("CARGO_PKG_VERSION"), h00ligan_engine::BUILD_IDENTITY)
        })
        .as_str()
}

fn compose_build_identity(package_version: &str, engine_identity: &str) -> String {
    let provenance = engine_identity
        .split_once('+')
        .map_or("nogit", |(_, suffix)| suffix);
    format!("{package_version}+{provenance}")
}

pub mod binding;
pub mod cli;
pub mod composite_cmd;
pub mod composite_cmd_query;
pub mod error;
pub mod graph_cmd;
pub mod index_cmd;
pub mod ligan_cmd;
mod output;
pub mod product;
pub mod runtime;
pub mod toolchain;
pub mod watch_cmd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_identity_uses_the_component_version_and_engine_provenance() {
        assert_eq!(
            compose_build_identity("9.8.7", "0.1.0+a1b2c3d+dirty"),
            "9.8.7+a1b2c3d+dirty"
        );
        assert_eq!(compose_build_identity("9.8.7", "invalid"), "9.8.7+nogit");
    }

    #[test]
    fn production_build_identity_starts_with_the_ligan_package_version() {
        assert!(
            build_identity().starts_with(concat!(env!("CARGO_PKG_VERSION"), "+")),
            "h00ligan identity must start with its own package version: {}",
            build_identity()
        );
    }

    #[test]
    fn telemetry_milliseconds_preserve_sub_millisecond_work() {
        let measured = duration_milliseconds(Duration::from_micros(125));
        assert!(
            (measured - 0.125).abs() < f64::EPSILON,
            "sub-millisecond telemetry must remain measurable, got {measured}"
        );
    }
}
