//! Shared h00ligan CLI surface and dispatch.
//!
//! One standalone command surface for immutable indexing, bounded queries,
//! MCP, WATCH, and product-owned semantic providers.
//!
//! Build: `cargo build -p h00ligan --bin h00ligan`

use std::path::PathBuf;

use clap::{Parser, Subcommand};

// All handler modules live in the h00ligan library crate.
use crate::composite_cmd::{
    self, AssessArgs, AuditArgs, DeadArgs, InspectArgs, OverviewArgs, TestsArgs,
};
use crate::composite_cmd_query;
use crate::error::LiganError;
use crate::index_cmd::{self, IndexArgs};
use crate::ligan_cmd::{self, CallsArgs, ReadSymbolArgs, TypeArgs};
use crate::watch_cmd::{self, WatchArgs};

/// h00ligan — standalone structural and compiler-backed code intelligence.
///
/// Standalone binary for code-intel operations: immutable indexing,
/// type/symbol/call analysis, and impact analysis.
///
#[derive(Parser, Debug)]
// Bare `version` omits revision provenance. The engine identity has provenance
// but carries h00ligan-engine's package version, which can diverge from component
// releases. `crate::build_identity()` deliberately combines h00ligan's
// SemVer with the engine build's Git suffix.
#[command(
    name = "h00ligan",
    version = crate::build_identity(),
    about
)]
struct LiganCli {
    /// Select a project root. Without this, discover the nearest Git ancestor.
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    /// Override code-intelligence data directory (default: <repo>/.h00ligan/code-intel).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: LiganCommand,
}

/// Code-intelligence subcommands.
#[derive(Subcommand, Debug)]
enum LiganCommand {
    /// Reuse an exact current index or publish a fresh immutable generation.
    ///
    /// This needs no daemon, service, embedding model, or external database.
    Index(IndexArgs),

    /// Continuously reconcile source changes into immutable generations.
    Watch(WatchArgs),

    /// Show complete type structure (fields, methods, impls, trait implementations).
    #[command(name = "type")]
    Type(TypeArgs),

    /// Read a function or type body by name via the knowledge graph.
    Read(ReadSymbolArgs),

    /// Find how a symbol is called — actual call expressions with source context.
    Calls(CallsArgs),

    /// Change impact analysis: blast radius + callers + tests + risk in one call.
    Assess(AssessArgs),

    /// 360-degree symbol view: source + structure + callers + field usage + tests + warnings.
    Inspect(InspectArgs),

    /// Dead code analysis: full report or single-symbol check.
    Dead(DeadArgs),

    /// Graph health check: staleness, stats, index status, verdict.
    Status(composite_cmd_query::StatusArgs),

    /// Unified symbol search: find symbols by name pattern or file path.
    Find(composite_cmd_query::FindArgs),

    /// Find test functions that exercise a given symbol.
    Tests(TestsArgs),

    /// Persisted polyglot project units, relationships, key types, and health.
    Overview(OverviewArgs),

    /// Quality audit from one immutable generation.
    Audit(AuditArgs),

    /// Direct dependencies and dependents for an indexed file or directory.
    Deps(composite_cmd_query::DepsArgs),

    /// Search live source; attach indexed context only for exact generation bytes.
    GrepContext(composite_cmd_query::GrepContextArgs),

    /// Compare the immutable structural generation with live worktree source.
    Diff(composite_cmd_query::DiffArgs),

    /// Serve the exact graph-only code-intelligence tool set over MCP stdio.
    McpServe,
}

impl LiganCommand {
    const fn requires_semantic_runtime(&self) -> bool {
        match self {
            Self::Index(_) | Self::Watch(_) | Self::McpServe => true,
            Self::Type(_)
            | Self::Read(_)
            | Self::Calls(_)
            | Self::Assess(_)
            | Self::Inspect(_)
            | Self::Dead(_)
            | Self::Status(_)
            | Self::Find(_)
            | Self::Tests(_)
            | Self::Overview(_)
            | Self::Audit(_)
            | Self::Deps(_)
            | Self::GrepContext(_)
            | Self::Diff(_) => false,
        }
    }
}

pub fn run() {
    run_with_runtime_factory(|| {
        crate::runtime::LiganRuntime::with_system_toolchains().map_err(|error| error.to_string())
    });
}

#[tokio::main]
pub async fn run_with_runtime_factory(
    runtime_factory: impl FnOnce() -> Result<crate::runtime::LiganRuntime, String>,
) {
    // Reset SIGPIPE to default behavior so piping to `head`, `jq`, etc.
    // doesn't panic with "Broken pipe".
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = LiganCli::parse();

    let runtime = match runtime_for_command(&cli.command, runtime_factory) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("h00ligan product initialization failed: {error}");
            std::process::exit(1);
        }
    };

    // Lightweight stderr tracing (shared by every h00ligan subcommand path).
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,lance=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();

    let startup = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Error: cannot read startup directory: {error}");
            std::process::exit(1);
        }
    };
    let binding = match crate::binding::resolve_project_binding(
        &startup,
        cli.root.as_deref(),
        cli.data_dir.as_deref(),
    ) {
        Ok(binding) => binding,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        LiganCommand::Index(args) => {
            index_cmd::run_index_with_runtime(
                args,
                &binding,
                runtime.as_ref().expect("index requires product runtime"),
            )
            .await
        }
        LiganCommand::Watch(args) => {
            watch_cmd::run_watch_with_runtime(
                args,
                &binding,
                runtime.as_ref().expect("watch requires product runtime"),
            )
            .await
        }
        LiganCommand::Type(args) => ligan_cmd::run_type(args, &binding).await,
        LiganCommand::Read(args) => ligan_cmd::run_read_symbol(args, &binding).await,
        LiganCommand::Calls(args) => ligan_cmd::run_call_sites(args, &binding).await,
        LiganCommand::Assess(args) => composite_cmd::run_assess(args, &binding).await,
        LiganCommand::Inspect(args) => composite_cmd::run_inspect(args, &binding).await,
        LiganCommand::Dead(args) => composite_cmd::run_dead(args, &binding).await,
        LiganCommand::Status(args) => composite_cmd_query::run_status(args, &binding).await,
        LiganCommand::Find(args) => composite_cmd_query::run_find(args, &binding).await,
        LiganCommand::Tests(args) => composite_cmd::run_tests(args, &binding).await,
        LiganCommand::Overview(args) => composite_cmd::run_overview(args, &binding).await,
        LiganCommand::Audit(args) => composite_cmd::run_audit(args, &binding).await,
        LiganCommand::Deps(args) => composite_cmd_query::run_deps(args, &binding).await,
        LiganCommand::GrepContext(args) => {
            composite_cmd_query::run_grep_context(args, &binding).await
        }
        LiganCommand::Diff(args) => composite_cmd_query::run_diff(args, &binding).await,
        LiganCommand::McpServe => {
            run_mcp_serve(
                &binding,
                runtime.as_ref().expect("MCP requires product runtime"),
            )
            .await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn runtime_for_command(
    command: &LiganCommand,
    runtime_factory: impl FnOnce() -> Result<crate::runtime::LiganRuntime, String>,
) -> Result<Option<crate::runtime::LiganRuntime>, String> {
    if command.requires_semantic_runtime() {
        runtime_factory().map(Some)
    } else {
        Ok(None)
    }
}

async fn load_code_intel_context(
    binding: &h00ligan_engine::project_binding::ProjectBinding,
    supervisor: std::sync::Arc<h00ligan_engine::code_intel_supervisor::IndexSupervisor>,
) -> Result<h00ligan_interface::CodeIntelContext, LiganError> {
    h00ligan_interface::CodeIntelContext::load_with_supervisor(
        binding.clone(),
        tokio_util::sync::CancellationToken::new(),
        supervisor,
    )
    .await
    .map_err(|error| LiganError::Config(error.to_string()))
}

async fn run_mcp_serve(
    binding: &h00ligan_engine::project_binding::ProjectBinding,
    runtime: &crate::runtime::LiganRuntime,
) -> Result<(), LiganError> {
    let supervisor = runtime
        .supervisor(binding)
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let context = match load_code_intel_context(binding, std::sync::Arc::clone(&supervisor)).await {
        Ok(context) => context,
        Err(error) => {
            // A damaged publication must remain unavailable to every read and
            // source-mutation request, but it cannot make the explicit
            // `reindex { recover_publication: true }` repair surface
            // unreachable. An unloaded context re-runs validation at request
            // admission and conveys no authority from the rejected bundle.
            tracing::warn!(
                error = %error,
                "starting MCP without a queryable publication; explicit recovery remains available"
            );
            h00ligan_interface::CodeIntelContext::load_failed_with_supervisor(
                binding.clone(),
                tokio_util::sync::CancellationToken::new(),
                error.to_string(),
                supervisor,
            )
        }
    };
    let dispatcher = h00ligan_interface::mcp::CodeIntelMcp::new(
        h00ligan_interface::CodeIntelRegistry::default(),
        context,
    );
    h00ligan_interface::mcp::run_stdio(
        std::sync::Arc::new(dispatcher),
        h00ligan_interface::mcp::McpServerIdentity::new("h00ligan", env!("CARGO_PKG_VERSION")),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use clap::Parser as _;

    use super::*;

    #[test]
    fn read_only_commands_do_not_initialize_semantic_runtime() {
        let status = LiganCli::try_parse_from(["h00ligan", "status", "--format", "json"])
            .expect("parse read-only status command");
        let calls = Cell::new(0usize);
        let result = runtime_for_command(&status.command, || {
            calls.set(calls.get() + 1);
            Err("semantic runtime factory fired".to_owned())
        });

        if let Err(error) = result {
            panic!("read-only dispatch called factory: {error}");
        }
        assert_eq!(calls.get(), 0, "read-only dispatch must leave factory idle");

        let index =
            LiganCli::try_parse_from(["h00ligan", "index"]).expect("parse semantic index command");
        let result = runtime_for_command(&index.command, || {
            calls.set(calls.get() + 1);
            Err("semantic runtime positive control".to_owned())
        });
        match result {
            Err(error) => assert_eq!(error, "semantic runtime positive control"),
            Ok(_) => panic!("index skipped the semantic runtime factory"),
        }
        assert_eq!(calls.get(), 1, "index must invoke the runtime factory once");
    }
}
