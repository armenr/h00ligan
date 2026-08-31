//! h00ligan-owned semantic toolchain discovery.
//!
//! The product may inspect ambient state once to resolve an exact system
//! toolchain, but the engine and provider receive only the explicit result.
//! Managed/downloaded toolchains can implement the same engine contract later.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use h00ligan_engine::code_intel_cancellation::IndexCancellation;
use h00ligan_engine::code_intel_toolchain::{
    ResolvedToolchain, ResolvedToolchainComponent, ToolchainOrigin, ToolchainResolutionError,
    ToolchainResolver,
};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt as _;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPORT_BYTES: usize = 16 * 1024;
const COMMON_TOOLCHAIN_ENVIRONMENT: &[&str] = &["PATH", "HOME", "TMPDIR"];
const SELF_CONTAINED_PROVIDER_ENVIRONMENT: &[&str] = &["TMPDIR", "TMP", "TEMP"];
const CORE_TOOLCHAIN_ENVIRONMENT: &[&str] = &[
    "CARGO",
    "RUSTC",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "DEVELOPER_DIR",
    "SDKROOT",
];
const GO_TOOLCHAIN_ENVIRONMENT: &[&str] = &[
    "GO",
    "SCIP_GO",
    "GO111MODULE",
    "GO386",
    "GOAMD64",
    "GOARCH",
    "GOARM",
    "GOARM64",
    "GOCACHE",
    "GOENV",
    "GOEXPERIMENT",
    "GOFLAGS",
    "GOMODCACHE",
    "GOMIPS",
    "GOMIPS64",
    "GONOPROXY",
    "GONOSUMDB",
    "GOOS",
    "GOPPC64",
    "GOPRIVATE",
    "GOPROXY",
    "GORISCV64",
    "GOROOT",
    "GOSUMDB",
    "GOTOOLCHAIN",
    "GOWORK",
    "GOVCS",
    "GOWASM",
    "CGO_ENABLED",
    "CGO_CFLAGS",
    "CGO_CPPFLAGS",
    "CGO_CXXFLAGS",
    "CGO_LDFLAGS",
];

/// Native-build inputs which Cargo, build scripts, and proc-macro crates may
/// legitimately need while rust-analyzer loads a workspace. This is an
/// explicit product policy: provider children receive these exact values and
/// bind them into toolchain identity, while unrelated application state and
/// credentials remain outside the launch boundary.
const NATIVE_BUILD_ENVIRONMENT: &[&str] = &[
    "AR",
    "AR_FOR_BUILD",
    "AR_FOR_TARGET",
    "BINDGEN_EXTRA_CLANG_ARGS",
    "CC",
    "CC_FOR_BUILD",
    "CC_FOR_TARGET",
    "CFLAGS",
    "CMAKE",
    "CMAKE_PREFIX_PATH",
    "CMAKE_TOOLCHAIN_FILE",
    "CPATH",
    "CPPFLAGS",
    "CPLUS_INCLUDE_PATH",
    "CRATE_CC_NO_DEFAULTS",
    "CXX",
    "CXX_FOR_BUILD",
    "CXX_FOR_TARGET",
    "CXXFLAGS",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "HOST_AR",
    "HOST_CC",
    "HOST_CXX",
    "LD",
    "LDFLAGS",
    "LIBCLANG_PATH",
    "LIBRARY_PATH",
    "LD_LIBRARY_PATH",
    "MACOSX_DEPLOYMENT_TARGET",
    "NIX_BINTOOLS",
    "NIX_BINTOOLS_FOR_TARGET",
    "NIX_CC",
    "NIX_CC_FOR_TARGET",
    "NIX_CFLAGS_COMPILE",
    "NIX_CFLAGS_COMPILE_FOR_TARGET",
    "NIX_ENFORCE_NO_NATIVE",
    "NIX_HARDENING_ENABLE",
    "NIX_LDFLAGS",
    "NIX_LDFLAGS_FOR_TARGET",
    "NIX_STORE",
    "NM",
    "OPENSSL_DIR",
    "OPENSSL_INCLUDE_DIR",
    "OPENSSL_LIB_DIR",
    "OPENSSL_NO_VENDOR",
    "OPENSSL_STATIC",
    "PKG_CONFIG",
    "PKG_CONFIG_ALLOW_CROSS",
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_SYSROOT_DIR",
    "PROTOC",
    "PROTOC_INCLUDE",
    "RANLIB",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "STRIP",
    "TARGET_AR",
    "TARGET_CC",
    "TARGET_CXX",
];

/// Environment entries whose values select executable bytes, rather than
/// flags, directories, or ordinary configuration strings. Every populated
/// entry becomes a typed toolchain component in addition to remaining in the
/// exact child environment.
const NATIVE_BUILD_EXECUTABLE_ENVIRONMENT: &[&str] = &[
    "AR",
    "AR_FOR_BUILD",
    "AR_FOR_TARGET",
    "CC",
    "CC_FOR_BUILD",
    "CC_FOR_TARGET",
    "CMAKE",
    "CXX",
    "CXX_FOR_BUILD",
    "CXX_FOR_TARGET",
    "HOST_AR",
    "HOST_CC",
    "HOST_CXX",
    "LD",
    "NM",
    "PKG_CONFIG",
    "PROTOC",
    "RANLIB",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "STRIP",
    "TARGET_AR",
    "TARGET_CC",
    "TARGET_CXX",
];

/// Resolver for already-installed semantic toolchains. It never downloads,
/// installs, or mutates a project; acquisition is a separate future policy.
#[derive(Debug, Clone)]
pub struct SystemToolchainResolver {
    policies: BTreeMap<&'static str, Arc<dyn SystemToolchainPolicy>>,
}

type ToolchainFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ResolvedToolchain, ToolchainResolutionError>> + Send + 'a>>;
type ToolchainPopulationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Vec<ResolvedToolchain>, ToolchainResolutionError>> + Send + 'a>,
>;

trait SystemToolchainPolicy: std::fmt::Debug + Send + Sync {
    fn language(&self) -> &'static str;
    fn policy_id(&self) -> &'static str;
    fn resolve<'a>(
        &'a self,
        execution_root: &'a Path,
        cancellation: &'a IndexCancellation,
    ) -> ToolchainFuture<'a>;
    fn resolve_population<'a>(
        &'a self,
        execution_roots: &'a [PathBuf],
        cancellation: &'a IndexCancellation,
    ) -> ToolchainPopulationFuture<'a>;
}

#[derive(Debug, Clone)]
struct CapturedSystemToolchain {
    environment: BTreeMap<String, String>,
    command_timeout: Duration,
}

#[derive(Debug)]
struct RustSystemToolchainPolicy {
    captured: CapturedSystemToolchain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoProviderAuthority {
    SystemScip,
    ProductEmbedded,
}

#[derive(Debug)]
struct GoSystemToolchainPolicy {
    captured: CapturedSystemToolchain,
    provider_authority: GoProviderAuthority,
}

#[derive(Debug)]
struct ManagedProviderToolchainPolicy {
    language: &'static str,
    policy_id: &'static str,
    captured: CapturedSystemToolchain,
}

struct SysrootProgramProbe<'a> {
    language: &'static str,
    candidate: PathBuf,
    arguments: &'static [&'static str],
    expected_report: &'a [u8],
    fallback: PathBuf,
}

#[derive(Debug)]
struct GoToolchainSelection {
    execution_root: PathBuf,
    provider: PathBuf,
    go: PathBuf,
    goroot: PathBuf,
}

impl SystemToolchainResolver {
    pub fn capture() -> Result<Self, ToolchainResolutionError> {
        Self::capture_with_go_provider(GoProviderAuthority::SystemScip)
    }

    /// Capture the product-owned persistent-provider policy collection. The
    /// Go provider executable is content-bound by product assembly, while the
    /// selected Go compiler remains explicit execution-root authority.
    pub fn capture_for_provider_products() -> Result<Self, ToolchainResolutionError> {
        Self::capture_with_go_provider(GoProviderAuthority::ProductEmbedded)
    }

    fn capture_with_go_provider(
        go_provider_authority: GoProviderAuthority,
    ) -> Result<Self, ToolchainResolutionError> {
        Self::capture_with_go_provider_from(std::env::vars_os(), go_provider_authority)
    }

    fn capture_with_go_provider_from(
        environment: impl IntoIterator<Item = (OsString, OsString)>,
        go_provider_authority: GoProviderAuthority,
    ) -> Result<Self, ToolchainResolutionError> {
        let mut environment = capture_environment(environment)?;
        environment.insert("CARGO_TERM_COLOR".into(), "never".into());
        // The product chooses one deterministic Go configuration instead of
        // inheriting a mutable per-user GOENV file or allowing module writes.
        environment.insert("GOENV".into(), "off".into());
        environment.insert("GOFLAGS".into(), "-mod=readonly".into());
        environment.insert("GOTOOLCHAIN".into(), "local".into());
        let captured = CapturedSystemToolchain {
            environment,
            command_timeout: COMMAND_TIMEOUT,
        };
        Ok(Self::from_captured(captured, go_provider_authority))
    }

    fn from_captured(
        captured: CapturedSystemToolchain,
        go_provider_authority: GoProviderAuthority,
    ) -> Self {
        let policies: BTreeMap<&'static str, Arc<dyn SystemToolchainPolicy>> = BTreeMap::from([
            (
                "rust",
                Arc::new(RustSystemToolchainPolicy {
                    captured: captured.clone(),
                }) as Arc<dyn SystemToolchainPolicy>,
            ),
            (
                "go",
                Arc::new(GoSystemToolchainPolicy {
                    captured: captured.clone(),
                    provider_authority: go_provider_authority,
                }) as Arc<dyn SystemToolchainPolicy>,
            ),
            (
                "python",
                Arc::new(ManagedProviderToolchainPolicy {
                    language: "python",
                    policy_id: "h00ligan/product-python-toolchain/v1",
                    captured: captured.clone(),
                }) as Arc<dyn SystemToolchainPolicy>,
            ),
            (
                "typescript",
                Arc::new(ManagedProviderToolchainPolicy {
                    language: "typescript",
                    policy_id: "h00ligan/product-typescript-toolchain/v1",
                    captured,
                }) as Arc<dyn SystemToolchainPolicy>,
            ),
        ]);
        debug_assert!(
            policies
                .iter()
                .all(|(language, policy)| *language == policy.language())
        );
        Self { policies }
    }
}

impl CapturedSystemToolchain {
    fn resolve_managed_provider(
        &self,
        language: &'static str,
        execution_root: &Path,
        cancellation: &IndexCancellation,
    ) -> Result<ResolvedToolchain, ToolchainResolutionError> {
        ensure_active(cancellation)?;
        let execution_root = std::fs::canonicalize(execution_root).map_err(|error| {
            resolution_error(
                language,
                execution_root,
                format!("canonicalize root: {error}"),
            )
        })?;
        if !execution_root.is_dir() || execution_root.to_str().is_none() {
            return Err(resolution_error(
                language,
                &execution_root,
                "execution root is not a UTF-8 directory",
            ));
        }
        let environment = self
            .environment
            .iter()
            .filter(|(name, _)| SELF_CONTAINED_PROVIDER_ENVIRONMENT.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        ResolvedToolchain::new(
            language,
            execution_root,
            ToolchainOrigin::Managed,
            [],
            None,
            environment,
        )
    }

    async fn resolve_rust(
        &self,
        execution_root: &Path,
        cancellation: &IndexCancellation,
    ) -> Result<ResolvedToolchain, ToolchainResolutionError> {
        ensure_active(cancellation)?;
        let execution_root = std::fs::canonicalize(execution_root).map_err(|error| {
            resolution_error(
                "rust",
                execution_root,
                format!("canonicalize root: {error}"),
            )
        })?;
        if !execution_root.is_dir() || execution_root.to_str().is_none() {
            return Err(resolution_error(
                "rust",
                &execution_root,
                "execution root is not a UTF-8 directory",
            ));
        }

        let rustc_invocation = self.resolve_program("rust", "RUSTC", "rustc", &execution_root)?;
        let cargo_invocation = self.resolve_program("rust", "CARGO", "cargo", &execution_root)?;
        let rustc_report = self
            .command_report(
                "rust",
                &rustc_invocation,
                &["-vV"],
                &execution_root,
                cancellation,
            )
            .await?;
        let cargo_report = self
            .command_report(
                "rust",
                &cargo_invocation,
                &["-V"],
                &execution_root,
                cancellation,
            )
            .await?;
        let sysroot_report = self
            .command_report(
                "rust",
                &rustc_invocation,
                &["--print", "sysroot"],
                &execution_root,
                cancellation,
            )
            .await?;
        let sysroot_text = report_text("rust", &sysroot_report, "rustc sysroot", &execution_root)?;
        let sysroot = std::fs::canonicalize(sysroot_text.trim()).map_err(|error| {
            resolution_error(
                "rust",
                &execution_root,
                format!("canonicalize reported sysroot: {error}"),
            )
        })?;
        if !sysroot.is_dir() || sysroot.to_str().is_none() {
            return Err(resolution_error(
                "rust",
                &execution_root,
                "reported sysroot is not a UTF-8 directory",
            ));
        }

        let rustc = self
            .prefer_sysroot_program(
                SysrootProgramProbe {
                    language: "rust",
                    candidate: sysroot.join("bin/rustc"),
                    arguments: &["-vV"],
                    expected_report: &rustc_report,
                    fallback: rustc_invocation,
                },
                &execution_root,
                cancellation,
            )
            .await?;
        let cargo = self
            .prefer_sysroot_program(
                SysrootProgramProbe {
                    language: "rust",
                    candidate: sysroot.join("bin/cargo"),
                    arguments: &["-V"],
                    expected_report: &cargo_report,
                    fallback: cargo_invocation,
                },
                &execution_root,
                cancellation,
            )
            .await?;
        ensure_active(cancellation)?;

        let rustc_sha256 = sha256_file(&rustc).await.map_err(|error| {
            resolution_error(
                "rust",
                &execution_root,
                format!("hash rustc {}: {error}", rustc.display()),
            )
        })?;
        let cargo_sha256 = sha256_file(&cargo).await.map_err(|error| {
            resolution_error(
                "rust",
                &execution_root,
                format!("hash cargo {}: {error}", cargo.display()),
            )
        })?;
        ensure_active(cancellation)?;

        let mut environment = self.environment_for_rust();
        environment.insert(
            "RUSTC".into(),
            path_text("rust", &rustc, "rustc", &execution_root)?,
        );
        environment.insert(
            "CARGO".into(),
            path_text("rust", &cargo, "cargo", &execution_root)?,
        );
        environment.insert(
            "PATH".into(),
            explicit_path(&rustc, &cargo, environment.get("PATH").map(String::as_str))?,
        );
        let mut components = vec![
            ResolvedToolchainComponent::new(
                "cargo",
                cargo,
                cargo_sha256,
                report_text("rust", &cargo_report, "cargo version", &execution_root)?,
            )?,
            ResolvedToolchainComponent::new(
                "rustc",
                rustc,
                rustc_sha256,
                report_text("rust", &rustc_report, "rustc version", &execution_root)?,
            )?,
        ];
        components.extend(
            self.resolve_native_build_components(
                "rust",
                &execution_root,
                &environment,
                cancellation,
            )
            .await?,
        );
        ResolvedToolchain::new(
            "rust",
            execution_root,
            ToolchainOrigin::System,
            components,
            Some(sysroot),
            environment,
        )
    }

    async fn resolve_go(
        &self,
        provider_authority: GoProviderAuthority,
        execution_root: &Path,
        cancellation: &IndexCancellation,
    ) -> Result<ResolvedToolchain, ToolchainResolutionError> {
        let selection = self
            .select_go(provider_authority, execution_root, cancellation)
            .await?;
        self.resolve_selected_go(provider_authority, &selection, cancellation)
            .await
    }

    /// Resolve only the execution-root-sensitive Go selector layer. PATH may
    /// contain a version-manager shim, so equal launcher bytes do not prove an
    /// equal effective GOROOT. Provider version and executable-byte work is
    /// intentionally deferred until equal effective selections are grouped.
    async fn select_go(
        &self,
        provider_authority: GoProviderAuthority,
        execution_root: &Path,
        cancellation: &IndexCancellation,
    ) -> Result<GoToolchainSelection, ToolchainResolutionError> {
        ensure_active(cancellation)?;
        let execution_root = std::fs::canonicalize(execution_root).map_err(|error| {
            resolution_error("go", execution_root, format!("canonicalize root: {error}"))
        })?;
        if !execution_root.is_dir() || execution_root.to_str().is_none() {
            return Err(resolution_error(
                "go",
                &execution_root,
                "execution root is not a UTF-8 directory",
            ));
        }

        let requested_provider = match provider_authority {
            GoProviderAuthority::SystemScip => {
                Some(self.resolve_program("go", "SCIP_GO", "scip-go", &execution_root)?)
            }
            GoProviderAuthority::ProductEmbedded => None,
        };
        let go_invocation = self.resolve_program("go", "GO", "go", &execution_root)?;
        let goroot_report = self
            .command_report(
                "go",
                &go_invocation,
                &["env", "GOROOT"],
                &execution_root,
                cancellation,
            )
            .await?;
        let goroot_text = report_text("go", &goroot_report, "Go root", &execution_root)?;
        let goroot = std::fs::canonicalize(goroot_text.trim()).map_err(|error| {
            resolution_error(
                "go",
                &execution_root,
                format!("canonicalize reported GOROOT: {error}"),
            )
        })?;
        if !goroot.is_dir() || goroot.to_str().is_none() {
            return Err(resolution_error(
                "go",
                &execution_root,
                "reported GOROOT is not a UTF-8 directory",
            ));
        }
        let go = validate_executable("go", goroot.join("bin/go"), "GOROOT go", &execution_root)?;
        let provider = requested_provider.unwrap_or_else(|| go.clone());
        ensure_active(cancellation)?;

        Ok(GoToolchainSelection {
            execution_root,
            provider,
            go,
            goroot,
        })
    }

    async fn resolve_selected_go(
        &self,
        provider_authority: GoProviderAuthority,
        selection: &GoToolchainSelection,
        cancellation: &IndexCancellation,
    ) -> Result<ResolvedToolchain, ToolchainResolutionError> {
        ensure_active(cancellation)?;
        let go_report = self
            .command_report(
                "go",
                &selection.go,
                &["version"],
                &selection.execution_root,
                cancellation,
            )
            .await?;
        let go_sha256 = sha256_file(&selection.go).await.map_err(|error| {
            resolution_error(
                "go",
                &selection.execution_root,
                format!("hash go {}: {error}", selection.go.display()),
            )
        })?;
        ensure_active(cancellation)?;

        let mut environment = self.environment_for_go();
        environment.insert(
            "GO".into(),
            path_text("go", &selection.go, "go", &selection.execution_root)?,
        );
        environment.insert(
            "GOROOT".into(),
            path_text("go", &selection.goroot, "GOROOT", &selection.execution_root)?,
        );
        environment.insert("GOENV".into(), "off".into());
        environment.insert("GOFLAGS".into(), "-mod=readonly".into());
        environment.insert("GOTOOLCHAIN".into(), "local".into());
        environment.insert(
            "PATH".into(),
            explicit_path(
                &selection.provider,
                &selection.go,
                environment.get("PATH").map(String::as_str),
            )?,
        );
        let mut components = vec![ResolvedToolchainComponent::new(
            "go",
            selection.go.clone(),
            go_sha256,
            report_text("go", &go_report, "go version", &selection.execution_root)?,
        )?];
        if provider_authority == GoProviderAuthority::SystemScip {
            let provider_report = self
                .command_report(
                    "go",
                    &selection.provider,
                    &["--version"],
                    &selection.execution_root,
                    cancellation,
                )
                .await?;
            let provider_sha256 = sha256_file(&selection.provider).await.map_err(|error| {
                resolution_error(
                    "go",
                    &selection.execution_root,
                    format!("hash scip-go {}: {error}", selection.provider.display()),
                )
            })?;
            let provider_report_text = report_text(
                "go",
                &provider_report,
                "scip-go version",
                &selection.execution_root,
            )?;
            let provider_version = provider_report_text
                .strip_prefix("scip-go")
                .map(str::trim)
                .filter(|version| !version.is_empty())
                .unwrap_or(provider_report_text)
                .to_owned();
            components.push(ResolvedToolchainComponent::new(
                "scip-go",
                selection.provider.clone(),
                provider_sha256,
                provider_version,
            )?);
        }
        components.extend(
            self.resolve_native_build_components(
                "go",
                &selection.execution_root,
                &environment,
                cancellation,
            )
            .await?,
        );
        ResolvedToolchain::new(
            "go",
            selection.execution_root.clone(),
            ToolchainOrigin::System,
            components,
            Some(selection.goroot.clone()),
            environment,
        )
    }

    fn resolve_program(
        &self,
        language: &str,
        override_name: &str,
        default_name: &str,
        execution_root: &Path,
    ) -> Result<PathBuf, ToolchainResolutionError> {
        Self::resolve_program_in_environment(
            &self.environment,
            language,
            override_name,
            default_name,
            execution_root,
        )
    }

    fn resolve_program_in_environment(
        environment: &BTreeMap<String, String>,
        language: &str,
        override_name: &str,
        default_name: &str,
        execution_root: &Path,
    ) -> Result<PathBuf, ToolchainResolutionError> {
        let requested = environment
            .get(override_name)
            .map_or(default_name, String::as_str);
        let requested_path = Path::new(requested);
        if requested_path.components().count() > 1 {
            let candidate = if requested_path.is_absolute() {
                requested_path.to_path_buf()
            } else {
                execution_root.join(requested_path)
            };
            return validate_executable(language, candidate, default_name, execution_root);
        }
        let path = environment.get("PATH").ok_or_else(|| {
            resolution_error(language, execution_root, "PATH snapshot is unavailable")
        })?;
        for directory in std::env::split_paths(OsStr::new(path)) {
            let candidate = directory.join(requested);
            if executable_file(&candidate) {
                return validate_executable(language, candidate, default_name, execution_root);
            }
        }
        Err(resolution_error(
            language,
            execution_root,
            format!("{default_name} is not present in the captured PATH"),
        ))
    }

    async fn resolve_native_build_components(
        &self,
        language: &str,
        execution_root: &Path,
        environment: &BTreeMap<String, String>,
        cancellation: &IndexCancellation,
    ) -> Result<Vec<ResolvedToolchainComponent>, ToolchainResolutionError> {
        let mut components = Vec::new();
        for name in environment
            .keys()
            .filter(|name| is_native_build_executable_environment(name))
        {
            ensure_active(cancellation)?;
            let executable = Self::resolve_program_in_environment(
                environment,
                language,
                name,
                name,
                execution_root,
            )?;
            let executable_sha256 = sha256_file(&executable).await.map_err(|error| {
                resolution_error(
                    language,
                    execution_root,
                    format!(
                        "hash native build tool {name} {}: {error}",
                        executable.display()
                    ),
                )
            })?;
            ensure_active(cancellation)?;
            components.push(ResolvedToolchainComponent::new(
                native_build_component_role(name),
                &executable,
                executable_sha256,
                format!("{name} resolved to {}", executable.display()),
            )?);
        }
        Ok(components)
    }

    async fn prefer_sysroot_program(
        &self,
        probe: SysrootProgramProbe<'_>,
        execution_root: &Path,
        cancellation: &IndexCancellation,
    ) -> Result<PathBuf, ToolchainResolutionError> {
        if !executable_file(&probe.candidate) {
            return Ok(probe.fallback);
        }
        let report = self
            .command_report(
                probe.language,
                &probe.candidate,
                probe.arguments,
                execution_root,
                cancellation,
            )
            .await?;
        if report == probe.expected_report {
            validate_executable(
                probe.language,
                probe.candidate,
                "sysroot tool",
                execution_root,
            )
        } else {
            Ok(probe.fallback)
        }
    }

    async fn command_report(
        &self,
        language: &str,
        program: &Path,
        arguments: &[&str],
        execution_root: &Path,
        cancellation: &IndexCancellation,
    ) -> Result<Vec<u8>, ToolchainResolutionError> {
        ensure_active(cancellation)?;
        let mut command = tokio::process::Command::new(program);
        command
            .args(arguments)
            .current_dir(execution_root)
            .env_clear()
            .envs(&self.environment)
            .kill_on_drop(true);
        let output = tokio::time::timeout(self.command_timeout, command.output())
            .await
            .map_err(|_| {
                resolution_error(
                    language,
                    execution_root,
                    format!("{} runtime identity command timed out", program.display()),
                )
            })?
            .map_err(|error| {
                resolution_error(
                    language,
                    execution_root,
                    format!("execute {}: {error}", program.display()),
                )
            })?;
        ensure_active(cancellation)?;
        if !output.status.success() {
            return Err(resolution_error(
                language,
                execution_root,
                format!(
                    "{} runtime identity command exited {}",
                    program.display(),
                    output.status
                ),
            ));
        }
        let report = if output.stdout.is_empty() {
            output.stderr
        } else {
            output.stdout
        };
        if report.is_empty() || report.len() > MAX_REPORT_BYTES {
            return Err(resolution_error(
                language,
                execution_root,
                format!("{} returned an invalid bounded report", program.display()),
            ));
        }
        Ok(report)
    }

    fn environment_for_rust(&self) -> BTreeMap<String, String> {
        self.environment
            .iter()
            .filter(|(name, _)| {
                COMMON_TOOLCHAIN_ENVIRONMENT.contains(&name.as_str())
                    || CORE_TOOLCHAIN_ENVIRONMENT.contains(&name.as_str())
                    || NATIVE_BUILD_ENVIRONMENT.contains(&name.as_str())
                    || is_target_specific_native_environment(name)
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    fn environment_for_go(&self) -> BTreeMap<String, String> {
        self.environment
            .iter()
            .filter(|(name, _)| {
                COMMON_TOOLCHAIN_ENVIRONMENT.contains(&name.as_str())
                    || GO_TOOLCHAIN_ENVIRONMENT.contains(&name.as_str())
                    || NATIVE_BUILD_ENVIRONMENT.contains(&name.as_str())
                    || is_target_specific_native_environment(name)
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

fn capture_environment(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<BTreeMap<String, String>, ToolchainResolutionError> {
    let mut captured = BTreeMap::new();
    for (name, value) in environment {
        let name = name.into_string().map_err(|_| {
            ToolchainResolutionError::Invalid(
                "system toolchain environment contains a non-UTF-8 name".into(),
            )
        })?;
        if !is_toolchain_environment(&name) {
            continue;
        }
        let value = value.into_string().map_err(|_| {
            ToolchainResolutionError::Invalid(format!(
                "system toolchain environment {name} is not UTF-8"
            ))
        })?;
        captured.insert(name, value);
    }
    Ok(captured)
}

fn is_toolchain_environment(name: &str) -> bool {
    COMMON_TOOLCHAIN_ENVIRONMENT.contains(&name)
        || SELF_CONTAINED_PROVIDER_ENVIRONMENT.contains(&name)
        || CORE_TOOLCHAIN_ENVIRONMENT.contains(&name)
        || GO_TOOLCHAIN_ENVIRONMENT.contains(&name)
        || NATIVE_BUILD_ENVIRONMENT.contains(&name)
        || is_target_specific_native_environment(name)
}

fn is_target_specific_native_environment(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "AR_",
        "CC_",
        "CFLAGS_",
        "CPPFLAGS_",
        "CXX_",
        "CXXFLAGS_",
        "LDFLAGS_",
        "RANLIB_",
    ];
    const NIX_WRAPPER_PREFIXES: &[&str] =
        &["NIX_BINTOOLS_WRAPPER_TARGET_", "NIX_CC_WRAPPER_TARGET_"];

    PREFIXES.iter().chain(NIX_WRAPPER_PREFIXES).any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
    }) || name.strip_prefix("CARGO_TARGET_").is_some_and(|suffix| {
        ["_LINKER", "_RUNNER", "_RUSTFLAGS"]
            .iter()
            .any(|ending| suffix.ends_with(ending) && suffix.len() > ending.len())
    })
}

fn is_native_build_executable_environment(name: &str) -> bool {
    if NATIVE_BUILD_EXECUTABLE_ENVIRONMENT.contains(&name) {
        return true;
    }
    ["AR_", "CC_", "CXX_", "RANLIB_"].iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
    }) || name
        .strip_prefix("CARGO_TARGET_")
        .is_some_and(|suffix| suffix.ends_with("_LINKER") && suffix.len() > "_LINKER".len())
}

fn native_build_component_role(environment_name: &str) -> String {
    format!("native-{}", environment_name.to_ascii_lowercase())
}

impl SystemToolchainPolicy for RustSystemToolchainPolicy {
    fn language(&self) -> &'static str {
        "rust"
    }

    fn policy_id(&self) -> &'static str {
        "h00ligan/system-rust-toolchain/v2"
    }

    fn resolve<'a>(
        &'a self,
        execution_root: &'a Path,
        cancellation: &'a IndexCancellation,
    ) -> ToolchainFuture<'a> {
        Box::pin(self.captured.resolve_rust(execution_root, cancellation))
    }

    fn resolve_population<'a>(
        &'a self,
        execution_roots: &'a [PathBuf],
        cancellation: &'a IndexCancellation,
    ) -> ToolchainPopulationFuture<'a> {
        let captured = self.captured.clone();
        let execution_roots = execution_roots.to_vec();
        let cancellation = cancellation.clone();
        Box::pin(async move {
            ensure_active(&cancellation)?;
            // Rust launchers are commonly directory-sensitive selector
            // proxies (`rustup` is the canonical example). Equal launcher
            // paths therefore do not prove equal effective sysroots. Resolve
            // every root concurrently while retaining input order.
            let mut tasks = tokio::task::JoinSet::new();
            for (index, root) in execution_roots.iter().cloned().enumerate() {
                let root_captured = captured.clone();
                let root_cancellation = cancellation.clone();
                tasks.spawn(async move {
                    (
                        index,
                        root_captured.resolve_rust(&root, &root_cancellation).await,
                    )
                });
            }
            let mut population = (0..execution_roots.len())
                .map(|_| None)
                .collect::<Vec<Option<Result<ResolvedToolchain, ToolchainResolutionError>>>>();
            while let Some(joined) = tasks.join_next().await {
                let (index, result) = joined.map_err(|error| {
                    ToolchainResolutionError::Invalid(format!(
                        "Rust toolchain population task failed: {error}"
                    ))
                })?;
                population[index] = Some(result);
            }
            population
                .into_iter()
                .map(|toolchain| {
                    toolchain.ok_or_else(|| {
                        ToolchainResolutionError::Invalid(
                            "Rust toolchain population result is incomplete".into(),
                        )
                    })?
                })
                .collect()
        })
    }
}

impl SystemToolchainPolicy for GoSystemToolchainPolicy {
    fn language(&self) -> &'static str {
        "go"
    }

    fn policy_id(&self) -> &'static str {
        match self.provider_authority {
            GoProviderAuthority::SystemScip => "h00ligan/system-go-scip-toolchain/v2",
            GoProviderAuthority::ProductEmbedded => "h00ligan/product-go-toolchain/v2",
        }
    }

    fn resolve<'a>(
        &'a self,
        execution_root: &'a Path,
        cancellation: &'a IndexCancellation,
    ) -> ToolchainFuture<'a> {
        Box::pin(
            self.captured
                .resolve_go(self.provider_authority, execution_root, cancellation),
        )
    }

    fn resolve_population<'a>(
        &'a self,
        execution_roots: &'a [PathBuf],
        cancellation: &'a IndexCancellation,
    ) -> ToolchainPopulationFuture<'a> {
        let captured = self.captured.clone();
        let provider_authority = self.provider_authority;
        let execution_roots = execution_roots.to_vec();
        let cancellation = cancellation.clone();
        Box::pin(async move {
            ensure_active(&cancellation)?;
            // Resolve the directory-sensitive launcher layer for every root
            // first. Only roots selecting the same real GOROOT/bin/go and
            // provider path may share version and executable-byte work.
            let mut selection_tasks = tokio::task::JoinSet::new();
            for (index, root) in execution_roots.iter().cloned().enumerate() {
                let root_captured = captured.clone();
                let root_cancellation = cancellation.clone();
                selection_tasks.spawn(async move {
                    (
                        index,
                        root_captured
                            .select_go(provider_authority, &root, &root_cancellation)
                            .await,
                    )
                });
            }
            let mut selections = (0..execution_roots.len())
                .map(|_| None)
                .collect::<Vec<Option<Result<GoToolchainSelection, ToolchainResolutionError>>>>();
            while let Some(joined) = selection_tasks.join_next().await {
                let (index, result) = joined.map_err(|error| {
                    ToolchainResolutionError::Invalid(format!(
                        "Go toolchain selection task failed: {error}"
                    ))
                })?;
                selections[index] = Some(result);
            }

            let mut groups =
                BTreeMap::<(PathBuf, PathBuf, PathBuf), Vec<(usize, GoToolchainSelection)>>::new();
            for (index, selection) in selections.into_iter().enumerate() {
                let selection = selection.ok_or_else(|| {
                    ToolchainResolutionError::Invalid(
                        "Go toolchain selection population is incomplete".into(),
                    )
                })??;
                let identity = (
                    selection.provider.clone(),
                    selection.go.clone(),
                    selection.goroot.clone(),
                );
                groups.entry(identity).or_default().push((index, selection));
            }

            let mut tasks = tokio::task::JoinSet::new();
            for members in groups.into_values() {
                let group_captured = captured.clone();
                let group_cancellation = cancellation.clone();
                let order = members[0].0;
                tasks.spawn(async move {
                    let representative = &members[0].1;
                    let result = group_captured
                        .resolve_selected_go(
                            provider_authority,
                            representative,
                            &group_cancellation,
                        )
                        .await;
                    (order, members, result)
                });
            }

            let mut group_results = BTreeMap::new();
            while let Some(joined) = tasks.join_next().await {
                let (order, members, result) = joined.map_err(|error| {
                    ToolchainResolutionError::Invalid(format!(
                        "Go toolchain population task failed: {error}"
                    ))
                })?;
                group_results.insert(order, (members, result));
            }
            let mut population = (0..execution_roots.len())
                .map(|_| None)
                .collect::<Vec<Option<ResolvedToolchain>>>();
            for (_order, (members, result)) in group_results {
                let shared = result?;
                for (index, selection) in members {
                    population[index] =
                        Some(shared.rebind_execution_root(selection.execution_root)?);
                }
            }
            population
                .into_iter()
                .map(|toolchain| {
                    toolchain.ok_or_else(|| {
                        ToolchainResolutionError::Invalid(
                            "Go toolchain population result is incomplete".into(),
                        )
                    })
                })
                .collect()
        })
    }
}

impl SystemToolchainPolicy for ManagedProviderToolchainPolicy {
    fn language(&self) -> &'static str {
        self.language
    }

    fn policy_id(&self) -> &'static str {
        self.policy_id
    }

    fn resolve<'a>(
        &'a self,
        execution_root: &'a Path,
        cancellation: &'a IndexCancellation,
    ) -> ToolchainFuture<'a> {
        Box::pin(async move {
            self.captured
                .resolve_managed_provider(self.language, execution_root, cancellation)
        })
    }

    fn resolve_population<'a>(
        &'a self,
        execution_roots: &'a [PathBuf],
        cancellation: &'a IndexCancellation,
    ) -> ToolchainPopulationFuture<'a> {
        Box::pin(async move {
            execution_roots
                .iter()
                .map(|root| {
                    self.captured
                        .resolve_managed_provider(self.language, root, cancellation)
                })
                .collect()
        })
    }
}

impl ToolchainResolver for SystemToolchainResolver {
    fn policy_id(&self, language: &str) -> Result<&'static str, ToolchainResolutionError> {
        self.policies
            .get(language)
            .map(|policy| policy.policy_id())
            .ok_or_else(|| ToolchainResolutionError::UnsupportedLanguage(language.into()))
    }

    fn resolve<'a>(
        &'a self,
        language: &'a str,
        execution_root: &'a Path,
        cancellation: &'a IndexCancellation,
    ) -> ToolchainFuture<'a> {
        let policy = self.policies.get(language).cloned();
        Box::pin(async move {
            let policy = policy
                .ok_or_else(|| ToolchainResolutionError::UnsupportedLanguage(language.into()))?;
            policy.resolve(execution_root, cancellation).await
        })
    }

    fn resolve_population<'a>(
        &'a self,
        language: &'a str,
        execution_roots: &'a [PathBuf],
        cancellation: &'a IndexCancellation,
    ) -> ToolchainPopulationFuture<'a> {
        let policy = self.policies.get(language).cloned();
        Box::pin(async move {
            let policy = policy
                .ok_or_else(|| ToolchainResolutionError::UnsupportedLanguage(language.into()))?;
            policy
                .resolve_population(execution_roots, cancellation)
                .await
        })
    }
}

fn validate_executable(
    language: &str,
    path: PathBuf,
    label: &str,
    execution_root: &Path,
) -> Result<PathBuf, ToolchainResolutionError> {
    if !path.is_absolute() || path.to_str().is_none() || !executable_file(&path) {
        return Err(resolution_error(
            language,
            execution_root,
            format!(
                "{label} is not an absolute executable file: {}",
                path.display()
            ),
        ));
    }
    Ok(path)
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn explicit_path(
    rustc: &Path,
    cargo: &Path,
    inherited: Option<&str>,
) -> Result<String, ToolchainResolutionError> {
    let mut seen = BTreeSet::new();
    let mut directories = Vec::new();
    for directory in [rustc.parent(), cargo.parent()].into_iter().flatten() {
        if seen.insert(directory.to_path_buf()) {
            directories.push(directory.to_path_buf());
        }
    }
    if let Some(inherited) = inherited {
        for directory in std::env::split_paths(OsStr::new(inherited)) {
            if seen.insert(directory.clone()) {
                directories.push(directory);
            }
        }
    }
    std::env::join_paths(directories)
        .map_err(|error| ToolchainResolutionError::Invalid(format!("construct PATH: {error}")))?
        .into_string()
        .map_err(|_| ToolchainResolutionError::Invalid("resolved PATH is not UTF-8".into()))
}

async fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    // Keep the I/O buffer off the async state machine's stack. Toolchain
    // resolution may retain several completed reports while awaiting another
    // executable hash; embedding one 64 KiB array per hash future inflated the
    // language resolvers to >600 KiB stack frames.
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn report_text<'a>(
    language: &str,
    report: &'a [u8],
    label: &str,
    execution_root: &Path,
) -> Result<&'a str, ToolchainResolutionError> {
    std::str::from_utf8(report)
        .map(str::trim)
        .ok()
        .filter(|report| !report.is_empty())
        .ok_or_else(|| {
            resolution_error(
                language,
                execution_root,
                format!("{label} is not nonempty UTF-8"),
            )
        })
}

fn path_text(
    language: &str,
    path: &Path,
    label: &str,
    execution_root: &Path,
) -> Result<String, ToolchainResolutionError> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        resolution_error(
            language,
            execution_root,
            format!("resolved {label} path is not UTF-8"),
        )
    })
}

fn ensure_active(cancellation: &IndexCancellation) -> Result<(), ToolchainResolutionError> {
    if cancellation.is_cancelled() {
        Err(ToolchainResolutionError::Cancelled)
    } else {
        Ok(())
    }
}

fn resolution_error(
    language: &str,
    root: &Path,
    detail: impl Into<String>,
) -> ToolchainResolutionError {
    ToolchainResolutionError::Resolution {
        language: language.into(),
        root: root.to_path_buf(),
        detail: detail.into(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::TempDir;

    use super::*;

    fn write_tool(path: &Path, body: &str) {
        std::fs::write(path, body).expect("write fake tool");
        let mut permissions = std::fs::metadata(path)
            .expect("tool metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("make tool executable");
    }

    fn canonical_fixture_path(path: PathBuf) -> PathBuf {
        std::fs::canonicalize(&path)
            .unwrap_or_else(|error| panic!("canonicalize fixture path {}: {error}", path.display()))
    }

    fn system_resolver(environment: BTreeMap<String, String>) -> SystemToolchainResolver {
        SystemToolchainResolver::from_captured(
            CapturedSystemToolchain {
                environment,
                command_timeout: Duration::from_secs(2),
            },
            GoProviderAuthority::SystemScip,
        )
    }

    #[test]
    fn language_policy_identity_isolated_from_other_provider_packaging() {
        let captured = CapturedSystemToolchain {
            environment: BTreeMap::new(),
            command_timeout: Duration::from_secs(2),
        };
        let system = SystemToolchainResolver::from_captured(
            captured.clone(),
            GoProviderAuthority::SystemScip,
        );
        let product =
            SystemToolchainResolver::from_captured(captured, GoProviderAuthority::ProductEmbedded);

        assert_eq!(
            system.policy_id("rust").expect("system Rust policy"),
            product.policy_id("rust").expect("product Rust policy"),
            "changing Go packaging must not invalidate Rust toolchain authority"
        );
        assert_ne!(
            system.policy_id("go").expect("system Go policy"),
            product.policy_id("go").expect("product Go policy"),
            "the Go executable population remains part of Go policy authority"
        );
        for language in ["python", "typescript"] {
            assert_eq!(
                system
                    .policy_id(language)
                    .expect("system managed-provider policy"),
                product
                    .policy_id(language)
                    .expect("product managed-provider policy"),
                "self-contained language policy is independent of Go packaging"
            );
        }
        assert!(matches!(
            product.policy_id("php"),
            Err(ToolchainResolutionError::UnsupportedLanguage(language)) if language == "php"
        ));
    }

    #[tokio::test]
    async fn managed_provider_languages_resolve_without_ambient_compilers() {
        let temporary = TempDir::new().expect("managed provider scratch");
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(&root).expect("execution root");
        let resolver = system_resolver(BTreeMap::from([
            ("PATH".into(), "/must/not/enter/provider".into()),
            ("HOME".into(), "/must/not/enter/provider".into()),
            (
                "TMPDIR".into(),
                temporary.path().to_string_lossy().into_owned(),
            ),
        ]));
        for language in ["python", "typescript"] {
            let resolved = resolver
                .resolve(language, &root, &IndexCancellation::new())
                .await
                .expect("self-contained managed environment");
            assert_eq!(resolved.origin, ToolchainOrigin::Managed);
            assert!(resolved.components.is_empty());
            assert_eq!(
                resolved
                    .environment
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec!["TMPDIR"],
                "ambient PATH and HOME must not become provider authority"
            );
        }
    }

    /// FALSIFIER: product startup used to require a global PATH snapshot even
    /// when the only indexed language had a self-contained managed provider.
    /// Ambient compiler authority belongs to the Rust and Go policies which
    /// consume it; it is not a prerequisite for constructing the product.
    #[tokio::test]
    async fn product_capture_without_path_defers_authority_to_each_language() {
        let temporary = TempDir::new().expect("managed provider scratch");
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(&root).expect("execution root");
        let resolver = SystemToolchainResolver::capture_with_go_provider_from(
            [(
                OsString::from("TMPDIR"),
                temporary.path().as_os_str().to_owned(),
            )],
            GoProviderAuthority::ProductEmbedded,
        )
        .expect("a self-contained provider does not require ambient PATH");

        let typescript = resolver
            .resolve("typescript", &root, &IndexCancellation::new())
            .await
            .expect("managed TypeScript authority");
        assert_eq!(typescript.origin, ToolchainOrigin::Managed);
        assert!(typescript.components.is_empty());
        assert_eq!(
            typescript.environment.get("TMPDIR").map(String::as_str),
            temporary.path().to_str(),
            "positive control: the allowed managed-provider environment was captured"
        );

        for language in ["rust", "go"] {
            let error = resolver
                .resolve(language, &root, &IndexCancellation::new())
                .await
                .expect_err("ambient toolchain authority is unavailable without PATH");
            assert!(
                matches!(
                    &error,
                    ToolchainResolutionError::Resolution {
                        language: resolved_language,
                        detail,
                        ..
                    } if resolved_language == language && detail == "PATH snapshot is unavailable"
                ),
                "{language} must own and precisely attribute its missing ambient authority: {error}"
            );
        }
    }

    fn fixture() -> (TempDir, PathBuf, SystemToolchainResolver) {
        let temporary = TempDir::new().expect("toolchain scratch");
        let root = temporary.path().join("repo");
        let sysroot = temporary.path().join("toolchain");
        let bin = sysroot.join("bin");
        std::fs::create_dir_all(&root).expect("execution root");
        std::fs::create_dir_all(&bin).expect("toolchain bin");
        write_tool(
            &bin.join("rustc"),
            &format!(
                "#!/bin/sh\nif [ \"$1\" = \"-vV\" ]; then printf 'rustc 1.97.1\\ncommit-hash: exact\\n'; elif [ \"$1 $2\" = \"--print sysroot\" ]; then printf '%s\\n' '{}'; else exit 9; fi\n",
                sysroot.display()
            ),
        );
        write_tool(
            &bin.join("cargo"),
            "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then printf 'cargo 1.97.1\\n'; else exit 9; fi\n",
        );
        let resolver = system_resolver(BTreeMap::from([
            ("PATH".into(), bin.to_string_lossy().into_owned()),
            ("CARGO_TERM_COLOR".into(), "never".into()),
        ]));
        (temporary, root, resolver)
    }

    fn go_fixture() -> (TempDir, PathBuf, SystemToolchainResolver) {
        let temporary = TempDir::new().expect("Go toolchain scratch");
        let root = temporary.path().join("repo");
        let goroot = temporary.path().join("go-root");
        let bin = temporary.path().join("bin");
        std::fs::create_dir_all(&root).expect("execution root");
        std::fs::create_dir_all(goroot.join("bin")).expect("Go root");
        std::fs::create_dir_all(&bin).expect("toolchain bin");
        write_tool(
            &bin.join("go"),
            &format!(
                "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'go version go1.26.5 linux/amd64\\n'; elif [ \"$1 $2\" = 'env GOROOT' ]; then printf '%s\\n' '{}'; else exit 9; fi\n",
                goroot.display()
            ),
        );
        write_tool(
            &goroot.join("bin/go"),
            "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'go version go1.26.5 linux/amd64\\n'; else exit 9; fi\n",
        );
        write_tool(
            &bin.join("scip-go"),
            "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'scip-go 0.2.7\\n'; else exit 9; fi\n",
        );
        let resolver = system_resolver(BTreeMap::from([
            ("PATH".into(), bin.to_string_lossy().into_owned()),
            (
                "HOME".into(),
                temporary.path().to_string_lossy().into_owned(),
            ),
            ("GOENV".into(), "off".into()),
            ("GOFLAGS".into(), "-mod=readonly".into()),
            ("GOTOOLCHAIN".into(), "local".into()),
            (
                "GOCACHE".into(),
                temporary
                    .path()
                    .join("go-cache")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "GOMODCACHE".into(),
                temporary
                    .path()
                    .join("go-module-cache")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "GOWORK".into(),
                root.join("go.work").to_string_lossy().into_owned(),
            ),
        ]));
        (temporary, root, resolver)
    }

    #[tokio::test]
    async fn system_resolution_is_explicit_and_changes_when_a_tool_changes() {
        let (_temporary, root, resolver) = fixture();
        let cancellation = IndexCancellation::new();
        let first = resolver
            .resolve("rust", &root, &cancellation)
            .await
            .expect("first resolved toolchain");
        assert_eq!(first.components.len(), 2, "positive component population");
        assert_eq!(
            first.environment.get("RUSTC").map(String::as_str),
            first
                .components
                .get("rustc")
                .and_then(|component| component.executable.to_str())
        );

        let cargo = first.components["cargo"].executable.clone();
        write_tool(
            &cargo,
            "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then printf 'cargo 1.97.2\\n'; else exit 9; fi\n",
        );
        let changed = resolver
            .resolve("rust", &root, &cancellation)
            .await
            .expect("changed resolved toolchain");
        assert_ne!(
            first.fingerprint_sha256(),
            changed.fingerprint_sha256(),
            "tool bytes and version drift must change authority"
        );
    }

    /// FALSIFIER: an executable-shaped native build input is not authorized by
    /// its environment string alone. Replacing the executable at the same path
    /// must change the resolved Rust toolchain before a retained provider
    /// session can be reused.
    #[tokio::test]
    async fn rust_resolution_binds_same_path_native_tool_bytes() {
        let (temporary, root, _resolver) = fixture();
        let bin = temporary.path().join("toolchain/bin");
        let cc = bin.join("cc");
        write_tool(&cc, "#!/bin/sh\nprintf 'cc fixture 1.0\\n'\n");
        let resolver = system_resolver(BTreeMap::from([
            ("PATH".into(), bin.to_string_lossy().into_owned()),
            ("CC".into(), cc.to_string_lossy().into_owned()),
        ]));
        let cancellation = IndexCancellation::new();
        let first = resolver
            .resolve("rust", &root, &cancellation)
            .await
            .expect("resolved Rust toolchain with explicit CC");
        assert_eq!(
            first.environment.get("CC").map(String::as_str),
            cc.to_str(),
            "positive control: CC crosses the explicit provider environment"
        );
        assert_eq!(
            first.components["native-cc"].executable, cc,
            "the executable-shaped input must have typed content authority"
        );

        write_tool(
            &cc,
            "#!/bin/sh\nprintf 'cc fixture 1.0\\n'\n# same report, changed executable bytes\n",
        );
        let changed = resolver
            .resolve("rust", &root, &cancellation)
            .await
            .expect("re-observed Rust toolchain with explicit CC");
        assert_eq!(
            first.components["native-cc"].version, changed.components["native-cc"].version,
            "version/report text is deliberately unchanged"
        );
        assert_ne!(
            first.components["native-cc"].executable_sha256,
            changed.components["native-cc"].executable_sha256,
            "same-path native executable bytes are an authority coordinate"
        );
        assert_ne!(
            first.fingerprint_sha256(),
            changed.fingerprint_sha256(),
            "native executable drift must invalidate retained semantic authority"
        );
    }

    /// The native component must name the executable that the sanitized child
    /// environment will actually launch. Rust resolution can prepend the
    /// selected sysroot to PATH, so consulting the earlier captured PATH here
    /// would bind different bytes than the provider receives.
    #[test]
    fn native_build_tool_resolution_uses_exact_child_environment() {
        let temporary = TempDir::new().expect("native PATH scratch");
        let root = temporary.path().join("repo");
        let captured_bin = temporary.path().join("captured-bin");
        let child_bin = temporary.path().join("child-bin");
        std::fs::create_dir_all(&root).expect("execution root");
        std::fs::create_dir_all(&captured_bin).expect("captured PATH");
        std::fs::create_dir_all(&child_bin).expect("child PATH");
        write_tool(&captured_bin.join("cc"), "#!/bin/sh\nexit 0\n");
        write_tool(&child_bin.join("cc"), "#!/bin/sh\nexit 0\n# child\n");

        let child_environment = BTreeMap::from([
            ("PATH".into(), child_bin.to_string_lossy().into_owned()),
            ("CC".into(), "cc".into()),
        ]);
        let resolved = CapturedSystemToolchain::resolve_program_in_environment(
            &child_environment,
            "rust",
            "CC",
            "CC",
            &root,
        )
        .expect("resolve native tool from exact child PATH");
        assert_eq!(resolved, child_bin.join("cc"));
        assert_ne!(resolved, captured_bin.join("cc"), "positive decoy control");
    }

    #[test]
    fn native_build_component_roles_preserve_distinct_target_names() {
        assert_eq!(
            native_build_component_role("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER"),
            "native-cargo_target_aarch64_unknown_linux_gnu_linker"
        );
        assert_ne!(
            native_build_component_role("CC_A_B"),
            native_build_component_role("CC_A-B"),
            "valid environment names must not collapse to one component owner"
        );
    }

    /// RIGHT-REASON REGRESSION: real Cargo/cc-rs target-qualified executable
    /// variables contain architecture digits. The product must represent that
    /// exact executable as typed authority rather than reject an otherwise
    /// valid toolchain because its internal component role contains `64`.
    #[tokio::test]
    async fn target_specific_native_tool_with_digits_is_typed_authority() {
        let (temporary, root, _resolver) = fixture();
        let bin = temporary.path().join("toolchain/bin");
        let target_cc = bin.join("aarch64-cc");
        write_tool(&target_cc, "#!/bin/sh\nexit 0\n");
        let resolver = system_resolver(BTreeMap::from([
            ("PATH".into(), bin.to_string_lossy().into_owned()),
            (
                "CC_aarch64_unknown_linux_gnu".into(),
                target_cc.to_string_lossy().into_owned(),
            ),
        ]));

        let resolved = resolver
            .resolve("rust", &root, &IndexCancellation::new())
            .await
            .expect("target-qualified native toolchain");
        let component = resolved
            .components
            .get("native-cc_aarch64_unknown_linux_gnu")
            .expect("typed target-specific CC authority");
        assert_eq!(component.executable, target_cc);
        assert_eq!(
            resolved
                .environment
                .get("CC_aarch64_unknown_linux_gnu")
                .map(String::as_str),
            target_cc.to_str(),
            "the typed component and exact child environment must name one executable"
        );
    }

    #[tokio::test]
    async fn go_resolution_binds_provider_compiler_environment_and_same_version_bytes() {
        let (_temporary, root, resolver) = go_fixture();
        let cancellation = IndexCancellation::new();
        let first = resolver
            .resolve("go", &root, &cancellation)
            .await
            .expect("resolved Go toolchain");
        assert_eq!(
            first
                .components
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["go", "scip-go"],
            "positive executable population"
        );
        assert_eq!(
            first.environment.get("GOTOOLCHAIN").map(String::as_str),
            Some("local"),
            "system resolution must not silently download another compiler"
        );
        assert_eq!(
            first.environment.get("GOENV").map(String::as_str),
            Some("off")
        );
        assert_eq!(
            first.environment.get("GOFLAGS").map(String::as_str),
            Some("-mod=readonly")
        );
        for name in ["GOCACHE", "GOMODCACHE", "GOWORK"] {
            assert!(
                first.environment.contains_key(name),
                "{name} must survive resolution into the env-cleared provider"
            );
        }

        let provider = first.components["scip-go"].executable.clone();
        let mut bytes = std::fs::read(&provider).expect("provider bytes");
        bytes.extend_from_slice(b"# same version, new bytes\n");
        write_tool(
            &provider,
            std::str::from_utf8(&bytes).expect("UTF-8 fixture script"),
        );
        let changed = resolver
            .resolve("go", &root, &cancellation)
            .await
            .expect("re-observed Go toolchain");
        assert_eq!(
            first.components["scip-go"].version, changed.components["scip-go"].version,
            "version-text positive control"
        );
        assert_ne!(
            first.fingerprint_sha256(),
            changed.fingerprint_sha256(),
            "same-path executable byte drift must invalidate Go authority"
        );
    }

    #[tokio::test]
    async fn malformed_go_identity_report_is_attributed_to_go() {
        let (temporary, root, resolver) = go_fixture();
        write_tool(
            &temporary.path().join("go-root/bin/go"),
            "#!/bin/sh\nif [ \"$1\" = version ]; then printf '\\377'; else exit 9; fi\n",
        );
        let error = resolver
            .resolve("go", &root, &IndexCancellation::new())
            .await
            .expect_err("non-UTF-8 Go identity must be rejected");
        assert!(matches!(
            error,
            ToolchainResolutionError::Resolution { language, .. } if language == "go"
        ));
    }

    #[tokio::test]
    async fn go_population_probes_one_shared_tool_identity_and_rebinds_both_roots() {
        let (temporary, root, resolver) = go_fixture();
        let other_root = temporary.path().join("other-repo");
        std::fs::create_dir_all(&other_root).expect("second execution root");
        let log = temporary.path().join("toolchain-probes.log");
        let bin = temporary.path().join("bin");
        let goroot = temporary.path().join("go-root");
        write_tool(
            &bin.join("go"),
            &format!(
                "#!/bin/sh\nprintf 'go:%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = version ]; then printf 'go version go1.26.5 linux/amd64\\n'; elif [ \"$1 $2\" = 'env GOROOT' ]; then printf '%s\\n' '{}'; else exit 9; fi\n",
                log.display(),
                goroot.display(),
            ),
        );
        write_tool(
            &bin.join("scip-go"),
            &format!(
                "#!/bin/sh\nprintf 'scip-go:%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = --version ]; then printf 'scip-go 0.2.7\\n'; else exit 9; fi\n",
                log.display(),
            ),
        );
        let roots = [root.clone(), other_root.clone()];
        let resolved = resolver
            .resolve_population("go", &roots, &IndexCancellation::new())
            .await
            .expect("shared Go toolchain population");
        assert_eq!(resolved.len(), 2, "positive root population");
        assert_eq!(
            resolved
                .iter()
                .map(|toolchain| toolchain.execution_root.clone())
                .collect::<Vec<_>>(),
            roots
                .iter()
                .map(|root| std::fs::canonicalize(root).expect("canonical root"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            resolved[0].fingerprint_sha256(),
            resolved[1].fingerprint_sha256(),
            "execution-root topology must not duplicate tool identity"
        );
        let probes = std::fs::read_to_string(&log).expect("toolchain probe log");
        assert_eq!(
            probes
                .lines()
                .filter(|line| line.starts_with("go:"))
                .count(),
            2,
            "each root must resolve its effective GOROOT through the shared launcher"
        );
        assert_eq!(
            probes
                .lines()
                .filter(|line| line.starts_with("scip-go:"))
                .count(),
            1,
            "one shared scip-go executable must be probed once per authority epoch"
        );
    }

    /// FALSIFIER: a shared launcher path is not a shared effective Rust
    /// toolchain. `rustup`-style proxies select a sysroot from the invocation
    /// directory, so every execution root must establish its own effective
    /// identity before any result can be reused.
    #[tokio::test]
    async fn rust_population_keeps_directory_selected_effective_toolchains_distinct() {
        let temporary = TempDir::new().expect("directory-selected toolchain scratch");
        let alpha_root = temporary.path().join("alpha");
        let beta_root = temporary.path().join("beta");
        let launcher_bin = temporary.path().join("launcher-bin");
        let alpha_sysroot = temporary.path().join("alpha-toolchain");
        let beta_sysroot = temporary.path().join("beta-toolchain");
        for directory in [
            &alpha_root,
            &beta_root,
            &launcher_bin,
            &alpha_sysroot.join("bin"),
            &beta_sysroot.join("bin"),
        ] {
            std::fs::create_dir_all(directory).expect("toolchain fixture directory");
        }
        let alpha_root = canonical_fixture_path(alpha_root);
        let beta_root = canonical_fixture_path(beta_root);
        let launcher_bin = canonical_fixture_path(launcher_bin);
        let alpha_sysroot = canonical_fixture_path(alpha_sysroot);
        let beta_sysroot = canonical_fixture_path(beta_sysroot);

        write_tool(
            &launcher_bin.join("rustc"),
            &format!(
                "#!/bin/sh\nif [ \"$PWD\" = '{}' ]; then label=alpha; sysroot='{}'; else label=beta; sysroot='{}'; fi\nif [ \"$1\" = -vV ]; then printf 'rustc 1.97.1-%s\\ncommit-hash: %s\\n' \"$label\" \"$label\"; elif [ \"$1 $2\" = '--print sysroot' ]; then printf '%s\\n' \"$sysroot\"; else exit 9; fi\n",
                alpha_root.display(),
                alpha_sysroot.display(),
                beta_sysroot.display(),
            ),
        );
        write_tool(
            &launcher_bin.join("cargo"),
            &format!(
                "#!/bin/sh\nif [ \"$PWD\" = '{}' ]; then label=alpha; else label=beta; fi\nif [ \"$1\" = -V ]; then printf 'cargo 1.97.1-%s\\n' \"$label\"; else exit 9; fi\n",
                alpha_root.display(),
            ),
        );
        for (label, sysroot) in [("alpha", &alpha_sysroot), ("beta", &beta_sysroot)] {
            write_tool(
                &sysroot.join("bin/rustc"),
                &format!(
                    "#!/bin/sh\nif [ \"$1\" = -vV ]; then printf 'rustc 1.97.1-{label}\\ncommit-hash: {label}\\n'; else exit 9; fi\n"
                ),
            );
            write_tool(
                &sysroot.join("bin/cargo"),
                &format!(
                    "#!/bin/sh\nif [ \"$1\" = -V ]; then printf 'cargo 1.97.1-{label}\\n'; else exit 9; fi\n"
                ),
            );
        }
        let captured = CapturedSystemToolchain {
            environment: BTreeMap::from([(
                "PATH".into(),
                launcher_bin.to_string_lossy().into_owned(),
            )]),
            command_timeout: Duration::from_secs(2),
        };
        assert_eq!(
            captured
                .resolve_program("rust", "RUSTC", "rustc", &alpha_root)
                .expect("alpha launcher"),
            captured
                .resolve_program("rust", "RUSTC", "rustc", &beta_root)
                .expect("beta launcher"),
            "positive control: both roots enter through the same launcher bytes"
        );
        let resolver =
            SystemToolchainResolver::from_captured(captured, GoProviderAuthority::SystemScip);

        let resolved = resolver
            .resolve_population(
                "rust",
                &[alpha_root.clone(), beta_root.clone()],
                &IndexCancellation::new(),
            )
            .await
            .expect("directory-selected Rust population");
        assert_eq!(resolved.len(), 2, "positive root population");
        assert_eq!(
            resolved[0].sysroot.as_deref(),
            Some(alpha_sysroot.as_path())
        );
        assert_eq!(resolved[1].sysroot.as_deref(), Some(beta_sysroot.as_path()));
        assert_ne!(
            resolved[0].fingerprint_sha256(),
            resolved[1].fingerprint_sha256(),
            "directory-selected effective Rust identities must never be collapsed"
        );
    }

    /// FALSIFIER: `GOTOOLCHAIN=local` disables Go's own automatic selection,
    /// but a PATH launcher may still be a directory-sensitive version-manager
    /// shim. Equal launcher bytes do not authorize sharing different effective
    /// GOROOT populations.
    #[tokio::test]
    async fn go_population_keeps_directory_selected_effective_goroots_distinct() {
        let temporary = TempDir::new().expect("directory-selected Go scratch");
        let alpha_root = temporary.path().join("alpha");
        let beta_root = temporary.path().join("beta");
        let launcher_bin = temporary.path().join("launcher-bin");
        let alpha_goroot = temporary.path().join("alpha-go");
        let beta_goroot = temporary.path().join("beta-go");
        for directory in [
            &alpha_root,
            &beta_root,
            &launcher_bin,
            &alpha_goroot.join("bin"),
            &beta_goroot.join("bin"),
        ] {
            std::fs::create_dir_all(directory).expect("Go selector fixture directory");
        }
        let alpha_root = canonical_fixture_path(alpha_root);
        let beta_root = canonical_fixture_path(beta_root);
        let launcher_bin = canonical_fixture_path(launcher_bin);
        let alpha_goroot = canonical_fixture_path(alpha_goroot);
        let beta_goroot = canonical_fixture_path(beta_goroot);
        write_tool(
            &launcher_bin.join("go"),
            &format!(
                "#!/bin/sh\nif [ \"$PWD\" = '{}' ]; then label=alpha; goroot='{}'; else label=beta; goroot='{}'; fi\nif [ \"$1\" = version ]; then printf 'go version go1.26.5-%s linux/amd64\\n' \"$label\"; elif [ \"$1 $2\" = 'env GOROOT' ]; then printf '%s\\n' \"$goroot\"; else exit 9; fi\n",
                alpha_root.display(),
                alpha_goroot.display(),
                beta_goroot.display(),
            ),
        );
        write_tool(
            &launcher_bin.join("scip-go"),
            "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'scip-go 0.2.7\\n'; else exit 9; fi\n",
        );
        for (label, goroot) in [("alpha", &alpha_goroot), ("beta", &beta_goroot)] {
            write_tool(
                &goroot.join("bin/go"),
                &format!(
                    "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'go version go1.26.5-{label} linux/amd64\\n'; else exit 9; fi\n"
                ),
            );
        }
        let resolver = system_resolver(BTreeMap::from([
            ("PATH".into(), launcher_bin.to_string_lossy().into_owned()),
            ("GOENV".into(), "off".into()),
            ("GOFLAGS".into(), "-mod=readonly".into()),
            ("GOTOOLCHAIN".into(), "local".into()),
        ]));

        let resolved = resolver
            .resolve_population(
                "go",
                &[alpha_root.clone(), beta_root.clone()],
                &IndexCancellation::new(),
            )
            .await
            .expect("directory-selected Go population");
        assert_eq!(resolved.len(), 2, "positive root population");
        assert_eq!(resolved[0].sysroot.as_deref(), Some(alpha_goroot.as_path()));
        assert_eq!(resolved[1].sysroot.as_deref(), Some(beta_goroot.as_path()));
        assert_ne!(
            resolved[0].fingerprint_sha256(),
            resolved[1].fingerprint_sha256(),
            "directory-selected effective Go identities must never be collapsed"
        );
    }

    #[tokio::test]
    async fn go_population_never_collapses_distinct_root_relative_toolchains() {
        let temporary = TempDir::new().expect("root-relative toolchain scratch");
        let log = temporary.path().join("toolchain-probes.log");
        let mut roots = Vec::new();
        for label in ["alpha", "beta"] {
            let root = temporary.path().join(label);
            let bin = root.join("tools");
            let goroot = root.join("go-root");
            std::fs::create_dir_all(&bin).expect("root-local tool directory");
            std::fs::create_dir_all(goroot.join("bin")).expect("root-local Go root");
            write_tool(
                &bin.join("go"),
                &format!(
                    "#!/bin/sh\nprintf '{label}-go:%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = version ]; then printf 'go version go1.26.5-{label} linux/amd64\\n'; elif [ \"$1 $2\" = 'env GOROOT' ]; then printf '%s\\n' '{}'; else exit 9; fi\n",
                    log.display(),
                    goroot.display(),
                ),
            );
            write_tool(
                &goroot.join("bin/go"),
                &format!(
                    "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'go version go1.26.5-{label} linux/amd64\\n'; else exit 9; fi\n"
                ),
            );
            write_tool(
                &bin.join("scip-go"),
                &format!(
                    "#!/bin/sh\nprintf '{label}-scip-go:%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = --version ]; then printf 'scip-go 0.2.7-{label}\\n'; else exit 9; fi\n",
                    log.display(),
                ),
            );
            roots.push(root);
        }
        let resolver = system_resolver(BTreeMap::from([
            ("GO".into(), "tools/go".into()),
            ("SCIP_GO".into(), "tools/scip-go".into()),
            ("GOENV".into(), "off".into()),
            ("GOFLAGS".into(), "-mod=readonly".into()),
            ("GOTOOLCHAIN".into(), "local".into()),
        ]));

        let resolved = resolver
            .resolve_population("go", &roots, &IndexCancellation::new())
            .await
            .expect("distinct root-local Go toolchains");
        assert_eq!(resolved.len(), 2, "positive root population");
        assert_ne!(
            resolved[0].fingerprint_sha256(),
            resolved[1].fingerprint_sha256(),
            "different executable paths and reports are separate authority"
        );
        let probes = std::fs::read_to_string(&log).expect("root-local probe log");
        for label in ["alpha", "beta"] {
            assert_eq!(
                probes
                    .lines()
                    .filter(|line| line.starts_with(&format!("{label}-go:")))
                    .count(),
                1,
                "each root-local launcher must establish its effective GOROOT"
            );
            assert_eq!(
                probes
                    .lines()
                    .filter(|line| line.starts_with(&format!("{label}-scip-go:")))
                    .count(),
                1,
                "each distinct provider identity must be probed"
            );
        }
    }

    #[tokio::test]
    async fn cancelled_or_unsupported_resolution_grants_no_toolchain_authority() {
        let (_temporary, root, resolver) = fixture();
        let cancellation = IndexCancellation::new();
        cancellation.cancel();
        assert_eq!(
            resolver.resolve("rust", &root, &cancellation).await,
            Err(ToolchainResolutionError::Cancelled)
        );
        assert!(matches!(
            resolver
                .resolve("php", &root, &IndexCancellation::new())
                .await,
            Err(ToolchainResolutionError::UnsupportedLanguage(language))
                if language == "php"
        ));
    }

    #[test]
    fn explicit_cargo_and_rustc_overrides_are_captured_as_toolchain_inputs() {
        let environment = capture_environment([
            (OsString::from("PATH"), OsString::from("/tools/bin")),
            (OsString::from("CARGO"), OsString::from("/exact/cargo")),
            (OsString::from("RUSTC"), OsString::from("/exact/rustc")),
        ])
        .expect("UTF-8 environment");
        assert_eq!(
            environment.get("CARGO").map(String::as_str),
            Some("/exact/cargo")
        );
        assert_eq!(
            environment.get("RUSTC").map(String::as_str),
            Some("/exact/rustc")
        );
    }

    /// FALSIFIER: resolving exact Cargo and rustc binaries is insufficient when
    /// the indexed workspace relies on a legitimate native build environment.
    /// The provider clears its ambient environment before launch, so every
    /// admitted native-build input must be selected here and subsequently bound
    /// into the resolved-toolchain fingerprint. Unrelated application secrets
    /// must not cross that boundary.
    #[test]
    fn native_build_environment_is_selected_without_inheriting_unrelated_state() {
        let environment = capture_environment([
            (OsString::from("PATH"), OsString::from("/tools/bin")),
            (OsString::from("CC"), OsString::from("/tools/bin/cc")),
            (
                OsString::from("NIX_LDFLAGS"),
                OsString::from("-L/nix/store/openssl/lib"),
            ),
            (
                OsString::from("OPENSSL_LIB_DIR"),
                OsString::from("/nix/store/openssl/lib"),
            ),
            (
                OsString::from("PKG_CONFIG_PATH"),
                OsString::from("/tools/lib/pkgconfig"),
            ),
            (
                OsString::from("LD_LIBRARY_PATH"),
                OsString::from("/tools/lib:/native/lib"),
            ),
            (
                OsString::from("CC_aarch64_unknown_linux_gnu"),
                OsString::from("/tools/bin/aarch64-linux-gnu-cc"),
            ),
            (
                OsString::from("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER"),
                OsString::from("/tools/bin/aarch64-linux-gnu-cc"),
            ),
            (
                OsString::from("DATABASE_URL"),
                OsString::from("postgres://must-not-cross"),
            ),
            (
                OsString::from("CARGO_REGISTRIES_PRIVATE_TOKEN"),
                OsString::from("must-not-cross"),
            ),
        ])
        .expect("UTF-8 build environment");

        for name in [
            "CC",
            "NIX_LDFLAGS",
            "OPENSSL_LIB_DIR",
            "PKG_CONFIG_PATH",
            "LD_LIBRARY_PATH",
            "CC_aarch64_unknown_linux_gnu",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER",
        ] {
            assert!(
                environment.contains_key(name),
                "native build input {name} must survive the explicit launch boundary"
            );
        }
        assert!(
            !environment.contains_key("DATABASE_URL"),
            "unrelated application state must not be inherited by build scripts"
        );
        assert!(
            !environment.contains_key("CARGO_REGISTRIES_PRIVATE_TOKEN"),
            "registry credentials must not cross the provider launch boundary"
        );

        let baseline = ResolvedToolchain::new(
            "rust",
            "/repo",
            ToolchainOrigin::System,
            [
                ResolvedToolchainComponent::new(
                    "cargo",
                    "/tools/bin/cargo",
                    "a".repeat(64),
                    "cargo 1.97.1",
                )
                .expect("cargo component"),
                ResolvedToolchainComponent::new(
                    "rustc",
                    "/tools/bin/rustc",
                    "b".repeat(64),
                    "rustc 1.97.1",
                )
                .expect("rustc component"),
            ],
            Some(PathBuf::from("/tools")),
            environment.clone(),
        )
        .expect("baseline toolchain");
        let mut changed_environment = environment;
        changed_environment.insert("NIX_LDFLAGS".into(), "-L/nix/store/other/lib".into());
        let changed = ResolvedToolchain::new(
            "rust",
            "/repo",
            ToolchainOrigin::System,
            baseline.components.values().cloned(),
            baseline.sysroot.clone(),
            changed_environment,
        )
        .expect("changed toolchain");
        assert_ne!(
            baseline.fingerprint_sha256(),
            changed.fingerprint_sha256(),
            "native build-environment drift must invalidate semantic authority"
        );
    }
}
