//! Supervised lifecycle for one exact persistent semantic-provider process.
//!
//! The child is disposable acceleration state. A transport, identity, timeout,
//! cancellation, or terminal-claim failure quarantines and reaps it; callers
//! must then create a new process and obtain a new full certification before
//! any affected-document result can carry authority.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use uuid::Uuid;

use h00ligan_provider_protocol::{
    PROVIDER_FRAME_HEADER_BYTES, ProviderFrame, ProviderFrameLimits, ProviderIdentity,
    ProviderOperation, ProviderRequest, ProviderRequestBody, ProviderRequestClaims,
    ProviderResponse, ProviderResponseBody, ProviderRuntimeConfiguration,
    SemanticProviderProtocolError, decode_provider_frame, encode_provider_frame,
    provider_frame_total_len_from_header, validate_provider_identity, validate_provider_request,
    validate_runtime_configuration,
};

use crate::code_intel_cancellation::IndexCancellation;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);
const DEFAULT_STDERR_BYTES: usize = 64 * 1024;
const REAP_TIMEOUT: Duration = Duration::from_secs(5);
const STDERR_DRAIN_TIMEOUT: Duration = Duration::from_millis(100);
const ERROR_STDERR_CHARS: usize = 2_048;

/// Explicit launch inputs. The environment is empty unless the owner supplies
/// exact entries; ambient compiler wrappers, Rust flags, and provider options
/// are never inherited accidentally.
#[derive(Debug, Clone)]
pub struct SemanticProviderProcessConfig {
    pub binary: PathBuf,
    pub expected_identity: ProviderIdentity,
    pub expected_toolchain_sha256: String,
    pub arguments: Vec<OsString>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub request_timeout: Duration,
    pub max_stderr_bytes: usize,
}

impl SemanticProviderProcessConfig {
    #[must_use]
    pub fn new(
        binary: impl Into<PathBuf>,
        expected_identity: ProviderIdentity,
        expected_toolchain_sha256: impl Into<String>,
        working_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            binary: binary.into(),
            expected_identity,
            expected_toolchain_sha256: expected_toolchain_sha256.into(),
            arguments: Vec::new(),
            working_directory: working_directory.into(),
            environment: BTreeMap::new(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_stderr_bytes: DEFAULT_STDERR_BYTES,
        }
    }
}

#[derive(Debug, Error)]
pub enum SemanticProviderProcessError {
    #[error("semantic-provider launch configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("semantic-provider executable differs from its expected identity")]
    ExecutableIdentityMismatch,
    #[error("semantic-provider filesystem operation failed: {0}")]
    Filesystem(String),
    #[error("semantic-provider process could not start: {0}")]
    Spawn(String),
    #[error("semantic-provider protocol failed: {0}")]
    Protocol(#[from] SemanticProviderProtocolError),
    #[error("semantic-provider request timed out")]
    Timeout,
    #[error("semantic-provider request was cancelled")]
    Cancelled,
    #[error("semantic-provider process exited before its terminal response")]
    Exited,
    #[error(
        "semantic-provider process failed: {source}; status={status}; stderr_tail={stderr_tail:?}"
    )]
    ProcessFailure {
        #[source]
        source: Box<Self>,
        status: String,
        stderr_tail: String,
    },
    #[error("semantic-provider terminal identity differs from the active process")]
    TerminalIdentityMismatch,
    #[error("semantic-provider returned a terminal for a different operation")]
    UnexpectedTerminal,
    #[error("semantic-provider hello returned an unexpected terminal")]
    UnexpectedHello,
    #[error("semantic-provider wire limits differ from the exact client build")]
    LimitsMismatch,
    #[error("semantic-provider runtime configuration is invalid")]
    RuntimeConfigurationInvalid,
    #[error("semantic-provider runtime differs from the resolved product toolchain")]
    ToolchainIdentityMismatch,
    #[error("semantic-provider process is quarantined")]
    Quarantined,
    #[error("semantic-provider close did not terminate cleanly")]
    CloseFailed,
}

struct ProviderChild {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    process_group: i32,
    stderr_task: JoinHandle<()>,
}

/// One uniquely identified provider boot.
///
/// Requests are sequential because the pinned provider owns one mutable
/// AnalysisHost. Every terminal is claimed once before it is returned to
/// higher-level authority admission.
pub struct SemanticProviderProcess {
    identity: ProviderIdentity,
    runtime_configuration: ProviderRuntimeConfiguration,
    limits: ProviderFrameLimits,
    session_id: String,
    claims: ProviderRequestClaims,
    child: Option<ProviderChild>,
    request_timeout: Duration,
    stderr: Arc<Mutex<VecDeque<u8>>>,
    quarantined: bool,
}

impl SemanticProviderProcess {
    /// Verify the expected identity and executable, start an isolated child, and
    /// complete an exact identity/limit hello before returning it.
    pub async fn spawn(
        config: SemanticProviderProcessConfig,
    ) -> Result<Self, SemanticProviderProcessError> {
        if config.request_timeout.is_zero()
            || config.max_stderr_bytes == 0
            || !is_sha256(&config.expected_toolchain_sha256)
        {
            return Err(SemanticProviderProcessError::InvalidConfiguration(
                "timeout and stderr bound must be nonzero".into(),
            ));
        }
        let (binary, working_directory, identity) = verify_executable(&config)?;
        let mut command = Command::new(binary);
        command
            .args(&config.arguments)
            .current_dir(working_directory)
            .env_clear()
            .envs(&config.environment)
            .env(
                h00ligan_provider_protocol::PROVIDER_PARENT_PID_ENV,
                std::process::id().to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .spawn()
            .map_err(|error| SemanticProviderProcessError::Spawn(error.to_string()))?;
        let process_group = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .ok_or_else(|| {
                SemanticProviderProcessError::Spawn("child PID is unavailable".into())
            })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            SemanticProviderProcessError::Spawn("child stdin is unavailable".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            SemanticProviderProcessError::Spawn("child stdout is unavailable".into())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            SemanticProviderProcessError::Spawn("child stderr is unavailable".into())
        })?;
        let stderr_tail = Arc::new(Mutex::new(VecDeque::with_capacity(config.max_stderr_bytes)));
        let stderr_task = tokio::spawn(drain_stderr(
            stderr,
            Arc::clone(&stderr_tail),
            config.max_stderr_bytes,
        ));
        let limits = ProviderFrameLimits::default();
        let session_id = format!("provider-{}", Uuid::new_v4().simple());
        let claims =
            ProviderRequestClaims::new(session_id.clone(), limits.max_outstanding_requests)?;
        let mut provider = Self {
            identity,
            runtime_configuration: ProviderRuntimeConfiguration {
                configuration_sha256: String::new(),
                resolved_toolchain_sha256: String::new(),
                component_sha256s: BTreeMap::new(),
                environment_sha256: String::new(),
                workspace_configuration_sha256: String::new(),
            },
            limits,
            session_id,
            claims,
            child: Some(ProviderChild {
                child,
                stdin,
                stdout,
                process_group,
                stderr_task,
            }),
            request_timeout: config.request_timeout,
            stderr: stderr_tail,
            quarantined: false,
        };
        let hello = provider
            .request(ProviderRequestBody::Hello, Vec::new(), None)
            .await?;
        match hello.metadata.body {
            ProviderResponseBody::Hello {
                limits,
                runtime_configuration,
            } if limits == provider.limits => {
                if validate_runtime_configuration(&runtime_configuration).is_err() {
                    let _ = provider.quarantine().await;
                    return Err(SemanticProviderProcessError::RuntimeConfigurationInvalid);
                }
                if runtime_configuration.resolved_toolchain_sha256
                    != config.expected_toolchain_sha256
                {
                    let _ = provider.quarantine().await;
                    return Err(SemanticProviderProcessError::ToolchainIdentityMismatch);
                }
                provider.runtime_configuration = runtime_configuration;
                Ok(provider)
            }
            ProviderResponseBody::Hello { .. } => {
                let _ = provider.quarantine().await;
                Err(SemanticProviderProcessError::LimitsMismatch)
            }
            _ => {
                let _ = provider.quarantine().await;
                Err(SemanticProviderProcessError::UnexpectedHello)
            }
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn limits(&self) -> ProviderFrameLimits {
        self.limits
    }

    #[must_use]
    pub const fn runtime_configuration(&self) -> &ProviderRuntimeConfiguration {
        &self.runtime_configuration
    }

    #[must_use]
    pub fn stderr_tail(&self) -> String {
        let bytes = self.stderr.lock().iter().copied().collect::<Vec<_>>();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Observe whether this exact owned child has already exited without
    /// issuing a provider request.
    ///
    /// A `false` result is deliberately not runtime authority: the child may
    /// still fail immediately afterward. This observation exists only so a
    /// coordinator can discard a process that is *already known dead* before
    /// choosing an incremental repair lane. `try_wait` also reaps that exact
    /// terminal child; normal drop cleanup still terminates its process group.
    pub fn observe_local_exit(&mut self) -> Result<bool, SemanticProviderProcessError> {
        if self.quarantined {
            return Ok(true);
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(true);
        };
        child
            .child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))
    }

    /// Send one exact request and return its one-use terminal. Any uncertainty
    /// kills this boot, so callers cannot continue incrementally after a
    /// partial frame, timeout, cancellation, crash, or identity mismatch.
    pub async fn request(
        &mut self,
        body: ProviderRequestBody,
        attachments: Vec<Vec<u8>>,
        cancellation: Option<&IndexCancellation>,
    ) -> Result<ProviderFrame<ProviderResponse>, SemanticProviderProcessError> {
        if self.quarantined {
            return Err(SemanticProviderProcessError::Quarantined);
        }
        let operation = operation_for_request(&body);
        let request_id = self.claims.issue(operation)?;
        let request = ProviderFrame {
            metadata: ProviderRequest {
                request_id,
                session_id: self.session_id.clone(),
                expected_provider: self.identity.clone(),
                body,
            },
            attachments,
        };
        if let Err(error) = validate_provider_request(&request, &self.limits) {
            let _ = self.quarantine().await;
            return Err(error.into());
        }
        let encoded = match encode_provider_frame(&request, &self.limits) {
            Ok(encoded) => encoded,
            Err(error) => {
                let _ = self.quarantine().await;
                return Err(error.into());
            }
        };
        let response = self.exchange(encoded, cancellation).await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                let contextualize = matches!(
                    error,
                    SemanticProviderProcessError::Filesystem(_)
                        | SemanticProviderProcessError::Protocol(_)
                        | SemanticProviderProcessError::Exited
                );
                let status = self.quarantine().await;
                if contextualize {
                    return Err(self.process_failure(error, status));
                }
                return Err(error);
            }
        };
        if response.metadata.request_id != request_id
            || response.metadata.session_id != self.session_id
            || response.metadata.provider != self.identity
        {
            let _ = self.quarantine().await;
            return Err(SemanticProviderProcessError::TerminalIdentityMismatch);
        }
        let is_error_terminal =
            matches!(response.metadata.body, ProviderResponseBody::Error { .. });
        if !is_error_terminal && operation_for_response(&response.metadata.body) != Some(operation)
        {
            let _ = self.quarantine().await;
            return Err(SemanticProviderProcessError::UnexpectedTerminal);
        }
        if let Err(error) = self.claims.claim(&self.session_id, request_id, operation) {
            let _ = self.quarantine().await;
            return Err(error.into());
        }
        // Every provider Error is explicitly non-retryable in this protocol.
        // Preserve the bounded terminal for caller diagnostics, but reap this
        // boot before returning it: an adapter may have partially mutated its
        // compiler/session state before discovering the failure, so no later
        // request may inherit authority from that uncertain state.
        if is_error_terminal {
            let _ = self.quarantine().await;
        }
        Ok(response)
    }

    /// End the exact boot. The CloseSession terminal proves the provider saw
    /// this owner's request; the disposable process group is then killed and
    /// reaped deliberately so rust-analyzer destructor latency cannot strand
    /// CLI/MCP/WATCH shutdown or leave descendants behind.
    pub async fn close(mut self) -> Result<(), SemanticProviderProcessError> {
        let response = self
            .request(ProviderRequestBody::CloseSession, Vec::new(), None)
            .await?;
        if !matches!(response.metadata.body, ProviderResponseBody::SessionClosed) {
            let _ = self.quarantine().await;
            return Err(SemanticProviderProcessError::CloseFailed);
        }
        let Some(mut child) = self.child.take() else {
            return Err(SemanticProviderProcessError::CloseFailed);
        };
        let _ = terminate_child(&mut child).await;
        Ok(())
    }

    async fn exchange(
        &mut self,
        encoded: Vec<u8>,
        cancellation: Option<&IndexCancellation>,
    ) -> Result<ProviderFrame<ProviderResponse>, SemanticProviderProcessError> {
        let child = self
            .child
            .as_mut()
            .ok_or(SemanticProviderProcessError::Quarantined)?;
        if child
            .child
            .try_wait()
            .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?
            .is_some()
        {
            return Err(SemanticProviderProcessError::Exited);
        }
        let exchange = async {
            child
                .stdin
                .write_all(&encoded)
                .await
                .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
            child
                .stdin
                .flush()
                .await
                .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
            read_async_frame(&mut child.stdout, &self.limits).await
        };
        let timed = timeout(self.request_timeout, exchange);
        if let Some(cancellation) = cancellation {
            tokio::select! {
                result = timed => result.map_err(|_| SemanticProviderProcessError::Timeout)?,
                () = wait_for_cancellation(cancellation) => Err(SemanticProviderProcessError::Cancelled),
            }
        } else {
            timed
                .await
                .map_err(|_| SemanticProviderProcessError::Timeout)?
        }
    }

    async fn quarantine(&mut self) -> Option<ExitStatus> {
        self.quarantined = true;
        let mut child = self.child.take()?;
        terminate_child(&mut child).await
    }

    fn process_failure(
        &self,
        source: SemanticProviderProcessError,
        status: Option<ExitStatus>,
    ) -> SemanticProviderProcessError {
        let stderr_tail = self.stderr_tail();
        SemanticProviderProcessError::ProcessFailure {
            source: Box::new(source),
            status: status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "unknown".to_owned()),
            stderr_tail: bounded_suffix(&stderr_tail, ERROR_STDERR_CHARS),
        }
    }
}

impl Drop for SemanticProviderProcess {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        kill_process_group(child.process_group);
        let _ = child.child.start_kill();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = timeout(REAP_TIMEOUT, child.child.wait()).await;
                child.stderr_task.abort();
            });
        } else {
            child.stderr_task.abort();
        }
    }
}

const fn operation_for_request(body: &ProviderRequestBody) -> ProviderOperation {
    match body {
        ProviderRequestBody::Hello => ProviderOperation::Hello,
        ProviderRequestBody::OpenSession { .. } => ProviderOperation::OpenSession,
        ProviderRequestBody::ReconfigureSession { .. } => ProviderOperation::ReconfigureSession,
        ProviderRequestBody::ApplyEpoch { .. } => ProviderOperation::ApplyEpoch,
        ProviderRequestBody::RefreshAffected { .. } => ProviderOperation::RefreshAffected,
        ProviderRequestBody::CertifyFull { .. } => ProviderOperation::CertifyFull,
        ProviderRequestBody::CloseSession => ProviderOperation::CloseSession,
    }
}

const fn operation_for_response(body: &ProviderResponseBody) -> Option<ProviderOperation> {
    match body {
        ProviderResponseBody::Hello { .. } => Some(ProviderOperation::Hello),
        ProviderResponseBody::SessionOpened { .. } => Some(ProviderOperation::OpenSession),
        ProviderResponseBody::SessionReconfigured { .. } => {
            Some(ProviderOperation::ReconfigureSession)
        }
        ProviderResponseBody::EpochApplied { .. } => Some(ProviderOperation::ApplyEpoch),
        ProviderResponseBody::AffectedRefreshed { .. } => Some(ProviderOperation::RefreshAffected),
        ProviderResponseBody::FullCertification { .. } => Some(ProviderOperation::CertifyFull),
        ProviderResponseBody::SessionClosed => Some(ProviderOperation::CloseSession),
        ProviderResponseBody::Error { .. } => None,
    }
}

async fn read_async_frame(
    reader: &mut ChildStdout,
    limits: &ProviderFrameLimits,
) -> Result<ProviderFrame<ProviderResponse>, SemanticProviderProcessError> {
    let mut header = [0_u8; PROVIDER_FRAME_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
    let total_len = provider_frame_total_len_from_header(&header, limits)?;
    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(&header);
    encoded.resize(total_len, 0);
    reader
        .read_exact(&mut encoded[PROVIDER_FRAME_HEADER_BYTES..])
        .await
        .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
    Ok(decode_provider_frame(&encoded, limits)?)
}

async fn wait_for_cancellation(cancellation: &IndexCancellation) {
    while !cancellation.is_cancelled() {
        sleep(Duration::from_millis(5)).await;
    }
}

async fn drain_stderr(
    mut stderr: tokio::process::ChildStderr,
    tail: Arc<Mutex<VecDeque<u8>>>,
    limit: usize,
) {
    let mut chunk = [0_u8; 4096];
    loop {
        let Ok(read) = stderr.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        let mut tail = tail.lock();
        tail.extend(&chunk[..read]);
        while tail.len() > limit {
            tail.pop_front();
        }
        drop(tail);
    }
}

fn verify_executable(
    config: &SemanticProviderProcessConfig,
) -> Result<(PathBuf, PathBuf, ProviderIdentity), SemanticProviderProcessError> {
    let binary = verify_provider_executable(&config.binary, &config.expected_identity)?;
    let working_directory = std::fs::canonicalize(&config.working_directory)
        .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
    Ok((binary, working_directory, config.expected_identity.clone()))
}

/// Validate one executable against an explicit build identity without
/// starting it. The protocol hello independently proves the spawned child
/// reports this same identity, closing a path-replacement race fail-closed.
pub(crate) fn verify_provider_executable(
    binary: &Path,
    expected_identity: &ProviderIdentity,
) -> Result<PathBuf, SemanticProviderProcessError> {
    validate_provider_identity(expected_identity)?;
    let binary = std::fs::canonicalize(binary)
        .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
    let metadata = std::fs::metadata(&binary)
        .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
    if !metadata.is_file() {
        return Err(SemanticProviderProcessError::ExecutableIdentityMismatch);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(SemanticProviderProcessError::ExecutableIdentityMismatch);
        }
    }
    if sha256_file(&binary)? != expected_identity.executable_sha256 {
        return Err(SemanticProviderProcessError::ExecutableIdentityMismatch);
    }
    Ok(binary)
}

async fn terminate_child(child: &mut ProviderChild) -> Option<ExitStatus> {
    let mut observed_status = child.child.try_wait().ok().flatten();
    kill_process_group(child.process_group);
    let _ = child.child.start_kill();
    // Tokio's `Child::wait` can remain pending until its full timeout after a
    // process-group kill even when the direct child has already disappeared.
    // Polling `try_wait` both reaps the exact child and observes an already
    // completed runtime reap without charging that false five-second tail to
    // every CLI/MCP/WATCH shutdown.
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        match child.child.try_wait() {
            Ok(Some(status)) => {
                observed_status = Some(status);
                break;
            }
            Err(_) => break,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => sleep(Duration::from_millis(10)).await,
        }
    }
    if timeout(STDERR_DRAIN_TIMEOUT, &mut child.stderr_task)
        .await
        .is_err()
    {
        child.stderr_task.abort();
    }
    observed_status
}

fn bounded_suffix(value: &str, max_chars: usize) -> String {
    let mut suffix = value.chars().rev().take(max_chars).collect::<Vec<_>>();
    suffix.reverse();
    suffix.into_iter().collect()
}

fn sha256_file(path: &Path) -> Result<String, SemanticProviderProcessError> {
    let mut file = File::open(path)
        .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| SemanticProviderProcessError::Filesystem(error.to_string()))?;
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn kill_process_group(process_group: i32) {
    // SAFETY: the child was spawned into a fresh process group whose positive
    // ID we captured directly from Tokio. Negative PID targets only that group.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
const fn kill_process_group(_process_group: i32) {}

#[cfg(all(test, unix))]
pub(crate) mod test_fixture {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use h00ligan_provider_protocol::{
        H00_RUST_ANALYZER_IMPLEMENTATION_V6, H00_RUST_ANALYZER_LANGUAGE,
        H00_RUST_ANALYZER_PROVIDER_ID, SEMANTIC_PROVIDER_FRAME_MAGIC, SEMANTIC_PROVIDER_PROTOCOL,
        rust_analyzer_source_components,
    };
    use tempfile::TempDir;

    use super::*;

    pub const FAKE_PROVIDER: &str = r#"import hashlib
import json
import os
import struct
import sys
import time

MAGIC = bytes.fromhex("__H00_FRAME_MAGIC_HEX__")
LIMITS = {
    "max_frame_bytes": 128 * 1024 * 1024,
    "max_metadata_bytes": 4 * 1024 * 1024,
    "max_attachments": 4096,
    "max_attachment_bytes": 64 * 1024 * 1024,
    "max_total_attachment_bytes": 120 * 1024 * 1024,
    "max_document_paths": 4096,
    "max_semantic_input_paths": 8192,
    "max_outstanding_requests": 64,
}
def sha256(value):
    return hashlib.sha256(value).hexdigest()

def field(hasher, value):
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)

components = {
    "cargo_version": sha256(b"fake-cargo-V"),
    "rustc_sysroot_path": sha256(b"fake-sysroot"),
    "rustc_verbose_version": sha256(b"fake-rustc-vV"),
}
environment = sha256(b"fake-cleared-environment")
workspace_configuration = sha256(b"fake-workspace-configuration")
resolved_toolchain = os.environ["H00_RESOLVED_TOOLCHAIN_SHA256"]
expected_parent = int(os.environ["H00_PROVIDER_PARENT_PID"])
if expected_parent != os.getppid():
    raise SystemExit(12)
runtime_hasher = hashlib.sha256()
field(runtime_hasher, b"h00/semantic-provider/runtime-configuration/v1\0")
field(runtime_hasher, resolved_toolchain.encode())
field(runtime_hasher, len(components).to_bytes(8, "big"))
for name, digest in sorted(components.items()):
    field(runtime_hasher, name.encode())
    field(runtime_hasher, digest.encode())
field(runtime_hasher, environment.encode())
field(runtime_hasher, workspace_configuration.encode())
RUNTIME_CONFIGURATION = {
    "configuration_sha256": runtime_hasher.hexdigest(),
    "resolved_toolchain_sha256": resolved_toolchain,
    "component_sha256s": components,
    "environment_sha256": environment,
    "workspace_configuration_sha256": workspace_configuration,
}

def read_exact(size):
    data = b""
    while len(data) < size:
        chunk = sys.stdin.buffer.read(size - len(data))
        if not chunk:
            raise SystemExit(3)
        data += chunk
    return data

def write_response(request, body):
    metadata = json.dumps({
        "request_id": request["request_id"],
        "session_id": request["session_id"],
        "provider": request["expected_provider"],
        "body": body,
    }, separators=(",", ":")).encode()
    payload = metadata
    sys.stdout.buffer.write(MAGIC + struct.pack(">III", len(payload), len(metadata), 0) + payload)
    sys.stdout.buffer.flush()

with open(os.environ["PID_FILE"], "w", encoding="utf-8") as handle:
    handle.write(str(os.getpid()))
with open(os.environ["ARGV_FILE"], "w", encoding="utf-8") as handle:
    json.dump(sys.argv[1:], handle, separators=(",", ":"))
sys.stderr.write("stderr-prefix:" + "x" * 2048)
sys.stderr.flush()
mode = os.environ.get("MODE", "normal")
request_log = os.environ.get("REQUEST_LOG")

while True:
    header = read_exact(20)
    if header[:8] != MAGIC:
        raise SystemExit(4)
    payload_len, metadata_len, _ = struct.unpack(">III", header[8:])
    payload = read_exact(payload_len)
    request = json.loads(payload[:metadata_len])
    operation = request["body"]["operation"]
    if request_log:
        with open(request_log, "a", encoding="utf-8") as handle:
            handle.write(operation + "\n")
    if operation == "hello" and (
        request["request_id"] == 1 or mode in ("normal", "recertify")
    ):
        write_response(request, {
            "result": "hello",
            "limits": LIMITS,
            "runtime_configuration": RUNTIME_CONFIGURATION,
        })
    elif operation == "open_session" and mode == "recertify":
        try:
            barrier = os.environ.get("OPEN_SESSION_BARRIER")
            if barrier:
                member = os.environ["OPEN_SESSION_BARRIER_MEMBER"]
                expected_members = int(os.environ["OPEN_SESSION_BARRIER_COUNT"])
                os.makedirs(barrier, exist_ok=True)
                with open(os.path.join(barrier, member + ".started"), "w", encoding="utf-8"):
                    pass
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    started = [name for name in os.listdir(barrier) if name.endswith(".started")]
                    if len(started) == expected_members:
                        break
                    time.sleep(0.005)
                else:
                    if request_log:
                        with open(request_log, "a", encoding="utf-8") as handle:
                            handle.write("open_session_barrier_timeout\n")
                    raise SystemExit(73)
            semantic_inputs = {
                "schema_version": "h00/semantic-provider/semantic-inputs/v4",
                "coverage": "complete",
                "paths": [],
                "environment": [],
                "issues": [],
            }
            semantic_hasher = hashlib.sha256()
            field(semantic_hasher, b"h00/semantic-provider/semantic-inputs-digest/v4\0")
            field(semantic_hasher, b"complete")
            authority = request["body"]["authority"].copy()
            authority["workspace_resolution_sha256"] = sha256(b"fake-workspace-resolution")
            authority["semantic_inputs_sha256"] = semantic_hasher.hexdigest()
            write_response(request, {
                "result": "session_opened",
                "authority": authority,
                "health": {
                    "components": {
                        "build_scripts": "not_applicable",
                        "proc_macros": "not_applicable",
                        "workspace_model": "healthy"
                    },
                    "diagnostics_complete": True,
                    "degradation_reasons": [],
                },
                "semantic_inputs": semantic_inputs,
            })
        except Exception as error:
            if request_log:
                with open(request_log, "a", encoding="utf-8") as handle:
                    handle.write("exception:" + repr(error) + "\n")
            raise
    elif operation == "close_session":
        write_response(request, {"result": "session_closed"})
        raise SystemExit(0)
    elif mode == "wrong_terminal":
        write_response(request, {"result": "session_closed"})
        time.sleep(60)
    elif mode == "partial":
        sys.stdout.buffer.write(MAGIC[:5])
        sys.stdout.buffer.flush()
        sys.stderr.write("\nh00-partial-frame-exit-7\n")
        sys.stderr.flush()
        raise SystemExit(7)
    elif mode == "timeout":
        time.sleep(60)
    else:
        write_response(request, {
            "result": "error",
            "code": "unsupported_test_operation",
            "message": "fixture supports only hello and close",
            "retryable": False,
        })
"#;

    pub struct FakeProvider {
        _temporary: TempDir,
        pub binary: PathBuf,
        pub identity: ProviderIdentity,
        pub pid_file: PathBuf,
        pub argv_file: PathBuf,
        pub request_log: PathBuf,
    }

    impl FakeProvider {
        pub fn new() -> Self {
            let temporary = TempDir::new().expect("provider scratch");
            let binary = temporary.path().join("fake-provider");
            let pid_file = temporary.path().join("provider.pid");
            let argv_file = temporary.path().join("provider.argv.json");
            let request_log = temporary.path().join("provider.requests");
            let python = std::env::var_os("PATH")
                .into_iter()
                .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                .map(|directory| directory.join("python3"))
                .find(|candidate| candidate.is_file())
                .expect("python3 in test PATH");
            let frame_magic_hex = SEMANTIC_PROVIDER_FRAME_MAGIC
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let provider_source =
                FAKE_PROVIDER.replace("__H00_FRAME_MAGIC_HEX__", &frame_magic_hex);
            fs::write(
                &binary,
                format!("#!{}\n{provider_source}", python.display()),
            )
            .expect("fake provider");
            let mut permissions = fs::metadata(&binary)
                .expect("provider metadata")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&binary, permissions).expect("provider executable mode");
            let binary_sha256 = sha256_file(&binary).expect("provider digest");
            let identity = ProviderIdentity {
                protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
                provider_id: H00_RUST_ANALYZER_PROVIDER_ID.into(),
                language: H00_RUST_ANALYZER_LANGUAGE.into(),
                implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
                source_components: rust_analyzer_source_components(),
                patch_sha256: "a".repeat(64),
                executable_sha256: binary_sha256,
            };
            Self {
                _temporary: temporary,
                binary,
                identity,
                pid_file,
                argv_file,
                request_log,
            }
        }

        pub fn config(
            &self,
            mode: &str,
            request_timeout: Duration,
        ) -> SemanticProviderProcessConfig {
            self.config_for_toolchain(mode, request_timeout, &"7".repeat(64))
        }

        pub fn config_for_toolchain(
            &self,
            mode: &str,
            request_timeout: Duration,
            resolved_toolchain_sha256: &str,
        ) -> SemanticProviderProcessConfig {
            let mut config = SemanticProviderProcessConfig::new(
                &self.binary,
                self.identity.clone(),
                resolved_toolchain_sha256,
                self.binary.parent().expect("provider directory"),
            );
            config.environment.insert(
                h00ligan_provider_protocol::RESOLVED_TOOLCHAIN_SHA256_ENV.into(),
                resolved_toolchain_sha256.into(),
            );
            config.environment.insert("MODE".into(), mode.into());
            config
                .environment
                .insert("PID_FILE".into(), self.pid_file.as_os_str().to_owned());
            config
                .environment
                .insert("ARGV_FILE".into(), self.argv_file.as_os_str().to_owned());
            config.environment.insert(
                "REQUEST_LOG".into(),
                self.request_log.as_os_str().to_owned(),
            );
            config.request_timeout = request_timeout;
            config.max_stderr_bytes = 128;
            config
        }

        pub fn pid(&self) -> i32 {
            fs::read_to_string(&self.pid_file)
                .expect("provider PID")
                .parse()
                .expect("numeric provider PID")
        }
    }

    pub fn process_exists(pid: i32) -> bool {
        // SAFETY: signal zero does not mutate the process; it only probes the
        // exact positive PID written by this test's private child.
        unsafe { libc::kill(pid, 0) == 0 }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use h00ligan_provider_protocol::{
        ExpectedFullCertification, ExpectedProviderDocument, H00_RUST_ANALYZER_IMPLEMENTATION_V6,
        H00_RUST_ANALYZER_LANGUAGE, ProviderAuthority, ProviderSourceIdentity,
        RESOLVED_CARGO_SHA256_ENV, RESOLVED_RUSTC_SHA256_ENV, RUST_SEMANTIC_PROFILE_ENV,
        RustSemanticProfile, rust_analyzer_source_components, sha256_hex, source_population_sha256,
        validate_full_certification,
    };
    use tempfile::TempDir;

    use super::test_fixture::{FAKE_PROVIDER, FakeProvider, process_exists};
    use super::*;
    use crate::code_intel_domain::CapabilityStatus;
    use crate::code_intel_inventory::{InventorySource, build_project_inventory};
    use crate::code_intel_semantic_provider::normalize_admitted_full_certification;
    use crate::scip_normalizer::IndexedSourceEvidence;

    fn runtime_program(name: &str, default: &str) -> PathBuf {
        let requested = std::env::var_os(name).unwrap_or_else(|| default.into());
        let requested = Path::new(&requested);
        if requested.components().count() > 1 {
            return if requested.is_absolute() {
                requested.to_path_buf()
            } else {
                std::env::current_dir()
                    .expect("current test directory")
                    .join(requested)
            };
        }
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .map(|directory| directory.join(requested))
            .find(|candidate| candidate.is_file())
            .unwrap_or_else(|| panic!("{default} in test PATH"))
    }

    #[tokio::test]
    async fn hidden_self_spawn_arguments_reach_the_exact_supervised_child() {
        let fixture = FakeProvider::new();
        let expected = vec![
            OsString::from("__h00-internal-provider"),
            OsString::from("rust"),
        ];
        let mut config = fixture.config("normal", Duration::from_secs(2));
        config.arguments = expected.clone();

        let provider = SemanticProviderProcess::spawn(config)
            .await
            .expect("hidden self-spawn provider boot");
        let observed: Vec<String> = serde_json::from_slice(
            &fs::read(&fixture.argv_file).expect("provider argument receipt"),
        )
        .expect("provider argument JSON");
        assert_eq!(
            observed,
            expected
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
        provider.close().await.expect("clean hidden provider close");
    }

    #[tokio::test]
    async fn exact_boots_are_unique_bounded_and_close_without_residue() {
        let fixture = FakeProvider::new();
        let mut first =
            SemanticProviderProcess::spawn(fixture.config("normal", Duration::from_secs(2)))
                .await
                .expect("first exact provider boot");
        let first_session = first.session_id().to_owned();
        let response = first
            .request(ProviderRequestBody::Hello, Vec::new(), None)
            .await
            .expect("exact terminal");
        assert!(matches!(
            response.metadata.body,
            ProviderResponseBody::Hello { .. }
        ));
        sleep(Duration::from_millis(20)).await;
        let tail = first.stderr_tail();
        assert_eq!(tail.len(), 128, "stderr tail is byte bounded");
        assert!(tail.bytes().all(|byte| byte == b'x'));
        let first_pid = fixture.pid();
        first.close().await.expect("clean close");
        assert!(!process_exists(first_pid), "closed provider must be reaped");

        let second =
            SemanticProviderProcess::spawn(fixture.config("normal", Duration::from_secs(2)))
                .await
                .expect("second exact provider boot");
        assert_ne!(
            second.session_id(),
            first_session,
            "every process boot must receive a unique session identity"
        );
        let second_pid = fixture.pid();
        second.close().await.expect("second clean close");
        assert!(
            !process_exists(second_pid),
            "second provider must be reaped"
        );
    }

    #[tokio::test]
    async fn wrong_terminal_partial_timeout_and_cancellation_quarantine_the_boot() {
        let cases = [
            ("wrong_terminal", None, "unexpected_terminal"),
            ("partial", None, "partial_frame"),
            ("timeout", None, "timeout"),
            ("timeout", Some(IndexCancellation::new()), "cancelled"),
        ];
        assert_eq!(cases.len(), 4, "non-vacuous lifecycle sabotage population");
        for (mode, cancellation, expected) in cases {
            if expected == "cancelled" {
                cancellation.as_ref().expect("cancellation token").cancel();
            }
            let fixture = FakeProvider::new();
            let mut provider =
                SemanticProviderProcess::spawn(fixture.config(mode, Duration::from_secs(2)))
                    .await
                    .expect("provider hello positive control");
            // Boot is a positive control, not part of the timeout sabotage.
            // Apply the deliberately short deadline only after the child has
            // completed its mandatory identity/limits hello.
            provider.request_timeout = Duration::from_millis(75);
            let pid = fixture.pid();
            let error = provider
                .request(
                    ProviderRequestBody::Hello,
                    Vec::new(),
                    cancellation.as_ref(),
                )
                .await
                .expect_err("sabotaged terminal must fail closed");
            match expected {
                "unexpected_terminal" => assert!(matches!(
                    error,
                    SemanticProviderProcessError::UnexpectedTerminal
                )),
                "partial_frame" => {
                    let rendered = error.to_string();
                    assert!(
                        rendered.contains("h00-partial-frame-exit-7") && rendered.contains('7'),
                        "a crashed provider must expose its bounded stderr tail and terminal status: {rendered}"
                    );
                }
                "timeout" => assert!(matches!(error, SemanticProviderProcessError::Timeout)),
                "cancelled" => {
                    assert!(matches!(error, SemanticProviderProcessError::Cancelled));
                }
                _ => unreachable!("bounded sabotage label"),
            }
            assert!(matches!(
                provider
                    .request(ProviderRequestBody::Hello, Vec::new(), None)
                    .await,
                Err(SemanticProviderProcessError::Quarantined)
            ));
            assert!(!process_exists(pid), "quarantined provider must be reaped");
        }
    }

    #[tokio::test]
    async fn explicit_error_terminal_quarantines_and_reaps_the_boot() {
        let fixture = FakeProvider::new();
        let mut provider =
            SemanticProviderProcess::spawn(fixture.config("error", Duration::from_secs(2)))
                .await
                .expect("provider hello positive control");
        let pid = fixture.pid();
        let response = provider
            .request(ProviderRequestBody::Hello, Vec::new(), None)
            .await
            .expect("the caller still receives the provider's bounded error terminal");
        assert!(
            matches!(
                response.metadata.body,
                ProviderResponseBody::Error {
                    retryable: false,
                    ..
                }
            ),
            "known-positive control: the fake provider must emit an explicit non-retryable error"
        );
        assert!(matches!(
            provider
                .request(ProviderRequestBody::Hello, Vec::new(), None)
                .await,
            Err(SemanticProviderProcessError::Quarantined)
        ));
        assert!(
            !process_exists(pid),
            "an explicit error terminal must reap the process before authority returns"
        );
    }

    #[tokio::test]
    async fn executable_tamper_is_rejected_before_process_start() {
        let fixture = FakeProvider::new();
        fs::write(&fixture.binary, format!("{FAKE_PROVIDER}\n# tampered\n"))
            .expect("tamper executable after identity capture");
        let error =
            match SemanticProviderProcess::spawn(fixture.config("normal", Duration::from_secs(1)))
                .await
            {
                Ok(_) => panic!("binary/identity mismatch must refuse startup"),
                Err(error) => error,
            };
        assert!(matches!(
            error,
            SemanticProviderProcessError::ExecutableIdentityMismatch
        ));
        assert!(
            !fixture.pid_file.exists(),
            "no child may start after tamper"
        );
    }

    #[tokio::test]
    #[ignore = "requires the explicitly built installed rust-analyzer sidecar"]
    async fn installed_sidecar_reaches_full_manager_and_normalizer_boundary() {
        let binary = PathBuf::from(
            std::env::var_os("H00_TEST_RA_PROVIDER_BINARY").expect("H00_TEST_RA_PROVIDER_BINARY"),
        );
        let receipt = PathBuf::from(
            std::env::var_os("H00_TEST_RA_PROVIDER_RECEIPT").expect("H00_TEST_RA_PROVIDER_RECEIPT"),
        );
        let temporary = TempDir::new().expect("installed provider project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"installed-manager\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"installed-manager\"\nversion = \"0.1.0\"\n",
        )
        .expect("lockfile");
        let source = b"pub fn target() {}\npub fn caller() { target(); }\n";
        let source_path = root.join("src/lib.rs");
        fs::write(&source_path, source).expect("source");

        let receipt_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt).expect("installed provider receipt"))
                .expect("installed provider receipt JSON");
        let receipt_text = |field: &str| {
            receipt_value[field]
                .as_str()
                .unwrap_or_else(|| panic!("installed receipt field {field}"))
                .to_owned()
        };
        let identity = ProviderIdentity {
            protocol: receipt_text("protocol"),
            provider_id: receipt_text("provider_id"),
            language: receipt_text("language"),
            implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
            source_components: rust_analyzer_source_components(),
            patch_sha256: receipt_text("patch_sha256"),
            executable_sha256: sha256_file(&binary).expect("installed provider binary digest"),
        };
        let resolved_toolchain_sha256 = "7".repeat(64);
        let mut config = SemanticProviderProcessConfig::new(
            &binary,
            identity,
            &resolved_toolchain_sha256,
            &root,
        );
        for name in ["PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                config.environment.insert(name.into(), value);
            }
        }
        config
            .environment
            .insert("RUSTUP_TOOLCHAIN".into(), "1.97.1".into());
        config
            .environment
            .insert("CARGO_TERM_COLOR".into(), "never".into());
        config.environment.insert(
            h00ligan_provider_protocol::RESOLVED_TOOLCHAIN_SHA256_ENV.into(),
            resolved_toolchain_sha256.into(),
        );
        for (path_name, default, digest_name) in [
            ("RUSTC", "rustc", RESOLVED_RUSTC_SHA256_ENV),
            ("CARGO", "cargo", RESOLVED_CARGO_SHA256_ENV),
        ] {
            let path = runtime_program(path_name, default);
            config
                .environment
                .insert(path_name.into(), path.as_os_str().to_owned());
            config.environment.insert(
                digest_name.into(),
                sha256_file(&path)
                    .expect("installed runtime executable digest")
                    .into(),
            );
        }
        config.environment.insert(
            RUST_SEMANTIC_PROFILE_ENV.into(),
            RustSemanticProfile::workspace_default()
                .to_environment_value()
                .expect("installed test semantic profile")
                .into(),
        );
        config.request_timeout = Duration::from_secs(60);
        let mut provider = SemanticProviderProcess::spawn(config)
            .await
            .expect("installed provider manager handshake");

        let source_identity = ProviderSourceIdentity {
            document_path: "src/lib.rs".into(),
            language: H00_RUST_ANALYZER_LANGUAGE.into(),
            content_identity: format!("blake3:{}", blake3::hash(source).to_hex()),
            content_sha256: sha256_hex(source),
        };
        let limits = provider.limits();
        let authority = ProviderAuthority {
            session_id: provider.session_id().into(),
            root_sha256: sha256_hex(root.to_string_lossy().as_bytes()),
            root_topology_sha256: sha256_hex(b"installed-manager-topology-v1"),
            configuration_sha256: provider
                .runtime_configuration()
                .configuration_sha256
                .clone(),
            workspace_resolution_sha256: None,
            semantic_inputs_sha256: None,
            population_sha256: source_population_sha256(
                std::slice::from_ref(&source_identity),
                &limits,
            )
            .expect("source population"),
            source_epoch: 1,
        };
        let opened = provider
            .request(
                ProviderRequestBody::OpenSession {
                    repository_root: root.to_string_lossy().into_owned(),
                    execution_root: root.to_string_lossy().into_owned(),
                    execution_prefix: String::new(),
                    authority: authority.clone(),
                    sources: vec![source_identity.clone()],
                    expected_semantic_inputs: None,
                },
                Vec::new(),
                None,
            )
            .await
            .expect("open installed provider session");
        let authority = match opened.metadata.body {
            ProviderResponseBody::SessionOpened {
                authority: resolved,
                health,
                semantic_inputs,
            } => {
                assert!(health.admits_complete());
                assert_eq!(resolved.session_id, authority.session_id);
                assert_eq!(resolved.root_sha256, authority.root_sha256);
                assert_eq!(
                    resolved.configuration_sha256,
                    authority.configuration_sha256
                );
                assert!(resolved.workspace_resolution_sha256.is_some());
                assert!(resolved.semantic_inputs_sha256.is_some());
                assert_eq!(
                    h00ligan_provider_protocol::provider_semantic_inputs_sha256(
                        &semantic_inputs,
                        &limits,
                    )
                    .expect("semantic input digest"),
                    resolved
                        .semantic_inputs_sha256
                        .clone()
                        .expect("resolved semantic inputs"),
                );
                resolved
            }
            other => panic!("unexpected open-session terminal: {other:?}"),
        };
        let expected = ExpectedFullCertification {
            request_id: 3,
            provider: provider.identity().clone(),
            authority: authority.clone(),
            documents: BTreeMap::from([(
                source_identity.document_path.clone(),
                ExpectedProviderDocument {
                    language: source_identity.language.clone(),
                    content_identity: source_identity.content_identity.clone(),
                },
            )]),
            analyses: BTreeMap::new(),
        };
        let full = provider
            .request(
                ProviderRequestBody::CertifyFull {
                    authority: authority.clone(),
                    analyses: Vec::new(),
                },
                Vec::new(),
                None,
            )
            .await
            .expect("full installed certification");
        let admitted = validate_full_certification(full.clone(), &expected, &limits)
            .expect("full protocol admission");
        assert_eq!(
            admitted.documents.len(),
            1,
            "exact full document population"
        );
        assert!(admitted.analyses.is_empty());

        let inventory = build_project_inventory(
            &root,
            &[InventorySource::new(
                "src/lib.rs",
                H00_RUST_ANALYZER_LANGUAGE,
            )],
        );
        let indexed_sources = vec![IndexedSourceEvidence {
            relative_path: "src/lib.rs".into(),
            language: H00_RUST_ANALYZER_LANGUAGE.into(),
            blake3_hash: blake3::hash(source).to_hex().to_string(),
            cross_document_surface_sha256: Some(sha256_hex(source)),
        }];
        let normalization = normalize_admitted_full_certification(
            &root,
            &root,
            full,
            &expected,
            &limits,
            &indexed_sources,
            &inventory,
        )
        .expect("installed sidecar reaches canonical normalizer");
        assert_eq!(
            normalization.evidence.receipt.status,
            CapabilityStatus::Complete
        );
        assert!(normalization.canonical_snapshot.is_some());
        assert_eq!(
            fs::read(&source_path).expect("source after provider"),
            source
        );
        provider.close().await.expect("installed provider close");
    }
}
