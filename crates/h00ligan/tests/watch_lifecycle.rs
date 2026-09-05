#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use std::{collections::BTreeSet, fs};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;

use h00ligan_engine::code_intel_publication::resolve_generation;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

#[cfg(target_os = "linux")]
fn direct_child_pids(parent: u32) -> BTreeSet<u32> {
    std::fs::read_dir(format!("/proc/{parent}/task"))
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|task| {
            std::fs::read_to_string(task.path().join("children"))
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|pid| pid.parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn descendant_diagnostics(root: u32) -> String {
    let mut pending = vec![root];
    let mut observed = BTreeSet::new();
    let mut rows = Vec::new();
    while let Some(pid) = pending.pop() {
        if !observed.insert(pid) {
            continue;
        }
        pending.extend(direct_child_pids(pid));
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap_or_else(|error| error.to_string())
            .lines()
            .filter(|line| {
                line.starts_with("Name:")
                    || line.starts_with("State:")
                    || line.starts_with("PPid:")
                    || line.starts_with("NSpgid:")
            })
            .collect::<Vec<_>>()
            .join(" ");
        let wait_channel =
            std::fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
        rows.push(format!("pid={pid} {status} wchan={}", wait_channel.trim()));
        if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            for task in tasks.flatten() {
                let tid = task.file_name().to_string_lossy().into_owned();
                let name = std::fs::read_to_string(task.path().join("comm")).unwrap_or_default();
                let wait = std::fs::read_to_string(task.path().join("wchan")).unwrap_or_default();
                rows.push(format!(
                    "  tid={tid} name={} wchan={}",
                    name.trim(),
                    wait.trim()
                ));
            }
        }
    }
    rows.join("\n")
}

#[cfg(target_os = "linux")]
fn wait_for_direct_child_at_root(parent: u32, executable: &Path, root: &Path) -> u32 {
    let executable = std::fs::canonicalize(executable).expect("canonical provider executable");
    let root = std::fs::canonicalize(root).expect("canonical provider execution root");
    let deadline = Instant::now() + test_timeout(5);
    loop {
        if let Some(pid) = direct_child_pids(parent).into_iter().find(|pid| {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .and_then(|path| std::fs::canonicalize(path).ok())
                .as_ref()
                == Some(&executable)
                && std::fs::read_link(format!("/proc/{pid}/cwd"))
                    .ok()
                    .and_then(|path| std::fs::canonicalize(path).ok())
                    .as_ref()
                    == Some(&root)
        }) {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "provider child for {} did not appear under {parent}\n{}",
            root.display(),
            descendant_diagnostics(parent)
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn process_exists(pid: u32) -> bool {
    // SAFETY: signal zero is a read-only liveness probe for the exact positive
    // PID recorded by the test-owned provider fixture.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn wait_for_process_exit(pid: u32, label: &str) {
    let deadline = Instant::now() + test_timeout(5);
    while process_exists(pid) {
        assert!(
            Instant::now() < deadline,
            "{label} process {pid} survived its owning WATCH process"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn provider_stdin_pending_bytes(pid: u32) -> usize {
    let stdin = std::fs::File::open(format!("/proc/{pid}/fd/0"))
        .unwrap_or_else(|error| panic!("open provider {pid} stdin pipe: {error}"));
    let mut pending: libc::c_int = 0;
    // SAFETY: `stdin` is this exact test-owned provider's read end. FIONREAD
    // observes the queued byte count without consuming or modifying the pipe.
    let result = unsafe { libc::ioctl(stdin.as_raw_fd(), libc::FIONREAD, &mut pending) };
    assert_eq!(
        result,
        0,
        "inspect provider {pid} stdin queue: {}",
        std::io::Error::last_os_error()
    );
    usize::try_from(pending).expect("provider stdin byte count is non-negative")
}

#[cfg(target_os = "linux")]
fn wait_for_blocked_provider_request(pid: u32) -> usize {
    let deadline = Instant::now() + test_timeout(5);
    loop {
        let pending = provider_stdin_pending_bytes(pid);
        if pending > 0 {
            return pending;
        }
        assert!(
            process_exists(pid),
            "provider {pid} exited before the blocked request non-vacuity control fired"
        );
        assert!(
            Instant::now() < deadline,
            "active reconciliation never sent a request to stopped provider {pid}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(target_os = "linux")]
struct StoppedProcess {
    pid: u32,
    resume_on_drop: bool,
}

#[cfg(target_os = "linux")]
impl StoppedProcess {
    fn stop(pid: u32) -> Self {
        // SAFETY: the caller supplies an exact child PID discovered beneath
        // the test-owned WATCH process. The guard resumes that process on
        // every unwind path so a failed assertion cannot strand a stopped
        // provider.
        assert_eq!(
            unsafe { libc::kill(pid as i32, libc::SIGSTOP) },
            0,
            "stop exact provider child: {}",
            std::io::Error::last_os_error()
        );
        let guard = Self {
            pid,
            resume_on_drop: true,
        };
        let deadline = Instant::now() + test_timeout(5);
        loop {
            let stopped = std::fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|status| {
                    status
                        .lines()
                        .find(|line| line.starts_with("State:"))
                        .map(str::to_owned)
                })
                .is_some_and(|state| {
                    state
                        .split_whitespace()
                        .nth(1)
                        .is_some_and(|code| matches!(code, "T" | "t"))
                });
            if stopped {
                return guard;
            }
            assert!(
                Instant::now() < deadline,
                "provider child {pid} did not enter a stopped state"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn resume(&mut self) {
        if !self.resume_on_drop {
            return;
        }
        // Cancellation normally quarantines and reaps this provider before
        // the test reaches here. If it is still alive, make it runnable again
        // before the successor reconciliation proceeds.
        if process_exists(self.pid) {
            // SAFETY: this is the same still-live, test-owned PID stopped by
            // `Self::stop` above.
            assert_eq!(
                unsafe { libc::kill(self.pid as i32, libc::SIGCONT) },
                0,
                "resume exact provider child: {}",
                std::io::Error::last_os_error()
            );
        }
        self.resume_on_drop = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for StoppedProcess {
    fn drop(&mut self) {
        if self.resume_on_drop {
            // SAFETY: best-effort unwind cleanup for the exact PID stopped by
            // this guard. The owned WATCH process remains alive until after
            // this guard is dropped, bounding PID ownership.
            let _ = unsafe { libc::kill(self.pid as i32, libc::SIGCONT) };
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn descendant_diagnostics(_root: u32) -> String {
    "process-tree diagnostics unavailable on this platform".into()
}

fn h00ligan_binary() -> PathBuf {
    std::env::var_os("H00_TEST_H00LIGAN_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_h00ligan")))
}

fn isolated_toolchain_search_path(
    temporary: &TempDir,
    directory_name: &str,
    tools: &[&str],
) -> std::ffi::OsString {
    let current_path = std::env::var_os("PATH").unwrap_or_default();
    // A rustup proxy is not a relocatable compiler: the child deliberately
    // loses RUSTUP_HOME/RUSTUP_TOOLCHAIN when its environment is cleared.
    // Resolve the selected compiler while that authority is still present,
    // then expose only the concrete drivers from the same installed sysroot.
    let rust_sysroot = tools
        .iter()
        .any(|tool| matches!(*tool, "cargo" | "rustc"))
        .then(|| {
            let report = Command::new("rustc")
                .args(["--print", "sysroot"])
                .output()
                .expect("resolve selected Rust sysroot before isolating PATH");
            assert!(report.status.success(), "selected Rust sysroot: {report:?}");
            PathBuf::from(
                String::from_utf8(report.stdout)
                    .expect("UTF-8 selected Rust sysroot")
                    .trim(),
            )
        });
    let isolated_bin = temporary.path().join(directory_name);
    std::fs::create_dir_all(&isolated_bin).expect("isolated toolchain PATH directory");
    for tool in tools {
        let candidate = if matches!(*tool, "cargo" | "rustc") {
            rust_sysroot
                .as_ref()
                .expect("selected Rust sysroot")
                .join("bin")
                .join(tool)
        } else {
            std::env::split_paths(&current_path)
                .map(|directory| directory.join(tool))
                .find(|candidate| candidate.is_file())
                .unwrap_or_else(|| panic!("installed {tool} driver in PATH"))
        };
        let executable = std::fs::canonicalize(&candidate).unwrap_or_else(|error| {
            panic!("resolve exact {} driver: {error}", candidate.display())
        });
        std::os::unix::fs::symlink(&executable, isolated_bin.join(tool))
            .unwrap_or_else(|error| panic!("link exact {tool} driver into isolated PATH: {error}"));
        assert!(isolated_bin.join(tool).is_file(), "positive {tool} control");
    }
    assert!(
        !isolated_bin.join("scip-go").exists(),
        "isolated product path must not contain scip-go"
    );
    std::env::join_paths([isolated_bin]).expect("isolated toolchain PATH")
}

/// Build a PATH that exposes the real Go driver and deliberately nothing
/// else. The installed one-file product must obtain semantic indexing from
/// its embedded provider, never from an adjacent or globally installed
/// `scip-go` executable.
fn go_only_search_path(temporary: &TempDir) -> std::ffi::OsString {
    isolated_toolchain_search_path(temporary, "go-only-bin", &["go"])
}

fn go_and_rust_search_path(temporary: &TempDir) -> std::ffi::OsString {
    isolated_toolchain_search_path(temporary, "go-rust-only-bin", &["go", "cargo", "rustc"])
}

#[test]
fn isolated_rust_toolchain_uses_selected_compiler_without_rustup_state() {
    let temporary = TempDir::new().expect("isolated Rust toolchain fixture");
    let report = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .expect("query selected Rust sysroot before clearing the environment");
    assert!(report.status.success(), "selected Rust toolchain must work");
    let sysroot = PathBuf::from(
        String::from_utf8(report.stdout)
            .expect("UTF-8 selected Rust sysroot")
            .trim(),
    );
    let search_path =
        isolated_toolchain_search_path(&temporary, "rust-only-bin", &["rustc", "cargo"]);
    let isolated_bin = std::env::split_paths(&search_path)
        .next()
        .expect("one isolated toolchain directory");
    for tool in ["rustc", "cargo"] {
        let selected = std::fs::canonicalize(sysroot.join("bin").join(tool))
            .expect("concrete selected Rust toolchain executable");
        let isolated = isolated_bin.join(tool);
        assert_eq!(
            std::fs::canonicalize(&isolated).expect("isolated executable target"),
            selected,
            "isolated {tool} must preserve the selected compiler, not a rustup launcher that loses its environment"
        );
        let version = Command::new(&isolated)
            .arg("--version")
            .current_dir(temporary.path())
            .env_clear()
            .env("PATH", &search_path)
            .env("CARGO_HOME", temporary.path().join("empty-cargo-home"))
            .env("RUSTUP_HOME", temporary.path().join("empty-rustup-home"))
            .output()
            .expect("run isolated compiler without inherited toolchain state");
        assert!(
            version.status.success() && !version.stdout.is_empty(),
            "isolated {tool} must execute without another rustup installation: {version:?}"
        );
    }
}

fn assert_one_embedded_go_provider(data_dir: &Path) -> PathBuf {
    assert_one_private_embedded_provider(data_dir, "h00-go-semantic-provider")
}

fn assert_one_private_embedded_provider(data_dir: &Path, executable_name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let executable_root = data_dir
        .join(h00ligan_engine::project_binding::PROVIDER_CACHE_DIRECTORY)
        .join("executables");
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(&executable_root)
        .unwrap_or_else(|error| panic!("read {}: {error}", executable_root.display()))
    {
        let entry = entry.expect("provider content-address entry");
        let digest = entry.file_name().to_string_lossy().into_owned();
        let candidate = entry.path().join(executable_name);
        if candidate.exists() {
            matches.push((digest, candidate));
        }
    }
    assert_eq!(
        matches.len(),
        1,
        "one installed product must materialize exactly one {executable_name}"
    );
    let (digest, binary) = matches.pop().expect("one provider match");
    assert_eq!(digest.len(), 64, "provider cache key must be SHA-256");
    assert!(
        digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "provider cache key must be hexadecimal: {digest}"
    );
    let metadata = std::fs::symlink_metadata(&binary).expect("materialized provider metadata");
    assert!(metadata.file_type().is_file());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    let observed = Sha256::digest(std::fs::read(&binary).expect("materialized provider bytes"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        observed, digest,
        "materialized provider bytes must match their content address"
    );
    binary
}

fn test_timeout(base_seconds: u64) -> Duration {
    let multiplier = std::env::var("H00_TEST_TIMEOUT_MULTIPLIER")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|multiplier| (1..=12).contains(multiplier))
        .unwrap_or(1);
    Duration::from_secs(base_seconds.saturating_mul(u64::from(multiplier)))
}

/// Installed-product discriminator for the atomic affected-refresh wire path.
/// The coordinator emits the exact admitted payload-producing protocol
/// operation; timing labels remain performance diagnostics only.
fn assert_atomic_affected_refresh_receipt(
    terminal: &serde_json::Value,
    language: &str,
    diagnostics: &str,
) {
    let refresh = terminal["semantic_provider_refreshes"]
        .as_array()
        .and_then(|refreshes| {
            refreshes
                .iter()
                .find(|refresh| refresh["language"] == language)
        })
        .unwrap_or_else(|| {
            panic!(
                "installed WATCH omitted the {language} provider refresh receipt: {terminal:?}\n{diagnostics}"
            )
        });
    assert_eq!(
        refresh["operation"], "refresh_affected",
        "installed WATCH did not receipt the atomic affected-refresh operation for {language}: {terminal:?}\n{diagnostics}"
    );

    let timings = terminal["phase_timings"]
        .as_array()
        .expect("profiled WATCH terminal must expose provider timings");
    let redundant_probe = format!("{language} provider terminal runtime authority");
    assert!(
        timings
            .iter()
            .all(|timing| timing["label"] != redundant_probe.as_str()),
        "atomic affected refresh issued the superseded terminal runtime probe for {language}: {terminal:?}\n{diagnostics}"
    );
}

fn assert_full_provider_refresh_receipt(
    terminal: &serde_json::Value,
    language: &str,
    diagnostics: &str,
) {
    let refreshes = terminal["semantic_provider_refreshes"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("installed WATCH omitted provider refresh receipts: {terminal:?}\n{diagnostics}")
        });
    assert_eq!(
        refreshes.len(),
        1,
        "single-language WATCH emitted an ambiguous refresh population: {terminal:?}\n{diagnostics}"
    );
    let refresh = &refreshes[0];
    assert_eq!(refresh["language"], language);
    assert_eq!(refresh["lane"], "full");
    assert_eq!(refresh["operation"], "certify_full");
    assert_eq!(refresh["documents"], serde_json::json!([]));
    assert_eq!(refresh["session_open"]["execution_roots"], 1);
    assert!(
        refresh["session_open"]["max_parallelism"]
            .as_u64()
            .is_some_and(|parallelism| parallelism > 0),
        "full {language} refresh omitted provider concurrency: {terminal:?}\n{diagnostics}"
    );
    assert!(
        refresh["session_open"]["duration_ms"].as_u64().is_some(),
        "full {language} refresh omitted session-open duration: {terminal:?}\n{diagnostics}"
    );
}

struct RunningWatch {
    child: Option<Child>,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl RunningWatch {
    const fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("WATCH child remains owned")
    }

    fn diagnostics(&self) -> String {
        let signal_state = self
            .child
            .as_ref()
            .and_then(|child| std::fs::read_to_string(format!("/proc/{}/status", child.id())).ok())
            .map(|status| {
                status
                    .lines()
                    .filter(|line| {
                        line.starts_with("SigBlk:")
                            || line.starts_with("SigIgn:")
                            || line.starts_with("SigCgt:")
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|| "signal state unavailable".into());
        format!(
            "stdout:\n{}\nstderr:\n{}\nsignals:\n{}\nprocesses:\n{}",
            std::fs::read_to_string(&self.stdout).unwrap_or_else(|error| error.to_string()),
            std::fs::read_to_string(&self.stderr).unwrap_or_else(|error| error.to_string()),
            signal_state,
            self.child.as_ref().map_or_else(
                || "WATCH child unavailable".into(),
                |child| { descendant_diagnostics(child.id()) }
            ),
        )
    }

    fn terminate(mut self) -> ExitStatus {
        let child = self.child.as_mut().expect("WATCH child remains owned");
        // SAFETY: the PID comes from this still-owned Child, and SIGTERM is the
        // shipped graceful-shutdown boundary exercised by this test.
        let signal_result = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        assert_eq!(
            signal_result,
            0,
            "send SIGTERM to WATCH child: {}",
            std::io::Error::last_os_error()
        );
        let deadline = Instant::now() + test_timeout(5);
        loop {
            if let Some(status) = child.try_wait().expect("inspect terminating WATCH child") {
                self.child.take();
                return status;
            }
            if Instant::now() >= deadline {
                let diagnostics = self.diagnostics();
                let child = self.child.as_mut().expect("WATCH child remains owned");
                let _ = child.kill();
                let _ = child.wait();
                self.child.take();
                panic!(
                    "WATCH did not stop within the configured timeout after SIGTERM\n{diagnostics}"
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for RunningWatch {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            // Preserve the shipped shutdown contract even when an assertion
            // unwinds the test. A direct SIGKILL of the top-level WATCH can
            // briefly orphan its provider child and destroy the lifecycle
            // evidence that made the assertion fail. Bound this best-effort
            // grace period so Drop itself can never hang the test process.
            // SAFETY: the PID comes from this still-owned Child.
            let _ = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
            let deadline = Instant::now() + test_timeout(5);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) | Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                }
            }
        }
    }
}

fn wait_for_generation(
    watch: &mut RunningWatch,
    root: &Path,
    data_dir: &Path,
    previous: Option<&str>,
) -> String {
    let deadline = Instant::now() + test_timeout(30);
    loop {
        if let Ok(generation) = resolve_generation(data_dir, root) {
            let current = generation.manifest.generation_id.to_string();
            if previous.is_none_or(|previous| current != previous) {
                return current;
            }
        }
        if let Some(status) = watch.child_mut().try_wait().expect("inspect WATCH child") {
            panic!(
                "WATCH exited before publishing the requested generation ({status})\n{}",
                watch.diagnostics()
            );
        }
        assert!(
            Instant::now() < deadline,
            "WATCH did not publish within the configured timeout\n{}",
            watch.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_fresh_terminal(watch: &mut RunningWatch, previous: Option<&str>) -> String {
    let deadline = Instant::now() + test_timeout(60);
    loop {
        let events = fs::read_to_string(&watch.stdout).unwrap_or_default();
        if let Some(generation) = events
            .lines()
            .filter_map(|line| {
                let event = serde_json::from_str::<serde_json::Value>(line).ok()?;
                (event["event"] == "reconciliation_terminal"
                    && event["state"] == "succeeded"
                    && event["reused_generation"] == false)
                    .then(|| event["generation"].as_str().map(str::to_owned))
                    .flatten()
            })
            .next_back()
            .filter(|generation| previous.is_none_or(|previous| generation != previous))
        {
            return generation;
        }
        if let Some(status) = watch.child_mut().try_wait().expect("inspect WATCH child") {
            panic!(
                "WATCH exited before a fresh terminal publication ({status})\n{}",
                watch.diagnostics()
            );
        }
        assert!(
            Instant::now() < deadline,
            "WATCH did not emit a fresh terminal publication\n{}",
            watch.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn terminal_event_for_generation(
    watch: &RunningWatch,
    generation: &str,
    label: &str,
) -> serde_json::Value {
    fs::read_to_string(&watch.stdout)
        .unwrap_or_else(|error| panic!("read {label} WATCH lifecycle: {error}"))
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .rfind(|event| {
            event["event"] == "reconciliation_terminal" && event["generation"] == generation
        })
        .unwrap_or_else(|| {
            panic!(
                "missing {label} WATCH terminal receipt for generation {generation}\n{}",
                watch.diagnostics()
            )
        })
}

fn wait_for_dirty_terminal_after(
    watch: &mut RunningWatch,
    previous_count: usize,
) -> serde_json::Value {
    let deadline = Instant::now() + test_timeout(60);
    loop {
        let terminals = fs::read_to_string(&watch.stdout)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| {
                event["event"] == "reconciliation_terminal"
                    && event["dirty_hint_count"]
                        .as_u64()
                        .is_some_and(|count| count > 0)
            })
            .collect::<Vec<_>>();
        if let Some(terminal) = terminals.get(previous_count) {
            return terminal.clone();
        }
        if let Some(status) = watch.child_mut().try_wait().expect("inspect WATCH child") {
            panic!(
                "WATCH exited before the next dirty reconciliation terminal ({status})\n{}",
                watch.diagnostics()
            );
        }
        assert!(
            Instant::now() < deadline,
            "WATCH did not emit the next dirty reconciliation terminal\n{}",
            watch.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_active_change_operation_after(
    watch: &mut RunningWatch,
    previous_count: usize,
) -> String {
    let deadline = Instant::now() + test_timeout(60);
    loop {
        let events = fs::read_to_string(&watch.stdout).unwrap_or_default();
        let parsed = events
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect::<Vec<_>>();
        let terminal = parsed
            .iter()
            .filter(|event| event["event"] == "reconciliation_terminal")
            .filter_map(|event| event["operation_id"].as_str())
            .collect::<BTreeSet<_>>();
        if let Some(operation_id) = parsed
            .iter()
            .filter(|event| event["event"] == "reconciliation_started")
            .skip(previous_count)
            .filter(|event| {
                event["trigger"] == "watch"
                    && event["dirty_hint_count"]
                        .as_u64()
                        .is_some_and(|count| count > 0)
            })
            .filter_map(|event| event["operation_id"].as_str())
            .find(|operation_id| !terminal.contains(operation_id))
        {
            return operation_id.to_owned();
        }
        if let Some(status) = watch.child_mut().try_wait().expect("inspect WATCH child") {
            panic!(
                "WATCH exited before the expected active reconciliation started ({status})\n{}",
                watch.diagnostics()
            );
        }
        assert!(
            Instant::now() < deadline,
            "WATCH did not retain the expected active reconciliation\n{}",
            watch.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_operation_terminal_state(
    watch: &mut RunningWatch,
    operation_id: &str,
    expected_state: &str,
) {
    let deadline = Instant::now() + test_timeout(60);
    loop {
        let events = fs::read_to_string(&watch.stdout).unwrap_or_default();
        if let Some(terminal) = events.lines().find_map(|line| {
            let event = serde_json::from_str::<serde_json::Value>(line).ok()?;
            (event["event"] == "reconciliation_terminal" && event["operation_id"] == operation_id)
                .then_some(event)
        }) {
            assert_eq!(
                terminal["state"],
                expected_state,
                "operation {operation_id} reached the wrong terminal: {terminal}\n{}",
                watch.diagnostics()
            );
            return;
        }
        if let Some(status) = watch.child_mut().try_wait().expect("inspect WATCH child") {
            panic!(
                "WATCH exited before operation {operation_id} reached {expected_state} ({status})\n{}",
                watch.diagnostics()
            );
        }
        assert!(
            Instant::now() < deadline,
            "operation {operation_id} did not reach {expected_state}\n{}",
            watch.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_reused_terminal(watch: &mut RunningWatch, expected: &str) {
    let deadline = Instant::now() + test_timeout(60);
    loop {
        let events = fs::read_to_string(&watch.stdout).unwrap_or_default();
        if events.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line).is_ok_and(|event| {
                event["event"] == "reconciliation_terminal"
                    && event["state"] == "succeeded"
                    && event["reused_generation"] == true
                    && event["generation"] == expected
            })
        }) {
            return;
        }
        if let Some(status) = watch.child_mut().try_wait().expect("inspect WATCH child") {
            panic!(
                "WATCH exited before exact startup reuse ({status})\n{}",
                watch.diagnostics()
            );
        }
        assert!(
            Instant::now() < deadline,
            "WATCH did not emit exact startup reuse for {expected}\n{}",
            watch.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn calls_json(binary: &Path, root: &Path, data_dir: &Path, symbol: &str) -> serde_json::Value {
    calls_json_at(binary, root, data_dir, symbol, "main.go")
}

fn calls_json_at(
    binary: &Path,
    root: &Path,
    data_dir: &Path,
    symbol: &str,
    file: &str,
) -> serde_json::Value {
    let output = Command::new(binary)
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .args([
            "calls", symbol, "--file", file, "--filter", "all", "--limit", "100", "--format",
            "json",
        ])
        .output()
        .expect("query installed Go Calls authority");
    assert!(
        output.status.success(),
        "Go Calls query for {symbol} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Go Calls JSON output")
}

fn isolated_calls_json_at(
    binary: &Path,
    root: &Path,
    data_dir: &Path,
    process_tmp: &Path,
    symbol: &str,
    file: &str,
    language: &str,
) -> serde_json::Value {
    let output = Command::new(binary)
        .env_clear()
        .env("TMPDIR", process_tmp)
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .args([
            "calls", symbol, "--file", file, "--filter", "all", "--limit", "100", "--format",
            "json",
        ])
        .output()
        .unwrap_or_else(|error| panic!("query installed {language} Calls authority: {error}"));
    assert!(
        output.status.success(),
        "{language} Calls query for {symbol} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{language} Calls JSON output: {error}"))
}

fn calls_items(value: &serde_json::Value) -> &Vec<serde_json::Value> {
    value["items"]
        .as_array()
        .unwrap_or_else(|| panic!("Calls result has no item population: {value}"))
}

fn semantic_calls_items(value: &serde_json::Value) -> serde_json::Value {
    fn strip_generation_bound_selectors(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    strip_generation_bound_selectors(value);
                }
            }
            serde_json::Value::Object(fields) => {
                fields.remove("symbol_id");
                for value in fields.values_mut() {
                    strip_generation_bound_selectors(value);
                }
            }
            _ => {}
        }
    }

    let mut items = serde_json::Value::Array(calls_items(value).clone());
    strip_generation_bound_selectors(&mut items);
    items
}

fn wait_for_nonempty_file(path: &Path, label: &str) {
    let deadline = Instant::now() + test_timeout(10);
    while std::fs::metadata(path).map_or(0, |metadata| metadata.len()) == 0 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {label}: {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

const CFG_SELECTED_CALLS_SOURCE: &str = r#"pub fn target_a() {}
pub fn target_b() {}
#[cfg(not(h00_select_b))]
use crate::target_a as selected;
#[cfg(h00_select_b)]
use crate::target_b as selected;
pub fn caller() { selected(); }
"#;

fn create_build_input_semantics_fixture_at(
    temporary: &TempDir,
    selector_relative: &str,
) -> (PathBuf, PathBuf) {
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"build-input-drift\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n[workspace]\n",
    )
    .expect("manifest");
    let build_script = format!(
        r#"fn main() {{
    println!("cargo:rerun-if-changed={selector_relative}");
    println!("cargo:rustc-check-cfg=cfg(h00_select_b)");
    let selected = std::fs::read_to_string("{selector_relative}").unwrap();
    if selected.trim() == "target_b" {{
        println!("cargo:rustc-cfg=h00_select_b");
    }}
}}
"#
    );
    std::fs::write(root.join("build.rs"), build_script).expect("build script");
    let selector = root.join(selector_relative);
    std::fs::create_dir_all(selector.parent().expect("selector parent"))
        .expect("selector directory");
    std::fs::write(&selector, "target_a\n").expect("initial build input");
    std::fs::write(root.join("src/lib.rs"), CFG_SELECTED_CALLS_SOURCE)
        .expect("cfg-selected call consumer");
    (root, selector)
}

fn create_build_input_semantics_fixture(temporary: &TempDir) -> (PathBuf, PathBuf) {
    create_build_input_semantics_fixture_at(temporary, "selector.txt")
}

fn path_with_blocking_second_rust_analyzer(temporary: &Path) -> std::ffi::OsString {
    use std::os::unix::fs::PermissionsExt as _;

    let fake_bin = temporary.join("blocking-provider-bin");
    std::fs::create_dir_all(&fake_bin).expect("blocking provider executable directory");
    let fake_rust_analyzer = fake_bin.join("rust-analyzer");
    std::fs::write(
        &fake_rust_analyzer,
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' 'rust-analyzer 1.97.1-watch-test'
  exit 0
fi
if [ "$1" != "scip" ]; then
  exit 64
fi
count=0
if [ -f "$H00_WATCH_PROVIDER_COUNT" ]; then
  count=$(cat "$H00_WATCH_PROVIDER_COUNT")
fi
count=$((count + 1))
printf '%s\n' "$count" > "$H00_WATCH_PROVIDER_COUNT"
if [ "$count" -eq 1 ]; then
  exit 17
fi
printf '%s\n' "$$" > "$H00_WATCH_PROVIDER_PID"
while :; do printf x >> "$H00_WATCH_PROVIDER_HEARTBEAT"; sleep 0.05; done &
printf '%s\n' "$!" > "$H00_WATCH_PROVIDER_DESCENDANT_PID"
wait
"#,
    )
    .expect("blocking fake rust-analyzer");
    let mut permissions = std::fs::metadata(&fake_rust_analyzer)
        .expect("blocking fake executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_rust_analyzer, permissions)
        .expect("make blocking fake executable runnable");

    let mut search_path = vec![fake_bin];
    search_path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(search_path).expect("joined blocking-provider search path")
}

struct FixtureProviderGuard {
    pid_path: PathBuf,
    armed: bool,
}

impl FixtureProviderGuard {
    const fn new(pid_path: PathBuf) -> Self {
        Self {
            pid_path,
            armed: true,
        }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FixtureProviderGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(pid) = std::fs::read_to_string(&self.pid_path) else {
            return;
        };
        let Ok(pid) = pid.trim().parse::<libc::pid_t>() else {
            return;
        };
        // SAFETY: the PID is written by the exact test-owned provider, which
        // the production launcher places in a private process group.
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
}

#[test]
fn shipped_watch_publishes_initial_and_changed_generations_then_stops_cleanly() {
    let temporary = TempDir::new().expect("WATCH scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let source = root.join("src/lib.rs");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"watch-boundary\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(&source, "pub fn watch_before() -> u8 { 1 }\n").expect("initial source");

    let stdout = temporary.path().join("watch.stdout");
    let stderr = temporary.path().join("watch.stderr");
    let child = Command::new(h00ligan_binary())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--format",
            "json",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "1",
            "--profile",
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn shipped WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_generation(&mut watch, &root, &data_dir, None);
    std::fs::write(&source, "pub fn watch_after() -> u8 { 2 }\n").expect("changed source");
    let changed = wait_for_generation(&mut watch, &root, &data_dir, Some(&initial));
    assert_ne!(changed, initial);

    let query = Command::new(h00ligan_binary())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "find",
            "watch_after",
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .expect("query WATCH publication through shipped CLI");
    assert!(
        query.status.success(),
        "query failed:\n{}",
        String::from_utf8_lossy(&query.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&query.stdout).expect("Find result JSON");
    assert!(
        result["items"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["symbol"]["name"] == "watch_after" || item["name"] == "watch_after"
            })
        }),
        "the changed symbol must be visible through the shipped query boundary: {result}"
    );

    let watch_output_path = watch.stdout.clone();
    let status = watch.terminate();
    assert!(status.success(), "WATCH shutdown failed: {status}");

    let events = fs::read_to_string(&watch_output_path)
        .expect("read complete WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let started = events
        .iter()
        .filter(|event| event["event"] == "reconciliation_started")
        .filter_map(|event| event["operation_id"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let terminal = events
        .iter()
        .filter(|event| event["event"] == "reconciliation_terminal")
        .filter_map(|event| event["operation_id"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert!(
        !started.is_empty(),
        "WATCH emitted no operation starts: {events:?}"
    );
    assert_eq!(
        terminal, started,
        "every announced operation must receive one retained terminal receipt"
    );
    assert!(
        events.iter().any(|event| {
            event["event"] == "reconciliation_terminal"
                && event["generation"] == changed
                && event["files_changed"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
                && event["reused_generation"] == false
        }),
        "the changed generation must retain the operation that actually published it: {events:?}"
    );
    let changed_terminal = events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == changed)
        .expect("changed generation terminal receipt");
    let phase_labels = changed_terminal["phase_timings"]
        .as_array()
        .expect("profiled WATCH terminal must expose coarse operation phases")
        .iter()
        .filter_map(|timing| timing["phase"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        phase_labels,
        BTreeSet::from(["reuse", "prepare", "structural", "finalize", "publish"]),
        "profiled WATCH must account for the complete publication operation"
    );
    let publication_timings = changed_terminal["publication_timings"]
        .as_array()
        .expect("profiled WATCH terminal must expose publication detail");
    assert!(
        publication_timings.len() >= 2
            && publication_timings
                .iter()
                .all(|timing| timing["work_items"].as_u64().is_some()),
        "publication detail must be a nonempty measured population: {publication_timings:?}"
    );
    let stopped = events
        .iter()
        .find(|event| event["event"] == "watch_stopped")
        .expect("WATCH stopped receipt");
    assert!(
        stopped["publication_probes"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "positive control: the shipped bounded publication probe must run: {stopped}"
    );
    assert!(
        stopped["publication_control_reads"]
            .as_u64()
            .zip(stopped["publication_probes"].as_u64())
            .is_some_and(|(reads, probes)| reads > 0 && reads < probes),
        "unchanged heartbeat probes must sparsify validated control reads: {stopped}"
    );
    assert_eq!(
        stopped["publication_drifts"], 0,
        "the WATCH process must not misclassify its own publications as foreign drift"
    );
}

#[test]
fn shipped_semantic_watch_serves_structural_truth_while_provider_is_blocked() {
    let temporary = TempDir::new().expect("semantic WATCH scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let source = root.join("src/lib.rs");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"watch-semantic-boundary\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(
        root.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"watch-semantic-boundary\"\nversion = \"0.0.0\"\n",
    )
    .expect("fixture lockfile");
    std::fs::write(&source, "pub fn semantic_before() -> u8 { 1 }\n").expect("initial source");

    let provider_count = temporary.path().join("provider-count");
    let provider_heartbeat = temporary.path().join("provider-heartbeat");
    let provider_pid = temporary.path().join("provider.pid");
    let provider_descendant_pid = temporary.path().join("provider-descendant.pid");
    let mut provider_guard = FixtureProviderGuard::new(provider_pid.clone());
    let stdout = temporary.path().join("watch-semantic.stdout");
    let stderr = temporary.path().join("watch-semantic.stderr");
    let child = Command::new(h00ligan_binary())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--allow-capability-downgrade",
            "--format",
            "json",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env(
            "PATH",
            path_with_blocking_second_rust_analyzer(temporary.path()),
        )
        .env("H00_WATCH_PROVIDER_COUNT", &provider_count)
        .env("H00_WATCH_PROVIDER_HEARTBEAT", &provider_heartbeat)
        .env("H00_WATCH_PROVIDER_PID", &provider_pid)
        .env(
            "H00_WATCH_PROVIDER_DESCENDANT_PID",
            &provider_descendant_pid,
        )
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("semantic WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("semantic WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn shipped semantic WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_generation(&mut watch, &root, &data_dir, None);
    assert_eq!(
        std::fs::read_to_string(&provider_count)
            .expect("initial provider invocation count")
            .trim(),
        "1",
        "positive control: startup must exercise exactly one fast-failing semantic provider"
    );

    std::fs::write(&source, "pub fn semantic_after() -> u8 { 2 }\n").expect("changed source");
    wait_for_nonempty_file(&provider_heartbeat, "blocked provider heartbeat");
    wait_for_nonempty_file(&provider_pid, "blocked provider PID receipt");
    wait_for_nonempty_file(
        &provider_descendant_pid,
        "blocked provider descendant PID receipt",
    );
    assert_eq!(
        std::fs::read_to_string(&provider_count)
            .expect("changed provider invocation count")
            .trim(),
        "2",
        "positive control: the changed epoch must enter semantic enrichment"
    );

    let changed = wait_for_generation(&mut watch, &root, &data_dir, Some(&initial));
    assert_ne!(changed, initial);
    let query = Command::new(h00ligan_binary())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "find",
            "semantic_after",
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .expect("query staged WATCH publication through shipped CLI");
    assert!(
        query.status.success(),
        "staged WATCH query failed:\n{}",
        String::from_utf8_lossy(&query.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&query.stdout).expect("staged Find result JSON");
    assert!(
        result["items"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["symbol"]["name"] == "semantic_after" || item["name"] == "semantic_after"
            })
        }),
        "changed structural truth must be queryable while semantic enrichment is blocked: {result}"
    );

    let watch_output_path = watch.stdout.clone();
    let status = watch.terminate();
    assert!(status.success(), "semantic WATCH shutdown failed: {status}");
    let provider_pid = std::fs::read_to_string(&provider_pid)
        .expect("provider PID after WATCH stop")
        .trim()
        .parse::<u32>()
        .expect("numeric provider PID");
    let provider_descendant_pid = std::fs::read_to_string(&provider_descendant_pid)
        .expect("provider descendant PID after WATCH stop")
        .trim()
        .parse::<u32>()
        .expect("numeric provider descendant PID");
    wait_for_process_exit(provider_pid, "provider parent");
    wait_for_process_exit(provider_descendant_pid, "provider descendant");
    let heartbeat_after_stop = std::fs::metadata(&provider_heartbeat)
        .expect("provider heartbeat after WATCH stop")
        .len();
    std::thread::sleep(Duration::from_millis(250));
    let heartbeat_after_grace = std::fs::metadata(&provider_heartbeat)
        .expect("provider heartbeat after WATCH shutdown grace")
        .len();
    assert_eq!(
        heartbeat_after_grace, heartbeat_after_stop,
        "WATCH stop must cancel and reap the blocked provider process group"
    );
    assert!(
        std::fs::read_dir(&data_dir)
            .expect("data directory after semantic WATCH stop")
            .all(|entry| !entry
                .expect("data directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".h00-provider-")),
        "WATCH stop must reclaim the disposable provider workspace"
    );

    let events = fs::read_to_string(&watch_output_path)
        .expect("read semantic WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let staged = events
        .iter()
        .find(|event| event["event"] == "structural_publication" && event["generation"] == changed)
        .expect("changed epoch structural-publication receipt");
    assert_eq!(
        staged["semantic_enrichment_pending_at_publication"], true,
        "the staged receipt must preserve that semantic enrichment was pending when structural truth became visible: {staged}"
    );
    match staged["semantic_enrichment_state"].as_str() {
        Some("pending") => assert_eq!(
            staged["semantic_enrichment_pending"], true,
            "live provider work must be reported as pending: {staged}"
        ),
        Some("cancelled") => assert_eq!(
            staged["semantic_enrichment_pending"], false,
            "cancelled provider work must not be reported as still running: {staged}"
        ),
        observed => panic!(
            "the blocked enrichment may only be observed before or after cancellation, never as completed or another terminal: {observed:?}: {staged}"
        ),
    }
    let operation_id = staged["operation_id"]
        .as_str()
        .expect("staged operation ID");
    assert!(
        events.iter().any(|event| {
            event["event"] == "reconciliation_terminal"
                && event["operation_id"] == operation_id
                && event["state"] == "cancelled"
        }),
        "stopping WATCH must terminally receipt the same staged operation: {events:?}"
    );
    let stopped = events
        .iter()
        .find(|event| event["event"] == "watch_stopped")
        .expect("semantic WATCH stopped receipt");
    assert_eq!(
        stopped["published_epoch"], staged["covered_epoch"],
        "stopping enrichment must retain the already-visible structural epoch: {stopped}"
    );

    provider_guard.disarm();
}

#[test]
fn unchanged_permissive_watch_reconciles_by_reusing_generation() {
    let temporary = TempDir::new().expect("permissive WATCH reuse workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let source = root.join("src/lib.rs");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"watch-permissive-reuse\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(&source, "pub fn unchanged_watch() -> u8 { 1 }\n").expect("initial source");

    let stdout = temporary.path().join("watch-permissive-reuse.stdout");
    let stderr = temporary.path().join("watch-permissive-reuse.stderr");
    let child = Command::new(h00ligan_binary())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--allow-capability-downgrade",
            "--format",
            "json",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "1",
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("permissive reuse WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("permissive reuse WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn shipped permissive reuse WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_generation(&mut watch, &root, &data_dir, None);

    // Cross one full integrity interval. The resulting authoritative source
    // check must reuse exact current evidence rather than interpreting
    // downgrade permission as a demand to publish another generation.
    std::thread::sleep(Duration::from_millis(1_500));
    let watch_output_path = watch.stdout.clone();
    let status = watch.terminate();
    assert!(
        status.success(),
        "permissive reuse WATCH shutdown failed: {status}"
    );
    let final_generation = resolve_generation(&data_dir, &root).expect("final current generation");
    assert_eq!(
        final_generation.manifest.generation_id.to_string(),
        initial,
        "an unchanged integrity reconciliation must not manufacture a new generation"
    );

    let events = fs::read_to_string(&watch_output_path)
        .expect("read permissive reuse WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    assert!(
        events.iter().any(|event| {
            event["event"] == "reconciliation_terminal"
                && event["state"] == "succeeded"
                && event["reused_generation"] == true
        }),
        "positive control: periodic integrity work must reach exact-generation reuse: {events:?}"
    );
    assert!(
        events.iter().any(|event| {
            event["event"] == "watch_stopped"
                && event["integrity_reconciliations"]
                    .as_u64()
                    .is_some_and(|count| count >= 1)
        }),
        "positive control: the configured integrity cadence must actually fire: {events:?}"
    );
}

/// Installed-product acceptance for the one-file semantic WATCH contract.
///
/// This is intentionally separate from
/// `shipped_semantic_watch_serves_structural_truth_while_provider_is_blocked`,
/// whose positive control injects the development build's external fallback
/// provider. A portable artifact owns an embedded hidden provider and must
/// never invoke that adjacent executable seam.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, an installed Rust toolchain, and native signal delivery"]
fn installed_one_file_watch_recertifies_hidden_cargo_configuration() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed WATCH acceptance"),
    );
    let temporary = TempDir::new().expect("installed semantic WATCH scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let source = root.join("src/lib.rs");
    let cargo = root.join(".cargo");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
    std::fs::create_dir_all(&cargo).expect("Cargo configuration directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"installed-watch\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .expect("manifest");
    std::fs::write(
        &source,
        "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
    )
    .expect("source");
    let configuration = cargo.join("config.toml");
    std::fs::write(&configuration, "[term]\nverbose = false\n")
        .expect("initial Cargo configuration");

    let stdout = temporary.path().join("installed-watch.stdout");
    let stderr = temporary.path().join("installed-watch.stderr");
    let child = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--require-complete-calls",
            "--profile",
            "--format",
            "json",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "1",
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("installed WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("installed WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn installed one-file WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_generation(&mut watch, &root, &data_dir, None);
    std::fs::write(&configuration, "[term]\nverbose = true\n")
        .expect("change hidden Cargo configuration");
    let changed = wait_for_generation(&mut watch, &root, &data_dir, Some(&initial));
    assert_ne!(changed, initial, "project-control drift must recertify");

    // The same live WATCH process still owns the exact sessions and runtime
    // authority that produced `changed`, so its next periodic reconciliation
    // may reuse that generation after probing the provider/toolchain again.
    wait_for_reused_terminal(&mut watch, &changed);

    let watch_output_path = watch.stdout.clone();
    let status = watch.terminate();
    assert!(
        status.success(),
        "installed semantic WATCH shutdown failed: {status}"
    );

    let status_output = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args(["status", "--format", "json"])
        .output()
        .expect("query installed semantic WATCH result");
    assert!(
        status_output.status.success(),
        "installed status query failed: {}",
        String::from_utf8_lossy(&status_output.stderr)
    );
    let status_json: serde_json::Value =
        serde_json::from_slice(&status_output.stdout).expect("installed status JSON");
    assert_eq!(status_json["generation_id"], changed);
    assert_eq!(status_json["capabilities"]["calls"]["status"], "complete");
    assert_eq!(
        status_json["capabilities"]["calls"]["languages"][0]["language_id"],
        "rust"
    );
    assert_eq!(
        status_json["capabilities"]["calls"]["languages"][0]["provider_id"],
        "h00-rust-analyzer-scip"
    );

    let events = fs::read_to_string(&watch_output_path)
        .expect("read installed WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    assert!(
        !root.join("Cargo.lock").exists(),
        "semantic indexing must keep an ordinary lockfile-free Cargo library root-clean"
    );
    assert!(
        events.iter().any(|event| {
            event["event"] == "reconciliation_terminal"
                && event["state"] == "succeeded"
                && event["phase_timings"].as_array().is_some_and(|timings| {
                    timings.iter().any(|timing| {
                        timing["label"] == "persistent rust-analyzer execution and cache work"
                    }) && timings.iter().all(|timing| {
                        timing["label"] != "persistent rust-analyzer certification failed"
                            && timing["label"]
                                != "persistent rust-analyzer failed; one-shot fallback"
                            && !timing["label"]
                                .as_str()
                                .is_some_and(|label| label.starts_with("rust-analyzer SCIP"))
                    })
                })
        }),
        "lockfile-free Rust authority must come from the persistent provider: {events:?}"
    );
    let changed_publication = events
        .iter()
        .find(|event| {
            event["event"] == "reconciliation_terminal"
                && event["generation"] == changed
                && event["reused_generation"] == false
        })
        .expect("the changed Cargo configuration must publish a fresh generation");
    assert!(
        changed_publication["phase_timings"]
            .as_array()
            .is_some_and(|timings| timings.iter().any(|timing| {
                timing["label"] == "persistent rust-analyzer execution and cache work"
            })),
        "the changed generation must be recertified by the persistent provider: {changed_publication:?}"
    );
    assert!(
        events.iter().any(|event| {
            event["event"] == "reconciliation_terminal"
                && event["generation"] == changed
                && event["dirty_hint_count"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
        }),
        "the hidden Cargo event must reach a terminal operation for the changed generation even when a periodic reconciliation publishes it first: {events:?}"
    );
    assert!(
        events.iter().any(|event| {
            event["event"] == "reconciliation_terminal"
                && event["generation"] == changed
                && event["reused_generation"] == true
        }),
        "the live provider session must retain a measured exact-reuse fast lane: {events:?}"
    );
    assert!(events.iter().any(|event| {
        event["event"] == "watch_stopped"
            && event["filesystem_batches"]
                .as_u64()
                .is_some_and(|count| count > 0)
    }));

    // Restarting the shipped WATCH has no live ownership of the provider
    // sessions that certified the preceding generation. It must perform one
    // startup recertification rather than inheriting semantic authority from
    // persisted receipts alone. When every source, project-control, provider,
    // invocation, and toolchain coordinate is still exact, that
    // recertification reuses the same content-addressed generation instead of
    // publishing byte-identical state under a new ID. This is not a phantom
    // filesystem batch or a periodic integrity event.
    let restart_stdout = temporary.path().join("installed-watch-restart.stdout");
    let restart_stderr = temporary.path().join("installed-watch-restart.stderr");
    let restart = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--require-complete-calls",
            "--profile",
            "--format",
            "json",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&restart_stdout).expect("restart WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&restart_stderr).expect("restart WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn restarted installed WATCH process");
    let mut restart = RunningWatch {
        child: Some(restart),
        stdout: restart_stdout.clone(),
        stderr: restart_stderr,
    };
    let deadline = Instant::now() + test_timeout(10);
    loop {
        let terminal_seen = fs::read_to_string(&restart_stdout)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .any(|event| event["event"] == "reconciliation_terminal");
        if terminal_seen {
            break;
        }
        if let Some(status) = restart
            .child_mut()
            .try_wait()
            .expect("inspect restarted WATCH child")
        {
            panic!(
                "restarted WATCH exited before its startup terminal ({status})\n{}",
                restart.diagnostics()
            );
        }
        assert!(
            Instant::now() < deadline,
            "restarted WATCH did not emit its startup terminal\n{}",
            restart.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(restart.terminate().success());
    let restart_events = fs::read_to_string(&restart_stdout)
        .expect("read restarted WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("restart event JSON"))
        .collect::<Vec<_>>();
    let restart_terminals = restart_events
        .iter()
        .filter(|event| event["event"] == "reconciliation_terminal")
        .collect::<Vec<_>>();
    assert_eq!(restart_terminals.len(), 1, "{restart_events:?}");
    assert_eq!(restart_terminals[0]["generation"], changed);
    assert_eq!(restart_terminals[0]["reused_generation"], true);
    let phase_timings = restart_terminals[0]["phase_timings"]
        .as_array()
        .expect("restart phase timings");
    assert!(
        phase_timings
            .iter()
            .any(|timing| timing["label"] == "checking current generation"),
        "restart must cross the exact-generation recertification lane: {restart_events:?}"
    );
    assert!(
        phase_timings.iter().all(|timing| {
            timing["label"] != "persistent rust-analyzer execution and cache work"
                && !timing["label"]
                    .as_str()
                    .is_some_and(|label| label.starts_with("rust-analyzer SCIP"))
        }),
        "exact recertification must not export and republish the provider graph: {restart_events:?}"
    );
    assert!(restart_events.iter().any(|event| {
        event["event"] == "watch_stopped"
            && event["filesystem_batches"] == 0
            && event["publication_drifts"] == 0
            && event["integrity_reconciliations"] == 0
    }));
}

/// RIGHT-REASON PERFORMANCE REGRESSION: an exact Rust-only source edit cannot
/// invalidate Go source, project-input, toolchain, provider, or configuration
/// authority. The long-lived shipped WATCH must therefore retain the admitted
/// Go semantic basis without refreshing its embedded gopls session. Typed
/// lifecycle receipts and one content-addressed private provider are the
/// production evidence; an external `scip-go` executable is deliberately
/// absent.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, Go, an installed Rust toolchain, and native signal delivery"]
fn installed_mixed_watch_does_not_rerun_go_for_a_rust_only_edit() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed WATCH acceptance"),
    );
    let temporary = TempDir::new().expect("mixed semantic WATCH workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(root.join("src")).expect("Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"mixed-watch\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .expect("Cargo manifest");
    let rust_source = root.join("src/lib.rs");
    std::fs::write(
        &rust_source,
        "pub fn rust_target() -> usize { 1 }\npub fn rust_caller() -> usize { rust_target() }\n",
    )
    .expect("Rust source");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/mixedwatch\n\ngo 1.27\n",
    )
    .expect("Go module");
    let go_source = root.join("main.go");
    std::fs::write(
        &go_source,
        "package main\nfunc goTarget() int { return 1 }\nfunc goCaller() int { return goTarget() }\n",
    )
    .expect("Go source");

    let search_path = go_and_rust_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");
    let cargo_home = temporary.path().join("cargo-home");

    let stdout = temporary.path().join("mixed-watch.stdout");
    let stderr = temporary.path().join("mixed-watch.stderr");
    let child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .env("CARGO_HOME", &cargo_home)
        .env("RUST_LOG", "h00ligan_engine=debug")
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("mixed WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("mixed WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn installed mixed WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_fresh_terminal(&mut watch, None);
    let materialized_provider = assert_one_embedded_go_provider(&data_dir);
    let initial_events = fs::read_to_string(&watch.stdout)
        .expect("initial mixed WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let initial_terminal = initial_events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == initial)
        .expect("initial mixed WATCH terminal receipt");
    let initial_refreshes = initial_terminal["semantic_provider_refreshes"]
        .as_array()
        .expect("cold mixed provider refreshes");
    assert_eq!(
        initial_refreshes.len(),
        2,
        "cold mixed WATCH must refresh Rust and Go exactly once: {initial_events:?}\n{}",
        watch.diagnostics()
    );
    for language in ["rust", "go"] {
        let refresh = initial_refreshes
            .iter()
            .find(|refresh| refresh["language"] == language)
            .unwrap_or_else(|| panic!("missing cold {language} refresh: {initial_events:?}"));
        assert_eq!(refresh["lane"], "full");
        assert_eq!(refresh["operation"], "certify_full");
        assert_eq!(refresh["documents"], serde_json::json!([]));
        assert_eq!(refresh["session_open"]["execution_roots"], 1);
        assert_eq!(refresh["session_open"]["max_parallelism"], 1);
        assert!(refresh["session_open"]["duration_ms"].as_u64().is_some());
    }

    std::fs::write(
        &rust_source,
        "pub fn rust_target() -> usize { 2 }\npub fn rust_caller() -> usize { rust_target() }\n",
    )
    .expect("Rust-only source edit");
    let changed = wait_for_fresh_terminal(&mut watch, Some(&initial));
    assert_ne!(changed, initial, "Rust truth must publish a new generation");

    // Symmetric positive control: the Rust edit really entered the provider
    // lane before this process exits.
    let first_events = fs::read_to_string(&watch.stdout)
        .expect("read first mixed WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let rust_changed_terminal = first_events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == changed)
        .expect("Rust-change terminal receipt");
    assert!(
        rust_changed_terminal["semantic_provider_refreshes"]
            .as_array()
            .is_some_and(|refreshes| {
                refreshes.iter().any(|refresh| {
                    refresh["language"] == "rust"
                        && refresh["lane"] == "affected_documents"
                        && refresh["operation"] == "refresh_affected"
                        && refresh["documents"] == serde_json::json!(["src/lib.rs"])
                }) && refreshes.iter().any(|refresh| {
                    refresh["language"] == "go"
                        && refresh["lane"] == "reused"
                        && refresh["operation"].is_null()
                }) && refreshes.iter().all(|refresh| {
                    refresh["language"] != "go"
                        || (refresh["lane"] != "full" && refresh["lane"] != "affected_documents")
                })
            }),
        "Rust-only edit refreshed Go despite exact retained authority: {first_events:?}\n{}",
        watch.diagnostics()
    );
    assert_eq!(
        assert_one_embedded_go_provider(&data_dir),
        materialized_provider,
        "Rust-only edit must retain the exact embedded Go provider"
    );
    assert_atomic_affected_refresh_receipt(rust_changed_terminal, "rust", &watch.diagnostics());
    assert!(
        rust_changed_terminal["phase_timings"]
            .as_array()
            .is_some_and(|timings| timings.iter().any(|timing| {
                timing["label"] == "persistent rust-analyzer execution and cache work"
            })),
        "positive control: the Rust edit did not exercise the Rust provider: {first_events:?}"
    );
    assert!(watch.terminate().success(), "first mixed WATCH shutdown");

    // Cross-process right-reason control: a newly started WATCH has no prior
    // in-memory Rust snapshot. It must recover the disposable snapshot whose
    // identity is sealed by the immutable payload, recertify that payload, and
    // reuse it after a Go-only edit without exporting Rust again.
    let restart_stdout = temporary.path().join("mixed-watch-restart.stdout");
    let restart_stderr = temporary.path().join("mixed-watch-restart.stderr");
    let restart = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .env("CARGO_HOME", &cargo_home)
        .env("RUST_LOG", "h00ligan_engine=debug")
        .stdout(Stdio::from(
            std::fs::File::create(&restart_stdout).expect("restarted mixed WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&restart_stderr).expect("restarted mixed WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn restarted installed mixed WATCH process");
    let mut restart = RunningWatch {
        child: Some(restart),
        stdout: restart_stdout,
        stderr: restart_stderr,
    };
    wait_for_reused_terminal(&mut restart, &changed);
    assert_eq!(
        assert_one_embedded_go_provider(&data_dir),
        materialized_provider,
        "restarted WATCH must recover the same content-addressed Go provider"
    );

    std::fs::write(
        &go_source,
        "package main\nfunc goTarget() int { return 2 }\nfunc goCaller() int { return goTarget() }\n",
    )
    .expect("Go-only source edit");
    let go_changed = wait_for_fresh_terminal(&mut restart, Some(&changed));
    assert_ne!(
        go_changed, changed,
        "Go truth must publish a new generation"
    );
    let events = fs::read_to_string(&restart.stdout)
        .expect("read restarted mixed WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let go_changed_terminal = events
        .iter()
        .find(|event| {
            event["event"] == "reconciliation_terminal" && event["generation"] == go_changed
        })
        .expect("Go-change terminal receipt");
    let canonical_cache = data_dir
        .join(h00ligan_engine::project_binding::PROVIDER_CACHE_DIRECTORY)
        .join("canonical-scip-v2");
    let cached_snapshots = std::fs::read_dir(&canonical_cache)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| {
                    format!(
                        "{}:{}",
                        entry.file_name().to_string_lossy(),
                        entry.metadata().map_or(0, |metadata| metadata.len())
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        go_changed_terminal["phase_timings"]
            .as_array()
            .is_some_and(|timings| {
                timings
                    .iter()
                    .any(|timing| timing["label"] == "rust exact semantic basis admission")
                    && timings.iter().all(|timing| {
                        timing["label"] != "persistent rust-analyzer execution and cache work"
                            && timing["label"] != "persistent rust-analyzer certification failed"
                    })
            }),
        "a Go-only edit entered the unchanged Rust provider path; cache={cached_snapshots:?}: {events:?}"
    );
    assert!(
        go_changed_terminal["semantic_provider_refreshes"]
            .as_array()
            .is_some_and(|refreshes| {
                refreshes.iter().any(|refresh| {
                    refresh["language"] == "rust"
                        && refresh["lane"] == "reused"
                        && refresh["operation"].is_null()
                }) && refreshes.iter().any(|refresh| {
                    refresh["language"] == "go"
                        && refresh["lane"] == "affected_documents"
                        && refresh["operation"] == "refresh_affected"
                        && refresh["documents"] == serde_json::json!(["main.go"])
                })
            }),
        "Go-only edit did not use the retained affected-document session: {events:?}\n{}",
        restart.diagnostics()
    );
    assert_atomic_affected_refresh_receipt(go_changed_terminal, "go", &restart.diagnostics());

    let status = restart.terminate();
    assert!(status.success(), "mixed WATCH shutdown failed: {status}");
}

/// RIGHT-REASON REGRESSION for the staged polyglot path used by MCP WATCH.
/// Publishing fast structural truth must not discard the previous semantic
/// basis before enrichment decides which language actually changed. The two
/// owned head writes also must not feed back as a foreign publication epoch.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, Pyrefly, an installed Rust toolchain, and native signal delivery"]
fn installed_staged_python_watch_reuses_rust_and_owns_both_publications() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for staged polyglot WATCH"),
    );
    let temporary = TempDir::new().expect("staged polyglot WATCH workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let process_tmp = temporary.path().join("tmp");
    std::fs::create_dir_all(&root).expect("polyglot repository root");
    std::fs::create_dir_all(&process_tmp).expect("private process temporary directory");
    let fixture = WorkspaceProviderWatchConformanceCase::Python.create_fixture(&root);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"staged-polyglot-watch\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .expect("Rust manifest");
    std::fs::write(
        root.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"staged-polyglot-watch\"\nversion = \"0.1.0\"\n",
    )
    .expect("Rust lockfile");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn rust_target() -> usize { 1 }\npub fn rust_caller() -> usize { rust_target() }\n",
    )
    .expect("unchanged Rust source");

    let search_path = go_and_rust_search_path(&temporary);
    let cargo_home = temporary.path().join("cargo-home");
    let stdout = temporary.path().join("staged-polyglot-watch.stdout");
    let stderr = temporary.path().join("staged-polyglot-watch.stderr");
    let child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", &process_tmp)
        .env("PATH", &search_path)
        .env("CARGO_HOME", &cargo_home)
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "watch",
            "--scip",
            "--allow-capability-downgrade",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("staged polyglot WATCH stdout"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("staged polyglot WATCH stderr"),
        ))
        .spawn()
        .expect("spawn installed staged polyglot WATCH");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_fresh_terminal(&mut watch, None);
    std::fs::write(&fixture.caller, fixture.changed_caller).expect("Python-only source edit");
    let changed = wait_for_fresh_terminal(&mut watch, Some(&initial));
    assert_ne!(
        changed, initial,
        "Python truth must publish a new generation"
    );

    // Cross at least several 10 ms publication probes after the final semantic
    // head is durable. Stopping immediately after the terminal would make the
    // old self-drift defect timing-dependent and vacuous.
    std::thread::sleep(Duration::from_millis(100));
    let watch_output = watch.stdout.clone();
    assert!(
        watch.terminate().success(),
        "staged polyglot WATCH shutdown"
    );
    let events = fs::read_to_string(&watch_output)
        .expect("read staged polyglot WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let terminal = events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == changed)
        .unwrap_or_else(|| panic!("Python-change terminal receipt is absent: {events:?}"));
    let refreshes = terminal["semantic_provider_refreshes"]
        .as_array()
        .expect("typed polyglot provider activity");
    assert!(
        refreshes.iter().any(|refresh| {
            refresh["language"] == "python"
                && refresh["lane"] == "affected_documents"
                && refresh["operation"] == "refresh_affected"
                && refresh["documents"]
                    == serde_json::json!([
                        WorkspaceProviderWatchConformanceCase::Python.caller_relative()
                    ])
        }),
        "positive control: the Python-only edit did not enter the Python affected-document lane: {events:?}"
    );
    assert!(
        refreshes.iter().any(|refresh| {
            refresh["language"] == "rust"
                && refresh["lane"] == "reused"
                && refresh["operation"].is_null()
        }),
        "the staged structural publication discarded unchanged Rust semantic reuse: {events:?}"
    );
    assert!(
        terminal["phase_timings"].as_array().is_some_and(|timings| {
            timings
                .iter()
                .any(|timing| timing["label"] == "rust exact semantic basis admission")
                && timings.iter().all(|timing| {
                    timing["label"] != "persistent rust-analyzer execution and cache work"
                        && timing["label"] != "persistent rust-analyzer certification failed"
                })
        }),
        "a Python-only edit entered the unchanged Rust provider refresh path: {events:?}"
    );
    let stopped = events
        .iter()
        .find(|event| event["event"] == "watch_stopped")
        .expect("staged polyglot WATCH stopped receipt");
    assert!(
        stopped["publication_probes"]
            .as_u64()
            .is_some_and(|probes| probes >= 3),
        "positive control: post-publication drift probes did not run: {stopped}"
    );
    assert_eq!(
        stopped["publication_drifts"], 0,
        "the structural and semantic heads are two owned writes in one source epoch: {stopped}"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceProviderWatchConformanceCase {
    Python,
    TypeScript,
}

const WORKSPACE_PROVIDER_WATCH_CONFORMANCE_MATRIX: [WorkspaceProviderWatchConformanceCase; 2] = [
    WorkspaceProviderWatchConformanceCase::Python,
    WorkspaceProviderWatchConformanceCase::TypeScript,
];

struct WorkspaceProviderWatchFixture {
    caller: PathBuf,
    initial_caller: &'static [u8],
    changed_caller: &'static [u8],
    source_before: Vec<(&'static str, Vec<u8>)>,
}

impl WorkspaceProviderWatchConformanceCase {
    const fn language(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::TypeScript => "typescript",
        }
    }

    const fn display_name(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::TypeScript => "TypeScript",
        }
    }

    const fn provider_id(self) -> &'static str {
        match self {
            Self::Python => "h00-pyrefly-scip",
            Self::TypeScript => "h00-typescript-native-scip",
        }
    }

    const fn provider_executable(self) -> &'static str {
        match self {
            Self::Python => "h00-pyrefly-semantic-provider",
            Self::TypeScript => "h00-typescript-semantic-provider",
        }
    }

    const fn caller_relative(self) -> &'static str {
        match self {
            Self::Python => "src/fixture/caller.py",
            Self::TypeScript => "src/caller.ts",
        }
    }

    const fn target_relative(self) -> &'static str {
        match self {
            Self::Python => "src/fixture/target.py",
            Self::TypeScript => "src/target.ts",
        }
    }

    const fn configuration_relative(self) -> &'static str {
        match self {
            Self::Python => "pyproject.toml",
            Self::TypeScript => "tsconfig.json",
        }
    }

    const fn initial_configuration(self) -> &'static [u8] {
        match self {
            Self::Python => concat!(
                "[project]\nname = \"python-watch\"\nversion = \"0.1.0\"\n\n",
                "[tool.pyrefly]\nproject_includes = [\"src\"]\n",
            )
            .as_bytes(),
            Self::TypeScript => br#"{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true},"include":["src/**/*.ts"]}"#,
        }
    }

    const fn changed_configuration(self) -> &'static [u8] {
        match self {
            Self::Python => concat!(
                "[project]\nname = \"python-watch\"\nversion = \"0.1.0\"\n\n",
                "[tool.pyrefly]\nproject_includes = [\"src\"]\npython-version = \"3.12\"\n",
            )
            .as_bytes(),
            Self::TypeScript => br#"{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true,"noImplicitOverride":true},"include":["src/**/*.ts"]}"#,
        }
    }

    const fn forbidden_residue(self) -> &'static [&'static str] {
        match self {
            Self::Python => &[".venv", "__pycache__", "src/fixture/__pycache__"],
            Self::TypeScript => &["node_modules", "package-lock.json"],
        }
    }

    fn create_fixture(self, root: &Path) -> WorkspaceProviderWatchFixture {
        match self {
            Self::Python => {
                std::fs::create_dir_all(root.join("src/fixture")).expect("Python source directory");
                std::fs::write(
                    root.join(self.configuration_relative()),
                    self.initial_configuration(),
                )
                .expect("Python package manifest");
                std::fs::write(root.join("src/fixture/__init__.py"), b"")
                    .expect("Python package marker");
                std::fs::write(
                    root.join("src/fixture/target.py"),
                    concat!(
                        "def targetA() -> int:\n    return 1\n\n",
                        "def targetB() -> int:\n    return 2\n",
                    ),
                )
                .expect("Python target source");
                let initial_caller = concat!(
                    "from fixture.target import targetA, targetB\n\n",
                    "def caller() -> int:\n    return targetA()\n",
                )
                .as_bytes();
                let changed_caller = concat!(
                    "from fixture.target import targetA, targetB\n\n",
                    "def caller() -> int:\n    return targetB()\n",
                )
                .as_bytes();
                let caller = root.join(self.caller_relative());
                std::fs::write(&caller, initial_caller).expect("initial Python caller source");
                WorkspaceProviderWatchFixture {
                    caller,
                    initial_caller,
                    changed_caller,
                    source_before: [
                        "pyproject.toml",
                        "src/fixture/__init__.py",
                        "src/fixture/target.py",
                        self.caller_relative(),
                    ]
                    .into_iter()
                    .map(|relative| {
                        (
                            relative,
                            std::fs::read(root.join(relative))
                                .unwrap_or_else(|error| panic!("read {relative}: {error}")),
                        )
                    })
                    .collect(),
                }
            }
            Self::TypeScript => {
                std::fs::create_dir_all(root.join("src")).expect("TypeScript source directory");
                std::fs::write(
                    root.join("package.json"),
                    r#"{"name":"typescript-watch","private":true,"type":"module"}"#,
                )
                .expect("TypeScript package manifest");
                std::fs::write(
                    root.join(self.configuration_relative()),
                    self.initial_configuration(),
                )
                .expect("TypeScript compiler configuration");
                std::fs::write(
                    root.join("src/target.ts"),
                    "export function targetA(): number { return 1; }\nexport function targetB(): number { return 2; }\n",
                )
                .expect("TypeScript target source");
                let initial_caller = b"import { targetA, targetB } from './target.js';\nexport function caller(): number { return targetA(); }\n";
                let changed_caller = b"import { targetA, targetB } from './target.js';\nexport function caller(): number { return targetB(); }\n";
                let caller = root.join(self.caller_relative());
                std::fs::write(&caller, initial_caller).expect("initial TypeScript caller source");
                WorkspaceProviderWatchFixture {
                    caller,
                    initial_caller,
                    changed_caller,
                    source_before: [
                        "package.json",
                        "tsconfig.json",
                        "src/target.ts",
                        self.caller_relative(),
                    ]
                    .into_iter()
                    .map(|relative| {
                        (
                            relative,
                            std::fs::read(root.join(relative))
                                .unwrap_or_else(|error| panic!("read {relative}: {error}")),
                        )
                    })
                    .collect(),
                }
            }
        }
    }
}

fn workspace_provider_full_baseline_calls(
    case: WorkspaceProviderWatchConformanceCase,
    binary: &Path,
    root: &Path,
    data_dir: &Path,
    process_tmp: &Path,
) -> (serde_json::Value, serde_json::Value) {
    let display = case.display_name();
    let baseline = Command::new(binary)
        .env_clear()
        .env("TMPDIR", process_tmp)
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run independent full {display} baseline: {error}"));
    assert!(
        baseline.status.success(),
        "full {display} baseline failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline_report: serde_json::Value = serde_json::from_slice(&baseline.stdout)
        .unwrap_or_else(|error| panic!("full {display} baseline JSON: {error}"));
    assert_eq!(
        baseline_report["capabilities"]["calls"]["status"],
        "complete"
    );
    assert_one_private_embedded_provider(data_dir, case.provider_executable());
    let baseline_a = isolated_calls_json_at(
        binary,
        root,
        data_dir,
        process_tmp,
        "targetA",
        case.target_relative(),
        display,
    );
    let baseline_b = isolated_calls_json_at(
        binary,
        root,
        data_dir,
        process_tmp,
        "targetB",
        case.target_relative(),
        display,
    );
    (baseline_a, baseline_b)
}

fn run_workspace_provider_watch_conformance(case: WorkspaceProviderWatchConformanceCase) {
    assert!(
        WORKSPACE_PROVIDER_WATCH_CONFORMANCE_MATRIX.contains(&case),
        "workspace-provider WATCH case is not registered in the conformance matrix"
    );
    let display = case.display_name();
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .unwrap_or_else(|| panic!("H00_TEST_H00LIGAN_BINARY for installed {display} WATCH")),
    );
    let temporary = TempDir::new()
        .unwrap_or_else(|error| panic!("persistent {display} WATCH workspace: {error}"));
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("watch-data");
    let baseline_data_dir = temporary.path().join("full-baseline-data");
    let configuration_baseline_data_dir = temporary.path().join("configuration-baseline-data");
    let process_tmp = temporary.path().join("tmp");
    std::fs::create_dir_all(&root).expect("workspace-provider repository root");
    std::fs::create_dir_all(&process_tmp).expect("private process temporary directory");
    let fixture = case.create_fixture(&root);

    let stdout = temporary
        .path()
        .join("persistent-workspace-provider-watch.stdout");
    let stderr = temporary
        .path()
        .join("persistent-workspace-provider-watch.stderr");
    let child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", &process_tmp)
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "watch",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("workspace-provider WATCH stdout"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("workspace-provider WATCH stderr"),
        ))
        .spawn()
        .unwrap_or_else(|error| panic!("spawn installed {display} WATCH: {error}"));
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_fresh_terminal(&mut watch, None);
    let materialized_provider =
        assert_one_private_embedded_provider(&data_dir, case.provider_executable());
    #[cfg(target_os = "linux")]
    let retained_provider_pid =
        wait_for_direct_child_at_root(watch.child_mut().id(), &materialized_provider, &root);
    let initial_terminal = terminal_event_for_generation(&watch, &initial, "initial");
    assert_full_provider_refresh_receipt(&initial_terminal, case.language(), &watch.diagnostics());

    let initial_a = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetA",
        case.target_relative(),
        display,
    );
    let initial_b = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetB",
        case.target_relative(),
        display,
    );
    assert_eq!(calls_items(&initial_a).len(), 1, "positive initial call");
    assert!(calls_items(&initial_b).is_empty(), "negative initial call");
    assert_eq!(initial_a["authority"]["provider_id"], case.provider_id());

    std::fs::write(&fixture.caller, fixture.changed_caller)
        .unwrap_or_else(|error| panic!("{display} body-only call-target edit: {error}"));
    let changed = wait_for_fresh_terminal(&mut watch, Some(&initial));
    assert_ne!(changed, initial, "body edit must publish a new generation");
    let changed_terminal = terminal_event_for_generation(&watch, &changed, "body-changed");
    assert_eq!(
        changed_terminal["semantic_provider_refreshes"],
        serde_json::json!([{
            "language": case.language(),
            "lane": "affected_documents",
            "operation": "refresh_affected",
            "documents": [case.caller_relative()],
            "session_open": null,
        }]),
        "body-only {display} edit must use the retained session's affected-document lane: {changed_terminal:?}\n{}",
        watch.diagnostics(),
    );
    assert_atomic_affected_refresh_receipt(
        &changed_terminal,
        case.language(),
        &watch.diagnostics(),
    );
    assert_eq!(
        assert_one_private_embedded_provider(&data_dir, case.provider_executable()),
        materialized_provider,
        "warm refresh must retain the same content-addressed embedded provider"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        wait_for_direct_child_at_root(watch.child_mut().id(), &materialized_provider, &root),
        retained_provider_pid,
        "affected-document refresh replaced its healthy {display} provider process"
    );

    let watch_a = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetA",
        case.target_relative(),
        display,
    );
    let watch_b = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetB",
        case.target_relative(),
        display,
    );
    assert!(
        calls_items(&watch_a).is_empty(),
        "stale targetA call survived"
    );
    assert_eq!(calls_items(&watch_b).len(), 1, "fresh targetB call missing");
    assert_eq!(
        calls_items(&watch_b)[0]["origin"]["identity"]["name"],
        "caller"
    );

    let (baseline_a, baseline_b) = workspace_provider_full_baseline_calls(
        case,
        &binary,
        &root,
        &baseline_data_dir,
        &process_tmp,
    );
    assert_eq!(
        semantic_calls_items(&watch_a),
        semantic_calls_items(&baseline_a),
        "retained-session targetA result differs from a fresh full {display} generation"
    );
    assert_eq!(
        semantic_calls_items(&watch_b),
        semantic_calls_items(&baseline_b),
        "retained-session targetB result differs from a fresh full {display} generation"
    );

    std::fs::write(&fixture.caller, fixture.initial_caller)
        .unwrap_or_else(|error| panic!("restore exact {display} caller bytes: {error}"));
    let restored = wait_for_fresh_terminal(&mut watch, Some(&changed));
    assert_ne!(
        restored, changed,
        "exact restore must publish a new generation"
    );
    let restored_terminal = terminal_event_for_generation(&watch, &restored, "body-restored");
    assert_eq!(
        restored_terminal["semantic_provider_refreshes"],
        serde_json::json!([{
            "language": case.language(),
            "lane": "affected_documents",
            "operation": "refresh_affected",
            "documents": [case.caller_relative()],
            "session_open": null,
        }]),
        "exact restore must retain the same affected-document session: {restored_terminal:?}"
    );
    assert_atomic_affected_refresh_receipt(
        &restored_terminal,
        case.language(),
        &watch.diagnostics(),
    );
    let restored_a = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetA",
        case.target_relative(),
        display,
    );
    let restored_b = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetB",
        case.target_relative(),
        display,
    );
    assert_eq!(
        semantic_calls_items(&restored_a),
        semantic_calls_items(&initial_a)
    );
    assert_eq!(
        semantic_calls_items(&restored_b),
        semantic_calls_items(&initial_b)
    );
    assert_eq!(
        restored_a["authority"]["input_fingerprints"], initial_a["authority"]["input_fingerprints"],
        "exact restore did not recover the initial {display} authority basis"
    );
    assert_eq!(restored_a["authority"]["status"], "complete");
    assert_eq!(restored_a["authority"]["provider_id"], case.provider_id());
    #[cfg(target_os = "linux")]
    assert_eq!(
        wait_for_direct_child_at_root(watch.child_mut().id(), &materialized_provider, &root),
        retained_provider_pid,
        "exact restore replaced its healthy {display} provider process"
    );

    let configuration_path = root.join(case.configuration_relative());
    std::fs::write(&configuration_path, case.changed_configuration())
        .unwrap_or_else(|error| panic!("change {display} semantic configuration: {error}"));
    let configured = wait_for_fresh_terminal(&mut watch, Some(&restored));
    let configured_terminal =
        terminal_event_for_generation(&watch, &configured, "configuration-changed");
    assert_full_provider_refresh_receipt(
        &configured_terminal,
        case.language(),
        &watch.diagnostics(),
    );
    assert_eq!(
        assert_one_private_embedded_provider(&data_dir, case.provider_executable()),
        materialized_provider,
        "configuration drift changed the embedded {display} provider artifact"
    );
    #[cfg(target_os = "linux")]
    let configured_provider_pid =
        wait_for_direct_child_at_root(watch.child_mut().id(), &materialized_provider, &root);
    #[cfg(target_os = "linux")]
    assert_ne!(
        configured_provider_pid, retained_provider_pid,
        "semantic-configuration drift retained the stale {display} compiler session"
    );

    let configured_a = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetA",
        case.target_relative(),
        display,
    );
    let configured_b = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetB",
        case.target_relative(),
        display,
    );
    assert_ne!(
        configured_a["authority"]["input_fingerprints"],
        initial_a["authority"]["input_fingerprints"],
        "semantic-configuration mutation did not change the admitted {display} authority basis"
    );
    let (configured_baseline_a, configured_baseline_b) = workspace_provider_full_baseline_calls(
        case,
        &binary,
        &root,
        &configuration_baseline_data_dir,
        &process_tmp,
    );
    assert_eq!(
        semantic_calls_items(&configured_a),
        semantic_calls_items(&configured_baseline_a),
        "configuration-restarted targetA result differs from a fresh full {display} generation"
    );
    assert_eq!(
        semantic_calls_items(&configured_b),
        semantic_calls_items(&configured_baseline_b),
        "configuration-restarted targetB result differs from a fresh full {display} generation"
    );

    std::fs::write(&configuration_path, case.initial_configuration())
        .unwrap_or_else(|error| panic!("restore exact {display} semantic configuration: {error}"));
    let configuration_restored = wait_for_fresh_terminal(&mut watch, Some(&configured));
    let configuration_restored_terminal =
        terminal_event_for_generation(&watch, &configuration_restored, "configuration-restored");
    assert_full_provider_refresh_receipt(
        &configuration_restored_terminal,
        case.language(),
        &watch.diagnostics(),
    );
    #[cfg(target_os = "linux")]
    assert_ne!(
        wait_for_direct_child_at_root(watch.child_mut().id(), &materialized_provider, &root),
        configured_provider_pid,
        "exact configuration restore retained the superseded {display} compiler session"
    );
    let configuration_restored_a = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetA",
        case.target_relative(),
        display,
    );
    let configuration_restored_b = isolated_calls_json_at(
        &binary,
        &root,
        &data_dir,
        &process_tmp,
        "targetB",
        case.target_relative(),
        display,
    );
    assert_eq!(
        semantic_calls_items(&configuration_restored_a),
        semantic_calls_items(&initial_a)
    );
    assert_eq!(
        semantic_calls_items(&configuration_restored_b),
        semantic_calls_items(&initial_b)
    );
    assert_eq!(
        configuration_restored_a["authority"]["input_fingerprints"],
        initial_a["authority"]["input_fingerprints"],
        "exact configuration restore did not recover the initial {display} authority basis"
    );

    let watch_output_path = watch.stdout.clone();
    let status = watch.terminate();
    assert!(
        status.success(),
        "persistent {display} WATCH shutdown failed: {status}"
    );
    let terminal_events = fs::read_to_string(&watch_output_path).expect("terminal WATCH events");
    assert!(
        terminal_events.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .is_ok_and(|event| event["event"] == "watch_stopped")
        }),
        "{display} WATCH emitted no terminal shutdown receipt: {terminal_events}"
    );
    for (relative, expected) in fixture.source_before {
        assert_eq!(
            std::fs::read(root.join(relative))
                .unwrap_or_else(|error| panic!("source after {display} WATCH: {error}")),
            expected,
            "installed {display} WATCH mutated {relative}"
        );
    }
    for relative in case.forbidden_residue() {
        assert!(
            !root.join(relative).exists(),
            "installed {display} WATCH left forbidden workspace residue: {relative}"
        );
    }
}

/// Installed-product WATCH acceptance for the native TypeScript lane. A
/// function with an explicit return type has a stable cross-document surface,
/// so changing only its call target must use the retained provider session's
/// affected-document refresh. The result must equal a fresh full certification,
/// survive an exact source restore, and require no ambient JavaScript tooling.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and native signal delivery"]
fn installed_typescript_watch_source_and_configuration_lifecycle_matches_full_baselines() {
    run_workspace_provider_watch_conformance(WorkspaceProviderWatchConformanceCase::TypeScript);
}

/// Installed-product WATCH acceptance for the native Pyrefly lane. A typed
/// function body switches between two already-imported targets without
/// changing the package surface. The retained provider session must publish
/// exact affected-document truth, equal a fresh full certification, and
/// recover the original authority basis after a byte-exact restore.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and native signal delivery"]
fn installed_python_watch_source_and_configuration_lifecycle_matches_full_baselines() {
    run_workspace_provider_watch_conformance(WorkspaceProviderWatchConformanceCase::Python);
}

/// RIGHT-REASON PERFORMANCE REGRESSION: a Go function-body edit leaves the
/// module topology and exported definition surface unchanged. A long-lived
/// WATCH therefore has enough authority to update the changed document from
/// one retained semantic session. Reopening the embedded provider would
/// discard the exact typed workspace state that WATCH exists to retain.
///
/// The speed claim is deliberately not a stopwatch assertion. The production
/// boundary must (1) reach the content-verified embedded provider without an
/// external `scip-go`, (2) report a full-to-affected live-session transition,
/// and (3) publish call results equal to an independently rebuilt full
/// generation over the same changed source.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, Go, and native signal delivery"]
fn installed_go_watch_body_edit_reuses_one_session_with_full_baseline_parity() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed WATCH acceptance"),
    );
    let temporary = TempDir::new().expect("persistent Go WATCH workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("watch-data");
    let baseline_data_dir = temporary.path().join("full-baseline-data");
    std::fs::create_dir_all(&root).expect("Go module directory");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/persistentwatch\n\ngo 1.27\n",
    )
    .expect("Go module");
    let source = root.join("main.go");
    std::fs::write(
        &source,
        "package main\nfunc targetA() int { return 1 }\nfunc targetB() int { return 2 }\nfunc caller() int { return targetA() }\n",
    )
    .expect("initial Go source");
    let search_path = go_only_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");

    let stdout = temporary.path().join("persistent-go-watch.stdout");
    let stderr = temporary.path().join("persistent-go-watch.stderr");
    let child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "watch",
            "--scip",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("persistent Go WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("persistent Go WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn installed persistent Go WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_fresh_terminal(&mut watch, None);
    let materialized_provider = assert_one_embedded_go_provider(&data_dir);
    assert!(
        !search_path
            .to_string_lossy()
            .split(':')
            .any(|directory| Path::new(directory).join("scip-go").exists()),
        "the accepted cold run must not discover external scip-go"
    );
    let initial_events = fs::read_to_string(&watch.stdout)
        .expect("initial WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let initial_terminal = initial_events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == initial)
        .expect("initial WATCH terminal receipt");
    let initial_refresh = &initial_terminal["semantic_provider_refreshes"][0];
    assert_eq!(initial_refresh["language"], "go");
    assert_eq!(initial_refresh["lane"], "full");
    assert_eq!(initial_refresh["documents"], serde_json::json!([]));
    assert_eq!(initial_refresh["session_open"]["execution_roots"], 1);
    assert_eq!(initial_refresh["session_open"]["max_parallelism"], 1);
    assert!(
        initial_refresh["session_open"]["duration_ms"]
            .as_u64()
            .is_some(),
        "cold WATCH must expose its provider-session wall timing: {initial_events:?}"
    );
    let initial_a = calls_json(&binary, &root, &data_dir, "targetA");
    let initial_b = calls_json(&binary, &root, &data_dir, "targetB");
    assert_eq!(calls_items(&initial_a).len(), 1, "positive initial call");
    assert!(calls_items(&initial_b).is_empty(), "negative initial call");
    assert_eq!(initial_a["authority"]["provider_id"], "h00-gopls-scip");

    // Only the caller body changes: the file, definitions, signatures, module,
    // toolchain, and execution-root topology remain the same.
    std::fs::write(
        &source,
        "package main\nfunc targetA() int { return 1 }\nfunc targetB() int { return 2 }\nfunc caller() int { return targetB() }\n",
    )
    .expect("Go body-only call-target edit");
    let changed = wait_for_fresh_terminal(&mut watch, Some(&initial));
    assert_ne!(changed, initial, "body edit must publish a new generation");
    let changed_events = fs::read_to_string(&watch.stdout)
        .expect("changed WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let changed_terminal = changed_events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == changed)
        .expect("changed WATCH terminal receipt");
    assert_eq!(
        changed_terminal["semantic_provider_refreshes"],
        serde_json::json!([{
            "language": "go",
            "lane": "affected_documents",
            "operation": "refresh_affected",
            "documents": ["main.go"],
            "session_open": null,
        }]),
        "body-only Go edit must use the retained session's affected-document lane: {changed_events:?}\n{}",
        watch.diagnostics(),
    );
    assert_atomic_affected_refresh_receipt(changed_terminal, "go", &watch.diagnostics());
    assert_eq!(
        assert_one_embedded_go_provider(&data_dir),
        materialized_provider,
        "warm refresh must retain the same content-addressed embedded provider"
    );

    let watch_a = calls_json(&binary, &root, &data_dir, "targetA");
    let watch_b = calls_json(&binary, &root, &data_dir, "targetB");
    assert!(
        calls_items(&watch_a).is_empty(),
        "stale targetA call survived"
    );
    assert_eq!(calls_items(&watch_b).len(), 1, "fresh targetB call missing");
    assert_eq!(
        calls_items(&watch_b)[0]["origin"]["identity"]["name"],
        "caller"
    );

    // Independent full rebuild: this is both the semantic parity oracle and a
    // non-vacuity control proving the counted batch provider still fires.
    let baseline = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&baseline_data_dir)
        .args(["index", "--scip", "--format", "json"])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .output()
        .expect("run independent full Go semantic baseline");
    assert!(
        baseline.status.success(),
        "full Go baseline failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline_report: serde_json::Value =
        serde_json::from_slice(&baseline.stdout).expect("full baseline JSON");
    assert_eq!(
        baseline_report["semantic_provider_refreshes"],
        serde_json::json!([]),
        "non-profile output must not expose provider lifecycle telemetry"
    );
    assert_one_embedded_go_provider(&baseline_data_dir);
    let baseline_a = calls_json(&binary, &root, &baseline_data_dir, "targetA");
    let baseline_b = calls_json(&binary, &root, &baseline_data_dir, "targetB");
    assert_eq!(
        semantic_calls_items(&watch_a),
        semantic_calls_items(&baseline_a),
        "retained-session targetA result differs from a fresh full embedded-provider generation"
    );
    assert_eq!(
        semantic_calls_items(&watch_b),
        semantic_calls_items(&baseline_b),
        "retained-session targetB result differs from a fresh full embedded-provider generation"
    );
    assert_ne!(
        calls_items(&watch_b)[0]["origin"]["identity"]["symbol_id"],
        calls_items(&baseline_b)[0]["origin"]["identity"]["symbol_id"],
        "positive control: public exact selectors must remain bound to their distinct immutable generations"
    );
    for result in [&watch_a, &watch_b] {
        assert!(
            matches!(
                result["authority"]["status"].as_str(),
                Some("complete" | "qualified")
            ),
            "retained session published no admitted Calls authority: {result}"
        );
        assert_eq!(
            result["authority"]["provider_id"], "h00-gopls-scip",
            "Calls authority must name the embedded provider"
        );
        assert!(
            result["authority"]["input_fingerprints"]
                .as_array()
                .is_some_and(|fingerprints| !fingerprints.is_empty()),
            "retained session published vacuous authority: {result}"
        );
    }

    let status = watch.terminate();
    assert!(
        status.success(),
        "persistent Go WATCH shutdown failed: {status}"
    );
}

/// RIGHT-REASON REGRESSION: changing a Go import changes gopls's observed
/// workspace witness. The first WATCH reconciliation must replace the pinned
/// provider session and publish the new truth atomically; it must not mutate a
/// retained session, fail full certification, and park until a later timer.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, Go, and native signal delivery"]
fn installed_go_watch_import_change_succeeds_in_first_reconciliation() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed WATCH acceptance"),
    );
    let temporary = TempDir::new().expect("Go import-change WATCH workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("watch-data");
    std::fs::create_dir_all(&root).expect("Go module directory");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/importwatch\n\ngo 1.27\n",
    )
    .expect("Go module");
    let source = root.join("main.go");
    std::fs::write(
        &source,
        "package main\nfunc target() int { return 1 }\nfunc caller() int { return target() }\n",
    )
    .expect("initial Go source");
    let search_path = go_only_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");
    let stdout = temporary.path().join("go-import-watch.stdout");
    let stderr = temporary.path().join("go-import-watch.stderr");
    let child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "watch",
            "--scip",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("Go import WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("Go import WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn installed Go import WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_fresh_terminal(&mut watch, None);
    assert_eq!(
        calls_items(&calls_json(&binary, &root, &data_dir, "target")).len(),
        1,
        "positive initial call control"
    );
    let prior_dirty_terminals = fs::read_to_string(&watch.stdout)
        .expect("initial Go import WATCH lifecycle")
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| {
            event["event"] == "reconciliation_terminal"
                && event["dirty_hint_count"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
        })
        .count();

    std::fs::write(
        &source,
        concat!(
            "package main\n",
            "import \"strings\"\n",
            "func target() int { return 1 }\n",
            "func caller() int { _ = strings.TrimSpace(\" value \" ); return target() }\n",
        ),
    )
    .expect("add Go import");
    let terminal = wait_for_dirty_terminal_after(&mut watch, prior_dirty_terminals);
    assert_eq!(
        terminal["state"],
        "succeeded",
        "the first import-changing WATCH reconciliation must publish without a parked failed epoch: {terminal:?}\n{}",
        watch.diagnostics()
    );
    assert_ne!(terminal["generation"], initial);
    assert!(terminal["error"].is_null());
    let refresh = terminal["semantic_provider_refreshes"]
        .as_array()
        .and_then(|refreshes| refreshes.iter().find(|refresh| refresh["language"] == "go"))
        .expect("Go import change provider refresh receipt");
    assert_eq!(refresh["lane"], "affected_roots");
    assert_eq!(
        refresh["operation"], "certify_full",
        "Go import change must receipt the exact replacement-session certification operation"
    );
    assert_eq!(
        calls_items(&calls_json(&binary, &root, &data_dir, "target")).len(),
        1,
        "import-changing reconciliation lost the live call"
    );
    assert!(
        watch.terminate().success(),
        "Go import-change WATCH shutdown"
    );
}

/// A healthy provider may intentionally omit a source file whose build
/// constraints exclude it from the selected Go toolchain. The installed
/// product must retain useful positive Calls evidence while qualifying every
/// negative claim and refusing `--require-complete-calls`.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and Go"]
fn installed_go_build_variant_is_explicitly_qualified() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed Go acceptance"),
    );
    let temporary = TempDir::new().expect("build-variant Go workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(&root).expect("Go module directory");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/buildvariant\n\ngo 1.27\n",
    )
    .expect("Go module");
    std::fs::write(
        root.join("main.go"),
        "package buildvariant\nfunc target() int { return 1 }\nfunc caller() int { return target() }\n",
    )
    .expect("active Go source");
    std::fs::write(
        root.join("windows.go"),
        "//go:build windows\npackage buildvariant\nfunc windowsCaller() int { return target() }\n",
    )
    .expect("excluded Go source");
    std::fs::create_dir_all(root.join("contractonly")).expect("custom-tag-only directory");
    std::fs::write(
        root.join("contractonly/only.go"),
        "//go:build contract_only\npackage contractonly\nfunc ContractCaller() int { return 1 }\n",
    )
    .expect("custom-tag-only Go source");
    let search_path = go_only_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");

    let best_effort = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .output()
        .expect("run installed build-variant index");
    assert!(
        best_effort.status.success(),
        "qualified provider evidence must remain usable:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&best_effort.stdout),
        String::from_utf8_lossy(&best_effort.stderr)
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&best_effort.stdout).expect("qualified index JSON");
    assert_eq!(
        receipt["capabilities"]["calls"]["status"],
        "qualified",
        "receipt={receipt}\nstderr={}",
        String::from_utf8_lossy(&best_effort.stderr)
    );
    assert_eq!(
        receipt["capabilities"]["calls"]["languages"][0]["qualifications"][0]["reason_code"],
        "provider_document_omitted"
    );
    let generation = receipt["generation_id"]
        .as_str()
        .expect("qualified generation ID")
        .to_owned();

    let calls = calls_json(&binary, &root, &data_dir, "target");
    assert_eq!(calls["authority"]["status"], "qualified", "{calls}");
    assert_eq!(
        calls_items(&calls).len(),
        1,
        "covered caller remains useful"
    );
    assert_eq!(
        calls_items(&calls)[0]["origin"]["identity"]["name"],
        "caller"
    );
    assert!(
        calls["authority"]["coverage_exclusions"]
            .as_array()
            .is_some_and(|exclusions| exclusions.iter().any(|exclusion| {
                exclusion["reason_code"] == "provider_document_omitted"
                    && exclusion["document_count"] == 2
            })),
        "the suffix- and custom-tag-omitted build variants must qualify every zero-result claim: {calls}"
    );

    let strict = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .output()
        .expect("run strict build-variant index");
    assert!(
        !strict.status.success(),
        "strict complete authority must not accept an omitted provider document"
    );
    assert!(
        String::from_utf8_lossy(&strict.stderr).contains("provider_document_omitted"),
        "strict refusal must explain the exact coverage gap: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
    assert_eq!(
        resolve_generation(&data_dir, &root)
            .expect("qualified generation remains current")
            .manifest
            .generation_id
            .0,
        generation,
        "strict refusal must not replace the last truthful generation"
    );
}

/// RIGHT-REASON PERFORMANCE REGRESSION: one source edit in a multi-module
/// `go.work` execution root cannot invalidate an unchanged sibling module.
/// The shipped WATCH must refresh only the changed document in its retained
/// embedded provider session, then compose that result with the exact retained
/// sibling basis before global normalization.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, Go, and native signal delivery"]
fn installed_go_workspace_watch_does_not_rerun_an_unchanged_module() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed WATCH acceptance"),
    );
    let temporary = TempDir::new().expect("multi-module Go WATCH workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let alpha_root = root.join("alpha");
    let beta_root = root.join("beta");
    std::fs::create_dir_all(&alpha_root).expect("alpha module directory");
    std::fs::create_dir_all(&beta_root).expect("beta module directory");
    std::fs::write(
        alpha_root.join("go.mod"),
        "module example.test/alpha\n\ngo 1.27\n\nrequire example.test/beta v0.0.0\n",
    )
    .expect("alpha module manifest");
    std::fs::write(
        alpha_root.join("module.go"),
        "package alpha\nimport \"example.test/beta\"\nfunc Caller() int { return beta.Target() }\n",
    )
    .expect("alpha module source");
    std::fs::write(
        beta_root.join("go.mod"),
        "module example.test/beta\n\ngo 1.27\n",
    )
    .expect("beta module manifest");
    std::fs::write(
        beta_root.join("module.go"),
        "package beta\nfunc Target() int { return 1 }\n",
    )
    .expect("beta module source");
    std::fs::write(
        root.join("go.work"),
        "go 1.27\n\nuse (\n\t./alpha\n\t./beta\n)\n",
    )
    .expect("multi-module Go workspace");
    let search_path = go_only_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");

    let stdout = temporary.path().join("go-workspace-watch.stdout");
    let stderr = temporary.path().join("go-workspace-watch.stderr");
    let child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn installed Go workspace WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_fresh_terminal(&mut watch, None);
    assert_one_embedded_go_provider(&data_dir);
    let initial_events = fs::read_to_string(&watch.stdout)
        .expect("initial Go workspace WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let initial_terminal = initial_events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == initial)
        .expect("initial Go workspace terminal receipt");
    let initial_refresh = &initial_terminal["semantic_provider_refreshes"][0];
    assert_eq!(initial_refresh["language"], "go");
    assert_eq!(initial_refresh["lane"], "full");
    assert_eq!(initial_refresh["documents"], serde_json::json!([]));
    assert_eq!(initial_refresh["session_open"]["execution_roots"], 1);
    assert_eq!(initial_refresh["session_open"]["max_parallelism"], 1);
    assert!(
        initial_refresh["session_open"]["duration_ms"]
            .as_u64()
            .is_some()
    );
    let cross_root_call_count = || {
        let output = Command::new(&binary)
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args([
                "calls",
                "Target",
                "--file",
                "beta/module.go",
                "--format",
                "json",
            ])
            .output()
            .expect("query cross-root Calls authority");
        assert!(
            output.status.success(),
            "cross-root Calls query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("Calls JSON output");
        assert_eq!(value["authority"]["provider_id"], "h00-gopls-scip");
        assert_eq!(
            value["authority"]["scopes"].as_array().map(Vec::len),
            Some(2),
            "cross-root Calls authority must cover both project units: {value}"
        );
        value["items"]
            .as_array()
            .unwrap_or_else(|| panic!("cross-root Calls items: {value}"))
            .len()
    };
    assert_eq!(
        cross_root_call_count(),
        1,
        "positive cross-root call control"
    );
    let prior_dirty_terminals = initial_events
        .iter()
        .filter(|event| {
            event["event"] == "reconciliation_terminal"
                && event["dirty_hint_count"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
        })
        .count();

    std::fs::write(
        alpha_root.join("module.go"),
        "package alpha\nimport \"example.test/beta\"\nfunc Caller() int { return beta.Target() + 1 }\n",
    )
    .expect("alpha-only source edit");
    let changed_terminal = wait_for_dirty_terminal_after(&mut watch, prior_dirty_terminals);
    assert_eq!(
        changed_terminal["state"],
        "succeeded",
        "the first alpha-only reconciliation must publish or expose its direct failure; a later safety scan is not evidence that the affected-document path worked: {changed_terminal:?}\n{}",
        watch.diagnostics()
    );
    let changed = changed_terminal["generation"]
        .as_str()
        .expect("successful changed terminal generation")
        .to_owned();
    assert_ne!(changed, initial, "changed root must publish new truth");
    let changed_events = fs::read_to_string(&watch.stdout)
        .expect("changed Go workspace WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    assert_eq!(
        changed_terminal["semantic_provider_refreshes"],
        serde_json::json!([{
            "language": "go",
            "lane": "affected_documents",
            "operation": "refresh_affected",
            "documents": ["alpha/module.go"],
            "session_open": null,
        }]),
        "unchanged beta module was recertified despite exact retained authority: {changed_events:?}\n{}",
        watch.diagnostics(),
    );
    assert_eq!(
        cross_root_call_count(),
        1,
        "fresh alpha references must still resolve to the retained beta definition"
    );

    let status = watch.terminate();
    assert!(
        status.success(),
        "Go workspace WATCH shutdown failed: {status}"
    );
}

/// RIGHT-REASON PERFORMANCE REGRESSION: independent Go modules are separate
/// semantic execution roots. Changing one module's project input must
/// reconfigure and recertify that root from its admitted gopls state without a
/// cold session open or disturbing a healthy sibling session. The recomposed
/// Calls result must still agree with a forced full certification; root-local
/// acceleration is never permission to weaken repository-wide publication or
/// capability authority.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, Go, and native signal delivery"]
fn installed_independent_go_project_input_change_reuses_only_affected_root() {
    assert!(
        std::thread::available_parallelism().is_ok_and(|parallelism| parallelism.get() >= 2),
        "installed provider-concurrency acceptance requires at least two logical CPUs"
    );
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed WATCH acceptance"),
    );
    let temporary = TempDir::new().expect("independent Go module WATCH workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let alpha_root = root.join("alpha");
    let beta_root = root.join("beta");
    std::fs::create_dir_all(&alpha_root).expect("alpha module directory");
    std::fs::create_dir_all(&beta_root).expect("beta module directory");
    let alpha_manifest = "module example.test/alpha\n\ngo 1.27\n";
    std::fs::write(alpha_root.join("go.mod"), alpha_manifest).expect("alpha module manifest");
    std::fs::write(
        alpha_root.join("main.go"),
        "package alpha\nfunc AlphaTarget() int { return 1 }\nfunc AlphaCaller() int { return AlphaTarget() }\n",
    )
    .expect("alpha module source");
    std::fs::write(
        beta_root.join("go.mod"),
        "module example.test/beta\n\ngo 1.27\n",
    )
    .expect("beta module manifest");
    std::fs::write(
        beta_root.join("main.go"),
        "package beta\nfunc BetaTarget() int { return 2 }\nfunc BetaCaller() int { return BetaTarget() }\n",
    )
    .expect("beta module source");
    let search_path = go_only_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");

    let query_calls = |symbol: &str, file: &str| {
        let output = Command::new(&binary)
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args([
                "calls", symbol, "--file", file, "--filter", "all", "--limit", "100", "--format",
                "json",
            ])
            .output()
            .expect("query independent-module Calls authority");
        assert!(
            output.status.success(),
            "Calls query for {symbol} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("Calls JSON output")
    };

    let stdout = temporary.path().join("independent-go-watch.stdout");
    let stderr = temporary.path().join("independent-go-watch.stderr");
    let child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            // This test asserts two concurrent roots; the automatic CPU
            // budget deliberately permits only one on smaller machines.
            "--jobs",
            "2",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn independent-module WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_fresh_terminal(&mut watch, None);
    let initial_events = fs::read_to_string(&watch.stdout)
        .expect("initial independent-module WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let initial_terminal = initial_events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == initial)
        .expect("initial independent-module terminal receipt");
    let initial_refresh = &initial_terminal["semantic_provider_refreshes"][0];
    assert_eq!(initial_refresh["language"], "go");
    assert_eq!(initial_refresh["lane"], "full");
    assert_eq!(initial_refresh["session_open"]["execution_roots"], 2);
    assert_eq!(initial_refresh["session_open"]["max_parallelism"], 2);
    let baseline_alpha = query_calls("AlphaTarget", "alpha/main.go");
    let baseline_beta = query_calls("BetaTarget", "beta/main.go");
    assert_eq!(baseline_alpha["authority"]["status"], "complete");
    assert_eq!(baseline_beta["authority"]["status"], "complete");
    assert_eq!(
        calls_items(&baseline_alpha).len(),
        1,
        "alpha positive control"
    );
    assert_eq!(
        calls_items(&baseline_beta).len(),
        1,
        "beta positive control"
    );

    // INSTALLED RIGHT-REASON REGRESSION: one crashed semantic-provider child
    // must be repaired without reopening or changing the independently healthy
    // sibling. Linux exposes the exact child executable and working directory,
    // so the sabotage targets alpha by owned process identity rather than by a
    // guessed process name. Other platforms retain the portable project-input
    // acceptance below; their process-oracle equivalent remains separate.
    #[cfg(target_os = "linux")]
    let pre_project_input_generation = {
        let provider_binary = assert_one_embedded_go_provider(&data_dir);
        let watch_pid = watch.child_mut().id();
        let alpha_provider =
            wait_for_direct_child_at_root(watch_pid, &provider_binary, &alpha_root);
        let beta_provider = wait_for_direct_child_at_root(watch_pid, &provider_binary, &beta_root);
        assert_ne!(
            alpha_provider, beta_provider,
            "positive control: roots own distinct provider children"
        );
        // SAFETY: alpha_provider is the exact direct child identified above by
        // executable bytes and canonical execution-root cwd.
        assert_eq!(
            unsafe { libc::kill(alpha_provider as i32, libc::SIGKILL) },
            0,
            "kill exact alpha provider child"
        );
        std::fs::write(
            alpha_root.join("main.go"),
            "package alpha\nfunc AlphaTarget() int { return 1 }\nfunc AlphaCaller() int { return AlphaTarget() + 1 }\n",
        )
        .expect("alpha source edit after provider crash");
        let recovered = wait_for_fresh_terminal(&mut watch, Some(&initial));
        let recovered_events = fs::read_to_string(&watch.stdout)
            .expect("provider-crash recovery lifecycle")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
            .collect::<Vec<_>>();
        let recovered_terminal = recovered_events
            .iter()
            .find(|event| {
                event["event"] == "reconciliation_terminal" && event["generation"] == recovered
            })
            .expect("provider-crash recovery terminal");
        let recovered_refreshes = recovered_terminal["semantic_provider_refreshes"]
            .as_array()
            .expect("provider-crash semantic refresh population");
        assert_eq!(recovered_refreshes.len(), 1);
        let recovered_refresh = &recovered_refreshes[0];
        assert_eq!(recovered_refresh["language"], "go");
        assert_eq!(recovered_refresh["lane"], "affected_roots");
        assert_eq!(recovered_refresh["documents"], serde_json::json!([]));
        assert_eq!(
            recovered_refresh["session_open"]["execution_roots"],
            1,
            "crashed alpha provider did not produce an exact one-root repair: {recovered_events:?}\n{}",
            watch.diagnostics(),
        );
        assert_eq!(recovered_refresh["session_open"]["max_parallelism"], 1);
        assert!(
            recovered_refresh["session_open"]["duration_ms"]
                .as_u64()
                .is_some(),
            "one-root repair must report a real session-open duration"
        );
        let replacement_alpha =
            wait_for_direct_child_at_root(watch_pid, &provider_binary, &alpha_root);
        let retained_beta = wait_for_direct_child_at_root(watch_pid, &provider_binary, &beta_root);
        assert_ne!(
            replacement_alpha, alpha_provider,
            "alpha child was not replaced"
        );
        assert_eq!(
            retained_beta, beta_provider,
            "healthy beta provider was unnecessarily reopened"
        );
        assert!(process_exists(replacement_alpha));
        assert!(process_exists(retained_beta));
        assert!(!process_exists(alpha_provider));
        assert_eq!(
            semantic_calls_items(&query_calls("AlphaTarget", "alpha/main.go")),
            semantic_calls_items(&baseline_alpha),
            "alpha repair changed its semantic call relation"
        );
        assert_eq!(
            semantic_calls_items(&query_calls("BetaTarget", "beta/main.go")),
            semantic_calls_items(&baseline_beta),
            "alpha repair changed retained beta semantic truth"
        );
        recovered
    };
    #[cfg(not(target_os = "linux"))]
    let pre_project_input_generation = initial.clone();

    std::fs::write(
        alpha_root.join("go.mod"),
        format!("{alpha_manifest}\n// h00ligan root-local project-input probe\n"),
    )
    .expect("alpha-only project-input edit");
    let changed = wait_for_fresh_terminal(&mut watch, Some(&pre_project_input_generation));
    let changed_events = fs::read_to_string(&watch.stdout)
        .expect("changed independent-module WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let changed_terminal = changed_events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == changed)
        .expect("changed independent-module terminal receipt");
    assert_eq!(
        changed_terminal["semantic_provider_refreshes"],
        serde_json::json!([{
            "language": "go",
            "lane": "affected_roots",
            "operation": "certify_full",
            "documents": [],
            "session_open": null,
        }]),
        "alpha project-input drift cold-opened a provider instead of reusing admitted gopls state: {changed_events:?}\n{}",
        watch.diagnostics(),
    );
    let changed_alpha = query_calls("AlphaTarget", "alpha/main.go");
    let changed_beta = query_calls("BetaTarget", "beta/main.go");
    assert_eq!(
        semantic_calls_items(&changed_alpha),
        semantic_calls_items(&baseline_alpha),
        "comment-only alpha project input changed semantic Calls output"
    );
    assert_eq!(
        semantic_calls_items(&changed_beta),
        semantic_calls_items(&baseline_beta),
        "retained beta Calls output changed during alpha recertification"
    );

    // RIGHT-REASON REGRESSION: a superseded root-local candidate is
    // disposable, but the previously admitted sibling session population is
    // not. On Linux, stop the exact test-owned alpha provider so the reverse
    // project-input transition cannot outrun the falsifier. Select a started
    // operation that has no terminal, supersede that exact operation with a
    // newer alpha epoch, and require its exact superseded receipt. Cancellation
    // may preserve the old alpha session or reopen alpha alone; neither outcome
    // may reopen the healthy beta session.
    #[cfg(target_os = "linux")]
    let superseding_generation = {
        let provider_binary = assert_one_embedded_go_provider(&data_dir);
        let watch_pid = watch.child_mut().id();
        let alpha_provider =
            wait_for_direct_child_at_root(watch_pid, &provider_binary, &alpha_root);
        let mut stopped_alpha = StoppedProcess::stop(alpha_provider);
        assert_eq!(
            provider_stdin_pending_bytes(alpha_provider),
            0,
            "positive baseline: no prior provider request may remain unread"
        );
        let started_before_supersession = fs::read_to_string(&watch.stdout)
            .expect("pre-supersession WATCH lifecycle")
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["event"] == "reconciliation_started")
            .count();
        std::fs::write(alpha_root.join("go.mod"), alpha_manifest)
            .expect("begin reverse alpha project-input transition");
        let superseded_operation =
            wait_for_active_change_operation_after(&mut watch, started_before_supersession);
        let blocked_request_bytes = wait_for_blocked_provider_request(alpha_provider);
        assert!(
            blocked_request_bytes > 0,
            "positive control: the stale candidate must be blocked inside the exact provider exchange"
        );
        std::fs::write(
            alpha_root.join("go.mod"),
            format!("{alpha_manifest}\n// h00ligan superseding root-local probe\n"),
        )
        .expect("supersede the in-flight alpha project-input transition");
        wait_for_operation_terminal_state(&mut watch, &superseded_operation, "superseded");
        stopped_alpha.resume();
        wait_for_fresh_terminal(&mut watch, Some(&changed))
    };
    // Other Unix platforms retain installed root-local reconfiguration and
    // full-baseline parity coverage without claiming Linux's exact `/proc`
    // child-process sabotage. A portable process oracle remains separate.
    #[cfg(not(target_os = "linux"))]
    let superseding_generation = {
        std::fs::write(alpha_root.join("go.mod"), alpha_manifest)
            .expect("reverse alpha project-input transition");
        let reversed = wait_for_fresh_terminal(&mut watch, Some(&changed));
        std::fs::write(
            alpha_root.join("go.mod"),
            format!("{alpha_manifest}\n// h00ligan superseding root-local probe\n"),
        )
        .expect("second alpha project-input transition");
        wait_for_fresh_terminal(&mut watch, Some(&reversed))
    };
    let superseding_events = fs::read_to_string(&watch.stdout)
        .expect("superseding independent-module WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let superseding_terminal = superseding_events
        .iter()
        .find(|event| {
            event["event"] == "reconciliation_terminal"
                && event["generation"] == superseding_generation
        })
        .expect("superseding independent-module terminal receipt");
    let superseding_refreshes = superseding_terminal["semantic_provider_refreshes"]
        .as_array()
        .expect("superseding semantic refresh population");
    assert_eq!(superseding_refreshes.len(), 1);
    let superseding_refresh = &superseding_refreshes[0];
    assert_eq!(superseding_refresh["language"], "go");
    assert_eq!(superseding_refresh["lane"], "affected_roots");
    assert_eq!(superseding_refresh["documents"], serde_json::json!([]));
    if !superseding_refresh["session_open"].is_null() {
        assert_eq!(
            superseding_refresh["session_open"]["execution_roots"],
            1,
            "superseding alpha drift reopened the healthy beta session: {superseding_events:?}\n{}",
            watch.diagnostics(),
        );
        assert_eq!(superseding_refresh["session_open"]["max_parallelism"], 1);
    }
    let superseding_alpha = query_calls("AlphaTarget", "alpha/main.go");
    let superseding_beta = query_calls("BetaTarget", "beta/main.go");
    assert_eq!(
        semantic_calls_items(&superseding_alpha),
        semantic_calls_items(&baseline_alpha),
        "superseding alpha project input changed semantic Calls output"
    );
    assert_eq!(
        semantic_calls_items(&superseding_beta),
        semantic_calls_items(&baseline_beta),
        "superseding alpha recertification changed retained beta Calls output"
    );

    let status = watch.terminate();
    assert!(
        status.success(),
        "independent-module WATCH shutdown failed: {status}"
    );
    let full = Command::new(&binary)
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "index",
            "--scip",
            "--force",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .env_clear()
        .env("TMPDIR", temporary.path())
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .output()
        .expect("run forced full independent-module certification");
    assert!(
        full.status.success(),
        "forced full certification failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&full.stdout),
        String::from_utf8_lossy(&full.stderr)
    );
    let full_alpha = query_calls("AlphaTarget", "alpha/main.go");
    let full_beta = query_calls("BetaTarget", "beta/main.go");
    for (partial, rebuilt, label) in [
        (&superseding_alpha, &full_alpha, "alpha"),
        (&superseding_beta, &full_beta, "beta"),
    ] {
        assert_eq!(
            partial["authority"]["status"],
            rebuilt["authority"]["status"]
        );
        assert_eq!(
            partial["authority"]["provider_id"],
            rebuilt["authority"]["provider_id"]
        );
        assert_eq!(
            partial["authority"]["scopes"],
            rebuilt["authority"]["scopes"]
        );
        assert_eq!(
            semantic_calls_items(partial),
            semantic_calls_items(rebuilt),
            "affected-root {label} Calls diverged from forced full certification"
        );
    }
    std::fs::write(alpha_root.join("go.mod"), alpha_manifest).expect("restore alpha project input");
}

/// A nested `go.work` owns every member manifest and its absent lock/vendor
/// companions. Changing those exact inputs must invalidate the one retained
/// gopls session without changing its path population or cold-opening a new
/// process. Create/delete is covered explicitly so a missing `go.sum` cannot
/// disappear from WATCH authority until the file happens to exist.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, Go, and native signal delivery"]
fn installed_nested_go_workspace_inputs_reconfigure_warm() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed WATCH acceptance"),
    );
    let temporary = TempDir::new().expect("nested Go WATCH workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let workspace_root = root.join("sub");
    let alpha_root = workspace_root.join("alpha");
    let beta_root = workspace_root.join("beta");
    std::fs::create_dir_all(&alpha_root).expect("nested alpha module");
    std::fs::create_dir_all(&beta_root).expect("nested beta module");
    let alpha_manifest = "module example.test/alpha\n\ngo 1.27\n";
    std::fs::write(alpha_root.join("go.mod"), alpha_manifest).expect("alpha manifest");
    std::fs::write(
        alpha_root.join("main.go"),
        "package alpha\nfunc AlphaTarget() int { return 1 }\nfunc AlphaCaller() int { return AlphaTarget() }\n",
    )
    .expect("alpha source");
    std::fs::write(
        beta_root.join("go.mod"),
        "module example.test/beta\n\ngo 1.27\n",
    )
    .expect("beta manifest");
    std::fs::write(
        beta_root.join("main.go"),
        "package beta\nfunc BetaTarget() int { return 2 }\nfunc BetaCaller() int { return BetaTarget() }\n",
    )
    .expect("beta source");
    std::fs::write(
        workspace_root.join("go.work"),
        "go 1.27\n\nuse (\n\t./alpha\n\t./beta\n)\n",
    )
    .expect("nested workspace manifest");

    let search_path = go_only_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");
    let stdout = temporary.path().join("nested-workspace-watch.stdout");
    let stderr = temporary.path().join("nested-workspace-watch.stderr");
    let child = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("WATCH stdout"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("WATCH stderr"),
        ))
        .spawn()
        .expect("spawn nested Go workspace WATCH");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let terminal_refresh = |watch: &RunningWatch, generation: &str| {
        fs::read_to_string(&watch.stdout)
            .expect("nested workspace lifecycle")
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| {
                event["event"] == "reconciliation_terminal"
                    && event["generation"] == generation
            })
            .unwrap_or_else(|| panic!("terminal receipt for {generation}"))["semantic_provider_refreshes"]
            [0]
        .clone()
    };
    let initial = wait_for_fresh_terminal(&mut watch, None);
    let initial_refresh = terminal_refresh(&watch, &initial);
    assert_eq!(initial_refresh["language"], "go");
    assert_eq!(initial_refresh["lane"], "full");
    assert_eq!(initial_refresh["session_open"]["execution_roots"], 1);
    let baseline = calls_json_at(
        &binary,
        &root,
        &data_dir,
        "AlphaTarget",
        "sub/alpha/main.go",
    );
    assert_eq!(calls_items(&baseline).len(), 1, "positive Calls control");

    let assert_warm = |watch: &RunningWatch, generation: &str, label: &str| {
        assert_eq!(
            terminal_refresh(watch, generation),
            serde_json::json!({
                "language": "go",
                "lane": "affected_roots",
                "operation": "certify_full",
                "documents": [],
                "session_open": null,
            }),
            "{label} cold-opened the nested workspace provider\n{}",
            watch.diagnostics(),
        );
    };

    let first_member_manifest = format!("{alpha_manifest}\n// member-manifest WATCH probe A\n");
    std::fs::write(alpha_root.join("go.mod"), &first_member_manifest)
        .expect("member manifest edit");
    let member_changed = wait_for_fresh_terminal(&mut watch, Some(&initial));
    assert_warm(&watch, &member_changed, "nested member go.mod edit");

    let manifest_path = alpha_root.join("go.mod");
    let member_mtime = std::fs::metadata(&manifest_path)
        .expect("member manifest metadata")
        .modified()
        .expect("member manifest mtime");
    let second_member_manifest = format!("{alpha_manifest}\n// member-manifest WATCH probe B\n");
    assert_eq!(
        first_member_manifest.len(),
        second_member_manifest.len(),
        "same-length gopls memoization collision control"
    );
    std::fs::write(&manifest_path, second_member_manifest).expect("same-length manifest rewrite");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&manifest_path)
        .expect("open manifest to restore mtime")
        .set_times(std::fs::FileTimes::new().set_modified(member_mtime))
        .expect("restore manifest mtime");
    assert_eq!(
        std::fs::metadata(&manifest_path)
            .expect("rewritten manifest metadata")
            .modified()
            .expect("rewritten manifest mtime"),
        member_mtime,
        "manifest mtime restoration control"
    );
    let mtime_changed = wait_for_fresh_terminal(&mut watch, Some(&member_changed));
    assert_warm(
        &watch,
        &mtime_changed,
        "same-length restored-mtime go.mod rewrite",
    );

    std::fs::write(alpha_root.join("go.sum"), "").expect("create missing companion");
    let lock_created = wait_for_fresh_terminal(&mut watch, Some(&mtime_changed));
    assert_warm(&watch, &lock_created, "missing go.sum creation");

    std::fs::remove_file(alpha_root.join("go.sum")).expect("delete lock companion");
    let lock_deleted = wait_for_fresh_terminal(&mut watch, Some(&lock_created));
    assert_warm(&watch, &lock_deleted, "go.sum deletion");

    let warm = calls_json_at(
        &binary,
        &root,
        &data_dir,
        "AlphaTarget",
        "sub/alpha/main.go",
    );
    assert_eq!(
        semantic_calls_items(&warm),
        semantic_calls_items(&baseline),
        "project-input-only transitions changed semantic Calls output"
    );
    let status = watch.terminate();
    assert!(
        status.success(),
        "nested workspace WATCH shutdown: {status}"
    );

    let full = Command::new(&binary)
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "index",
            "--scip",
            "--force",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .env_clear()
        .env("TMPDIR", temporary.path())
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .output()
        .expect("forced full nested workspace certification");
    assert!(
        full.status.success(),
        "forced full nested certification failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&full.stdout),
        String::from_utf8_lossy(&full.stderr)
    );
    let rebuilt = calls_json_at(
        &binary,
        &root,
        &data_dir,
        "AlphaTarget",
        "sub/alpha/main.go",
    );
    assert_eq!(warm["authority"]["status"], rebuilt["authority"]["status"]);
    assert_eq!(
        warm["authority"]["provider_id"],
        rebuilt["authority"]["provider_id"]
    );
    assert_eq!(
        semantic_calls_items(&warm),
        semantic_calls_items(&rebuilt),
        "warm nested input transitions diverged from forced full certification"
    );
}

/// RIGHT-REASON PROCESS-BOUNDARY REGRESSION: an exact semantic generation was
/// published by an installed one-shot CLI process, so a subsequently started
/// WATCH has no process-local canonical snapshot. It must re-establish live
/// gopls authority before exactly reusing that generation. A subsequent
/// project-input edit can alter package resolution beyond the edited module,
/// so it must recertify the complete affected execution root rather than
/// pretending source-local affected-document authority. Once the exact root
/// session is re-established, that recertification should reuse its admitted
/// gopls process instead of cold-opening the same root again.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY, Go, and native signal delivery"]
fn installed_go_workspace_watch_recovers_exact_basis_after_process_restart() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed WATCH acceptance"),
    );
    let temporary = TempDir::new().expect("restarted multi-module Go WATCH workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    let alpha_root = root.join("alpha");
    let beta_root = root.join("beta");
    std::fs::create_dir_all(&alpha_root).expect("alpha module directory");
    std::fs::create_dir_all(&beta_root).expect("beta module directory");
    std::fs::write(
        alpha_root.join("go.mod"),
        "module example.test/alpha\n\ngo 1.27\n\nrequire example.test/beta v0.0.0\n",
    )
    .expect("alpha module manifest");
    std::fs::write(
        alpha_root.join("module.go"),
        "package alpha\nimport \"example.test/beta\"\nfunc Caller() int { return beta.Target() }\n",
    )
    .expect("alpha module source");
    std::fs::write(
        beta_root.join("go.mod"),
        "module example.test/beta\n\ngo 1.27\n",
    )
    .expect("beta module manifest");
    std::fs::write(
        beta_root.join("module.go"),
        "package beta\nfunc Target() int { return 1 }\n",
    )
    .expect("beta module source");
    std::fs::write(
        root.join("go.work"),
        "go 1.27\n\nuse (\n\t./alpha\n\t./beta\n)\n",
    )
    .expect("multi-module Go workspace");
    let search_path = go_only_search_path(&temporary);
    let go_cache = temporary.path().join("go-cache");
    let go_module_cache = temporary.path().join("go-module-cache");

    let seed = Command::new(&binary)
        .env_clear()
        .env("TMPDIR", temporary.path())
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json", "--profile"])
        .env("PATH", &search_path)
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .output()
        .expect("seed semantic generation in a separate installed process");
    assert!(
        seed.status.success(),
        "seeding semantic generation failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&seed.stdout),
        String::from_utf8_lossy(&seed.stderr)
    );
    let seed_generation = resolve_generation(&data_dir, &root)
        .expect("resolve seeded generation")
        .manifest
        .generation_id
        .to_string();
    let seed_report: serde_json::Value =
        serde_json::from_slice(&seed.stdout).expect("seed index JSON");
    let seed_refresh = &seed_report["semantic_provider_refreshes"][0];
    assert_eq!(seed_refresh["language"], "go");
    assert_eq!(seed_refresh["lane"], "full");
    assert_eq!(seed_refresh["documents"], serde_json::json!([]));
    assert_eq!(seed_refresh["session_open"]["execution_roots"], 1);
    assert_eq!(seed_refresh["session_open"]["max_parallelism"], 1);
    let materialized_provider = assert_one_embedded_go_provider(&data_dir);
    let cross_root_call_count = || {
        let output = Command::new(&binary)
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args([
                "calls",
                "Target",
                "--file",
                "beta/module.go",
                "--format",
                "json",
            ])
            .output()
            .expect("query cross-root Calls authority");
        assert!(
            output.status.success(),
            "cross-root Calls query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("Calls JSON output");
        assert_eq!(value["authority"]["provider_id"], "h00-gopls-scip");
        value["items"]
            .as_array()
            .unwrap_or_else(|| panic!("cross-root Calls items: {value}"))
            .len()
    };
    assert_eq!(
        cross_root_call_count(),
        1,
        "positive seeded cross-root call control"
    );

    let stdout = temporary.path().join("restarted-go-workspace-watch.stdout");
    let stderr = temporary.path().join("restarted-go-workspace-watch.stderr");
    let child = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--debug",
            "--format",
            "json",
            "--profile",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .env_clear()
        .env("PATH", search_path)
        .env("TMPDIR", temporary.path())
        .env("GOCACHE", &go_cache)
        .env("GOMODCACHE", &go_module_cache)
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn restarted installed Go workspace WATCH process");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };
    wait_for_reused_terminal(&mut watch, &seed_generation);
    assert_eq!(
        assert_one_embedded_go_provider(&data_dir),
        materialized_provider,
        "restarted WATCH must recertify with the same embedded provider bytes"
    );
    #[cfg(target_os = "linux")]
    let retained_provider_pid =
        wait_for_direct_child_at_root(watch.child_mut().id(), &materialized_provider, &root);

    std::fs::write(
        alpha_root.join("go.mod"),
        "module example.test/alpha\n\ngo 1.27\n\nrequire example.test/beta v0.0.0\n\n// h00ligan project-input recertification probe\n",
    )
    .expect("alpha-only project-input edit after process restart");
    let changed = wait_for_fresh_terminal(&mut watch, Some(&seed_generation));
    assert_ne!(
        changed, seed_generation,
        "changed root must publish new truth"
    );
    let events = fs::read_to_string(&watch.stdout)
        .expect("restarted Go workspace WATCH lifecycle")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("WATCH event JSON"))
        .collect::<Vec<_>>();
    let changed_terminal = events
        .iter()
        .find(|event| event["event"] == "reconciliation_terminal" && event["generation"] == changed)
        .expect("project-input change terminal receipt");
    let changed_refresh = &changed_terminal["semantic_provider_refreshes"][0];
    assert_eq!(changed_refresh["language"], "go");
    assert_eq!(changed_refresh["lane"], "affected_roots");
    assert_eq!(changed_refresh["documents"], serde_json::json!([]));
    assert!(
        changed_refresh["session_open"].is_null(),
        "an admitted root-local project-input refresh must not cold-open the same root: {events:?}\n{}",
        watch.diagnostics(),
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        wait_for_direct_child_at_root(watch.child_mut().id(), &materialized_provider, &root),
        retained_provider_pid,
        "root-local project-input recertification replaced its healthy gopls process"
    );
    assert_eq!(
        assert_one_embedded_go_provider(&data_dir),
        materialized_provider,
        "root-local recertification must retain one exact embedded provider"
    );

    assert_eq!(
        cross_root_call_count(),
        1,
        "fresh alpha references must resolve to the retained beta definition"
    );

    let status = watch.terminate();
    assert!(
        status.success(),
        "restarted Go workspace WATCH shutdown failed: {status}"
    );
}

/// RIGHT-REASON REGRESSION: a warm rust-analyzer session has already executed
/// its build scripts. Treating a later build-script body edit like an ordinary
/// source overlay leaves generated cfg authority stale while still claiming
/// Complete Calls. The shipped WATCH boundary must reopen the provider and
/// observe the changed call target.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and an installed Rust toolchain"]
fn installed_one_file_watch_reloads_changed_build_script_semantics() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for build-script drift acceptance"),
    );
    let temporary = TempDir::new().expect("build-script drift scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"build-script-drift\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n[workspace]\n",
    )
    .expect("manifest");
    let build_script = root.join("build.rs");
    std::fs::write(
        &build_script,
        "fn main() { println!(\"cargo:rustc-check-cfg=cfg(h00_select_b)\"); }\n",
    )
    .expect("initial build script");
    std::fs::write(root.join("src/lib.rs"), CFG_SELECTED_CALLS_SOURCE)
        .expect("cfg-sensitive source");

    let stdout = temporary.path().join("build-script-drift.stdout");
    let stderr = temporary.path().join("build-script-drift.stderr");
    let child = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn installed semantic WATCH");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_generation(&mut watch, &root, &data_dir, None);
    let call_count = |symbol: &str| {
        let output = Command::new(&binary)
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["calls", symbol, "--format", "json"])
            .output()
            .expect("query Calls authority");
        assert!(
            output.status.success(),
            "Calls query for {symbol} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("Calls JSON output");
        value["items"]
            .as_array()
            .unwrap_or_else(|| panic!("Calls items for {symbol}: {value}"))
            .len()
    };
    assert_eq!(call_count("target_a"), 1, "positive initial cfg control");
    assert_eq!(call_count("target_b"), 0, "negative initial cfg control");

    std::fs::write(
        &build_script,
        "fn main() { println!(\"cargo:rustc-check-cfg=cfg(h00_select_b)\"); println!(\"cargo:rustc-cfg=h00_select_b\"); }\n",
    )
    .expect("change build-script semantics without changing its function surface");
    let changed = wait_for_generation(&mut watch, &root, &data_dir, Some(&initial));
    assert_ne!(changed, initial);
    assert_eq!(
        call_count("target_a"),
        0,
        "stale build-script output must not retain the old active call"
    );
    assert_eq!(
        call_count("target_b"),
        1,
        "reopened provider must observe the newly active cfg branch"
    );

    assert!(watch.terminate().success());
    let status = Command::new(&binary)
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("query implicit build-input freshness");
    assert!(status.status.success());
    let status: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("Status JSON output");
    assert_eq!(
        status["freshness"], "unknown",
        "a build script with Cargo's implicit package-wide rerun population must not manufacture reproducible Fresh authority: {status}"
    );
    assert_eq!(
        status["freshness_reason"], "provider_semantic_inputs_unverifiable",
        "the machine reason must identify the exact missing authority seam: {status}"
    );
    assert!(
        !root.join("Cargo.lock").exists(),
        "build-script recertification must retain lockfile-free cleanliness"
    );
}

fn assert_installed_watch_reloads_changed_build_input_semantics(selector_relative: &str) {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for build-input drift acceptance"),
    );
    let temporary = TempDir::new().expect("build-input drift scratch workspace");
    let (root, selector) = create_build_input_semantics_fixture_at(&temporary, selector_relative);
    let data_dir = temporary.path().join("data");

    let stdout = temporary.path().join("build-input-drift.stdout");
    let stderr = temporary.path().join("build-input-drift.stderr");
    let child = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "watch",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
            "--debounce-ms",
            "25",
            "--publication-probe-ms",
            "10",
            "--reconcile-secs",
            "60",
        ])
        .stdout(Stdio::from(
            std::fs::File::create(&stdout).expect("WATCH stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr).expect("WATCH stderr file"),
        ))
        .spawn()
        .expect("spawn installed semantic WATCH");
    let mut watch = RunningWatch {
        child: Some(child),
        stdout,
        stderr,
    };

    let initial = wait_for_generation(&mut watch, &root, &data_dir, None);
    let call_count = |symbol: &str| {
        let output = Command::new(&binary)
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["calls", symbol, "--format", "json"])
            .output()
            .expect("query Calls authority");
        assert!(
            output.status.success(),
            "Calls query for {symbol} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("Calls JSON output");
        value["items"]
            .as_array()
            .unwrap_or_else(|| panic!("Calls items for {symbol}: {value}"))
            .len()
    };
    assert_eq!(call_count("target_a"), 1, "positive initial input control");
    assert_eq!(call_count("target_b"), 0, "negative initial input control");

    std::fs::write(&selector, "target_b\n").expect("change only the Cargo-declared build input");
    let changed = wait_for_generation(&mut watch, &root, &data_dir, Some(&initial));
    assert_ne!(changed, initial);
    assert_eq!(
        call_count("target_a"),
        0,
        "stale generated output must not retain the old active call"
    );
    assert_eq!(
        call_count("target_b"),
        1,
        "reopened provider must observe the changed build input"
    );

    assert!(watch.terminate().success());
    assert!(
        !root.join("Cargo.lock").exists(),
        "build-input recertification must retain lockfile-free cleanliness"
    );
}

/// RIGHT-REASON REGRESSION: a build script's implementation can remain byte
/// identical while an arbitrary `rerun-if-changed` input alters the generated
/// Rust program. WATCH must admit the asset event, invalidate the warm
/// provider session, rerun Cargo, and publish the newly selected call target.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and an installed Rust toolchain"]
fn installed_one_file_watch_reloads_changed_build_input_semantics() {
    assert_installed_watch_reloads_changed_build_input_semantics("selector.txt");
}

/// RIGHT-REASON FALSIFIER: provider admission can discover an exact semantic
/// input inside a hidden directory that generic source discovery deliberately
/// excludes. Once the initial generation is published, WATCH must register
/// that exact declared population and use its native event as a low-latency
/// reconciliation hint; the 60-second integrity fallback is outside this
/// test's bounded wait and cannot manufacture a pass.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and an installed Rust toolchain"]
fn installed_one_file_watch_reloads_hidden_declared_build_input_semantics() {
    assert_installed_watch_reloads_changed_build_input_semantics(".semantic-input/selector.txt");
}

/// RIGHT-REASON REGRESSION: provider admission must publish the exact
/// repository-local non-source inputs that substantiated Complete Calls.
/// Otherwise a fresh CLI process can call an obsolete generated program
/// "fresh" after WATCH and its live provider session have exited.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and an installed Rust toolchain"]
fn installed_one_file_status_detects_persisted_build_input_drift() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for persisted build-input authority"),
    );
    let temporary = TempDir::new().expect("persisted build-input scratch workspace");
    let (root, selector) = create_build_input_semantics_fixture(&temporary);
    let data_dir = temporary.path().join("data");

    let indexed = Command::new(&binary)
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--require-complete-calls"])
        .output()
        .expect("index provider-backed build-input fixture");
    assert!(
        indexed.status.success(),
        "provider-backed index failed: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let status = || {
        let output = Command::new(&binary)
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["status", "--format", "json"])
            .output()
            .expect("query persisted build-input freshness");
        assert!(
            output.status.success(),
            "status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("Status JSON")
    };
    let just_published_status = status();
    let just_published = resolve_generation(&data_dir, &root)
        .expect("resolve just-published build-input generation");
    let structural_receipts = just_published
        .manifest
        .receipts
        .iter()
        .filter(|receipt| receipt.capability_id == "structural_graph")
        .collect::<Vec<_>>();
    assert_eq!(
        just_published_status["freshness"], "fresh",
        "positive control: the just-published generation must be fresh; status={just_published_status}; structural_receipts={structural_receipts:#?}"
    );

    std::fs::write(&selector, "target_b\n").expect("change only the declared build input");
    assert_eq!(
        status()["freshness"],
        "stale",
        "a fresh process must reject the persisted generation after its declared semantic input changes"
    );
}

/// A provider that cannot prove build-script health must not be replaced by
/// the older one-shot Rust artifact lane. That lane does not carry the same
/// health or workspace-resolution evidence and therefore cannot satisfy a
/// strict Calls request merely because it managed to emit protobuf bytes.
#[test]
#[ignore = "requires H00_TEST_H00LIGAN_BINARY and an installed Rust toolchain"]
fn installed_one_file_refuses_weaker_rust_fallback_after_health_failure() {
    let binary = PathBuf::from(
        std::env::var_os("H00_TEST_H00LIGAN_BINARY")
            .expect("H00_TEST_H00LIGAN_BINARY for installed provider-health acceptance"),
    );
    let temporary = TempDir::new().expect("provider-health scratch workspace");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("data");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"provider-health\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n[workspace]\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"provider-health\"\nversion = \"0.1.0\"\n",
    )
    .expect("lockfile");
    std::fs::write(
        root.join("build.rs"),
        "fn main() { panic!(\"provider health sentinel\"); }\n",
    )
    .expect("failing build script");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
    )
    .expect("source");
    let root_before = fs::read_dir(&root)
        .expect("root entries before indexing")
        .map(|entry| entry.expect("root entry").file_name())
        .collect::<BTreeSet<_>>();

    let output = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            data_dir.to_str().expect("UTF-8 data directory"),
        ])
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--profile",
            "--format",
            "json",
        ])
        .output()
        .expect("run strict installed provider-health boundary");
    assert!(
        !output.status.success(),
        "unhealthy persistent provider must not be rescued by weaker authority: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        transcript.contains("persistent rust-analyzer certification failed")
            || transcript.contains("Rust Calls authority is unavailable")
            || transcript.contains("refusing weaker one-shot authority"),
        "strict refusal must retain the persistent-provider reason: {transcript}"
    );
    assert!(
        !transcript.contains("one-shot fallback") && !transcript.contains("rust-analyzer SCIP (.)"),
        "the shipped product must not execute or advertise weaker Rust fallback: {transcript}"
    );
    assert!(
        resolve_generation(&data_dir, &root).is_err(),
        "strict semantic failure must not publish a falsely Complete generation"
    );

    let degraded_data = temporary.path().join("degraded-data");
    let degraded = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            degraded_data.to_str().expect("UTF-8 degraded data"),
        ])
        .args(["index", "--scip", "--profile", "--format", "json"])
        .output()
        .expect("run non-strict provider-health boundary");
    assert!(
        degraded.status.success(),
        "non-strict indexing must publish honest unavailable authority: stdout={} stderr={}",
        String::from_utf8_lossy(&degraded.stdout),
        String::from_utf8_lossy(&degraded.stderr)
    );
    let degraded_report: serde_json::Value =
        serde_json::from_slice(&degraded.stdout).expect("degraded index JSON");
    let failed_activity = degraded_report["semantic_provider_refreshes"]
        .as_array()
        .and_then(|activities| {
            activities.iter().find(|activity| {
                activity["language"] == "rust" && activity["lane"] == "failed"
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "provider failure disappeared behind timing prose instead of emitting typed activity: {degraded_report}"
            )
        });
    assert!(failed_activity["operation"].is_null());
    assert!(
        failed_activity["attempted_operations"]
            .as_array()
            .is_some_and(|operations| !operations.is_empty()),
        "failed provider activity must name its attempted protocol operations: {failed_activity}"
    );
    let status_output = Command::new(&binary)
        .args(["--root", root.to_str().expect("UTF-8 root")])
        .args([
            "--data-dir",
            degraded_data.to_str().expect("UTF-8 degraded data"),
        ])
        .args(["status", "--format", "json"])
        .output()
        .expect("query unavailable provider lineage");
    assert!(status_output.status.success());
    let status: serde_json::Value =
        serde_json::from_slice(&status_output.stdout).expect("status JSON");
    let rust = &status["capabilities"]["calls"]["languages"][0];
    assert_eq!(rust["language_id"], "rust");
    assert_eq!(rust["status"], "unavailable");
    assert!(
        rust["provider_id"].is_null(),
        "an unavailable capability must not present a provider as active authority"
    );
    assert_eq!(
        rust["gaps"][0]["reason_code"], "provider_health_build_scripts",
        "the installed status boundary must retain the exact failed provider-health component"
    );
    let degraded_generation =
        resolve_generation(&degraded_data, &root).expect("resolve degraded generation receipt");
    let rust_calls_receipt = degraded_generation
        .manifest
        .receipts
        .iter()
        .find(|receipt| {
            receipt.capability_id == "calls"
                && receipt
                    .scope
                    .language_id()
                    .is_some_and(|language| language.0 == "rust")
        })
        .expect("Rust Calls receipt after provider failure");
    assert_eq!(
        rust_calls_receipt.provider_id.0, "h00-rust-analyzer-scip",
        "persistent-provider failure receipt must not be attributed to the legacy one-shot provider"
    );
    let root_after = fs::read_dir(&root)
        .expect("root entries after indexing")
        .map(|entry| entry.expect("root entry").file_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        root_after, root_before,
        "provider failure must stay root-clean"
    );
}
