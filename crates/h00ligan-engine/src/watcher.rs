//! Bounded filesystem hints and long-lived supervised index reconciliation.
//!
//! Native watcher events are latency hints only. Every emitted batch advances
//! the [`IndexSupervisor`](crate::code_intel_supervisor::IndexSupervisor)
//! epoch, whose indexing pipeline performs complete discovery and hashing.
//! Cheap bounded publication-control probes detect an independently advanced
//! head without opening the generation database. Queue overflow and slower
//! byte-exact integrity reconciliations keep dropped events from silently
//! becoming stale publication authority.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use h00ligan_provider_protocol::{
    ProviderFrameLimits, ProviderSemanticInputCoverage, ProviderSemanticPathKind,
    provider_semantic_paths_are_current,
};

use crate::code_intel_payload::NormalizedProviderPayload;
use crate::code_intel_publication::{PublicationControlToken, PublicationControlWitness};
use crate::code_intel_supervisor::{
    IndexOperationTrigger, IndexScheduleSnapshot, IndexSupervisor, IndexSupervisorError,
    IndexSupervisorRequest,
};

const RAW_EVENT_CAPACITY: usize = 1_024;
const BATCH_CAPACITY: usize = 64;
const MAX_BATCH_PATHS: usize = 256;

/// Why a watcher batch requested authoritative reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchHintReason {
    Filesystem,
    GitState,
    QueueOverflow,
}

/// One bounded set of non-authoritative path hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchHintBatch {
    pub paths: Vec<PathBuf>,
    pub reason: WatchHintReason,
    pub overflowed: bool,
}

/// Native watcher configuration. Use [`Self::exclude_root`] for the selected
/// code-intelligence data directory when it resides below the project root.
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    pub root: PathBuf,
    pub debounce: Duration,
    excluded_roots: Vec<PathBuf>,
    exclusion_patterns: Vec<String>,
}

impl WatcherConfig {
    #[must_use]
    pub const fn new(root: PathBuf, debounce_ms: u64) -> Self {
        Self {
            root,
            debounce: Duration::from_millis(debounce_ms),
            excluded_roots: Vec::new(),
            exclusion_patterns: Vec::new(),
        }
    }

    #[must_use]
    pub fn exclude_root(mut self, root: PathBuf) -> Self {
        self.excluded_roots.push(root);
        self
    }

    #[must_use]
    pub fn exclude_patterns(mut self, patterns: Vec<String>) -> Self {
        self.exclusion_patterns = patterns;
        self
    }
}

/// Independent cadences for cheap publication drift detection and expensive
/// byte-exact repository reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchCadence {
    pub publication_probe_interval: Duration,
    pub integrity_reconciliation_interval: Duration,
}

impl WatchCadence {
    #[must_use]
    pub const fn new(
        publication_probe_interval: Duration,
        integrity_reconciliation_interval: Duration,
    ) -> Self {
        Self {
            publication_probe_interval,
            integrity_reconciliation_interval,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("notify error: {0}")]
    Notify(#[from] notify::Error),
    #[error("watcher channel closed")]
    ChannelClosed,
    #[error("index supervisor error: {0}")]
    Supervisor(#[from] IndexSupervisorError),
    #[error("watch service task failed: {0}")]
    Task(String),
    #[error("watch cadence intervals must both be greater than zero")]
    InvalidCadence,
    #[error("declared semantic-input watch population is invalid: {0}")]
    InvalidSemanticInput(String),
    #[error("declared semantic-input watch population update failed: {0}")]
    PopulationUpdate(String),
    #[error("declared semantic-input watch population could not be read: {0}")]
    PopulationIo(String),
    #[error("watch source-population discovery failed: {0}")]
    SourceDiscovery(#[from] crate::source_discovery::SourceDiscoveryError),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeclaredWatchInput {
    path: PathBuf,
    kind: ProviderSemanticPathKind,
}

struct WatchPopulationCommand {
    inputs: BTreeSet<DeclaredWatchInput>,
    completion: oneshot::Sender<Result<(), String>>,
}

struct DebouncerChannels {
    raw_events: mpsc::Receiver<Result<Event, notify::Error>>,
    batches: mpsc::Sender<WatchHintBatch>,
    overflowed: Arc<AtomicBool>,
    population: mpsc::Receiver<WatchPopulationCommand>,
}

#[derive(Clone)]
struct WatchPopulationControl {
    commands: mpsc::Sender<WatchPopulationCommand>,
}

impl WatchPopulationControl {
    async fn replace(&self, inputs: BTreeSet<DeclaredWatchInput>) -> Result<(), WatcherError> {
        let (completion, result) = oneshot::channel();
        self.commands
            .send(WatchPopulationCommand { inputs, completion })
            .await
            .map_err(|_| WatcherError::ChannelClosed)?;
        result
            .await
            .map_err(|_| WatcherError::ChannelClosed)?
            .map_err(WatcherError::PopulationUpdate)
    }
}

/// Armed native event stream plus its current bounded watch population.
pub struct FileWatchStream {
    batches: mpsc::Receiver<WatchHintBatch>,
    population: WatchPopulationControl,
    watched_directories: Arc<AtomicU64>,
}

impl FileWatchStream {
    #[must_use]
    pub fn watched_directory_count(&self) -> u64 {
        self.watched_directories.load(Ordering::Acquire)
    }

    /// Receive the next debounced, non-authoritative change-hint batch.
    pub async fn recv(&mut self) -> Option<WatchHintBatch> {
        self.batches.recv().await
    }
}

/// Native event collector. It never indexes or mutates publication state.
pub struct FileWatcher {
    config: WatcherConfig,
}

impl FileWatcher {
    #[must_use]
    pub const fn new(config: WatcherConfig) -> Self {
        Self { config }
    }

    /// Arm the recursive native watcher and return debounced hint batches.
    /// Registration completes before this function returns.
    pub fn start(&self) -> Result<FileWatchStream, WatcherError> {
        let (raw_tx, raw_rx) = mpsc::channel::<Result<Event, notify::Error>>(RAW_EVENT_CAPACITY);
        let (batch_tx, batch_rx) = mpsc::channel::<WatchHintBatch>(BATCH_CAPACITY);
        let (population_tx, population_rx) = mpsc::channel::<WatchPopulationCommand>(8);
        let overflowed = Arc::new(AtomicBool::new(false));
        let callback_overflow = Arc::clone(&overflowed);
        let mut watcher = RecommendedWatcher::new(
            move |event| match raw_tx.try_send(event) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    callback_overflow.store(true, Ordering::Release);
                }
            },
            notify::Config::default().with_follow_symlinks(false),
        )?;
        let watched_directories = Arc::new(AtomicU64::new(0));
        let mut watched = BTreeSet::new();
        refresh_watch_population(
            &mut watcher,
            &self.config,
            &BTreeSet::new(),
            &mut watched,
            &watched_directories,
        )?;

        let config = self.config.clone();
        let task_watch_count = Arc::clone(&watched_directories);
        tokio::spawn(run_debouncer(
            watcher,
            DebouncerChannels {
                raw_events: raw_rx,
                batches: batch_tx,
                overflowed,
                population: population_rx,
            },
            config,
            watched,
            task_watch_count,
        ));
        Ok(FileWatchStream {
            batches: batch_rx,
            population: WatchPopulationControl {
                commands: population_tx,
            },
            watched_directories,
        })
    }
}

#[cfg(test)]
fn desired_watch_directories(config: &WatcherConfig) -> Result<BTreeSet<PathBuf>, WatcherError> {
    desired_watch_directories_with_inputs(config, &BTreeSet::new())
}

fn desired_watch_directories_with_inputs(
    config: &WatcherConfig,
    declared_inputs: &BTreeSet<DeclaredWatchInput>,
) -> Result<BTreeSet<PathBuf>, WatcherError> {
    let mut pruned_roots = config.excluded_roots.clone();
    if config.root.join("Cargo.toml").is_file() {
        pruned_roots.push(config.root.join("target"));
    }
    let mut desired = crate::source_discovery::discover_source_directories(
        &config.root,
        &config.exclusion_patterns,
        &pruned_roots,
    )?
    .into_iter()
    .collect::<BTreeSet<_>>();
    add_project_control_directories(&mut desired);
    add_git_control_directories(&config.root, &mut desired);
    add_declared_input_directories(config, declared_inputs, &mut desired)?;
    Ok(desired)
}

fn add_declared_input_directories(
    config: &WatcherConfig,
    declared_inputs: &BTreeSet<DeclaredWatchInput>,
    desired: &mut BTreeSet<PathBuf>,
) -> Result<(), WatcherError> {
    for input in declared_inputs {
        if !input.path.is_absolute() || !input.path.starts_with(&config.root) {
            return Err(WatcherError::InvalidSemanticInput(format!(
                "path escapes repository root: {}",
                input.path.display()
            )));
        }
        if is_generated_or_excluded(config, &input.path) {
            return Err(WatcherError::InvalidSemanticInput(format!(
                "path overlaps a generated or excluded root: {}",
                input.path.display()
            )));
        }

        if input.kind == ProviderSemanticPathKind::Directory && is_plain_directory(&input.path) {
            add_plain_directory_tree(&input.path, desired)?;
            continue;
        }
        if input.kind == ProviderSemanticPathKind::DirectoryListing
            && is_plain_directory(&input.path)
        {
            desired.insert(input.path.clone());
            continue;
        }

        let mut candidate = input.path.parent();
        while let Some(directory) = candidate {
            if !directory.starts_with(&config.root) {
                break;
            }
            if is_plain_directory(directory) {
                desired.insert(directory.to_path_buf());
                break;
            }
            candidate = directory.parent();
        }
    }
    Ok(())
}

fn add_plain_directory_tree(
    root: &Path,
    desired: &mut BTreeSet<PathBuf>,
) -> Result<(), WatcherError> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        if !is_plain_directory(&directory) || !visited.insert(directory.clone()) {
            continue;
        }
        desired.insert(directory.clone());
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            WatcherError::PopulationIo(format!("read {}: {error}", directory.display()))
        })?;
        for entry in entries {
            let path = entry
                .map_err(|error| {
                    WatcherError::PopulationIo(format!(
                        "read entry below {}: {error}",
                        directory.display()
                    ))
                })?
                .path();
            if is_plain_directory(&path) {
                pending.push(path);
            }
        }
    }
    Ok(())
}

fn is_generated_or_excluded(config: &WatcherConfig, path: &Path) -> bool {
    config
        .excluded_roots
        .iter()
        .any(|excluded| path.starts_with(excluded))
        || (config.root.join("Cargo.toml").is_file()
            && path.starts_with(config.root.join("target")))
}

fn add_project_control_directories(desired: &mut BTreeSet<PathBuf>) {
    let source_directories = desired.iter().cloned().collect::<Vec<_>>();
    for directory in source_directories {
        let cargo = directory.join(".cargo");
        if is_plain_directory(&cargo) {
            desired.insert(cargo);
        }
    }
}

fn add_git_control_directories(root: &Path, desired: &mut BTreeSet<PathBuf>) {
    let git = root.join(".git");
    if is_plain_directory(&git) {
        desired.insert(git.clone());
    }
    let refs = git.join("refs");
    if is_plain_directory(&refs) {
        desired.insert(refs.clone());
    }
    let heads = refs.join("heads");
    if !is_plain_directory(&heads) {
        return;
    }
    let mut pending = vec![heads];
    while let Some(directory) = pending.pop() {
        if !desired.insert(directory.clone()) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_plain_directory(&path) {
                pending.push(path);
            }
        }
    }
}

fn is_plain_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
}

fn refresh_watch_population(
    watcher: &mut RecommendedWatcher,
    config: &WatcherConfig,
    declared_inputs: &BTreeSet<DeclaredWatchInput>,
    watched: &mut BTreeSet<PathBuf>,
    watched_directory_count: &AtomicU64,
) -> Result<(), WatcherError> {
    let desired = desired_watch_directories_with_inputs(config, declared_inputs)?;
    // Add before removing so a failed expansion retains the complete previous
    // authority population rather than opening an event-loss window.
    let added = desired.difference(watched).cloned().collect::<Vec<_>>();
    for path in added {
        if let Err(error) = watcher.watch(&path, RecursiveMode::NonRecursive) {
            watched_directory_count.store(watched.len() as u64, Ordering::Release);
            return Err(error.into());
        }
        watched.insert(path);
    }
    let removed = watched.difference(&desired).cloned().collect::<Vec<_>>();
    for path in removed {
        let _ = watcher.unwatch(&path);
        watched.remove(&path);
    }
    watched_directory_count.store(watched.len() as u64, Ordering::Release);
    Ok(())
}

async fn run_debouncer(
    mut watcher: RecommendedWatcher,
    channels: DebouncerChannels,
    config: WatcherConfig,
    mut watched: BTreeSet<PathBuf>,
    watched_directory_count: Arc<AtomicU64>,
) {
    let DebouncerChannels {
        mut raw_events,
        batches,
        overflowed,
        mut population,
    } = channels;
    let mut declared_inputs = BTreeSet::new();
    let mut pending = BTreeSet::new();
    let mut pending_reason = WatchHintReason::Filesystem;
    let mut deadline: Option<tokio::time::Instant> = None;

    loop {
        if overflowed.swap(false, Ordering::AcqRel) {
            pending_reason = WatchHintReason::QueueOverflow;
            deadline = Some(tokio::time::Instant::now() + config.debounce);
        }

        let sleep_deadline = deadline;
        let sleeper = async move {
            match sleep_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(sleeper);

        tokio::select! {
            command = population.recv() => {
                let Some(command) = command else {
                    let _ = flush_batch(&batches, &mut pending, pending_reason, true).await;
                    return;
                };
                let result = refresh_watch_population(
                    &mut watcher,
                    &config,
                    &command.inputs,
                    &mut watched,
                    &watched_directory_count,
                );
                if result.is_ok() {
                    declared_inputs = command.inputs;
                }
                let _ = command.completion.send(result.map_err(|error| error.to_string()));
            }
            raw = raw_events.recv() => {
                let Some(raw) = raw else {
                    let _ = flush_batch(&batches, &mut pending, pending_reason, true).await;
                    return;
                };
                match raw {
                    Ok(event) => {
                        let refresh_population = event_requires_population_refresh(&event, &watched);
                        let previously_watched = event
                            .paths
                            .iter()
                            .map(|path| watch_population_contains(&watched, path))
                            .collect::<Vec<_>>();
                        if refresh_population
                            && refresh_watch_population(
                                &mut watcher,
                                &config,
                                &declared_inputs,
                                &mut watched,
                                &watched_directory_count,
                            )
                            .is_err()
                        {
                            pending_reason = WatchHintReason::QueueOverflow;
                            deadline = Some(tokio::time::Instant::now() + config.debounce);
                        }
                        for (index, path) in event.paths.into_iter().enumerate() {
                            let topology_change = refresh_population
                                && (previously_watched.get(index).copied().unwrap_or(false)
                                    || watch_population_contains(&watched, &path));
                            let classified = classify_path_with_declared_inputs(
                                &config,
                                &declared_inputs,
                                &event.kind,
                                &path,
                            ).or_else(|| {
                                topology_change.then_some(if is_git_state_path(&path) {
                                    WatchHintReason::GitState
                                } else {
                                    WatchHintReason::Filesystem
                                })
                            });
                            if let Some(reason) = classified {
                                pending_reason = combine_reason(pending_reason, reason);
                                if pending.len() < MAX_BATCH_PATHS {
                                    pending.insert(path);
                                } else if !pending.contains(&path) {
                                    pending_reason = WatchHintReason::QueueOverflow;
                                }
                                deadline = Some(tokio::time::Instant::now() + config.debounce);
                            }
                        }
                    }
                    Err(_) => {
                        pending_reason = WatchHintReason::QueueOverflow;
                        deadline = Some(tokio::time::Instant::now() + config.debounce);
                    }
                }
            }
            () = &mut sleeper => {
                let overflow = pending_reason == WatchHintReason::QueueOverflow;
                if flush_batch(&batches, &mut pending, pending_reason, overflow)
                    .await
                    .is_err()
                {
                    return;
                }
                pending_reason = WatchHintReason::Filesystem;
                deadline = None;
            }
        }
    }
}

fn event_requires_population_refresh(event: &Event, watched: &BTreeSet<PathBuf>) -> bool {
    let topology_kind = matches!(
        event.kind,
        EventKind::Create(notify::event::CreateKind::Folder)
            | EventKind::Remove(notify::event::RemoveKind::Folder)
            | EventKind::Modify(notify::event::ModifyKind::Name(_))
            | EventKind::Any
    );
    let policy_may_have_changed = event_kind_may_change_path(&event.kind);
    topology_kind
        || event.paths.iter().any(|path| {
            (policy_may_have_changed
                && path.file_name().and_then(|name| name.to_str()) == Some(".gitignore"))
                || (matches!(
                    event.kind,
                    EventKind::Create(notify::event::CreateKind::Any)
                        | EventKind::Remove(notify::event::RemoveKind::Any)
                ) && (is_plain_directory(path) || watch_population_contains(watched, path)))
        })
}

const fn event_kind_may_change_path(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Create(_)
            | EventKind::Modify(_)
            | EventKind::Remove(_)
            | EventKind::Access(notify::event::AccessKind::Close(
                notify::event::AccessMode::Write
            ))
            | EventKind::Any
    )
}

fn watch_population_contains(watched: &BTreeSet<PathBuf>, path: &Path) -> bool {
    watched.contains(path) || watched.iter().any(|directory| directory.starts_with(path))
}

async fn flush_batch(
    sender: &mpsc::Sender<WatchHintBatch>,
    pending: &mut BTreeSet<PathBuf>,
    reason: WatchHintReason,
    overflowed: bool,
) -> Result<(), mpsc::error::SendError<WatchHintBatch>> {
    if pending.is_empty() && !overflowed {
        return Ok(());
    }
    sender
        .send(WatchHintBatch {
            paths: std::mem::take(pending).into_iter().collect(),
            reason,
            overflowed,
        })
        .await
}

fn combine_reason(current: WatchHintReason, next: WatchHintReason) -> WatchHintReason {
    if current == WatchHintReason::QueueOverflow || next == WatchHintReason::QueueOverflow {
        WatchHintReason::QueueOverflow
    } else if current == WatchHintReason::GitState || next == WatchHintReason::GitState {
        WatchHintReason::GitState
    } else {
        WatchHintReason::Filesystem
    }
}

#[cfg(test)]
fn classify_path(config: &WatcherConfig, kind: &EventKind, path: &Path) -> Option<WatchHintReason> {
    classify_path_with_declared_inputs(config, &BTreeSet::new(), kind, path)
}

fn classify_path_with_declared_inputs(
    config: &WatcherConfig,
    declared_inputs: &BTreeSet<DeclaredWatchInput>,
    kind: &EventKind,
    path: &Path,
) -> Option<WatchHintReason> {
    if !event_kind_may_change_path(kind) {
        return None;
    }
    if is_generated_or_excluded(config, path) {
        return None;
    }
    if is_git_state_path(path) {
        return Some(WatchHintReason::GitState);
    }
    if crate::code_intel_project_inputs::is_project_control_path(path) {
        return Some(WatchHintReason::Filesystem);
    }
    if declared_inputs.iter().any(|input| {
        input.path == path
            || (input.kind == ProviderSemanticPathKind::Directory && path.starts_with(&input.path))
            || (input.kind == ProviderSemanticPathKind::DirectoryListing
                && path.parent() == Some(input.path.as_path())
                && matches!(
                    kind,
                    EventKind::Create(_)
                        | EventKind::Remove(_)
                        | EventKind::Modify(notify::event::ModifyKind::Name(_))
                        | EventKind::Modify(notify::event::ModifyKind::Any)
                        | EventKind::Any
                ))
    }) {
        return Some(WatchHintReason::Filesystem);
    }
    if path
        .strip_prefix(&config.root)
        .ok()
        .is_some_and(|relative| {
            relative.components().any(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .is_some_and(|name| name.starts_with('.'))
            })
        })
    {
        return None;
    }
    // A Cargo build script may make any ordinary workspace file a semantic
    // input through `rerun-if-changed`. The native watcher is only a bounded
    // latency hint—the indexing/provider authority paths still decide whether
    // bytes actually changed—so admit the remaining non-hidden, non-generated
    // path population instead of guessing from language extensions here.
    Some(WatchHintReason::Filesystem)
}

fn declared_watch_inputs(
    repository_root: &Path,
    payloads: &[NormalizedProviderPayload],
) -> Result<BTreeSet<DeclaredWatchInput>, WatcherError> {
    let mut inputs = BTreeSet::new();
    for payload in payloads {
        for input in &payload.payload().semantic_inputs().paths {
            let relative = Path::new(&input.path);
            let is_root_listing =
                input.path == "." && input.kind == ProviderSemanticPathKind::DirectoryListing;
            if (!is_root_listing && relative.is_absolute())
                || relative.components().any(|component| {
                    !matches!(component, std::path::Component::Normal(_))
                        && !(is_root_listing && matches!(component, std::path::Component::CurDir))
                })
            {
                return Err(WatcherError::InvalidSemanticInput(input.path.clone()));
            }
            let path = if is_root_listing {
                repository_root.to_path_buf()
            } else {
                repository_root.join(relative)
            };
            if !path.starts_with(repository_root) {
                return Err(WatcherError::InvalidSemanticInput(input.path.clone()));
            }
            inputs.insert(DeclaredWatchInput {
                path,
                kind: input.kind,
            });
        }
    }
    Ok(inputs)
}

fn complete_semantic_paths_are_current(
    repository_root: &Path,
    payloads: &[NormalizedProviderPayload],
) -> Result<bool, WatcherError> {
    let limits = ProviderFrameLimits::default();
    for payload in payloads {
        let semantic_inputs = payload.payload().semantic_inputs();
        if semantic_inputs.coverage == ProviderSemanticInputCoverage::Complete
            && !provider_semantic_paths_are_current(repository_root, semantic_inputs, &limits)
                .map_err(|error| WatcherError::PopulationUpdate(error.to_string()))?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn is_git_state_path(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    components
        .windows(2)
        .any(|window| window == [".git", "HEAD"])
        || components
            .windows(3)
            .any(|window| window == [".git", "refs", "heads"])
}

#[cfg(test)]
fn is_project_input(path: &Path) -> bool {
    crate::code_intel_project_inputs::is_project_control_path(path)
        || path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                matches!(
                    extension,
                    "rs" | "go" | "py" | "pyi" | "js" | "jsx" | "ts" | "tsx" | "php"
                )
            })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexWatchStatus {
    pub running: bool,
    pub started_at_unix_ms: u64,
    pub watched_directories: u64,
    pub filesystem_batches: u64,
    pub filesystem_paths: u64,
    pub overflow_batches: u64,
    pub publication_probes: u64,
    pub publication_control_reads: u64,
    pub publication_probe_failures: u64,
    pub publication_drifts: u64,
    pub integrity_reconciliations: u64,
    pub desired_epoch: u64,
    pub published_epoch: u64,
    pub active_trigger: Option<IndexOperationTrigger>,
    pub last_error: Option<String>,
}

impl IndexWatchStatus {
    fn new(watched_directories: u64) -> Self {
        Self {
            running: true,
            started_at_unix_ms: unix_ms(),
            watched_directories,
            filesystem_batches: 0,
            filesystem_paths: 0,
            overflow_batches: 0,
            publication_probes: 0,
            publication_control_reads: 0,
            publication_probe_failures: 0,
            publication_drifts: 0,
            integrity_reconciliations: 0,
            desired_epoch: 0,
            published_epoch: 0,
            active_trigger: None,
            last_error: None,
        }
    }
}

/// One long-lived bridge from native hints to the shared supervisor.
pub struct IndexWatchService {
    supervisor: IndexSupervisor,
    status: Arc<Mutex<IndexWatchStatus>>,
    watched_directories: Arc<AtomicU64>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl IndexWatchService {
    pub fn start(
        supervisor: IndexSupervisor,
        config: WatcherConfig,
        request: IndexSupervisorRequest,
        cadence: WatchCadence,
    ) -> Result<Self, WatcherError> {
        if cadence.publication_probe_interval.is_zero()
            || cadence.integrity_reconciliation_interval.is_zero()
        {
            return Err(WatcherError::InvalidCadence);
        }
        let repository_root = config.root.clone();
        let mut publication_updates = supervisor.subscribe_publications();
        let mut batches = FileWatcher::new(config).start()?;
        let population = batches.population.clone();
        let watched_directories = Arc::clone(&batches.watched_directories);
        supervisor.enable_watch(request, true)?;
        let status = Arc::new(Mutex::new(IndexWatchStatus::new(
            batches.watched_directory_count(),
        )));
        let task_status = Arc::clone(&status);
        let task_supervisor = supervisor.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let now = tokio::time::Instant::now();
            let mut publication_probe = tokio::time::interval_at(
                now + cadence.publication_probe_interval,
                cadence.publication_probe_interval,
            );
            let mut integrity_reconciliation = tokio::time::interval_at(
                now + cadence.integrity_reconciliation_interval,
                cadence.integrity_reconciliation_interval,
            );
            let mut publication_tracker = PublicationProbeTracker::default();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    update = publication_updates.changed() => {
                        if update.is_err() {
                            task_status.lock().last_error = Some(
                                "supervisor publication update channel closed".into()
                            );
                            break;
                        }
                        let Some(published) = publication_updates.borrow_and_update().clone() else {
                            continue;
                        };
                        let inputs = match declared_watch_inputs(
                            &repository_root,
                            &published.publication.provider_payloads,
                        ) {
                            Ok(inputs) => inputs,
                            Err(error) => {
                                task_status.lock().last_error = Some(error.to_string());
                                break;
                            }
                        };
                        if let Err(error) = population.replace(inputs.clone()).await {
                            task_status.lock().last_error = Some(error.to_string());
                            break;
                        }

                        // Registration closes the future-event side of the
                        // handoff. Re-observation closes the publication-to-
                        // registration race: a change in that interval is
                        // immediately scheduled even though no native event
                        // could have been received yet.
                        if !complete_semantic_paths_are_current(
                            &repository_root,
                            &published.publication.provider_payloads,
                        )
                        .unwrap_or(false)
                        {
                            match task_supervisor.observe_changes(
                                inputs.into_iter().map(|input| input.path),
                            ) {
                                Ok(observation) => {
                                    let schedule = task_supervisor.schedule_snapshot();
                                    let mut current = task_status.lock();
                                    current.desired_epoch = observation.desired_epoch;
                                    current.published_epoch = schedule.published_epoch;
                                    current.active_trigger = schedule.active_trigger;
                                }
                                Err(error) => {
                                    task_status.lock().last_error = Some(error.to_string());
                                    break;
                                }
                            }
                        }
                    }
                    batch = batches.recv() => {
                        let Some(batch) = batch else {
                            task_status.lock().last_error = Some("native watcher channel closed".into());
                            break;
                        };
                        let path_count = batch.paths.len() as u64;
                        match task_supervisor.observe_changes(batch.paths) {
                            Ok(observation) => {
                                let schedule = task_supervisor.schedule_snapshot();
                                let mut current = task_status.lock();
                                current.filesystem_batches += 1;
                                current.filesystem_paths += path_count;
                                current.overflow_batches += u64::from(batch.overflowed);
                                current.desired_epoch = observation.desired_epoch;
                                current.published_epoch = schedule.published_epoch;
                                current.active_trigger = schedule.active_trigger;
                            }
                            Err(error) => {
                                task_status.lock().last_error = Some(error.to_string());
                                break;
                            }
                        }
                    }
                    _ = publication_probe.tick() => {
                        let schedule = task_supervisor.schedule_snapshot();
                        let witness = task_supervisor.publication_control_witness();
                        let probe = publication_tracker.observe(&schedule, witness, || {
                            PublicationProbeState::capture(&task_supervisor)
                        });
                        let probe_failed = probe.control_unavailable
                            && schedule.published_epoch > 0
                            && schedule.active_operation.is_none()
                            && schedule.desired_epoch == schedule.published_epoch;
                        let mut current = task_status.lock();
                        current.publication_probes += 1;
                        current.publication_control_reads += u64::from(probe.control_read);
                        current.publication_probe_failures += u64::from(probe_failed);
                        drop(current);
                        if probe.drifted {
                            match task_supervisor.request_periodic_reconciliation() {
                                Ok(observation) => {
                                    let schedule = task_supervisor.schedule_snapshot();
                                    let mut current = task_status.lock();
                                    current.publication_drifts += 1;
                                    current.desired_epoch = observation.desired_epoch;
                                    current.published_epoch = schedule.published_epoch;
                                    current.active_trigger = schedule.active_trigger;
                                }
                                Err(error) => {
                                    task_status.lock().last_error = Some(error.to_string());
                                    break;
                                }
                            }
                        }
                    }
                    _ = integrity_reconciliation.tick() => {
                        match task_supervisor.request_periodic_reconciliation() {
                            Ok(observation) => {
                                let schedule = task_supervisor.schedule_snapshot();
                                let mut current = task_status.lock();
                                current.integrity_reconciliations += 1;
                                current.desired_epoch = observation.desired_epoch;
                                current.published_epoch = schedule.published_epoch;
                                current.active_trigger = schedule.active_trigger;
                            }
                            Err(error) => {
                                task_status.lock().last_error = Some(error.to_string());
                                break;
                            }
                        }
                    }
                }
            }
            task_supervisor.disable_watch();
            let schedule = task_supervisor.schedule_snapshot();
            let mut current = task_status.lock();
            current.running = false;
            current.desired_epoch = schedule.desired_epoch;
            current.published_epoch = schedule.published_epoch;
            current.active_trigger = schedule.active_trigger;
        });
        Ok(Self {
            supervisor,
            status,
            watched_directories,
            stop: Some(stop),
            task: Some(task),
        })
    }

    #[must_use]
    pub fn status(&self) -> IndexWatchStatus {
        let schedule = self.supervisor.schedule_snapshot();
        let mut status = self.status.lock().clone();
        status.watched_directories = self.watched_directories.load(Ordering::Acquire);
        status.desired_epoch = schedule.desired_epoch;
        status.published_epoch = schedule.published_epoch;
        status.active_trigger = schedule.active_trigger;
        status
    }

    pub async fn stop(mut self) -> Result<IndexWatchStatus, WatcherError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|error| WatcherError::Task(error.to_string()))?;
        }
        self.supervisor.wait_for_watch_idle().await;
        Ok(self.status())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicationProbeState {
    Current(PublicationControlToken),
    Unavailable,
}

impl PublicationProbeState {
    fn capture(supervisor: &IndexSupervisor) -> Self {
        supervisor
            .publication_control_token()
            .map_or(Self::Unavailable, Self::Current)
    }
}

#[derive(Default)]
struct PublicationProbeTracker {
    observed_published_epoch: u64,
    last_witness: Option<PublicationControlWitness>,
    last_state: Option<PublicationProbeState>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PublicationProbeObservation {
    drifted: bool,
    control_read: bool,
    control_unavailable: bool,
}

impl PublicationProbeTracker {
    /// Read validated control bytes only after the bounded metadata population
    /// changes, then return drift exactly once for a foreign idle transition.
    fn observe(
        &mut self,
        schedule: &IndexScheduleSnapshot,
        witness: PublicationControlWitness,
        capture_control: impl FnOnce() -> PublicationProbeState,
    ) -> PublicationProbeObservation {
        let own_publication_advanced = schedule.published_epoch != self.observed_published_epoch;
        let baseline_missing = self.last_witness.is_none() || self.last_state.is_none();
        if !own_publication_advanced
            && !baseline_missing
            && self.last_witness.as_ref() == Some(&witness)
        {
            return PublicationProbeObservation::default();
        }
        let idle = schedule.active_operation.is_none()
            && schedule.desired_epoch == schedule.published_epoch;
        if !own_publication_advanced && !baseline_missing && !idle {
            return PublicationProbeObservation::default();
        }

        let state = capture_control();
        let drifted = !own_publication_advanced
            && !baseline_missing
            && self.last_state.as_ref() != Some(&state);
        self.observed_published_epoch = schedule.published_epoch;
        self.last_witness = Some(witness);
        self.last_state = Some(state);
        PublicationProbeObservation {
            drifted,
            control_read: true,
            control_unavailable: self.last_state == Some(PublicationProbeState::Unavailable),
        }
    }
}

impl Drop for IndexWatchService {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.supervisor.disable_watch();
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::time::timeout;

    fn probe_token(value: &str) -> PublicationProbeState {
        PublicationProbeState::Current(
            serde_json::from_value(serde_json::Value::String(value.into()))
                .expect("opaque publication token"),
        )
    }

    fn probe_witness(temporary: &TempDir, label: &str) -> PublicationControlWitness {
        let graph = temporary.path().join(label);
        std::fs::create_dir(&graph).expect("witness graph directory");
        crate::code_intel_publication::publication_control_witness(&graph)
    }

    fn idle_schedule(epoch: u64) -> IndexScheduleSnapshot {
        IndexScheduleSnapshot {
            desired_epoch: epoch,
            published_epoch: epoch,
            active_operation: None,
            active_trigger: None,
            manual_queued: false,
            watch_enabled: true,
        }
    }

    fn watch_fixture() -> (
        TempDir,
        PathBuf,
        PathBuf,
        crate::project_binding::ProjectBinding,
        IndexSupervisor,
    ) {
        let temporary = TempDir::new().expect("watch-service scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        let source = root.join("src/lib.rs");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::create_dir_all(&data).expect("data directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"watch-cadence\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        std::fs::write(&source, "pub fn before() -> u8 { 1 }\n").expect("source fixture");
        let binding = crate::project_binding::ProjectBinding::explicit(&root, &data)
            .expect("explicit watch binding");
        let root = binding.root().to_path_buf();
        let source = root.join("src/lib.rs");
        let supervisor = IndexSupervisor::new(binding.clone());
        (temporary, root, source, binding, supervisor)
    }

    async fn wait_for_epoch_after(supervisor: &IndexSupervisor, previous: u64) -> u64 {
        timeout(Duration::from_secs(20), async {
            loop {
                let schedule = supervisor.schedule_snapshot();
                if schedule.published_epoch > previous && schedule.active_operation.is_none() {
                    return schedule.published_epoch;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("WATCH did not publish the next epoch")
    }

    #[test]
    fn publication_probe_sparsifies_control_reads_and_schedules_foreign_drift_once() {
        let temporary = TempDir::new().expect("probe witness scratch");
        let initial_witness = probe_witness(&temporary, "initial");
        let self_witness = probe_witness(&temporary, "self");
        let touched_witness = probe_witness(&temporary, "touched");
        let foreign_witness = probe_witness(&temporary, "foreign");
        let unavailable_witness = probe_witness(&temporary, "unavailable");
        let later_self_witness = probe_witness(&temporary, "later-self");
        let mut tracker = PublicationProbeTracker::default();

        let initial_build = IndexScheduleSnapshot {
            desired_epoch: 1,
            published_epoch: 0,
            active_operation: None,
            active_trigger: Some(IndexOperationTrigger::Watch),
            manual_queued: false,
            watch_enabled: true,
        };
        let initial = tracker.observe(&initial_build, initial_witness, || {
            PublicationProbeState::Unavailable
        });
        assert!(initial.control_read);
        assert!(initial.control_unavailable);
        assert!(!initial.drifted);

        let own_publication = tracker.observe(&idle_schedule(1), self_witness.clone(), || {
            probe_token("self-a")
        });
        assert!(own_publication.control_read);
        assert!(
            !own_publication.drifted,
            "the supervisor's own completed publication must establish the baseline"
        );

        for _ in 0..100 {
            let unchanged = tracker.observe(&idle_schedule(1), self_witness.clone(), || {
                panic!("unchanged metadata must not read validated control bytes")
            });
            assert_eq!(unchanged, PublicationProbeObservation::default());
        }

        let metadata_only =
            tracker.observe(&idle_schedule(1), touched_witness, || probe_token("self-a"));
        assert!(metadata_only.control_read);
        assert!(
            !metadata_only.drifted,
            "metadata-only churn with identical validated controls is not publication drift"
        );

        let foreign = tracker.observe(&idle_schedule(1), foreign_witness.clone(), || {
            probe_token("foreign-b")
        });
        assert!(foreign.control_read);
        assert!(
            foreign.drifted,
            "positive control: foreign idle control drift must schedule authority"
        );
        let replay = tracker.observe(&idle_schedule(1), foreign_witness, || {
            panic!("an unchanged foreign witness must not reread control bytes")
        });
        assert!(
            !replay.drifted && !replay.control_read,
            "an unchanged drift token must not replay reconciliation"
        );

        let unavailable = tracker.observe(&idle_schedule(1), unavailable_witness, || {
            PublicationProbeState::Unavailable
        });
        assert!(
            unavailable.drifted && unavailable.control_read && unavailable.control_unavailable,
            "loss of readable control authority must also schedule one fail-closed reconciliation"
        );

        let later_self = tracker.observe(&idle_schedule(2), later_self_witness, || {
            probe_token("self-c")
        });
        assert!(
            later_self.control_read && !later_self.drifted,
            "a later self-publication advances the owned epoch and must not look foreign"
        );
    }

    #[tokio::test]
    async fn idle_control_probes_do_not_run_full_reconciliation() {
        let (_temporary, root, _source, _binding, supervisor) = watch_fixture();
        // This is the publication-probe causal control. Native source delivery
        // has its own real-watcher test below; mixing the two lets Darwin's
        // coarse registration events masquerade as probe-driven work.
        let watcher = WatcherConfig::new(root.clone(), 10).exclude_root(root);
        let service = IndexWatchService::start(
            supervisor.clone(),
            watcher,
            IndexSupervisorRequest::default(),
            WatchCadence::new(Duration::from_millis(10), Duration::from_secs(30)),
        )
        .expect("start WATCH service");

        wait_for_epoch_after(&supervisor, 0).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        let idle_status = service.status();
        assert!(
            idle_status.publication_probes >= 3,
            "positive control: bounded control probes must actually run: {idle_status:?}"
        );
        assert!(
            idle_status.publication_control_reads > 0
                && idle_status.publication_control_reads < idle_status.publication_probes,
            "unchanged heartbeat probes must avoid repeated validated control reads: {idle_status:?}"
        );
        assert_eq!(idle_status.publication_drifts, 0);
        assert_eq!(idle_status.integrity_reconciliations, 0);
        assert_eq!(
            supervisor.retained_snapshots().len(),
            1,
            "unchanged control probes must not schedule whole-repository operations"
        );

        let stopped = service.stop().await.expect("stop WATCH service");
        assert!(!stopped.running);
    }

    /// FALSIFIER for hidden project-control drift: observing `.cargo` is not
    /// sufficient unless its native event reaches the shared supervisor and
    /// publishes a new authority epoch even when no source file changed.
    #[tokio::test]
    async fn hidden_cargo_configuration_event_reaches_supervisor_reconciliation() {
        let (_temporary, root, _source, _binding, supervisor) = watch_fixture();
        let cargo = root.join(".cargo");
        std::fs::create_dir_all(&cargo).expect("Cargo configuration directory");
        let configuration = cargo.join("config.toml");
        std::fs::write(&configuration, "[build]\ntarget-dir = \"before\"\n")
            .expect("initial Cargo configuration");
        let service = IndexWatchService::start(
            supervisor.clone(),
            WatcherConfig::new(root, 10),
            IndexSupervisorRequest::default(),
            WatchCadence::new(Duration::from_millis(10), Duration::from_secs(30)),
        )
        .expect("start WATCH service");

        let initial_epoch = wait_for_epoch_after(&supervisor, 0).await;
        std::fs::write(&configuration, "[build]\ntarget-dir = \"after\"\n")
            .expect("changed Cargo configuration");
        let changed_epoch = wait_for_epoch_after(&supervisor, initial_epoch).await;
        let status = service.status();
        let latest = supervisor
            .latest_snapshot()
            .expect("Cargo configuration reconciliation");

        assert!(changed_epoch > initial_epoch);
        assert!(
            status.filesystem_batches >= 1 && status.filesystem_paths >= 1,
            "the hidden Cargo control must traverse the native-event lane: {status:?}"
        );
        assert!(
            latest.dirty_hint_count >= 1,
            "the supervisor receipt must retain a bounded event witness"
        );
        assert!(
            latest
                .publication
                .as_ref()
                .is_some_and(|publication| !publication.reused_generation),
            "changed project-control bytes must publish a new generation, not reuse stale authority"
        );

        service.stop().await.expect("stop WATCH service");
    }

    #[tokio::test]
    async fn deep_integrity_reconciliation_recovers_a_deliberately_hidden_source_event() {
        let (_temporary, root, source, _binding, supervisor) = watch_fixture();
        let watcher = WatcherConfig::new(root.clone(), 10).exclude_root(root.join("src"));
        let service = IndexWatchService::start(
            supervisor.clone(),
            watcher,
            IndexSupervisorRequest::default(),
            WatchCadence::new(Duration::from_millis(10), Duration::from_millis(80)),
        )
        .expect("start WATCH service");

        let initial_epoch = wait_for_epoch_after(&supervisor, 0).await;
        std::fs::write(&source, "pub fn silently_changed() -> u8 { 3 }\n")
            .expect("source change hidden from native watcher");
        // The integrity cadence is deliberately much shorter than a real
        // deployment interval. A successful recovery may therefore be
        // followed by an exact-reuse receipt before this task is rescheduled.
        // Bind the assertion to the retained recovery operation rather than
        // sampling whichever harmless successor happens to be latest.
        let recovered = timeout(Duration::from_secs(20), async {
            loop {
                if let Some(recovered) =
                    supervisor
                        .retained_snapshots()
                        .into_iter()
                        .find(|snapshot| {
                            snapshot.covered_epoch > initial_epoch
                                && snapshot.dirty_hint_count == 0
                                && snapshot.publication.as_ref().is_some_and(|publication| {
                                    !publication.reused_generation && publication.files_changed == 1
                                })
                        })
                {
                    return recovered;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("deep integrity reconciliation did not publish the hidden source change");
        assert!(recovered.covered_epoch > initial_epoch);
        let status = service.status();
        assert_eq!(
            status.filesystem_batches, 0,
            "the positive control requires recovery without a native source event"
        );
        assert!(
            status.integrity_reconciliations >= 1,
            "the byte-exact audit must be the recovery authority: {status:?}"
        );
        assert!(
            recovered
                .publication
                .as_ref()
                .is_some_and(|publication| publication.files_changed == 1),
            "the recovery operation must observe the hidden changed file: {recovered:?}"
        );

        service.stop().await.expect("stop WATCH service");
    }

    #[tokio::test]
    async fn publication_probe_reconciles_one_external_head_advance_without_replay() {
        let (_temporary, root, source, binding, supervisor) = watch_fixture();
        // Isolate the publication-control path from platform-specific native
        // event coalescing. Some Darwin backends report a coarse parent event
        // for an excluded descendant; this test is specifically the no-native-
        // event control for foreign immutable-head adoption.
        let watcher = WatcherConfig::new(root.clone(), 10).exclude_root(root.clone());
        let service = IndexWatchService::start(
            supervisor.clone(),
            watcher,
            IndexSupervisorRequest::default(),
            WatchCadence::new(Duration::from_millis(10), Duration::from_secs(30)),
        )
        .expect("start WATCH service");

        let initial_epoch = wait_for_epoch_after(&supervisor, 0).await;
        std::fs::write(&source, "pub fn externally_published() -> u8 { 4 }\n")
            .expect("external source change");
        let external = IndexSupervisor::new(binding);
        let outcome = external
            .start_manual(IndexSupervisorRequest::default())
            .expect("start external publication")
            .wait()
            .await
            .expect("external publication outcome");
        assert!(
            matches!(
                outcome,
                crate::code_intel_supervisor::IndexOperationOutcome::Published(_)
            ),
            "positive control: the second supervisor must advance the immutable head: {outcome:?}"
        );
        external.shutdown_and_wait().await;

        let reconciled_epoch = wait_for_epoch_after(&supervisor, initial_epoch).await;
        assert!(reconciled_epoch > initial_epoch);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let status = service.status();
        assert_eq!(status.filesystem_batches, 0);
        assert_eq!(status.integrity_reconciliations, 0);
        assert_eq!(
            status.publication_drifts, 1,
            "one foreign head transition must trigger exactly one reconciliation: {status:?}"
        );
        assert_eq!(
            supervisor.retained_snapshots().len(),
            2,
            "an unchanged foreign token must not replay additional operations"
        );
        let latest = supervisor
            .latest_snapshot()
            .expect("foreign reconciliation");
        assert!(
            latest
                .publication
                .as_ref()
                .is_some_and(|publication| publication.reused_generation),
            "the WATCH process must adopt the externally published current generation"
        );

        service.stop().await.expect("stop WATCH service");
    }

    #[test]
    fn relevant_inputs_cover_current_and_planned_core_languages() {
        for path in [
            "src/lib.rs",
            "cmd/main.go",
            "pkg/mod.py",
            "web/app.tsx",
            "web/index.js",
            "src/Plugin.php",
            "Cargo.toml",
            "go.work",
            "pyproject.toml",
            "package.json",
            "composer.lock",
            "tsconfig.build.json",
            ".gitignore",
        ] {
            assert!(is_project_input(Path::new(path)), "missed {path}");
        }
        for path in ["README.md", "image.png"] {
            assert!(!is_project_input(Path::new(path)), "false input {path}");
        }
    }

    #[test]
    fn classifier_excludes_outputs_but_keeps_git_head_as_a_rescan_hint() {
        let temporary = TempDir::new().expect("classifier scratch");
        let root = temporary.path().to_path_buf();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n")
            .expect("Cargo-root positive control");
        let config =
            WatcherConfig::new(root.clone(), 50).exclude_root(root.join("custom-code-intel-data"));
        let modify = EventKind::Modify(notify::event::ModifyKind::Any);
        assert_eq!(
            classify_path(&config, &modify, &root.join("src/lib.rs")),
            Some(WatchHintReason::Filesystem)
        );
        assert_eq!(
            classify_path(&config, &modify, &root.join("src/domain/target/model.rs")),
            Some(WatchHintReason::Filesystem),
            "a nested source directory named target is not Cargo's root build output"
        );
        assert_eq!(
            classify_path(&config, &modify, &root.join(".git/HEAD")),
            Some(WatchHintReason::GitState)
        );
        for excluded in [
            root.join("target/generated.rs"),
            root.join(".h00ligan/code-intel/head.json"),
            root.join("custom-code-intel-data/publication-v4/head-0.json"),
        ] {
            assert_eq!(classify_path(&config, &modify, &excluded), None);
        }
    }

    /// FALSIFIER: repository-local Cargo and ignore controls remain indexing
    /// inputs even though their conventional paths begin with a dot. WATCH
    /// must register the exact control directory and classify its changes;
    /// the generic hidden-directory exclusion must not erase authority inputs.
    #[test]
    fn hidden_project_controls_are_registered_and_classified() {
        let temporary = TempDir::new().expect("classifier scratch");
        let root = temporary.path().to_path_buf();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(root.join(".cargo")).expect("Cargo control directory");
        std::fs::write(root.join("src/lib.rs"), "pub fn target() {}\n")
            .expect("source positive control");
        std::fs::write(root.join("Cargo.toml"), "[package]\nname='watch-fixture'\n")
            .expect("manifest positive control");
        std::fs::write(root.join(".cargo/config.toml"), "[build]\n").expect("Cargo config");
        std::fs::write(root.join(".gitignore"), "/target/\n").expect("ignore policy");
        let config = WatcherConfig::new(root.clone(), 50);

        let desired = desired_watch_directories(&config).expect("watch population");
        assert!(desired.contains(&root), "repository root positive control");
        assert!(
            desired.contains(&root.join(".cargo")),
            "the hidden Cargo control directory must receive native events: {desired:?}"
        );

        let modify = EventKind::Modify(notify::event::ModifyKind::Any);
        for input in [root.join(".cargo/config.toml"), root.join(".gitignore")] {
            assert_eq!(
                classify_path(&config, &modify, &input),
                Some(WatchHintReason::Filesystem),
                "project authority input was erased by hidden-path filtering: {}",
                input.display()
            );
        }
        assert_eq!(
            classify_path(&config, &modify, &root.join(".codex/config.toml")),
            None,
            "unrelated hidden configuration remains outside source authority"
        );
    }

    #[test]
    fn declared_hidden_semantic_inputs_expand_and_narrow_the_watch_population() {
        let temporary = TempDir::new().expect("declared-input watcher scratch");
        let root = temporary.path().join("repo");
        let hidden = root.join(".semantic-input");
        let selector = hidden.join("selector.txt");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&hidden).expect("hidden semantic-input directory");
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("Cargo control");
        std::fs::write(root.join("src/lib.rs"), "pub fn control() {}\n")
            .expect("source positive control");
        std::fs::write(&selector, "a\n").expect("declared semantic input");
        let config = WatcherConfig::new(root, 25);
        let declared = BTreeSet::from([DeclaredWatchInput {
            path: selector.clone(),
            kind: ProviderSemanticPathKind::File,
        }]);

        let ordinary = desired_watch_directories(&config).expect("ordinary population");
        assert!(
            !ordinary.contains(&hidden),
            "positive exclusion control: hidden non-controls are not watched generically"
        );
        let expanded = desired_watch_directories_with_inputs(&config, &declared)
            .expect("declared semantic-input population");
        assert!(
            expanded.contains(&hidden),
            "the exact declared input parent must receive native events: {expanded:?}"
        );

        let modify = EventKind::Modify(notify::event::ModifyKind::Data(
            notify::event::DataChange::Content,
        ));
        assert_eq!(
            classify_path_with_declared_inputs(&config, &declared, &modify, &selector),
            Some(WatchHintReason::Filesystem)
        );
        assert_eq!(
            classify_path_with_declared_inputs(
                &config,
                &declared,
                &modify,
                &hidden.join("unrelated.txt"),
            ),
            None,
            "declaring one hidden file must not authorize the entire hidden directory"
        );
    }

    /// A compiler access trace owns immediate directory membership, not every
    /// descendant byte. WATCH must therefore register exactly that directory
    /// and classify create/remove hints without recursively expanding it.
    #[test]
    fn declared_directory_listing_watches_only_immediate_membership() {
        let temporary = TempDir::new().expect("directory-listing watcher scratch");
        let root = temporary.path().join("repo");
        let listing = root.join(".compiler-cache");
        let nested = listing.join("nested");
        std::fs::create_dir_all(&nested).expect("compiler directory tree");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(root.join("src/lib.rs"), "pub fn control() {}\n")
            .expect("source positive control");
        let config = WatcherConfig::new(root, 25);
        let declared = BTreeSet::from([DeclaredWatchInput {
            path: listing.clone(),
            kind: ProviderSemanticPathKind::DirectoryListing,
        }]);

        let desired = desired_watch_directories_with_inputs(&config, &declared)
            .expect("compiler listing watch population");
        assert!(desired.contains(&listing));
        assert!(
            !desired.contains(&nested),
            "a shallow compiler listing must not recursively watch descendants"
        );

        let member = listing.join("new-entry.d.ts");
        assert_eq!(
            classify_path_with_declared_inputs(
                &config,
                &declared,
                &EventKind::Create(notify::event::CreateKind::File),
                &member,
            ),
            Some(WatchHintReason::Filesystem),
            "immediate membership changes must reach authoritative reconciliation"
        );
        assert_eq!(
            classify_path_with_declared_inputs(
                &config,
                &declared,
                &EventKind::Modify(notify::event::ModifyKind::Data(
                    notify::event::DataChange::Content,
                )),
                &member,
            ),
            None,
            "unread descendant bytes are not directory-membership authority"
        );
    }

    /// RIGHT-REASON FALSIFIER: Cargo build scripts may declare arbitrary
    /// files as semantic inputs. Native WATCH already observes the containing
    /// source directory, so dropping a non-language file here prevents the
    /// authoritative reconciliation path from ever seeing that input change.
    #[test]
    fn cargo_build_input_assets_are_reconciliation_hints() {
        let temporary = tempfile::tempdir().expect("temporary repository");
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(&root).expect("repository root");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"build-input-watch\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo manifest");
        let config = WatcherConfig::new(root.clone(), 25);

        assert_eq!(
            classify_path(
                &config,
                &EventKind::Modify(notify::event::ModifyKind::Data(
                    notify::event::DataChange::Content,
                )),
                &root.join("selector.txt"),
            ),
            Some(WatchHintReason::Filesystem),
            "an arbitrary Cargo-declared build input must reach reconciliation"
        );
    }

    #[test]
    fn reading_ignore_policy_cannot_trigger_a_population_refresh_loop() {
        let path = PathBuf::from("/repo/.gitignore");
        let watched = BTreeSet::from([PathBuf::from("/repo")]);
        let read = Event::new(EventKind::Access(notify::event::AccessKind::Open(
            notify::event::AccessMode::Read,
        )))
        .add_path(path.clone());
        assert!(
            !event_requires_population_refresh(&read, &watched),
            "reading ignore policy during discovery must not recursively rescan the watch population"
        );

        let changed = Event::new(EventKind::Modify(notify::event::ModifyKind::Data(
            notify::event::DataChange::Content,
        )))
        .add_path(path);
        assert!(
            event_requires_population_refresh(&changed, &watched),
            "positive control: changing ignore policy must rebuild the native watch population"
        );
    }

    /// Linux notify reports `IN_CLOSE_WRITE` as Access(Close(Write)). That
    /// event proves a writer finished touching the path and must remain a
    /// reconciliation hint even if a preceding Modify event was coalesced or
    /// dropped. Read-only closes remain non-events.
    #[test]
    fn completed_writes_are_change_hints_but_read_closes_are_not() {
        let temporary = TempDir::new().expect("close-write classifier scratch");
        let root = temporary.path().to_path_buf();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n")
            .expect("Cargo-root positive control");
        let config = WatcherConfig::new(root.clone(), 25);
        let close_write = EventKind::Access(notify::event::AccessKind::Close(
            notify::event::AccessMode::Write,
        ));
        let close_read = EventKind::Access(notify::event::AccessKind::Close(
            notify::event::AccessMode::Read,
        ));

        assert_eq!(
            classify_path(&config, &close_write, &root.join("src/lib.rs")),
            Some(WatchHintReason::Filesystem),
            "a completed write must independently reach reconciliation"
        );
        assert_eq!(
            classify_path(&config, &close_read, &root.join("src/lib.rs")),
            None,
            "closing a read-only descriptor must not create a WATCH loop"
        );

        let watched = BTreeSet::from([root.clone()]);
        let ignore_close = Event::new(close_write).add_path(root.join(".gitignore"));
        assert!(
            event_requires_population_refresh(&ignore_close, &watched),
            "a completed ignore-policy write must refresh the watch population"
        );
    }

    #[tokio::test]
    async fn real_watcher_debounces_a_nonempty_source_batch() {
        let temporary = TempDir::new().expect("watch scratch");
        let source = temporary.path().join("src/lib.rs");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::write(&source, "pub fn before() {}\n").expect("initial source");
        let watcher = FileWatcher::new(WatcherConfig::new(temporary.path().to_path_buf(), 50));
        let mut batches = watcher.start().expect("arm watcher");
        std::fs::write(&source, "pub fn after() {}\n").expect("changed source");
        let batch = timeout(Duration::from_secs(5), batches.recv())
            .await
            .expect("watch event timeout")
            .expect("watch channel closed");
        assert!(
            !batch.paths.is_empty(),
            "real event must not false-pass empty"
        );
        assert!(batch.paths.iter().any(|path| path.ends_with("src/lib.rs")));
    }

    #[tokio::test]
    async fn real_watcher_emits_hidden_cargo_configuration_changes() {
        let temporary = TempDir::new().expect("watch scratch");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical watch root");
        let source = root.join("src/lib.rs");
        let cargo_config = root.join(".cargo/config.toml");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::create_dir_all(cargo_config.parent().expect("Cargo config parent"))
            .expect("Cargo control directory");
        std::fs::write(&source, "pub fn target() {}\n").expect("source positive control");
        std::fs::write(root.join("Cargo.toml"), "[package]\nname='watch-fixture'\n")
            .expect("manifest positive control");
        std::fs::write(&cargo_config, "[build]\nrustflags=[]\n").expect("initial Cargo config");

        let watcher = FileWatcher::new(WatcherConfig::new(root, 50));
        let mut batches = watcher.start().expect("arm watcher");
        std::fs::write(&cargo_config, "[build]\nrustflags=['--cfg','changed']\n")
            .expect("changed Cargo config");
        let batch = timeout(Duration::from_secs(5), batches.recv())
            .await
            .expect("Cargo config event timeout")
            .expect("watch channel closed");

        assert_eq!(batch.reason, WatchHintReason::Filesystem);
        assert!(
            batch.paths.contains(&cargo_config),
            "the exact tool configuration path must reach reconciliation: {batch:?}"
        );
    }

    #[tokio::test]
    async fn real_watcher_emits_hidden_toolchain_selector_changes() {
        let temporary = TempDir::new().expect("watch scratch");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical watch root");
        let source = root.join("src/lib.rs");
        let selector = root.join(".tool-versions");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::write(&source, "pub fn target() {}\n").expect("source positive control");
        std::fs::write(root.join("Cargo.toml"), "[package]\nname='watch-fixture'\n")
            .expect("manifest positive control");
        std::fs::write(&selector, "rust 1.97.1\n").expect("initial toolchain selector");

        let watcher = FileWatcher::new(WatcherConfig::new(root, 50));
        let mut batches = watcher.start().expect("arm watcher");
        std::fs::write(&selector, "rust 1.98.0\n").expect("changed toolchain selector");
        let batch = timeout(Duration::from_secs(5), batches.recv())
            .await
            .expect("toolchain selector event timeout")
            .expect("watch channel closed");

        assert_eq!(batch.reason, WatchHintReason::Filesystem);
        assert!(
            batch.paths.contains(&selector),
            "the exact hidden toolchain selector must reach reconciliation: {batch:?}"
        );
    }

    #[tokio::test]
    async fn native_registration_prunes_outputs_and_arms_new_source_directories() {
        let temporary = TempDir::new().expect("filtered watch scratch");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical watch root");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"filtered-watch\"\nversion = \"0.0.0\"\n",
        )
        .expect("manifest");
        std::fs::write(root.join(".gitignore"), "/target/\n").expect("ignore policy");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let mut generated = root.join("target");
        for index in 0..32 {
            generated.push(format!("nested-{index}"));
            std::fs::create_dir_all(&generated).expect("generated directory");
        }

        let watcher = FileWatcher::new(WatcherConfig::new(root.clone(), 25));
        let mut stream = watcher.start().expect("arm filtered watcher");
        assert_eq!(
            stream.watched_directory_count(),
            2,
            "only the project root and admitted src directory should consume native watches"
        );

        let package = root.join("new-package");
        std::fs::create_dir(&package).expect("new source directory");
        let source = package.join("lib.rs");
        std::fs::write(&source, "pub fn newly_visible() {}\n").expect("new source");
        let batch = timeout(Duration::from_secs(5), stream.recv())
            .await
            .expect("new-directory watch timeout")
            .expect("new-directory watch channel");
        assert!(
            batch.paths.contains(&package) || batch.paths.contains(&source),
            "directory topology must trigger reconciliation even if its first file races registration: {batch:?}"
        );
        assert_eq!(
            stream.watched_directory_count(),
            3,
            "the new admitted directory must become a native non-recursive watch"
        );
    }
}
