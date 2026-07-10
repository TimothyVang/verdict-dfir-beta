//! `proc_runner` — bounded, process-group-isolated subprocess execution.
//!
//! The long-running exec verbs (`vol_run`, `plaso_parse`) used to call a bare,
//! blocking `std::process::Command::output()`: no timeout and no process-group
//! isolation. A hung `vol`/`plaso` (a wedged plugin, a stuck NFS read, a parser
//! that never returns) blocked the single-threaded MCP server **forever**, and
//! any child processes those tools spawned were left orphaned. This module is the
//! shared runner those tools now go through:
//!
//!   1. **Own process group.** On Unix the child is launched in its own process
//!      group via [`std::os::unix::process::CommandExt::process_group`] (a safe
//!      std builder — this crate is `#![forbid(unsafe_code)]`), so the child's
//!      whole subtree is isolated from the server's group and can be reasoned
//!      about as one unit.
//!   2. **Configurable timeout.** [`run_with_timeout`] bounds the wall-clock the
//!      child may run; [`timeout_from_env`] reads an env override with a default.
//!   3. **Whole-group force-kill + reap on timeout.** When the deadline passes the
//!      runner force-kills the child's **entire process group** (leader plus the
//!      descendants the tool spawned) and reaps the leader, then returns a typed
//!      [`RunError::Timeout`] so the caller surfaces an honest error instead of
//!      wedging or orphaning children.
//!
//! ### How the whole-group reap stays `unsafe`-free and safe
//!
//! The textbook whole-group kill is `kill(-pgid, SIGKILL)` (a negative PID targets
//! the group). Direct FFI needs `unsafe`, which is forbidden for this crate. The
//! reaper is therefore split by platform, and both paths stay `unsafe`-free:
//!
//! - **Linux** enumerates the group's members from `/proc` and `SIGKILL`s each by
//!   its own positive PID via `kill(1)` — no negative-PID group signal, and it
//!   only kills PIDs whose PGID equals the verified child group, so an unrelated
//!   process can never be hit.
//! - **macOS/Darwin** have no `/proc`, and raw `libproc` FFI needs `unsafe`, so the
//!   runner enumerates the group with `pgrep -g <pgid>` and reuses the same
//!   positive-PID `kill(1)` reap as Linux. This is deliberately *not* `killpg`: on
//!   Darwin `killpg` returns `EPERM` (not `ESRCH`) once the group leader has been
//!   reaped while a member still lives, which would surface as a spurious I/O error
//!   instead of a survivor-detected reap. `pgrep -g` matches only PIDs whose PGID
//!   equals the verified child group, so an unrelated process can never be hit.
//! - **Other BSDs** (no `/proc`, no `pgrep` guarantee) fall back to `killpg(SIGKILL)`
//!   through the `rustix` safe wrapper, looping until the group drains to `ESRCH`.
//!   The child is in its own distinct PGID (via `process_group(0)`), so the group
//!   signal cannot reach an unrelated process; lingering zombies are reaped by
//!   the reparenting init process and cannot mutate output.
//!
//! Before spawning, the runner captures the server's own PGID; `process_group(0)`
//! establishes `child PID == child PGID` atomically in the pre-exec child, so that
//! distinct identity can be captured from `Child::id()` even if the leader exits
//! immediately. The leader is always `SIGKILL`ed directly too (backstop +
//! non-Unix targets).

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// How often [`run_with_timeout`] polls the child for exit. Small enough that a
/// timeout is detected promptly; large enough that the poll loop is not a busy
/// spin. The actual sleep is capped at the remaining budget so we never overshoot.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Maximum time spent waiting for stdout/stderr readers after the process
/// leader exits. A descendant may inherit a pipe and keep it open indefinitely;
/// cleanup must never turn that hostile descriptor into a server hang.
const READER_JOIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Filesystem-output quotas are checked less often than process/stdout state
/// because walking a large parser tree on every 50 ms process poll would itself
/// become expensive. The final tree is always checked once more after exit.
const OUTPUT_QUOTA_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub const STDOUT_LIMIT_ENV: &str = "FINDEVIL_SUBPROCESS_STDOUT_MAX_BYTES";
pub const STDERR_LIMIT_ENV: &str = "FINDEVIL_SUBPROCESS_STDERR_MAX_BYTES";

const DEFAULT_STDOUT_MAX_BYTES: usize = 64 * 1024 * 1024;
const HARD_STDOUT_MAX_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_STDERR_MAX_BYTES: usize = 4 * 1024 * 1024;
const HARD_STDERR_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Per-stream capture ceilings for one child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureLimits {
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

/// Hard ceilings for a subprocess-created file or directory tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputQuota {
    root: PathBuf,
    max_bytes: u64,
    max_entries: usize,
}

impl OutputQuota {
    #[must_use]
    pub const fn new(root: PathBuf, max_bytes: u64, max_entries: usize) -> Self {
        Self {
            root,
            max_bytes,
            max_entries,
        }
    }
}

/// Why a subprocess output tree was rejected.
#[derive(Debug, thiserror::Error)]
pub enum OutputQuotaError {
    #[error(
        "subprocess output tree exceeded its {limit} byte quota (observed at least {observed})"
    )]
    Bytes { limit: u64, observed: u64 },

    #[error(
        "subprocess output tree exceeded its {limit} entry quota (observed at least {observed})"
    )]
    Entries { limit: usize, observed: usize },

    #[error("subprocess output tree contained a symlink, hard link, or non-file entry")]
    UnsafeEntry,

    #[error("could not measure subprocess output tree safely: {0}")]
    Io(std::io::Error),
}

impl CaptureLimits {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            stdout_bytes: byte_limit_from_env(
                STDOUT_LIMIT_ENV,
                DEFAULT_STDOUT_MAX_BYTES,
                HARD_STDOUT_MAX_BYTES,
            ),
            stderr_bytes: byte_limit_from_env(
                STDERR_LIMIT_ENV,
                DEFAULT_STDERR_MAX_BYTES,
                HARD_STDERR_MAX_BYTES,
            ),
        }
    }
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self::from_env()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureStream {
    Stdout,
    Stderr,
}

impl fmt::Display for CaptureStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

/// Captured result of a bounded child run. Field names mirror
/// [`std::process::Output`] so callers that previously used `Command::output()`
/// need no downstream churn.
#[derive(Debug)]
pub struct RunOutput {
    /// The child's exit status.
    pub status: ExitStatus,
    /// Everything the child wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the child wrote to stderr.
    pub stderr: Vec<u8>,
}

/// Process-group identity captured from `child.id()` immediately after a
/// successful `process_group(0)` spawn. It remains valid after the leader exits,
/// so cleanup never depends on `/proc/<leader>` still existing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChildProcessGroup {
    pgid: Option<u32>,
}

impl ChildProcessGroup {
    #[must_use]
    const fn pgid(self) -> Option<u32> {
        self.pgid
    }
}

/// Typed failure modes of [`run_with_timeout`].
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The child could not be spawned. The inner [`std::io::Error`] is preserved
    /// so callers can distinguish [`std::io::ErrorKind::NotFound`] (binary
    /// missing) from other spawn failures.
    #[error("spawn failed: {0}")]
    Spawn(std::io::Error),

    /// An I/O error occurred while waiting on or draining the child.
    #[error("io error while running child: {0}")]
    Io(std::io::Error),

    /// The child exceeded its time budget and was force-killed (and reaped).
    #[error("subprocess exceeded its {} s time budget and was killed", .0.as_secs())]
    Timeout(Duration),

    /// A captured stream exceeded its byte ceiling. The entire child tree was
    /// killed and reaped; partial output is deliberately not returned as if it
    /// represented complete parser coverage.
    #[error("subprocess {stream} exceeded its {limit} byte capture limit and was killed")]
    OutputLimit { stream: CaptureStream, limit: usize },

    /// A parser-created file/tree breached a byte/entry/type quota. The entire
    /// child tree was killed and reaped before this error is returned.
    #[error("{0}")]
    OutputQuota(OutputQuotaError),

    /// The process leader exited but one or more descendants retained a capture
    /// pipe. Reader joins were bounded and the verified child group was killed.
    #[error("subprocess leader exited but inherited {streams:?} pipe(s) remained open")]
    PipeStillOpen { streams: Vec<CaptureStream> },

    /// The leader exited while another member of its verified process group
    /// remained alive. The group was killed before any output was consumed.
    #[error("subprocess leader exited while descendant processes were still running")]
    ChildTreeStillRunning,

    /// An output-draining thread panicked (should be unreachable).
    #[error("output reader thread panicked")]
    ReaderPanicked,
}

/// Resolve a timeout from an environment variable, falling back to `default`.
///
/// The variable must hold a positive integer count of **seconds**; any missing,
/// empty, non-numeric, or zero value falls back to `default`.
#[must_use]
pub fn timeout_from_env(var: &str, default: Duration) -> Duration {
    parse_timeout_secs(std::env::var(var).ok().as_deref(), default)
}

/// Resolve a positive seconds override and clamp it to a non-negotiable hard
/// ceiling.
///
/// Parser lanes use this form so an accidental environment value
/// cannot restore an effectively unbounded subprocess lifetime.
#[must_use]
pub fn timeout_from_env_clamped(var: &str, default: Duration, hard: Duration) -> Duration {
    parse_timeout_secs(std::env::var(var).ok().as_deref(), default).min(hard)
}

pub(crate) fn byte_limit_from_env(var: &str, default: usize, hard: usize) -> usize {
    parse_byte_limit(std::env::var(var).ok().as_deref(), default, hard)
}

fn parse_byte_limit(raw: Option<&str>, default: usize, hard: usize) -> usize {
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|&value| value > 0)
        .map_or(default, |value| value.min(hard))
}

/// Pure parse half of [`timeout_from_env`] (unit-tested without touching env).
fn parse_timeout_secs(raw: Option<&str>, default: Duration) -> Duration {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .map_or(default, Duration::from_secs)
}

/// Run `command` to completion, capturing stdout/stderr, but kill it if it runs
/// longer than `timeout`.
///
/// The child is launched in its own process group (Unix), with stdin set to null
/// and stdout/stderr piped. Both pipes are drained on dedicated threads so a child
/// that emits more than the OS pipe-buffer's worth of output cannot deadlock the
/// wait loop (the same concurrency guarantee `Command::output()` gives, plus the
/// timeout). On timeout the child is `SIGKILL`ed and reaped before returning.
///
/// # Errors
/// * [`RunError::Spawn`] — the child could not be started.
/// * [`RunError::Timeout`] — the child outran `timeout` and was killed.
/// * [`RunError::Io`] — an I/O error while waiting on / draining the child.
/// * [`RunError::ReaderPanicked`] — a drain thread panicked (unreachable).
pub fn run_with_timeout(command: Command, timeout: Duration) -> Result<RunOutput, RunError> {
    run_with_limits(command, timeout, CaptureLimits::from_env())
}

/// Run a child with explicit capture ceilings. Exposed separately so a lane can
/// choose a lower bound than the shared operator ceiling.
///
/// Exact resource
/// regressions do not mutate process-global environment variables.
pub fn run_with_limits(
    command: Command,
    timeout: Duration,
    limits: CaptureLimits,
) -> Result<RunOutput, RunError> {
    run_with_optional_output_quota(command, timeout, limits, None, true)
}

/// Run a command that is explicitly expected to daemonize after closing its
/// capture pipes. This exception is reserved for tracked mount helpers (FUSE);
/// forensic parser lanes must use [`run_with_limits`] and fully quiesce.
pub(crate) fn run_with_limits_allow_background(
    command: Command,
    timeout: Duration,
    limits: CaptureLimits,
) -> Result<RunOutput, RunError> {
    run_with_optional_output_quota(command, timeout, limits, None, false)
}

/// Run a child with the shared capture ceilings and a hard quota on its
/// filesystem output. The output root may be created by the child after spawn.
pub fn run_with_output_quota(
    command: Command,
    timeout: Duration,
    output_quota: &OutputQuota,
) -> Result<RunOutput, RunError> {
    run_with_optional_output_quota(
        command,
        timeout,
        CaptureLimits::from_env(),
        Some(output_quota),
        true,
    )
}

fn run_with_optional_output_quota(
    mut command: Command,
    timeout: Duration,
    limits: CaptureLimits,
    output_quota: Option<&OutputQuota>,
    require_quiescence: bool,
) -> Result<RunOutput, RunError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let (mut child, verified_group) = spawn_isolated(&mut command)?;

    // Drain both pipes concurrently so a large writer cannot block before exit.
    let stdout = child.stdout.take().expect("stdout piped above");
    let stderr = child.stderr.take().expect("stderr piped above");
    let (event_tx, event_rx) = mpsc::channel();
    let mut out_reader = Some(spawn_reader(
        stdout,
        CaptureStream::Stdout,
        limits.stdout_bytes,
        event_tx.clone(),
    ));
    let mut err_reader = Some(spawn_reader(
        stderr,
        CaptureStream::Stderr,
        limits.stderr_bytes,
        event_tx,
    ));

    let status = match wait_with_deadline(&mut child, timeout, &event_rx, output_quota)? {
        WaitOutcome::Exited(status) => {
            if let Err(error) =
                validate_exited_child(verified_group, output_quota, require_quiescence)
            {
                let _ = wait_for_readers(
                    out_reader.as_ref(),
                    err_reader.as_ref(),
                    READER_JOIN_TIMEOUT,
                );
                return Err(error);
            }
            status
        }
        WaitOutcome::Timeout => {
            kill_child_tree_in_group(&mut child, verified_group);
            let _ = child.wait();
            let _ = wait_for_readers(
                out_reader.as_ref(),
                err_reader.as_ref(),
                READER_JOIN_TIMEOUT,
            );
            drop(out_reader);
            drop(err_reader);
            return Err(RunError::Timeout(timeout));
        }
        WaitOutcome::OutputLimit { stream, limit } => {
            kill_child_tree_in_group(&mut child, verified_group);
            let _ = child.wait();
            let _ = wait_for_readers(
                out_reader.as_ref(),
                err_reader.as_ref(),
                READER_JOIN_TIMEOUT,
            );
            drop(out_reader);
            drop(err_reader);
            return Err(RunError::OutputLimit { stream, limit });
        }
        WaitOutcome::OutputQuota(error) => {
            kill_child_tree_in_group(&mut child, verified_group);
            let _ = child.wait();
            let _ = wait_for_readers(
                out_reader.as_ref(),
                err_reader.as_ref(),
                READER_JOIN_TIMEOUT,
            );
            drop(out_reader);
            drop(err_reader);
            return Err(RunError::OutputQuota(error));
        }
    };

    let live_streams = wait_for_readers(
        out_reader.as_ref(),
        err_reader.as_ref(),
        READER_JOIN_TIMEOUT,
    );
    if !live_streams.is_empty() {
        // The leader has already been reaped by try_wait, so use the process
        // group that was verified immediately after spawn rather than trying to
        // re-prove ownership through a vanished /proc/<leader> entry.
        kill_child_tree_in_group(&mut child, verified_group);
        let _ = wait_for_readers(
            out_reader.as_ref(),
            err_reader.as_ref(),
            READER_JOIN_TIMEOUT,
        );
        drop(out_reader);
        drop(err_reader);
        return Err(RunError::PipeStillOpen {
            streams: live_streams,
        });
    }

    let stdout = join_reader(&mut out_reader)?;
    let stderr = join_reader(&mut err_reader)?;
    Ok(RunOutput {
        status,
        stdout,
        stderr,
    })
}

fn validate_exited_child(
    verified_group: ChildProcessGroup,
    output_quota: Option<&OutputQuota>,
    require_quiescence: bool,
) -> Result<(), RunError> {
    if require_quiescence {
        quiesce_process_group(verified_group)?;
    }
    if let Some(quota) = output_quota {
        check_output_quota(quota).map_err(RunError::OutputQuota)?;
    }
    Ok(())
}

/// Reject a nominally successful subprocess if any live member remains in its
/// captured process group. Surviving members are killed before the error is
/// returned, so callers never consume output while a descendant can mutate it.
pub(crate) fn quiesce_process_group(group: ChildProcessGroup) -> Result<(), RunError> {
    if terminate_surviving_group(group)? {
        return Err(RunError::ChildTreeStillRunning);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum ReaderEvent {
    OutputLimit { stream: CaptureStream, limit: usize },
}

#[derive(Debug)]
enum ReaderFailure {
    Io(std::io::Error),
    OutputLimit { stream: CaptureStream, limit: usize },
}

type ReaderResult = Result<Vec<u8>, ReaderFailure>;

fn spawn_reader(
    reader: impl Read + Send + 'static,
    stream: CaptureStream,
    limit: usize,
    event_tx: Sender<ReaderEvent>,
) -> JoinHandle<ReaderResult> {
    thread::spawn(move || read_bounded(reader, stream, limit, &event_tx))
}

fn read_bounded(
    mut reader: impl Read,
    stream: CaptureStream,
    limit: usize,
    event_tx: &Sender<ReaderEvent>,
) -> ReaderResult {
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut chunk = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut chunk).map_err(ReaderFailure::Io)?;
        if read == 0 {
            return Ok(output);
        }
        let remaining = limit.saturating_sub(output.len());
        output.extend_from_slice(&chunk[..read.min(remaining)]);
        if read > remaining {
            let failure = ReaderEvent::OutputLimit { stream, limit };
            let _ = event_tx.send(failure);
            return Err(ReaderFailure::OutputLimit { stream, limit });
        }
    }
}

fn wait_for_readers(
    stdout: Option<&JoinHandle<ReaderResult>>,
    stderr: Option<&JoinHandle<ReaderResult>>,
    timeout: Duration,
) -> Vec<CaptureStream> {
    let deadline = Instant::now() + timeout;
    loop {
        let live = live_reader_streams(stdout, stderr);
        if live.is_empty() || Instant::now() >= deadline {
            return live;
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn live_reader_streams(
    stdout: Option<&JoinHandle<ReaderResult>>,
    stderr: Option<&JoinHandle<ReaderResult>>,
) -> Vec<CaptureStream> {
    let mut live = Vec::new();
    if stdout.is_some_and(|handle| !handle.is_finished()) {
        live.push(CaptureStream::Stdout);
    }
    if stderr.is_some_and(|handle| !handle.is_finished()) {
        live.push(CaptureStream::Stderr);
    }
    live
}

fn join_reader(handle: &mut Option<JoinHandle<ReaderResult>>) -> Result<Vec<u8>, RunError> {
    let result = handle
        .take()
        .expect("reader handle present")
        .join()
        .map_err(|_| RunError::ReaderPanicked)?;
    match result {
        Ok(bytes) => Ok(bytes),
        Err(ReaderFailure::Io(error)) => Err(RunError::Io(error)),
        Err(ReaderFailure::OutputLimit { stream, limit }) => {
            Err(RunError::OutputLimit { stream, limit })
        }
    }
}

/// Poll `child` until it exits or `timeout` elapses. `Ok(Some(status))` on exit,
/// `Ok(None)` on deadline, `Err` on a wait I/O error.
enum WaitOutcome {
    Exited(ExitStatus),
    Timeout,
    OutputLimit { stream: CaptureStream, limit: usize },
    OutputQuota(OutputQuotaError),
}

fn wait_with_deadline(
    child: &mut Child,
    timeout: Duration,
    events: &Receiver<ReaderEvent>,
    output_quota: Option<&OutputQuota>,
) -> Result<WaitOutcome, RunError> {
    let start = Instant::now();
    let mut next_output_check = start;
    loop {
        if let Ok(ReaderEvent::OutputLimit { stream, limit }) = events.try_recv() {
            return Ok(WaitOutcome::OutputLimit { stream, limit });
        }
        if let Some(status) = child.try_wait().map_err(RunError::Io)? {
            if let Ok(ReaderEvent::OutputLimit { stream, limit }) = events.try_recv() {
                return Ok(WaitOutcome::OutputLimit { stream, limit });
            }
            return Ok(WaitOutcome::Exited(status));
        }
        let now = Instant::now();
        if now >= next_output_check {
            if let Some(quota) = output_quota {
                if let Err(error) = check_output_quota(quota) {
                    return Ok(WaitOutcome::OutputQuota(error));
                }
            }
            next_output_check = now + OUTPUT_QUOTA_POLL_INTERVAL;
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Ok(WaitOutcome::Timeout);
        }
        let remaining = timeout - elapsed;
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn check_output_quota(quota: &OutputQuota) -> Result<(), OutputQuotaError> {
    let root_metadata = match std::fs::symlink_metadata(&quota.root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(OutputQuotaError::Io(error)),
    };
    if root_metadata.file_type().is_symlink() {
        return Err(OutputQuotaError::UnsafeEntry);
    }
    if root_metadata.is_file() {
        require_safe_output_file(&root_metadata)?;
        return check_output_totals(quota, root_metadata.len(), 1);
    }
    if !root_metadata.is_dir() {
        return Err(OutputQuotaError::UnsafeEntry);
    }

    let mut bytes = 0_u64;
    let mut entries = 0_usize;
    let mut directories = vec![quota.root.clone()];
    while let Some(directory) = directories.pop() {
        let children = std::fs::read_dir(&directory).map_err(OutputQuotaError::Io)?;
        for child in children {
            let child = child.map_err(OutputQuotaError::Io)?;
            let path = child.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(OutputQuotaError::Io(error)),
            };
            entries = entries.saturating_add(1);
            if entries > quota.max_entries {
                return Err(OutputQuotaError::Entries {
                    limit: quota.max_entries,
                    observed: entries,
                });
            }
            if metadata.file_type().is_symlink() {
                return Err(OutputQuotaError::UnsafeEntry);
            }
            if metadata.is_dir() {
                directories.push(path);
            } else if metadata.is_file() {
                require_safe_output_file(&metadata)?;
                bytes = bytes.saturating_add(metadata.len());
                if bytes > quota.max_bytes {
                    return Err(OutputQuotaError::Bytes {
                        limit: quota.max_bytes,
                        observed: bytes,
                    });
                }
            } else {
                return Err(OutputQuotaError::UnsafeEntry);
            }
        }
    }
    Ok(())
}

const fn check_output_totals(
    quota: &OutputQuota,
    bytes: u64,
    entries: usize,
) -> Result<(), OutputQuotaError> {
    if entries > quota.max_entries {
        return Err(OutputQuotaError::Entries {
            limit: quota.max_entries,
            observed: entries,
        });
    }
    if bytes > quota.max_bytes {
        return Err(OutputQuotaError::Bytes {
            limit: quota.max_bytes,
            observed: bytes,
        });
    }
    Ok(())
}

fn require_safe_output_file(metadata: &std::fs::Metadata) -> Result<(), OutputQuotaError> {
    if !single_link_regular(metadata) {
        return Err(OutputQuotaError::UnsafeEntry);
    }
    Ok(())
}

/// Open a parser-created output without following a final symlink, then prove
/// that the opened handle is the same single-linked regular file inspected by
/// name. Callers use the handle metadata for bounded allocation/read decisions.
pub(crate) fn open_stable_output_file(
    path: &Path,
) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let before = std::fs::symlink_metadata(path)?;
    if !single_link_regular(&before) {
        return Err(invalid_output_file());
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let after = file.metadata()?;
    if !single_link_regular(&after) || !same_file_identity(&before, &after) {
        return Err(invalid_output_file());
    }
    Ok((file, after))
}

fn single_link_regular(metadata: &std::fs::Metadata) -> bool {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn same_file_identity(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev() && before.ino() == after.ino()
    }
    #[cfg(not(unix))]
    {
        before.len() == after.len()
    }
}

fn invalid_output_file() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "subprocess output is not one stable, non-linked regular file",
    )
}

/// Spawn after capturing the server's own process group. On Linux,
/// `process_group(0)` establishes the invariant `child PID == child PGID` before
/// exec, so the returned identity is safe to capture directly from `child.id()`
/// even if the leader exits before `spawn` returns. Other Unix platforms fail
/// closed until they have a portable group-inspection implementation.
pub(crate) fn spawn_isolated(
    command: &mut Command,
) -> Result<(Child, ChildProcessGroup), RunError> {
    #[cfg(unix)]
    let own_pgid = current_process_group()?;

    isolate_process_group(command);
    let mut child = command.spawn().map_err(RunError::Spawn)?;

    #[cfg(unix)]
    {
        let group = match capture_child_group(child.id(), own_pgid) {
            Ok(group) => group,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok((child, group))
    }
    #[cfg(not(unix))]
    {
        Ok((child, ChildProcessGroup { pgid: None }))
    }
}

#[cfg(target_os = "linux")]
fn current_process_group() -> Result<u32, RunError> {
    read_pgid("self").ok_or_else(|| {
        RunError::Io(io_error(
            std::io::ErrorKind::PermissionDenied,
            "cannot establish the server process group from /proc/self/stat",
        ))
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn current_process_group() -> Result<u32, RunError> {
    // BSD/macOS have no `/proc`; `getpgrp()` returns our own PGID directly and
    // cannot fail. The whole-group reap below enumerates via `pgrep -g` on macOS
    // and falls back to `killpg` on other BSDs (see `kill_verified_group`).
    Ok(rustix::process::Pid::as_raw(Some(rustix::process::getpgrp())) as u32)
}

#[cfg(unix)]
fn capture_child_group(child_pid: u32, own_pgid: u32) -> Result<ChildProcessGroup, RunError> {
    if child_pid <= 1 || child_pid == own_pgid {
        return Err(RunError::Io(io_error(
            std::io::ErrorKind::PermissionDenied,
            "isolated child process group is not distinct from the server group",
        )));
    }
    Ok(ChildProcessGroup {
        pgid: Some(child_pid),
    })
}

fn io_error(kind: std::io::ErrorKind, message: &'static str) -> std::io::Error {
    std::io::Error::new(kind, message)
}

/// Force-kill a previously captured child group and its leader. The group token
/// must come from [`spawn_isolated`]; it is never reconstructed from a possibly
/// vanished `/proc/<leader>` entry.
pub(crate) fn kill_child_tree(child: &mut Child, group: ChildProcessGroup) {
    // Both Linux (via `/proc`) and BSD/macOS (via `killpg`) reap the whole
    // captured group; only non-Unix targets fall back to leader-only kill.
    #[cfg(unix)]
    if let Some(pgid) = group.pgid() {
        let _ = kill_verified_group(pgid);
    }
    #[cfg(not(unix))]
    let _ = group;

    let _ = child.kill();
}

fn kill_child_tree_in_group(child: &mut Child, group: ChildProcessGroup) {
    kill_child_tree(child, group);
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn kill_verified_group(pgid: u32) -> Result<(), RunError> {
    // Repeat bounded positive-PID passes so a descendant that forks during the
    // first enumeration cannot escape. Zombie members are excluded because
    // they cannot mutate output and cannot be killed again.
    for _ in 0..4 {
        let members = group_member_pids(pgid).map_err(RunError::Io)?;
        if members.is_empty() {
            return Ok(());
        }
        let mut cmd = Command::new("kill");
        cmd.arg("-KILL");
        for pid in &members {
            cmd.arg(pid.to_string());
        }
        let _ = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(RunError::Io)?;
        thread::sleep(Duration::from_millis(10));
    }
    if group_member_pids(pgid).map_err(RunError::Io)?.is_empty() {
        Ok(())
    } else {
        Err(RunError::Io(io_error(
            std::io::ErrorKind::TimedOut,
            "subprocess group did not quiesce after forced cleanup",
        )))
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn terminate_surviving_group(group: ChildProcessGroup) -> Result<bool, RunError> {
    if let Some(pgid) = group.pgid() {
        let survivors = !group_member_pids(pgid).map_err(RunError::Io)?.is_empty();
        if survivors {
            kill_verified_group(pgid)?;
        }
        return Ok(survivors);
    }
    Ok(false)
}

/// BSD/macOS counterpart of the Linux [`terminate_surviving_group`]. Without
/// `/proc` we cannot enumerate members, so we probe-and-kill with `killpg`: if
/// the group still has a live member, `killpg(SIGKILL)` delivers and returns
/// `Ok` (survivors existed); an empty group returns `ESRCH`. The leader is
/// already reaped by `try_wait` before this runs, so in the clean-exit path the
/// group is empty and this reports no survivors.
#[cfg(all(unix, not(target_os = "linux"), not(target_vendor = "apple")))]
fn terminate_surviving_group(group: ChildProcessGroup) -> Result<bool, RunError> {
    let Some(pgid) = group.pgid() else {
        return Ok(false);
    };
    let pid = bsd_group_pid(pgid)?;
    match rustix::process::kill_process_group(pid, rustix::process::Signal::Kill) {
        Ok(()) => {
            // A member was alive and has now been SIGKILLed; drain the rest.
            kill_verified_group(pgid)?;
            Ok(true)
        }
        Err(e) if e == rustix::io::Errno::SRCH => Ok(false),
        Err(other) => Err(RunError::Io(other.into())),
    }
}

#[cfg(not(unix))]
fn terminate_surviving_group(group: ChildProcessGroup) -> Result<bool, RunError> {
    let _ = group;
    Ok(false)
}

/// Convert a captured PGID into a rustix [`Pid`](rustix::process::Pid).
#[cfg(all(unix, not(target_os = "linux"), not(target_vendor = "apple")))]
fn bsd_group_pid(pgid: u32) -> Result<rustix::process::Pid, RunError> {
    rustix::process::Pid::from_raw(pgid as i32).ok_or_else(|| {
        RunError::Io(io_error(
            std::io::ErrorKind::InvalidInput,
            "isolated child process group id is not a valid PID",
        ))
    })
}

/// BSD/macOS whole-group force-kill. `killpg(SIGKILL)` signals the child's
/// distinct process group atomically (no enumeration race), and we loop until
/// the group drains to `ESRCH`. Any remaining zombies are reaped by the
/// reparenting init process and cannot mutate output, mirroring the Linux
/// path's exclusion of zombie members, so the bounded loop returns `Ok` rather
/// than a spurious timeout if a zombie lingers past the final pass.
#[cfg(all(unix, not(target_os = "linux"), not(target_vendor = "apple")))]
fn kill_verified_group(pgid: u32) -> Result<(), RunError> {
    let pid = bsd_group_pid(pgid)?;
    for _ in 0..64 {
        match rustix::process::kill_process_group(pid, rustix::process::Signal::Kill) {
            Ok(()) => thread::sleep(Duration::from_millis(10)),
            Err(e) if e == rustix::io::Errno::SRCH => return Ok(()),
            Err(other) => return Err(RunError::Io(other.into())),
        }
    }
    Ok(())
}

/// Launch configuration shared by bounded subprocess runners that need to kill
/// and reap a parser's complete child tree on a hard resource-limit breach.
pub(crate) fn isolate_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        command.process_group(0);
    }
}

/// Every PID currently in process group `pgid`, read from `/proc`. Used to reap a
/// timed-out child's whole tree by individual positive-PID `SIGKILL` (avoiding a
/// negative-PID group signal). Only numeric `/proc/<pid>` entries are considered;
/// any unreadable/exited entry is skipped. The caller supplies the distinct PGID
/// captured from the `process_group(0)` spawn invariant, so every returned PID
/// belongs to the isolated child group.
#[cfg(target_os = "linux")]
fn group_member_pids(pgid: u32) -> std::io::Result<Vec<u32>> {
    let mut members = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(member_pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if read_process_state_and_pgid(&member_pid.to_string())
            .is_some_and(|(state, process_group)| state != 'Z' && process_group == pgid)
        {
            members.push(member_pid);
        }
    }
    Ok(members)
}

/// Every PID currently in process group `pgid`, read via `pgrep -g <pgid>` — the
/// macOS analog of the Linux `/proc` scan. This crate is `#![forbid(unsafe_code)]`,
/// so the enumeration must avoid raw `libproc` FFI; `pgrep`'s `-g` selector matches
/// exactly the processes whose process group ID is `pgid`, confining the result to
/// the isolated child group just as the Linux path is (the PGID comes from the
/// `process_group(0)` spawn invariant, so an unrelated process can never appear).
/// `pgrep` excludes itself, and exit status 1 (no matches) maps to an empty group —
/// the common clean-exit case where the leader is already reaped.
#[cfg(target_vendor = "apple")]
fn group_member_pids(pgid: u32) -> std::io::Result<Vec<u32>> {
    let output = Command::new("pgrep")
        .arg("-g")
        .arg(pgid.to_string())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    // pgrep exits 1 with no stdout when the group has no members; any other
    // non-empty stdout is a whitespace-separated list of PIDs.
    let members = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|token| token.parse::<u32>().ok())
        // PID 1 (launchd) is never our descendant; 0 never appears here.
        .filter(|&pid| pid > 1)
        .collect();
    Ok(members)
}

/// Read the process-group ID (PGID) from `/proc/<who>/stat` (`who` is a PID string
/// or `"self"`). `None` if `/proc` is unavailable or unparsable. The `comm` field
/// is parenthesized and may contain spaces/parens, so the numeric fields are read
/// from after the LAST `)`, where the layout is `state ppid pgrp ...` — making
/// PGID the third whitespace token.
#[cfg(target_os = "linux")]
fn read_pgid(who: &str) -> Option<u32> {
    read_process_state_and_pgid(who).map(|(_, pgid)| pgid)
}

#[cfg(target_os = "linux")]
fn read_process_state_and_pgid(who: &str) -> Option<(char, u32)> {
    let stat = std::fs::read_to_string(format!("/proc/{who}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let mut fields = after_comm.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let _parent_pid = fields.next()?;
    let pgid = fields.next()?.parse::<u32>().ok()?;
    Some((state, pgid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timeout_secs_falls_back_on_bad_or_missing_values() {
        let default = Duration::from_secs(99);
        assert_eq!(parse_timeout_secs(None, default), default);
        assert_eq!(parse_timeout_secs(Some(""), default), default);
        assert_eq!(parse_timeout_secs(Some("   "), default), default);
        assert_eq!(parse_timeout_secs(Some("abc"), default), default);
        // Zero is rejected: a zero-second budget would kill every child instantly.
        assert_eq!(parse_timeout_secs(Some("0"), default), default);
        assert_eq!(parse_timeout_secs(Some("-5"), default), default);
    }

    #[test]
    fn parse_timeout_secs_accepts_positive_integers() {
        let default = Duration::from_secs(99);
        assert_eq!(
            parse_timeout_secs(Some("120"), default),
            Duration::from_secs(120)
        );
        // Surrounding whitespace is tolerated.
        assert_eq!(
            parse_timeout_secs(Some("  90 "), default),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse_timeout_secs(Some("9999"), default).min(Duration::from_secs(300)),
            Duration::from_secs(300),
            "operator timeout overrides must remain hard-clamped"
        );
    }

    #[test]
    fn timeout_from_env_uses_default_for_unset_var() {
        // A var name that is essentially guaranteed unset in the test environment.
        let default = Duration::from_secs(123);
        assert_eq!(
            timeout_from_env("FINDEVIL_PROC_RUNNER_TEST_UNSET_XYZZY", default),
            default
        );
    }

    #[test]
    fn byte_ceiling_parser_clamps_operator_override_to_hard_max() {
        assert_eq!(parse_byte_limit(Some("2048"), 256, 1024), 1024);
        assert_eq!(parse_byte_limit(Some("512"), 256, 1024), 512);
        assert_eq!(parse_byte_limit(Some("0"), 256, 1024), 256);
        assert_eq!(parse_byte_limit(Some("not-a-number"), 256, 1024), 256);
    }

    // The exec-backed tests below rely on standard Unix coreutils. They are
    // gated to Unix because the runner's process-group isolation is Unix-only.
    #[cfg(unix)]
    mod unix {
        use super::*;

        #[test]
        fn runs_fast_command_and_captures_stdout() {
            let mut cmd = Command::new("echo");
            cmd.arg("hello-proc-runner");
            let out = run_with_timeout(cmd, Duration::from_secs(30)).expect("echo runs");
            assert!(out.status.success(), "echo should exit 0");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                "hello-proc-runner"
            );
        }

        #[test]
        fn propagates_nonzero_exit_status() {
            let out = run_with_timeout(Command::new("false"), Duration::from_secs(30))
                .expect("`false` spawns and exits");
            assert!(!out.status.success(), "`false` exits non-zero");
        }

        #[test]
        fn large_output_does_not_deadlock() {
            // `seq 1 50000` emits well over the ~64 KiB pipe buffer. If the runner
            // did not drain the pipe concurrently, the child would block on write,
            // never exit, and this would (wrongly) time out. A generous timeout
            // means a pass proves the concurrent drain, not a lucky race.
            let mut cmd = Command::new("seq");
            cmd.args(["1", "50000"]);
            let out = run_with_timeout(cmd, Duration::from_secs(60)).expect("seq runs");
            assert!(out.status.success());
            assert!(
                out.stdout.len() > 64 * 1024,
                "expected >64 KiB of output, got {} bytes",
                out.stdout.len()
            );
        }

        #[test]
        fn times_out_and_kills_long_running_child() {
            // `sleep 30` would block the server forever under the old code path.
            let mut cmd = Command::new("sleep");
            cmd.arg("30");
            let start = Instant::now();
            let err = run_with_timeout(cmd, Duration::from_millis(200)).unwrap_err();
            let elapsed = start.elapsed();
            assert!(
                matches!(err, RunError::Timeout(_)),
                "expected Timeout, got {err:?}"
            );
            // The call must return promptly (the child was killed), not after the
            // full 30 s sleep. A few seconds of slack absorbs slow CI scheduling.
            assert!(
                elapsed < Duration::from_secs(10),
                "timeout teardown took too long: {elapsed:?}"
            );
        }

        // Linux-only: the whole-group-reap guarantee is implemented via `/proc`.
        // On other Unix (macOS/BSD) the runner deliberately degrades to a
        // leader-only kill, so this stronger property does not hold there.
        #[cfg(target_os = "linux")]
        #[test]
        fn stdout_overflow_kills_child_and_returns_typed_limit() {
            let mut cmd = Command::new("sh");
            cmd.args(["-c", "while :; do printf '0123456789abcdef'; done"]);
            let start = Instant::now();
            let err = run_with_limits(
                cmd,
                Duration::from_secs(30),
                CaptureLimits {
                    stdout_bytes: 128,
                    stderr_bytes: 128,
                },
            )
            .unwrap_err();
            assert!(matches!(
                err,
                RunError::OutputLimit {
                    stream: CaptureStream::Stdout,
                    limit: 128,
                }
            ));
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "overflow teardown must be prompt"
            );
        }

        #[test]
        fn stderr_overflow_kills_child_and_returns_typed_limit() {
            let mut cmd = Command::new("sh");
            cmd.args(["-c", "while :; do printf '0123456789abcdef' >&2; done"]);
            let err = run_with_limits(
                cmd,
                Duration::from_secs(30),
                CaptureLimits {
                    stdout_bytes: 128,
                    stderr_bytes: 96,
                },
            )
            .unwrap_err();
            assert!(matches!(
                err,
                RunError::OutputLimit {
                    stream: CaptureStream::Stderr,
                    limit: 96,
                }
            ));
        }

        #[test]
        fn output_tree_overflow_kills_child_and_returns_typed_quota() {
            let root = tempfile::tempdir().unwrap();
            let output = root.path().join("output");
            std::fs::create_dir(&output).unwrap();
            let mut cmd = Command::new("sh");
            cmd.env("FINDEVIL_TEST_OUTPUT_ROOT", &output).args([
                "-c",
                "dd if=/dev/zero of=\"$FINDEVIL_TEST_OUTPUT_ROOT/blob\" bs=4096 count=64 2>/dev/null; sleep 30",
            ]);
            let start = Instant::now();
            let err = run_with_output_quota(
                cmd,
                Duration::from_secs(30),
                &OutputQuota::new(output, 32 * 1024, 16),
            )
            .unwrap_err();
            assert!(matches!(
                err,
                RunError::OutputQuota(OutputQuotaError::Bytes { limit: 32_768, .. })
            ));
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "output-quota teardown must be prompt"
            );
        }

        #[test]
        fn output_tree_rejects_symlinks_without_following_them() {
            use std::os::unix::fs::symlink;

            let root = tempfile::tempdir().unwrap();
            symlink("/dev/zero", root.path().join("unsafe-link")).unwrap();
            let error = check_output_quota(&OutputQuota::new(root.path().to_path_buf(), 1024, 16))
                .unwrap_err();
            assert!(matches!(error, OutputQuotaError::UnsafeEntry));
        }

        #[test]
        fn stable_output_open_rejects_final_symlink() {
            use std::os::unix::fs::symlink;

            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("target");
            std::fs::write(&target, b"secret").unwrap();
            let alias = root.path().join("alias");
            symlink(&target, &alias).unwrap();
            assert!(open_stable_output_file(&alias).is_err());
        }

        #[test]
        fn closed_pipe_descendant_cannot_write_after_leader_exit() {
            let root = tempfile::tempdir().unwrap();
            let output = root.path().join("output");
            std::fs::create_dir(&output).unwrap();
            let delayed = output.join("delayed.bin");
            let mut cmd = Command::new("sh");
            cmd.env("FINDEVIL_TEST_OUTPUT_ROOT", &output).args([
                "-c",
                "(exec >/dev/null 2>/dev/null; sleep 1; dd if=/dev/zero of=\"$FINDEVIL_TEST_OUTPUT_ROOT/delayed.bin\" bs=4096 count=64) & exit 0",
            ]);
            let error = run_with_output_quota(
                cmd,
                Duration::from_secs(30),
                &OutputQuota::new(output, 32 * 1024, 16),
            )
            .unwrap_err();
            assert!(matches!(error, RunError::ChildTreeStillRunning));

            thread::sleep(Duration::from_millis(1_300));
            assert!(!delayed.exists(), "closed-pipe descendant survived cleanup");
        }

        #[test]
        fn capture_only_runner_rejects_closed_pipe_descendant() {
            let root = tempfile::tempdir().unwrap();
            let delayed = root.path().join("delayed");
            let mut cmd = Command::new("sh");
            cmd.env("FINDEVIL_TEST_DELAYED", &delayed).args([
                "-c",
                "(exec >/dev/null 2>/dev/null; sleep 1; touch \"$FINDEVIL_TEST_DELAYED\") & exit 0",
            ]);
            let error = run_with_limits(
                cmd,
                Duration::from_secs(30),
                CaptureLimits {
                    stdout_bytes: 1024,
                    stderr_bytes: 1024,
                },
            )
            .unwrap_err();
            assert!(matches!(error, RunError::ChildTreeStillRunning));

            thread::sleep(Duration::from_millis(1_300));
            assert!(
                !delayed.exists(),
                "capture-only descendant survived cleanup"
            );
        }

        #[test]
        #[cfg(target_os = "linux")]
        fn captured_group_identity_survives_fast_leader_exit() {
            let root = tempfile::tempdir().unwrap();
            let delayed = root.path().join("fast-leader-delayed");
            let own_pgid = current_process_group().expect("read own process group");
            let mut cmd = Command::new("sh");
            cmd.env("FINDEVIL_TEST_DELAYED", &delayed)
                .args([
                    "-c",
                    "(exec >/dev/null 2>/dev/null; sleep 1; touch \"$FINDEVIL_TEST_DELAYED\") & exit 0",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            isolate_process_group(&mut cmd);
            let mut child = cmd.spawn().unwrap();
            let child_pid = child.id();
            child.wait().unwrap();

            let group = capture_child_group(child_pid, own_pgid)
                .expect("process_group(0) establishes pid == pgid without a live leader");
            assert_eq!(group.pgid(), Some(child_pid));
            assert!(terminate_surviving_group(group).expect("quiesce captured group"));

            thread::sleep(Duration::from_millis(1_300));
            assert!(!delayed.exists(), "fast-leader descendant escaped cleanup");
        }

        #[test]
        fn inherited_pipe_after_leader_exit_is_bounded_and_tree_is_killed() {
            let sentinel = std::env::temp_dir().join(format!(
                "findevil-inherited-pipe-{}-{:?}.sentinel",
                std::process::id(),
                thread::current().id()
            ));
            let _ = std::fs::remove_file(&sentinel);
            let script = format!("(sleep 2; touch '{}') & exit 0", sentinel.display());
            let mut cmd = Command::new("sh");
            cmd.args(["-c", &script]);

            let start = Instant::now();
            let err = run_with_limits(
                cmd,
                Duration::from_secs(30),
                CaptureLimits {
                    stdout_bytes: 1024,
                    stderr_bytes: 1024,
                },
            )
            .unwrap_err();
            // The inheriting descendant is detected and the tree killed on both
            // platforms, but the error variant differs by how the survivor is
            // first observed. On Linux the `/proc` group enumeration in
            // `quiesce_process_group` sees the live member and returns
            // `ChildTreeStillRunning`. On BSD/macOS `killpg(pgid)` returns `ESRCH`
            // once the group *leader* has exited and been reaped (even while a
            // member lives), so quiescence passes and the survivor is instead
            // caught one step later by the still-open inherited pipe
            // (`PipeStillOpen`). Both prove the descendant was found and the tree
            // reaped; the sentinel assertion below verifies the actual safety
            // property on either path.
            assert!(
                matches!(
                    err,
                    RunError::ChildTreeStillRunning | RunError::PipeStillOpen { .. }
                ),
                "expected a survivor-detected/tree-killed error, got {err:?}"
            );
            assert!(
                start.elapsed() < Duration::from_millis(1500),
                "reader joins must be bounded: {:?}",
                start.elapsed()
            );

            thread::sleep(Duration::from_millis(2300));
            let leaked = sentinel.exists();
            let _ = std::fs::remove_file(&sentinel);
            assert!(!leaked, "inheriting descendant survived runner cleanup");
        }

        #[test]
        #[cfg(target_os = "linux")]
        fn spawned_child_owns_a_distinct_group() {
            // Proves process_group(0) takes effect here: a child launched the way
            // run_with_timeout launches it is its OWN group leader (its /proc PGID
            // equals its PID) and that group is NOT the test runner's group. This
            // is the precondition that lets the timeout path issue a SAFE whole-
            // group kill instead of silently degrading to a leader-only kill.
            let mut cmd = Command::new("sleep");
            cmd.arg("5").stdin(Stdio::null());
            let (mut child, group) = spawn_isolated(&mut cmd).expect("sleep spawns in own group");
            let pid = child.id();
            assert_eq!(
                read_pgid(&pid.to_string()),
                Some(pid),
                "child should lead its own group"
            );
            assert_ne!(
                read_pgid("self"),
                Some(pid),
                "child group must differ from ours"
            );
            assert_eq!(group.pgid(), Some(pid));
            kill_child_tree(&mut child, group);
            let _ = child.wait();
        }

        // Runs on every Unix: this crate reaps the child's whole process group on
        // all Unix targets (positive-PID `/proc` enumeration on Linux, `libproc`
        // enumeration on macOS, `killpg` on other BSDs), so the grandchild is
        // killed on each and the sentinel never appears. (Unlike
        // spawned_child_owns_a_distinct_group, this test uses no `/proc` reader,
        // so it is not Linux-gated.)
        #[cfg(unix)]
        #[test]
        fn timeout_reaps_whole_process_group_not_just_leader() {
            // Distinguishes a whole-group kill from a leader-only kill. The leader
            // `sh` backgrounds a GRANDCHILD subshell that sleeps then touches a
            // sentinel, and the leader itself sleeps long. We time out almost
            // immediately: a whole-group `kill -KILL -<pgid>` kills the grandchild
            // before its sleep elapses, so the sentinel is NEVER created. A
            // leader-only kill would orphan the grandchild, which would survive its
            // sleep and create the sentinel — failing this assertion.
            let sentinel = std::env::temp_dir().join(format!(
                "findevil-pgkill-{}-{:?}.sentinel",
                std::process::id(),
                thread::current().id()
            ));
            let _ = std::fs::remove_file(&sentinel);
            let script = format!("(sleep 1; touch '{}') & sleep 30", sentinel.display());
            let mut cmd = Command::new("sh");
            cmd.args(["-c", &script]);
            let err = run_with_timeout(cmd, Duration::from_millis(200)).unwrap_err();
            assert!(
                matches!(err, RunError::Timeout(_)),
                "expected Timeout, got {err:?}"
            );

            // Wait well past the grandchild's 1 s sleep. If the group kill worked,
            // the grandchild died at ~200 ms and the sentinel never appears.
            thread::sleep(Duration::from_millis(2000));
            let leaked = sentinel.exists();
            let _ = std::fs::remove_file(&sentinel);
            assert!(
                !leaked,
                "grandchild survived the timeout and wrote {} — group not reaped",
                sentinel.display()
            );
        }

        #[test]
        fn missing_binary_surfaces_spawn_not_found() {
            let cmd = Command::new("definitely-not-a-real-binary-zzz-proc-runner");
            let err = run_with_timeout(cmd, Duration::from_secs(5)).unwrap_err();
            match err {
                RunError::Spawn(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                }
                other => panic!("expected Spawn(NotFound), got {other:?}"),
            }
        }
    }
}
