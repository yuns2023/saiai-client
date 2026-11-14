//! A downloaded fixed-source update candidate: its bounded `--version`
//! probe, its removal, and the installation-directory lock that keeps
//! updates, `uninstall` and the Windows replacement helper apart.
//!
//! The candidate and everything it starts run in their own process group
//! (Unix) or job object (Windows). Every way out of the probe ends that
//! group or job, so a descendant can neither keep the probe past its budget
//! nor keep running from (and holding) the candidate file. A descendant that
//! leaves its process group on purpose (`setsid`, `setpgid`) is not tracked
//! on Unix; on Windows the job also holds the descendants it starts.

use anyhow::{Context, Result, bail};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);
/// How long ending the candidate (and on Windows its job) may take.
const STOP_BUDGET: Duration = Duration::from_secs(2);
/// How long the output may stay open after the candidate exited (a
/// descendant holding it ends the probe then, not at the deadline).
const OUTPUT_GRACE: Duration = Duration::from_secs(1);

/// `<candidate> --version` standard output, bounded: the candidate runs past
/// `timeout`, prints more than `limit` bytes, keeps running after closing
/// its output, or leaves something that keeps the output open: an error. A
/// failed exit or a read error is an error too. Whatever the outcome, the
/// candidate's process group or job is ended and the candidate is reaped
/// before this returns.
pub(crate) fn probe_candidate_version(
    path: &Path,
    timeout: Duration,
    limit: usize,
) -> Result<String> {
    use std::io::Read;
    let mut candidate = Candidate::spawn(path)?;
    let deadline = Instant::now() + timeout;
    let Some(stdout) = candidate.child.stdout.take() else {
        let _ = candidate.stop();
        bail!("candidate stdout is not captured");
    };
    let mut reader = Some(std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut output = Vec::new();
        stdout.take(limit as u64 + 1).read_to_end(&mut output)?;
        Ok(output)
    }));
    let watched = watch(path, &mut candidate, &mut reader, deadline, timeout, limit);
    let stopped = candidate.stop();
    // With the group or job ended the output closes: give the reader a
    // moment to finish instead of leaving it blocked on the pipe.
    if let Some(reader) = reader {
        let until = Instant::now() + STOP_BUDGET;
        while !reader.is_finished() && Instant::now() < until {
            std::thread::sleep(POLL);
        }
        if reader.is_finished() {
            let _ = reader.join();
        }
    }
    match (watched, stopped) {
        (Ok(bytes), Ok(status)) => {
            if !status.success() {
                bail!("{} exited with {status}", path.display());
            }
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(error), Err(cleanup)) => Err(error.context(format!("{cleanup:#}"))),
    }
}

/// The complete output once the reader finished within `limit`, and the
/// candidate has exited (not reaped) by the deadline.
fn watch(
    path: &Path,
    candidate: &mut Candidate,
    reader: &mut Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    deadline: Instant,
    timeout: Duration,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut exited_at = None;
    while !reader.as_ref().is_some_and(JoinHandle::is_finished) {
        if exited_at.is_none() && candidate.exited()? {
            exited_at = Some(Instant::now());
        }
        if let Some(exited_at) = exited_at
            && Instant::now() >= deadline.min(exited_at + OUTPUT_GRACE)
        {
            // Exited, but something it started keeps the output open.
            bail!("{} left its output open", path.display());
        }
        if Instant::now() >= deadline {
            bail!(
                "{} did not exit within {}s",
                path.display(),
                timeout.as_secs()
            );
        }
        std::thread::sleep(POLL);
    }
    let bytes = reader
        .take()
        .context("candidate output reader is missing")?
        .join()
        .map_err(|_| anyhow::anyhow!("reading {} panicked", path.display()))?
        .with_context(|| format!("failed to read the output of {}", path.display()))?;
    if bytes.len() > limit {
        bail!("{} printed more than {limit} bytes", path.display());
    }
    // Output complete: the candidate must exit by the deadline.
    while !candidate.exited()? {
        if Instant::now() >= deadline {
            bail!("{} did not exit after printing its version", path.display());
        }
        std::thread::sleep(POLL);
    }
    Ok(bytes)
}

/// The probed candidate process and its process group (Unix).
#[cfg(unix)]
struct Candidate {
    child: Child,
}

#[cfg(unix)]
impl Candidate {
    fn spawn(path: &Path) -> Result<Self> {
        use std::os::unix::process::CommandExt;
        let child = Command::new(path)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            // A new process group, led by the candidate.
            .process_group(0)
            .spawn()
            .with_context(|| format!("failed to execute {}", path.display()))?;
        Ok(Self { child })
    }

    /// Whether the candidate has exited, without reaping it: until it is
    /// reaped its process ID, and with it the group's, cannot be reused.
    fn exited(&mut self) -> Result<bool> {
        loop {
            // SAFETY: a zeroed siginfo_t is a valid output buffer.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: waitid writes into `info` only.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                // Nothing to report leaves the zeroed signal number.
                return Ok(info.si_signo == libc::SIGCHLD);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error)
                    .with_context(|| format!("failed to wait for process {}", self.child.id()));
            }
        }
    }

    /// Kills the whole group (the candidate is not reaped yet, so its ID
    /// still names this group), then reaps the candidate within the budget.
    fn stop(&mut self) -> Result<ExitStatus> {
        let group = self.child.id() as libc::pid_t;
        // SAFETY: plain signal delivery to the candidate's own group.
        let killed = if unsafe { libc::kill(-group, libc::SIGKILL) } == 0 {
            Ok(())
        } else {
            // No member left (ESRCH), or only a reaped-but-unwaited leader
            // (EPERM on macOS): nothing to end.
            Err(std::io::Error::last_os_error())
        };
        reap(&mut self.child, &killed)
    }
}

/// The probed candidate process and the job holding it and everything it
/// starts (Windows). Closing the job ends whatever is still in it.
#[cfg(windows)]
struct Candidate {
    child: Child,
    job: windows_job::Job,
}

#[cfg(windows)]
impl Candidate {
    fn spawn(path: &Path) -> Result<Self> {
        use std::os::windows::process::CommandExt;
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        let job = windows_job::Job::new()?;
        // Suspended until it is in the job, so nothing it starts escapes.
        let mut child = Command::new(path)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_SUSPENDED)
            .spawn()
            .with_context(|| format!("failed to execute {}", path.display()))?;
        if let Err(error) = job
            .assign(&child)
            .and_then(|()| windows_job::resume(child.id()))
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).with_context(|| format!("failed to start {}", path.display()));
        }
        Ok(Self { child, job })
    }

    fn exited(&mut self) -> Result<bool> {
        Ok(self
            .child
            .try_wait()
            .with_context(|| format!("failed to wait for process {}", self.child.id()))?
            .is_some())
    }

    /// Ends every process in the job, reaps the candidate and waits (within
    /// the budget) until the job is empty, so the candidate file is no
    /// longer in use.
    fn stop(&mut self) -> Result<ExitStatus> {
        let killed = self.job.terminate();
        let status = reap(&mut self.child, &killed)?;
        let until = Instant::now() + STOP_BUDGET;
        loop {
            let active = self.job.active_processes()?;
            if active == 0 {
                return Ok(status);
            }
            if Instant::now() >= until {
                bail!(
                    "{active} process(es) started by candidate process {} could not be stopped ({killed:?})",
                    self.child.id()
                );
            }
            std::thread::sleep(POLL);
        }
    }
}

/// Reaps `child` after it was killed, within the budget.
fn reap(child: &mut Child, killed: &std::io::Result<()>) -> Result<ExitStatus> {
    let until = Instant::now() + STOP_BUDGET;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < until => std::thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                bail!(
                    "candidate process {} could not be stopped ({killed:?})",
                    child.id()
                );
            }
            Err(error) => {
                return Err(error)
                    .context(format!("failed to reap candidate process {}", child.id()));
            }
        }
    }
}

#[cfg(windows)]
mod windows_job {
    use anyhow::{Result, bail};
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    /// An unnamed job that ends its processes when its last handle closes.
    pub(super) struct Job(HANDLE);

    impl Job {
        pub(super) fn new() -> Result<Self> {
            // SAFETY: an unnamed job with default security.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let job = Self(handle);
            // SAFETY: zeroed limits with one flag set, passed with their size.
            let set = unsafe {
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if set == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(job)
        }

        pub(super) fn assign(&self, child: &Child) -> Result<()> {
            // SAFETY: both handles are open for the duration of the call.
            if unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }

        pub(super) fn terminate(&self) -> std::io::Result<()> {
            // SAFETY: the job handle is open.
            if unsafe { TerminateJobObject(self.0, 1) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        pub(super) fn active_processes(&self) -> Result<u32> {
            // SAFETY: a zeroed output buffer passed with its size.
            unsafe {
                let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
                if QueryInformationJobObject(
                    self.0,
                    JobObjectBasicAccountingInformation,
                    (&raw mut info).cast(),
                    std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                ) == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                Ok(info.ActiveProcesses)
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: closes the handle this value owns.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Resumes the (suspended) threads of process `pid`.
    pub(super) fn resume(pid: u32) -> Result<()> {
        // SAFETY: a thread snapshot, closed below.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut resumed = 0;
        let mut failure = None;
        // SAFETY: entries sized as the API requires; handles are closed.
        unsafe {
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut more = Thread32First(snapshot, &mut entry) != 0;
            while more {
                if entry.th32OwnerProcessID == pid {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if thread.is_null() || ResumeThread(thread) == u32::MAX {
                        failure = Some(std::io::Error::last_os_error());
                    } else {
                        resumed += 1;
                    }
                    if !thread.is_null() {
                        CloseHandle(thread);
                    }
                }
                more = Thread32Next(snapshot, &mut entry) != 0;
            }
            CloseHandle(snapshot);
        }
        if let Some(error) = failure {
            return Err(error.into());
        }
        if resumed == 0 {
            bail!("process {pid} has no thread to resume");
        }
        Ok(())
    }
}

/// Removes a candidate the update does not install. An error names why it
/// is left behind; on Windows a file that is briefly in use (a scanner, an
/// image still being unmapped) is retried for a few seconds.
pub(crate) fn remove_candidate(path: &Path) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) if cfg!(windows) && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to remove {}", path.display()));
            }
        }
    }
}

/// `error`, after removing the candidate at `path`; a candidate that cannot
/// be removed is named in the error.
pub(crate) fn discard_candidate(path: &Path, error: anyhow::Error) -> anyhow::Error {
    match remove_candidate(path) {
        Ok(()) => error,
        Err(cleanup) => error.context(format!(
            "the downloaded candidate was left behind: {cleanup:#}"
        )),
    }
}

// ------------------------------------------------------------ Directory lock

/// Exclusive lock of an installation directory, held until dropped: a
/// fixed-source update holds it for its whole run, `uninstall` while it
/// changes the installation. A second holder fails at once.
///
/// On Unix the directory itself is locked (nothing to delete or replace).
/// On Windows `<candidate prefix>lock` is held open without sharing, plus
/// `<candidate prefix>helper-lock`, which the replacement helper an update
/// leaves running takes over (see [`InstallationLock::hand_over_to_helper`])
/// and holds until it finishes.
#[derive(Debug)]
pub(crate) struct InstallationLock {
    #[cfg(unix)]
    _directory: fs::File,
    #[cfg(windows)]
    main: (PathBuf, fs::File),
    #[cfg(windows)]
    helper: Option<(PathBuf, fs::File)>,
    /// The helper lock file (also once handed over).
    #[cfg(windows)]
    helper_path: PathBuf,
}

/// The lock files of `directory` (Windows): the main lock and the helper
/// lock. Unix locks the directory and has none.
pub(crate) fn installation_lock_files(directory: &Path, candidate_prefix: &str) -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![
            directory.join(format!("{candidate_prefix}lock")),
            directory.join(format!("{candidate_prefix}helper-lock")),
        ]
    } else {
        Vec::new()
    }
}

pub(crate) fn lock_installation(
    directory: &Path,
    candidate_prefix: &str,
    binary: &str,
) -> Result<InstallationLock> {
    let busy = || {
        anyhow::anyhow!(
            "another {binary} update or uninstall is running in {}",
            directory.display()
        )
    };
    #[cfg(unix)]
    {
        let _ = candidate_prefix;
        let file = fs::File::open(directory)
            .with_context(|| format!("failed to open {}", directory.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(InstallationLock { _directory: file }),
            Err(fs::TryLockError::WouldBlock) => Err(busy()),
            Err(fs::TryLockError::Error(error)) => {
                Err(error).with_context(|| format!("failed to lock {}", directory.display()))
            }
        }
    }
    #[cfg(windows)]
    {
        let files = installation_lock_files(directory, candidate_prefix);
        let main = match open_exclusive(&files[0])? {
            Some(file) => (files[0].clone(), file),
            None => return Err(busy()),
        };
        let helper = match open_exclusive(&files[1])? {
            Some(file) => (files[1].clone(), file),
            None => bail!(
                "a previous {binary} update is still being installed in {}; try again when it has finished",
                directory.display()
            ),
        };
        Ok(InstallationLock {
            main,
            helper_path: helper.0.clone(),
            helper: Some(helper),
        })
    }
}

/// The file opened without sharing, or `None` while another handle holds it.
#[cfg(windows)]
fn open_exclusive(path: &Path) -> Result<Option<fs::File>> {
    use std::os::windows::fs::OpenOptionsExt;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    match fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .share_mode(0)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to lock {}", path.display())),
    }
}

impl InstallationLock {
    /// Whether `path` is one of the files this lock holds open.
    pub(crate) fn holds(&self, path: &Path) -> bool {
        #[cfg(windows)]
        {
            self.main.0 == path || self.helper.as_ref().is_some_and(|(held, _)| held == path)
        }
        #[cfg(unix)]
        {
            let _ = path;
            false
        }
    }

    /// Windows: the helper lock file of this installation directory.
    #[cfg(windows)]
    pub(crate) fn helper_lock_path(&self) -> &Path {
        &self.helper_path
    }

    /// Windows: releases the helper lock, runs `start` (which starts the
    /// replacement helper), and waits up to `wait` until the helper holds it,
    /// so no update or uninstall can slip in between this command's exit
    /// and the helper's work. `Ok((_, false))`: the helper did not take it
    /// in time; the caller must stop that helper before letting go.
    #[cfg(windows)]
    pub(crate) fn hand_over_to_helper<T>(
        &mut self,
        wait: Duration,
        start: impl FnOnce() -> Result<T>,
    ) -> Result<(T, bool)> {
        let path = self
            .helper
            .take()
            .map(|(path, _)| path)
            .context("the helper lock was already handed over")?;
        let started = start()?;
        let until = Instant::now() + wait;
        loop {
            match open_exclusive(&path) {
                Ok(None) => return Ok((started, true)),
                // Free: closed at once, before waiting (the helper retries).
                Ok(Some(file)) => drop(file),
                Err(_) => {}
            }
            if Instant::now() >= until {
                return Ok((started, false));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
