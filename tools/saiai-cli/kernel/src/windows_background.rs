//! Hold a Windows process handle while checking identity and terminating it.
//! PID reuse must never turn one environment's stop into another one's stop.
use crate::brand::BRAND;
use anyhow::{Context, Result, bail};
use std::ffi::c_void;

#[repr(C)]
#[derive(Default)]
struct FileTime {
    low: u32,
    high: u32,
}

type Handle = *mut c_void;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetProcessTimes(
        handle: Handle,
        created: *mut FileTime,
        exited: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn TerminateProcess(handle: Handle, exit_code: u32) -> i32;
}

pub(crate) struct Process {
    handle: Handle,
    pub pid: u32,
    pub created: u64,
}

impl Process {
    pub fn open(pid: u32, terminate: bool) -> Result<Option<Self>> {
        if pid <= 1 {
            bail!("invalid background process ID");
        }
        let rights = 0x1000 | 0x0010_0000 | if terminate { 1 } else { 0 };
        let handle = unsafe { OpenProcess(rights, 0, pid) };
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(87) {
                return Ok(None);
            }
            return Err(error).with_context(|| {
                format!(
                    "cannot inspect {brand_product} process identity",
                    brand_product = BRAND.product_name
                )
            });
        }
        let mut process = Self {
            handle,
            pid,
            created: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
        );
        if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "cannot read {brand_product} process creation time",
                    brand_product = BRAND.product_name
                )
            });
        }
        process.created = (u64::from(created.high) << 32) | u64::from(created.low);
        Ok(Some(process))
    }

    pub fn running(&self) -> bool {
        unsafe { WaitForSingleObject(self.handle, 0) == 258 }
    }

    pub fn stop(&self) -> Result<()> {
        match self.wait(0) {
            Wait::Exited => return Ok(()),
            Wait::TimedOut => {}
            Wait::Failed(error) => return Err(error).with_context(wait_failed),
        }
        // Read the error at once: the waits below overwrite the thread's
        // last error.
        let terminate_error = if unsafe { TerminateProcess(self.handle, 0) } == 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        finish_stop(terminate_error, |milliseconds| self.wait(milliseconds))
    }

    /// Waits on this verified handle (never a PID reopened later).
    fn wait(&self, milliseconds: u32) -> Wait {
        match unsafe { WaitForSingleObject(self.handle, milliseconds) } {
            WAIT_OBJECT_0 => Wait::Exited,
            WAIT_TIMEOUT => Wait::TimedOut,
            WAIT_FAILED => Wait::Failed(std::io::Error::last_os_error()),
            other => Wait::Failed(std::io::Error::other(format!(
                "unexpected wait result {other:#x}"
            ))),
        }
    }
}

const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const ERROR_ACCESS_DENIED: i32 = 5;
const EXIT_WAIT_MILLISECONDS: u32 = 10_000;

#[derive(Debug)]
enum Wait {
    Exited,
    TimedOut,
    Failed(std::io::Error),
}

/// Outcome of a stop after `TerminateProcess`. Termination counts only when
/// the process is seen to exit. Access denied usually means the process is
/// already exiting, so it gets the same bounded wait; if the process is
/// still there afterwards the original termination error is returned.
/// Other termination errors succeed only if the process has already exited.
fn finish_stop(
    terminate_error: Option<std::io::Error>,
    wait: impl FnOnce(u32) -> Wait,
) -> Result<()> {
    let milliseconds = match &terminate_error {
        None => EXIT_WAIT_MILLISECONDS,
        Some(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) => EXIT_WAIT_MILLISECONDS,
        Some(_) => 0,
    };
    match (wait(milliseconds), terminate_error) {
        (Wait::Exited, _) => Ok(()),
        (Wait::Failed(error), _) => Err(error).with_context(wait_failed),
        (Wait::TimedOut, Some(error)) => Err(error).with_context(|| {
            format!(
                "cannot terminate selected {brand_product} process",
                brand_product = BRAND.product_name
            )
        }),
        (Wait::TimedOut, None) => bail!(
            "selected {brand_product} process did not exit after termination",
            brand_product = BRAND.product_name
        ),
    }
}

fn wait_failed() -> String {
    format!(
        "cannot wait for selected {brand_product} process to exit",
        brand_product = BRAND.product_name
    )
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn os_error(code: i32) -> std::io::Error {
        std::io::Error::from_raw_os_error(code)
    }

    fn os_code(error: &anyhow::Error) -> Option<i32> {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error)
    }

    #[test]
    fn access_denied_counts_only_once_the_process_has_exited() {
        let waited = Cell::new(None);
        finish_stop(Some(os_error(ERROR_ACCESS_DENIED)), |ms| {
            waited.set(Some(ms));
            Wait::Exited
        })
        .unwrap();
        assert_eq!(waited.get(), Some(EXIT_WAIT_MILLISECONDS));

        // Still running after the bounded wait: the original error, kept.
        let error =
            finish_stop(Some(os_error(ERROR_ACCESS_DENIED)), |_| Wait::TimedOut).unwrap_err();
        assert_eq!(os_code(&error), Some(ERROR_ACCESS_DENIED));
        assert_eq!(error.to_string(), "cannot terminate selected KTEST process");
    }

    #[test]
    fn other_termination_errors_are_not_waited_out() {
        let waited = Cell::new(None);
        let error = finish_stop(Some(os_error(6)), |ms| {
            waited.set(Some(ms));
            Wait::TimedOut
        })
        .unwrap_err();
        assert_eq!(waited.get(), Some(0));
        assert_eq!(os_code(&error), Some(6));
        // Already gone: nothing left to stop.
        finish_stop(Some(os_error(6)), |_| Wait::Exited).unwrap();
    }

    #[test]
    fn a_failed_wait_is_reported_as_such() {
        for terminate_error in [None, Some(os_error(ERROR_ACCESS_DENIED))] {
            let error = finish_stop(terminate_error, |_| Wait::Failed(os_error(6))).unwrap_err();
            assert_eq!(os_code(&error), Some(6));
            assert_eq!(
                error.to_string(),
                "cannot wait for selected KTEST process to exit"
            );
        }
        let error = finish_stop(None, |_| Wait::TimedOut).unwrap_err();
        assert_eq!(
            error.to_string(),
            "selected KTEST process did not exit after termination"
        );
    }

    /// The real path on a child process: one that is running (no
    /// grandchildren), and one that exited before the stop. The window
    /// between the running check and TerminateProcess is covered by the
    /// decision tests above.
    #[test]
    fn stop_terminates_a_running_child_and_accepts_one_that_already_exited() {
        let mut running = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let process = Process::open(running.id(), true).unwrap().unwrap();
        assert!(process.running());
        process.stop().unwrap();
        assert!(!process.running());
        running.wait().unwrap();

        let mut quick = std::process::Command::new("cmd")
            .args(["/D", "/C", "exit 0"])
            .spawn()
            .unwrap();
        let process = Process::open(quick.id(), true).unwrap().unwrap();
        quick.wait().unwrap();
        process.stop().unwrap();
        assert!(!process.running());
    }
}
