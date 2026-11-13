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
        if !self.running() {
            return Ok(());
        }
        if unsafe { TerminateProcess(self.handle, 0) } == 0 && self.running() {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "cannot terminate selected {brand_product} process",
                    brand_product = BRAND.product_name
                )
            });
        }
        if unsafe { WaitForSingleObject(self.handle, 10_000) } != 0 {
            bail!(
                "selected {brand_product} process did not exit after termination",
                brand_product = BRAND.product_name
            );
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
