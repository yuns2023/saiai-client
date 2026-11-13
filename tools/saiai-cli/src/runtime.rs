//! Facts about the final program, supplied by its entry point.
//!
//! The library is linked into a distribution-specific binary; its own
//! package metadata (`CARGO_PKG_*`) describes the library, not the program a
//! user installed. Everything that reports the program's identity to users,
//! the update channel or a Gateway reads it from here.

use anyhow::{Result, bail};
use std::sync::OnceLock;

/// Release facts of the program running this library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeContext {
    /// Released program version (`--version`, update checks, client proof
    /// enrollment, Codex daemon client info).
    pub version: &'static str,
}

static CONTEXT: OnceLock<RuntimeContext> = OnceLock::new();

/// Installs the context once per process; `run` does this before parsing.
/// A later `run` in the same process must describe the same program.
pub(crate) fn install(context: RuntimeContext) -> Result<()> {
    install_into(&CONTEXT, context)
}

fn install_into(slot: &OnceLock<RuntimeContext>, context: RuntimeContext) -> Result<()> {
    let installed = slot.get_or_init(|| context);
    if *installed != context {
        bail!("this process already runs as version {}", installed.version);
    }
    Ok(())
}

/// The released program version.
pub(crate) fn version() -> &'static str {
    match CONTEXT.get() {
        Some(context) => context.version,
        None => uninstalled_version(),
    }
}

#[cfg(not(test))]
fn uninstalled_version() -> &'static str {
    panic!("the runtime context is installed by run() before any command executes")
}

// Unit tests call library functions without going through `run`; they see
// this package's own version, which is also the released SAIAI version.
#[cfg(test)]
fn uninstalled_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    // A local slot: the process-wide context is never installed by tests.
    #[test]
    fn install_accepts_the_same_context_and_rejects_another_without_overwriting() {
        let slot = OnceLock::new();
        let first = RuntimeContext { version: "1.2.3" };
        install_into(&slot, first).unwrap();
        install_into(&slot, first).unwrap();
        let error = install_into(&slot, RuntimeContext { version: "9.9.9" }).unwrap_err();
        assert!(error.to_string().contains("1.2.3"), "{error}");
        assert_eq!(slot.get(), Some(&first));
    }
}
