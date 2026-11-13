//! Facts about the final program, supplied by its entry point.
//!
//! The library is linked into a distribution-specific binary; its own
//! package metadata (`CARGO_PKG_*`) describes the library, not the program a
//! user installed. Everything that reports the program's identity to users,
//! the update channel or a Gateway reads it from here.

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
pub(crate) fn install(context: RuntimeContext) {
    let _ = CONTEXT.set(context);
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
