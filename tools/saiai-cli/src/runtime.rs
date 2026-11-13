//! Facts about the final program, supplied by its entry point.
//!
//! The library is linked into a distribution-specific binary; its own
//! package metadata (`CARGO_PKG_*`) describes the library, not the program a
//! user installed. Everything that reports the program's identity to users,
//! the update channel or a Gateway reads it from here.

use crate::gateway::GatewayExtension;
use anyhow::{Result, bail};
use std::sync::OnceLock;

/// Release facts of the program running this library.
#[derive(Clone, Copy)]
pub struct RuntimeContext {
    /// Released program version (`--version`, update checks, client proof
    /// enrollment, Codex daemon client info).
    pub version: &'static str,
    /// Gateway behavior of this distribution; `&NoGatewayExtension` for a
    /// Gateway without extra protocol. Pass a named `static`. Identity is the
    /// concrete type at its address: zero-sized extensions carry no state, so
    /// two statics of the same zero-sized type are the same logical extension
    /// (they may share an address); different types are always told apart.
    pub gateway: &'static dyn GatewayExtension,
}

impl PartialEq for RuntimeContext {
    fn eq(&self, other: &Self) -> bool {
        // The same extension instance: same type at the same address (vtable
        // pointers may differ between codegen units, so they are ignored).
        self.version == other.version
            && std::ptr::addr_eq(self.gateway, other.gateway)
            && self.gateway.extension_type() == other.gateway.extension_type()
    }
}

impl Eq for RuntimeContext {}

impl std::fmt::Debug for RuntimeContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeContext")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
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
        bail!(
            "this process already runs as version {} with another Gateway extension",
            installed.version
        );
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

/// The Gateway extension of the program.
pub(crate) fn gateway() -> &'static dyn GatewayExtension {
    match CONTEXT.get() {
        Some(context) => context.gateway,
        None => uninstalled_gateway(),
    }
}

#[cfg(not(test))]
fn uninstalled_gateway() -> &'static dyn GatewayExtension {
    panic!("the runtime context is installed by run() before any command executes")
}

// Unit tests see the SAIAI extension, matching the SAIAI fallback brand.
#[cfg(test)]
fn uninstalled_gateway() -> &'static dyn GatewayExtension {
    &crate::gateway_saiai::SAIAI_GATEWAY
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
        static OTHER: crate::gateway::NoGatewayExtension = crate::gateway::NoGatewayExtension;
        let slot = OnceLock::new();
        let first = RuntimeContext {
            version: "1.2.3",
            gateway: &crate::gateway_saiai::SAIAI_GATEWAY,
        };
        install_into(&slot, first).unwrap();
        install_into(&slot, first).unwrap();
        let error = install_into(
            &slot,
            RuntimeContext {
                version: "9.9.9",
                ..first
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("1.2.3"), "{error}");
        assert!(
            install_into(
                &slot,
                RuntimeContext {
                    gateway: &OTHER,
                    ..first
                }
            )
            .is_err()
        );
        assert_eq!(slot.get(), Some(&first));
    }
}
