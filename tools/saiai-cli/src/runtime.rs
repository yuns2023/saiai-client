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
    /// concrete type at its address. Zero-sized extensions carry no state:
    /// two statics of the same zero-sized type that share an address count as
    /// one logical extension (distinct statics are not guaranteed to be told
    /// apart); different types are always told apart.
    pub gateway: &'static dyn GatewayExtension,
}

impl PartialEq for RuntimeContext {
    fn eq(&self, other: &Self) -> bool {
        // The same extension instance: same type at the same address (vtable
        // pointers may differ between codegen units, so they are ignored).
        self.version == other.version && same_extension(self.gateway, other.gateway)
    }
}

impl Eq for RuntimeContext {}

fn same_extension(left: &dyn GatewayExtension, right: &dyn GatewayExtension) -> bool {
    std::ptr::addr_eq(left, right)
        && crate::gateway::extension_type(left) == crate::gateway::extension_type(right)
}

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
    // An unusable extension never occupies the slot.
    crate::gateway::validate_extension(context.gateway)?;
    let installed = slot.get_or_init(|| context);
    if installed.version != context.version {
        bail!(
            "this process already runs as version {}, not {}",
            installed.version,
            context.version
        );
    }
    if !same_extension(installed.gateway, context.gateway) {
        bail!("this process already runs with another Gateway extension");
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

    // A local slot: these tests never touch the process-wide context
    // (contract tests install the SAIAI context there).
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
        assert!(
            error.to_string().contains("version 1.2.3, not 9.9.9"),
            "{error}"
        );
        let error = install_into(
            &slot,
            RuntimeContext {
                gateway: &OTHER,
                ..first
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("another Gateway extension"),
            "{error}"
        );
        assert_eq!(slot.get(), Some(&first));
    }

    #[test]
    fn an_extension_reserving_protected_headers_is_refused_before_installing() {
        struct Reserves(&'static [&'static str]);
        impl GatewayExtension for Reserves {
            fn signature_headers(&self) -> &'static [&'static str] {
                self.0
            }
            fn start(
                &self,
                _start: crate::gateway::GatewayStart,
            ) -> std::sync::Arc<dyn crate::gateway::GatewaySession> {
                unreachable!()
            }
        }
        static HANDSHAKE: Reserves = Reserves(&["sec-websocket-key"]);
        static CREDENTIAL: Reserves = Reserves(&["authorization"]);
        static UPPER: Reserves = Reserves(&["X-Proof"]);
        for gateway in [&HANDSHAKE, &CREDENTIAL, &UPPER] {
            let slot = OnceLock::new();
            let context = RuntimeContext {
                version: "1.2.3",
                gateway,
            };
            assert!(install_into(&slot, context).is_err());
            assert!(slot.get().is_none());
        }
    }
}
