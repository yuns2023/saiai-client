//! The SAIAI distribution of the managed local proxy: its brand values and
//! its Gateway extension (the client device proof). The program (`main.rs`)
//! runs the kernel (`proxy_cli`) with them.

pub mod brand_saiai;
mod client_proof;
pub mod gateway_saiai;

// SAIAI goldens that need the kernel's contract entries (feature `contract`).
#[cfg(all(test, feature = "contract"))]
mod client_proof_saiai_tests;
#[cfg(all(test, feature = "contract"))]
mod contract_desktop_tests;

// Kernel items the SAIAI modules name as `crate::X`: they reach the kernel
// only through its public root.
#[cfg(all(test, feature = "contract"))]
use proxy_cli::wire_target;
use proxy_cli::{
    Brand, CertificateNames, ConfigNames, ConfiguredRoute, EnvironmentNames, GatewayExtension,
    GatewayHttp, GatewaySession, GatewayStart, NativeChatProtocol, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, SignInput, StateFile, UpdateNames,
    write_file_atomically,
};
#[cfg(all(test, feature = "contract"))]
use proxy_cli::{RuntimeContext, Transport, contract};

/// The SAIAI brand and Gateway extension installed as the program installs
/// them (tests that reach brand-dependent kernel code).
#[cfg(all(test, feature = "contract"))]
fn installed_saiai() {
    contract::install(
        &brand_saiai::SAIAI_BRAND,
        RuntimeContext {
            version: env!("CARGO_PKG_VERSION"),
            gateway: &gateway_saiai::SAIAI_GATEWAY,
        },
    )
    .unwrap();
}
