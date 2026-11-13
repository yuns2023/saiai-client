//! The `saiai` program: the shared client library plus this distribution's
//! identity (`brand_saiai.rs`) and release facts.

mod brand_saiai;

use proxy_cli::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, UpdateNames,
};

fn main() -> anyhow::Result<()> {
    proxy_cli::run(
        &brand_saiai::SAIAI_BRAND,
        proxy_cli::RuntimeContext {
            version: env!("CARGO_PKG_VERSION"),
            gateway: &proxy_cli::gateway_saiai::SAIAI_GATEWAY,
        },
    )
}
