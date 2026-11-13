//! The `saiai` program: the kernel (`proxy_cli`) run with this
//! distribution's identity and Gateway extension (`saiai`) and its release
//! facts.

use saiai::{brand_saiai, gateway_saiai};

fn main() -> anyhow::Result<()> {
    proxy_cli::run(
        &brand_saiai::SAIAI_BRAND,
        proxy_cli::RuntimeContext {
            version: env!("CARGO_PKG_VERSION"),
            gateway: &gateway_saiai::SAIAI_GATEWAY,
        },
    )
}
