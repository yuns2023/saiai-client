//! The `aitp` program: the kernel run with the AITP distribution's names
//! (`brand`), no Gateway extension (any relay Gateway the user configures
//! with `aitp init --base-url … --api-key …`), and this package's version.
//! It updates from the project's GitHub releases.

mod brand;

fn main() -> anyhow::Result<()> {
    proxy_cli::run(
        &brand::AITP_BRAND,
        proxy_cli::RuntimeContext {
            version: env!("CARGO_PKG_VERSION"),
            gateway: &proxy_cli::NoGatewayExtension,
        },
    )
}
