//! The `saiai` program: the shared client library plus this release's facts.

fn main() -> anyhow::Result<()> {
    proxy_cli::run(proxy_cli::RuntimeContext {
        version: env!("CARGO_PKG_VERSION"),
    })
}
