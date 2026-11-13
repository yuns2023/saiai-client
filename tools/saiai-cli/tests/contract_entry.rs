//! The `contract` entries used from outside the library (feature on, the
//! library built without `cfg(test)`, so no fallback brand): one process,
//! one sequence, because the brand and runtime are installed once.

use proxy_cli::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, UpdateNames,
};

#[path = "../src/brand_saiai.rs"]
mod brand_saiai;

use brand_saiai::{SAIAI_BRAND, SAIAI_VALUES};
use proxy_cli::RuntimeContext;
use proxy_cli::contract::desktop::{self, Answer, Request};

const AUTOMATIONS: Request<'static> = Request {
    method: "GET",
    target: "/automations",
    headers: &[],
    body: b"",
};

fn context(
    version: &'static str,
    gateway: &'static dyn proxy_cli::GatewayExtension,
) -> RuntimeContext {
    RuntimeContext { version, gateway }
}

#[test]
fn entries_need_an_installed_brand_and_keep_the_first_context() {
    static OTHER: Brand = Brand {
        binary_name: "other",
        ..SAIAI_VALUES
    };
    static NONE: proxy_cli::NoGatewayExtension = proxy_cli::NoGatewayExtension;
    let saiai_gateway = &proxy_cli::gateway_saiai::SAIAI_GATEWAY;
    let version = env!("CARGO_PKG_VERSION");

    // Nothing installed: the entry refuses instead of guessing a brand.
    let error = desktop::sidecar(&SAIAI_BRAND, &AUTOMATIONS, true).unwrap_err();
    assert_eq!(
        error.to_string(),
        "contract entry called before a brand was installed"
    );

    proxy_cli::contract::install(&SAIAI_BRAND, context(version, saiai_gateway)).unwrap();
    let expected = Answer {
        status: 501,
        content_type: Some("application/json"),
        body: br#"{"error":{"type":"desktop_control_unsupported","message":"This Desktop control endpoint is unavailable through SAIAI."}}"#.to_vec(),
        reason: "desktop_control_unsupported",
        headers: Vec::new(),
    };
    assert_eq!(
        desktop::sidecar(&SAIAI_BRAND, &AUTOMATIONS, true).unwrap(),
        Some(expected)
    );

    // The same installation again is fine.
    proxy_cli::contract::install(&SAIAI_BRAND, context(version, saiai_gateway)).unwrap();
    // Another brand, version or extension is refused.
    assert!(proxy_cli::contract::install(&OTHER, context(version, saiai_gateway)).is_err());
    assert!(proxy_cli::contract::install(&SAIAI_BRAND, context("0.0.1", saiai_gateway)).is_err());
    assert!(proxy_cli::contract::install(&SAIAI_BRAND, context(version, &NONE)).is_err());
    assert!(desktop::sidecar(&OTHER, &AUTOMATIONS, true).is_err());

    // The first context is still the one in use.
    let answer = desktop::sidecar(&SAIAI_BRAND, &AUTOMATIONS, true)
        .unwrap()
        .unwrap();
    assert_eq!(answer.status, 501);
    assert_eq!(
        std::str::from_utf8(&answer.body).unwrap(),
        r#"{"error":{"type":"desktop_control_unsupported","message":"This Desktop control endpoint is unavailable through SAIAI."}}"#
    );
}
