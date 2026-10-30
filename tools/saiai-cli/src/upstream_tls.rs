//! TLS trust for connections from SAIAI to the Gateway.
//!
//! Corporate networks that decrypt HTTPS re-sign every certificate with a
//! company CA that is trusted by the operating system but absent from the
//! bundled webpki roots. Upstream connections therefore trust the union of the
//! bundled roots and the platform store. The installation-specific SAIAI CA is
//! always removed from that union: it may sit in the platform store (Windows
//! trust setup) or in SSL_CERT_FILE (child-process environment), and it must
//! never be able to vouch for the Gateway. When that CA cannot be identified,
//! only the bundled roots are trusted.
//!
//! The configs mirror what reqwest 0.12 and tokio-tungstenite 0.27 build by
//! default, so only the trusted roots change, not the TLS parameters.

use rustls::RootCertStore;
use rustls::client::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use std::sync::{Arc, OnceLock};

/// Loaded once per process: a CA installed later needs a SAIAI restart.
fn native_roots() -> &'static [CertificateDer<'static>] {
    static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut certs = Vec::new();
        let mut errors = Vec::new();
        load_platform_roots(&mut certs, &mut errors);
        load_ssl_cert_env_roots(&mut certs, &mut errors);
        for error in &errors {
            eprintln!("warning: failed to load system root certificates: {error}");
        }
        let mut seen = std::collections::HashSet::new();
        certs.retain(|cert| seen.insert(cert.as_ref().to_vec()));
        certs
    })
}

// rustls_native_certs::load_native_certs() reads only SSL_CERT_FILE/SSL_CERT_DIR
// when either is set, and SAIAI points SSL_CERT_FILE at its own CA for Codex
// and its child shells. Those files are therefore added to the platform store
// here instead of replacing it.
fn load_ssl_cert_env_roots(certs: &mut Vec<CertificateDer<'static>>, errors: &mut Vec<String>) {
    if std::env::var_os("SSL_CERT_FILE").is_none() && std::env::var_os("SSL_CERT_DIR").is_none() {
        return;
    }
    let result = rustls_native_certs::load_native_certs();
    certs.extend(result.certs);
    errors.extend(result.errors.iter().map(ToString::to_string));
}

#[cfg(target_os = "windows")]
fn load_platform_roots(certs: &mut Vec<CertificateDer<'static>>, errors: &mut Vec<String>) {
    use schannel::cert_context::ValidUses;
    use schannel::cert_store::CertStore;

    // Same selection as rustls-native-certs 0.8: the current-user logical ROOT
    // store (which includes machine and Group Policy roots), limited to
    // certificates that are time-valid and usable for server authentication.
    match CertStore::open_current_user("ROOT") {
        Ok(store) => {
            for cert in store.certs() {
                let server_auth = match cert.valid_uses() {
                    Ok(ValidUses::All) => true,
                    Ok(ValidUses::Oids(oids)) => oids.iter().any(|oid| oid == "1.3.6.1.5.5.7.3.1"),
                    Err(_) => false,
                };
                if server_auth && cert.is_time_valid().unwrap_or(false) {
                    certs.push(CertificateDer::from(cert.to_der().to_vec()));
                }
            }
        }
        Err(error) => errors.push(format!("failed to open current user ROOT store: {error}")),
    }
}

#[cfg(target_os = "macos")]
fn load_platform_roots(certs: &mut Vec<CertificateDer<'static>>, errors: &mut Vec<String>) {
    use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
    use std::collections::HashMap;

    // Same selection as rustls-native-certs 0.8: user settings override admin
    // settings, which override system settings; keep certificates trusted as roots.
    let mut decisions = HashMap::new();
    for domain in [Domain::User, Domain::Admin, Domain::System] {
        let settings = TrustSettings::new(domain);
        let iter = match settings.iter() {
            Ok(iter) => iter,
            Err(error) => {
                errors.push(format!("failed to load {domain:?} trust settings: {error}"));
                continue;
            }
        };
        for cert in iter {
            match settings.tls_trust_settings_for_certificate(&cert) {
                Ok(trust) => {
                    decisions
                        .entry(cert.to_der())
                        .or_insert(trust.unwrap_or(TrustSettingsForCertificate::TrustRoot));
                }
                Err(error) => errors.push(format!("certificate not trusted: {error}")),
            }
        }
    }
    certs.extend(decisions.into_iter().filter_map(|(der, trust)| {
        matches!(
            trust,
            TrustSettingsForCertificate::TrustRoot | TrustSettingsForCertificate::TrustAsRoot
        )
        .then(|| CertificateDer::from(der))
    }));
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn load_platform_roots(_certs: &mut Vec<CertificateDer<'static>>, _errors: &mut Vec<String>) {}

#[cfg(target_os = "linux")]
fn load_platform_roots(certs: &mut Vec<CertificateDer<'static>>, errors: &mut Vec<String>) {
    // The distribution locations openssl-probe 0.2 knows for Linux, read
    // directly because probe() lets SSL_CERT_FILE replace the bundle.
    const BUNDLES: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/ssl/cert.pem",
        "/opt/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/cacert.pem",
    ];
    const DIRS: &[&str] = &[
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/etc/security/certificates",
    ];

    let bundle = BUNDLES
        .iter()
        .map(std::path::Path::new)
        .find(|path| path.exists());
    let mut results = vec![rustls_native_certs::load_certs_from_paths(bundle, None)];
    for dir in DIRS
        .iter()
        .map(std::path::Path::new)
        .filter(|path| path.exists())
    {
        results.push(rustls_native_certs::load_certs_from_paths(None, Some(dir)));
    }
    for result in results {
        certs.extend(result.certs);
        errors.extend(result.errors.iter().map(ToString::to_string));
    }
}

/// Every certificate in the PEM, or None unless all of them parse as CA
/// certificates: an unrecognised entry could hide the real SAIAI CA.
fn installation_ca_ders(installation_ca_pem: &str) -> Option<Vec<CertificateDer<'static>>> {
    let ders = rustls_pemfile::certs(&mut std::io::Cursor::new(installation_ca_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let mut parsed = RootCertStore::empty();
    for der in &ders {
        parsed.add(der.clone()).ok()?;
    }
    (!ders.is_empty()).then_some(ders)
}

fn build_root_store(
    native: &[CertificateDer<'static>],
    installation_ca_pem: &str,
) -> RootCertStore {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let Some(excluded) = installation_ca_ders(installation_ca_pem) else {
        eprintln!(
            "warning: SAIAI installation CA is unreadable; trusting only bundled root certificates"
        );
        return roots;
    };
    roots.add_parsable_certificates(
        native
            .iter()
            .filter(|cert| !excluded.contains(cert))
            .cloned(),
    );
    roots
}

/// `installation_ca_pem` is the SAIAI CA certificate PEM. If it holds no
/// certificate, system roots are skipped rather than risk trusting that CA.
pub(crate) fn upstream_root_store(installation_ca_pem: &str) -> RootCertStore {
    build_root_store(native_roots(), installation_ca_pem)
}

fn provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// Config for reqwest clients (HTTP/1.1 only, as built without the http2 feature).
pub(crate) fn upstream_http_tls_config(installation_ca_pem: &str) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .expect("default TLS versions are supported by every rustls provider")
        .with_root_certificates(upstream_root_store(installation_ca_pem))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Config for Gateway WebSocket connections (no ALPN, like tokio-tungstenite).
pub(crate) fn upstream_websocket_tls_config(installation_ca_pem: &str) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("default TLS versions are supported by every rustls provider")
        .with_root_certificates(upstream_root_store(installation_ca_pem))
        .with_no_client_auth()
}

/// reqwest ignores its own TLS options (roots, SNI, TLS versions, identity)
/// once a preconfigured config is supplied; change them in the ClientConfig.
pub(crate) fn upstream_http_client_builder(installation_ca_pem: &str) -> reqwest::ClientBuilder {
    reqwest::Client::builder().use_preconfigured_tls(upstream_http_tls_config(installation_ca_pem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    fn self_signed_ca(name: &str) -> (String, CertificateDer<'static>) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
        (cert.pem(), cert.der().clone())
    }

    fn anchor(cert: &CertificateDer<'static>) -> rustls::pki_types::TrustAnchor<'static> {
        let mut store = RootCertStore::empty();
        store.add(cert.clone()).unwrap();
        store.roots.remove(0)
    }

    fn bundled_roots() -> Vec<rustls::pki_types::TrustAnchor<'static>> {
        webpki_roots::TLS_SERVER_ROOTS.to_vec()
    }

    #[test]
    fn root_store_trusts_system_roots_except_the_installation_ca() {
        let (_, corporate) = self_signed_ca("Corporate Inspection CA");
        let (saiai_pem, saiai) = self_signed_ca("SAIAI Local CA");

        let roots = build_root_store(&[corporate.clone(), saiai.clone()], &saiai_pem);

        let mut expected = bundled_roots();
        expected.push(anchor(&corporate));
        assert_eq!(roots.roots, expected);
        assert!(!roots.roots.contains(&anchor(&saiai)));
    }

    #[test]
    fn root_store_falls_back_to_bundled_roots_without_installation_ca() {
        let (_, corporate) = self_signed_ca("Corporate Inspection CA");

        let invalid_der = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        for unreadable in ["", "not a certificate", invalid_der] {
            let roots = build_root_store(std::slice::from_ref(&corporate), unreadable);
            assert_eq!(roots.roots, bundled_roots());
        }
    }

    #[test]
    fn root_store_ignores_unparsable_system_certificates() {
        let (saiai_pem, _) = self_signed_ca("SAIAI Local CA");
        let garbage = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03]);

        let roots = build_root_store(&[garbage], &saiai_pem);

        assert_eq!(roots.roots, bundled_roots());
    }
}
