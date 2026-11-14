//! Evidence that a client configuration is managed by *another* program
//! built on this kernel (another distribution's local proxy), read from the
//! files themselves.
//!
//! The rules are distribution-neutral: they rely on structures every
//! distribution of this kernel writes (installation CA naming, managed
//! markers, the placeholder login shape), never on a distribution's name.
//! Anything that belongs to the running brand is never evidence, and an
//! ambiguous or unreadable value is no evidence (the caller then behaves as
//! before). The rules recognise remains; they are not a complete ownership
//! record: a configuration whose CA was deleted, for example, carries none.

use crate::brand::BRAND;
use base64::Engine;
use serde_json::{Map, Value};
use std::path::Path;

/// Suffix every installation CA common-name prefix carries (checked by
/// `brand::install`); the common name is the prefix, optionally followed by
/// a space and eight lowercase hexadecimal digits.
pub(crate) const INSTALLATION_CA_SUFFIX: &str = " local installation CA";

/// Who issued an installation CA certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CertificateOwner {
    /// Carries this brand's organization.
    Ours,
    /// An installation CA (by the kernel's naming) of another organization.
    Foreign(String),
    /// Anything else (no organization, other naming, not a CA).
    Unknown,
}

fn is_installation_ca_name(common_name: &str) -> bool {
    let prefix = match common_name.rsplit_once(' ') {
        Some((prefix, suffix))
            if suffix.len() == 8
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            prefix
        }
        _ => common_name,
    };
    prefix.len() > INSTALLATION_CA_SUFFIX.len() && prefix.ends_with(INSTALLATION_CA_SUFFIX)
}

/// Classifies one certificate (DER). A certificate that does not parse is
/// an error, not "unknown": callers that delete must keep it.
pub(crate) fn classify_certificate(der: &[u8]) -> anyhow::Result<CertificateOwner> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("certificate does not parse: {error}"))?;
    let subject = certificate.subject();
    let organizations: Vec<&str> = subject
        .iter_organization()
        .filter_map(|attribute| attribute.as_str().ok())
        .collect();
    if organizations
        .iter()
        .any(|organization| *organization == BRAND.certificates.ca_organization)
    {
        return Ok(CertificateOwner::Ours);
    }
    let common_names: Vec<&str> = subject
        .iter_common_name()
        .filter_map(|attribute| attribute.as_str().ok())
        .collect();
    let is_ca = certificate
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraints| constraints.value.ca);
    let self_issued = certificate.issuer() == subject;
    Ok(match (common_names.as_slice(), organizations.first()) {
        ([common_name], Some(organization))
            if is_ca && self_issued && is_installation_ca_name(common_name) =>
        {
            CertificateOwner::Foreign((*organization).to_string())
        }
        _ => CertificateOwner::Unknown,
    })
}

/// The certificates of a PEM text, in order (blocks that do not decode are
/// errors).
pub(crate) fn pem_certificates(pem: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes()))
        .map(|certificate| {
            certificate
                .map(|der| der.as_ref().to_vec())
                .map_err(|error| anyhow::anyhow!("PEM certificate does not decode: {error}"))
        })
        .collect()
}

/// A CA file referenced by a configuration: `Ours` when any certificate is
/// ours (a mixed bundle is never evidence), else `Foreign` when any is
/// another installation's, else `Unknown` (also when unreadable).
pub(crate) fn classify_ca_file(path: &Path) -> CertificateOwner {
    let Ok(pem) = std::fs::read_to_string(path) else {
        return CertificateOwner::Unknown;
    };
    let Ok(certificates) = pem_certificates(&pem) else {
        return CertificateOwner::Unknown;
    };
    let owners: Vec<_> = certificates
        .iter()
        .filter_map(|der| classify_certificate(der).ok())
        .collect();
    if owners.contains(&CertificateOwner::Ours) {
        return CertificateOwner::Ours;
    }
    owners
        .into_iter()
        .find(|owner| matches!(owner, CertificateOwner::Foreign(_)))
        .unwrap_or(CertificateOwner::Unknown)
}

/// `http(s)://host[:port][/]` with a loopback host.
pub(crate) fn is_loopback_proxy(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value.trim()) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

const PROXY_KEYS: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
];

/// E1: Claude `settings.json` whose `env` routes through a loopback proxy and
/// trusts another installation's CA.
pub(crate) fn claude_settings_evidence(settings: &Map<String, Value>) -> Option<String> {
    let env = settings.get("env")?.as_object()?;
    let proxy = PROXY_KEYS.iter().find(|key| {
        env.get(**key)
            .and_then(Value::as_str)
            .is_some_and(is_loopback_proxy)
    })?;
    let ca = env.get("NODE_EXTRA_CA_CERTS")?.as_str()?;
    match classify_ca_file(Path::new(ca)) {
        CertificateOwner::Foreign(organization) => Some(format!(
            "env.{proxy} points at a local proxy and env.NODE_EXTRA_CA_CERTS ({ca}) is the installation CA of \"{organization}\""
        )),
        _ => None,
    }
}

/// One `KEY=value` line of a dotenv file: key and decoded value.
fn dotenv_assignment(line: &str) -> Option<(&str, String)> {
    let mut assignment = line.trim();
    if let Some(rest) = assignment.strip_prefix("export ") {
        assignment = rest.trim_start();
    }
    if assignment.starts_with('#') {
        return None;
    }
    let (key, raw) = assignment.split_once('=')?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return None;
    }
    let raw = raw.trim();
    let value = if raw.starts_with('"') {
        serde_json::from_str::<String>(raw).ok()?
    } else if let Some(inner) = raw
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    {
        inner.to_string()
    } else {
        raw.to_string()
    };
    Some((key, value))
}

/// The value of `key` when every assignment of it in the file agrees.
fn unambiguous<'a>(assignments: &'a [(String, String)], key: &str) -> Option<&'a str> {
    let mut values = assignments
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.as_str());
    let first = values.next()?;
    values.all(|value| value == first).then_some(first)
}

/// `# BEGIN <NAME> CODEX IDE (managed)` / `# END …`: the name, if the line is
/// one of them.
fn codex_marker(line: &str, kind: &str) -> Option<String> {
    let name = line
        .strip_prefix(&format!("# {kind} "))?
        .strip_suffix(" CODEX IDE (managed)")?;
    (!name.is_empty()).then(|| name.to_string())
}

/// E2/E3: a Codex `CODEX_HOME/.env` with another installation's managed
/// block that still routes through a loopback proxy, or whose CA file is
/// another installation's (with a loopback proxy). Overlapping, nested or
/// unterminated blocks and conflicting assignments are no evidence.
pub(crate) fn codex_env_evidence(raw: &str) -> Option<String> {
    let text = raw.replace("\r\n", "\n");
    let lines: Vec<&str> = text.lines().collect();
    let assignments: Vec<(String, String)> = lines
        .iter()
        .filter_map(|line| dotenv_assignment(line))
        .map(|(key, value)| (key.to_string(), value))
        .collect();
    let effective_proxy = PROXY_KEYS.iter().find_map(|key| {
        unambiguous(&assignments, key)
            .filter(|value| is_loopback_proxy(value))
            .map(|_| *key)
    });
    // Blocks: every BEGIN closed by the matching END before another marker.
    let mut open: Option<(String, usize)> = None;
    let mut foreign_block = None;
    for (index, line) in lines.iter().enumerate() {
        let line = line.trim_end();
        if let Some(name) = codex_marker(line, "BEGIN") {
            if open.is_some() {
                return None;
            }
            open = Some((name, index));
        } else if let Some(name) = codex_marker(line, "END") {
            let (begin, start) = open.take()?;
            if begin != name {
                return None;
            }
            if format!("# BEGIN {begin} CODEX IDE (managed)") == BRAND.markers.codex_ide_env_begin {
                continue;
            }
            let routes = lines[start + 1..index].iter().any(|line| {
                dotenv_assignment(line).is_some_and(|(key, value)| {
                    PROXY_KEYS.contains(&key)
                        && is_loopback_proxy(&value)
                        && unambiguous(&assignments, key) == Some(value.as_str())
                })
            });
            if routes && foreign_block.is_none() {
                foreign_block = Some(begin);
            }
        }
    }
    if open.is_some() {
        return None;
    }
    if let Some(name) = foreign_block {
        return Some(format!(
            "it holds the managed block \"{name} CODEX IDE\" of another local proxy program"
        ));
    }
    let proxy = effective_proxy?;
    let ca = unambiguous(&assignments, "SSL_CERT_FILE")?;
    match classify_ca_file(Path::new(ca)) {
        CertificateOwner::Foreign(organization) => Some(format!(
            "{proxy} points at a local proxy and SSL_CERT_FILE ({ca}) is the installation CA of \"{organization}\""
        )),
        _ => None,
    }
}

/// The `<x>` of a kernel-shaped placeholder login token, if `token` is one.
fn placeholder_name(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else {
        return None;
    };
    let decode = |part: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .ok()
    };
    let header: Value = serde_json::from_slice(&decode(header)?).ok()?;
    if header != serde_json::json!({"alg": "none", "typ": "JWT"}) {
        return None;
    }
    let payload: Value = serde_json::from_slice(&decode(payload)?).ok()?;
    let from_email = payload
        .get("email")?
        .as_str()?
        .strip_suffix("-local-proxy@invalid")?;
    let from_account = payload
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()?
        .strip_suffix("-local-proxy-account")?;
    let signature = String::from_utf8(decode(signature)?).ok()?;
    let from_signature = signature.strip_suffix("-local-proxy")?;
    (!from_email.is_empty() && from_email == from_account && from_email == from_signature)
        .then(|| from_email.to_string())
}

/// E4: a Codex `auth.json` signed in with another installation's placeholder
/// (the access token decides; an id token alone never does, so a real login
/// with a stale placeholder id token is not blocked).
pub(crate) fn codex_auth_evidence(auth: &Value) -> Option<String> {
    let access = auth.get("tokens")?.get("access_token")?.as_str()?;
    if access == BRAND.placeholders.codex_token {
        return None;
    }
    let name = placeholder_name(access)?;
    Some(format!(
        "it is signed in with the placeholder login \"{name}-local-proxy\" of another local proxy program"
    ))
}

/// Codex profile evidence (E2/E3 from `.env`, E4 from `auth.json`).
pub(crate) fn codex_profile_evidence(codex_dir: &Path) -> Option<(std::path::PathBuf, String)> {
    let env = codex_dir.join(".env");
    if let Some(reason) = std::fs::read_to_string(&env)
        .ok()
        .and_then(|raw| codex_env_evidence(&raw))
    {
        return Some((env, reason));
    }
    let auth = codex_dir.join("auth.json");
    std::fs::read(&auth)
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .and_then(|value| codex_auth_evidence(&value))
        .map(|reason| (auth, reason))
}

/// Claude profile evidence (E1 from `settings.json`).
pub(crate) fn claude_profile_evidence(settings_path: &Path) -> Option<String> {
    std::fs::read(settings_path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .and_then(|value| value.as_object().and_then(claude_settings_evidence))
}

/// The refusal for a configuration another program manages.
pub(crate) fn refusal(path: &Path, reason: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{} is managed by another local proxy program ({reason}); {brand_product} does not take it over. Use a separate configuration directory for {brand_product} (CLAUDE_CONFIG_DIR or CODEX_HOME), or remove the other program's settings after confirming they are no longer used",
        path.display(),
        brand_product = BRAND.product_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    use serde_json::json;

    /// A certificate with these subject attributes (in order), a CA unless
    /// `ca` is false, self-issued unless an issuer is given.
    fn certificate(
        attributes: &[(DnType, &str)],
        ca: bool,
        issuer: Option<(&rcgen::Certificate, &KeyPair)>,
    ) -> (String, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        let mut name = DistinguishedName::new();
        for (kind, value) in attributes {
            name.push(kind.clone(), *value);
        }
        params.distinguished_name = name;
        let certificate = match issuer {
            None => params.self_signed(&key).unwrap(),
            Some((issuer, issuer_key)) => params.signed_by(&key, issuer, issuer_key).unwrap(),
        };
        (certificate.pem(), certificate.der().to_vec())
    }

    fn installation_ca(common_name: &str, organization: &str) -> (String, Vec<u8>) {
        certificate(
            &[
                (DnType::CommonName, common_name),
                (DnType::OrganizationName, organization),
            ],
            true,
            None,
        )
    }

    fn owner(der: &[u8]) -> CertificateOwner {
        classify_certificate(der).unwrap()
    }

    #[test]
    fn installation_cas_are_told_apart_by_organization_and_naming() {
        let foreign = || CertificateOwner::Foreign("OTHER".to_string());
        // Another installation, with or without the CN suffix.
        assert_eq!(
            owner(&installation_ca("OTHER local installation CA 0123abcd", "OTHER").1),
            foreign()
        );
        assert_eq!(
            owner(&installation_ca("OTHER local installation CA", "OTHER").1),
            foreign()
        );
        // Ours, whatever the CN. (The generator keeps one attribute per
        // type, so several CNs or Os in one subject are not built here.)
        assert_eq!(
            owner(&installation_ca("KTEST local installation CA", "KTEST").1),
            CertificateOwner::Ours
        );
        assert_eq!(
            owner(
                &certificate(
                    &[
                        (DnType::CommonName, "OTHER local installation CA"),
                        (DnType::OrganizationName, "OTHER"),
                        (DnType::OrganizationName, "KTEST"),
                    ],
                    true,
                    None
                )
                .1
            ),
            CertificateOwner::Ours
        );
        // Not the kernel's naming, an uppercase suffix, an empty prefix, not
        // a CA, no organization: no evidence.
        for der in [
            installation_ca("Corporate Inspection CA", "OTHER").1,
            installation_ca("OTHER local installation CA 0123ABCD", "OTHER").1,
            installation_ca(" local installation CA", "OTHER").1,
            certificate(
                &[
                    (DnType::CommonName, "OTHER local installation CA"),
                    (DnType::OrganizationName, "OTHER"),
                ],
                false,
                None,
            )
            .1,
            certificate(
                &[(DnType::CommonName, "OTHER local installation CA")],
                true,
                None,
            )
            .1,
        ] {
            assert_eq!(owner(&der), CertificateOwner::Unknown);
        }
        assert_eq!(
            owner(&installation_ca("ktest local installation CA", "ktest").1),
            CertificateOwner::Foreign("ktest".to_string())
        );
        // Issued by another CA (not self-issued): no evidence.
        let issuer_key = KeyPair::generate().unwrap();
        let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = issuer_params.self_signed(&issuer_key).unwrap();
        let issued = certificate(
            &[
                (DnType::CommonName, "OTHER local installation CA"),
                (DnType::OrganizationName, "OTHER"),
            ],
            true,
            Some((&issuer, &issuer_key)),
        );
        assert_eq!(owner(&issued.1), CertificateOwner::Unknown);
        // Garbage is an error, not "unknown".
        assert!(classify_certificate(b"not a certificate").is_err());
    }

    #[test]
    fn ca_files_with_several_certificates_prefer_ours() {
        let directory = tempfile::tempdir().unwrap();
        let write = |name: &str, pems: &[&str]| {
            let path = directory.path().join(name);
            std::fs::write(&path, pems.concat()).unwrap();
            path
        };
        let (ours, _) = installation_ca("KTEST local installation CA", "KTEST");
        let (foreign, _) = installation_ca("OTHER local installation CA", "OTHER");
        let (corporate, _) = installation_ca("Corporate Inspection CA", "Corp");
        assert_eq!(
            classify_ca_file(&write("mixed.pem", &[&foreign, &ours])),
            CertificateOwner::Ours
        );
        assert_eq!(
            classify_ca_file(&write("bundle.pem", &[&corporate, &foreign])),
            CertificateOwner::Foreign("OTHER".to_string())
        );
        assert_eq!(
            classify_ca_file(&write("corporate.pem", &[&corporate])),
            CertificateOwner::Unknown
        );
        assert_eq!(
            classify_ca_file(&write("garbage.pem", &["not pem"])),
            CertificateOwner::Unknown
        );
        assert_eq!(
            classify_ca_file(&directory.path().join("missing.pem")),
            CertificateOwner::Unknown
        );
    }

    #[test]
    fn loopback_proxies_are_recognized() {
        for value in [
            "http://127.0.0.1:19908",
            "http://127.1.2.3:1/",
            "https://localhost:8080",
            "http://LOCALHOST:1",
            "http://[::1]:9",
        ] {
            assert!(is_loopback_proxy(value), "{value}");
        }
        for value in [
            "http://10.0.0.1:8080",
            "http://proxy.example:3128",
            "socks5://127.0.0.1:1080",
            "127.0.0.1:19908",
            "",
        ] {
            assert!(!is_loopback_proxy(value), "{value}");
        }
    }

    #[test]
    fn claude_settings_are_foreign_with_a_local_proxy_and_a_foreign_ca() {
        let directory = tempfile::tempdir().unwrap();
        let ca = |name: &str, organization: &str| {
            let path = directory.path().join(name);
            std::fs::write(
                &path,
                installation_ca(
                    &format!("{organization} local installation CA"),
                    organization,
                )
                .0,
            )
            .unwrap();
            path.to_string_lossy().into_owned()
        };
        let (foreign, ours) = (ca("other-ca.crt", "OTHER"), ca("ktest-ca.crt", "KTEST"));
        let settings = |proxy_key: &str, proxy: &str, ca: &str| {
            json!({"env": {proxy_key: proxy, "NODE_EXTRA_CA_CERTS": ca}})
                .as_object()
                .unwrap()
                .clone()
        };
        for key in ["https_proxy", "http_proxy", "all_proxy", "HTTPS_PROXY"] {
            assert!(
                claude_settings_evidence(&settings(key, "http://127.0.0.1:4000", &foreign))
                    .is_some(),
                "{key}"
            );
        }
        // Ours, a remote proxy, no CA, no proxy: no evidence.
        assert!(
            claude_settings_evidence(&settings("https_proxy", "http://127.0.0.1:4000", &ours))
                .is_none()
        );
        assert!(
            claude_settings_evidence(&settings("https_proxy", "http://10.0.0.1:3128", &foreign))
                .is_none()
        );
        assert!(
            claude_settings_evidence(
                json!({"env": {"https_proxy": "http://127.0.0.1:4000"}})
                    .as_object()
                    .unwrap()
            )
            .is_none()
        );
        assert!(
            claude_settings_evidence(
                json!({"env": {"NODE_EXTRA_CA_CERTS": foreign}})
                    .as_object()
                    .unwrap()
            )
            .is_none()
        );
        assert!(claude_settings_evidence(json!({}).as_object().unwrap()).is_none());
    }

    fn foreign_block(proxy: &str) -> String {
        format!(
            "# BEGIN OTHER CODEX IDE (managed)\nSSL_CERT_FILE=\"/x/other-ca.crt\"\nHTTPS_PROXY=\"{proxy}\"\nhttps_proxy=\"{proxy}\"\n# END OTHER CODEX IDE (managed)\n"
        )
    }

    #[test]
    fn codex_env_files_with_another_programs_live_block_are_foreign() {
        let block = foreign_block("http://127.0.0.1:4000");
        assert!(
            codex_env_evidence(&block)
                .unwrap()
                .contains("OTHER CODEX IDE")
        );
        assert!(
            codex_env_evidence(&format!("USER=1\r\n{}", block.replace('\n', "\r\n"))).is_some()
        );
        // Our own block is never evidence.
        let ours = block.replace("OTHER", "KTEST");
        assert!(codex_env_evidence(&ours).is_none());
        // A leftover empty block, a block without a local proxy, a proxy that
        // is assigned differently elsewhere, an unterminated, nested or
        // mismatched block: no evidence.
        for raw in [
            "# BEGIN OTHER CODEX IDE (managed)\n# END OTHER CODEX IDE (managed)\n".to_string(),
            foreign_block("http://10.0.0.1:3128"),
            format!(
                "{block}HTTPS_PROXY=\"http://127.0.0.1:5000\"\nhttps_proxy=\"http://127.0.0.1:5000\"\n"
            ),
            "# BEGIN OTHER CODEX IDE (managed)\nHTTPS_PROXY=\"http://127.0.0.1:4000\"\n"
                .to_string(),
            format!("# BEGIN KTEST CODEX IDE (managed)\n{block}# END KTEST CODEX IDE (managed)\n"),
            block.replace("# END OTHER", "# END THIRD"),
            block.replace("# BEGIN OTHER", "# BEGIN  OTHER"),
        ] {
            assert!(codex_env_evidence(&raw).is_none(), "{raw}");
        }
        // The same assignment repeated identically is still unambiguous.
        assert!(
            codex_env_evidence(&format!("{block}https_proxy=\"http://127.0.0.1:4000\"\n"))
                .is_some()
        );
    }

    #[test]
    fn codex_env_files_with_a_foreign_ca_and_a_local_proxy_are_foreign() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("other-ca.crt");
        std::fs::write(
            &path,
            installation_ca("OTHER local installation CA", "OTHER").0,
        )
        .unwrap();
        let ca = serde_json::to_string(&path.to_string_lossy()).unwrap();
        let raw = format!("SSL_CERT_FILE={ca}\nHTTPS_PROXY=\"http://127.0.0.1:4000\"\n");
        assert!(codex_env_evidence(&raw).unwrap().contains("\"OTHER\""));
        // Unquoted values work too; a conflicting second CA does not count.
        assert!(
            codex_env_evidence(&format!(
                "export SSL_CERT_FILE={}\nHTTPS_PROXY=http://127.0.0.1:4000\n",
                path.display()
            ))
            .is_some()
        );
        assert!(codex_env_evidence(&format!("{raw}SSL_CERT_FILE=\"/elsewhere.crt\"\n")).is_none());
        assert!(codex_env_evidence(&format!("SSL_CERT_FILE={ca}\n")).is_none());
    }

    fn jwt(header: &Value, payload: &Value, signature: &str) -> String {
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        format!(
            "{}.{}.{}",
            encode(header.to_string().as_bytes()),
            encode(payload.to_string().as_bytes()),
            encode(signature.as_bytes())
        )
    }

    fn placeholder(email: &str, account: &str, signature: &str) -> String {
        jwt(
            &json!({"alg": "none", "typ": "JWT"}),
            &json!({
                "email": email,
                "https://api.openai.com/auth": {"chatgpt_account_id": account},
            }),
            signature,
        )
    }

    fn auth(access: &str, id: &str) -> Value {
        json!({"tokens": {"access_token": access, "id_token": id}})
    }

    #[test]
    fn codex_logins_are_foreign_only_with_another_programs_placeholder_access_token() {
        let other = placeholder(
            "other-local-proxy@invalid",
            "other-local-proxy-account",
            "other-local-proxy",
        );
        let real = jwt(
            &json!({"alg": "RS256", "typ": "JWT"}),
            &json!({"email": "user@example.com"}),
            "signature",
        );
        let ours = BRAND.placeholders.codex_token;
        assert!(
            codex_auth_evidence(&auth(&other, &other))
                .unwrap()
                .contains("other-local-proxy")
        );
        assert!(codex_auth_evidence(&auth(&other, &real)).is_some());
        // A real login with a stale placeholder id token is not blocked.
        assert!(codex_auth_evidence(&auth(&real, &other)).is_none());
        assert!(codex_auth_evidence(&auth(ours, ours)).is_none());
        assert!(codex_auth_evidence(&auth(&real, &real)).is_none());
        // Shapes that are not the kernel's placeholder.
        for token in [
            placeholder(
                "a-local-proxy@invalid",
                "b-local-proxy-account",
                "a-local-proxy",
            ),
            placeholder(
                "a-local-proxy@invalid",
                "a-local-proxy-account",
                "b-local-proxy",
            ),
            placeholder(
                "-local-proxy@invalid",
                "-local-proxy-account",
                "-local-proxy",
            ),
            jwt(
                &json!({"alg": "none", "typ": "JWT", "kid": "x"}),
                &json!({"email": "a-local-proxy@invalid", "https://api.openai.com/auth": {"chatgpt_account_id": "a-local-proxy-account"}}),
                "a-local-proxy",
            ),
            format!("{other}.extra"),
            "ktest-local-proxy-placeholder-old".to_string(),
        ] {
            assert!(
                codex_auth_evidence(&auth(&token, &token)).is_none(),
                "{token}"
            );
        }
        assert!(codex_auth_evidence(&json!({"OPENAI_API_KEY": "sk"})).is_none());
    }
}
