//! SAIAI client proof v1 (see docs/CLIENT_PROOF.md).
//!
//! The local proxy holds a per-installation ECDSA P-256 device key, enrolls
//! its public half with each Gateway in the background, and signs every
//! request it sends to that Gateway. This is device binding and server-side
//! visibility, not secrecy: the Gateway only observes the result in v1.
//! Enrollment or signing problems never block forwarding; requests are then
//! sent without a proof header.

use anyhow::{Context, Result, bail};
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::Zeroizing;

macro_rules! eprintln {
    ($($arg:tt)*) => {
        ::std::eprintln!("[{}] {}", chrono::Utc::now().to_rfc3339(), format_args!($($arg)*));
    };
}

pub const HEADER_NAME: &str = "x-saiai-client-proof";
const MESSAGE_DOMAIN: &str = "saiai-client-proof-v1";
const KEY_FILENAME: &str = "client-device-key";
const DEVICE_FILENAME: &str = "client-device.json";
const ENROLL_PATH: &str = "/api/v1/client/devices/enroll";
const ENROLL_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_ENROLL_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_DEVICE_ID_LEN: usize = 64;
const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";
/// Retry delays for network/5xx enrollment failures; the last value repeats.
pub const ENROLL_BACKOFF: [Duration; 3] = [
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(30 * 60),
];

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The exact byte string covered by the signature (contract §3).
pub fn proof_message(method: &str, target: &str, ts: u64, nonce: &str, api_key: &str) -> String {
    format!(
        "{MESSAGE_DOMAIN}\n{}\n{target}\n{ts}\n{nonce}\n{:x}",
        method.to_ascii_uppercase(),
        Sha256::digest(api_key.as_bytes())
    )
}

/// base64url of the raw 64-byte `r||s` signature over SHA-256(message).
pub fn sign_message(key: &SigningKey, message: &str) -> String {
    let signature: Signature = key.sign(message.as_bytes());
    b64url(&signature.to_bytes())
}

/// base64url of the 65-byte uncompressed SEC1 public point.
pub fn public_key_b64url(key: &SigningKey) -> String {
    b64url(key.verifying_key().to_encoded_point(false).as_bytes())
}

pub fn proof_header(
    key: &SigningKey,
    device_id: &str,
    method: &str,
    target: &str,
    api_key: &str,
    ts: u64,
    nonce: &str,
) -> String {
    let signature = sign_message(key, &proof_message(method, target, ts, nonce, api_key));
    format!("v1.{device_id}.{ts}.{nonce}.{signature}")
}

/// Request target exactly as written on the wire for an absolute URL.
pub fn wire_target(url: &Url) -> String {
    let mut target = url.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

fn random_nonce() -> String {
    let mut bytes = [0_u8; 16];
    rand::fill(&mut bytes);
    b64url(&bytes)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn generate_signing_key() -> SigningKey {
    loop {
        let mut seed = Zeroizing::new([0_u8; 32]);
        rand::fill(seed.as_mut_slice());
        // Rejects the negligible zero/out-of-range scalar.
        if let Ok(key) = SigningKey::from_slice(seed.as_slice()) {
            return key;
        }
    }
}

fn encode_private_key_pem(key: &SigningKey) -> Result<Zeroizing<String>> {
    let secret = p256::SecretKey::from_bytes(&key.to_bytes())
        .context("failed to encode client device key")?;
    let der = secret
        .to_pkcs8_der()
        .context("failed to encode client device key")?;
    let body = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(der.as_bytes()));
    let mut pem = Zeroizing::new(String::with_capacity(body.len() + 80));
    pem.push_str(PEM_BEGIN);
    pem.push('\n');
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(PEM_END);
    pem.push('\n');
    Ok(pem)
}

pub fn decode_private_key_pem(pem: &str) -> Result<SigningKey> {
    let pem = pem.trim();
    let Some(inner) = pem
        .strip_prefix(PEM_BEGIN)
        .and_then(|rest| rest.strip_suffix(PEM_END))
    else {
        bail!("client device key is not a PKCS#8 PEM private key");
    };
    let body: Zeroizing<String> = Zeroizing::new(inner.split_whitespace().collect());
    let der = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .context("client device key PEM is not valid base64")?,
    );
    let secret = p256::SecretKey::from_pkcs8_der(&der)
        .context("client device key is not a valid P-256 key")?;
    Ok(SigningKey::from(&secret))
}

fn valid_device_id(device_id: &str) -> bool {
    !device_id.is_empty()
        && device_id.len() <= MAX_DEVICE_ID_LEN
        && device_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayDevice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revoked: bool,
}

/// Gateway base URL -> sha256 hex of the enrolling API key -> device.
/// Devices belong to (user, public key) on the Gateway, so records are kept
/// per credential: two keys of different users on one Gateway must not share
/// a device id.
type DeviceMap = BTreeMap<String, BTreeMap<String, GatewayDevice>>;

#[derive(Debug, Default, Serialize, Deserialize)]
struct DeviceFile {
    public_key_sha256: String,
    #[serde(default)]
    gateways: DeviceMap,
}

fn credential_id(api_key: &str) -> String {
    format!("{:x}", Sha256::digest(api_key.as_bytes()))
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnrollOutcome {
    Enrolled(String),
    Revoked,
    /// Permanent for this process (e.g. 429 device limit, bad API key).
    Stop(String),
    /// Network error or server-side failure; retry with backoff.
    Retry(String),
}

pub fn classify_enroll_response(status: u16, body: &[u8]) -> EnrollOutcome {
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("code").and_then(Value::as_str).map(str::to_owned));
    match status {
        200..=299 => {
            let device_id = serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|value| {
                    value
                        .get("device_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
            match device_id {
                Some(device_id) if valid_device_id(&device_id) => {
                    EnrollOutcome::Enrolled(device_id)
                }
                _ => EnrollOutcome::Stop(format!("status={status} invalid_device_id")),
            }
        }
        403 if code.as_deref() == Some("client_device_revoked") => EnrollOutcome::Revoked,
        429 => EnrollOutcome::Stop(format!(
            "status=429 code={}",
            code.as_deref().unwrap_or("none")
        )),
        // 404 covers a Gateway which has not deployed enrollment yet.
        404 | 408 | 500..=599 => EnrollOutcome::Retry(format!("status={status}")),
        _ => EnrollOutcome::Stop(format!(
            "status={status} code={}",
            code.as_deref().unwrap_or("none")
        )),
    }
}

pub struct ClientProof {
    dir: PathBuf,
    key: SigningKey,
    public_key: String,
    public_key_sha256: String,
    gateways: Mutex<DeviceMap>,
    // Serializes device-file writes without holding `gateways`, so signing
    // never waits on disk I/O.
    persist: Mutex<()>,
}

impl std::fmt::Debug for ClientProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientProof")
            .field("public_key_sha256", &self.public_key_sha256)
            .finish_non_exhaustive()
    }
}

impl ClientProof {
    /// Loads (or creates) the device key and per-Gateway device records under
    /// `dir`. An unreadable key is replaced by a new one, i.e. a new device.
    pub fn load(dir: &Path) -> Result<Self> {
        let key_path = dir.join(KEY_FILENAME);
        let key = match fs::read(&key_path) {
            Ok(pem) => match std::str::from_utf8(&pem)
                .context("client device key is not UTF-8")
                .and_then(decode_private_key_pem)
            {
                Ok(key) => key,
                Err(err) => {
                    eprintln!(
                        "client proof: device key {} is unreadable ({err:#}); generating a new device key",
                        key_path.display()
                    );
                    write_new_key(&key_path)?
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => write_new_key(&key_path)?,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", key_path.display()));
            }
        };
        let public_point = key.verifying_key().to_encoded_point(false);
        let public_key_sha256 = format!("{:x}", Sha256::digest(public_point.as_bytes()));
        let device_path = dir.join(DEVICE_FILENAME);
        let gateways = match fs::read(&device_path) {
            Ok(bytes) => match serde_json::from_slice::<DeviceFile>(&bytes) {
                // Device ids belong to one public key; a new key is a new device.
                Ok(file) if file.public_key_sha256 == public_key_sha256 => file.gateways,
                Ok(_) => BTreeMap::new(),
                Err(err) => {
                    eprintln!(
                        "client proof: device file {} is unreadable ({err}); re-enrolling",
                        device_path.display()
                    );
                    BTreeMap::new()
                }
            },
            Err(_) => BTreeMap::new(),
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            public_key: public_key_b64url(&key),
            key,
            public_key_sha256,
            gateways: Mutex::new(gateways),
            persist: Mutex::new(()),
        })
    }

    #[cfg(test)]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn device(&self, gateway: &str, api_key: &str) -> Option<GatewayDevice> {
        self.lock()
            .get(gateway)?
            .get(&credential_id(api_key))
            .cloned()
    }

    /// Fresh `X-Saiai-Client-Proof` value for one request attempt, or `None`
    /// while the Gateway has not issued a device id or revoked this key.
    pub fn sign_request(
        &self,
        gateway: &str,
        method: &str,
        target: &str,
        api_key: &str,
    ) -> Option<String> {
        let device = self.device(gateway, api_key)?;
        if device.revoked {
            return None;
        }
        let device_id = device.device_id?;
        Some(proof_header(
            &self.key,
            &device_id,
            method,
            target,
            api_key,
            now_unix(),
            &random_nonce(),
        ))
    }

    pub fn record_device(&self, gateway: &str, api_key: &str, device_id: &str) -> Result<()> {
        self.update(gateway, api_key, |device| {
            device.device_id = Some(device_id.to_string());
            device.revoked = false;
        })
    }

    pub fn record_revoked(&self, gateway: &str, api_key: &str) -> Result<()> {
        self.update(gateway, api_key, |device| device.revoked = true)
    }

    fn update(
        &self,
        gateway: &str,
        api_key: &str,
        change: impl FnOnce(&mut GatewayDevice),
    ) -> Result<()> {
        let _persist = match self.persist.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let gateways = {
            let mut gateways = self.lock();
            change(
                gateways
                    .entry(gateway.to_string())
                    .or_default()
                    .entry(credential_id(api_key))
                    .or_default(),
            );
            gateways.clone()
        };
        let file = DeviceFile {
            public_key_sha256: self.public_key_sha256.clone(),
            gateways,
        };
        let mut bytes = serde_json::to_vec_pretty(&file)?;
        bytes.push(b'\n');
        super::write_bytes_atomic(&self.dir.join(DEVICE_FILENAME), &bytes, 0o600)
    }

    fn lock(&self) -> MutexGuard<'_, DeviceMap> {
        match self.gateways.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    async fn enroll_once(
        &self,
        client: &reqwest::Client,
        gateway: &str,
        api_key: &str,
    ) -> EnrollOutcome {
        let body = json!({
            "public_key": self.public_key,
            "client_version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        });
        let response = client
            .post(format!("{gateway}{ENROLL_PATH}"))
            .bearer_auth(api_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .timeout(ENROLL_TIMEOUT)
            .send()
            .await;
        let mut response = match response {
            Ok(response) => response,
            Err(err) => return EnrollOutcome::Retry(format!("request failed: {err}")),
        };
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if bytes.len() + chunk.len() > MAX_ENROLL_RESPONSE_BYTES {
                        break;
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                // Only success and 403 need the body; other statuses are
                // classified by status alone, so 429 still stops here.
                Err(err) if matches!(status, 200..=299 | 403) => {
                    return EnrollOutcome::Retry(format!("status={status} body failed: {err}"));
                }
                Err(_) => {
                    bytes.clear();
                    break;
                }
            }
        }
        classify_enroll_response(status, &bytes)
    }

    /// Enrolls this device with `gateway` once per process. Runs in the
    /// background; failures only leave the requests unsigned.
    pub async fn enroll(
        self: Arc<Self>,
        client: reqwest::Client,
        gateway: String,
        api_key: Zeroizing<String>,
        backoff: &'static [Duration],
    ) -> Option<GatewayDevice> {
        if self
            .device(&gateway, &api_key)
            .is_some_and(|device| device.revoked)
        {
            eprintln!("client proof: device revoked by gateway={gateway}; requests stay unsigned");
            return self.device(&gateway, &api_key);
        }
        let mut attempt = 0usize;
        loop {
            match self.enroll_once(&client, &gateway, &api_key).await {
                EnrollOutcome::Enrolled(device_id) => {
                    if let Err(err) = self.record_device(&gateway, &api_key, &device_id) {
                        eprintln!("client proof: failed to persist device record: {err:#}");
                    }
                    eprintln!(
                        "client proof: device active gateway={gateway} device_id={device_id}"
                    );
                    return self.device(&gateway, &api_key);
                }
                EnrollOutcome::Revoked => {
                    if let Err(err) = self.record_revoked(&gateway, &api_key) {
                        eprintln!("client proof: failed to persist device record: {err:#}");
                    }
                    eprintln!(
                        "client proof: device revoked by gateway={gateway}; requests stay unsigned"
                    );
                    return self.device(&gateway, &api_key);
                }
                EnrollOutcome::Stop(reason) => {
                    eprintln!(
                        "client proof: enrollment stopped gateway={gateway} {reason}; requests stay unsigned"
                    );
                    return self.device(&gateway, &api_key);
                }
                EnrollOutcome::Retry(reason) => {
                    let Some(delay) = backoff.get(attempt).or_else(|| backoff.last()).copied()
                    else {
                        return self.device(&gateway, &api_key);
                    };
                    eprintln!(
                        "client proof: enrollment deferred gateway={gateway} {reason}; retry_in_s={}",
                        delay.as_secs()
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

fn write_new_key(path: &Path) -> Result<SigningKey> {
    let key = generate_signing_key();
    let pem = encode_private_key_pem(&key)?;
    super::write_bytes_atomic(path, pem.as_bytes(), 0o600)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const FAST_RETRY: [Duration; 1] = [Duration::from_millis(1)];
    const SLOW_RETRY: [Duration; 1] = [Duration::from_secs(3600)];
    const VECTOR: &str = include_str!("../tests/fixtures/client-proof-v1-vector.json");

    fn vector() -> Value {
        serde_json::from_str(VECTOR).unwrap()
    }

    fn field<'a>(vector: &'a Value, name: &str) -> &'a str {
        vector[name].as_str().unwrap()
    }

    fn vector_message(vector: &Value) -> String {
        proof_message(
            field(vector, "method"),
            field(vector, "target"),
            vector["ts"].as_u64().unwrap(),
            field(vector, "nonce"),
            field(vector, "api_key"),
        )
    }

    fn verify(public_key: &str, message: &str, signature: &str) -> bool {
        let point = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(public_key)
            .unwrap();
        let key = VerifyingKey::from_sec1_bytes(&point).unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .unwrap();
        let Ok(signature) = Signature::from_slice(&raw) else {
            return false;
        };
        key.verify(message.as_bytes(), &signature).is_ok()
    }

    #[test]
    fn vector_message_and_public_point_encoding_are_exact() {
        let vector = vector();
        assert_eq!(vector_message(&vector), field(&vector, "message"));
        let key = decode_private_key_pem(field(&vector, "private_key_pkcs8_pem")).unwrap();
        let public_key = public_key_b64url(&key);
        assert_eq!(public_key, field(&vector, "public_key"));
        assert_eq!(public_key.len(), 87);
        let point = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&public_key)
            .unwrap();
        assert_eq!((point.len(), point[0]), (65, 0x04));
    }

    #[test]
    fn vector_signature_verifies_with_vector_public_key() {
        let vector = vector();
        assert!(verify(
            field(&vector, "public_key"),
            field(&vector, "message"),
            field(&vector, "signature"),
        ));
        assert!(!verify(
            field(&vector, "public_key"),
            &field(&vector, "message").replace("POST", "GET"),
            field(&vector, "signature"),
        ));
    }

    #[test]
    fn vector_pem_produces_verifiable_signature_and_header() {
        let vector = vector();
        let key = decode_private_key_pem(field(&vector, "private_key_pkcs8_pem")).unwrap();
        let header = proof_header(
            &key,
            field(&vector, "device_id"),
            field(&vector, "method"),
            field(&vector, "target"),
            field(&vector, "api_key"),
            vector["ts"].as_u64().unwrap(),
            field(&vector, "nonce"),
        );
        let expected = field(&vector, "header");
        let prefix = &expected[..expected.rfind('.').unwrap() + 1];
        assert!(header.starts_with(prefix), "{header}");
        let signature = &header[prefix.len()..];
        assert_eq!(signature.len(), 86);
        assert!(verify(
            field(&vector, "public_key"),
            field(&vector, "message"),
            signature
        ));
        assert!(header.len() <= 256);
    }

    #[test]
    fn method_is_uppercased_and_target_keeps_raw_query() {
        let message = proof_message("post", "/v1/responses?a=%2F&b=", 1, "n", "k");
        assert!(message.starts_with("saiai-client-proof-v1\nPOST\n/v1/responses?a=%2F&b=\n1\nn\n"));
        assert!(!message.ends_with('\n'));
        for (url, target) in [
            (
                "https://gw.example/v1/messages?beta=true",
                "/v1/messages?beta=true",
            ),
            (
                "https://gw.example/prefix/v1/responses",
                "/prefix/v1/responses",
            ),
            ("https://gw.example", "/"),
            ("wss://gw.example/v1/responses?", "/v1/responses?"),
            ("http://gw.example/v1/x?a=%2Fb&a=a+b", "/v1/x?a=%2Fb&a=a+b"),
        ] {
            assert_eq!(wire_target(&Url::parse(url).unwrap()), target, "{url}");
        }
    }

    #[test]
    fn generated_device_pem_round_trips_and_is_private() {
        let directory = tempfile::tempdir().unwrap();
        let first = ClientProof::load(directory.path()).unwrap();
        let second = ClientProof::load(directory.path()).unwrap();
        assert_eq!(first.public_key, second.public_key);
        let pem = fs::read_to_string(directory.path().join(KEY_FILENAME)).unwrap();
        assert!(pem.starts_with(PEM_BEGIN));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(directory.path().join(KEY_FILENAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let format = format!("{first:?}");
        assert!(!format.contains(&pem[PEM_BEGIN.len() + 1..PEM_BEGIN.len() + 20]));
    }

    #[test]
    fn corrupted_device_pem_becomes_new_device_and_drops_old_records() {
        let directory = tempfile::tempdir().unwrap();
        let first = ClientProof::load(directory.path()).unwrap();
        first
            .record_device("https://gw.example", "k", "cd_old")
            .unwrap();
        fs::write(directory.path().join(KEY_FILENAME), "not a key").unwrap();
        let second = ClientProof::load(directory.path()).unwrap();
        assert_ne!(first.public_key, second.public_key);
        assert_eq!(second.device("https://gw.example", "k"), None);
        fs::write(directory.path().join(DEVICE_FILENAME), "{").unwrap();
        let third = ClientProof::load(directory.path()).unwrap();
        assert_eq!(third.public_key, second.public_key);
        assert_eq!(third.device("https://gw.example", "k"), None);
        fs::write(directory.path().join(KEY_FILENAME), [0xff, 0xfe, 0x00]).unwrap();
        let fourth = ClientProof::load(directory.path()).unwrap();
        assert_ne!(fourth.public_key, second.public_key);
    }

    #[test]
    fn signs_only_with_active_device_and_fresh_nonce() {
        let directory = tempfile::tempdir().unwrap();
        let proof = ClientProof::load(directory.path()).unwrap();
        let gateway = "https://gw.example";
        assert_eq!(proof.sign_request(gateway, "POST", "/v1/x", "k"), None);
        proof
            .record_device(gateway, "k", "cd_AAAAAAAAAAAAAAAAAAAAAA")
            .unwrap();
        let first = proof.sign_request(gateway, "POST", "/v1/x", "k").unwrap();
        let second = proof.sign_request(gateway, "POST", "/v1/x", "k").unwrap();
        let parts = first.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "v1");
        assert_eq!(parts[1], "cd_AAAAAAAAAAAAAAAAAAAAAA");
        assert!(parts[2].parse::<u64>().unwrap() > 1_700_000_000);
        assert_eq!(parts[3].len(), 22);
        assert_ne!(parts[3], second.split('.').nth(3).unwrap());
        let message = proof_message("POST", "/v1/x", parts[2].parse().unwrap(), parts[3], "k");
        assert!(verify(&proof.public_key, &message, parts[4]));
        assert_eq!(
            proof.sign_request("https://other.example", "POST", "/v1/x", "k"),
            None
        );
        // A different credential on the same Gateway has its own device record.
        assert_eq!(proof.sign_request(gateway, "POST", "/v1/x", "other"), None);
        proof.record_revoked(gateway, "k").unwrap();
        assert_eq!(proof.sign_request(gateway, "POST", "/v1/x", "k"), None);
        let reloaded = ClientProof::load(directory.path()).unwrap();
        assert!(reloaded.device(gateway, "k").unwrap().revoked);
        assert_eq!(reloaded.sign_request(gateway, "POST", "/v1/x", "k"), None);
    }

    #[test]
    fn classifies_enrollment_responses() {
        assert_eq!(
            classify_enroll_response(200, br#"{"device_id":"cd_x","status":"active"}"#),
            EnrollOutcome::Enrolled("cd_x".into())
        );
        assert!(matches!(
            classify_enroll_response(200, br#"{"device_id":"bad.id"}"#),
            EnrollOutcome::Stop(_)
        ));
        assert_eq!(
            classify_enroll_response(403, br#"{"code":"client_device_revoked"}"#),
            EnrollOutcome::Revoked
        );
        assert!(matches!(
            classify_enroll_response(403, br#"{"code":"other"}"#),
            EnrollOutcome::Stop(_)
        ));
        assert!(matches!(
            classify_enroll_response(429, br#"{"code":"client_device_limit"}"#),
            EnrollOutcome::Stop(_)
        ));
        assert!(matches!(
            classify_enroll_response(401, b""),
            EnrollOutcome::Stop(_)
        ));
        for status in [404, 500, 502, 503] {
            assert!(matches!(
                classify_enroll_response(status, b"<html>"),
                EnrollOutcome::Retry(_)
            ));
        }
    }

    /// Serves one canned response per connection and returns the requests.
    async fn mock_gateway(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0_u8; 16 * 1024];
                let mut read = 0;
                loop {
                    let n = stream.read(&mut buffer[read..]).await.unwrap();
                    read += n;
                    let text = String::from_utf8_lossy(&buffer[..read]);
                    if let Some(split) = text.find("\r\n\r\n") {
                        let length = text[..split]
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if read >= split + 4 + length {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                requests.push(String::from_utf8_lossy(&buffer[..read]).into_owned());
                // An empty body is announced as 64 bytes and then cut off.
                let declared = if body.is_empty() { 64 } else { body.len() };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n{body}"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (base, server)
    }

    #[tokio::test]
    async fn enrollment_retries_server_errors_then_records_device() {
        let (gateway, server) = mock_gateway(vec![
            (503, "{}"),
            (
                200,
                r#"{"device_id":"cd_BBBBBBBBBBBBBBBBBBBBBB","status":"active"}"#,
            ),
        ])
        .await;
        let directory = tempfile::tempdir().unwrap();
        let proof = Arc::new(ClientProof::load(directory.path()).unwrap());
        let device = Arc::clone(&proof)
            .enroll(
                reqwest::Client::new(),
                gateway.clone(),
                Zeroizing::new("MOCK_ONLY_KEY".into()),
                &FAST_RETRY,
            )
            .await
            .unwrap();
        assert_eq!(
            device.device_id.as_deref(),
            Some("cd_BBBBBBBBBBBBBBBBBBBBBB")
        );
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);
        let request = &requests[1];
        assert!(request.starts_with("POST /api/v1/client/devices/enroll HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer mock_only_key")
        );
        let body: Value =
            serde_json::from_str(&request[request.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        assert_eq!(body["public_key"], proof.public_key.as_str());
        assert_eq!(body["client_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["os"], std::env::consts::OS);
        assert_eq!(body["arch"], std::env::consts::ARCH);
        let reloaded = ClientProof::load(directory.path()).unwrap();
        assert!(
            reloaded
                .sign_request(&gateway, "GET", "/v1/models", "MOCK_ONLY_KEY")
                .is_some()
        );
    }

    #[tokio::test]
    async fn enrollment_revocation_persists_and_skips_later_enrollment() {
        let (gateway, server) =
            mock_gateway(vec![(403, r#"{"code":"client_device_revoked"}"#)]).await;
        let directory = tempfile::tempdir().unwrap();
        let proof = Arc::new(ClientProof::load(directory.path()).unwrap());
        proof
            .record_device(&gateway, "MOCK_ONLY_KEY", "cd_old")
            .unwrap();
        let device = Arc::clone(&proof)
            .enroll(
                reqwest::Client::new(),
                gateway.clone(),
                Zeroizing::new("MOCK_ONLY_KEY".into()),
                &FAST_RETRY,
            )
            .await
            .unwrap();
        assert!(device.revoked);
        assert_eq!(server.await.unwrap().len(), 1);
        assert_eq!(
            proof.sign_request(&gateway, "GET", "/", "MOCK_ONLY_KEY"),
            None
        );
        // A restarted process neither re-enrolls nor signs for this Gateway.
        let restarted = Arc::new(ClientProof::load(directory.path()).unwrap());
        let device = Arc::clone(&restarted)
            .enroll(
                reqwest::Client::new(),
                gateway.clone(),
                Zeroizing::new("MOCK_ONLY_KEY".into()),
                &[],
            )
            .await
            .unwrap();
        assert!(device.revoked);
        assert_eq!(
            restarted.sign_request(&gateway, "GET", "/", "MOCK_ONLY_KEY"),
            None
        );
    }

    #[tokio::test]
    async fn enrollment_device_limit_with_truncated_body_still_stops() {
        let (gateway, server) = mock_gateway(vec![(429, "")]).await;
        let directory = tempfile::tempdir().unwrap();
        let proof = Arc::new(ClientProof::load(directory.path()).unwrap());
        let device = Arc::clone(&proof)
            .enroll(
                reqwest::Client::new(),
                gateway,
                Zeroizing::new("MOCK_ONLY_KEY".into()),
                &FAST_RETRY,
            )
            .await;
        assert_eq!(device, None);
        assert_eq!(server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn enrollment_device_limit_stops_without_retry() {
        let (gateway, server) =
            mock_gateway(vec![(429, r#"{"code":"client_device_limit"}"#)]).await;
        let directory = tempfile::tempdir().unwrap();
        let proof = Arc::new(ClientProof::load(directory.path()).unwrap());
        let device = Arc::clone(&proof)
            .enroll(
                reqwest::Client::new(),
                gateway.clone(),
                Zeroizing::new("MOCK_ONLY_KEY".into()),
                &FAST_RETRY,
            )
            .await;
        assert_eq!(device, None);
        assert_eq!(server.await.unwrap().len(), 1);
        assert_eq!(
            proof.sign_request(&gateway, "GET", "/", "MOCK_ONLY_KEY"),
            None
        );
    }

    #[tokio::test]
    async fn enrollment_network_failure_backs_off() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let directory = tempfile::tempdir().unwrap();
        let proof = Arc::new(ClientProof::load(directory.path()).unwrap());
        let enrollment = tokio::spawn(Arc::clone(&proof).enroll(
            reqwest::Client::new(),
            gateway,
            Zeroizing::new("MOCK_ONLY_KEY".into()),
            &SLOW_RETRY,
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!enrollment.is_finished());
        enrollment.abort();
    }
}
