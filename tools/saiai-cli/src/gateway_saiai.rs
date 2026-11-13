//! SAIAI Gateway extension: the client device proof.
//!
//! An adapter around [`ClientProof`] that keeps its lifecycle exactly as it
//! was inside the local proxy: the key is loaded and the configured routes
//! are enrolled in the background, signing starts as soon as the key is
//! loaded (without waiting for enrollment), unknown Bearers get bounded
//! on-demand enrollment, and every problem leaves requests unsigned.

use crate::client_proof::{self, ClientProof};
use crate::{
    ConfiguredRoute, GatewayExtension, GatewayHttp, GatewaySession, GatewayStart,
    NativeChatProtocol, SignInput, StateFile,
};
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

/// The SAIAI Gateway's Native Chat update channel and the response header
/// marking a restored Chat preference.
const CHAT_UPDATES_PATH: &str = "/backend-api/saiai/chat-updates";
const CHAT_PREFERENCE_RESTORED_HEADER: &str = "x-saiai-chat-preference-restored";

/// The SAIAI Gateway extension instance.
pub static SAIAI_GATEWAY: SaiaiGateway = SaiaiGateway { _instance: () };

pub struct SaiaiGateway {
    _instance: (),
}

impl GatewayExtension for SaiaiGateway {
    fn signature_headers(&self) -> &'static [&'static str] {
        &[client_proof::HEADER_NAME]
    }

    /// The device key, its records, their lock and an unreadable key kept
    /// aside, each with backups and atomic-write leftovers.
    fn owned_state_files(&self) -> &'static [StateFile] {
        const fn family(name: &'static str) -> StateFile {
            StateFile {
                name,
                backups: true,
                atomic_temporaries: true,
            }
        }
        const FILES: &[StateFile] = &[
            family(client_proof::KEY_FILENAME),
            family(client_proof::DEVICE_FILENAME),
            family(client_proof::LOCK_FILENAME),
            family(client_proof::CORRUPT_KEY_FILENAME),
        ];
        FILES
    }

    /// The SAIAI Gateway relays ordinary Chat for the official Desktop.
    fn native_chat(&self) -> Option<NativeChatProtocol> {
        Some(NativeChatProtocol {
            updates_path: CHAT_UPDATES_PATH,
            preference_restored_header: CHAT_PREFERENCE_RESTORED_HEADER,
            // The historical local bootstrap placeholder is never a provider
            // proof; a real registration replaces it on startup.
            rejected_device_proofs: &["saiai-local-proxy"],
        })
    }

    fn start(&self, start: GatewayStart) -> Arc<dyn GatewaySession> {
        start_session(start)
    }
}

/// [`SaiaiGateway::start`], returning the concrete session.
fn start_session(start: GatewayStart) -> Arc<SaiaiSession> {
    let session = Arc::new(SaiaiSession {
        proof: OnceLock::new(),
        http: start.http,
        runtime: start.runtime.clone(),
    });
    let Some(dir) = start.state_dir else {
        return session;
    };
    let version = start.version;
    let routes = start.routes;
    let loader = Arc::clone(&session);
    start.runtime.spawn(async move {
        let proof =
            match tokio::task::spawn_blocking(move || ClientProof::load_for_version(&dir, version))
                .await
            {
                Ok(Ok(proof)) => Arc::new(proof),
                Ok(Err(err)) => {
                    eprintln!("client proof disabled: {err:#}");
                    return;
                }
                Err(err) => {
                    eprintln!("client proof disabled: {err}");
                    return;
                }
            };
        // Claim the configured routes before publishing the key so they
        // never count against the on-demand budget.
        for route in &routes {
            loader.start_enrollment(&proof, route, false);
        }
        let _ = loader.proof.set(proof);
    });
    session
}

/// Belongs to one local proxy run: it spawns enrollment on the runtime that
/// started it (the run's runtime) and must not outlive it or be used from
/// another runtime.
pub(crate) struct SaiaiSession {
    // Set by the background loader; until then requests are sent unsigned.
    proof: OnceLock<Arc<ClientProof>>,
    http: Arc<dyn GatewayHttp>,
    runtime: tokio::runtime::Handle,
}

impl SaiaiSession {
    fn start_enrollment(&self, proof: &Arc<ClientProof>, route: &ConfiguredRoute, on_demand: bool) {
        self.enroll(proof, &route.base_url, &route.api_key, on_demand);
    }

    fn enroll(&self, proof: &Arc<ClientProof>, gateway: &str, api_key: &str, on_demand: bool) {
        if !proof.claim_enrollment(gateway, api_key, on_demand) {
            return;
        }
        self.runtime.spawn(Arc::clone(proof).enroll(
            Arc::clone(&self.http),
            gateway.to_string(),
            Zeroizing::new(api_key.to_string()),
            &client_proof::ENROLL_BACKOFF,
        ));
    }
}

impl GatewaySession for SaiaiSession {
    /// Proof header for one Gateway request attempt; `bearer` is the exact
    /// API key carried in its `Authorization: Bearer` header. A Bearer not
    /// enrolled by this process yet (e.g. a Claude credential that differs
    /// from the configured route key) gets one bounded background enrollment.
    fn sign(&self, input: &SignInput<'_>) -> Vec<(String, String)> {
        let Some(proof) = self.proof.get() else {
            return Vec::new();
        };
        let Some(bearer) = input.bearer else {
            return Vec::new();
        };
        self.enroll(proof, input.gateway, bearer, true);
        proof
            .sign_request(input.gateway, input.method, input.target, bearer)
            .map(|value| vec![(client_proof::HEADER_NAME.to_string(), value)])
            .unwrap_or_default()
    }
}

/// The SAIAI session lifecycle, driven through the extension interface the
/// kernel calls (moved from the kernel's proxy tests, which now use the
/// kernel's own test extension).
#[cfg(all(test, feature = "contract"))]
mod tests {
    use super::*;
    use crate::{SignInput, Transport};
    use base64::Engine as _;
    use futures_util::future::BoxFuture;
    use std::path::Path;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    const KEY: &str = "MOCK_ONLY_GATEWAY";
    const DEVICE: &str = "cd_MOCKMOCKMOCKMOCKMOCK00";

    /// The SAIAI brand and runtime, as the program installs them (the
    /// session writes its files through the brand's atomic writer).
    fn saiai() {
        crate::contract::install(
            &crate::brand_saiai::SAIAI_BRAND,
            crate::RuntimeContext {
                version: env!("CARGO_PKG_VERSION"),
                gateway: &SAIAI_GATEWAY,
            },
        )
        .unwrap();
    }

    struct DirectHttp;

    impl GatewayHttp for DirectHttp {
        fn client_for<'a>(
            &'a self,
            _url: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<reqwest::Client>> {
            Box::pin(async { Ok(reqwest::Client::builder().no_proxy().build()?) })
        }
    }

    #[derive(Clone, Copy)]
    enum Enroll {
        /// Answer 429, which ends that enrollment.
        TooMany,
        /// Hold the connection open, never answering.
        Hold,
    }

    /// A mock Gateway; every request's text is sent to the receiver.
    async fn gateway(enroll: Enroll) -> (String, mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, receiver) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    request.extend_from_slice(&buffer[..read]);
                    let text = String::from_utf8_lossy(&request).to_string();
                    let complete = text.find("\r\n\r\n").is_some_and(|split| {
                        let length = text[..split]
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        request.len() >= split + 4 + length
                    });
                    if complete || read == 0 {
                        break;
                    }
                }
                let _ = sender.send(String::from_utf8_lossy(&request).to_string());
                match enroll {
                    Enroll::Hold => held.push(stream),
                    Enroll::TooMany => {
                        let _ = stream
                            .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                            .await;
                    }
                }
            }
        });
        (url, receiver)
    }

    fn start(state_dir: Option<&Path>, routes: &[(&str, &str)]) -> Arc<SaiaiSession> {
        start_session(GatewayStart {
            state_dir: state_dir.map(Path::to_path_buf),
            routes: routes
                .iter()
                .map(|(base_url, key)| ConfiguredRoute {
                    base_url: base_url.to_string(),
                    api_key: Zeroizing::new(key.to_string()),
                })
                .collect(),
            http: Arc::new(DirectHttp),
            runtime: tokio::runtime::Handle::current(),
            version: "test-version",
        })
    }

    async fn loaded(session: &SaiaiSession) -> Arc<ClientProof> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(proof) = session.proof.get() {
                    return Arc::clone(proof);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the key is loaded in the background")
    }

    async fn next_enrollment(requests: &mut mpsc::UnboundedReceiver<String>) -> String {
        let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
            .await
            .expect("an enrollment request")
            .unwrap();
        assert!(
            request.starts_with("POST /api/v1/client/devices/enroll HTTP/1.1\r\n"),
            "{request}"
        );
        request
    }

    fn sign(
        session: &SaiaiSession,
        gateway: &str,
        method: &str,
        target: &str,
        bearer: Option<&str>,
    ) -> Vec<(String, String)> {
        session.sign(&SignInput {
            transport: Transport::Http,
            gateway,
            method,
            target,
            bearer,
        })
    }

    /// A proof header verifies for (METHOD, target, key) with the loaded key.
    fn verify(proof: &ClientProof, header: &str, method: &str, target: &str, key: &str) -> String {
        use p256::ecdsa::signature::Verifier;
        let parts = header.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 5, "{header}");
        assert_eq!(parts[..2], ["v1", DEVICE]);
        let message =
            client_proof::proof_message(method, target, parts[2].parse().unwrap(), parts[3], key);
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let public =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&engine.decode(proof.public_key()).unwrap())
                .unwrap();
        let signature =
            p256::ecdsa::Signature::from_slice(&engine.decode(parts[4]).unwrap()).unwrap();
        public
            .verify(message.as_bytes(), &signature)
            .expect("client proof must verify");
        parts[3].to_string()
    }

    /// `start` returns at once; the key is created and loaded in the
    /// background and the configured route is enrolled with its own key.
    #[tokio::test]
    async fn the_key_loads_in_the_background_and_configured_routes_enroll() {
        saiai();
        let (url, mut requests) = gateway(Enroll::TooMany).await;
        let directory = tempfile::tempdir().unwrap();
        let session = start(Some(directory.path()), &[(&url, KEY)]);
        let enrollment = next_enrollment(&mut requests).await;
        assert!(
            enrollment.to_ascii_lowercase().contains(&format!(
                "authorization: bearer {}",
                KEY.to_ascii_lowercase()
            )),
            "{enrollment}"
        );
        loaded(&session).await;
        assert!(directory.path().join("client-device-key").exists());
        // No state directory: nothing is loaded or signed.
        let stateless = start(None, &[(&url, KEY)]);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(stateless.proof.get().is_none());
        assert!(sign(&stateless, &url, "POST", "/v1/messages", Some(KEY)).is_empty());
    }

    /// Signing starts as soon as the key is loaded, while the configured
    /// route's enrollment is still in flight, and that configured claim uses
    /// none of the on-demand enrollment budget. Every attempt gets a fresh,
    /// verifiable proof of the method (any case), wire target and key.
    #[tokio::test]
    async fn signing_does_not_wait_for_enrollment_and_configured_routes_use_no_budget() {
        saiai();
        let (url, mut requests) = gateway(Enroll::Hold).await;
        let directory = tempfile::tempdir().unwrap();
        ClientProof::load_for_version(directory.path(), "test-version")
            .unwrap()
            .record_device(&url, KEY, DEVICE)
            .unwrap();
        let session = start(Some(directory.path()), &[(&url, KEY)]);
        next_enrollment(&mut requests).await;
        let proof = loaded(&session).await;
        let mut nonces = std::collections::HashSet::new();
        for target in ["/v1/messages", "/prefix/v1/responses?future=a%2Fb&x="] {
            for _ in 0..2 {
                let headers = sign(&session, &url, "post", target, Some(KEY));
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].0, "x-saiai-client-proof");
                assert!(nonces.insert(verify(&proof, &headers[0].1, "POST", target, KEY)));
            }
        }
        // The whole on-demand budget (16 extra credentials) is still available.
        for index in 0..16 {
            assert!(proof.claim_enrollment(&url, &format!("TEST_ONLY_EXTRA_{index}"), true));
        }
        assert!(!proof.claim_enrollment(&url, "TEST_ONLY_EXTRA_16", true));
    }

    /// Unenrolled credentials and non-Bearer requests stay unsigned; an
    /// unknown Bearer is enrolled on demand in the background.
    #[tokio::test]
    async fn unenrolled_requests_stay_unsigned_and_unknown_bearers_enroll_on_demand() {
        saiai();
        for (enrolled, bearer, enrolls) in [
            (false, Some("MOCK_ONLY_CLIENT"), true),
            (true, None, false),
            (true, Some("MOCK_ONLY_OTHER_USER"), true),
        ] {
            let (url, mut requests) = gateway(Enroll::TooMany).await;
            let directory = tempfile::tempdir().unwrap();
            if enrolled {
                ClientProof::load_for_version(directory.path(), "test-version")
                    .unwrap()
                    .record_device(&url, KEY, DEVICE)
                    .unwrap();
            }
            let session = start(Some(directory.path()), &[]);
            loaded(&session).await;
            assert!(sign(&session, &url, "POST", "/v1/messages", bearer).is_empty());
            if enrolls {
                let enrollment = next_enrollment(&mut requests).await;
                let expected = format!("authorization: bearer {}", bearer.unwrap());
                assert!(
                    enrollment
                        .to_ascii_lowercase()
                        .contains(&expected.to_ascii_lowercase()),
                    "{enrollment}"
                );
            } else {
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert!(requests.try_recv().is_err());
            }
        }
    }

    /// A state directory that cannot hold the key disables the proof: the
    /// session keeps answering, unsigned.
    #[tokio::test]
    async fn an_unusable_state_directory_leaves_requests_unsigned() {
        saiai();
        let (url, _requests) = gateway(Enroll::TooMany).await;
        let root = tempfile::tempdir().unwrap();
        let blocked = root.path().join("not-a-directory");
        std::fs::write(&blocked, b"file").unwrap();
        let session = start(Some(&blocked), &[(&url, KEY)]);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(session.proof.get().is_none());
        assert!(sign(&session, &url, "POST", "/v1/messages", Some(KEY)).is_empty());
    }
}
