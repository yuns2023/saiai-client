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
            let proof = match tokio::task::spawn_blocking(move || {
                ClientProof::load_for_version(&dir, version)
            })
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

    /// Test access to the loaded proof.
    #[cfg(test)]
    pub(crate) fn proof(&self) -> Option<&Arc<ClientProof>> {
        self.proof.get()
    }

    /// A session with an already loaded proof (tests).
    #[cfg(test)]
    pub(crate) fn with_proof(
        proof: Arc<ClientProof>,
        http: Arc<dyn GatewayHttp>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        let session = Self {
            proof: OnceLock::new(),
            http,
            runtime,
        };
        let _ = session.proof.set(proof);
        session
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

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
