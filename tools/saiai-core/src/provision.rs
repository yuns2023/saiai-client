use std::fmt;
use std::time::Duration;

use futures_util::StreamExt;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::json;
use toml_edit::{DocumentMut, Item, Table, value};
use zeroize::Zeroizing;

use crate::{
    CLAUDE_STREAM_IDLE_TIMEOUT_ENV, CLAUDE_STREAM_IDLE_TIMEOUT_VALUE, ClaudeSetupArtifacts,
    CodexSetupArtifacts, Error, GatewayUrl, Product, ProductSetupArtifacts, Result, SaiaiCore,
    SecretString, SetupRequest, SetupStatus,
};

pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 2;

const BOOTSTRAP_PATH: &str = "/api/v1/client/bootstrap";
const MAX_BOOTSTRAP_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_GATEWAY_VERSION_BYTES: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(20);

/// Effective routing capabilities for the authenticated API key.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapCapabilities {
    #[serde(default)]
    pub claude: bool,
    #[serde(default)]
    pub codex: bool,
    #[serde(default)]
    pub codex_responses: bool,
    #[serde(default)]
    pub codex_websockets: bool,
    /// Informational compatibility feature. It never satisfies native Claude
    /// routing for V2 Claude setup.
    #[serde(default)]
    pub openai_messages_dispatch: bool,
}

/// Authenticated, non-billable gateway metadata returned during provision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapData {
    pub schema_version: u32,
    #[serde(deserialize_with = "deserialize_gateway_version")]
    pub gateway_version: String,
    pub capabilities: BootstrapCapabilities,
}

/// Complete non-secret result shared by CLI and Tauri callers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProvisionReport {
    pub product: Product,
    pub bootstrap: BootstrapData,
    pub setup: SetupStatus,
}

/// Validated input for one authenticated product provision.
pub struct ProvisionRequest {
    base_url: GatewayUrl,
    credential: SecretString,
}

impl ProvisionRequest {
    pub fn new(base_url: &str, credential: impl Into<String>) -> Result<Self> {
        // Wrap first so an invalid URL does not leave the credential in a
        // normal String during struct-field evaluation.
        let credential = SecretString::new(credential)?;
        Self::from_validated(GatewayUrl::parse(base_url)?, credential)
    }

    pub fn from_validated(base_url: GatewayUrl, credential: SecretString) -> Result<Self> {
        base_url.reject_credential_url_component(&credential)?;
        Ok(Self {
            base_url,
            credential,
        })
    }

    pub fn base_url(&self) -> &GatewayUrl {
        &self.base_url
    }
}

impl fmt::Debug for ProvisionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionRequest")
            .field("base_url", &self.base_url)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl SaiaiCore {
    /// Validate and atomically provision only `product`. No model endpoint is
    /// called and the other product's state is not replaced.
    pub async fn provision(
        &self,
        product: Product,
        request: ProvisionRequest,
    ) -> Result<ProvisionReport> {
        self.validate_shared_base_url(product, &request.base_url)?;
        let bootstrap = fetch_bootstrap(&request.base_url, &request.credential).await?;
        validate_required_capabilities(product, &bootstrap.capabilities)?;
        let artifacts =
            build_product_artifacts(product, &request.base_url, &bootstrap.capabilities)?;
        let setup_request = SetupRequest::from_validated(request.base_url, request.credential)?;
        let setup = self.setup_product_with_artifacts(setup_request, artifacts)?;
        Ok(ProvisionReport {
            product,
            bootstrap,
            setup,
        })
    }
}

#[derive(Deserialize)]
struct BootstrapEnvelope {
    code: i64,
    data: Option<BootstrapData>,
}

async fn fetch_bootstrap(
    service_root: &GatewayUrl,
    credential: &SecretString,
) -> Result<BootstrapData> {
    let endpoint = bootstrap_endpoint(service_root);
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .build()
        .map_err(|_| Error::BootstrapClient)?;
    let response = client
        .get(endpoint)
        .bearer_auth(credential.expose_secret())
        .send()
        .await
        .map_err(|_| Error::BootstrapTransport)?;
    let status = response.status();
    if !status.is_success() {
        return Err(bootstrap_http_error(status));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BOOTSTRAP_RESPONSE_BYTES as u64)
    {
        return Err(Error::BootstrapResponseTooLarge);
    }

    let mut bytes = Zeroizing::new(Vec::new());
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|_| Error::BootstrapTransport)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_BOOTSTRAP_RESPONSE_BYTES {
            return Err(Error::BootstrapResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }

    let envelope: BootstrapEnvelope = serde_json::from_slice(&bytes)
        .map_err(|_| Error::InvalidBootstrapResponse("expected a JSON success envelope"))?;
    if envelope.code != 0 {
        return Err(Error::InvalidBootstrapResponse(
            "the success envelope code is not numeric zero",
        ));
    }
    let data = envelope.data.ok_or(Error::InvalidBootstrapResponse(
        "the success envelope does not contain data",
    ))?;
    if data.schema_version != BOOTSTRAP_SCHEMA_VERSION {
        return Err(Error::InvalidBootstrapResponse(
            "the bootstrap schema version is unsupported",
        ));
    }
    if data.gateway_version.contains(credential.expose_secret()) {
        return Err(Error::InvalidBootstrapResponse(
            "the gateway version is not safe to report",
        ));
    }
    Ok(data)
}

fn bootstrap_endpoint(service_root: &GatewayUrl) -> String {
    format!(
        "{}{}",
        service_root.as_str().trim_end_matches('/'),
        BOOTSTRAP_PATH
    )
}

fn bootstrap_http_error(status: StatusCode) -> Error {
    let category = match status {
        StatusCode::UNAUTHORIZED => "invalid credential",
        StatusCode::FORBIDDEN => "credential not permitted",
        StatusCode::NOT_FOUND => "bootstrap endpoint unavailable",
        StatusCode::TOO_MANY_REQUESTS => "rate limited",
        status if status.is_server_error() => "gateway unavailable",
        status if status.is_redirection() => "redirect refused",
        _ => "request rejected",
    };
    Error::BootstrapHttp {
        status: status.as_u16(),
        category,
    }
}

fn validate_required_capabilities(
    product: Product,
    capabilities: &BootstrapCapabilities,
) -> Result<()> {
    match product {
        Product::Claude if !capabilities.claude => Err(Error::IncompatibleGateway(
            "the API key cannot route native Claude requests for Claude setup",
        )),
        Product::Codex if !capabilities.codex => Err(Error::IncompatibleGateway(
            "the API key cannot route Codex requests for Codex setup",
        )),
        Product::Codex if !capabilities.codex_responses => Err(Error::IncompatibleGateway(
            "the API key cannot use the Codex Responses API for Codex setup",
        )),
        _ => Ok(()),
    }
}

fn build_product_artifacts(
    product: Product,
    service_root: &GatewayUrl,
    capabilities: &BootstrapCapabilities,
) -> Result<ProductSetupArtifacts> {
    match product {
        Product::Claude => {
            let (ca_certificate_pem, ca_private_key_pem) = generate_installation_ca()?;
            let settings = serde_json::to_vec_pretty(&json!({
                "env": {
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    (CLAUDE_STREAM_IDLE_TIMEOUT_ENV): CLAUDE_STREAM_IDLE_TIMEOUT_VALUE,
                    "ENABLE_PROMPT_CACHING_1H": "1",
                    "ENABLE_TOOL_SEARCH": "true"
                }
            }))
            .map_err(|_| Error::InvalidArtifact {
                artifact: "settings.json",
                reason: "could not generate clean Claude settings".into(),
            })?;
            let state = serde_json::to_vec_pretty(&json!({
                "hasCompletedOnboarding": true
            }))
            .map_err(|_| Error::InvalidArtifact {
                artifact: ".claude.json",
                reason: "could not generate clean Claude state".into(),
            })?;
            Ok(ProductSetupArtifacts::Claude(ClaudeSetupArtifacts::new(
                settings,
                state,
                ca_certificate_pem,
                ca_private_key_pem,
            )?))
        }
        Product::Codex => Ok(ProductSetupArtifacts::Codex(CodexSetupArtifacts::new(
            build_codex_config(service_root, capabilities)?,
        )?)),
    }
}

fn generate_installation_ca() -> Result<(String, String)> {
    let key = KeyPair::generate().map_err(|error| Error::InvalidArtifact {
        artifact: "saiai-ca.key",
        reason: format!("could not generate installation key: {error}"),
    })?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|error| Error::InvalidArtifact {
            artifact: "saiai-ca.crt",
            reason: format!("could not create installation CA parameters: {error}"),
        })?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "SAIAI local installation CA");
    distinguished_name.push(DnType::OrganizationName, "SAIAI");
    params.distinguished_name = distinguished_name;
    let certificate = params
        .self_signed(&key)
        .map_err(|error| Error::InvalidArtifact {
            artifact: "saiai-ca.crt",
            reason: format!("could not self-sign installation CA: {error}"),
        })?;
    Ok((certificate.pem(), key.serialize_pem()))
}

fn build_codex_config(
    service_root: &GatewayUrl,
    capabilities: &BootstrapCapabilities,
) -> Result<String> {
    let mut document = DocumentMut::new();
    document["model_provider"] = value("saiai");
    document["disable_response_storage"] = value(true);
    document["model_providers"] = Item::Table(Table::new());
    let providers = document["model_providers"]
        .as_table_mut()
        .expect("new model_providers table");
    providers.insert("saiai", Item::Table(Table::new()));
    let provider = providers
        .get_mut("saiai")
        .and_then(Item::as_table_mut)
        .expect("new SAIAI provider table");
    provider.insert("name", value("SAIAI"));
    provider.insert(
        "base_url",
        value(service_root.as_str().trim_end_matches('/')),
    );
    provider.insert("wire_api", value("responses"));
    provider.insert("requires_openai_auth", value(false));
    provider.insert("env_key", value("SAIAI_CODEX_API_KEY"));

    if capabilities.codex_websockets {
        provider.insert("supports_websockets", value(true));
        document["features"] = Item::Table(Table::new());
        document["features"]["responses_websockets_v2"] = value(true);
    }

    let rendered = document.to_string();
    rendered
        .parse::<DocumentMut>()
        .map_err(|_| Error::InvalidArtifact {
            artifact: "config.toml",
            reason: "generated Codex configuration is invalid".into(),
        })?;
    Ok(rendered)
}

fn deserialize_gateway_version<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let version = String::deserialize(deserializer)?;
    // This value is rendered in CLI/UI diagnostics, and real gateway versions
    // need no Unicode. Restrict it to ordinary printable ASCII (plus a normal
    // space) so bidi, zero-width, ANSI, and future Unicode format controls are
    // rejected as a class rather than maintained as a fragile denylist.
    let display_safe = version
        .bytes()
        .all(|byte| byte == b' ' || byte.is_ascii_graphic());
    if version.len() > MAX_GATEWAY_VERSION_BYTES || !display_safe {
        return Err(de::Error::custom("gateway_version is not safe to display"));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{self, Receiver};
    use std::thread::JoinHandle;

    use crate::{AppPaths, ProductSetupState, SetupState};

    struct Fixture {
        _temp: tempfile::TempDir,
        core: SaiaiCore,
        legacy_sentinels: Vec<(PathBuf, Vec<u8>)>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            let paths = AppPaths::from_app_dirs(
                root.join("xdg-config/saiai"),
                root.join("xdg-data/saiai"),
                root.join("xdg-state/saiai"),
            )
            .unwrap();
            let legacy_sentinels = [".saiai", ".claude", ".codex"]
                .into_iter()
                .map(|directory| {
                    let path = root.join("home").join(directory).join("sentinel");
                    let contents = format!("legacy-{directory}").into_bytes();
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    fs::write(&path, &contents).unwrap();
                    (path, contents)
                })
                .collect();
            Self {
                _temp: temp,
                core: SaiaiCore::new(paths),
                legacy_sentinels,
            }
        }

        fn assert_legacy_untouched(&self) {
            for (path, expected) in &self.legacy_sentinels {
                assert_eq!(&fs::read(path).unwrap(), expected);
            }
        }
    }

    struct MockServer {
        service_root: String,
        request: Receiver<Vec<u8>>,
        worker: Option<JoinHandle<()>>,
    }

    impl MockServer {
        fn finish(mut self) -> Vec<u8> {
            let request = self.request.recv().unwrap();
            self.worker.take().unwrap().join().unwrap();
            request
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    fn spawn_server(
        prefix: &str,
        responder: impl FnOnce(TcpStream) + Send + 'static,
    ) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0, "client closed before sending all headers");
                request.extend_from_slice(&buffer[..count]);
                assert!(request.len() <= 64 * 1024, "request headers are too large");
            }
            request_tx.send(request).unwrap();
            responder(stream);
        });
        MockServer {
            service_root: format!("http://{address}{prefix}"),
            request: request_rx,
            worker: Some(worker),
        }
    }

    fn response(status: &str, body: impl AsRef<[u8]>, extra_headers: &str) -> Vec<u8> {
        let body = body.as_ref();
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn spawn_fixed_server(prefix: &str, raw_response: Vec<u8>) -> MockServer {
        spawn_server(prefix, move |mut stream| {
            stream.write_all(&raw_response).unwrap();
        })
    }

    fn bootstrap_body(
        schema: u32,
        claude: bool,
        codex: bool,
        codex_responses: bool,
        dispatch: bool,
    ) -> Vec<u8> {
        bootstrap_body_with_websockets(schema, claude, codex, codex_responses, false, dispatch)
    }

    fn bootstrap_body_with_websockets(
        schema: u32,
        claude: bool,
        codex: bool,
        codex_responses: bool,
        codex_websockets: bool,
        dispatch: bool,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "code": 0,
            "message": "success",
            "future_envelope_field": true,
            "data": {
                "schema_version": schema,
                "gateway_version": "test-gateway-2.0.0",
                "future_data_field": [1, 2],
                "capabilities": {
                    "claude": claude,
                    "codex": codex,
                    "codex_responses": codex_responses,
                    "codex_websockets": codex_websockets,
                    "openai_messages_dispatch": dispatch,
                    "future_capability": true
                }
            }
        }))
        .unwrap()
    }

    fn header_value<'a>(request: &'a str, expected_name: &str) -> Option<&'a str> {
        request.lines().skip(1).find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected_name)
                .then(|| value.trim())
        })
    }

    fn all_file_contents(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        if !root.exists() {
            return Vec::new();
        }
        let mut pending = vec![root.to_path_buf()];
        let mut contents = Vec::new();
        while let Some(path) = pending.pop() {
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                pending.extend(
                    fs::read_dir(path)
                        .unwrap()
                        .map(|entry| entry.unwrap().path()),
                );
            } else if metadata.is_file() {
                contents.push((path.clone(), fs::read(path).unwrap()));
            }
        }
        contents
    }

    #[tokio::test]
    async fn claude_provision_requires_only_native_claude_and_writes_only_claude() {
        let api_key = "sk-claude-provision-only-secret";
        let server = spawn_fixed_server(
            "/tenant/",
            response("200 OK", bootstrap_body(2, true, false, false, false), ""),
        );
        let fixture = Fixture::new();
        let request = ProvisionRequest::new(&server.service_root, api_key).unwrap();
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(api_key));
        assert!(request_debug.contains("REDACTED"));
        let report = fixture
            .core
            .provision(Product::Claude, request)
            .await
            .unwrap();
        assert_eq!(report.product, Product::Claude);
        assert_eq!(report.setup.state, SetupState::Ready);
        assert_eq!(
            report
                .setup
                .products
                .iter()
                .find(|status| status.product == Product::Codex)
                .unwrap()
                .state,
            ProductSetupState::Unconfigured
        );
        for rendered in [
            format!("{report:?}"),
            serde_json::to_string(&report).unwrap(),
        ] {
            assert!(!rendered.contains(api_key));
            assert!(!rendered.contains("PRIVATE KEY"));
        }
        let claude_home = fixture.core.client_home(Product::Claude).unwrap();
        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(claude_home.join("settings.json")).unwrap()).unwrap();
        assert_eq!(
            settings["env"][CLAUDE_STREAM_IDLE_TIMEOUT_ENV],
            CLAUDE_STREAM_IDLE_TIMEOUT_VALUE
        );
        assert_eq!(
            settings["env"]["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"],
            "1"
        );
        assert!(settings.get("oauthAccount").is_none());
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(claude_home.join(".claude.json")).unwrap()).unwrap();
        assert_eq!(state["hasCompletedOnboarding"], true);
        assert!(claude_home.join("saiai-ca.crt").is_file());
        assert!(claude_home.join("saiai-ca.key").is_file());
        assert!(matches!(
            fixture.core.client_home(Product::Codex),
            Err(Error::ProductNotConfigured(Product::Codex))
        ));

        let request = String::from_utf8(server.finish()).unwrap();
        assert!(request.starts_with("GET /tenant/api/v1/client/bootstrap "));
        assert_eq!(
            header_value(&request, "authorization"),
            Some("Bearer sk-claude-provision-only-secret")
        );

        let credentials = fixture.core.paths().credentials_dir();
        let allowed_private_key = claude_home.join("saiai-ca.key");
        for root in [
            fixture.core.paths().config_dir(),
            fixture.core.paths().data_dir(),
            fixture.core.paths().state_dir(),
        ] {
            for (path, contents) in all_file_contents(root) {
                if path.starts_with(&credentials) {
                    continue;
                }
                assert!(
                    !contents
                        .windows(api_key.len())
                        .any(|window| window == api_key.as_bytes()),
                    "API key leaked to {}",
                    path.display()
                );
                if contents
                    .windows(b"PRIVATE KEY".len())
                    .any(|window| window == b"PRIVATE KEY")
                {
                    assert_eq!(
                        path, allowed_private_key,
                        "installation private key leaked outside its product-owned key file"
                    );
                }
            }
        }
        assert!(
            fs::read(&allowed_private_key)
                .unwrap()
                .windows(b"PRIVATE KEY".len())
                .any(|window| window == b"PRIVATE KEY")
        );
        fixture.assert_legacy_untouched();
    }

    #[tokio::test]
    async fn codex_provision_requires_codex_responses_and_writes_only_codex() {
        let api_key = "sk-codex-clean-secret";
        let server = spawn_fixed_server(
            "",
            response("200 OK", bootstrap_body(2, false, true, true, true), ""),
        );
        let fixture = Fixture::new();
        let report = fixture
            .core
            .provision(
                Product::Codex,
                ProvisionRequest::new(&server.service_root, api_key).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(report.setup.state, SetupState::Ready);
        let config = fs::read_to_string(
            fixture
                .core
                .client_home(Product::Codex)
                .unwrap()
                .join("config.toml"),
        )
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
        assert_eq!(
            config["model_providers"]["saiai"]["wire_api"].as_str(),
            Some("responses")
        );
        assert_eq!(
            config["model_providers"]["saiai"]["env_key"].as_str(),
            Some("SAIAI_CODEX_API_KEY")
        );
        assert_eq!(
            config["model_providers"]["saiai"]["requires_openai_auth"].as_bool(),
            Some(false)
        );
        assert_eq!(config["disable_response_storage"].as_bool(), Some(true));
        assert!(config.get("model").is_none());
        assert!(config.get("features").is_none());
        assert!(!config.to_string().contains("OPENAI_API_KEY"));
        let codex_home = fixture.core.client_home(Product::Codex).unwrap();
        assert!(!codex_home.join("auth.json").exists());
        assert!(!codex_home.join(".credentials.json").exists());
        assert!(matches!(
            fixture.core.client_home(Product::Claude),
            Err(Error::ProductNotConfigured(Product::Claude))
        ));

        let credentials = fixture.core.paths().credentials_dir();
        for root in [
            fixture.core.paths().config_dir(),
            fixture.core.paths().data_dir(),
            fixture.core.paths().state_dir(),
        ] {
            for (path, contents) in all_file_contents(root) {
                if path.starts_with(&credentials) {
                    continue;
                }
                assert!(
                    !contents
                        .windows(api_key.len())
                        .any(|window| window == api_key.as_bytes()),
                    "API key leaked to {}",
                    path.display()
                );
                assert!(
                    !contents
                        .windows(b"PRIVATE KEY".len())
                        .any(|window| window == b"PRIVATE KEY"),
                    "unexpected private key in {}",
                    path.display()
                );
            }
        }
        server.finish();
    }

    #[tokio::test]
    async fn websocket_capability_controls_both_codex_websocket_settings() {
        for enabled in [false, true] {
            let server = spawn_fixed_server(
                "",
                response(
                    "200 OK",
                    bootstrap_body_with_websockets(2, false, true, true, enabled, false),
                    "",
                ),
            );
            let fixture = Fixture::new();
            let report = fixture
                .core
                .provision(
                    Product::Codex,
                    ProvisionRequest::new(&server.service_root, "sk-websocket").unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(report.bootstrap.capabilities.codex_websockets, enabled);
            let config = fs::read_to_string(
                fixture
                    .core
                    .client_home(Product::Codex)
                    .unwrap()
                    .join("config.toml"),
            )
            .unwrap()
            .parse::<DocumentMut>()
            .unwrap();
            if enabled {
                assert_eq!(
                    config["model_providers"]["saiai"]["supports_websockets"].as_bool(),
                    Some(true)
                );
                assert_eq!(
                    config["features"]["responses_websockets_v2"].as_bool(),
                    Some(true)
                );
            } else {
                assert!(
                    config["model_providers"]["saiai"]
                        .as_table()
                        .unwrap()
                        .get("supports_websockets")
                        .is_none()
                );
                assert!(config.get("features").is_none());
            }
            server.finish();
            fixture.assert_legacy_untouched();
        }
    }

    #[tokio::test]
    async fn messages_dispatch_does_not_satisfy_native_claude_capability() {
        let server = spawn_fixed_server(
            "",
            response("200 OK", bootstrap_body(2, false, true, true, true), ""),
        );
        let fixture = Fixture::new();
        let error = fixture
            .core
            .provision(
                Product::Claude,
                ProvisionRequest::new(&server.service_root, "sk-dispatch-only").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("native Claude"));
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Uninitialized
        );
        server.finish();
    }

    #[tokio::test]
    async fn selected_product_capabilities_fail_independently() {
        for (product, body, expected) in [
            (
                Product::Codex,
                bootstrap_body(2, true, false, true, false),
                "Codex requests",
            ),
            (
                Product::Codex,
                bootstrap_body(2, true, true, false, false),
                "Responses API",
            ),
            (
                Product::Claude,
                bootstrap_body(2, false, true, true, false),
                "Claude",
            ),
        ] {
            let server = spawn_fixed_server("", response("200 OK", body, ""));
            let fixture = Fixture::new();
            let error = fixture
                .core
                .provision(
                    product,
                    ProvisionRequest::new(&server.service_root, "sk-denied").unwrap(),
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected));
            assert_eq!(
                fixture.core.setup_status().unwrap().state,
                SetupState::Uninitialized
            );
            server.finish();
        }
    }

    #[tokio::test]
    async fn bootstrap_schema_one_is_not_accepted_or_migrated() {
        let server = spawn_fixed_server(
            "",
            response("200 OK", bootstrap_body(1, true, true, true, false), ""),
        );
        let fixture = Fixture::new();
        let error = fixture
            .core
            .provision(
                Product::Claude,
                ProvisionRequest::new(&server.service_root, "sk-old").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, Error::InvalidBootstrapResponse(_)));
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Uninitialized
        );
        server.finish();
    }

    #[tokio::test]
    async fn redirect_is_refused_without_reflecting_the_credential() {
        let server = spawn_fixed_server(
            "",
            response(
                "302 Found",
                b"attacker body sk-secret",
                "Location: /sink\r\n",
            ),
        );
        let fixture = Fixture::new();
        let error = fixture
            .core
            .provision(
                Product::Claude,
                ProvisionRequest::new(&server.service_root, "sk-secret").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::BootstrapHttp {
                status: 302,
                category: "redirect refused"
            }
        ));
        assert!(!error.to_string().contains("sk-secret"));
        server.finish();
    }

    #[tokio::test]
    async fn malicious_gateway_bodies_are_never_reflected_in_errors() {
        let api_key = "sk-never-reflect-this";
        let cases = [
            (
                "401 Unauthorized",
                format!("attacker-body terminal\u{1b}[31m {api_key}").into_bytes(),
            ),
            (
                "200 OK",
                serde_json::to_vec(&json!({
                    "code": 123,
                    "message": format!("attacker-body terminal\u{1b}[31m {api_key}")
                }))
                .unwrap(),
            ),
        ];
        for (status, body) in cases {
            let server = spawn_fixed_server("", response(status, body, ""));
            let fixture = Fixture::new();
            let error = fixture
                .core
                .provision(
                    Product::Claude,
                    ProvisionRequest::new(&server.service_root, api_key).unwrap(),
                )
                .await
                .unwrap_err();
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains(api_key));
                assert!(!rendered.contains("attacker-body"));
                assert!(!rendered.contains("terminal"));
                assert!(!rendered.contains('\u{1b}'));
            }
            server.finish();
            assert!(!fixture.core.paths().config_dir().exists());
            fixture.assert_legacy_untouched();
        }
    }

    #[tokio::test]
    async fn chunked_bootstrap_is_stopped_at_the_streaming_one_mib_limit() {
        let server = spawn_server("", |mut stream| {
            let headers = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            if stream.write_all(headers).is_err() {
                return;
            }
            let chunk = vec![b'x'; 64 * 1024];
            let mut remaining = MAX_BOOTSTRAP_RESPONSE_BYTES + 1;
            while remaining > 0 {
                let count = remaining.min(chunk.len());
                if stream
                    .write_all(format!("{count:x}\r\n").as_bytes())
                    .is_err()
                    || stream.write_all(&chunk[..count]).is_err()
                    || stream.write_all(b"\r\n").is_err()
                {
                    return;
                }
                remaining -= count;
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        let fixture = Fixture::new();
        let error = fixture
            .core
            .provision(
                Product::Claude,
                ProvisionRequest::new(&server.service_root, "sk-size-limit").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, Error::BootstrapResponseTooLarge));
        server.finish();
        assert!(!fixture.core.paths().config_dir().exists());
        fixture.assert_legacy_untouched();
    }

    #[tokio::test]
    async fn unsafe_versions_codes_and_credential_echoes_are_rejected_safely() {
        let capabilities = json!({
            "claude": true,
            "codex": false,
            "codex_responses": false
        });
        let oversized = "v".repeat(MAX_GATEWAY_VERSION_BYTES + 1);
        let cases = vec![
            (
                "sk-control-version",
                json!({
                    "code": 0,
                    "data": {"schema_version": 2, "gateway_version": "bad\nversion", "capabilities": capabilities.clone()}
                }),
            ),
            (
                "sk-bidi-version",
                json!({
                    "code": 0,
                    "data": {"schema_version": 2, "gateway_version": "safe\u{061c}\u{202e}spoof", "capabilities": capabilities.clone()}
                }),
            ),
            (
                "sk-format-version",
                json!({
                    "code": 0,
                    "data": {"schema_version": 2, "gateway_version": "safe\u{206a}\u{200b}spoof", "capabilities": capabilities.clone()}
                }),
            ),
            (
                "sk-string-code",
                json!({
                    "code": "0",
                    "data": {"schema_version": 2, "gateway_version": "safe", "capabilities": capabilities.clone()}
                }),
            ),
            (
                "sk-long-version",
                json!({
                    "code": 0,
                    "data": {"schema_version": 2, "gateway_version": oversized, "capabilities": capabilities.clone()}
                }),
            ),
            (
                "sk-echoed-version",
                json!({
                    "code": 0,
                    "data": {"schema_version": 2, "gateway_version": "gateway-sk-echoed-version", "capabilities": capabilities}
                }),
            ),
        ];

        for (api_key, value) in cases {
            let body = serde_json::to_vec(&value).unwrap();
            let server = spawn_fixed_server("", response("200 OK", body, ""));
            let fixture = Fixture::new();
            let error = fixture
                .core
                .provision(
                    Product::Claude,
                    ProvisionRequest::new(&server.service_root, api_key).unwrap(),
                )
                .await
                .unwrap_err();
            let rendered = format!("{error:?}");
            assert!(!rendered.contains(api_key));
            assert!(!rendered.contains('\u{061c}'));
            assert!(!rendered.contains('\u{202e}'));
            assert!(!rendered.contains('\u{206a}'));
            assert!(!rendered.contains('\u{200b}'));
            server.finish();
            assert!(!fixture.core.paths().config_dir().exists());
            fixture.assert_legacy_untouched();
        }
    }

    #[test]
    fn bootstrap_dtos_ignore_unknown_secret_like_fields_and_remain_safe_to_render() {
        let secret = "sk-ignored-future-field";
        let data: BootstrapData = serde_json::from_value(json!({
            "schema_version": 2,
            "gateway_version": "",
            "capabilities": {
                "claude": true,
                "future_secret": secret
            },
            "future_credential": secret
        }))
        .unwrap();
        assert!(!data.capabilities.codex_websockets);
        for rendered in [format!("{data:?}"), serde_json::to_string(&data).unwrap()] {
            assert!(!rendered.contains(secret));
            assert!(!rendered.contains("credential"));
            assert!(!rendered.contains("PRIVATE KEY"));
        }
    }

    #[test]
    fn invalid_gateway_url_errors_never_include_the_owned_credential() {
        let secret = "sk-never-render-invalid-url";
        let error = ProvisionRequest::new("not a gateway URL", secret.to_owned()).unwrap_err();
        assert!(!format!("{error}").contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn gateway_path_cannot_persist_the_api_key() {
        let secret = "sk-never-persist-in-gateway-path";
        for gateway in [
            format!("https://api.example.test/v2/{secret}"),
            "https://api.example.test/v2/%73k-never-persist-in-gateway-path".to_owned(),
            format!("https://{secret}.example.test/v2"),
        ] {
            let error = ProvisionRequest::new(&gateway, secret).unwrap_err();
            let rendered = format!("{error}\n{error:?}");
            assert!(rendered.contains("must not contain the API key"));
            assert!(!rendered.contains(secret));
        }

        let mixed_case_secret = "SK-Mixed-Case-Host-Key";
        let error = ProvisionRequest::new(
            "https://SK-Mixed-Case-Host-Key.example.test/v2",
            mixed_case_secret,
        )
        .unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        assert!(rendered.contains("host label or path segment"));
        assert!(!rendered.contains(mixed_case_secret));

        let percent_secret = "%73k-never-persist-encoded-key";
        let error = ProvisionRequest::new(
            "https://api.example.test/v2/%73k-never-persist-encoded-key",
            percent_secret,
        )
        .unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        assert!(rendered.contains("must not contain the API key"));
        assert!(!rendered.contains(percent_secret));

        let error = SetupRequest::new("https://api.example.test/team/key", "team/key").unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        assert!(rendered.contains("must not contain the API key"));
        assert!(!rendered.contains("team/key"));

        let error = SetupRequest::new("https://api.example.test//key", "/key").unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        assert!(rendered.contains("must not contain the API key"));
        assert!(!rendered.contains("/key"));

        let request = ProvisionRequest::new("https://api.example.test/tenant/v2", secret).unwrap();
        assert_eq!(
            request.base_url().as_str(),
            "https://api.example.test/tenant/v2"
        );
    }
}
