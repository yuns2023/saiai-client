//! Claude Desktop control plane; all real credentials remain in the parent proxy.
use super::*;
use crate::brand::BRAND;
use crate::claude_desktop::Identity;
use crate::claude_desktop_fixtures::{self as fixtures, Route};

const MAX_PUBLIC_BODY: usize = 32 * 1024 * 1024;
struct AuthorizationCode {
    created: Instant,
    challenge: String,
    state: String,
    redirect: String,
    owner: String,
}
static CODES: LazyLock<Mutex<HashMap<String, AuthorizationCode>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
type ModelCache = HashMap<String, (Instant, Vec<Value>)>;
static MODELS: LazyLock<Mutex<ModelCache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug)]
struct IdentityUnavailable;
impl std::fmt::Display for IdentityUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Claude Desktop identity is unreadable or invalid")
    }
}
impl std::error::Error for IdentityUnavailable {}

fn identity(state: &State) -> Result<Option<Identity>> {
    state
        .desktop_config_root
        .as_deref()
        .map(Identity::load)
        .transpose()
        .map(Option::flatten)
        .map_err(|_| IdentityUnavailable.into())
}

pub(super) fn auth_error(error: &anyhow::Error) -> (StatusCode, &'static [u8]) {
    if error.is::<IdentityUnavailable>() {
        (StatusCode::SERVICE_UNAVAILABLE, br#"{"error":"desktop_identity_invalid","message":"Repair the isolated Desktop identity file and relaunch saiai desktop claude"}"#)
    } else {
        (
            StatusCode::UNAUTHORIZED,
            br#"{"error":"invalid_local_desktop_token"}"#,
        )
    }
}

/// Credential policy for the Desktop-only listener. Only the Desktop's own
/// placeholder is ever swapped for the route key; a missing Authorization,
/// an `x-api-key`-only request or any other Bearer is refused here instead of
/// reaching the shared forwarder, which injects the route key when no
/// Authorization header survives filtering.
pub(super) fn credential_policy(
    state: &State,
    request: &IncomingRequest,
) -> Result<CredentialPolicy> {
    match classify_request(state, request)? {
        CredentialPolicy::DesktopPlaceholder => Ok(CredentialPolicy::DesktopPlaceholder),
        _ => bail!("Claude Desktop listener requires its local placeholder token"),
    }
}

fn classify_request(state: &State, request: &IncomingRequest) -> Result<CredentialPolicy> {
    let headers: Vec<_> = request
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .collect();
    if !headers
        .iter()
        .filter_map(|(_, value)| bearer_token(value))
        .any(|token| {
            token.starts_with(BRAND.placeholders.desktop_token_prefix)
                || token.starts_with(BRAND.placeholders.legacy_codex_token_prefix)
                || token.starts_with("sk-ant")
        })
    {
        return Ok(CredentialPolicy::Preserve);
    }
    let id = identity(state)?;
    classify_credential(
        &headers.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>(),
        id.as_ref().map(|i| i.access_token.as_str()),
    )
}
fn classify_credential(headers: &[&str], expected: Option<&str>) -> Result<CredentialPolicy> {
    let tokens: Vec<_> = headers.iter().filter_map(|s| bearer_token(s)).collect();
    let desktop = tokens.iter().any(|t| Some(*t) == expected);
    let reserved = tokens.iter().any(|t| {
        t.starts_with("sk-ant")
            || t.starts_with(BRAND.placeholders.desktop_token_prefix)
            || t.starts_with(BRAND.placeholders.legacy_codex_token_prefix)
    });
    if desktop && headers.len() == 1 {
        return Ok(CredentialPolicy::DesktopPlaceholder);
    }
    if reserved || desktop {
        bail!("unknown Claude Desktop placeholder or provider token");
    }
    Ok(CredentialPolicy::Preserve)
}

pub(super) fn inspect_message(body: &[u8]) -> Result<()> {
    let parsed: Value = serde_json::from_slice(body).context("invalid Desktop message JSON")?;
    fn email(text: &str) -> bool {
        text.contains("<system-reminder>")
            && text.contains("# userEmail")
            && text.contains("The user's email address is")
    }
    let has_email = parsed["messages"].as_array().is_some_and(|messages| {
        messages.iter().any(|message| {
            let content = &message["content"];
            content.as_str().is_some_and(email)
                || content.as_array().is_some_and(|parts| {
                    parts.iter().any(|part| {
                        part["type"] == "text" && part["text"].as_str().is_some_and(email)
                    })
                })
        })
    });
    if has_email {
        bail!(
            "login_state_user_email_context_present; close Desktop and relaunch saiai desktop claude to clear isolated login identity"
        );
    }
    if let Some(user) = parsed.pointer("/metadata/user_id").and_then(Value::as_str) {
        let nonempty = serde_json::from_str::<Value>(user)
            .ok()
            .and_then(|v| {
                v.get("account_uuid")
                    .and_then(Value::as_str)
                    .map(|s| !s.is_empty())
            })
            .or_else(|| {
                user.split_once("_account_")
                    .and_then(|(_, v)| v.split_once("_session_"))
                    .map(|(v, _)| !v.is_empty())
            });
        eprintln!(
            "Claude Desktop metadata: account_uuid_nonempty={}",
            nonempty.map_or("unknown", |v| if v { "true" } else { "false" })
        );
    }
    Ok(())
}

fn session_valid(request: &IncomingRequest, id: &Identity) -> bool {
    let cookie = header_value(&request.headers, "cookie").is_some_and(|s| {
        s.split(';').any(|part| {
            part.trim()
                .split_once('=')
                .is_some_and(|(k, v)| matches!(k, "sessionKey" | "sessionKeyV3") && v == id.session)
        })
    });
    // Desktop's native authorize call carries the session Cookie value as Bearer.
    cookie
        || header_value(&request.headers, "authorization").and_then(bearer_token)
            == Some(id.session.as_str())
}
fn access_valid(request: &IncomingRequest, id: &Identity) -> bool {
    header_value(&request.headers, "authorization").and_then(bearer_token)
        == Some(id.access_token.as_str())
}
fn token_response(id: &Identity) -> Value {
    json!({"access_token":id.access_token,"refresh_token":id.refresh_token,"token_type":"Bearer",
        "expires_in":315360000u64,"scope":"user:inference user:profile","account":{"email_address":""},
        "organization":{"uuid":id.organization}})
}
fn oauth(request: &IncomingRequest, path: &str, id: &Identity, now: Instant) -> (u16, Value) {
    let error = |message: &str| (400, json!({"error":message}));
    if path == "/api/oauth/profile" && request.method == "GET" {
        return if access_valid(request, id) {
            (
                200,
                json!({"account":{"email_address":"","display_name":"SAIAI Local Code"},"organization":fixtures::organization(id)}),
            )
        } else {
            (401, json!({"error":"invalid_local_token"}))
        };
    }
    if path == "/v1/oauth/revoke" && request.method == "POST" {
        return (200, json!({}));
    }
    if request.method != "POST" {
        return (405, json!({"error":"method_not_allowed"}));
    }
    let data: Value = if header_value(&request.headers, "content-type")
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"))
    {
        Value::Object(
            url::form_urlencoded::parse(&request.body)
                .map(|(k, v)| (k.into_owned(), Value::String(v.into_owned())))
                .collect(),
        )
    } else {
        match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(_) => return error("invalid_request"),
        }
    };
    if path == format!("/v1/oauth/{}/authorize", id.organization) {
        if !session_valid(request, id) {
            return (401, json!({"error":"invalid_local_session"}));
        }
        if data["organization_uuid"] != id.organization || data["code_challenge_method"] != "S256" {
            return error("invalid_request");
        }
        let (Some(challenge), Some(state), Some(redirect)) = (
            data["code_challenge"].as_str(),
            data["state"].as_str(),
            data["redirect_uri"].as_str(),
        ) else {
            return error("invalid_request");
        };
        let Ok(mut url) = Url::parse(redirect) else {
            return error("invalid_redirect_uri");
        };
        let loopback = url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if !(loopback || url.scheme() == "claude")
            || url.fragment().is_some()
            || url.query().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || challenge.len() != 43
            || state.is_empty()
            || state.len() > 1024
        {
            return error("invalid_request");
        }
        let code = uuid::Uuid::new_v4().simple().to_string();
        let mut codes = CODES.lock().unwrap_or_else(|p| p.into_inner());
        codes.retain(|_, v| now.saturating_duration_since(v.created) < Duration::from_secs(120));
        if codes.len() >= 1024 {
            return (503, json!({"error":"local_authorization_capacity"}));
        }
        codes.insert(
            code.clone(),
            AuthorizationCode {
                created: now,
                challenge: challenge.into(),
                state: state.into(),
                redirect: redirect.into(),
                owner: id.access_token.clone(),
            },
        );
        url.query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", state);
        return (200, json!({"redirect_uri":url.as_str()}));
    }
    if path != "/v1/oauth/token" {
        return (501, json!({"error":"desktop_control_unsupported"}));
    }
    if data["grant_type"] == "refresh_token" {
        return if data["refresh_token"] == id.refresh_token {
            (200, token_response(id))
        } else {
            error("invalid_grant")
        };
    }
    if data["grant_type"] != "authorization_code" {
        return error("unsupported_grant_type");
    }
    let code = data["code"].as_str().unwrap_or("");
    let pending = CODES.lock().unwrap_or_else(|p| p.into_inner()).remove(code);
    let verifier = data["code_verifier"].as_str().unwrap_or("");
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
    {
        return error("invalid_grant");
    }
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    if !pending.is_some_and(|p| {
        p.owner == id.access_token
            && now.saturating_duration_since(p.created) < Duration::from_secs(120)
            && p.challenge == challenge
            && data["state"] == p.state
            && data["redirect_uri"] == p.redirect
    }) {
        return error("invalid_grant");
    }
    (200, token_response(id))
}

fn public_request_header(name: &str) -> bool {
    // Reserved headers are refused before the allowlist is consulted.
    !crate::gateway::is_reserved_inbound_header(name)
        && matches!(
            name.to_ascii_lowercase().as_str(),
            "accept"
                | "accept-language"
                | "user-agent"
                | "if-none-match"
                | "if-modified-since"
                | "range"
        )
}
fn public_response_header(name: &str, value: &str) -> bool {
    should_forward_response_header(name)
        && !matches!(
            name.to_ascii_lowercase().as_str(),
            "connection" | "transfer-encoding" | "content-length"
        )
        && !(name.eq_ignore_ascii_case("set-cookie")
            && value.split_once('=').is_some_and(|(key, _)| {
                matches!(key.trim(), "sessionKey" | "sessionKeyV3" | "lastActiveOrg")
            }))
}

async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_PUBLIC_BODY {
            bail!("Desktop public response exceeds size limit");
        }
        body.extend(chunk);
    }
    Ok(body)
}

pub(super) async fn models(state: &State, id: &Identity) -> Result<Vec<Value>> {
    if let Some((at, models)) = MODELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&id.access_token)
        && at.elapsed() < Duration::from_secs(60)
    {
        return Ok(models.clone());
    }
    let route = state.route_for_host(ANTHROPIC_HOST);
    let mut target = "/v1/models".to_string();
    let mut result = Vec::new();
    for _ in 0..20 {
        let url = state.upstream_url(&target, route)?;
        let client = state.http.for_url(&url).await?;
        let mut request = client
            .get(&url)
            .bearer_auth(&*route.api_key)
            .header("anthropic-version", "2023-06-01")
            .timeout(Duration::from_secs(30));
        let parsed = Url::parse(&url)?;
        for (name, value) in state.gateway_signature(
            crate::gateway::Transport::Http,
            route,
            "GET",
            &crate::gateway::wire_target(&parsed),
            Some(&route.api_key),
        ) {
            request = request.header(name, value);
        }
        let response = request.send().await?.error_for_status()?;
        let body: Value = serde_json::from_slice(&bounded_body(response).await?)?;
        let data = body
            .get("data")
            .or_else(|| body.get("models"))
            .and_then(Value::as_array)
            .context("Gateway model catalog has no model array")?;
        for model in data {
            let id = model["id"].as_str().context("Gateway model has no id")?;
            result.push(json!({"id":id,"name":model.get("display_name").or_else(||model.get("name")).and_then(Value::as_str).unwrap_or(id),"section":"main","disabled":false}));
        }
        if body["has_more"] != true {
            if result.is_empty() {
                bail!("Gateway returned an empty Claude model catalog");
            }
            MODELS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(id.access_token.clone(), (Instant::now(), result.clone()));
            return Ok(result);
        }
        let last = body["last_id"]
            .as_str()
            .context("paginated catalog has no last_id")?;
        target = format!(
            "/v1/models?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("after_id", last)
                .finish()
        );
    }
    bail!("Gateway model catalog exceeded pagination limit")
}
fn selection(state: &State, models: &[Value]) -> Result<Value> {
    let path = state
        .desktop_config_root
        .as_ref()
        .context("Desktop state unavailable")?
        .join("desktop/claude/state/model.json");
    if let Ok(bytes) = fs::read(path) {
        let value: Value = serde_json::from_slice(&bytes)?;
        if models.iter().any(|m| m["id"] == value["model"]) {
            return Ok(value);
        }
    }
    Ok(
        json!({"id":"code","model":models[0]["id"],"selection_source":"default","thinking":null,"thinking_by_model":[]}),
    )
}

async fn public(
    state: &State,
    request: &IncomingRequest,
    path: &str,
    id: &Identity,
    bootstrap: bool,
) -> Result<(StatusCode, Vec<(String, String)>, Vec<u8>)> {
    let target = if bootstrap {
        if path.contains("/app_start") {
            "/edge-api/bootstrap"
        } else {
            path
        }
    } else {
        &request.target
    };
    // Only origin-form targets can reach this fetch; absolute targets must not select an upstream host.
    let url = format!("https://claude.ai{target}");
    let client = state.http.for_url(&url).await?;
    let mut builder = client
        .request(Method::from_bytes(request.method.as_bytes())?, &url)
        .header("accept-encoding", "identity")
        .timeout(Duration::from_secs(30));
    for (name, value) in &request.headers {
        if public_request_header(name)
            && !(bootstrap && name.to_ascii_lowercase().starts_with("if-"))
        {
            builder = builder.header(name, value);
        }
    }
    let response = builder.send().await?;
    let status = response.status();
    if bootstrap && status != StatusCode::OK {
        bail!("anonymous bootstrap returned HTTP {status}");
    }
    let mut headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .filter(|v| public_response_header(k.as_str(), v))
                .map(|v| (k.to_string(), v.to_string()))
        })
        .collect();
    let mut body = bounded_body(response).await?;
    if bootstrap {
        let mut value: Value =
            serde_json::from_slice(&body).context("anonymous bootstrap is not JSON")?;
        let models = models(state, id).await?;
        fixtures::patch(&mut value, id, &models, &selection(state, &models)?)?;
        body = serde_json::to_vec(&value)?;
        headers.retain(|(k, _)| {
            !matches!(
                k.as_str(),
                "content-encoding" | "etag" | "cache-control" | "content-type"
            )
        });
        headers.push(("content-type".into(), "application/json".into()));
        headers.push(("cache-control".into(), "no-store".into()));
    }
    if path == "/" || path == "/epitaxy" || bootstrap {
        for (name, value) in [
            ("sessionKey", &id.session),
            ("sessionKeyV3", &id.session),
            ("lastActiveOrg", &id.organization),
        ] {
            headers.push(("set-cookie".into(),format!("{name}={value}; Domain=.claude.ai; Path=/; Max-Age=315360000; Secure; SameSite=Lax{}",if name=="lastActiveOrg" {""} else {"; HttpOnly"})));
        }
    }
    Ok((status, headers, body))
}

pub(super) async fn handle<W: AsyncWrite + Unpin>(
    state: &State,
    writer: &mut W,
    request: &IncomingRequest,
    host: &str,
    close: bool,
) -> Result<bool> {
    if !matches!(host, "claude.ai" | ANTHROPIC_HOST) {
        return Ok(false);
    }
    let id = match identity(state) {
        Ok(Some(id)) => id,
        Ok(None) => {
            write_static_response(writer, StatusCode::SERVICE_UNAVAILABLE, "application/json", br#"{"error":"desktop_identity_missing","message":"Run saiai desktop claude to initialize this environment"}"#, close).await?;
            return Ok(true);
        }
        Err(error) => {
            let (status, body) = auth_error(&error);
            write_static_response(writer, status, "application/json", body, close).await?;
            return Ok(true);
        }
    };
    let path = request_path(&request.target)?;
    let oauth_path = path.starts_with("/v1/oauth/") || path == "/api/oauth/profile";
    let update = path == "/api/desktop/linux/x64/deb/latest";
    if host != "claude.ai" && !oauth_path && !update {
        return Ok(false);
    }
    let reply = |status: u16, value: Value| {
        (
            StatusCode::from_u16(status).unwrap(),
            Vec::new(),
            serde_json::to_vec(&value).unwrap(),
        )
    };
    let mut result = if request.target.contains('#') {
        reply(400, json!({"error":"invalid_desktop_target"}))
    } else if update {
        reply(204, Value::Null)
    } else {
        if !request.target.starts_with('/')
            || request.target.starts_with("//")
            || fixtures::classify(&request.method, &path, &id.organization) == Route::Reject
        {
            reply(400, json!({"error":"invalid_desktop_target"}))
        } else if request.method == "OPTIONS"
            && header_value(&request.headers, "origin") == Some("https://claude.ai")
        {
            let known = matches!(
                path.as_str(),
                "/v1/oauth/token" | "/v1/oauth/revoke" | "/api/oauth/profile"
            ) || path == format!("/v1/oauth/{}/authorize", id.organization)
                || fixtures::local("GET", &path, &id).is_some()
                || matches!(
                    fixtures::classify("GET", &path, &id.organization),
                    Route::Bootstrap | Route::Public
                )
                || path
                    == format!(
                        "/api/organizations/{}/model_selector_state/code",
                        id.organization
                    )
                || path
                    == format!(
                        "/api/claude_code/organizations/{}/user_settings",
                        id.organization
                    );
            if known {
                reply(204, Value::Null)
            } else {
                reply(501, json!({"error":"desktop_control_unsupported"}))
            }
        } else if oauth_path {
            let (status, value) = oauth(request, &path, &id, Instant::now());
            reply(status, value)
        } else {
            match fixtures::classify(&request.method, &path, &id.organization) {
                Route::Public | Route::Bootstrap => {
                    let bootstrap = fixtures::classify(&request.method, &path, &id.organization)
                        == Route::Bootstrap;
                    match public(state, request, &path, &id, bootstrap).await {
                        Ok(r) => r,
                        Err(e) => {
                            // Error messages must not include upstream URLs or credentials.
                            eprintln!(
                                "Claude Desktop anonymous resource/bootstrap failed ({})",
                                if bootstrap { "bootstrap" } else { "public" }
                            );
                            let _ = e;
                            reply(
                                502,
                                json!({"error":{"type":"desktop_bootstrap_unavailable","message":"Anonymous Desktop resource or Gateway model catalog unavailable"}}),
                            )
                        }
                    }
                }
                _ => {
                    let selector = format!("/api/organizations/{}/model_selector", id.organization);
                    let settings = format!(
                        "/api/claude_code/organizations/{}/user_settings",
                        id.organization
                    );
                    if path == format!("{selector}/code")
                        || path == format!("{selector}_state/code")
                    {
                        match model_response(state, request, &path, &id, &selector).await {
                            Ok((s, v)) => reply(s, v),
                            Err(_) => {
                                reply(502, json!({"error":"gateway_model_catalog_unavailable"}))
                            }
                        }
                    } else if path == settings && matches!(request.method.as_str(), "GET" | "PUT") {
                        let file = state
                            .desktop_config_root
                            .as_ref()
                            .unwrap()
                            .join("desktop/claude/state/settings.json");
                        if request.method == "PUT" {
                            if !session_valid(request, &id) {
                                reply(401, json!({"error":"invalid_local_session"}))
                            } else if request.body.len() > 65536 {
                                reply(413, json!({"error":"settings_too_large"}))
                            } else if let Ok(value) = serde_json::from_slice::<Value>(&request.body)
                            {
                                crate::claude_desktop::private_write(
                                    &file,
                                    &serde_json::to_vec(&value)?,
                                )?;
                                reply(200, value)
                            } else {
                                reply(400, json!({"error":"invalid_settings"}))
                            }
                        } else {
                            reply(
                                200,
                                fs::read(file)
                                    .ok()
                                    .and_then(|v| serde_json::from_slice(&v).ok())
                                    .unwrap_or(json!({})),
                            )
                        }
                    } else if let Some((status, value)) =
                        fixtures::local(&request.method, &path, &id)
                    {
                        reply(status, value)
                    } else {
                        reply(
                            501,
                            json!({"error":{"type":"desktop_control_unsupported","message":"This Desktop control endpoint is unavailable through SAIAI."}}),
                        )
                    }
                }
            }
        }
    };
    if path == "/logout" || path == "/api/auth/logout" {
        for name in ["sessionKey", "sessionKeyV3", "lastActiveOrg"] {
            result.1.push((
                "set-cookie".into(),
                format!("{name}=; Domain=.claude.ai; Path=/; Max-Age=0; Secure"),
            ));
        }
    }
    if header_value(&request.headers, "origin") == Some("https://claude.ai") {
        result.1.extend([
            (
                "access-control-allow-origin".into(),
                "https://claude.ai".into(),
            ),
            ("access-control-allow-credentials".into(), "true".into()),
            (
                "access-control-allow-methods".into(),
                "GET, HEAD, POST, PUT, PATCH, OPTIONS".into(),
            ),
            (
                "access-control-allow-headers".into(),
                "authorization, content-type, anthropic-version".into(),
            ),
        ]);
    }
    if request.method == "HEAD" || result.0 == StatusCode::NO_CONTENT {
        result.2.clear();
    }
    let headers: Vec<_> = result
        .1
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    writer
        .write_all(
            format!(
                "HTTP/1.1 {} {}\r\nConnection: {}\r\nContent-Length: {}\r\n",
                result.0.as_u16(),
                result.0.canonical_reason().unwrap_or(""),
                if close { "close" } else { "keep-alive" },
                result.2.len()
            )
            .as_bytes(),
        )
        .await?;
    if !result.2.is_empty()
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    {
        writer
            .write_all(b"Content-Type: application/json\r\n")
            .await?;
    }
    for (name, value) in headers {
        writer
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    writer.write_all(b"\r\n").await?;
    writer.write_all(&result.2).await?;
    writer.flush().await?;
    Ok(true)
}

async fn model_response(
    state: &State,
    request: &IncomingRequest,
    path: &str,
    id: &Identity,
    prefix: &str,
) -> Result<(u16, Value)> {
    let models = models(state, id).await?;
    let mut selected = selection(state, &models)?;
    if request.method == "PATCH" && path == format!("{prefix}_state/code") {
        let value: Value = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(_) => return Ok((400, json!({"error":"invalid_selection"}))),
        };
        if !session_valid(request, id) {
            return Ok((401, json!({"error":"invalid_local_session"})));
        }
        if !models.iter().any(|m| m["id"] == value["model"]) {
            return Ok((400, json!({"error":"unknown_model"})));
        }
        selected["model"] = value["model"].clone();
        for key in ["thinking", "fast_mode", "extra_option"] {
            if let Some(v) = value.get(key) {
                selected[key] = v.clone();
            }
        }
        selected["selection_source"] = json!("user_setting");
        crate::claude_desktop::private_write(
            &state
                .desktop_config_root
                .as_ref()
                .unwrap()
                .join("desktop/claude/state/model.json"),
            &serde_json::to_vec(&selected)?,
        )?;
    } else if request.method != "GET" {
        return Ok((405, json!({"error":"method_not_allowed"})));
    }
    Ok((
        200,
        if path == format!("{prefix}_state/code") {
            selected
        } else {
            json!({"model_selector_config":fixtures::selectors(&models,&selected),"model_selector_state":[selected]})
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id() -> Identity {
        let d = tempfile::tempdir().unwrap();
        Identity::prepare(d.path()).unwrap()
    }
    fn request(body: Value, id: &Identity) -> IncomingRequest {
        IncomingRequest {
            method: "POST".into(),
            target: "/".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![("Cookie".into(), format!("sessionKey={}", id.session))],
            body: serde_json::to_vec(&body).unwrap(),
        }
    }
    #[test]
    fn authentication_is_scoped_and_unknown_placeholders_never_leave() {
        let id = id();
        let auth = format!("Bearer {}", id.access_token);
        assert_eq!(
            classify_credential(&[&auth], Some(&id.access_token)).unwrap(),
            CredentialPolicy::DesktopPlaceholder
        );
        assert_eq!(
            classify_credential(&["Bearer ordinary-saiai-key"], Some(&id.access_token)).unwrap(),
            CredentialPolicy::Preserve
        );
        for auth in [
            "Bearer sk-ant-real",
            "Bearer saiai-desktop-claude-foreign",
            "Bearer saiai-local-proxy-placeholder-other",
        ] {
            assert!(classify_credential(&[auth], Some(&id.access_token)).is_err());
        }
        assert!(classify_credential(&[&auth, "Bearer other"], Some(&id.access_token)).is_err());
    }
    #[test]
    fn anonymous_headers_drop_credentials_but_keep_public_cookies() {
        for name in [
            "cookie",
            "authorization",
            "x-api-key",
            "proxy-authorization",
            "x-saiai-client-proof",
            "referer",
            "x-account-id",
        ] {
            assert!(!public_request_header(name));
        }
        for cookie in [
            "sessionKey=secret; Secure",
            "sessionKeyV3=secret",
            "lastActiveOrg=uuid",
        ] {
            assert!(!public_response_header("Set-Cookie", cookie));
        }
        assert!(public_response_header(
            "Set-Cookie",
            "public-cookie=value; Secure"
        ));
    }
    #[test]
    fn email_context_is_rejected_without_mutating_messages() {
        assert!(inspect_message(br#"{"system":"The user's email address is x"}"#).is_ok());
        assert!(inspect_message(br#"{"system":"The user's email address is\u0020x"}"#).is_ok());
        assert!(
            inspect_message(br#"{"metadata":{"user_id":"{\"account_uuid\":\"nonempty\"}"}}"#)
                .is_ok()
        );
    }
    #[test]
    fn email_inspection_matches_server_content_scope() {
        let text =
            "<system-reminder> # userEmail The user's email address is fixture@example.invalid";
        for content in [json!(text), json!([{"type":"text","text":text}])] {
            let body = serde_json::to_vec(&json!({"messages":[{"content":content}]})).unwrap();
            assert!(inspect_message(&body).is_err());
        }
        for body in [
            json!({"system":text}),
            json!({"messages":[{"content":"The user's email address is fixture@example.invalid"}]}),
            json!({"messages":[{"content":[{"type":"tool_result","content":text}]}]}),
            json!({"messages":[{"content":[{"type":"text","text":"<system-reminder>"},{"type":"text","text":"# userEmail The user's email address is x"}]}]}),
        ] {
            assert!(inspect_message(&serde_json::to_vec(&body).unwrap()).is_ok());
        }
    }

    #[test]
    fn oauth_verifier_requires_rfc7636_length_and_alphabet() {
        let id = id();
        let now = Instant::now();
        for (verifier, expected) in [
            ("a".repeat(42), 400),
            ("a".repeat(43), 200),
            ("a".repeat(128), 200),
            ("a".repeat(129), 400),
            (format!("{}!", "a".repeat(42)), 400),
            (format!("{}-._~", "a".repeat(39)), 200),
        ] {
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(verifier.as_bytes()));
            let authorize = request(
                json!({"organization_uuid":id.organization,"code_challenge_method":"S256","code_challenge":challenge,"state":"test","redirect_uri":"http://localhost:1234/callback"}),
                &id,
            );
            let (_, value) = oauth(
                &authorize,
                &format!("/v1/oauth/{}/authorize", id.organization),
                &id,
                now,
            );
            let url = Url::parse(value["redirect_uri"].as_str().unwrap()).unwrap();
            let code = url
                .query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned();
            let token = request(
                json!({"grant_type":"authorization_code","code":code,"code_verifier":verifier,"state":"test","redirect_uri":"http://localhost:1234/callback"}),
                &id,
            );
            assert_eq!(oauth(&token, "/v1/oauth/token", &id, now).0, expected);
        }
    }

    #[test]
    fn oauth_checks_pkce_state_replay_expiry_and_refresh() {
        let id = id();
        let now = Instant::now();
        let verifier = "a".repeat(43);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let authorize = request(
            json!({"organization_uuid":id.organization,"code_challenge_method":"S256","code_challenge":challenge,"state":"test-state","redirect_uri":"http://localhost:1234/callback"}),
            &id,
        );
        for (state, elapsed, valid_pkce, expected) in [
            ("test-state", 0, true, 200),
            ("wrong", 0, true, 400),
            ("test-state", 121, true, 400),
            ("test-state", 0, false, 400),
        ] {
            let (status, value) = oauth(
                &authorize,
                &format!("/v1/oauth/{}/authorize", id.organization),
                &id,
                now,
            );
            assert_eq!(status, 200);
            let url = Url::parse(value["redirect_uri"].as_str().unwrap()).unwrap();
            let code = url
                .query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned();
            let token = request(
                json!({"grant_type":"authorization_code","code":code,"code_verifier":if valid_pkce {verifier.as_str()} else {"wrong-verifier"},"state":state,"redirect_uri":"http://localhost:1234/callback"}),
                &id,
            );
            assert_eq!(
                oauth(
                    &token,
                    "/v1/oauth/token",
                    &id,
                    now + Duration::from_secs(elapsed)
                )
                .0,
                expected
            );
            assert_eq!(oauth(&token, "/v1/oauth/token", &id, now).0, 400);
        }
        let refresh = request(
            json!({"grant_type":"refresh_token","refresh_token":id.refresh_token}),
            &id,
        );
        let (status, value) = oauth(&refresh, "/v1/oauth/token", &id, now);
        assert_eq!(status, 200);
        assert_eq!(value["access_token"], id.access_token);
        assert!(value["account"].get("uuid").is_none());
        assert_eq!(
            oauth(
                &request(
                    json!({"grant_type":"refresh_token","refresh_token":"wrong"}),
                    &id
                ),
                "/v1/oauth/token",
                &id,
                now
            )
            .0,
            400
        );
        let mut bad = authorize;
        bad.headers.clear();
        assert_eq!(
            oauth(
                &bad,
                &format!("/v1/oauth/{}/authorize", id.organization),
                &id,
                now
            )
            .0,
            401
        );
    }
}
