//! Byte goldens of the synthetic responses the local proxy answers itself
//! (Codex/ChatGPT Desktop sidecars, Claude Desktop control plane). Frozen
//! from the SAIAI build before their brand names moved to `Brand`; with the
//! SAIAI brand every byte must stay as written here.

use super::*;
use serde_json::json;

fn req(method: &str, target: &str, headers: &[(&str, &str)], body: &str) -> IncomingRequest {
    IncomingRequest {
        method: method.into(),
        target: target.into(),
        http_version: "HTTP/1.1".into(),
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
        body: body.as_bytes().to_vec(),
    }
}

const ACCOUNT: [(&str, &str); 1] = [("chatgpt-account-id", "acct-fixed")];

const STATIC_INIT_BROWSER_FALSE: &str = r#"{"feature_gates":{},"dynamic_configs":{},"layer_configs":{"72216192":{"name":"72216192","value":{"enable_i18n":true},"rule_id":"saiai-local-i18n","secondary_exposures":[],"is_user_in_experiment":false,"is_experiment_active":false,"allocated_experiment_name":"","explicit_parameters":["enable_i18n"],"undelegated_secondary_exposures":[]}},"has_updates":true,"time":0,"user":{"userID":"saiai-local-proxy-user","customIDs":{"stableID":"saiai-local-proxy"}}}"#;
const ACCOUNT_INIT_BROWSER_FALSE: &str = r#"{"dynamic_configs":{},"feature_gates":{},"has_updates":true,"layer_configs":{"72216192":{"allocated_experiment_name":"","explicit_parameters":["enable_i18n"],"is_experiment_active":false,"is_user_in_experiment":false,"name":"72216192","rule_id":"saiai-local-i18n","secondary_exposures":[],"undelegated_secondary_exposures":[],"value":{"enable_i18n":true}}},"time":0,"user":{"customIDs":{"stableID":"s-fixed"},"userID":"u-fixed"}}"#;
const STATSIG_BOOTSTRAP_BROWSER_FALSE: &str = r#"{"statsigPayload":"{\"dynamic_configs\":{},\"feature_gates\":{},\"has_updates\":true,\"layer_configs\":{\"72216192\":{\"allocated_experiment_name\":\"\",\"explicit_parameters\":[\"enable_i18n\"],\"is_experiment_active\":false,\"is_user_in_experiment\":false,\"name\":\"72216192\",\"rule_id\":\"saiai-local-i18n\",\"secondary_exposures\":[],\"undelegated_secondary_exposures\":[],\"value\":{\"enable_i18n\":true}}},\"time\":0,\"user\":{\"custom\":{\"auth_method\":\"chatgpt\"},\"customIDs\":{\"account_id\":\"acct-fixed\",\"workspace_id\":\"acct-fixed\"},\"userID\":\"saiai-local-proxy-user\"}}"}"#;
const STATIC_INIT_BROWSER_TRUE: &str = r#"{"dynamic_configs":{},"feature_gates":{"1146407612":{"id_type":"userID","name":"1146407612","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true},"1506311413":{"id_type":"userID","name":"1506311413","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true},"1892382740":{"id_type":"userID","name":"1892382740","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true},"410065390":{"id_type":"userID","name":"410065390","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true},"410262010":{"id_type":"userID","name":"410262010","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true}},"has_updates":true,"layer_configs":{"72216192":{"allocated_experiment_name":"","explicit_parameters":["enable_i18n"],"is_experiment_active":false,"is_user_in_experiment":false,"name":"72216192","rule_id":"saiai-local-i18n","secondary_exposures":[],"undelegated_secondary_exposures":[],"value":{"enable_i18n":true}}},"time":0,"user":{"customIDs":{"stableID":"saiai-local-proxy"},"userID":"saiai-local-proxy-user"}}"#;
const ACCOUNT_INIT_BROWSER_TRUE: &str = r#"{"dynamic_configs":{},"feature_gates":{"1146407612":{"id_type":"userID","name":"1146407612","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true},"1506311413":{"id_type":"userID","name":"1506311413","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true},"1892382740":{"id_type":"userID","name":"1892382740","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true},"410065390":{"id_type":"userID","name":"410065390","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true},"410262010":{"id_type":"userID","name":"410262010","rule_id":"saiai-local-browser-use","secondary_exposures":[],"value":true}},"has_updates":true,"layer_configs":{"72216192":{"allocated_experiment_name":"","explicit_parameters":["enable_i18n"],"is_experiment_active":false,"is_user_in_experiment":false,"name":"72216192","rule_id":"saiai-local-i18n","secondary_exposures":[],"undelegated_secondary_exposures":[],"value":{"enable_i18n":true}}},"time":0,"user":{"customIDs":{"stableID":"s-fixed"},"userID":"u-fixed"}}"#;
const STATSIG_BOOTSTRAP_BROWSER_TRUE: &str = r#"{"statsigPayload":"{\"dynamic_configs\":{},\"feature_gates\":{\"1146407612\":{\"id_type\":\"userID\",\"name\":\"1146407612\",\"rule_id\":\"saiai-local-browser-use\",\"secondary_exposures\":[],\"value\":true},\"1506311413\":{\"id_type\":\"userID\",\"name\":\"1506311413\",\"rule_id\":\"saiai-local-browser-use\",\"secondary_exposures\":[],\"value\":true},\"1892382740\":{\"id_type\":\"userID\",\"name\":\"1892382740\",\"rule_id\":\"saiai-local-browser-use\",\"secondary_exposures\":[],\"value\":true},\"410065390\":{\"id_type\":\"userID\",\"name\":\"410065390\",\"rule_id\":\"saiai-local-browser-use\",\"secondary_exposures\":[],\"value\":true},\"410262010\":{\"id_type\":\"userID\",\"name\":\"410262010\",\"rule_id\":\"saiai-local-browser-use\",\"secondary_exposures\":[],\"value\":true}},\"has_updates\":true,\"layer_configs\":{\"72216192\":{\"allocated_experiment_name\":\"\",\"explicit_parameters\":[\"enable_i18n\"],\"is_experiment_active\":false,\"is_user_in_experiment\":false,\"name\":\"72216192\",\"rule_id\":\"saiai-local-i18n\",\"secondary_exposures\":[],\"undelegated_secondary_exposures\":[],\"value\":{\"enable_i18n\":true}}},\"time\":0,\"user\":{\"custom\":{\"auth_method\":\"chatgpt\"},\"customIDs\":{\"account_id\":\"acct-fixed\",\"workspace_id\":\"acct-fixed\"},\"userID\":\"saiai-local-proxy-user\"}}"}"#;

/// The local Statsig bootstrap: the static answer, the identity-preserving
/// re-evaluation and the wham bootstrap, with and without browser control.
#[test]
fn desktop_statsig_answers_are_byte_identical() {
    for (browser_use, static_body, account_body, bootstrap_body) in [
        (
            false,
            STATIC_INIT_BROWSER_FALSE,
            ACCOUNT_INIT_BROWSER_FALSE,
            STATSIG_BOOTSTRAP_BROWSER_FALSE,
        ),
        (
            true,
            STATIC_INIT_BROWSER_TRUE,
            ACCOUNT_INIT_BROWSER_TRUE,
            STATSIG_BOOTSTRAP_BROWSER_TRUE,
        ),
    ] {
        let features = DesktopFeatures { browser_use };
        let response =
            chatgpt_sidecar_response_with(&req("POST", "/v1/initialize", &[], "{}"), features)
                .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.content_type, "application/json");
        assert_eq!(response.reason, "desktop_statsig_local_bootstrap");
        assert_eq!(std::str::from_utf8(response.body).unwrap(), static_body);

        let user = r#"{"user":{"userID":"u-fixed","customIDs":{"stableID":"s-fixed"}}}"#;
        let (status, body, reason, headers) = chatgpt_account_sidecar_response_with(
            &req("POST", "/v1/initialize", &[], user),
            features,
        )
        .unwrap();
        assert_eq!(
            (status, reason, headers.len()),
            (StatusCode::OK, "desktop_statsig_identity_bootstrap", 0)
        );
        assert_eq!(std::str::from_utf8(&body).unwrap(), account_body);

        // No OAuth identity: the synthetic user id stands in.
        let (status, body, _, _) = chatgpt_account_sidecar_response_with(
            &req(
                "POST",
                "/backend-api/wham/statsig/bootstrap",
                &ACCOUNT,
                "{}",
            ),
            features,
        )
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&body).unwrap(), bootstrap_body);
    }
}

/// Fixed Desktop sidecar refusals.
#[test]
fn desktop_sidecar_refusals_are_byte_identical() {
    let features = DesktopFeatures { browser_use: true };
    for (method, target, status, body) in [
        (
            "PUT",
            "/backend-api/notifications/settings",
            501,
            r#"{"error":{"type":"desktop_notification_settings_unsupported","message":"Notification settings are unavailable through SAIAI Desktop."}}"#,
        ),
        (
            "GET",
            "/automations",
            501,
            r#"{"error":{"type":"desktop_control_unsupported","message":"This Desktop control endpoint is unavailable through SAIAI."}}"#,
        ),
    ] {
        let response =
            chatgpt_sidecar_response_with(&req(method, target, &[], ""), features).unwrap();
        assert_eq!(response.status.as_u16(), status, "{method} {target}");
        assert_eq!(response.content_type, "application/json");
        assert_eq!(
            std::str::from_utf8(response.body).unwrap(),
            body,
            "{method} {target}"
        );
    }
}

/// Local identity answers, including the synthetic user id used when the
/// request carries no OAuth identity and the local MCP server's name.
#[test]
fn desktop_identity_answers_are_byte_identical() {
    let features = DesktopFeatures { browser_use: true };
    for (method, target, request_body, status, body) in [
        (
            "POST",
            "/backend-api/me",
            r#""#,
            501,
            r#"{"error":{"type":"desktop_identity_write_unsupported","message":"Hosted account changes are unavailable through SAIAI Desktop."}}"#,
        ),
        (
            "POST",
            "/backend-api/ps/mcp",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            200,
            r#"{"id":1,"jsonrpc":"2.0","result":{"capabilities":{"tools":{}},"protocolVersion":"2025-03-26","serverInfo":{"name":"saiai-local","version":"1"}}}"#,
        ),
        (
            "PATCH",
            "/backend-api/profiles/me",
            r#""#,
            501,
            r#"{"error":{"type":"desktop_profile_update_unsupported","message":"Profile updates are unavailable through SAIAI Desktop."}}"#,
        ),
        (
            "GET",
            "/backend-api/me",
            r#""#,
            200,
            r#"{"account_id":"acct-fixed","email":"saiai-local-proxy@example.invalid","id":"acct-fixed"}"#,
        ),
        (
            "GET",
            "/backend-api/wham/accounts/check",
            r#""#,
            200,
            r#"{"account_ordering":["acct-fixed"],"accounts":[{"account_routing_override":"NO_CONSTRAINT","account_user_id":"saiai-local-proxy-user","account_user_role":"standard-user","can_access_with_session":true,"enable_account_switching":false,"id":"acct-fixed","is_deactivated":false,"is_openai_internal":false,"is_zdr":false,"name":null,"plan_type":"plus","profile_picture_url":null,"structure":"personal","workspace_backend_origin":"NO_CONSTRAINT"}],"default_account_id":"acct-fixed"}"#,
        ),
        (
            "GET",
            "/backend-api/accounts/optimized/check",
            r#""#,
            200,
            r#"{"account":{"id":"acct-fixed","is_fedramp_compliant_workspace":false},"account_user":{"account_id":"acct-fixed","pending_seat_upgrade_request":false,"seat_type":"default","trial_expires_at":null,"user_id":"saiai-local-proxy-user"}}"#,
        ),
    ] {
        let (code, response, _, headers) = chatgpt_account_sidecar_response_with(
            &req(method, target, &ACCOUNT, request_body),
            features,
        )
        .unwrap();
        assert_eq!(code.as_u16(), status, "{method} {target}");
        assert!(headers.is_empty());
        assert_eq!(
            std::str::from_utf8(&response).unwrap(),
            body,
            "{method} {target}"
        );
    }
}

/// Claude Desktop control-plane fixtures (identity values fixed here; the
/// real ones are random, see `Identity::prepare`).
#[test]
fn claude_desktop_fixtures_are_byte_identical() {
    let id = crate::claude_desktop::Identity {
        account: "acct-uuid".into(),
        organization: "org-uuid".into(),
        access_token: "MOCK_ONLY_ACCESS".into(),
        refresh_token: "MOCK_ONLY_REFRESH".into(),
        session: "MOCK_ONLY_SESSION".into(),
    };
    assert_eq!(
        crate::claude_desktop_fixtures::account(&id).to_string(),
        r#"{"age_is_verified":true,"created_at":"2026-01-01T00:00:00Z","display_name":"SAIAI Local Code","email_address":"","full_name":"SAIAI Local Code","has_completed_onboarding":true,"has_consented_to_terms":true,"invites":[],"is_verified":true,"memberships":[{"organization":{"active_flags":[],"capabilities":["chat","claude_pro","claude_code"],"created_at":"2026-01-01T00:00:00Z","name":"SAIAI Local Code","rate_limit_tier":"default_claude_ai","settings":{},"uuid":"org-uuid"},"role":"owner"}],"settings":{"has_finished_claudeai_onboarding":true},"uuid":"acct-uuid"}"#
    );
    assert_eq!(
        crate::claude_desktop_fixtures::selectors(&[], &json!({"id":"code","model":"m"}))
            .to_string(),
        r#"[{"default_model":"m","id":"code","models":[],"revision":"saiai-local-1"},{"default_model":null,"id":"chat","models":[],"revision":"saiai-local-1"}]"#
    );
    for (method, path, status, body) in [
        (
            "GET",
            "/logout",
            200,
            r#"{"logged_out":true,"message":"Local session ended. Relaunch saiai desktop claude to reconnect."}"#,
        ),
        (
            "POST",
            "/api/organizations/org-uuid/chat_conversations/c/completion",
            409,
            r#"{"error":{"message":"SAIAI supports Code only. Open the Code tab; Chat and Cowork are not supported.","type":"desktop_surface_unsupported"}}"#,
        ),
    ] {
        let (code, value) = crate::claude_desktop_fixtures::local(method, path, &id).unwrap();
        assert_eq!(code, status, "{method} {path}");
        assert_eq!(value.to_string(), body, "{method} {path}");
    }
}

/// The synthetic names come from the brand: another brand's answers carry
/// its own names and none of SAIAI's.
#[test]
fn synthetic_names_follow_the_brand() {
    use crate::brand::{Brand, PlaceholderIdentities};
    use crate::brand_saiai::SAIAI_VALUES;
    static ACME: Brand = Brand {
        binary_name: "acme",
        product_name: "Acme",
        placeholders: PlaceholderIdentities {
            synthetic_id_prefix: "acme-local",
            ..SAIAI_VALUES.placeholders
        },
        ..SAIAI_VALUES
    };
    let payload = desktop_statsig_local_payload(&ACME);
    for name in [
        r#""rule_id":"acme-local-i18n""#,
        r#""userID":"acme-local-proxy-user""#,
        r#""stableID":"acme-local-proxy""#,
    ] {
        assert!(payload.contains(name), "{payload}");
    }
    let browser = desktop_statsig_base(&ACME, DesktopFeatures { browser_use: true }).to_string();
    assert!(
        browser.contains(r#""rule_id":"acme-local-browser-use""#),
        "{browser}"
    );
    assert_eq!(synthetic_user_id(&ACME), "acme-local-proxy-user");
    assert_eq!(
        desktop_control_unsupported_message(&ACME),
        "This Desktop control endpoint is unavailable through Acme."
    );
    assert_eq!(
        crate::claude_desktop_fixtures::local_code_name(&ACME),
        "Acme Local Code"
    );
    assert_eq!(
        crate::claude_desktop_fixtures::desktop_claude_command(&ACME),
        "acme desktop claude"
    );
    for text in [payload, browser] {
        assert!(!text.to_ascii_lowercase().contains("saiai"), "{text}");
    }
}
