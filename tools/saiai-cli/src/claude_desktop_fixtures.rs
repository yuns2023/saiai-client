//! Versioned local control-plane patches for Desktop 4.23118.0.
use crate::claude_desktop::Identity;
use serde_json::{Value, json};

#[derive(Debug, PartialEq)]
pub(crate) enum Route {
    Bootstrap,
    Public,
    Local,
    Reject,
}

pub(crate) fn classify(method: &str, path: &str, org: &str) -> Route {
    // Do not let URL normalization turn an encoded API path into a public page.
    if !path.starts_with('/')
        || path.contains(['%', '\\', '#'])
        || path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Route::Reject;
    }
    if method == "GET"
        && (matches!(path, "/api/bootstrap" | "/edge-api/bootstrap")
            || path == format!("/api/bootstrap/{org}/app_start")
            || path == format!("/edge-api/bootstrap/{org}/app_start"))
    {
        return Route::Bootstrap;
    }
    if matches!(method, "GET" | "HEAD")
        && (path == "/api/desktop/features"
            || (!path.split('/').nth(1).is_some_and(|s| {
                matches!(s.to_ascii_lowercase().as_str(), "api" | "edge-api" | "v1")
            }) && path != "/logout"))
    {
        return Route::Public;
    }
    Route::Local
}

pub(crate) fn account(id: &Identity) -> Value {
    json!({"uuid":id.account,"email_address":"","full_name":"SAIAI Local Code","display_name":"SAIAI Local Code",
        "created_at":"2026-01-01T00:00:00Z","has_consented_to_terms":true,"has_completed_onboarding":true,
        "is_verified":true,"settings":{"has_finished_claudeai_onboarding":true},
        "memberships":[{"role":"owner","organization":organization(id)}],"invites":[],"age_is_verified":true})
}
pub(crate) fn organization(id: &Identity) -> Value {
    json!({"uuid":id.organization,"name":"SAIAI Local Code","capabilities":["chat","claude_pro","claude_code"],
        "settings":{},"active_flags":[],"created_at":"2026-01-01T00:00:00Z","rate_limit_tier":"default_claude_ai"})
}
fn access() -> Value {
    json!({"features":[{"feature":"claude_code","status":"available"},{"feature":"claude_code_desktop","status":"available"}],
        "account_features":[],"organization_permissions":[]})
}

pub(crate) fn patch(
    bootstrap: &mut Value,
    id: &Identity,
    models: &[Value],
    selection: &Value,
) -> anyhow::Result<()> {
    let object = bootstrap
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("anonymous bootstrap is not an object"))?;
    object.insert("account".into(), account(id));
    object.insert("featureFlagsOrgUuid".into(), json!(id.organization));
    object.insert("current_user_access".into(), access());
    object.insert("model_selector_config".into(), selectors(models, selection));
    object.insert(
        "model_selector_state".into(),
        json!([selection, {"id":"chat","model":null,"thinking":null,"thinking_by_model":[]} ]),
    );
    Ok(())
}
pub(crate) fn selectors(models: &[Value], selection: &Value) -> Value {
    json!([{"id":"code","revision":"saiai-local-1","models":models,"default_model":selection["model"]},
        {"id":"chat","revision":"saiai-local-1","models":[],"default_model":null}])
}

pub(crate) fn local(method: &str, path: &str, id: &Identity) -> Option<(u16, Value)> {
    if path == "/api/event_logging/v2/batch" || path == "/edge-api/browser-reports" {
        return Some((204, Value::Null));
    }
    if path == "/api/desktop/linux/x64/deb/latest" {
        return Some((204, Value::Null));
    }
    if path == "/logout" || path == "/api/auth/logout" {
        return Some((
            200,
            json!({"logged_out":true,"message":"Local session ended. Relaunch saiai desktop claude to reconnect."}),
        ));
    }
    if path.contains("/completion")
        || path.ends_with("/messages")
        || (method != "GET"
            && (path.contains("/chat_conversations")
                || path.contains("/cowork")
                || path.starts_with("/v1/code/")))
    {
        return Some((
            409,
            json!({"error":{"type":"desktop_surface_unsupported","message":"SAIAI supports Code only. Open the Code tab; Chat and Cowork are not supported."}}),
        ));
    }
    if method == "PUT" && path == "/v1/privacy-consents" {
        return Some((200, json!({})));
    }
    if method != "GET" {
        return None;
    }
    let org = format!("/api/organizations/{}", id.organization);
    let bootstrap = format!("/api/bootstrap/{}", id.organization);
    if path == format!("{org}/model_selector/chat") {
        return Some((
            200,
            json!({"model_selector_config":[{"id":"chat","models":[],"default_model":null}],"model_selector_state":[{"id":"chat","model":null}]}),
        ));
    }
    if path == format!("{org}/model_selector_state/chat") {
        return Some((200, json!({"id":"chat","model":null})));
    }
    let value = match path {
        "/api/account" | "/api/account_profile" => account(id),
        "/api/organizations" => json!([organization(id)]),
        "/api/organizations/discoverable" => json!([]),
        "/api/claude_code/settings" | "/api/referral" => json!({}),
        "/api/account/raven_eligible" => json!({"eligible":false}),
        "/edge-api/client-health/check" => json!({"status":"ok"}),
        "/v1/code/sessions" => json!({"data":[],"sessions":[],"has_more":false}),
        "/v1/code/triggers" => json!({"data":[],"triggers":[],"has_more":false}),
        "/v1/privacy-consents" => {
            json!({"consents":[{"consent_type":"cookies.analytics","consent_decision":"CONSENT_DECISION_OPT_OUT"},{"consent_type":"cookies.marketing","consent_decision":"CONSENT_DECISION_OPT_OUT"}]})
        }
        _ if path == org => organization(id),
        _ if path == format!("{bootstrap}/current_user_access") => access(),
        _ if path == format!("{bootstrap}/system_prompts")
            || path == format!("{bootstrap}/cowork_sysprompt_map") =>
        {
            json!({})
        }
        _ if path == format!("/api/billing/{}/gift/purchase_eligibility", id.organization) => {
            json!({"eligible":false,"can_purchase":false})
        }
        _ if path
            == format!(
                "/v1/environment_providers/private/organizations/{}/environments",
                id.organization
            ) =>
        {
            json!({"environments":[],"has_more":false})
        }
        _ => match path.strip_prefix(&format!("{org}/"))? {
            "usage" => json!({"five_hour":null,"seven_day":null}),
            "plugins/list-plugins" => json!({"plugins":[],"has_more":false}),
            "skills/list-skills" => json!({"skills":[]}),
            "marketplaces/list-default-marketplaces" => json!({"marketplaces":[]}),
            "chat_conversations" | "projects" => json!([]),
            "chat_conversations_v2" => json!({"conversations":[],"has_more":false}),
            "projects_v2" => json!({"data":[],"projects":[],"has_more":false}),
            "projects/count" => json!({"count":0}),
            "memory/settings" => json!({"enabled_saffron":false,"memory_mode":"off"}),
            "cowork_plugin_metadata" => json!({"plugins":{}}),
            "activation/cowork/tasks" | "activation/chorus_free/tasks" => json!({"tasks":[]}),
            "subscription_details" => json!({"is_mock":true}),
            "sync/github/auth" => {
                json!({"is_authenticated":false,"github_accounts":[],"ghe_connections":[]})
            }
            _ => return None,
        },
    };
    Some((200, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_do_not_turn_unknown_or_encoded_api_calls_into_public_pages() {
        for path in [
            "/",
            "/epitaxy",
            "/static/app.js",
            "/cdn-cgi/challenge-platform/a",
            "/api/desktop/features",
        ] {
            assert_eq!(classify("GET", path, "org"), Route::Public);
        }
        for path in [
            "/api/unknown",
            "/API/private",
            "/Edge-Api/private",
            "/V1/private",
            "/api",
            "/edge-api/private",
            "/v1/private",
            "/edge-api/bootstrap/other/app_start",
        ] {
            assert_eq!(classify("GET", path, "org"), Route::Local);
        }
        for path in [
            "/%61pi/private",
            "/api#x",
            "/api%2fprivate",
            "//api/private",
            "/a/../api/private",
            "/api\\private",
        ] {
            assert_eq!(classify("GET", path, "org"), Route::Reject);
        }
        assert_eq!(
            classify("GET", "/edge-api/bootstrap/org/app_start", "org"),
            Route::Bootstrap
        );
        assert_eq!(classify("POST", "/page", "org"), Route::Local);
    }
    #[test]
    fn fixtures_are_scoped_and_keep_ui_identity_separate() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::prepare(dir.path()).unwrap();
        assert!(local("GET", "/api/organizations/foreign", &id).is_none());
        assert_eq!(account(&id)["email_address"], "");
        assert_ne!(account(&id)["uuid"], organization(&id)["uuid"]);
        assert_eq!(
            local(
                "POST",
                "/api/organizations/x/chat_conversations/y/completion",
                &id
            )
            .unwrap()
            .0,
            409
        );
    }
}
