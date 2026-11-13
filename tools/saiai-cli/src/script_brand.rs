//! Brand names inside the program's own helper scripts.
//!
//! PowerShell helpers are templates: `@@ENV@@` (helper environment variable
//! prefix), `@@ID@@` (prefix of .NET types and PowerShell functions the
//! scripts define), `@@APP_DIR@@` (Windows per-user directory) and
//! `@@CA_ORG@@` (installation CA organization). [`render`] replaces them with
//! the installed brand's values; Rust passes variables named by [`env`], so
//! both sides read the same brand field.
//!
//! Escaping: instead of quoting, every value is restricted to a character set
//! that cannot leave its position — no quotes, `$`, backtick, backslash,
//! dot or other regex/PowerShell metacharacters — and a value outside it
//! panics before any script runs. Templates are rendered before any
//! user-controlled data is added, so data is never scanned for tokens.

use crate::brand::BRAND;

/// Name of an environment variable handed to one of the program's helpers.
// Helper scripts run only on Windows.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn env(name: &str) -> String {
    format!("{}{name}", values().env_prefix)
}

/// Marker for "no value" passed to the Windows proxy settings helper.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn null_sentinel() -> String {
    format!("__{}NULL__", values().env_prefix)
}

/// Prefix of .NET types and PowerShell functions, for helpers assembled with
/// `format!` around user data (insert it as an argument instead of rendering
/// the finished text).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn identifier_prefix() -> &'static str {
    values().identifier_prefix
}

/// A helper script with the brand tokens replaced.
// Helper scripts run only on Windows.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn render(template: &str) -> String {
    let values = values();
    let rendered = template
        .replace("@@ENV@@", values.env_prefix)
        .replace("@@ID@@", values.identifier_prefix)
        .replace("@@APP_DIR@@", values.app_dir)
        .replace("@@CA_ORG@@", values.ca_organization);
    assert!(
        !rendered.contains("@@"),
        "helper script contains an unknown brand token"
    );
    rendered
}

struct Values {
    env_prefix: &'static str,
    identifier_prefix: &'static str,
    app_dir: &'static str,
    ca_organization: &'static str,
}

fn values() -> Values {
    let values = Values {
        env_prefix: BRAND.scripts.env_prefix,
        identifier_prefix: BRAND.scripts.identifier_prefix,
        app_dir: BRAND.windows_app_dir_name,
        ca_organization: BRAND.certificates.ca_organization,
    };
    for (field, value, valid) in [
        (
            "scripts.env_prefix",
            values.env_prefix,
            valid_env_prefix as fn(&str) -> bool,
        ),
        (
            "scripts.identifier_prefix",
            values.identifier_prefix,
            valid_identifier,
        ),
        ("windows_app_dir_name", values.app_dir, valid_plain_name),
        (
            "certificates.ca_organization",
            values.ca_organization,
            valid_plain_name,
        ),
    ] {
        assert!(
            valid(value),
            "brand {field} is not safe in helper scripts: {value:?}"
        );
    }
    values
}

/// `[A-Z][A-Z0-9_]*_`
fn valid_env_prefix(value: &str) -> bool {
    value.starts_with(|ch: char| ch.is_ascii_uppercase())
        && value.ends_with('_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// `[A-Z][A-Za-z0-9]*`
fn valid_identifier(value: &str) -> bool {
    value.starts_with(|ch: char| ch.is_ascii_uppercase())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// `[A-Za-z0-9][A-Za-z0-9 _-]*`
fn valid_plain_name(value: &str) -> bool {
    value.starts_with(|ch: char| ch.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brand_values_are_checked_against_script_injection() {
        assert!(valid_env_prefix("SAIAI_"));
        assert!(valid_identifier("Saiai"));
        assert!(valid_plain_name("SAIAI"));
        for value in ["", "SAIAI", "saiai_", "SA$AI_", "SA'_", "SA`_", "SA I_"] {
            assert!(!valid_env_prefix(value), "{value:?}");
        }
        for value in ["", "saiai", "Sai-ai", "Sai.ai", "Sai'ai", "Sai$x"] {
            assert!(!valid_identifier(value), "{value:?}");
        }
        for value in [
            "", " SAIAI", "SA'AI", "SA$AI", "SA`AI", "SA\\AI", "SA.AI", "SA(AI)", "SA|AI", "SA;AI",
        ] {
            assert!(!valid_plain_name(value), "{value:?}");
        }
    }

    #[test]
    fn rendering_replaces_every_token_with_the_installed_brand() {
        assert_eq!(
            render("$env:@@ENV@@X [@@ID@@Y] '@@APP_DIR@@\\z' 'O=@@CA_ORG@@'"),
            "$env:SAIAI_X [SaiaiY] 'SAIAI\\z' 'O=SAIAI'"
        );
        assert_eq!(env("CA_FILES"), "SAIAI_CA_FILES");
        assert_eq!(null_sentinel(), "__SAIAI_NULL__");
        assert_eq!(identifier_prefix(), "Saiai");
    }

    #[test]
    #[should_panic(expected = "unknown brand token")]
    fn unknown_tokens_are_rejected() {
        render("@@OTHER@@");
    }
}
