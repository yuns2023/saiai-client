//! Egress route for connections SAIAI makes to the Gateway and to passthrough
//! destinations (CONNECT tunnels and plain HTTP forwarding).
//!
//! By default SAIAI follows the user's own network: a proxy configured in the
//! SAIAI service environment (`HTTPS_PROXY` and friends) or in the operating
//! system is used, and without one SAIAI connects directly. A configured but
//! unusable proxy fails the connection instead of silently going direct, as a
//! browser would. `upstream_proxy` in the SAIAI config, or the
//! `SAIAI_UPSTREAM_PROXY` environment variable, selects `system` (default),
//! `direct`, or a fixed `http://[user:password@]host:port` proxy.
//!
//! Only HTTP proxies (with optional Basic authentication) are supported.
//! Windows proxy auto-configuration (PAC/WPAD) is evaluated by WinHTTP; macOS
//! automatic configuration is not evaluated and SAIAI connects directly.
//!
//! The policy is re-read every 30 seconds. Each change publishes a new
//! snapshot with a new generation; HTTP clients are rebuilt per generation so
//! pooled connections never outlive a route change, while established tunnels
//! and WebSockets keep their route until they close.

use anyhow::{Context, Result, bail};
use base64::Engine;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};

pub(crate) const UPSTREAM_PROXY_ENV: crate::brand::BrandValue<&'static str> =
    crate::brand::BrandValue(|brand| brand.env.upstream_proxy);
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PROXY_RESPONSE_HEAD: usize = 16 * 1024;
const PAC_QUEUE_BUDGET: Duration = Duration::from_secs(30);
#[cfg(target_os = "windows")]
const PAC_CACHE_TTL: Duration = Duration::from_secs(300);
#[cfg(target_os = "windows")]
const PAC_ERROR_TTL: Duration = Duration::from_secs(30);

/// An HTTP proxy. Credentials never appear in `Debug`/`Display` output.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct Endpoint {
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
}

impl Endpoint {
    /// Parses `http://[user:password@]host[:port]` or a bare `host:port`.
    /// Errors never echo the value, which may contain a password.
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let candidate = if value.contains("://") {
            value.to_string()
        } else {
            format!("http://{value}")
        };
        let url =
            url::Url::parse(&candidate).map_err(|_| anyhow::anyhow!("is not a valid proxy URL"))?;
        match url.scheme() {
            "http" => {}
            "https" => bail!("is an https:// proxy; only http:// proxies are supported"),
            scheme if scheme.starts_with("socks") => {
                bail!("is a SOCKS proxy; only http:// proxies are supported")
            }
            _ => bail!("is not an http:// proxy URL"),
        }
        let host = match url.host() {
            Some(url::Host::Domain(host)) => host.to_string(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => bail!("has no proxy host"),
        };
        if !matches!(url.path(), "" | "/") || url.query().is_some() {
            bail!("must not contain a path or query");
        }
        let decode = |part: &str| {
            percent_decode(part).map_err(|_| anyhow::anyhow!("has invalid credential encoding"))
        };
        Ok(Self {
            host,
            port: url.port_or_known_default().unwrap_or(80),
            username: decode(url.username())?,
            password: url.password().map(decode).transpose()?,
        })
    }

    fn has_credentials(&self) -> bool {
        !self.username.is_empty() || self.password.is_some()
    }

    fn authority(&self) -> String {
        host_port(&self.host, self.port)
    }

    fn proxy_authorization(&self) -> Option<String> {
        self.has_credentials().then(|| {
            let credentials = format!(
                "{}:{}",
                self.username,
                self.password.as_deref().unwrap_or_default()
            );
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(credentials)
            )
        })
    }

    /// True when the proxy is this SAIAI listener itself, e.g. an inherited
    /// `HTTPS_PROXY` that SAIAI set for a Claude or Codex child.
    fn is_listener(&self, listen: Option<SocketAddr>) -> bool {
        let Some(listen) = listen else {
            return false;
        };
        if self.port != listen.port() {
            return false;
        }
        let host = normalize_host(&self.host);
        host == "localhost"
            || host.ends_with(".localhost")
            || host
                .parse::<IpAddr>()
                .map(|ip| ip.to_canonical())
                .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified() || ip == listen.ip())
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "http://{}", self.authority())?;
        if self.has_credentials() {
            formatter.write_str(" (with credentials)")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

fn percent_decode(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3).ok_or(())?;
            let hex = std::str::from_utf8(hex).map_err(|_| ())?;
            decoded.push(u8::from_str_radix(hex, 16).map_err(|_| ())?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Route {
    Direct,
    Proxy(Endpoint),
}

impl fmt::Display for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Route::Direct => formatter.write_str("direct"),
            Route::Proxy(endpoint) => write!(formatter, "via {endpoint}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    System,
    Direct,
    Fixed(Endpoint),
}

fn parse_mode(value: &str) -> Result<Mode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "system" => Ok(Mode::System),
        "direct" | "none" => Ok(Mode::Direct),
        _ => Endpoint::parse(value).map(Mode::Fixed),
    }
}

/// Human-readable setting with credentials removed.
pub(crate) fn describe_setting(setting: Option<&str>) -> String {
    match setting.map(parse_mode) {
        None => "system (default)".to_string(),
        Some(Ok(Mode::System)) => "system".to_string(),
        Some(Ok(Mode::Direct)) => "direct".to_string(),
        Some(Ok(Mode::Fixed(endpoint))) => endpoint.to_string(),
        Some(Err(_)) => "invalid".to_string(),
    }
}

/// Validates a value for the `upstream_proxy` setting.
pub(crate) fn validate_setting(value: &str) -> Result<()> {
    parse_mode(value)
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("upstream proxy {error}"))
}

// ---------------------------------------------------------------------------
// Bypass rules

#[derive(Clone, Debug, PartialEq, Eq)]
enum BypassRule {
    All,
    /// Windows `<local>` and macOS "exclude simple hostnames".
    SimpleHostnames,
    Glob(String),
    Domain(String),
    Network(IpAddr, u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BypassEntry {
    rule: BypassRule,
    /// `host:port` entries only match that destination port.
    port: Option<u16>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Bypass {
    rules: Vec<BypassEntry>,
    /// `NO_PROXY`/macOS style: `example.com` also covers its subdomains.
    /// Windows `ProxyOverride` entries match exactly unless they use `*`.
    subdomains: bool,
}

impl Bypass {
    fn parse<'a>(entries: impl IntoIterator<Item = &'a str>, subdomains: bool) -> Self {
        let mut rules = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            let entry = entry
                .strip_prefix("http://")
                .or_else(|| entry.strip_prefix("https://"))
                .unwrap_or(entry);
            if entry.is_empty() {
                continue;
            }
            // A malformed port is skipped rather than widened to all ports.
            let Some((entry, port)) = split_entry_port(entry) else {
                continue;
            };
            let rule = if entry == "*" {
                BypassRule::All
            } else if entry.eq_ignore_ascii_case("<local>") {
                BypassRule::SimpleHostnames
            } else if let Some(network) = parse_network(entry) {
                network
            } else if entry.contains('*') {
                BypassRule::Glob(entry.to_ascii_lowercase())
            } else {
                BypassRule::Domain(normalize_host(entry))
            };
            rules.push(BypassEntry { rule, port });
        }
        Self { rules, subdomains }
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        let host = normalize_host(host);
        let ip = host.parse::<IpAddr>().ok();
        self.rules.iter().any(|entry| {
            entry.port.is_none_or(|only| only == port)
                && match &entry.rule {
                    BypassRule::All => true,
                    BypassRule::SimpleHostnames => ip.is_none() && !host.contains('.'),
                    BypassRule::Glob(pattern) => glob_matches(pattern, &host),
                    BypassRule::Domain(domain) => {
                        let bare = domain.trim_start_matches('.');
                        host == bare
                            || ((self.subdomains || domain.starts_with('.'))
                                && host.ends_with(&format!(".{bare}")))
                    }
                    BypassRule::Network(network, prefix) => {
                        ip.is_some_and(|ip| ip_in_network(ip, *network, *prefix))
                    }
                }
        })
    }
}

/// Splits `host:port`, `[v6]:port` and `[v6]`; bare IPv6 literals and CIDR
/// ranges keep their colons. `None` for a malformed port.
fn split_entry_port(entry: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        return match tail {
            "" => Some((host, None)),
            _ => Some((host, Some(tail.strip_prefix(':')?.parse().ok()?))),
        };
    }
    match entry.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host, Some(port.parse().ok()?))),
        _ => Some((entry, None)),
    }
}

fn parse_network(entry: &str) -> Option<BypassRule> {
    let (address, prefix) = match entry.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
        None => (entry, None),
    };
    let ip = match address.parse::<IpAddr>() {
        Ok(ip) => ip,
        // macOS writes abbreviated IPv4 networks such as `169.254/16`.
        Err(_) if prefix.is_some() => {
            let octets = address
                .split('.')
                .map(|part| part.parse::<u8>().ok())
                .collect::<Option<Vec<_>>>()?;
            if octets.is_empty() || octets.len() > 4 {
                return None;
            }
            let mut full = [0_u8; 4];
            full[..octets.len()].copy_from_slice(&octets);
            IpAddr::from(full)
        }
        Err(_) => return None,
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(max);
    (prefix <= max).then_some(BypassRule::Network(ip, prefix))
}

fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t) = (0, 0);
    let (mut star, mut resume) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == text[t] || pattern[p] == b'?') {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            resume = t;
            p += 1;
        } else if let Some(star) = star {
            p = star + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

fn is_loopback_target(host: &str) -> bool {
    let host = normalize_host(host);
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

// ---------------------------------------------------------------------------
// Policy

// Holds raw proxy configuration (possibly credentials): no Debug outside tests.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
struct StaticProxies {
    http: Option<Endpoint>,
    https: Option<Endpoint>,
    /// A scheme whose only configured proxy is unsupported (e.g. a SOCKS
    /// `ALL_PROXY` with no `HTTP_PROXY`) fails instead of going direct.
    http_error: Option<String>,
    https_error: Option<String>,
    bypass: Bypass,
}

impl StaticProxies {
    fn route(&self, https: bool, host: &str, port: u16) -> Result<Route, String> {
        if self.bypass.matches(host, port) {
            return Ok(Route::Direct);
        }
        let (endpoint, error) = if https {
            (&self.https, &self.https_error)
        } else {
            (&self.http, &self.http_error)
        };
        match (endpoint, error) {
            (Some(endpoint), _) => Ok(Route::Proxy(endpoint.clone())),
            (None, Some(error)) => Err(error.clone()),
            (None, None) => Ok(Route::Direct),
        }
    }
}

// Holds raw proxy configuration (possibly credentials): no Debug outside tests.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
enum Policy {
    Direct,
    Static(StaticProxies),
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    WindowsAuto {
        auto_detect: bool,
        config_url: Option<String>,
        fallback: StaticProxies,
    },
    Unavailable(String),
}

/// Raw proxy configuration as read from the environment and the OS. Two
/// equal readings yield the same policy, so only changes publish a snapshot.
// Holds raw proxy configuration (possibly credentials): no Debug outside tests.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
struct Inputs {
    mode: Result<Mode, String>,
    env: EnvProxies,
    os: OsProxy,
}

// Holds raw proxy configuration (possibly credentials): no Debug outside tests.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
struct EnvProxies {
    https: Option<(&'static str, String)>,
    http: Option<(&'static str, String)>,
    all: Option<(&'static str, String)>,
    no_proxy: Option<String>,
}

impl EnvProxies {
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let first = |names: &[&'static str]| {
            names.iter().find_map(|name| {
                lookup(name)
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| (*name, value))
            })
        };
        Self {
            https: first(&["https_proxy", "HTTPS_PROXY"]),
            http: first(&["http_proxy", "HTTP_PROXY"]),
            all: first(&["all_proxy", "ALL_PROXY"]),
            no_proxy: first(&["no_proxy", "NO_PROXY"]).map(|(_, value)| value),
        }
    }
}

// Each platform constructs only its own variant.
// Holds raw proxy configuration (possibly credentials): no Debug outside tests.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
enum OsProxy {
    None,
    Windows {
        auto_detect: bool,
        config_url: Option<String>,
        proxy: Option<String>,
        bypass: Option<String>,
    },
    MacOs(String),
    Unreadable(String),
}

fn policy_from_inputs(inputs: &Inputs, listen: Option<SocketAddr>) -> (Policy, String) {
    let mode = match &inputs.mode {
        Ok(mode) => mode,
        Err(error) => return (Policy::Unavailable(error.clone()), error.clone()),
    };
    match mode {
        Mode::Direct => (Policy::Direct, "direct (configured)".to_string()),
        Mode::Fixed(endpoint) if endpoint.is_listener(listen) => {
            let message = "the configured upstream proxy is this SAIAI proxy itself".to_string();
            (Policy::Unavailable(message.clone()), message)
        }
        Mode::Fixed(endpoint) => (
            Policy::Static(StaticProxies {
                http: Some(endpoint.clone()),
                https: Some(endpoint.clone()),
                bypass: Bypass::default(),
                ..StaticProxies::default()
            }),
            format!("{endpoint} (configured)"),
        ),
        Mode::System => system_policy(&inputs.env, &inputs.os, listen),
    }
}

fn system_policy(env: &EnvProxies, os: &OsProxy, listen: Option<SocketAddr>) -> (Policy, String) {
    let mut ignored = Vec::new();
    let mut parse_env = |entry: &Option<(&'static str, String)>| -> Result<Option<Endpoint>> {
        let Some((name, value)) = entry else {
            return Ok(None);
        };
        let endpoint =
            Endpoint::parse(value).with_context(|| format!("{name} in the SAIAI environment"))?;
        if endpoint.is_listener(listen) {
            ignored.push(*name);
            return Ok(None);
        }
        Ok(Some(endpoint))
    };
    // ALL_PROXY only fills a scheme without its own proxy, so an unused
    // value (often a SOCKS URL next to HTTP ones) does not matter, and an
    // unsupported value only fails the scheme that needs it.
    let mut scheme = |own: &Option<(&'static str, String)>| {
        // A scheme variable pointing at this listener is ignored like an
        // unset one, so ALL_PROXY still applies.
        if let Some(endpoint) = parse_env(own).map_err(|error| format!("{error:#}"))? {
            return Ok(Some(endpoint));
        }
        parse_env(&env.all).map_err(|error| format!("{error:#}"))
    };
    let https = scheme(&env.https);
    let http = scheme(&env.http);
    if let (Err(message), Err(_)) = (&https, &http) {
        return (Policy::Unavailable(message.clone()), message.clone());
    }
    let note = if ignored.is_empty() {
        String::new()
    } else {
        format!(
            " (ignored {} pointing at this SAIAI proxy)",
            ignored.join(", ")
        )
    };
    if !matches!((&https, &http), (Ok(None), Ok(None))) {
        let describe_scheme = |scheme: &Result<Option<Endpoint>, String>| match scheme {
            Ok(endpoint) => describe(endpoint),
            Err(message) => format!("unavailable ({message})"),
        };
        let description = format!(
            "environment: https {}, http {}{note}",
            describe_scheme(&https),
            describe_scheme(&http)
        );
        let proxies = StaticProxies {
            https_error: https.as_ref().err().cloned(),
            http_error: http.as_ref().err().cloned(),
            https: https.ok().flatten(),
            http: http.ok().flatten(),
            bypass: Bypass::parse(env.no_proxy.as_deref().unwrap_or_default().split(','), true),
        };
        return (Policy::Static(proxies), description);
    }
    let (policy, description) = os_policy(os, listen);
    (policy, format!("{description}{note}"))
}

fn describe(endpoint: &Option<Endpoint>) -> String {
    endpoint
        .as_ref()
        .map_or_else(|| "direct".to_string(), ToString::to_string)
}

fn os_policy(os: &OsProxy, listen: Option<SocketAddr>) -> (Policy, String) {
    let unavailable = |message: String| (Policy::Unavailable(message.clone()), message);
    match os {
        OsProxy::None => (Policy::Direct, "direct (no proxy configured)".to_string()),
        OsProxy::Unreadable(error) => {
            unavailable(format!("failed to read the system proxy: {error}"))
        }
        OsProxy::Windows {
            auto_detect,
            config_url,
            proxy,
            bypass,
        } => {
            let fallback = match windows_static_proxies(proxy.as_deref(), bypass.as_deref(), listen)
            {
                Ok(fallback) => fallback,
                Err(error) => return unavailable(format!("Windows proxy {error:#}")),
            };
            if *auto_detect || config_url.is_some() {
                // A configured script that fails is an error; only WPAD
                // finding nothing falls back to the static settings.
                let description = if config_url.is_some() {
                    "Windows automatic configuration script".to_string()
                } else {
                    format!(
                        "Windows automatic proxy detection, else {}",
                        describe_static(&fallback)
                    )
                };
                return (
                    Policy::WindowsAuto {
                        auto_detect: *auto_detect,
                        config_url: config_url.clone(),
                        fallback,
                    },
                    description,
                );
            }
            let description = format!("Windows system proxy: {}", describe_static(&fallback));
            (Policy::Static(fallback), description)
        }
        OsProxy::MacOs(scutil) => macos_policy(scutil, listen),
    }
}

fn describe_static(proxies: &StaticProxies) -> String {
    if proxies.https.is_none() && proxies.http.is_none() {
        return "direct".to_string();
    }
    format!(
        "https {}, http {}",
        describe(&proxies.https),
        describe(&proxies.http)
    )
}

/// Parses WinINet `ProxyServer` (`host:port` or `http=a:1;https=b:2;socks=c:3`)
/// and `ProxyOverride`.
fn windows_static_proxies(
    proxy: Option<&str>,
    bypass: Option<&str>,
    listen: Option<SocketAddr>,
) -> Result<StaticProxies> {
    let mut all = None;
    let mut http = None;
    let mut https = None;
    let mut socks = false;
    for entry in proxy
        .unwrap_or_default()
        .split([';', ' ', '\t', '\r', '\n'])
        .filter(|entry| !entry.trim().is_empty())
    {
        let (scheme, value) = match entry.split_once('=') {
            Some((scheme, value)) => (Some(scheme.trim().to_ascii_lowercase()), value),
            None => (None, entry),
        };
        let slot = match scheme.as_deref() {
            None => &mut all,
            Some("http") => &mut http,
            Some("https") => &mut https,
            Some("socks") => {
                socks = true;
                continue;
            }
            Some(_) => continue,
        };
        let endpoint = Endpoint::parse(value).context("ProxyServer entry")?;
        if !endpoint.is_listener(listen) && slot.is_none() {
            *slot = Some(endpoint);
        }
    }
    let https = https.or_else(|| all.clone());
    let http = http.or(all);
    if socks && https.is_none() && http.is_none() {
        bail!("is a SOCKS proxy; only HTTP proxies are supported");
    }
    // `socks=` serves every scheme without its own entry.
    let socks_error =
        || socks.then(|| "Windows SOCKS proxy is not supported; only HTTP proxies are".to_string());
    let proxies = StaticProxies {
        https_error: https.is_none().then(socks_error).flatten(),
        http_error: http.is_none().then(socks_error).flatten(),
        https,
        http,
        bypass: Bypass::parse(bypass.unwrap_or_default().split([';', ' ']), false),
    };
    Ok(proxies)
}

/// Parses `scutil --proxy` output.
fn macos_policy(scutil: &str, listen: Option<SocketAddr>) -> (Policy, String) {
    let mut values = HashMap::new();
    let mut exceptions = Vec::new();
    let mut in_exceptions = false;
    for line in scutil.lines() {
        let line = line.trim();
        if in_exceptions {
            if line == "}" {
                in_exceptions = false;
            } else if let Some((_, value)) = line.split_once(" : ") {
                exceptions.push(value.trim().to_string());
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(" : ") {
            if key == "ExceptionsList" {
                in_exceptions = value.trim().starts_with("<array>");
            } else {
                values.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    let enabled = |key: &str| values.get(key).is_some_and(|value| value == "1");
    if enabled("ProxyAutoConfigEnable") || enabled("ProxyAutoDiscoveryEnable") {
        return (
            Policy::Direct,
            "direct (macOS automatic proxy configuration is not evaluated)".to_string(),
        );
    }
    let endpoint = |prefix: &str| -> Result<Option<Endpoint>> {
        if !enabled(&format!("{prefix}Enable")) {
            return Ok(None);
        }
        let host = values
            .get(&format!("{prefix}Proxy"))
            .filter(|host| !host.is_empty())
            .with_context(|| format!("{prefix} proxy has no host"))?;
        let port = values
            .get(&format!("{prefix}Port"))
            .map(String::as_str)
            .unwrap_or("80");
        let endpoint = Endpoint::parse(&host_port(host, port.parse().unwrap_or(80)))
            .with_context(|| format!("{prefix} proxy"))?;
        Ok((!endpoint.is_listener(listen)).then_some(endpoint))
    };
    let (https, http) = match (endpoint("HTTPS"), endpoint("HTTP")) {
        (Ok(https), Ok(http)) => (https, http),
        (Err(error), _) | (_, Err(error)) => {
            let message = format!("macOS system proxy: {error:#}");
            return (Policy::Unavailable(message.clone()), message);
        }
    };
    if https.is_none() && http.is_none() {
        if enabled("SOCKSEnable") {
            let message =
                "macOS system proxy is a SOCKS proxy; only HTTP proxies are supported".to_string();
            return (Policy::Unavailable(message.clone()), message);
        }
        return (Policy::Direct, "direct (no proxy configured)".to_string());
    }
    let mut bypass = Bypass::parse(exceptions.iter().map(String::as_str), true);
    if enabled("ExcludeSimpleHostnames") {
        bypass.rules.push(BypassEntry {
            rule: BypassRule::SimpleHostnames,
            port: None,
        });
    }
    let proxies = StaticProxies {
        https,
        http,
        bypass,
        ..StaticProxies::default()
    };
    let description = format!("macOS system proxy: {}", describe_static(&proxies));
    (Policy::Static(proxies), description)
}

// ---------------------------------------------------------------------------
// Snapshots and the resolver

/// One published policy. HTTP clients built from a snapshot keep using it.
pub(crate) struct Snapshot {
    generation: u64,
    description: String,
    policy: Policy,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    listen: Option<SocketAddr>,
    #[cfg(target_os = "windows")]
    pac: windows::PacState,
}

impl Snapshot {
    fn new(
        generation: u64,
        policy: Policy,
        description: String,
        listen: Option<SocketAddr>,
    ) -> Self {
        Self {
            generation,
            description,
            policy,
            listen,
            #[cfg(target_os = "windows")]
            pac: windows::PacState::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn direct_for_tests() -> Arc<Self> {
        Arc::new(Self::new(1, Policy::Direct, "direct".to_string(), None))
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn description(&self) -> &str {
        &self.description
    }

    /// The policy error, if no connection can be routed at all.
    pub(crate) fn unavailable(&self) -> Option<&str> {
        match &self.policy {
            Policy::Unavailable(message) => Some(message),
            _ => None,
        }
    }

    /// Route for `host:port`. May block on Windows automatic configuration;
    /// async callers use [`Snapshot::route`].
    pub(crate) fn route_blocking(&self, https: bool, host: &str, port: u16) -> Result<Route> {
        if is_loopback_target(host) {
            return Ok(Route::Direct);
        }
        match &self.policy {
            Policy::Direct => Ok(Route::Direct),
            Policy::Static(proxies) => proxies
                .route(https, host, port)
                .map_err(|message| anyhow::anyhow!("upstream proxy unavailable: {message}")),
            Policy::Unavailable(message) => bail!("upstream proxy unavailable: {message}"),
            #[cfg(target_os = "windows")]
            Policy::WindowsAuto {
                auto_detect,
                config_url,
                fallback,
            } => self
                .pac
                .route(
                    *auto_detect,
                    config_url.as_deref(),
                    fallback,
                    self.listen,
                    https,
                    host,
                    port,
                )
                .map_err(|message| anyhow::anyhow!("upstream proxy unavailable: {message}")),
            #[cfg(not(target_os = "windows"))]
            Policy::WindowsAuto { fallback, .. } => fallback
                .route(https, host, port)
                .map_err(|message| anyhow::anyhow!("upstream proxy unavailable: {message}")),
        }
    }

    pub(crate) async fn route(
        self: &Arc<Self>,
        https: bool,
        host: &str,
        port: u16,
    ) -> Result<Route> {
        if !matches!(self.policy, Policy::WindowsAuto { .. }) {
            return self.route_blocking(https, host, port);
        }
        #[cfg(target_os = "windows")]
        if let Some(route) = self.pac.cached(&(https, normalize_host(host), port)) {
            return route
                .map_err(|message| anyhow::anyhow!("upstream proxy unavailable: {message}"));
        }
        // Bound the blocking threads WinHTTP evaluations may hold and how
        // long a request waits for one.
        static PAC_EVALUATIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
        let _permit = tokio::time::timeout(PAC_QUEUE_BUDGET, PAC_EVALUATIONS.acquire())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "upstream proxy unavailable: proxy auto-configuration is not responding"
                )
            })?
            .context("proxy auto-configuration is shutting down")?;
        let snapshot = Arc::clone(self);
        let host = host.to_string();
        tokio::task::spawn_blocking(move || snapshot.route_blocking(https, &host, port))
            .await
            .context("proxy auto-configuration task failed")?
    }

    /// Opens a TCP connection to `host:port`, through an HTTP CONNECT tunnel
    /// when the route uses a proxy. `https` selects the HTTPS proxy setting
    /// (CONNECT tunnels and `wss://`) rather than the plain HTTP one.
    pub(crate) async fn connect(
        self: &Arc<Self>,
        https: bool,
        host: &str,
        port: u16,
    ) -> Result<TcpStream> {
        match self.route(https, host, port).await? {
            Route::Direct => connect_direct(host, port).await,
            Route::Proxy(endpoint) => open_tunnel(&endpoint, host, port).await,
        }
    }
}

/// Configures `builder` for exactly one route. reqwest never evaluates a
/// proxy itself: callers resolve the route first (off the async workers for
/// Windows automatic configuration) and use one client per route, so a
/// route change never reuses another route's pooled connection.
pub(crate) fn client_builder_for_route(
    builder: reqwest::ClientBuilder,
    route: &Route,
) -> Result<reqwest::ClientBuilder> {
    Ok(match route {
        Route::Direct => builder.no_proxy(),
        Route::Proxy(endpoint) => {
            let mut proxy = reqwest::Proxy::all(format!("http://{}", endpoint.authority()))
                .context("invalid upstream proxy")?;
            // The exact header used for CONNECT tunnels. reqwest's
            // `basic_auth` would route the decoded credentials through URL
            // userinfo and decode them a second time.
            if let Some(authorization) = endpoint.proxy_authorization() {
                let mut header = reqwest::header::HeaderValue::from_str(&authorization)
                    .context("invalid upstream proxy credentials")?;
                header.set_sensitive(true);
                proxy = proxy.custom_http_auth(header);
            }
            builder.proxy(proxy)
        }
    })
}

/// Route for an absolute URL; blocking for Windows automatic configuration.
pub(crate) fn route_for_url_blocking(snapshot: &Snapshot, url: &str) -> Result<Route> {
    let (https, host, port) = url_target(url)?;
    snapshot.route_blocking(https, &host, port)
}

fn url_target(url: &str) -> Result<(bool, String, u16)> {
    let url = url::Url::parse(url).context("invalid upstream URL")?;
    let host = url
        .host_str()
        .context("upstream URL has no host")?
        .to_string();
    let port = url
        .port_or_known_default()
        .context("upstream URL has no port")?;
    Ok((matches!(url.scheme(), "https" | "wss"), host, port))
}

/// HTTP clients of a long-running process, one per (policy generation,
/// route).
type ConfigureClient = Box<dyn Fn() -> reqwest::ClientBuilder + Send + Sync>;

pub(crate) struct HttpClients {
    upstream: Arc<UpstreamProxy>,
    configure: ConfigureClient,
    cache: Mutex<(u64, HashMap<Route, reqwest::Client>)>,
}

impl HttpClients {
    pub(crate) fn new(
        upstream: Arc<UpstreamProxy>,
        configure: impl Fn() -> reqwest::ClientBuilder + Send + Sync + 'static,
    ) -> Self {
        Self {
            upstream,
            configure: Box::new(configure),
            cache: Mutex::new((0, HashMap::new())),
        }
    }

    pub(crate) fn upstream(&self) -> &Arc<UpstreamProxy> {
        &self.upstream
    }

    /// Client for a request to `url`; fails instead of going direct when
    /// the configured proxy cannot be used.
    pub(crate) async fn for_url(&self, url: &str) -> Result<reqwest::Client> {
        let (https, host, port) = url_target(url)?;
        let snapshot = self.upstream.snapshot();
        let route = snapshot.route(https, &host, port).await?;
        self.client(snapshot.generation(), route)
    }

    fn client(&self, generation: u64, route: Route) -> Result<reqwest::Client> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if generation > cache.0 {
            *cache = (generation, HashMap::new());
        }
        if generation == cache.0
            && let Some(client) = cache.1.get(&route)
        {
            return Ok(client.clone());
        }
        let client = client_builder_for_route((self.configure)(), &route)?
            .build()
            .context("failed to build upstream HTTP client")?;
        if generation == cache.0 {
            cache.1.insert(route, client.clone());
        }
        Ok(client)
    }
}

pub(crate) struct UpstreamProxy {
    mode: Result<Mode, String>,
    listen: Option<SocketAddr>,
    prewarm: Vec<(String, u16)>,
    current: RwLock<Arc<Snapshot>>,
    last_inputs: Mutex<Option<Inputs>>,
}

impl UpstreamProxy {
    /// `setting` is the `upstream_proxy` config value; `SAIAI_UPSTREAM_PROXY`
    /// overrides it. `listen` is this SAIAI listener, never used as upstream.
    /// `prewarm` lists Gateway origins resolved whenever a policy changes.
    pub(crate) fn new(
        setting: Option<&str>,
        listen: Option<SocketAddr>,
        prewarm: Vec<(String, u16)>,
    ) -> Self {
        let env_setting = std::env::var(UPSTREAM_PROXY_ENV.get())
            .ok()
            .filter(|value| !value.trim().is_empty());
        let mode = match (&env_setting, setting) {
            (Some(value), _) => {
                parse_mode(value).map_err(|error| format!("{UPSTREAM_PROXY_ENV} {error:#}"))
            }
            (None, Some(value)) => {
                parse_mode(value).map_err(|error| format!("upstream_proxy setting {error:#}"))
            }
            (None, None) => Ok(Mode::System),
        };
        let proxy = Self {
            mode,
            listen,
            prewarm,
            current: RwLock::new(Arc::new(Snapshot::new(
                0,
                Policy::Unavailable("not resolved yet".to_string()),
                "not resolved yet".to_string(),
                listen,
            ))),
            last_inputs: Mutex::new(None),
        };
        proxy.refresh();
        proxy
    }

    pub(crate) fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.current.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Re-reads the proxy configuration (blocking) and publishes a new
    /// snapshot when it changed. A failed system read publishes an
    /// unavailable policy: an unknown configuration is never assumed to be
    /// the previous one.
    pub(crate) fn refresh(&self) -> bool {
        self.publish(self.read_inputs())
    }

    fn read_inputs(&self) -> Inputs {
        Inputs {
            mode: self.mode.clone(),
            env: if self.mode == Ok(Mode::System) {
                EnvProxies::from_lookup(|name| std::env::var(name).ok())
            } else {
                EnvProxies::default()
            },
            os: if self.mode == Ok(Mode::System) {
                read_os_proxy()
            } else {
                OsProxy::None
            },
        }
    }

    fn publish(&self, inputs: Inputs) -> bool {
        let mut last = self.last_inputs.lock().unwrap_or_else(|e| e.into_inner());
        if last.as_ref() == Some(&inputs) {
            return false;
        }
        let (policy, description) = policy_from_inputs(&inputs, self.listen);
        let generation = self.snapshot().generation + 1;
        let snapshot = Arc::new(Snapshot::new(generation, policy, description, self.listen));
        *last = Some(inputs);
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = snapshot;
        true
    }

    /// Resolves the Gateway origins once per snapshot so Windows automatic
    /// configuration (WPAD discovery can take seconds) is cached before the
    /// first request. Blocking; never on the startup path.
    fn prewarm(&self) {
        let snapshot = self.snapshot();
        for (host, port) in &self.prewarm {
            let _ = snapshot.route_blocking(true, host, *port);
        }
    }

    /// Keeps the snapshot current for a long-running proxy process.
    pub(crate) fn spawn_refresh(self: &Arc<Self>) {
        let proxy = Arc::clone(self);
        tokio::spawn(async move {
            let warming = Arc::clone(&proxy);
            let _ = tokio::task::spawn_blocking(move || warming.prewarm()).await;
            let mut interval = tokio::time::interval(REFRESH_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                let refreshing = Arc::clone(&proxy);
                let changed = tokio::task::spawn_blocking(move || {
                    let changed = refreshing.refresh();
                    if changed {
                        refreshing.prewarm();
                    }
                    changed
                })
                .await;
                if let Ok(true) = changed {
                    eprintln!("upstream proxy: {}", proxy.snapshot().description());
                }
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn read_os_proxy() -> OsProxy {
    OsProxy::None
}

#[cfg(target_os = "macos")]
fn read_os_proxy() -> OsProxy {
    match std::process::Command::new("/usr/sbin/scutil")
        .arg("--proxy")
        .output()
    {
        Ok(output) if output.status.success() => {
            OsProxy::MacOs(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Ok(output) => OsProxy::Unreadable(format!("scutil --proxy exited with {}", output.status)),
        Err(error) => OsProxy::Unreadable(format!("scutil --proxy: {error}")),
    }
}

#[cfg(target_os = "windows")]
fn read_os_proxy() -> OsProxy {
    windows::read_ie_proxy_config()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn read_os_proxy() -> OsProxy {
    OsProxy::None
}

// ---------------------------------------------------------------------------
// Connections

/// Direct TCP connection, trying every resolved address in order.
pub(crate) async fn connect_direct(host: &str, port: u16) -> Result<TcpStream> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs = lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve {host}:{port}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        bail!("no addresses resolved for {host}:{port}");
    }

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    match last_err {
        Some(err) => Err(err).with_context(|| format!("failed to connect to {host}:{port}")),
        None => bail!("no usable addresses resolved for {host}:{port}"),
    }
}

/// Opens an HTTP CONNECT tunnel to `host:port` through `endpoint`. The
/// target name is sent unresolved so the proxy performs DNS.
async fn open_tunnel(endpoint: &Endpoint, host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = tokio::time::timeout(
        PROXY_CONNECT_TIMEOUT,
        connect_direct(&endpoint.host, endpoint.port),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))
    .and_then(|result| result)
    .with_context(|| format!("upstream proxy {endpoint} is unreachable"))?;

    let target = host_port(&normalize_host(host), port);
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(authorization) = endpoint.proxy_authorization() {
        request.push_str(&format!("Proxy-Authorization: {authorization}\r\n"));
    }
    request.push_str("\r\n");

    let head = tokio::time::timeout(PROXY_RESPONSE_TIMEOUT, async {
        stream.write_all(request.as_bytes()).await?;
        read_response_head(&mut stream).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for the CONNECT response"))
    .and_then(|result| result)
    .with_context(|| format!("upstream proxy {endpoint} failed to open a tunnel to {target}"))?;

    let status = parse_status(&head)
        .with_context(|| format!("upstream proxy {endpoint} sent an invalid CONNECT response"))?;
    match status {
        200..=299 => Ok(stream),
        407 => bail!(
            "upstream proxy {endpoint} requires authentication (407); SAIAI supports Basic credentials in the proxy URL"
        ),
        status => bail!("upstream proxy {endpoint} refused the tunnel to {target} (HTTP {status})"),
    }
}

/// Reads up to the end of the response head, one byte at a time, so no
/// tunneled byte after the head is consumed.
async fn read_response_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    loop {
        if head.len() >= MAX_PROXY_RESPONSE_HEAD {
            bail!("CONNECT response head exceeds {MAX_PROXY_RESPONSE_HEAD} bytes");
        }
        let byte = stream
            .read_u8()
            .await
            .context("proxy closed the connection during CONNECT")?;
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
}

fn parse_status(head: &[u8]) -> Result<u16> {
    let line = head
        .split(|&byte| byte == b'\n')
        .next()
        .context("missing status line")?;
    let line = std::str::from_utf8(line).context("status line is not UTF-8")?;
    let mut parts = line.trim_end_matches('\r').splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        bail!("unexpected protocol");
    }
    let status = parts.next().unwrap_or_default();
    if status.len() != 3 {
        bail!("malformed status code");
    }
    status.parse().context("malformed status code")
}

// ---------------------------------------------------------------------------
// Windows automatic configuration decisions (platform-independent, tested
// everywhere) and the WinHTTP calls that feed them.

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const ERROR_AUTODETECTION_FAILED: u32 = 12180;

/// Turns a WinHTTP `GetProxyForUrl` outcome into a route, and whether WPAD
/// discovery found nothing. A script that cannot be fetched or evaluated,
/// or names no usable proxy, is an error; only WPAD finding no
/// configuration falls back to the static settings.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn pac_decision(
    outcome: Result<Option<String>, u32>,
    has_script: bool,
    fallback: &StaticProxies,
    listen: Option<SocketAddr>,
    https: bool,
    host: &str,
    port: u16,
) -> (Result<Route, String>, bool) {
    match outcome {
        Ok(None) => (Ok(Route::Direct), false),
        Ok(Some(list)) => (
            match first_proxy(&list) {
                Some(endpoint) if endpoint.is_listener(listen) => {
                    Err("proxy auto-configuration returned this SAIAI proxy itself".to_string())
                }
                Some(endpoint) => Ok(Route::Proxy(endpoint)),
                None => Err("proxy auto-configuration returned no usable HTTP proxy".to_string()),
            },
            false,
        ),
        Err(ERROR_AUTODETECTION_FAILED) if !has_script => (fallback.route(https, host, port), true),
        Err(code) => (
            Err(format!(
                "proxy auto-configuration failed (WinHTTP error {code})"
            )),
            false,
        ),
    }
}

/// First usable `host:port` of a WinHTTP proxy list (`a:1;b:2`).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn first_proxy(list: &str) -> Option<Endpoint> {
    list.split([';', ' '])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .find_map(|entry| match entry.split_once('=') {
            Some((scheme, value)) if !scheme.eq_ignore_ascii_case("socks") => {
                Endpoint::parse(value).ok()
            }
            Some(_) => None,
            None => Endpoint::parse(entry).ok(),
        })
}

// Windows: WinHTTP reads the user's Internet settings and evaluates PAC/WPAD.

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{GetLastError, GlobalFree};
    use windows_sys::Win32::Networking::WinHttp::*;

    pub(super) type CacheKey = (bool, String, u16);
    type CacheEntry = (Instant, Result<Route, String>);
    const PAC_CACHE_LIMIT: usize = 1024;
    // After WPAD finds nothing, retry discovery after this long (e.g. once a
    // laptop joins the corporate VPN) instead of never.
    const AUTO_DETECT_RETRY: Duration = Duration::from_secs(300);

    #[derive(Default)]
    pub(super) struct PacState {
        cache: Mutex<HashMap<CacheKey, CacheEntry>>,
        auto_detect_failed_at: Mutex<Option<Instant>>,
        /// One WinHTTP evaluation at a time; concurrent requests for the
        /// same target then reuse its result.
        evaluating: Mutex<()>,
    }

    impl PacState {
        /// Route from WinHTTP automatic configuration. A script that cannot
        /// be fetched or evaluated, or returns an unusable proxy, is an
        /// error, never a direct connection. Only WPAD finding no
        /// configuration at all falls back to the static settings.
        #[allow(clippy::too_many_arguments)]
        pub(super) fn route(
            &self,
            auto_detect: bool,
            config_url: Option<&str>,
            fallback: &StaticProxies,
            listen: Option<SocketAddr>,
            https: bool,
            host: &str,
            port: u16,
        ) -> Result<Route, String> {
            let key = (https, normalize_host(host), port);
            if let Some(route) = self.cached(&key) {
                return route;
            }
            let _evaluating = self.evaluating.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(route) = self.cached(&key) {
                return route;
            }
            // Like WinINet, the bypass list also applies with auto-config.
            let route = if fallback.bypass.matches(host, port) {
                Ok(Route::Direct)
            } else {
                self.evaluate(auto_detect, config_url, fallback, listen, https, host, port)
            };
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if cache.len() >= PAC_CACHE_LIMIT {
                cache.clear();
            }
            cache.insert(key, (Instant::now(), route.clone()));
            route
        }

        pub(super) fn cached(&self, key: &CacheKey) -> Option<Result<Route, String>> {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            let (at, route) = cache.get(key)?;
            let ttl = if route.is_ok() {
                PAC_CACHE_TTL
            } else {
                PAC_ERROR_TTL
            };
            (at.elapsed() < ttl).then(|| route.clone())
        }

        #[allow(clippy::too_many_arguments)]
        fn evaluate(
            &self,
            auto_detect: bool,
            config_url: Option<&str>,
            fallback: &StaticProxies,
            listen: Option<SocketAddr>,
            https: bool,
            host: &str,
            port: u16,
        ) -> Result<Route, String> {
            let auto_detect = auto_detect
                && self
                    .auto_detect_failed_at
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_none_or(|at| at.elapsed() >= AUTO_DETECT_RETRY);
            if !auto_detect && config_url.is_none() {
                return fallback.route(https, host, port);
            }
            let scheme = if https { "https" } else { "http" };
            let url = format!("{scheme}://{}/", host_port(&normalize_host(host), port));
            let outcome = get_proxy_for_url(&url, auto_detect, config_url);
            let (route, discovery_failed) = pac_decision(
                outcome,
                config_url.is_some(),
                fallback,
                listen,
                https,
                host,
                port,
            );
            if discovery_failed {
                *self
                    .auto_detect_failed_at
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            }
            route
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    /// Takes ownership of a WinHTTP-allocated string.
    unsafe fn take(value: *mut u16) -> Option<String> {
        if value.is_null() {
            return None;
        }
        let mut len = 0;
        // SAFETY: WinHTTP returns NUL-terminated strings.
        while unsafe { *value.add(len) } != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, len) });
        unsafe { GlobalFree(value.cast()) };
        Some(text).filter(|text| !text.trim().is_empty())
    }

    pub(super) fn read_ie_proxy_config() -> OsProxy {
        let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        // SAFETY: `config` is a valid out-parameter; strings are freed below.
        if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut config) } == 0 {
            let code = unsafe { GetLastError() };
            return OsProxy::Unreadable(format!(
                "WinHttpGetIEProxyConfigForCurrentUser error {code}"
            ));
        }
        let (config_url, proxy, bypass) = unsafe {
            (
                take(config.lpszAutoConfigUrl),
                take(config.lpszProxy),
                take(config.lpszProxyBypass),
            )
        };
        let auto_detect = config.fAutoDetect != 0;
        if !auto_detect && config_url.is_none() && proxy.is_none() {
            return OsProxy::None;
        }
        OsProxy::Windows {
            auto_detect,
            config_url,
            proxy,
            bypass,
        }
    }

    /// `Ok(Some(list))` for a named proxy, `Ok(None)` for DIRECT, `Err` with
    /// the WinHTTP error code when no decision was made.
    fn get_proxy_for_url(
        url: &str,
        auto_detect: bool,
        config_url: Option<&str>,
    ) -> Result<Option<String>, u32> {
        if !auto_detect && config_url.is_none() {
            return Err(0);
        }
        let agent = wide(crate::brand::BRAND.winhttp_agent);
        // SAFETY: plain WinHTTP session; closed before returning.
        let session = unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if session.is_null() {
            return Err(unsafe { GetLastError() });
        }
        unsafe { WinHttpSetTimeouts(session, 5_000, 5_000, 5_000, 5_000) };
        let url = wide(url);
        let config_url = config_url.map(wide);
        let mut options = WINHTTP_AUTOPROXY_OPTIONS::default();
        if auto_detect {
            options.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
            options.dwAutoDetectFlags =
                WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        }
        if let Some(config_url) = &config_url {
            options.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
            options.lpszAutoConfigUrl = config_url.as_ptr();
        }
        options.fAutoLogonIfChallenged = 1;
        let mut info = WINHTTP_PROXY_INFO::default();
        // SAFETY: all pointers outlive the call; returned strings are freed.
        let ok = unsafe { WinHttpGetProxyForUrl(session, url.as_ptr(), &mut options, &mut info) };
        let result = if ok == 0 {
            Err(unsafe { GetLastError() })
        } else {
            let proxy = unsafe { take(info.lpszProxy) };
            let _ = unsafe { take(info.lpszProxyBypass) };
            if info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY {
                Ok(proxy)
            } else {
                Ok(None)
            }
        };
        unsafe { WinHttpCloseHandle(session) };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen() -> Option<SocketAddr> {
        Some("127.0.0.1:19908".parse().unwrap())
    }

    fn system(env: EnvProxies, os: OsProxy) -> (Policy, String) {
        policy_from_inputs(
            &Inputs {
                mode: Ok(Mode::System),
                env,
                os,
            },
            listen(),
        )
    }

    fn route(policy: &Policy, https: bool, host: &str) -> Route {
        Snapshot::new(1, policy.clone(), String::new(), listen())
            .route_blocking(https, host, 443)
            .unwrap()
    }

    fn proxy(authority: &str) -> Route {
        Route::Proxy(Endpoint::parse(authority).unwrap())
    }

    #[test]
    fn parses_proxy_urls_without_echoing_credentials() {
        let endpoint = Endpoint::parse("http://us%40er:p%3Ass@proxy.corp:3128").unwrap();
        assert_eq!(endpoint.username, "us@er");
        assert_eq!(endpoint.password.as_deref(), Some("p:ss"));
        assert_eq!(
            endpoint.to_string(),
            "http://proxy.corp:3128 (with credentials)"
        );
        assert_eq!(format!("{endpoint:?}"), endpoint.to_string());
        assert_eq!(
            endpoint.proxy_authorization().unwrap(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("us@er:p:ss")
            )
        );

        assert_eq!(
            Endpoint::parse("127.0.0.1:7890").unwrap().authority(),
            "127.0.0.1:7890"
        );
        assert_eq!(
            Endpoint::parse("http://[::1]:7890").unwrap().authority(),
            "[::1]:7890"
        );
        assert_eq!(Endpoint::parse("http://proxy").unwrap().port, 80);
        for invalid in [
            "socks5://user:secret@host:1080",
            "https://user:secret@host:443",
            "http://user:secret@host:80/path",
            "http://user:secret@:80",
        ] {
            let error = format!("{:#}", Endpoint::parse(invalid).unwrap_err());
            assert!(!error.contains("secret"), "{error}");
        }
    }

    #[test]
    fn modes_select_direct_fixed_or_system() {
        assert_eq!(parse_mode("").unwrap(), Mode::System);
        assert_eq!(parse_mode("System").unwrap(), Mode::System);
        assert_eq!(parse_mode("direct").unwrap(), Mode::Direct);
        assert!(matches!(parse_mode("http://p:1").unwrap(), Mode::Fixed(_)));
        assert!(validate_setting("socks5://p:1").is_err());

        let fixed = policy_from_inputs(
            &Inputs {
                mode: parse_mode("http://corp:8080").map_err(|e| e.to_string()),
                env: EnvProxies::default(),
                os: OsProxy::None,
            },
            listen(),
        )
        .0;
        assert_eq!(route(&fixed, true, "api.saiai.top"), proxy("corp:8080"));
        assert_eq!(route(&fixed, true, "localhost"), Route::Direct);

        let looped = policy_from_inputs(
            &Inputs {
                mode: parse_mode("http://localhost:19908").map_err(|e| e.to_string()),
                env: EnvProxies::default(),
                os: OsProxy::None,
            },
            listen(),
        )
        .0;
        assert!(matches!(looped, Policy::Unavailable(_)));
    }

    #[test]
    fn environment_proxy_wins_and_ignores_this_listener() {
        let env = |pairs: &[(&str, &str)]| {
            let pairs: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            EnvProxies::from_lookup(|name| pairs.get(name).cloned())
        };
        let windows_os = OsProxy::Windows {
            auto_detect: false,
            config_url: None,
            proxy: Some("127.0.0.1:7890".to_string()),
            bypass: None,
        };

        let (policy, _) = system(
            env(&[
                ("HTTPS_PROXY", "http://corp:8080"),
                ("NO_PROXY", ".internal,10.0.0.0/8"),
            ]),
            windows_os.clone(),
        );
        assert_eq!(route(&policy, true, "api.saiai.top"), proxy("corp:8080"));
        assert_eq!(route(&policy, true, "git.internal"), Route::Direct);
        assert_eq!(route(&policy, true, "10.1.2.3"), Route::Direct);
        assert_eq!(route(&policy, false, "example.com"), Route::Direct);

        // SAIAI's own child environment must not loop back into SAIAI.
        for value in [
            "http://127.0.0.1:19908",
            "http://localhost:19908",
            "http://LOCALHOST.:19908",
            "http://[::1]:19908",
            "http://0.0.0.0:19908",
        ] {
            let (policy, description) = system(
                env(&[
                    ("https_proxy", value),
                    ("http_proxy", value),
                    ("all_proxy", value),
                ]),
                windows_os.clone(),
            );
            assert_eq!(
                route(&policy, true, "api.saiai.top"),
                proxy("127.0.0.1:7890"),
                "{value}"
            );
            assert!(description.contains("ignored"), "{description}");
        }
        // A scheme variable pointing at SAIAI falls back to ALL_PROXY.
        let (policy, _) = system(
            env(&[
                ("HTTPS_PROXY", "http://localhost:19908"),
                ("ALL_PROXY", "http://localhost:7890"),
            ]),
            OsProxy::None,
        );
        assert_eq!(
            route(&policy, true, "api.saiai.top"),
            proxy("localhost:7890")
        );
        // Same host, different port: a real local proxy such as Clash.
        let (policy, _) = system(
            env(&[("HTTPS_PROXY", "http://127.0.0.1:7890")]),
            OsProxy::None,
        );
        assert_eq!(
            route(&policy, true, "api.saiai.top"),
            proxy("127.0.0.1:7890")
        );

        // An unused SOCKS ALL_PROXY next to HTTP proxies is common and ignored.
        let (policy, _) = system(
            env(&[
                ("HTTPS_PROXY", "http://127.0.0.1:7890"),
                ("HTTP_PROXY", "http://127.0.0.1:7890"),
                ("ALL_PROXY", "socks5://127.0.0.1:7891"),
            ]),
            OsProxy::None,
        );
        assert_eq!(
            route(&policy, true, "api.saiai.top"),
            proxy("127.0.0.1:7890")
        );
        // Only the scheme that would need the SOCKS ALL_PROXY fails.
        let (policy, _) = system(
            env(&[
                ("HTTPS_PROXY", "http://127.0.0.1:7890"),
                ("ALL_PROXY", "socks5://127.0.0.1:7891"),
            ]),
            OsProxy::None,
        );
        assert_eq!(
            route(&policy, true, "api.saiai.top"),
            proxy("127.0.0.1:7890")
        );
        let snapshot = Snapshot::new(1, policy, String::new(), listen());
        assert!(snapshot.route_blocking(false, "example.com", 80).is_err());
        let (policy, _) = system(
            env(&[("ALL_PROXY", "socks5://127.0.0.1:7891")]),
            OsProxy::None,
        );
        assert!(matches!(policy, Policy::Unavailable(_)));
        assert!(
            Endpoint::parse("http://[::ffff:127.0.0.1]:19908")
                .unwrap()
                .is_listener(listen())
        );

        let (policy, _) = system(env(&[("ALL_PROXY", "http://corp:8080")]), OsProxy::None);
        assert_eq!(route(&policy, false, "example.com"), proxy("corp:8080"));

        let (policy, description) = system(
            env(&[("HTTPS_PROXY", "socks5://user:secret@corp:1080")]),
            OsProxy::None,
        );
        let snapshot = Snapshot::new(1, policy, String::new(), listen());
        assert!(snapshot.route_blocking(true, "api.saiai.top", 443).is_err());
        assert!(!description.contains("secret"), "{description}");
    }

    #[test]
    fn windows_proxy_server_formats() {
        let routes = |proxy: &str, bypass: Option<&str>| {
            windows_static_proxies(Some(proxy), bypass, listen()).unwrap()
        };
        let all = routes("127.0.0.1:7890", Some("localhost;127.*;10.*;<local>"));
        assert_eq!(
            all.route(true, "api.saiai.top", 443),
            Ok(proxy("127.0.0.1:7890"))
        );
        assert_eq!(
            all.route(false, "api.saiai.top", 443),
            Ok(proxy("127.0.0.1:7890"))
        );
        assert_eq!(all.route(true, "10.2.3.4", 443), Ok(Route::Direct));
        assert_eq!(all.route(true, "intranet", 443), Ok(Route::Direct));
        assert_eq!(
            all.route(true, "sub.localhost.example", 443),
            Ok(proxy("127.0.0.1:7890"))
        );

        let split = routes("https=secure:443;http=plain:80;ftp=f:21", None);
        assert_eq!(split.route(true, "a.com", 443), Ok(proxy("secure:443")));
        assert_eq!(split.route(false, "a.com", 443), Ok(proxy("plain:80")));
        let http_only = routes("http=plain:80", None);
        assert_eq!(http_only.route(true, "a.com", 443), Ok(Route::Direct));
        let reversed = routes(" https=b:2 ; http=a:1 ", None);
        assert_eq!(reversed.route(true, "a.com", 443), Ok(proxy("b:2")));

        assert!(windows_static_proxies(Some("socks=127.0.0.1:1080"), None, listen()).is_err());
        let http_and_socks = routes("socks=s:1;http=h:2", None);
        assert_eq!(http_and_socks.route(false, "a.com", 80), Ok(proxy("h:2")));
        assert!(http_and_socks.route(true, "a.com", 443).is_err());
        assert_eq!(
            routes("socks=s:1;https=h:2", None).route(true, "a.com", 443),
            Ok(proxy("h:2"))
        );
        assert!(windows_static_proxies(Some("http=:80"), None, listen()).is_err());

        let exact = routes("p:1", Some("example.com;*.corp.com"));
        assert_eq!(exact.route(true, "example.com", 443), Ok(Route::Direct));
        assert_eq!(exact.route(true, "www.example.com", 443), Ok(proxy("p:1")));
        assert_eq!(exact.route(true, "a.corp.com", 443), Ok(Route::Direct));
    }

    #[test]
    fn windows_auto_config_keeps_static_fallback() {
        let (policy, description) = os_policy(
            &OsProxy::Windows {
                auto_detect: true,
                config_url: None,
                proxy: Some("127.0.0.1:7890".to_string()),
                bypass: None,
            },
            listen(),
        );
        assert!(matches!(policy, Policy::WindowsAuto { .. }), "{policy:?}");
        assert!(
            description.contains("detection, else https"),
            "{description}"
        );
    }

    #[test]
    fn macos_scutil_output() {
        let clash = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : 192.168.0.0/16\n    1 : *.local\n    2 : 169.254/16\n    3 : example.com\n  }\n  ExcludeSimpleHostnames : 1\n  HTTPEnable : 1\n  HTTPPort : 7890\n  HTTPProxy : 127.0.0.1\n  HTTPSEnable : 1\n  HTTPSPort : 7890\n  HTTPSProxy : 127.0.0.1\n  SOCKSEnable : 1\n  SOCKSPort : 7891\n  SOCKSProxy : 127.0.0.1\n}\n";
        let (policy, _) = macos_policy(clash, listen());
        assert_eq!(
            route(&policy, true, "api.saiai.top"),
            proxy("127.0.0.1:7890")
        );
        assert_eq!(route(&policy, true, "192.168.1.5"), Route::Direct);
        assert_eq!(route(&policy, true, "169.254.1.1"), Route::Direct);
        assert_eq!(route(&policy, true, "printer.local"), Route::Direct);
        assert_eq!(route(&policy, true, "printer"), Route::Direct);
        assert_eq!(route(&policy, true, "www.example.com"), Route::Direct);
        assert_eq!(
            route(&policy, true, "evil-example.com"),
            proxy("127.0.0.1:7890")
        );

        let (policy, _) = macos_policy("<dictionary> {\n  HTTPEnable : 0\n}\n", listen());
        assert_eq!(policy, Policy::Direct);
        let (policy, _) = macos_policy(
            "<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://wpad/x.pac\n  HTTPSEnable : 1\n  HTTPSProxy : p\n  HTTPSPort : 1\n}\n",
            listen(),
        );
        assert_eq!(policy, Policy::Direct);
        let (policy, _) = macos_policy(
            "<dictionary> {\n  SOCKSEnable : 1\n  SOCKSPort : 1080\n  SOCKSProxy : 127.0.0.1\n}\n",
            listen(),
        );
        assert!(matches!(policy, Policy::Unavailable(_)));
    }

    #[test]
    fn pac_outcomes_never_fall_back_to_direct_on_script_errors() {
        let fallback = StaticProxies {
            https: Some(Endpoint::parse("manual:3128").unwrap()),
            ..StaticProxies::default()
        };
        let decide = |outcome, has_script| {
            pac_decision(
                outcome,
                has_script,
                &fallback,
                listen(),
                true,
                "api.saiai.top",
                443,
            )
        };
        assert_eq!(decide(Ok(None), true), (Ok(Route::Direct), false));
        assert_eq!(
            decide(Ok(Some("corp:8080; backup:8080".to_string())), true),
            (Ok(proxy("corp:8080")), false)
        );
        assert_eq!(
            decide(Ok(Some("socks=s:1080;https=h:8443".to_string())), true),
            (Ok(proxy("h:8443")), false)
        );
        assert!(
            decide(Ok(Some("socks=s:1080".to_string())), true)
                .0
                .is_err()
        );
        assert!(
            decide(Ok(Some("127.0.0.1:19908".to_string())), true)
                .0
                .is_err()
        );
        // Script download/evaluation failures are errors, with or without WPAD.
        assert!(decide(Err(12167), true).0.is_err());
        assert!(decide(Err(ERROR_AUTODETECTION_FAILED), true).0.is_err());
        assert!(decide(Err(12167), false).0.is_err());
        // WPAD alone finding nothing uses the manual settings.
        assert_eq!(
            decide(Err(ERROR_AUTODETECTION_FAILED), false),
            (Ok(proxy("manual:3128")), true)
        );
    }

    #[test]
    fn an_unreadable_system_proxy_replaces_the_previous_policy() {
        let upstream = UpstreamProxy::new(Some("system"), listen(), Vec::new());
        let inputs = |os| Inputs {
            mode: Ok(Mode::System),
            env: EnvProxies::default(),
            os,
        };
        upstream.publish(inputs(OsProxy::None));
        assert_eq!(
            upstream
                .snapshot()
                .route_blocking(true, "api.saiai.top", 443)
                .unwrap(),
            Route::Direct
        );
        assert!(upstream.publish(inputs(OsProxy::Unreadable("scutil failed".to_string()))));
        assert!(
            upstream
                .snapshot()
                .route_blocking(true, "api.saiai.top", 443)
                .is_err()
        );
        assert!(upstream.publish(inputs(OsProxy::None)));
        assert!(
            upstream
                .snapshot()
                .route_blocking(true, "api.saiai.top", 443)
                .is_ok()
        );
    }

    #[test]
    fn bypass_rules() {
        let bypass = Bypass::parse(
            ".corp.com,exact.org,10.0.0.0/8,fc00::/7,*.svc.local,host.with.port:8443,*".split(','),
            true,
        );
        assert!(bypass.matches("anything", 443));
        let bypass = Bypass::parse(
            ".corp.com,exact.org,10.0.0.0/8,fc00::/7,*.svc.local,host.with.port:8443".split(','),
            true,
        );
        assert!(bypass.matches("a.corp.com", 443));
        assert!(bypass.matches("corp.com", 443));
        assert!(!bypass.matches("evilcorp.com", 443));
        assert!(bypass.matches("exact.org", 443));
        assert!(bypass.matches("sub.exact.org", 443));
        assert!(!bypass.matches("notexact.org", 443));
        assert!(bypass.matches("10.255.0.1", 443));
        assert!(!bypass.matches("11.0.0.1", 443));
        assert!(bypass.matches("[fd00::1]", 443));
        assert!(bypass.matches("a.svc.local", 443));
        assert!(bypass.matches("host.with.port", 8443));
        assert!(!bypass.matches("host.with.port", 443));
        let ipv6_port = Bypass::parse(["[fd00::1]:8443", "[fd00::2]"], false);
        assert!(ipv6_port.matches("fd00::1", 8443));
        assert!(!ipv6_port.matches("fd00::1", 443));
        assert!(ipv6_port.matches("[fd00::2]", 443));
        // Malformed ports are dropped, never widened to every port.
        let malformed = Bypass::parse(
            ["[fd00::3]:bad", "[fd00::3]:65536", "[fd00::3]x", "h:99999"],
            true,
        );
        assert!(malformed.rules.is_empty(), "{malformed:?}");
        assert!(bypass.matches("EXACT.ORG.", 443));
        assert!(glob_matches("*.example.*", "a.example.com"));
        assert!(!glob_matches("a*b", "ac"));
    }

    #[test]
    fn parses_connect_status_lines() {
        assert_eq!(
            parse_status(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap(),
            200
        );
        assert_eq!(
            parse_status(b"HTTP/1.0 407 Proxy Auth\r\n\r\n").unwrap(),
            407
        );
        assert!(parse_status(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
        assert!(parse_status(b"HTTP/1.1 2000 OK\r\n\r\n").is_err());
    }

    async fn fake_proxy(response: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_response_head(&mut socket).await.unwrap();
            socket.write_all(response).await.unwrap();
            socket.write_all(b"tunneled").await.unwrap();
            request
        });
        (address, task)
    }

    #[tokio::test]
    async fn tunnels_through_a_proxy_and_keeps_tunneled_bytes() {
        let (address, task) =
            fake_proxy(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: x\r\n\r\n").await;
        let endpoint =
            Endpoint::parse(&format!("http://user:pa%20ss@127.0.0.1:{}", address.port())).unwrap();
        let mut stream = open_tunnel(&endpoint, "api.saiai.top", 443).await.unwrap();
        let mut tunneled = [0_u8; 8];
        stream.read_exact(&mut tunneled).await.unwrap();
        assert_eq!(&tunneled, b"tunneled");
        let request = String::from_utf8(task.await.unwrap()).unwrap();
        assert!(
            request
                .starts_with("CONNECT api.saiai.top:443 HTTP/1.1\r\nHost: api.saiai.top:443\r\n")
        );
        let expected = base64::engine::general_purpose::STANDARD.encode("user:pa ss");
        assert!(
            request.contains(&format!("Proxy-Authorization: Basic {expected}\r\n")),
            "{request}"
        );

        let (address, task) = fake_proxy(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", address.port())).unwrap();
        open_tunnel(&endpoint, "::1", 8443).await.unwrap();
        let request = String::from_utf8(task.await.unwrap()).unwrap();
        assert!(
            request.starts_with("CONNECT [::1]:8443 HTTP/1.1"),
            "{request}"
        );
        assert!(!request.contains("Proxy-Authorization"));
    }

    #[tokio::test]
    async fn proxy_failures_do_not_fall_back_to_direct() {
        let (address, _task) =
            fake_proxy(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        let endpoint =
            Endpoint::parse(&format!("http://u:secret@127.0.0.1:{}", address.port())).unwrap();
        let error = format!(
            "{:#}",
            open_tunnel(&endpoint, "api.saiai.top", 443)
                .await
                .unwrap_err()
        );
        assert!(error.contains("407"), "{error}");
        assert!(!error.contains("secret"), "{error}");

        let (address, _task) = fake_proxy(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        let endpoint = Endpoint::parse(&format!("127.0.0.1:{}", address.port())).unwrap();
        let error = format!(
            "{:#}",
            open_tunnel(&endpoint, "api.saiai.top", 443)
                .await
                .unwrap_err()
        );
        assert!(error.contains("HTTP 403"), "{error}");

        // A failing proxy is an error attributed to that proxy, never a
        // silent direct connection.
        let through = |port: u16| {
            Arc::new(Snapshot::new(
                1,
                Policy::Static(StaticProxies {
                    http: None,
                    https: Some(Endpoint::parse(&format!("127.0.0.1:{port}")).unwrap()),
                    bypass: Bypass::default(),
                    ..StaticProxies::default()
                }),
                String::new(),
                None,
            ))
        };
        // A proxy that accepts and immediately closes (deterministic).
        let closing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closing.local_addr().unwrap().port();
        let closer = tokio::spawn(async move {
            let (socket, _) = closing.accept().await.unwrap();
            drop(socket);
        });
        let error = format!(
            "{:#}",
            through(port)
                .connect(true, "api.saiai.top", 443)
                .await
                .unwrap_err()
        );
        closer.await.unwrap();
        assert!(
            error.contains(&format!(
                "upstream proxy http://127.0.0.1:{port} failed to open a tunnel"
            )),
            "{error}"
        );
        // A closed proxy port: usually refused ("unreachable"); if another
        // process reuses the port meanwhile, the tunnel fails instead. Both
        // name the proxy, so neither went direct.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let error = format!(
            "{:#}",
            through(port)
                .connect(true, "api.saiai.top", 443)
                .await
                .unwrap_err()
        );
        let proxy = format!("upstream proxy http://127.0.0.1:{port} ");
        assert!(
            error.contains(&format!("{proxy}is unreachable"))
                || error.contains(&format!("{proxy}failed to open a tunnel")),
            "{error}"
        );

        let unavailable = Arc::new(Snapshot::new(
            1,
            Policy::Unavailable("SOCKS".to_string()),
            String::new(),
            None,
        ));
        assert!(
            unavailable
                .connect(true, "api.saiai.top", 443)
                .await
                .is_err()
        );
        assert!(route_for_url_blocking(&unavailable, "https://api.saiai.top").is_err());
    }

    #[tokio::test]
    async fn http_clients_send_through_the_snapshot_proxy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let head = read_response_head(&mut socket).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            String::from_utf8(head).unwrap()
        });
        // `%2541` is a literal `%41` in the password; reqwest must not
        // decode it a second time.
        let upstream = Arc::new(UpstreamProxy::new(
            Some(&format!("http://u:p%2541@127.0.0.1:{port}")),
            listen(),
            Vec::new(),
        ));
        let clients = HttpClients::new(upstream, reqwest::Client::builder);
        let client = clients.for_url("http://upstream.example/x").await.unwrap();
        let response = client
            .get("http://upstream.example/x")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
        let head = server.await.unwrap();
        assert!(
            head.starts_with("GET http://upstream.example/x HTTP/1.1"),
            "{head}"
        );
        let expected = format!(
            "proxy-authorization: basic {}",
            base64::engine::general_purpose::STANDARD.encode("u:p%41")
        );
        assert!(
            head.to_ascii_lowercase()
                .contains(&expected.to_ascii_lowercase()),
            "{head}"
        );

        // HTTPS goes through a CONNECT tunnel with the same credentials.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let head = read_response_head(&mut socket).await.unwrap();
            let _ = socket.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
            String::from_utf8(head).unwrap()
        });
        let upstream = Arc::new(UpstreamProxy::new(
            Some(&format!("http://u:p%2541@127.0.0.1:{port}")),
            listen(),
            Vec::new(),
        ));
        let clients = HttpClients::new(upstream, reqwest::Client::builder);
        let client = clients.for_url("https://api.saiai.top/x").await.unwrap();
        assert!(client.get("https://api.saiai.top/x").send().await.is_err());
        let head = server.await.unwrap();
        assert!(
            head.starts_with("CONNECT api.saiai.top:443 HTTP/1.1"),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains(&expected.to_ascii_lowercase()),
            "{head}"
        );
    }

    #[tokio::test]
    async fn each_route_gets_its_own_client_and_pool() {
        // Counts accepted connections; each connection serves any number of
        // keep-alive requests, so a reused pool shows up as one connection.
        async fn recording_proxy() -> (Endpoint, Arc<std::sync::atomic::AtomicUsize>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = Endpoint::parse(&format!(
                "127.0.0.1:{}",
                listener.local_addr().unwrap().port()
            ))
            .unwrap();
            let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = Arc::clone(&accepted);
            tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::spawn(async move {
                        while read_response_head(&mut socket).await.is_ok() {
                            let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
                            if socket.write_all(response).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            (endpoint, accepted)
        }
        let (first, first_task) = recording_proxy().await;
        let (second, second_task) = recording_proxy().await;
        let clients = HttpClients::new(
            Arc::new(UpstreamProxy::new(Some("direct"), listen(), Vec::new())),
            reqwest::Client::builder,
        );
        // Same generation, as when a PAC result changes from one proxy to
        // another: requests follow the new route instead of a pooled one.
        for endpoint in [&first, &second, &first] {
            let client = clients.client(1, Route::Proxy(endpoint.clone())).unwrap();
            let response = client
                .get("http://upstream.example/x")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 204);
        }
        let count = |accepted: &std::sync::atomic::AtomicUsize| {
            accepted.load(std::sync::atomic::Ordering::SeqCst)
        };
        assert_eq!(
            count(&first_task),
            1,
            "the first route's pool was not reused"
        );
        assert_eq!(count(&second_task), 1);
    }
}
