# Claude Desktop Linux adapter (MVP)

`saiai desktop claude` launches the apt-installed `/usr/bin/claude-desktop`
with an isolated profile. Only the **Code** surface is supported. Chat and
Cowork requests are refused locally. macOS and Windows are not supported.

The compatibility baseline is Desktop **4.23118.0**, bundled Code **2.1.317**.
The launcher checks the installed apt package version. Other Desktop versions
require the explicit `SAIAI_CLAUDE_DESKTOP_ALLOW_UNTESTED=1` override; the
bundled Code version and native UI behavior still need machine acceptance.
This adapter does not modify the installed application or the normal profile.

## Usage

Initialize the selected SAIAI environment's Claude route first, then run:

```sh
saiai desktop claude
saiai doctor --desktop claude
```

A running older proxy must be restarted with `saiai restart`. The launcher
verifies the selected environment's CA and the dedicated Claude entry
before launching; it never falls back to the shared proxy port. Linux Chromium requires the isolated HOME NSS database. Install `certutil` with
`sudo apt install libnss3-tools`; absence stops launch. Claude receives no
`--ignore-certificate-errors-*` switches. Code inherits proxy variables,
`NODE_EXTRA_CA_CERTS`, and a system-roots-plus-SAIAI `SSL_CERT_FILE` bundle.
No global trust store is changed.

Extra Desktop command-line arguments are intentionally rejected in this MVP so
profile and proxy flags cannot override the managed launch. A `SingletonLock`
or active launcher lock causes an error; the launcher never kills an existing
Desktop process or deletes its lock.

## State and authentication

All state lives under `<selected SAIAI config>/desktop/claude/`:

- `home/`: isolated HOME, XDG state and Claude Code configuration.
- `user-data/`: Chromium profile, Cookies and Desktop's own safeStorage cache.
- `state/identity.json`: separate random account/org UUIDs, local session,
  access and refresh placeholders, written with mode 0600.
- `state/model.json`, `settings.json`: model choice and local user settings.
- `state/ca-bundle.pem`, `launcher.lock`: generated trust bundle and launch lock.
- `state/proxy.json`: dedicated loopback listener address and its main listener
  identity, owned by the running proxy (not a proof that it is alive).

The local access token has a ten-year advertised lifetime. Refresh returns the
same locally persisted pair. Authorization codes require the local session,
PKCE S256, state and redirect matching; they expire after 120 seconds and are
single-use. Authorization codes are in memory, so a proxy restart during an
exchange requires retrying that exchange.

The root/epitaxy/bootstrap response sets local session Cookies. This uses
Chromium's own cookie persistence; there is no SQLite dependency or direct
safeStorage encryption implementation. Acceptance must confirm that a clean
Desktop profile consumes these Cookies before native authorization. Existing
normal-profile Cookies, token caches and CLI credentials are never copied.

Only the dedicated Desktop listener recognizes the environment's placeholder, strips inbound
Authorization, x-api-key and Cookie, and injects the configured **Anthropic**
route key. Client proof signs the substituted key. Other ordinary CLI Bearers
retain their previous behavior. On the Desktop listener, provider `sk-ant` tokens
and unknown Desktop placeholders are rejected. The main listener continues to
forward these Bearers unchanged, including when Desktop state is absent or corrupt.

UI account responses have the synthetic UUID but an empty email. OAuth
account/profile responses omit the account UUID and have an empty email.
Launch clears `oauthAccount` only in isolated Code configuration and removes
inherited email/token/routing overrides. Desktop model messages fail locally without rewriting the body only when one
`messages[].content` string (or a `type=text` part) contains all of
`<system-reminder>`, `# userEmail`, and `The user's email address is`.
Tool results and ordinary mentions of the sentence are allowed.
Nonempty metadata account UUID is diagnostic-only, never rewritten or rejected.

## Network contract

The policies below apply **only to the dedicated Claude Desktop listener**.
The main listener (normally 19908) keeps its original routing: `claude.ai` is a
plain CONNECT tunnel and Anthropic OAuth sidecars/credentials retain their old
behavior. This isolates Codex's browser, editor-wide proxies and other clients.
The only shared network-policy addition is the browser Datadog intake deny rule.

Only on Linux, when this environment already has a Desktop identity, does the
same proxy process bind a second IPv4 loopback listener. Without that identity
(or on other platforms), startup adds no Desktop port, files, directories or logs.
On first launch, if the main proxy is already running without this entry, the
launcher tells the user to run `saiai restart` in this environment and retry
`saiai desktop claude`. It does not automatically interrupt other clients'
active connections. The listener first tries the
last address in `state/proxy.json`; if occupied or missing, the OS assigns a free
port. The receipt is updated atomically with mode 0600. Foreground and service
modes use this same startup path and both sockets close with the process. Failure
to start/persist the extra listener leaves the main listener available and makes
Desktop launch fail explicitly. After a port change, relaunch Desktop to pick
up the new address. No second process or CA is created.

Desktop state uses an explicit `desktop_config_root`, independent of the optional
client-proof directory. Missing/corrupt identity produces a local JSON 503 on the
Desktop entry; it cannot interfere with the main entry.

- `claude.ai` and `api.anthropic.com` use the dedicated listener and shared CA.
- `/api/bootstrap`, `/edge-api/bootstrap` fetch anonymous upstream JSON and patch
  local account, organization, access and Gateway-derived model selectors.
  Organization `app_start` requests fetch anonymous `/edge-api/bootstrap`.
  Upstream/catalog failure is an explicit 502, not a fake successful bootstrap.
- `/api/desktop/features` and non-API GET/HEAD pages/resources are anonymously
  fetched. `/cdn-cgi/challenge-platform/*` is included. Only public request
  headers are forwarded; upstream sessionKey/sessionKeyV3/lastActiveOrg Cookies
  are discarded. Redirects are returned to the browser, not followed by the
  credential-bearing Gateway client. Responses are bounded to 32 MiB.
- Account, organization, model selection and the prototype's startup sidecars
  are local. Unknown API/edge-api/v1 routes return 501. Ambiguous encoded or
  traversal paths are rejected rather than treated as public resources.
- Chat completions return 409; event logging is discarded with 204. Logout
  clears local Cookies and never contacts the real account service. Long-lived
  placeholders remain reusable by the managed launcher; logout is not Gateway
  credential revocation. Both hosts' Linux update check returns 204.
- CDN domains remain ordinary tunnels. hCaptcha, Intercom and Google login have
  no special adapter policy. `browser-intake-us5-datadoghq.com` joins the existing
  telemetry denylist.
- Models come from the Anthropic Gateway `/v1/models`, with pagination and a
  60-second in-memory cache. Selections are validated against this catalog.

`saiai uninstall` already includes the entire selected environment's `desktop/`
directory. No extra external installation artifacts or uninstall paths were added.
Close the isolated Desktop before uninstalling it. Normal Claude profiles and
user project folders are outside this adapter's state directory.

## Acceptance checklist

Verified on Linux (Desktop 4.23118.0, bundled Code 2.1.317) through an isolated
test SAIAI instance:

- Reaches the visible logged-in Code UI ("SAIAI Local Code"), with the model
  dropdown populated from the real Gateway `/v1/models` catalog.
- First launch with the dedicated port not yet bound correctly asks the user to
  run `saiai restart`; Chromium trusts the SAIAI CA through the isolated NSS db
  (no `--ignore-certificate-errors` switch — Desktop refuses to start with one).
- The bundled Code runtime completes a real `/v1/messages` turn through the
  placeholder→Gateway credential swap (real model replied, exit 0).

Still to watch (not blockers; confirm under normal use):

1. Fresh-profile Cookie injection, native authorize/token exchange and restart
   persistence across a full day of use.
2. OAuth account UUID omission stays accepted; Desktop does not repopulate a
   nonempty `metadata.user_id.account_uuid` over a long session (currently only
   logged). Login email context was confirmed absent on the verified turn.
4. Model dropdown, persistence and switching; empty/failed catalog behavior.
5. Refresh grant, proxy/Desktop restart and long-lived login behavior.
6. Chat/Cowork refusal, no real account API leakage, anonymous public resource
   loading, browser intake blocking, unknown API 501 and disabled app update.
7. Parallel normal-profile Desktop remains unchanged; occupied port, wrong CA,
   existing SingletonLock and untested version fail clearly.
8. If a group uses `observe`/`enforce`, an administrator must add
   `claude-desktop` to that group's allowlist. No server PR is required; this
   client does not change the group policy or strict billing validation.
9. With Desktop absent, running and with corrupt state, main-port clients still
   tunnel `claude.ai` and preserve Anthropic OAuth/Bearer behavior. Confirm both
   listeners restart together and Desktop detects a changed/occupied port.

## Suggested PR description

Add `saiai desktop claude` for the Linux Claude Desktop Code surface. Previously
Claude parsed as a Desktop product but had no adapter. The new isolated launcher
uses local login fixtures and opaque OAuth placeholders; a dedicated loopback
listener in the same proxy process substitutes the matching placeholder with the
Anthropic route credential. Main-port clients retain their existing behavior.
Gateway routing and credential policy are now explicit independent enums.

Public bootstrap remains anonymous upstream data plus a local patch. Private
control paths are local or rejected; Chat/Cowork remain unsupported. No new
Cargo dependencies or server changes are included. Existing `desktop/` uninstall
coverage includes the new profile.

Validation: CLI/core tests and CI-level fmt/clippy pass in the authorized Docker
image. Verified on Linux: the logged-in Code UI with the real Gateway model
catalog, and a real `/v1/messages` turn through the credential swap. Remaining to
watch under normal use: first-response Cookie injection over long sessions,
possible metadata UUID writeback, and adding `claude-desktop` to any
observe/enforce group allowlist.

### Known non-blocking follow-ups

- Public HEAD and conditional-GET 304 responses rebuild `Content-Length` from the
  (empty) body rather than echoing the upstream representation length. Harmless on
  the verified GET bootstrap path; tighten to omit or preserve the real length.
- The Gateway model catalog fetch is not coalesced across concurrent refreshes,
  and its 30 s timeout / 32 MiB bound are per page (the real catalog is one page);
  add per-identity coalescing and an overall fetch deadline.
- Add tests for HEAD/304 public responses, oversized/slow catalog fetches,
  pagination exhaustion, and keep-alive consecutive requests on one TLS connection.


The launcher removes inherited Codex/OpenAI credentials, `NODE_OPTIONS` and
`ELECTRON_RUN_AS_NODE`. Remaining launch arguments and environment variables
still need validation on Desktop 4.23118.0; the development host has no
`/usr/lib/claude-desktop` binary to inspect. OAuth `claude:` redirects retain
the existing host/path policy until the actual callback is observed; the Code
launch deep link alone does not establish the OAuth callback.
