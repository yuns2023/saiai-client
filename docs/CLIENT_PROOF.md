# SAIAI client proof v1 — wire contract (Server ↔ local proxy)

Goal: let the Gateway tell requests sent by the SAIAI local proxy from requests sent directly
with the API key. Both repos are public, so this is device binding + server-side visibility,
not secrecy. v1 is OBSERVE ONLY: the Gateway never rejects a request because of the proof.

## 1. Device key
- Client generates an ECDSA P-256 key pair on first use (Rust `p256` crate, enable `ecdsa`
  feature; Go `crypto/ecdsa`). Private key stored in `~/.saiai/client-device-key` (PKCS#8 PEM,
  0600 on unix; on Windows rely on the user-profile ACL), plus `~/.saiai/client-device.json`
  `{ "device_id": "...", "gateway": "<base url>", "public_key_sha256": "<hex>" }`.
- Public key encoding on the wire: base64url (no padding) of the SEC1 **uncompressed** point
  (65 bytes, leading 0x04). Server rejects anything else.

## 2. Enrollment
`POST /api/v1/client/devices/enroll` with `Authorization: Bearer <api key>` (same auth as
`/api/v1/client/bootstrap`). JSON body:
```json
{ "public_key": "<b64url 65 bytes>", "client_version": "1.1.54", "os": "windows", "arch": "x86_64" }
```
- Idempotent on (user_id, sha256(public_key)): returns the existing device.
- 200 → `{ "device_id": "cd_<22 chars b64url of 16 random bytes>", "status": "active" }`
- 403 `{ "code": "client_device_revoked" }` when that key was revoked → client stops signing for
  this gateway (does not auto-generate a new key).
- 429 `{ "code": "client_device_limit" }` when the user already has 50 non-revoked devices.
- Field limits: client_version ≤ 64, os/arch ≤ 32 chars; bigger body (>4 KiB) → 400.
- Client: enroll once per process start in the background (non-blocking), retry with backoff
  (1m, 5m, 30m cap) on network/5xx; until a device_id is known, forward requests unsigned.
  Enrollment failure must never break forwarding.

## 3. Request proof header
`X-Saiai-Client-Proof: v1.<device_id>.<ts>.<nonce>.<sig>`
- ts: unix seconds (decimal). nonce: base64url(16 random bytes) = 22 chars. Fresh per request
  attempt — every retry / reconnect / WS handshake is signed anew.
- sig: base64url of the 64-byte raw `r||s` ECDSA P-256 signature over SHA-256 of the message:
```
saiai-client-proof-v1\n
<METHOD uppercase>\n
<request target exactly as sent on the wire: path + optional "?query", no scheme/host>\n
<ts>\n
<nonce>\n
<lowercase hex sha256 of the exact API key string sent in Authorization Bearer>
```
  (lines joined with "\n", no trailing newline).
- Server takes the target from `c.Request.RequestURI` (raw, before any endpointNorm rewrite).
- Header total length cap 256; any parse error → `invalid`.
- Applies to every request the local proxy sends to the Gateway: HTTP forwarding paths and the
  WebSocket upgrade GET. WS: only the handshake is signed.
- The local proxy must never forward a client-supplied `X-Saiai-Client-Proof` (drop it, then add
  its own). The Gateway must strip it before any upstream request (all platforms/paths).

## 4. Server verification (observe mode)
Status enum (stored as smallint in `usage_logs.client_attestation`, NULL = not collected):
1 valid, 2 missing, 3 invalid (format/signature/key mismatch), 4 stale (|now-ts| > 300s),
5 replay (nonce seen; Redis `SET NX` TTL 900s), 6 unknown_device (no such device, or device
belongs to another user than the API key's user), 7 revoked, 8 unverified (Redis/DB error —
fail open, short timeout).
- Computed only when the request's group has `client_attestation_policy = observe`; `off` →
  NULL. Never rejects in v1 (`enforce` reserved, not selectable yet).
- Device lookups cached in-process ≤ 60s; revocation invalidates the local cache entry
  immediately (other instances converge within the TTL).
- On `valid`: update device `last_seen_at`, `last_ip`, and `last_claude_at` or `last_codex_at`
  (by platform of the route/group), throttled per (device, field) to once per 5 min.

## 5. Admin
- Users list: column "Codex 设备" = number of non-revoked devices with `last_codex_at` within 30
  days (clicking opens the user's client-device modal, with revoke); column "客户端校验（7天）"
  aggregating `usage_logs.client_attestation` for the current page's user ids over 7 days
  (billing requests only — say so in the header tooltip).
- Usage table: badge on rows whose status is not valid/NULL.
- Group edit: `client_attestation_policy` select (off / observe).
- Neutral wording everywhere (no "逆向/作弊"). Labels: 通过 / 未携带 / 校验失败 / 时间偏差 /
  重复请求 / 设备未知 / 设备已吊销 / 未校验 / 未采集.

## 6. Client notes (local proxy)
- Files live in the SAIAI config directory (`SAIAI_HOME`, default `~/.saiai`):
  `client-device-key` and `client-device.json`. The JSON is client-local; it records
  `gateways[<base url>][<sha256(api key)>] = { device_id, revoked }` so several gateways
  and several users of one gateway can coexist.
- Key creation/recovery and every `client-device.json` read-merge-write happen under an
  exclusive OS file lock on `client-device.lock` (background threads only; if locking
  fails, proofs are disabled for that process). A corrupted key is kept as
  `client-device-key.corrupt` and replaced by a new key (a new device).
- Each Bearer is enrolled at most once per process. Bearers not configured on a route are
  enrolled on demand; beyond 16 distinct unconfigured Bearers per process, later ones stay
  unsigned until restart.
- Recovery from revocation (or to start over as a new device): stop the local proxy,
  delete both files, and start it again. A new key is generated and enrolled.
