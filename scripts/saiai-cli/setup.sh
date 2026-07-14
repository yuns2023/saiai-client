#!/usr/bin/env bash
# Install the SAIAI V2 client binary. Product setup is performed by `saiai`.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: setup.sh [install]

This wrapper installs only the SAIAI V2 client binary. It never reads an API
key and never initializes Claude or Codex. After installation, run one of:

  saiai claude
  saiai codex
  saiai setup claude
  saiai setup codex

Environment:
  SAIAI_DOWNLOAD_BASE  Flat manifest/asset base URL
                       (default: https://api.saiai.top/saiai-cli)
  SAIAI_INSTALL_DIR    Install directory (default: ~/.local/bin)
EOF
}

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "install" ]; }; then
  usage
  exit 2
fi

DEFAULT_DOWNLOAD_BASE="https://api.saiai.top/saiai-cli"
DOWNLOAD_BASE="${SAIAI_DOWNLOAD_BASE:-${DEFAULT_DOWNLOAD_BASE}}"
DOWNLOAD_BASE="${DOWNLOAD_BASE%/}"
INSTALL_DIR="${SAIAI_INSTALL_DIR:-${HOME:?HOME is required}/.local/bin}"

case "$(uname -s)" in
  Linux) platform="linux" ;;
  Darwin) platform="macos" ;;
  *)
    echo "Unsupported operating system. Use setup.ps1 or setup.cmd on Windows." >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) architecture="x86_64" ;;
  arm64|aarch64) architecture="aarch64" ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

asset="saiai-${platform}-${architecture}"
manifest_url="${DOWNLOAD_BASE}/manifest.json"
asset_url="${DOWNLOAD_BASE}/${asset}"
temporary="$(mktemp -d)"
staged_path=""
cleanup() {
  rm -rf "${temporary}"
  if [ -n "${staged_path}" ]; then
    rm -f -- "${staged_path}"
  fi
}
trap cleanup EXIT
manifest_path="${temporary}/manifest.json"
candidate_path="${temporary}/saiai"
metadata_path="${temporary}/asset-metadata"
install_path="${INSTALL_DIR}/saiai"
backup_path="${INSTALL_DIR}/saiai-previous"

echo "Checking ${manifest_url}" >&2
curl -fsSL --proto '=https,file,http' -o "${manifest_path}" "${manifest_url}"

if command -v python3 >/dev/null 2>&1; then
  python_command="$(command -v python3)"
  "${python_command}" - "${manifest_path}" "${asset}" >"${metadata_path}" <<'PY'
import json
import re
import sys

path, asset = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
if manifest.get("manifest_schema") != 1:
    raise SystemExit("unsupported SAIAI manifest schema")
if manifest.get("bootstrap_schema_version") != 2:
    raise SystemExit("release is not compatible with SAIAI bootstrap schema 2")
entry = manifest.get("assets", {}).get(asset)
if not isinstance(entry, dict):
    raise SystemExit(f"manifest does not contain {asset}")
sha256 = entry.get("sha256")
size = entry.get("size")
if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
    raise SystemExit(f"manifest sha256 is invalid for {asset}")
if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
    raise SystemExit(f"manifest size is invalid for {asset}")
print(sha256)
print(size)
PY
elif command -v python >/dev/null 2>&1; then
  python_command="$(command -v python)"
  "${python_command}" - "${manifest_path}" "${asset}" >"${metadata_path}" <<'PY'
import json
import re
import sys

path, asset = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
if manifest.get("manifest_schema") != 1:
    raise SystemExit("unsupported SAIAI manifest schema")
if manifest.get("bootstrap_schema_version") != 2:
    raise SystemExit("release is not compatible with SAIAI bootstrap schema 2")
entry = manifest.get("assets", {}).get(asset)
if not isinstance(entry, dict):
    raise SystemExit("manifest does not contain {0}".format(asset))
sha256 = entry.get("sha256")
size = entry.get("size")
if not isinstance(sha256, str) or not re.match(r"^[0-9a-f]{64}$", sha256):
    raise SystemExit("manifest sha256 is invalid for {0}".format(asset))
if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
    raise SystemExit("manifest size is invalid for {0}".format(asset))
print(sha256)
print(size)
PY
elif command -v node >/dev/null 2>&1; then
  node - "${manifest_path}" "${asset}" >"${metadata_path}" <<'JS'
const fs = require("node:fs");
const [path, asset] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
if (manifest.manifest_schema !== 1) throw new Error("unsupported SAIAI manifest schema");
if (manifest.bootstrap_schema_version !== 2) throw new Error("release is not compatible with SAIAI bootstrap schema 2");
const entry = manifest.assets?.[asset];
if (!entry || typeof entry !== "object") throw new Error(`manifest does not contain ${asset}`);
if (typeof entry.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error(`manifest sha256 is invalid for ${asset}`);
if (!Number.isSafeInteger(entry.size) || entry.size <= 0) throw new Error(`manifest size is invalid for ${asset}`);
process.stdout.write(`${entry.sha256}\n${entry.size}\n`);
JS
else
  echo "Python or Node.js is required to validate the SAIAI release manifest." >&2
  exit 1
fi

expected_sha256="$(sed -n '1p' "${metadata_path}")"
expected_size="$(sed -n '2p' "${metadata_path}")"

echo "Downloading ${asset_url}" >&2
curl -fsSL --proto '=https,file,http' -o "${candidate_path}" "${asset_url}"
actual_size="$(wc -c <"${candidate_path}" | tr -d '[:space:]')"
if [ "${actual_size}" != "${expected_size}" ]; then
  echo "Size mismatch for ${asset}" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "${candidate_path}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_sha256="$(shasum -a 256 "${candidate_path}" | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
  actual_sha256="$(openssl dgst -sha256 "${candidate_path}" | awk '{print $NF}')"
else
  echo "No SHA-256 implementation is available." >&2
  exit 1
fi
actual_sha256="$(printf '%s' "${actual_sha256}" | tr 'A-F' 'a-f')"
if [ "${actual_sha256}" != "${expected_sha256}" ]; then
  echo "SHA-256 mismatch for ${asset}" >&2
  exit 1
fi

mkdir -p "${INSTALL_DIR}"
if [ -L "${install_path}" ]; then
  echo "Refusing to replace symbolic link: ${install_path}" >&2
  exit 1
fi
if [ -e "${install_path}" ] && [ ! -f "${install_path}" ]; then
  echo "Install path is not a regular file: ${install_path}" >&2
  exit 1
fi
if [ -f "${install_path}" ] && ! cmp -s "${install_path}" "${candidate_path}"; then
  if [ -L "${backup_path}" ]; then
    echo "Refusing to replace symbolic-link backup: ${backup_path}" >&2
    exit 1
  fi
  if [ ! -e "${backup_path}" ]; then
    cp "${install_path}" "${backup_path}"
    chmod 0755 "${backup_path}"
    echo "Preserved the previous client at ${backup_path}" >&2
  fi
fi
chmod 0755 "${candidate_path}"
staged_path="$(mktemp "${INSTALL_DIR}/.saiai.install.XXXXXX")"
cp "${candidate_path}" "${staged_path}"
chmod 0755 "${staged_path}"
mv -f "${staged_path}" "${install_path}"
staged_path=""

echo "SAIAI V2 installed at ${install_path}" >&2
case ":${PATH:-}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) echo "Add ${INSTALL_DIR} to PATH, or run ${install_path} directly." >&2 ;;
esac
echo "Next: ${install_path} claude or ${install_path} codex" >&2
echo "Explicit setup: ${install_path} setup claude or ${install_path} setup codex" >&2
