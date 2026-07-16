#!/usr/bin/env bash
# Install or reuse SAIAI, configure the requested client, and start the Claude
# local proxy service for the Claude setup path.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  setup.sh <base_url> <api_key>
  setup.sh init-codex <base_url> <api_key> [--websockets]

The wrapper checks the release manifest on every run. It downloads the binary
only when the installed binary differs, then always applies the supplied config.
Claude setup also starts or refreshes the per-user local proxy service.

Environment:
  SAIAI_DOWNLOAD_BASE  Flat manifest/asset base URL
                       (default: https://api.saiai.top/saiai-cli)
  SAIAI_INSTALL_DIR    Install directory (default: ~/.local/bin)
  SAIAI_SKIP_START=1   Configure Claude without starting the proxy service
EOF
}

if [ "$#" -lt 2 ]; then
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
    echo "Unsupported operating system. Use setup.ps1 on Windows." >&2
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
install_path="${INSTALL_DIR}/saiai"
backup_path="${INSTALL_DIR}/saiai-previous"
temporary="$(mktemp -d)"
staged_path=""
cleanup() {
  rm -rf -- "${temporary}"
  if [ -n "${staged_path}" ]; then
    rm -f -- "${staged_path}"
  fi
}
trap cleanup EXIT

manifest_path="${temporary}/manifest.json"
metadata_path="${temporary}/asset-metadata"
candidate_path="${temporary}/saiai"

echo "Checking SAIAI client release metadata..." >&2
curl -fsSL --proto '=https,file,http' -o "${manifest_path}" "${manifest_url}"

if command -v python3 >/dev/null 2>&1; then
  python_command="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  python_command="$(command -v python)"
else
  python_command=""
fi

if [ -n "${python_command}" ]; then
  "${python_command}" - "${manifest_path}" "${asset}" >"${metadata_path}" <<'PY'
import json
import re
import sys

path, asset = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
if manifest.get("manifest_schema") != 1:
    raise SystemExit("unsupported SAIAI manifest schema")
if manifest.get("client_mode") != "local-proxy":
    raise SystemExit("release is not a SAIAI local-proxy client")
if manifest.get("configuration_schema_version") != 1:
    raise SystemExit("unsupported SAIAI configuration schema")
entry = manifest.get("assets", {}).get(asset)
if not isinstance(entry, dict):
    raise SystemExit("manifest does not contain " + asset)
sha256 = entry.get("sha256")
size = entry.get("size")
if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
    raise SystemExit("manifest sha256 is invalid for " + asset)
if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
    raise SystemExit("manifest size is invalid for " + asset)
print(sha256)
print(size)
print(manifest.get("version", ""))
PY
elif command -v node >/dev/null 2>&1; then
  node - "${manifest_path}" "${asset}" >"${metadata_path}" <<'JS'
const fs = require("node:fs");
const [path, asset] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
if (manifest.manifest_schema !== 1) throw new Error("unsupported SAIAI manifest schema");
if (manifest.client_mode !== "local-proxy") throw new Error("release is not a SAIAI local-proxy client");
if (manifest.configuration_schema_version !== 1) throw new Error("unsupported SAIAI configuration schema");
const entry = manifest.assets?.[asset];
if (!entry || typeof entry !== "object") throw new Error(`manifest does not contain ${asset}`);
if (typeof entry.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error(`manifest sha256 is invalid for ${asset}`);
if (!Number.isSafeInteger(entry.size) || entry.size <= 0) throw new Error(`manifest size is invalid for ${asset}`);
process.stdout.write(`${entry.sha256}\n${entry.size}\n${manifest.version ?? ""}\n`);
JS
else
  echo "Python or Node.js is required to validate the SAIAI release manifest." >&2
  exit 1
fi

expected_sha256="$(sed -n '1p' "${metadata_path}")"
expected_size="$(sed -n '2p' "${metadata_path}")"
release_version="$(sed -n '3p' "${metadata_path}")"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
  else
    echo "No SHA-256 implementation is available." >&2
    return 1
  fi
}

mkdir -p -- "${INSTALL_DIR}"
if [ -L "${install_path}" ]; then
  echo "Refusing to use symbolic-link install path: ${install_path}" >&2
  exit 1
fi
if [ -e "${install_path}" ] && [ ! -f "${install_path}" ]; then
  echo "Install path is not a regular file: ${install_path}" >&2
  exit 1
fi

installed_matches=0
if [ -f "${install_path}" ]; then
  installed_sha256="$(sha256_file "${install_path}")"
  if [ "${installed_sha256}" = "${expected_sha256}" ]; then
    installed_matches=1
  fi
fi

if [ "${installed_matches}" -eq 1 ]; then
  echo "SAIAI ${release_version} is already installed; binary download skipped." >&2
else
  echo "Downloading ${asset}..." >&2
  curl -fsSL --proto '=https,file,http' -o "${candidate_path}" "${asset_url}"
  actual_size="$(wc -c <"${candidate_path}" | tr -d '[:space:]')"
  if [ "${actual_size}" != "${expected_size}" ]; then
    echo "Size mismatch for ${asset}." >&2
    exit 1
  fi
  actual_sha256="$(sha256_file "${candidate_path}")"
  if [ "${actual_sha256}" != "${expected_sha256}" ]; then
    echo "SHA-256 mismatch for ${asset}." >&2
    exit 1
  fi

  if [ -f "${install_path}" ] && [ ! -e "${backup_path}" ]; then
    if [ -L "${backup_path}" ]; then
      echo "Refusing to replace symbolic-link backup: ${backup_path}" >&2
      exit 1
    fi
    cp -- "${install_path}" "${backup_path}"
    chmod 0755 "${backup_path}"
    echo "Preserved the previous client at ${backup_path}." >&2
  fi
  chmod 0755 "${candidate_path}"
  staged_path="$(mktemp "${INSTALL_DIR}/.saiai.install.XXXXXX")"
  cp -- "${candidate_path}" "${staged_path}"
  chmod 0755 "${staged_path}"
  mv -f -- "${staged_path}" "${install_path}"
  staged_path=""
  echo "Installed SAIAI ${release_version} at ${install_path}." >&2
fi

case ":${PATH:-}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) echo "Add ${INSTALL_DIR} to PATH when you want to run saiai directly." >&2 ;;
esac

if [ "${1:-}" = "init-codex" ]; then
  "${install_path}" "$@"
else
  "${install_path}" init "$@"
  if [ "${SAIAI_SKIP_START:-0}" != "1" ]; then
    "${install_path}" start
  fi
fi
