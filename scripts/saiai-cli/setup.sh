#!/usr/bin/env bash
# Install or reuse SAIAI, configure the requested client, and start the Claude
# local proxy service for the Claude setup path.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  setup.sh <base_url> <api_key>
  setup.sh init-codex
  setup.sh init-codex <base_url> <api_key> [--websockets]
  setup.sh uninstall [--yes] [--dry-run] [--forget-unknown-environments]

The wrapper checks the release manifest on every run. It downloads the binary
only when the installed binary differs, then always applies the supplied config.
Both Claude and Codex setup start or refresh the per-user local proxy service.

Environment:
  SAIAI_DOWNLOAD_BASE  Flat manifest/asset base URL
                       (default: https://api.saiai.top/saiai-cli)
  SAIAI_INSTALL_DIR    Install directory (default: ~/.local/bin)
  SAIAI_SKIP_START=1   Configure without starting the proxy service
EOF
}

DEFAULT_DOWNLOAD_BASE="https://api.saiai.top/saiai-cli"
DOWNLOAD_BASE="${SAIAI_DOWNLOAD_BASE:-${DEFAULT_DOWNLOAD_BASE}}"
DOWNLOAD_BASE="${DOWNLOAD_BASE%/}"
INSTALL_DIR="${SAIAI_INSTALL_DIR:-${HOME:?HOME is required}/.local/bin}"

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

# Pick a JSON reader: sets json_tool to python, node, plutil or empty, and
# python_command for python. On macOS without the Command Line Tools,
# /usr/bin/python3 is a stub that opens an install dialog instead of running,
# so it is skipped there; plutil ships with every macOS.
select_json_tool() {
  local name candidate
  json_tool=""
  python_command=""
  for name in python3 python; do
    candidate="$(command -v "${name}" 2>/dev/null)" || continue
    case "${candidate}" in
      /usr/bin/*)
        if [ "$(uname -s)" = "Darwin" ] && ! xcode-select -p >/dev/null 2>&1; then
          continue
        fi
        ;;
    esac
    json_tool="python"
    python_command="${candidate}"
    return 0
  done
  if command -v node >/dev/null 2>&1; then
    json_tool="node"
  elif [ "$(uname -s)" = "Darwin" ] && command -v plutil >/dev/null 2>&1; then
    json_tool="plutil"
  fi
}

# Print the scalar at key path $1 of JSON file $2 with plutil, failing unless
# its type is $3 (string, integer, ...). plutil reports a missing key on
# stdout, so the value is printed only on success.
plutil_value() {
  local type value
  type="$(plutil -type "$1" "$2" 2>/dev/null)" || return 1
  [ "${type}" = "$3" ] || return 1
  value="$(plutil -extract "$1" raw -o - "$2" 2>/dev/null)" || return 1
  printf '%s\n' "${value}"
}

# Validate the release manifest inside directory $1. Sets asset,
# expected_sha256, expected_size and release_version.
fetch_release_metadata() {
  local work="$1" platform architecture json_tool python_command
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
  local manifest_path="${work}/manifest.json"
  local metadata_path="${work}/asset-metadata"

  echo "Checking SAIAI client release metadata..." >&2
  curl -fsSL --proto '=https,file,http' -o "${manifest_path}" "${DOWNLOAD_BASE}/manifest.json"

  select_json_tool

  if [ "${json_tool}" = "python" ]; then
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
  elif [ "${json_tool}" = "node" ]; then
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
  elif [ "${json_tool}" = "plutil" ]; then
    local manifest_schema client_mode configuration_schema sha256 size version
    # plutil -type and "raw" need macOS 12 or later.
    if ! plutil -type manifest_schema "${manifest_path}" >/dev/null 2>&1; then
      echo "Could not read the SAIAI release manifest with this macOS plutil; install Python or Node.js and retry." >&2
      exit 1
    fi
    manifest_schema="$(plutil_value manifest_schema "${manifest_path}" integer)" || manifest_schema=""
    client_mode="$(plutil_value client_mode "${manifest_path}" string)" || client_mode=""
    configuration_schema="$(plutil_value configuration_schema_version "${manifest_path}" integer)" || configuration_schema=""
    if [ "$(plutil -type "assets.${asset}" "${manifest_path}" 2>/dev/null)" != "dictionary" ]; then
      echo "manifest does not contain ${asset}" >&2
      exit 1
    fi
    sha256="$(plutil_value "assets.${asset}.sha256" "${manifest_path}" string)" || sha256=""
    size="$(plutil_value "assets.${asset}.size" "${manifest_path}" integer)" || size=""
    version="$(plutil_value version "${manifest_path}" string)" || version=""
    if [ "${manifest_schema}" != "1" ]; then
      echo "unsupported SAIAI manifest schema" >&2
      exit 1
    fi
    if [ "${client_mode}" != "local-proxy" ]; then
      echo "release is not a SAIAI local-proxy client" >&2
      exit 1
    fi
    if [ "${configuration_schema}" != "1" ]; then
      echo "unsupported SAIAI configuration schema" >&2
      exit 1
    fi
    if ! [[ "${sha256}" =~ ^[0-9a-f]{64}$ ]]; then
      echo "manifest sha256 is invalid for ${asset}" >&2
      exit 1
    fi
    if ! [[ "${size}" =~ ^[1-9][0-9]*$ ]]; then
      echo "manifest size is invalid for ${asset}" >&2
      exit 1
    fi
    printf '%s\n%s\n%s\n' "${sha256}" "${size}" "${version}" >"${metadata_path}"
  else
    echo "Python or Node.js is required to validate the SAIAI release manifest." >&2
    exit 1
  fi

  expected_sha256="$(sed -n '1p' "${metadata_path}")"
  expected_size="$(sed -n '2p' "${metadata_path}")"
  release_version="$(sed -n '3p' "${metadata_path}")"
}

# Download the manifest-verified release asset to $1.
download_release_asset() {
  local destination="$1" actual_size actual_sha256
  echo "Downloading ${asset}..." >&2
  curl -fsSL --proto '=https,file,http' -o "${destination}" "${DOWNLOAD_BASE}/${asset}"
  actual_size="$(wc -c <"${destination}" | tr -d '[:space:]')"
  if [ "${actual_size}" != "${expected_size}" ]; then
    echo "Size mismatch for ${asset}." >&2
    exit 1
  fi
  actual_sha256="$(sha256_file "${destination}")"
  if [ "${actual_sha256}" != "${expected_sha256}" ]; then
    echo "SHA-256 mismatch for ${asset}." >&2
    exit 1
  fi
  chmod 0755 "${destination}"
}

# The native client is the only uninstall executor: this wrapper finds or
# downloads a capable client and never deletes files itself.
if [ "${1:-}" = "uninstall" ]; then
  shift
  for argument in "$@"; do
    case "${argument}" in
      --yes|--dry-run|--forget-unknown-environments) ;;
      *)
        usage
        exit 2
        ;;
    esac
  done
  executor=""
  for candidate in ${SAIAI_INSTALL_DIR:+"${SAIAI_INSTALL_DIR}/saiai"} "${HOME}/.local/bin/saiai" "$(command -v saiai 2>/dev/null || true)"; do
    if [ -n "${candidate}" ] && [ -f "${candidate}" ] && [ -x "${candidate}" ] &&
      probe="$("${candidate}" uninstall --dry-run --yes "$@" 2>/dev/null </dev/null)"; then
      case $'\n'"${probe}"$'\n' in
        *$'\nSAIAI uninstall plan\n'*)
          executor="${candidate}"
          break
          ;;
      esac
    fi
  done
  if [ -z "${executor}" ]; then
    echo "No installed SAIAI client supports uninstall; downloading the current release to a temporary directory." >&2
    uninstall_temporary="$(mktemp -d)"
    trap 'rm -rf -- "${uninstall_temporary}"' EXIT
    set +e
    (
      set -e
      fetch_release_metadata "${uninstall_temporary}"
      download_release_asset "${uninstall_temporary}/saiai-uninstall"
    )
    download_status=$?
    set -e
    if [ "${download_status}" -ne 0 ]; then
      cat >&2 <<'EOF'
Could not download a SAIAI client that supports uninstall. Nothing was changed.
Retry when the network is available, or remove SAIAI manually:
  1. Stop the proxy with `saiai stop`.
  2. Delete ~/.saiai and ~/.local/bin/saiai (or saiai in SAIAI_INSTALL_DIR).
  3. In ~/.claude/settings.json remove the SAIAI env entries CLAUDE_CODE_OAUTH_TOKEN,
     http_proxy, https_proxy, all_proxy, no_proxy and NODE_EXTRA_CA_CERTS.
  4. In ~/.codex/.env remove the "# BEGIN SAIAI CODEX IDE (managed)" block, then run `codex login`.
EOF
      exit 1
    fi
    executor="${uninstall_temporary}/saiai-uninstall"
  fi
  # The client confirms through the terminal, never through this script's stdin.
  set +e
  "${executor}" uninstall "$@"
  uninstall_status=$?
  set -e
  exit "${uninstall_status}"
fi

if [ "$#" -eq 1 ] && [ "$1" = "init-codex" ]; then
  codex_mode=1
  config_path="${SAIAI_HOME:-${HOME:?HOME is required}/.saiai}/config.json"
  base_url=""
  api_key=""
  # A product override may identify a project. Never silently import the
  # default proxy's credentials into it; let the caller supply its own pair.
  if [ "${CODEX_HOME+x}" = x ]; then
    config_path=""
  fi
  if [ -f "${config_path}" ]; then
    select_json_tool
    if [ "${json_tool}" = "python" ]; then
      read -r base_url api_key < <("${python_command}" - "${config_path}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    config = json.load(handle)
print(config.get("base_url", ""), config.get("api_key", ""))
PY
      )
    elif [ "${json_tool}" = "node" ]; then
      read -r base_url api_key < <(node - "${config_path}" <<'JS'
const fs = require("node:fs");
const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(`${config.base_url ?? ""} ${config.api_key ?? ""}\n`);
JS
      )
    elif [ "${json_tool}" = "plutil" ]; then
      if ! plutil -convert json -o /dev/null "${config_path}" >/dev/null 2>&1; then
        echo "Could not read ${config_path}." >&2
        exit 1
      fi
      base_url="$(plutil_value base_url "${config_path}" string)" || base_url=""
      api_key="$(plutil_value api_key "${config_path}" string)" || api_key=""
    fi
  fi
  if [ -z "${base_url}" ]; then
    read -r -p "SAIAI Gateway URL [https://api.saiai.top]: " base_url
    base_url="${base_url:-https://api.saiai.top}"
  fi
  if [ -z "${api_key}" ]; then
    read -r -s -p "SAIAI API key: " api_key
    printf '\n' >&2
  fi
  set -- init-codex "${base_url}" "${api_key}"
elif [ "$#" -lt 2 ]; then
  usage
  exit 2
fi

temporary="$(mktemp -d)"
staged_path=""
cleanup() {
  rm -rf -- "${temporary}"
  if [ -n "${staged_path}" ]; then
    rm -f -- "${staged_path}"
  fi
}
trap cleanup EXIT

install_path="${INSTALL_DIR}/saiai"
backup_path="${INSTALL_DIR}/saiai-previous"
candidate_path="${temporary}/saiai"

fetch_release_metadata "${temporary}"

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
binary_updated=0
if [ -f "${install_path}" ]; then
  installed_sha256="$(sha256_file "${install_path}")"
  if [ "${installed_sha256}" = "${expected_sha256}" ]; then
    installed_matches=1
  fi
fi

if [ "${installed_matches}" -eq 1 ]; then
  echo "SAIAI ${release_version} is already installed; binary download skipped." >&2
else
  binary_updated=1
  download_release_asset "${candidate_path}"

  if [ -f "${install_path}" ] && [ ! -e "${backup_path}" ]; then
    if [ -L "${backup_path}" ]; then
      echo "Refusing to replace symbolic-link backup: ${backup_path}" >&2
      exit 1
    fi
    cp -- "${install_path}" "${backup_path}"
    chmod 0755 "${backup_path}"
    echo "Preserved the previous client at ${backup_path}." >&2
  fi
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
  SAIAI_BINARY_UPDATED="${binary_updated}" "${install_path}" "$@"
else
  SAIAI_BINARY_UPDATED="${binary_updated}" "${install_path}" init "$@"
fi
