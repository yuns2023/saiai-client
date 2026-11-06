#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

fixtures="${temporary}/fixtures"
fake_bin="${temporary}/fake-bin"
home="${temporary}/home"
install_dir="${temporary}/install"
output="${temporary}/output"
invoked="${temporary}/binary-invoked"
curl_log="${temporary}/curl-log"
mkdir -p "${fixtures}" "${fake_bin}" "${home}" "${install_dir}"

asset="${fixtures}/saiai-linux-x86_64"
cat >"${asset}" <<'SH'
#!/usr/bin/env bash
if [ "${1:-}" = "uninstall" ] && [ "${2:-}" = "--dry-run" ] && [ "${3:-}" = "--yes" ]; then
  printf 'SAIAI uninstall plan\nSAIAI home: test\n'
  exit 0
fi
printf 'UPDATED=%s\n' "${SAIAI_BINARY_UPDATED:-}" >>"${SAIAI_TEST_BINARY_INVOKED:?}"
printf 'CALL\n' >>"${SAIAI_TEST_BINARY_INVOKED:?}"
printf '%s\n' "$@" >>"${SAIAI_TEST_BINARY_INVOKED:?}"
exit "${SAIAI_TEST_EXIT:-0}"
SH
chmod +x "${asset}"
sha256="$(sha256sum "${asset}" | awk '{print $1}')"
size="$(wc -c <"${asset}" | tr -d '[:space:]')"
printf '{"client_mode":"local-proxy","configuration_schema_version":1,"manifest_schema":1,"version":"1.1.25","assets":{"saiai-linux-x86_64":{"sha256":"%s","size":%s},"saiai-macos-aarch64":{"sha256":"%s","size":%s}}}\n' \
  "${sha256}" "${size}" "${sha256}" "${size}" >"${fixtures}/manifest.json"

cat >"${fake_bin}/uname" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  -s) printf '%s\n' "${SAIAI_TEST_UNAME_S:-Linux}" ;;
  -m) printf '%s\n' "${SAIAI_TEST_UNAME_M:-x86_64}" ;;
  *) exit 1 ;;
esac
SH
chmod +x "${fake_bin}/uname"

cat >"${fake_bin}/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
destination=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) destination="$2"; shift 2 ;;
    --proto) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "${url}" >>"${SAIAI_TEST_CURL_LOG:?}"
if [ "${SAIAI_TEST_CURL_FAIL:-}" = 1 ]; then
  exit 22
fi
case "${url}" in
  */manifest.json) cp "${SAIAI_TEST_FIXTURES:?}/manifest.json" "${destination}" ;;
  */saiai-linux-x86_64|*/saiai-macos-aarch64) cp "${SAIAI_TEST_FIXTURES:?}/saiai-linux-x86_64" "${destination}" ;;
  *) echo "unexpected wrapper URL: ${url}" >&2; exit 1 ;;
esac
SH
chmod +x "${fake_bin}/curl"

run_setup() {
  rm -f "${output}" "${invoked}"
  local scope_environment=()
  if [ "${SAIAI_TEST_CODEX_HOME+x}" = x ]; then
    scope_environment=("CODEX_HOME=${SAIAI_TEST_CODEX_HOME}")
  fi
  env -u CODEX_HOME -u CLAUDE_CONFIG_DIR "${scope_environment[@]}" \
    HOME="${home}" \
    SAIAI_HOME="${home}/.saiai" \
    PATH="${SAIAI_TEST_PATH:-${fake_bin}:${PATH}}" \
    SAIAI_DOWNLOAD_BASE="https://download.example.test/client" \
    SAIAI_INSTALL_DIR="${install_dir}" \
    SAIAI_TEST_FIXTURES="${fixtures}" \
    SAIAI_TEST_BINARY_INVOKED="${invoked}" \
    SAIAI_TEST_CURL_LOG="${curl_log}" \
    bash "${script_dir}/setup.sh" "$@" >"${output}" 2>&1
}

first_key="TEST_ONLY_KEY_WITH_'_AND_SPACE"
run_setup "https://gateway.example.test" "${first_key}"
test -x "${install_dir}/saiai"
cmp -s "${asset}" "${install_dir}/saiai"
mapfile -t first_invocation <"${invoked}"
test "${first_invocation[0]}" = "UPDATED=1"
test "${first_invocation[1]}" = "CALL"
test "${first_invocation[2]}" = "init"
test "${first_invocation[3]}" = "https://gateway.example.test"
test "${first_invocation[4]}" = "${first_key}"
test "${#first_invocation[@]}" -eq 5
test "$(grep -Fc '/manifest.json' "${curl_log}")" -eq 1
test "$(grep -Fc '/saiai-linux-x86_64' "${curl_log}")" -eq 1
if grep -Fq "${first_key}" "${output}"; then
  echo "wrapper printed the API key" >&2
  exit 1
fi

second_key="TEST_ONLY_REPLACEMENT_KEY"
run_setup "https://new-gateway.example.test" "${second_key}"
mapfile -t second_invocation <"${invoked}"
test "${second_invocation[0]}" = "UPDATED=0"
test "${second_invocation[1]}" = "CALL"
test "${second_invocation[2]}" = "init"
test "${second_invocation[3]}" = "https://new-gateway.example.test"
test "${second_invocation[4]}" = "${second_key}"
test "${#second_invocation[@]}" -eq 5
test "$(grep -Fc '/manifest.json' "${curl_log}")" -eq 2
test "$(grep -Fc '/saiai-linux-x86_64' "${curl_log}")" -eq 1
grep -Fq 'binary download skipped' "${output}"

run_setup init-codex "https://gateway.example.test/v1" "TEST_ONLY_CODEX_KEY" --websockets
mapfile -t codex_invocation <"${invoked}"
test "${codex_invocation[0]}" = "UPDATED=0"
test "${codex_invocation[1]}" = "CALL"
test "${codex_invocation[2]}" = "init-codex"
test "${codex_invocation[3]}" = "https://gateway.example.test/v1"
test "${codex_invocation[4]}" = "TEST_ONLY_CODEX_KEY"
test "${codex_invocation[5]}" = "--websockets"
test "${#codex_invocation[@]}" -eq 6
test "$(grep -Fc '/manifest.json' "${curl_log}")" -eq 3
test "$(grep -Fc '/saiai-linux-x86_64' "${curl_log}")" -eq 1

mkdir -p "${home}/.saiai"
printf '%s\n' '{"base_url":"https://reuse.example.test","api_key":"TEST_ONLY_REUSED_CODEX_KEY"}' >"${home}/.saiai/config.json"
run_setup init-codex
mapfile -t reused_invocation <"${invoked}"
test "${reused_invocation[0]}" = "UPDATED=0"
test "${reused_invocation[1]}" = "CALL"
test "${reused_invocation[2]}" = "init-codex"
test "${reused_invocation[3]}" = "https://reuse.example.test"
test "${reused_invocation[4]}" = "TEST_ONLY_REUSED_CODEX_KEY"
test "${#reused_invocation[@]}" -eq 5
test "$(grep -Fc '/manifest.json' "${curl_log}")" -eq 4
test "$(grep -Fc '/saiai-linux-x86_64' "${curl_log}")" -eq 1

# macOS without the Command Line Tools: /usr/bin/python3 is an installer stub
# and must not run. With Node available the wrapper uses Node.
real_node="$(command -v node)"
real_python="$(command -v python3)"
mac_bin="${temporary}/mac-bin"
mkdir -p "${mac_bin}"
for tool in bash env awk sed sha256sum wc tr mktemp mkdir cp mv chmod rm cat grep; do
  ln -s "$(command -v "${tool}")" "${mac_bin}/${tool}"
done
ln -s "${fake_bin}/uname" "${mac_bin}/uname"
ln -s "${fake_bin}/curl" "${mac_bin}/curl"
printf '#!/usr/bin/env bash\nexit 2\n' >"${mac_bin}/xcode-select"
chmod +x "${mac_bin}/xcode-select"
node_log="${temporary}/node-log"
printf '#!/usr/bin/env bash\necho node >>"%s"\nexec "%s" "$@"\n' "${node_log}" "${real_node}" >"${mac_bin}/node"
chmod +x "${mac_bin}/node"
# The PATH below resolves python3 to /usr/bin/python3, standing in for the stub.
test -x /usr/bin/python3
export SAIAI_TEST_UNAME_S=Darwin SAIAI_TEST_UNAME_M=arm64
SAIAI_TEST_PATH="${mac_bin}:/usr/bin" run_setup init-codex "https://mac.example.test/v1" "TEST_ONLY_MAC_KEY"
test -s "${node_log}"
mapfile -t mac_node_invocation <"${invoked}"
test "${mac_node_invocation[2]}" = "init-codex"
test "${mac_node_invocation[3]}" = "https://mac.example.test/v1"

# macOS with neither a usable Python nor Node: plutil reads the manifest and
# the saved config. The fake plutil mirrors `plutil -extract KEY raw -o - FILE`.
rm -f "${mac_bin}/node"
cat >"${mac_bin}/plutil" <<SH
#!/usr/bin/env bash
exec "${real_python}" -I - "\$@" <<'PY'
import json, sys
args = sys.argv[1:]
if args[0] == "-convert":
    assert args[1:4] == ["json", "-o", "/dev/null"], args
    try:
        json.load(open(args[4]))
    except ValueError:
        sys.exit(1)
    sys.exit(0)
if args[0] == "-type":
    path = args[2]
else:
    assert args[0] == "-extract" and args[2] == "raw" and args[3:5] == ["-o", "-"], args
    path = args[5]
value = json.load(open(path))
for part in args[1].split("."):
    if not isinstance(value, dict) or part not in value:
        print(path + ": Could not extract value, error: No value at that key path")
        sys.exit(1)
    value = value[part]
if args[0] == "-type":
    kinds = [(bool, "bool"), (int, "integer"), (float, "float"), (str, "string"), (dict, "dictionary"), (list, "array")]
    print(next(name for kind, name in kinds if isinstance(value, kind)))
elif isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (dict, list)):
    print("\n".join(value))
else:
    print(value)
PY
SH
chmod +x "${mac_bin}/plutil"
plutil_path="${mac_bin}"
if PATH="${plutil_path}" command -v node >/dev/null || PATH="${plutil_path}" command -v python3 >/dev/null; then
  echo "test PATH still exposes node or python3" >&2
  exit 1
fi
printf '%s\n' '{"base_url":"https://plutil.example.test","api_key":"TEST_ONLY_PLUTIL_KEY"}' >"${home}/.saiai/config.json"
SAIAI_TEST_PATH="${plutil_path}" run_setup init-codex
mapfile -t plutil_invocation <"${invoked}"
test "${plutil_invocation[2]}" = "init-codex"
test "${plutil_invocation[3]}" = "https://plutil.example.test"
test "${plutil_invocation[4]}" = "TEST_ONLY_PLUTIL_KEY"
test "${#plutil_invocation[@]}" -eq 5

# plutil rejects a bad manifest the same way Python and Node do.
cp "${fixtures}/manifest.json" "${temporary}/manifest.good"
sed -i 's/"local-proxy"/"other"/' "${fixtures}/manifest.json"
if SAIAI_TEST_PATH="${plutil_path}" run_setup "https://gateway.example.test" "TEST_ONLY_KEY"; then
  echo "plutil path accepted a non-local-proxy manifest" >&2
  exit 1
fi
grep -Fq 'release is not a SAIAI local-proxy client' "${output}"
cp "${temporary}/manifest.good" "${fixtures}/manifest.json"
sed -i 's/"saiai-macos-aarch64":{"sha256":"[0-9a-f]*"/"saiai-macos-aarch64":{"sha256":"bad"/' "${fixtures}/manifest.json"
if SAIAI_TEST_PATH="${plutil_path}" run_setup "https://gateway.example.test" "TEST_ONLY_KEY"; then
  echo "plutil path accepted an invalid sha256" >&2
  exit 1
fi
grep -Fq 'manifest sha256 is invalid for saiai-macos-aarch64' "${output}"
cp "${temporary}/manifest.good" "${fixtures}/manifest.json"
sed -i 's/"saiai-macos-aarch64":{"sha256":"\([0-9a-f]*\)","size":\([0-9]*\)/"saiai-macos-aarch64":{"sha256":"\1","size":"\2"/' "${fixtures}/manifest.json"
if SAIAI_TEST_PATH="${plutil_path}" run_setup "https://gateway.example.test" "TEST_ONLY_KEY"; then
  echo "plutil path accepted a string size" >&2
  exit 1
fi
grep -Fq 'manifest size is invalid for saiai-macos-aarch64' "${output}"
sed -i 's/"manifest_schema":1/"manifest_schema":"1"/' "${temporary}/manifest.good"
cp "${temporary}/manifest.good" "${fixtures}/manifest.json"
if SAIAI_TEST_PATH="${plutil_path}" run_setup "https://gateway.example.test" "TEST_ONLY_KEY"; then
  echo "plutil path accepted a string manifest schema" >&2
  exit 1
fi
grep -Fq 'unsupported SAIAI manifest schema' "${output}"
sed -i 's/"manifest_schema":"1"/"manifest_schema":1/; s/"saiai-macos-aarch64"/"saiai-macos-other"/' "${fixtures}/manifest.json"
if SAIAI_TEST_PATH="${plutil_path}" run_setup "https://gateway.example.test" "TEST_ONLY_KEY"; then
  echo "plutil path accepted a manifest without the asset" >&2
  exit 1
fi
grep -Fq 'manifest does not contain saiai-macos-aarch64' "${output}"
sed -i 's/"manifest_schema":"1"/"manifest_schema":1/' "${temporary}/manifest.good"
cp "${temporary}/manifest.good" "${fixtures}/manifest.json"
printf '{broken' >"${home}/.saiai/config.json"
if SAIAI_TEST_PATH="${plutil_path}" run_setup init-codex </dev/null; then
  echo "plutil path accepted a broken config" >&2
  exit 1
fi
grep -Fq "Could not read ${home}/.saiai/config.json." "${output}"
unset SAIAI_TEST_UNAME_S SAIAI_TEST_UNAME_M

before_invalid="$(wc -l <"${curl_log}")"
if run_setup "only-one-argument"; then
  echo "wrapper accepted a missing API key" >&2
  exit 1
fi
after_invalid="$(wc -l <"${curl_log}")"
test "${before_invalid}" -eq "${after_invalid}"
grep -Fq 'Usage:' "${output}"

for wrapper in setup.sh setup.ps1 setup.cmd; do
  test -s "${script_dir}/${wrapper}"
  grep -Fq 'https://api.saiai.top/saiai-cli' "${script_dir}/${wrapper}"
  grep -Fq 'local-proxy' "${script_dir}/${wrapper}"
  if grep -Fq 'bootstrap_schema_version' "${script_dir}/${wrapper}"; then
    echo "${wrapper} still depends on the withdrawn V2 bootstrap contract" >&2
    exit 1
  fi
done

grep -Fq 'installed_matches=1' "${script_dir}/setup.sh"
grep -Fq 'binary download skipped' "${script_dir}/setup.sh"
grep -Fq '$installedMatches' "${script_dir}/setup.ps1"
grep -Fq 'binary download skipped' "${script_dir}/setup.ps1"
grep -Fq 'INSTALLED_MATCHES=1' "${script_dir}/setup.cmd"
grep -Fq 'binary download skipped' "${script_dir}/setup.cmd"


# An interactive project setup must not silently reuse the default Key.
mkdir -p "${home}/.saiai"
printf '%s\n' '{"base_url":"https://default.example.test","api_key":"TEST_ONLY_DEFAULT_SCOPE_KEY"}' >"${home}/.saiai/config.json"
printf 'https://project.example.test\nTEST_ONLY_PROJECT_SCOPE_KEY\n' | \
  SAIAI_TEST_CODEX_HOME="${home}/project-codex" run_setup init-codex
mapfile -t project_invocation <"${invoked}"
test "${project_invocation[2]}" = "init-codex"
test "${project_invocation[3]}" = "https://project.example.test"
test "${project_invocation[4]}" = "TEST_ONLY_PROJECT_SCOPE_KEY"
if grep -Fq 'TEST_ONLY_DEFAULT_SCOPE_KEY' "${invoked}"; then
  echo "interactive project setup reused the default Key" >&2
  exit 1
fi

# Uninstall: the wrapper only selects a capable native executor.
curl_before="$(wc -l <"${curl_log}")"
export SAIAI_TEST_EXIT=3
if run_setup uninstall --yes --forget-unknown-environments; then
  echo "wrapper did not pass the uninstall exit code through" >&2
  exit 1
fi
unset SAIAI_TEST_EXIT
mapfile -t uninstall_invocation <"${invoked}"
test "${uninstall_invocation[1]}" = "CALL"
test "${uninstall_invocation[2]}" = "uninstall"
test "${uninstall_invocation[3]}" = "--yes"
test "${uninstall_invocation[4]}" = "--forget-unknown-environments"
test "${#uninstall_invocation[@]}" -eq 5
test "$(wc -l <"${curl_log}")" -eq "${curl_before}"
test -x "${install_dir}/saiai"

if run_setup uninstall --force; then
  echo "wrapper accepted an unknown uninstall option" >&2
  exit 1
fi
test ! -e "${invoked}"
grep -Fq 'uninstall [--yes] [--dry-run] [--forget-unknown-environments]' "${output}"

# An installed client that does not know a requested option is not chosen.
printf '#!/usr/bin/env bash\nfor a in "$@"; do [ "$a" = --forget-unknown-environments ] && exit 1; done\nprintf "SAIAI uninstall plan\\n"\n' >"${install_dir}/saiai"
chmod +x "${install_dir}/saiai"
curl_before="$(wc -l <"${curl_log}")"
run_setup uninstall --yes --forget-unknown-environments
mapfile -t option_invocation <"${invoked}"
test "${option_invocation[2]}" = "uninstall"
test "${option_invocation[4]}" = "--forget-unknown-environments"
test "$(wc -l <"${curl_log}")" -eq "$((curl_before + 2))"

# An installed client without uninstall support: use a verified temporary copy.
curl_before="$(wc -l <"${curl_log}")"
printf '#!/usr/bin/env bash\necho "Unknown command: $1" >&2\nexit 1\n' >"${install_dir}/saiai"
cp "${install_dir}/saiai" "${temporary}/old-client"
run_setup uninstall --dry-run
mapfile -t temporary_invocation <"${invoked}"
test "${temporary_invocation[2]}" = "uninstall"
test "${temporary_invocation[3]}" = "--dry-run"
test "$(wc -l <"${curl_log}")" -eq "$((curl_before + 2))"
cmp -s "${install_dir}/saiai" "${temporary}/old-client"

export SAIAI_TEST_CURL_FAIL=1
if run_setup uninstall --yes; then
  echo "wrapper reported success without an uninstall executor" >&2
  exit 1
fi
unset SAIAI_TEST_CURL_FAIL
test ! -e "${invoked}"
grep -Fq 'Could not download a SAIAI client that supports uninstall' "${output}"
cmp -s "${install_dir}/saiai" "${temporary}/old-client"

echo "SAIAI local-proxy wrapper checks passed"
