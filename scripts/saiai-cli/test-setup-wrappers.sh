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
printf '%s\n' "$@" >"${SAIAI_TEST_BINARY_INVOKED:?}"
SH
chmod +x "${asset}"
sha256="$(sha256sum "${asset}" | awk '{print $1}')"
size="$(wc -c <"${asset}" | tr -d '[:space:]')"
printf '{"client_mode":"global-config","configuration_schema_version":1,"manifest_schema":1,"version":"1.0.0","assets":{"saiai-linux-x86_64":{"sha256":"%s","size":%s}}}\n' \
  "${sha256}" "${size}" >"${fixtures}/manifest.json"

cat >"${fake_bin}/uname" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
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
case "${url}" in
  */manifest.json) cp "${SAIAI_TEST_FIXTURES:?}/manifest.json" "${destination}" ;;
  */saiai-linux-x86_64) cp "${SAIAI_TEST_FIXTURES:?}/saiai-linux-x86_64" "${destination}" ;;
  *) echo "unexpected wrapper URL: ${url}" >&2; exit 1 ;;
esac
SH
chmod +x "${fake_bin}/curl"

run_setup() {
  rm -f "${output}" "${invoked}"
  HOME="${home}" \
    PATH="${fake_bin}:${PATH}" \
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
test "${first_invocation[0]}" = "https://gateway.example.test"
test "${first_invocation[1]}" = "${first_key}"
test "$(grep -Fc '/manifest.json' "${curl_log}")" -eq 1
test "$(grep -Fc '/saiai-linux-x86_64' "${curl_log}")" -eq 1
if grep -Fq "${first_key}" "${output}"; then
  echo "wrapper printed the API key" >&2
  exit 1
fi

second_key="TEST_ONLY_REPLACEMENT_KEY"
run_setup "https://new-gateway.example.test" "${second_key}"
mapfile -t second_invocation <"${invoked}"
test "${second_invocation[0]}" = "https://new-gateway.example.test"
test "${second_invocation[1]}" = "${second_key}"
test "$(grep -Fc '/manifest.json' "${curl_log}")" -eq 2
test "$(grep -Fc '/saiai-linux-x86_64' "${curl_log}")" -eq 1
grep -Fq 'binary download skipped' "${output}"

run_setup init-codex "https://gateway.example.test/v1" "TEST_ONLY_CODEX_KEY" --websockets
mapfile -t codex_invocation <"${invoked}"
test "${codex_invocation[0]}" = "init-codex"
test "${codex_invocation[1]}" = "https://gateway.example.test/v1"
test "${codex_invocation[2]}" = "TEST_ONLY_CODEX_KEY"
test "${codex_invocation[3]}" = "--websockets"
test "$(grep -Fc '/manifest.json' "${curl_log}")" -eq 3
test "$(grep -Fc '/saiai-linux-x86_64' "${curl_log}")" -eq 1

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
  grep -Fq 'global-config' "${script_dir}/${wrapper}"
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

echo "SAIAI global-config wrapper checks passed"
