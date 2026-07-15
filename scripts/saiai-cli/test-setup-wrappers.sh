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
mkdir -p "${fixtures}" "${fake_bin}" "${home}" "${install_dir}"

asset="${fixtures}/saiai-linux-x86_64"
cat >"${asset}" <<'SH'
#!/usr/bin/env bash
: >"${SAIAI_TEST_BINARY_INVOKED:?}"
SH
chmod +x "${asset}"
sha256="$(sha256sum "${asset}" | awk '{print $1}')"
size="$(wc -c <"${asset}" | tr -d '[:space:]')"
version="$(awk -F '"' '/^[[:space:]]*version[[:space:]]*=/{print $2; exit}' "${script_dir}/../../tools/saiai-cli/Cargo.toml")"
printf '{"manifest_schema":1,"bootstrap_schema_version":2,"version":"%s","assets":{"saiai-linux-x86_64":{"sha256":"%s","size":%s}}}\n' \
  "${version}" "${sha256}" "${size}" >"${fixtures}/manifest.json"

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
case "${url}" in
  */manifest.json) cp "${SAIAI_TEST_FIXTURES:?}/manifest.json" "${destination}" ;;
  */saiai-linux-x86_64) cp "${SAIAI_TEST_FIXTURES:?}/saiai-linux-x86_64" "${destination}" ;;
  *) echo "unexpected wrapper URL: ${url}" >&2; exit 1 ;;
esac
SH
chmod +x "${fake_bin}/curl"

run_install() {
  rm -f "${output}" "${invoked}"
  HOME="${home}" \
    PATH="${fake_bin}:${PATH}" \
    SAIAI_DOWNLOAD_BASE="https://download.example.test/client" \
    SAIAI_INSTALL_DIR="${install_dir}" \
    SAIAI_TEST_FIXTURES="${fixtures}" \
    SAIAI_TEST_BINARY_INVOKED="${invoked}" \
    bash "${script_dir}/setup.sh" "$@" >"${output}" 2>&1
}

previous="${temporary}/previous-saiai"
printf 'previous preview client\n' >"${previous}"
cp "${previous}" "${install_dir}/saiai"
chmod +x "${install_dir}/saiai"

run_install install
test -x "${install_dir}/saiai"
cmp -s "${asset}" "${install_dir}/saiai"
cmp -s "${previous}" "${install_dir}/saiai-previous"
test ! -e "${invoked}"
grep -Fq "Next: ${install_dir}/saiai claude or ${install_dir}/saiai codex" "${output}"

run_install
test -x "${install_dir}/saiai"
test ! -e "${invoked}"

if run_install "https://gateway.example.test" "not-a-key"; then
  echo "install-only wrapper accepted legacy initialization arguments" >&2
  exit 1
fi
grep -Fq "Usage: setup.sh [install]" "${output}"
test ! -e "${invoked}"

for wrapper in setup.sh setup.ps1 setup.cmd; do
  test -s "${script_dir}/${wrapper}"
  if grep -Eiq 'init-codex|legacy-doctor|saiai start|ANTHROPIC_AUTH_TOKEN' "${script_dir}/${wrapper}"; then
    echo "${wrapper} contains a legacy initialization path" >&2
    exit 1
  fi
done

grep -Fq 'Invoke-Saiai [install]' "${script_dir}/setup.ps1"
grep -Fq 'saiai-windows-x86_64.exe' "${script_dir}/setup.ps1"
grep -Fq 'saiai-windows-aarch64.exe' "${script_dir}/setup.ps1"
grep -Fq 'saiai-previous.exe' "${script_dir}/setup.ps1"
grep -Fq 'Usage: setup.cmd [install]' "${script_dir}/setup.cmd"
grep -Fq 'saiai-windows-x86_64.exe' "${script_dir}/setup.cmd"
grep -Fq 'saiai-windows-aarch64.exe' "${script_dir}/setup.cmd"
grep -Fq 'saiai-previous.exe' "${script_dir}/setup.cmd"

echo "SAIAI V2 install-only wrapper checks passed"
