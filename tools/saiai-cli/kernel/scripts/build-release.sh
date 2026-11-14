#!/usr/bin/env bash
# Builds the release `aitp` program with the build machine's directories
# remapped to neutral prefixes, so the program carries no local path:
#
#   HOME         -> /aitp/home
#   RUSTUP_HOME  -> /aitp/rustup
#   CARGO_HOME   -> /aitp/cargo  (crate sources in panic locations)
#   workspace    -> /aitp/src    (the Cargo workspace holding this kernel)
#   target dir   -> /aitp/target (build script outputs, generated sources)
#
# Rust code is remapped with `--remap-path-prefix`, C code built by
# dependencies (ring, aws-lc) with `-ffile-prefix-map` (GCC 8+, Clang 10+).
#
# Usage: build-release.sh [cargo build arguments, e.g. --locked --target T]
# It refuses to build while the brand's update signing keys are the
# placeholders (see below).
# The target directory is CARGO_TARGET_DIR or <workspace>/target; set
# CARGO_TARGET_DIR instead of passing --target-dir. The build always names
# its one target explicitly (so a `build.target` in a configuration file
# cannot change it), and the program is written to
# <target dir>/<triple>/release/aitp; that path is the script's only output
# on stdout.
#
# The flags are passed through CARGO_ENCODED_RUSTFLAGS, which takes the place
# of rustflags from Cargo configuration files; RUSTFLAGS or
# CARGO_ENCODED_RUSTFLAGS already in the environment are kept. C flags are
# added to CFLAGS and CXXFLAGS and to every target- or host-specific C flag
# variable that is set (the cc crate uses the most specific one); a variable
# whose name holds a dash cannot be extended from the shell, so the script
# refuses to run while one is set. (AWS-LC maps its own sources already;
# the C flags cover the remaining C code and generated headers.)
set -euo pipefail

fail() {
  echo "build-release.sh: $*" >&2
  exit 1
}

# Only Linux GNU targets are verified: CARGO_ENCODED_RUSTFLAGS replaces the
# rustflags of Cargo configuration files (the repository sets
# `link-arg=/Brepro` for Windows MSVC), and other platforms embed paths
# differently. The target comes from --target, else CARGO_BUILD_TARGET, else
# the host; it is then passed to Cargo explicitly.
targets=()
cargo_arguments=()
previous=""
for argument in "$@"; do
  if [[ "$previous" == "--target" ]]; then
    targets+=("$argument")
  else
    case "$argument" in
      --target-dir | --target-dir=*) fail "set CARGO_TARGET_DIR instead of $argument" ;;
      --target=*) targets+=("${argument#--target=}") ;;
      --target) ;;
      *) cargo_arguments+=("$argument") ;;
    esac
  fi
  previous="$argument"
done
[[ "$previous" == "--target" ]] && fail "--target needs a value"
if [[ ${#targets[@]} -eq 0 ]]; then
  if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    targets=("$CARGO_BUILD_TARGET")
  else
    host="$(rustc -vV | sed -n 's/^host: //p')"
    [[ -n "$host" ]] || fail "cannot read the host target from rustc -vV"
    targets=("$host")
  fi
fi
[[ ${#targets[@]} -eq 1 ]] || fail "build one target at a time, not ${targets[*]}"
triple="${targets[0]}"
case "$triple" in
  *-linux-gnu | *-linux-gnu?*) ;;
  *) fail "only Linux GNU targets are verified for the remapped release build, not $triple" ;;
esac
if env | grep -E '^(C|CXX)FLAGS_[^=]*-' >/dev/null; then
  fail "C flag variables named with a dash cannot be extended; use the underscore form"
fi

kernel="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$kernel/Cargo.toml"

# A published program must trust the maintainer's real update signing keys,
# never the placeholders the brand carries until they are filled in. Builds
# that are only checked and never published (CI) may set
# AITP_ALLOW_PLACEHOLDER_SIGNING_KEY=1.
if [[ "${AITP_ALLOW_PLACEHOLDER_SIGNING_KEY:-}" != "1" ]]; then
  python3 "$kernel/scripts/release_manifest.py" keys --require-real >&2 ||
    fail "the update signing keys are placeholders (AITP_ALLOW_PLACEHOLDER_SIGNING_KEY=1 only for builds that are never published)"
fi
workspace_manifest="$(cargo locate-project --workspace --manifest-path "$manifest" --message-format plain)"
workspace="$(dirname "$workspace_manifest")"

target_dir="${CARGO_TARGET_DIR:-$workspace/target}"
mkdir -p "$target_dir"
target_dir="$(cd "$target_dir" && pwd)"
export CARGO_TARGET_DIR="$target_dir"

home="${HOME:-}"
cargo_home="${CARGO_HOME:-${home:+$home/.cargo}}"
rustup_home="${RUSTUP_HOME:-${home:+$home/.rustup}}"

# "from<TAB>to" lines; each directory also by its physical path when that
# differs (a symbolic link in the path).
mappings=""
add_mapping() {
  local from="$1" to="$2" physical
  [[ -n "$from" && "$from" != "/" ]] || return 0
  [[ "$from" == /* ]] || fail "not an absolute path: $from"
  [[ "$from" =~ [[:space:]=] ]] && fail "paths with whitespace or '=' cannot be remapped: $from"
  from="${from%/}"
  mappings+="$from"$'\t'"$to"$'\n'
  if [[ -d "$from" ]]; then
    physical="$(cd "$from" && pwd -P)"
    if [[ "$physical" != "$from" ]]; then
      [[ "$physical" =~ [[:space:]=] ]] && fail "paths with whitespace or '=' cannot be remapped: $physical"
      mappings+="$physical"$'\t'"$to"$'\n'
    fi
  fi
}
add_mapping "$home" /aitp/home
add_mapping "$rustup_home" /aitp/rustup
add_mapping "$cargo_home" /aitp/cargo
add_mapping "$workspace" /aitp/src
add_mapping "$target_dir" /aitp/target

# The compilers apply the last matching mapping: the longest (most specific)
# prefix goes last, so a directory inside another maps to its own prefix.
# (Generated first, so a failure stops the script under set -e/pipefail.)
ordered="$(printf '%s' "$mappings" | awk -F '\t' 'NF == 2 { print length($1) "\t" $0 }' | sort -n -k1,1)"
rust_flags=()
c_flags=""
while IFS=$'\t' read -r _ from to; do
  [[ -n "$from" ]] || continue
  rust_flags+=("--remap-path-prefix=$from=$to")
  c_flags+=" -ffile-prefix-map=$from=$to"
done <<<"$ordered"
[[ ${#rust_flags[@]} -gt 0 ]] || fail "no directory to remap"

separator=$'\x1f'
encoded="${CARGO_ENCODED_RUSTFLAGS:-}"
if [[ -z "$encoded" && -n "${RUSTFLAGS:-}" ]]; then
  read -r -d "" -a existing <<<"$RUSTFLAGS" || true
  encoded="$(IFS="$separator"; printf '%s' "${existing[*]}")"
fi
for flag in "${rust_flags[@]}"; do
  encoded="${encoded:+$encoded$separator}$flag"
done
export CARGO_ENCODED_RUSTFLAGS="$encoded"
unset RUSTFLAGS
export CFLAGS="${CFLAGS:-}$c_flags"
export CXXFLAGS="${CXXFLAGS:-}$c_flags"
while IFS= read -r name; do
  export "$name=${!name}$c_flags"
done < <(compgen -e | grep -E '^((C|CXX)FLAGS_[A-Za-z0-9_]+|(TARGET|HOST)_(C|CXX)FLAGS)$' || true)

# Cargo reports on stderr; stdout carries only the program's path.
cargo build --manifest-path "$manifest" --release --bin aitp --target "$triple" \
  ${cargo_arguments[@]+"${cargo_arguments[@]}"} >&2
program="$target_dir/$triple/release/aitp"
[[ -f "$program" ]] || fail "cargo did not write $program"
printf '%s\n' "$program"
