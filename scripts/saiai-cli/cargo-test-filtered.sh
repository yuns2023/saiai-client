#!/usr/bin/env bash
# Runs one package's tests whose names match a filter and fails unless at
# least one test actually ran (a filter that matches nothing passes
# vacuously under plain `cargo test`).
#
# usage: cargo-test-filtered.sh <package> <filter> [-- <test binary args>]
set -euo pipefail
package="$1"
filter="$2"
shift 2
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
cargo test --locked --manifest-path "$repo_root/tools/saiai-cli/Cargo.toml" \
  -p "$package" "$filter" "$@" 2>&1 | tee "$log"
ran="$(grep -Eo '^test result: ok\. [0-9]+ passed' "$log" | awk '{sum += $4} END {print sum + 0}')"
if [ "$ran" -eq 0 ]; then
  echo "no test of $package matched $filter" >&2
  exit 1
fi
echo "$ran test(s) of $package matched $filter"
