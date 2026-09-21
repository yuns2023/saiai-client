#!/usr/bin/env bash
# Build native static Linux assets with AWS-LC's getrandom/urandom backend.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target="${1:?usage: build-linux.sh <native-linux-musl-target>}"
case "$(uname -m):$target" in
  x86_64:x86_64-unknown-linux-musl|aarch64:aarch64-unknown-linux-musl) ;;
  *) echo "ERROR: expected a native x86_64 or aarch64 Linux musl target" >&2; exit 1 ;;
esac

# musl-tools alone does not expose Linux UAPI headers. Without linux/random.h,
# AWS-LC selects getentropy(), whose musl implementation has no ENOSYS fallback.
# Expose only kernel headers, never the host glibc include directory.
uapi_dir="$(mktemp -d /tmp/saiai-linux-uapi.XXXXXX)"
trap 'rm -rf "$uapi_dir"' EXIT
multiarch="$(gcc -print-multiarch)"
for name in linux asm-generic; do
  test -d "/usr/include/$name"
  ln -s "/usr/include/$name" "$uapi_dir/$name"
done
test -d "/usr/include/$multiarch/asm"
ln -s "/usr/include/$multiarch/asm" "$uapi_dir/asm"

target_suffix="${target//-/_}"
cc_variable="CC_$target_suffix"
cflags_variable="CFLAGS_$target_suffix"
export "$cc_variable=${!cc_variable:-${CC:-musl-gcc}}"
export "$cflags_variable=${!cflags_variable:-${CFLAGS:-}} -isystem $uapi_dir"

# Fail before building if the headers cannot be used with this musl toolchain.
printf '#include <linux/random.h>\n#include <stdlib.h>\nint main(void) { return RNDGETENTCNT == 0; }\n' |
  "${!cc_variable}" -isystem "$uapi_dir" -Werror -x c -c -o "$uapi_dir/probe.o" -

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
cargo build --locked --manifest-path "$repo_root/tools/saiai-cli/Cargo.toml" \
  --release --target "$target"
