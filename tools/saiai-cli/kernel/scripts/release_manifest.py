#!/usr/bin/env python3
"""AITP release manifest: generate it unsigned, check its offline signature.

The maintainer signs the manifest offline with minisign (0.10 or later) in
its legacy Ed25519 format, the only one the program accepts:

  minisign -S -l -s aitp-release.key -p aitp-release.pub -m aitp-manifest.json \
      -x aitp-manifest.json.minisig -t "aitp-manifest X.Y.Z sha256:<manifest sha256>"

(`generate` prints this command with the values filled in; the recovery key
signs the same way with aitp-recovery.key / aitp-recovery.pub.)

  release_manifest.py generate --dist DIR [--version X.Y.Z] [--output FILE]
      Writes aitp-manifest.json (canonical JSON) for the release assets in DIR
      and prints the exact signing command.

  release_manifest.py verify --manifest FILE [--signature FILE] --dist DIR
                             [--artifact PROGRAM ...]
      Before upload: the signature verifies with a key the AITP program
      trusts (never a placeholder), the manifest names this distribution,
      the package version and exactly the release assets in DIR with their
      size and SHA-256, and each of those assets (and every --artifact)
      carries the trusted keys and no placeholder.

  release_manifest.py keys [--require-real]
      Lists the trusted keys of the AITP brand; with --require-real, exits
      with status 3 while a placeholder (or unusable) key is in place.

Ed25519 verification below is a plain implementation of RFC 8032
(section 5.1.7, cofactorless) with the libsodium checks minisign relies on:
canonical encodings, S < L, and no small-order key or R. It only verifies;
it never sees a private key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path

KERNEL = Path(__file__).resolve().parent.parent
BRAND_SOURCE = KERNEL / "src" / "bin" / "aitp" / "brand.rs"
CARGO_TOML = KERNEL / "Cargo.toml"

MANIFEST_NAME = "aitp-manifest.json"
SIGNATURE_SUFFIX = ".minisig"
SIGNATURE_LIMIT = 4096
MANIFEST_LIMIT = 1024 * 1024
MANIFEST_SCHEMA = 1
ASSET_MIN = 1024 * 1024
ASSET_MAX = 64 * 1024 * 1024
ASSETS = (
    "aitp-linux-x86_64",
    "aitp-linux-aarch64",
    "aitp-macos-x86_64",
    "aitp-macos-aarch64",
    "aitp-windows-x86_64.exe",
    "aitp-windows-aarch64.exe",
)

# The placeholder keys the brand carries until the maintainer's real keys
# are filled in. They are well-formed minisign key lines whose key bytes are
# not a curve point, so nothing verifies with them; release checks refuse
# them by this exact list.
PLACEHOLDER_KEYS = (
    "RWQAITPxPRIMARYxPLACEHOLDERxKEYxNOTxFORxRELEASE222222222",
    "RWQAITPxRECOVERYxPLACEHOLDERxKEYxNOTxFORxRELEASEXXXXXXXX",
)


# Exit status of `keys --require-real` when a key is a placeholder (or not
# usable); other failures exit 1.
PLACEHOLDER_EXIT = 3


class CheckError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckError(message)


# --- Ed25519 (RFC 8032) -----------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    a_ = (y1 - x1) * (y2 - x2) % P
    b_ = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b_ - a_, d - c, d + c, b_ + a_
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar: int, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(a, b) -> bool:
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def decode_point(data: bytes):
    """A canonically encoded curve point, or None."""
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


_IDENTITY = (0, 1, 1, 0)
_BASE = (lambda y: (_recover_x(y, 0), y, 1, _recover_x(y, 0) * y % P))(4 * pow(5, P - 2, P) % P)


def is_small_order(point) -> bool:
    return _equal(_mul(8, point), _IDENTITY)


def usable_public_key(key: bytes) -> bool:
    point = decode_point(key)
    return point is not None and not is_small_order(point)


def ed25519_verify(key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    a = decode_point(key)
    r = decode_point(signature[:32])
    if a is None or r is None or is_small_order(a) or is_small_order(r):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + key + message).digest(), "little") % L
    return _equal(_mul(s, _BASE), _add(r, _mul(h, a)))


# --- minisign ---------------------------------------------------------------


def decode_exact(text: bytes, length: int, what: str) -> bytes:
    """Strict standard base64 of exactly `length` bytes."""
    require(re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", text) is not None, f"{what} is not canonical base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError as error:
        raise CheckError(f"{what} is not canonical base64") from error
    require(base64.b64encode(raw) == text, f"{what} is not canonical base64")
    require(len(raw) == length, f"{what} has {len(raw)} bytes, not {length}")
    return raw


def key_id_text(key_id: bytes) -> str:
    # As minisign prints it: upper-case hexadecimal without leading zeros.
    return f"{int.from_bytes(key_id, 'little'):X}"


def parse_public_key(text: str) -> tuple[bytes, bytes]:
    """(key id, Ed25519 key) of a minisign public key line."""
    raw = decode_exact(text.encode(), 42, "the signing key")
    require(raw[:2] == b"Ed", "the signing key is not a minisign Ed25519 key")
    return raw[2:10], raw[10:]


def parse_signature_file(data: bytes) -> dict:
    require(len(data) <= SIGNATURE_LIMIT, f"the signature file is larger than {SIGNATURE_LIMIT} bytes")
    require(b"\0" not in data, "the signature file contains a NUL byte")
    # Each LF may be preceded by one CR, which belongs to the line break.
    body = data
    if body.endswith(b"\n"):
        body = body[:-1]
        if body.endswith(b"\r"):
            body = body[:-1]
    lines = body.split(b"\n")
    lines = [line[:-1] if line.endswith(b"\r") else line for line in lines[:-1]] + lines[-1:]
    require(not any(b"\r" in line for line in lines), "the signature file has a line break that is not LF or CRLF")
    require(
        not any((byte < 0x20 and byte != 0x09) or byte == 0x7F for line in lines for byte in line),
        "the signature file contains a control character",
    )
    require(len(lines) == 4, f"the signature file has {len(lines)} lines, a minisign signature has 4")
    untrusted, envelope, trusted, global_line = lines
    require(untrusted.startswith(b"untrusted comment: "), "the signature file does not start with an untrusted comment line")
    envelope = decode_exact(envelope, 74, "the signature line")
    require(trusted.startswith(b"trusted comment: "), "the signature file has no trusted comment line")
    return {
        "algorithm": envelope[:2],
        "key_id": envelope[2:10],
        "signature": envelope[10:],
        "trusted_comment": trusted[len(b"trusted comment: "):],
        "global_signature": decode_exact(global_line, 64, "the trusted comment signature"),
    }


def verify_signature(manifest: bytes, signature_file: bytes, trusted: list[str]) -> str:
    """The id of the trusted key that signed `manifest`; raises otherwise."""
    keys = {}
    for text in trusted:
        key_id, key = parse_public_key(text)
        require(key_id not in keys, f"signing key {key_id_text(key_id)} is listed twice")
        keys[key_id] = key
    parsed = parse_signature_file(signature_file)
    require(
        parsed["algorithm"] != b"ED",
        "the manifest is signed in minisign's prehashed format; sign with `minisign -S -l`",
    )
    require(parsed["algorithm"] == b"Ed", "the signature does not use minisign's Ed25519 format")
    key = keys.get(parsed["key_id"])
    require(
        key is not None,
        f"the manifest is signed by key {key_id_text(parsed['key_id'])}, which is not trusted "
        f"(trusted: {', '.join(key_id_text(key_id) for key_id in keys)})",
    )
    require(
        ed25519_verify(key, manifest, parsed["signature"]),
        f"the manifest signature does not verify with key {key_id_text(parsed['key_id'])}",
    )
    require(
        ed25519_verify(key, parsed["signature"] + parsed["trusted_comment"], parsed["global_signature"]),
        f"the signature's trusted comment does not verify with key {key_id_text(parsed['key_id'])}",
    )
    return key_id_text(parsed["key_id"])


# --- the manifest -----------------------------------------------------------


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, f"the manifest repeats the field {name!r}")
        result[name] = value
    return result


def _is_integer(value) -> bool:
    return type(value) is int


def parse_manifest(data: bytes, distribution: str) -> dict:
    """The manifest as the client reads it, at least as strictly: the
    client checks only its own platform's asset, this checks every one."""
    require(len(data) <= MANIFEST_LIMIT, f"the manifest is larger than {MANIFEST_LIMIT} bytes")
    try:
        manifest = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CheckError(f"the manifest is not JSON: {error}") from error
    require(isinstance(manifest, dict), "the manifest is not a JSON object")
    require(
        set(manifest) == {"manifest_schema", "distribution", "version", "assets"},
        f"the manifest has fields {sorted(manifest)}",
    )
    schema = manifest["manifest_schema"]
    require(_is_integer(schema) and schema == MANIFEST_SCHEMA, f"the manifest has schema {schema!r}, not {MANIFEST_SCHEMA}")
    require(
        manifest["distribution"] == distribution,
        f"the manifest is for distribution {manifest['distribution']!r}, not {distribution!r}",
    )
    version = manifest["version"]
    require(
        isinstance(version, str) and re.fullmatch(r"(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){2}", version) is not None,
        f"the manifest names version {version!r}, not X.Y.Z",
    )
    assets = manifest["assets"]
    require(isinstance(assets, dict), "the manifest assets are not an object")
    for name, info in assets.items():
        require(isinstance(info, dict) and set(info) <= {"sha256", "size"} and "sha256" in info, f"manifest asset {name} is malformed")
        require(
            isinstance(info["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", info["sha256"]) is not None,
            f"manifest asset {name} has invalid sha256 {info['sha256']!r}",
        )
        size = info.get("size")
        require(
            _is_integer(size) and ASSET_MIN <= size <= ASSET_MAX,
            f"manifest asset {name} has no size between {ASSET_MIN} and {ASSET_MAX} bytes",
        )
    return manifest


def file_metadata(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), f"release asset is missing or not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return {"sha256": digest.hexdigest(), "size": size}


def render_manifest(distribution: str, version: str, assets: dict) -> bytes:
    manifest = {
        "assets": assets,
        "distribution": distribution,
        "manifest_schema": MANIFEST_SCHEMA,
        "version": version,
    }
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()


# --- the AITP brand ---------------------------------------------------------


def _brand_body(source: str) -> str:
    return source.split("#[cfg(test)]")[0]


def brand_distribution(source: str | None = None) -> str:
    body = _brand_body(source if source is not None else BRAND_SOURCE.read_text(encoding="utf-8"))
    found = re.findall(r'\bdistribution:\s*"([a-z0-9-]+)"', body)
    require(len(found) == 1, f"cannot read the update distribution from {BRAND_SOURCE}")
    return found[0]


def brand_keys(source: str | None = None) -> list[str]:
    """The trusted signing keys of the AITP brand source, in order: the
    string literals of `signing_keys: &[ ... ]`, with line comments between
    them skipped (base64 itself may contain `//`)."""
    body = _brand_body(source if source is not None else BRAND_SOURCE.read_text(encoding="utf-8"))
    starts = [match.end() for match in re.finditer(r"\bsigning_keys:\s*&\[", body)]
    require(len(starts) == 1, f"cannot read the update signing keys from {BRAND_SOURCE}")
    keys = []
    index = starts[0]
    while True:
        require(index < len(body), f"the update signing key list in {BRAND_SOURCE} is not closed")
        char = body[index]
        if char in " \t\r\n,":
            index += 1
        elif body.startswith("//", index):
            end = body.find("\n", index)
            index = len(body) if end < 0 else end
        elif char == '"':
            end = body.find('"', index + 1)
            require(end > index, f"unterminated string in {BRAND_SOURCE}")
            literal = body[index + 1:end]
            require("\\" not in literal, f"escaped signing key in {BRAND_SOURCE}")
            keys.append(literal)
            index = end + 1
        elif char == "]":
            break
        else:
            raise CheckError(f"unexpected {char!r} in the update signing key list of {BRAND_SOURCE}")
    require(keys, f"the update signing key list in {BRAND_SOURCE} is empty")
    for key in keys:
        parse_public_key(key)
    return keys


def require_real_keys(keys: list[str]) -> None:
    placeholders = [key for key in keys if key in PLACEHOLDER_KEYS]
    require(
        not placeholders,
        f"the AITP update signing keys are still placeholders ({len(placeholders)} of {len(keys)}); "
        "fill in the maintainer's real public keys before a release",
    )
    seen = set()
    for key in keys:
        key_id, material = parse_public_key(key)
        require(usable_public_key(material), f"signing key {key_id_text(key_id)} is not a usable Ed25519 key")
        require(material not in seen and key_id not in seen, f"signing key {key_id_text(key_id)} repeats another key or key id")
        seen.update((material, key_id))


def cargo_version() -> str:
    text = CARGO_TOML.read_text(encoding="utf-8")
    package = re.search(r"(?ms)^\[package\]\s*$\n(.*?)(?=^\[|\Z)", text)
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', package.group(1) if package else "")
    require(match is not None, f"cannot read the package version from {CARGO_TOML}")
    return match.group(1)


# File names the printed commands may carry: nothing a shell would
# interpret, so the commands read the same in a POSIX shell and PowerShell.
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def sign_command(manifest: Path, version: str, digest: str, key: str = "aitp-release") -> str:
    """The minisign command for the signing machine (POSIX shell quoting;
    with a safe manifest name only the trusted comment is quoted, in single
    quotes, which PowerShell reads the same way)."""
    require(SAFE_NAME.fullmatch(manifest.name) is not None, f"unsafe manifest file name {manifest.name!r}")
    return shlex.join([
        "minisign", "-S", "-l", "-s", f"{key}.key", "-p", f"{key}.pub", "-m", manifest.name,
        "-x", manifest.name + SIGNATURE_SUFFIX, "-t", f"aitp-manifest {version} sha256:{digest}",
    ])


def verify_command(manifest: Path, dist: Path) -> str:
    """The pre-upload check (POSIX shell quoting, any path)."""
    return shlex.join(["python3", str(Path(__file__)), "verify", "--manifest", str(manifest), "--dist", str(dist)])


# --- commands ---------------------------------------------------------------


def command_generate(args) -> int:
    version = args.version or cargo_version()
    distribution = brand_distribution()
    names = tuple(args.asset or ASSETS)
    require(len(set(names)) == len(names), "the asset list repeats a name")
    for name in names:
        require(re.fullmatch(r"[A-Za-z0-9._-]+", name) is not None and name not in (".", ".."), f"bad asset name {name!r}")
    assets = {name: file_metadata(args.dist / name) for name in names}
    rendered = render_manifest(distribution, version, assets)
    parse_manifest(rendered, distribution)
    output = args.output or args.dist / MANIFEST_NAME
    require(
        SAFE_NAME.fullmatch(output.name) is not None,
        f"the manifest file name {output.name!r} may only use letters, digits, '.', '_' and '-'",
    )
    output.write_bytes(rendered)
    digest = hashlib.sha256(rendered).hexdigest()
    print(f"wrote {output} ({len(rendered)} bytes, sha256 {digest})")
    print("Sign it on the offline signing machine, in the directory holding the key and the manifest")
    print("(POSIX shell or PowerShell):")
    print(f"  {sign_command(output, version, digest)}")
    print("Then copy back only the signature file; check it before upload with (POSIX shell):")
    print(f"  {verify_command(output, args.dist)}")
    return 0


def read_bounded(path: Path, limit: int, what: str) -> bytes:
    require(path.is_file(), f"{what} is missing: {path}")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    require(len(data) <= limit, f"{what} is larger than {limit} bytes: {path}")
    return data


def require_program_keys(path: Path, keys: list[str]) -> None:
    """A release program carries every trusted key and no placeholder."""
    data = path.read_bytes()
    missing = [key for key in keys if key.encode() not in data]
    require(not missing, f"{path} does not carry the trusted keys {missing}")
    found = [key for key in PLACEHOLDER_KEYS if key.encode() in data]
    require(not found, f"{path} carries placeholder signing keys")


def verify_release(manifest_path: Path, signature_path: Path, dist: Path, artifacts: list[Path] = (),
                   version: str | None = None, assets: tuple[str, ...] = ASSETS, keys: list[str] | None = None,
                   distribution: str | None = None) -> str:
    """All pre-upload checks; returns the signing key id. The release assets
    in `dist` (exactly the manifest's, by size and SHA-256) must each carry
    the trusted keys; `artifacts` are further programs checked the same way."""
    keys = brand_keys() if keys is None else keys
    distribution = brand_distribution() if distribution is None else distribution
    require_real_keys(keys)
    manifest_bytes = read_bounded(manifest_path, MANIFEST_LIMIT, "manifest")
    signature_bytes = read_bounded(signature_path, SIGNATURE_LIMIT, "signature")
    key_id = verify_signature(manifest_bytes, signature_bytes, keys)
    manifest = parse_manifest(manifest_bytes, distribution)
    expected_version = version or cargo_version()
    require(manifest["version"] == expected_version, f"the manifest names {manifest['version']}, the package is {expected_version}")
    require(
        sorted(manifest["assets"]) == sorted(assets),
        f"the manifest lists {sorted(manifest['assets'])}, the release has {sorted(assets)}",
    )
    for name in assets:
        require(file_metadata(dist / name) == manifest["assets"][name], f"{dist / name} does not match the manifest")
        require_program_keys(dist / name, keys)
    for artifact in artifacts:
        require(artifact.is_file(), f"program is missing: {artifact}")
        require_program_keys(artifact, keys)
    return key_id


def command_verify(args) -> int:
    signature = args.signature or args.manifest.with_name(args.manifest.name + SIGNATURE_SUFFIX)
    key_id = verify_release(args.manifest, signature, args.dist, args.artifact)
    print(f"{args.manifest} is signed by trusted key {key_id} and matches the release")
    return 0


def command_keys(args) -> int:
    keys = brand_keys()
    for key in keys:
        key_id, _ = parse_public_key(key)
        state = "PLACEHOLDER" if key in PLACEHOLDER_KEYS else "key"
        print(f"{key_id_text(key_id)} {state} {key}")
    if args.require_real:
        try:
            require_real_keys(keys)
        except CheckError as error:
            print(f"release_manifest.py: {error}", file=sys.stderr)
            return PLACEHOLDER_EXIT
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate")
    generate.add_argument("--dist", required=True, type=Path)
    generate.add_argument("--version")
    generate.add_argument("--asset", action="append")
    generate.add_argument("--output", type=Path)
    generate.set_defaults(run=command_generate)
    verify = commands.add_parser("verify")
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--signature", type=Path)
    verify.add_argument("--dist", required=True, type=Path)
    verify.add_argument("--artifact", action="append", default=[], type=Path)
    verify.set_defaults(run=command_verify)
    keys = commands.add_parser("keys")
    keys.add_argument("--require-real", action="store_true")
    keys.set_defaults(run=command_keys)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except CheckError as error:
        print(f"release_manifest.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
