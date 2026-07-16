#!/usr/bin/env python3
"""Generate the deterministic SAIAI managed-local-proxy client manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path


MANIFEST_SCHEMA = 1
CLIENT_MODE = "local-proxy"
CONFIGURATION_SCHEMA_VERSION = 1
DEFAULT_ASSETS = (
    "saiai-linux-x86_64",
    "saiai-linux-aarch64",
    "saiai-macos-x86_64",
    "saiai-macos-aarch64",
    "saiai-windows-x86_64.exe",
    "saiai-windows-aarch64.exe",
)
WRAPPERS = ("setup.sh", "setup.ps1", "setup.cmd")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    version = parser.add_mutually_exclusive_group(required=True)
    version.add_argument("--version")
    version.add_argument("--cargo-toml", type=Path)
    parser.add_argument("--asset", action="append", dest="assets")
    parser.add_argument(
        "--wrappers-dir",
        type=Path,
        help="Hash the three canonical wrappers from this directory",
    )
    return parser.parse_args()


def cargo_version(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    try:
        import tomllib

        value = tomllib.loads(text).get("package", {}).get("version")
        if isinstance(value, str) and value.strip():
            return value.strip()
    except (ImportError, ValueError):
        pass
    package = re.search(r"(?ms)^\[package\]\s*$\n(.*?)(?=^\[|\Z)", text)
    match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', package.group(1) if package else "")
    if match is None:
        raise ValueError(f"could not read package.version from {path}")
    return match.group(1)


def metadata(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"required release file is missing: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    size = os.path.getsize(path)
    if size <= 0:
        raise ValueError(f"release file is empty: {path}")
    return {"sha256": digest.hexdigest(), "size": size}


def build_manifest(
    dist: Path,
    version: str,
    assets: tuple[str, ...],
    wrappers_dir: Path | None,
) -> dict[str, object]:
    if not version or version.strip() != version:
        raise ValueError("client version is empty or contains surrounding whitespace")
    if len(set(assets)) != len(assets):
        raise ValueError("release asset list contains duplicates")
    result: dict[str, object] = {
        "manifest_schema": MANIFEST_SCHEMA,
        "client_mode": CLIENT_MODE,
        "configuration_schema_version": CONFIGURATION_SCHEMA_VERSION,
        "version": version,
        "assets": {name: metadata(dist / name) for name in assets},
    }
    if wrappers_dir is not None:
        result["wrappers"] = {name: metadata(wrappers_dir / name) for name in WRAPPERS}
    return result


def main() -> int:
    args = arguments()
    version = args.version.strip() if args.version else cargo_version(args.cargo_toml)
    manifest = build_manifest(
        args.dist,
        version,
        tuple(args.assets or DEFAULT_ASSETS),
        args.wrappers_dir,
    )
    rendered = json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
