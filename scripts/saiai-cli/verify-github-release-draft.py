#!/usr/bin/env python3
"""Verify every GitHub draft-release asset before immutable publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


BINARIES = (
    "saiai-linux-x86_64",
    "saiai-linux-aarch64",
    "saiai-macos-x86_64",
    "saiai-macos-aarch64",
    "saiai-windows-x86_64.exe",
    "saiai-windows-aarch64.exe",
)
WRAPPERS = ("setup.sh", "setup.ps1", "setup.cmd")
EXPECTED_FILES = frozenset((*BINARIES, *WRAPPERS, "manifest.json"))
MAX_RESPONSE_BYTES = 2_000_000


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_release() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_RESPONSE_BYTES + 1)
    require(len(raw) <= MAX_RESPONSE_BYTES, "release response exceeds 2 MB")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("release response is not valid JSON") from error
    require(isinstance(value, dict), "release response root is not an object")
    return value


def verify_local_dist(dist: Path) -> dict[str, Path]:
    require(dist.is_dir(), "release distribution directory is missing")
    files = {path.name: path for path in dist.iterdir() if path.is_file()}
    require(set(files) == EXPECTED_FILES, "local release file set is not exact")
    for name, path in files.items():
        require(path.stat().st_size > 0, f"local release file is empty: {name}")
    return files


def verify_release(
    release: dict[str, Any], files: dict[str, Path], expected_tag: str
) -> None:
    require(release.get("draft") is True, "release is not a draft")
    require(release.get("prerelease") is True, "release is not a prerelease")
    if "immutable" in release:
        require(release["immutable"] is False, "draft is already immutable")
    require(release.get("tag_name") == expected_tag, "release tag differs")

    assets = release.get("assets")
    require(isinstance(assets, list), "release assets are not a list")
    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        require(isinstance(asset, dict), "release asset is not an object")
        name = asset.get("name")
        require(isinstance(name, str) and name, "release asset name is invalid")
        require(name not in by_name, "release contains a duplicate asset name")
        by_name[name] = asset
    require(set(by_name) == EXPECTED_FILES, "remote release asset set is not exact")

    for name, path in files.items():
        asset = by_name[name]
        require(asset.get("state") == "uploaded", f"release asset is not uploaded: {name}")
        require(asset.get("size") == path.stat().st_size, f"release asset size differs: {name}")
        require(
            asset.get("digest") == f"sha256:{sha256(path)}",
            f"release asset digest differs: {name}",
        )


def main() -> int:
    args = arguments()
    try:
        files = verify_local_dist(args.dist)
        verify_release(load_release(), files, args.tag)
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"PASS: verified {len(files)} draft assets for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
