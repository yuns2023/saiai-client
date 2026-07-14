#!/usr/bin/env python3
"""Smoke-test a packaged SAIAI V2 binary and the install-only Unix wrapper."""

from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import json
import os
import platform
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path


ALL_ASSETS = {
    "saiai-linux-x86_64",
    "saiai-linux-aarch64",
    "saiai-macos-x86_64",
    "saiai-macos-aarch64",
    "saiai-windows-x86_64.exe",
    "saiai-windows-aarch64.exe",
}
WRAPPERS = ("setup.sh", "setup.ps1", "setup.cmd")


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--setup-sh", required=True, type=Path)
    parser.add_argument("--asset")
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def native_asset() -> str:
    systems = {"Linux": "linux", "Darwin": "macos"}
    machines = {
        "x86_64": "x86_64",
        "AMD64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }
    try:
        return f"saiai-{systems[platform.system()]}-{machines[platform.machine()]}"
    except KeyError as error:
        raise AssertionError(
            f"unsupported native release-smoke platform: {platform.system()} {platform.machine()}"
        ) from error


def assert_metadata(path: Path, metadata: object, label: str) -> None:
    if not isinstance(metadata, dict):
        raise AssertionError(f"manifest has no metadata for {label}")
    if metadata.get("sha256") != sha256(path):
        raise AssertionError(f"manifest hash differs for {label}")
    if metadata.get("size") != path.stat().st_size:
        raise AssertionError(f"manifest size differs for {label}")


def run_checked(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def main() -> int:
    args = parse_args()
    bundle = args.bundle.resolve()
    setup_sh = args.setup_sh.resolve()
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_schema") != 1:
        raise AssertionError("release manifest schema is not 1")
    if manifest.get("bootstrap_schema_version") != 2:
        raise AssertionError("release manifest does not require bootstrap schema 2")
    version = manifest.get("version")
    if not isinstance(version, str) or not version:
        raise AssertionError("release manifest has no client version")
    assets = manifest.get("assets")
    if not isinstance(assets, dict):
        raise AssertionError("release manifest has no assets object")

    asset = args.asset or native_asset()
    if asset not in ALL_ASSETS:
        raise AssertionError(f"unknown release asset: {asset}")
    if args.asset is None and set(assets) != ALL_ASSETS:
        raise AssertionError("assembled release manifest does not contain exactly six assets")
    binary = bundle / asset
    assert_metadata(binary, assets.get(asset), asset)

    wrappers = manifest.get("wrappers")
    if wrappers is not None:
        if set(wrappers) != set(WRAPPERS):
            raise AssertionError("manifest wrapper set is not canonical")
        for name in WRAPPERS:
            wrapper = bundle / name
            if not wrapper.is_file() and setup_sh.parent / name == setup_sh:
                wrapper = setup_sh
            assert_metadata(wrapper, wrappers.get(name), name)

    handler = functools.partial(QuietHandler, directory=str(bundle))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="saiai-v2-bundle-") as temporary_text:
            temporary = Path(temporary_text)
            home = temporary / "home"
            install = temporary / "install"
            xdg_config = temporary / "xdg-config"
            xdg_data = temporary / "xdg-data"
            xdg_state = temporary / "xdg-state"
            home.mkdir()
            install.mkdir()

            sentinels = {
                home / ".saiai" / "sentinel": b"legacy-saiai\n",
                home / ".claude" / "sentinel": b"legacy-claude\n",
                home / ".codex" / "sentinel": b"legacy-codex\n",
            }
            for path, contents in sentinels.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "XDG_CONFIG_HOME": str(xdg_config),
                    "XDG_DATA_HOME": str(xdg_data),
                    "XDG_STATE_HOME": str(xdg_state),
                    "SAIAI_INSTALL_DIR": str(install),
                    "SAIAI_DOWNLOAD_BASE": f"http://127.0.0.1:{server.server_port}",
                }
            )
            installed = install / "saiai"
            wrapper = run_checked(["bash", str(setup_sh), "install"], environment)
            expected_next = f"Next: {installed} claude or {installed} codex"
            if expected_next not in wrapper.stdout + wrapper.stderr:
                raise AssertionError("install-only wrapper omitted V2 next-step guidance")
            if not installed.is_file() or installed.read_bytes() != binary.read_bytes():
                raise AssertionError("install-only wrapper did not install the selected binary exactly")

            reported = run_checked([str(installed), "--version"], environment)
            if f"saiai {version}" not in reported.stdout + reported.stderr:
                raise AssertionError("packaged binary version differs from manifest version")
            help_result = run_checked([str(installed), "--help"], environment)
            help_text = help_result.stdout + help_result.stderr
            for command in (
                "saiai setup [claude|codex]",
                "saiai claude",
                "saiai codex",
                "saiai revoke --all",
                "saiai doctor",
            ):
                if command not in help_text:
                    raise AssertionError(f"packaged V2 help omitted: {command}")

            unexpected_v2_roots = (
                xdg_config / "saiai",
                xdg_data / "saiai",
                xdg_state / "saiai",
                home / "Library" / "Application Support" / "SAIAI",
            )
            if any(path.exists() for path in unexpected_v2_roots):
                raise AssertionError("install/help/version initialized V2 state")
            for path, contents in sentinels.items():
                if path.read_bytes() != contents:
                    raise AssertionError("install/help/version changed legacy client state")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
