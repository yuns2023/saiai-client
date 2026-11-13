#!/usr/bin/env python3
"""Frozen SAIAI release, installer and Desktop identity contract.

Expected values are hand-written literals describing what published clients,
installers and the update channel already depend on. They must not be read
from the scripts under test or from a future brand definition. See the
tools/saiai-cli/tests/saiai_*.rs contract tests for the client half.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / "scripts" / "saiai-cli"

ASSETS = (
    "saiai-linux-x86_64",
    "saiai-linux-aarch64",
    "saiai-macos-x86_64",
    "saiai-macos-aarch64",
    "saiai-windows-x86_64.exe",
    "saiai-windows-aarch64.exe",
)
WRAPPERS = ("setup.sh", "setup.ps1", "setup.cmd")
DOWNLOAD_BASE = "https://api.saiai.top/saiai-cli"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def cargo_version() -> str:
    package = text("tools/saiai-cli/Cargo.toml").split("\n[", 1)[0]
    match = re.search(r'(?m)^version = "([^"]+)"$', package)
    assert match, "tools/saiai-cli/Cargo.toml has no package version"
    return match.group(1)


class ManifestContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = load_module("saiai_generate_manifest", SCRIPT_DIR / "generate-manifest.py")

    def test_manifest_constants_are_frozen(self) -> None:
        self.assertEqual(self.generator.MANIFEST_SCHEMA, 1)
        self.assertEqual(self.generator.CLIENT_MODE, "local-proxy")
        self.assertEqual(self.generator.CONFIGURATION_SCHEMA_VERSION, 1)
        self.assertEqual(tuple(self.generator.DEFAULT_ASSETS), ASSETS)
        self.assertEqual(tuple(self.generator.WRAPPERS), WRAPPERS)

    def test_rendered_manifest_shape_is_frozen(self) -> None:
        with tempfile.TemporaryDirectory(prefix="saiai-brand-contract-") as temporary:
            dist = Path(temporary)
            for name in ASSETS + WRAPPERS:
                (dist / name).write_bytes(name.encode("ascii"))
            output = dist / "manifest.json"
            subprocess.run(
                [
                    sys.executable, str(SCRIPT_DIR / "generate-manifest.py"),
                    "--dist", str(dist),
                    "--cargo-toml", str(ROOT / "tools/saiai-cli/Cargo.toml"),
                    "--wrappers-dir", str(dist),
                    "--output", str(output),
                ],
                check=True,
            )
            manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(manifest),
            ["assets", "client_mode", "configuration_schema_version", "manifest_schema", "version", "wrappers"],
        )
        self.assertEqual(manifest["manifest_schema"], 1)
        self.assertEqual(manifest["client_mode"], "local-proxy")
        self.assertEqual(manifest["configuration_schema_version"], 1)
        # The update channel compares this with the client's own version.
        self.assertEqual(manifest["version"], cargo_version())
        self.assertEqual(sorted(manifest["assets"]), sorted(ASSETS))
        self.assertEqual(sorted(manifest["wrappers"]), sorted(WRAPPERS))
        for entry in list(manifest["assets"].values()) + list(manifest["wrappers"].values()):
            self.assertEqual(sorted(entry), ["sha256", "size"])

    def test_release_workflow_publishes_the_frozen_assets(self) -> None:
        workflow = text(".github/workflows/saiai-cli-release.yml")
        published = re.findall(r"(?m)^\s+asset: (\S+)$", workflow)
        self.assertEqual(sorted(published), sorted(ASSETS))


FAKE_ASSET = """#!/usr/bin/env bash
printf 'UPDATED=%s\\n' "${SAIAI_BINARY_UPDATED:-}" >>"${SAIAI_CONTRACT_LOG:?}"
printf 'ARGS=%s\\n' "$*" >>"${SAIAI_CONTRACT_LOG:?}"
"""

FAKE_UNAME = """#!/usr/bin/env bash
case "${1:-}" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 1 ;; esac
"""

FAKE_CURL = """#!/usr/bin/env bash
set -euo pipefail
destination=""; url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) destination="$2"; shift 2 ;;
    --proto) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\\n' "${url}" >>"${SAIAI_CONTRACT_URLS:?}"
case "${url}" in
  */manifest.json) cp "${SAIAI_CONTRACT_FIXTURES:?}/manifest.json" "${destination}" ;;
  */saiai-linux-x86_64) cp "${SAIAI_CONTRACT_FIXTURES:?}/saiai-linux-x86_64" "${destination}" ;;
  *) echo "unexpected URL ${url}" >&2; exit 1 ;;
esac
"""


class InstallerBehaviorTests(unittest.TestCase):
    """Runs the real setup.sh with offline curl/uname stand-ins and no
    location overrides, so the defaults themselves are exercised."""

    @unittest.skipIf(sys.platform == "win32", "setup.sh is the Linux/macOS installer")
    def test_unix_installer_defaults(self) -> None:
        with tempfile.TemporaryDirectory(prefix="saiai-brand-installer-") as temporary:
            root = Path(temporary)
            home, fixtures, fake = root / "home", root / "fixtures", root / "bin"
            for directory in (home, fixtures, fake):
                directory.mkdir()
            asset = fixtures / "saiai-linux-x86_64"
            asset.write_text(FAKE_ASSET)
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            (fixtures / "manifest.json").write_text(json.dumps({
                "manifest_schema": 1, "client_mode": "local-proxy",
                "configuration_schema_version": 1, "version": "0.0.1",
                "assets": {"saiai-linux-x86_64": {"sha256": digest, "size": asset.stat().st_size}},
            }))
            for name, body in (("curl", FAKE_CURL), ("uname", FAKE_UNAME)):
                (fake / name).write_text(body)
                (fake / name).chmod(0o755)
            log, urls = root / "invoked", root / "urls"
            environment = {
                key: value for key, value in os.environ.items()
                if not key.startswith("SAIAI_") and key not in ("CODEX_HOME", "CLAUDE_CONFIG_DIR")
            }
            environment.update({
                "HOME": str(home),
                "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}",
                "SAIAI_CONTRACT_LOG": str(log),
                "SAIAI_CONTRACT_URLS": str(urls),
                "SAIAI_CONTRACT_FIXTURES": str(fixtures),
            })
            result = subprocess.run(
                ["bash", str(SCRIPT_DIR / "setup.sh"), "https://gateway.example.test", "TEST_ONLY_INSTALLER_KEY"],
                env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                urls.read_text().splitlines(),
                [f"{DOWNLOAD_BASE}/manifest.json", f"{DOWNLOAD_BASE}/saiai-linux-x86_64"],
            )
            installed = home / ".local" / "bin" / "saiai"
            self.assertEqual(installed.read_bytes(), asset.read_bytes())
            self.assertEqual(
                log.read_text().splitlines(),
                ["UPDATED=1", "ARGS=init https://gateway.example.test TEST_ONLY_INSTALLER_KEY"],
            )


class InstallerContractTests(unittest.TestCase):
    """Source inventory, not a behavioral golden: these only prove the
    literals are still written in the installers. A comment or dead branch
    could satisfy them and an equivalent rewrite would trip them; the
    behavioral check above covers the Unix defaults, the Windows wrappers are
    exercised by the Windows CI smoke tests."""

    def test_unix_installer_locations_are_frozen(self) -> None:
        setup = text("scripts/saiai-cli/setup.sh")
        for required in (
            f'DEFAULT_DOWNLOAD_BASE="{DOWNLOAD_BASE}"',
            'DOWNLOAD_BASE="${SAIAI_DOWNLOAD_BASE:-${DEFAULT_DOWNLOAD_BASE}}"',
            'INSTALL_DIR="${SAIAI_INSTALL_DIR:-${HOME:?HOME is required}/.local/bin}"',
            'config_path="${SAIAI_HOME:-${HOME:?HOME is required}/.saiai}/config.json"',
            'SAIAI_BINARY_UPDATED="${binary_updated}"',
            "SAIAI_SKIP_START=1",
        ):
            self.assertIn(required, setup)

    def test_windows_installer_locations_are_frozen(self) -> None:
        powershell = text("scripts/saiai-cli/setup.ps1")
        for required in (
            f'return "{DOWNLOAD_BASE}"',
            "$env:SAIAI_DOWNLOAD_BASE",
            "$env:SAIAI_INSTALL_DIR",
            'Join-Path $env:LOCALAPPDATA "SAIAI\\bin"',
            'Join-Path $env:USERPROFILE "AppData\\Local\\SAIAI\\bin"',
            'Join-Path $directory "saiai.exe"',
            '-Name "SAIAI_HOME" -Default (Join-Path $env:USERPROFILE ".saiai")',
            "SAIAI_BINARY_UPDATED",
        ):
            self.assertIn(required, powershell)
        command = text("scripts/saiai-cli/setup.cmd")
        for required in (
            f'set "DOWNLOAD_BASE={DOWNLOAD_BASE}"',
            'set "INSTALL_DIR=%LOCALAPPDATA%\\SAIAI\\bin"',
            'set "INSTALL_DIR=%USERPROFILE%\\AppData\\Local\\SAIAI\\bin"',
            'set "UNINSTALL_EXE=%LOCALAPPDATA%\\SAIAI\\bin\\saiai.exe"',
        ):
            self.assertIn(required, command)


class DesktopContractTests(unittest.TestCase):
    def test_desktop_bundle_identity_is_frozen(self) -> None:
        config = json.loads(text("tools/saiai-desktop/src-tauri/tauri.conf.json"))
        self.assertEqual(config["productName"], "SAIAI")
        self.assertEqual(config["identifier"], "top.saiai.desktop")


if __name__ == "__main__":
    unittest.main(verbosity=2)
