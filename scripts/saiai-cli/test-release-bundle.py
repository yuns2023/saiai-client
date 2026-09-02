#!/usr/bin/env python3
"""Smoke-test a packaged SAIAI managed-local-proxy binary and Unix wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path


ASSETS = (
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
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--setup-sh", type=Path)
    parser.add_argument("--asset", choices=ASSETS)
    return parser.parse_args()


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def native_asset() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    architecture = "x86_64" if machine in {"x86_64", "amd64"} else "aarch64"
    if machine not in {"x86_64", "amd64", "aarch64", "arm64"}:
        raise AssertionError(f"unsupported native test architecture: {machine}")
    if system == "Linux":
        return f"saiai-linux-{architecture}"
    if system == "Darwin":
        return f"saiai-macos-{architecture}"
    raise AssertionError(f"unsupported native test system: {system}")


def run_checked(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, env=environment, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {command[0]}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def verify_manifest(bundle: Path, selected_asset: str) -> dict[str, object]:
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("manifest_schema") != 1:
        raise AssertionError("release manifest schema differs")
    if manifest.get("client_mode") != "local-proxy":
        raise AssertionError("release is not a local-proxy client")
    if manifest.get("configuration_schema_version") != 1:
        raise AssertionError("configuration schema differs")
    if "bootstrap_schema_version" in manifest:
        raise AssertionError("release still claims V2 bootstrap compatibility")
    entry = manifest.get("assets", {}).get(selected_asset)
    if not isinstance(entry, dict):
        raise AssertionError(f"manifest omits {selected_asset}")
    binary = bundle / selected_asset
    if entry.get("sha256") != digest(binary) or entry.get("size") != binary.stat().st_size:
        raise AssertionError(f"manifest metadata differs for {selected_asset}")
    wrappers = manifest.get("wrappers")
    if isinstance(wrappers, dict):
        for name in WRAPPERS:
            wrapper = bundle / name
            metadata = wrappers.get(name)
            if not isinstance(metadata, dict):
                raise AssertionError(f"manifest omits wrapper {name}")
            if metadata.get("sha256") != digest(wrapper) or metadata.get("size") != wrapper.stat().st_size:
                raise AssertionError(f"manifest metadata differs for {name}")
    return manifest


def main() -> int:
    args = arguments()
    bundle = args.bundle.resolve()
    selected_asset = args.asset or native_asset()
    setup_sh = (args.setup_sh or bundle / "setup.sh").resolve()
    verify_manifest(bundle, selected_asset)
    binary = bundle / selected_asset
    binary.chmod(binary.stat().st_mode | 0o111)

    with tempfile.TemporaryDirectory(prefix="saiai-config-bundle-") as temporary_text:
        temporary = Path(temporary_text)
        home = temporary / "home"
        install = temporary / "install"
        claude_dir = home / ".claude"
        home.mkdir()
        install.mkdir()
        claude_dir.mkdir()
        (claude_dir / "settings.json").write_text(
            json.dumps(
                {
                    "permissions": {"allow": ["Read"]},
                    "env": {
                        "KEEP_ME": "yes",
                        "ANTHROPIC_AUTH_TOKEN": "old",
                        "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR": "9",
                        "CLAUDE_CODE_CLIENT_CERT": "/tmp/old-client.crt",
                        "VERTEX_REGION_CLAUDE_4_6_SONNET": "old-region",
                        "http_proxy": "http://127.0.0.1:19908",
                        "NODE_EXTRA_CA_CERTS": str(claude_dir / "saiai-ca.crt"),
                    },
                }
            ),
            encoding="utf-8",
        )
        (home / ".claude.json").write_text(
            json.dumps({"oauthAccount": {"email": "old"}, "userID": "kept"}),
            encoding="utf-8",
        )
        (claude_dir / ".credentials.json").write_text('{"oauth":"old"}', encoding="utf-8")
        (claude_dir / "saiai-ca.crt").write_text("old ca", encoding="utf-8")

        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "SAIAI_DOWNLOAD_BASE": bundle.as_uri(),
                "SAIAI_INSTALL_DIR": str(install),
                "SAIAI_SKIP_START": "1",
            }
        )
        first_key = "TEST_ONLY_BUNDLE_KEY"
        first = run_checked(
            ["bash", str(setup_sh), "https://gateway.example.test", first_key],
            environment,
        )
        if first_key in first.stdout or first_key in first.stderr:
            raise AssertionError("wrapper or CLI printed the API key")
        installed = install / "saiai"
        if installed.read_bytes() != binary.read_bytes():
            raise AssertionError("wrapper did not install the selected binary exactly")

        settings = json.loads((claude_dir / "settings.json").read_text(encoding="utf-8"))
        settings_env = settings["env"]
        if settings_env.get("CLAUDE_CODE_OAUTH_TOKEN") != first_key:
            raise AssertionError("Claude OAuth token was not configured")
        if "ANTHROPIC_BASE_URL" in settings_env:
            raise AssertionError("direct Claude gateway override remains")
        if settings_env.get("CLAUDE_STREAM_IDLE_TIMEOUT_MS") != "600000":
            raise AssertionError("Claude stream timeout differs")
        for removed in (
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
            "CLAUDE_CODE_CLIENT_CERT",
            "VERTEX_REGION_CLAUDE_4_6_SONNET",
        ):
            if removed in settings_env:
                raise AssertionError(f"conflicting environment value remains: {removed}")
        if settings_env.get("KEEP_ME") != "yes" or settings["permissions"]["allow"] != ["Read"]:
            raise AssertionError("unrelated Claude settings were not preserved")
        expected_proxy = "http://127.0.0.1:19908"
        for proxy_key in ("http_proxy", "https_proxy", "all_proxy"):
            if settings_env.get(proxy_key) != expected_proxy:
                raise AssertionError(f"local proxy setting differs: {proxy_key}")
        ca_path = claude_dir / "saiai-ca.crt"
        ca_key_path = claude_dir / "saiai-ca.key"
        if settings_env.get("NODE_EXTRA_CA_CERTS") != str(ca_path):
            raise AssertionError("Claude CA path was not configured")
        if not ca_path.is_file() or not ca_key_path.is_file():
            raise AssertionError("per-user CA pair was not generated")
        first_ca = ca_path.read_bytes()
        first_ca_key = ca_key_path.read_bytes()
        state = json.loads((home / ".claude.json").read_text(encoding="utf-8"))
        if "oauthAccount" in state or state.get("userID") != "kept":
            raise AssertionError("Claude state cleanup did not preserve machine identity")
        if (claude_dir / ".credentials.json").exists():
            raise AssertionError("stale OAuth credentials remain")
        saiai_config = json.loads((home / ".saiai" / "config.json").read_text(encoding="utf-8"))
        if saiai_config.get("version") != 2 or saiai_config.get("api_key") != first_key:
            raise AssertionError("local proxy config was not written")

        second_key = "TEST_ONLY_REPLACEMENT_KEY"
        second = run_checked(
            ["bash", str(setup_sh), "https://new-gateway.example.test", second_key],
            environment,
        )
        if "binary download skipped" not in second.stderr:
            raise AssertionError("same release did not take the no-download path")
        settings = json.loads((claude_dir / "settings.json").read_text(encoding="utf-8"))
        if settings["env"].get("CLAUDE_CODE_OAUTH_TOKEN") != second_key:
            raise AssertionError("repeat setup did not replace the API key")
        saiai_config = json.loads((home / ".saiai" / "config.json").read_text(encoding="utf-8"))
        if saiai_config.get("base_url") != "https://new-gateway.example.test":
            raise AssertionError("repeat setup did not replace the gateway")
        if ca_path.read_bytes() != first_ca or ca_key_path.read_bytes() != first_ca_key:
            raise AssertionError("repeat setup unnecessarily rotated the installation CA")

        help_output = run_checked([str(installed), "--help"], environment)
        if "saiai start" not in help_output.stdout or second_key in help_output.stdout:
            raise AssertionError("local-proxy commands are missing or the API key leaked")

    print("SAIAI local-proxy release bundle smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
