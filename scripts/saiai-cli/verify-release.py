#!/usr/bin/env python3
"""Compile-free checks for the SAIAI managed-local-proxy release contract."""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
from pathlib import Path


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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def load_generator():
    path = SCRIPT_DIR / "generate-manifest.py"
    spec = importlib.util.spec_from_file_location("saiai_manifest", path)
    require(spec is not None and spec.loader is not None, "cannot load manifest generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_cli() -> None:
    cargo = text("tools/saiai-cli/Cargo.toml")
    require('version = "1.1.5"' in cargo, "CLI version is not 1.1.5")
    require("saiai-core" not in cargo, "local-proxy client still links the V2 runtime core")
    for dependency in ("reqwest", "tokio", "rustls", "rcgen", "zeroize", "libc"):
        require(dependency in cargo, f"local-proxy dependency is missing: {dependency}")

    main = text("tools/saiai-cli/src/main.rs")
    for required in (
        "saiai start",
        "saiai stop",
        "saiai status",
        "saiai logs",
        "saiai update",
        "saiai restart",
        "saiai doctor",
        "saiai init <base_url> <api_key>",
        "saiai init-codex <base_url> <api_key>",
        '"CLAUDE_CODE_OAUTH_TOKEN"',
        '"CLAUDE_STREAM_IDLE_TIMEOUT_MS"',
        'const CLAUDE_STREAM_IDLE_TIMEOUT_MS: &str = "600000"',
        '"SAIAI_HOME"',
        'settings.remove("oauthAccount")',
        'state.remove("oauthAccount")',
        "remove_if_exists_with_backup(credentials_path",
        "generate_installation_ca",
        "SAIAI_CA_KEY_FILENAME",
        "is_managed_claude_env",
        '"VERTEX_REGION_CLAUDE_"',
        '"CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"',
        '"CLAUDE_CODE_CLIENT_CERT"',
        '"http_proxy"',
        '"NODE_EXTRA_CA_CERTS"',
        "create_new(true)",
        "MOVEFILE_REPLACE_EXISTING",
        "file.sync_all()",
        "SAIAI_LINUX_BACKGROUND_COMMAND",
        "start_linux_background_proxy",
        "start_time_ticks",
        "apply_systemd_user_environment",
        "SAIAI_WINDOWS_BACKGROUND_COMMAND",
        "run_windows_background_proxy_worker",
    ):
        require(required in main, f"CLI contract is missing {required!r}")
    for withdrawn in (
        "mod v2",
        "mod claude_proxy",
        "saiai setup [claude|codex]",
        "saiai claude [--",
        "saiai revoke --all",
        "client/bootstrap",
        "run_claude",
        "include_str!(\"../../piproxy/internal/certs/assets/piproxy-ca.key\")",
    ):
        require(withdrawn not in main, f"CLI still exposes withdrawn V2 behavior: {withdrawn}")
    require(not (ROOT / "tools/saiai-cli/src/v2.rs").exists(), "V2 CLI module still exists")
    proxy = text("tools/saiai-cli/src/local_proxy.rs")
    require("ca_key_pem" in proxy, "local proxy does not require runtime CA material")
    require("piproxy-ca.key" not in proxy, "local proxy still embeds the historical shared CA key")
    windows_runtime = text("scripts/saiai-cli/test-windows-runtime.ps1")
    for required in (
        "TEST_ONLY_WINDOWS_REPLACEMENT_KEY",
        "Repeated setup did not replace the API key",
        "Repeated setup replaced a valid CA key",
        "service active: yes",
    ):
        require(required in windows_runtime, f"Windows repeat smoke is missing {required!r}")


def verify_manifest_and_wrappers() -> None:
    generator = load_generator()
    require(generator.MANIFEST_SCHEMA == 1, "manifest schema differs")
    require(generator.CLIENT_MODE == "local-proxy", "manifest client mode differs")
    require(generator.CONFIGURATION_SCHEMA_VERSION == 1, "configuration schema differs")
    require(tuple(generator.DEFAULT_ASSETS) == ASSETS, "fixed release asset names differ")

    with tempfile.TemporaryDirectory(prefix="saiai-manifest-") as temporary:
        root = Path(temporary)
        for name in ASSETS:
            (root / name).write_bytes((name + "\n").encode())
        wrappers = root / "wrappers"
        wrappers.mkdir()
        for name in WRAPPERS:
            (wrappers / name).write_bytes((name + "\n").encode())
        manifest = generator.build_manifest(root, "1.1.5", ASSETS, wrappers)
        require(manifest.get("manifest_schema") == 1, "generated manifest schema differs")
        require(manifest.get("client_mode") == "local-proxy", "generated client mode differs")
        require(
            manifest.get("configuration_schema_version") == 1,
            "generated configuration schema differs",
        )
        require("bootstrap_schema_version" not in manifest, "manifest still claims V2 bootstrap")

    for name in WRAPPERS:
        wrapper = (SCRIPT_DIR / name).read_text(encoding="utf-8")
        for required in (
            "https://api.saiai.top/saiai-cli",
            "local-proxy",
            "configuration_schema_version",
            "binary download skipped",
        ):
            require(required in wrapper, f"{name} is missing {required!r}")
        require("bootstrap_schema_version" not in wrapper, f"{name} still requires V2 bootstrap")
    shell = (SCRIPT_DIR / "setup.sh").read_text(encoding="utf-8")
    require('"${install_path}" init "$@"' in shell, "Unix wrapper does not initialize Claude")
    require('"${install_path}" start' in shell, "Unix wrapper does not start the local proxy")
    require("installed_matches=1" in shell, "Unix wrapper cannot skip the binary download")
    powershell = (SCRIPT_DIR / "setup.ps1").read_text(encoding="utf-8")
    require(
        "Stop-SaiaiForReplacement" in powershell,
        "PowerShell wrapper cannot stop an in-use client before replacement",
    )
    require(
        "Move-SaiaiCandidate" in powershell,
        "PowerShell wrapper does not retry Windows binary replacement",
    )
    require(
        "Start-SaiaiBackground" in powershell and "start | Out-Host" not in powershell,
        "PowerShell wrapper still starts the background proxy through an output pipeline",
    )
    windows_release = text("scripts/saiai-cli/test-windows-release.ps1")
    require(
        "Running-client upgrade did not install the release binary" in windows_release,
        "Windows release smoke does not cover a running-client upgrade",
    )


def verify_workflows_and_docs() -> None:
    release = text(".github/workflows/saiai-cli-release.yml")
    ci = text(".github/workflows/ci.yml")
    for asset in ASSETS:
        require(asset in release, f"release workflow omits {asset}")
    for required in (
        "verify-release.py",
        "test-release-bundle.py",
        "test-linux-service.py",
        "prerelease: false",
        'name: SAIAI CLI ${{ github.ref_name }}',
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
    ):
        require(required in release, f"release workflow is missing {required!r}")
    require(
        "test-linux-service.py" in ci,
        "CI workflow does not exercise the Linux headless service fallback",
    )
    linux_service = text("scripts/saiai-cli/test-linux-service.py")
    for required in (
        "test-forced headless mode",
        '"start"',
        '"status"',
        '"logs"',
        '"restart"',
        '"stop"',
        "start_time_ticks",
    ):
        require(required in linux_service, f"Linux service smoke is missing {required!r}")
    for withdrawn in ("test-v2-", "V2 Preview", "saiai-core/Cargo.toml"):
        require(withdrawn not in release, f"release workflow still contains {withdrawn!r}")
        require(withdrawn not in ci, f"CI workflow still contains {withdrawn!r}")
    require(not (ROOT / ".github/workflows/saiai-desktop-preview.yml").exists(), "V2 desktop publisher still exists")

    combined_docs = "\n".join(
        text(path) for path in ("README.md", "docs/CLIENT_DESIGN.md", "docs/WINDOWS.md")
    )
    for required in (
        "local-proxy",
        "saiai start",
        "SAIAI_HOME",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_STREAM_IDLE_TIMEOUT_MS=600000",
        "二进制下载",
    ):
        require(required in combined_docs, f"public docs are missing {required!r}")
    for path in ("README.md", "docs/CLIENT_DESIGN.md", "docs/WINDOWS.md"):
        require("SAIAI_HOME" in text(path), f"{path} does not document SAIAI_HOME")
    require("SAIAI V2 Preview" not in combined_docs, "public docs still advertise V2 Preview")


def verify_no_non_test_credentials() -> None:
    key_pattern = re.compile(r"(?i)(?:sk|key)[-_][A-Za-z0-9_-]{16,}")
    roots = (
        ROOT / "tools" / "saiai-cli",
        ROOT / "scripts" / "saiai-cli",
        ROOT / ".github" / "workflows",
        ROOT / "docs",
        ROOT / "README.md",
    )
    for source in roots:
        paths = (source,) if source.is_file() else source.rglob("*")
        for path in paths:
            if not path.is_file() or "target" in path.parts:
                continue
            if path.suffix.lower() not in {".rs", ".py", ".sh", ".ps1", ".cmd", ".md", ".yml", ".yaml"}:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
            for match in key_pattern.findall(content):
                require(
                    "TEST" in match.upper() or "YOUR" in match.upper(),
                    f"possible credential in {path}",
                )


def main() -> int:
    verify_cli()
    verify_manifest_and_wrappers()
    verify_workflows_and_docs()
    verify_no_non_test_credentials()
    print("SAIAI local-proxy public release contract verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"SAIAI local-proxy release contract failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
