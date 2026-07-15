#!/usr/bin/env python3
"""Compile-free verification for the standalone public SAIAI V2 client repo."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / "scripts" / "saiai-cli"
CORE_DIR = ROOT / "tools" / "saiai-core"
CLI_DIR = ROOT / "tools" / "saiai-cli"
DESKTOP_DIR = ROOT / "tools" / "saiai-desktop"
CONTRACT_PATH = ROOT / "contracts" / "bootstrap-v2.json"
CLI_VERSION = "0.9.2"
DESKTOP_VERSION = "0.9.0-preview.1"
ASSETS = (
    "saiai-linux-x86_64",
    "saiai-linux-aarch64",
    "saiai-macos-x86_64",
    "saiai-macos-aarch64",
    "saiai-windows-x86_64.exe",
    "saiai-windows-aarch64.exe",
)
WRAPPERS = ("setup.sh", "setup.ps1", "setup.cmd")


def require(condition: object, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def package_version(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    package = re.search(r"(?ms)^\[package\]\s*$\n(.*?)(?=^\[|\Z)", text)
    require(package is not None, f"{path} has no package table")
    version = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', package.group(1))
    require(version is not None and version.group(1), f"{path} has no package version")
    return version.group(1)


def locked_version(path: Path, package_name: str) -> str:
    blocks = re.split(r"(?m)^\[\[package\]\]\s*$", path.read_text(encoding="utf-8"))[1:]
    matches: list[str] = []
    for block in blocks:
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
        if name is not None and name.group(1) == package_name and version is not None:
            matches.append(version.group(1))
    require(len(matches) == 1, f"{path} must lock {package_name} once")
    return matches[0]


def verify_contract() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    require(contract.get("contract") == "top.saiai.client.bootstrap", "bootstrap contract id differs")
    require(contract.get("contract_version") == 1, "bootstrap contract version differs")
    require(contract.get("bootstrap_schema_version") == 2, "bootstrap schema is not 2")
    request = contract.get("request")
    require(isinstance(request, dict), "bootstrap contract request is missing")
    require(request.get("method") == "GET", "bootstrap method is not GET")
    require(request.get("path_suffix") == "/api/v1/client/bootstrap", "bootstrap path differs")
    require(request.get("redirects_allowed") is False, "bootstrap contract permits redirects")
    require(request.get("billable") is False, "bootstrap contract is not explicitly non-billable")
    authentication = request.get("authentication")
    require(
        authentication == {"scheme": "Bearer", "required": True},
        "bootstrap bearer authentication contract differs",
    )

    response = contract.get("response")
    require(isinstance(response, dict), "bootstrap response contract is missing")
    require(response.get("success_status") == 200, "bootstrap success status differs")
    require(response.get("maximum_body_bytes") == 1024 * 1024, "bootstrap size limit differs")
    envelope = response.get("envelope")
    require(isinstance(envelope, dict), "bootstrap envelope contract is missing")
    require(envelope.get("code") == {"type": "integer", "const": 0}, "bootstrap success code differs")
    data = envelope.get("data")
    require(isinstance(data, dict), "bootstrap data contract is missing")
    require(data.get("schema_version") == {"type": "integer", "const": 2}, "data schema differs")
    gateway_version = data.get("gateway_version")
    require(isinstance(gateway_version, dict), "gateway_version contract is missing")
    require(gateway_version.get("maximum_utf8_bytes") == 128, "gateway_version limit differs")
    capabilities = data.get("capabilities")
    require(isinstance(capabilities, dict), "capability contract is missing")
    fields = capabilities.get("fields")
    expected_fields = {
        "claude": "boolean",
        "codex": "boolean",
        "codex_responses": "boolean",
        "codex_websockets": "boolean",
        "openai_messages_dispatch": "boolean",
    }
    require(fields == expected_fields, "bootstrap capability field set differs")
    requirements = contract.get("product_requirements")
    require(
        requirements == {"claude": ["claude"], "codex": ["codex", "codex_responses"]},
        "per-product capability requirements differ",
    )
    dispatch = contract.get("semantics", {}).get("openai_messages_dispatch")
    require(
        isinstance(dispatch, str) and "never satisfies native Claude" in dispatch,
        "Messages Dispatch semantics could satisfy V2 Claude",
    )


def verify_rust_contract() -> None:
    toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    require('channel = "1.97.0"' in toolchain, "Rust toolchain is not pinned")
    require(package_version(CLI_DIR / "Cargo.toml") == CLI_VERSION, "CLI version differs")
    require(locked_version(CLI_DIR / "Cargo.lock", "saiai") == CLI_VERSION, "CLI lock version differs")
    require((CORE_DIR / "Cargo.lock").is_file(), "saiai-core lockfile is missing")
    cli_manifest = (CLI_DIR / "Cargo.toml").read_text(encoding="utf-8")
    require('rust-version = "1.97"' in cli_manifest, "CLI minimum Rust version differs")
    require(
        re.search(
            r'(?m)^saiai-core\s*=\s*\{[^\n}]*path\s*=\s*"\.\./saiai-core"[^\n}]*\}',
            cli_manifest,
        )
        is not None,
        "CLI does not use the local shared saiai-core",
    )

    main = (CLI_DIR / "src" / "main.rs").read_text(encoding="utf-8")
    for required in (
        "saiai setup [claude|codex]",
        "saiai claude",
        "saiai claude revoke",
        "saiai codex",
        "saiai codex revoke",
        "saiai revoke --all",
        "saiai doctor",
        "saiai ui",
        "API keys are never accepted on the command line",
    ):
        require(required in main, f"V2-only CLI contract is missing: {required}")
    for forbidden in (
        '"init" =>',
        '"init-codex" =>',
        '"start" =>',
        '"stop" =>',
        '"restart" =>',
        '"update" =>',
        '"legacy-doctor" =>',
    ):
        require(forbidden not in main, f"CLI still parses a legacy command: {forbidden}")
    require(not (CLI_DIR / "src" / "local_proxy.rs").exists(), "legacy local_proxy.rs is present")
    require(not (CLI_DIR / "assets" / "saiai-ca.key").exists(), "legacy shared CA key is present")

    provision = (CORE_DIR / "src" / "provision.rs").read_text(encoding="utf-8")
    for required in (
        "pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 2;",
        'const BOOTSTRAP_PATH: &str = "/api/v1/client/bootstrap";',
        "const MAX_BOOTSTRAP_RESPONSE_BYTES: usize = 1024 * 1024;",
        "const MAX_GATEWAY_VERSION_BYTES: usize = 128;",
        "pub openai_messages_dispatch: bool",
        "Product::Claude if !capabilities.claude",
        "Product::Codex if !capabilities.codex",
        "Product::Codex if !capabilities.codex_responses",
    ):
        require(required in provision, f"Rust bootstrap implementation differs from public contract: {required}")
    config = (CORE_DIR / "src" / "config.rs").read_text(encoding="utf-8")
    require("pub const CONFIG_SCHEMA_VERSION: u32 = 2;" in config, "local config schema is not 2")


def verify_desktop_contract() -> None:
    package = json.loads((DESKTOP_DIR / "package.json").read_text(encoding="utf-8"))
    tauri = json.loads((DESKTOP_DIR / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    versions = {
        package.get("version"),
        package_version(DESKTOP_DIR / "src-tauri" / "Cargo.toml"),
        locked_version(DESKTOP_DIR / "src-tauri" / "Cargo.lock", "saiai-desktop"),
        tauri.get("version"),
    }
    require(versions == {DESKTOP_VERSION}, f"desktop versions differ: {versions}")
    require(tauri.get("identifier") == "top.saiai.desktop", "desktop identifier differs")
    bundle = tauri.get("bundle")
    require(isinstance(bundle, dict) and bundle.get("active") is True, "desktop bundling is disabled")
    require(bundle.get("createUpdaterArtifacts") is False, "unsigned updater artifacts are enabled")
    icons = bundle.get("icon")
    require(isinstance(icons, list) and icons, "desktop bundle icon set is missing")
    for icon in icons:
        require(
            isinstance(icon, str) and (DESKTOP_DIR / "src-tauri" / icon).is_file(),
            f"desktop bundle icon is missing: {icon}",
        )
    capability = json.loads(
        (DESKTOP_DIR / "src-tauri" / "capabilities" / "main-ui.json").read_text(encoding="utf-8")
    )
    require(capability.get("permissions") == [], "desktop WebView has plugin permissions")


def load_generator():
    path = SCRIPT_DIR / "generate-manifest.py"
    spec = importlib.util.spec_from_file_location("saiai_manifest", path)
    require(spec is not None and spec.loader is not None, "manifest generator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_manifest_and_wrappers() -> None:
    generator = load_generator()
    require(tuple(generator.DEFAULT_ASSETS) == ASSETS, "manifest asset contract differs")
    require(tuple(generator.WRAPPERS) == WRAPPERS, "manifest wrapper contract differs")
    require(generator.MANIFEST_SCHEMA == 1, "manifest schema differs")
    require(generator.BOOTSTRAP_SCHEMA_VERSION == 2, "manifest bootstrap schema differs")

    for name in WRAPPERS:
        text = (SCRIPT_DIR / name).read_text(encoding="utf-8")
        for forbidden in ("init-codex", "legacy-doctor", "saiai start", "ANTHROPIC_AUTH_TOKEN"):
            require(forbidden not in text, f"{name} contains legacy initialization: {forbidden}")
        require("setup claude" in text and "setup codex" in text, f"{name} omits V2 setup guidance")
        require("saiai-previous" in text, f"{name} does not preserve one previous Preview binary")
    shell = (SCRIPT_DIR / "setup.sh").read_text(encoding="utf-8")
    for token in ('platform="linux"', 'platform="macos"', 'architecture="x86_64"', 'architecture="aarch64"'):
        require(token in shell, f"Unix wrapper mapping is missing: {token}")
    for name in ("setup.ps1", "setup.cmd"):
        text = (SCRIPT_DIR / name).read_text(encoding="utf-8")
        require("saiai-windows-x86_64.exe" in text, f"{name} omits Windows x86_64")
        require("saiai-windows-aarch64.exe" in text, f"{name} omits Windows ARM64")

    with tempfile.TemporaryDirectory(prefix="saiai-public-contract-") as temporary_text:
        temporary = Path(temporary_text)
        dist = temporary / "dist"
        dist.mkdir()
        expected: dict[str, str] = {}
        for index, name in enumerate(ASSETS):
            content = f"public release fixture {index}: {name}\n".encode()
            (dist / name).write_bytes(content)
            expected[name] = hashlib.sha256(content).hexdigest()
        output = temporary / "manifest.json"
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "generate-manifest.py"),
                "--dist",
                str(dist),
                "--version",
                CLI_VERSION,
                "--wrappers-dir",
                str(SCRIPT_DIR),
                "--output",
                str(output),
            ],
            check=True,
        )
        manifest = json.loads(output.read_text(encoding="utf-8"))
        require(manifest.get("manifest_schema") == 1, "generated manifest schema differs")
        require(manifest.get("bootstrap_schema_version") == 2, "generated bootstrap schema differs")
        require(manifest.get("version") == CLI_VERSION, "generated CLI version differs")
        require(set(manifest.get("assets", {})) == set(ASSETS), "generated asset set differs")
        for name, digest in expected.items():
            require(manifest["assets"][name]["sha256"] == digest, f"generated hash differs: {name}")
        require(set(manifest.get("wrappers", {})) == set(WRAPPERS), "generated wrapper set differs")


def verify_workflows_are_public_only() -> None:
    workflows = {
        name: (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        for name in ("ci.yml", "saiai-cli-release.yml", "saiai-desktop-preview.yml")
    }
    combined = "\n".join(workflows.values())
    require(combined.count("toolchain: '1.97.0'") == 9, "workflow Rust toolchains are not pinned")
    for forbidden in (
        "back" + "end/",
        "front" + "end/",
        "AG" + "ENTS.md",
        "re" + "search/",
        "pi" + "proxy",
        ".github" + "_pat",
        "self" + "-hosted",
    ):
        require(forbidden not in combined, f"public workflow depends on private monorepo state: {forbidden}")
    for name, workflow in workflows.items():
        require("permissions:\n  contents: read" in workflow, f"{name} default permissions are not read-only")
        require("timeout-minutes:" in workflow, f"{name} has no bounded job timeout")
        require("concurrency:" in workflow, f"{name} has no concurrency policy")
        for action, reference in re.findall(r"(?m)^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)", workflow):
            require(
                re.fullmatch(r"[0-9a-f]{40}", reference) is not None,
                f"{name} does not pin {action} to a full commit SHA",
            )

    ci = workflows["ci.yml"]
    require("pull_request:" in ci and "branches: [main]" in ci, "public CI is not enabled for PR/main")
    for runner in ("ubuntu-22.04", "windows-latest"):
        require(runner in ci, f"public CI omits standard runner: {runner}")

    cargo_config = (ROOT / ".cargo" / "config.toml").read_text(encoding="utf-8")
    for target in ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"):
        require(
            f"[target.{target}]" in cargo_config,
            f"Cargo linker configuration omits static Linux target: {target}",
        )
    require(
        cargo_config.count('linker = "cc"') == 2,
        "Rust musl linkers must use native cc with the bundled self-contained CRT",
    )
    require(
        'linker = "musl-gcc"' not in cargo_config,
        "musl-gcc as the Rust linker can produce a dynamically loaded musl binary",
    )

    for workflow_name in ("ci.yml", "saiai-cli-release.yml"):
        workflow = workflows[workflow_name]
        for target in ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"):
            require(target in workflow, f"{workflow_name} omits static Linux target: {target}")
        for forbidden_target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            require(
                forbidden_target not in workflow,
                f"{workflow_name} still builds host-glibc target: {forbidden_target}",
            )
        require(
            "verify-linux-portability.py" in workflow,
            f"{workflow_name} does not enforce Linux release portability",
        )

    subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "test-linux-portability.py")],
        check=True,
    )
    subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "test-github-release-draft.py")],
        check=True,
    )

    cli = workflows["saiai-cli-release.yml"]
    require("saiai-v*" in cli, "CLI tag trigger is missing")
    require("workflow_dispatch:" in cli, "CLI manual Preview trigger is missing")
    require("Package validation bundle" in cli, "CLI validation bundle job is missing")
    require("contents: write" in cli, "CLI tag job cannot publish")
    require("prerelease: true" in cli, "CLI tagged build is not a Preview prerelease")
    require("draft: true" in cli, "immutable CLI release is not uploaded as a draft")
    require(
        "verify-github-release-draft.py" in cli,
        "immutable CLI draft assets are not verified before publication",
    )
    require(
        "--local-only" in cli and "already_published=true" in cli,
        "immutable CLI release preconditions or rerun state are not verified",
    )
    require(
        cli.count("--state published") == 2,
        "immutable CLI release is not verified before rerun and after publication",
    )
    require(
        'gh api --method PATCH "$release_endpoint" --input -' in cli
        and 'payload=\'{"draft":false,"prerelease":true}\'' in cli,
        "immutable CLI release is not published by verified release ID",
    )
    require(
        'gh api --method DELETE "$release_endpoint"' in cli,
        "invalid reusable CLI draft has no safe cleanup path",
    )
    require(
        cli.count("verify-linux-portability.py") == 3,
        "CLI release does not verify each Linux build and both assembled bundles",
    )
    for asset in ASSETS:
        require(f"asset: {asset}" in cli, f"CLI matrix omits {asset}")
    for wrapper in WRAPPERS:
        require(wrapper in cli, f"CLI bundle does not publish {wrapper}")
    require("files: dist/*" not in cli, "CLI release uploads an unbounded file glob")
    for release_file in (*ASSETS, *WRAPPERS, "manifest.json"):
        require(
            f"            dist/{release_file}" in cli,
            f"CLI immutable draft upload omits exact file: {release_file}",
        )
    require(
        "test-v2-windows-runtime.ps1" in cli,
        "CLI release does not run the native Windows V2 runtime smoke",
    )

    desktop = workflows["saiai-desktop-preview.yml"]
    require("saiai-desktop-v*" in desktop, "desktop tag trigger is missing")
    require("workflow_dispatch:" in desktop, "desktop manual Preview trigger is missing")
    require("codex/saiai-v2-preview" not in desktop, "desktop still depends on a private branch name")
    require("prerelease: true" in desktop, "desktop tagged build is not a prerelease")
    require("uploadUpdaterJson: false" in desktop, "desktop updater JSON is enabled")


def verify_no_private_tree_references() -> None:
    roots = (SCRIPT_DIR, ROOT / ".github" / "workflows", ROOT / "contracts")
    allowed_suffixes = {".py", ".sh", ".ps1", ".cmd", ".yml", ".yaml", ".json"}
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in allowed_suffixes:
                continue
            if path.resolve() == Path(__file__).resolve():
                continue
            text = path.read_text(encoding="utf-8")
            for forbidden in (
                "/work" + "space/",
                "/home/" + "admin/",
                ".github" + "_pat",
                "front" + "end/public",
                "front" + "end/src",
                "back" + "end/internal",
                "re" + "search/",
            ):
                require(forbidden not in text, f"{path} contains private path reference: {forbidden}")


def main() -> int:
    verify_contract()
    verify_rust_contract()
    verify_desktop_contract()
    verify_manifest_and_wrappers()
    verify_workflows_are_public_only()
    verify_no_private_tree_references()
    print("Standalone SAIAI V2 public release contract verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Standalone SAIAI V2 public release contract failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
