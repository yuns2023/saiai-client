#!/usr/bin/env python3
"""Compile-free checks for the SAIAI managed-local-proxy release contract."""

from __future__ import annotations

import argparse
import importlib.util
import os
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
WITHDRAWN_V2_MARKERS = (
    "mod v2",
    "mod claude_proxy",
    "saiai setup [claude|codex]",
    "saiai revoke --all",
    "client/bootstrap",
    "run_claude",
    'include_str!("../../piproxy/internal/certs/assets/piproxy-ca.key")',
)


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


class UnreadableRustLiteral(ValueError):
    pass


def rust_trivia_end(source: str, index: int) -> int:
    """Index after the whitespace and (nested) comments starting at `index`."""
    while index < len(source):
        if source[index].isspace():
            index += 1
        elif source.startswith("//", index):
            newline = source.find("\n", index)
            index = len(source) if newline < 0 else newline
        elif source.startswith("/*", index):
            depth = 0
            while index < len(source):
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                    if depth == 0:
                        break
                else:
                    index += 1
        else:
            break
    return index


def rust_string_literal(source: str, index: int) -> tuple[int, str] | None:
    """(end, decoded text) of the Rust string literal starting at `index`;
    raises UnreadableRustLiteral for an escape Rust would not accept."""
    raw = re.match(r'[bc]?r(#*)"', source[index:])
    if raw:
        body = index + raw.end()
        terminator = '"' + raw.group(1)
        end = source.find(terminator, body)
        if end < 0:
            raise UnreadableRustLiteral("unterminated raw string")
        return end + len(terminator), source[body:end]
    plain = re.match(r'[bc]?"', source[index:])
    if not plain:
        return None
    position = index + plain.end()
    decoded = []
    simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
    while position < len(source) and source[position] != '"':
        if source[position] != "\\":
            decoded.append(source[position])
            position += 1
            continue
        escape = source[position + 1 : position + 2]
        hex_byte = re.match(r"x([0-9a-fA-F]{2})", source[position + 1 :])
        unicode = re.match(r"u\{([0-9a-fA-F_]+)\}", source[position + 1 :])
        if hex_byte:
            decoded.append(chr(int(hex_byte.group(1), 16)))
            position += 1 + hex_byte.end()
        elif unicode:
            digits = unicode.group(1).replace("_", "")
            value = int(digits, 16) if 1 <= len(digits) <= 6 else -1
            if not (0 <= value <= 0x10FFFF and not 0xD800 <= value <= 0xDFFF):
                raise UnreadableRustLiteral(f"invalid unicode escape \\u{{{unicode.group(1)}}}")
            decoded.append(chr(value))
            position += 1 + unicode.end()
        elif escape == "\n":
            position += 2
            while position < len(source) and source[position] in " \t\r\n":
                position += 1
        elif escape in simple:
            decoded.append(simple[escape])
            position += 2
        else:
            raise UnreadableRustLiteral(f"unsupported escape \\{escape}")
    if position >= len(source):
        raise UnreadableRustLiteral("unterminated string")
    return position + 1, "".join(decoded)


def rust_without_comments(source: str, blank_literals: bool = False) -> str:
    """`source` with comments replaced by a space; string and char literals
    are kept, or replaced by a space when `blank_literals`."""
    output = []
    index = 0
    while index < len(source):
        if source.startswith("//", index) or source.startswith("/*", index):
            output.append(" ")
            index = rust_trivia_end(source, index)
            continue
        previous = source[index - 1] if index else " "
        end = None
        if not (previous.isalnum() or previous == "_"):
            literal = rust_string_literal(source, index)
            char = re.match(
                r"b?'(?:\\x[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F_]+\}|\\.|[^\\'])'", source[index:]
            )
            end = literal[0] if literal else (index + char.end() if char else None)
        if end is not None:
            output.append(" " if blank_literals else source[index:end])
            index = end
            continue
        output.append(source[index])
        index += 1
    return "".join(output)


def rust_macro_invocations(source: str, names: str) -> list[tuple[str, str]]:
    """(name, arguments) of every `name!(…)`, `name![…]` or `name!{…}` call in
    code (not in comments or literals), with any path prefix and any
    whitespace or comments between the name, `!` and the delimiter."""
    name_pattern = re.compile(r"\b(" + names + r")\b")
    closers = {"(": ")", "[": "]", "{": "}"}

    def skip_literal(index: int) -> int | None:
        previous = source[index - 1] if index else " "
        if previous.isalnum() or previous == "_":
            return None
        literal = rust_string_literal(source, index)
        if literal:
            return literal[0]
        char = re.match(
            r"b?'(?:\\x[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F_]+\}|\\.|[^\\'])'", source[index:]
        )
        return index + char.end() if char else None

    found = []
    position = 0
    while position < len(source):
        after_trivia = rust_trivia_end(source, position)
        if after_trivia != position:
            position = after_trivia
            continue
        skipped = skip_literal(position)
        if skipped is not None:
            position = skipped
            continue
        call = name_pattern.match(source, position)
        previous = source[position - 1] if position else " "
        if call and not (previous.isalnum() or previous == "_"):
            bang = rust_trivia_end(source, call.end())
            opening = rust_trivia_end(source, bang + 1) if source.startswith("!", bang) else -1
            if opening >= 0 and opening < len(source) and source[opening] in closers:
                stack = [closers[source[opening]]]
                index = opening + 1
                while index < len(source) and stack:
                    after = rust_trivia_end(source, index)
                    if after != index:
                        index = after
                        continue
                    inner = skip_literal(index)
                    if inner is not None:
                        index = inner
                        continue
                    if source[index] in closers:
                        stack.append(closers[source[index]])
                    elif source[index] == stack[-1]:
                        stack.pop()
                    index += 1
                found.append((call.group(1), source[opening + 1 : index - 1]))
                position = index
                continue
            position = call.end()
            continue
        position += 1
    return found


def verify_claude_launcher(main: str) -> None:
    for required in (
        "mod claude_launcher;",
        "saiai claude [-- <claude arguments>]",
        "Command::Claude(args) => claude_launcher::run(&args)",
        '"init" => return Ok(Command::Init(',
        "Command::Init(init) => init_claude(init)",
        "Command::VSCode => configure_vscode()",
    ):
        require(required in main, f"optional Claude dispatch is missing {required!r}")
    require(
        main.count("claude_launcher::run(") == 1,
        "optional Claude launcher must not become an initialization or default entrypoint",
    )
    source = text("tools/saiai-cli/kernel/src/claude_launcher.rs")
    production, separator, tests = source.partition("#[cfg(test)]\nmod tests")
    require(bool(separator), "optional Claude launcher has no regression tests")
    tests, test_end, trailing = tests.partition("\n}")
    require(bool(test_end) and not trailing.strip(), "Claude test module must be the final source item")
    compact = re.sub(r"\s+", "", production).replace(",)", ")")
    conflict_list = re.search(r"const CONFLICTING_ENV:.*?=\s*&\[(.*?)\];", production, re.DOTALL)
    require(conflict_list is not None, "Claude conflicting environment list is missing")
    conflicts = set(re.findall(r'"([^"\n]+)"', conflict_list.group(1)))
    no_proxy = re.search(r'const LOCAL_NO_PROXY:\s*&str\s*=\s*"([^"\n]+)";', production)
    require(
        no_proxy is not None and no_proxy.group(1) == "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local",
        "Claude NO_PROXY must remain limited to local/private ranges",
    )
    for required in (
        "pub(crate) fn run(args: &[String])",
        "let mut command = process_command()?",
        "read_app_config()",
        "let token = claude_token(&config)?",
        "validate_listen(&config.listen)?",
        "read_runtime_ca(&config)",
        "ensure_local_proxy_running_with_start(&config.listen",
        "apply_environment(&mut command, &config, token)",
        "command.args(args)",
        "command.exec()",
        "command.status()",
        "status.code().unwrap_or(1)",
        "config.providers.claude.as_ref()",
        "config.providers.is_empty()",
        "address.ip().is_loopback()",
        "address.port() == 0",
        "for name in CONFLICTING_ENV",
        "command.env_remove(name)",
        'starts_with("VERTEX_REGION_CLAUDE_")',
        '.env("ANTHROPIC_BASE_URL", "https://api.anthropic.com")',
        '.env("CLAUDE_CODE_OAUTH_TOKEN", token)',
        '.env("NODE_EXTRA_CA_CERTS", &config.ca_cert_path)',
        '.env("CLAUDE_STREAM_IDLE_TIMEOUT_MS", CLAUDE_STREAM_IDLE_TIMEOUT_MS)',
    ):
        require(
            re.sub(r"\s+", "", required) in compact,
            f"optional Claude launcher contract is missing {required!r}",
        )
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        require(f'.env("{name}",&proxy)' in compact, f"Claude child proxy is missing {name}")
    for name in ("NO_PROXY", "no_proxy"):
        require(f'.env("{name}",LOCAL_NO_PROXY)' in compact, f"Claude child proxy is missing {name}")
    for name in (
        "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_API_KEY", "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
        "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "ANTHROPIC_CUSTOM_HEADERS",
        "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
        "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", "NODE_TLS_REJECT_UNAUTHORIZED",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "CLAUDE_CODE_CLIENT_CERT",
        "CLAUDE_CODE_CLIENT_KEY", "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
    ):
        require(name in conflicts, f"Claude conflicting environment is missing {name}")
    for forbidden in WITHDRAWN_V2_MARKERS + (
        "env::set_var", "env::remove_var", "set_current_dir", ".current_dir(", "init_claude(",
        "write_json", "fs::write", "File::create", "OpenOptions", "create_dir",
        "remove_file", "rename(", "--settings", "--setting-sources", "apiKeyHelper",
        "settings.json", ".credentials.json", "reqwest::", "TcpStream::", "/v1/messages",
    ):
        require(forbidden not in production, f"optional Claude launcher contains forbidden behavior: {forbidden}")
    for name in (
        "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "CLAUDE_CONFIG_DIR",
        "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", "NODE_TLS_REJECT_UNAUTHORIZED",
    ):
        require(f'.env("{name}",' not in compact, f"Claude launcher must not override {name}")
    for name in (
        "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "CLAUDE_CONFIG_DIR",
        "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    ):
        require(name not in conflicts, f"Claude launcher must not remove {name}")
        require(f'.env_remove("{name}")' not in compact, f"Claude launcher must not remove {name}")
    # Diagnostics may name the program (each brand placeholder bound to its
    # Brand field by a named argument) but never interpolate anything else.
    # Every delimiter form counts, and the format string is judged after its
    # escapes are decoded (`"\x7btoken\x7d"` is the capture `{token}`).
    brand_argument = r"\s*,\s*(?:brand_product\s*=\s*BRAND\.product_name|brand_binary\s*=\s*BRAND\.binary_name)"
    try:
        invocations = rust_macro_invocations(production, r"e?print(?:ln)?|dbg")
    except UnreadableRustLiteral as error:
        require(False, f"optional Claude launcher has an unreadable string literal: {error}")
    # An alias (`use std::eprintln as notice;`) would escape the name-based
    # checks below, so output macros may not be imported under another name.
    for item in re.findall(r"(?<!r#)\buse\b[^;]*;", rust_without_comments(production, blank_literals=True)):
        require(
            re.search(r"\b(?:e?print(?:ln)?|dbg)\s+as\b", item) is None,
            "Claude diagnostics must not import output macros under another name",
        )
    for name, arguments in invocations:
        require(not name.startswith("print"), "Claude diagnostics must not use stdout")
        try:
            literal = rust_string_literal(arguments, rust_trivia_end(arguments, 0))
        except UnreadableRustLiteral as error:
            require(False, f"optional Claude diagnostics have an unreadable format string: {error}")
        rest = rust_without_comments(arguments[literal[0]:]) if literal else ""
        bound_arguments = re.fullmatch(r"((?:" + brand_argument + r")*)\s*,?\s*", rest)
        format_text = literal[1] if literal else ""
        used = set(re.findall(r"\{(brand_product|brand_binary)\}", format_text))
        bound = set(re.findall(r"\b(brand_product|brand_binary)\s*=", rest))
        require(
            literal is not None
            and bound_arguments is not None
            and not re.search(r"[{}]", re.sub(r"\{brand_(?:product|binary)\}", "", format_text))
            and used <= bound,
            "optional Claude diagnostics must not interpolate credentials or configuration",
        )
    for required in (
        "claude_launcher_replaces_only_child_routing_environment",
        "claude_launcher_reuses_reachable_proxy_without_starting_service",
        "claude_launcher_selects_claude_route_and_rejects_codex_only_config",
        "claude_launcher_requires_loopback_listener",
        "claude_launcher_child_process_preserves_profile_and_parent_environment",
    ):
        require(required in tests, f"optional Claude regression is missing {required!r}")


def verify_cli() -> None:
    cargo = text("tools/saiai-cli/Cargo.toml")
    kernel = text("tools/saiai-cli/kernel/Cargo.toml")
    require('version = "1.1.59"' in cargo, "CLI version is not 1.1.59")
    for manifest in (cargo, kernel):
        require("saiai-core" not in manifest, "local-proxy client still links the V2 runtime core")
    for dependency in ("reqwest", "tokio", "tokio-tungstenite", "rustls", "rcgen", "zeroize", "libc"):
        require(dependency in kernel, f"local-proxy dependency is missing: {dependency}")

    # The SAIAI program (workspace root) runs the kernel package `proxy-cli`
    # (crate proxy_cli, no workspace of its own) with its brand and extension.
    require(
        '[workspace]\nmembers = ["kernel"]' in cargo
        and '[[bin]]\nname = "saiai"\npath = "src/main.rs"' in cargo
        and 'proxy-cli = { path = "kernel" }' in cargo
        and 'name = "proxy-cli"' in kernel
        and '[lib]\nname = "proxy_cli"\npath = "src/lib.rs"' in kernel
        and "[workspace]" not in kernel,
        "CLI must build the saiai binary from the shared client kernel",
    )
    # The binary only supplies the SAIAI brand, extension and release facts;
    # the client lives in the kernel.
    entry = text("tools/saiai-cli/src/main.rs")
    for required in (
        "use saiai::{brand_saiai, gateway_saiai};",
        "proxy_cli::run(\n        &brand_saiai::SAIAI_BRAND,\n        proxy_cli::RuntimeContext {",
        'version: env!("CARGO_PKG_VERSION"),',
        "gateway: &gateway_saiai::SAIAI_GATEWAY,",
    ):
        require(required in entry, f"CLI entry point is missing {required!r}")
    for withdrawn in WITHDRAWN_V2_MARKERS:
        require(withdrawn not in entry, f"CLI entry point exposes withdrawn V2 behavior: {withdrawn}")

    main = text("tools/saiai-cli/kernel/src/lib.rs")
    # User-visible text names the program through Brand placeholders; check
    # the text as the SAIAI build renders it. The binding check here is only
    # file-level (the bindings exist somewhere in lib.rs); that every
    # placeholder is bound in its own call is proven by the Rust test
    # saiai_source_contract::brand_text_renders_the_frozen_saiai_bytes.
    for binding in ("brand_binary = BRAND.binary_name", "brand_product = BRAND.product_name"):
        require(binding in main, f"CLI text is missing the brand binding {binding!r}")
    main = main.replace("{brand_binary}", "saiai").replace("{brand_product}", "SAIAI")
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
        "saiai codex [-- <codex arguments>]",
        "initialize_codex_local_proxy",
        "start_managed_service_after_initialization",
        "initialization_requires_proxy_refresh",
        "env::var(BRAND.env.binary_updated)",
        "binary and runtime configuration are unchanged",
        "env::var(BRAND.env.skip_start)",
        "SAIAI configured Codex for local-proxy OAuth mode.",
        "configure_codex_oauth_local_proxy",
        "write_codex_ide_env(&env_path, &proxy_init.listen",
        '"CODEX_CA_CERTIFICATE"',
        '"OPENAI_API_KEY"',
        '"CLAUDE_CODE_OAUTH_TOKEN"',
        '"CLAUDE_STREAM_IDLE_TIMEOUT_MS"',
        'const CLAUDE_STREAM_IDLE_TIMEOUT_MS: &str = "600000"',
        'Value::String("chatgptAuthTokens".to_string())',
        '"features.apps=false".to_string()',
        '"otel.metrics_exporter=\\\"none\\\"".to_string()',
        '"include_environment_context_time=false".to_string()',
        'const CODEX_ENVIRONMENT_CONTEXT_TIME_KEY: &str = "include_environment_context_time"',
        '"features.respect_system_proxy={}"',
        'directory.join("node_modules/@openai/codex/bin/codex.js")',
        'home.join(".local/bin/codex")',
        "env_dir_override(BRAND.env.home)",
        'settings.remove("oauthAccount")',
        'state.remove("oauthAccount")',
        "remove_if_exists_with_backup(credentials_path",
        "generate_installation_ca",
        "CA_KEY_FILENAME",
        "is_managed_claude_env",
        '"VERTEX_REGION_CLAUDE_"',
        '"CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"',
        '"CLAUDE_CODE_CLIENT_CERT"',
        '"http_proxy"',
        '"NODE_EXTRA_CA_CERTS"',
        "create_new(true)",
        "MOVEFILE_REPLACE_EXISTING",
        "file.sync_all()",
        "LINUX_BACKGROUND_COMMAND",
        "start_linux_background_proxy",
        "start_time_ticks",
        "apply_systemd_user_environment",
        "WINDOWS_BACKGROUND_COMMAND",
        "run_windows_background_proxy_worker",
    ):
        require(required in main, f"CLI contract is missing {required!r}")
    brand = text("tools/saiai-cli/src/brand_saiai.rs")
    for required in (
        'binary_updated: "SAIAI_BINARY_UPDATED"',
        'skip_start: "SAIAI_SKIP_START"',
        'home: "SAIAI_HOME"',
    ):
        require(required in brand, f"SAIAI brand is missing {required!r}")
    for withdrawn in WITHDRAWN_V2_MARKERS:
        require(withdrawn not in main, f"CLI still exposes withdrawn V2 behavior: {withdrawn}")
    verify_claude_launcher(main)
    for forced_model_default in (
        'doc["model"] = value(',
        'doc["review_model"] = value(',
        'doc["model_reasoning_effort"] = value(',
        'doc["model_context_window"] = value(',
        'doc["model_auto_compact_token_limit"] = value(',
    ):
        require(
            forced_model_default not in main,
            f"CLI still forces the Codex model tuning key {forced_model_default!r}",
        )
    for withdrawn_direct_codex in (
        "fn merge_codex_config",
        "fn merge_codex_auth",
        "CODEX_LEGACY_PROVIDER_ID",
        "install_codex_legacy_provider_alias",
    ):
        require(
            withdrawn_direct_codex not in main,
            f"CLI still retains withdrawn direct Codex compatibility {withdrawn_direct_codex!r}",
        )
    for source_root in ("src", "kernel/src"):
        require(not (ROOT / "tools/saiai-cli" / source_root / "v2.rs").exists(), "V2 CLI module still exists")
    proxy = text("tools/saiai-cli/kernel/src/local_proxy.rs")
    require("ca_key_pem" in proxy, "local proxy does not require runtime CA material")
    require("piproxy-ca.key" not in proxy, "local proxy still embeds the historical shared CA key")
    require('const OPENAI_HOST: &str = "api.openai.com"' in proxy, "Codex OpenAI MITM route is missing")
    require("replace_authorization" in proxy, "Codex Gateway authorization boundary is missing")
    require("serve_openai_websocket" in proxy, "Codex WebSocket bridge is missing")
    windows_runtime = text("scripts/saiai-cli/test-windows-runtime.ps1")
    for required in (
        "TEST_ONLY_WINDOWS_REPLACEMENT_KEY",
        "Repeated setup did not replace the API key",
        "Repeated setup replaced a valid CA key",
        "Codex initialization did not normalize the local-proxy Gateway root",
        "Codex local-proxy launcher is missing",
        "Codex initialization did not create local-proxy OAuth auth",
        "Codex initialization did not synchronize the local proxy port",
        "Unchanged Codex initialization interrupted the managed proxy",
        "SAIAI_WINDOWS_NPM_CODEX",
        "features.apps=false",
        "otel.metrics_exporter=",
        "include_environment_context_time=false",
        "include_environment_context_time = false",
        "features.respect_system_proxy=false",
        "service active: yes",
        "Claude initialization did not start the managed proxy",
        "Codex initialization did not refresh the managed proxy",
    ):
        require(required in windows_runtime, f"Windows repeat smoke is missing {required!r}")
    windows_codex_capture = text("scripts/saiai-cli/test-windows-codex-proxy.py")
    for required in (
        "BLOCKED_PROVIDER_HOSTS",
        'path == "/v1/responses"',
        'auth.get("auth_mode") != "chatgptAuthTokens"',
        "original_hosts",
    ):
        require(required in windows_codex_capture, f"Windows Codex capture is missing {required!r}")


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
        manifest = generator.build_manifest(root, "1.1.59", ASSETS, wrappers)
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
    require('"${install_path}" "$@"' in shell, "Unix wrapper does not initialize Codex")
    require(
        '"${install_path}" start' not in shell,
        "Unix wrapper duplicates the native local-proxy start",
    )
    require("installed_matches=1" in shell, "Unix wrapper cannot skip the binary download")
    require(
        'SAIAI_BINARY_UPDATED="${binary_updated}"' in shell,
        "Unix wrapper does not tell native setup whether it replaced the binary",
    )
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
        "[System.IO.File]::Replace($Source, $Destination, $replacementBackup, $true)" in powershell,
        "PowerShell wrapper does not explicitly replace an existing Windows binary",
    )
    require(
        "Move-Item -LiteralPath $Source -Destination $Destination -Force" not in powershell,
        "PowerShell wrapper still relies on Move-Item to replace an existing Windows binary",
    )
    require(
        "Start-SaiaiBackground" not in powershell
        and "Invoke-SaiaiNative" in powershell
        and "& $installPath @provided | Out-Host" not in powershell,
        "PowerShell wrapper does not delegate proxy start to the native initializer",
    )
    require(
        "ConvertTo-WindowsCommandLineArgument" in powershell
        and "$startInfo.Arguments =" in powershell
        and ".ArgumentList" not in powershell,
        "PowerShell wrapper is not compatible with Windows PowerShell 5.1 argument passing",
    )
    require(
        '$env:SAIAI_BINARY_UPDATED = if ($binaryUpdated) { "1" } else { "0" }' in powershell,
        "PowerShell wrapper does not tell native setup whether it replaced the binary",
    )
    command = (SCRIPT_DIR / "setup.cmd").read_text(encoding="utf-8")
    require(
        'set "SAIAI_BINARY_UPDATED=0"' in command
        and 'set "SAIAI_BINARY_UPDATED=1"' in command,
        "CMD wrapper does not tell native setup whether it replaced the binary",
    )
    windows_release = text("scripts/saiai-cli/test-windows-release.ps1")
    require(
        "Running-client upgrade did not install the release binary" in windows_release,
        "Windows release smoke does not cover a running-client upgrade",
    )
    require(
        "Codex initialization did not start the background proxy" in windows_release,
        "Windows release smoke does not cover native Codex initialization start",
    )
    require(
        "Windows PowerShell 5.1 setup wrapper smoke failed" in windows_release
        and "TEST_ONLY_WINDOWS_PS51_CODEX_KEY WITH SPACE" in windows_release,
        "Windows release smoke does not cover Windows PowerShell 5.1 wrapper arguments",
    )
    self_update = text("scripts/saiai-cli/test-windows-self-update.py")
    require(
        "same-path log follower exited before update" in self_update
        and "installed binary does not match release" in self_update,
        "Windows self-update smoke does not cover a running same-path client",
    )


# ---------------------------------------------------------------------------
# Workflows, read as GitHub reads them.
#
# Everyday "Client CI" runs on Linux only; the native macOS and Windows checks
# of this distribution run in "SAIAI CLI Release" (every preview and release
# tag); the kernel's own tests on every platform run in the kernel
# repository's CI. The checks below hold that division by structure: a
# required command counts only as a whole top-level command of a step that
# runs for the platform in question (its `if` evaluated), in a shell that
# stops on its failure, with nothing that masks the failure, and the kernel
# tests see this distribution's name in their effective environment. A
# comment, a heredoc line, `|| true`, `if: false`, `continue-on-error` or an
# environment override no longer satisfies a check.

CI_WORKFLOW = ".github/workflows/ci.yml"
RELEASE_WORKFLOW = ".github/workflows/saiai-cli-release.yml"
FOREIGN_NAMES_ENV = "AITP_TEST_FOREIGN_NAMES"
WORKFLOW_PARSER_HINT = (
    "python3 -m pip install --no-deps --only-binary pyyaml --require-hashes "
    "-r scripts/saiai-cli/requirements-verify.txt"
)
ALLOWED_ACTIONS = frozenset(
    {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
        "Swatinem/rust-cache@42dc69e1aa15d09112580998cf2ef0119e2e91ae",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65",
    }
)
RUNNER_SYSTEMS = (("ubuntu-", "Linux"), ("macos-", "macOS"), ("windows-", "Windows"))
STATIC_LINUX_MATRIX = (
    {"os": "ubuntu-22.04", "target": "x86_64-unknown-linux-musl", "asset": "saiai-linux-x86_64"},
)
RELEASE_MATRIX = (
    {"os": "ubuntu-22.04", "target": "x86_64-unknown-linux-musl", "asset": "saiai-linux-x86_64"},
    {"os": "ubuntu-22.04-arm", "target": "aarch64-unknown-linux-musl", "asset": "saiai-linux-aarch64"},
    {"os": "macos-15-intel", "target": "x86_64-apple-darwin", "asset": "saiai-macos-x86_64"},
    {"os": "macos-15", "target": "aarch64-apple-darwin", "asset": "saiai-macos-aarch64"},
    {"os": "windows-latest", "target": "x86_64-pc-windows-msvc", "asset": "saiai-windows-x86_64.exe"},
    {"os": "windows-latest", "target": "aarch64-pc-windows-msvc", "asset": "saiai-windows-aarch64.exe"},
)
# The release gate (job "mode"), word for word: changing it is a reviewed
# change of this file too.
RELEASE_MODE_ENV = {
    "EVENT": "${{ github.event_name }}",
    "REF": "${{ github.ref }}",
    "REF_NAME": "${{ github.ref_name }}",
    "CONFIRMATION": "${{ inputs.publish_confirmation }}",
    "GH_TOKEN": "${{ github.token }}",
}
RELEASE_MODE_SCRIPT = """set -euo pipefail
case "$EVENT:$REF" in
  push:refs/tags/saiai-v*)
    mode=draft ;;
  workflow_dispatch:refs/tags/saiai-v*)
    if [ "$CONFIRMATION" != "publish $REF_NAME" ]; then
      echo "::error::to publish, run on the tag with publish_confirmation: publish $REF_NAME" >&2
      exit 1
    fi
    mode=publish ;;
  workflow_dispatch:refs/heads/*)
    if [ -n "$CONFIRMATION" ]; then
      echo "::error::only a run on a saiai-v* tag publishes; leave publish_confirmation empty for a preview" >&2
      exit 1
    fi
    mode=preview ;;
  *)
    echo "::error::unsupported trigger $EVENT on $REF" >&2
    exit 1 ;;
esac
if [ "$mode" != preview ]; then
  # Without branch or tag protection, a release tag must point into main.
  status="$(gh api "repos/$GITHUB_REPOSITORY/compare/$GITHUB_SHA...main" --jq .status)"
  case "$status" in
    identical|ahead) ;;
    *)
      echo "::error::$REF_NAME ($GITHUB_SHA) is not on main (compare status: $status)" >&2
      exit 1 ;;
  esac
fi
echo "mode=$mode" >>"$GITHUB_OUTPUT"
"""
RELEASE_MODES = {
    "preview": {"mode", "verify", "build", "package-preview"},
    "draft": {"mode", "verify", "build", "draft"},
    "publish": {"mode", "publish"},
}


def load_workflow(relative: str) -> dict:
    """The workflow as GitHub reads it (YAML 1.2 booleans, so `on` stays a
    key); repeated keys and merge keys are refused."""
    try:
        import yaml
    except ImportError:
        require(False, f"reading the workflows needs PyYAML: {WORKFLOW_PARSER_HINT}")

    class Loader(yaml.SafeLoader):
        pass

    bool_tag = "tag:yaml.org,2002:bool"
    Loader.yaml_implicit_resolvers = {
        first: [(tag, pattern) for tag, pattern in resolvers if tag != bool_tag]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    Loader.add_implicit_resolver(
        bool_tag, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
    )

    def mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            require(key_node.tag != "tag:yaml.org,2002:merge", f"{relative} uses a YAML merge key")
            key = loader.construct_object(key_node, deep=True)
            require(isinstance(key, str), f"{relative} has a non-text key {key!r}")
            require(key not in result, f"{relative} repeats the key {key!r}")
            result[key] = loader.construct_object(value_node, deep=True)
        return result

    Loader.add_constructor("tag:yaml.org,2002:map", mapping)
    try:
        document = yaml.load(text(relative), Loader=Loader)
    except yaml.YAMLError as error:
        require(False, f"{relative} is not valid YAML: {error}")
    require(isinstance(document, dict), f"{relative} is not a workflow")
    require(isinstance(document.get("jobs"), dict) and document["jobs"], f"{relative} has no jobs")
    return document


EXPRESSION_TOKEN = re.compile(
    r"\s*(?:(?P<op>==|!=|&&|\|\||!|\(|\)|,)|(?P<string>'(?:[^']|'')*')|(?P<word>[A-Za-z_][A-Za-z0-9_.-]*))"
)


def evaluate(expression, context: dict[str, str]):
    """Value of an `if:` expression: literals, the context names given,
    ==/!= (case-insensitive, as GitHub compares text), !, &&, ||,
    parentheses, startsWith and the status functions (the success path).
    Anything else is refused rather than guessed."""
    if isinstance(expression, bool):
        return expression
    require(isinstance(expression, str), f"unsupported condition {expression!r}")
    source = expression.strip()
    wrapped = re.fullmatch(r"\$\{\{(.*)\}\}", source, re.DOTALL)
    if wrapped:
        source = wrapped.group(1)
    tokens = []
    position = 0
    while position < len(source):
        if source[position:].strip() == "":
            break
        match = EXPRESSION_TOKEN.match(source, position)
        require(match is not None, f"unsupported condition {expression!r}")
        tokens.append(match)
        position = match.end()
    index = 0

    def peek():
        return tokens[index] if index < len(tokens) else None

    def take(op: str | None = None):
        nonlocal index
        token = peek()
        require(token is not None, f"incomplete condition {expression!r}")
        if op is not None:
            require(token.group("op") == op, f"unsupported condition {expression!r}")
        index += 1
        return token

    def truthy(value) -> bool:
        return value not in (False, None, "", 0)

    def equal(left, right) -> bool:
        # GitHub converts mixed types to numbers before comparing; only
        # text against text is read here.
        require(
            isinstance(left, str) and isinstance(right, str),
            f"condition {expression!r} compares {left!r} with {right!r}, which is not read here",
        )
        return left.lower() == right.lower()

    def primary():
        token = take()
        if token.group("op") == "(":
            value = either()
            take(")")
            return value
        if token.group("string") is not None:
            return token.group("string")[1:-1].replace("''", "'")
        word = token.group("word")
        require(word is not None, f"unsupported condition {expression!r}")
        following = peek()
        if following is not None and following.group("op") == "(":
            take("(")
            arguments = []
            if not (peek() is not None and peek().group("op") == ")"):
                arguments.append(either())
                while peek() is not None and peek().group("op") == ",":
                    take(",")
                    arguments.append(either())
            take(")")
            status = {"success": True, "always": True, "failure": False, "cancelled": False}
            if word in status and not arguments:
                return status[word]
            if word == "startsWith" and len(arguments) == 2 and all(isinstance(a, str) for a in arguments):
                return arguments[0].lower().startswith(arguments[1].lower())
            require(False, f"unsupported function {word} in {expression!r}")
        if word in ("true", "false"):
            return word == "true"
        if word == "null":
            return None
        require(word in context, f"condition {expression!r} uses {word}, unknown here")
        return context[word]

    # Precedence as GitHub documents it: ! binds tighter than == and !=.
    def negation():
        token = peek()
        if token is not None and token.group("op") == "!":
            take("!")
            return not truthy(negation())
        return primary()

    def comparison():
        left = negation()
        token = peek()
        if token is not None and token.group("op") in ("==", "!="):
            take()
            right = negation()
            return equal(left, right) == (token.group("op") == "==")
        return left

    def both():
        value = comparison()
        while peek() is not None and peek().group("op") == "&&":
            take("&&")
            right = comparison()
            value = right if truthy(value) else value
        return value

    def either():
        value = both()
        while peek() is not None and peek().group("op") == "||":
            take("||")
            right = both()
            value = value if truthy(value) else right
        return value

    value = either()
    require(index == len(tokens), f"unsupported condition {expression!r}")
    return truthy(value)


def substitute(script: str, context: dict[str, str]) -> str:
    """`script` with the `${{ name }}` values the context knows filled in."""
    def fill(match: re.Match) -> str:
        name = match.group(1)
        return context[name] if name in context else match.group(0)

    return re.sub(r"\$\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}", fill, script)


# Words that change how later commands run, or whether their failure
# counts, wherever they start a command (after ;, &&, ||, | or a newline).
BASH_MASK_WORDS = frozenset(
    {
        "exec", "return", "trap", "alias", "shopt", "function", "source", ".", "eval",
        "unset", "export", "declare", "typeset", "readonly", "local", "enable",
        "builtin", "command", "hash", "cd", "pushd", "popd",
    }
)
BASH_MASKS = re.compile(
    r"\|\|\s*(?:true|:)(?:\s|;|$)|\bexit\s+0\b|[A-Za-z0-9_-]+\s*\(\s*\)|\$\{!|(?:\|\||&&|\|)\s*$"
)
PWSH_MASKS = re.compile(
    r"\b(?:try|catch|trap|return|function|filter|Set-Alias|New-Alias|Set-Location|Push-Location|Invoke-Expression|iex)\b"
    r"|ErrorActionPreference|SilentlyContinue|-ErrorAction\b|\bexit\s+0\b|\$env:\w+\s*=",
    re.IGNORECASE,
)


def bash_masks(command: str) -> bool:
    if BASH_MASKS.search(command):
        return True
    for segment in re.split(r"\|\||&&|[|;&(){}]|\bthen\b|\bdo\b|\belse\b", command):
        words = segment.split()
        if words and words[0] in BASH_MASK_WORDS:
            return True
        # `set -euo pipefail` is fine; `set +e` / `set +o errexit` is not.
        if words and words[0] == "set" and any(word.startswith("+") for word in words[1:]):
            return True
    return False


NATIVE_FAILURES_STOP = "$PSNativeCommandUseErrorActionPreference = $true"


def logical_commands(script: str, shell: str) -> list[tuple[str, int]]:
    """(command, nesting depth) of every logical line of a run script:
    continuation lines joined, comments, blank lines and heredoc bodies
    dropped, whitespace collapsed. Unbalanced nesting is refused."""
    continuation = "`" if shell == "pwsh" else "\\"
    lines = script.split("\n")
    commands = []
    depth = 0
    pending = ""
    heredoc = None
    for line in lines:
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith(continuation):
            pending += stripped[:-1] + " "
            continue
        command = re.sub(r"\s+", " ", (pending + stripped).strip())
        pending = ""
        commands.append((command, depth))
        if shell != "pwsh":
            marker = re.search(r"<<-?\s*(['\"]?)([^\s'\"<>|;&]+)\1", command)
            if marker:
                heredoc = marker.group(2)
            unquoted = re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", " ", command)
            words = [word for word in re.split(r"[\s;]+", unquoted) if word]
            depth += sum(word in ("if", "case", "for", "while", "until", "select", "{", "(") for word in words)
            depth -= sum(word in ("fi", "esac", "done", "}", ")") for word in words)
        else:
            plain = re.sub(r"'[^']*'|\"(?:[^\"`]|`.)*\"", "", command)
            depth += plain.count("{") - plain.count("}")
        require(depth >= 0, f"unbalanced run script near {command!r}")
    require(not pending and heredoc is None and depth == 0, "unbalanced run script")
    return commands


def step_shell(step: dict, system: str) -> str:
    shell = step.get("shell")
    if shell is None:
        return "pwsh" if system == "Windows" else "bash"
    require(shell in ("bash", "pwsh"), f"step {step.get('name')!r} uses the shell {shell!r}")
    return shell


def effective_commands(step: dict, system: str, context: dict[str, str]) -> list[str]:
    """The commands of `step` whose failure fails the step."""
    script = step.get("run")
    if not isinstance(script, str):
        return []
    shell = step_shell(step, system)
    commands = logical_commands(substitute(script, context), shell)
    if shell == "pwsh":
        first = 1 if commands and commands[0][0] == NATIVE_FAILURES_STOP else 0
        if any(PWSH_MASKS.search(command) for command, _ in commands[first:]):
            return []
    elif any(bash_masks(command) for command, _ in commands):
        return []
    top = [command for command, depth in commands if depth == 0]
    if shell == "bash":
        return top
    # pwsh stops at a failing native command only with this preference set
    # first; otherwise only the last command's status counts.
    if commands and commands[0][0] == NATIVE_FAILURES_STOP:
        return [command for command in top[1:] if not command.startswith("& ") or command == top[-1]]
    return top[-1:] if commands and commands[-1][1] == 0 else []


def runner_system(job: dict, entry: dict[str, str]) -> str:
    runs_on = substitute(str(job.get("runs-on")), {f"matrix.{key}": value for key, value in entry.items()})
    for prefix, system in RUNNER_SYSTEMS:
        if runs_on.startswith(prefix):
            return system
    require(False, f"unknown runner {runs_on!r}")


def matrix_entries(job: dict) -> list[dict[str, str]]:
    strategy = job.get("strategy")
    if strategy is None:
        return [{}]
    require(isinstance(strategy, dict) and set(strategy) <= {"fail-fast", "matrix", "max-parallel"}, "unsupported strategy")
    matrix = strategy.get("matrix")
    require(isinstance(matrix, dict) and set(matrix) == {"include"}, "a matrix must list its entries under include only")
    entries = matrix["include"]
    require(isinstance(entries, list) and entries, "empty matrix")
    for entry in entries:
        require(isinstance(entry, dict) and all(isinstance(v, str) for v in entry.values()), "unsupported matrix entry")
    return entries


def job_context(job: dict, entry: dict[str, str], base: dict[str, str]) -> dict[str, str]:
    context = dict(base)
    context["runner.os"] = runner_system(job, entry)
    context.update({f"matrix.{key}": value for key, value in entry.items()})
    return context


def check_workflow_basics(relative: str, workflow: dict) -> None:
    """What holds for every job and step of both workflows."""
    require("defaults" not in workflow, f"{relative} must not change step defaults")
    for name, value in (workflow.get("env") or {}).items():
        require(name != FOREIGN_NAMES_ENV or value == "saiai", f"{relative} overrides {FOREIGN_NAMES_ENV}")
    for job_id, job in workflow["jobs"].items():
        require(isinstance(job, dict), f"{relative} job {job_id} is not a mapping")
        require("uses" not in job, f"{relative} job {job_id} calls another workflow")
        require("defaults" not in job, f"{relative} job {job_id} changes step defaults")
        require(not job.get("continue-on-error"), f"{relative} job {job_id} continues on error")
        for name, value in (job.get("env") or {}).items():
            require(name != FOREIGN_NAMES_ENV or value == "saiai", f"{relative} job {job_id} overrides {FOREIGN_NAMES_ENV}")
        steps = job.get("steps")
        require(isinstance(steps, list) and steps, f"{relative} job {job_id} has no steps")
        for step in steps:
            require(isinstance(step, dict), f"{relative} job {job_id} has an unreadable step")
            label = f"{relative} job {job_id} step {step.get('name') or step.get('uses')!r}"
            require(not step.get("continue-on-error"), f"{label} continues on error")
            require("working-directory" not in step, f"{label} changes the working directory")
            uses = step.get("uses")
            require(uses is None or uses in ALLOWED_ACTIONS, f"{label} uses an action that is not pinned here: {uses}")
            if str(uses).startswith("actions/checkout@"):
                require("with" not in step, f"{label} must check out the commit that started the run")
            require((uses is None) != ("run" not in step), f"{label} must either run or use")
            for name, value in (step.get("env") or {}).items():
                require(name != FOREIGN_NAMES_ENV or value == "saiai", f"{label} overrides {FOREIGN_NAMES_ENV}")
            script = step.get("run")
            if isinstance(script, str):
                for forbidden in (FOREIGN_NAMES_ENV, "GITHUB_ENV", "GITHUB_PATH"):
                    require(forbidden not in script, f"{label} touches {forbidden}")


def runs_command(
    relative: str,
    workflow: dict,
    job_id: str,
    command: str,
    *,
    base: dict[str, str],
    entries: list[dict[str, str]] | None = None,
    foreign_names: bool = False,
    purpose: str,
) -> None:
    """`command` fails job `job_id` when it fails, for every matrix entry in
    `entries` (default: all), with the kernel tests' foreign names in its
    effective environment when `foreign_names`. `command` may name the
    entry's values as {target}, {asset}, {os}."""
    job = workflow["jobs"].get(job_id)
    require(isinstance(job, dict), f"{relative} has no job {job_id} ({purpose})")
    available = matrix_entries(job)
    for entry in available if entries is None else entries:
        require(entry in available, f"{relative} job {job_id} lacks the matrix entry {entry} ({purpose})")
        context = job_context(job, entry, base)
        expected = re.sub(r"\s+", " ", command.format(**entry)).strip()
        found = False
        for step in job["steps"]:
            if expected not in effective_commands(step, context["runner.os"], context):
                continue
            if not evaluate(step.get("if", True), context):
                continue
            if foreign_names:
                names = {**(workflow.get("env") or {}), **(job.get("env") or {}), **(step.get("env") or {})}
                if names.get(FOREIGN_NAMES_ENV) != "saiai":
                    continue
            found = True
        where = f" on {entry.get('target') or entry.get('os')}" if entry else ""
        require(found, f"{relative} job {job_id} does not run {purpose}{where}: {expected!r}")


def jobs_that_run(workflow: dict, base: dict[str, str]) -> set[str]:
    jobs = workflow["jobs"]
    ran: dict[str, bool] = {}

    def runs(job_id: str, trail: tuple[str, ...] = ()) -> bool:
        require(job_id in jobs and job_id not in trail, f"job dependency on {job_id} is broken")
        if job_id not in ran:
            job = jobs[job_id]
            needs = job.get("needs", [])
            needs = [needs] if isinstance(needs, str) else needs
            condition = job.get("if", True)
            require(
                not (isinstance(condition, str) and re.search(r"\b(?:always|failure|cancelled)\s*\(", condition)),
                f"job {job_id} runs regardless of its needs",
            )
            ran[job_id] = all(runs(need, trail + (job_id,)) for need in needs) and evaluate(condition, base)
        return ran[job_id]

    return {job_id for job_id in jobs if runs(job_id)}


def verify_ci_workflow() -> None:
    relative = CI_WORKFLOW
    workflow = load_workflow(relative)
    check_workflow_basics(relative, workflow)
    # Ops finds the release source's "Client CI" run by this name, event push
    # and branch main.
    require(workflow.get("name") == "Client CI", f"{relative} must stay named 'Client CI'")
    require(
        workflow.get("on") == {
            "pull_request": {"branches": ["main"]},
            "push": {"branches": ["main"]},
            "workflow_dispatch": None,
        },
        f"{relative} must run on every pull request to main and every push to main",
    )
    require((workflow.get("env") or {}).get(FOREIGN_NAMES_ENV) == "saiai", f"{relative} does not name SAIAI to the kernel's tests")
    for job_id, job in workflow["jobs"].items():
        require("needs" not in job, f"{relative} job {job_id} waits on another job")
        for entry in matrix_entries(job):
            require(
                runner_system(job, entry) == "Linux",
                f"{relative} job {job_id} leaves Linux: native macOS and Windows checks belong to the release workflow",
            )
    for event, ref in (("pull_request", "refs/pull/1/merge"), ("push", "refs/heads/main")):
        base = {"github.event_name": event, "github.ref": ref}
        require(jobs_that_run(workflow, base) == set(workflow["jobs"]), f"{relative} skips a job on {event}")

        def check(job_id: str, command: str, purpose: str, **options) -> None:
            runs_command(relative, workflow, job_id, command, base=base, purpose=purpose, **options)

        check("client-linux", "python3 scripts/saiai-cli/test-scan-kernel-names.py", "the kernel name scan tests")
        check("client-linux", "python3 scripts/saiai-cli/scan-kernel-names.py tools/saiai-cli/kernel", "the kernel name scan")
        check("client-linux", "cargo fmt --manifest-path tools/saiai-cli/Cargo.toml --all --check", "the format check")
        check("client-linux", "cargo clippy --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace --all-targets -- -D warnings", "the lint")
        check(
            "client-linux",
            "cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace",
            "the workspace tests with SAIAI named to the kernel's tests",
            foreign_names=True,
        )
        for command in (
            "cargo clippy --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace --features contract --all-targets -- -D warnings",
            "cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml -p saiai --features contract --lib --test contract_entry --test saiai_render_contract --test kernel_consumer",
            "python3 scripts/saiai-cli/test-codex-daemon.py --binary tools/saiai-cli/target/debug/saiai --codex dist/codex-daemon-regression/codex-x86_64-unknown-linux-musl",
            "node --test scripts/saiai-cli/test-vscode-certificates.js",
            "python3 scripts/saiai-cli/test-release-contract.py",
            "python3 scripts/saiai-cli/test-github-release-draft.py",
            "python3 scripts/saiai-cli/test-fetch-github-release.py",
            "python3 scripts/saiai-cli/test-brand-contract.py",
            "python3 tools/saiai-cli/kernel/scripts/test_release_manifest.py",
            "python3 scripts/saiai-cli/test-installed-codex-desktop-probe.py",
            "python3 scripts/saiai-cli/test-windows-self-update-polling.py",
            "bash scripts/saiai-cli/test-setup-wrappers.sh",
            "python3 scripts/saiai-cli/verify-release.py",
        ):
            check("client-linux", command, "the SAIAI contract and golden checks")
        require(
            tuple(matrix_entries(workflow["jobs"]["static-linux"])) == STATIC_LINUX_MATRIX,
            f"{relative} static Linux matrix differs",
        )
        for command in (
            'bash scripts/saiai-cli/build-linux.sh "{target}"',
            'python3 scripts/saiai-cli/verify-linux-portability.py "dist/{asset}"',
            'python3 scripts/saiai-cli/verify-release.py --artifact "dist/{asset}"',
            "python3 scripts/saiai-cli/test-linux-entropy.py --binary dist/{asset}",
            "python3 scripts/saiai-cli/test-initialization-scope.py --binary dist/{asset}",
            "python3 scripts/saiai-cli/test-linux-service.py --binary dist/{asset}",
            "python3 scripts/saiai-cli/test-environment-isolation.py --binary dist/{asset}",
            "python3 scripts/saiai-cli/test-uninstall.py --binary dist/{asset}",
        ):
            check("static-linux", command, "the static Linux client checks")


def verify_release_workflow() -> None:
    relative = RELEASE_WORKFLOW
    workflow = load_workflow(relative)
    check_workflow_basics(relative, workflow)
    jobs = workflow["jobs"]
    require(workflow.get("name") == "SAIAI CLI Release", f"{relative} must stay named 'SAIAI CLI Release'")
    require(
        workflow.get("on") == {
            "workflow_dispatch": {
                "inputs": {
                    "publish_confirmation": {
                        "description": workflow.get("on", {}).get("workflow_dispatch", {}).get("inputs", {}).get("publish_confirmation", {}).get("description"),
                        "required": False,
                        "default": "",
                        "type": "string",
                    }
                }
            },
            "push": {"tags": ["saiai-v*"]},
        },
        f"{relative} must start only by hand or by a saiai-v* tag push",
    )
    require(workflow.get("permissions") == {"contents": "read"}, f"{relative} must default to read-only")
    require(set(jobs) == {"mode", "verify", "build", "package-preview", "draft", "publish"}, f"{relative} jobs differ")

    # The gate: job "mode" decides preview, draft or publish, word for word.
    mode = jobs["mode"]
    gate = [step for step in mode["steps"] if step.get("id") == "mode"]
    require(
        len(mode["steps"]) == 1 and len(gate) == 1
        and "if" not in mode and "if" not in gate[0] and "needs" not in mode and "shell" not in gate[0]
        and gate[0].get("env") == RELEASE_MODE_ENV and gate[0].get("run") == RELEASE_MODE_SCRIPT
        and mode.get("outputs") == {"mode": "${{ steps.mode.outputs.mode }}"}
        and runner_system(mode, {}) == "Linux",
        f"{relative} release gate (job mode) differs from the reviewed gate",
    )
    for name, expected in RELEASE_MODES.items():
        ran = jobs_that_run(workflow, {"needs.mode.outputs.mode": name})
        require(ran == expected, f"{relative} runs {sorted(ran)} for a {name} run, not {sorted(expected)}")
    # Only the draft and publish jobs write; only publish makes a release public.
    for job_id, job in jobs.items():
        writes = (job.get("permissions") or {}).get("contents") == "write"
        require(writes == (job_id in ("draft", "publish")), f"{relative} job {job_id} has the wrong contents permission")
        publishes = '"draft":false' in "\n".join(str(step.get("run", "")) for step in job["steps"])
        require(publishes == (job_id == "publish"), f"{relative} job {job_id} must {'' if job_id == 'publish' else 'not '}publish")
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("softprops/action-gh-release@"):
                require(job_id == "draft" and step.get("with", {}).get("draft") is True, f"{relative} uploads a non-draft release")
                require(step.get("with", {}).get("prerelease") is False, f"{relative} release must not be a prerelease")
                require(step.get("with", {}).get("name") == "SAIAI CLI ${{ github.ref_name }}", f"{relative} release name differs")
                files = set(step.get("with", {}).get("files", "").split())
                require(files == {f"dist/{name}" for name in ASSETS + WRAPPERS + ("manifest.json",)}, f"{relative} draft files differ")
    require(jobs["publish"].get("environment") == "release", f"{relative} publish job lost its environment")
    # Each job waits on exactly these: a failed verify or build stops the
    # draft and the preview.
    for job_id, needs in (
        ("verify", ["mode"]), ("build", ["verify"]), ("package-preview", ["mode", "build"]),
        ("draft", ["mode", "build"]), ("publish", ["mode"]),
    ):
        actual = jobs[job_id].get("needs")
        require(([actual] if isinstance(actual, str) else actual) == needs, f"{relative} job {job_id} must need {needs}")
    # Nothing but the publish job may make a release public, by any means.
    for job_id, job in jobs.items():
        for step in job["steps"]:
            script = str(step.get("run", ""))
            if job_id != "publish":
                for publishing in ("gh release", "PATCH", "draft\":false", "--draft", "draft=false"):
                    require(publishing not in script, f"{relative} job {job_id} must not publish ({publishing!r})")
    # The draft is uploaded (its condition holds whenever nothing is
    # published yet) and its digests recorded for the publish run.
    upload = [step for step in jobs["draft"]["steps"] if str(step.get("uses", "")).startswith("softprops/action-gh-release@")]
    require(len(upload) == 1, f"{relative} draft job must upload one release draft")
    require(
        evaluate(upload[0].get("if", True), {"steps.preflight.outputs.already_published": "false"}),
        f"{relative} draft job skips the draft upload",
    )
    draft = {"needs.mode.outputs.mode": "draft"}
    runs_command(
        relative, workflow, "draft",
        "sha256sum " + " ".join(f"dist/{name}" for name in sorted(ASSETS + WRAPPERS + ("manifest.json",))) + " > release-digests.sha256",
        base=draft, purpose="the record of the draft's digests",
    )
    digests = [
        step for step in jobs["draft"]["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
        and step.get("with", {}).get("name") == "release-digests"
        and step.get("with", {}).get("path") == "release-digests.sha256"
        and "if" not in step
    ]
    require(len(digests) == 1, f"{relative} draft job does not keep the draft's digests")
    # The publish run checks the fetched assets against those digests and
    # never rewrites them before checking.
    for step in jobs["publish"]["steps"]:
        script = str(step.get("run", ""))
        require(
            re.search(r"(?:\b(?:cp|mv|install|ln|tee|touch|rm|sed)\b[^\n]*|>>?\s*\"?)\bdist/", script) is None,
            f"{relative} publish job rewrites the fetched release assets",
        )

    for mode_name in ("preview", "draft"):
        base = {"needs.mode.outputs.mode": mode_name}

        def check(job_id: str, command: str, purpose: str, **options) -> None:
            runs_command(relative, workflow, job_id, command, base=base, purpose=purpose, **options)

        for command in (
            "cargo fmt --manifest-path tools/saiai-cli/Cargo.toml --all --check",
            "cargo clippy --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace --all-targets -- -D warnings",
            "python3 scripts/saiai-cli/test-scan-kernel-names.py",
            "python3 scripts/saiai-cli/scan-kernel-names.py tools/saiai-cli/kernel",
            "cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml -p saiai --features contract --lib --test contract_entry --test saiai_render_contract --test kernel_consumer",
            "node --test scripts/saiai-cli/test-vscode-certificates.js",
            "python3 scripts/saiai-cli/test-release-contract.py",
            "python3 scripts/saiai-cli/test-github-release-draft.py",
            "python3 scripts/saiai-cli/test-fetch-github-release.py",
            "python3 scripts/saiai-cli/test-installed-codex-desktop-probe.py",
            "python3 scripts/saiai-cli/test-windows-self-update-polling.py",
            "bash scripts/saiai-cli/test-setup-wrappers.sh",
            "python3 scripts/saiai-cli/verify-release.py",
        ):
            check("verify", command, "the release verification")
        check(
            "verify",
            "cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace",
            "the workspace tests with SAIAI named to the kernel's tests",
            foreign_names=True,
        )

        require(tuple(matrix_entries(jobs["build"])) == RELEASE_MATRIX, f"{relative} build matrix differs")
        linux = [entry for entry in RELEASE_MATRIX if entry["os"].startswith("ubuntu-")]
        macos = [entry for entry in RELEASE_MATRIX if entry["os"].startswith("macos-")]
        windows = [entry for entry in RELEASE_MATRIX if entry["os"].startswith("windows-")]
        windows_x64 = [entry for entry in windows if entry["target"] == "x86_64-pc-windows-msvc"]
        apple_silicon = [entry for entry in macos if entry["target"] == "aarch64-apple-darwin"]
        native = [entry for entry in RELEASE_MATRIX if entry["target"] != "aarch64-pc-windows-msvc"]
        program = "tools/saiai-cli/target/{target}/release/saiai"
        for command, entries, purpose in (
            ("node --test scripts/saiai-cli/test-vscode-certificates.js", None, "the VSCode certificate guard"),
            ('bash scripts/saiai-cli/build-linux.sh "{target}"', linux, "the static Linux build"),
            (
                "cargo build --locked --manifest-path tools/saiai-cli/Cargo.toml -p saiai --bin saiai --release --target {target}",
                macos + windows, "the release build",
            ),
            ("cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml -p saiai", macos + windows_x64, "this distribution's tests"),
            (
                "cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml -p saiai --features contract --lib --test contract_entry --test saiai_render_contract --test kernel_consumer",
                macos + windows_x64, "the platform SAIAI goldens",
            ),
            ("python3 scripts/saiai-cli/verify-linux-portability.py \"dist/{asset}\"", linux, "the Linux portability check"),
            ("python3 scripts/saiai-cli/test-linux-entropy.py --binary dist/{asset}", linux, "the old-kernel TLS check"),
            ("python3 scripts/saiai-cli/test-linux-service.py --binary dist/{asset}", linux, "the Linux service smoke"),
            ("python3 scripts/saiai-cli/test-environment-isolation.py --binary dist/{asset}", linux, "the environment isolation check"),
            ("python3 scripts/saiai-cli/test-uninstall.py --binary dist/{asset}", linux, "the uninstall check"),
            ("python scripts/saiai-cli/test-initialization-scope.py --binary dist/{asset}", native, "the initialization scope check"),
            (
                'python3 scripts/saiai-cli/test-release-bundle.py --bundle dist --setup-sh dist/setup.sh --asset "{asset}"',
                linux + macos, "the native Unix bundle smoke",
            ),
            (f"python3 scripts/saiai-cli/test-macos-service.py --binary {program}", macos, "the macOS LaunchAgent smoke"),
            (f"python3 scripts/saiai-cli/test-macos-environments.py --binary {program}", macos, "the macOS environment isolation"),
            (
                f'python3 scripts/saiai-cli/test-windows-codex-proxy.py --saiai {program} --codex-prefix "$prefix/bin" --codex-version 0.153.4',
                apple_silicon, "the official macOS Codex capture",
            ),
            (f"python scripts/saiai-cli/verify-windows-reproducibility.py {program}.exe", windows, "the reproducible Windows image check"),
            (
                "python -c \"import runpy; runpy.run_path('scripts/saiai-cli/test-initialization-scope.py')['windows_roots'](); print('Windows Root inventory read passed')\"",
                windows_x64, "the read-only Windows certificate inventory",
            ),
            (
                "bash scripts/saiai-cli/cargo-test-filtered.sh proxy-cli windows_desktop_runtime::tests -- --test-threads=1",
                windows_x64, "the Windows Desktop runtime tests",
            ),
            (
                f'& "$PWD/scripts/saiai-cli/test-windows-runtime.ps1" -BinaryPath "$PWD/{program}.exe"',
                windows_x64, "the Windows local proxy runtime smoke",
            ),
            (f"python scripts/saiai-cli/test-windows-log-encoding.py --binary {program}.exe", windows_x64, "the Windows log encoding check"),
            (f"python scripts/saiai-cli/test-windows-environments.py --binary {program}.exe", windows_x64, "the Windows environment isolation"),
            (
                '& "$env:WINDIR/System32/WindowsPowerShell/v1.0/powershell.exe" -NoProfile -NonInteractive -File scripts/saiai-cli/test-setup-environments.ps1 -WrapperPath "$PWD/scripts/saiai-cli/setup.ps1"',
                windows_x64, "the Windows installer environment routing",
            ),
            (
                '& "$PWD/scripts/saiai-cli/test-windows-release.ps1" -BundleDir dist -SetupPs1 dist/setup.ps1 -SetupCmd dist/setup.cmd -AssetName "{asset}"',
                windows_x64, "the Windows bundle and PowerShell 5.1 wrapper smoke",
            ),
            ("python scripts/saiai-cli/test-windows-self-update.py --binary dist/{asset}", windows_x64, "the Windows self-update smoke"),
        ) + tuple(
            (
                f'python scripts/saiai-cli/test-windows-codex-proxy.py --saiai {program}.exe --codex-prefix "$env:RUNNER_TEMP/codex-{version}" --codex-version {version}',
                windows_x64, f"the official Windows Codex {version} capture",
            )
            for version in ("0.146.0", "0.153.4")
        ):
            check("build", command, purpose, entries=entries)

    preview = {"needs.mode.outputs.mode": "preview"}
    every_artifact = " ".join(f"--artifact dist/{asset}" for asset in ASSETS)
    for command in (
        f"python3 scripts/saiai-cli/verify-release.py {every_artifact}",
        "python3 scripts/saiai-cli/test-release-bundle.py --bundle dist --setup-sh dist/setup.sh",
    ):
        runs_command(relative, workflow, "package-preview", command, base=preview, purpose="the six-platform validation bundle")
    publish = {"needs.mode.outputs.mode": "publish", "steps.fetch.outputs.state": "draft"}
    for command in (
        'sha256sum --check --strict "$RUNNER_TEMP/release-digests/release-digests.sha256"',
        'cmp "$RUNNER_TEMP/manifest.json" dist/manifest.json',
        'python3 scripts/saiai-cli/verify-github-release-draft.py --dist dist --tag "$GITHUB_REF_NAME" --state published <"$release_json"',
        f"python3 scripts/saiai-cli/verify-release.py {every_artifact}",
        "python3 scripts/saiai-cli/test-release-bundle.py --bundle dist --setup-sh dist/setup.sh",
    ):
        runs_command(relative, workflow, "publish", command, base=publish, purpose="the published release check")


def verify_workflows_and_docs() -> None:
    verify_ci_workflow()
    verify_release_workflow()
    pre_push = text("scripts/git-hooks/pre-push")
    for required in (
        "python3 scripts/saiai-cli/test-release-contract.py",
        "AITP_TEST_FOREIGN_NAMES=saiai",
        "python3 scripts/saiai-cli/test-scan-kernel-names.py",
        "python3 scripts/saiai-cli/scan-kernel-names.py tools/saiai-cli/kernel",
    ):
        require(required in pre_push, f"the pre-push hook does not run {required!r}")
    # The kernel's AITP release build script (built and checked by the
    # kernel's own CI) keeps remapping the build machine's paths.
    remap = text(AITP_RELEASE_BUILD)
    for required in (
        "--remap-path-prefix=",
        "-ffile-prefix-map=",
        "CARGO_ENCODED_RUSTFLAGS",
        "--bin aitp",
        "only Linux GNU targets are verified",
        '--target "$triple"',
    ):
        require(required in remap, f"AITP release build script is missing {required!r}")
    for prefix in AITP_NEUTRAL_PREFIXES:
        require(
            re.search(r'^add_mapping "\$\w+" ' + re.escape(prefix) + r"$", remap, re.MULTILINE) is not None,
            f"AITP release build script does not map to {prefix}",
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
    require(
        "unchanged initialization did not preserve the managed proxy" in linux_service,
        "Linux service smoke does not prove unchanged setup preserves the proxy",
    )
    macos_service = text("scripts/saiai-cli/test-macos-service.py")
    for required in (
        '"init-codex"',
        "init-codex did not synchronize CODEX_HOME/.env to config listen",
        "init-codex retained a direct-provider compatibility route",
    ):
        require(required in macos_service, f"macOS service smoke is missing {required!r}")
    for relative in (CI_WORKFLOW, RELEASE_WORKFLOW):
        workflow = text(relative)
        for withdrawn in ("test-v2-", "V2 Preview", "saiai-core/Cargo.toml"):
            require(withdrawn not in workflow, f"{relative} still contains {withdrawn!r}")
        # The placeholder exception is gone, and AITP releases are built and
        # checked by the kernel's own CI, not here.
        for forbidden in ("ALLOW_PLACEHOLDER", "allow-placeholder", "build-release.sh", "remap-path-prefix", "--aitp-artifact"):
            require(forbidden not in workflow, f"{relative} must not use {forbidden!r}")
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


CREDENTIAL_PATTERN = re.compile(r"(?i)(?:sk|key)[-_][A-Za-z0-9_-]{16,}")


def is_possible_credential(match: str) -> bool:
    # Lowercase snake_case is a Rust identifier such as rcgen's
    # `use_authority_key_identifier_extension`; real keys carry digits or
    # uppercase letters.
    if re.fullmatch(r"[a-z_]+", match):
        return False
    return "TEST" not in match.upper() and "YOUR" not in match.upper()


def verify_no_non_test_credentials() -> None:
    key_pattern = CREDENTIAL_PATTERN
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
                    not is_possible_credential(match),
                    f"possible credential in {path}",
                )


AITP_BRAND_SOURCE = "tools/saiai-cli/kernel/src/bin/aitp/brand.rs"
AITP_RELEASE_BUILD = "tools/saiai-cli/kernel/scripts/build-release.sh"
AITP_RELEASE_MANIFEST = "tools/saiai-cli/kernel/scripts/release_manifest.py"


def load_release_manifest():
    """The kernel's own release manifest tool (signature checks included)."""
    spec = importlib.util.spec_from_file_location("aitp_release_manifest", ROOT / AITP_RELEASE_MANIFEST)
    require(spec is not None and spec.loader is not None, "cannot load the AITP release manifest tool")
    module = importlib.util.module_from_spec(spec)
    # No bytecode cache inside the kernel directory (it must never name SAIAI).
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def verify_aitp_signing_keys(artifacts: list[Path]) -> None:
    """AITP release programs trust the maintainer's real update signing keys:
    the brand names no placeholder or unusable key, and every program
    carries each of the brand's keys and no placeholder."""
    if not artifacts:
        return
    tool = load_release_manifest()
    try:
        keys = tool.brand_keys()
        tool.require_real_keys(keys)
        # Every program carries all of the brand's keys and no placeholder.
        for artifact in artifacts:
            tool.require_program_keys(artifact, keys)
    except tool.CheckError as error:
        raise AssertionError(str(error)) from error


def verify_aitp_signed_manifest(manifest: Path, signature: Path | None, dist: Path, artifacts: list[Path]) -> None:
    """Before upload: the maintainer's signature over the AITP manifest
    verifies with a key the brand trusts (never a placeholder), the manifest
    matches the release assets in `dist`, and those assets (and the
    artifacts) carry the trusted keys."""
    tool = load_release_manifest()
    signature = signature or manifest.with_name(manifest.name + tool.SIGNATURE_SUFFIX)
    try:
        key = tool.verify_release(manifest, signature, dist, artifacts)
    except tool.CheckError as error:
        raise AssertionError(str(error)) from error
    print(f"{manifest} is signed by trusted key {key} and matches {len(artifacts)} AITP program(s)")


def aitp_brand_markers() -> list[bytes]:
    """Distinctive AITP brand strings (from its brand source) that only the
    AITP program carries; short or generic values are left out."""
    source = text(AITP_BRAND_SOURCE)
    values = re.findall(r'b?"((?:[^"\\]|\\.)*)"', source.split("#[cfg(test)]")[0])
    markers = sorted(
        {
            value
            for value in values
            if len(value) >= 10 and re.search(r"aitp|2742zdz", value, re.IGNORECASE)
        }
    )
    # Values are compared as raw bytes: escapes would not match the binary.
    require(
        not any("\\" in marker for marker in markers),
        f"AITP brand markers with escape sequences are not supported: {AITP_BRAND_SOURCE}",
    )
    require(len(markers) >= 10, f"too few AITP brand markers found in {AITP_BRAND_SOURCE}")
    require(
        "AITP local installation CA" in markers
        and "io.github.2742zdz.aitp.local-proxy" in markers,
        "AITP brand markers miss the CA and service identities",
    )
    return [marker.encode() for marker in markers]


def verify_artifacts_carry_no_aitp_brand(artifacts: list[Path]) -> None:
    """Built SAIAI programs contain none of the AITP distribution's data."""
    markers = aitp_brand_markers()
    for artifact in artifacts:
        require(artifact.is_file(), f"release artifact is missing: {artifact}")
        data = artifact.read_bytes()
        found = [marker.decode() for marker in markers if marker in data]
        require(not found, f"{artifact} carries AITP brand data: {found}")
    if artifacts:
        print(f"{len(artifacts)} release artifact(s) carry no AITP brand data")


OTHER_DISTRIBUTION_NAME = b"saiai"


# The neutral prefixes build-release.sh maps the build machine's paths to.
AITP_NEUTRAL_PREFIXES = ("/aitp/home", "/aitp/rustup", "/aitp/cargo", "/aitp/src", "/aitp/target")


def build_machine_paths(build_dirs: list[Path], environ) -> list[str]:
    """Absolute paths of the build machine that an AITP release program must
    not carry: the given build directories and the HOME, CARGO_HOME and
    RUSTUP_HOME (default under HOME) of the environment that built it, each
    also in its resolved form."""
    for directory in build_dirs:
        require(directory.is_absolute(), f"build directory is not absolute: {directory}")
    home = environ.get("HOME", "")
    candidates = [str(directory) for directory in build_dirs] + [
        home,
        environ.get("USERPROFILE", ""),
        environ.get("CARGO_HOME") or (home and str(Path(home) / ".cargo")),
        environ.get("RUSTUP_HOME") or (home and str(Path(home) / ".rustup")),
    ]
    paths = []
    for candidate in candidates:
        if not candidate:
            continue
        for form in (candidate, os.path.realpath(candidate)):
            form = form.rstrip("/\\")
            # The file system root (or a bare drive) would match every path.
            if re.fullmatch(r"(?:[A-Za-z]:)?", form) is None and form not in paths:
                paths.append(form)
    for path in paths:
        # A build path at or below /aitp, or a leading part of a neutral
        # prefix, cannot be told apart from the remapped paths.
        view = path_view(path.encode()).decode(errors="replace")
        require(
            not (view == "/aitp" or view.startswith("/aitp/"))
            and not any(prefix.startswith(view) for prefix in AITP_NEUTRAL_PREFIXES),
            f"build machine path {path} overlaps the neutral prefixes {AITP_NEUTRAL_PREFIXES}",
        )
    return paths


# What may follow a whole neutral prefix: a separator, the NUL that ends a C
# string, or the end of the data. Anything else (another file name byte, or
# the first byte of a string stored right after it) makes the occurrence an
# ordinary path, so a remapped directory that a following string happens to
# abut is reported rather than excused (a conservative false positive).
NEUTRAL_PREFIX_END = rb"(?=/|\x00|\Z)"


def names_path(view: bytes, path: str) -> bool:
    """Whether `view` (see `path_view`) holds `path` anywhere, as a plain
    substring (strings in a program sit next to each other without a
    separator, so no boundary is required). Only an occurrence that lies
    wholly inside a whole neutral prefix (see NEUTRAL_PREFIX_END), such as `/src` or `/home` inside `/aitp/src/…` or
    `/aitp/home/…`, is not counted: those bytes are the neutral prefix
    itself. `build_machine_paths` refuses build paths that could be mistaken
    for the prefixes (`/aitp/…`, `/ait`)."""
    neutral = {
        (match.start(), match.end())
        for prefix in AITP_NEUTRAL_PREFIXES
        for match in re.finditer(re.escape(prefix.encode()) + NEUTRAL_PREFIX_END, view)
    }
    needle = path_view(path.encode())
    start = view.find(needle)
    while start >= 0:
        end = start + len(needle)
        if not any(low <= start and end <= high for low, high in neutral):
            return True
        start = view.find(needle, start + 1)
    return False


def path_view(data: bytes) -> bytes:
    """`data` lower-cased with both path separators as `/`, so a path matches
    in any case and with either separator (Windows drive letters and
    extended-length prefixes included)."""
    return data.lower().replace(b"\\", b"/")


def verify_aitp_artifacts(artifacts: list[Path], build_dirs: list[Path], environ=os.environ) -> None:
    """Built AITP release programs carry the AITP brand data, never the other
    distribution's name, and no path of the machine that built them."""
    if not artifacts:
        return
    require(bool(build_dirs), "--aitp-artifact needs at least one --build-dir")
    markers = aitp_brand_markers()
    paths = build_machine_paths(build_dirs, environ)
    for artifact in artifacts:
        require(artifact.is_file(), f"AITP artifact is missing: {artifact}")
        data = artifact.read_bytes()
        missing = [marker.decode() for marker in markers if marker not in data]
        require(not missing, f"{artifact} lacks AITP brand data: {missing}")
        view = path_view(data)
        require(
            OTHER_DISTRIBUTION_NAME not in view,
            f"{artifact} names the other distribution",
        )
        found = [path for path in paths if names_path(view, path)]
        require(not found, f"{artifact} carries build machine paths: {found}")
    print(f"{len(artifacts)} AITP artifact(s) carry AITP brand data and no build machine path")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        type=Path,
        help="built SAIAI program that must not carry AITP brand data (repeatable)",
    )
    parser.add_argument(
        "--aitp-artifact",
        action="append",
        default=[],
        type=Path,
        help="built AITP release program to check (repeatable; needs --build-dir)",
    )
    parser.add_argument(
        "--aitp-manifest",
        type=Path,
        help="signed AITP release manifest to check before upload (needs --aitp-artifact and --aitp-dist)",
    )
    parser.add_argument("--aitp-signature", type=Path, help="its signature (default: MANIFEST.minisig)")
    parser.add_argument("--aitp-dist", type=Path, help="directory holding the AITP release assets")
    parser.add_argument(
        "--build-dir",
        action="append",
        default=[],
        type=Path,
        help="absolute build directory the AITP artifacts must not name (repeatable)",
    )
    arguments = parser.parse_args()
    if arguments.build_dir and not arguments.aitp_artifact:
        parser.error("--build-dir is only used with --aitp-artifact")
    if arguments.aitp_manifest is not None:
        if not arguments.aitp_artifact or arguments.aitp_dist is None:
            parser.error("--aitp-manifest needs --aitp-artifact and --aitp-dist")
    elif arguments.aitp_signature is not None or arguments.aitp_dist is not None:
        parser.error("--aitp-signature and --aitp-dist are only used with --aitp-manifest")
    verify_cli()
    verify_manifest_and_wrappers()
    verify_workflows_and_docs()
    verify_no_non_test_credentials()
    verify_artifacts_carry_no_aitp_brand(arguments.artifact)
    verify_aitp_artifacts(arguments.aitp_artifact, arguments.build_dir)
    verify_aitp_signing_keys(arguments.aitp_artifact)
    if arguments.aitp_manifest is not None:
        verify_aitp_signed_manifest(
            arguments.aitp_manifest, arguments.aitp_signature, arguments.aitp_dist, arguments.aitp_artifact
        )
    print("SAIAI local-proxy public release contract verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"SAIAI local-proxy release contract failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
