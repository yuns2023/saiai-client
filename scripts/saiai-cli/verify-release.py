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
    source = text("tools/saiai-cli/src/claude_launcher.rs")
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
    require('version = "1.1.59"' in cargo, "CLI version is not 1.1.59")
    require("saiai-core" not in cargo, "local-proxy client still links the V2 runtime core")
    for dependency in ("reqwest", "tokio", "tokio-tungstenite", "rustls", "rcgen", "zeroize", "libc"):
        require(dependency in cargo, f"local-proxy dependency is missing: {dependency}")

    require(
        '[lib]\nname = "proxy_cli"\npath = "src/lib.rs"' in cargo
        and '[[bin]]\nname = "saiai"\npath = "src/main.rs"' in cargo,
        "CLI must build the saiai binary from the shared client library",
    )
    # The binary only supplies the SAIAI brand and release facts; the client
    # lives in lib.rs.
    entry = text("tools/saiai-cli/src/main.rs")
    for required in (
        "mod brand_saiai;",
        "proxy_cli::run(\n        &brand_saiai::SAIAI_BRAND,\n        proxy_cli::RuntimeContext {",
        'version: env!("CARGO_PKG_VERSION"),',
        "gateway: &proxy_cli::gateway_saiai::SAIAI_GATEWAY,",
    ):
        require(required in entry, f"CLI entry point is missing {required!r}")
    for withdrawn in WITHDRAWN_V2_MARKERS:
        require(withdrawn not in entry, f"CLI entry point exposes withdrawn V2 behavior: {withdrawn}")

    main = text("tools/saiai-cli/src/lib.rs")
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
    require(not (ROOT / "tools/saiai-cli/src/v2.rs").exists(), "V2 CLI module still exists")
    proxy = text("tools/saiai-cli/src/local_proxy.rs")
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


def verify_workflows_and_docs() -> None:
    release = text(".github/workflows/saiai-cli-release.yml")
    ci = text(".github/workflows/ci.yml")
    for path in (".github/workflows/ci.yml", ".github/workflows/saiai-cli-release.yml", "scripts/git-hooks/pre-push"):
        require(
            "python3 scripts/saiai-cli/test-release-contract.py" in text(path),
            f"{path} does not run the optional Claude contract regressions",
        )
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
    for workflow in (ci, release):
        for required in ("build-linux.sh", "linux-libc-dev", "test-linux-entropy.py"):
            require(required in workflow, f"Linux entropy contract is missing {required!r}")
        require(
            "test-windows-codex-proxy.py" in workflow
            and '"0.146.0", "0.153.4"' in workflow,
            "Windows workflows do not capture both supported official Codex versions",
        )
        require(
            "Capture official macOS Codex through local proxy" in workflow
            and 'codex-prefix "$prefix/bin"' in workflow,
            "macOS workflows do not capture the official Apple Silicon Codex client",
        )
    require(
        "Smoke-test Windows PowerShell 5.1 setup wrapper" in ci
        and "test-windows-release.ps1" in ci,
        "source CI does not execute the Windows PowerShell 5.1 setup-wrapper smoke",
    )
    require(
        "test-windows-self-update.py" in ci and "test-windows-self-update.py" in release,
        "Windows self-update smoke must run in source CI and release workflow",
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
