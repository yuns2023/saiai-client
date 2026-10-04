#!/usr/bin/env python3
"""Validate a SAIAI candidate against an installed Codex Desktop app-server.

The probe uses an isolated temporary HOME/CODEX_HOME/SAIAI_HOME, synthetic
credentials, and a loopback-only mock Gateway. By default it exercises
initialization, ``getAuthStatus``, and ``account/read``. The optional storage
fixture also lists, reads, resumes and reopens synthetic history, with an
authenticated empty-home negative control; it never starts a model turn.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import platform
import plistlib
import queue
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any


TEST_KEY = "TEST_ONLY_CODEX_DESKTOP_FIELD_PROBE"
EXPECTED_ROUTING_OVERRIDE = "NO_CONSTRAINT"


class ProbeError(RuntimeError):
    pass


class LoopbackGateway(http.server.BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []

    def _path(self) -> str:
        path = urllib.parse.urlsplit(self.path).path
        type(self).requests.append((self.command, path))
        return path

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        path = self._path()
        if path == "/v1/models":
            body = b'{"object":"list","data":[]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._path()
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        body = b'{"error":{"type":"test_only","message":"model requests are forbidden"}}'
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--saiai", required=True, type=Path)
    parser.add_argument(
        "--app-server",
        type=Path,
        help="Override automatic discovery of the installed Desktop app-server",
    )
    parser.add_argument("--json", action="store_true", help="Emit one JSON result")
    parser.add_argument("--storage-fixture", action="store_true", help="Also list/read/resume synthetic history without starting a model turn")
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sanitized_version(output: str, prefix: str) -> str:
    pattern = re.compile(rf"^{re.escape(prefix)} [0-9A-Za-z][0-9A-Za-z.+_-]*$")
    matches = [line.strip() for line in output.splitlines() if pattern.fullmatch(line.strip())]
    if len(matches) != 1:
        raise ProbeError(f"could not parse {prefix} version output")
    return matches[0]


def run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        env=env,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def process_group_options() -> dict[str, object]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def terminate_process_tree(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        process.wait(timeout=15)
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def windows_desktop_app_server() -> tuple[Path, str, str]:
    script = r"""
$packages = @()
foreach ($name in @('OpenAI.Codex', 'OpenAI.ChatGPT')) {
  $packages += @(Get-AppxPackage $name -ErrorAction SilentlyContinue)
}
$package = $packages | Sort-Object Version -Descending | Select-Object -First 1
if ($null -eq $package) { exit 3 }
$candidate = Join-Path $package.InstallLocation 'app\resources\codex.exe'
if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { exit 4 }
@{
  path = $candidate
  identity = $package.Name
  version = [string]$package.Version
} | ConvertTo-Json -Compress
"""
    result = run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
    )
    if result.returncode != 0:
        raise ProbeError("installed OpenAI Codex Desktop app-server was not found")
    try:
        document = json.loads(result.stdout.strip().splitlines()[-1])
        path = Path(document["path"])
        identity = str(document["identity"])
        version = str(document["version"])
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ProbeError("could not parse Windows Desktop package metadata") from error
    return path, identity, version


def macos_desktop_app_server(
    home: Path | None = None, system_applications: Path = Path("/Applications")
) -> tuple[Path, str, str]:
    homes = [(home or Path.home()) / "Applications", system_applications]
    for directory in homes:
        for name in ("Codex.app", "ChatGPT.app"):
            bundle = directory / name
            info = bundle / "Contents/Info.plist"
            if not info.is_file():
                continue
            try:
                metadata = plistlib.loads(info.read_bytes())
            except (OSError, plistlib.InvalidFileException):
                continue
            identifier = str(metadata.get("CFBundleIdentifier", ""))
            if identifier != "com.openai.codex":
                continue
            version = str(
                metadata.get("CFBundleShortVersionString")
                or metadata.get("CFBundleVersion")
                or "unknown"
            )
            resources = bundle / "Contents/Resources"
            exact = resources / "codex"
            if exact.is_file():
                return exact, identifier, version
            candidates = sorted(
                path
                for path in resources.glob("codex*")
                if path.is_file() and os.access(path, os.X_OK)
            )
            if candidates:
                return candidates[0], identifier, version
    raise ProbeError("installed signed com.openai.codex Desktop app-server was not found")


def discover_app_server(override: Path | None) -> tuple[Path, str, str]:
    if override is not None:
        path = override.resolve(strict=True)
        return path, "operator-override", "unknown"
    if os.name == "nt":
        return windows_desktop_app_server()
    if platform.system() == "Darwin":
        return macos_desktop_app_server()
    raise ProbeError("automatic installed Desktop discovery supports Windows and macOS")


def wait_for_proxy(process: subprocess.Popen[Any], listen: str) -> None:
    parsed = urllib.parse.urlsplit("//" + listen)
    if parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ProbeError("candidate wrote a non-loopback or invalid listen address")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ProbeError("candidate proxy exited during startup")
        try:
            with socket.create_connection((parsed.hostname, parsed.port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise ProbeError("candidate proxy did not become reachable")


def read_response(
    output: queue.Queue[dict[str, Any]], request_id: int, timeout: float
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            message = output.get(timeout=min(0.5, deadline - time.monotonic()))
        except queue.Empty:
            continue
        if message.get("id") == request_id:
            return message
    raise ProbeError(f"app-server did not answer request {request_id}")


def validate_account_response(response: dict[str, Any]) -> dict[str, str]:
    if "error" in response:
        message = response.get("error", {}).get("message", "unknown account/read error")
        raise ProbeError(f"account/read failed: {message}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ProbeError("account/read returned no result object")
    account = result.get("account")
    if not isinstance(account, dict) or account.get("type") != "chatgpt":
        raise ProbeError("account/read did not report ChatGPT login mode")
    routing = result.get("workspaceRouting")
    if not isinstance(routing, dict):
        raise ProbeError("account/read returned no workspace routing")
    backend_origin = routing.get("backendOrigin")
    parsed = urllib.parse.urlsplit(str(backend_origin))
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProbeError("account/read returned an invalid workspace backend origin")
    override = routing.get("accountRoutingOverride")
    if override != EXPECTED_ROUTING_OVERRIDE:
        raise ProbeError("account/read returned an unexpected routing override")
    return {
        "auth_mode": "chatgpt",
        "backend_origin": f"{parsed.scheme}://{parsed.hostname}",
        "account_routing_override": str(override),
    }


def validate_auth_status_response(response: dict[str, Any]) -> str:
    if "error" in response:
        message = response.get("error", {}).get("message", "unknown getAuthStatus error")
        raise ProbeError(f"getAuthStatus failed: {message}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ProbeError("getAuthStatus returned no result object")
    auth_method = result.get("authMethod")
    if auth_method != "chatgptAuthTokens":
        raise ProbeError("getAuthStatus did not report external ChatGPT token mode")
    return auth_method


def account_shape(response: dict[str, Any]) -> dict[str, bool]:
    result = response.get("result")
    has_result = isinstance(result, dict)
    if not isinstance(result, dict):
        result = {}
    account = result.get("account")
    return {
        "result_object": has_result,
        "chatgpt_account": isinstance(account, dict) and account.get("type") == "chatgpt",
        "workspace_routing_object": isinstance(result.get("workspaceRouting"), dict),
        "rpc_error": "error" in response,
    }


def isolated_environment(root: Path, inherited: dict[str, str]) -> dict[str, str]:
    allowed = {
        "PATH": "PATH", "SYSTEMROOT": "SystemRoot", "WINDIR": "WINDIR",
        "COMSPEC": "COMSPEC", "PATHEXT": "PATHEXT", "LANG": "LANG", "LC_ALL": "LC_ALL",
    }
    env = {
        allowed[name.upper()]: value
        for name, value in inherited.items() if name.upper() in allowed
    }
    directories = {
        "HOME": root / "home", "USERPROFILE": root / "home",
        "CODEX_HOME": root / "codex", "SAIAI_HOME": root / "saiai",
        "APPDATA": root / "home/AppData/Roaming",
        "LOCALAPPDATA": root / "home/AppData/Local",
        "TEMP": root / "tmp", "TMP": root / "tmp", "TMPDIR": root / "tmp",
    }
    for name, directory in directories.items():
        directory.mkdir(parents=True, exist_ok=True)
        env[name] = str(directory)
    return env


def copy_app_server(source: Path, root: Path) -> Path:
    name = "codex-app-server.exe" if os.name == "nt" or source.suffix == ".exe" else "codex-app-server"
    destination = root / name
    shutil.copy2(source, destination)
    destination.chmod(0o700)
    return destination


def seed_storage_fixture(codex_home: Path, cwd: Path, version: str) -> tuple[str, str]:
    thread_id = str(uuid.uuid4())
    answer = "SAIAI synthetic stored assistant; no model was called."
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    directory = codex_home / "sessions" / timestamp[:4] / timestamp[5:7] / timestamp[8:10]
    directory.mkdir(parents=True)
    records = [
        {"type": "session_meta", "payload": {
            "id": thread_id, "session_id": thread_id, "timestamp": timestamp,
            "cwd": str(cwd), "originator": "codex_cli_rs", "cli_version": version,
            "source": "cli", "model_provider": "openai",
            "base_instructions": {"text": "Synthetic storage test only."},
        }},
        {"type": "event_msg", "payload": {"type": "task_started", "turn_id": str(uuid.uuid4()),
            "model_context_window": 258400, "collaboration_mode_kind": "default"}},
        {"type": "response_item", "payload": {"type": "message", "role": "user",
            "content": [{"type": "input_text", "text": "SAIAI synthetic history fixture"}]}},
        {"type": "event_msg", "payload": {"type": "user_message", "message": "SAIAI synthetic history fixture",
            "images": [], "local_images": [], "text_elements": []}},
        {"type": "response_item", "payload": {"type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": answer}]}},
        {"type": "event_msg", "payload": {"type": "agent_message", "message": answer}},
        {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": answer}},
    ]
    rollout = directory / f"rollout-{timestamp[:-1].replace(':', '-')}-{thread_id}.jsonl"
    rollout.write_text("".join(json.dumps({"timestamp": timestamp, **record}) + "\n" for record in records), encoding="utf-8")
    return thread_id, answer


def storage_checks(listed: dict[str, Any], read: dict[str, Any], resumed: dict[str, Any],
                   thread_id: str, answer: str) -> dict[str, bool]:
    def result_object(response: dict[str, Any]) -> dict[str, Any]:
        result = response.get("result")
        return result if isinstance(result, dict) else {}
    def thread_object(response: dict[str, Any]) -> dict[str, Any]:
        thread = result_object(response).get("thread")
        return thread if isinstance(thread, dict) else {}
    def has_assistant(response: dict[str, Any]) -> bool:
        turns = thread_object(response).get("turns")
        if not isinstance(turns, list):
            return False
        for turn in turns:
            items = turn.get("items") if isinstance(turn, dict) else None
            if isinstance(items, list) and any(
                isinstance(item, dict) and item.get("type") == "agentMessage" and item.get("text") == answer
                for item in items
            ):
                return True
        return False
    threads = result_object(listed).get("data")
    return {
        "history_listed": isinstance(threads, list) and any(
            isinstance(thread, dict) and thread.get("id") == thread_id for thread in threads),
        "history_readable": isinstance(read.get("result"), dict) and "error" not in read,
        "assistant_text_restored": has_assistant(read),
        "resume_control_plane": "result" in resumed and "error" not in resumed,
        "resumed_thread_matches": thread_object(resumed).get("id") == thread_id,
        "resumed_assistant_text_restored": has_assistant(resumed),
    }


def storage_session(binary: Path, env: dict[str, str], cwd: Path,
                    thread_id: str, answer: str, *, empty_home: bool) -> dict[str, bool]:
    process = subprocess.Popen([str(binary), "app-server"], env=env, cwd=cwd,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="replace", **process_group_options())
    reader: threading.Thread | None = None
    try:
        if process.stdin is None or process.stdout is None:
            raise ProbeError("storage app-server pipes were not created")
        messages: queue.Queue[dict[str, Any]] = queue.Queue()
        def collect() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(message, dict):
                    messages.put(message)
        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        def request(request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
            if method not in {"initialize", "getAuthStatus", "account/read", "thread/list", "thread/read", "thread/resume"}:
                raise ProbeError("storage probe forbids model or mutation RPCs")
            assert process.stdin is not None
            process.stdin.write(json.dumps({"id": request_id, "method": method, "params": params}) + "\n")
            process.stdin.flush()
            return read_response(messages, request_id, 20)
        initialized = request(1, "initialize", {"clientInfo": {"name": "Codex Desktop", "version": "SAIAI_STORAGE_PROBE"},
            "capabilities": {"experimentalApi": True}})
        if "result" not in initialized:
            raise ProbeError("storage app-server initialize failed")
        process.stdin.write('{"method":"initialized"}\n')
        process.stdin.flush()
        validate_auth_status_response(request(2, "getAuthStatus", {"includeToken": False, "refreshToken": False}))
        validate_account_response(request(3, "account/read", {"refreshToken": False}))
        listed = request(4, "thread/list", {"limit": 100, "modelProviders": [],
            "sourceKinds": ["exec", "cli", "appServer", "vscode"]})
        read = request(5, "thread/read", {"threadId": thread_id, "includeTurns": True})
        if empty_home:
            checks = storage_checks(listed, read, {}, thread_id, answer)
            return {"authenticated_empty_home": True, "list_succeeded": isinstance(listed.get("result"), dict),
                "fixture_not_listed": not checks["history_listed"], "fixture_read_rejected": isinstance(read.get("error"), dict)}
        resumed = request(6, "thread/resume", {"threadId": thread_id})
        return {"authenticated_reopen": True, **storage_checks(listed, read, resumed, thread_id, answer)}
    finally:
        terminate_process_tree(process)
        if reader is not None:
            reader.join(timeout=2)
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()


def probe(
    saiai: Path,
    app_server_override: Path | None,
    *,
    diagnostics: dict[str, Any] | None = None,
    storage_fixture: bool = False,
) -> dict[str, Any]:
    observations = diagnostics if diagnostics is not None else {}
    stages = {
        "initialize": "not_tested",
        "get_auth_status": "not_tested",
        "account_read": "not_tested",
    }
    observations.update({
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "control_plane": stages,
        "real_provider_requests": 0,
        "real_model_requests": 0,
        "temporary_state_removed": False,
        "probe_sha256": sha256(Path(__file__)),
    })
    saiai = saiai.resolve(strict=True)
    if not saiai.is_file():
        raise ProbeError("SAIAI candidate is not a regular file")
    source_app_server, package_identity, package_version = discover_app_server(
        app_server_override
    )
    LoopbackGateway.requests = []
    gateway = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LoopbackGateway)
    gateway_thread = threading.Thread(target=gateway.serve_forever, daemon=True)
    gateway_thread.start()
    proxy: subprocess.Popen[Any] | None = None
    app_server: subprocess.Popen[Any] | None = None
    temporary_root: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="saiai-desktop-field-") as temporary:
            root = Path(temporary)
            temporary_root = root
            home = root / "home"
            codex_home = root / "codex"
            saiai_home = root / "saiai"
            for directory in (home, codex_home, saiai_home):
                directory.mkdir(parents=True)
            copied_app_server = copy_app_server(source_app_server, root)

            env = isolated_environment(root, dict(os.environ))
            observations["environment_isolation"] = "allowlisted-system-variables-and-temporary-profiles"
            init_env = env.copy()
            init_env["SAIAI_SKIP_START"] = "1"
            saiai_version = sanitized_version(
                run([str(saiai), "--version"], env=init_env, cwd=root).stdout,
                "saiai",
            )
            app_server_version = sanitized_version(
                run([str(copied_app_server), "--version"], env=init_env, cwd=root).stdout,
                "codex-cli",
            )
            observations["saiai"] = {"version": saiai_version, "sha256": sha256(saiai)}
            observations["desktop"] = {
                "package_identity": package_identity,
                "package_version": package_version,
                "app_server_version": app_server_version,
                "app_server_sha256": sha256(copied_app_server),
            }
            init = run(
                [
                    str(saiai),
                    "init-codex",
                    f"http://127.0.0.1:{gateway.server_port}/v1",
                    TEST_KEY,
                ],
                env=init_env,
                cwd=root,
            )
            if init.returncode != 0:
                raise ProbeError("candidate init-codex failed in the isolated home")
            config = json.loads((saiai_home / "config.json").read_text(encoding="utf-8"))
            ca_path = Path(config["ca_cert_path"])
            listen = str(config["listen"])
            proxy_url = f"http://{listen}"
            managed_env = {
                "CODEX_CA_CERTIFICATE": str(ca_path),
                "SSL_CERT_FILE": str(ca_path),
                "HTTP_PROXY": proxy_url,
                "HTTPS_PROXY": proxy_url,
                "ALL_PROXY": proxy_url,
                "NO_PROXY": "localhost,127.0.0.1,::1",
                "http_proxy": proxy_url,
                "https_proxy": proxy_url,
                "all_proxy": proxy_url,
                "no_proxy": "localhost,127.0.0.1,::1",
            }
            env.update(managed_env)
            fixture = seed_storage_fixture(codex_home, root, app_server_version.split(" ", 1)[1]) if storage_fixture else None
            fixture_hashes = {
                filename: sha256(codex_home / filename) for filename in ("config.toml", "auth.json", ".env")
            } if storage_fixture else {}

            proxy_log_path = root / "proxy.log"
            app_stderr_path = root / "app-server.log"
            with proxy_log_path.open("wb") as proxy_log, app_stderr_path.open(
                "wb"
            ) as app_stderr:
                proxy = subprocess.Popen(
                    [str(saiai), "--verbose"],
                    env=env,
                    cwd=root,
                    stdin=subprocess.DEVNULL,
                    stdout=proxy_log,
                    stderr=proxy_log,
                    **process_group_options(),
                )
                wait_for_proxy(proxy, listen)
                app_server = subprocess.Popen(
                    [str(copied_app_server), "app-server"],
                    env=env,
                    cwd=root,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=app_stderr,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    **process_group_options(),
                )
                if app_server.stdin is None or app_server.stdout is None:
                    raise ProbeError("app-server pipes were not created")
                messages: queue.Queue[dict[str, Any]] = queue.Queue()

                def collect_stdout() -> None:
                    assert app_server is not None and app_server.stdout is not None
                    for line in app_server.stdout:
                        try:
                            message = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(message, dict):
                            messages.put(message)

                threading.Thread(target=collect_stdout, daemon=True).start()

                def send(message: dict[str, Any]) -> None:
                    assert app_server is not None and app_server.stdin is not None
                    app_server.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
                    app_server.stdin.flush()

                send(
                    {
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "clientInfo": {
                                "name": "Codex Desktop",
                                "title": "Codex",
                                "version": "SAIAI_FIELD_PROBE",
                            },
                            "capabilities": {"experimentalApi": True},
                        },
                    }
                )
                initialize = read_response(messages, 1, 20)
                if "result" not in initialize:
                    raise ProbeError("app-server initialize failed")
                stages["initialize"] = "pass"
                send({"method": "initialized"})
                send(
                    {
                        "id": 2,
                        "method": "getAuthStatus",
                        "params": {"includeToken": False, "refreshToken": False},
                    }
                )
                auth_method = validate_auth_status_response(
                    read_response(messages, 2, 30)
                )
                stages["get_auth_status"] = "pass"
                stages["auth_method"] = auth_method
                send(
                    {
                        "id": 3,
                        "method": "account/read",
                        "params": {"refreshToken": False},
                    }
                )
                account_response = read_response(messages, 3, 30)
                observations["account_shape"] = account_shape(account_response)
                stages["account_read"] = "fail"
                account = validate_account_response(account_response)
                stages["account_read"] = "pass"
                if fixture is not None:
                    thread_id, answer = fixture
                    def request_storage(request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
                        send({"id": request_id, "method": method, "params": params})
                        return read_response(messages, request_id, 20)
                    listed = request_storage(4, "thread/list", {"limit": 100, "modelProviders": [],
                        "sourceKinds": ["exec", "cli", "appServer", "vscode"]})
                    read = request_storage(5, "thread/read", {"threadId": thread_id, "includeTurns": True})
                    resumed = request_storage(6, "thread/resume", {"threadId": thread_id})
                    checks = storage_checks(listed, read, resumed, thread_id, answer)
                    checks["profile_config_auth_env_unchanged"] = all(
                        sha256(codex_home / filename) == expected for filename, expected in fixture_hashes.items()
                    )
                    observations["storage"] = checks
                    if not all(checks.values()):
                        raise ProbeError("synthetic storage fixture failed list/read/resume acceptance")

            assert app_server is not None and proxy is not None
            terminate_process_tree(app_server)
            app_server = None
            if fixture is not None:
                thread_id, answer = fixture
                reopened = storage_session(copied_app_server, env, root, thread_id, answer, empty_home=False)
                empty_codex = root / "empty-codex"
                empty_codex.mkdir()
                for filename in fixture_hashes:
                    shutil.copy2(codex_home / filename, empty_codex / filename)
                negative = storage_session(copied_app_server, {**env, "CODEX_HOME": str(empty_codex)},
                    root, thread_id, answer, empty_home=True)
                observations["storage_reopen"] = reopened
                observations["storage_negative_control"] = negative
                observations["storage"]["profile_config_auth_env_unchanged"] = all(
                    sha256(codex_home / filename) == expected for filename, expected in fixture_hashes.items()
                )
                if not all(reopened.values()) or not all(negative.values()) or not all(observations["storage"].values()):
                    raise ProbeError("synthetic storage reopen or negative control failed acceptance")
            terminate_process_tree(proxy)
            proxy = None
            proxy_log = proxy_log_path.read_text(encoding="utf-8", errors="replace")
            if "chatgpt account sidecar response" not in proxy_log:
                raise ProbeError("candidate proxy did not record an account sidecar response")
            model_requests = sum(
                method == "POST" for method, _path in LoopbackGateway.requests
            )
            if model_requests:
                raise ProbeError("field probe unexpectedly attempted a model request")
            return {
                "schema_version": 1,
                "result": "pass",
                "probe_sha256": observations["probe_sha256"],
                "platform": platform.system().lower(),
                "architecture": platform.machine().lower(),
                "saiai": {
                    "version": saiai_version,
                    "sha256": sha256(saiai),
                },
                "desktop": {
                    "package_identity": package_identity,
                    "package_version": package_version,
                    "app_server_version": app_server_version,
                    "app_server_sha256": observations["desktop"]["app_server_sha256"],
                },
                "control_plane": {
                    "initialize": "pass",
                    "get_auth_status": "pass",
                    "account_read": "pass",
                    "auth_mode": account["auth_mode"],
                    "auth_method": auth_method,
                    "backend_origin": account["backend_origin"],
                    "account_routing_override": account[
                        "account_routing_override"
                    ],
                    "candidate_sidecar_observed": True,
                },
                "loopback_gateway_requests": len(LoopbackGateway.requests),
                "mock_model_requests_attempted": model_requests,
                "real_provider_requests": 0,
                "real_model_requests": 0,
                "temporary_state_removed": True,
                **({"storage": observations["storage"], "storage_reopen": observations["storage_reopen"],
                    "storage_negative_control": observations["storage_negative_control"],
                    "resume_model_turn_started": False} if storage_fixture else {}),
            }
    finally:
        if app_server is not None:
            terminate_process_tree(app_server)
        if proxy is not None:
            terminate_process_tree(proxy)
        gateway.shutdown()
        gateway.server_close()
        gateway_thread.join(timeout=5)
        observations["loopback_gateway_requests"] = len(LoopbackGateway.requests)
        observations["mock_model_requests_attempted"] = sum(
            method == "POST" for method, _path in LoopbackGateway.requests
        )
        observations["temporary_state_removed"] = (
            temporary_root is not None and not temporary_root.exists()
        )


def main() -> int:
    args = parse_args()
    diagnostics: dict[str, Any] = {}
    try:
        result = probe(args.saiai, args.app_server, diagnostics=diagnostics, storage_fixture=args.storage_fixture)
    except (OSError, ProbeError, subprocess.SubprocessError, ValueError) as error:
        if args.json:
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        **diagnostics,
                        "result": "fail",
                        "error": str(error),
                        "real_model_requests": 0,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        else:
            print(f"FAIL: {error}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            "PASS: installed Codex Desktop app-server accepted the isolated "
            f"SAIAI candidate ({result['desktop']['app_server_version']}); "
            "real_model_requests=0"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
