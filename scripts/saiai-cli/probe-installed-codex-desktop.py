#!/usr/bin/env python3
"""Validate a SAIAI candidate against an installed Codex Desktop app-server.

The probe uses an isolated temporary HOME/CODEX_HOME/SAIAI_HOME, synthetic
credentials, and a loopback-only mock Gateway.  It exercises only app-server
initialization and ``account/read``; it never starts a model turn.
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
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
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
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def probe(saiai: Path, app_server_override: Path | None) -> dict[str, Any]:
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
    try:
        with tempfile.TemporaryDirectory(prefix="saiai-desktop-field-") as temporary:
            root = Path(temporary)
            home = root / "home"
            codex_home = root / "codex"
            saiai_home = root / "saiai"
            for directory in (home, codex_home, saiai_home):
                directory.mkdir(parents=True)
            copied_app_server = root / ("codex.exe" if os.name == "nt" else "codex")
            shutil.copy2(source_app_server, copied_app_server)
            copied_app_server.chmod(0o700)

            env = os.environ.copy()
            for name in (
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "OPENAI_API_BASE",
                "CODEX_ACCESS_TOKEN",
                "CODEX_CA_CERTIFICATE",
                "SSL_CERT_FILE",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "NO_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "no_proxy",
            ):
                env.pop(name, None)
            env.update(
                {
                    "HOME": str(home),
                    "USERPROFILE": str(home),
                    "CODEX_HOME": str(codex_home),
                    "SAIAI_HOME": str(saiai_home),
                }
            )
            init_env = env.copy()
            init_env["SAIAI_SKIP_START"] = "1"
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
                send({"method": "initialized"})
                send(
                    {
                        "id": 2,
                        "method": "account/read",
                        "params": {"refreshToken": False},
                    }
                )
                account = validate_account_response(read_response(messages, 2, 30))

            assert app_server is not None and proxy is not None
            terminate_process_tree(app_server)
            app_server = None
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
            saiai_version = run([str(saiai), "--version"], env=env, cwd=root).stdout.strip()
            app_server_version = run(
                [str(copied_app_server), "--version"], env=env, cwd=root
            ).stdout.strip()
            return {
                "schema_version": 1,
                "result": "pass",
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
                },
                "control_plane": {
                    "initialize": "pass",
                    "account_read": "pass",
                    "auth_mode": account["auth_mode"],
                    "backend_origin": account["backend_origin"],
                    "account_routing_override": account[
                        "account_routing_override"
                    ],
                    "candidate_sidecar_observed": True,
                },
                "loopback_gateway_requests": len(LoopbackGateway.requests),
                "real_provider_requests": 0,
                "real_model_requests": 0,
                "temporary_state_removed": True,
            }
    finally:
        if app_server is not None:
            terminate_process_tree(app_server)
        if proxy is not None:
            terminate_process_tree(proxy)
        gateway.shutdown()
        gateway.server_close()
        gateway_thread.join(timeout=5)


def main() -> int:
    args = parse_args()
    try:
        result = probe(args.saiai, args.app_server)
    except (OSError, ProbeError, subprocess.SubprocessError, ValueError) as error:
        if args.json:
            print(
                json.dumps(
                    {
                        "schema_version": 1,
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
