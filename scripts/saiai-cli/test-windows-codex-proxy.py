#!/usr/bin/env python3
"""Prove an official Windows Codex Responses request reaches the SAIAI proxy.

The fixture uses only synthetic credentials and a loopback Gateway. Provider
hostnames are temporarily pinned to loopback so a routing regression cannot
send the fixture prompt to an external service.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import urllib.parse


TEST_KEY = "TEST_ONLY_WINDOWS_CODEX_CAPTURE_KEY"
BLOCKED_PROVIDER_HOSTS = ("chatgpt.com", "api.openai.com", "ab.chatgpt.com")


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    responses_event = threading.Event()

    def _record(self) -> str:
        path = urllib.parse.urlsplit(self.path).path
        self.requests.append((self.command, path))
        return path

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        path = self._record()
        if path == "/v1/models":
            body = json.dumps({"object": "list", "data": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(426)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        path = self._record()
        if path == "/v1/responses":
            self.responses_event.set()
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        body = json.dumps(
            {"error": {"message": "TEST_ONLY_LOOPBACK_CAPTURE", "type": "test"}}
        ).encode()
        self.send_response(401 if path == "/v1/responses" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def run(command: list[str], env: dict[str, str], cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--saiai", required=True, type=Path)
    parser.add_argument("--codex-prefix", required=True, type=Path)
    parser.add_argument("--codex-version", required=True)
    args = parser.parse_args()

    saiai = args.saiai.resolve()
    codex_prefix = args.codex_prefix.resolve()
    hosts_path = Path(os.environ["SystemRoot"]) / "System32/drivers/etc/hosts"
    original_hosts = hosts_path.read_bytes()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        with hosts_path.open("ab") as hosts:
            hosts.write(b"\n# BEGIN SAIAI CODEX TEST\n")
            for host in BLOCKED_PROVIDER_HOSTS:
                hosts.write(f"127.0.0.1 {host}\n::1 {host}\n".encode())
            hosts.write(b"# END SAIAI CODEX TEST\n")

        with tempfile.TemporaryDirectory(prefix="saiai-windows-codex-proxy-") as temporary:
            root = Path(temporary)
            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(root / "home"),
                    "USERPROFILE": str(root / "home"),
                    "LOCALAPPDATA": str(root / "local-app-data"),
                    "CODEX_HOME": str(root / "codex"),
                    "SAIAI_HOME": str(root / "saiai"),
                    "PATH": str(codex_prefix) + os.pathsep + env.get("PATH", ""),
                }
            )
            init = run(
                [
                    str(saiai),
                    "init-codex",
                    f"http://127.0.0.1:{server.server_port}/v1",
                    TEST_KEY,
                ],
                env,
                root,
            )
            if init.returncode != 0:
                raise RuntimeError("SAIAI init-codex failed in the Windows capture fixture")

            capture = subprocess.Popen(
                [
                    str(saiai),
                    "codex",
                    "--",
                    "exec",
                    "--skip-git-repo-check",
                    "--ephemeral",
                    "-m",
                    "gpt-5.1",
                    "TEST_ONLY_PROXY_ROUTING_PROBE",
                ],
                cwd=root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 60
            while (
                time.monotonic() < deadline
                and not CaptureHandler.responses_event.is_set()
                and capture.poll() is None
            ):
                time.sleep(0.1)
            capture_exit = capture.poll()
            try:
                if capture_exit is None:
                    subprocess.run(
                        ["taskkill", "/PID", str(capture.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                        check=False,
                    )
                    capture.wait(timeout=15)
            finally:
                run([str(saiai), "stop"], env, root, timeout=15)

            paths = list(CaptureHandler.requests)
            if not CaptureHandler.responses_event.is_set():
                raise AssertionError(
                    f"Codex {args.codex_version} did not send Responses through the loopback Gateway; "
                    f"captured method/path pairs: {paths!r}; exit={capture_exit}"
                )
            auth = json.loads((root / "codex/auth.json").read_text(encoding="utf-8"))
            if auth.get("auth_mode") != "chatgptAuthTokens":
                raise AssertionError("Codex capture did not use external ChatGPT token mode")

            print(
                f"PASS: official Codex {args.codex_version} reached /v1/responses through the "
                "Windows SAIAI child proxy environment"
            )
            return 0
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        hosts_path.write_bytes(original_hosts)


if __name__ == "__main__":
    raise SystemExit(main())
