#!/usr/bin/env python3
"""Prove an official Codex Responses request reaches the SAIAI proxy.

The fixture uses only synthetic credentials and a loopback Gateway. Provider
hostnames are temporarily pinned to loopback so a routing regression cannot
send the fixture prompt to an external service.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import platform
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse


TEST_KEY = "TEST_ONLY_CODEX_CAPTURE_KEY"
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


def process_group_options() -> dict[str, object]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
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


def write_hosts(path: Path, content: bytes) -> None:
    if os.name == "nt":
        path.write_bytes(content)
        return
    subprocess.run(
        ["sudo", "tee", str(path)],
        input=content,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=True,
    )


def wait_for_proxy(process: subprocess.Popen[bytes], port: int = 19908) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("SAIAI foreground proxy exited during startup")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("SAIAI foreground proxy did not start")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--saiai", required=True, type=Path)
    parser.add_argument("--codex-prefix", required=True, type=Path)
    parser.add_argument("--codex-version", required=True)
    args = parser.parse_args()

    saiai = args.saiai.resolve()
    codex_prefix = args.codex_prefix.resolve()
    hosts_path = (
        Path(os.environ["SystemRoot"]) / "System32/drivers/etc/hosts"
        if os.name == "nt"
        else Path("/etc/hosts")
    )
    original_hosts = hosts_path.read_bytes()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        hosts_block = bytearray(b"\n# BEGIN SAIAI CODEX TEST\n")
        for host in BLOCKED_PROVIDER_HOSTS:
            hosts_block.extend(f"127.0.0.1 {host}\n::1 {host}\n".encode())
        hosts_block.extend(b"# END SAIAI CODEX TEST\n")
        write_hosts(hosts_path, original_hosts + hosts_block)

        with tempfile.TemporaryDirectory(prefix="saiai-codex-proxy-") as temporary:
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
                raise RuntimeError("SAIAI init-codex failed in the capture fixture")

            config = json.loads((root / "saiai" / "config.json").read_text())
            listen = urllib.parse.urlsplit("//" + config["listen"])
            proxy_port = listen.port
            if proxy_port is None:
                raise RuntimeError("SAIAI init-codex wrote an invalid listen address")

            proxy = subprocess.Popen(
                [str(saiai), "--verbose"],
                cwd=root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **process_group_options(),
            )
            wait_for_proxy(proxy, proxy_port)
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
                **process_group_options(),
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
                    terminate_process_tree(capture)
            finally:
                terminate_process_tree(proxy)

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
                f"{platform.system()} SAIAI child proxy environment"
            )
            return 0
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        write_hosts(hosts_path, original_hosts)


if __name__ == "__main__":
    raise SystemExit(main())
