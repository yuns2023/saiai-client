#!/usr/bin/env python3
"""Probe official Codex 0.162.1 daemon refresh in a temporary home, without turns."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Control:
    def __init__(self, home):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(10)
        # Resolve Codex's short-path symlink before connecting on Unix.
        path = home / "app-server-control/app-server-control.sock"
        self.socket.connect(str(path.resolve()))
        key = base64.b64encode(os.urandom(16)).decode()
        self.socket.sendall((
            "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n\r\n"
        ).encode())
        headers = b""
        while not headers.endswith(b"\r\n\r\n"):
            headers += self.exact(1)
            assert len(headers) < 16384
        assert headers.startswith(b"HTTP/1.1 101")
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        ).digest())
        assert accept in headers
        self.request_id = 0
        self.call("initialize", {
            "clientInfo": {"name": "saiai_daemon_regression", "version": "0.0.0"},
            "capabilities": {"experimentalApi": True},
        })
        self.send({"method": "initialized"})

    def exact(self, count):
        data = b""
        while len(data) < count:
            chunk = self.socket.recv(count - len(data))
            if not chunk:
                raise EOFError("control socket closed")
            data += chunk
        return data

    def frame(self, opcode, payload):
        length = len(payload)
        header = bytes([128 | opcode, 128 | (length if length < 126 else 126)])
        if length >= 126:
            header += struct.pack("!H", length)
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.socket.sendall(header + mask + masked)

    def send(self, value):
        self.frame(1, json.dumps(value).encode())

    def call(self, method, params):
        # No generation/review/turn API may be used by this test.
        assert method in {"initialize", "account/read", "thread/start", "thread/loaded/list"}
        self.request_id += 1
        self.send({"id": self.request_id, "method": method, "params": params})
        for _ in range(100):
            header = self.exact(2)
            opcode, length = header[0] & 15, header[1] & 127
            assert not header[1] & 128
            if length == 126:
                length = struct.unpack("!H", self.exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.exact(8))[0]
            assert length <= 1024 * 1024
            payload = self.exact(length)
            if opcode == 9:
                self.frame(10, payload)
                continue
            assert opcode == 1
            response = json.loads(payload)
            if response.get("id") == self.request_id:
                assert "result" in response, "control API failed; raw response withheld"
                return response["result"]
        raise AssertionError("control API response not received")

    def close(self):
        try:
            self.frame(8, b"")
        finally:
            self.socket.close()


def invoke(program, arguments, environment, *, success=True):
    result = subprocess.run(
        [str(program), *arguments], env=environment, stdin=subprocess.DEVNULL,
        cwd=environment["HOME"], capture_output=True, timeout=65,
    )
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    assert "DAEMON_TEST_KEY" not in output, "synthetic credential printed"
    if success:
        assert result.returncode == 0, "command failed; raw output withheld"
    return output


def check_plain_tui(codex, environment):
    import fcntl
    import pty
    import termios

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 100, 0, 0))
    process = subprocess.Popen(
        [str(codex)], env={**environment, "TERM": "xterm-256color"},
        cwd=environment["HOME"], stdin=slave, stdout=slave, stderr=slave,
    )
    os.close(slave)
    try:
        output = b""
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                chunk = os.read(master, 65536)
                output += chunk
                for query, response in (
                    (b"\x1b[6n", b"\x1b[1;1R"),
                    (b"\x1b]10;?", b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\"),
                    (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
                    (b"\x1b[?u", b"\x1b[?0u"),
                    (b"\x1b[c", b"\x1b[?1;2c"),
                ):
                    if query in chunk:
                        os.write(master, response)
                assert len(output) <= 1024 * 1024
                # Ratatui positions cells with cursor escapes instead of spaces.
                plain = re.sub(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*?(?:\x07|\x1b\\))", b"", output)
                compact = re.sub(rb"\s+", b"", plain)
                assert b"SigninwithChatGPT" not in compact, "plain TUI still shows login menu"
                # Empty homes show a logo instead of the returning-user help.
                # The model footer is drawn after authenticated app bootstrap.
                if b"AskCodextodoanything" in compact and b"GPT-6.1-Sol" in compact:
                    return
            assert process.poll() is None, "plain TUI exited during startup"
        raise AssertionError("plain TUI did not finish startup; raw output withheld")
    finally:
        os.write(master, b"\x03")
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--codex", type=Path, required=True,
                        help="Official standalone 0.162.1 executable (not npm JS shim)")
    args = parser.parse_args()
    binary, codex = args.binary.resolve(strict=True), args.codex.resolve(strict=True)
    if platform.system() != "Linux":
        raise SystemExit("official lifecycle integration currently covers Linux; other native socket protocols are tested by Rust CI")
    requests = []

    class Gateway(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(("GET", self.path.split("?", 1)[0]))
            health = self.path in {"/health", "/healthz"}
            body = json.dumps({"status": "ok"} if health else {"error": "fixture"}).encode()
            self.send_response(200 if health else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            requests.append(("POST", self.path.split("?", 1)[0]))
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_):
            pass

    gateway = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
    server = threading.Thread(target=gateway.serve_forever, daemon=True)
    server.start()
    try:
        # Deep runner temp paths can exceed sun_path.
        with tempfile.TemporaryDirectory(prefix="saiai-daemon-", dir="/tmp") as temporary:
            home = Path(temporary)
            codex_home = home / ".codex"
            environment = os.environ.copy()
            environment.update({
                "HOME": str(home), "CODEX_HOME": str(codex_home),
                "SAIAI_HOME": str(home / ".saiai"), "XDG_CONFIG_HOME": str(home / ".config"),
            })
            for name in ("OPENAI_API_KEY", "CODEX_ACCESS_TOKEN", "SAIAI_SKIP_START"):
                environment.pop(name, None)
            commands = home / "bin"
            commands.mkdir()
            (commands / "codex").symlink_to(codex)
            # Force headless proxy mode; never touch the real user's service/NSS.
            for name in ("systemctl", "certutil"):
                path = commands / name
                path.write_text("#!/bin/sh\nexit 1\n")
                path.chmod(0o755)
            environment["PATH"] = str(commands) + os.pathsep + environment.get("PATH", "")
            managed = codex_home / "packages/app-server-daemon/current/bin"
            managed.mkdir(parents=True)
            (managed / "codex").symlink_to(codex)
            state = codex_home / "app-server-daemon"
            state.mkdir()
            (state / "settings.json").write_text(json.dumps({
                "autoUpdateEnabled": False, "shutdownGraceSeconds": 1,
            }))
            (codex_home / "config.toml").write_text(
                'model="gpt-6.1-sol"\n[features]\napps=false\n[otel]\nmetrics_exporter="none"\n'
                f'[projects.{json.dumps(str(home))}]\ntrust_level="trusted"\n'
            )
            assert "codex-cli 0.162.1" in invoke(codex, ["--version"], environment).splitlines()
            control = None
            try:
                invoke(codex, ["app-server", "daemon", "start"], environment)
                control = Control(codex_home)
                assert control.call("account/read", {"refreshToken": False})["account"] is None
                control.close()
                control = None
                setup = ["init-codex", f"http://127.0.0.1:{gateway.server_port}", "DAEMON_TEST_KEY"]
                skipped = {**environment, "SAIAI_SKIP_START": "1"}
                output = invoke(binary, setup, skipped)
                assert "Codex daemon refresh skipped" in output
                output = invoke(binary, ["doctor", "codex"], environment, success=False)
                assert "auth.json is valid but the running daemon is not signed in" in output
                output = invoke(binary, setup, environment)
                assert "Codex daemon restarted and recognizes ChatGPT authentication" in output
                control = Control(codex_home)
                assert control.call("account/read", {"refreshToken": False})["account"]["type"] == "chatgpt"
                output = invoke(binary, ["doctor", "codex"], environment, success=False)
                assert "OK   Codex daemon auth:" in output
                check_plain_tui(codex, environment)
                # Loading a thread starts no turn, but must inhibit automatic restart.
                control.call("thread/start", {"cwd": str(home)})
                assert control.call("thread/loaded/list", {})["data"]
                output = invoke(binary, setup, environment)
                assert "Codex daemon has loaded sessions; left running" in output
                assert control.call("thread/loaded/list", {})["data"]
                assert not any(method == "POST" for method, _ in requests), "unexpected generation request reached fixture"
                print("Official Codex 0.162.1: stale auth detected, idle daemon refreshed, plain TUI passed, loaded session preserved; model requests=0")
            finally:
                if control:
                    control.close()
                invoke(codex, ["app-server", "daemon", "stop"], environment, success=False)
                invoke(binary, ["stop"], environment, success=False)
    finally:
        gateway.shutdown()
        gateway.server_close()


if __name__ == "__main__":
    main()
