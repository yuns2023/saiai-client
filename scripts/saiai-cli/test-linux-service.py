#!/usr/bin/env python3
"""Exercise the Linux headless service fallback without model traffic."""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator


LISTEN_HOST = "127.0.0.1"
TIMEOUT_SECONDS = 15.0
TEST_KEY = "TEST_ONLY_LINUX_SERVICE_KEY"


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def local_health_server() -> Iterator[str]:
    server = ThreadingHTTPServer((LISTEN_HOST, 0), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{LISTEN_HOST}:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    return parser.parse_args()


def run_checked(
    command: list[str], environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {command[0]}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    if TEST_KEY in result.stdout or TEST_KEY in result.stderr:
        raise AssertionError(f"command printed the test API key: {command[0]}")
    return result


def unused_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind((LISTEN_HOST, 0))
        return int(listener.getsockname()[1])


def port_is_open(port: int) -> bool:
    try:
        with socket.create_connection((LISTEN_HOST, port), timeout=0.25):
            return True
    except OSError:
        return False


def wait_for_port(port: int, expected_open: bool) -> None:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if port_is_open(port) is expected_open:
            return
        time.sleep(0.1)
    state = "open" if expected_open else "closed"
    raise AssertionError(f"local proxy port {port} did not become {state}")


def stop_service(binary: Path, environment: dict[str, str]) -> None:
    result = subprocess.run(
        [str(binary), "stop"],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"cleanup stop failed ({result.returncode})\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def verify_logs_command(binary: Path, environment: dict[str, str]) -> None:
    process = subprocess.Popen(
        [str(binary), "logs"],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        time.sleep(1.0)
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise AssertionError(
                f"logs command exited early ({process.returncode})\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)


def main() -> int:
    if platform.system() != "Linux":
        raise AssertionError("Linux service fallback smoke must run on Linux")

    args = arguments()
    binary = args.binary.resolve()
    if not binary.is_file():
        raise AssertionError(f"SAIAI binary is missing: {binary}")
    binary.chmod(binary.stat().st_mode | 0o111)

    port = unused_loopback_port()
    with local_health_server() as gateway_url, tempfile.TemporaryDirectory(
        prefix="saiai-linux-service-"
    ) as temporary_text:
        temporary = Path(temporary_text)
        home = temporary / "home"
        claude_dir = home / ".claude"
        saiai_home = home / ".saiai"
        fake_bin = temporary / "fake-bin"
        home.mkdir()
        claude_dir.mkdir()
        fake_bin.mkdir()

        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/bin/sh\n"
            "if [ \"${1:-}\" = \"--version\" ]; then\n"
            "  echo 'systemd test stub'\n"
            "  exit 0\n"
            "fi\n"
            "echo 'Failed to connect to bus: test-forced headless mode' >&2\n"
            "exit 1\n",
            encoding="utf-8",
        )
        systemctl.chmod(0o755)

        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "CLAUDE_CONFIG_DIR": str(claude_dir),
                "SAIAI_HOME": str(saiai_home),
                "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            }
        )
        environment.pop("DBUS_SESSION_BUS_ADDRESS", None)
        environment.pop("XDG_RUNTIME_DIR", None)

        run_checked(
            [
                str(binary),
                "init",
                gateway_url,
                TEST_KEY,
            ],
            environment,
        )
        config_path = saiai_home / "config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["listen"] = f"{LISTEN_HOST}:{port}"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        settings_path = claude_dir / "settings.json"
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        proxy_url = f"http://{LISTEN_HOST}:{port}"
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            settings["env"][key] = proxy_url
        settings_path.write_text(json.dumps(settings), encoding="utf-8")

        state_path = saiai_home / "saiai.pid"
        log_path = saiai_home / "saiai.log"
        lock_path = saiai_home / "saiai.lock"
        try:
            start = run_checked([str(binary), "start"], environment)
            if "SAIAI background proxy started or refreshed." not in start.stdout:
                raise AssertionError(f"start did not select the fallback:\n{start.stdout}")
            if "using a managed background process" not in start.stderr:
                raise AssertionError(f"start did not explain the fallback:\n{start.stderr}")
            wait_for_port(port, True)

            state = json.loads(state_path.read_text(encoding="utf-8"))
            first_pid = int(state["pid"])
            if state.get("schema_version") != 1 or int(state["start_time_ticks"]) <= 0:
                raise AssertionError(f"invalid managed background state: {state}")
            if TEST_KEY in state_path.read_text(encoding="utf-8"):
                raise AssertionError("managed background state contains the API key")
            for private_path in (state_path, log_path, lock_path):
                mode = stat.S_IMODE(private_path.stat().st_mode)
                if mode != 0o600:
                    raise AssertionError(f"{private_path} has unsafe mode {mode:#o}")

            status = run_checked([str(binary), "status"], environment)
            for expected in (
                "service manager: background process",
                "service active: yes",
                f"pid: {first_pid}",
            ):
                if expected not in status.stdout:
                    raise AssertionError(f"status omitted {expected!r}:\n{status.stdout}")

            doctor = run_checked([str(binary), "doctor"], environment)
            if "OK   service: managed background process active" not in doctor.stdout:
                raise AssertionError(
                    f"doctor did not recognize the fallback:\n{doctor.stdout}"
                )

            verify_logs_command(binary, environment)

            restart = run_checked([str(binary), "restart"], environment)
            if "SAIAI background proxy started or refreshed." not in restart.stdout:
                raise AssertionError(f"restart did not use the fallback:\n{restart.stdout}")
            wait_for_port(port, True)
            second_pid = int(json.loads(state_path.read_text(encoding="utf-8"))["pid"])
            if second_pid == first_pid:
                raise AssertionError("restart did not replace the managed background process")

            stopped = run_checked([str(binary), "stop"], environment)
            if "SAIAI background proxy stopped." not in stopped.stdout:
                raise AssertionError(f"stop did not report the fallback:\n{stopped.stdout}")
            wait_for_port(port, False)
            if state_path.exists():
                raise AssertionError("stop left the managed background state file")

            status = run_checked([str(binary), "status"], environment)
            if "service active: no" not in status.stdout:
                raise AssertionError(f"stop left the fallback active:\n{status.stdout}")
            if log_path.is_file() and TEST_KEY in log_path.read_text(
                encoding="utf-8", errors="replace"
            ):
                raise AssertionError("managed background log contains the API key")
        finally:
            stop_service(binary, environment)

    print("SAIAI Linux headless service fallback smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
