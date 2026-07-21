#!/usr/bin/env python3
"""Exercise the native macOS LaunchAgent lifecycle without model traffic."""

from __future__ import annotations

import argparse
import os
import platform
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 19908
LAUNCHD_LABEL = "top.saiai.local-proxy"
TIMEOUT_SECONDS = 15.0


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
    return result


def port_is_open() -> bool:
    try:
        with socket.create_connection((LISTEN_HOST, LISTEN_PORT), timeout=0.25):
            return True
    except OSError:
        return False


def wait_for_port(expected_open: bool) -> None:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if port_is_open() is expected_open:
            return
        time.sleep(0.1)
    state = "open" if expected_open else "closed"
    raise AssertionError(f"local proxy port did not become {state}")


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
    if platform.system() != "Darwin":
        raise AssertionError("macOS LaunchAgent smoke must run on macOS")

    args = arguments()
    binary = args.binary.resolve()
    if not binary.is_file():
        raise AssertionError(f"SAIAI binary is missing: {binary}")
    binary.chmod(binary.stat().st_mode | 0o111)

    if port_is_open():
        raise AssertionError(f"test port {LISTEN_HOST}:{LISTEN_PORT} is already in use")

    with tempfile.TemporaryDirectory(prefix="saiai-macos-service-") as temporary_text:
        temporary = Path(temporary_text)
        home = temporary / "home"
        claude_dir = home / ".claude"
        saiai_home = home / ".saiai"
        home.mkdir()
        claude_dir.mkdir()

        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "CLAUDE_CONFIG_DIR": str(claude_dir),
                "SAIAI_HOME": str(saiai_home),
            }
        )

        run_checked(
            [
                str(binary),
                "init",
                "https://gateway.example.test",
                "TEST_ONLY_MACOS_SERVICE_KEY",
            ],
            environment,
        )

        plist = home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        try:
            start = run_checked([str(binary), "start"], environment)
            if "SAIAI LaunchAgent started." not in start.stdout:
                raise AssertionError("start did not report a successful LaunchAgent")
            if not plist.is_file():
                raise AssertionError(f"LaunchAgent plist was not written: {plist}")
            wait_for_port(True)

            status = run_checked([str(binary), "status"], environment)
            if "service active: yes" not in status.stdout:
                raise AssertionError(f"status did not find the LaunchAgent:\n{status.stdout}")

            verify_logs_command(binary, environment)

            restart = run_checked([str(binary), "restart"], environment)
            if "SAIAI LaunchAgent started." not in restart.stdout:
                raise AssertionError("restart did not start the LaunchAgent")
            wait_for_port(True)
        finally:
            stop_service(binary, environment)

        wait_for_port(False)
        status = run_checked([str(binary), "status"], environment)
        if "service active: no" not in status.stdout:
            raise AssertionError(f"stop left the LaunchAgent active:\n{status.stdout}")

    print("SAIAI macOS LaunchAgent lifecycle smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
