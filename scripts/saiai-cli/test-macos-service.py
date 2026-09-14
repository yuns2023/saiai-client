#!/usr/bin/env python3
"""Exercise the native macOS LaunchAgent lifecycle without model traffic."""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import socket
import subprocess
import tempfile
import time
import urllib.parse
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

    with tempfile.TemporaryDirectory(prefix="saiai-macos-service-") as temporary_text:
        temporary = Path(temporary_text)
        home = temporary / "home"
        claude_dir = home / ".claude"
        saiai_home = home / ".saiai"
        home.mkdir()
        claude_dir.mkdir()
        codex_dir = home / ".codex"
        codex_dir.mkdir()

        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "CLAUDE_CONFIG_DIR": str(claude_dir),
                "CODEX_HOME": str(codex_dir),
                "SAIAI_HOME": str(saiai_home),
            }
        )

        auth_path = codex_dir / "auth.json"
        auth_path.write_text(
            json.dumps(
                {
                    "auth_mode": "chatgptAuthTokens",
                    "tokens": {
                        "access_token": "TEST_ONLY_MACOS_DESKTOP_ACCESS",
                        "refresh_token": "",
                        "account_id": "test-only-macos-desktop-account",
                    },
                    "OPENAI_API_KEY": None,
                }
            ),
            encoding="utf-8",
        )
        auth_path.chmod(0o600)

        desktop_capture = temporary / "desktop-capture.json"
        fake_bundle = home / "Applications" / "Codex.app"
        fake_contents = fake_bundle / "Contents"
        fake_macos = fake_contents / "MacOS"
        fake_macos.mkdir(parents=True)
        fake_chatgpt = fake_macos / "FixtureDesktop"
        fake_chatgpt.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

keys = [
    "HOME",
    "USERPROFILE",
    "CODEX_HOME",
    "CODEX_ELECTRON_USER_DATA_PATH",
    "CODEX_CA_CERTIFICATE",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "TZ",
]
capture = {
    "argv": sys.argv[1:],
    "env": {key: os.environ.get(key) for key in keys},
}
Path(os.environ["SAIAI_DESKTOP_CAPTURE"]).write_text(
    json.dumps(capture), encoding="utf-8"
)
""",
            encoding="utf-8",
        )
        fake_chatgpt.chmod(0o700)
        (fake_contents / "Info.plist").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>FixtureDesktop</string>
<key>CFBundleIdentifier</key><string>top.saiai.fixture-codex</string>
</dict></plist>
""",
            encoding="utf-8",
        )
        environment.update(
            {
                "SAIAI_CHATGPT_TIMEZONE": "America/Los_Angeles",
                "SAIAI_DESKTOP_CAPTURE": str(desktop_capture),
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
        config = json.loads((saiai_home / "config.json").read_text(encoding="utf-8"))
        listen = urllib.parse.urlsplit("//" + config["listen"])
        if listen.port is None:
            raise AssertionError("SAIAI initialization wrote an invalid listen address")
        global LISTEN_PORT
        LISTEN_PORT = listen.port
        if port_is_open():
            raise AssertionError(f"test port {LISTEN_HOST}:{LISTEN_PORT} is already in use")

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

            desktop = run_checked(
                [str(binary), "chatgpt", "--", "--smoke-argument"], environment
            )
            if "Starting ChatGPT Desktop through the SAIAI local proxy." not in desktop.stdout:
                raise AssertionError(
                    f"desktop launcher did not report startup:\n{desktop.stdout}"
                )
            captured = json.loads(desktop_capture.read_text(encoding="utf-8"))
            desktop_root = saiai_home / "desktop"
            expected_desktop_home = desktop_root / "home"
            expected_desktop_codex = desktop_root / "codex"
            expected_user_data = desktop_root / "user-data"
            expected_proxy = f"http://{LISTEN_HOST}:{LISTEN_PORT}"
            expected_ca = str(claude_dir / "saiai-ca.crt")
            expected_args = {
                f"--user-data-dir={expected_user_data}",
                f"--proxy-server={expected_proxy}",
                "--smoke-argument",
            }
            if not expected_args.issubset(set(captured["argv"])):
                raise AssertionError(f"desktop arguments are incomplete: {captured['argv']}")
            expected_environment = {
                "HOME": str(expected_desktop_home),
                "USERPROFILE": str(expected_desktop_home),
                "CODEX_HOME": str(expected_desktop_codex),
                "CODEX_ELECTRON_USER_DATA_PATH": str(expected_user_data),
                "CODEX_CA_CERTIFICATE": expected_ca,
                "SSL_CERT_FILE": expected_ca,
                "NODE_EXTRA_CA_CERTS": expected_ca,
                "HTTP_PROXY": expected_proxy,
                "HTTPS_PROXY": expected_proxy,
                "ALL_PROXY": expected_proxy,
                "TZ": "America/Los_Angeles",
            }
            for key, expected in expected_environment.items():
                if captured["env"].get(key) != expected:
                    raise AssertionError(
                        f"desktop environment mismatch for {key}: {captured['env'].get(key)!r}"
                    )
            desktop_config = (expected_desktop_codex / "config.toml").read_text(
                encoding="utf-8"
            )
            if "respect_system_proxy = false" not in desktop_config:
                raise AssertionError(
                    "macOS Desktop config did not disable platform DIRECT proxy precedence"
                )
            account_id = (desktop_root / "account-id").read_text(encoding="utf-8")
            if account_id != "test-only-macos-desktop-account":
                raise AssertionError("macOS Desktop account identity was not isolated")

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
