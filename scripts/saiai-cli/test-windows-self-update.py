#!/usr/bin/env python3
"""Exercise native Windows self-update with an active same-path proxy and log follower."""

import argparse
import faulthandler
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(exe: Path, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    # The initialized proxy is detached, but Windows descendants can still
    # inherit a pipe handle. Redirect to files so communicate() cannot wait
    # forever for EOF after the command itself has exited.
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stdout:
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stderr:
            completed = subprocess.run(
                [str(exe), *args], env=env, stdout=stdout, stderr=stderr,
                timeout=45, check=False,
            )
            stdout.seek(0)
            stderr.seek(0)
            result = subprocess.CompletedProcess(
                completed.args, completed.returncode, stdout.read(), stderr.read()
            )
    if result.returncode:
        raise AssertionError(f"{args!r} exited {result.returncode}: {result.stdout}\n{result.stderr}")
    return result


def main() -> None:
    faulthandler.dump_traceback_later(90, exit=True)
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    source = args.binary.resolve()
    release_hash = sha256(source)
    version = subprocess.check_output([str(source), "--version"], text=True).split()[1]

    with tempfile.TemporaryDirectory(prefix="saiai-windows-self-update-") as raw_root:
        root = Path(raw_root)
        install = root / "install"
        fixture = root / "http" / "saiai-cli"
        install.mkdir()
        fixture.mkdir(parents=True)
        installed = install / "saiai.exe"
        shutil.copy2(source, installed)
        with installed.open("ab") as output:
            output.write(b"OLDER_TEST_BUILD")
        assert sha256(installed) != release_hash
        shutil.copy2(source, fixture / "saiai-windows-x86_64.exe")
        (fixture / "manifest.json").write_text(
            json.dumps({"version": version, "assets": {
                "saiai-windows-x86_64.exe": {"sha256": release_hash, "size": source.stat().st_size}
            }}), encoding="utf-8"
        )

        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root / "http"))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        home = root / "home"
        home.mkdir()
        env = os.environ.copy()
        env.update({
            "HOME": str(home), "USERPROFILE": str(home),
            "LOCALAPPDATA": str(root / "local-app-data"),
            "APPDATA": str(root / "roaming-app-data"),
            "CLAUDE_CONFIG_DIR": str(home / ".claude"),
            "SAIAI_HOME": str(home / ".saiai"),
        })
        straggler = None
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"
            print("Windows self-update fixture: initializing isolated client", flush=True)
            run(installed, env, "init", base_url, "TEST_ONLY_WINDOWS_UPDATE_KEY")
            assert "service active: yes" in run(installed, env, "status").stdout
            straggler = subprocess.Popen(
                [str(installed), "logs"], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(0.5)
            assert straggler.poll() is None, "same-path log follower exited before update"

            print("Windows self-update fixture: running native update", flush=True)
            staged = run(installed, env, "update")
            assert "not yet installed" in staged.stdout
            result_path = install / ".saiai-update-status.txt"
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if result_path.exists():
                    result = result_path.read_text(encoding="utf-8-sig").strip()
                    if result.startswith("failed:"):
                        raise AssertionError(result)
                    if result.startswith("updated:"):
                        break
                time.sleep(0.1)
            else:
                raise AssertionError("Windows update helper did not record completion")
            assert result == f"updated: {release_hash}", result
            print("Windows self-update fixture: replacement completed", flush=True)
            assert sha256(installed) == release_hash, "installed binary does not match release"
            assert straggler.wait(timeout=5) is not None
            assert "service active: yes" in run(installed, env, "status").stdout
        finally:
            print("Windows self-update fixture: cleaning up", flush=True)
            if installed.exists() and (home / ".saiai").exists():
                subprocess.run([str(installed), "stop"], env=env, capture_output=True, timeout=20)
            if straggler and straggler.poll() is None:
                straggler.kill()
                straggler.wait(timeout=5)
            server.shutdown()
            server.server_close()

    print("SAIAI native Windows self-update smoke passed")


if __name__ == "__main__":
    main()
