#!/usr/bin/env python3
"""Native macOS default/project LaunchAgent isolation; TLS handshakes only."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import ssl
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    if platform.system() != "Darwin":
        raise SystemExit("requires native macOS")
    with tempfile.TemporaryDirectory(prefix="saiai-macos-environments-") as temporary:
        root = Path(temporary).resolve()
        home = root / "home"
        home.mkdir()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("SAIAI_", "CLAUDE_", "CODEX_", "ANTHROPIC_", "OPENAI_"))}
        env.update(HOME=str(home), SAIAI_HOME=str(home / ".saiai"))
        a = {**env, "CODEX_HOME": str(root / "project-a/codex")}
        b = {**env, "CODEX_HOME": str(root / "project-b/codex")}
        initialized = []

        def run(environment, *args):
            result = subprocess.run([str(binary), *args], env=environment, capture_output=True, text=True, timeout=40)
            output = result.stdout + result.stderr
            assert "TEST_ONLY_MACOS_ENV_KEY" not in output
            assert result.returncode == 0, f"{args[0]} failed: {output}"
            return output

        def label(path):
            if path.parent == home / ".saiai":
                return "top.saiai.local-proxy"
            return "top.saiai.local-proxy-" + hashlib.sha256(os.fsencode(path.parent)).hexdigest()[:24]

        def pid(path):
            result = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{label(path)}"],
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode == 0
            match = re.search(r"\bpid = (\d+)", result.stdout)
            assert match, "LaunchAgent has no running process"
            return match.group(1)

        def probe(config):
            context = ssl.create_default_context(cafile=config["ca_cert_path"])
            deadline = time.monotonic() + 10
            while True:
                connection = http.client.HTTPSConnection("127.0.0.1", int(config["listen"].split(":")[-1]), context=context, timeout=3)
                connection.set_tunnel("api.openai.com", 443)
                try:
                    connection.connect(); connection.close()
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)

        try:
            paths = []
            for index, environment in enumerate((env, a, b)):
                existing = set((home / ".saiai").glob("environments/*/config.json"))
                # Record before invoking, so a partial startup is also cleaned up.
                initialized.append(environment)
                run(environment, "init-codex", "http://127.0.0.1:9", "TEST_ONLY_MACOS_ENV_KEY")
                path = home / ".saiai/config.json" if index == 0 else next(iter(set((home / ".saiai").glob("environments/*/config.json")) - existing))
                paths.append(path)
                probe(json.loads(path.read_text()))
                plist = home / "Library/LaunchAgents" / (label(path) + ".plist")
                unit = plistlib.loads(plist.read_bytes())
                assert unit["Label"] == label(path)
                assert unit["ProgramArguments"][1:] == ["--instance-dir", str(path.parent)]
            saved = [p.read_bytes() for p in paths]
            pids = [pid(p) for p in paths]
            assert len(set(pids)) == 3
            assert len({json.loads(data)["listen"] for data in saved}) == 3
            run(a, "init-codex", "http://127.0.0.1:9", "TEST_ONLY_MACOS_ENV_KEY_NEW")
            assert paths[0].read_bytes() == saved[0] and pid(paths[0]) == pids[0]
            assert paths[2].read_bytes() == saved[2] and pid(paths[2]) == pids[2]
            run(a, "stop")
            probe(json.loads(saved[0])); probe(json.loads(saved[2]))
            assert pid(paths[0]) == pids[0] and pid(paths[2]) == pids[2]
            run(a, "start")
            probe(json.loads(paths[1].read_bytes()))
            assert pid(paths[0]) == pids[0] and pid(paths[2]) == pids[2]
            print("PASS: native macOS independent LaunchAgents, credentials, refresh, stop/start; zero upstream requests")
        finally:
            for environment in reversed(initialized):
                subprocess.run([str(binary), "stop"], env=environment, capture_output=True, timeout=40)


if __name__ == "__main__":
    main()
