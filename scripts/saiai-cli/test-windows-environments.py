#!/usr/bin/env python3
"""Native Windows environment lifecycle and stale-PID safety, with no upstream requests."""
import argparse
import faulthandler
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time


def main():
    faulthandler.dump_traceback_later(240, exit=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    if os.name != "nt":
        raise SystemExit("requires native Windows")
    with tempfile.TemporaryDirectory(prefix="saiai-windows-environments-") as temporary:
        root = Path(temporary)
        home = root / "home"
        home.mkdir()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("SAIAI_", "CLAUDE_", "CODEX_", "ANTHROPIC_", "OPENAI_"))}
        env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / "AppData/Roaming"),
                   LOCALAPPDATA=str(home / "AppData/Local"), SAIAI_HOME=str(home / ".saiai"))
        a = {**env, "CODEX_HOME": str(root / "project-a/codex")}
        b = {**env, "CODEX_HOME": str(root / "project-b/codex")}
        initialized, followers = [], []

        def run(environment, *args, ok=True):
            print("Windows environment check: " + args[0], flush=True)
            # A detached worker can retain inherited Windows pipe handles even
            # after the CLI exits. Wait on the CLI, not pipe EOF (as in the
            # existing native runtime fixture), and collect output in a file.
            capture = root / f"command-{time.monotonic_ns()}.log"
            with capture.open("wb") as output_file:
                result = subprocess.run([str(binary), *args], env=environment,
                                        stdout=output_file, stderr=subprocess.STDOUT, timeout=40)
            output = capture.read_bytes().decode("utf-8", errors="replace")
            assert "TEST_ONLY_WINDOWS_ENV_KEY" not in output
            assert (result.returncode == 0) == ok, f"unexpected result for {args[0]}: {output}"
            return output

        def probe(config):
            # A TLS handshake only; no HTTP application or upstream request.
            context = ssl.create_default_context(cafile=config["ca_cert_path"])
            conn = http.client.HTTPSConnection("127.0.0.1", int(config["listen"].split(":")[-1]), context=context, timeout=5)
            conn.set_tunnel("api.openai.com", 443)
            deadline = time.monotonic() + 10
            while True:
                try:
                    conn.connect()
                    conn.close()
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)

        try:
            paths = []
            for index, environment in enumerate((env, a, b)):
                existing = set((home / ".saiai").glob("environments/*/config.json"))
                run(environment, "init-codex", "http://127.0.0.1:9", "TEST_ONLY_WINDOWS_ENV_KEY")
                initialized.append(environment)
                path = home / ".saiai/config.json" if index == 0 else next(iter(set((home / ".saiai").glob("environments/*/config.json")) - existing))
                paths.append(path)
                probe(json.loads(path.read_text()))
            states = [p.with_name("saiai.pid") for p in paths]
            snapshots = [p.read_bytes() for p in states]
            configs = [p.read_bytes() for p in paths]
            assert len({json.loads(c)["listen"] for c in configs}) == 3
            # A legacy bare PID must not be allowed to stop a new project worker.
            states[0].write_text(str(json.loads(snapshots[2])["pid"]))
            run(env, "stop")
            assert "service active: yes" in run(b, "status")
            states[0].write_bytes(snapshots[0])
            # Scoped stop must neither terminate another environment nor trust its copied receipt.
            states[1].write_bytes(snapshots[2])
            run(a, "stop", ok=False)
            states[1].write_bytes(snapshots[1])
            assert "service active: yes" in run(b, "status")
            # Reused pid with mismatched creation time is stale, never killed.
            stale = json.loads(snapshots[1])
            stale["pid"] = json.loads(snapshots[2])["pid"]
            stale["created"] = 1
            states[1].write_text(json.dumps(stale))
            run(a, "stop")
            assert "service active: yes" in run(b, "status")
            states[1].write_bytes(snapshots[1])
            # Track log followers per instance; default stop must leave project logs alive.
            for environment in (env, a):
                follower = subprocess.Popen([str(binary), "logs"], env=environment,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                followers.append(follower)
            for path in paths[:2]:
                deadline = time.monotonic() + 10
                while not list(path.parent.glob("log-followers/*.json")):
                    assert time.monotonic() < deadline, "log follower registration timed out"
                    time.sleep(0.1)
            run(env, "stop")
            followers[0].wait(timeout=10)
            assert followers[1].poll() is None
            assert states[1].read_bytes() == snapshots[1] and states[2].read_bytes() == snapshots[2]
            probe(json.loads(configs[1])); probe(json.loads(configs[2]))
            # Exercise the supported upgrade shape: an old default worker command
            # with a bare PID, using only the test binary and temporary config.
            with (root / "legacy-worker.log").open("wb") as legacy_output:
                legacy_worker = subprocess.Popen([str(binary), "__run-background-proxy"], env=env,
                                                 stdout=legacy_output, stderr=subprocess.STDOUT)
            try:
                states[0].write_text(str(legacy_worker.pid))
                probe(json.loads(configs[0]))
                run(env, "stop")
                legacy_worker.wait(timeout=10)
            finally:
                if legacy_worker.poll() is None:
                    legacy_worker.kill()
                    legacy_worker.wait(timeout=10)
            run(a, "restart")
            assert states[2].read_bytes() == snapshots[2]
            assert [p.read_bytes() for p in paths] == configs
            probe(json.loads(configs[1])); probe(json.loads(configs[2]))
            print("PASS: Windows default/projects, stale PID and foreign receipt rejection, scoped log followers, restart isolation; zero upstream requests")
        finally:
            for environment in reversed(initialized):
                subprocess.run([str(binary), "stop"], env=environment, capture_output=True, timeout=40)
            for follower in followers:
                if follower.poll() is None:
                    follower.kill()
                follower.wait(timeout=10)


if __name__ == "__main__":
    main()
