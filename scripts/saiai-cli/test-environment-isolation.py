#!/usr/bin/env python3
"""Linux multi-environment lifecycle and local mock credential routing; no live traffic."""
import argparse
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time


# Client-proof device enrollment (docs/CLIENT_PROOF.md) runs in the background
# and is not part of the forwarded traffic this test inspects.
ENROLL_PATH = "/api/v1/client/devices/enroll"


class Gateway(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path.split("?", 1)[0] == ENROLL_PATH:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.server.seen.append((self.path, self.headers.get("Authorization"), self.headers.get("x-api-key")))
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    if not __import__("sys").platform.startswith("linux"):
        raise SystemExit("Linux lifecycle test requires Linux")
    with tempfile.TemporaryDirectory(prefix="saiai-env-isolation-") as temporary:
        root = Path(temporary)
        home, fake = root / "home", root / "bin"
        home.mkdir(); fake.mkdir()
        marker = root / "nss-calls"
        (fake / "systemctl").write_text("#!/bin/sh\nexit 1\n")
        (fake / "certutil").write_text(f"#!/bin/sh\necho called >> '{marker}'\nexit 0\n")
        for path in fake.iterdir():
            path.chmod(0o755)
        child_capture = root / "child.json"
        for program in ("claude", "codex"):
            path = fake / program
            path.write_text("#!/usr/bin/env python3\nimport os,json\nfrom pathlib import Path\n"
                            + f"Path({str(child_capture)!r}).write_text(json.dumps({{k:os.environ.get(k) for k in ['CODEX_HOME','CLAUDE_CONFIG_DIR','HTTPS_PROXY','CODEX_CA_CERTIFICATE','NODE_EXTRA_CA_CERTS']}}))\n")
            path.chmod(0o755)
        environment = {k: v for k, v in os.environ.items()
                       if not k.startswith(("SAIAI_", "CLAUDE_", "CODEX_", "ANTHROPIC_", "OPENAI_"))
                       and k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        environment.update(HOME=str(home), USERPROFILE=str(home), SAIAI_HOME=str(home / ".saiai"),
                           XDG_CONFIG_HOME=str(home / ".config"), PATH=str(fake) + os.pathsep + environment["PATH"])
        a = {**environment, "CODEX_HOME": str(root / "project-a/codex")}
        b = {**environment, "CODEX_HOME": str(root / "project-b/codex")}
        both = {**a, "CLAUDE_CONFIG_DIR": str(root / "project-a/claude")}
        servers = [ThreadingHTTPServer(("127.0.0.1", 0), Gateway) for _ in range(3)]
        for server in servers:
            server.seen = []
            threading.Thread(target=server.serve_forever, daemon=True).start()
        urls = [f"http://127.0.0.1:{s.server_port}" for s in servers]
        initialized = []

        def invoke(env, *args, success=True):
            result = subprocess.run([str(binary), *args], env=env, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            assert "TEST_ENV_KEY_" not in output, "credential leaked to output"
            assert (result.returncode == 0) == success, f"unexpected exit for {args[0]}: {output}"
            return output

        def config_for(env, product="codex"):
            variable = "CODEX_HOME" if product == "codex" else "CLAUDE_CONFIG_DIR"
            directory = env.get(variable)
            if directory and Path(directory).resolve() != home / (".codex" if product == "codex" else ".claude"):
                digest = hashlib.sha256(os.fsencode(Path(directory).resolve())).hexdigest()[:24]
                path = home / ".saiai/environments" / f"{product}-{digest}" / "config.json"
            else:
                path = home / ".saiai/config.json"
            return path, json.loads(path.read_text())

        def pid(path):
            return json.loads(path.with_name("saiai.pid").read_text())["pid"]

        def request(config, server, key, product="codex"):
            host = "api.openai.com" if product == "codex" else "api.anthropic.com"
            path = "/v1/responses" if product == "codex" else "/v1/messages"
            context = ssl.create_default_context(cafile=config["ca_cert_path"])
            port = int(config["listen"].split(":")[-1])
            connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=10)
            connection.set_tunnel(host, 443)
            connection.request("POST", path, b"{}", {"Content-Type": "application/json", "Authorization": "Bearer " + (key if product == "claude" else "synthetic-client")})
            response = connection.getresponse()
            response.read()
            assert response.status == 200
            connection.close()
            received = server.seen[-1]
            assert received[0] == path
            assert received[1] == f"Bearer {key}" or received[2] == key, "wrong environment credential"

        try:
            # Default service and both products retain the shared legacy location.
            invoke(environment, "init", urls[0], "TEST_ENV_KEY_DEFAULT_CLAUDE")
            initialized.append((environment, None))
            invoke(environment, "init-codex", urls[0], "TEST_ENV_KEY_DEFAULT_CODEX")
            default_path, default = config_for(environment)
            default_bytes, default_pid = default_path.read_bytes(), pid(default_path)
            default_ca = Path(default["ca_cert_path"]).read_bytes()
            nss_before = marker.read_bytes()
            protected = {p: p.read_bytes() for directory in (home / ".claude", home / ".codex")
                         for p in directory.iterdir() if p.is_file()}
            invoke(a, "init-codex", urls[1], "TEST_ENV_KEY_A")
            initialized.append((a, None))
            invoke(b, "init-codex", urls[2], "TEST_ENV_KEY_B")
            initialized.append((b, None))
            path_a, cfg_a = config_for(a)
            path_b, cfg_b = config_for(b)
            assert len({default["listen"], cfg_a["listen"], cfg_b["listen"]}) == 3
            assert len({default["ca_cert_path"], cfg_a["ca_cert_path"], cfg_b["ca_cert_path"]}) == 3
            request(default, servers[0], "TEST_ENV_KEY_DEFAULT_CODEX")
            request(default, servers[0], "TEST_ENV_KEY_DEFAULT_CLAUDE", "claude")
            request(cfg_a, servers[1], "TEST_ENV_KEY_A")
            request(cfg_b, servers[2], "TEST_ENV_KEY_B")
            b_pid, b_bytes = pid(path_b), path_b.read_bytes()
            a_ca = Path(cfg_a["ca_cert_path"]).read_bytes()
            invoke(a, "init-codex", urls[1], "TEST_ENV_KEY_A_CHANGED")
            _, refreshed = config_for(a)
            assert refreshed["listen"] == cfg_a["listen"]
            assert Path(refreshed["ca_cert_path"]).read_bytes() == a_ca
            request(refreshed, servers[1], "TEST_ENV_KEY_A_CHANGED")
            assert pid(default_path) == default_pid and default_path.read_bytes() == default_bytes
            assert pid(path_b) == b_pid and path_b.read_bytes() == b_bytes
            # Both variables: product initialization is unambiguous; generic stop is not.
            invoke(both, "init", urls[1], "TEST_ENV_KEY_A_CLAUDE")
            initialized.append((both, "claude"))
            claude_path, claude = config_for(both, "claude")
            assert claude["listen"] not in {default["listen"], cfg_a["listen"], cfg_b["listen"]}
            request(claude, servers[1], "TEST_ENV_KEY_A_CLAUDE", "claude")
            assert "both Claude and Codex" in invoke(both, "stop", success=False)
            assert "service active: yes" in invoke(both, "--environment", "codex", "status")
            # Explicit default aliases must not allocate a second environment.
            aliases = {**environment, "CODEX_HOME": str(home / ".codex"), "CLAUDE_CONFIG_DIR": str(home / ".claude")}
            assert str(default_path) in invoke(aliases, "status")
            for invalid in ("", "   "):
                invoke({**a, "CODEX_HOME": invalid}, "init-codex", urls[1], "TEST_ENV_KEY_BAD", success=False)
            # Relative and symlink aliases select the same environment.
            alias = root / "alias"
            alias.symlink_to(Path(a["CODEX_HOME"]), target_is_directory=True)
            assert str(path_a) in invoke({**a, "CODEX_HOME": str(alias)}, "status")
            relative = os.path.relpath(Path(a["CODEX_HOME"]), Path.cwd())
            assert str(path_a) in invoke({**a, "CODEX_HOME": relative}, "status")
            # Actual launcher subprocesses must pin the selected scope when both vars exist.
            invoke(both, "--environment", "claude", "stop")
            invoke(both, "claude")
            child = json.loads(child_capture.read_text())
            assert child["HTTPS_PROXY"] == "http://" + claude["listen"]
            assert child["CLAUDE_CONFIG_DIR"] == both["CLAUDE_CONFIG_DIR"]
            assert child["NODE_EXTRA_CA_CERTS"] == claude["ca_cert_path"]
            assert "service active: yes" in invoke(both, "--environment", "claude", "status")
            invoke(both, "codex")
            child = json.loads(child_capture.read_text())
            assert child["HTTPS_PROXY"] == "http://" + refreshed["listen"]
            assert child["CODEX_CA_CERTIFICATE"] == refreshed["ca_cert_path"]
            # Old project config continues to launch on its explicit shared route.
            legacy_home = root / "legacy/codex"
            legacy_home.mkdir(parents=True)
            legacy = {**environment, "CODEX_HOME": str(legacy_home)}
            for name in ("config.toml", "auth.json", ".env"):
                (legacy_home / name).write_bytes((home / ".codex" / name).read_bytes())
            assert "existing shared proxy route" in invoke(legacy, "codex")
            assert json.loads(child_capture.read_text())["HTTPS_PROXY"] == "http://" + default["listen"]
            invoke(legacy, "init-codex", urls[1], "TEST_ENV_KEY_LEGACY")
            initialized.append((legacy, None))
            _, migrated = config_for(legacy)
            assert migrated["listen"] != default["listen"]
            request(migrated, servers[1], "TEST_ENV_KEY_LEGACY")
            invoke({**environment, "CODEX_HOME": str(root / "fresh")}, "codex", success=False)
            # A copied receipt from another instance must never authorize stopping it.
            own_state = path_a.with_name("saiai.pid").read_bytes()
            path_a.with_name("saiai.pid").write_bytes(path_b.with_name("saiai.pid").read_bytes())
            invoke(a, "stop", success=False)
            assert pid(path_b) == b_pid
            request(cfg_b, servers[2], "TEST_ENV_KEY_B")
            path_a.with_name("saiai.pid").write_bytes(own_state)
            # Stop only A; then restart it. Default and B keep their exact process.
            invoke(a, "stop")
            assert not path_a.with_name("saiai.pid").exists()
            assert pid(default_path) == default_pid and pid(path_b) == b_pid
            request(cfg_b, servers[2], "TEST_ENV_KEY_B")
            invoke(a, "start")
            request(refreshed, servers[1], "TEST_ENV_KEY_A_CHANGED")
            # A stale/incorrect port cannot authenticate as another environment.
            original_a = path_a.read_bytes()
            wrong_port = {**refreshed, "listen": cfg_b["listen"]}
            path_a.write_text(json.dumps(wrong_port))
            before = len(servers[2].seen)
            invoke(a, "codex", success=False)
            assert len(servers[2].seen) == before, "identity probe reached the Gateway"
            path_a.write_bytes(original_a)
            # Foreground proxy is supported without a managed PID, verified by its CA.
            invoke(a, "stop")
            foreground = subprocess.Popen([str(binary)], env=a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                port = int(refreshed["listen"].split(":")[-1])
                for _ in range(100):
                    assert foreground.poll() is None, "foreground proxy exited"
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                invoke(a, "codex")
                assert json.loads(child_capture.read_text())["HTTPS_PROXY"] == "http://" + refreshed["listen"]
            finally:
                foreground.terminate()
                foreground.wait(timeout=10)
            # Stop A and occupy its port with a foreign listener: init moves only A.
            invoke(a, "stop")
            with socket.socket() as foreign:
                foreign.bind(("127.0.0.1", int(refreshed["listen"].split(":")[-1])))
                foreign.listen()
                invoke(a, "start", success=False)
                invoke(a, "init-codex", urls[1], "TEST_ENV_KEY_A_CHANGED")
                _, moved = config_for(a)
                assert moved["listen"] != refreshed["listen"]
                assert foreign.fileno() >= 0
                request(moved, servers[1], "TEST_ENV_KEY_A_CHANGED")
            assert pid(default_path) == default_pid and default_path.read_bytes() == default_bytes
            assert pid(path_b) == b_pid and path_b.read_bytes() == b_bytes
            assert marker.read_bytes() == nss_before, "project setup changed user NSS"
            assert Path(default["ca_cert_path"]).read_bytes() == default_ca
            assert all(p.read_bytes() == data for p, data in protected.items()), "default client configuration changed"
            # Credential files must stay user-only.
            for path in (path_a, path_b, claude_path):
                assert path.stat().st_mode & 0o077 == 0
            # Systemd unit names/commands are scoped even when the user manager is available.
            # Stop real test workers before switching to a pure command-recording manager.
            for env, target in reversed(initialized):
                invoke(env, *((["--environment", target] if target else []) + ["stop"]))
            systemd_calls = root / "systemd-calls"
            (fake / "systemctl").write_text(
                "#!/bin/sh\n" + f"echo \"$*\" >> '{systemd_calls}'\n"
                + 'case "$*" in *is-active*) exit 1;; *LoadState*) echo loaded;; esac\nexit 0\n')
            # No actual daemons are started by this manager stub.
            invoke(environment, "start")
            invoke(a, "start")
            invoke(b, "start")
            units = list((home / ".config/systemd/user").glob("saiai*.service"))
            assert len(units) == 3
            assert (home / ".config/systemd/user/saiai.service").exists()
            scoped_units = [p for p in units if p.name != "saiai.service"]
            assert len({p.name for p in scoped_units}) == 2
            for config_path in (path_a, path_b):
                unit = next(p for p in scoped_units if str(config_path.parent) in p.read_text())
                assert "--instance-dir" in unit.read_text()
            systemd_calls.write_text("")
            invoke(a, "stop")
            calls = systemd_calls.read_text()
            unit_a = next(p for p in scoped_units if str(path_a.parent) in p.read_text())
            assert f"disable --now {unit_a.name}" in calls
            assert "disable --now saiai.service" not in calls
            print("PASS: default + two Codex projects + Claude project; mock routing, refresh, stop/start, aliases, ambiguity, port collision, NSS isolation")
        finally:
            for env, target in reversed(initialized):
                args = (["--environment", target] if target else []) + ["stop"]
                subprocess.run([str(binary), *args], env=env, capture_output=True, timeout=30)
            for server in servers:
                server.shutdown(); server.server_close()


if __name__ == "__main__":
    main()
