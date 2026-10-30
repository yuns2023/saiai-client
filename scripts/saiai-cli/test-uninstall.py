#!/usr/bin/env python3
"""Linux `saiai uninstall` lifecycle in a temporary HOME; no live traffic."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pty
import shutil
import signal
import subprocess
import sys
import tempfile
import threading

KEY_PREFIX = "TEST_UNINSTALL_KEY_"
FAKE_CERTUTIL = r'''#!/usr/bin/env python3
import shutil, sys
from pathlib import Path
args = sys.argv[1:]
def value(flag):
    return args[args.index(flag) + 1] if flag in args else None
if "-V" in args:
    sys.exit(0)
db = Path(value("-d").split(":", 1)[-1])
nick = value("-n")
stored = db / f"fake-{nick}.pem"
if "-N" in args:
    db.mkdir(parents=True, exist_ok=True)
    (db / "cert9.db").write_text("fake")
elif "-A" in args:
    shutil.copyfile(value("-i"), stored)
elif "-D" in args:
    if not stored.exists():
        sys.exit(255)
    stored.unlink()
elif "-L" in args:
    if not stored.exists():
        sys.exit(255)
    if "-a" in args:
        sys.stdout.write(stored.read_text())
'''


class Gateway(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST

    def log_message(self, *_):
        pass


def snapshot(*roots):
    files = {}
    for root in roots:
        for path in sorted(Path(root).rglob("*")):
            name = path.name
            if name.startswith(("saiai.log", "client-device")) or path.is_dir():
                continue
            files[str(path)] = path.read_bytes() if not path.is_symlink() else os.readlink(path)
    return files


def alive(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, IndexError):
        return False
    return state not in ("Z", "X")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    source = parser.parse_args().binary.resolve(strict=True)
    if not sys.platform.startswith("linux"):
        raise SystemExit("uninstall lifecycle test requires Linux")
    with tempfile.TemporaryDirectory(prefix="saiai-uninstall-") as temporary:
        root = Path(temporary)
        home, fake, install = root / "home", root / "fake-bin", root / "install"
        for directory in (home, fake, install):
            directory.mkdir()
        binary = install / "saiai"
        shutil.copy2(source, binary)
        for name in ("saiai-previous", "saiai.bak-20260101-000000", ".saiai-update-1-2"):
            shutil.copy2(source, install / name)
        (install / "other-tool").write_text("user program\n")
        (fake / "systemctl").write_text("#!/bin/sh\nexit 1\n")
        (fake / "certutil").write_text(FAKE_CERTUTIL)
        for path in fake.iterdir():
            path.chmod(0o755)
        environment = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("SAIAI_", "CLAUDE_", "CODEX_", "ANTHROPIC_", "OPENAI_", "VSCODE_"))
            and k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        }
        environment.update(
            HOME=str(home),
            USERPROFILE=str(home),
            XDG_CONFIG_HOME=str(home / ".config"),
            SAIAI_INSTALL_DIR=str(install),
            PATH=str(fake) + os.pathsep + environment["PATH"],
        )
        project_a = {**environment, "CODEX_HOME": str(root / "project-a/codex")}
        project_b = {**environment, "CODEX_HOME": str(root / "project-b/codex")}
        server = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_port}"
        pids = []

        def invoke(env, *args, success=True, program=binary, **kwargs):
            kwargs.setdefault("stdin", subprocess.DEVNULL)
            result = subprocess.run(
                [str(program), *args], env=env, capture_output=True, text=True, timeout=120, **kwargs
            )
            output = result.stdout + result.stderr
            assert KEY_PREFIX not in output, f"credential leaked to output of {args}"
            assert (result.returncode == 0) == success, f"unexpected exit {result.returncode} for {args}: {output}"
            return output

        try:
            (home / ".claude").mkdir()
            (home / ".claude/settings.json").write_text('{"theme": "dark"}\n')
            invoke(environment, "init", url, KEY_PREFIX + "DEFAULT_CLAUDE")
            invoke(environment, "init-codex", url, KEY_PREFIX + "DEFAULT_CODEX")
            invoke(project_a, "init-codex", url, KEY_PREFIX + "PROJECT_A")
            invoke(project_b, "init-codex", url, KEY_PREFIX + "PROJECT_B")
            saiai = home / ".saiai"
            environments = sorted((saiai / "environments").iterdir())
            assert len(environments) == 2, environments
            for state in [saiai / "saiai.pid", *(e / "saiai.pid" for e in environments)]:
                pids.append(json.loads(state.read_text())["pid"])
            assert all(alive(pid) for pid in pids)
            default = json.loads((saiai / "config.json").read_text())
            nss = home / ".pki/nssdb"
            assert (nss / "fake-saiai-local-proxy.pem").exists(), "init-codex did not import the NSS CA"
            (nss / "fake-user-ca.pem").write_text("user certificate\n")

            # User-owned values that uninstall must keep.
            claude_settings = home / ".claude/settings.json"
            settings = json.loads(claude_settings.read_text())
            settings["env"]["USER_ENV"] = "keep"
            settings["env"]["https_proxy"] = "http://127.0.0.1:7890"
            claude_settings.write_text(json.dumps(settings, indent=2) + "\n")
            codex_env = home / ".codex/.env"
            codex_env.write_text("# user\nUSER_LINE=1\n" + codex_env.read_text())
            codex_auth = home / ".codex/auth.json"
            auth = json.loads(codex_auth.read_text())
            auth["user_field"] = "keep"
            codex_auth.write_text(json.dumps(auth))
            # A dotfiles-style symlink keeps pointing at its cleaned target.
            dotfiles = root / "dotfiles"
            dotfiles.mkdir()
            linked_env = root / "project-a/codex/.env"
            shutil.move(linked_env, dotfiles / "codex.env")
            linked_env.symlink_to(dotfiles / "codex.env")
            user_settings = "{\n  \"editor.fontSize\": 14\n}\n"
            proxy = "http://" + default["listen"]
            managed = (
                "{\n  // SAIAI managed VSCode proxy: " + proxy + "\n\n  \"editor.fontSize\": 14,\n\n"
                f"  \"http.proxy\": \"{proxy}\",\n  \"http.proxySupport\": \"override\",\n"
                "  \"http.proxyStrictSSL\": true,\n  \"http.fetchAdditionalSupport\": true,\n"
                "  \"http.systemCertificates\": true,\n  \"http.systemCertificatesNode\": false,\n"
                "  \"http.noProxy\": [\"localhost\",\"127.0.0.1\",\".local\"]\n}\n"
            )
            vscode = home / ".config/Code/User"
            (vscode / "profiles/other").mkdir(parents=True)
            (vscode / "settings.json").write_text(managed)
            foreign = managed.replace(proxy, "http://127.0.0.1:7890")
            (vscode / "profiles/other/settings.json").write_text(foreign)

            roots = (home, install, root / "project-a", root / "project-b", root / "dotfiles")
            before = snapshot(*roots)
            output = invoke(project_a, "uninstall", "--dry-run", "--yes")
            assert output.startswith("SAIAI uninstall plan\n"), output
            assert "Dry run: nothing was changed." in output
            assert "CODEX_HOME=<that project's directory>" in output, output
            assert snapshot(*roots) == before, "dry run changed files"
            assert all(alive(pid) for pid in pids)

            # Refusals: an interactive "n" and a missing terminal change nothing.
            master, slave = pty.openpty()
            try:
                os.write(master, b"n\n")
                output = invoke(project_a, "uninstall", stdin=slave, success=False)
            finally:
                os.close(slave)
                os.close(master)
            assert "cancelled" in output, output
            output = invoke(project_a, "uninstall", success=False, start_new_session=True)
            assert "no terminal" in output, output
            assert invoke(project_a, "uninstall", "--bogus", success=False)
            assert invoke(project_a, "--environment", "codex", "uninstall", success=False)
            assert snapshot(*roots) == before, "refused uninstall changed files"
            assert all(alive(pid) for pid in pids)

            output = invoke(project_a, "uninstall", "--yes")
            assert "codex login" in output and "codex app-server daemon update" in output, output
            assert not any(alive(pid) for pid in pids), "background proxies are still running"
            assert not saiai.exists(), sorted(saiai.rglob("*"))
            assert sorted(p.name for p in install.iterdir()) == ["other-tool"]
            settings = json.loads(claude_settings.read_text())
            assert settings["theme"] == "dark"
            assert settings["env"] == {
                "USER_ENV": "keep",
                "https_proxy": "http://127.0.0.1:7890",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "ENABLE_PROMPT_CACHING_1H": "1",
                "ENABLE_TOOL_SEARCH": "true",
                "CLAUDE_STREAM_IDLE_TIMEOUT_MS": "600000",
            }, settings["env"]
            assert not list((home / ".claude").glob("saiai-ca*"))
            assert list((home / ".claude").glob("settings.json.bak-*")), "Claude backups were removed"
            assert codex_env.read_text() == "# user\nUSER_LINE=1\n"
            assert json.loads(codex_auth.read_text()) == {"user_field": "keep"}
            assert (home / ".codex/config.toml").exists()
            assert list((home / ".codex").glob("auth.json.bak-*")), "Codex backups were removed"
            assert linked_env.is_symlink() and (dotfiles / "codex.env").read_text() == ""
            assert not (root / "project-a/codex/auth.json").exists()
            for name in (".env", "auth.json"):
                assert (root / "project-b/codex" / name).exists(), "unknown project was edited"
            assert (vscode / "settings.json").read_text() == user_settings
            assert (vscode / "profiles/other/settings.json").read_text() == foreign
            assert not (nss / "fake-saiai-local-proxy.pem").exists(), "NSS CA was kept"
            assert (nss / "fake-user-ca.pem").exists()

            # Rerun from a copy outside the install directory, as setup.sh does.
            after = snapshot(*roots)
            rerun = root / "rerun/saiai-executor"
            rerun.parent.mkdir()
            shutil.copy2(source, rerun)
            output = invoke(project_a, "uninstall", "--yes", program=rerun)
            assert "Nothing to remove." in output, output
            assert snapshot(*roots) == after, "repeated uninstall changed files"
            print("PASS: uninstall dry-run, refusals, owned-value removal, user values kept, idempotent rerun")
        finally:
            for pid in pids:
                if alive(pid):
                    os.kill(pid, signal.SIGKILL)
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
