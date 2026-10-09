#!/usr/bin/env python3
"""Verify provider initialization preserves editor settings and Windows roots."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile


def windows_roots():
    if os.name != "nt":
        return None
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = r"""+$ErrorActionPreference='Stop'
$roots=@{}
foreach($scope in @('CurrentUser','LocalMachine')) {
  $roots[$scope]=@((Get-ChildItem ('Cert:\'+$scope+'\Root')).Thumbprint | Sort-Object)
}
$roots|ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, timeout=20, check=True,
    )
    return json.loads(result.stdout.decode("utf-8-sig"))


def invoke(binary, arguments, environment):
    result = subprocess.run(
        [str(binary), *arguments], env=environment, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=30,
    )
    text = (result.stdout + result.stderr).decode("utf-8-sig", errors="replace")
    if "TEST_ONLY_SCOPE_KEY" in text:
        raise AssertionError("initialization printed the synthetic credential")
    return result.returncode, text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    roots = windows_roots()
    with tempfile.TemporaryDirectory(prefix="saiai-initialization-scope-") as temporary:
        home = Path(temporary) / "home"
        home.mkdir()
        environment = os.environ.copy()
        environment.update({
            "HOME": str(home), "USERPROFILE": str(home),
            "APPDATA": str(home / "AppData/Roaming"),
            "LOCALAPPDATA": str(home / "AppData/Local"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "SAIAI_HOME": str(home / ".saiai"),
            "CLAUDE_CONFIG_DIR": str(home / ".claude"),
            "CODEX_HOME": str(home / ".codex"),
            "SAIAI_SKIP_START": "1",
        })
        editor_roots = [
            home / ".config/Code/User",
            home / "Library/Application Support/Code/User",
            home / "AppData/Roaming/Code/User",
            home / ".vscode-server/data/Machine",
        ]
        plain = b'{"editor.fontSize": 15}\n'
        # An existing managed editor must also remain byte-identical; opting
        # out does not silently undo an earlier authorized integration.
        managed = b'{\n// SAIAI managed VSCode proxy: http://127.0.0.1:32111\n"http.proxy": "http://127.0.0.1:32111"\n}\n'
        protected = {}
        for index, root in enumerate(editor_roots):
            root.mkdir(parents=True)
            path = root / "settings.json"
            path.write_bytes(plain if index % 2 == 0 else managed)
            protected[path] = path.read_bytes()
        for index, verb in enumerate(("init", "init-codex", "init")):
            code, output = invoke(binary, [verb, "--base-url", "http://127.0.0.1:9", "--api-key", "TEST_ONLY_SCOPE_KEY"], environment)
            assert code == 0, "provider initialization failed; raw output withheld"
            assert "VSCode editor settings and OS certificate stores were preserved" in output
            assert not any(message in output for message in (
                "Trust this CA", "Trusting this installation", "Windows may show a Security Warning",
                "VSCode editor setup is incomplete", "VSCode's certificate loader",
            )), "ordinary provider setup entered optional editor trust flow"
            assert all(path.read_bytes() == data for path, data in protected.items()), "editor settings changed"
            for root in editor_roots:
                assert {p.name for p in root.iterdir()} == {"settings.json"}, "editor setup created a backup or profile"
            assert windows_roots() == roots, "Windows root store changed"
            if index == 0:
                # Never let doctor contact an unrelated proxy already running
                # on the default port of a field machine.
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    listen = "127.0.0.1:" + str(reservation.getsockname()[1])
                path = home / ".saiai/config.json"
                config = json.loads(path.read_text())
                config["listen"] = listen
                path.write_text(json.dumps(config))
        claude = json.loads((home / ".claude/settings.json").read_text())
        config = json.loads((home / ".saiai/config.json").read_text())
        assert claude["env"]["NODE_EXTRA_CA_CERTS"] == config["ca_cert_path"]
        assert Path(config["ca_cert_path"]).is_file()
        assert claude["env"]["https_proxy"] == "http://" + config["listen"]
        assert "SSL_CERT_FILE=" in (home / ".codex/.env").read_text()
        # Claude diagnostics must inspect the provider CA, without requiring
        # the unrelated editor-wide trust/configuration that was not selected.
        _, doctor = invoke(binary, ["doctor", "claude"], environment)
        assert "OK   NODE_EXTRA_CA_CERTS:" in doctor
        assert "VSCode certificate loader" not in doctor and "VSCode settings:" not in doctor
    assert windows_roots() == roots
    print(json.dumps({
        "status": "pass", "platform": platform.system(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "ordinary_claude_and_codex_init_no_trust_flow": True,
        "editor_files_byte_identical": True,
        "windows_root_stores_unchanged": True if roots is not None else None,
        "claude_process_ca_configured": True,
        "claude_doctor_does_not_require_editor_trust": True,
        "temporary_state_removed": True, "provider_model_requests": 0,
    }))


if __name__ == "__main__":
    main()
