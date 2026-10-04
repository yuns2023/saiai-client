#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import plistlib
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("probe-installed-codex-desktop.py")
SPEC = importlib.util.spec_from_file_location("installed_codex_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class InstalledCodexDesktopProbeTests(unittest.TestCase):
    def test_storage_fixture_is_only_temporary_synthetic_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            thread_id, answer = PROBE.seed_storage_fixture(root / "codex", root, "0.158.0-alpha.2.1")
            files = list((root / "codex").glob("sessions/**/*.jsonl"))
            self.assertEqual(len(files), 1)
            records = [json.loads(line) for line in files[0].read_text().splitlines()]
            self.assertEqual(records[0]["payload"]["id"], thread_id)
            self.assertEqual(records[0]["payload"]["model_provider"], "openai")
            self.assertIn(answer, files[0].read_text())
            self.assertNotIn("authorization", files[0].read_text().lower())

    def test_storage_acceptance_requires_actual_turn_text_not_sidebar_preview(self) -> None:
        listed = {"result": {"data": [{"id": "fixture"}]}}
        read = {"result": {"thread": {"preview": "assistant", "turns": []}}}
        resumed = {"result": {"thread": {"id": "fixture"}}}
        checks = PROBE.storage_checks(listed, read, resumed, "fixture", "assistant")
        self.assertTrue(checks["history_listed"])
        self.assertFalse(checks["assistant_text_restored"])
        read["result"]["thread"]["turns"] = [{"items": [{"type": "agentMessage", "text": "assistant"}]}]
        resumed["result"]["thread"]["turns"] = read["result"]["thread"]["turns"]
        self.assertTrue(all(PROBE.storage_checks(listed, read, resumed, "fixture", "assistant").values()))

    def test_storage_requires_assistant_type_and_resume_content(self) -> None:
        listed = {"result": {"data": [{"id": "fixture"}]}}
        read = {"result": {"thread": {"turns": [{"items": [{"type": "userMessage", "text": "assistant"}]}]}}}
        resumed = {"result": {"thread": {"id": "fixture", "turns": []}}}
        checks = PROBE.storage_checks(listed, read, resumed, "fixture", "assistant")
        self.assertFalse(checks["assistant_text_restored"])
        self.assertFalse(checks["resumed_assistant_text_restored"])

    def test_storage_malformed_shapes_fail_without_retaining_raw_content(self) -> None:
        for malformed in ({"result": None}, {"result": []}, {"result": {"thread": "unexpected", "data": None}}):
            with self.subTest(malformed=malformed):
                checks = PROBE.storage_checks(malformed, malformed, malformed, "fixture", "assistant")
                self.assertFalse(checks["history_listed"])
                self.assertFalse(checks["assistant_text_restored"])
                self.assertFalse(checks["resumed_thread_matches"])
                self.assertTrue(all(isinstance(value, bool) for value in checks.values()))

    def test_storage_rejects_wrong_resumed_thread_and_rpc_errors(self) -> None:
        checks = PROBE.storage_checks({"error": {}}, {"error": {}},
            {"result": {"thread": {"id": "other"}}}, "fixture", "assistant")
        self.assertFalse(checks["history_listed"])
        self.assertFalse(checks["history_readable"])
        self.assertFalse(checks["assistant_text_restored"])
        self.assertFalse(checks["resumed_thread_matches"])

    def test_environment_allowlist_removes_unknown_auth_and_provider_overrides(self) -> None:
        inherited = {"PATH": "/system/bin", "OPENAI_API_KEY": "SYNTHETIC_NOT_RETAINED",
                     "CODEX_UNKNOWN_AUTH": "SYNTHETIC_NOT_RETAINED", "HTTP_PROXY": "http://stale.invalid",
                     "GH_TOKEN": "SYNTHETIC_NOT_RETAINED", "SSL_CERT_FILE": "/original/ca"}
        original = inherited.copy()
        with tempfile.TemporaryDirectory() as temporary:
            env = PROBE.isolated_environment(Path(temporary), inherited)
            self.assertEqual(env["PATH"], inherited["PATH"])
            self.assertNotIn("SYNTHETIC_NOT_RETAINED", str(env))
            self.assertNotIn("HTTP_PROXY", env)
            self.assertNotIn("SSL_CERT_FILE", env)
        self.assertEqual(inherited, original)

    def test_environment_rehomes_every_profile_and_temp_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = PROBE.isolated_environment(root, {"HOME": "/original", "APPDATA": "/original"})
            for name in ("HOME", "USERPROFILE", "CODEX_HOME", "SAIAI_HOME", "APPDATA",
                         "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR"):
                with self.subTest(name=name):
                    self.assertTrue(Path(env[name]).is_relative_to(root))
                    self.assertTrue(Path(env[name]).is_dir())

    def test_environment_handles_windows_system_variable_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            env = PROBE.isolated_environment(Path(temporary),
                {"SYSTEMROOT": "C:/Windows", "Path": "C:/Windows/System32", "ComSpec": "C:/Windows/cmd.exe"})
            self.assertEqual(env["SystemRoot"], "C:/Windows")
            self.assertEqual(env["PATH"], "C:/Windows/System32")
            self.assertEqual(env["COMSPEC"], "C:/Windows/cmd.exe")

    def test_account_shape_retains_only_schema_booleans(self) -> None:
        observed = PROBE.account_shape({"result": {
            "account": {"type": "chatgpt", "email": "private@example.invalid"},
            "workspaceRouting": {"chatgptAccountId": "private-account"},
        }})
        self.assertEqual(observed, {
            "result_object": True,
            "chatgpt_account": True,
            "workspace_routing_object": True,
            "rpc_error": False,
        })
        self.assertTrue(all(isinstance(value, bool) for value in observed.values()))

    def test_account_shape_distinguishes_legacy_shape_without_accepting_it(self) -> None:
        response = {"result": {"account": {"type": "chatgpt"}}}
        self.assertTrue(PROBE.account_shape(response)["chatgpt_account"])
        self.assertFalse(PROBE.account_shape(response)["workspace_routing_object"])
        with self.assertRaises(PROBE.ProbeError):
            PROBE.validate_account_response(response)
        self.assertTrue(PROBE.account_shape({"error": {"code": -32603}})["rpc_error"])
        self.assertFalse(PROBE.account_shape({"result": None})["result_object"])
        self.assertTrue(PROBE.account_shape({"result": {}})["result_object"])

    def test_copied_app_server_never_collides_with_codex_home(self) -> None:
        for name in ("codex", "codex.exe"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                profile = root / "codex"
                profile.mkdir()
                installed = root / "installed"
                installed.mkdir()
                source = installed / name
                source.write_bytes(b"synthetic executable")
                copied = PROBE.copy_app_server(source, root)
                self.assertTrue(copied.is_file())
                self.assertTrue(profile.is_dir())
                self.assertNotEqual(copied, profile)
                self.assertEqual(copied.read_bytes(), source.read_bytes())

    def test_version_output_discards_packaged_app_warnings(self) -> None:
        output = (
            'WARNING: Refusing helper path C:\\Users\\someone\\AppData\\Local\\Temp\\\n'
            "codex-cli 0.155.0-alpha.9\n"
        )
        self.assertEqual(
            PROBE.sanitized_version(output, "codex-cli"),
            "codex-cli 0.155.0-alpha.9",
        )

    def test_accepts_chatgpt_workspace_routing(self) -> None:
        result = PROBE.validate_account_response(
            {
                "result": {
                    "account": {"type": "chatgpt", "email": "not-retained@example.invalid"},
                    "workspaceRouting": {
                        "chatgptAccountId": "not-retained",
                        "backendOrigin": "https://chatgpt.com",
                        "accountRoutingOverride": "NO_CONSTRAINT",
                    },
                }
            }
        )
        self.assertEqual(result["auth_mode"], "chatgpt")
        self.assertEqual(result["backend_origin"], "https://chatgpt.com")
        self.assertNotIn("chatgptAccountId", result)

    def test_accepts_external_chatgpt_token_auth_status(self) -> None:
        self.assertEqual(
            PROBE.validate_auth_status_response(
                {"result": {"authMethod": "chatgptAuthTokens"}}
            ),
            "chatgptAuthTokens",
        )

    def test_rejects_missing_external_chatgpt_token_auth_status(self) -> None:
        with self.assertRaisesRegex(PROBE.ProbeError, "external ChatGPT token mode"):
            PROBE.validate_auth_status_response({"result": {"authMethod": None}})

    def test_rejects_failed_workspace_discovery(self) -> None:
        with self.assertRaisesRegex(PROBE.ProbeError, "workspace routing discovery"):
            PROBE.validate_account_response(
                {
                    "error": {
                        "code": -32603,
                        "message": "workspace routing discovery failed",
                    }
                }
            )

    def test_rejects_missing_routing(self) -> None:
        with self.assertRaisesRegex(PROBE.ProbeError, "no workspace routing"):
            PROBE.validate_account_response(
                {"result": {"account": {"type": "chatgpt"}}}
            )

    def test_discovers_signed_macos_codex_bundle_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            bundle = home / "Applications/Codex.app"
            resources = bundle / "Contents/Resources"
            resources.mkdir(parents=True)
            (bundle / "Contents/Info.plist").write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "com.openai.codex",
                        "CFBundleShortVersionString": "26.915",
                    }
                )
            )
            app_server = resources / "codex"
            app_server.write_bytes(b"fixture")
            app_server.chmod(0o700)
            path, identity, version = PROBE.macos_desktop_app_server(
                home=home, system_applications=home / "SystemApplications"
            )
            self.assertEqual(path, app_server)
            self.assertEqual(identity, "com.openai.codex")
            self.assertEqual(version, "26.915")


if __name__ == "__main__":
    unittest.main()
