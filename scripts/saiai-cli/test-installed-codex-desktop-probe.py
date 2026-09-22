#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
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
