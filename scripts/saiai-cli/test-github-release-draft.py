#!/usr/bin/env python3
"""Regression tests for immutable GitHub draft-release verification."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
VERIFIER = SCRIPT_DIR / "verify-github-release-draft.py"
TAG = "saiai-v9.8.7"
FILES = (
    "saiai-linux-x86_64",
    "saiai-linux-aarch64",
    "saiai-macos-x86_64",
    "saiai-macos-aarch64",
    "saiai-windows-x86_64.exe",
    "saiai-windows-aarch64.exe",
    "setup.sh",
    "setup.ps1",
    "setup.cmd",
    "manifest.json",
)


class ReleaseDraftVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="saiai-release-draft-")
        self.dist = Path(self.temporary.name) / "dist"
        self.dist.mkdir()
        assets: list[dict[str, Any]] = []
        for index, name in enumerate(FILES):
            content = f"fixture {index}: {name}\n".encode()
            (self.dist / name).write_bytes(content)
            assets.append(
                {
                    "name": name,
                    "size": len(content),
                    "state": "uploaded",
                    "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
                }
            )
        self.release: dict[str, Any] = {
            "draft": True,
            "prerelease": False,
            "immutable": False,
            "tag_name": TAG,
            "assets": assets,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_verifier(
        self, release: dict[str, Any] | None = None, state: str = "draft"
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--dist",
                str(self.dist),
                "--tag",
                TAG,
                "--state",
                state,
            ],
            input=json.dumps(release if release is not None else self.release),
            text=True,
            capture_output=True,
            check=False,
        )

    def test_accepts_exact_uploaded_draft(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified 10 draft assets", result.stdout)

    def test_accepts_exact_immutable_published_release(self) -> None:
        release = copy.deepcopy(self.release)
        release["draft"] = False
        release["immutable"] = True
        result = self.run_verifier(release, state="published")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified 10 published assets", result.stdout)

    def test_accepts_exact_local_set_without_remote_input(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--dist",
                str(self.dist),
                "--local-only",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_published_release(self) -> None:
        release = copy.deepcopy(self.release)
        release["draft"] = False
        self.assertNotEqual(self.run_verifier(release).returncode, 0)

    def test_rejects_mutable_published_release(self) -> None:
        release = copy.deepcopy(self.release)
        release["draft"] = False
        release["immutable"] = False
        self.assertNotEqual(
            self.run_verifier(release, state="published").returncode,
            0,
        )

    def test_rejects_wrong_tag(self) -> None:
        release = copy.deepcopy(self.release)
        release["tag_name"] = "saiai-v9.8.8"
        self.assertNotEqual(self.run_verifier(release).returncode, 0)

    def test_rejects_prerelease(self) -> None:
        release = copy.deepcopy(self.release)
        release["prerelease"] = True
        self.assertNotEqual(self.run_verifier(release).returncode, 0)

    def test_rejects_missing_remote_asset(self) -> None:
        release = copy.deepcopy(self.release)
        release["assets"].pop()
        self.assertNotEqual(self.run_verifier(release).returncode, 0)

    def test_rejects_wrong_remote_digest(self) -> None:
        release = copy.deepcopy(self.release)
        release["assets"][0]["digest"] = f"sha256:{'0' * 64}"
        self.assertNotEqual(self.run_verifier(release).returncode, 0)

    def test_rejects_extra_local_file(self) -> None:
        (self.dist / "unexpected").write_text("unexpected\n", encoding="utf-8")
        self.assertNotEqual(self.run_verifier().returncode, 0)


if __name__ == "__main__":
    unittest.main()
