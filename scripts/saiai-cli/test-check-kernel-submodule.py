#!/usr/bin/env python3
"""Tests for check-kernel-submodule.py on throwaway repositories: a local
stand-in for AITP and a workspace that pins it as tools/saiai-cli/kernel."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-kernel-submodule.py"
SPEC = importlib.util.spec_from_file_location("check_kernel_submodule", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

KERNEL = CHECK.KERNEL_PATH
GITMODULES = f'[submodule "{KERNEL}"]\n\tpath = {KERNEL}\n\turl = {CHECK.AITP_URL}\n'
LOCK = """version = 4

[[package]]
name = "proxy-cli"
version = "0.1.0"
dependencies = [
 "tokio",
]

[[package]]
name = "tokio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum}"
"""
WORKSPACE_LOCK = LOCK + """
[[package]]
name = "saiai"
version = "1.0.0"
"""
ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
}


def git(cwd: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=cwd, check=True, text=True, capture_output=True, env=ENV,
    ).stdout.strip()


class KernelSubmoduleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        base = Path(self.scratch.name)
        # The AITP stand-in: one commit on main, one on a side branch.
        self.aitp = base / "aitp"
        self.aitp.mkdir()
        git(self.aitp, "init", "--quiet", "--initial-branch=main")
        (self.aitp / "Cargo.lock").write_text(LOCK.format(checksum="aa"), encoding="utf-8")
        (self.aitp / "Cargo.toml").write_text('[package]\nname = "proxy-cli"\n', encoding="utf-8")
        git(self.aitp, "add", ".")
        git(self.aitp, "commit", "--quiet", "-m", "main")
        self.on_main = git(self.aitp, "rev-parse", "HEAD")
        git(self.aitp, "checkout", "--quiet", "-b", "side")
        (self.aitp / "README.md").write_text("side\n", encoding="utf-8")
        git(self.aitp, "add", ".")
        git(self.aitp, "commit", "--quiet", "-m", "side")
        self.off_main = git(self.aitp, "rev-parse", "HEAD")
        git(self.aitp, "checkout", "--quiet", "main")
        # The workspace pinning it.
        self.root = base / "client"
        self.root.mkdir()
        git(self.root, "init", "--quiet", "--initial-branch=main")
        (self.root / "tools/saiai-cli").mkdir(parents=True)
        (self.root / "tools/saiai-cli/Cargo.lock").write_text(WORKSPACE_LOCK.format(checksum="aa"), encoding="utf-8")
        self.pin(self.on_main)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def pin(self, commit: str, gitmodules: str = GITMODULES) -> None:
        kernel = self.root / KERNEL
        if kernel.exists():
            shutil.rmtree(kernel)
        git(self.root, "clone", "--quiet", "--no-checkout", str(self.aitp), KERNEL)
        git(kernel, "checkout", "--quiet", commit)
        (self.root / ".gitmodules").write_text(gitmodules, encoding="utf-8")
        git(self.root, "add", ".gitmodules", "tools/saiai-cli/Cargo.lock")
        git(self.root, "update-index", "--add", "--cacheinfo", f"160000,{commit},{KERNEL}")
        git(self.root, "commit", "--quiet", "--allow-empty", "-m", f"pin {commit}")

    def findings(self, offline: bool = False) -> list[str]:
        return CHECK.check(self.root, offline, url=str(self.aitp))

    def assertFinds(self, text: str, offline: bool = False) -> None:
        findings = self.findings(offline)
        self.assertTrue(any(text in finding for finding in findings), findings)

    def test_accepts_a_pinned_commit_on_main(self) -> None:
        self.assertEqual(self.findings(), [])
        self.assertEqual(self.findings(offline=True), [])

    def test_rejects_a_commit_not_on_main(self) -> None:
        self.pin(self.off_main)
        self.assertFinds("is not on main")
        self.assertEqual(self.findings(offline=True), [])

    def test_rejects_a_commit_gone_from_main(self) -> None:
        # main force-pushed to a new root: the pinned commit is unreachable.
        git(self.aitp, "checkout", "--quiet", "--orphan", "rewritten")
        git(self.aitp, "commit", "--quiet", "-m", "rewritten")
        git(self.aitp, "branch", "--quiet", "-D", "main")
        git(self.aitp, "branch", "--quiet", "-m", "main")
        self.assertFinds("is not on main")

    def test_rejects_an_unreachable_repository(self) -> None:
        findings = CHECK.check(self.root, False, url=str(self.root / "missing"))
        self.assertTrue(any("cannot fetch main" in finding for finding in findings), findings)

    def test_rejects_another_checked_out_commit(self) -> None:
        git(self.root / KERNEL, "checkout", "--quiet", self.off_main)
        self.assertFinds("is checked out at", offline=True)

    def test_rejects_local_changes_in_the_kernel(self) -> None:
        (self.root / KERNEL / "Cargo.toml").write_text("changed\n", encoding="utf-8")
        self.assertFinds("has local changes", offline=True)
        git(self.root / KERNEL, "checkout", "--quiet", "--", "Cargo.toml")
        (self.root / KERNEL / "extra.rs").write_text("\n", encoding="utf-8")
        self.assertFinds("has local changes", offline=True)

    def test_rejects_a_kernel_that_is_not_checked_out(self) -> None:
        shutil.rmtree(self.root / KERNEL)
        (self.root / KERNEL).mkdir()
        self.assertFinds("is not checked out", offline=True)

    def test_rejects_another_url_or_extra_settings(self) -> None:
        for gitmodules in (
            GITMODULES.replace(CHECK.AITP_URL, CHECK.AITP_URL + ".git"),
            GITMODULES.replace(CHECK.AITP_URL, "https://github.com/someone/AITP"),
            GITMODULES + "\tbranch = side\n",
            GITMODULES + '[submodule "other"]\n\tpath = other\n\turl = https://example.invalid/other\n',
        ):
            with self.subTest(gitmodules=gitmodules):
                self.pin(self.on_main, gitmodules)
                self.assertFinds(".gitmodules must list only", offline=True)

    def test_rejects_an_uncommitted_gitmodules_change(self) -> None:
        (self.root / ".gitmodules").write_text(GITMODULES.replace("AITP", "Other"), encoding="utf-8")
        self.assertFinds(".gitmodules differs from the commit", offline=True)

    def test_rejects_a_plain_directory(self) -> None:
        git(self.root, "rm", "--quiet", "--cached", KERNEL)
        (self.root / KERNEL / ".git").rename(self.root / "kernel-git")
        git(self.root, "add", KERNEL)
        git(self.root, "commit", "--quiet", "-m", "plain directory")
        self.assertFinds("is not a submodule in the commit", offline=True)

    def write_workspace_lock(self, text: str) -> None:
        (self.root / "tools/saiai-cli/Cargo.lock").write_text(text, encoding="utf-8")

    def test_rejects_other_kernel_package_versions(self) -> None:
        self.write_workspace_lock(WORKSPACE_LOCK.format(checksum="bb"))
        self.assertFinds("does not resolve the kernel's dependencies as AITP's lock does", offline=True)
        self.write_workspace_lock(
            WORKSPACE_LOCK.format(checksum="aa").replace('version = "1.0.0"\nsource', 'version = "1.0.1"\nsource'),
        )
        self.assertFinds("tokio 1.0.0", offline=True)

    def test_rejects_the_kernel_moved_to_another_version_kept_for_others(self) -> None:
        # tokio 1.0.0 stays locked (for another package), but the kernel
        # itself resolves to 1.0.1.
        moved = WORKSPACE_LOCK.format(checksum="aa").replace(' "tokio",\n', ' "tokio 1.0.1",\n') + (
            '\n[[package]]\nname = "tokio"\nversion = "1.0.1"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "cc"\n'
            '\n[[package]]\nname = "other"\nversion = "1.0.0"\ndependencies = [\n "tokio 1.0.0",\n]\n'
        )
        self.write_workspace_lock(moved)
        self.assertFinds("does not resolve the kernel's dependencies", offline=True)

    def test_accepts_packages_only_the_program_uses(self) -> None:
        self.write_workspace_lock(
            WORKSPACE_LOCK.format(checksum="aa")
            + '\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "dd"\n'
        )
        self.assertEqual(self.findings(offline=True), [])

    def test_rejects_an_unresolvable_or_missing_kernel_package(self) -> None:
        self.write_workspace_lock(WORKSPACE_LOCK.format(checksum="aa").replace('name = "proxy-cli"', 'name = "renamed"'))
        self.assertFinds("does not lock the kernel package proxy-cli", offline=True)
        self.write_workspace_lock(WORKSPACE_LOCK.format(checksum="aa").replace(' "tokio",\n', ' "tokio 9.9.9",\n'))
        self.assertFinds("which names 0 packages", offline=True)

    def test_rejects_repeated_gitmodules_keys(self) -> None:
        for gitmodules in (
            f'[submodule "{KERNEL}"]\n\tpath = {KERNEL}\n\turl = https://example.invalid/x\n\turl = {CHECK.AITP_URL}\n',
            GITMODULES + GITMODULES,
        ):
            with self.subTest(gitmodules=gitmodules):
                self.pin(self.on_main, gitmodules)
                self.assertFinds(".gitmodules repeats", offline=True)

    def test_rejects_a_staged_gitmodules_change(self) -> None:
        (self.root / ".gitmodules").write_text(GITMODULES.replace("AITP", "Other"), encoding="utf-8")
        git(self.root, "add", ".gitmodules")
        (self.root / ".gitmodules").write_text(GITMODULES, encoding="utf-8")
        self.assertFinds(".gitmodules in the index differs from the commit", offline=True)

    def test_accepts_ignored_build_output_in_the_kernel(self) -> None:
        info = self.root / KERNEL / ".git" / "info"
        info.mkdir(exist_ok=True)
        (info / "exclude").write_text("target/\n", encoding="utf-8")
        (self.root / KERNEL / "target").mkdir()
        (self.root / KERNEL / "target" / "out").write_text("x\n", encoding="utf-8")
        self.assertEqual(self.findings(offline=True), [])
        # A file that is not ignored, even in a new directory, is a change.
        (self.root / KERNEL / "new").mkdir()
        (self.root / KERNEL / "new" / "src.rs").write_text("\n", encoding="utf-8")
        self.assertFinds("has local changes", offline=True)

    def test_the_real_constants(self) -> None:
        self.assertEqual(CHECK.KERNEL_PATH, "tools/saiai-cli/kernel")
        self.assertEqual(CHECK.AITP_URL, "https://github.com/2742zdz/AITP")
        self.assertEqual(CHECK.AITP_BRANCH, "main")


if __name__ == "__main__":
    unittest.main()
