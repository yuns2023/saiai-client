#!/usr/bin/env python3
"""Check the kernel submodule tools/saiai-cli/kernel.

Usage: check-kernel-submodule.py [--offline]

The kernel is the public AITP repository, checked out as a git submodule.
This fails unless

* .gitmodules lists exactly that one submodule, at that path, from AITP's
  public URL, with no other settings;
* the commit being checked pins the kernel (a gitlink), and the checked-out
  kernel is that commit, with no local change;
* AITP's lock file pins every third-party package exactly as this
  workspace's lock file does (a kernel dependency is updated in AITP first,
  then the submodule moves);
* unless --offline: the pinned commit is on AITP's main branch, fetched
  afresh (a commit never pushed there, or force-pushed away, could not be
  rebuilt). Only commits are fetched, into a temporary repository.

Findings go to standard error, one per line, and the exit status is 1.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KERNEL_PATH = "tools/saiai-cli/kernel"
AITP_URL = "https://github.com/2742zdz/AITP"
AITP_BRANCH = "main"
WORKSPACE_LOCK = "tools/saiai-cli/Cargo.lock"
COMMIT = re.compile(r"[0-9a-f]{40}")


def git(*arguments: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
    )


def submodule_settings(root: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Each submodule's settings as .gitmodules (in the commit) lists them."""
    found: dict[str, dict[str, str]] = {}
    listed = git("config", "--blob", "HEAD:.gitmodules", "--list", cwd=root, check=False)
    if listed.returncode != 0:
        return found, [".gitmodules is missing from the commit or unreadable"]
    for line in listed.stdout.splitlines():
        key, _, value = line.partition("=")
        match = re.fullmatch(r"submodule\.(.+)\.([^.]+)", key)
        if match is None:
            return found, [f".gitmodules has an unexpected entry: {key}"]
        found.setdefault(match.group(1), {})[match.group(2)] = value
    return found, []


def check_structure(root: Path) -> tuple[str | None, list[str]]:
    """The pinned commit and every finding about the submodule's form."""
    settings, findings = submodule_settings(root)
    if findings:
        return None, findings
    expected = {KERNEL_PATH: {"path": KERNEL_PATH, "url": AITP_URL}}
    if settings != expected:
        findings.append(f".gitmodules must list only {expected}, found {settings}")
    working = root / ".gitmodules"
    committed = git("show", "HEAD:.gitmodules", cwd=root).stdout
    if not working.is_file() or working.read_text(encoding="utf-8") != committed:
        findings.append(".gitmodules differs from the commit")

    entries = git("ls-tree", "-z", "HEAD", "--", KERNEL_PATH, cwd=root).stdout.split("\0")
    entries = [entry for entry in entries if entry]
    gitlinks = [entry for entry in entries if entry.startswith("160000 commit ")]
    if len(entries) != 1 or len(gitlinks) != 1:
        findings.append(f"{KERNEL_PATH} is not a submodule in the commit: {entries}")
        return None, findings
    pinned = gitlinks[0].split()[2]
    if COMMIT.fullmatch(pinned) is None:
        findings.append(f"{KERNEL_PATH} pins an unreadable commit {pinned!r}")
        return None, findings
    others = [
        line for line in git("ls-files", "-s", cwd=root).stdout.splitlines()
        if line.startswith("160000 ") and not line.endswith("\t" + KERNEL_PATH)
    ]
    if others:
        findings.append(f"other submodules in the index: {others}")
    staged = [line for line in git("ls-files", "-s", "--", KERNEL_PATH, cwd=root).stdout.splitlines()]
    if staged != [f"160000 {pinned} 0\t{KERNEL_PATH}"]:
        findings.append(f"the index does not pin {pinned} at {KERNEL_PATH}: {staged}")

    kernel = root / KERNEL_PATH
    if not (kernel / ".git").exists():
        findings.append(f"{KERNEL_PATH} is not checked out (run: git submodule update --init)")
        return pinned, findings
    head = git("rev-parse", "HEAD", cwd=kernel, check=False).stdout.strip()
    if head != pinned:
        findings.append(f"{KERNEL_PATH} is checked out at {head or 'nothing'}, the commit pins {pinned}")
    top = git("rev-parse", "--show-toplevel", cwd=kernel, check=False).stdout.strip()
    if not top or Path(top).resolve() != kernel.resolve():
        findings.append(f"{KERNEL_PATH} is not its own git checkout")
    changes = git("status", "--porcelain", cwd=kernel, check=False)
    if changes.returncode != 0 or changes.stdout.strip():
        findings.append(f"{KERNEL_PATH} has local changes: {changes.stdout.strip() or changes.stderr.strip()}")
    return pinned, findings


def locked_packages(text: str) -> dict[tuple[str, str], tuple[str, str | None]]:
    """Third-party packages of a Cargo.lock: (name, version) -> (source, checksum)."""
    found = {}
    for block in text.split("[[package]]")[1:]:
        def field(name: str) -> str | None:
            match = re.search(rf'^{name} = "([^"]*)"', block, re.MULTILINE)
            return match.group(1) if match else None

        if field("source"):
            found[(field("name"), field("version"))] = (field("source"), field("checksum"))
    return found


def check_locks(root: Path) -> list[str]:
    kernel_lock = root / KERNEL_PATH / "Cargo.lock"
    if not kernel_lock.is_file():
        return [f"{KERNEL_PATH}/Cargo.lock is missing"]
    kernel = locked_packages(kernel_lock.read_text(encoding="utf-8"))
    workspace = locked_packages((root / WORKSPACE_LOCK).read_text(encoding="utf-8"))
    if not kernel:
        return [f"{KERNEL_PATH}/Cargo.lock locks no third-party package"]
    differ = sorted(f"{name} {version}" for (name, version), value in kernel.items() if workspace.get((name, version)) != value)
    if differ:
        return [
            f"{WORKSPACE_LOCK} does not lock these kernel packages as AITP does "
            f"(update kernel dependencies in AITP, then move the submodule): {', '.join(differ)}"
        ]
    return []


def check_on_main(pinned: str, url: str = AITP_URL, branch: str = AITP_BRANCH) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="kernel-main-") as scratch:
        mirror = Path(scratch)
        git("init", "--quiet", "--bare", cwd=mirror)
        fetched = git(
            "-c", "protocol.version=2", "fetch", "--quiet", "--no-tags", "--filter=tree:0",
            url, f"+refs/heads/{branch}:refs/heads/{branch}",
            cwd=mirror, check=False,
        )
        if fetched.returncode != 0:
            return [f"cannot fetch {branch} of {url}: {fetched.stderr.strip()}"]
        if git("cat-file", "-e", f"{pinned}^{{commit}}", cwd=mirror, check=False).returncode != 0:
            return [f"the pinned kernel commit {pinned} is not on {branch} of {url}"]
        if git("merge-base", "--is-ancestor", pinned, f"refs/heads/{branch}", cwd=mirror, check=False).returncode != 0:
            return [f"the pinned kernel commit {pinned} is not on {branch} of {url}"]
    return []


def check(root: Path, offline: bool, url: str = AITP_URL) -> list[str]:
    pinned, findings = check_structure(root)
    if pinned is not None and (root / KERNEL_PATH / ".git").exists():
        findings += check_locks(root)
    if pinned is not None and not offline:
        findings += check_on_main(pinned, url)
    return findings


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--offline", action="store_true", help="skip the check against AITP's main branch")
    options = parser.parse_args(arguments)
    findings = check(ROOT, options.offline)
    for finding in findings:
        print(f"kernel submodule: {finding}", file=sys.stderr)
    if findings:
        return 1
    print("kernel submodule: pinned commit checked out, locks agree" + ("" if options.offline else ", on AITP main"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
