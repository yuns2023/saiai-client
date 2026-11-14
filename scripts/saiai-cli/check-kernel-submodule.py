#!/usr/bin/env python3
"""Check the kernel submodule tools/saiai-cli/kernel.

Usage: check-kernel-submodule.py [--offline]

The kernel is the public AITP repository, checked out as a git submodule.
This fails unless

* .gitmodules lists exactly that one submodule, at that path, from AITP's
  public URL, with no other settings;
* the commit being checked pins the kernel (a gitlink), and the checked-out
  kernel is that commit, with no local change;
* the kernel package resolves to the same packages (name, version, source,
  checksum), with the same dependency edges, in AITP's lock file and in
  this workspace's (a kernel dependency is updated in AITP first, then the
  submodule moves);
* unless --offline: the pinned commit is on AITP's main branch, fetched
  afresh (a commit never pushed there, or force-pushed away, could not be
  rebuilt). Only commits are fetched, into a temporary repository;
* unless --offline: AITP's own CI (.github/workflows/ci.yml) ran for the
  pinned commit on a push to main and succeeded (GitHub Actions API; with
  GITHUB_TOKEN or GH_TOKEN from the environment when set, else anonymous).

Findings go to standard error, one per line, and the exit status is 1.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KERNEL_PATH = "tools/saiai-cli/kernel"
AITP_URL = "https://github.com/2742zdz/AITP"
AITP_BRANCH = "main"
WORKSPACE_LOCK = "tools/saiai-cli/Cargo.lock"
COMMIT = re.compile(r"[0-9a-f]{40}")
FETCH_TIMEOUT = 180


def git(*arguments: str, cwd: Path, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def submodule_settings(root: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Each submodule's settings as .gitmodules (in the commit) lists them."""
    found: dict[str, dict[str, str]] = {}
    listed = git("config", "-z", "--blob", "HEAD:.gitmodules", "--list", cwd=root, check=False)
    if listed.returncode != 0:
        return found, [".gitmodules is missing from the commit or unreadable"]
    for record in listed.stdout.split("\0"):
        if not record:
            continue
        key, _, value = record.partition("\n")
        match = re.fullmatch(r"submodule\.(.+)\.([^.]+)", key)
        if match is None:
            return found, [f".gitmodules has an unexpected entry: {key!r}"]
        section = found.setdefault(match.group(1), {})
        # A repeated key is refused, not resolved (git readers differ).
        if match.group(2) in section:
            return found, [f".gitmodules repeats {key!r}"]
        section[match.group(2)] = value
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
    staged_gitmodules = git("show", ":.gitmodules", cwd=root, check=False)
    if staged_gitmodules.returncode != 0 or staged_gitmodules.stdout != committed:
        findings.append(".gitmodules in the index differs from the commit")
    committed_links = [
        line for line in git("ls-tree", "-r", "HEAD", cwd=root).stdout.splitlines()
        if line.startswith("160000 ") and not line.endswith("\t" + KERNEL_PATH)
    ]
    if committed_links:
        findings.append(f"other submodules in the commit: {committed_links}")

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
    # Tracked changes and untracked files that are not ignored (a build
    # directory such as target/ is ignored by AITP's .gitignore).
    changes = git("status", "--porcelain", "--untracked-files=all", cwd=kernel, check=False)
    if changes.returncode != 0 or changes.stdout.strip():
        findings.append(f"{KERNEL_PATH} has local changes: {changes.stdout.strip() or changes.stderr.strip()}")
    return pinned, findings


KERNEL_PACKAGE = "proxy-cli"
Package = tuple[str, str, str | None, str | None]  # name, version, source, checksum
# Every line of a [[package]] table as cargo writes it.
LOCK_LINE = re.compile(r'(?:name|version|source|checksum) = "[^"]*"|dependencies = \[| "[^"\n]*",|\]')


def lock_graph(text: str, label: str) -> tuple[dict[Package, set[Package]], list[str]]:
    """The dependency graph of a Cargo.lock (version 3/4 layout): each
    package with the packages its `dependencies` entries resolve to."""
    packages: list[tuple[Package, list[str]]] = []
    findings = []
    for block in text.split("[[package]]")[1:]:
        # Without a trailing table such as [metadata] (older lock files).
        block = block.split("\n[", 1)[0]

        def field(name: str) -> str | None:
            match = re.search(rf'^{name} = "([^"]*)"', block, re.MULTILINE)
            return match.group(1) if match else None

        # Only the layout cargo writes is read; anything else is refused
        # rather than read as "no dependencies".
        unknown = [line for line in block.split("\n") if line and LOCK_LINE.fullmatch(line) is None]
        if unknown:
            findings.append(f"{label}: unsupported lock file lines {unknown}")
            continue
        if field("name") is None or field("version") is None:
            findings.append(f"{label}: a package without a name or version")
            continue
        dependencies = []
        if re.search(r"^dependencies\b", block, re.MULTILINE):
            listed = re.search(r"^dependencies = \[\n((?: \"[^\"\n]*\",\n)*)\]$", block, re.MULTILINE)
            if listed is None:
                findings.append(f"{label}: cannot read the dependencies of {field('name')} {field('version')}")
                continue
            dependencies = re.findall(r'^ "([^"]*)",$', listed.group(1), re.MULTILINE)
        packages.append(((field("name"), field("version"), field("source"), field("checksum")), dependencies))
    graph: dict[Package, set[Package]] = {}
    for package, dependencies in packages:
        edges = set()
        for dependency in dependencies:
            # "name", "name version" or "name version (source)".
            match = re.fullmatch(r"(\S+)(?: (\S+))?(?: \((.+)\))?", dependency)
            candidates = [
                other for other, _ in packages
                if match and other[0] == match.group(1)
                and (match.group(2) is None or other[1] == match.group(2))
                and (match.group(3) is None or other[2] == match.group(3))
            ]
            if len(candidates) != 1:
                findings.append(f"{label}: {package[0]} {package[1]} depends on {dependency!r}, which names {len(candidates)} packages")
                continue
            edges.add(candidates[0])
        if package in graph:
            findings.append(f"{label}: {package[0]} {package[1]} is listed twice")
        graph[package] = edges
    return graph, findings


def kernel_closure(graph: dict[Package, set[Package]], label: str) -> tuple[dict[Package, set[Package]], list[str]]:
    """The kernel package and everything it depends on, with their edges."""
    roots = [package for package in graph if package[0] == KERNEL_PACKAGE and package[2] is None]
    if len(roots) != 1:
        return {}, [f"{label} does not lock the kernel package {KERNEL_PACKAGE} exactly once"]
    closure: dict[Package, set[Package]] = {}
    pending = roots
    while pending:
        package = pending.pop()
        if package not in closure:
            closure[package] = graph[package]
            pending.extend(graph[package])
    return closure, []


def check_locks(root: Path) -> list[str]:
    """The kernel resolves to the same packages, with the same edges, in
    AITP's lock file and in this workspace's (the workspace may lock more
    for the SAIAI program)."""
    kernel_lock = root / KERNEL_PATH / "Cargo.lock"
    if not kernel_lock.is_file():
        return [f"{KERNEL_PATH}/Cargo.lock is missing"]
    closures = []
    findings = []
    for label, path in ((f"{KERNEL_PATH}/Cargo.lock", kernel_lock), (WORKSPACE_LOCK, root / WORKSPACE_LOCK)):
        graph, problems = lock_graph(path.read_text(encoding="utf-8"), label)
        closure, missing = kernel_closure(graph, label)
        findings += problems + missing
        closures.append(closure)
    if findings:
        return findings
    aitp, workspace = closures
    if aitp != workspace:
        name = lambda package: f"{package[0]} {package[1]}"
        only_aitp = sorted(name(package) for package in set(aitp) - set(workspace))
        only_workspace = sorted(name(package) for package in set(workspace) - set(aitp))
        edges = sorted(name(package) for package in set(aitp) & set(workspace) if aitp[package] != workspace[package])
        return [
            f"{WORKSPACE_LOCK} does not resolve the kernel's dependencies as AITP's lock does "
            f"(update kernel dependencies in AITP, then move the submodule): only in AITP's lock {only_aitp}, "
            f"only in the workspace's {only_workspace}, other dependencies of {edges}"
        ]
    return []


def check_on_main(pinned: str, url: str = AITP_URL, branch: str = AITP_BRANCH) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="kernel-main-") as scratch:
        mirror = Path(scratch)
        git("init", "--quiet", "--bare", cwd=mirror)
        try:
            fetched = git(
                "-c", "protocol.version=2", "fetch", "--quiet", "--no-tags", "--filter=tree:0",
                url, f"+refs/heads/{branch}:refs/heads/{branch}",
                cwd=mirror, check=False, timeout=FETCH_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return [f"fetching {branch} of {url} took longer than {FETCH_TIMEOUT} s"]
        if fetched.returncode != 0:
            return [f"cannot fetch {branch} of {url}: {fetched.stderr.strip()}"]
        if git("cat-file", "-e", f"{pinned}^{{commit}}", cwd=mirror, check=False).returncode != 0:
            return [f"the pinned kernel commit {pinned} is not on {branch} of {url}"]
        if git("merge-base", "--is-ancestor", pinned, f"refs/heads/{branch}", cwd=mirror, check=False).returncode != 0:
            return [f"the pinned kernel commit {pinned} is not on {branch} of {url}"]
    return []


AITP_API = "https://api.github.com/repos/2742zdz/AITP"
AITP_CI_WORKFLOW = ".github/workflows/ci.yml"
API_TIMEOUT = 30


def list_ci_runs(pinned: str, token: str | None) -> object:
    """AITP's push runs on main for `pinned` (GitHub Actions API)."""
    request = urllib.request.Request(
        f"{AITP_API}/actions/runs?head_sha={pinned}&event=push&branch={AITP_BRANCH}&per_page=100",
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
        return json.load(response)


def check_ci_run(pinned: str, runs=list_ci_runs, environ=os.environ) -> list[str]:
    token = environ.get("GITHUB_TOKEN") or environ.get("GH_TOKEN") or None
    try:
        listed = runs(pinned, token)
    except Exception as error:  # network, HTTP status, timeout, bad JSON
        return [f"cannot list AITP's CI runs for {pinned}: {type(error).__name__}: {error}"]
    workflow_runs = listed.get("workflow_runs") if isinstance(listed, dict) else None
    if not isinstance(workflow_runs, list):
        return [f"AITP's CI runs for {pinned} are unreadable"]
    matching = [
        run for run in workflow_runs
        if isinstance(run, dict)
        and run.get("head_sha") == pinned
        and run.get("event") == "push"
        and run.get("head_branch") == AITP_BRANCH
        and run.get("path") == AITP_CI_WORKFLOW
    ]
    if not matching:
        return [f"AITP's CI ({AITP_CI_WORKFLOW}) has no push run on {AITP_BRANCH} for {pinned}"]
    if not any(run.get("status") == "completed" and run.get("conclusion") == "success" for run in matching):
        states = sorted({f"{run.get('status')}/{run.get('conclusion')}" for run in matching})
        return [f"AITP's CI ({AITP_CI_WORKFLOW}) has not succeeded for {pinned} on {AITP_BRANCH}: {states}"]
    return []


def check(root: Path, offline: bool, url: str = AITP_URL, runs=list_ci_runs, environ=os.environ) -> list[str]:
    pinned, findings = check_structure(root)
    if pinned is not None and (root / KERNEL_PATH / ".git").exists():
        findings += check_locks(root)
    if pinned is not None and not offline:
        findings += check_on_main(pinned, url)
        findings += check_ci_run(pinned, runs, environ)
    return findings


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--offline", action="store_true", help="skip the checks against AITP's main branch and CI")
    options = parser.parse_args(arguments)
    findings = check(ROOT, options.offline)
    for finding in findings:
        print(f"kernel submodule: {finding}", file=sys.stderr)
    if findings:
        return 1
    if options.offline:
        print("kernel submodule: pinned commit checked out, locks agree; "
              "--offline: NOT checked that the commit is on AITP main or that AITP's CI passed for it")
    else:
        print("kernel submodule: pinned commit checked out, locks agree, on AITP main, AITP CI passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
