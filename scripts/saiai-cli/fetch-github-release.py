#!/usr/bin/env python3
"""Fetch the GitHub release of a saiai-v* tag and its assets for the publish
run of "SAIAI CLI Release".

Only a release that a successful tag run (event push) of this very commit
produced is fetched, and only the exact release asset names are written."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
WORKFLOW_NAME = "SAIAI CLI Release"
WORKFLOW_PATH = ".github/workflows/saiai-cli-release.yml"
SHA_RE = re.compile(r"[0-9a-f]{40}")


def load_draft_verifier():
    spec = importlib.util.spec_from_file_location(
        "saiai_release_draft", SCRIPT_DIR / "verify-github-release-draft.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXPECTED_FILES = load_draft_verifier().EXPECTED_FILES


class FetchError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FetchError(message)


def tag_run(runs: Any, tag: str, sha: str) -> dict[str, Any]:
    """The latest successful tag run of this workflow for `tag` at `sha`."""
    require(isinstance(runs, list), "workflow runs are not a list")
    matching = [
        run
        for run in runs
        if isinstance(run, dict)
        and run.get("name") == WORKFLOW_NAME
        and run.get("path") == WORKFLOW_PATH
        and run.get("event") == "push"
        and run.get("head_branch") == tag
        and run.get("head_sha") == sha
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and isinstance(run.get("id"), int)
    ]
    require(bool(matching), f"no successful {WORKFLOW_NAME!r} tag run of {tag} at {sha}")
    return max(matching, key=lambda run: run["id"])


def tag_release(pages: Any, tag: str) -> dict[str, Any]:
    """The one release (draft or published) of `tag` in paginated results."""
    require(isinstance(pages, list), "release pages are not a list")
    releases = []
    for page in pages:
        require(isinstance(page, list), "a release page is not a list")
        releases.extend(page)
    matching = [release for release in releases if isinstance(release, dict) and release.get("tag_name") == tag]
    require(len(matching) == 1, f"expected exactly one release of {tag}, found {len(matching)}")
    release = matching[0]
    require(isinstance(release.get("id"), int), "release id is invalid")
    require(isinstance(release.get("draft"), bool), "release draft flag is invalid")
    require(release.get("prerelease") is False, "release is marked as a prerelease")
    return release


def asset_plan(release: dict[str, Any]) -> list[tuple[int, str]]:
    """(asset id, file name) for exactly the expected release files."""
    assets = release.get("assets")
    require(isinstance(assets, list), "release assets are not a list")
    plan = []
    for asset in assets:
        require(isinstance(asset, dict), "release asset is not an object")
        name, identifier = asset.get("name"), asset.get("id")
        require(name in EXPECTED_FILES, f"unexpected release asset: {name!r}")
        require(isinstance(identifier, int), f"release asset id is invalid: {name}")
        plan.append((identifier, name))
    names = [name for _, name in plan]
    require(len(set(names)) == len(names), "release contains a duplicate asset name")
    require(set(names) == EXPECTED_FILES, "remote release asset set is not exact")
    return sorted(plan, key=lambda item: item[1])


def gh(*arguments: str) -> bytes:
    result = subprocess.run(["gh", "api", *arguments], capture_output=True, check=False)
    if result.returncode != 0:
        raise FetchError(f"gh api {arguments[-1]} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--release-json", required=True, type=Path)
    parser.add_argument("--github-output", required=True, type=Path)
    args = parser.parse_args()
    try:
        require(re.fullmatch(r"saiai-v[0-9A-Za-z.+-]+", args.tag) is not None, "tag is not a saiai-v* tag")
        require(SHA_RE.fullmatch(args.sha) is not None, "commit is not a full SHA")
        require(not args.dist.exists(), f"{args.dist} already exists")
        # Runs of this workflow file only: another workflow may carry the same name.
        runs = json.loads(gh(
            f"repos/{args.repository}/actions/workflows/{Path(WORKFLOW_PATH).name}/runs"
            f"?event=push&head_sha={args.sha}&per_page=100"
        ))
        run = tag_run(runs.get("workflow_runs") if isinstance(runs, dict) else None, args.tag, args.sha)
        pages = json.loads(gh("--paginate", "--slurp", f"repos/{args.repository}/releases?per_page=100"))
        release = tag_release(pages, args.tag)
        plan = asset_plan(release)
        args.dist.mkdir(parents=True)
        for identifier, name in plan:
            data = gh("-H", "Accept: application/octet-stream", f"repos/{args.repository}/releases/assets/{identifier}")
            require(len(data) > 0, f"release asset is empty: {name}")
            (args.dist / name).write_bytes(data)
        args.release_json.write_text(json.dumps(release), encoding="utf-8")
        state = "draft" if release["draft"] else "published"
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"id={release['id']}\nstate={state}\nrun_id={run['id']}\n")
    except (FetchError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"fetched {state} release {release['id']} of {args.tag} ({len(plan)} assets), built by run {run['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
