#!/usr/bin/env python3
"""Regression tests for choosing the release the publish run fetches."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("saiai_fetch_release", SCRIPT_DIR / "fetch-github-release.py")
FETCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FETCH)

TAG = "saiai-v9.8.7"
SHA = "a" * 40


def run(**changes):
    value = {
        "id": 7, "name": "SAIAI CLI Release", "event": "push", "head_branch": TAG,
        "head_sha": SHA, "status": "completed", "conclusion": "success",
    }
    value.update(changes)
    return value


def release(**changes):
    value = {
        "id": 11, "tag_name": TAG, "draft": True, "prerelease": False,
        "assets": [{"id": index, "name": name} for index, name in enumerate(sorted(FETCH.EXPECTED_FILES))],
    }
    value.update(changes)
    return value


class TagRunTests(unittest.TestCase):
    def test_accepts_the_latest_successful_tag_run(self) -> None:
        self.assertEqual(FETCH.tag_run([run(id=3), run(id=9), run(id=12, conclusion="failure")], TAG, SHA)["id"], 9)

    def test_rejects_other_runs(self) -> None:
        for other in (
            run(event="workflow_dispatch"), run(head_branch="main"), run(head_sha="b" * 40),
            run(name="Client CI"), run(conclusion="failure"), run(status="in_progress"), run(id="7"),
        ):
            with self.subTest(other=other), self.assertRaisesRegex(FETCH.FetchError, "no successful"):
                FETCH.tag_run([other], TAG, SHA)


class TagReleaseTests(unittest.TestCase):
    def test_finds_the_release_across_pages(self) -> None:
        found = FETCH.tag_release([[release(id=1, tag_name="saiai-v1.0.0")], [release()]], TAG)
        self.assertEqual(found["id"], 11)

    def test_requires_exactly_one_release(self) -> None:
        for pages in ([[]], [[release()], [release(id=12)]]):
            with self.subTest(pages=len(pages)), self.assertRaisesRegex(FETCH.FetchError, "exactly one"):
                FETCH.tag_release(pages, TAG)

    def test_rejects_prerelease_and_bad_fields(self) -> None:
        for bad in (release(prerelease=True), release(draft="true"), release(id="11")):
            with self.subTest(bad=bad), self.assertRaises(FETCH.FetchError):
                FETCH.tag_release([[bad]], TAG)


class AssetPlanTests(unittest.TestCase):
    def test_plans_exactly_the_release_files(self) -> None:
        self.assertEqual({name for _, name in FETCH.asset_plan(release())}, FETCH.EXPECTED_FILES)

    def test_rejects_unexpected_missing_and_duplicate_assets(self) -> None:
        extra = release()
        extra["assets"].append({"id": 99, "name": "../escape"})
        missing = release()
        missing["assets"].pop()
        duplicate = release()
        duplicate["assets"].append(copy.deepcopy(duplicate["assets"][0]))
        for bad, message in ((extra, "unexpected"), (missing, "not exact"), (duplicate, "duplicate")):
            with self.subTest(message=message), self.assertRaisesRegex(FETCH.FetchError, message):
                FETCH.asset_plan(bad)


if __name__ == "__main__":
    unittest.main()
