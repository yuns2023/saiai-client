#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).with_name("test-windows-self-update.py")
SPEC = importlib.util.spec_from_file_location("windows_self_update_smoke", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class WindowsSelfUpdatePollingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.status_path = Mock(spec=Path)
        self.success = "updated: TEST_ONLY_EXPECTED_HASH"

    def test_reads_completed_status_without_delay(self) -> None:
        self.status_path.read_text.return_value = self.success + "\n"
        with patch.object(SMOKE.time, "sleep") as sleep:
            self.assertEqual(SMOKE.wait_for_update_status(self.status_path), self.success)
        self.status_path.read_text.assert_called_once_with(encoding="utf-8-sig")
        sleep.assert_not_called()

    def test_retries_creation_and_exclusive_writer_races(self) -> None:
        self.status_path.read_text.side_effect = [
            FileNotFoundError(), PermissionError(), "pending: replacing binary", self.success,
        ]
        with patch.object(SMOKE.time, "sleep") as sleep:
            self.assertEqual(SMOKE.wait_for_update_status(self.status_path), self.success)
        self.assertEqual(self.status_path.read_text.call_count, 4)
        self.assertEqual(sleep.call_count, 3)

    def test_helper_failure_is_not_retried_or_ignored(self) -> None:
        self.status_path.read_text.return_value = "failed: TEST_ONLY_HELPER_FAILURE"
        with patch.object(SMOKE.time, "sleep") as sleep:
            with self.assertRaisesRegex(AssertionError, "TEST_ONLY_HELPER_FAILURE"):
                SMOKE.wait_for_update_status(self.status_path)
        sleep.assert_not_called()

    def test_persistent_lock_cannot_extend_the_deadline(self) -> None:
        self.status_path.read_text.side_effect = PermissionError()
        with patch.object(SMOKE.time, "monotonic", side_effect=[0, 0, 0.1, 0.2]):
            with patch.object(SMOKE.time, "sleep") as sleep:
                with self.assertRaisesRegex(AssertionError, "status file not readable yet"):
                    SMOKE.wait_for_update_status(self.status_path, timeout=0.15)
        self.assertEqual(self.status_path.read_text.call_count, 2)
        self.assertEqual(sleep.call_count, 2)

    def test_pending_status_still_requires_completion(self) -> None:
        self.status_path.read_text.return_value = "pending: waiting for updater"
        with patch.object(SMOKE.time, "monotonic", side_effect=[0, 0, 1]):
            with patch.object(SMOKE.time, "sleep"):
                with self.assertRaisesRegex(AssertionError, "pending: waiting for updater"):
                    SMOKE.wait_for_update_status(self.status_path, timeout=0.5)

    def test_unrelated_read_failure_propagates_immediately(self) -> None:
        self.status_path.read_text.side_effect = OSError("TEST_ONLY_UNEXPECTED_READ_ERROR")
        with patch.object(SMOKE.time, "sleep") as sleep:
            with self.assertRaisesRegex(OSError, "TEST_ONLY_UNEXPECTED_READ_ERROR"):
                SMOKE.wait_for_update_status(self.status_path)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
