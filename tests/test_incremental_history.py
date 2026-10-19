"""Unit tests for incremental scan results, resilience to truncated lines,
and backward compatibility."""

import tempfile
import unittest
from pathlib import Path

from reconflow.history import (
    finalize_run,
    init_run,
    list_runs,
    load_snapshot,
    record_host,
    record_subdomain,
    save_snapshot,
)


class TestIncrementalHistory(unittest.TestCase):
    """Test suite for incremental saving, incomplete scan metadata, and truncated JSONL parsing."""

    def test_init_run_marks_incomplete(self):
        """init_run should immediately create snapshot.json with incomplete metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            run_id, run_dir = init_run(out_dir, domain="example.com")

            snapshot = load_snapshot(run_dir)
            self.assertEqual(snapshot["run_id"], run_id)
            self.assertEqual(snapshot["status"], "incomplete")
            self.assertTrue(snapshot["incomplete"])
            self.assertEqual(snapshot["subdomains"], [])
            self.assertEqual(snapshot["hosts"], [])

    def test_incremental_records_flushed(self):
        """record_subdomain and record_host should append and flush to scan.jsonl."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            run_id, run_dir = init_run(out_dir, domain="example.com")

            record_subdomain(run_dir, "api.example.com")
            record_subdomain(run_dir, "dev.example.com")
            record_host(run_dir, {"url": "https://api.example.com", "status_code": 200})

            jsonl_file = run_dir / "scan.jsonl"
            self.assertTrue(jsonl_file.exists())
            content = jsonl_file.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(content), 3)

            # Incomplete run should recover the recorded subdomains and hosts
            snapshot = load_snapshot(run_dir)
            self.assertEqual(snapshot["status"], "incomplete")
            self.assertEqual(snapshot["subdomains"], ["api.example.com", "dev.example.com"])
            self.assertEqual(len(snapshot["hosts"]), 1)
            self.assertEqual(snapshot["hosts"][0]["url"], "https://api.example.com")

    def test_truncated_last_line_handled(self):
        """load_snapshot should gracefully ignore a truncated last line in scan.jsonl."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            run_id, run_dir = init_run(out_dir, domain="example.com")

            record_subdomain(run_dir, "api.example.com")
            record_host(run_dir, {"url": "https://api.example.com", "status_code": 200})

            # Simulate an abrupt crash or SIGKILL that leaves a truncated last line
            jsonl_file = run_dir / "scan.jsonl"
            with open(jsonl_file, "a", encoding="utf-8") as f:
                f.write('{"type": "host", "host": {"url": "https://crashed.exam')

            snapshot = load_snapshot(run_dir)
            self.assertEqual(snapshot["status"], "incomplete")
            self.assertEqual(snapshot["subdomains"], ["api.example.com"])
            self.assertEqual(len(snapshot["hosts"]), 1)
            self.assertEqual(snapshot["hosts"][0]["url"], "https://api.example.com")

    def test_finalize_run_marks_complete(self):
        """finalize_run should update snapshot.json to complete."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            run_id, run_dir = init_run(out_dir, domain="example.com")

            subs = ["api.example.com", "example.com"]
            hosts = [{"url": "https://api.example.com", "status_code": 200}]
            finalize_run(run_dir, subs, hosts, domain="example.com")

            snapshot = load_snapshot(run_dir)
            self.assertEqual(snapshot["status"], "complete")
            self.assertFalse(snapshot["incomplete"])
            self.assertEqual(snapshot["subdomains"], subs)
            self.assertEqual(snapshot["hosts"], hosts)

    def test_backward_compatible_legacy_snapshot(self):
        """Legacy snapshots from v0.2.x without status field load cleanly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            runs_dir = out_dir / "runs"
            run_dir = runs_dir / "2026-10-18_120000"
            run_dir.mkdir(parents=True, exist_ok=True)

            legacy_data = """{
  "run_id": "2026-10-18_120000",
  "timestamp": "2026-10-18T12:00:00",
  "subdomains": ["old.example.com"],
  "hosts": [{"url": "https://old.example.com", "status_code": 200}]
}"""
            (run_dir / "snapshot.json").write_text(legacy_data, encoding="utf-8")

            runs = list_runs(out_dir)
            self.assertEqual(len(runs), 1)

            snapshot = load_snapshot(run_dir)
            self.assertEqual(snapshot["status"], "complete")
            self.assertFalse(snapshot["incomplete"])
            self.assertEqual(snapshot["subdomains"], ["old.example.com"])
            self.assertEqual(len(snapshot["hosts"]), 1)

    def test_save_snapshot_backward_compatibility(self):
        """save_snapshot function remains backward compatible."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            run_id = save_snapshot(
                out_dir,
                ["sub.example.com"],
                [{"url": "https://sub.example.com", "status_code": 200}],
            )
            runs = list_runs(out_dir)
            self.assertEqual(len(runs), 1)
            snapshot = load_snapshot(runs[0])
            self.assertEqual(snapshot["run_id"], run_id)
            self.assertEqual(snapshot["status"], "complete")


if __name__ == "__main__":
    unittest.main()
