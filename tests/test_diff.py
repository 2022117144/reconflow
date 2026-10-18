"""Unit tests for reconflow.history and reconflow.diff modules."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.diff import compare, format_diff, run as run_diff
from reconflow.history import list_runs, load_snapshot, save_snapshot


class TestDiffCompare(unittest.TestCase):
    """Test suite for compare() pure function with hand-written snapshots."""

    def test_compare_no_changes(self):
        old = {
            "subdomains": ["app.example.com", "example.com"],
            "hosts": [
                {
                    "url": "https://example.com",
                    "status_code": 200,
                    "title": "Home",
                    "technologies": ["Nginx"],
                }
            ],
        }
        new = {
            "subdomains": ["app.example.com", "example.com"],
            "hosts": [
                {
                    "url": "https://example.com",
                    "status_code": 200,
                    "title": "Home",
                    "technologies": ["Nginx"],
                }
            ],
        }
        res = compare(old, new)
        self.assertEqual(res["new_subdomains"], [])
        self.assertEqual(res["removed_subdomains"], [])
        self.assertEqual(res["new_live"], [])
        self.assertEqual(res["gone_live"], [])
        self.assertEqual(res["changed"], {})

    def test_compare_one_new_host(self):
        """Verify hand-written snapshot with exactly one new host."""
        old = {
            "subdomains": ["example.com"],
            "hosts": [{"url": "https://example.com", "status_code": 200}],
        }
        new = {
            "subdomains": ["example.com", "api.example.com"],
            "hosts": [
                {"url": "https://example.com", "status_code": 200},
                {"url": "https://api.example.com", "status_code": 200},
            ],
        }
        res = compare(old, new)
        self.assertEqual(res["new_live"], ["https://api.example.com"])
        self.assertEqual(res["gone_live"], [])
        self.assertEqual(res["changed"], {})
        self.assertEqual(res["new_subdomains"], ["api.example.com"])
        self.assertEqual(res["removed_subdomains"], [])

    def test_compare_one_status_change(self):
        """Verify hand-written snapshot with exactly one status change."""
        old = {
            "subdomains": ["admin.example.com"],
            "hosts": [
                {"url": "https://admin.example.com", "status_code": 403, "title": "Access Denied"}
            ],
        }
        new = {
            "subdomains": ["admin.example.com"],
            "hosts": [
                {"url": "https://admin.example.com", "status_code": 200, "title": "Dashboard"}
            ],
        }
        res = compare(old, new)
        self.assertEqual(res["new_live"], [])
        self.assertEqual(res["gone_live"], [])
        self.assertIn("https://admin.example.com", res["changed"])
        diffs = res["changed"]["https://admin.example.com"]
        self.assertEqual(diffs["status_code"], (403, 200))
        self.assertEqual(diffs["title"], ("Access Denied", "Dashboard"))

    def test_compare_one_removed_host(self):
        """Verify hand-written snapshot with exactly one removed host."""
        old = {
            "subdomains": ["staging.example.com", "example.com"],
            "hosts": [
                {"url": "https://example.com", "status_code": 200},
                {"url": "https://staging.example.com", "status_code": 200},
            ],
        }
        new = {
            "subdomains": ["example.com"],
            "hosts": [{"url": "https://example.com", "status_code": 200}],
        }
        res = compare(old, new)
        self.assertEqual(res["new_live"], [])
        self.assertEqual(res["gone_live"], ["https://staging.example.com"])
        self.assertEqual(res["removed_subdomains"], ["staging.example.com"])
        self.assertEqual(res["new_subdomains"], [])
        self.assertEqual(res["changed"], {})

    def test_compare_new_and_removed_subdomains(self):
        old = {
            "subdomains": ["api.example.com", "legacy.example.com"],
            "hosts": [],
        }
        new = {
            "subdomains": ["api.example.com", "v2.example.com"],
            "hosts": [],
        }
        res = compare(old, new)
        self.assertEqual(res["new_subdomains"], ["v2.example.com"])
        self.assertEqual(res["removed_subdomains"], ["legacy.example.com"])

    def test_compare_technology_diff(self):
        old = {
            "subdomains": [],
            "hosts": [
                {"url": "https://app.test", "status_code": 200, "technologies": ["Apache"]}
            ],
        }
        new = {
            "subdomains": [],
            "hosts": [
                {"url": "https://app.test", "status_code": 200, "technologies": ["Apache", "PHP"]}
            ],
        }
        res = compare(old, new)
        self.assertIn("https://app.test", res["changed"])
        diffs = res["changed"]["https://app.test"]
        self.assertEqual(diffs["technologies"], (["Apache"], ["Apache", "PHP"]))


class TestDiffFormatting(unittest.TestCase):
    """Test suite for human-readable diff output."""

    def test_format_diff_no_changes(self):
        diff_res = {
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_live": [],
            "gone_live": [],
            "changed": {},
        }
        text = format_diff(diff_res, "run1", "run2")
        self.assertIn("No changes detected", text)

    def test_format_diff_with_all_sections(self):
        diff_res = {
            "new_subdomains": ["new.example.com"],
            "removed_subdomains": ["old.example.com"],
            "new_live": ["https://new.example.com"],
            "gone_live": ["https://old.example.com"],
            "changed": {
                "https://api.example.com": {
                    "status_code": (403, 200),
                    "title": ("Denied", "Welcome"),
                    "technologies": (["Apache"], ["Nginx"]),
                }
            },
        }
        text = format_diff(diff_res, "run1", "run2")
        self.assertIn("NEW SUBDOMAINS (1):", text)
        self.assertIn("+ new.example.com", text)
        self.assertIn("NEWLY LIVE HOSTS (1):", text)
        self.assertIn("+ https://new.example.com", text)
        self.assertIn("CHANGED HOSTS (1):", text)
        self.assertIn("status: 403 -> 200", text)
        self.assertIn("title: 'Denied' -> 'Welcome'", text)
        self.assertIn("tech: ['Apache'] -> ['Nginx']", text)
        self.assertIn("Removed subdomains (1) [informational]:", text)
        self.assertIn("Inactive hosts (1) [informational]:", text)


class TestHistory(unittest.TestCase):
    """Test suite for snapshot save and load."""

    def test_save_and_load_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            subs = ["a.example.com", "b.example.com"]
            hosts = [{"url": "https://a.example.com", "status_code": 200}]

            run_id = save_snapshot(out_dir, subs, hosts)
            runs = list_runs(out_dir)
            self.assertEqual(len(runs), 1)

            loaded = load_snapshot(runs[0])
            self.assertEqual(loaded["run_id"], run_id)
            self.assertEqual(loaded["subdomains"], sorted(subs))
            self.assertEqual(len(loaded["hosts"]), 1)
            self.assertEqual(loaded["hosts"][0]["url"], "https://a.example.com")


class TestDiffCLI(unittest.TestCase):
    """Test suite for reconflow diff command execution."""

    def test_diff_not_enough_runs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = MagicMock(domain="example.com", output=tmpdir, json_report=False, json=False)
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    run_diff(args)
                self.assertEqual(cm.exception.code, 0)
                self.assertIn("No scan history found", mock_out.getvalue())

    def test_diff_single_run_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            domain = "example.com"
            out_dir = Path(tmpdir) / domain
            save_snapshot(out_dir, ["a.example.com"], [])

            args = MagicMock(domain=domain, output=tmpdir, json_report=False, json=False)
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    run_diff(args)
                self.assertEqual(cm.exception.code, 0)
                self.assertIn("Need at least 2 runs to compare", mock_out.getvalue())

    def test_diff_with_changes_human(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            domain = "example.com"
            out_dir = Path(tmpdir) / domain

            save_snapshot(
                out_dir,
                ["a.example.com"],
                [{"url": "https://a.example.com", "status_code": 403}],
            )
            save_snapshot(
                out_dir,
                ["a.example.com", "b.example.com"],
                [{"url": "https://a.example.com", "status_code": 200}],
            )

            args = MagicMock(domain=domain, output=tmpdir, json_report=False, json=False)
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    run_diff(args)
                self.assertEqual(cm.exception.code, 1)
                output = mock_out.getvalue()
                self.assertIn("NEW SUBDOMAINS", output)
                self.assertIn("b.example.com", output)
                self.assertIn("CHANGED HOSTS", output)
                self.assertIn("status: 403 -> 200", output)

    def test_diff_with_changes_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            domain = "example.com"
            out_dir = Path(tmpdir) / domain

            save_snapshot(out_dir, ["a.example.com"], [])
            save_snapshot(out_dir, ["a.example.com", "new.example.com"], [])

            args = MagicMock(domain=domain, output=tmpdir, json_report=True, json=False)
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    run_diff(args)
                self.assertEqual(cm.exception.code, 1)
                data = json.loads(mock_out.getvalue())
                self.assertTrue(data["has_changes"])
                self.assertEqual(data["new_subdomains"], ["new.example.com"])

    def test_diff_no_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            domain = "example.com"
            out_dir = Path(tmpdir) / domain

            save_snapshot(out_dir, ["a.example.com"], [{"url": "https://a.example.com"}])
            save_snapshot(out_dir, ["a.example.com"], [{"url": "https://a.example.com"}])

            args = MagicMock(domain=domain, output=tmpdir, json_report=False, json=False)
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    run_diff(args)
                self.assertEqual(cm.exception.code, 0)
                self.assertIn("No changes detected", mock_out.getvalue())


if __name__ == "__main__":
    unittest.main()
