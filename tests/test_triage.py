"""Unit tests for reconflow mark triage state and diff suppression."""

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow import diff, triage
from reconflow.cli import main


class TestTriageState(unittest.TestCase):
    """Test suite for host triage state management."""

    def test_normalize_target_host(self):
        """Host normalization strips scheme, credentials, ports, and paths."""
        self.assertEqual(
            triage.normalize_target_host("https://admin.example.com:8443/path?q=1"),
            "admin.example.com",
        )
        self.assertEqual(triage.normalize_target_host("API.Example.com."), "api.example.com")
        self.assertEqual(
            triage.normalize_target_host("http://user:pass@internal.net:80/"),
            "internal.net",
        )

    def test_mark_host_tested_and_ignore(self):
        """mark_host stores tested and ignore records in triage.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            domain_dir = Path(tmpdir) / "example.com"

            triage.mark_host(domain_dir, "admin.example.com", "tested", notes="Reviewed panel")
            data = triage.load_triage(domain_dir)
            self.assertIn("admin.example.com", data["hosts"])
            self.assertEqual(data["hosts"]["admin.example.com"]["status"], "tested")
            self.assertEqual(data["hosts"]["admin.example.com"]["notes"], "Reviewed panel")

            # Update to ignore
            triage.mark_host(domain_dir, "https://admin.example.com/", "ignore")
            data = triage.load_triage(domain_dir)
            self.assertEqual(data["hosts"]["admin.example.com"]["status"], "ignore")

    def test_infer_domain(self):
        """infer_domain extracts root domain or matches output folders."""
        self.assertEqual(triage.infer_domain("api.sub.example.com"), "example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir)
            (out_path / "target.org").mkdir()
            self.assertEqual(
                triage.infer_domain("sub.dev.target.org", output_dir=out_path),
                "target.org",
            )

    def test_diff_suppresses_tested_host(self):
        """Tested hosts must not appear as new_live in differential scans."""
        old = {
            "run_id": "run1",
            "hosts": [{"url": "https://a.example.com"}],
            "subdomains": ["a.example.com"],
        }
        new = {
            "run_id": "run2",
            "hosts": [
                {"url": "https://a.example.com"},
                {"url": "https://admin.example.com", "status_code": 200},
                {"url": "https://api.example.com", "status_code": 200},
            ],
            "subdomains": ["a.example.com", "admin.example.com", "api.example.com"],
        }

        # admin.example.com is triaged as tested
        triage_hosts = {"admin.example.com": {"status": "tested"}}

        result = diff.compare(old, new, triage_hosts=triage_hosts)
        # admin.example.com should be suppressed from new_live
        self.assertEqual(result["new_live"], ["https://api.example.com"])
        self.assertIn("https://admin.example.com", result.get("suppressed_triaged", []))

        # Check formatted diff output mentions filtered hosts
        formatted = diff.format_diff(result, "run1", "run2")
        self.assertIn("Filtered out 1 triaged host", formatted)
        self.assertNotIn("+ https://admin.example.com", formatted)

    def test_diff_suppresses_changed_host_if_triaged(self):
        """Changed hosts that are already triaged must be suppressed."""
        old = {
            "run_id": "run1",
            "hosts": [{"url": "https://admin.example.com", "status_code": 403}],
            "subdomains": ["admin.example.com"],
        }
        new = {
            "run_id": "run2",
            "hosts": [{"url": "https://admin.example.com", "status_code": 200}],
            "subdomains": ["admin.example.com"],
        }

        triage_hosts = {"admin.example.com": {"status": "ignore"}}
        result = diff.compare(old, new, triage_hosts=triage_hosts)

        self.assertEqual(result["changed"], {})
        self.assertIn("https://admin.example.com", result.get("suppressed_triaged", []))

    def test_diff_resurfaces_tested_host_on_change(self):
        """A host marked --tested resurfaces in changed if its status/tech changes."""
        old = {
            "run_id": "run1",
            "hosts": [{"url": "https://admin.example.com", "status_code": 403}],
            "subdomains": ["admin.example.com"],
        }
        new = {
            "run_id": "run2",
            "hosts": [{"url": "https://admin.example.com", "status_code": 200}],
            "subdomains": ["admin.example.com"],
        }

        triage_hosts = {"admin.example.com": {"status": "tested"}}
        result = diff.compare(old, new, triage_hosts=triage_hosts)

        # Must resurface in changed!
        self.assertIn("https://admin.example.com", result["changed"])
        self.assertEqual(result["changed"]["https://admin.example.com"]["status_code"], (403, 200))

    def test_cli_mark_dispatch(self):
        """CLI 'reconflow mark <host> --tested' updates triage state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                main([
                    "mark",
                    "admin.example.com",
                    "--tested",
                    "--domain",
                    "example.com",
                    "-o",
                    tmpdir,
                ])
                out = mock_out.getvalue()

            self.assertIn("Marked admin.example.com as 'tested'", out)
            data = triage.load_triage(Path(tmpdir) / "example.com")
            self.assertEqual(data["hosts"]["admin.example.com"]["status"], "tested")

    def test_cli_mark_missing_flag_aborts(self):
        """reconflow mark without --tested or --ignore aborts with error."""
        with self.assertRaises(SystemExit):
            args = MagicMock()
            args.host = "admin.example.com"
            args.tested = False
            args.ignore = False
            args.list = False
            args.domain = "example.com"
            args.output = "output"
            triage.run(args)


if __name__ == "__main__":
    unittest.main()
