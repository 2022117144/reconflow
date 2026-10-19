"""Unit tests for reconflow report regeneration without re-scanning."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.cli import build_parser, main
from reconflow.history import save_snapshot
from reconflow.report import run as run_report


class TestReportGeneration(unittest.TestCase):
    """Test suite for reconflow report subcommand."""

    def setUp(self):
        self.parser = build_parser()

    def test_report_subcommand_defaults(self):
        """Parsing 'report example.com' sets proper defaults."""
        args = self.parser.parse_args(["report", "example.com"])
        self.assertEqual(args.command, "report")
        self.assertEqual(args.domain, "example.com")
        self.assertEqual(args.output, "output")
        self.assertIsNone(args.run_id)
        self.assertFalse(args.json_report)

    @patch("reconflow.report.run")
    def test_main_dispatch_report(self, mock_report_run):
        """main(['report', 'example.com', '--json']) routes to report.run."""
        main(["report", "example.com", "--json"])
        self.assertTrue(mock_report_run.called)
        called_args = mock_report_run.call_args[0][0]
        self.assertEqual(called_args.domain, "example.com")
        self.assertTrue(called_args.json_report)

    def test_regenerate_report_latest_run(self):
        """reconflow report regenerates report.md and report.json from latest snapshot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            domain = "example.com"
            out_dir = Path(tmpdir) / domain

            # Save two snapshots
            save_snapshot(
                out_dir,
                ["old.example.com"],
                [{"url": "https://old.example.com", "status_code": 200}],
                domain=domain,
            )
            run2 = save_snapshot(
                out_dir,
                ["new.example.com", "api.example.com"],
                [
                    {"url": "https://new.example.com", "status_code": 200, "title": "New"},
                    {"url": "https://api.example.com", "status_code": 403, "title": "API"},
                ],
                domain=domain,
            )

            args = MagicMock(
                domain=domain,
                output=tmpdir,
                run_id=None,
                json_report=False,
                json=False,
            )

            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                run_report(args)
                output = mock_out.getvalue()

            self.assertIn(f"Run ID: `{run2}`", output)
            self.assertIn("https://new.example.com [200] [New]", output)
            self.assertIn("https://api.example.com [403] [API]", output)

            # Check files were written
            md_file = out_dir / "report.md"
            json_file = out_dir / "report.json"
            self.assertTrue(md_file.exists())
            self.assertTrue(json_file.exists())

            json_content = json.loads(json_file.read_text(encoding="utf-8"))
            self.assertEqual(json_content["run_id"], run2)
            self.assertEqual(json_content["live_count"], 2)

    def test_regenerate_report_specific_run(self):
        """reconflow report --run <id> regenerates report for that specific run."""
        with tempfile.TemporaryDirectory() as tmpdir:
            domain = "example.com"
            out_dir = Path(tmpdir) / domain

            run1 = save_snapshot(
                out_dir,
                ["first.example.com"],
                [{"url": "https://first.example.com", "status_code": 200, "title": "First"}],
                domain=domain,
            )
            save_snapshot(
                out_dir,
                ["second.example.com"],
                [{"url": "https://second.example.com", "status_code": 200, "title": "Second"}],
                domain=domain,
            )

            args = MagicMock(
                domain=domain,
                output=tmpdir,
                run_id=run1,
                json_report=False,
                json=False,
            )

            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                run_report(args)
                output = mock_out.getvalue()

            self.assertIn(f"Run ID: `{run1}`", output)
            self.assertIn("https://first.example.com [200] [First]", output)
            self.assertNotIn("second.example.com", output)

    def test_report_json_flag(self):
        """reconflow report --json outputs structured JSON to stdout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            domain = "example.com"
            out_dir = Path(tmpdir) / domain

            save_snapshot(
                out_dir,
                ["api.example.com"],
                [{"url": "https://api.example.com", "status_code": 200}],
                domain=domain,
            )

            args = MagicMock(
                domain=domain,
                output=tmpdir,
                run_id=None,
                json_report=True,
                json=True,
            )

            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                run_report(args)
                output = mock_out.getvalue()

            data = json.loads(output)
            self.assertEqual(data["domain"], "example.com")
            self.assertEqual(data["subdomains_count"], 1)
            self.assertEqual(data["live_count"], 1)

    def test_report_no_history_exits_cleanly(self):
        """When no history exists, report prints friendly message and exits."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = MagicMock(
                domain="nonexistent.test",
                output=tmpdir,
                run_id=None,
                json_report=False,
                json=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    run_report(args)
                self.assertEqual(cm.exception.code, 0)
                self.assertIn("No scan history found", mock_out.getvalue())

    def test_report_missing_specific_run_exits_with_error(self):
        """When specified --run ID does not exist, report exits with error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            domain = "example.com"
            out_dir = Path(tmpdir) / domain
            save_snapshot(out_dir, ["sub.example.com"], [], domain=domain)

            args = MagicMock(
                domain=domain,
                output=tmpdir,
                run_id="2099-01-01_999999",
                json_report=False,
                json=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    run_report(args)
                self.assertEqual(cm.exception.code, 1)
                self.assertIn("not found for example.com", mock_out.getvalue())


if __name__ == "__main__":
    unittest.main()
