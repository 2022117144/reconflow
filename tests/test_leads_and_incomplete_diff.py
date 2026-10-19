"""Unit tests for lead hints in diff and incomplete scan safeguards."""

import unittest

from reconflow import diff
from reconflow.leads import (
    extract_hints_for_change,
    extract_hints_for_host,
)


class TestLeadHints(unittest.TestCase):
    """Test suite for lead hint extraction rules."""

    def test_hostname_keywords(self):
        """Hostname keywords trigger appropriate 'worth checking' hints."""
        hints = extract_hints_for_host("https://admin.staging.example.com")
        self.assertTrue(any("admin" in h.lower() for h in hints))
        self.assertTrue(any("staging" in h.lower() for h in hints))
        for h in hints:
            self.assertTrue(h.startswith("Worth checking:"))

    def test_tech_and_title_hints(self):
        """Recognized technologies and titles generate actionable lead hints."""
        hints = extract_hints_for_host(
            "https://api.example.com",
            status_code=200,
            title="Swagger UI - API Docs",
            tech=["Spring Boot", "Nginx"],
        )
        self.assertTrue(any("swagger" in h.lower() for h in hints))
        self.assertTrue(any("spring boot" in h.lower() for h in hints))
        for h in hints:
            self.assertTrue(h.startswith("Worth checking:"))

    def test_status_code_403_hint(self):
        """Newly live host with 403 status returns auth barrier hint."""
        hints = extract_hints_for_host("https://portal.example.com", status_code=403)
        self.assertTrue(any("401/403" in h for h in hints))

    def test_status_code_transition_hint(self):
        """Changed host from 403 -> 200 generates status unblock hint."""
        diffs = {"status_code": (403, 200)}
        hints = extract_hints_for_change("https://admin.example.com", diffs)
        self.assertTrue(any("403 to 200" in h for h in hints))
        for h in hints:
            self.assertTrue(h.startswith("Worth checking:"))

    def test_worded_as_worth_checking_not_confirmed_vulnerability(self):
        """All hints must be phrased as 'Worth checking', never as confirmed findings."""
        hints = extract_hints_for_host(
            "https://jenkins.dev.example.com",
            status_code=500,
            title="Index of /",
            tech=["Jenkins", "Laravel"],
        )
        self.assertGreater(len(hints), 0)
        for h in hints:
            self.assertTrue(h.startswith("Worth checking:"), f"Bad phrasing: {h}")
            self.assertNotIn("vulnerable", h.lower())


class TestIncompleteScanSafeguards(unittest.TestCase):
    """Test suite ensuring incomplete scans never report hosts as gone."""

    def test_old_scan_incomplete_never_reports_gone(self):
        """If previous scan was incomplete, missing hosts must NOT be reported as gone."""
        old = {
            "run_id": "2026-10-18_100000",
            "status": "incomplete",
            "incomplete": True,
            "subdomains": ["a.example.com", "b.example.com"],
            "hosts": [
                {"url": "https://a.example.com", "status_code": 200},
                {"url": "https://b.example.com", "status_code": 200},
            ],
        }
        new = {
            "run_id": "2026-10-18_110000",
            "status": "complete",
            "incomplete": False,
            "subdomains": ["a.example.com"],
            "hosts": [{"url": "https://a.example.com", "status_code": 200}],
        }

        result = diff.compare(old, new)
        self.assertEqual(result["gone_live"], [])
        self.assertEqual(result["removed_subdomains"], [])
        self.assertIn("incomplete_warning", result)
        self.assertIn("incomplete scan", result["incomplete_warning"])

        formatted = diff.format_diff(result, old["run_id"], new["run_id"], new_data=new)
        self.assertIn("[!] Warning: Comparison involves an incomplete scan", formatted)
        self.assertNotIn("Inactive hosts", formatted)

    def test_new_scan_incomplete_never_reports_gone(self):
        """If current scan was interrupted, missing hosts must NOT be reported as gone."""
        old = {
            "run_id": "2026-10-18_100000",
            "status": "complete",
            "incomplete": False,
            "subdomains": ["a.example.com", "b.example.com"],
            "hosts": [
                {"url": "https://a.example.com", "status_code": 200},
                {"url": "https://b.example.com", "status_code": 200},
            ],
        }
        new = {
            "run_id": "2026-10-18_110000",
            "status": "incomplete",
            "incomplete": True,
            "subdomains": ["a.example.com"],
            "hosts": [{"url": "https://a.example.com", "status_code": 200}],
        }

        result = diff.compare(old, new)
        self.assertEqual(result["gone_live"], [])
        self.assertEqual(result["removed_subdomains"], [])
        self.assertIn("incomplete_warning", result)

    def test_format_diff_displays_lead_hints(self):
        """format_diff displays lead hints under new and changed hosts."""
        old = {
            "run_id": "2026-10-18_100000",
            "subdomains": ["example.com"],
            "hosts": [{"url": "https://example.com", "status_code": 403}],
        }
        new = {
            "run_id": "2026-10-18_110000",
            "subdomains": ["example.com", "admin.example.com"],
            "hosts": [
                {"url": "https://example.com", "status_code": 200},
                {
                    "url": "https://admin.example.com",
                    "status_code": 200,
                    "title": "Swagger UI",
                },
            ],
        }

        result = diff.compare(old, new)
        formatted = diff.format_diff(result, old["run_id"], new["run_id"], new_data=new)

        self.assertIn("https://admin.example.com", formatted)
        self.assertIn("* Worth checking:", formatted)
        self.assertIn("Administrative interface", formatted)
        self.assertIn("403 to 200", formatted)


if __name__ == "__main__":
    unittest.main()
