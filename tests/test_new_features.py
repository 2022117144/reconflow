"""
Unit tests for the new reconflow modules: takeover, scope, github_leaks,
cve_correlate. Append these test classes into tests/test_reconflow.py
(or keep as a separate tests/test_new_features.py — unittest discover
picks up both).
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconflow.scope import filter_in_scope, load_scope
from reconflow.takeover import TAKEOVER_FINGERPRINTS, detect_subdomain_takeovers


class TestScope(unittest.TestCase):
    def test_load_scope_plain_text(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope_file = Path(tmpdir) / "scope.txt"
            scope_file.write_text("example.com\n*.example.com\n!internal.example.com\n# comment\n")
            scope = load_scope(str(scope_file))
            self.assertIn("example.com", scope["in_scope"])
            self.assertIn("internal.example.com", scope["out_of_scope"])

    def test_load_scope_hackerone_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope_file = Path(tmpdir) / "scope.json"
            scope_file.write_text(json.dumps([
                {"asset_identifier": "*.example.com", "asset_type": "WILDCARD",
                 "eligible_for_submission": True},
                {"asset_identifier": "internal.example.com", "asset_type": "URL",
                 "eligible_for_submission": False},
                {"asset_identifier": "com.example.app", "asset_type": "GOOGLE_PLAY_APP_ID",
                 "eligible_for_submission": True},
            ]))
            scope = load_scope(str(scope_file))
            self.assertIn("example.com", scope["in_scope"])
            self.assertIn("internal.example.com", scope["out_of_scope"])
            # Mobile app IDs should be skipped, not treated as domains
            self.assertNotIn("com.example.app", scope["in_scope"])

    def test_filter_in_scope(self):
        scope = {"in_scope": ["example.com"], "out_of_scope": ["internal.example.com"]}
        subs = ["api.example.com", "internal.example.com", "other.com"]
        kept, dropped = filter_in_scope(subs, scope)
        self.assertIn("api.example.com", kept)
        self.assertIn("internal.example.com", dropped)
        self.assertIn("other.com", dropped)


class TestTakeover(unittest.TestCase):
    def test_fingerprints_cover_major_providers(self):
        self.assertIn("github.io", TAKEOVER_FINGERPRINTS)
        self.assertIn("s3.amazonaws.com", TAKEOVER_FINGERPRINTS)
        self.assertIn("herokuapp.com", TAKEOVER_FINGERPRINTS)

    def test_detect_confirms_matching_fingerprint(self):
        cname_findings = [{
            "subdomain": "old.example.com",
            "cname": "old-bucket.s3.amazonaws.com",
            "provider": "s3.amazonaws.com",
            "active_dns": False,
        }]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            with patch("reconflow.takeover._fetch", return_value="<Error>NoSuchBucket</Error>"):
                confirmed = detect_subdomain_takeovers(cname_findings, out_dir)
            self.assertEqual(len(confirmed), 1)
            self.assertEqual(confirmed[0]["subdomain"], "old.example.com")

    def test_detect_no_match_when_fingerprint_absent(self):
        cname_findings = [{
            "subdomain": "live.example.com",
            "cname": "live-bucket.s3.amazonaws.com",
            "provider": "s3.amazonaws.com",
            "active_dns": True,
        }]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            with patch("reconflow.takeover._fetch", return_value="<html>Welcome</html>"):
                confirmed = detect_subdomain_takeovers(cname_findings, out_dir)
            self.assertEqual(confirmed, [])


class TestGithubLeaks(unittest.TestCase):
    def test_no_token_skips_cleanly(self):
        from reconflow.github_leaks import search_github_leaks
        with tempfile.TemporaryDirectory() as tmpdir:
            result = search_github_leaks("example.com", Path(tmpdir), token=None)
            self.assertEqual(result, [])


class TestCveCorrelate(unittest.TestCase):
    def test_no_tech_detected_returns_empty(self):
        from reconflow.cve_correlate import correlate_cves
        with tempfile.TemporaryDirectory() as tmpdir:
            result = correlate_cves([{"tech": []}], Path(tmpdir))
            self.assertEqual(result, [])

    @patch("reconflow.cve_correlate._query_nvd")
    def test_correlate_queries_each_detected_tech(self, mock_query):
        from reconflow.cve_correlate import correlate_cves
        mock_query.return_value = [{"cve_id": "CVE-2024-0001", "summary": "x", "cvss_score": 7.5}]
        httpx_records = [{"tech": ["nginx:1.18.0", "php:7.4"]}]
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("time.sleep"):  # skip the real rate-limit delay in tests
                result = correlate_cves(httpx_records, Path(tmpdir))
            self.assertEqual(mock_query.call_count, 2)
            self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
