"""
Unit tests for reconflow.passive_lookup and reconflow.permute_scale.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.passive_lookup import censys_lookup, shodan_internetdb_lookup
from reconflow.permute_scale import load_wordlist


class TestPassiveLookup(unittest.TestCase):
    @patch("reconflow.passive_lookup._resolve_ips", return_value=["93.184.216.34"])
    @patch("urllib.request.urlopen")
    def test_shodan_internetdb_finds_data(self, mock_urlopen, mock_resolve):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "ports": [80, 443],
            "vulns": ["CVE-2024-1234"],
            "hostnames": ["example.com"],
            "cpes": [],
            "tags": [],
        }).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            results = shodan_internetdb_lookup(["https://example.com"], Path(tmpdir))
            self.assertEqual(len(results), 1)
            self.assertIn("CVE-2024-1234", results[0]["vulns"])

    def test_censys_skips_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = censys_lookup(["https://example.com"], Path(tmpdir), None, None)
            self.assertEqual(result, [])


class TestPermuteScale(unittest.TestCase):
    def test_load_wordlist_skips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wl = Path(tmpdir) / "words.txt"
            wl.write_text("dev\n# comment\n\nstaging\nAPI\n", encoding="utf-8")
            words = load_wordlist(str(wl))
            self.assertIn("dev", words)
            self.assertIn("staging", words)
            self.assertIn("api", words)  # lowercased
            self.assertNotIn("# comment", words)
            self.assertEqual(len(words), 3)


if __name__ == "__main__":
    unittest.main()
