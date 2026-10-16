"""
Unit tests for Round 3 features:
1. reconflow.batch (multi-target batch runner)
2. reconflow.sarif (SARIF v2.1.0 export)
3. reconflow.zone_transfer (DNS AXFR misconfiguration check)
4. reconflow.jwt_analyzer (AppSec JWT vulnerability scanner)
"""

import base64
import hashlib
import hmac
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.batch import load_targets, run_batch
from reconflow.jwt_analyzer import (
    analyze_jwt,
    audit_jwts,
    decode_jwt,
    extract_jwts,
)
from reconflow.sarif import generate_sarif
from reconflow.zone_transfer import (
    _build_axfr_query,
    _test_nameserver_axfr,
    audit_zone_transfer,
)


class TestBatch(unittest.TestCase):
    def test_load_targets_cleaning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "targets.txt"
            f.write_text(
                "example.com\n"
                "# comment\n"
                "\n"
                "https://api.example.com/\n"
                "test.com:8080\n"
                "example.com\n",  # duplicate
                encoding="utf-8",
            )
            targets = load_targets(f)
            self.assertEqual(targets, ["example.com", "api.example.com", "test.com"])

    def test_load_targets_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_targets("nonexistent_targets_file_98765.txt")

    def test_run_batch_error_isolation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)

            def mock_scan(target):
                if target == "fail.com":
                    raise RuntimeError("Connection dropped")
                return {"subdomains": 5, "live_hosts": 2}

            summary = run_batch(["good.com", "fail.com"], mock_scan, out_dir)
            self.assertEqual(summary["total_targets"], 2)
            self.assertEqual(summary["successful"], 1)
            self.assertEqual(summary["failed"], 1)
            self.assertEqual(summary["targets"]["good.com"]["status"], "success")
            self.assertEqual(summary["targets"]["fail.com"]["status"], "error")
            self.assertTrue((out_dir / "batch_summary.json").exists())


class TestSarif(unittest.TestCase):
    def test_generate_sarif_structure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            findings = {
                "takeovers": [
                    {
                        "subdomain": "sub.example.com",
                        "matched_service": "GitHub Pages",
                        "cname": "example.github.io",
                    }
                ],
                "vulns": [
                    {
                        "info": {"severity": "critical", "name": "RCE in Endpoint"},
                        "matched-at": "https://example.com/api",
                    }
                ],
                "secrets": [
                    {"url": "https://example.com/app.js", "type": "AWS Key", "match": "AKIA..."}
                ],
                "sensitive_files": [
                    {"url": "https://example.com/.env", "status": 200, "content_length": 150}
                ],
                "zone_transfers": [
                    {"nameserver": "ns1.example.com", "ip": "1.2.3.4", "vulnerable": True,
                     "records_count": 42}
                ],
                "jwts": [
                    {
                        "vulnerabilities": [
                            {"severity": "CRITICAL", "title": "alg:none",
                             "description": "Unsigned token"}
                        ]
                    }
                ],
                "email_security": {
                    "spf": {"status": "Missing", "spoofable": True},
                    "dmarc": {"policy": "None", "spoofable": True},
                },
                "cves": [
                    {
                        "tech": "Nginx",
                        "cves": [{"cve_id": "CVE-2023-1234", "description": "Buffer overflow"}],
                    }
                ],
            }
            doc = generate_sarif("example.com", out_dir, findings)
            self.assertEqual(doc["version"], "2.1.0")
            self.assertEqual(len(doc["runs"]), 1)
            run = doc["runs"][0]
            self.assertEqual(run["tool"]["driver"]["name"], "reconflow")
            self.assertTrue(len(run["results"]) >= 8)
            self.assertTrue((out_dir / "results.sarif").exists())


class TestZoneTransfer(unittest.TestCase):
    def test_build_axfr_query(self):
        pkt = _build_axfr_query("example.com")
        self.assertTrue(len(pkt) > 14)
        msg_len = struct.unpack("!H", pkt[:2])[0]
        self.assertEqual(len(pkt) - 2, msg_len)

    @patch("socket.socket")
    def test_test_nameserver_axfr_vulnerable(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        # Mock 12-byte response header: TXID=0x1337, Flags=0x0000 (RCODE=0), ANCOUNT=10
        resp_payload = struct.pack("!HHHHHH", 0x1337, 0x0000, 1, 10, 0, 0)
        mock_sock.recv.side_effect = [
            struct.pack("!H", len(resp_payload)),  # length prefix
            resp_payload,  # payload
        ]

        res = _test_nameserver_axfr("example.com", "1.2.3.4")
        self.assertTrue(res["vulnerable"])
        self.assertEqual(res["rcode"], 0)
        self.assertEqual(res["records_count"], 10)

    @patch("socket.socket")
    def test_test_nameserver_axfr_refused(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        # Mock 12-byte response header: Flags with RCODE=5 (REFUSED)
        resp_payload = struct.pack("!HHHHHH", 0x1337, 0x8185, 1, 0, 0, 0)
        mock_sock.recv.side_effect = [
            struct.pack("!H", len(resp_payload)),
            resp_payload,
        ]

        res = _test_nameserver_axfr("example.com", "1.2.3.4")
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["rcode"], 5)
        self.assertEqual(res["status"], "Refused (Secure)")

    @patch("reconflow.zone_transfer._query_doh_ns", return_value=[])
    def test_audit_zone_transfer_no_ns(self, mock_doh):
        with tempfile.TemporaryDirectory() as tmpdir:
            res = audit_zone_transfer("example.com", Path(tmpdir))
            self.assertEqual(res, [])


class TestJwtAnalyzer(unittest.TestCase):
    def _make_jwt(self, header: dict, payload: dict, secret: str = None) -> str:
        h_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        if secret and header.get("alg") == "HS256":
            sig = hmac.new(
                secret.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256
            ).digest()
            s_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
            return f"{h_b64}.{p_b64}.{s_b64}"
        return f"{h_b64}.{p_b64}."

    def test_extract_jwts(self):
        sample = "Token is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123xyz and done"
        jwts = extract_jwts(sample)
        self.assertEqual(len(jwts), 1)
        self.assertTrue(jwts[0].startswith("eyJ"))

    def test_decode_jwt_valid(self):
        token = self._make_jwt({"alg": "HS256"}, {"user": "alice"})
        h, p, _ = decode_jwt(token)
        self.assertEqual(h.get("alg"), "HS256")
        self.assertEqual(p.get("user"), "alice")

    def test_analyze_jwt_alg_none_critical(self):
        token = self._make_jwt({"alg": "none"}, {"sub": "1234"})
        res = analyze_jwt(token)
        self.assertEqual(res["risk_level"], "CRITICAL")
        titles = [v["title"] for v in res["vulnerabilities"]]
        self.assertTrue(any("none" in t.lower() for t in titles))

    def test_analyze_jwt_weak_secret_cracked(self):
        token = self._make_jwt({"alg": "HS256"}, {"user": "admin"}, secret="secret")
        res = analyze_jwt(token)
        self.assertEqual(res["risk_level"], "CRITICAL")
        cracked = any("Weak / Default HMAC" in v["title"] for v in res["vulnerabilities"])
        self.assertTrue(cracked)

    def test_analyze_jwt_missing_exp_and_sensitive_key(self):
        token = self._make_jwt({"alg": "RS256"}, {"password": "PlainTextPassword123"})
        res = analyze_jwt(token)
        self.assertEqual(res["risk_level"], "HIGH")
        titles = [v["title"] for v in res["vulnerabilities"]]
        self.assertTrue(any("Sensitive Key" in t for t in titles))
        self.assertTrue(any("Missing Expiration" in t for t in titles))

    def test_audit_jwts_writes_file(self):
        token = self._make_jwt({"alg": "none"}, {"user": "guest"})
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            results = audit_jwts([token], out_dir)
            self.assertEqual(len(results), 1)
            self.assertTrue((out_dir / "jwt_analysis.json").exists())


if __name__ == "__main__":
    unittest.main()
