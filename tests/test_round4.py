"""Unit tests for round 4 enhancements:
- JS endpoint extraction & secrets in JS (js_endpoints.py)
- DNSSEC, CAA & dangling delegation audit (dns_sec.py)
- Web cache deception & CDN header reflection audit (cache_audit.py)
- Parameter mining & high-risk attack matrix (params_analyzer.py)
"""

import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import json

from reconflow.js_endpoints import extract_routes_from_text
from reconflow.dns_sec import audit_dnssec, audit_caa, audit_nameservers, audit_dns_security
from reconflow.cache_audit import audit_host_cache
from reconflow.params_analyzer import classify_parameter, analyze_parameters
from reconflow.sarif import generate_sarif
from reconflow.report import build_html_report


class TestJSEndpoints(unittest.TestCase):
    def test_extract_endpoints(self):
        js_sample = '''
        const apiUrl = "/api/v1/users";
        fetch('/api/v2/orders/checkout', {method: 'POST'});
        axios.get("https://auth.example.com/oauth/token?client_id=123");
        const query = `query GetUserProfile { user(id: $id) { name email } }`;
        const mutation = "mutation DeleteAccount { deleteUser { success } }";
        '''
        res = extract_routes_from_text(js_sample, domain="example.com")
        self.assertTrue(any("checkout" in r for r in res["all_routes"]) or any("users" in r for r in res["all_routes"]))
        self.assertTrue(len(res["graphql_operations"]) >= 2)
        self.assertIn("client_id", res["parameters"])

    def test_extract_empty(self):
        res = extract_routes_from_text("", domain="example.com")
        self.assertEqual(res["routes_count"], 0)
        self.assertEqual(res["all_routes"], [])
        self.assertEqual(res["graphql_operations"], [])
        self.assertEqual(res["parameters"], [])


class TestDNSSecAndDelegation(unittest.TestCase):
    @patch("reconflow.dns_sec.query_doh")
    def test_dnssec_signed(self, mock_doh):
        mock_doh.side_effect = lambda domain, rtype: {
            "Answer": [{"data": "dummy"}]
        }
        res = audit_dnssec("example.com")
        self.assertEqual(res["status"], "SIGNED")
        self.assertTrue(res["is_signed"])

    @patch("reconflow.dns_sec.query_doh")
    def test_dnssec_unsigned(self, mock_doh):
        mock_doh.side_effect = lambda domain, rtype: {}
        res = audit_dnssec("example.com")
        self.assertEqual(res["status"], "UNSIGNED")
        self.assertFalse(res["is_signed"])

    @patch("reconflow.dns_sec.query_doh")
    def test_caa_records(self, mock_doh):
        mock_doh.return_value = {
            "Answer": [{"data": '0 issue "letsencrypt.org"'}]
        }
        res = audit_caa("example.com")
        self.assertTrue(res["has_caa"])
        self.assertEqual(res["status"], "PROTECTED")
        self.assertIn("letsencrypt.org", res["issue_cas"])

    @patch("reconflow.dns_sec.query_doh")
    @patch("socket.getaddrinfo")
    def test_dangling_nameservers(self, mock_addr, mock_doh):
        import socket
        mock_doh.return_value = {
            "Answer": [{"data": "ns-123.awsdns-01.com."}]
        }
        mock_addr.side_effect = socket.gaierror("Name or service not known")

        res = audit_nameservers("example.com")
        self.assertEqual(res["nameservers_count"], 1)
        self.assertTrue(res["has_dangling_ns"])
        self.assertEqual(len(res["dangling_nameservers"]), 1)
        self.assertEqual(res["dangling_nameservers"][0]["cloud_provider"], "awsdns")


class TestCacheAudit(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_cache_vulnerabilities(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "cache-control": "public, max-age=86400",
            "cf-cache-status": "HIT",
            "set-cookie": "sessionid=secret_123; Path=/",
            "x-forwarded-host": "reconflow-unkeyed-probe.test"
        }
        mock_resp.read.return_value = b'Reflected header reconflow-unkeyed-probe.test in body'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = audit_host_cache("https://example.com/api/user")
        self.assertEqual(res["url"], "https://example.com/api/user")
        self.assertEqual(res["cdn_detected"], "Cloudflare")
        self.assertTrue(len(res["findings"]) >= 2)


class TestParamsAnalyzer(unittest.TestCase):
    def test_parameter_classification(self):
        cats_redirect = classify_parameter("redirect_url")
        self.assertIn("ssrf_open_redirect", cats_redirect)

        cats_idor = classify_parameter("account_id")
        self.assertIn("idor_bola", cats_idor)

        cats_admin = classify_parameter("is_admin")
        self.assertIn("admin_bypass", cats_admin)

        cats_sqli = classify_parameter("order_by")
        self.assertIn("sqli_injection", cats_sqli)

    def test_analyze_parameters(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            params = ["user_id", "admin", "redirect", "file", "sort"]
            urls = [
                "https://example.com/view?file=doc.pdf&user_id=123",
                "https://example.com/login?redirect=https://target.com"
            ]
            res = analyze_parameters(params, urls, Path(tmpdir))
            self.assertTrue(res["total_parameters_evaluated"] >= 5)
            self.assertTrue(res["total_high_value_flagged"] >= 4)
            self.assertTrue((Path(tmpdir) / "param_matrix.json").exists())


class TestExportIntegrations(unittest.TestCase):
    def test_sarif_export_with_new_features(self):
        findings = {
            "dns_sec": {
                "dnssec": {"status": "UNSIGNED"},
                "caa": {"has_caa": False},
                "nameservers": {
                    "dangling_nameservers": [{"nameserver": "ns1.bad.com", "error": "NXDOMAIN"}]
                }
            },
            "cache_audits": [
                {
                    "url": "https://example.com/a.css",
                    "findings": [
                        {"type": "SENSITIVE_DATA_PUBLIC_CACHE", "severity": "CRITICAL", "description": "Public Cookie"},
                        {"type": "UNKEYED_HEADER_REFLECTION", "severity": "HIGH", "description": "Reflection"}
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            sarif = generate_sarif("example.com", Path(tmpdir), findings)
            self.assertEqual(len(sarif["runs"][0]["results"]), 5)

    def test_html_report_rendering(self):
        js_endpoints = {
            "routes_count": 2,
            "categorized_routes": {
                "admin_internal": ["/admin/dashboard"],
                "auth_oauth": ["/api/v1/token"],
                "graphql": [],
                "api_rest": ["/api/v1/users"],
                "general": []
            },
            "graphql_operations": ["query GetUsers"],
            "parameters": ["client_id"]
        }
        dns_audit = {
            "dnssec": {
                "status": "UNSIGNED",
                "description": "Missing DNSSEC"
            },
            "caa": {
                "status": "MISSING",
                "summary": "Missing CAA"
            },
            "nameservers": {
                "nameservers_count": 2,
                "nameservers": ["ns1.bad.com"],
                "has_dangling_ns": True,
                "dangling_nameservers": [{"nameserver": "ns1.bad.com", "cloud_provider": "awsdns"}]
            }
        }
        cache_audits = [
            {
                "url": "https://example.com/profile.css",
                "cdn_detected": "Cloudflare",
                "cache_control": "public, max-age=3600",
                "findings": [{"severity": "CRITICAL", "type": "SENSITIVE_DATA_PUBLIC_CACHE", "description": "Public Set-Cookie"}]
            }
        ]
        param_matrix = {
            "total_parameters_evaluated": 4,
            "total_high_value_flagged": 3,
            "categories": {
                "ssrf_open_redirect": {
                    "label": "SSRF / Open Redirect",
                    "description": "desc",
                    "matched_params": [{"name": "dest"}, {"name": "url"}],
                    "params_count": 2
                },
                "idor_bola": {
                    "label": "IDOR / BOLA",
                    "description": "desc",
                    "matched_params": [{"name": "user_id"}],
                    "params_count": 1
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            out_p = Path(tmpdir)
            build_html_report(
                domain="example.com",
                output_dir=out_p,
                subdomains=["a.example.com"],
                live_hosts=["https://a.example.com"],
                js_endpoints=js_endpoints,
                dns_sec=dns_audit,
                cache_audits=cache_audits,
                param_matrix=param_matrix
            )
            report_file = out_p / "report.html"
            self.assertTrue(report_file.exists())
            html = report_file.read_text(encoding="utf-8")
            self.assertIn("JavaScript API Routes & Endpoints", html)
            self.assertIn("DNS Infrastructure & Security Posture", html)
            self.assertIn("Web Cache & CDN Edge Policy Audit", html)
            self.assertIn("High-Value Parameter Attack Surface Matrix", html)


if __name__ == "__main__":
    unittest.main()
