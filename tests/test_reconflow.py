"""
Unit tests for the reconflow package.

Covers:
- Configuration loader & fallback YAML parser
- Run state checkpointing and resuming
- Secret detection & regex matching
- Parameter and URL parsing
- Cloud asset discovery regexes
- Security header weights & grading logic
- Platform detection & OS-specific installation hints
- Report building (HTML/summary stats)
- Webhook notification payload formatting
"""

import json
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.audits import CLOUD_PATTERNS, SECURITY_HEADERS, detect_cloud_assets
from reconflow.config import _cast_value, _simple_yaml_parse, load_config
from reconflow.modules import PARAM_RE, SECRET_PATTERNS, _extract_js_urls
from reconflow.notify import send_webhook
from reconflow.platform_check import (
    ARCH_PACKAGES,
    DEBIAN_PACKAGES,
    FEDORA_PACKAGES,
    detect_distro,
    get_install_hint,
    is_arch_linux,
    is_debian_linux,
    is_fedora_linux,
)
from reconflow.report import _stat, _vuln_table, build_html_report
from reconflow.state import StateManager


class TestConfig(unittest.TestCase):
    def test_cast_value(self):
        self.assertIs(_cast_value("true"), True)
        self.assertIs(_cast_value("True"), True)
        self.assertIs(_cast_value("false"), False)
        self.assertIs(_cast_value("False"), False)
        self.assertEqual(_cast_value("123"), 123)
        self.assertEqual(_cast_value("example"), "example")

    def test_simple_yaml_parse_basic(self):
        sample = textwrap.dedent("""
        # Comments should be ignored
        threads: 25
        timeout: 10
        resume: true
        target: example.com
        """).strip()
        parsed = _simple_yaml_parse(sample)
        self.assertEqual(parsed.get("threads"), 25)
        self.assertEqual(parsed.get("timeout"), 10)
        self.assertIs(parsed.get("resume"), True)
        self.assertEqual(parsed.get("target"), "example.com")

    def test_simple_yaml_parse_nested_sections(self):
        sample = textwrap.dedent("""
        core:
          threads: 40
          json: true
        audits:
          cloud: true
          cname: false
        """).strip()
        parsed = _simple_yaml_parse(sample)
        self.assertIn("core", parsed)
        self.assertIn("audits", parsed)
        self.assertEqual(parsed["core"]["threads"], 40)
        self.assertIs(parsed["core"]["json"], True)
        self.assertIs(parsed["audits"]["cloud"], True)
        self.assertIs(parsed["audits"]["cname"], False)

    def test_load_config_missing_file(self):
        cfg = load_config("nonexistent_config_file_12345.yaml")
        self.assertEqual(cfg, {})

    def test_load_config_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = Path(tmpdir) / "config.json"
            json_file.write_text(json.dumps({"threads": 15, "domain": "test.com"}))
            cfg = load_config(str(json_file))
            self.assertEqual(cfg.get("threads"), 15)
            self.assertEqual(cfg.get("domain"), "test.com")


class TestState(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.output_dir = Path(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_state_init_fresh(self):
        sm = StateManager(self.output_dir, "example.com", resume=False)
        self.assertEqual(sm.domain, "example.com")
        self.assertEqual(sm.state["stages_completed"], [])
        self.assertFalse(sm.is_completed("subfinder"))

    def test_mark_completed_and_flush(self):
        sm = StateManager(self.output_dir, "example.com", resume=False)
        sm.mark_completed("subfinder", {"found": 42})
        self.assertIn("subfinder", sm.state["stages_completed"])
        self.assertEqual(sm.state.get("metadata", {}).get("subfinder", {}).get("found"), 42)

        # Check state file exists on disk
        state_file = self.output_dir / "state.json"
        self.assertTrue(state_file.exists())
        data = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertIn("subfinder", data["stages_completed"])

    def test_resume_existing_state(self):
        sm1 = StateManager(self.output_dir, "example.com", resume=False)
        sm1.mark_completed("subfinder")
        sm1.mark_completed("httpx")

        # Resume scan
        sm2 = StateManager(self.output_dir, "example.com", resume=True)
        self.assertTrue(sm2.is_completed("subfinder"))
        self.assertTrue(sm2.is_completed("httpx"))
        self.assertFalse(sm2.is_completed("naabu"))


class TestModules(unittest.TestCase):
    def test_extract_js_urls(self):
        urls = [
            "https://example.com/app.js",
            "https://example.com/bundle.js?v=1.2.3",
            "https://example.com/index.html",
            "https://example.com/api/v1/users",
            "https://example.com/static/vendor.js#hash",
        ]
        js_urls = _extract_js_urls(urls)
        self.assertIn("https://example.com/app.js", js_urls)
        self.assertIn("https://example.com/bundle.js?v=1.2.3", js_urls)
        self.assertNotIn("https://example.com/index.html", js_urls)
        self.assertNotIn("https://example.com/api/v1/users", js_urls)

    def test_param_regex(self):
        url = "https://example.com/search?q=test&page=2&filter[category]=sec"
        params = [m.group(1) for m in PARAM_RE.finditer(url)]
        self.assertIn("q", params)
        self.assertIn("page", params)
        self.assertIn("filter[category]", params)

    def test_secret_patterns(self):
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        self.assertTrue(bool(SECRET_PATTERNS["AWS Access Key"].search(aws_key)))

        slack_token = "xoxb-1234567890-abcdefghij"
        self.assertTrue(bool(SECRET_PATTERNS["Slack Token"].search(slack_token)))

        google_key = "AIzaSyA_1234567890abcdefghijklmnopqrstuv"
        self.assertTrue(bool(SECRET_PATTERNS["Google API Key"].search(google_key)))

        priv_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAz..."
        self.assertTrue(bool(SECRET_PATTERNS["Private Key Block"].search(priv_key)))


class TestAudits(unittest.TestCase):
    def test_cloud_patterns_regex(self):
        s3_url = "https://my-company-backup.s3.amazonaws.com/data.zip"
        self.assertTrue(bool(CLOUD_PATTERNS["AWS S3"].search(s3_url)))

        gcs_url = "https://storage.googleapis.com/target-public-bucket/index.html"
        self.assertTrue(bool(CLOUD_PATTERNS["Google Cloud Storage"].search(gcs_url)))

        azure_url = "https://corpdata.blob.core.windows.net/exports/users.csv"
        self.assertTrue(bool(CLOUD_PATTERNS["Azure Blob Storage"].search(azure_url)))

    def test_detect_cloud_assets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            urls = [
                "https://example.com/assets.js",
                "https://target-assets.s3.amazonaws.com/logo.png",
            ]
            live_hosts = ["https://storage.googleapis.com/target-data"]
            found = detect_cloud_assets(urls, live_hosts, out_dir)
            self.assertGreaterEqual(len(found), 2)
            providers = {f["provider"] for f in found}
            self.assertIn("AWS S3", providers)
            self.assertIn("Google Cloud Storage", providers)

    def test_security_headers_weights(self):
        total_weight = sum(weight for _, weight, _ in SECURITY_HEADERS.values())
        self.assertEqual(total_weight, 100)
        self.assertIn("strict-transport-security", SECURITY_HEADERS)
        self.assertIn("content-security-policy", SECURITY_HEADERS)


class TestPlatformCheck(unittest.TestCase):
    def test_packages_presence(self):
        for pkg_map in (ARCH_PACKAGES, DEBIAN_PACKAGES, FEDORA_PACKAGES):
            self.assertIn("subfinder", pkg_map)
            self.assertIn("httpx", pkg_map)
            self.assertIn("nuclei", pkg_map)
            self.assertIn("ffuf", pkg_map)

    def test_get_install_hint(self):
        # On unknown platforms, should return friendly default hint
        with patch("reconflow.platform_check.is_arch_linux", return_value=False), \
             patch("reconflow.platform_check.is_debian_linux", return_value=False), \
             patch("reconflow.platform_check.is_fedora_linux", return_value=False):
            hint = get_install_hint("subfinder")
            self.assertEqual(hint, "Install it to enable this feature.")

        # On Arch Linux, should return pacman command
        with patch("reconflow.platform_check.is_arch_linux", return_value=True):
            hint = get_install_hint("subfinder")
            self.assertEqual(hint, "Install with: sudo pacman -S subfinder")

        # On Debian / Kali Linux, should return apt command
        with patch("reconflow.platform_check.is_arch_linux", return_value=False), \
             patch("reconflow.platform_check.is_debian_linux", return_value=True):
            hint = get_install_hint("subfinder")
            self.assertEqual(hint, "Install with: sudo apt install subfinder")

        # On Fedora Linux, should return dnf/go command
        with patch("reconflow.platform_check.is_arch_linux", return_value=False), \
             patch("reconflow.platform_check.is_debian_linux", return_value=False), \
             patch("reconflow.platform_check.is_fedora_linux", return_value=True):
            hint = get_install_hint("subfinder")
            self.assertIn("go install", hint)

    def test_is_arch_linux_non_linux(self):
        with patch("platform.system", return_value="Windows"):
            self.assertFalse(is_arch_linux())
            self.assertFalse(is_debian_linux())
            self.assertFalse(is_fedora_linux())
            self.assertEqual(detect_distro(), "unknown")


class TestReport(unittest.TestCase):
    def test_stat_formatting(self):
        html_stat = _stat("active targets", 12)
        self.assertIn("<b>12</b>", html_stat)
        self.assertIn("active targets", html_stat)

    def test_vuln_table_empty(self):
        table = _vuln_table([])
        self.assertIn("No vulnerabilities flagged", table)

    def test_build_html_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            report_path = build_html_report(
                domain="target.com",
                subdomains=["a.target.com", "b.target.com"],
                live_hosts=["https://a.target.com"],
                output_dir=out_dir,
            )
            self.assertTrue(report_path.exists())
            content = report_path.read_text(encoding="utf-8")
            self.assertIn("reconflow report — target.com", content)
            self.assertIn("subdomains", content)
            self.assertIn("live hosts", content)


class TestNotify(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_send_webhook_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"ok"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        send_webhook(
            webhook_url="https://discord.com/api/webhooks/test",
            domain="example.com",
            stats={"Subdomains": 15, "Live Hosts": 8},
        )
        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertIn("reconflow finished: example.com", payload["content"])
        self.assertIn("Subdomains: 15", payload["content"])


class TestReconflowLegacy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("reconflow_legacy", "reconflow.py")
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)

    def test_detect_wildcard_none(self):
        with patch.object(self.mod, "resolve", return_value=set()):
            ips = self.mod.detect_wildcard("example.com")
            self.assertEqual(ips, set())

    def test_detect_wildcard_found(self):
        with patch.object(self.mod, "resolve", return_value={"192.0.2.1"}):
            ips = self.mod.detect_wildcard("example.com", min_samples=2, max_samples=4)
            self.assertEqual(ips, {"192.0.2.1"})

    def test_filter_wildcard(self):
        def fake_resolve(host):
            if host == "wildcard.example.com":
                return {"192.0.2.1"}
            elif host == "real.example.com":
                return {"198.51.100.5"}
            return set()

        with patch.object(self.mod, "resolve", side_effect=fake_resolve):
            subs = ["wildcard.example.com", "real.example.com", "dead.example.com"]
            filtered = self.mod.filter_wildcard(subs, {"192.0.2.1"})
            self.assertEqual(filtered, ["real.example.com"])


if __name__ == "__main__":
    unittest.main()
