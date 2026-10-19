"""Unit tests for reconflow scope parsing, matching, and enforcement."""

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.cli import main
from reconflow.scope import (
    ScopeError,
    is_in_scope,
    load_scope,
    normalize_host,
)


class TestScopeMatching(unittest.TestCase):
    """Test suite for scope matching rules and hostname normalization."""

    def test_normalize_host(self):
        """Hostnames should be stripped of schemes, ports, paths, and trailing dots."""
        self.assertEqual(normalize_host("https://example.com/"), "example.com")
        self.assertEqual(
            normalize_host("http://SUB.Example.COM:8080/path?q=1#frag"), "sub.example.com"
        )
        self.assertEqual(normalize_host("target.com."), "target.com")
        self.assertEqual(
            normalize_host("https://user:pass@admin.target.com:443/"), "admin.target.com"
        )
        self.assertEqual(normalize_host("[2001:db8::1]:8080"), "2001:db8::1")

    def test_wildcard_matches_subdomains_only(self):
        """*.example.com matches subdomains only."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("*.example.com\n")
            f.flush()
            scope = load_scope(f.name)

        self.assertTrue(is_in_scope("sub.example.com", scope))
        self.assertTrue(is_in_scope("a.b.example.com", scope))
        self.assertTrue(is_in_scope("https://api.example.com/v1", scope))

    def test_wildcard_not_apex(self):
        """*.example.com must NOT match example.com itself; apex must be listed explicitly."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("*.example.com\n")
            f.flush()
            scope = load_scope(f.name)

        self.assertFalse(is_in_scope("example.com", scope))
        self.assertFalse(is_in_scope("https://example.com", scope))

    def test_wildcard_not_subdomain_suffix(self):
        """*.example.com must NOT match notexample.com or fake-example.com."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("*.example.com\n")
            f.flush()
            scope = load_scope(f.name)

        self.assertFalse(is_in_scope("notexample.com", scope))
        self.assertFalse(is_in_scope("fakeexample.com", scope))
        self.assertFalse(is_in_scope("evil-example.com", scope))

    def test_exact_domain_matching(self):
        """Exact domain matches only that domain and not subdomains or apex without rule."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("example.com\napi.target.com\n")
            f.flush()
            scope = load_scope(f.name)

        self.assertTrue(is_in_scope("example.com", scope))
        self.assertTrue(is_in_scope("api.target.com", scope))
        self.assertFalse(is_in_scope("sub.example.com", scope))
        self.assertFalse(is_in_scope("target.com", scope))

    def test_out_of_scope_overrides_in_scope(self):
        """Out-of-scope entries ALWAYS override in-scope entries."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write(
                "*.example.com\n"
                "example.com\n"
                "!admin.example.com\n"
                "!*.internal.example.com\n"
                "!internal.example.com\n"
            )
            f.flush()
            scope = load_scope(f.name)

        self.assertTrue(is_in_scope("example.com", scope))
        self.assertTrue(is_in_scope("public.example.com", scope))
        # Excluded exact host
        self.assertFalse(is_in_scope("admin.example.com", scope))
        # Excluded wildcard subdomain
        self.assertFalse(is_in_scope("dev.internal.example.com", scope))
        self.assertFalse(is_in_scope("internal.example.com", scope))

    def test_ip_and_cidr_matching(self):
        """IP addresses and CIDR ranges match correctly for in-scope and out-of-scope."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("192.168.1.0/24\n10.0.0.1\n!192.168.1.50\n")
            f.flush()
            scope = load_scope(f.name)

        self.assertTrue(is_in_scope("192.168.1.10", scope))
        self.assertTrue(is_in_scope("10.0.0.1", scope))
        self.assertFalse(is_in_scope("192.168.1.50", scope))  # out-of-scope overrides
        self.assertFalse(is_in_scope("192.168.2.1", scope))
        self.assertFalse(is_in_scope("10.0.0.2", scope))


class TestScopeSafetyFailClosed(unittest.TestCase):
    """Test suite ensuring scope verification fails closed on invalid/missing input."""

    def test_fail_closed_missing_file(self):
        """Missing scope file must raise ScopeError."""
        with self.assertRaises(ScopeError) as cm:
            load_scope("nonexistent_scope_file_12345.txt")
        self.assertIn("not found", str(cm.exception))

    def test_fail_closed_empty_file(self):
        """Empty scope file must raise ScopeError."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("   \n# Only comments\n\n")
            f.flush()
            with self.assertRaises(ScopeError) as cm:
                load_scope(f.name)
            self.assertIn("empty", str(cm.exception))

    def test_fail_closed_no_in_scope_entries(self):
        """Scope file with no valid in-scope entries must raise ScopeError."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("# Scope with only out of scope\n!admin.example.com\n!*.evil.com\n")
            f.flush()
            with self.assertRaises(ScopeError) as cm:
                load_scope(f.name)
            self.assertIn("no valid in-scope entries", str(cm.exception))


class TestScopeCLIAndScanIntegration(unittest.TestCase):
    """Test suite for reconflow scope CLI command and scan integration."""

    def test_scope_cli_command(self):
        """reconflow scope <file> <targets...> should print IN or OUT of scope."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("*.example.com\n!admin.example.com\n")
            f.flush()
            scope_file = f.name

        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            main([
                "scope",
                scope_file,
                "api.example.com",
                "admin.example.com",
                "notexample.com",
            ])
            output = mock_out.getvalue()
            self.assertIn("[+] api.example.com: IN SCOPE", output)
            self.assertIn("[-] admin.example.com: OUT OF SCOPE", output)
            self.assertIn("[-] notexample.com: OUT OF SCOPE", output)

    @patch("reconflow.scan.check_tools")
    @patch("reconflow.scan.find_subdomains")
    @patch("reconflow.scan.detect_wildcard")
    @patch("reconflow.scan.probe_hosts")
    def test_scan_drops_out_of_scope_before_network(
        self,
        mock_probe,
        mock_wildcard,
        mock_subdomains,
        mock_check_tools,
    ):
        """scan with --scope drops out-of-scope subdomains before network probing."""
        from reconflow.scan import run as run_scan

        # Discovered subdomains include one in-scope, one out-of-scope, one not-subdomain
        mock_subdomains.return_value = [
            "api.example.com",
            "admin.example.com",
            "notexample.com",
        ]
        mock_wildcard.return_value = set()
        mock_probe.return_value = (["https://api.example.com [200]"], None)

        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as sf:
            sf.write("*.example.com\n!admin.example.com\n")
            sf.flush()
            scope_file = sf.name

        with tempfile.TemporaryDirectory() as tmpdir:
            args = MagicMock(
                domain="example.com",
                output=tmpdir,
                scope=scope_file,
                threads=10,
                timeout=5,
                keep_wildcard=False,
                json_report=False,
                json=False,
                screenshots=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                result = run_scan(args)
                stdout_text = mock_stdout.getvalue()

            # Verify out of scope hosts logged as skipped
            self.assertIn("Skipped out-of-scope host: admin.example.com", stdout_text)
            self.assertIn("Skipped out-of-scope host: notexample.com", stdout_text)

            # Only api.example.com remained
            self.assertEqual(result["subdomains"], ["api.example.com"])

            # Verify subdomains.txt contains ONLY in-scope hosts
            subs_txt = Path(tmpdir) / "example.com" / "subdomains.txt"
            content = subs_txt.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(content, ["api.example.com"])

    def test_redirect_out_of_scope_handling_json_path(self):
        """Probing in JSON mode detects redirects to out-of-scope targets and marks them."""
        from reconflow.scan import probe_hosts

        mock_proc = MagicMock()
        mock_proc.stdout = iter([
            '{"url": "https://sso.example.com", "final_url": "https://login.microsoftonline.com", '
            '"status_code": 302, "title": "Redirect"}\n',
        ])
        mock_proc.wait.return_value = None
        mock_proc.returncode = 0
        mock_proc.__enter__.return_value = mock_proc
        mock_proc.__exit__.return_value = None

        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as sf:
            sf.write("*.example.com\n")
            sf.flush()
            scope_data = load_scope(sf.name)

        with tempfile.TemporaryDirectory() as tmpdir:
            subs_file = Path(tmpdir) / "subs.txt"
            subs_file.write_text("sso.example.com\n", encoding="utf-8")
            out_file = Path(tmpdir) / "live.txt"

            with patch("subprocess.Popen", return_value=mock_proc):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    lines, hosts_data = probe_hosts(
                        subs_file,
                        out_file,
                        json_report=True,
                        scope_data=scope_data,
                    )
                    stdout_str = mock_out.getvalue()

            self.assertIn("Redirect target out of scope", stdout_str)
            self.assertIn("https://login.microsoftonline.com", stdout_str)
            self.assertEqual(len(hosts_data), 1)
            self.assertEqual(
                hosts_data[0].get("redirect_out_of_scope"),
                "https://login.microsoftonline.com",
            )
            # Original URL is preserved, not replaced by out-of-scope redirect target
            self.assertEqual(hosts_data[0]["url"], "https://sso.example.com")

    def test_redirect_out_of_scope_handling_default_path(self):
        """Probing in default (plain-text) mode captures out-of-scope redirects from -location."""
        from reconflow.scan import probe_hosts

        mock_proc = MagicMock()
        mock_proc.stdout = iter([
            "https://sso.example.com [302] [Redirect] [https://login.microsoftonline.com]\n",
        ])
        mock_proc.wait.return_value = None
        mock_proc.returncode = 0
        mock_proc.__enter__.return_value = mock_proc
        mock_proc.__exit__.return_value = None

        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as sf:
            sf.write("*.example.com\n")
            sf.flush()
            scope_data = load_scope(sf.name)

        with tempfile.TemporaryDirectory() as tmpdir:
            subs_file = Path(tmpdir) / "subs.txt"
            subs_file.write_text("sso.example.com\n", encoding="utf-8")
            out_file = Path(tmpdir) / "live.txt"

            with patch("subprocess.Popen", return_value=mock_proc):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    lines, hosts_data = probe_hosts(
                        subs_file,
                        out_file,
                        json_report=False,
                        scope_data=scope_data,
                    )
                    stdout_str = mock_out.getvalue()

            self.assertIn("Redirect target out of scope", stdout_str)
            self.assertIn("https://login.microsoftonline.com", stdout_str)
            self.assertEqual(len(hosts_data), 1)
            self.assertEqual(
                hosts_data[0].get("redirect_out_of_scope"),
                "https://login.microsoftonline.com",
            )
            self.assertIn("redirect out of scope:", lines[0])

    def test_capture_screenshots_skips_out_of_scope_redirects(self):
        """capture_screenshots must skip any host that redirected out of scope."""
        from reconflow.scan import capture_screenshots

        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as sf:
            sf.write("*.example.com\n")
            sf.flush()
            scope_data = load_scope(sf.name)

        live_hosts = [
            "https://api.example.com [200]",
            "https://sso.example.com [302] [redirect out of scope: https://evil.com]",
        ]
        hosts_data = [
            {"url": "https://api.example.com", "status_code": 200},
            {
                "url": "https://sso.example.com",
                "status_code": 302,
                "redirect_out_of_scope": "https://evil.com",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            screenshots_dir = Path(tmpdir) / "screenshots"

            with patch("reconflow.scan.run_cmd") as mock_run_cmd:
                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    capture_screenshots(
                        live_hosts,
                        screenshots_dir,
                        scope_data=scope_data,
                        hosts_data=hosts_data,
                    )
                    stdout_str = mock_out.getvalue()

            self.assertIn("Skipping screenshot for https://sso.example.com", stdout_str)
            self.assertIn("redirects to out-of-scope target (https://evil.com)", stdout_str)

            # Check that gowitness was called and targets file only had api.example.com
            self.assertTrue(mock_run_cmd.called)
            cmd = mock_run_cmd.call_args[0][0]
            self.assertEqual(cmd[0], "gowitness")

    def test_scope_audit_dns_ip_resolution(self):
        """DNS resolution filtering must drop subdomains resolving to out-of-scope IPs."""
        from reconflow.scan import filter_wildcard

        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as sf:
            sf.write("*.example.com\n!192.168.0.0/16\n")
            sf.flush()
            scope_data = load_scope(sf.name)

        subs = ["good.example.com", "bad-ip.example.com"]

        def fake_resolve(host):
            if host == "bad-ip.example.com":
                return {"192.168.1.50"}
            return {"93.184.216.34"}

        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            kept = filter_wildcard(
                subs,
                wildcard_ips=set(),
                resolve_fn=fake_resolve,
                scope_data=scope_data,
            )
            stdout_str = mock_out.getvalue()

        self.assertEqual(kept, ["good.example.com"])
        self.assertIn("Skipped host resolving to out-of-scope IP", stdout_str)

    def test_utf8_bom_scope_file(self):
        """Scope files with UTF-8 BOM are decoded without corrupting the first rule."""
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write("\ufeff*.example.com\nexample.com\n".encode("utf-8"))
            f.flush()
            scope = load_scope(f.name)

        self.assertTrue(is_in_scope("api.example.com", scope))
        self.assertTrue(is_in_scope("example.com", scope))
        self.assertFalse(is_in_scope("notexample.com", scope))


if __name__ == "__main__":
    unittest.main()
