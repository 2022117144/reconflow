import unittest

from reconflow.diff import compare


def host(url, status=200, title="T", tech=None):
    return {"url": url, "status_code": status, "title": title, "technologies": tech or []}


def snap(*hosts):
    return {"subdomains": [], "hosts": list(hosts)}


class TestDiffNoise(unittest.TestCase):
    def test_scheme_flip_is_not_new_or_gone(self):
        result = compare(snap(host("https://a.example.com")), snap(host("http://a.example.com")))
        self.assertEqual(result["new_live"], [])
        self.assertEqual(result["gone_live"], [])
        self.assertEqual(result["changed"], {})

    def test_transport_tags_are_ignored(self):
        old = snap(host("https://a.example.com", tech=["Cloudflare"]))
        new = snap(host("https://a.example.com", tech=["Cloudflare", "HTTP/2", "HSTS"]))
        self.assertEqual(compare(old, new)["changed"], {})

    def test_real_tech_change_is_reported(self):
        old = snap(host("https://a.example.com", tech=["Apache"]))
        new = snap(host("https://a.example.com", tech=["Apache", "PHP", "HTTP/2"]))
        self.assertIn("https://a.example.com", compare(old, new)["changed"])

    def test_genuinely_new_host_is_reported(self):
        result = compare(
            snap(host("https://a.example.com")),
            snap(host("https://a.example.com"), host("https://b.example.com")),
        )
        self.assertEqual(result["new_live"], ["https://b.example.com"])


if __name__ == "__main__":
    unittest.main()
