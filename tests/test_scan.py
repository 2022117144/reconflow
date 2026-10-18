import itertools
import unittest

from reconflow import scan


class TestWildcard(unittest.TestCase):
    def test_detect_wildcard_none(self):
        ips = scan.detect_wildcard("example.com", resolve_fn=lambda host: set())
        self.assertEqual(ips, set())

    def test_detect_wildcard_found(self):
        ips = scan.detect_wildcard(
            "example.com",
            min_samples=2,
            max_samples=4,
            resolve_fn=lambda host: {"192.0.2.1"},
        )
        self.assertEqual(ips, {"192.0.2.1"})

    def test_detect_wildcard_rotating_pool(self):
        pool = itertools.cycle([{"192.0.2.1"}, {"192.0.2.2"}])
        ips = scan.detect_wildcard("example.com", resolve_fn=lambda host: next(pool))
        self.assertEqual(ips, {"192.0.2.1", "192.0.2.2"})

    def test_filter_wildcard(self):
        table = {
            "fake.example.com": {"192.0.2.1"},
            "real.example.com": {"198.51.100.5"},
            "dead.example.com": set(),
        }
        kept = scan.filter_wildcard(
            list(table), {"192.0.2.1"}, resolve_fn=lambda host: table[host]
        )
        self.assertEqual(kept, ["real.example.com"])


if __name__ == "__main__":
    unittest.main()
