import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vibetrackosint


class ValidationTests(unittest.TestCase):
    def test_valid_ip(self):
        self.assertEqual(str(vibetrackosint.valid_ip("8.8.8.8")), "8.8.8.8")

    def test_invalid_ip(self):
        self.assertIsNone(vibetrackosint.valid_ip("999.1.1.1"))

    def test_url_normalization(self):
        self.assertEqual(vibetrackosint.normalize_url("example.com"), "https://example.com/")

    def test_reject_non_http_scheme(self):
        with self.assertRaises(ValueError):
            vibetrackosint.normalize_url("ftp://example.com")

    def test_host_normalization(self):
        self.assertEqual(vibetrackosint.normalize_host("Example.COM"), "example.com")

    def test_reject_url_in_host_field(self):
        with self.assertRaises(ValueError):
            vibetrackosint.normalize_host("https://example.com/path")


if __name__ == "__main__":
    unittest.main()
