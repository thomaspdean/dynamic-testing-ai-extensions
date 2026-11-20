"""Encoding-aware token matching. Run: python3 -m unittest discover tests"""
import base64
import gzip
import json
import random
import sys
import unittest
import zlib
from pathlib import Path
from urllib.parse import quote, quote_plus, urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dyntest import tokens  # noqa: E402
from dyntest.matcher import Matcher, encode_uri_component  # noqa: E402

DOC = tokens.load()
STRONG = [t for t in DOC["tokens"] if t["strength"] == "strong"]
M = Matcher(DOC["tokens"])


def fields_found(hits, strong_only=True):
    return {h.token["value"] for h in hits if not strong_only or h.token["strength"] == "strong"}


class TestEveryEncoding(unittest.TestCase):
    """Each strong token, wrapped in realistic surroundings, is found and labelled with its encoding."""

    ENCODERS = {
        "raw": lambda v: v.encode(),
        "raw+case": lambda v: v.upper().encode(),
        "url": lambda v: quote(v, safe="").encode(),
        "url(plus)": lambda v: quote_plus(v).encode(),
        "url-double": lambda v: quote(quote(v, safe=""), safe="").encode(),
        "json": lambda v: json.dumps({"x": v})[6:-1].encode(),
        "json-unicode": lambda v: "".join(c if c.isalnum() else f"\\u{ord(c):04x}" for c in v).encode(),
        "hex": lambda v: v.encode().hex().encode(),
        "hex(upper)": lambda v: v.encode().hex().upper().encode(),
    }

    def test_each_token_each_encoding(self):
        for t in STRONG:
            for name, enc in self.ENCODERS.items():
                with self.subTest(token=t["fields"][0], encoding=name):
                    blob = b'{"page":"https://example.org/x","data":"' + enc(t["value"]) + b'","n":42}'
                    self.assertIn(t["value"], fields_found(M.find(blob, "body")))

    def test_base64_all_alignments_inside_larger_blob(self):
        for t in STRONG:
            for prefix_len in range(3):
                for urlsafe in (False, True):
                    with self.subTest(token=t["fields"][0], prefix=prefix_len, urlsafe=urlsafe):
                        raw = b"x" * prefix_len + b'{"v":"' + t["value"].encode() + b'","more":"data"}'
                        enc = base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)
                        hits = M.find(b"payload=" + enc, "body")
                        self.assertIn(t["value"], fields_found(hits))
                        self.assertTrue(any(h.encoding.startswith("base64") for h in hits))

    def test_encode_uri_component_matches_javascript(self):
        # expected strings produced by JavaScript's encodeURIComponent (not by our own function)
        self.assertEqual(encode_uri_component("Mira Holloway"), "Mira%20Holloway")
        self.assertEqual(encode_uri_component("+1-202-555-0147"), "%2B1-202-555-0147")
        self.assertEqual(encode_uri_component("a b!'()*~"), "a%20b!'()*~")
        m = Matcher([{"value": "it's (really) secret!", "fields": ["f"], "kind": "k", "strength": "strong"}])
        hits = m.find(b"v=it's%20(really)%20secret!", "url")   # quote() would give %27 %28 %29 %21
        self.assertEqual([h.encoding for h in hits], ["url"])

    def test_digit_only_alts(self):
        hits = M.find(b"ssn=900123456&tel=12025550147", "body")
        got = {(h.token["fields"][0], h.encoding) for h in hits}
        self.assertIn(("ssn", "digits+raw"), got)
        self.assertIn(("phone", "digits+raw"), got)

    def test_cookie_header_as_set_by_honeypot(self):
        # honeypot: document.cookie = `pollen_test_${key}=${encodeURIComponent(value)}`
        cookie = "; ".join(f"pollen_test_{t['fields'][0]}={encode_uri_component(t['value'])}" for t in STRONG
                           if t["fields"][0] != "login_password")
        self.assertEqual(fields_found(M.find(cookie.encode(), "header:cookie")),
                         {t["value"] for t in STRONG} - {"Pollen!Test2048"})

    def test_url_mode_query_string(self):
        q = urlencode({f: t["value"] for t in DOC["tokens"] for f in t["fields"]})
        hits = M.find(f"https://quillbert.github.io/honey/url/results/?{q}".encode(), "url")
        self.assertEqual(fields_found(hits), {t["value"] for t in STRONG})


class TestCompressed(unittest.TestCase):
    PAYLOAD = json.dumps({"type": "rrweb", "events": [{"node": {"tag": "dd", "text": "900-12-3456"}},
                                                      {"node": {"tag": "input", "value": "Pollen!Test2048"}}]}).encode()

    def test_zlib_stream_inside_binary_body(self):
        body = b"\x00\x01header-bytes" + zlib.compress(self.PAYLOAD) + b"\xff trailer"
        self.assertEqual(M.find(body, "body"), [])  # not visible without inflating
        hits = M.scan(body, "body")
        self.assertEqual(fields_found(hits), {"900-12-3456", "Pollen!Test2048"})
        self.assertTrue(all(h.location.startswith("body>zlib@") for h in hits))

    def test_gzip_stream(self):
        hits = M.scan(b"--boundary\r\n" + gzip.compress(self.PAYLOAD), "body")
        self.assertEqual(fields_found(hits), {"900-12-3456", "Pollen!Test2048"})

    def test_base64_wrapped_gzip_in_json(self):
        body = json.dumps({"replay": base64.b64encode(gzip.compress(self.PAYLOAD)).decode()}).encode()
        hits = M.scan(body, "body")
        self.assertEqual(fields_found(hits), {"900-12-3456", "Pollen!Test2048"})
        self.assertTrue(all(">base64>gzip@" in h.location for h in hits))


class TestPrecision(unittest.TestCase):
    def test_weak_values_need_boundaries(self):
        self.assertEqual(M.find(b"id=4123987&v=11230&ZZtop", "body"), [])
        hits = M.find(b"cvc=123&state=ZZ&zip=00000", "body")
        self.assertEqual({h.token["value"] for h in hits}, {"123", "ZZ", "00000"})
        self.assertTrue(all(h.token["strength"] == "weak" for h in hits))

    def test_weak_values_get_no_base64_or_hex(self):
        self.assertFalse([n for n in M.needles if n.token["strength"] == "weak"
                          and ("base64" in n.encoding or "hex" in n.encoding)])

    def test_longer_token_wins_on_overlap(self):
        hits = M.find(b'{"email":"mira.holloway@example.com"}', "body")
        self.assertEqual([h.token["fields"][0] for h in hits], ["email"])
        hits = M.find(b'{"email":"mira.holloway@example.com","user":"mira.holloway"}', "body")
        self.assertEqual(sorted(h.token["fields"][0] for h in hits), ["email", "username"])

    def test_counts_and_context(self):
        (h,) = M.find(b"a 900-12-3456 b 900-12-3456 c", "body")
        self.assertEqual((h.count, h.encoding), (2, "raw"))
        self.assertIn("900-12-3456", h.context)

    def test_no_false_positives_on_unrelated_traffic(self):
        rng = random.Random(6262)
        noise = bytes(rng.randrange(256) for _ in range(300_000))
        b64 = base64.b64encode(noise)
        text = json.dumps({"q": "summarize this article about holloway caves", "user": "mira", "n": 2025}).encode()
        for blob in (noise, b64, noise.hex().encode(), text, zlib.compress(noise)):
            self.assertEqual([h for h in M.scan(blob, "body") if h.token["strength"] == "strong"], [])


if __name__ == "__main__":
    unittest.main()
