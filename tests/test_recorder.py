"""Recorder: phases, honeypot vs. leak, extension origin, JSONL output. Run: python3 -m unittest discover tests"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dyntest import tokens  # noqa: E402
from dyntest.recorder import Recorder  # noqa: E402

EXT = "chrome-extension://mfcncdeeeekkjgonodmcjajafigpgnhh"


def read_jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text().splitlines()]


class TestRecorder(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.rec = Recorder(self.dir, tokens.load())

    def tearDown(self):
        self.rec.close()
        shutil.rmtree(self.dir)

    def phase(self, name):
        (self.dir / "phase").write_text(name + "\n")

    def test_phase_tags_follow_the_phase_file(self):
        self.rec.on_request("GET", "https://example.com/", "example.com", [])
        self.phase("setup")
        self.rec.on_request("POST", "https://api.x.com/login", "api.x.com", [], b"pw=Pollen!Test2048")
        self.phase("passive")
        self.rec.on_request("POST", "https://api.x.com/log", "api.x.com", [], b'{"ssn":"900-12-3456"}')
        self.assertEqual([r["phase"] for r in read_jsonl(self.dir / "requests.jsonl")], ["unknown", "setup", "passive"])
        self.assertEqual([(h["phase"], h["field"]) for h in read_jsonl(self.dir / "hits.jsonl")],
                         [("setup", "login_password"), ("passive", "ssn")])

    def test_honeypot_vs_other_host_and_extension_origin(self):
        self.phase("passive")
        cookie = [("Cookie", "pollen_test_name=Mira%20Holloway")]
        self.rec.on_request("GET", "https://quillbert.github.io/honey/cookies/read/", "quillbert.github.io", cookie)
        self.rec.on_request("POST", "https://api.zetoe.com/playwright", "api.zetoe.com",
                            [("Origin", EXT), ("Content-Type", "application/json")],
                            b'{"cookies":[{"name":"pollen_test_name","value":"Mira%20Holloway"}]}')
        hp, leak = read_jsonl(self.dir / "hits.jsonl")
        self.assertEqual((hp["to_honeypot"], hp["location"], hp["is_extension_origin"]), (True, "header:cookie", False))
        self.assertEqual((leak["to_honeypot"], leak["location"], leak["is_extension_origin"], leak["encoding"]),
                         (False, "body", True, "url"))
        self.assertEqual((leak["field"], leak["value_kind"], leak["strength"]), ("name,cc_name", "identity", "strong"))

    def test_every_request_logged_even_without_hits(self):
        self.rec.on_request("GET", "https://example.com/a", "Example.COM", [("Sec-Fetch-Site", "none")])
        (r,) = read_jsonl(self.dir / "requests.jsonl")
        self.assertEqual((r["host"], r["n_hits"], r["sec_fetch_site"], r["type"]), ("example.com", 0, "none", "http"))
        self.assertEqual(read_jsonl(self.dir / "hits.jsonl"), [])

    def test_websocket_message_and_tls_failure(self):
        self.rec.on_ws_message("wss://chat.x.com/s", "chat.x.com", [("Origin", EXT)], b'{"page":"SSN 900-12-3456"}')
        self.rec.on_tls_failed("pinned.example.com", "certificate rejected")
        (h,) = read_jsonl(self.dir / "hits.jsonl")
        self.assertEqual((h["type"], h["location"], h["is_extension_origin"]), ("ws", "ws-message", True))
        ws, tls = read_jsonl(self.dir / "requests.jsonl")
        self.assertEqual((tls["type"], tls["host"]), ("tls_failed", "pinned.example.com"))

    def test_request_ids_continue_after_reopen(self):
        self.rec.on_request("GET", "https://a.com/", "a.com", [])
        self.rec.close()
        self.rec = Recorder(self.dir, tokens.load())
        self.rec.on_request("GET", "https://b.com/", "b.com", [])
        self.assertEqual([r["id"] for r in read_jsonl(self.dir / "requests.jsonl")], [1, 2])


if __name__ == "__main__":
    unittest.main()
