"""End to end: real mitmdump + the addon, real HTTP requests, a local http.server as "the internet".

Uses a throwaway mitmproxy config dir (nothing written to ~/.mitmproxy) and plain HTTP on
127.0.0.1, so it needs no certificates and no network. Skipped if mitmdump isn't installed.
"""
import base64
import gzip
import http.client
import json
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from dyntest import mitm, tokens  # noqa: E402

MITMDUMP = shutil.which("mitmdump")
EXT = "chrome-extension://mfcncdeeeekkjgonodmcjajafigpgnhh"


class _Sink(BaseHTTPRequestHandler):
    def _ok(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = _ok

    def log_message(self, *a):
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(MITMDUMP, "mitmdump not installed")
class TestMitmdumpAddon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.run_dir = cls.tmp / "run"
        cls.run_dir.mkdir()
        # "localhost" plays the honeypot; "127.0.0.1" plays any other server. Both reach the sink.
        doc = tokens.load()
        doc["honeypot"]["hosts"] = ["localhost"]
        (cls.tmp / "tokens.json").write_text(json.dumps(doc))

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
        cls.web_port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

        cls.proxy_port = _free_port()
        cls.proc = subprocess.Popen(
            [MITMDUMP, "--listen-host", "127.0.0.1", "-p", str(cls.proxy_port), *mitm.PROXY_OPTIONS,
             "--set", f"confdir={cls.tmp / 'conf'}", "-w", str(cls.run_dir / "flows.mitm"),
             "-s", str(REPO / "dyntest" / "detect_tokens.py"),
             "--set", f"dyn_run_dir={cls.run_dir}", "--set", f"dyn_tokens={cls.tmp / 'tokens.json'}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", cls.proxy_port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            cls.proc.kill()
            raise RuntimeError("mitmdump did not start:\n" + cls.proc.stdout.read().decode(errors="replace"))

        cls.send("setup", "POST", "127.0.0.1", "/login", b"user=mira.holloway&pw=Pollen%21Test2048",
                 {"Content-Type": "application/x-www-form-urlencoded"})
        blob = base64.b64encode(json.dumps({"ssn": "900-12-3456", "ua": "x"}).encode()).decode()
        cls.send("passive", "GET", "127.0.0.1", f"/collect?d={blob}", None, {"Origin": EXT})
        cls.send("passive", "POST", "127.0.0.1", "/ingest", gzip.compress(b'{"email":"mira.holloway@example.com"}'),
                 {"Content-Encoding": "gzip", "Content-Type": "application/json"})
        cls.send("passive", "GET", "localhost", "/honey/cookies/read/", None,
                 {"Cookie": "pollen_test_name=Mira%20Holloway"})
        cls.send("active:summarize", "GET", "127.0.0.1", "/clean?q=hello", None, {})
        cls.send_to_dead_server()


        cls.proc.send_signal(signal.SIGINT)            # graceful stop: flushes flows.mitm
        cls.output = cls.proc.communicate(timeout=30)[0].decode(errors="replace")
        cls.server.shutdown()
        cls.server.server_close()
        cls.hits = [json.loads(l) for l in (cls.run_dir / "hits.jsonl").read_text().splitlines()]
        cls.reqs = [json.loads(l) for l in (cls.run_dir / "requests.jsonl").read_text().splitlines()]

    @classmethod
    def send(cls, phase, method, host, path, body, headers):
        (cls.run_dir / "phase").write_text(phase)
        c = http.client.HTTPConnection("127.0.0.1", cls.proxy_port, timeout=15)
        c.request(method, f"http://{host}:{cls.web_port}{path}", body=body, headers=headers)
        r = c.getresponse()
        r.read()
        c.close()
        assert r.status == 200, (r.status, path)

    @classmethod
    def send_to_dead_server(cls):
        """HTTPS POST to a server that isn't there (like Zetoe's backend in the pilot). The body must
        still be recorded: that only works because the proxy reads the request before connecting."""
        (cls.run_dir / "phase").write_text("passive")
        dead = _free_port()                                   # nothing listens here
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # throwaway CA in a temp confdir
        c = http.client.HTTPSConnection("127.0.0.1", cls.proxy_port, timeout=15, context=ctx)
        c.set_tunnel("api.dead-backend.test", dead)
        try:
            c.request("POST", "/api/playwright", body=b'{"cookies":"pollen_test_ssn=900-12-3456"}',
                      headers={"Origin": EXT, "Content-Type": "application/json"})
            cls.dead_status = c.getresponse().status         # mitmproxy answers 502
        except OSError as e:
            cls.dead_status = repr(e)
        finally:
            c.close()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def hit(self, field):
        found = [h for h in self.hits if h["field"].split(",")[0] == field]
        self.assertTrue(found, f"no hit for {field}; hits: {[(h['field'], h['location']) for h in self.hits]}")
        return found[0]

    def test_every_request_recorded_with_its_phase(self):
        self.assertEqual([(r["phase"], r["method"], r["n_hits"] > 0) for r in self.reqs if r["type"] == "http"],
                         [("setup", "POST", True), ("passive", "GET", True), ("passive", "POST", True),
                          ("passive", "GET", True), ("active:summarize", "GET", False), ("passive", "POST", True)])

    def test_setup_password_tagged_setup(self):
        h = self.hit("login_password")
        self.assertEqual((h["phase"], h["location"], h["encoding"]), ("setup", "body", "url"))

    def test_base64_in_query_from_extension(self):
        h = self.hit("ssn")
        self.assertEqual((h["location"], h["is_extension_origin"], h["to_honeypot"]), ("url", True, False))
        self.assertTrue(h["encoding"].startswith("base64"))

    def test_gzip_content_encoding_is_undone(self):
        h = self.hit("email")
        self.assertEqual((h["location"], h["encoding"], h["host"]), ("body", "raw", "127.0.0.1"))
        self.assertFalse([x for x in self.hits if x["field"].startswith("username") and x["request_id"] == h["request_id"]],
                         "username inside the email must not be reported separately")

    def test_cookie_to_honeypot_flagged(self):
        h = self.hit("name")
        self.assertEqual((h["location"], h["to_honeypot"], h["host"]), ("header:cookie", True, "localhost"))

    def test_request_to_dead_server_is_still_searched(self):
        h = [x for x in self.hits if x["host"] == "api.dead-backend.test"]
        self.assertTrue(h, f"body never reached the detector (status {self.dead_status})")
        self.assertEqual((h[0]["field"], h[0]["location"], h[0]["is_extension_origin"]), ("ssn", "body", True))
        nr = [r for r in self.reqs if r["type"] == "no_response"]
        self.assertEqual([(r["host"], r["phase"]) for r in nr], [("api.dead-backend.test", "passive")])

    def test_flows_saved(self):
        self.assertGreater((self.run_dir / "flows.mitm").stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
