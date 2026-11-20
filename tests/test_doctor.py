"""mitmproxy CA, SPKI hash, and Chrome trusting the proxy. Run: python3 -m unittest discover tests

Uses a throwaway mitmproxy config dir, never ~/.mitmproxy. The trust tests are skipped if
mitmdump or Chrome for Testing is missing; nothing they do leaves the machine.
"""
import base64
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from dyntest import browser, mitm  # noqa: E402

MITMDUMP, CFT, OPENSSL = mitm.find("mitmdump"), browser.find_cft(), shutil.which("openssl")


def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


class TestSpkiDer(unittest.TestCase):
    SPKI = _tlv(0x30, _tlv(0x30, b"\x06\x03algo") + _tlv(0x03, b"\x00" + b"K" * 300))  # long-form length

    def cert(self, with_version=True):
        fields = [_tlv(0x02, b"\x01"), _tlv(0x30, b""), _tlv(0x30, b"issuer"), _tlv(0x30, b"validity"),
                  _tlv(0x30, b"subject"), self.SPKI, _tlv(0xA3, b"ext")]
        if with_version:
            fields.insert(0, _tlv(0xA0, _tlv(0x02, b"\x02")))
        return _tlv(0x30, _tlv(0x30, b"".join(fields)) + _tlv(0x30, b"sigalg") + _tlv(0x03, b"sig"))

    def test_finds_spki_with_and_without_version(self):
        for v in (True, False):
            self.assertEqual(mitm.spki_der(self.cert(v)), self.SPKI)

    def test_rejects_garbage(self):
        for bad in (b"", b"\x02\x01\x00", self.cert()[:40]):
            with self.assertRaises((ValueError, IndexError, StopIteration)):
                mitm.spki_der(bad)

    def test_pem_round_trip(self):
        pem = "-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(self.cert()).decode() + "-----END CERTIFICATE-----\n"
        self.assertEqual(mitm.pem_to_der(pem), self.cert())


@unittest.skipUnless(MITMDUMP, "mitmdump not installed")
class TestRealCa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conf = Path(tempfile.mkdtemp(prefix="dyn-test-ca-"))
        cls.cert, cls.created = mitm.ensure_ca(MITMDUMP, cls.conf)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.conf, ignore_errors=True)

    def test_ca_created_once(self):
        self.assertTrue(self.created)
        self.assertEqual(mitm.ensure_ca(MITMDUMP, self.conf), (self.cert, False))

    @unittest.skipUnless(OPENSSL, "openssl not installed")
    def test_spki_hash_matches_openssl(self):
        pub = subprocess.run([OPENSSL, "x509", "-in", str(self.cert), "-pubkey", "-noout"],
                             capture_output=True, check=True).stdout
        der = subprocess.run([OPENSSL, "pkey", "-pubin", "-outform", "der"], input=pub,
                             capture_output=True, check=True).stdout
        self.assertEqual(mitm.spki_hash(self.cert), base64.b64encode(hashlib.sha256(der).digest()).decode())

    @unittest.skipUnless(CFT, "Chrome for Testing not found")
    def test_chrome_trusts_proxy_only_with_spki_flag(self):
        port, events = mitm.free_port(), self.conf / "events.txt"
        proc = subprocess.Popen([str(MITMDUMP), "--listen-host", "127.0.0.1", "-p", str(port),
                                 "--set", f"confdir={self.conf}", "--set", "connection_strategy=lazy",
                                 "-s", str(REPO / "dyntest" / "mitm_selftest.py"), "--set", f"selftest_out={events}"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(mitm.wait_for_port(port))
            ok, why = browser.check_trust(CFT, port, mitm.spki_hash(self.cert), events)
            self.assertTrue(ok, why)
            ok, why = browser.check_trust(CFT, port, None, events)        # negative control
            self.assertFalse(ok)
            self.assertIn("rejected", why)
        finally:
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
