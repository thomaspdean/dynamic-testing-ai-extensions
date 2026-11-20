"""CRX parsing and extension-ID derivation. Run: python3 -m unittest discover tests"""
import base64
import hashlib
import io
import json
import struct
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dyntest import EXT_DIR  # noqa: E402
from dyntest.crx import CrxError, id_from_public_key, parse_crx, read_crx  # noqa: E402
from dyntest import extension  # noqa: E402


def _varint(n: int) -> bytes:
    out = b""
    while True:
        b, n = n & 0x7F, n >> 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def _field(num: int, payload: bytes) -> bytes:  # length-delimited protobuf field
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def _zip(manifest: dict, files: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps(manifest))
        for name, data in (files or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


def make_crx3(dev_key: bytes, zip_bytes: bytes, decoy_key: bytes = b"webstore-key", crx_id: bytes | None = None):
    """A CRX3 shaped like a store download: a decoy (Web Store) RSA proof before the developer's."""
    proof = lambda k: _field(1, k) + _field(2, b"sig")
    signed = _field(1, crx_id if crx_id is not None else hashlib.sha256(dev_key).digest()[:16])
    header = _field(2, proof(decoy_key)) + _field(2, proof(dev_key)) + _field(10000, signed)
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_bytes


class TestIdDerivation(unittest.TestCase):
    def test_known_mapping(self):
        # SHA-256 of b"" starts e3b0c442 98fc1c14 9afbf4c8 996fb924 -> hex digits mapped 0-f -> a-p
        self.assertEqual(id_from_public_key(b""), "odlameecjipmbmbejkplpemijjgpljce")

    def test_id_is_32_letters_a_to_p(self):
        eid = id_from_public_key(b"any key bytes")
        self.assertEqual(len(eid), 32)
        self.assertTrue(set(eid) <= set("abcdefghijklmnop"))


class TestParseCrx3(unittest.TestCase):
    def setUp(self):
        self.key = b"developer-public-key-der"
        self.manifest = {"manifest_version": 3, "name": "__MSG_appName__", "version": "1.2.3",
                         "default_locale": "en"}
        self.zip = _zip(self.manifest, {"_locales/en/messages.json": json.dumps({"APPNAME": {"message": "Test Ext"}})})

    def test_picks_key_matching_crx_id_not_decoy(self):
        c = parse_crx(make_crx3(self.key, self.zip))
        self.assertEqual(c.public_key, self.key)
        self.assertEqual(c.ext_id, id_from_public_key(self.key))
        self.assertEqual(c.manifest_key, base64.b64encode(self.key).decode())
        self.assertEqual(c.crx_version, 3)

    def test_manifest_and_localized_name(self):
        c = parse_crx(make_crx3(self.key, self.zip))
        self.assertEqual(c.manifest()["version"], "1.2.3")
        self.assertEqual(c.display_name(), "Test Ext")  # message keys are case-insensitive

    def test_sha256_is_of_whole_file(self):
        data = make_crx3(self.key, self.zip)
        self.assertEqual(parse_crx(data).sha256, hashlib.sha256(data).hexdigest())

    def test_no_key_matches_crx_id(self):
        with self.assertRaisesRegex(CrxError, "matches crx_id"):
            parse_crx(make_crx3(self.key, self.zip, crx_id=b"\x00" * 16))

    def test_bad_magic(self):
        with self.assertRaisesRegex(CrxError, "magic"):
            parse_crx(b"PK\x03\x04" + self.zip)

    def test_truncated_header(self):
        data = make_crx3(self.key, self.zip)
        with self.assertRaises(CrxError):
            parse_crx(data[:20])

    def test_crx2(self):
        data = b"Cr24" + struct.pack("<III", 2, len(self.key), 3) + self.key + b"sig" + self.zip
        c = parse_crx(data)
        self.assertEqual((c.ext_id, c.crx_version), (id_from_public_key(self.key), 2))


class TestResolveAndDescribe(unittest.TestCase):
    """Finding a file by path, by name in the drop folder, or by ID; describing it from the file alone."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.key = b"dev-key"
        manifest = {"manifest_version": 3, "name": "Demo", "version": "2.0", "oauth2": {"client_id": "x"}}
        (self.tmp / "demo.crx").write_bytes(make_crx3(self.key, _zip(manifest)))
        self._orig, extension.EXT_DIR = extension.EXT_DIR, self.tmp

    def tearDown(self):
        import shutil
        extension.EXT_DIR = self._orig
        shutil.rmtree(self.tmp)

    def test_resolve_by_path_name_and_id(self):
        f = self.tmp / "demo.crx"
        for sel in (str(f), "demo", "demo.crx", id_from_public_key(self.key)):
            self.assertEqual(extension.resolve(sel), f, sel)

    def test_resolve_missing(self):
        with self.assertRaises(FileNotFoundError):
            extension.resolve("nope")

    def test_describe(self):
        f = self.tmp / "demo.crx"
        d = extension.describe(read_crx(f), f)
        self.assertEqual((d["label"], d["name"], d["version"]), ("demo", "Demo", "2.0"))
        self.assertTrue(d["needs_branded_chrome"])   # has an oauth2 section -> getAuthToken
        self.assertFalse(d["manifest_has_key"])


@unittest.skipUnless(any(EXT_DIR.glob("*.crx")), "no .crx files in extensions/")
class TestRealPackages(unittest.TestCase):
    """Every .crx in extensions/: the header's crx_id agrees with the chosen key, the zip and manifest read."""

    def test_packages_in_drop_folder(self):
        for path in sorted(EXT_DIR.glob("*.crx")):
            with self.subTest(file=path.name):
                c = read_crx(path)
                self.assertEqual(id_from_public_key(c.public_key), c.ext_id)
                self.assertTrue(c.manifest().get("version"))


if __name__ == "__main__":
    unittest.main()
