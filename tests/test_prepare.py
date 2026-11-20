"""Unpacking with the manifest key, and the in-Chrome ID check. Run: python3 -m unittest discover tests"""
import base64
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # tests/ (shared helpers)
from dyntest import EXT_DIR, browser, prepare as prep  # noqa: E402
from dyntest.crx import CrxError, id_from_public_key, parse_crx, read_crx  # noqa: E402
from test_crx import _zip, make_crx3  # noqa: E402


class TestPrepare(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig, prep.BUILD = prep.BUILD, self.tmp / "build"
        self.key = b"developer-key"
        self.files = {"background.js": "console.log(1)", "_metadata/verified_contents.json": "[]",
                      "sub/dir/page.html": "<p>x</p>"}

    def tearDown(self):
        prep.BUILD = self._orig
        shutil.rmtree(self.tmp)

    def _prepare(self, manifest, files=None, **kw):
        crx = parse_crx(make_crx3(self.key, _zip(manifest, self.files if files is None else files)))
        return crx, prep.prepare(crx, Path("x.crx"), **kw)

    def _manifest(self, rec):
        return json.loads((Path(rec["path"]) / "manifest.json").read_text())

    def test_adds_key_and_only_changes_manifest(self):
        m = {"manifest_version": 3, "name": "A", "version": "1"}
        crx, rec = self._prepare(m)
        out = Path(rec["path"])
        self.assertEqual(rec["key"], "added")
        self.assertEqual(self._manifest(rec), {**m, "key": base64.b64encode(self.key).decode()})
        self.assertEqual(rec["unpacked_id"], crx.ext_id)
        for name, text in self.files.items():  # every other file kept byte for byte, _metadata included
            self.assertEqual((out / name).read_text(), text)

    def test_keeps_matching_key(self):
        m = {"manifest_version": 3, "name": "A", "version": "1", "key": base64.b64encode(self.key).decode()}
        _, rec = self._prepare(m)
        self.assertEqual(rec["key"], "kept")

    def test_replaces_wrong_key(self):
        m = {"manifest_version": 3, "name": "A", "version": "1", "key": base64.b64encode(b"other").decode()}
        crx, rec = self._prepare(m)
        self.assertEqual(rec["key"], "replaced")
        self.assertEqual(id_from_public_key(base64.b64decode(self._manifest(rec)["key"])), crx.ext_id)

    def test_cache_reused_for_same_file_and_redone_for_different_file(self):
        m = {"manifest_version": 3, "name": "A", "version": "1"}
        _, rec1 = self._prepare(m)
        marker = Path(rec1["path"]) / "marker"
        marker.write_text("cached")
        _, rec2 = self._prepare(m)
        self.assertTrue(marker.exists())                       # same SHA-256: cached unpack reused
        _, rec3 = self._prepare({**m, "version": "2"})
        self.assertFalse(marker.exists())                      # different file: fresh unpack
        self.assertEqual(rec3["version"], "2")

    def test_rejects_path_traversal(self):
        with self.assertRaisesRegex(CrxError, "unsafe path"):
            self._prepare({"manifest_version": 3, "name": "A", "version": "1"}, {"../evil.js": "x"})
        self.assertFalse((self.tmp / "evil.js").exists())


CFT = browser.find_cft()
REAL = sorted(EXT_DIR.glob("*.crx"))


@unittest.skipUnless(CFT and REAL, "needs Chrome for Testing and a .crx in extensions/")
class TestChromeAssignsRealId(unittest.TestCase):
    """Real browser, network blocked. Positive: keyed copy loads as its store ID.
    Negative control: the same folder without "key" gets a different ID, so the check can fail."""

    @classmethod
    def setUpClass(cls):
        cls.crx = read_crx(REAL[-1])
        cls.rec = prep.prepare(cls.crx, REAL[-1])

    def test_keyed_copy_loads_as_store_id(self):
        ok, seen, _ = browser.verify_load(CFT, Path(self.rec["path"]), self.crx.ext_id)
        self.assertTrue(ok, f"Chrome saw {list(seen)}")

    def test_copy_without_key_gets_other_id(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            nokey = tmp / "nokey"
            shutil.copytree(self.rec["path"], nokey)
            mpath = nokey / "manifest.json"
            m = json.loads(mpath.read_text())
            m.pop("key", None)
            mpath.write_text(json.dumps(m))
            ok, seen, _ = browser.verify_load(CFT, nokey, self.crx.ext_id)
            self.assertFalse(ok)
            self.assertTrue(any(Path(p).resolve() == nokey.resolve() for p in seen.values()),
                            "the unkeyed copy should still load, just under a different ID")
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
