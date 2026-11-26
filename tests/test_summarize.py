"""summarize: leak rule, control comparison, the three CSVs. Run: python3 -m unittest discover tests

Run folders are produced by the real Recorder (same JSONL the detector writes) plus a meta.json.
"""
import base64
import csv
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dyntest import tokens  # noqa: E402
from dyntest.recorder import Recorder  # noqa: E402
from dyntest.summarize import summarize  # noqa: E402

EXT = "chrome-extension://mfcncdeeeekkjgonodmcjajafigpgnhh"
HP = "quillbert.github.io"


def make_run(root: Path, run_id: str, control: bool, mode: str, events: list, aborted=False):
    """events: (phase, host, headers, body) in order."""
    d = root / run_id
    rec = Recorder(d, tokens.load())
    phases = []
    for phase, host, headers, body in events:
        if not phases or phases[-1] != phase:
            phases.append(phase)
        (d / "phase").write_text(phase)
        rec.on_request("POST" if body else "GET", f"https://{host}/x", host, headers, body)
    rec.close()
    meta = {"run_id": run_id, "mode": mode, "control": control,
            "extension": None if control else {"label": "zetoe", "file": "zetoe.crx", "ext_id": EXT[19:],
                                               "name": "Zetoe", "version": "1.1.8", "crx_sha256": "c3b5"},
            "browser": {"kind": "cft", "version": "131"}, "started": "2026-11-21T10:00:00+00:00",
            "ended": "2026-11-21T10:12:30+00:00", "phases": phases + ["finished"], "aborted": aborted,
            "id_confirmed": None if control else True}
    (d / "meta.json").write_text(json.dumps(meta))
    return d


def rows(path: Path) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


class TestSummarize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        runs = cls.tmp / "runs"
        make_run(runs, "r1_control_session", True, "session", [
            ("startup", "accounts.google.com", [], b""),
            ("baseline", "example.com", [], b""),
            ("passive", HP, [("Cookie", "pollen_test_name=Mira%20Holloway")], b""),
            ("passive", "clients2.google.com", [], b""),
        ])
        make_run(runs, "r2_zetoe_session", False, "session", [
            ("setup", "api.zetoe.com", [("Origin", EXT)], b'{"login":"mira.holloway@example.com"}'),   # setup: not a leak
            ("baseline", "api.zetoe.com", [("Origin", EXT)], b'{"ping":1}'),
            ("passive", HP, [], b'{"ssn":"900-12-3456"}'),                                          # honeypot: not a leak
            ("passive", "api.zetoe.com", [("Origin", EXT)], b'{"ssn":"900-12-3456","cvc":"123"}'),    # leak + weak co-hit
            ("active:autofill", "collector.example.net", [], b"pw=Pollen%21Test2048"),               # leak, page origin
            ("active:autofill", "clients2.google.com", [], b""),                                      # Chrome noise
        ])
        with open(runs / "r2_zetoe_session" / "requests.jsonl", "a") as f:     # api.zetoe.com never answered once
            f.write(json.dumps({"run_id": "r2_zetoe_session", "ts": "", "phase": "passive", "type": "no_response",
                                "method": "POST", "host": "api.zetoe.com", "url": "https://api.zetoe.com/x",
                                "error": "Client disconnected."}) + "\n")
        (runs / "r2_zetoe_session" / "notes.md").write_text("# notes")
        make_run(runs, "r3_zetoe_url", False, "url", [("baseline", "api.zetoe.com", [], b"")], aborted=True)
        (runs / "not-a-run").mkdir()
        make_run(runs, "r4_zetoe_cookies", False, "cookies", [
            ("passive", "api.zetoe.com", [("Origin", EXT)], b'{"cookies":[{"value":"0048172396"}]}'),
            ("active:improve", "ai.example.org", [("Origin", EXT)], base64.b64encode(b"key sk-proj-TEST" + b"0" * 42)),
        ])
        cls.res = summarize([runs], cls.tmp / "results")
        cls.ext = rows(cls.tmp / "results" / "extensions.csv")
        cls.runs = {r["run_id"]: r for r in rows(cls.tmp / "results" / "runs.csv")}
        cls.hits = rows(cls.tmp / "results" / "hits.csv")
        cls.hosts = rows(cls.tmp / "results" / "hosts.csv")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_finds_runs_and_skips_other_folders(self):
        self.assertEqual(set(self.runs), {"r1_control_session", "r2_zetoe_session", "r3_zetoe_url", "r4_zetoe_cookies"})

    def test_leak_rule(self):
        r = self.runs["r2_zetoe_session"]
        self.assertEqual(r["leak"], "Y")
        self.assertEqual(r["leak_fields"], "login_password; ssn")          # not the setup-phase email
        self.assertEqual(r["leak_hosts"], "api.zetoe.com; collector.example.net")
        self.assertEqual(r["leak_phases"], "active:autofill; passive")
        self.assertEqual((r["leak_in_passive"], r["leak_in_active"]), ("Y", "Y"))
        self.assertEqual(r["leak_from_extension_origin"], "mixed")
        self.assertEqual(r["leak_kinds"], "credential; government_id")
        self.assertEqual(r["weak_cohits"], "cc_cvc")
        self.assertEqual(self.runs["r1_control_session"]["leak"], "N")    # honeypot cookie isn't a leak

    def test_control_comparison(self):
        r = self.runs["r2_zetoe_session"]
        self.assertEqual(r["hosts"], "4")
        self.assertEqual(r["hosts_not_in_control"], "2")                  # api.zetoe.com, collector.example.net
        self.assertEqual(r["leak_hosts_not_in_control"], "api.zetoe.com; collector.example.net")
        h = {(x["run_id"], x["host"]): x for x in self.hosts}
        self.assertEqual(h[("r2_zetoe_session", "clients2.google.com")]["in_control"], "Y")
        self.assertEqual(h[("r2_zetoe_session", "api.zetoe.com")]["in_control"], "N")
        self.assertEqual(h[("r2_zetoe_session", HP)]["honeypot"], "Y")

    def test_no_response_reported_not_counted_as_request(self):
        r = self.runs["r2_zetoe_session"]
        self.assertEqual((r["no_response"], r["requests"]), ("api.zetoe.com", "6"))
        z = {x["host"]: x for x in self.hosts if x["run_id"] == "r2_zetoe_session"}["api.zetoe.com"]
        self.assertEqual(z["no_response"], "1")

    def test_extension_row_rolls_up_modes(self):
        (z,) = self.ext                                                   # one extension, control excluded
        self.assertEqual((z["extension"], z["id_confirmed"], z["aborted_runs_skipped"]), ("zetoe", "Y", "1"))
        self.assertEqual(z["runs"], "r2_zetoe_session; r4_zetoe_cookies")  # aborted url run left out
        self.assertEqual((z["modes_run"], z["modes_missing"], z["control_modes"]), ("session; cookies", "url", "session"))
        self.assertEqual((z["session_leak"], z["url_leak"], z["cookies_leak"]), ("Y", "", "Y"))   # url not run: blank

    def test_extension_row_kinds_and_delivery(self):
        (z,) = self.ext
        self.assertEqual((z["leak_password"], z["leak_api_keys"], z["leak_government_id"], z["leak_financial"],
                          z["leak_identity"]), ("Y", "Y", "Y", "Y", "N"))
        self.assertEqual(z["n_strong_fields_leaked"], "4/12")
        self.assertEqual((z["passive_leak"], z["active_leak"]), ("Y", "Y"))
        self.assertEqual(z["leak_hosts_no_response"], "api.zetoe.com")
        self.assertEqual(z["delivered"], "partial")                         # zetoe never answered, the others did
        self.assertEqual(z["obfuscated"], "Y")                              # the base64'd API key
        self.assertEqual((z["store_label"], z["disclosed_by_label"]), ("", ""))   # manual columns left blank

    def test_hosts_table(self):
        z = {x["host"]: x for x in self.hosts if x["run_id"] == "r2_zetoe_session"}["api.zetoe.com"]
        self.assertEqual((z["requests"], z["phases"], z["first_phase"], z["from_extension_origin"]),
                         ("3", "setup; baseline; passive", "setup", "3"))
        self.assertEqual((z["strong_hits"], z["leak_hits"], z["leak_fields"]), ("2", "1", "ssn"))

    def test_hits_table_marks_leaks(self):
        by = {(h["run_id"], h["phase"], h["field"], h["host"]): h for h in self.hits}
        self.assertEqual(by[("r2_zetoe_session", "setup", "email", "api.zetoe.com")]["is_leak"], "N")
        self.assertEqual(by[("r2_zetoe_session", "passive", "ssn", HP)]["is_leak"], "N")
        self.assertEqual(by[("r2_zetoe_session", "passive", "ssn", "api.zetoe.com")]["is_leak"], "Y")
        self.assertEqual(by[("r2_zetoe_session", "passive", "cc_cvc", "api.zetoe.com")]["is_leak"], "N")  # weak
        self.assertEqual(by[("r2_zetoe_session", "passive", "ssn", "api.zetoe.com")]["extension"], "zetoe")

    def test_run_metadata_columns(self):
        r = self.runs["r2_zetoe_session"]
        self.assertEqual((r["extension"], r["version"], r["mode"], r["id_confirmed"], r["minutes"]),
                         ("zetoe", "1.1.8", "session", "Y", "12.5"))
        self.assertEqual(r["phases"], "setup; baseline; passive; active:autofill")
        self.assertTrue(r["notes"].endswith("notes.md"))
        self.assertEqual(self.runs["r3_zetoe_url"]["aborted"], "Y")

    def test_without_control_runs_columns_are_blank_not_wrong(self):
        res = summarize([self.tmp / "runs" / "r2_zetoe_session"], self.tmp / "nocontrol")
        (r,) = res["runs"]
        self.assertFalse(res["have_control"])
        self.assertEqual((r["hosts_not_in_control"], r["leak_hosts_not_in_control"]), ("", ""))

    def test_rerun_overwrites_and_dedupes_runs(self):
        res = summarize([self.tmp / "runs", self.tmp / "runs" / "r2_zetoe_session"], self.tmp / "results")
        self.assertEqual(len(res["runs"]), 4)


if __name__ == "__main__":
    unittest.main()
