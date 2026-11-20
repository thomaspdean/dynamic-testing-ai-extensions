"""The honeytoken file. Run: python3 -m unittest discover tests"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dyntest import tokens  # noqa: E402


class TestTokenFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = tokens.load()  # raises if the file fails validation
        cls.by_field = {f: t for t in cls.doc["tokens"] for f in t["fields"]}

    def test_every_honeypot_field_is_covered(self):
        # the 19 profile fields + 3 login fields rendered by the honeypot (assets/app.js)
        fields = {"name", "username", "account_number", "email", "ssn", "openai_api_key", "robinhood_api_key",
                  "bitcoin_wallet_address", "bitcoin_wallet_key", "street_address", "city", "state", "zip",
                  "cc_name", "cc_number", "cc_exp", "cc_cvc", "dob", "phone",
                  "login_username", "login_account_number", "login_password"}
        self.assertEqual(set(self.by_field), fields)

    def test_weak_values_are_exactly_the_generic_ones(self):
        weak = {t["value"] for t in self.doc["tokens"] if t["strength"] == "weak"}
        self.assertEqual(weak, {"123", "00000", "ZZ", "Testville", "4111111111111111", "1990-01-15", "2030-12"})

    def test_digit_only_alts(self):
        self.assertEqual(self.by_field["ssn"]["alts"], [tokens.digits_only("900-12-3456")])
        self.assertEqual(self.by_field["phone"]["alts"], ["2025550147"])  # national number, no +1
        self.assertIn("2025550147", tokens.digits_only("+1-202-555-0147"))  # so "12025550147" also matches

    def test_password_is_strong_credential(self):
        t = self.by_field["login_password"]
        self.assertEqual((t["value"], t["kind"], t["strength"]), ("Pollen!Test2048", "credential", "strong"))

    def test_validation_catches_mistakes(self):
        bad = copy.deepcopy(self.doc)
        bad["tokens"].append({"value": "abc", "fields": ["x"], "kind": "k", "strength": "strong"})
        bad["tokens"].append({"value": "MIRA HOLLOWAY", "fields": ["y"], "kind": "k", "strength": "strong"})
        bad["honeypot"]["hosts"] = []
        problems = " | ".join(tokens.validate(bad))
        self.assertIn("too short", problems)
        self.assertIn("repeats", problems)        # duplicates are case-insensitive
        self.assertIn("honeypot.hosts", problems)

    def test_check_live_reports_missing_values(self):
        page = "\n".join(t["value"] for t in self.doc["tokens"][1:])
        self.assertEqual(tokens.check_live(self.doc, fetch=lambda url: page), [self.doc["tokens"][0]["value"]])


if __name__ == "__main__":
    unittest.main()
