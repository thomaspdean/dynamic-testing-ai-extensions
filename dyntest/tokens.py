"""Load and check data/tokens.json (the honeytokens the detector looks for).

Kept dependency-free on purpose: the mitmproxy addon (step 4) runs in mitmproxy's own Python and
loads this file by path.
"""
import json
import re
from pathlib import Path

TOKENS_FILE = Path(__file__).resolve().parent.parent / "data" / "tokens.json"
MIN_STRONG_LEN = 8  # a "strong" value shorter than this would match by chance


class TokenFileError(ValueError):
    pass


def load(path: Path = TOKENS_FILE) -> dict:
    """Parse and validate the tokens file. Returns the whole document."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    problems = validate(doc)
    if problems:
        raise TokenFileError(f"{path}: " + "; ".join(problems))
    return doc


def validate(doc: dict) -> list[str]:
    problems = []
    hp = doc.get("honeypot", {})
    if not hp.get("hosts"):
        problems.append("honeypot.hosts is empty (needed to tell honeypot traffic from leaks)")
    for mode, flow in hp.get("flows", {}).items():
        if not flow.get("start") or not flow.get("steps"):
            problems.append(f"honeypot.flows.{mode}: needs a start path and steps")
    seen = {}
    for i, t in enumerate(doc.get("tokens", [])):
        where = f"tokens[{i}]"
        v = t.get("value", "")
        if not v or not t.get("fields"):
            problems.append(f"{where}: needs a value and at least one field")
            continue
        if t.get("strength") not in ("strong", "weak"):
            problems.append(f"{where} {v!r}: strength must be 'strong' or 'weak'")
        if t.get("strength") == "strong" and len(v) < MIN_STRONG_LEN:
            problems.append(f"{where} {v!r}: too short to be 'strong' (min {MIN_STRONG_LEN} chars)")
        for alt in t.get("alts", []):
            if alt == v or len(alt) < MIN_STRONG_LEN and t.get("strength") == "strong":
                problems.append(f"{where} alt {alt!r}: duplicate or too short")
        for needle in [v, *t.get("alts", [])]:
            if needle.lower() in seen:
                problems.append(f"{where}: value {needle!r} repeats {seen[needle.lower()]}")
            seen[needle.lower()] = where
    if not seen:
        problems.append("no tokens")
    return problems


def digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def check_live(doc: dict, fetch=None) -> list[str]:
    """Fetch the honeypot's pages and report any token value that no longer appears on them."""
    if fetch is None:
        import urllib.request

        def fetch(url):
            req = urllib.request.Request(url, headers={"User-Agent": "dyntest-tokens-check"})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode("utf-8", "replace")
    corpus = "\n".join(fetch(u) for u in doc["honeypot"]["pages"])
    return [t["value"] for t in doc["tokens"] if t["value"] not in corpus]
