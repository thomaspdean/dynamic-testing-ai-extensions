"""Find honeytokens in bytes, in any of the encodings extensions commonly use. Standard library only.

Each token value (and each of its `alts`) is expanded into needles, one per encoding:

  raw          the value itself (matched case-insensitively; "+case" is appended if case differs)
  url          quote(safe=""), quote_plus, JavaScript encodeURIComponent, and double-encoded
  json         JSON string escaping, plus "\\uXXXX for every non-alphanumeric" (some serializers)
  hex          UTF-8 bytes as hex (case-insensitive, so upper and lower both match)
  base64       standard and URL-safe, at all 3 byte alignments, so the value is found even inside
               a larger base64 blob that doesn't start on it
  digits       an `alts` entry, e.g. the SSN without dashes (then also url/json/... of it)

Weak tokens (short, generic values) only get raw/url/json needles and must sit between
non-alphanumeric characters: otherwise "123" would match inside every number.

Compressed data: `scan()` also looks for zlib and gzip streams inside the bytes (e.g. session-replay
uploads), and for long base64 runs that decode to one, inflates them, and searches the result.
Raw deflate without a header can't be found this way.

Overlaps: where a match lies inside a longer match of a different token (the "mira.holloway"
inside "mira.holloway@example.com"), only the longer one is reported.
"""
import base64
import binascii
import json
import re
import zlib
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus

MIN_ENCODED_LEN = 8          # shorter base64 needles would match by chance
MAX_INFLATE = 32 << 20       # cap per inflated stream (32 MiB)
MAX_STREAMS = 64             # compressed streams tried per scanned blob
MAX_DEPTH = 2                # nested inflation depth
CONTEXT = 40                 # bytes of context kept around the first match


def encode_uri_component(v: str) -> str:
    """JavaScript's encodeURIComponent (differs from quote() on ! ' ( ) * ~)."""
    return quote(v, safe="-_.!~*'()")


def json_escape(v: str) -> str:
    return json.dumps(v, ensure_ascii=True)[1:-1]


def json_unicode_escape(v: str) -> str:
    return "".join(c if c.isalnum() else f"\\u{ord(c):04x}" for c in v)


def base64_needles(raw: bytes) -> dict[str, bytes]:
    """The part of base64(prefix + raw + suffix) that depends only on raw, for prefix length 0, 1, 2."""
    out = {}
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + raw)
        first = -(-8 * k // 6)                 # first char whose 6 bits all come from raw
        last = (8 * (k + len(raw))) // 6       # chars before this are fully determined by raw
        piece = enc[first:last].rstrip(b"=")
        if len(piece) >= MIN_ENCODED_LEN:
            out[f"base64@{k}"] = piece
            out[f"base64url@{k}"] = piece.translate(bytes.maketrans(b"+/", b"-_"))
    return out


@dataclass(frozen=True)
class Needle:
    token: dict          # the tokens.json entry
    matched: str         # which string was encoded: the value or an alt
    encoding: str
    text: bytes          # what is searched for
    casefold: bool       # matched against the lowercased haystack


def build_needles(tokens: list[dict]) -> list[Needle]:
    needles, seen = [], set()

    def add(token, matched, encoding, text: bytes, casefold: bool):
        key = (text.lower() if casefold else text, casefold)
        if key not in seen:          # identical bytes from two encodings: keep the first (simplest) label
            seen.add(key)
            needles.append(Needle(token, matched, encoding, text, casefold))

    for t in tokens:
        weak = t["strength"] == "weak"
        for i, v in enumerate([t["value"], *t.get("alts", [])]):
            pre = "" if i == 0 else "digits+"
            add(t, v, pre + "raw", v.encode(), True)
            for enc, s in (("url", quote(v, safe="")), ("url", quote_plus(v)), ("url", encode_uri_component(v)),
                           ("url-double", quote(quote(v, safe=""), safe="")),
                           ("json", json_escape(v)), ("json-unicode", json_unicode_escape(v))):
                add(t, v, pre + enc, s.encode(), True)
            if weak:
                continue
            add(t, v, pre + "hex", v.encode().hex().encode(), True)
            for enc, s in base64_needles(v.encode()).items():
                add(t, v, pre + enc, s, False)
    needles.sort(key=lambda n: len(n.text), reverse=True)
    return needles


@dataclass
class Hit:
    token: dict
    matched: str
    encoding: str
    location: str
    count: int = 1
    context: str = ""

    @property
    def fields(self) -> list[str]:
        return self.token["fields"]


@dataclass
class Matcher:
    tokens: list[dict]
    needles: list[Needle] = field(init=False)

    def __post_init__(self):
        self.needles = build_needles(self.tokens)

    def find(self, data: bytes, location: str) -> list[Hit]:
        """Hits in these bytes only (no decompression). One Hit per (token, matched, encoding), with a count.

        Uses bytes.find per needle (C speed). Where a match lies inside a longer match of another
        needle (the username inside the email), only the longer one is kept.
        """
        lower = data.lower()                     # ASCII lowercasing keeps every offset the same
        occ = []                                 # (start, end, needle)
        for n in self.needles:
            hay, text = (lower, n.text.lower()) if n.casefold else (data, n.text)
            weak = n.token["strength"] == "weak"
            i = hay.find(text)
            while i != -1:
                j = i + len(text)
                if not weak or ((i == 0 or not hay[i - 1:i].isalnum()) and (j == len(hay) or not hay[j:j + 1].isalnum())):
                    occ.append((i, j, n))
                i = hay.find(text, i + 1)
        # Sweep by start (longest first at equal start). Every earlier match starts at or before
        # this one, so this match lies inside an earlier one exactly when it ends at or before
        # the furthest end seen so far. One pass, O(n log n) even with 100k+ matches.
        kept, reach = [], -1
        for i, j, n in sorted(occ, key=lambda o: (o[0], o[0] - o[1])):
            if j <= reach:
                continue
            kept.append((i, j, n))
            reach = j
        hits: dict[tuple, Hit] = {}
        for i, j, n in kept:
            enc = n.encoding + ("+case" if n.casefold and data[i:j] != n.text else "")
            key = (id(n.token), n.matched, enc)
            if key in hits:
                hits[key].count += 1
            else:
                ctx = data[max(0, i - CONTEXT):j + CONTEXT].decode("utf-8", "replace")
                hits[key] = Hit(n.token, n.matched, enc, location, 1, ctx)
        return list(hits.values())

    def scan(self, data: bytes, location: str, depth: int = 0) -> list[Hit]:
        """find() plus any zlib/gzip streams embedded in the data, raw or base64-wrapped."""
        hits = self.find(data, location)
        if depth < MAX_DEPTH and data:
            for offset, how, inflated in embedded_streams(data):
                hits += self.scan(inflated, f"{location}>{how}@{offset}", depth + 1)
        return hits


_B64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{64,}={0,2}")


def _inflate(data: bytes, wbits: int) -> bytes | None:
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(data, MAX_INFLATE)
    except zlib.error:
        return None
    return out if len(out) >= 16 else None


def embedded_streams(data: bytes):
    """Yield (offset, kind, inflated bytes) for zlib/gzip streams in data, raw or inside base64 runs."""
    tried = 0
    # zlib: 0x78 then a byte making the 16-bit header a multiple of 31. gzip: 1f 8b 08.
    for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]|\x1f\x8b\x08", data):
        if tried >= MAX_STREAMS:
            return
        tried += 1
        gz = m.group().startswith(b"\x1f")
        out = _inflate(data[m.start():], 31 if gz else 15)
        if out is not None:
            yield m.start(), "gzip" if gz else "zlib", out
    for m in _B64_RUN.finditer(data):
        if tried >= MAX_STREAMS:
            return
        run = m.group().replace(b"-", b"+").replace(b"_", b"/")
        try:
            raw = base64.b64decode(run + b"=" * (-len(run) % 4))
        except (binascii.Error, ValueError):
            continue
        if raw[:3] == b"\x1f\x8b\x08" or (raw[:1] == b"\x78" and len(raw) > 1 and (raw[0] * 256 + raw[1]) % 31 == 0):
            tried += 1
            gz = raw[:1] == b"\x1f"
            out = _inflate(raw, 31 if gz else 15)
            if out is not None:
                yield m.start(), "base64>" + ("gzip" if gz else "zlib"), out
