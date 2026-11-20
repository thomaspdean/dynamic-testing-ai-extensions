"""Per-run recording: search each request / WebSocket message for honeytokens, write JSONL.

Plain Python (no mitmproxy import) so it can be unit tested; dyntest/detect_tokens.py is the thin
mitmproxy addon that feeds it.

<run_dir>/requests.jsonl   one line per request or client WebSocket message (every one, hit or not)
<run_dir>/hits.jsonl       one line per (request, token, encoding, location) match
<run_dir>/phase            written by the run driver; read here so every line carries the phase
"""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from .matcher import Matcher

URL_KEEP = 2000   # characters of URL kept per line (full URLs are in flows.mitm)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Recorder:
    def __init__(self, run_dir: str | Path, tokens_doc: dict, run_id: str = ""):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or self.run_dir.name
        self.matcher = Matcher(tokens_doc["tokens"])
        self.honeypot_hosts = {h.lower() for h in tokens_doc["honeypot"]["hosts"]}
        self._req = open(self.run_dir / "requests.jsonl", "a", buffering=1, encoding="utf-8")
        self._hits = open(self.run_dir / "hits.jsonl", "a", buffering=1, encoding="utf-8")
        self._phase_file = self.run_dir / "phase"
        self._phase, self._phase_mtime = "unknown", None
        with open(self.run_dir / "requests.jsonl", encoding="utf-8") as f:
            self._n = sum(1 for _ in f)          # continue request ids if the proxy restarts

    # -- phase ---------------------------------------------------------------------------------
    def phase(self) -> str:
        """Current phase from <run_dir>/phase (re-read only when the file changes)."""
        try:
            mtime = os.stat(self._phase_file).st_mtime_ns
        except OSError:
            return self._phase
        if mtime != self._phase_mtime:
            self._phase_mtime = mtime
            self._phase = self._phase_file.read_text(encoding="utf-8").strip() or "unknown"
        return self._phase

    # -- inputs ----------------------------------------------------------------------------------
    def on_request(self, method: str, url: str, host: str, headers: list[tuple[str, str]],
                   body: bytes = b"", ts: str | None = None) -> list[dict]:
        hdr = {k.lower(): v for k, v in headers}
        parts = [("url", url.encode("utf-8", "replace"))]
        parts += [(f"header:{k.lower()}", v.encode("utf-8", "replace")) for k, v in headers]
        if body:
            parts.append(("body", body))
        return self._record("http", method, url, host, hdr, parts, len(body), ts)

    def on_ws_message(self, url: str, host: str, headers: list[tuple[str, str]], content: bytes,
                      ts: str | None = None) -> list[dict]:
        """A WebSocket message sent by the browser (the handshake's headers give its origin)."""
        hdr = {k.lower(): v for k, v in headers}
        return self._record("ws", "WS", url, host, hdr, [("ws-message", content)], len(content), ts)

    def on_tls_failed(self, host: str, error: str, ts: str | None = None) -> None:
        """A connection we could NOT decrypt (e.g. certificate pinning): its contents are not searched."""
        self._n += 1
        self._write(self._req, {"run_id": self.run_id, "id": self._n, "ts": ts or _now(), "phase": self.phase(),
                                "type": "tls_failed", "host": host, "error": error[:300]})

    # -- core ------------------------------------------------------------------------------------
    def _record(self, kind, method, url, host, hdr, parts, size, ts) -> list[dict]:
        ts, phase = ts or _now(), self.phase()
        self._n += 1
        origin = hdr.get("origin", "")
        referer = hdr.get("referer", "")
        is_ext = origin.startswith("chrome-extension://") or referer.startswith("chrome-extension://")
        host = host.lower()
        to_honeypot = host in self.honeypot_hosts
        base = {"run_id": self.run_id, "request_id": self._n, "ts": ts, "phase": phase, "type": kind,
                "method": method, "host": host, "url": url[:URL_KEEP]}

        hits = []
        for location, data in parts:
            for h in self.matcher.scan(data, location):
                hits.append({**base, "location": h.location, "field": ",".join(h.fields),
                             "value_kind": h.token["kind"], "strength": h.token["strength"],
                             "matched": h.matched, "encoding": h.encoding, "count": h.count,
                             "origin": origin, "is_extension_origin": is_ext,
                             "content_type": hdr.get("content-type", ""), "size": size,
                             "to_honeypot": to_honeypot, "context": h.context})
        for h in hits:
            self._write(self._hits, h)
        self._write(self._req, {**{k: base[k] for k in ("run_id", "ts", "phase", "type", "method", "host", "url")},
                                "id": self._n, "origin": origin, "is_extension_origin": is_ext,
                                "sec_fetch_site": hdr.get("sec-fetch-site", ""),
                                "sec_fetch_dest": hdr.get("sec-fetch-dest", ""),
                                "content_type": hdr.get("content-type", ""), "size": size,
                                "to_honeypot": to_honeypot, "n_hits": len(hits),
                                "n_strong_hits": sum(h["strength"] == "strong" for h in hits)})
        return hits

    @staticmethod
    def _write(f, obj) -> None:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def close(self) -> None:
        self._req.close()
        self._hits.close()
