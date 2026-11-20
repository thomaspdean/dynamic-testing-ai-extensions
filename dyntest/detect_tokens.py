"""mitmproxy addon: search every request and client WebSocket message for honeytokens.

    mitmdump -s dyntest/detect_tokens.py --set dyn_run_dir=runs/<run> [--set dyn_tokens=data/tokens.json]

mitmproxy runs addons in its own bundled Python, which can't see this repo's packages, so the repo
root is put on sys.path here. All logic lives in dyntest/recorder.py and dyntest/matcher.py
(standard library only, unit tested without mitmproxy); this file only translates mitmproxy flows.
"""
import logging
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from mitmproxy import ctx  # noqa: E402

from dyntest import tokens as token_file  # noqa: E402
from dyntest.recorder import Recorder  # noqa: E402

log = logging.getLogger("dyntest")


def _headers(h) -> list[tuple[str, str]]:
    return [(k.decode("latin-1"), v.decode("latin-1")) for k, v in h.fields]


class DetectTokens:
    def __init__(self):
        self.rec: Recorder | None = None

    def load(self, loader):
        loader.add_option("dyn_run_dir", str, "", "Run folder: hits.jsonl, requests.jsonl and the phase file live here.")
        loader.add_option("dyn_tokens", str, "", "Honeytoken file (default: data/tokens.json in the repo).")
        loader.add_option("dyn_run_id", str, "", "Run id written on every line (default: run folder name).")

    def configure(self, updated):
        if not ({"dyn_run_dir", "dyn_tokens", "dyn_run_id"} & set(updated)):
            return
        if self.rec:
            self.rec.close()
            self.rec = None
        if not ctx.options.dyn_run_dir:
            log.warning("dyntest: dyn_run_dir not set, detector idle")
            return
        doc = token_file.load(Path(ctx.options.dyn_tokens) if ctx.options.dyn_tokens else token_file.TOKENS_FILE)
        self.rec = Recorder(ctx.options.dyn_run_dir, doc, ctx.options.dyn_run_id)
        log.info("dyntest: %d tokens, %d needles -> %s", len(doc["tokens"]), len(self.rec.matcher.needles),
                 ctx.options.dyn_run_dir)

    def request(self, flow):
        if not self.rec:
            return
        r = flow.request
        try:
            body = r.get_content(strict=False) or b""   # undoes gzip/br/deflate/zstd Content-Encoding
        except Exception:  # noqa: BLE001 - never break the proxied request
            body = r.raw_content or b""
        try:
            self.rec.on_request(r.method, r.pretty_url, r.pretty_host, _headers(r.headers), body)
        except Exception:  # noqa: BLE001
            log.exception("dyntest: failed to scan %s", r.pretty_url)

    def websocket_message(self, flow):
        if not self.rec or not flow.websocket:
            return
        msg = flow.websocket.messages[-1]
        if not msg.from_client:
            return
        try:
            self.rec.on_ws_message(flow.request.pretty_url, flow.request.pretty_host,
                                   _headers(flow.request.headers), msg.content)
        except Exception:  # noqa: BLE001
            log.exception("dyntest: failed to scan websocket message")

    def tls_failed_client(self, data):
        if not self.rec:
            return
        conn = getattr(data, "conn", None)
        host = getattr(conn, "sni", None) or str(getattr(getattr(data, "context", None), "server", ""))
        self.rec.on_tls_failed(host or "?", str(getattr(conn, "error", "") or "client TLS handshake failed"))

    def done(self):
        if self.rec:
            self.rec.close()


addons = [DetectTokens()]
