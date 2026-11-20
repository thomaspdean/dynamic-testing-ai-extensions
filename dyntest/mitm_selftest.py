"""mitmproxy addon used by `dyn.py doctor`: answers every request itself, so nothing goes upstream.

Run with --set connection_strategy=lazy so mitmproxy never opens a connection to the real server.
It appends one line per event to --set selftest_out=<file>:
    request <host>       Chrome completed TLS with mitmproxy's certificate and sent the request
    tls_failed <sni>     Chrome rejected mitmproxy's certificate
That proves proxy + certificate trust without any traffic leaving the machine.
"""
from mitmproxy import ctx, http


def load(loader):
    loader.add_option("selftest_out", str, "", "file to append request / tls_failed lines to")


def _note(line: str) -> None:
    if ctx.options.selftest_out:
        with open(ctx.options.selftest_out, "a") as f:
            f.write(line + "\n")


def request(flow: http.HTTPFlow) -> None:
    _note(f"request {flow.request.pretty_host}")
    flow.response = http.Response.make(200, b"<html><body>dyn-doctor-ok</body></html>",
                                       {"Content-Type": "text/html"})


def tls_failed_client(data) -> None:
    _note(f"tls_failed {getattr(getattr(data, 'conn', None), 'sni', '') or '?'}")
