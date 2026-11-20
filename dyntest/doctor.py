"""`dyn.py doctor`: is this machine ready to run captures? Fixes what it safely can.

Each check returns (status, what, detail, fix). Status: OK, WARN (works, with a caveat), FAIL (run
will not work until fixed), INFO.
"""
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import EXT_DIR, REPO, browser, mitm
from .crx import CrxError, read_crx
from .extension import describe

OK, WARN, FAIL, INFO = "OK", "WARN", "FAIL", "INFO"
PROXY_PORT, WEB_PORT = 8080, 8081

INSTALL_MITM = {
    "Darwin": "brew install --cask mitmproxy   (or download from https://mitmproxy.org)",
    "Linux": "pipx install mitmproxy   (or download from https://mitmproxy.org)",
    "Windows": "download the installer from https://mitmproxy.org",
}.get(platform.system(), "see https://mitmproxy.org")
INSTALL_CFT = "npx @puppeteer/browsers install chrome@stable   (or set DYN_CHROME to a Chrome for Testing binary)"


def run_checks(online: bool = True):
    """Yield check results one at a time, so the CLI can print as it goes."""
    ok_py = sys.version_info >= (3, 10)
    yield (OK if ok_py else FAIL, "Python", platform.python_version(), "" if ok_py else "install Python 3.10+")

    mitmdump, mitmweb = mitm.find("mitmdump"), mitm.find("mitmweb")
    if not mitmdump or not mitmweb:
        yield FAIL, "mitmproxy", "mitmdump/mitmweb not on PATH", INSTALL_MITM
        return
    yield OK, "mitmproxy", f"{mitm.version(mitmdump)}  ({mitmdump.parent})", ""

    try:
        cert, created = mitm.ensure_ca(mitmdump)
    except RuntimeError as e:
        yield FAIL, "mitmproxy CA", str(e), "run mitmdump once by hand and check its output"
        return
    spki = mitm.spki_hash(cert)
    yield OK, "mitmproxy CA", f"{cert}{'  (created now)' if created else ''}", ""
    yield INFO, "CA SPKI hash", spki, ""

    cft, branded = browser.find_cft(), browser.find_branded_chrome()
    cft_ver = browser.chrome_version(cft) if cft else ""
    if cft:
        yield OK, "Chrome for Testing", f"{cft_ver}  ({cft})", ""
    else:
        yield FAIL, "Chrome for Testing", "not found", INSTALL_CFT

    exts, needs_branded = [], []
    for f in sorted(EXT_DIR.glob("*.crx")):
        try:
            exts.append(describe(read_crx(f), f))
        except (CrxError, OSError, ValueError) as e:
            yield FAIL, f"extensions/{f.name}", f"unreadable: {e}", "replace the file"
    needs_branded = [d["label"] for d in exts if d["needs_branded_chrome"]]
    if branded:
        yield OK, "Google Chrome (branded)", f"{browser.chrome_version(branded)}  ({branded})", ""
    else:
        yield (WARN if needs_branded else INFO, "Google Chrome (branded)", "not found",
               f"needed for: {', '.join(needs_branded)}" if needs_branded else
               "only needed for extensions that use chrome.identity.getAuthToken")

    port = mitm.free_port()
    events = Path(tempfile.mkdtemp(prefix="dyn-doctor-")) / "events.txt"
    proc = subprocess.Popen([str(mitmdump), "--listen-host", "127.0.0.1", "-p", str(port),
                             "--set", f"confdir={mitm.confdir()}", "--set", "connection_strategy=lazy",
                             "-s", str(REPO / "dyntest" / "mitm_selftest.py"), "--set", f"selftest_out={events}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not mitm.wait_for_port(port):
            yield FAIL, "proxy self-test", "mitmdump did not start", "run mitmdump by hand and read its error"
        else:
            for name, chrome in (("Chrome for Testing", cft), ("Google Chrome", branded)):
                if not chrome:
                    continue
                trusted, why = browser.check_trust(chrome, port, spki, events)
                yield ((OK, f"{name} → proxy → HTTPS", "trusts mitmproxy in a test profile (test page served "
                        "locally, nothing left this machine)", "") if trusted else
                       (FAIL, f"{name} → proxy → HTTPS", why, f"check the CA in {mitm.confdir()}"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(events.parent, ignore_errors=True)

    for p, what in ((PROXY_PORT, "proxy port"), (WEB_PORT, "mitmweb UI port")):
        free = mitm.port_free(p)
        yield (OK if free else WARN, f"{what} {p}", "free" if free else "in use",
               "" if free else f"stop whatever uses it (lsof -nP -iTCP:{p}), or pass another port to run")

    if exts:
        major = int(cft_ver.split(".")[0]) if cft_ver else 0
        too_new = [f"{d['label']} (needs {d['minimum_chrome_version']})" for d in exts
                   if d["minimum_chrome_version"] and major
                   and int(str(d["minimum_chrome_version"]).split(".")[0]) > major]
        detail = f"{len(exts)} .crx readable" + (f"; branded Chrome needed for: {', '.join(needs_branded)}"
                                                 if needs_branded else "")
        yield OK, "extensions/", detail, ""
        if too_new:
            yield FAIL, "Chrome for Testing version", f"too old for: {', '.join(too_new)}", INSTALL_CFT
    else:
        yield INFO, "extensions/", "no .crx files yet", f"drop .crx files into {EXT_DIR}"

    if online:
        from . import tokens
        try:
            missing = tokens.check_live(tokens.load())
            yield ((OK, "honeypot", "reachable; all token values present", "") if not missing else
                   (FAIL, "honeypot", f"values missing from the live site: {missing}", "update data/tokens.json"))
        except OSError as e:
            yield WARN, "honeypot", f"could not reach it: {e}", "check your network; retry with dyn.py tokens --check"
