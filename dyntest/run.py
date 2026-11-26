"""`dyn.py run`: one guided capture.

  prepare the extension -> start mitmweb + detector -> launch a fresh Chrome -> walk the tester
  through setup / baseline / passive / active / notes -> shut everything down cleanly.

Everything lands in runs/<YYYY-MM-DD_HHMM>_<name>_<mode>/:
  meta.json       what was tested (ID, version, SHA-256), with what (Chrome, mitmproxy, CA), when
  phase           current phase (read live by the detector)
  phases.jsonl    every phase start, timestamped
  requests.jsonl  every request (detector)       hits.jsonl   every honeytoken found (detector)
  flows.mitm      full capture                   flows.har    the same as HAR
  mitm.log                                       notes.md     the tester's notes
  chrome.log      Chrome's log incl. every console message from pages, content scripts and the
                  extension's service worker (why an extension did or didn't do something)
  profile/        the throwaway Chrome profile (deleted with --discard-profile)
"""
import json
import os
import platform
import queue
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import REPO, browser, mitm, tokens
from .crx import read_crx
from .extension import describe, resolve
from .prepare import prepare

RUNS = REPO / "runs"
MODES = ("session", "url", "cookies")
BASELINE_URL = "https://example.com/"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class RunOptions:
    selector: str                      # extension (file name, path or ID) or "control"
    mode: str
    browser: str | None = None         # "cft" | "chrome" | None (auto from the manifest)
    baseline: int = 60                 # seconds of hands-off on example.com
    passive: int = 60                  # seconds of hands-off on the honeypot, after the tester's clicks
    proxy_port: int = 8080
    web_port: int = 8081
    discard_profile: bool = False
    # test hooks (hidden on the command line)
    script: list[str] | None = None    # lines fed in place of keyboard input
    headless: bool = False
    out: object = field(default=sys.stdout)


class Console:
    """Prompts and countdowns. Reads keyboard lines on a background thread (works on every OS),
    or takes them from a script in tests."""

    def __init__(self, opts: RunOptions):
        self.q: queue.Queue[str] = queue.Queue()
        self.out = opts.out
        self.scripted = opts.script is not None
        if self.scripted:
            for line in opts.script:
                self.q.put(line)
        else:
            threading.Thread(target=self._read_stdin, daemon=True).start()

    def _read_stdin(self):
        for line in sys.stdin:
            self.q.put(line.rstrip("\n"))
        self.q.put("\x04")  # EOF

    def say(self, text: str = "") -> None:
        print(text, file=self.out, flush=True)

    def ask(self, prompt: str) -> str:
        print(prompt, end=" ", file=self.out, flush=True)
        line = self.q.get()
        if self.scripted:
            print(line, file=self.out, flush=True)
        if line == "\x04":
            raise KeyboardInterrupt
        return line.strip()

    def countdown(self, seconds: int, on_tick=None) -> None:
        """Wait `seconds`, or until Enter. Calls on_tick() about once a second (live hit display)."""
        end = time.time() + seconds
        if self.scripted:                     # tests: just wait; don't consume scripted answers
            while time.time() < end:
                if on_tick:
                    on_tick()
                time.sleep(min(0.25, max(0.0, end - time.time())))
            if on_tick:
                on_tick()
            return
        last = None
        while (left := int(end - time.time())) > 0:
            if left != last and (left % 15 == 0 or left <= 5):
                print(f"\r   {left // 60}:{left % 60:02d} left (Enter to skip)   ", end="", file=self.out, flush=True)
            last = left
            if on_tick:
                on_tick()
            try:
                line = self.q.get(timeout=min(1.0, max(0.05, end - time.time())))
                if line == "\x04":
                    raise KeyboardInterrupt
                break
            except queue.Empty:
                pass
        if on_tick:
            on_tick()
        print("\r" + " " * 40 + "\r", end="", file=self.out, flush=True)


class HitWatcher:
    """Tails hits.jsonl and reports new strong hits to non-honeypot hosts (potential leaks)."""

    def __init__(self, path: Path, console: Console):
        self.path, self.console, self.pos, self.leaks = path, console, 0, 0

    def poll(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as f:
                f.seek(self.pos)
                lines = f.readlines()
                self.pos = f.tell()
        except OSError:
            return
        for line in lines:
            try:
                h = json.loads(line)
            except ValueError:
                continue
            if h["strength"] == "strong" and not h["to_honeypot"] and h["phase"] != "setup":
                self.leaks += 1
                self.console.say(f"\n   ⚑ {h['field']} → {h['host']}  ({h['location']}, {h['encoding']}, {h['phase']})")


class Run:
    def __init__(self, opts: RunOptions):
        if opts.mode not in MODES:
            raise SystemExit(f"--mode must be one of {MODES}")
        self.o = opts
        self.c = Console(opts)
        self.doc = tokens.load()
        self.flow = self.doc["honeypot"]["flows"].get(opts.mode)
        if not self.flow:
            raise SystemExit(f"data/tokens.json has no honeypot flow for mode {opts.mode!r}")
        self.control = opts.selector.lower() == "control"
        self.procs: dict[str, subprocess.Popen] = {}
        self.logs = []                                    # log file handles, closed at shutdown
        self.phases: list[str] = []
        self.meta: dict = {}

    # -- setup ---------------------------------------------------------------------------------------
    def _prepare(self):
        o = self.o
        self.ext = None
        if not self.control:
            path = resolve(o.selector)
            crx = read_crx(path)
            self.ext = describe(crx, path)
            self.prepared = prepare(crx, path)
        kind = o.browser or ("chrome" if self.ext and self.ext["needs_branded_chrome"] else "cft")
        self.kind = kind
        self.chrome = browser.find_cft() if kind == "cft" else browser.find_branded_chrome()
        if not self.chrome:
            raise SystemExit(f"{'Chrome for Testing' if kind == 'cft' else 'Google Chrome'} not found: run dyn.py doctor")
        self.mitmweb = mitm.find("mitmweb")
        if not self.mitmweb:
            raise SystemExit("mitmweb not found: run dyn.py doctor")
        cert, _ = mitm.ensure_ca(mitm.find("mitmdump"))
        self.spki = mitm.spki_hash(cert)
        for port in (o.proxy_port, o.web_port):
            if not mitm.port_free(port):
                raise SystemExit(f"port {port} is in use (another run still open?). Free it or pass --proxy-port/--web-port")

        label = "control" if self.control else self.ext["label"]
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        rd = RUNS / f"{stamp}_{label}_{o.mode}"
        n = 2
        while rd.exists():
            rd, n = RUNS / f"{stamp}_{label}_{o.mode}-{n}", n + 1
        rd.mkdir(parents=True)
        self.dir, self.profile = rd, rd / "profile"
        self.meta = {
            "run_id": rd.name, "mode": o.mode, "control": self.control,
            "extension": None if self.control else {
                **{k: self.ext[k] for k in ("label", "file", "ext_id", "name", "version", "crx_sha256",
                                            "manifest_has_key", "needs_branded_chrome")},
                "unpacked_path": self.prepared["path"], "key": self.prepared["key"]},
            "browser": {"kind": kind, "path": str(self.chrome), "version": browser.chrome_version(self.chrome),
                        "headless": o.headless},
            "mitmproxy": {"version": mitm.version(mitm.find("mitmdump")), "ca_spki_sha256": self.spki,
                          "proxy_port": o.proxy_port, "web_port": o.web_port},
            "honeypot": self.doc["honeypot"]["base_url"],
            "host": {"os": f"{platform.system()} {platform.release()}", "python": platform.python_version()},
            "started": _now(), "ended": None, "phases": [], "aborted": False,
            "id_confirmed": None, "summary": None,
        }
        self._write_meta()

    def _write_meta(self):
        (self.dir / "meta.json").write_text(json.dumps(self.meta, indent=2) + "\n")

    def set_phase(self, name: str):
        (self.dir / "phase").write_text(name + "\n")
        with open(self.dir / "phases.jsonl", "a") as f:
            f.write(json.dumps({"ts": _now(), "phase": name}) + "\n")
        self.phases.append(name)
        self.meta["phases"] = self.phases
        self._write_meta()

    def _start_proxy(self):
        o = self.o
        token = secrets.token_hex(12)          # mitmweb UI access token (only valid while this run is open)
        log = open(self.dir / "mitm.log", "wb")
        self.logs.append(log)
        self.procs["mitmweb"] = subprocess.Popen(
            [str(self.mitmweb), "--listen-host", "127.0.0.1", "-p", str(o.proxy_port),
             "--web-host", "127.0.0.1", "--web-port", str(o.web_port), "--set", "web_open_browser=false",
             *mitm.PROXY_OPTIONS,
             "--set", f"web_password={token}", "--set", f"confdir={mitm.confdir()}",
             "--set", f"save_stream_file={self.dir / 'flows.mitm'}", "--set", f"hardump={self.dir / 'flows.har'}",
             "-s", str(REPO / "dyntest" / "detect_tokens.py"),
             "--set", f"dyn_run_dir={self.dir}", "--set", f"dyn_run_id={self.dir.name}"],
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True)   # Ctrl-C reaches only us
        if not mitm.wait_for_port(o.proxy_port):
            raise SystemExit(f"mitmweb did not start; see {self.dir / 'mitm.log'}")
        self.web_url = f"http://127.0.0.1:{o.web_port}/?token={token}"

    def _start_chrome(self):
        ext_dir = Path(self.prepared["path"]) if (self.ext and self.kind == "cft") else None
        browser.seed_profile(self.profile)
        args = [str(self.chrome), *(["--headless=new"] if self.o.headless else []),
                *browser.chrome_flags(self.profile, f"127.0.0.1:{self.o.proxy_port}", self.spki, ext_dir),
                "--enable-logging=stderr", "--v=0",   # console messages (pages, content scripts, service
                "about:blank"]                        # workers) -> chrome.log, e.g. "[Zetoe] Autofill disabled"
        log = open(self.dir / "chrome.log", "wb")
        self.logs.append(log)
        self.procs["chrome"] = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)

    def open_url(self, url: str):
        """Open a tab in the running test Chrome (a second launch with the same profile hands the URL over)."""
        if self.o.headless:
            return
        # Same flags as the first launch (mock keychain, no first-run/sign-in screens, proxy, trust),
        # minus --load-extension, which the running browser would treat as a reload request.
        subprocess.Popen([str(self.chrome), *browser.chrome_flags(self.profile, f"127.0.0.1:{self.o.proxy_port}",
                                                                  self.spki), url],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _confirm_id(self, wait: float) -> bool | None:
        if self.control:
            return None
        want = Path(self.prepared["path"]).resolve()
        deadline = time.time() + wait
        while True:
            seen = browser.loaded_extensions(self.profile)
            if Path(seen.get(self.ext["ext_id"], "")).resolve() == want:
                return True
            if time.time() >= deadline:
                return False
            time.sleep(1)

    # -- phases --------------------------------------------------------------------------------------
    def _phases(self):
        c, o, watch = self.c, self.o, self.watch
        base = self.doc["honeypot"]["base_url"]

        if not self.control:
            c.say("\n── SETUP ─────────────────────────────────────────────")
            if self.kind == "chrome":
                c.say("  This extension needs branded Chrome, which can't load it automatically:")
                c.say("   1. Open chrome://extensions, turn on Developer mode (top right).")
                c.say(f"   2. Click \"Load unpacked\" and choose:\n      {self.prepared['path']}")
                c.say("   3. Sign in to Chrome / Google with a THROWAWAY account if the extension needs it.")
            c.say("  • Sign in to the extension with a THROWAWAY account if it needs one; finish onboarding.")
            c.say("  • Close any welcome tabs. Don't open the honeypot yet.")
            c.say("  Nothing found during setup counts as a leak.")
            c.ask("  Press Enter when setup is done.")
            confirmed = self._confirm_id(wait=20)
            self.meta["id_confirmed"] = confirmed
            c.say("  ✓ extension loaded under its real ID" if confirmed else
                  "  ! couldn't confirm the extension's ID in the profile yet (checked again at the end)")

        self.set_phase("baseline")
        c.say(f"\n── BASELINE ({o.baseline // 60}:{o.baseline % 60:02d}) ─────────────────────────────")
        c.say(f"  Opening {BASELINE_URL}. Don't touch anything until the timer ends.")
        self.open_url(BASELINE_URL)
        c.countdown(o.baseline, watch.poll)

        self.set_phase("passive")
        start = base + self.flow["start"]
        c.say("\n── PASSIVE ───────────────────────────────────────────")
        c.say(f"  Opening {start}")
        for i, step in enumerate(self.flow["steps"], 1):
            c.say(f"   {i}. {step}")
        c.say("  Do NOT click the extension's icon, sidebar or popups. If it pops up by itself, leave it and note it.")
        self.open_url(start)
        c.ask("  Press Enter once you've done the steps above.")
        watch.poll()
        # Extensions often send late (batched analytics, replay uploads, idle callbacks): wait hands-off.
        c.say(f"  Now hands off for {o.passive // 60}:{o.passive % 60:02d}: leave the page open, touch nothing.")
        c.countdown(o.passive, watch.poll)

        if not self.control:
            c.say("\n── ACTIVE ────────────────────────────────────────────")
            c.say("  Use the extension's features on the honeypot page, one at a time.")
            c.say("  e.g. summarize, chat, select-text, right-click, autofill, translate")
            while True:
                name = c.ask("  Feature name (or 'done'):").lower()
                if name in ("done", "d", ""):
                    if name == "" and not self.c.scripted:
                        continue
                    break
                name = re.sub(r"[^a-z0-9_-]+", "-", name).strip("-") or "feature"
                self.set_phase(f"active:{name}")
                c.ask(f"  [{name}] Use it now; press Enter when finished.")
                watch.poll()

        self.set_phase("notes")
        notes = self.dir / "notes.md"
        if not notes.exists():
            notes.write_text(NOTES_TEMPLATE.format(run=self.dir.name, ext=self.meta["extension"]["name"]
                                                   if self.ext else "control (no extension)", mode=o.mode))
        c.say(f"\n── NOTES ─────────────────────────────────────────────\n  Fill in {notes}")
        c.ask("  Press Enter when saved (Chrome and the proxy close next).")

    # -- shutdown ------------------------------------------------------------------------------------
    def _stop(self):
        chrome = self.procs.pop("chrome", None)
        if chrome and chrome.poll() is None:
            chrome.terminate()                       # graceful: flushes the profile's preference files
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
                chrome.wait()
        web = self.procs.pop("mitmweb", None)
        if web and web.poll() is None:
            web.send_signal(signal.SIGINT if os.name != "nt" else signal.SIGTERM)  # flushes flows + HAR
            try:
                web.wait(timeout=30)
            except subprocess.TimeoutExpired:
                web.kill()
                web.wait()
        for f in self.logs:
            f.close()

    def _summarize(self) -> dict:
        def jl(name):
            p = self.dir / name
            return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
        reqs, hits = jl("requests.jsonl"), jl("hits.jsonl")
        leaks = [h for h in hits if h["strength"] == "strong" and not h["to_honeypot"] and h["phase"] != "setup"]
        return {
            "requests": sum(r["type"] in ("http", "ws") for r in reqs),
            "tls_failed": [f"{r['host']} ({r['error']})" for r in reqs if r["type"] == "tls_failed"],
            "no_response": sorted({r["host"] for r in reqs if r["type"] == "no_response"}),
            "hosts": len({r["host"] for r in reqs if r["type"] in ("http", "ws")}),
            "hits": len(hits),
            "leak_hits": len(leaks),
            "fields_leaked": sorted({h["field"] for h in leaks}),
            "leak_hosts": sorted({h["host"] for h in leaks}),
            "flows_mitm_bytes": (self.dir / "flows.mitm").stat().st_size if (self.dir / "flows.mitm").exists() else 0,
            "flows_har_bytes": (self.dir / "flows.har").stat().st_size if (self.dir / "flows.har").exists() else 0,
        }

    def execute(self) -> Path:
        self._prepare()
        c = self.c
        c.say(f"run      {self.dir}")
        if self.ext:
            c.say(f"testing  {self.ext['name']}  v{self.ext['version']}  ({self.ext['ext_id']})")
        c.say(f"browser  {'Chrome for Testing' if self.kind == 'cft' else 'Google Chrome'} "
              f"{self.meta['browser']['version']}, fresh profile, all traffic through mitmproxy")
        try:
            self._start_proxy()
            c.say(f"live UI  {self.web_url}")
            self.set_phase("startup" if self.control else "setup")   # Chrome's launch traffic
            self._start_chrome()
            self.watch = HitWatcher(self.dir / "hits.jsonl", c)
            self._phases()
        except KeyboardInterrupt:
            self.meta["aborted"] = True
            c.say("\n\nCtrl-C: stopping and saving what was captured…")
        finally:
            if (self.dir / "phase").exists():
                self.set_phase("finished")
            self._stop()
            if self.ext and self.meta.get("id_confirmed") is not True:
                self.meta["id_confirmed"] = self._confirm_id(wait=0)
            self.meta["ended"] = _now()
            self.meta["summary"] = self._summarize()
            self._write_meta()
            if self.o.discard_profile:
                shutil.rmtree(self.profile, ignore_errors=True)
        s = self.meta["summary"]
        c.say("\n── DONE ──────────────────────────────────────────────")
        c.say(f"  {s['requests']} requests to {s['hosts']} hosts; {s['hits']} token hits; "
              f"{s['leak_hits']} strong hit(s) to non-honeypot hosts outside setup")
        if s["leak_hits"]:
            c.say(f"  fields: {', '.join(s['fields_leaked'])}\n  hosts:  {', '.join(s['leak_hosts'])}")
        if s["tls_failed"]:
            c.say(f"  note: {len(s['tls_failed'])} TLS handshake(s) didn't complete, so those weren't inspected: "
                  f"{'; '.join(s['tls_failed'][:5])}")
        if s["no_response"]:
            c.say(f"  note: these servers never answered (requests were still recorded and searched): "
                  f"{', '.join(s['no_response'])}")
        if self.ext and self.meta["id_confirmed"] is False:
            c.say("  ! the extension was NOT confirmed under its real ID in this profile")
        c.say(f"  saved in {self.dir}")
        c.say("  Upload the folder to the private Drive folder; never commit it.")
        return self.dir


NOTES_TEMPLATE = """# Notes: {run}

Extension: {ext}
Mode: {mode}

- Account used (throwaway; no passwords here):
- Setup problems / features that didn't work:
- Did the extension do anything by itself during baseline/passive (popups, tabs, banners)?
- Features used in the active phase, and what each did:
- Anything else odd:
"""


def run(opts: RunOptions) -> Path:
    return Run(opts).execute()
