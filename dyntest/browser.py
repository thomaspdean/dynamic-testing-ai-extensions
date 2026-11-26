"""Find Chrome builds and read which extensions a profile has loaded."""
import json
import os
import platform
import shutil
from pathlib import Path

HOME = Path.home()


def find_cft() -> Path | None:
    """Chrome for Testing: $DYN_CHROME, else the newest puppeteer / @puppeteer/browsers install."""
    if os.environ.get("DYN_CHROME"):
        p = Path(os.environ["DYN_CHROME"]).expanduser()
        return p if p.exists() else None
    exe = {
        "Darwin": "*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        "Linux": "*/chrome",
        "Windows": "*/chrome.exe",
    }[platform.system()]
    roots = [HOME / ".cache/puppeteer/chrome", HOME / "chrome", Path.cwd() / "chrome"]
    found = [p for r in roots if r.is_dir() for d in r.iterdir() if d.is_dir() for p in d.glob(exe)]

    def version(p: Path):
        tag = next((part for part in p.parts if part.count(".") == 3 and "-" in part), "0.0.0.0")
        return tuple(int(x) for x in tag.split("-")[-1].split(".") if x.isdigit())

    return max(found, key=version) if found else None


def find_branded_chrome() -> Path | None:
    candidates = {
        "Darwin": [Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")],
        "Linux": [Path(p) for p in (shutil.which("google-chrome") or "", shutil.which("google-chrome-stable") or "") if p],
        "Windows": [Path(os.environ.get(v, "")) / "Google/Chrome/Application/chrome.exe"
                    for v in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")],
    }[platform.system()]
    return next((p for p in candidates if p.is_file()), None)


def loaded_extensions(profile: Path) -> dict[str, str]:
    """ext_id -> path for extensions recorded in the profile (Secure Preferences, then Preferences)."""
    out = {}
    for name in ("Secure Preferences", "Preferences"):
        f = profile / "Default" / name
        try:
            settings = json.loads(f.read_text()).get("extensions", {}).get("settings", {})
        except (OSError, ValueError):
            continue
        for eid, s in settings.items():
            if isinstance(s, dict) and s.get("path"):
                out.setdefault(eid, s["path"])
    return out


def chrome_version(chrome: Path) -> str:
    import re
    import subprocess
    try:
        out = subprocess.run([str(chrome), "--version"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""


def chrome_flags(profile: Path, proxy: str | None = None, spki: str | None = None,
                 extension: Path | None = None) -> list[str]:
    """The flags every Chrome the harness starts gets (doctor, prepare --verify, run)."""
    flags = [
        f"--user-data-dir={profile}",          # fresh throwaway profile; also required for the SPKI flag
        "--use-mock-keychain",                 # macOS: never prompt for / touch the real Keychain
        "--no-first-run", "--no-default-browser-check",
        "--disable-sync",                      # no Google account sync traffic
        "--disable-background-networking",     # no Chrome background fetches (variations, suggestions...)
        "--disable-component-update",          # no component updater downloads
        "--disable-quic",                      # QUIC (HTTP/3 over UDP) would bypass the HTTP proxy
        "--disable-features=DisableLoadExtensionCommandLineSwitch,AutofillServerCommunication",  # keep --load-extension; no form data to Google autofill
    ]
    if proxy:
        flags.append(f"--proxy-server={proxy}")
    if spki:
        flags.append(f"--ignore-certificate-errors-spki-list={spki}")  # trust mitmproxy's CA, this profile only
    if extension:
        flags += [f"--load-extension={extension}", f"--disable-extensions-except={extension}"]
    return flags


# Written into a new profile before Chrome first starts. These stop Chrome itself from sending what
# you type in the address bar to Google, which would show up as a "leak" (e.g. a url-mode honeypot
# URL full of values typed or pasted into the omnibox) that isn't the extension's.
PROFILE_PREFS = {
    "search": {"suggest_enabled": False},              # no omnibox search suggestions
    "alternate_error_pages": {"enabled": False},       # no "did you mean" lookups for failed URLs
}


def seed_profile(profile: Path) -> None:
    """Create <profile>/Default/Preferences with PROFILE_PREFS (only for a brand-new profile)."""
    prefs = profile / "Default" / "Preferences"
    if prefs.exists():
        return
    prefs.parent.mkdir(parents=True, exist_ok=True)
    prefs.write_text(json.dumps(PROFILE_PREFS))


def check_trust(chrome: Path, proxy_port: int, spki: str | None, events: Path,
                host: str = "dyn-doctor.test", timeout: float = 20) -> tuple[bool, str]:
    """Open https://<host>/ in headless Chrome through the proxy; True once mitmproxy saw the request.

    Pair with dyntest/mitm_selftest.py (writing to `events`): it answers inside mitmproxy, so
    nothing leaves the machine. mitmproxy only sees the request if Chrome accepted its certificate.
    """
    import subprocess
    import tempfile
    import time

    events.write_text("")
    profile = Path(tempfile.mkdtemp(prefix="dyn-doctor-"))
    proc = subprocess.Popen([str(chrome), "--headless=new",
                             *chrome_flags(profile, f"127.0.0.1:{proxy_port}", spki), f"https://{host}/"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            seen = events.read_text()
            if f"request {host}" in seen:
                return True, seen
            if f"tls_failed {host}" in seen:
                return False, "Chrome rejected mitmproxy's certificate"
            if proc.poll() is not None:
                return False, f"Chrome exited early (code {proc.returncode})"
            time.sleep(0.2)
        return False, "no request reached the proxy"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        shutil.rmtree(profile, ignore_errors=True)


def verify_load(chrome: Path, ext_dir: Path, ext_id: str, settle: float = 6.0) -> tuple[bool, dict, str]:
    """Load ext_dir in a throwaway headless profile and return (loaded under ext_id?, ids seen, log tail).

    The proxy points at a closed local port, so nothing the extension does at startup leaves
    the machine: this checks the ID without sending any traffic to the extension's servers.
    """
    import subprocess
    import tempfile
    import time

    profile = Path(tempfile.mkdtemp(prefix="dyn-verify-"))
    log = profile / "chrome.log"
    args = [str(chrome), "--headless=new",
            *chrome_flags(profile, proxy="127.0.0.1:9", extension=ext_dir),  # port 9: requests fail locally
            "--enable-logging=stderr", "--v=0", "about:blank"]
    try:
        with open(log, "wb") as lf:
            proc = subprocess.Popen(args, stdout=lf, stderr=subprocess.STDOUT)
            time.sleep(settle)
            proc.terminate()  # graceful shutdown flushes the profile's preference files
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        seen = loaded_extensions(profile)
        ok = Path(seen.get(ext_id, "")).resolve() == ext_dir.resolve()
        tail = "\n".join(l for l in log.read_text(errors="replace").splitlines()
                         if "extension" in l.lower() or "manifest" in l.lower())[-2000:]
        return ok, seen, tail
    finally:
        shutil.rmtree(profile, ignore_errors=True)
