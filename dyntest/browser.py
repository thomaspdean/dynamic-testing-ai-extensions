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
    args = [str(chrome), f"--user-data-dir={profile}", "--headless=new",
            "--use-mock-keychain",  # macOS: never prompt for / touch the real Keychain
            "--no-first-run", "--no-default-browser-check", "--disable-sync",
            "--disable-background-networking", "--disable-component-update",
            "--proxy-server=127.0.0.1:9",  # discard port: every request fails locally
            "--disable-features=DisableLoadExtensionCommandLineSwitch",
            f"--load-extension={ext_dir}", f"--disable-extensions-except={ext_dir}",
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
