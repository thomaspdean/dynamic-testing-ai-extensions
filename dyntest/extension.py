"""Find an extension file and describe it, using nothing but the file itself."""
import re
from pathlib import Path

from . import EXT_DIR
from .crx import Crx, CrxError, read_crx


def resolve(selector: str) -> Path:
    """A path to a .crx, a file name in extensions/ (with or without .crx), or an extension ID."""
    p = Path(selector).expanduser()
    if p.is_file():
        return p
    for cand in (EXT_DIR / selector, EXT_DIR / f"{selector}.crx"):
        if cand.is_file():
            return cand
    if re.fullmatch(r"[a-p]{32}", selector):
        for f in sorted(EXT_DIR.glob("*.crx")):
            try:
                if read_crx(f).ext_id == selector:
                    return f
            except CrxError:
                continue
    raise FileNotFoundError(f"no extension {selector!r}: give a .crx path, or drop the file into {EXT_DIR}/")


def describe(crx: Crx, path: Path) -> dict:
    """Everything the harness needs about an extension. All of it comes from the file."""
    m = crx.manifest()
    return {
        "file": path.name,
        "label": path.stem,                     # used in run folder names
        "ext_id": crx.ext_id,
        "name": crx.display_name(),
        "version": m.get("version", ""),
        "crx_sha256": crx.sha256,
        "crx_format": crx.crx_version,
        "manifest_version": m.get("manifest_version"),
        "minimum_chrome_version": m.get("minimum_chrome_version", ""),
        "manifest_has_key": "key" in m,
        # chrome.identity.getAuthToken needs an "oauth2" manifest section and a browser signed in
        # to Google, which Chrome for Testing can't provide. launchWebAuthFlow needs neither.
        "needs_branded_chrome": "oauth2" in m,
    }
