"""Unpack a .crx into a folder Chrome can load with --load-extension, under its real store ID.

build/extensions/<ext_id>/                 the unpacked extension (manifest has "key")
build/extensions/<ext_id>.prepared.json    what was done, incl. the source SHA-256

Steps:
  1. safe unzip of every file (refuses absolute paths and "..")
  2. set manifest "key" to the developer public key from the CRX header (left untouched if the
     manifest already has the same key). This is the only change made to the package.
  3. recompute the ID from the key that was written and require it == the CRX's ID
The result is cached by the .crx SHA-256: a different file always gets a fresh unpack.
_metadata/ (the Web Store's file signatures) is kept: Chrome ignores it for unpacked extensions
and loads fine with it present (checked with Chrome for Testing 131).
"""
import base64
import json
import shutil
from pathlib import Path, PurePosixPath

from . import REPO
from .crx import Crx, CrxError, id_from_public_key

BUILD = REPO / "build" / "extensions"


def _safe_extract(crx: Crx, dest: Path) -> None:
    with crx.zip() as z:
        for info in z.infolist():
            p = PurePosixPath(info.filename)
            if p.is_absolute() or ".." in p.parts or ":" in p.parts[0]:
                raise CrxError(f"unsafe path in package: {info.filename!r}")
            target = dest.joinpath(*p.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def prepare(crx: Crx, source: Path, force: bool = False) -> dict:
    """Unpack (or reuse a cached unpack of) this exact .crx. Returns the prepared.json record."""
    out = BUILD / crx.ext_id
    record_path = BUILD / f"{crx.ext_id}.prepared.json"
    if not force and out.is_dir() and record_path.exists():
        rec = json.loads(record_path.read_text())
        if rec.get("crx_sha256") == crx.sha256:
            return rec

    tmp = BUILD / f".{crx.ext_id}.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    try:
        _safe_extract(crx, tmp)
        mpath = tmp / "manifest.json"
        manifest = json.loads(mpath.read_text(encoding="utf-8-sig"))

        existing = manifest.get("key")
        if existing:
            try:
                existing_id = id_from_public_key(base64.b64decode("".join(existing.split())))
            except ValueError:
                existing_id = None
            key_action = "kept" if existing_id == crx.ext_id else "replaced"
        else:
            key_action = "added"
        if key_action != "kept":
            manifest["key"] = crx.manifest_key
            mpath.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        written = json.loads(mpath.read_text(encoding="utf-8"))["key"]
        unpacked_id = id_from_public_key(base64.b64decode("".join(written.split())))
        if unpacked_id != crx.ext_id:
            raise CrxError(f"manifest key gives ID {unpacked_id}, expected {crx.ext_id}")

        shutil.rmtree(out, ignore_errors=True)
        tmp.rename(out)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    rec = {
        "ext_id": crx.ext_id, "version": manifest.get("version", ""), "crx_sha256": crx.sha256,
        "source": str(source), "path": str(out), "key": key_action,
        "unpacked_id": unpacked_id,
    }
    record_path.write_text(json.dumps(rec, indent=2) + "\n")
    return rec
