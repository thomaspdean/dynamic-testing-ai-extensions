#!/usr/bin/env python3
"""Dynamic testing harness CLI. Python 3.10+, standard library only.

Drop a .crx into extensions/ (or pass any path), then:
  python3 dyn.py doctor               # check this machine; creates mitmproxy's CA on first use
  python3 dyn.py info zetoe            # what the harness reads from the file
  python3 dyn.py prepare zetoe --verify   # unpack with its real ID; prove it in Chrome (network blocked)
  python3 dyn.py tokens --check        # the honeytokens; confirm they're still on the live honeypot

More subcommands (run, summarize) are added step by step; see docs/WALKTHROUGH.md.
"""
import argparse
import sys
from pathlib import Path

if sys.version_info < (3, 10):
    sys.exit("dyn.py needs Python 3.10+")

from dyntest import EXT_DIR
from dyntest.crx import CrxError, read_crx
from dyntest.extension import describe, resolve


def load(selector: str) -> dict:
    try:
        path = resolve(selector)
        return describe(read_crx(path), path)
    except (FileNotFoundError, CrxError) as e:
        sys.exit(str(e))


def cmd_info(a):
    selectors = a.ext or sorted(f.name for f in EXT_DIR.glob("*.crx"))
    if not selectors:
        sys.exit(f"no .crx files in {EXT_DIR}/")
    for s in selectors:
        d = load(s)
        if a.brief:
            print(f"{d['label']:<12} {d['ext_id']}  v{d['version']:<16} "
                  f"{'branded Chrome' if d['needs_branded_chrome'] else 'Chrome for Testing'}")
        else:
            print("\n".join(f"{k:>22}: {v}" for k, v in d.items()) + "\n")


def cmd_prepare(a):
    from dyntest import browser
    from dyntest.prepare import prepare

    chrome = None
    if a.verify:
        chrome = browser.find_cft()
        if not chrome:
            sys.exit("--verify needs Chrome for Testing (set DYN_CHROME or see README)")
    selectors = a.ext or sorted(f.name for f in EXT_DIR.glob("*.crx"))
    failed = 0
    for s in selectors:
        try:
            path = resolve(s)
            crx = read_crx(path)
            rec = prepare(crx, path, force=a.force)
        except (FileNotFoundError, CrxError) as e:
            print(f"FAIL {s}: {e}")
            failed += 1
            continue
        line = f"{path.stem:<12} {rec['ext_id']}  v{rec['version']:<16} key {rec['key']:<8}"
        if chrome:
            ok, seen, tail = browser.verify_load(chrome, Path(rec["path"]), rec["ext_id"])
            line += "  Chrome: " + ("loaded with this ID" if ok else f"NOT loaded as this ID (saw {list(seen) or 'none'})")
            if not ok:
                failed += 1
                line += "\n" + tail
        print(line)
    if failed:
        sys.exit(f"{failed} failed")


def cmd_doctor(a):
    from dyntest.doctor import FAIL, run_checks

    marks = {"OK": "  ok ", "WARN": " WARN", "FAIL": " FAIL", "INFO": "     "}
    failed = 0
    for status, what, detail, fix in run_checks(online=not a.offline):
        print(f"{marks[status]}  {what:<34} {detail}")
        if fix:
            print(f"{'':7}{'':<34} → {fix}")
        failed += status == FAIL
    print("\nready" if not failed else f"\n{failed} problem(s) to fix before running captures")
    sys.exit(1 if failed else 0)


def cmd_tokens(a):
    from dyntest import tokens

    try:
        doc = tokens.load()
    except (OSError, ValueError) as e:
        sys.exit(str(e))
    hp = doc["honeypot"]
    print(f"honeypot: {hp['name']}  {hp['base_url']}  (hosts: {', '.join(hp['hosts'])})")
    for strength in ("strong", "weak"):
        rows = [t for t in doc["tokens"] if t["strength"] == strength]
        print(f"\n{strength} ({len(rows)}):")
        for t in rows:
            alts = f"  also: {', '.join(t['alts'])}" if t.get("alts") else ""
            print(f"  {t['kind']:<13} {','.join(t['fields']):<38} {t['value']}{alts}")
    if a.check:
        try:
            missing = tokens.check_live(doc)
        except OSError as e:
            sys.exit(f"\ncould not fetch the honeypot: {e}")
        if missing:
            sys.exit(f"\nNOT on the live honeypot any more: {missing}  (update data/tokens.json)")
        print(f"\nlive check: all {len(doc['tokens'])} values found on {len(hp['pages'])} honeypot pages")


def main(argv=None):
    p = argparse.ArgumentParser(prog="dyn.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="show what the harness reads from a .crx (default: every file in extensions/)")
    s.add_argument("ext", nargs="*", help="a .crx path, a file name in extensions/, or an extension ID")
    s.add_argument("--brief", action="store_true", help="one line per extension")
    s.set_defaults(fn=cmd_info)

    s = sub.add_parser("prepare", help="unpack .crx file(s) into build/ with the manifest key (run does this itself)")
    s.add_argument("ext", nargs="*", help="a .crx path, a file name in extensions/, or an extension ID (default: all)")
    s.add_argument("--force", action="store_true", help="re-unpack even if a cached unpack of the same file exists")
    s.add_argument("--verify", action="store_true",
                   help="load it in headless Chrome for Testing (network blocked) and check the ID Chrome assigns")
    s.set_defaults(fn=cmd_prepare)

    s = sub.add_parser("doctor", help="check mitmproxy, its CA, Chrome, ports and the honeypot")
    s.add_argument("--offline", action="store_true", help="skip the live honeypot check")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("tokens", help="list the honeytokens in data/tokens.json")
    s.add_argument("--check", action="store_true", help="fetch the honeypot pages and confirm every value is still there")
    s.set_defaults(fn=cmd_tokens)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
