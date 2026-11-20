#!/usr/bin/env python3
"""Dynamic testing harness CLI. Python 3.10+, standard library only.

Drop a .crx into extensions/ (or pass any path), then:
  python3 dyn.py info zetoe            # what the harness reads from the file

More subcommands (prepare, doctor, run, summarize) are added step by step; see docs/WALKTHROUGH.md.
"""
import argparse
import sys

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


def main(argv=None):
    p = argparse.ArgumentParser(prog="dyn.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="show what the harness reads from a .crx (default: every file in extensions/)")
    s.add_argument("ext", nargs="*", help="a .crx path, a file name in extensions/, or an extension ID")
    s.add_argument("--brief", action="store_true", help="one line per extension")
    s.set_defaults(fn=cmd_info)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
