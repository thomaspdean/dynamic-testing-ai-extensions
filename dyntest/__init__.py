"""Dynamic testing harness for browser extensions. See docs/WALKTHROUGH.md (use) and docs/DESIGN.md (internals)."""
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXT_DIR = REPO / "extensions"  # drop .crx files here (git-ignored)
