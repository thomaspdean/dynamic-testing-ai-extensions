"""Dynamic testing harness for browser extensions. See docs/WALKTHROUGH.md."""
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXT_DIR = REPO / "extensions"  # drop .crx files here (git-ignored)
