@CONTEXT.md

## Working rules for this repo
- Tooling is Python 3.10+, standard library only (no pip installs). The mitmproxy addon runs inside
  mitmproxy's bundled Python, so it must be self-contained too.
- Drop in a `.crx`, run it: everything the harness needs comes from the file itself (no registry,
  no tester names, nothing specific to the 15 CS6262 picks). No dependency on the static repo:
  comparing with static results or store labels is the user's own analysis afterwards.
- For CS6262, test the scanned packages in `extensions/` (from the private Drive folder), never a
  store install.
- Never commit captures (`runs/`, `results/`, `*.mitm`, `*.har`): they hold test-account tokens.
- Don't use the hard-coded developer keys from the static notes, and don't send traffic to extension
  backends beyond normal use (no fuzzing, no replaying captured tokens).
- `docs/WALKTHROUGH.md` is the step-by-step usage guide (commands and what they do); keep it in
  sync with the CLI. `docs/DESIGN.md` explains how each piece works; update it when a piece changes.
