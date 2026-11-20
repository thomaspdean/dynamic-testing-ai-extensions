# Walkthrough: how the dynamic testing harness works

This explains the harness one step at a time, in the order it's built: what each piece does,
where its input comes from, how it serves the research question, and what it outputs.
`README.md` is the short tester guide. Background is in `CONTEXT.md` (sections C and D).

**What the harness answers:** when a user visits a page holding sensitive data, does an
extension send that data out of the browser, and if so, which data, where to, how encoded, and
in which phase?

**Method:**
1. Put fake sensitive values (honeytokens) on a page.
2. Run one extension in a clean browser.
3. Record every network request.
4. Search those requests for the fake values.

**Design rule: drop in a `.crx`, run it.** Everything the harness needs comes from the extension
file itself. There's no registry to fill in, no tester names, nothing specific to the CS6262
picks, and no dependency on the static-analysis repo. Comparing results with static predictions
or store labels is analysis you do afterwards. Every run records the extension's ID, version and
file SHA-256, so that comparison is easy to join.

## The flow

```mermaid
flowchart TD
    CRX["extensions/NAME.crx<br/>(any extension; for CS6262 the 15 scanned packages from Drive)"]
    H["honeypot site: Pollen Bank<br/>quillbert.github.io/honey/<br/>fake SSN, password, API keys…"]

    CRX -->|"1 · read the file<br/>ID, name, version, SHA-256,<br/>needs branded Chrome?"| INFO["dyn.py info NAME"]
    CRX -->|"2 · unpack with manifest key,<br/>re-check ID (automatic inside run)"| BUILD["build/extensions/ID/<br/>loads with its real store ID"]
    H -->|"3 · values copied by hand"| TOK["data/tokens.json<br/>strong vs. weak tokens,<br/>digit-only variants"]
    TOK -->|"4 · matcher + mitm addon"| DET["dyntest/detect_tokens.py<br/>raw · url · json · hex · base64<br/>· inflated zlib/gzip"]
    DOC["5 · dyn.py doctor<br/>mitm CA + SPKI hash,<br/>Chrome paths, port 8080"]

    BUILD --> RUN
    DET --> RUN
    DOC --> RUN
    RUN["6 · dyn.py run NAME --mode session|url|cookies<br/>fresh Chrome profile + 1 extension → mitmweb + detector<br/>phases: setup → baseline → passive → active → notes"]
    H -. "you browse it" .-> RUN
    RUN --> OUT["runs/DATETIME_NAME_MODE/<br/>meta.json · phases.jsonl · hits.jsonl<br/>requests.jsonl · flows.mitm · flows.har · notes.md"]
    CTRL["dyn.py run control<br/>(same script, no extension)"] --> OUT
    OUT -->|"7 · dyn.py summarize<br/>leak = strong token → non-honeypot host,<br/>outside setup"| RES["results/runs.csv · hits.csv · hosts.csv"]
    OUT -. "share" .-> DRIVE["private storage<br/>(never git)"]
    RES -. "outside the harness" .-> REP["your analysis: compare with<br/>static results, store labels"]
```

## Build order

| Step | Piece | Status |
|---|---|---|
| 1 | Read an extension from its `.crx` (parser + `dyn.py info`) | **done** |
| 2 | Unpack with the manifest `key` so it keeps its real ID (automatic in `run`; `dyn.py prepare` to check it alone) | **done** |
| 3 | `data/tokens.json`: the values the detector looks for | |
| 4 | Detector: encoding-aware matcher + mitmproxy addon, with tests | |
| 5 | `dyn.py doctor`: environment check | |
| 6 | `dyn.py run`: one guided capture | |
| 7 | `dyn.py summarize`: results tables | |
| 8 | `README.md` usage guide | |
| 9 | Self-test: control run plus a pilot on Zetoe or Devi | |

---

## Step 1: Read an extension from its `.crx` file

### What it does
Put a `.crx` in `extensions/`. The file name becomes its label (`extensions/zetoe.crx` → `zetoe`).
Then:
```
python3 dyn.py info               # every .crx in extensions/
python3 dyn.py info zetoe         # one, by file name
python3 dyn.py info mfcncdeeeekkjgonodmcjajafigpgnhh      # or by extension ID
python3 dyn.py info ~/Downloads/other.crx                 # or any path
python3 dyn.py info --brief       # one line each
```
`info` is mostly a check that the file is readable. The same reading happens at the start of
every `run`, and its output goes into that run's `meta.json`.

### What's read from the file, and why each value matters

| Value | Read from | Used for |
|---|---|---|
| `ext_id` | The CRX header's signed `crx_id`, matched to the developer's public key (below) | Loading the extension under its real ID (step 2), and recognising its background requests by `Origin: chrome-extension://<id>` |
| `name`, `version` | `manifest.json`. A placeholder name like `__MSG_appName__` is looked up in `_locales/` | Recorded in the run, so results say exactly what was tested |
| `crx_sha256` | SHA-256 of the whole file | Fingerprint of the exact package. Two runs with the same hash tested the same code |
| `needs_branded_chrome` | Does the manifest have an `oauth2` section? | `chrome.identity.getAuthToken` only works with an `oauth2` section **and** a browser signed in to Google, which Chrome for Testing can't do. So `run` will tell you to use branded Chrome and load the extension by hand. `launchWebAuthFlow` (Gene) needs neither, so it works in Chrome for Testing |
| `manifest_has_key` | Does the manifest already have `"key"`? | If not, step 2 adds one |
| `minimum_chrome_version` | `manifest.json` | `doctor` and `run` can warn if the Chrome build is too old |

For the 15 CS6262 packages, only OG AI comes out as `needs_branded_chrome`. That matches what was
found by hand. Gene has the `identity` permission but no `oauth2` section, so it stays on Chrome
for Testing.

### How the ID is read from a `.crx`
A CRX3 file is `"Cr24"`, a version number, a header length, a protobuf header, then an ordinary
zip of the extension. The header holds:
- **key proofs:** pairs of (public key, signature). A store download has **three**: the
  developer's key plus keys added by the Web Store.
- **`signed_header_data.crx_id`:** the 16-byte extension ID, covered by the signatures.

The extension ID is `SHA-256(public key)[:16]`, written as hex with the digits `0-f` mapped to the
letters `a-p`. The parser picks the one public key whose hash starts with `crx_id`. Step 2 writes
that key into `manifest.json` as `"key"`.

**Why this matters:** without `key`, Chrome gives an unpacked extension a **random ID**. Only
3 of the 15 packages ship with one (AITOPIA, QuestionAI, Spekit). A wrong ID:
- breaks Google sign-in through `chrome.identity`;
- can make backends reject requests from an `Origin` they don't recognise;
- loses the `Origin` header that tells us a request came from the extension rather than the page.

Signatures aren't verified: the file's SHA-256 is recorded instead. CRX2 (the old format: key and
signature lengths, then the zip) is also supported.

### Where the `.crx` files live (not in git)
`extensions/*.crx` is git-ignored. The folder itself is kept, via `.gitkeep`.
- **Size:** 15 packages are 217 MB, git history keeps binaries forever, and every clone pays for them.
- **Ownership:** they're third-party proprietary packages, and committing them redistributes them.

For CS6262, the 15 scanned packages live in the private Drive folder. Use those, not the Chrome Web
Store, which only serves the current version: Merlin, Shizue and Spekit have already changed since
the scan.

### Scaffolding added with this step
- `.gitignore`:
  - Captures (`runs/`, `results/`, `*.mitm`, `*.har`, `hits.jsonl`, `requests.jsonl`) hold the
    test accounts' cookies and tokens, so they never go in git.
  - Generated folders: `build/`, `profiles/`.
  - Extension packages: `extensions/*.crx`.
- `CLAUDE.md`: imports `CONTEXT.md` and lists the repo rules.
- Code layout: `dyn.py` is the only command and stays thin. Logic lives in `dyntest/`:
  - `crx.py`: CRX parser, standard library only;
  - `extension.py`: finds a file by path, name or ID, and describes it.
- Tests: `python3 -m unittest discover tests`.

### How it was checked
`tests/test_crx.py` (13 tests, all passing):
- **ID mapping:** a known hash maps to the expected 32-letter ID.
- **Synthetic CRX3 with a decoy key before the developer's key:** the parser picks the right key,
  ID and `key` value, resolves the localised name, and hashes the whole file.
- **Errors:** wrong magic, a truncated header, and no key matching `crx_id` all fail clearly.
  CRX2 is parsed.
- **Finding files:** by path, by name with or without `.crx`, and by ID. A missing file gives a
  clear error. `describe` flags an `oauth2` manifest as needing branded Chrome.
- **Every `.crx` in `extensions/`:** the header's `crx_id` agrees with the chosen key, and the
  manifest reads. This test is skipped if the folder is empty.

Independent cross-check: for all 15 CS6262 packages, the ID, version, SHA-256 and name read from
the files alone matched what the static scan recorded when it downloaded them.

---

## Step 2: Unpack with the real ID (`prepare`)

### What it does
```
python3 dyn.py prepare zetoe            # unpack one
python3 dyn.py prepare                  # unpack every .crx in extensions/
python3 dyn.py prepare --verify         # ...and prove the ID in a real Chrome
```
`run` calls the same code automatically. `prepare` exists so you can check a new extension before
starting a capture.

**Input:** the `.crx` from step 1.

**Output:** `build/extensions/<ext_id>/`, a folder Chrome loads with `--load-extension`, plus
`build/extensions/<ext_id>.prepared.json`, which records the source file, its SHA-256, the
version, and what happened to the key. `build/` is git-ignored and can be deleted at any time.

### The steps
1. **Safe unzip** of every file in the package. Paths that are absolute or contain `..` are
   refused, so a malicious package can't write outside `build/`.
2. **Set `manifest.json` `"key"`** to the developer public key from the CRX header (step 1).
   - If the manifest already has the *same* key, it's left alone (`key kept`).
   - A *different* key is replaced (`key replaced`). Otherwise the key is added (`key added`).
   - **This is the only change made to the package.** Every other file is byte-for-byte the
     original, so we're testing the developer's code.
3. **Recompute the ID** from the key that was written, and require it to equal the CRX's ID.
4. **Cache by SHA-256:** the same file reuses its unpack. A different file (e.g. a new version
   with the same ID) always gets a fresh unpack, so a run can never use stale code.

### `--verify`: proving it in a real browser
Computing the ID ourselves only shows the arithmetic is right. `--verify` asks Chrome itself:
1. Launch Chrome for Testing **headless**, with a brand-new throwaway profile and only this
   extension loaded.
2. Point its proxy at a closed local port (`127.0.0.1:9`). **Every network request fails
   locally**, so whatever the extension does at startup (install pages, analytics, config fetches)
   never reaches its servers. That keeps us within "no traffic to extension backends beyond
   normal use".
3. Wait ~6 s, shut Chrome down gracefully (so it writes its profile files), and read the
   profile's `Default/Secure Preferences` → `extensions.settings`, where Chrome records each
   installed extension's ID and folder.
4. Pass if the ID Chrome recorded for our folder equals the store ID, then delete the profile.

`run` (step 6) will do the same profile check on the real capture profile.

**The macOS Keychain prompt and `--use-mock-keychain`:** on macOS, Chrome asks the Keychain for
"Chrome Safe Storage" (the key it encrypts cookies and passwords with) when it opens a profile.
Chrome for Testing is a separate app, so macOS shows a permission popup, and Chrome **blocks until
it's answered**. The first `--verify` attempt hung for exactly this reason. Every Chrome the
harness launches gets `--use-mock-keychain`, a fake in-memory keychain, so there's no popup and
the real Keychain is never touched. If the popup appears anyway, click **Deny**.

### Findings while building this
- **`_metadata/` is kept.** Every store package has `_metadata/verified_contents.json` (the Web
  Store's signature of the files). I expected Chrome to refuse an unpacked folder containing it,
  because names starting with `_` are reserved. Tested with Chrome for Testing 131, it loads fine,
  so nothing is removed.
- **12 of the 15 needed a key added.** AITOPIA, QuestionAI and Spekit already ship the right key.

### How it was checked
- **`dyn.py prepare --verify` on all 15 CS6262 packages:** each loaded in Chrome under its real
  store ID (12 key added, 3 kept), in about 6 s each.
- **`tests/test_prepare.py`** (7 tests, all passing):
  - **Synthetic packages:** the key is added, kept or replaced correctly. Every other file,
    including `_metadata/`, is unchanged. The cache is reused for the same file and redone for a
    different one. `../` paths are refused and nothing is written outside `build/`.
  - **Real Chrome, positive:** a keyed copy loads as its store ID.
  - **Real Chrome, negative control:** the same folder *without* `key` still loads, but under a
    different ID, and the check reports a failure. This proves the check isn't something that
    always passes.
  - The Chrome tests are skipped automatically if Chrome for Testing or a `.crx` isn't available.
- Full suite: `python3 -m unittest discover tests` gives 20 tests, all passing (~13 s).
