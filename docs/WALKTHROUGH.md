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

The user-level flow (diagram, browsing steps, files) is in [`README.md`](../README.md#how-it-works); this file covers how each piece works inside.

## Build order

| Step | Piece | Status |
|---|---|---|
| 1 | Read an extension from its `.crx` (parser + `dyn.py info`) | **done** |
| 2 | Unpack with the manifest `key` so it keeps its real ID (automatic in `run`; `dyn.py prepare` to check it alone) | **done** |
| 3 | `data/tokens.json`: the values the detector looks for | **done** |
| 4 | Detector: encoding-aware matcher + mitmproxy addon, with tests | **done** |
| 5 | `dyn.py doctor`: environment check | **done** |
| 6 | `dyn.py run`: one guided capture | **done** |
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

---

## Step 3: The honeytokens (`data/tokens.json`)

### What it is
The list of fake sensitive values the honeypot puts on its pages. The detector (step 4) searches
every captured request for exactly these. This is the harness's definition of "user data", so a
value missing from this file can never be reported as a leak.

```
python3 dyn.py tokens            # list them
python3 dyn.py tokens --check    # also fetch the live honeypot and confirm every value is still there
```

### Where the values come from
The honeypot's own source, not memory or a copy in a document:
- `assets/app.js` (the `defaults` and `loginDefaults` objects);
- the `value="…"` attributes in its HTML forms, which is where URL mode gets its values;
- the honeypot repo ([Quillbert/honey](https://github.com/Quillbert/honey)) has one commit, 21ebc36
  from 2026-11-11. The file records it.

Session, URL and cookie mode all use the **same** values, so the mode a value leaked from comes
from the run's mode, not from the value. Each run uses one mode and a fresh profile.

`--check` downloads the honeypot pages listed in the file and fails if any value is missing.
Run it if the honeypot might have changed. A silently changed honeypot would make every run
report "no leak". It currently passes: all 19 values were found on the 6 pages.

### What's in the file

| Part | Purpose |
|---|---|
| `honeypot.hosts` | `quillbert.github.io`. Requests *to the honeypot itself* are expected (the page loading its own data), so a leak means a value reaching **any other host** |
| `honeypot.pages` | What `--check` fetches |
| `tokens[]` | One entry per distinct value. Each has `value`, the honeypot `fields` that use it, a `kind`, a `strength`, and optional `alts` |

**One entry per value, not per field.** 22 field names but 19 distinct values:
- `cc_name` is the same string as `name`;
- the login username and account number repeat the profile ones.

A hit is reported against all the fields sharing that value, e.g. `name,cc_name`.

**`kind`:** what sort of data it is: `identity`, `contact`, `government_id`, `financial`,
`address`, `credential`, `crypto`. Used later to say *what* leaked (e.g. "a credential and a
government ID", not just "3 tokens").

### Strong vs. weak

| Strength | Values | Rule |
|---|---|---|
| **strong** (12) | name, username, email, account number, SSN, phone, street address, password, OpenAI key, Robinhood key, bitcoin address, bitcoin key | Distinctive enough that a match isn't a coincidence. **A strong value reaching a non-honeypot host outside the setup phase is a leak.** |
| **weak** (7) | `Testville`, `ZZ`, `00000`, `1990-01-15`, `4111111111111111`, `2030-12`, `123` | Generic: `123` and `00000` appear in ordinary traffic constantly, `4111…` is the standard Visa test number, and dates and `ZZ` are short. Reported in a separate column, **never counted as a leak on their own**. They're still useful as corroboration: a request with the SSN *and* `4111…` *and* `123` is clearly the whole form |

The loader enforces a minimum length of 8 characters for anything marked strong, so a short value
can't be marked strong by mistake.

### Alternate forms (`alts`)
Code often normalises data before sending it, e.g. a form library stripping punctuation. Two
values get a digits-only form as an extra needle:
- **SSN** `900-12-3456` → also `900123456`.
- **Phone** `+1-202-555-0147` → also `2025550147`, the national number without the country code.
  That one form also catches `12025550147` and `+12025550147`, since they contain it.

Other transformations (lowercase, URL-encoding, base64, hex, JSON escaping, compression) aren't
listed here. The detector applies them to every value automatically (step 4).

### Note for step 4: overlapping values
`mira.holloway` is inside `mira.holloway@example.com`, so every email hit is also a username hit.
The detector should report the longer token for that spot and not double-count.

### Making it general
Nothing here is specific to an extension. To use a different honeypot, edit this file: hosts,
pages, values. The loader validates it:
- the honeypot hosts are present;
- every entry has a value and fields;
- strong values are at least 8 characters;
- no value repeats, ignoring case.

### How it was checked
- `dyn.py tokens --check` against the live site: all 19 values present on the 6 pages.
- `tests/test_tokens.py` (6 tests, all passing):
  - all 22 honeypot fields are covered;
  - the weak set is exactly the 7 generic values;
  - the digit-only alts are right;
  - the password is a strong credential;
  - validation catches a too-short strong value, a case-insensitive duplicate, and missing honeypot hosts;
  - `--check` reports a value that's missing from the pages (with a fake fetch, no network).
- Full suite: 26 tests, all passing.

---

## Step 4: The detector

### What it does
While a run is capturing, mitmproxy hands every request the browser makes to the detector. The
detector searches that request for the honeytokens and writes what it found. It sees requests from
the page and from the extension alike: the browser can't send anything that doesn't pass through it.

**Input:** each HTTP request and each WebSocket message the browser sends, plus
`data/tokens.json` and the run's `phase` file.

**Output**, in the run folder:

| File | One line per | Holds |
|---|---|---|
| `requests.jsonl` | every request and WebSocket message, hit or not, plus every connection that couldn't be decrypted (`tls_failed`) | time, phase, method, host, URL, `Origin`, whether the origin is a `chrome-extension://` page, `Sec-Fetch-Site/Dest`, content type, size, whether it went to the honeypot, number of (strong) hits |
| `hits.jsonl` | each (request, token, encoding, location) match | the above plus `field` (e.g. `name,cc_name`), `value_kind`, `strength`, `matched` (value or digits-only alt), `encoding`, `location`, `count`, and `context`: 40 bytes either side, as evidence |

`requests.jsonl` matters even when nothing leaks. It's the full list of hosts the extension
contacted, which `summarize` compares against the control run (step 7).

### Three layers
| File | Role | Why separate |
|---|---|---|
| `dyntest/matcher.py` | Turns tokens into encoded forms; searches bytes; inflates embedded compressed streams | Pure standard library, unit tested in plain Python |
| `dyntest/recorder.py` | Per request: splits it into parts, runs the matcher on each, tags phase / honeypot / extension origin, writes JSONL | Same: testable without mitmproxy |
| `dyntest/detect_tokens.py` | The mitmproxy addon: converts mitmproxy's request objects into plain values for the recorder | mitmproxy runs addons in its **own bundled Python** (3.15 in the cask app), which can't import anything installed in yours. The addon puts the repo root on its import path and stays as thin as possible |

### Where in a request it looks (`location`)
- `url`: the whole URL, including the host, so data packed into a subdomain is caught too.
- `header:<name>`: every header separately, e.g. `header:cookie`, `header:referer`, custom ones.
- `body`: after mitmproxy undoes `Content-Encoding` (gzip, br, deflate, zstd).
- `ws-message`: WebSocket messages sent by the browser.
- `…>zlib@<offset>`, `…>gzip@<offset>`, `…>base64>gzip@<offset>`: a compressed stream found
  *inside* one of the above and inflated, e.g. a session-replay upload. The offset says where.

### Which encodings (`encoding`)
Every token value and alt becomes a set of "needles", the exact bytes searched for:

| Encoding | Example (SSN `900-12-3456` or name `Mira Holloway`) | Where you'd see it |
|---|---|---|
| `raw` (`raw+case` if the case differs) | `900-12-3456` | JSON bodies, plain text |
| `url` | `Mira%20Holloway`, `Mira+Holloway`, JS `encodeURIComponent` | query strings, form posts, the honeypot's own cookies |
| `url-double` | `Mira%2520Holloway` | a URL inside another URL's parameter |
| `json` / `json-unicode` | `\u002d` escapes | some serializers |
| `hex` | `3930302d31322d33343536` (either case) | URL hashing/obfuscation (GoGPT hex-encodes URLs) |
| `base64@k` / `base64url@k`, k = 0, 1, 2 | the stretch of base64 that depends only on the token, for each of the 3 byte offsets it could start at | the token *inside* a larger base64 blob, e.g. a whole JSON payload base64'd into a query parameter |
| `digits+…` | `900123456`, `2025550147` | values with formatting stripped |

**Weak tokens** (`123`, `ZZ`, `00000`…) only get raw/url/json needles, and must sit between
non-alphanumeric characters. Otherwise `123` would match inside every number.

**Not detected**, a stated limitation:
- hashed values (e.g. `sha256(email)`, which trackers send);
- encryption or custom obfuscation;
- raw deflate without a zlib/gzip header.

### Precision rules
- **Overlap:** when a match lies inside a longer match, only the longer one is kept, so an email
  hit is not also reported as a username hit. The username is still reported where it appears on
  its own.
- **Counting:** one `hits.jsonl` line per (token, matched value, encoding) per request part, with
  `count` for repeats. A page-dump body containing the SSN 40,000 times is one line.

### Attribution fields
- `is_extension_origin`: the request's `Origin` or `Referer` is `chrome-extension://…`. That's
  true for the extension's background/service-worker requests and its own pages. Content scripts
  send requests as the page, so they show the page's origin. Those are told apart by the control
  run and by the extension's DevTools (CONTEXT §D).
- `to_honeypot`: the host is in `tokens.json` → `honeypot.hosts`. The page sending its own data
  to its own server is expected, so `summarize` only calls a hit a leak when this is false.
- `phase`: read from `<run_dir>/phase`, which `run` writes as the tester moves on. The file is
  re-read only when it changes.

### What was fixed along the way
- **Speed:** the first version used one big regex alternation and took **5 s** per 2 MB body,
  which would stall large requests in the proxy. It now uses `bytes.find` per needle: **0.07 s**
  per 2 MB.
- **A quadratic overlap check:** a body containing a token 160,000 times hung the first rewrite.
  The overlap rule is now a single sorted sweep: 0.19 s for that body.
- **A test that tested itself:** the `encodeURIComponent` test built its expected strings with
  the function under test, so breaking the function went unnoticed. It now uses hard-coded
  JavaScript outputs. A deliberate break of the base64 alignment logic was confirmed to fail its
  test.

### How it was checked
- `tests/test_matcher.py` (14 tests):
  - every strong token, in every encoding above, inside realistic surroundings;
  - base64 at all 3 offsets × standard/URL-safe;
  - the digit-only alts;
  - the honeypot's own cookie format, and a full URL-mode query string;
  - zlib in a binary body, gzip in a multipart body, base64-wrapped gzip in JSON;
  - weak-value boundaries, and no base64/hex needles for weak values;
  - overlap and counting;
  - **no strong false positives** on 300 KB of random bytes, its base64, hex and zlib forms,
    and look-alike text ("holloway caves").
- `tests/test_recorder.py` (5 tests):
  - phase tagging follows the phase file;
  - honeypot vs. other host, and extension origin, on the honeypot-cookie and Zetoe-style POST cases;
  - every request is logged even with no hits;
  - WebSocket messages and TLS failures are recorded;
  - request ids continue after a restart.
- `tests/test_detector_integration.py` (6 tests): **real `mitmdump`** with the addon, real HTTP
  requests through it, and a local `http.server` as the destination. It uses a throwaway
  mitmproxy config dir and plain HTTP, so there are no certificates, nothing in `~/.mitmproxy`,
  and no network. Checks:
  - every request is recorded with the right phase;
  - a password in a form post is tagged `setup`;
  - a base64 SSN in a query string from a `chrome-extension://` origin is caught and attributed;
  - a `Content-Encoding: gzip` body is decoded and the email found, without a duplicate username hit;
  - the honeypot cookie is flagged `to_honeypot`;
  - `flows.mitm` is written.
- Full suite: **51 tests** pass (~14 s).

---

## Step 5: Environment check (`doctor`)

### What it does
```
python3 dyn.py doctor            # all checks
python3 dyn.py doctor --offline  # skip the live honeypot check
```
It prints one line per check: `ok`, `WARN` (works, with a caveat), `FAIL` (captures won't work
until fixed, with the fix on the next line), or info. It exits non-zero if anything failed. It is
the first thing a new tester runs, and the only command that changes anything outside the repo:
it creates mitmproxy's certificate authority in `~/.mitmproxy` if there isn't one.

| Check | Passes when | If not |
|---|---|---|
| Python | 3.10+ | install it |
| mitmproxy | `mitmdump` and `mitmweb` are on `PATH`; version shown | install hint for the OS |
| mitmproxy CA | `~/.mitmproxy/mitmproxy-ca-cert.pem` exists. If not, `doctor` starts mitmdump once so it creates one | n/a |
| CA SPKI hash | computed from the CA (shown for reference) | n/a |
| Chrome for Testing | found (newest under `~/.cache/puppeteer/chrome`, or `$DYN_CHROME`); version shown | install command |
| Google Chrome (branded) | found; version shown | `WARN` only if an extension in `extensions/` needs it (has an `oauth2` manifest section) |
| **Each browser → proxy → HTTPS** | a headless Chrome, given the SPKI flag, completes an HTTPS request through mitmproxy | `FAIL`: captures would be empty or broken |
| Ports 8080 / 8081 | free (proxy, mitmweb UI) | `WARN` with how to find what's using it |
| `extensions/` | every `.crx` readable; Chrome for Testing new enough for each `minimum_chrome_version`; lists those needing branded Chrome | `FAIL` per bad file or too-old Chrome |
| honeypot | reachable and every token value still on it (same as `tokens --check`) | `FAIL` if values changed, `WARN` if unreachable |

### How Chrome trusts mitmproxy, and only in the test profile
To read HTTPS, mitmproxy presents certificates signed by its own CA. Normally you'd install that
CA in the system keychain, which makes **every** app on the machine trust it. Instead, the harness
starts Chrome with:
```
--ignore-certificate-errors-spki-list=<base64(SHA-256(the CA's SubjectPublicKeyInfo))>
```
Chrome then accepts certificates chaining to that one key, and only in a Chrome started with that
flag **and** a `--user-data-dir`. Your normal browser and the rest of the system are unaffected.

The hash is computed with the standard library. `dyntest/mitm.py` has a small DER reader that walks
the certificate to its `SubjectPublicKeyInfo` and hashes it, so no `cryptography` package is
needed. It matches `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst
-sha256 -binary | base64` exactly.

### The end-to-end trust check (nothing leaves the machine)
1. Start mitmdump with `dyntest/mitm_selftest.py`, a tiny addon that **answers every request
   itself**. With `connection_strategy=lazy`, mitmproxy never connects to a real server.
2. Start headless Chrome with the harness's normal flags plus the SPKI flag, opening
   `https://dyn-doctor.test/` (`.test` is a reserved, non-existent domain).
3. The addon writes `request dyn-doctor.test` if Chrome completed TLS with mitmproxy's certificate
   and sent the request, or `tls_failed dyn-doctor.test` if Chrome rejected it.
   **Pass = the request arrived.**

Both browsers are checked: Chrome for Testing 131 and branded Chrome 157 (used for OG AI).

### Shared Chrome flags
`dyntest/browser.py → chrome_flags()` is now the single list every Chrome the harness starts gets:
`doctor`, `prepare --verify`, and `run`.

| Flag | Why |
|---|---|
| `--user-data-dir=<fresh dir>` | throwaway profile: no cookies or history carried between runs. Also required for the SPKI flag |
| `--use-mock-keychain` | macOS: no Keychain popup, real Keychain untouched (found in step 2) |
| `--no-first-run --no-default-browser-check` | no first-run UI |
| `--disable-sync --disable-background-networking --disable-component-update` | cuts Chrome's own background traffic, so captures are mostly the page and the extension |
| `--disable-quic` | HTTP/3 runs over UDP and would bypass the HTTP proxy, so it's turned off |
| `--disable-features=DisableLoadExtensionCommandLineSwitch` | keeps `--load-extension` working |
| `--proxy-server=127.0.0.1:<port>` | all traffic through mitmproxy |
| `--ignore-certificate-errors-spki-list=<hash>` | trust mitmproxy, this profile only |
| `--load-extension=<dir> --disable-extensions-except=<dir>` | exactly one extension |

### Found while building this
- **`--dump-dom` hangs intermittently.** The first version asked Chrome to print the page and exit.
  Chrome for Testing 131 sometimes hung for 40 s+ (passed 0.6 s, then hung, on back-to-back runs).
  The check now relies on proxy-side evidence: did mitmproxy receive the decrypted request? That is
  also the more meaningful test. It passed 3/3 consecutive `doctor` runs.
- The shared marker constant first lived in the addon file, which imports `mitmproxy`, so our
  Python couldn't import it. Addon files must not be imported by our own code.

### Output on this machine
```
  ok   Python                             3.14.7
  ok   mitmproxy                          12.3.1
  ok   mitmproxy CA                       ~/.mitmproxy/mitmproxy-ca-cert.pem  (created now)
       CA SPKI hash                       jq5jYfeWx/XN2Pj5DQSlVpFr6/HjFr6eW62a24GtR0M=
  ok   Chrome for Testing                 131.0.6778.204
  ok   Google Chrome (branded)            157.0.8103.80
  ok   Chrome for Testing → proxy → HTTPS trusts mitmproxy in a test profile (…nothing left this machine)
  ok   Google Chrome → proxy → HTTPS      trusts mitmproxy in a test profile (…)
  ok   proxy port 8080                    free
  ok   mitmweb UI port 8081               free
  ok   extensions/                        15 .crx readable; branded Chrome needed for: ogai
  ok   honeypot                           reachable; all token values present
ready
```
(The SPKI hash is specific to each machine's CA. Each tester's `doctor` shows their own.)

### How it was checked
- `tests/test_doctor.py` (6 tests, all passing; temp mitmproxy config dir, never `~/.mitmproxy`):
  - **DER reader:** finds the SPKI in synthetic certificates with and without the version field
    and with long-form lengths; rejects garbage; PEM round trip.
  - **Real CA:** mitmdump creates one, and a second call reuses it.
  - **The hash equals `openssl`'s** for that real CA.
  - **Real Chrome, positive and negative:** with the SPKI flag the HTTPS request reaches the proxy;
    **without it Chrome rejects the certificate** (`tls_failed`). So the check can genuinely fail.
- `dyn.py doctor` run for real 4 times on this machine: all `ok` after the `--dump-dom` fix.
- Full suite: **57 tests**, all passing (~17 s).

---

## Step 6: One guided capture (`run`)

### What it does
```
python3 dyn.py run zetoe --mode session        # an extension: file name, path or ID
python3 dyn.py run control --mode session      # no extension: Chrome's own traffic
   [--browser cft|chrome] [--baseline 120] [--passive 180] [--proxy-port 8080] [--web-port 8081]
   [--discard-profile]
```
`run` ties steps 1–5 together. The tester only follows prompts.

| Stage | What happens | Built on |
|---|---|---|
| 1. Prepare | read the `.crx`; unpack with its real ID (cached); pick the browser (branded Chrome if the manifest has `oauth2`); make sure the CA exists and compute its SPKI hash; check ports 8080/8081 are free | steps 1, 2, 5 |
| 2. Run folder | `runs/<YYYY-MM-DD_HHMM>_<name>_<mode>/` (with `-2`, `-3` suffixes if it exists); `meta.json` written straight away | n/a |
| 3. Proxy | `mitmweb` on 127.0.0.1 with the detector addon, saving `flows.mitm` (streamed) and `flows.har` (on exit). Its UI is protected by a random token; the link is printed. It doesn't open a browser | step 4 |
| 4. Chrome | a visible Chrome with a fresh profile in `<run>/profile/`, the shared flags (step 5), and only this extension. Both processes run in their own session, so Ctrl-C reaches only `run`, which then shuts them down in order | step 5 |
| 5. Phases | prompts and countdowns (below). Every transition is written to `phase` (read live by the detector) and `phases.jsonl` | step 4 |
| 6. Shutdown | Chrome first (graceful, so its profile files are written), then mitmweb with SIGINT (writes the HAR); re-check the extension ID; write the summary into `meta.json`; optionally delete the profile | n/a |

### The phases as the tester sees them
| Phase | Prompt | Ends |
|---|---|---|
| `setup` (extensions only) | sign in with a throwaway account, finish onboarding, close welcome tabs, don't open the honeypot. For branded Chrome: the exact "Load unpacked" steps and folder path | Enter; then the extension ID is confirmed from the profile's `Secure Preferences` (up to 20 s) |
| `startup` (control only) | none: just Chrome launching | automatically |
| `baseline` | opens example.com; "don't touch anything" | timer (default 2 min) or Enter |
| `passive` | opens the mode's start page and prints its steps from `tokens.json` → `honeypot.flows`; "don't click the extension" | timer (default 3 min) or Enter |
| `active:<feature>` (extensions only) | type a feature name; use it; Enter. Repeat; `done` ends | `done` |
| `notes` | writes a `notes.md` template and asks you to fill it in | Enter |
| `finished` | written at shutdown, also after Ctrl-C | n/a |

While countdowns run, new **strong hits to non-honeypot hosts outside setup** are printed live,
e.g. `⚑ ssn → api.x.com (body, raw, passive)`.

**Opening pages** in the tester's window: `run` launches the same Chrome binary again with the
same `--user-data-dir` and a URL. Chrome hands the URL to the already-running browser as a new tab.
No remote-debugging port is needed.

**The honeypot steps moved into `data/tokens.json`** (`honeypot.flows.<mode>`: start path and
steps), so `run` contains nothing honeypot-specific. The step text uses the site's real button
labels, "Sign in securely" and "Review information", which were checked against the live pages.
The README had them wrong ("Log in / Continue") until this step.

### `meta.json`
- **What was tested:** mode; control or not; the extension's label, file, ID, name, version,
  SHA-256, whether its manifest had a key, whether it needs branded Chrome, and the unpacked path.
- **With what:** browser kind, path and version; mitmproxy version, CA SPKI hash and ports; the
  honeypot URL; the host OS and Python.
- **When:** start and end time, phases completed, `aborted` (Ctrl-C), and `id_confirmed`
  (`true`/`false`, or `null` for control).
- **`summary`:**
  - requests and distinct hosts;
  - token hits;
  - **leak hits** (strong, non-honeypot, outside setup), with the fields and hosts;
  - TLS handshakes that didn't complete (host and reason);
  - capture file sizes.

### Found while building this
- **Back-to-back runs were blocked.** After a run, the proxy port has connections in TCP
  TIME_WAIT for about a minute. The plain "is the port free?" bind failed on them, so a second run
  would have refused to start. The check now binds like a server (`SO_REUSEADDR`) and still detects
  a port something is really listening on.
- **The mitmweb UI link was missing its token.** mitmweb buffers its log, so the token line
  wasn't there yet when read. `run` now generates the token itself and passes it as `web_password`.
  Checked: the right token gives 200, none or a wrong one gives 403.
- **Chrome's own autofill service** (`content-autofill.googleapis.com`) appeared in a control
  run's passive phase: Chrome reports form structure to Google. Since the passive phase is all
  forms, `--disable-features=AutofillServerCommunication` was added to the shared flags.
  `accounts.google.com` and `clients2.google.com` also appear with no extension. That's exactly
  what the control run is for.
- The one `tls_failed` seen in a control run was Chrome closing an `accounts.google.com`
  connection early, not certificate pinning. The end-of-run message now lists host and reason
  instead of a vague warning.

### How it was checked
- `tests/test_run.py` (2 tests, ~22 s). Real mitmweb + detector + headless Chrome for Testing,
  short timers, answers scripted instead of typed:
  - **Full extension run** with a tiny local test extension (real RSA key from `openssl`, so
    Chrome accepts its manifest key). Its service worker keeps POSTing the fake SSN and a
    base64'd password over plain HTTP to `dyn-run-test.test`, a reserved name that doesn't exist.
    mitmproxy records the request and then fails to forward it, so nothing leaves the machine.
    Checks:
    - phases are exactly `setup, baseline, passive, active:summarize, notes, finished`, in both
      `meta.json` and `phases.jsonl`;
    - **the ID is confirmed in the live profile**;
    - the SSN and password are found as leaks from the extension's origin, the password as base64;
    - the summary counts them;
    - `flows.mitm` and `flows.har` are non-empty, and `notes.md` and the profile exist;
    - both ports are free afterwards.
  - **Ctrl-C** (end-of-input at the notes prompt) in a control run: `aborted` is true, phases are
    closed with `finished`, the end time is set, `flows.mitm` exists, and `--discard-profile`
    removed the profile.
- A short **visible** control run: the URL handoff works (example.com in `baseline`, the
  honeypot in `passive`).
- Full suite: **59 tests**, all passing (~37 s).

Not yet exercised: a real extension against the real honeypot with a real account. That's the
step 9 pilot.
