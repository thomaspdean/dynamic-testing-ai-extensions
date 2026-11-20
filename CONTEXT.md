# Context: dynamic testing harness for GenAI browser extensions

This file gives a new repo (and anyone, human or AI, working in it) the full background. It was
written on 2026-11-12, at the end of the static-analysis phase. Copy it into the new repo as
`CONTEXT.md` (or `CLAUDE.md` if you use Claude Code there).

---

## A. The project

**Course:** CS 6262 (Network Security), team of three.

**Research question:** What user data do GenAI / AI-assistant Chrome extensions send off the
device, and does that match what they disclose (Chrome Web Store privacy label)?

**Method: a funnel.**
1. **Static analysis (done):** 64 AI-assistant extensions, sampled across 7 user-count tiers
   (`1M+`, `100K to 1M`, `10K to 100K`, `1K to 10K`, `500 to 1K`, `100 to 500`, `<100`).
   Unpack each one, read its manifest, scan its code for data-collection and exfiltration
   signals, classify the endpoints it references, scrape its store page, and score/rank it.
   It's cheap and wide but only produces *leads*: it shows what code *could* do.
2. **Dynamic analysis (this repo):** take the top 15 by static score, run each one in a real
   browser against a honeypot site full of fake sensitive data (honeytokens), capture all
   network traffic with mitmproxy, and see which tokens leave the browser and where they go.
   It's narrow but shows what actually happens.
3. **Final report:** for each extension, compare static predictions, dynamic observations and
   the store disclosure. The main deliverable table has one row per extension, with yes/no
   columns for behaviours and value columns (counts, hosts, categories).

**Split:** each of the three team members dynamically tests 5 of the 15 extensions, the same way.

---

## B. Where static analysis ended up

### The static scanner (`extscan`, other repo: `static-scanning-ai-extensions`)
Pipeline: `ingest → analyze → scan → classify → scrape → score → report`, plus v2:
`scan2 → score2 → report2`. One JSON record per extension in `out/records/<ext_id>.json`.

- **v1 score** (kept for comparison): six components, mostly measuring code size and manifest
  permissions. Its page_harvesting component was at the cap for 39 of 64 extensions, so it
  didn't discriminate.
- **v2 score** (used for selection), 0-100, five parts:

| Part | Max | Earns points for |
|---|---|---|
| Page access | 25 | Code that runs *inside web pages* reading full text/HTML, form values, iframes, shadow DOM, the site's local/session storage; screenshots; captured URLs |
| Data flow | 30 | What it reads sitting next to code that sends data out (network call or message to the background); reading all cookies; sending site cookies, visited URLs, location |
| Destinations | 25 | Unidentified third-party servers near a send, session-replay code, trackers (by kind), affiliate/ad SDKs, remote iframe UIs, IP-geolocation lookups |
| Reach | 10 | Runs on every site / all frames / before page load; high-risk permissions |
| Code risk | 10 | eval/new Function, remote code, script injection, obfuscation, hard-coded keys |

  v2 tags every file by where it runs (page / background / extension UI), counts reads but not
  writes, stops marking big first-party bundles as "vendor" because of a library banner, and
  adds proximity flow signals. Remaining limits: bigger extensions still score somewhat higher
  (Spearman with code size 0.73), and weights were set against one manual review of these 64.

- **Selection rule (deterministic):** top 15 by v2 rank, skipping an extension that shares a
  declared developer domain with a higher-ranked pick. Smart Sidebar (#15) was skipped as the
  same developer as #5 (both `aitopia.ai`; 290 identical code files), so #16 Shizue got in.

### Static outputs that matter for dynamic testing
- `out/summary_v2.csv`: one row per extension, v2/v1 ranks, yes/no behaviour columns, counts, store label.
- `out/static_scan_results.xlsx`: partner workbook. Tabs: *Start here* (score guide), *Top 15 to test*
  (why flagged, what to plant, code-review notes, Tester column), *All 64 extensions*.
- `out/endpoints.csv`: every (extension, host) pair with party/category (`first_party`, `tracker`,
  `llm_provider`, `known_service`, `cdn_static`, `unknown`) and `near_sink`. Use it as the
  **expected destinations** list: a host seen dynamically but absent here is a finding.
- `work/unpacked/<ext_id>/`: the exact extension code that was scanned.
- `extension-targets/<folder>/`: original `.crx` + `.zip` + `meta.json` (with SHA-256) for all 64.
- `notes/user-harm-leads.md`, `notes/hardcoded-secrets.md`: manual code-review findings.

### The 15 extensions to test

`key?` = manifest already has a `key` (keeps its real ID when loaded unpacked). `identity` =
uses `chrome.identity` (Google sign-in), which breaks if the ID changes. Static flags are from
v2. Hosts are a partial, noisy list of third-party/own hosts near a send: use `endpoints.csv` for the full list.

| # | Extension | ext_id | Scanned ver. | Tier | v2 | key? | identity | Store label | Static flags | Hosts near a send (partial) |
|---|---|---|---|---|---|---|---|---|---|---|
|1|Sider|`difoiogjjojoaoomphldepapgpbgkhkb`|5.35.3|1M+|91.0|no|no|declares collection|page data near send, reads page, password/hidden fields, ad SDK (zeroclick.dev)|sidercontent.com, openai.com, anthropic.com, deepseek.com, groq.com, googleapis|
|2|Quillbot|`iidnbdjijdkbmajdffnidomddglmieko`|4.123.0|1M+|78.7|no|no|declares collection|reads page, dumps page storage, session replay (rrweb)|languagetool.org|
|3|Devi|`obofmdbkmindkbmdjkfdmehmddjfnhad`|3.3.5|1K-10K|70.0|no|no|declares collection|page data near send, reads ALL cookies, sends site cookies, session replay (Clarity)|zapier.com, visadb.workers.dev|
|4|Monica|`ofpnmcalabcbjgholdjcjblkibolbppb`|9.0.23|1M+|65.5|no|no|declares collection (omits Website content)|reads page, dumps page storage|monica.im|
|5|Chat with all AI (aitopia)|`becfinhbfclcgokjlobojlnldbfillpf`|6.9.2|1M+|64.8|yes|no|declares collection|page data near send, dumps page storage|aitopia.ai|
|6|TypeOS|`hikgnomhpklghakgjgecehpfodfmaanm`|1.0.1|1K-10K|63.2|no|no|**says collects nothing**|page data near send|typeos.com, vibegrade.com|
|7|Merlin AI|`camppjleccjaphfdbohjdohecfnoikec`|8.3.1|100K-1M|60.3|no|no|declares collection|reads page, affiliate SDK (GiveFreely) on every site|-|
|8|NativeMind|`mgchaojnijgpemdfhpnbeejnppigfllj`|1.12.3|1K-10K|60.0|no|no|**says collects nothing**|page data near send (claims fully local; test the claim)|-|
|9|Gene|`padcpabfckdbahodkfkincpaaeinejik`|1.2.64|10K-100K|59.3|no|**yes**|declares collection|page data near send; every-frame page text to background|own Cloud Run backends|
|10|OG AI Sidebar|`ikijlojkgdhdjdmdfaikclceioppbaoh`|2.6.0|100-500|57.9|no|**yes**|declares collection|reads page, password/hidden fields|ogsolver.com|
|11|QuestionAI|`hajphibbdloomfdkeoejchiikjggnaif`|2.8.28|100K-1M|57.5|yes|no|declares collection|page data near send (full page HTML)|-|
|12|Zetoe|`mfcncdeeeekkjgonodmcjajafigpgnhh`|1.1.8|<100|54.8|no|no|**says collects nothing**|dumps page storage, sends site cookies, password/hidden fields|zetoe.com|
|13|Spekit|`nbphjjmibhopfgkkbpoggemjnihnchhk`|2026.400.42.44|10K-100K|53.8|yes|no|declares collection|reads page (Gmail via InboxSDK), password/hidden fields|seismic.com, segment, sentry|
|14|Scribbly AI|`emmdlhdabimooaadedpcdllojcfggkhg`|0.0.11|500-1K|52.3|no|no|declares collection|reads page, sends site cookies, session replay (rrweb)|scribbly.ai|
|15|Shizue|`mpcbgfkoholfgapcgcmfjobnfcbnfanm`|0.3.12|500-1K|50.4|no|no|declares collection|page data near send (full-page translation)|openai, anthropic, openrouter, googleapis|

**Confirmed by reading the code** (strongest leads, so pilot on these):
- **Zetoe:** with autofill on, the content script copies the site's entire `localStorage` and
  `sessionStorage`. The background then collects the site's cookies (`chrome.cookies.getAll`
  by URL and by domain) and POSTs `{pageUrl, cookies, localStorageDump, sessionStorageDump}` to
  its own `/playwright` API. Its store label says it collects nothing.
- **Devi:** `chrome.cookies.getAll({})` (every cookie in the browser), filtered for an `auth` cookie.
- **GoGPT** (#18, not in the 15, a good optional extra): a `webNavigation.onCommitted` listener on
  all sites sends the hex-encoded visited URL to offidocs.com and can redirect the tab.
- **Sider:** a third-party ad beacon (zeroclick.dev) inside the chat UI.

**Setup needs known so far:**
- Gene and OG AI Sidebar: Google sign-in.
- Spekit: possibly a work account.
- Scribbly: Gmail or Outlook.
- NativeMind: a local model (Ollama, or WebLLM in the browser).
- Several others: a free account or an API key.

**Version drift:** the store versions have moved past the scanned versions for Merlin (8.3.1 →
8.3.2), Shizue (0.3.12 → 0.3.17) and Spekit (numbering changed). Always test the **scanned copy**
loaded unpacked, never a store install, so static and dynamic results describe the same code.

---

## C. The honeypot site ("Pollen Bank")

Built by a teammate. Live at https://quillbert.github.io/honey/, source at https://github.com/Quillbert/honey
(one commit, static GitHub Pages site, no backend, no third-party scripts, so captures stay clean).
Everything is in `assets/app.js` plus static HTML pages.

### Pages and modes
| Path | What it does |
|---|---|
| `/honey/` | Landing page: choose a flow |
| `/honey/session/` → `profile/` → `results/` | **Session mode.** The login form (username, account number, `type=password` field) and the 19-field profile form save to `sessionStorage` under keys `pollenBankLoginData` / `pollenBankTestData`. Results page renders every value as visible text (`<dd id="<field>">`). |
| `/honey/url/` → `profile/` → `results/` | **URL mode.** Native GET forms: values travel in the query string. The profile page adds the login values (including the password) as **hidden inputs**, so they end up in the results URL. Results renders the query values as text. |
| `/honey/cookies/` | **Cookie mode.** The profile form plus "Set cookies" / "Clear cookies". Sets `pollen_test_<field>=<urlencoded value>` via `document.cookie` with `Path=/honey/cookies/; SameSite=Lax; Secure` (no HttpOnly; can't be set from JS). |
| `/honey/cookies/read/` | Loads with the cookies attached but never displays them. |

### Token values (identical in every mode)
```
name: Mira Holloway                 username: mira.holloway          account_number: 0048172396
email: mira.holloway@example.com    ssn: 900-12-3456                 dob: 1990-01-15
phone: +1-202-555-0147              street_address: 100 Example Street
city: Testville  state: ZZ  zip: 00000
openai_api_key: sk-proj-TEST000000000000000000000000000000000000000000
robinhood_api_key: rh-api-00000000-0000-4000-8000-000000000000
bitcoin_wallet_address: 1LExV4tbwUBEzzk1pCv4r7UhtZaGr9hGNp
bitcoin_wallet_key: L2ExPcddmtpQRugJFHzgFopACqiJeDzb55VwRUxBXdf44nb8eD71
cc_name: Mira Holloway  cc_number: 4111111111111111  cc_exp: 2030-12  cc_cvc: 123
login_password: Pollen!Test2048
```

### What works now vs what needs updating
| Context | Status |
|---|---|
| Session storage flow | **Works.** |
| URL / query-string flow, hidden inputs | **Works.** Requests to `quillbert.github.io` itself are expected; a leak is the URL or its values reaching *another* host. |
| Password field, visible text | **Works.** |
| Cookies | **Partial.** `chrome.cookies` users (Devi, Zetoe) will see them. Path-limited to `/honey/cookies/`, so `document.cookie` on other pages won't. No HttpOnly. |
| Telling modes apart | **Workaround:** values are identical across modes, so run one mode per capture with a fresh profile. |
| Generic values (`123`, `00000`, `ZZ`, `Testville`, `4111111111111111`, `1990-01-15`) | **Workaround:** the detector ignores them (false matches). Use only long, distinctive values. |
| Hidden DOM node, iframe, shadow DOM, `localStorage` | **Missing.** Planned study contexts; ask the honeypot author to add them. |

**Suggested honeypot changes** (later):
- Make values unique per mode and field (e.g. account number ending …96 / …97 / …98).
- Replace the generic values.
- Add a `display:none` node, a same-origin iframe, an open and a closed shadow root, and a `localStorage` copy.
- Also set a `Path=/` cookie.
- Optionally add a tiny backend that sets an HttpOnly cookie (only `chrome.cookies` can read that, which proves privileged access).

---

## D. The dynamic testing plan

### What mitmproxy does for us
mitmproxy sits between Chrome and the internet. Chrome sends all traffic to it (`127.0.0.1:8080`),
it decrypts HTTPS with its own certificate (trusted only by the test Chrome profile), records
everything and forwards it. For each request we see the URL and query, headers, cookies, body and
WebSocket messages: exactly what left the browser and where it went.
- Tools: `mitmweb` (live browser UI on :8081), `mitmdump` (headless, scriptable), `mitmproxy` (TUI).
- Addons (Python scripts) can inspect every request automatically.
- Sessions save to `.mitm` files and export to HAR.
- **It does not tell you which extension or script sent a request.** We get attribution from:
  - one extension per run, plus a no-extension control run
  - the `Origin: chrome-extension://<id>` header on background/service-worker requests (content-script
    requests look like the page's)
  - manual checks in the extension's service-worker DevTools (chrome://extensions → "service worker" → Network)
- It only sees what reaches the network: data read but kept local is invisible, which is the honest result.

### Tooling to build (and why)
Plain Chrome + mitmweb would work, but these make three people's runs identical, clean and comparable:

```
add_key.py ──> extension copy with its real store ID
                     │
run.sh ──> fresh Chrome profile + proxy + detector ──> tester follows the script
                                     │
                     detect_tokens.py (reads tokens.yaml) ──> hits.jsonl + flows.mitm/.har
                                     │
                          summarize.py ──> rows for the results table
```

| Piece | What it does | Why |
|---|---|---|
| `add_key.py` | Copies `work/unpacked/<id>` (scanned version) and writes the manifest `key` taken from the `.crx` header (CRX3 public key, base64). The unpacked extension then gets its real store ID. | 12 of 15 lack a `key`. A changed ID breaks `chrome.identity` sign-in (Gene, OG AI) and can fail backend origin allowlists. Verify: the computed ID must equal the ext_id. |
| `tokens.yaml` | Every honeypot value tagged `{field, mode(s), sensitivity, min-length OK?}` | Single source of truth for the detector; update it when the honeypot changes. |
| `detect_tokens.py` | mitmproxy addon: for every request and WebSocket message, search URL, headers, cookies and body (decompressed) for each token as raw, URL-encoded (both `%20`/`+`), base64 (standard and urlsafe, all 3 alignments), hex (upper/lower), JSON-escaped, and lowercased. Writes one JSONL line per hit: `run_id, ts, phase, method, host, url, location, token_field, encoding, origin_header, is_extension_origin, content_type, size`. Skips requests to the honeypot host itself unless the token appears in a *different* path's query. | Manual search misses encoded or compressed leaks (GoGPT hex-encodes URLs). Consistent for all testers. |
| `run.sh <ext_id> <mode> <tester>` | Creates `runs/<date>_<tester>_<ext>_<mode>/`, starts `mitmweb`/`mitmdump` with the addon writing `flows.mitm` and `hits.jsonl`, and launches Chrome with a fresh `--user-data-dir`, `--proxy-server=127.0.0.1:8080`, `--ignore-certificate-errors-spki-list=<mitm CA SPKI hash>`, `--disable-background-networking --disable-sync --no-first-run --disable-component-update`. Writes a `phase` marker file the addon reads (setup / baseline / passive / active / cookies). | Clean profiles stop tokens and cookies leaking from one run into the next; certificate trust is scoped to the test profile only (not the Mac keychain); identical settings for everyone. |
| `summarize.py` | Turns `hits.jsonl` plus `endpoints.csv` (static expected hosts and categories) into results rows | Comparable write-ups; flags new hosts the static scan didn't predict. |
| `README.md` | One-page tester instructions | Handoff to partners. |

**Chrome note:** recent branded Google Chrome builds no longer accept the `--load-extension`
launch flag. Either load by hand (chrome://extensions → Developer mode → Load unpacked) or use
**Chrome for Testing** (`npx @puppeteer/browsers install chrome@stable`), where the flag works.
Chrome for Testing is recommended: scriptable and separate from your normal browser.

**Phase marking:** the tester switches phase (e.g. `./phase passive`) so every hit is tagged with
when it happened. Hits during `setup` (logging in) don't count as leaks.

### Per-extension protocol (each tester, about 45 min per extension)
1. **Prep (5 min):** read the extension's Top-15 row: why it's flagged, what to plant, setup
   needed. Note the expected hosts from `endpoints.csv`.
2. **Start a run:** `./run.sh <ext_id> <mode> <tester>` → fresh profile + proxy + detector.
3. **Setup phase:** load the keyed extension copy; log in with a **throwaway account** if needed;
   finish any onboarding. Phase = `setup`.
4. **Baseline phase (2 min):** idle on a neutral page (e.g. example.com).
5. **Passive phase (~3 min):** walk through the honeypot flow for this mode, then sit on the
   results page **without touching the extension**. Leaks here are the strongest findings.
6. **Active phase (~1 min per feature, same script for everyone):** summarize the page, chat
   about the page, select text and use the right-click menu, autofill, translate, whichever exist.
   Note each feature's start time.
7. **Cookie step:** `/honey/cookies/` → Set cookies → `/honey/cookies/read/` → back to the flow pages.
8. **Stop:** save `flows.mitm`, export `flows.har`, keep `hits.jsonl`, write `notes.md`.
9. **Repeat per mode** (session, URL, cookie-focused), each with a fresh profile.
10. **Control run (once per tester or once for the team):** the same script with no extension,
    to learn Chrome's own background traffic.

### What to look at for each hit
- **What:** which field leaked (password, SSN, API key, card…) and from which mode or context.
- **Where:** the destination host and its category (developer's own / AI provider / tracker /
  unknown third party). Was it in the static `endpoints.csv`? A new host is a finding.
- **How:** in the URL, body, header, cookie or WebSocket message, and in what encoding.
- **When:** passive vs active; more than the feature needs? (e.g. a summarize request
  that also carries the password field or cookies).
- **Disclosed?** Does the store label cover that data type? (Labels are in `summary_v2.csv`:
  `privacy_status`, `declared_data_types`.)

### Where to record
- **Raw evidence:** a private shared folder (Drive or Box, **never a public repo**, since captures contain
  test-account tokens): `dynamic/<ext_id>/<run_id>/` holding `flows.mitm`, `flows.har`, `hits.jsonl`, `notes.md`, screenshots.
- **Results table:** a "Dynamic results" tab or shared sheet, one row per (extension × mode):
  `tester, date, ext_id, version tested, ID matched store?, account used, phases run, any leak (Y/N),
  fields leaked, destination hosts, host category, passive/active, predicted by static (Y/N/partial),
  disclosed by label (Y/N), notes`. These rows join to the static columns for the final report.

### Setup checklist
1. **Build tooling:**
   - [ ] `add_key.py`
   - [ ] `tokens.yaml`
   - [ ] `detect_tokens.py`
   - [ ] `run.sh` + phase helper
   - [ ] `summarize.py`
   - [ ] results template
   - [ ] `README.md`
2. **Self-test:**
   - [ ] `brew install mitmproxy`; run once to create `~/.mitmproxy/` certificates.
   - [ ] Pilot one full run on **Zetoe** or **Devi** (known expected leaks): the detector must catch them.
   - [ ] Do one control run.
   - [ ] Fix the README wherever it was unclear.
3. **Shared pieces:**
   - [ ] Private capture folder.
   - [ ] Shared results sheet.
   - [ ] Tester assignment (5 each).
   - [ ] Throwaway accounts (Google, Gmail/Outlook, per-extension sign-ups).
4. **Honeypot fixes (optional, later):** see section C.
5. **Hand off:** partners install mitmproxy → clone → `add_key.py` → `run.sh` per extension and mode → follow the README → upload run folders → fill in results rows.

---

## E. Other context and cautions

- **Static ≠ proof, dynamic ≠ complete.** Dynamic tests show what happened in *our* session with
  *our* clicks. Extensions may send data only under conditions we didn't trigger (specific sites,
  remote config flags, after N days, for logged-in paid users). Report "not observed", not "doesn't happen".
- **Disclosure comparison** is the analysis after dynamic testing. Store labels are already
  scraped; privacy-policy *text* was not fetched (only URLs).
- **Extensions talk to LLM providers by design.** Sending page text to OpenAI when the user
  clicks "summarize" is expected; the interesting cases are passive sends, sends to trackers or
  unknown third parties, sends of fields the feature doesn't need (password, cookies, storage),
  and contradictions with a "collects nothing" label.
- **Bring-your-own-key extensions** (user supplies an API key): any key leak to a non-provider
  host is serious. Use a fake key on the honeypot (already present) and a real low-limit key only when needed for functionality.
- **Ethics / safety:**
  - Throwaway accounts only, never personal ones.
  - Never put real personal data in the test profile.
  - Keep captures private.
  - Don't send traffic to extension backends beyond normal use (no fuzzing, no replaying captured tokens against their APIs).
  - All honeypot data is synthetic (SSN 900-xx is an invalid range; 4111… is a test card).
- **Hard-coded secrets** found statically (notes/hardcoded-secrets.md) are developer keys in
  public code. They weren't tested and must not be used.
- **Known static gaps to cite as limitations:**
  - Zetoe's storage dump goes through a wrapper function, so static couldn't link it to the send.
  - ZhiNang's 7.6 MB content script, FuseBase and others had library-tagging problems in v1 (fixed in v2).
  - The scan reads raw minified text, so line numbers in evidence point into very long lines.
- **Tier spread of the 15:** 1M+ ×5, 100K-1M ×2, 10K-100K ×2, 1K-10K ×3, 500-1K ×2,
  100-500 ×1, <100 ×1. Useful for "does popularity correlate with behaviour" in the report,
  but n=15 is too small for prevalence claims, and the sample is biased toward suspicious extensions by design.
