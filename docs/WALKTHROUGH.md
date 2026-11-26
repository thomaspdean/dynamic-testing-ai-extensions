# Walkthrough

From a `.crx` file to a results table, step by step. Each step lists the command and what it does.
For how the pieces work inside, see [`DESIGN.md`](DESIGN.md).

**What you get:** for each extension, which fake sensitive values (name, SSN, password, API keys,
cookies…) it sent out of the browser, where to, when, and how encoded.

---

## 0. One-time install

| Need | Install |
|---|---|
| Python 3.10+ | already on most systems (`python3 --version`) |
| mitmproxy | macOS: `brew install --cask mitmproxy`; others: https://mitmproxy.org |
| Chrome for Testing | `npx @puppeteer/browsers install chrome@stable` |

No `pip install`: the harness is standard-library Python only.

---

## 1. Drop in the extensions

Copy the `.crx` files you want to test into `extensions/`, e.g. `extensions/zetoe.crx`.

```
python3 dyn.py info --brief
```
Reads each `.crx` and prints one line per file: the name to use, store ID, version, and which browser it needs (`info` without `--brief` also shows the SHA-256 and manifest details). Use it to check that every
file is readable, and to see which name to use in later commands.

---

## 2. Check the setup

```
python3 dyn.py doctor
```
Checks everything a run needs, and prints a fix for anything missing:

- mitmproxy is installed, and its certificate exists (it creates one if not);
- Chrome for Testing is found;
- a test Chrome actually trusts mitmproxy, using a local-only request;
- ports 8080/8081 are free;
- every `.crx` in `extensions/` is readable and new enough for your Chrome;
- the honeypot site is up and still has the expected values.

Repeat until it ends with `ready`.

---

## 3. One control run per mode (no extension)

```
python3 dyn.py run control --mode session
python3 dyn.py run control --mode url
python3 dyn.py run control --mode cookies
```
Each control run follows exactly the same steps as step 4, without any extension. This records
the traffic Chrome makes by itself, so it isn't blamed on an extension later. Do these once per
machine. Each one takes about 4 minutes.

---

## 4. Run each extension in all three modes

```
python3 dyn.py run <name> --mode session
python3 dyn.py run <name> --mode url
python3 dyn.py run <name> --mode cookies
```
`<name>` is the file name without `.crx` (e.g. `zetoe`), a path, or the store ID.

**Why three modes:** the honeypot puts the same fake values in a different place each time, and
the mode tells you where a leaked value came from.

| Mode | Where the values live | Catches extensions that… |
|---|---|---|
| `session` | the page's `sessionStorage`, a password field, and visible text | dump page storage, or scrape page text and forms |
| `url` | the page URL (the forms submit as GET, password included) | send or log the URLs you visit |
| `cookies` | the site's cookies | read cookies |

Run all three for every extension, even one without the `cookies` permission: "nothing sent" is a
result too.

**What `run` does when you start it:**

1. Unpacks the extension so it keeps its real store ID, and checks Chrome loaded it under that ID.
2. Starts mitmproxy with the detector, which searches every request as it passes. It prints a
   link to mitmproxy's live traffic view.
3. Opens a fresh Chrome profile that trusts mitmproxy (that profile only), with only this
   extension installed.
4. Walks you through the phases below in the terminal.

**The phases.** The terminal tells you when to do what:

| Phase | You do | How long |
|---|---|---|
| **setup** | Sign in to the extension with a **throwaway** account if it needs one, and finish onboarding. Close welcome tabs. Press Enter. Nothing here counts as a leak. | as long as needed |
| **baseline** | Nothing. Chrome sits on example.com. | 1 min |
| **passive** | Do the 2–3 clicks the terminal lists on the honeypot (don't edit the fields), press Enter, then **hands off**. Don't touch the extension; if it pops up by itself, leave it and note it. | clicks + 1 min |
| **active** | Type a feature name (`summarize`, `chat`, `select`, `autofill`, `translate`…), use that feature once on the honeypot page, wait 15–20 s, press Enter. Repeat for each feature, then type `done`. | ~1 min per feature |
| **notes** | Fill in the `notes.md` whose path it prints (account type, what each feature did, anything odd). Press Enter. | 1 min |

While it runs, each fake value seen going to a non-honeypot host prints a line, e.g.
`⚑ ssn → api.example.com (body, raw, passive)`. At the end it prints a summary and closes Chrome
and mitmproxy. **Ctrl-C** at any point stops the run and still saves what was captured.

**What a run leaves behind:** a folder `runs/<date>_<time>_<name>_<mode>/` with:

| File | What's in it |
|---|---|
| `hits.jsonl` | every fake value found: request, phase, where in the request, encoding |
| `requests.jsonl` | every request (hit or not); also requests whose server never answered (`no_response`) and connections that couldn't be decrypted (`tls_failed`) |
| `flows.har` / `flows.mitm` | the full capture (open the HAR in Chrome DevTools → Network → import) |
| `chrome.log` | every console message from the page and the extension |
| `meta.json`, `phases.jsonl`, `notes.md` | what was tested, phase times, your notes |
| `profile/` | the Chrome profile, which holds your throwaway login |

**Useful options:**
- `--baseline 120 --passive 180`: longer hands-off timers, for extensions that send on a slow timer.
- `--browser chrome`: use branded Chrome. This is chosen automatically for extensions that sign
  in with Google (`chrome.identity`), and the terminal then tells you how to load the extension by hand.
- `--discard-profile`: delete `profile/` after the run.

---

## 5. Build the results tables

```
python3 dyn.py summarize
python3 dyn.py summarize runs/ path/to/other/runs/      # also include runs from other machines
```
Reads every run folder and writes four CSVs to `results/` (overwritten each time). It prints one
line per run, and warns if an extension is still missing a mode.

| File | One row per | Use it for |
|---|---|---|
| `extensions.csv` | extension | **The final results table**: all its runs rolled into one row, plus blank columns for your own analysis |
| `runs.csv` | run | per-run detail |
| `hits.csv` | fake value found | the evidence: exact request, phase, encoding, surrounding bytes |
| `hosts.csv` | server contacted per run | every server the extension talked to, and whether Chrome alone (control) also did |

**A leak** is a distinctive fake value (not a generic one like `123` or `ZZ`) reaching any server
other than the honeypot, outside setup.

**`extensions.csv` columns:**

| Group | Columns |
|---|---|
| What was tested | extension, name, ext_id, version, crx_sha256, browser, id_confirmed |
| Coverage | modes_run, modes_missing, control_modes, runs, aborted_runs_skipped |
| Where the data came from | session_leak, url_leak, cookies_leak (blank if that mode wasn't run) |
| What was sent | leak_identity, leak_contact, leak_address, leak_government_id, leak_financial, leak_password, leak_api_keys, leak_crypto, leak_fields, n_strong_fields_leaked, weak_cohits |
| When | passive_leak (no user action: the strongest finding), active_leak, leak_phases |
| Where it went | leak_hosts, leak_hosts_not_in_control, leak_from_extension_origin, leak_hosts_no_response, delivered (Y / N / partial: did the receiving server answer?) |
| How | leak_locations, leak_encodings, obfuscated (base64 / hex / compressed) |
| Context | hosts_not_in_control, tls_failed, notes |
| **You fill in** | account_used, features_tried, passive_trigger, active_sends_more_than_needed, host_category, predicted_by_static, store_label, disclosed_by_label, analyst_notes |

---

## 6. Read the results

1. Open `results/extensions.csv` (or import it into a spreadsheet). Start with `passive_leak`,
   the three mode columns, and `leak_password` / `leak_api_keys`.
2. For any `Y`, filter `hits.csv` to that extension with `is_leak = Y`. The `context` column shows
   the bytes around each value, so you can see exactly what was sent.
3. Open the run's `flows.har` to see the full request.
4. `delivered = N` or `partial` means a server never answered. The extension *tried* to send
   the data, but it may not have arrived. Report it as "attempted".
5. Fill in the blank columns: what the store label claims, whether your static analysis predicted
   this, and what kind of host received the data.

**Keep in mind:** a run shows what happened in *your* session with *your* clicks. "No leak"
means "not observed", not "never happens".

---

## 7. Sharing results

- To combine several people's runs, collect their run folders in one place and run
  `python3 dyn.py summarize runs/ <their folders>`. Each run is counted once.
