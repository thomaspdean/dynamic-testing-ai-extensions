# dynamic-testing-ai-extensions

A dynamic testing harness for Chrome extensions. Drop in an extension's `.crx`, browse a honeypot
page full of fake sensitive data, and see which of those values the extension sends out of the
browser, where to, and how encoded.

It was built for a CS 6262 study of GenAI browser extensions, but works with any extension.
Python 3.10+, standard library only. Needs mitmproxy and Chrome for Testing.

## How it works

```mermaid
flowchart TD
    CRX["extensions/NAME.crx<br/>(any extension; for CS6262 the 15 scanned packages from Drive)"]
    H["honeypot site: Pollen Bank<br/>quillbert.github.io/honey/<br/>fake SSN, password, API keys…"]

    CRX -->|"1 · read the file<br/>ID, name, version, SHA-256,<br/>needs branded Chrome?"| INFO["dyn.py info NAME"]
    CRX -->|"2 · unpack with manifest key,<br/>re-check ID (automatic inside run)"| BUILD["build/extensions/ID/<br/>loads with its real store ID"]
    H -->|"3 · values taken from its source,<br/>re-checked live: dyn.py tokens --check"| TOK["data/tokens.json<br/>12 strong + 7 weak values,<br/>digit-only variants"]
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

## Usage so far

The harness is being built step by step, and this README becomes the full usage guide once `run`
exists. What works today:

```
python3 dyn.py info                      # what the harness reads from each .crx in extensions/
python3 dyn.py prepare zetoe --verify    # unpack with its real ID; prove it in Chrome (network blocked)
python3 dyn.py tokens --check            # the honeytokens; confirm they're still on the live honeypot
python3 -m unittest discover tests       # test suite
```

- `docs/WALKTHROUGH.md` explains each piece: what it does, why, and how it was checked.
- `CONTEXT.md` has the project background.
