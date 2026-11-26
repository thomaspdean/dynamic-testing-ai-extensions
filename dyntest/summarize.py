"""`dyn.py summarize`: turn run folders into four CSV tables in results/.

  results/extensions.csv  one row per extension: all its runs (modes) rolled up into the final
                          results-table row, plus blank columns for the manual analysis
  results/runs.csv    one row per run (extension x mode): what was tested, did anything leak, what,
                      where, in which phases, how encoded
  results/hits.csv    every token hit from every run (the evidence), with is_leak
  results/hosts.csv   every host each run contacted, and whether a control run also contacted it

Leak = a strong token reaching a non-honeypot host outside the setup/startup phases.
Control runs (`dyn.py run control`) show Chrome's own traffic; hosts they contacted are marked
in_control so they aren't blamed on an extension.
no_response lists hosts that never answered a request: the request was still recorded and searched.

Comparing these with static analysis or store labels is done outside the harness: join on
ext_id + crx_sha256.
"""
import csv
import json
from collections import defaultdict
from pathlib import Path

from . import REPO, tokens

RESULTS = REPO / "results"
NOT_COUNTED = {"setup", "startup"}


def is_leak(h: dict) -> bool:
    return h["strength"] == "strong" and not h["to_honeypot"] and h["phase"] not in NOT_COUNTED


def _jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass            # a line cut off by a crash; skip it
    return out


def load_runs(paths: list[Path]) -> list[dict]:
    """Every run folder under the given paths (a path may itself be a run folder)."""
    dirs = []
    for p in paths:
        p = Path(p)
        if (p / "meta.json").exists():
            dirs.append(p)
        elif p.is_dir():
            dirs += sorted(d for d in p.iterdir() if (d / "meta.json").exists())
    runs, seen = [], set()
    for d in dirs:
        meta = json.loads((d / "meta.json").read_text())
        if meta["run_id"] in seen:          # the same run reachable via two paths
            continue
        seen.add(meta["run_id"])
        runs.append({"dir": d, "meta": meta, "requests": _jsonl(d / "requests.jsonl"), "hits": _jsonl(d / "hits.jsonl")})
    return runs


def _yn(b) -> str:
    return "" if b is None else ("Y" if b else "N")


def _j(items) -> str:
    return "; ".join(sorted(set(items)))


def _minutes(meta) -> str:
    from datetime import datetime
    try:
        a, b = datetime.fromisoformat(meta["started"]), datetime.fromisoformat(meta["ended"])
        return f"{(b - a).total_seconds() / 60:.1f}"
    except (TypeError, ValueError, KeyError):
        return ""


RUN_FIELDS = [
    "run_id", "date", "mode", "control", "extension", "ext_id", "name", "version", "crx_sha256", "browser",
    "id_confirmed", "aborted", "phases", "minutes", "requests", "hosts", "hosts_not_in_control",
    "leak", "leak_fields", "leak_kinds", "leak_hosts", "leak_hosts_not_in_control", "leak_phases",
    "leak_in_passive", "leak_in_active", "leak_encodings", "leak_locations", "leak_from_extension_origin",
    "weak_cohits", "tls_failed", "no_response", "notes",
]
HIT_FIELDS = [
    "run_id", "extension", "mode", "request_id", "ts", "phase", "type", "method", "host", "url", "location",
    "field", "value_kind", "strength", "matched", "encoding", "count", "origin", "is_extension_origin",
    "content_type", "size", "to_honeypot", "host_in_control", "is_leak", "context",
]
HOST_FIELDS = [
    "run_id", "extension", "mode", "host", "requests", "phases", "first_phase", "from_extension_origin",
    "honeypot", "in_control", "no_response", "strong_hits", "leak_hits", "leak_fields",
]


MODES = ("session", "url", "cookies")
# leak columns by data kind; credentials are split into the password and API keys
KIND_COLUMNS = [("leak_identity", "identity"), ("leak_contact", "contact"), ("leak_address", "address"),
                ("leak_government_id", "government_id"), ("leak_financial", "financial"),
                ("leak_password", "password"), ("leak_api_keys", "api_key"), ("leak_crypto", "crypto")]
MANUAL_FIELDS = ["account_used", "features_tried", "passive_trigger", "active_sends_more_than_needed",
                 "host_category", "predicted_by_static", "store_label", "disclosed_by_label", "analyst_notes"]
EXT_FIELDS = [
    "extension", "name", "ext_id", "version", "crx_sha256", "browser", "id_confirmed",
    "modes_run", "modes_missing", "control_modes", "runs", "aborted_runs_skipped",
    *(f"{m}_leak" for m in MODES), *(c for c, _ in KIND_COLUMNS),
    "leak_fields", "n_strong_fields_leaked", "weak_cohits",
    "passive_leak", "active_leak", "leak_phases",
    "leak_hosts", "leak_hosts_not_in_control", "leak_from_extension_origin",
    "leak_hosts_no_response", "delivered",
    "leak_locations", "leak_encodings", "obfuscated",
    "hosts_not_in_control", "tls_failed", "notes", *MANUAL_FIELDS,
]


def _kind(h: dict) -> str:
    if h["value_kind"] != "credential":
        return h["value_kind"]
    return "api_key" if "api_key" in h["field"] else "password"


def _extension_rows(runs, control_hosts, have_control, n_strong) -> list[dict]:
    """Roll each extension's runs up into one row. Grouped by ext_id + crx_sha256 (a different
    file is a different row). Aborted runs are left out unless they're all there is."""
    control_modes = sorted({r["meta"]["mode"] for r in runs if r["meta"]["control"] and not r["meta"].get("aborted")})
    groups = defaultdict(list)
    for run in runs:
        ext = run["meta"].get("extension")
        if not run["meta"]["control"] and ext:
            groups[(ext.get("ext_id"), ext.get("crx_sha256"))].append(run)
    rows = []
    for _, group in sorted(groups.items(), key=lambda kv: kv[1][0]["meta"]["extension"].get("label", "")):
        done = [r for r in group if not r["meta"].get("aborted")]
        use = done or group
        ext = use[-1]["meta"]["extension"]
        hits = [dict(h, mode=r["meta"]["mode"]) for r in use for h in r["hits"]]
        reqs = [x for r in use for x in r["requests"]]
        leaks = [h for h in hits if is_leak(h)]
        weak = [h for h in hits if h["strength"] == "weak" and not h["to_honeypot"] and h["phase"] not in NOT_COUNTED]
        modes = {r["meta"]["mode"] for r in use}
        no_resp = {x["host"] for x in reqs if x.get("type") == "no_response"}
        lhosts = {h["host"] for h in leaks}
        origins = {h["is_extension_origin"] for h in leaks}
        ids = {r["meta"].get("id_confirmed") for r in use}
        hosts = {x["host"] for x in reqs if x.get("type") in ("http", "ws")}
        leaked_tokens = {h["field"] for h in leaks}
        row = {
            "extension": ext.get("label", ""), "name": ext.get("name", ""), "ext_id": ext.get("ext_id", ""),
            "version": ext.get("version", ""), "crx_sha256": ext.get("crx_sha256", ""),
            "browser": _j(f"{r['meta']['browser']['kind']} {r['meta']['browser']['version']}" for r in use),
            "id_confirmed": "Y" if ids == {True} else "N" if False in ids else "",
            "modes_run": "; ".join(m for m in MODES if m in modes) + "".join(f"; {m}" for m in sorted(modes - set(MODES))),
            "modes_missing": "; ".join(m for m in MODES if m not in modes),
            "control_modes": "; ".join(control_modes),
            "runs": "; ".join(r["meta"]["run_id"] for r in use),
            "aborted_runs_skipped": len(group) - len(use),
            **{f"{m}_leak": (_yn(any(h["mode"] == m for h in leaks)) if m in modes else "") for m in MODES},
            **{col: _yn(any(_kind(h) == kind for h in leaks)) for col, kind in KIND_COLUMNS},
            "leak_fields": _j(leaked_tokens), "n_strong_fields_leaked": f"{len(leaked_tokens)}/{n_strong}",
            "weak_cohits": _j(h["field"] for h in weak),
            "passive_leak": _yn(any(h["phase"] == "passive" for h in leaks)),
            "active_leak": _yn(any(h["phase"].startswith("active") for h in leaks)),
            "leak_phases": _j(h["phase"] for h in leaks),
            "leak_hosts": _j(lhosts),
            "leak_hosts_not_in_control": _j(lhosts - control_hosts) if have_control else "",
            "leak_from_extension_origin": ("" if not leaks else "Y" if origins == {True} else "N" if origins == {False}
                                           else "mixed"),
            "leak_hosts_no_response": _j(lhosts & no_resp),
            "delivered": ("" if not leaks else "N" if lhosts <= no_resp else
                          "Y" if not (lhosts & no_resp) else "partial"),
            "leak_locations": _j(h["location"] for h in leaks), "leak_encodings": _j(h["encoding"] for h in leaks),
            "obfuscated": ("" if not leaks else _yn(any("base64" in h["encoding"] or "hex" in h["encoding"]
                                                        or ">" in h["location"] for h in leaks))),
            "hosts_not_in_control": _j(hosts - control_hosts) if have_control else "",
            "tls_failed": _j(x["host"] for x in reqs if x.get("type") == "tls_failed"),
            "notes": "; ".join(f"{r['dir'].name}/notes.md" for r in use if (r["dir"] / "notes.md").exists()),
            **{f: "" for f in MANUAL_FIELDS},
        }
        rows.append(row)
    return rows


def summarize(paths: list[Path], out: Path = RESULTS) -> dict:
    runs = load_runs(paths)
    if not runs:
        return {"runs": [], "extensions": [], "hits": 0, "hosts": 0, "have_control": False, "out": out}
    control_hosts = {r["host"] for run in runs if run["meta"]["control"]
                     for r in run["requests"] if r.get("type") in ("http", "ws")}
    have_control = any(run["meta"]["control"] for run in runs)
    in_control = (lambda h: _yn(h in control_hosts)) if have_control else (lambda h: "")

    run_rows, hit_rows, host_rows = [], [], []
    for run in runs:
        m, reqs, hits = run["meta"], run["requests"], run["hits"]
        ext = m.get("extension") or {}
        label = "control" if m["control"] else ext.get("label", "")
        http = [r for r in reqs if r.get("type") in ("http", "ws")]
        hosts = {r["host"] for r in http}
        leaks = [h for h in hits if is_leak(h)]
        weak = [h for h in hits if h["strength"] == "weak" and not h["to_honeypot"] and h["phase"] not in NOT_COUNTED]
        lphases = {h["phase"] for h in leaks}
        origins = {h["is_extension_origin"] for h in leaks}
        notes = run["dir"] / "notes.md"
        run_rows.append({
            "run_id": m["run_id"], "date": (m.get("started") or "")[:10], "mode": m["mode"],
            "control": _yn(m["control"]), "extension": label, "ext_id": ext.get("ext_id", ""),
            "name": ext.get("name", ""), "version": ext.get("version", ""), "crx_sha256": ext.get("crx_sha256", ""),
            "browser": f"{m['browser']['kind']} {m['browser']['version']}",
            "id_confirmed": _yn(m.get("id_confirmed")), "aborted": _yn(m.get("aborted")),
            "phases": "; ".join(p for p in m.get("phases", []) if p != "finished"),
            "minutes": _minutes(m), "requests": len(http), "hosts": len(hosts),
            "hosts_not_in_control": (len(hosts - control_hosts) if have_control and not m["control"] else ""),
            "leak": _yn(bool(leaks)), "leak_fields": _j(h["field"] for h in leaks),
            "leak_kinds": _j(h["value_kind"] for h in leaks), "leak_hosts": _j(h["host"] for h in leaks),
            "leak_hosts_not_in_control": (_j(h["host"] for h in leaks if h["host"] not in control_hosts)
                                          if have_control else ""),
            "leak_phases": _j(lphases),
            "leak_in_passive": _yn(any(p == "passive" for p in lphases)),
            "leak_in_active": _yn(any(p.startswith("active") for p in lphases)),
            "leak_encodings": _j(h["encoding"] for h in leaks), "leak_locations": _j(h["location"] for h in leaks),
            "leak_from_extension_origin": ("" if not leaks else "Y" if origins == {True} else "N" if origins == {False}
                                           else "mixed"),
            "weak_cohits": _j(h["field"] for h in weak),
            "tls_failed": "; ".join(f"{r['host']} ({r.get('error', '')})" for r in reqs if r.get("type") == "tls_failed"),
            "no_response": _j(r["host"] for r in reqs if r.get("type") == "no_response"),
            "notes": str(notes) if notes.exists() else "",
        })
        for h in hits:
            hit_rows.append({**{k: h.get(k, "") for k in HIT_FIELDS}, "extension": label, "mode": m["mode"],
                             "host_in_control": in_control(h["host"]), "is_leak": _yn(is_leak(h))})
        per = defaultdict(lambda: {"requests": 0, "phases": [], "ext": 0, "honeypot": False})
        for r in http:
            p = per[r["host"]]
            p["requests"] += 1
            if r["phase"] not in p["phases"]:
                p["phases"].append(r["phase"])
            p["ext"] += bool(r.get("is_extension_origin"))
            p["honeypot"] |= bool(r.get("to_honeypot"))
        for host, p in sorted(per.items()):
            hh = [h for h in hits if h["host"] == host]
            host_rows.append({
                "run_id": m["run_id"], "extension": label, "mode": m["mode"], "host": host,
                "requests": p["requests"], "phases": "; ".join(p["phases"]), "first_phase": p["phases"][0],
                "from_extension_origin": p["ext"], "honeypot": _yn(p["honeypot"]), "in_control": in_control(host),
                "no_response": sum(r.get("type") == "no_response" and r["host"] == host for r in reqs),
                "strong_hits": sum(h["strength"] == "strong" for h in hh),
                "leak_hits": sum(is_leak(h) for h in hh), "leak_fields": _j(h["field"] for h in hh if is_leak(h)),
            })

    n_strong = sum(t["strength"] == "strong" for t in tokens.load()["tokens"])
    ext_rows = _extension_rows(runs, control_hosts, have_control, n_strong)
    out.mkdir(parents=True, exist_ok=True)
    for name, fields, rows in (("extensions.csv", EXT_FIELDS, ext_rows), ("runs.csv", RUN_FIELDS, run_rows), ("hits.csv", HIT_FIELDS, hit_rows),
                               ("hosts.csv", HOST_FIELDS, host_rows)):
        with open(out / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
    return {"runs": run_rows, "extensions": ext_rows, "hits": len(hit_rows), "hosts": len(host_rows), "have_control": have_control, "out": out}
