"""Narrow silences (OROS DEC-4, decision 0020).

python -m netlab.silence           check monitoring/silences.yml, then add each current silence to Alertmanager
python -m netlab.silence --check   check only (tests/test_silence.py runs the same check in `make test`)

A silence covers one alert rule and the labels that pick out exactly one object it watches, or one node
for a maintenance window of at most MAINTENANCE_HOURS. Everything else that rule or node watches still
pages. Each silence ends (at most MAX_DAYS after it starts), says who set it, and gives its reason and a
reference that will still be there when an auditor or the next scan raises the finding again: a risk
(RISK-n), a decision (0012), a verdict (V-005) or a ticket's https URL. Matchers are equality only, so a
silence can't grow to cover a new object by matching a pattern.

Alertmanager keeps silences in its own state, which a redeploy starts empty, so `make deploy` runs this
again; the file is the record of every silence, expired ones included. A silence in Alertmanager that the
file doesn't hold (one added by hand with amtool or the web page) is reported, and `make silence` fails.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from .inventory import Inventory, load
from .observe import Noc, lab_name
from . import monitoring

ROOT = Path(__file__).resolve().parent.parent
SILENCES = ROOT / "monitoring" / "silences.yml"
MAX_DAYS = 7
MAINTENANCE_HOURS = 4
# Never silenced: the alert path's own heartbeat. Silencing it is the broken mail path it exists to catch.
NEVER = {"Watchdog", "CauseSeen"}


def when(value) -> datetime | None:
    """A YAML timestamp (parsed already) or an ISO 8601 string, as an aware UTC datetime."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=value.tzinfo or timezone.utc).astimezone(timezone.utc)


def known_refs(root: Path = ROOT) -> set[str]:
    """Every record id a silence may cite: risks, decisions and verdicts."""
    risks = {e["id"] for e in yaml.safe_load((root / "docs" / "risks.yml").read_text())}
    decisions = {p.name[:4] for p in (root / "docs" / "decisions").glob("[0-9][0-9][0-9][0-9]-*.md")}
    verdicts = {e["id"] for e in yaml.safe_load((root / "docs" / "verdicts.yml").read_text())}
    return risks | decisions | verdicts


def matchers(entry: dict) -> dict:
    """The labels Alertmanager matches, each one by equality."""
    if "maintenance" in entry:
        return {"node": str(entry["maintenance"])}
    return {"alertname": str(entry.get("alert")), **{k: str(v) for k, v in (entry.get("labels") or {}).items()}}


def key(entry: dict) -> str:
    """A short, stable name for the entry, written into the silence's comment so it is added only once."""
    return hashlib.sha256(repr(sorted(entry.items(), key=str)).encode()).hexdigest()[:10]


def problems(entry: dict, inv: Inventory, refs: set[str]) -> list[str]:
    name = f"silence {entry.get('alert') or 'maintenance ' + str(entry.get('maintenance'))} {entry.get('labels') or ''}".strip()
    out = []
    starts, ends = when(entry.get("starts")), when(entry.get("ends"))
    if not starts or not ends:
        out.append(f"{name}: starts and ends must both be ISO 8601 times")
    elif ends <= starts:
        out.append(f"{name}: ends before it starts")
    if "maintenance" in entry:
        if entry["maintenance"] not in inv.devices or entry.get("alert") or entry.get("labels"):
            out.append(f"{name}: a maintenance window names one device of the inventory, and nothing else")
        elif starts and ends and ends - starts > timedelta(hours=MAINTENANCE_HOURS):
            out.append(f"{name}: a maintenance window lasts at most {MAINTENANCE_HOURS} h")
    else:
        alert, labels = entry.get("alert"), entry.get("labels") or {}
        rules = [r for r in monitoring.alert_rules(inv) if r["alert"] == alert]
        hits = [r for r in rules if all(r["labels"].get(k) == str(v) for k, v in labels.items())]
        if alert in NEVER or not rules:
            out.append(f"{name}: {alert!r} is not an alert that pages, so there is nothing to silence")
        elif len(hits) != 1:
            out.append(f"{name}: picks out {len(hits)} of {alert}'s {len(rules)} objects; a silence covers exactly one "
                       f"(by labels such as {', '.join(sorted(set(rules[0]['labels']) - {'owner', 'role', 'deps'}))})")
    if starts and ends and ends - starts > timedelta(days=MAX_DAYS):
        out.append(f"{name}: lasts over {MAX_DAYS} days; set a shorter end and renew it if it still holds")
    if len(str(entry.get("reason") or "").split()) < 5:
        out.append(f"{name}: needs a reason, a sentence an auditor can read")
    ref = str(entry.get("ref") or "")
    if not (ref in refs or re.fullmatch(r"https://\S+", ref)):
        out.append(f"{name}: ref {ref!r} is not a risk, decision or verdict id, nor an https URL")
    if not entry.get("by"):
        out.append(f"{name}: needs `by`, who set it")
    return out


def check(entries: list[dict], inv: Inventory, refs: set[str]) -> list[str]:
    return [p for e in entries for p in problems(e, inv, refs)]


OPS = {(True, False): "=", (True, True): "=~", (False, False): "!=", (False, True): "!~"}
FROM_FILE = re.compile(r"\(monitoring/silences\.yml #([0-9a-f]{10})\)$")


def in_place(noc) -> dict[str | None, list[dict]]:
    """Alertmanager's active and pending silences by the file key in their comment (None: no key)."""
    out: dict[str | None, list[dict]] = {}
    for s in noc.silences():
        if s["status"]["state"] in ("active", "pending"):
            m = FROM_FILE.search(s.get("comment") or "")
            out.setdefault(m.group(1) if m else None, []).append(s)
    return out


def apply(entries: list[dict], noc, now: datetime | None = None) -> list[tuple[dict, str]]:
    """Add each silence that hasn't ended to Alertmanager, unless it is there already (by its key).
    [(entry, silence id)] for each one now in place."""
    now, out = now or datetime.now(timezone.utc), []
    present = {k: found[0]["id"] for k, found in in_place(noc).items() if k}
    for e in entries:
        if when(e["ends"]) <= now:
            continue  # kept in the file as the record; Alertmanager has nothing to do
        k = key(e)
        if k not in present:
            present[k] = noc.add_silence(matchers(e), when(e["starts"]).isoformat(), when(e["ends"]).isoformat(),
                                         str(e["by"]), f"{e['reason']} [{e['ref']}] (monitoring/silences.yml #{k})")
        out.append((e, present[k]))
    return out


def strays(entries: list[dict], noc) -> list[dict]:
    """Active or pending silences the file doesn't hold: added by hand, or left after their entry was removed."""
    keys = {key(e) for e in entries}
    return [s for k, found in in_place(noc).items() if k not in keys for s in found]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.silence")
    p.add_argument("--check", action="store_true", help="check the file only")
    p.add_argument("--file", default=str(SILENCES))
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    inv = load(args.inventory)
    entries = (yaml.safe_load(Path(args.file).read_text()) or {}).get("silences") or []
    found = check(entries, inv, known_refs())
    for problem in found:
        print(problem, file=sys.stderr)
    if found or args.check:
        print(f"{len(entries)} silences, " + (f"{len(found)} problems" if found else "each narrow, time-boxed and justified"))
        return 1 if found else 0
    noc = Noc(lab_name(), monitoring.host(inv))
    for e, sid in apply(entries, noc):
        print(f"{sid}  {matchers(e)}  until {when(e['ends']).isoformat()}  ({e['ref']}, {e['by']})")
    loose = strays(entries, noc)
    for s in loose:
        what = " ".join(m["name"] + OPS[m.get("isEqual", True), m["isRegex"]] + repr(m["value"]) for m in s["matchers"])
        print(f"{s['id']}  {what}  until {s['endsAt']}  by {s.get('createdBy')!r}: not in monitoring/silences.yml; "
              "add it there with its reason and record, or expire it", file=sys.stderr)
    print(f"{len(entries)} silences in the file, {len(loose)} in Alertmanager that it doesn't hold")
    return 1 if loose else 0


if __name__ == "__main__":
    sys.exit(main())
