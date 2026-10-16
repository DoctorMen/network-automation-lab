"""Lint the runbooks (docs/runbooks/*.md) and the record of who has run them (dry-runs.yml).

A runbook nobody can trust is worse than none: it names a router that was renamed, or it was last
read two redesigns ago. So every runbook says who owns it, who coordinates, who updates
stakeholders, when it was last reviewed and which hosts it touches, and every host it names or runs
a command on must be in the inventory. Like the inventory check, it reports every problem at once.
(OROS 0.3 REC-6.)
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import yaml

FIELDS = ("owner", "coordinator", "comms", "last_reviewed", "hosts", "written_by")
REVIEW_DAYS = 180  # a runbook unread for half a year has probably missed a change
RESULTS = {"pass", "fail"}
# Where a runbook names a device it acts on: a lab container (clab-<lab>-r2), an Ansible --limit, or locate's SRC.
DEVICE_REFS = re.compile(r"\bclab-(?:<lab>|[a-z0-9]+)-([a-z][a-z0-9]*)\b|(?:--limit |SRC=)([a-z][a-z0-9]*)\b")


def read(path: Path) -> tuple[dict | None, str]:
    """(front matter, body). Front matter is YAML between --- lines at the top, as in docs/decisions/."""
    parts = path.read_text().split("---\n", 2)
    if len(parts) == 3 and not parts[0]:
        meta = yaml.safe_load(parts[1])
        return (meta if isinstance(meta, dict) else None), parts[2]
    return None, path.read_text()


def runbooks(folder: Path) -> list[Path]:
    return sorted(p for p in folder.glob("*.md") if p.name != "README.md")


def lint(folder: Path, devices: list[str], today: date | None = None) -> list[str]:
    today = today or date.today()
    problems: list[str] = []
    books = runbooks(folder)
    if not books:
        return [f"{folder}: no runbooks"]
    for path in books:
        label = path.name
        meta, body = read(path)
        if meta is None:
            problems.append(f"{label}: no YAML front matter between --- lines")
            continue
        problems += [f"{label}: no {f}" for f in FIELDS if not meta.get(f)]
        reviewed = meta.get("last_reviewed")
        if reviewed and not isinstance(reviewed, date):
            problems.append(f"{label}: last_reviewed {reviewed!r} is not YYYY-MM-DD")
        elif reviewed and reviewed > today:
            problems.append(f"{label}: last_reviewed {reviewed} is in the future")
        elif reviewed and (today - reviewed).days > REVIEW_DAYS:
            problems.append(f"{label}: last reviewed {reviewed}, {(today - reviewed).days} days ago (limit {REVIEW_DAYS})")
        hosts = meta.get("hosts") or []
        if not isinstance(hosts, list):
            problems.append(f"{label}: hosts must be a list")
            hosts = []
        problems += [f"{label}: host {h} is not in the inventory" for h in hosts if h not in devices]
        used = sorted({a or b for a, b in DEVICE_REFS.findall(body)})
        problems += [f"{label}: names {h}, which is not in the inventory" for h in used if h not in devices]
        problems += [f"{label}: acts on {h}, which hosts: doesn't list" for h in used if h in devices and h not in hosts]
        if not re.search(r"^## Who does what\b", body, re.M):
            problems.append(f"{label}: no '## Who does what' section")
    return problems + lint_runs(folder, today)


def lint_runs(folder: Path, today: date) -> list[str]:
    """dry-runs.yml: each run names a runbook that exists, a date, who ran it and the result."""
    path = folder / "dry-runs.yml"
    if not path.exists():
        return [f"{path.name}: missing (the record of who has run each runbook)"]
    runs = (yaml.safe_load(path.read_text()) or {}).get("runs") or []
    names = {p.stem for p in runbooks(folder)}
    problems = []
    for i, run in enumerate(runs, start=1):
        label = f"{path.name}: run #{i}"
        if not isinstance(run, dict):
            problems.append(f"{label} is not a mapping")
            continue
        problems += [f"{label}: no {f}" for f in ("date", "runbook", "by", "result") if not run.get(f)]
        if not isinstance(run.get("help_needed"), bool):
            problems.append(f"{label}: no help_needed (true or false)")
        if run.get("runbook") and run["runbook"] not in names:
            problems.append(f"{label}: no runbook called {run['runbook']}")
        if run.get("result") and run["result"] not in RESULTS:
            problems.append(f"{label}: result {run['result']!r} is not one of {sorted(RESULTS)}")
        if run.get("date") and not (isinstance(run["date"], date) and run["date"] <= today):
            problems.append(f"{label}: date {run['date']!r} is not a past YYYY-MM-DD")
    return problems
