"""Lint the outside-levers contact sheet (docs/outside-levers.yml, OROS REC-7): every lever names
who holds it, how to reach them and the evidence they need, all checked within the sheet's cycle."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml

SHEET = Path(__file__).resolve().parent.parent / "docs" / "outside-levers.yml"
FIELDS = ("threat", "lever", "holder", "contact", "evidence", "checked", "how")


def lint(path: str | Path = SHEET, today: date | None = None) -> list[str]:
    """Every problem in the sheet, not just the first."""
    today = today or date.today()
    doc = yaml.safe_load(Path(path).read_text()) or {}
    cycle = doc.get("cycle_days")
    problems = [] if isinstance(cycle, int) and cycle > 0 else [f"cycle_days {cycle!r} is not a number of days"]
    levers = doc.get("levers") or []
    if not levers:
        problems.append("no levers listed")
    for i, lever in enumerate(levers):
        label = lever.get("threat") or f"lever #{i + 1}"
        problems += [f"{label}: no {name}" for name in FIELDS if not lever.get(name)]
        evidence = lever.get("evidence")
        if evidence and not (isinstance(evidence, list) and all(str(e).strip() for e in evidence)):
            problems.append(f"{label}: evidence must be a list of what to bring")
        checked = lever.get("checked")
        if checked and not isinstance(checked, date):
            problems.append(f"{label}: checked {checked!r} is not YYYY-MM-DD")
        elif checked and checked > today:
            problems.append(f"{label}: checked {checked} is in the future")
        elif checked and isinstance(cycle, int) and (today - checked).days > cycle:
            problems.append(f"{label}: last checked {(today - checked).days} days ago, cycle is {cycle}")
    return problems
