"""Lint the lab's written records: decision records (docs/decisions/), tool selection records
(docs/selections/) and the verdict log (docs/verdicts.yml). Like the inventory check, it collects
every problem, not just the first."""
from __future__ import annotations

import re
from datetime import date, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "github.com/DoctorMen/network-automation-lab"

DECISION_FIELDS = ("id", "title", "date", "status", "decider", "constraint", "alternatives", "sources", "stake")
STATUSES = {"proposed", "accepted", "superseded"}
VERDICT_FIELDS = ("id", "opened", "version", "symptom", "evidence")
VERDICTS = {"my-config", "normal-behaviour", "platform-bug", "lab-artifact"}
DAYS_TO_CLASSIFY = 5  # working days an odd behaviour may stay without a verdict


def lint(path: str | Path, today: date | None = None) -> list[str]:
    """A folder of decision records, one record (.md), or the verdict log (.yml)."""
    path = Path(path)
    if path.is_dir():
        records = sorted(path.glob("[0-9][0-9][0-9][0-9]-*.md"))
        problems = [] if records else [f"{path}: no decision records"]
        # A misnamed record (009-x.md) would otherwise be skipped without a word.
        problems += [f"{p.name}: not named NNNN-slug.md, so it is not linted" for p in sorted(path.glob("*.md"))
                     if p not in records and p.name != "README.md"]
        numbers = [r.name[:4] for r in records]
        problems += [f"{path}: {n} is used by more than one record" for n in sorted(set(numbers)) if numbers.count(n) > 1]
        return problems + [p for r in records for p in lint_decision(r)]
    if path.suffix == ".md":
        return lint_decision(path)
    return lint_verdicts(path, today or date.today())


def lint_decision(path: Path) -> list[str]:
    label = path.name
    parts = path.read_text().split("---\n", 2)
    meta = yaml.safe_load(parts[1]) if len(parts) == 3 and not parts[0] else None
    if not isinstance(meta, dict):
        return [f"{label}: no YAML front matter between --- lines"]
    body = parts[2]
    problems = [f"{label}: missing {f}" for f in DECISION_FIELDS if not meta.get(f)]

    # Unquoted, YAML reads 0001 as the number 1.
    if meta.get("id") and str(meta["id"]) != path.name[:4]:
        problems.append(f"{label}: id {meta['id']!r} does not match the file name (quote it: \"{path.name[:4]}\")")
    if meta.get("date") and not isinstance(meta["date"], date):
        problems.append(f"{label}: date {meta['date']!r} is not YYYY-MM-DD")
    if meta.get("status") and str(meta["status"]) not in STATUSES:
        problems.append(f"{label}: status {meta['status']!r} is not one of {sorted(STATUSES)}")

    alternatives = meta.get("alternatives") or []
    if len(alternatives) < 2:
        problems.append(f"{label}: needs at least two alternatives")
    for alt in alternatives:
        if not (isinstance(alt, dict) and alt.get("name") and alt.get("why_not")):
            problems.append(f"{label}: alternative {alt!r} needs a name and a why_not")
    if not any(isinstance(a, dict) and str(a.get("name", "")).lower() == "do nothing" for a in alternatives):
        problems.append(f"{label}: no 'do nothing' alternative")

    # A source the reader can check without trusting this repo: a standard or vendor doc.
    sources = [str(s) for s in meta.get("sources") or []]
    if sources and not any(re.match(r"https?://", s) and REPO_URL not in s for s in sources):
        problems.append(f"{label}: no outside source (every source points inside the repo)")

    for fm in meta.get("failure_modes") or []:
        missing = [k for k in ("mode", "mitigation", "test") if not (isinstance(fm, dict) and fm.get(k))]
        if missing:
            problems.append(f"{label}: failure mode {fm!r} is missing {', '.join(missing)}")
        elif str(fm["test"]).startswith("none"):
            # An untested mode is allowed only as a stated decision: "none (accepted risk ...)".
            if not re.match(r"none \(.+\)$", str(fm["test"])):
                problems.append(f"{label}: failure mode {fm['mode']!r} has no test; say why as none (reason)")
        elif not names_a_test(fm["test"]):
            problems.append(f"{label}: failure mode test {fm['test']} does not exist")

    for heading in ("Context", "Decision", "Consequences"):
        if not re.search(rf"^[#*\s]*{heading}\b", body, re.M):
            problems.append(f"{label}: body has no {heading} section")
    return problems


SELECTION_FIELDS = ("kind", "id", "title", "date", "status", "decider", "constraint", "choice", "alternatives",
                    "no_purchase", "staffing", "vendor_domains", "independent_sources", "uses")


def lint_selections(folder: str | Path) -> list[str]:
    """Tool selection records (docs/selections/, OROS JUS-3): each choice judged against its
    constraint, with a no-purchase line and at least one source the tool's own maker didn't write."""
    folder = Path(folder)
    records = sorted(folder.glob("*.md"))
    problems = [] if records else [f"{folder}: no selection records"]
    for path in records:
        label = path.name
        parts = path.read_text().split("---\n", 2)
        meta = yaml.safe_load(parts[1]) if len(parts) == 3 and not parts[0] else None
        if not isinstance(meta, dict):
            problems.append(f"{label}: no YAML front matter between --- lines")
            continue
        problems += [f"{label}: missing {f}" for f in SELECTION_FIELDS if not meta.get(f)]
        if meta.get("kind") and meta["kind"] != "selection":
            problems.append(f"{label}: kind {meta['kind']!r} is not selection")
        if meta.get("id") and meta["id"] != path.stem:
            problems.append(f"{label}: id {meta['id']!r} does not match the file name")
        if meta.get("date") and not isinstance(meta["date"], date):
            problems.append(f"{label}: date {meta['date']!r} is not YYYY-MM-DD")
        alternatives = meta.get("alternatives") or []
        if len(alternatives) < 2:
            problems.append(f"{label}: needs at least two alternatives")
        for alt in alternatives:
            if not (isinstance(alt, dict) and alt.get("name") and alt.get("why_not")):
                problems.append(f"{label}: alternative {alt!r} needs a name and a why_not")

        # Independent of the seller: an outside page not on the maker's own domains, or a test or data
        # file of our own (a benchmark we ran). At least one of ours, so no choice rests on reading alone.
        vendor = [str(d).lower() for d in meta.get("vendor_domains") or []]
        independent = ours = 0
        for source in meta.get("independent_sources") or []:
            ref = str(source).split()[0]
            if re.match(r"https?://", ref):
                if any(d in ref.lower() for d in vendor):
                    problems.append(f"{label}: {ref} is the seller's own site, not an independent source")
                else:
                    independent += 1
            elif names_a_test(ref) or ("::" not in ref and (ROOT / ref).is_file()):
                independent += 1
                ours += 1
            else:
                problems.append(f"{label}: source {ref} is neither a URL nor a test or file in this repo")
        if meta.get("independent_sources") and not independent:
            problems.append(f"{label}: no independent source")
        elif meta.get("independent_sources") and not ours:
            problems.append(f"{label}: no measurement of our own (a test or data file in this repo)")
        for heading in ("Context", "Decision", "Consequences"):
            if not re.search(rf"^[#*\s]*{heading}\b", parts[2], re.M):
                problems.append(f"{label}: body has no {heading} section")
    return problems


def names_a_test(ref: str) -> bool:
    """'tests/live/test_x.py::test_name' points at a test function that is really there."""
    file, _, name = ref.partition("::")
    target = ROOT / file
    return bool(name) and target.is_file() and f"def {name}(" in target.read_text()


def working_days(start: date, end: date) -> int:
    """Monday-to-Friday days after start, up to and including end."""
    return sum((start + timedelta(n)).weekday() < 5 for n in range(1, (end - start).days + 1))


def lint_verdicts(path: Path, today: date) -> list[str]:
    entries = yaml.safe_load(path.read_text()) or []
    if not isinstance(entries, list):
        return [f"{path.name}: expected a list of entries"]
    problems: list[str] = []
    seen: set[str] = set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            problems.append(f"{path.name}: entry #{i + 1} is not a mapping")
            continue
        name = e.get("id") or f"entry #{i + 1}"
        label = f"{path.name}: {name}"
        problems += [f"{label}: missing {f}" for f in VERDICT_FIELDS if not e.get(f)]
        if name in seen:
            problems.append(f"{label}: id is used more than once")
        seen.add(name)
        opened = e.get("opened")
        if opened and not isinstance(opened, date):
            problems.append(f"{label}: opened {opened!r} is not YYYY-MM-DD")
            opened = None  # can't count days, but keep checking the rest of the entry
        verdict = e.get("verdict")
        if not verdict:
            # Still being looked at: allowed, but only for a few working days.
            days = working_days(opened, today) if opened else 0
            if days > DAYS_TO_CLASSIFY:
                problems.append(f"{label}: unclassified for {days} working days (limit {DAYS_TO_CLASSIFY})")
            continue
        if str(verdict) not in VERDICTS:  # a list of two verdicts is not one verdict
            problems.append(f"{label}: unknown verdict {verdict!r}, expected one of {sorted(VERDICTS)}")
        if not (e.get("fixed_in") or e.get("workaround")):
            problems.append(f"{label}: neither fixed_in nor workaround")
    return problems
