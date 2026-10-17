"""Is every claimed control's latest test green, and inside the control's period? (OROS 0.3 ATT-4)

docs/controls.yml names, for every control, the tests that prove it and how often they must pass.
The proof is CI's dated JUnit files (pytest --junitxml): offline-results, review-results,
results-and-backups, observe-1-results to observe-3-results and drill-results, kept 90 days as run artifacts. This reads them
newest first, this run's own results included, and for each test takes its latest result that ran (a
skip is not a result). That result must be a pass, and younger than the period. Any other answer
fails, naming the control and test.

python -m netlab.control_status [--evidence build/evidence] [--repo OWNER/NAME] [--offline]
Without --offline it fetches older runs on main with the GitHub CLI (`gh`, needs actions: read).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import controls

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ("ci.yml", "drills.yml")  # the workflows that run the register's tests
ARTIFACTS = "*results*"               # offline-results, review-results, results-and-backups, observe-1-results to -3, drill-results
# `--branch main` matches a run's head branch, and a pull request from a fork whose own branch is called
# main has head branch main too. Only these events run main's own code in this repository.
MAIN_EVENTS = {"push", "schedule", "workflow_dispatch"}


@dataclass(frozen=True)
class Result:
    test: str        # pytest node id, tests/live/test_x.py::test_name
    when: datetime   # when its test suite started (the JUnit timestamp), UTC
    outcome: str     # passed, failed or skipped


def node_id(classname: str, name: str) -> str:
    """JUnit's classname 'tests.live.test_routing' and name 'test_x[a]' -> 'tests/live/test_routing.py::test_x'.
    Parameters are dropped: a control names the test function, and every case of it must pass."""
    return f"{classname.replace('.', '/')}.py::{name.split('[')[0]}"


def read_junit(path: Path) -> list[Result]:
    results = []
    for suite in ET.parse(path).getroot().iter("testsuite"):
        when = datetime.fromisoformat(suite.get("timestamp"))
        when = when if when.tzinfo else when.replace(tzinfo=timezone.utc)  # older pytest wrote local time; CI runs in UTC
        for case in suite.iter("testcase"):
            tags = {child.tag for child in case}
            outcome = "failed" if tags & {"failure", "error"} else "skipped" if "skipped" in tags else "passed"
            results.append(Result(node_id(case.get("classname", ""), case.get("name", "")), when.astimezone(timezone.utc), outcome))
    return results


def collect(evidence: Path) -> list[Result]:
    return [r for path in sorted(evidence.rglob("*.xml")) for r in read_junit(path)]


def latest(results: list[Result]) -> dict[str, Result]:
    """Each test's newest result that ran. When one run has several cases of a test, a failed one wins."""
    newest: dict[str, Result] = {}
    for r in results:
        if r.outcome == "skipped":
            continue
        old = newest.get(r.test)
        if old is None or r.when > old.when or (r.when == old.when and r.outcome == "failed"):
            newest[r.test] = r
    return newest


def period(control: dict) -> timedelta:
    return timedelta(days=int(re.fullmatch(r"P(\d+)D", str(control["period"]))[1]))


def check(register: list[dict], results: list[Result], now: datetime) -> tuple[list[str], list[str]]:
    """(one line per control and test, problems). No problems means ATT-4 holds for the whole register."""
    newest = latest(results)
    lines, problems = [], []
    for control in register:
        for test in controls.tests_of(control):
            r = newest.get(test)
            if r is None:
                problems.append(f"{control['id']}: {test} has no result in the evidence")
                continue
            age = now - r.when
            line = f"{control['id']}: {test} {r.outcome} {r.when:%Y-%m-%d %H:%M}Z, {age.days} days ago (period {control['period']})"
            lines.append(line)
            if r.outcome != "passed":
                problems.append(f"{control['id']}: {test} latest result {r.outcome} at {r.when:%Y-%m-%d %H:%M}Z")
            elif age > period(control):
                problems.append(f"{control['id']}: {test} last passed {age.days} days ago, longer than {control['period']}")
    return lines, problems


def gh(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=300)


def fetch(repo: str | None, evidence: Path, needed: set[str], since: datetime) -> None:
    """Download the JUnit artifacts of runs on main, newest first, until every needed test has a result
    that ran. Older runs can't change a test's latest result, so there's no need to read them all.
    A pull request's run is never read, even one from a branch named main. With no repo, gh takes it
    from the checkout's git remote."""
    where = ["--repo", repo] if repo else []
    runs = []
    for workflow in WORKFLOWS:
        listed = gh("run", "list", *where, "--workflow", workflow, "--branch", "main",
                    "--limit", "200", "--json", "databaseId,createdAt,event")
        if listed.returncode:
            raise RuntimeError(f"gh run list --workflow {workflow} failed: {listed.stderr.strip()}")
        runs += [run for run in json.loads(listed.stdout) if run.get("event") in MAIN_EVENTS]
    for run in sorted(runs, key=lambda r: r["createdAt"], reverse=True):
        if needed <= set(latest(collect(evidence))):
            return
        if datetime.fromisoformat(run["createdAt"].replace("Z", "+00:00")) < since:
            return
        target = evidence / str(run["databaseId"])
        if not target.exists():  # this run's own results are already here
            # No matching artifact (a run that failed before uploading, or expired) is not an error.
            gh("run", "download", str(run["databaseId"]), *where, "--dir", str(target), "--pattern", ARTIFACTS)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.control_status")
    p.add_argument("--evidence", default=ROOT / "build" / "evidence", type=Path, help="JUnit files, one folder per run")
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"), help="OWNER/NAME; set in CI, else gh reads the git remote")
    p.add_argument("--offline", action="store_true", help="only the files already in --evidence")
    args = p.parse_args(argv)
    register = controls.load()
    now = datetime.now(timezone.utc)
    args.evidence.mkdir(parents=True, exist_ok=True)
    if not args.offline:
        needed = {t for c in register for t in controls.tests_of(c)}
        fetch(args.repo, args.evidence, needed, since=now - max(period(c) for c in register))
    lines, problems = check(register, collect(args.evidence), now)
    print("\n".join(lines))
    if problems:
        print(f"\n{len(problems)} control test(s) not green within their period:\n  - " + "\n  - ".join(problems), file=sys.stderr)
        return 1
    distinct = len({t for c in register for t in controls.tests_of(c)})
    print(f"\nevery control in docs/controls.yml: latest test green and inside its period "
          f"({len(lines)} control-test pairs, {distinct} distinct tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
