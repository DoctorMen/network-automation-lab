"""Lint the control register: every claimed control names its test, how often that test must pass,
what the control defends against and how it fails."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REGISTER = Path(__file__).resolve().parent.parent / "docs" / "controls.yml"
FIELDS = ("id", "claim", "test", "period", "threat", "fails_when")


def load(path: str | Path = REGISTER) -> list[dict]:
    return yaml.safe_load(Path(path).read_text())["controls"]


def tests_of(control: dict) -> list[str]:
    """`test` is one pytest node id, or a list of them when one claim needs several tests."""
    test = control.get("test") or []
    return [test] if isinstance(test, str) else list(test)


def lint(controls: list[dict], known_tests: set[str]) -> list[str]:
    """Every problem in the register, not just the first. known_tests: pytest node ids that exist."""
    problems: list[str] = []
    seen: set[str] = set()
    for i, control in enumerate(controls):
        label = control.get("id") or f"control #{i + 1}"
        if label in seen:
            problems.append(f"{label}: duplicate id")
        seen.add(label)
        for name in FIELDS:
            if not str(control.get(name) or "").strip():
                problems.append(f"{label}: no {name}")
        # ISO 8601 duration in days, e.g. P31D: the latest green run must be younger than this.
        if control.get("period") and not re.fullmatch(r"P\d+D", str(control["period"])):
            problems.append(f"{label}: period {control['period']!r} is not a day count like P31D")
        for test in tests_of(control):
            if test not in known_tests:
                problems.append(f"{label}: unknown test {test}")
    return problems
