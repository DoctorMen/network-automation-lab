"""The verdict log: every odd behaviour ends with one verdict class and a fix or a workaround."""
from datetime import date
from pathlib import Path

import yaml

from netlab.records import lint

VERDICTS = Path(__file__).resolve().parent.parent / "docs" / "verdicts.yml"
ENTRY = {"id": "V-100", "opened": date(2026, 10, 12), "version": "frrouting/frr:v8.4.1",
         "symptom": "something odd", "verdict": "my-config", "evidence": ["seen in the lab"],
         "fixed_in": "abc1234"}


def log_with(tmp_path, **changes):
    """A one-entry log; a change of None removes that field."""
    entry = {k: v for k, v in {**ENTRY, **changes}.items() if v is not None}
    path = tmp_path / "verdicts.yml"
    path.write_text(yaml.safe_dump([entry]))
    return path


def test_verdict_log_lints_clean():
    """docs/verdicts.yml: every entry has a known verdict, a version, evidence and a fix or workaround."""
    assert lint(VERDICTS) == []


def test_entry_without_fix_or_workaround_fails(tmp_path):
    assert lint(log_with(tmp_path, fixed_in=None)) == ["verdicts.yml: V-100: neither fixed_in nor workaround"]


def test_unknown_verdict_class_fails(tmp_path):
    problems = lint(log_with(tmp_path, verdict="probably-fine"))
    assert any("unknown verdict 'probably-fine'" in p for p in problems)
    # Two classes are not one verdict, and must be reported rather than crash the lint.
    problems = lint(log_with(tmp_path, verdict=["my-config", "platform-bug"]))
    assert any("unknown verdict ['my-config', 'platform-bug']" in p for p in problems)


def test_unclassified_entry_gets_five_working_days(tmp_path):
    """Opened Monday 2026-10-12: still open on Monday 10-19 is fine, on Tuesday 10-20 it is reported."""
    path = log_with(tmp_path, verdict=None, fixed_in=None)
    assert lint(path, today=date(2026, 10, 19)) == []
    assert lint(path, today=date(2026, 10, 20)) == ["verdicts.yml: V-100: unclassified for 6 working days (limit 5)"]
