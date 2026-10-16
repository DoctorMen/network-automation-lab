"""The CI workflow's wiring: which job waits for which, so a review that falls due never stops the lab job."""
import re
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path

import yaml

from netlab import control_status

ROOT = Path(__file__).resolve().parent.parent
JOBS = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]
# The tests that compare a record's date with today, so they go red on a date with no commit at all.
DATED = {
    "tests/test_verdicts.py::test_verdict_log_lints_clean",
    "tests/test_levers.py::test_contact_sheet_lints_clean",
    "tests/test_risks.py::test_every_risky_config_line_has_a_risk_record",
    "tests/test_runbooks.py::test_runbooks_lint_clean",
}


def waits_for(job: str) -> set[str]:
    """Every job this one waits for, directly or through another job's needs."""
    direct = JOBS[job].get("needs") or []
    direct = [direct] if isinstance(direct, str) else direct
    return set(direct).union(*(waits_for(j) for j in direct))


def commands(job: str) -> str:
    return "\n".join(step.get("run", "") for step in JOBS[job]["steps"])


def test_review_dates_never_hold_up_the_lab():
    """The dated tests carry the review marker, `make test` leaves them out, and only the review job runs them: the lab job never waits for it, and control-status reads its results."""
    out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", "review", "tests", "--ignore=tests/live"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    assert {line for line in out.splitlines() if "::" in line} == DATED
    test_recipe = re.search(r"^test:.*\n\t(.*)", (ROOT / "Makefile").read_text(), re.M)[1]
    assert '-m "not review"' in test_recipe, "make test runs the dated reviews, so a due review would stop the lab job"
    assert [job for job in JOBS if "make review" in commands(job)] == ["review"]
    assert "review" not in waits_for("lab"), "the lab job waits for the review job, so a due review skips the live tests and the backup"
    assert all("make test" in commands(job) for job in waits_for("lab"))
    assert "review" in waits_for("control-status")
    uploads = [step["with"]["name"] for step in JOBS["review"]["steps"] if step.get("uses", "").startswith("actions/upload-artifact")]
    assert [name for name in uploads if fnmatch(name, control_status.ARTIFACTS)] == ["review-results"]
