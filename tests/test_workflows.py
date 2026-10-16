"""The CI workflows' wiring: which job waits for which, so a review that falls due never stops the lab job;
that a backup saved to the cache is checked there; and that nothing the secret scan flags is published."""
import os
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


def steps_of(workflow: str):
    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())["jobs"]
    return [step for job in jobs.values() for step in job["steps"]]


def test_every_cache_save_is_looked_up_afterwards():
    """actions/cache/save only warns when its upload fails, so each save is followed by an exact lookup of its key that fails on a miss; the key names the attempt, since keys can't be overwritten and a re-run keeps its run id."""
    saves = 0
    for workflow in ("ci.yml", "drills.yml"):
        steps = steps_of(workflow)
        for i, step in enumerate(steps):
            if not step.get("uses", "").startswith("actions/cache/save@"):
                continue
            saves += 1
            key = step["with"]["key"]
            assert "github.run_attempt" in key, f"{workflow}: {key} is the same on a re-run, which can't save"
            check = steps[i + 1]
            assert check.get("uses", "").startswith("actions/cache/restore@"), f"{workflow}: nothing checks that {key} reached the cache"
            assert check["with"] == {**check["with"], "key": key, "lookup-only": True, "fail-on-cache-miss": True}
            assert "restore-keys" not in check["with"], "a prefix match would find an older repository"
    assert saves == 2


def scan_step(tmp_path, *fake_tools):
    """Run the lab job's secret scan step, under the shell flags GitHub uses, in a folder holding this
    run's password in its own file. `make` (so gitleaks) is a no-op here; fake_tools are (name, script)."""
    step = next(s for s in JOBS["lab"]["steps"] if s.get("id") == "secret-scan")
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    for name, script in (("make", "exit 0"), *fake_tools):
        (bindir / name).write_text(f"#!/bin/sh\n{script}\n")
        (bindir / name).chmod(0o755)
    store = tmp_path / "secrets"
    store.mkdir()
    (store / "bgp-r2-isp").write_text("0123456789abcdef0123456789abcdef\n")
    work = tmp_path / "work"
    for folder in ("results", "build"):
        (work / folder).mkdir(parents=True)
        (work / folder / "a.txt").write_text("nothing to see\n")
    env = {**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}", "NETLAB_SECRETS": str(store)}
    return work, lambda: subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                                        cwd=work, env=env, capture_output=True, text=True).returncode


def test_password_grep_passes_only_when_grep_found_nothing(tmp_path):
    """No match passes; a match fails although backups/ was never written; a grep error fails, even one that also matched."""
    work, run = scan_step(tmp_path / "clean")
    assert run() == 0
    (work / "results" / "live.xml").write_text("<failure>password 0123456789abcdef0123456789abcdef</failure>")
    assert run() == 1, "the password in results/ passed because backups/ is missing (grep exit 2)"
    _, run = scan_step(tmp_path / "error", ("grep", "echo backups/r2.conf; exit 2"))
    assert run() == 1, "grep matched and also hit a read error (exit 2), and the step passed"


def test_uploads_wait_for_the_secret_scan_and_the_measurement():
    """Results, backups and the finding bundle are published only when the secret scan didn't fail, and sizing data only after this run measured."""
    steps = JOBS["lab"]["steps"]
    scan = next(i for i, s in enumerate(steps) if s.get("id") == "secret-scan")
    uploads = [(i, s) for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/upload-artifact@")]
    scanned = [(i, s) for i, s in uploads if re.search(r"\b(results|backups)/", s["with"]["path"])]
    assert len(scanned) == 2
    for i, s in scanned:
        assert i > scan and "steps.secret-scan.outcome != 'failure'" in s["if"], f"{s['name']} is published after a failed secret scan"
    sizing = next(s for _, s in uploads if "docs/sizing" in s["with"]["path"])
    assert any(s.get("id") == "measure" for s in steps) and "steps.measure.outcome == 'success'" in sizing["if"], \
        "a skipped measurement would upload the committed reading as this run's"
