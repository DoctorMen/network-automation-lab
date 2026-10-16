"""Runbooks name who does what, have a recent review date, and act only on hosts in the inventory."""
import shutil
from datetime import timedelta
from pathlib import Path

import pytest

from netlab import runbooks
from netlab.inventory import load

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT / "docs" / "runbooks"
DEVICES = load(ROOT / "inventory" / "network.yml").devices
# The newest review date in the shipped runbooks, so bumping a last_reviewed (every 180 days) never
# turns these tests into "in the future" failures.
REVIEWED = {p.name: runbooks.read(p)[0]["last_reviewed"] for p in runbooks.runbooks(FOLDER)}
TODAY = max(REVIEWED.values())


def folder_with(tmp_path, name, old, new):
    """A copy of the real runbooks with one change to one of them, so each test breaks one thing."""
    copy = tmp_path / "runbooks"
    shutil.copytree(FOLDER, copy)
    path = copy / f"{name}.md"
    text = path.read_text()
    assert old in text, old
    path.write_text(text.replace(old, new, 1))
    return copy


@pytest.mark.review
def test_runbooks_lint_clean():
    """Every shipped runbook has all its front matter, a review date under 180 days old and only inventory hosts."""
    assert runbooks.lint(FOLDER, DEVICES) == []


def test_top_incident_dr_and_power_event_types_have_runbooks():
    """The top incident types, restoring from backup (DR) and the power event each have a runbook (OROS REC-6)."""
    names = {p.stem for p in runbooks.runbooks(FOLDER)}
    assert {"link-failure", "bgp-down", "config-drift", "restore-from-backup", "power-event"} <= names


def test_unknown_host_is_reported(tmp_path):
    """A runbook that acts on r9, which the inventory doesn't have, fails the check, front matter or body."""
    bad = folder_with(tmp_path, "bgp-down", "hosts: [r1, r2, h1, isp]", "hosts: [r1, r2, h1, isp, r9]")
    assert runbooks.lint(bad, DEVICES, TODAY) == ["bgp-down.md: host r9 is not in the inventory"]
    bad = folder_with(tmp_path / "body", "bgp-down", "docker exec clab-<lab>-r2 ip -s link", "docker exec clab-<lab>-r9 ip -s link")
    assert runbooks.lint(bad, DEVICES, TODAY) == ["bgp-down.md: names r9, which is not in the inventory"]


def test_missing_or_stale_review_date_is_reported(tmp_path):
    """A runbook without last_reviewed, or reviewed more than 180 days ago, is named."""
    no_date = folder_with(tmp_path, "power-event", f"last_reviewed: {REVIEWED['power-event.md']}\n", "")
    assert runbooks.lint(no_date, DEVICES, TODAY) == ["power-event.md: no last_reviewed"]
    later = TODAY + timedelta(days=runbooks.REVIEW_DAYS + 1)  # every runbook is now too old
    assert runbooks.lint(FOLDER, DEVICES, later) == [
        f"{name}: last reviewed {d}, {(later - d).days} days ago (limit {runbooks.REVIEW_DAYS})" for name, d in REVIEWED.items()]


def test_every_problem_is_reported_at_once(tmp_path):
    """Two problems in one runbook and one in another: all three are reported."""
    bad = folder_with(tmp_path, "link-failure", "coordinator: NOC shift lead\n", "")
    path = bad / "link-failure.md"
    path.write_text(path.read_text().replace("hosts: [r1, r2, r3, fw1, h1]", "hosts: [r1, r2, r3, fw1, h1, sw9]"))
    path = bad / "bgp-down.md"
    path.write_text(path.read_text().replace("## Who does what", "## Roles"))
    assert sorted(runbooks.lint(bad, DEVICES, TODAY)) == [
        "bgp-down.md: no '## Who does what' section",
        "link-failure.md: host sw9 is not in the inventory",
        "link-failure.md: no coordinator",
    ]


def test_hosts_list_covers_every_device_acted_on(tmp_path):
    """A command on fw1 in a runbook whose hosts: doesn't list fw1 is reported, so the host list can be trusted."""
    bad = folder_with(tmp_path, "bgp-down", "docker exec clab-<lab>-h1 ping -c 3 203.0.113.1` works",
                      "docker exec clab-<lab>-fw1 iptables -vnL` works")
    assert runbooks.lint(bad, DEVICES, TODAY) == ["bgp-down.md: acts on fw1, which hosts: doesn't list"]


def test_dry_run_record_is_checked(tmp_path):
    """Each recorded run names a runbook that exists and a result of pass or fail."""
    copy = tmp_path / "runbooks"
    shutil.copytree(FOLDER, copy)
    (copy / "dry-runs.yml").write_text(
        "runs:\n"
        "  - {date: 2026-10-14, runbook: link-failure, by: DoctorMen, help_needed: false, result: pass}\n"
        "  - {date: 2026-10-14, runbook: bgp-down, by: DoctorMen, help_needed: true, result: pass}\n"
        "  - {date: 2026-10-14, runbook: power-event, by: Claude (AI assistant), help_needed: false, result: pass}\n"
        "  - {date: 2026-10-14, runbook: rip-down, by: DoctorMen, help_needed: false, result: maybe}\n")
    assert runbooks.lint(copy, DEVICES, TODAY) == [
        "dry-runs.yml: run #4: no runbook called rip-down",
        "dry-runs.yml: run #4: result 'maybe' is not one of ['fail', 'pass']",
    ]
