"""The control-status check (ATT-4) fails on a control whose latest test is red, stale or missing, read from JUnit files."""
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone

from netlab import control_status

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
OSPF = "tests/live/test_routing.py::test_ospf_adjacencies_are_full"
DRILL = "tests/live/test_restore.py::test_every_router_restores_cleanly"
REGISTER = [
    {"id": "ospf-adjacencies", "test": OSPF, "period": "P31D"},
    {"id": "restore-drill", "test": [DRILL], "period": "P90D"},
]


def junit(path, when, cases):
    """A JUnit file as pytest writes it. cases: {node id: 'passed' | 'failed' | 'skipped'}."""
    body = ""
    for test, outcome in cases.items():
        module, name = test.split("::")
        child = {"failed": "<failure message='x'/>", "skipped": "<skipped message='x'/>"}.get(outcome, "")
        body += f'<testcase classname="{module[:-3].replace("/", ".")}" name="{name}" time="1">{child}</testcase>'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'<?xml version="1.0"?><testsuites><testsuite name="pytest" timestamp="{when.isoformat()}">'
                    f"{body}</testsuite></testsuites>")


def status(tmp_path):
    return control_status.check(REGISTER, control_status.collect(tmp_path), NOW)[1]


def test_junit_names_become_node_ids():
    assert control_status.node_id("tests.live.test_routing", "test_ospf_adjacencies_are_full") == OSPF
    assert control_status.node_id("tests.test_inventory", "test_case[r1]") == "tests/test_inventory.py::test_case"


def test_green_and_fresh_passes(tmp_path):
    junit(tmp_path / "2" / "live.xml", NOW - timedelta(days=1), {OSPF: "passed", DRILL: "skipped"})
    junit(tmp_path / "1" / "drill.xml", NOW - timedelta(days=60), {DRILL: "passed"})
    assert status(tmp_path) == []


def test_latest_green_older_than_its_period_fails(tmp_path):
    junit(tmp_path / "1" / "live.xml", NOW - timedelta(days=32), {OSPF: "passed", DRILL: "passed"})
    assert status(tmp_path) == [f"ospf-adjacencies: {OSPF} last passed 32 days ago, longer than P31D"]


def test_latest_red_fails_even_with_an_older_green(tmp_path):
    """The Pass line asks for the latest test to be green, not for some green inside the period."""
    junit(tmp_path / "1" / "live.xml", NOW - timedelta(days=3), {OSPF: "passed", DRILL: "passed"})
    junit(tmp_path / "2" / "live.xml", NOW - timedelta(days=1), {OSPF: "failed"})
    assert status(tmp_path) == [f"ospf-adjacencies: {OSPF} latest result failed at 2026-10-14 12:00Z"]


def test_skips_are_not_evidence(tmp_path):
    """A test skipped in every run (the drill outside its own job) has no result, so it fails."""
    junit(tmp_path / "1" / "live.xml", NOW - timedelta(days=1), {OSPF: "passed", DRILL: "skipped"})
    assert status(tmp_path) == [f"restore-drill: {DRILL} has no result in the evidence"]


def fake_gh(tmp_path, runs, monkeypatch):
    """A `gh` on PATH that lists `runs` ({id: (created, {test: outcome})}) for ci.yml and 'downloads'
    each run's JUnit file. It logs every call, so a test can see which runs were fetched."""
    artifacts = tmp_path / "artifacts"
    for rid, (when, cases) in runs.items():
        junit(artifacts / rid / "results-and-backups" / "live.xml", when, cases)
    listing = [{"databaseId": int(rid), "createdAt": when.isoformat().replace("+00:00", "Z")} for rid, (when, _) in runs.items()]
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "gh"
    script.write_text(f"""#!{sys.executable}
import json, shutil, sys
args = sys.argv[1:]
with open({str(tmp_path / "calls.log")!r}, "a") as log:
    log.write(" ".join(args[:3]) + "\\n")
if args[:2] == ["run", "list"]:
    print(json.dumps({listing!r} if args[args.index("--workflow") + 1] == "ci.yml" else []))
elif args[:2] == ["run", "download"]:
    shutil.copytree({str(artifacts)!r} + "/" + args[2], args[args.index("--dir") + 1])
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


def test_fetch_reads_newest_runs_first_and_stops_when_every_test_has_a_result(tmp_path, monkeypatch):
    """Runs 3 and 2 cover both tests; run 1 is older and is never downloaded."""
    fake_gh(tmp_path, {
        "3": (NOW - timedelta(days=1), {OSPF: "passed", DRILL: "skipped"}),
        "2": (NOW - timedelta(days=5), {DRILL: "passed"}),
        "1": (NOW - timedelta(days=9), {OSPF: "failed", DRILL: "failed"}),
    }, monkeypatch)
    evidence = tmp_path / "evidence"
    control_status.fetch("o/r", evidence, {OSPF, DRILL}, since=NOW - timedelta(days=90))
    downloads = [line.split()[2] for line in (tmp_path / "calls.log").read_text().splitlines() if line.startswith("run download")]
    assert downloads == ["3", "2"]
    assert control_status.check(REGISTER, control_status.collect(evidence), NOW)[1] == []
