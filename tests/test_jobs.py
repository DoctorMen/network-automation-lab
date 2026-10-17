"""Dead-man's switch (OROS NOT-4, decision 0022): every unattended job reports its success as its last step,
each has a window that matches its schedule, and the alert path's heartbeat goes by mail while the alarm
for its silence goes by the webhook."""
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

from netlab import monitoring, observe
from netlab.inventory import load
from netlab.render import render_all

ROOT = Path(__file__).resolve().parent.parent
inv = load(ROOT / "inventory" / "network.yml")
JOBS = inv.monitoring["jobs"]
DAY = 86400


def recipe(target):
    lines = (ROOT / "Makefile").read_text().split(f"\n{target}:", 1)[1].split("\n\n", 1)[0].splitlines()[1:]
    return [l.strip() for l in lines if l.startswith("\t")]


def test_every_job_reports_success_as_its_last_step():
    """make runs a recipe's lines in order and stops at the first that fails, so the success line, last,
    runs only when the job really did its work."""
    for j in JOBS:
        assert recipe(j["name"])[-1] == f"$(SUCCESS) {j['name']}", j["name"]
    assert "SUCCESS = $(PY) -m netlab.observe success" in (ROOT / "Makefile").read_text()


def test_every_window_matches_the_jobs_schedule():
    """A job's every is its workflow's cron: nightly (minute hour * * *) or weekly (minute hour * * day)."""
    workflows = {p.name: p.read_text() for p in (ROOT / ".github" / "workflows").glob("*.yml")}
    for j in JOBS:
        where = [name for name, text in workflows.items() if re.search(rf"run: make {j['name']}\b", text)]
        assert where, f"no workflow runs make {j['name']}"
        cron = yaml.safe_load(workflows[where[0]])[True]["schedule"][0]["cron"].split()
        assert j["every"] == (7 * DAY if cron[4] != "*" else DAY), (j["name"], cron)
        assert 0 < j["grace"] < j["every"]


def test_a_job_that_never_reported_pages_from_the_nocs_start():
    """No success at all since the NOC started counts from the NOC's start, so a job that never ran pages
    one window later instead of never."""
    for r in [r for r in monitoring.alert_rules(inv) if r["alert"] == "JobMissed"]:
        j = next(x for x in JOBS if x["name"] == r["labels"]["job"])
        assert r["expr"] == (f'time() - (max(netlab_job_last_success_timestamp_seconds{{job="{j["name"]}"}}) '
                             f'or on() max(process_start_time_seconds{{job="pushgateway"}})) > {j["every"] + j["grace"]}')


def test_the_heartbeat_goes_by_mail_and_its_silence_pages_on_the_webhook(tmp_path):
    render_all(inv, tmp_path)
    am = yaml.safe_load((tmp_path / monitoring.host(inv) / "alertmanager.yml").read_text())
    receivers = {r["name"]: r for r in am["receivers"]}
    watchdog = next(r for r in am["route"]["routes"] if r["matchers"] == ['alertname="Watchdog"'])
    assert watchdog["receiver"] == "mail" and "webhook_configs" not in receivers["mail"]
    # Alertmanager mails again on the first flush (every group_interval) after repeat_interval has passed, so
    # the mail goes every `every` s only with repeat_interval between the flush before it and `every`.
    every, flush = inv.monitoring["alert_path"]["every"], int(am["route"]["group_interval"].removesuffix("s"))
    repeat = int(watchdog["repeat_interval"].removesuffix("s"))
    assert every % flush == 0 and every - flush < repeat < every, (every, flush, repeat)
    # AlertPathSilent takes the default route: the webhook sink.
    assert not any("AlertPathSilent" in str(r["matchers"]) for r in am["route"]["routes"])
    assert am["route"]["receiver"] == "sink" and receivers["sink"]["webhook_configs"]
    path = next(r for r in monitoring.alert_rules(inv) if r["alert"] == "AlertPathSilent")
    assert 'log_last_seen_seconds{node="noc",source="mail"}' in path["expr"]
    vector = yaml.safe_load((tmp_path / monitoring.host(inv) / "vector.yaml").read_text())
    assert vector["sources"]["mailbox"]["address"] == f"127.0.0.1:{monitoring.PORTS['mail_hook']}"
    mailbox = monitoring.sidecars(inv)[f"{monitoring.host(inv)}-mailbox"]["cmd"]
    assert f"--webhook-url http://127.0.0.1:{monitoring.PORTS['mail_hook']}/" in mailbox


@pytest.fixture
def heartbeat(monkeypatch):
    """A stand-in for an outside heartbeat check (healthchecks.io style): it records each path pinged."""
    pinged = []

    class Ping(BaseHTTPRequestHandler):
        def do_GET(self):
            pinged.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Ping)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("HEARTBEAT_URL", f"http://127.0.0.1:{server.server_port}/key")
    yield pinged
    server.shutdown()


def test_success_without_a_noc_warns_and_still_pings_the_heartbeat(heartbeat, capsys):
    """The lab job deploys no NOC: the push only warns, and the outside heartbeat still gets its ping."""
    assert observe.success(inv, "no-such-lab", "drift") == 0
    assert "did not reach the NOC" in capsys.readouterr().err
    assert heartbeat == ["/key/drift"]


def test_a_failed_heartbeat_warns_and_the_job_still_passes(monkeypatch, capsys):
    """The job's work is done (make backup has verified its snapshot): an outside check that can't be reached
    pages by itself when the ping is late, and failing here would only make CI skip saving that backup."""
    monkeypatch.setenv("HEARTBEAT_URL", "http://127.0.0.1:9/check-key-123")  # discard port: nothing listens
    assert observe.success(inv, "no-such-lab", "drift") == 0
    out = capsys.readouterr()
    assert "heartbeat ping failed" in out.err
    assert "check-key-123" not in out.err + out.out, "the URL holds the check's key; never print it"


def test_the_alert_path_is_not_due_before_the_first_resend():
    """At the NOC's start Prometheus may send Watchdog before Alertmanager answers, and sends it again a
    resend delay later: AlertPathSilent counts from then, so a deploy or a power cut doesn't page."""
    path = next(r for r in monitoring.alert_rules(inv) if r["alert"] == "AlertPathSilent")
    assert path["expr"] == ('time() - (max(log_last_seen_seconds{node="noc",source="mail"}) or on() '
                            f'(max(process_start_time_seconds{{job="pushgateway"}}) + {monitoring.RESEND_DELAY})) '
                            f'> {inv.monitoring["alert_path"]["silent_after"]}')
    prometheus = monitoring.sidecars(inv)[f"{monitoring.host(inv)}-prometheus"]["cmd"]
    assert "--rules.alert.resend-delay" not in prometheus and monitoring.RESEND_DELAY >= 60, "Prometheus' default is 1m"


def test_only_a_listed_job_can_report():
    assert observe.success(inv, "no-such-lab", "nightly-typo") == 2


def test_only_a_scheduled_run_that_passed_pings_the_outside_check():
    """The nightly run pings HEARTBEAT_URL/nightly once every job it runs has passed, the dated reviews' job
    aside, and each job's own success reaches the outside check on scheduled runs only: a push or a pull
    request never stands in for a night that didn't run."""
    flows = {p.name: yaml.safe_load(p.read_text()) for p in (ROOT / ".github" / "workflows").glob("*.yml")}
    ci = flows["ci.yml"]["jobs"]
    beat = ci["heartbeat"]
    assert beat["if"] == "${{ github.event_name == 'schedule' }}", "a status function in `if` would let it ping after a failure"
    # Every job but the review job: a dated review falling due turns that job red on purpose, and must stop
    # neither the live tests, the backup nor this ping.
    assert set(beat["needs"]) == set(ci) - {"heartbeat", "control-status", "review"}
    assert "review" not in beat["needs"], "a review falling due would stop the outside ping"
    assert '"$HEARTBEAT_URL/nightly"' in beat["steps"][-1]["run"]
    gated = "${{ github.event_name == 'schedule' && secrets.HEARTBEAT_URL || '' }}"
    for j in JOBS:
        runs = [(f, job) for f, flow in flows.items() for job in flow["jobs"].values()
                if any(re.match(rf"make {j['name']}\b", str(step.get("run", ""))) for step in job.get("steps", []))
                and True in flow and "schedule" in flow[True]]
        assert any(job.get("env", {}).get("HEARTBEAT_URL") == gated for _, job in runs), \
            f"no scheduled job runs make {j['name']} with the outside check"
    for f, flow in flows.items():
        for name, job in flow["jobs"].items():
            assert job.get("env", {}).get("HEARTBEAT_URL", gated) == gated, f"{f} {name}: HEARTBEAT_URL not gated on schedule"
