"""OROS NOT-4, dead-man's switch (decision 0022): a job that reports no success in its window pages, and
an alert mail path that stops delivering is caught over the webhook, the second channel.

The job is the real `make drift`, whose last line reports its success to the NOC. "Never started" is that
success being older than the job's window; waiting out a real day is not a test, so the test pushes the
last success back by a window, the time a nightly job that stopped running would leave it at. The mail
path is broken where it reaches the mailbox: SMTP refused on noc, while the mailbox itself still answers."""
import subprocess
import time
from datetime import datetime

import pytest

from netlab import monitoring, observe

from ..conftest import ROOT, wait_for
from .conftest import quiet, wait_alert, wait_resolved


def created(mail):
    return datetime.fromisoformat(mail["Created"].replace("Z", "+00:00")).timestamp()


@pytest.fixture(scope="module")
def deadman(node, mon, noc):
    """Refuse SMTP on noc, run make drift, age its success past the window, wait for both pages, then put
    both back and wait for both to resolve."""
    job, path, interval = mon["jobs"][0], mon["alert_path"], mon["interval"]
    metric = f'{observe.SUCCESS}{{job="{job["name"]}"}}'
    mail_age = f'time() - max(log_last_seen_seconds{{node="{mon["host"]}",source="mail"}})'
    quiet(noc, "JobMissed", job=job["name"])
    quiet(noc, "AlertPathSilent", channel="mail")
    assert wait_for(lambda: (noc.value(mail_age) or 1e9) < path["silent_after"], timeout=60, interval=2), \
        "no mail reached the mailbox before the test, so the path wasn't working to begin with"
    out = {"job": job, "mail_before": noc.mail()}
    rule = ["INPUT", "-i", "lo", "-p", "tcp", "--dport", str(monitoring.PORTS["smtp"]), "-j", "REJECT", "--reject-with", "tcp-reset"]
    nocnode, real = node(mon["host"]), None
    out["blocked"] = time.time()
    nocnode.run("iptables", "-I", *rule)
    try:
        ran = subprocess.run(["make", "-s", "drift"], cwd=ROOT, capture_output=True, text=True, timeout=600)
        out["drift"] = (ran.returncode, (ran.stdout + ran.stderr)[-2000:])
        out["reported"] = wait_for(lambda: (noc.value(metric) or 0) >= out["blocked"], timeout=3 * interval, interval=1)
        real = noc.value(metric)
        out["quiet_while_fresh"] = not noc.alerts(None, alertname="JobMissed", job=job["name"])
        # The last success, a window ago: what a nightly job that stopped running leaves behind.
        out["aged"] = time.time()
        noc.push({"job": job["name"]}, observe.exposition(observe.SUCCESS, [({}, out["aged"] - job["every"] - job["grace"] - 2 * interval)]))
        out["missed"] = wait_alert(noc, "JobMissed", out["aged"], mon["alert_within"]["JobMissed"] + 5, job=job["name"])
        out["silent"] = wait_alert(noc, "AlertPathSilent", out["blocked"],
                                   path["silent_after"] + mon["alert_within"]["AlertPathSilent"] + 5, channel="mail")
        out["mail_during"] = [m for m in noc.mail() if created(m) > out["blocked"] + 2]  # the mailbox still answers
    finally:
        nocnode.run("iptables", "-D", *rule, check=False)
        if real:
            noc.push({"job": job["name"]}, observe.exposition(observe.SUCCESS, [({}, real)]))
        else:
            noc.send(monitoring.PORTS["pushgateway"], f"/metrics/job/{job['name']}", "", method="DELETE")
    out["missed_resolved"] = wait_resolved(noc, "JobMissed", out["aged"], 30, job=job["name"])
    out["silent_resolved"] = wait_resolved(noc, "AlertPathSilent", out["blocked"],
                                           2 * path["every"] + mon["alert_within"]["AlertPathSilent"] + 15, channel="mail")
    return out


def test_a_job_that_never_starts_pages(deadman, mon):
    """make drift's own last line reports its success; with that success a window old, JobMissed pages."""
    d = deadman
    assert d["drift"][0] == 0, f"make drift failed: {d['drift'][1]}"
    assert d["reported"], "make drift's success never reached the NOC"
    assert d["quiet_while_fresh"], "JobMissed was active right after a real run"
    assert d["missed"], f"no JobMissed for {d['job']['name']} with its last success older than its window"
    assert d["missed"]["received"] - d["aged"] <= mon["alert_within"]["JobMissed"]
    assert d["missed_resolved"], "JobMissed did not resolve once the real success was back"


def test_a_broken_mail_path_pages_on_the_second_channel(deadman, mon):
    """With SMTP refused, no mail arrives while the mailbox still answers, and AlertPathSilent reaches the
    webhook pager within its bound; once mail flows again it resolves."""
    d, path = deadman, mon["alert_path"]
    assert any("Watchdog" in m["Subject"] for m in d["mail_before"]), "no Watchdog mail before the block"
    assert d["mail_during"] == [], f"mail arrived through a refused SMTP port: {[m['Subject'] for m in d['mail_during']]}"
    assert d["silent"], "a broken mail path did not page on the webhook"
    assert d["silent"]["received"] - d["blocked"] <= path["silent_after"] + mon["alert_within"]["AlertPathSilent"]
    assert d["silent_resolved"], "AlertPathSilent did not resolve once mail flowed again"
