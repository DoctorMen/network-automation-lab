"""The NOC's own tests (decisions 0018 and 0019): they need the full lab, sidecars included (`make deploy`),
and run as `make observe`. The network's tests (`make live`) never need them.

Every value they compare against comes from expected_state.json's `monitoring` block, generated from the
inventory. Each test that breaks something puts it back, and checks its alert against the moment it
broke it: an alert raised before the test started can't count."""
import re
import subprocess
import time
from datetime import datetime

import pytest

from netlab.observe import Noc

from ..conftest import wait_for


@pytest.fixture(scope="session")
def mon(expected):
    if not expected.get("monitoring"):
        pytest.skip("the inventory has no monitoring block")
    return expected["monitoring"]


@pytest.fixture(scope="session")
def noc(lab_name, mon):
    """The NOC, settled: every scrape answering, Loki ready, every log source heard from, and nothing firing
    but Watchdog, the alert path's heartbeat, which always fires (decision 0022). A lab started without its
    sidecars (make deploy-network) has no NOC, and these tests can't run there."""
    sidecar = f"clab-{lab_name}-{mon['sidecars'][0]}"
    if subprocess.run(["docker", "inspect", sidecar], capture_output=True).returncode:
        pytest.skip(f"{sidecar} is not running: the NOC's tests need the full lab (make deploy), not make deploy-network")
    n = Noc(lab_name, mon["host"])
    # Right after a deploy the first heartbeat may have gone out before OSPF had a route to the NOC; the
    # next one is a heartbeat later. If it never settles, the tests say what is wrong.
    wait_for(lambda: n.settled(mon["sources"]), timeout=mon["heartbeat"] + 60, interval=3)
    return n


def firing(noc, state="firing"):
    """Every alert Prometheus has in this state, except Watchdog, which fires all the time."""
    return noc.firing(state)


def halfway_between_scrapes(noc, interval, **labels):
    """Sleep until halfway between two scrapes of this target. Prometheus scrapes a target at a fixed offset,
    so its last scrape says when the next ones come; a change made here is as far from both as it can be."""
    target = next(t for t in noc.targets() if all(t["labels"].get(k) == v for k, v in labels.items()))
    # Prometheus writes nanoseconds; Python reads at most microseconds.
    last = datetime.fromisoformat(re.sub(r"(\.\d{6})\d*", r"\1", target["lastScrape"]).replace("Z", "+00:00")).timestamp()
    time.sleep((last + interval / 2 - time.time()) % interval)


def quiet(noc, alert, timeout=90, **labels):
    """Wait until this object's alert is neither pending nor firing, and the pager's last word on it was
    "resolved", before a test breaks the object: Alertmanager sends no new page for an alert it already
    paged. A previous test's knock-on can still be resolving (FRR drops a link's BFD session when OSPF
    drops the adjacency there)."""
    def calm():
        if noc.alerts(None, alertname=alert, **labels):
            return False
        last = {}
        for x in noc.notifications(0, alertname=alert, **labels):
            last[tuple(sorted(x["labels"].items()))] = x["status"]
        return all(s == "resolved" for s in last.values())
    assert wait_for(calm, timeout=timeout, interval=1), \
        f"{alert} {labels} was still active before the test broke anything: {noc.alerts(None, alertname=alert, **labels)}"


def wait_alert(noc, alert, since, timeout, **labels):
    """The first firing notification the sink received for this alert after `since`, or None."""
    def delivered():
        return next((x for x in noc.notifications(since, alertname=alert, **labels) if x["status"] == "firing"), None)
    return wait_for(delivered, timeout=timeout, interval=1)


def wait_resolved(noc, alert, since, timeout, **labels):
    def delivered():
        return next((x for x in noc.notifications(since, alertname=alert, **labels) if x["status"] == "resolved"), None)
    return wait_for(delivered, timeout=timeout, interval=1)


def others_firing(noc, alert, since, **labels):
    """Notifications for this alert after `since` about any other object: there should be none."""
    return [x["labels"] for x in noc.notifications(since, alertname=alert)
            if x["status"] == "firing" and any(x["labels"].get(k) != v for k, v in labels.items())]

