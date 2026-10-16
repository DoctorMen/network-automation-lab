"""One outage, read two ways (decisions 0020 and 0021).

OROS DEC-5, one alert per cause: a router cut off from every link, and in the same window frr_exporter
killed beside a healthy router, page exactly twice: NodeDown for the router and TargetDown for the exporter.
Every alert that follows from either (its neighbors' sessions, the hosts behind it, its own exporters, the
sessions read through the dead exporter) is in Alertmanager, held back by a cause its deps label lists, and
nothing pages late once both recover.

OROS DEC-1, why it fired, what is normal, what changed: every alert of that outage, 20 or more, carries the
rule's condition with the value now, a link to its signal's last 7 days, and the commit `make apply` last
applied, raised within the hour after that apply."""
import calendar
import subprocess
import time
import urllib.parse

import pytest

from netlab.inventory import load
from netlab.observe import commit

from ..conftest import ROOT, wait_for
from .conftest import firing, wait_alert, wait_resolved

# OROS DEC-1's default sample.
SAMPLE = 20


def deps(alert):
    return set(alert["labels"].get("deps", "/").strip("/").split("/")) - {""}


@pytest.fixture(scope="module")
def outage(lab_name, node, mon, noc):
    """Break both, hold until every dependent with a `for` has fired, put both back, and wait until both
    pages have resolved, the parent's after it kept firing. Returns what the pager and Alertmanager saw."""
    inv, routers, causes = load(ROOT / "inventory" / "network.yml"), list(mon["exporters"]), mon["causes"]
    rules = noc.rules()
    # The NOC's first hop hides everything when it fails, the killed exporter included, so the parent is the
    # router with the most alerts depending on it after that one; the healthy router depends on neither.
    first_hop = next(r for r in routers if all(o in causes[r]["covers"] for o in routers if o != r))
    parent = max((r for r in routers if r != first_hop),
                 key=lambda r: sum(f"/{r}/" in x.get("labels", {}).get("deps", "") for x in rules))
    healthy = next(r for r in routers if r not in (parent, first_hop) and r not in causes[parent]["covers"])
    exporter = f"clab-{lab_name}-{healthy}-frr-exporter"
    assert f"{healthy}-frr-exporter" in mon["sidecars"]
    ifaces = [ep.interface for ep in inv.interfaces(parent)]
    # Start from a NOC with nothing pending or firing, so every alert below is this outage's.
    assert wait_for(lambda: not firing(noc, None), timeout=150, interval=2), f"still active before the outage: {firing(noc, None)}"
    since = time.time()
    for i in ifaces:
        node(parent).run("ip", "link", "set", i, "down")
    subprocess.run(["docker", "kill", exporter], check=True, capture_output=True, timeout=30)
    out = {"parent": parent, "healthy": healthy, "since": since}
    try:
        out["parent_page"] = wait_alert(noc, "NodeDown", since, mon["alert_within"]["NodeDown"] + 10, node=parent)
        out["service_page"] = wait_alert(noc, "TargetDown", since, mon["alert_within"]["TargetDown"] + 10, job="frr", node=healthy)
        # Every state rule with a `for` has fired by its bound; 5 s more for Alertmanager to hold it back.
        hold = since + max(mon["alert_within"][a] for a in ("BGPSessionDown", "OSPFNeighborDown", "BFDPeerDown",
                                                            "WebContentWrong", "NodeDown", "LinkDown", "TargetDown")) + 5
        time.sleep(max(0, hold - time.time()))
        out["held"] = noc.am_alerts()
        out["applied"] = {n["node"]: n["value"] for n in noc.query("netlab_config_applied_timestamp_seconds")}
    finally:
        for i in ifaces:
            node(parent).run("ip", "link", "set", i, "up")
        subprocess.run(["docker", "start", exporter], check=True, capture_output=True, timeout=30)
    # The parent's page keeps firing for keep_firing seconds after it answers again, holding back what is
    # still recovering behind it, then resolves.
    back = mon["keep_firing"] + mon["alert_within"]["NodeDown"] + 30
    out["parent_resolved"] = wait_resolved(noc, "NodeDown", since, back, node=parent)
    out["service_resolved"] = wait_resolved(noc, "TargetDown", since, 60, job="frr", node=healthy)
    out["quiet_after"] = wait_for(lambda: not firing(noc), timeout=60, interval=2)
    out["pages"] = [x for x in noc.notifications(since) if x["status"] == "firing"]
    return out


def test_a_parent_failure_pages_once_and_a_killed_service_pages_again(outage, mon):
    """Two causes, two pages; the rest held back by the cause each lists, and nothing late after recovery."""
    o, parent, healthy = outage, outage["parent"], outage["healthy"]
    assert o["parent_page"], f"NodeDown {parent} did not page"
    assert o["service_page"], f"TargetDown for frr_exporter on {healthy}, a healthy router, did not page"
    paged = sorted((x["labels"]["alertname"], x["labels"].get("node"), x["labels"].get("job")) for x in o["pages"])
    assert paged == [("NodeDown", parent, None), ("TargetDown", healthy, "frr")], f"pages for this outage: {paged}"
    held = [a for a in o["held"] if a["status"]["inhibitedBy"]]
    pages = {("NodeDown", parent), ("TargetDown", healthy)}
    for a in o["held"]:
        name = a["labels"]["alertname"]
        if name in ("Watchdog", "CauseSeen") or (name, a["labels"].get("node")) in pages and "cause" in a["labels"]:
            continue
        assert a["status"]["state"] == "suppressed" and a["status"]["inhibitedBy"], f"not held back: {a['labels']}"
        assert deps(a) & ({parent, f"frr@{healthy}"} | {c for c in mon["causes"] if c in mon["causes"][parent]["covers"]}), \
            f"held back, but lists neither cause: {a['labels']}"
    # Each kind of knock-on: the parent's own exporter, a neighbor's session with it, a device behind it, and
    # a session on the healthy router read through the dead exporter.
    kinds = {
        "the parent's own exporter": lambda l: l["alertname"] == "TargetDown" and l.get("node") == parent,
        "a neighbor's adjacency with the parent": lambda l: l["alertname"] == "OSPFNeighborDown" and l.get("neighbor") == parent,
        "a device behind the parent": lambda l: l["alertname"] == "NodeDown" and l.get("node") in mon["causes"][parent]["covers"],
        "a session read through the dead exporter": lambda l: l.get("node") == healthy and l.get("neighbor") not in (None, parent),
    }
    for kind, test in kinds.items():
        assert any(test(a["labels"]) for a in held), f"nothing held back for {kind}"
    assert len(held) >= 10, f"only {len(held)} alerts held back"
    assert o["parent_resolved"] and o["service_resolved"], "a page never resolved"
    assert o["quiet_after"], "alerts still firing after both causes recovered"


def test_every_alert_says_why_what_is_normal_and_what_changed(outage, noc):
    """A sample of 20 or more alerts: all three filled in by Prometheus, the baseline link's expression
    selects that object's own history, and an alert on a router names the commit applied to it, raised
    within an hour of that apply."""
    sample = outage["held"]
    assert len(sample) >= SAMPLE, f"only {len(sample)} alerts in the sample"
    head, named = commit(), 0
    for a in sample:
        note, what = a["annotations"], f"{a['labels']['alertname']} {a['labels'].get('node', '')}"
        for k in ("why_fired", "baseline", "changes"):
            assert note.get(k) and "error expanding" not in note[k] and "<no value>" not in note[k], f"{what}: {k} = {note.get(k)!r}"
        assert "; now: " in note["why_fired"] and note["why_fired"].split("; now: ")[1].strip(), f"{what}: no value now"
        link = note["baseline"].split("over the last 7 days: ", 1)[1]
        url = urllib.parse.urlparse(link)
        assert url.path == "/graph" and url.netloc, f"{what}: baseline is not a graph link: {link}"
        expr = urllib.parse.parse_qs(url.query)["g0.expr"][0]
        assert noc.query(f"count_over_time(({expr})[1h:5s])"), f"{what}: the baseline link shows no history: {expr}"
        node = a["labels"].get("node")
        if node in outage["applied"]:
            assert f"commit {head} " in note["changes"] and f"applied to {node} " in note["changes"], f"{what}: {note['changes']}"
            started = calendar.timegm(time.strptime(a["startsAt"][:19], "%Y-%m-%dT%H:%M:%S"))  # RFC 3339, UTC
            assert 0 <= started - outage["applied"][node] < 3600, f"{what}: raised {started - outage['applied'][node]:.0f} s after the apply"
            named += 1
        else:
            assert "applied to" in note["changes"] or "no config apply recorded" in note["changes"], f"{what}: {note['changes']}"
    assert named, "no alert in the sample was about a router make apply changed"
