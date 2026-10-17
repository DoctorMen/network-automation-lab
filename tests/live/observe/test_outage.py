"""One outage, read two ways (decisions 0020 and 0021), and a short one.

OROS DEC-5, one alert per cause: in one window, a router cut off from every link, frr_exporter killed beside
a healthy router, and that router's link to a device behind it cut, page exactly three times: NodeDown for
the router, TargetDown for the exporter and LinkDown for the link. Every alert that follows from them (the
router's neighbors' sessions with it, the devices behind it and behind the link, its own exporters, the
sessions read through the dead exporter) is in Alertmanager, held back by a cause its deps label lists, and
nothing pages late once all three recover, the carrier flaps that end the outage included. A link down for
7 s, seen by a scrape but too short for LinkDown, pages once, as a flap.

OROS DEC-1, why it fired, what is normal, what changed: every alert of that outage, 20 or more besides the
cause markers and Watchdog, carries the rule's condition with the value now, a link to its signal's last 7
days, and the commit `make apply` last applied, raised within the hour after that apply."""
import calendar
import re
import subprocess
import time
import urllib.parse

import pytest

from netlab import monitoring
from netlab.inventory import load
from netlab.observe import commit

from ..conftest import ROOT, wait_for
from .conftest import firing, quiet, wait_alert, wait_resolved

# OROS DEC-1's default sample.
SAMPLE = 20
# Alerts that are not about the outage: the cause markers, which never page, and the alert path's heartbeat.
NOT_SAMPLED = ("CauseSeen", "Watchdog")
# Seconds the short outage lasts: over a scrape and its timeout, so a scrape sees it, and under LinkDown's
# `for` (10 s) by more than the ping's own timeout, so neither LinkDown nor NodeDown fires.
SHORT = 7


def deps(alert):
    return set(alert["labels"].get("deps", "/").strip("/").split("/")) - {""}


def stub_links(inv, causes, routers):
    """[(link, router, interface)]: each link from a router we own to devices that reach the NOC only through
    it, with no router among them, so cutting it moves no route."""
    out = []
    for link in inv.links:
        lid = monitoring.link_id(link)
        covers = set(causes.get(lid, {}).get("covers", []))
        for ep in (link.a, link.b):
            if ep.device in routers and covers and not covers & set(inv.routers):
                out.append((lid, ep.device, ep.interface))
    return out


@pytest.fixture(scope="module")
def outage(lab_name, node, mon, noc):
    """Break both, hold until every dependent with a `for` has fired, put both back, and wait until both
    pages have resolved and the markers have stopped holding. Returns what the pager and Alertmanager saw."""
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
    # The third cause: the healthy router's link to what is behind it.
    link, _, port = next(s for s in stub_links(inv, causes, routers) if s[1] == healthy)
    # Start from a NOC with nothing pending or firing, so every alert below is this outage's.
    assert wait_for(lambda: not firing(noc, None), timeout=150, interval=2), f"still active before the outage: {firing(noc, None)}"
    since = time.time()
    for i in ifaces:
        node(parent).run("ip", "link", "set", i, "down")
    node(healthy).run("ip", "link", "set", port, "down")
    subprocess.run(["docker", "kill", exporter], check=True, capture_output=True, timeout=30)
    out = {"parent": parent, "healthy": healthy, "link": link, "since": since}
    try:
        out["parent_page"] = wait_alert(noc, "NodeDown", since, mon["alert_within"]["NodeDown"] + 10, node=parent)
        out["service_page"] = wait_alert(noc, "TargetDown", since, mon["alert_within"]["TargetDown"] + 10, job="frr", node=healthy)
        out["link_page"] = wait_alert(noc, "LinkDown", since, mon["alert_within"]["LinkDown"] + 10, cause=link)
        # Every state rule with a `for` has fired by its bound; 5 s more for Alertmanager to hold it back.
        hold = since + max(mon["alert_within"][a] for a in ("BGPSessionDown", "OSPFNeighborDown", "BFDPeerDown",
                                                            "WebContentWrong", "NodeDown", "LinkDown", "TargetDown")) + 5
        time.sleep(max(0, hold - time.time()))
        out["held"] = noc.am_alerts()
        out["applied"] = {n["node"]: n["value"] for n in noc.query("netlab_config_applied_timestamp_seconds")}
    finally:
        for i in ifaces:
            node(parent).run("ip", "link", "set", i, "up")
        node(healthy).run("ip", "link", "set", port, "up")
        subprocess.run(["docker", "start", exporter], check=True, capture_output=True, timeout=30)
    # The pages resolve once their objects answer; each cause's marker keeps firing for keep_firing
    # seconds more, holding back what is still recovering behind it, then everything is quiet.
    out["parent_resolved"] = wait_resolved(noc, "NodeDown", since, mon["alert_within"]["NodeDown"] + 30, node=parent)
    out["service_resolved"] = wait_resolved(noc, "TargetDown", since, 60, job="frr", node=healthy)
    out["link_resolved"] = wait_resolved(noc, "LinkDown", since, mon["alert_within"]["LinkDown"] + 30, cause=link)
    out["quiet_after"] = wait_for(lambda: not firing(noc), timeout=mon["keep_firing"] + 30, interval=2)
    out["pages"] = [x for x in noc.notifications(since) if x["status"] == "firing"]
    return out


def test_a_parent_failure_pages_once_and_a_killed_service_pages_again(outage, mon):
    """Three causes, three pages; the rest held back by the cause each lists, and nothing late after recovery."""
    o, parent, healthy, link = outage, outage["parent"], outage["healthy"], outage["link"]
    assert o["parent_page"], f"NodeDown {parent} did not page"
    assert o["service_page"], f"TargetDown for frr_exporter on {healthy}, a healthy router, did not page"
    assert o["link_page"], f"LinkDown {link} did not page"
    own = {parent: "NodeDown", f"frr@{healthy}": "TargetDown", link: "LinkDown"}
    paged = sorted((x["labels"]["alertname"], x["labels"].get("node") or "", x["labels"].get("cause") or "") for x in o["pages"])
    assert paged == sorted((a, mon["causes"][c]["labels"]["node"], c) for c, a in own.items()), f"pages for this outage: {paged}"
    held = [a for a in o["held"] if a["status"]["inhibitedBy"]]
    behind = {c for c in mon["causes"] for x in (parent, link) if c in mon["causes"][x]["covers"]}
    for a in o["held"]:
        name = a["labels"]["alertname"]
        if name in NOT_SAMPLED or own.get(a["labels"].get("cause")) == name:
            continue
        assert a["status"]["state"] == "suppressed" and a["status"]["inhibitedBy"], f"not held back: {a['labels']}"
        assert deps(a) & (set(own) | behind), f"held back, but lists no cause of this outage: {a['labels']}"
    # Each kind of knock-on: the parent's own exporter, a neighbor's session with it, a device behind it, a
    # session on the healthy router read through the dead exporter, and a device behind the cut link.
    kinds = {
        "the parent's own exporter": lambda l: l["alertname"] == "TargetDown" and l.get("node") == parent,
        "a neighbor's adjacency with the parent": lambda l: l["alertname"] == "OSPFNeighborDown" and l.get("neighbor") == parent,
        "a device behind the parent": lambda l: l["alertname"] == "NodeDown" and l.get("node") in mon["causes"][parent]["covers"],
        "a session read through the dead exporter": lambda l: l.get("node") == healthy and l.get("neighbor") not in (None, parent),
        "a device behind the cut link": lambda l: l["alertname"] == "NodeDown" and l.get("node") in mon["causes"][link]["covers"],
    }
    for kind, test in kinds.items():
        assert any(test(a["labels"]) for a in held), f"nothing held back for {kind}"
    assert len(held) >= 10, f"only {len(held)} alerts held back"
    assert o["parent_resolved"] and o["service_resolved"] and o["link_resolved"], "a page never resolved"
    assert o["quiet_after"], "alerts still firing after every cause recovered"


def test_every_alert_says_why_what_is_normal_and_what_changed(outage, noc):
    """A sample of 20 or more alerts, every one of the outage's: all three filled in by Prometheus, the
    baseline link's expression selects that object's own history, and an alert on a router names the
    commit applied to it, raised within an hour of that apply."""
    sample = [a for a in outage["held"] if a["labels"]["alertname"] not in NOT_SAMPLED]
    assert len(sample) >= SAMPLE, f"only {len(sample)} alerts in the sample: {sorted(a['labels']['alertname'] for a in sample)}"
    # The commit HEAD names; an edit not yet committed, at apply or now, adds -dirty and changes nothing applied.
    head, named = commit().removesuffix("-dirty"), 0
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
            assert re.search(f"commit {head}(-dirty)? ", note["changes"]) and f"applied to {node} " in note["changes"], \
                f"{what}: {note['changes']} (HEAD is {head}: a lab applied from another commit needs make apply first)"
            started = calendar.timegm(time.strptime(a["startsAt"][:19], "%Y-%m-%dT%H:%M:%S"))  # RFC 3339, UTC
            assert 0 <= started - outage["applied"][node] < 3600, f"{what}: raised {started - outage['applied'][node]:.0f} s after the apply"
            named += 1
        else:
            assert "applied to" in note["changes"] or "no config apply recorded" in note["changes"], f"{what}: {note['changes']}"
    assert named, "no alert in the sample was about a router make apply changed"


def test_a_link_down_for_seconds_pages_once_as_a_flap(node, mon, noc):
    """A router's link to a device behind it down for 7 s: a scrape sees it, so the link's marker fires, but
    LinkDown's `for` is longer. The flap pages once the carrier is back, and nothing else pages, also after
    every marker has stopped holding."""
    inv = load(ROOT / "inventory" / "network.yml")
    link, router, device = stub_links(inv, mon["causes"], list(mon["exporters"]))[0]
    assert wait_for(lambda: not firing(noc, None), timeout=150, interval=2), f"still active before the outage: {firing(noc, None)}"
    quiet(noc, "InterfaceFlapped", node=router, device=device)
    since = time.time()
    try:
        node(router).run("sh", "-c", f"ip link set {device} down && sleep {SHORT} && ip link set {device} up")
    finally:
        node(router).run("ip", "link", "set", device, "up")
    back = time.time()
    page = wait_alert(noc, "InterfaceFlapped", back, mon["alert_within"]["InterfaceFlapped"] + 5, node=router, device=device)
    marker = f'ALERTS{{alertname="CauseSeen",alertstate="firing",cause="{link}"}}'
    seen = noc.value(f"max_over_time({marker}[{int(time.time() - since) + 5}s])")
    quiet_after = wait_for(lambda: not firing(noc, None), timeout=mon["keep_firing"] + 60, interval=2)
    pages = [(x["labels"]["alertname"], x["labels"].get("node"), x["labels"].get("device"))
             for x in noc.notifications(since) if x["status"] == "firing"]
    assert seen == 1, f"no scrape saw {link} down, so its marker never fired and this proves nothing"
    assert page, f"{router} {device} down for {SHORT} s did not page"
    assert page["received"] - back <= mon["alert_within"]["InterfaceFlapped"] + 2
    assert pages == [("InterfaceFlapped", router, device)], f"pages for a {SHORT} s outage of {link}: {pages}"
    assert quiet_after, f"still active after the markers' hold: {firing(noc, None)}"
