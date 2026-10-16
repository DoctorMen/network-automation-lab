"""One page per cause (OROS DEC-5, decision 0021): what each alert depends on comes from the inventory's
graph of devices and links, each cause holds back what lists it, and no two causes hold each other back."""
import copy
import re
from pathlib import Path

import yaml

from netlab import monitoring
from netlab.inventory import load
from netlab.render import render_all

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "network.yml"
inv = load(INVENTORY)


def deps(rule):
    return set(rule["labels"].get("deps", "/").strip("/").split("/")) - {""}


def rules(alert, **labels):
    return [r for r in monitoring.alert_rules(inv) if r["alert"] == alert
            and all(r["labels"].get(k) == v for k, v in labels.items())]


def test_dependencies_come_from_the_inventory_graph():
    """h2 reaches the NOC only through r3 and its link to r3, and r1 only through r2: so h2's alerts list r3
    and that link, r1's list r2 and not r3, and fw1's list r1 and the link to it. Nothing here names them;
    the graph does."""
    for r in [*rules("NodeDown", node="h2"), *rules("WebContentWrong", node="h2"), *rules("SourceSilent", node="h2")]:
        assert {"r2", "r3", "h2:eth1-r3:eth3"} <= deps(r), r["labels"]
    assert deps(rules("NodeDown", node="r1")[0]) == {"r2"}
    assert deps(rules("NodeDown", node="r2")[0]) == set(), "r2 is the NOC's first hop: nothing the NOC sees is in front of it"
    # So a dead uplink from the NOC is still one page, NodeDown for r2 (RISK-43).
    assert all("r2" in deps(r) for r in rules("NodeDown") if r["labels"]["node"] != "r2")
    assert {"r1", "fw1:eth2-r1:eth3"} <= deps(rules("NodeDown", node="fw1")[0])
    # A session's alerts list both ends of their link and the collector they are read through.
    for r in rules("OSPFNeighborDown", node="r1", neighbor="r3"):
        assert {"r1", "r3", "r1:eth2-r3:eth2", "frr@r1"} <= deps(r)


def test_a_flap_is_never_held_back_by_its_own_link():
    """A scrape that sees a short outage fires the link's marker, and its LinkDown needs 10 s to page: a flap
    behind its own link would then page nothing. Each flap lists its router and what is in front of it."""
    for r in rules("InterfaceFlapped"):
        link = monitoring.link_id(monitoring.link_at(inv, r["labels"]["node"], r["labels"]["device"]))
        assert link not in deps(r), r["labels"]
        assert deps(r) == deps(rules("NodeDown", node=r["labels"]["node"])[0]) | {r["labels"]["node"]}, r["labels"]


def test_every_alert_lists_only_causes_and_every_cause_has_one_inhibit_rule(tmp_path):
    render_all(inv, tmp_path)
    am = yaml.safe_load((tmp_path / monitoring.host(inv) / "alertmanager.yml").read_text())
    causes = monitoring.causes(inv)
    rules_by_cause = {re.fullmatch(r'cause="(.+)"', i["source_matchers"][0]).group(1): i for i in am["inhibit_rules"]}
    assert set(rules_by_cause) == set(causes)
    for c, i in rules_by_cause.items():
        assert i["target_matchers"] == [f'deps=~".*/{c}/.*"']
    for r in monitoring.alert_rules(inv):
        assert deps(r) <= set(causes), f"{r['alert']} {r['labels']} lists something that is not a cause"
        # The regex finds a cause only where it is listed whole: r1 must not match r1:eth1-r2:eth1.
        for c in causes:
            assert bool(re.fullmatch(f".*/{re.escape(c)}/.*", r["labels"].get("deps", "/"))) == (c in deps(r))


def test_no_two_causes_hold_each_other_back():
    """A cause's page leaves itself out, and the causes form no loop: otherwise two failures that hold each
    other back would page nothing at all."""
    pages = {r["labels"]["cause"]: deps(r) for r in monitoring.alert_rules(inv) if "cause" in r["labels"]}
    assert set(pages) == set(monitoring.causes(inv)), "every cause has a page of its own"
    for c, d in pages.items():
        assert c not in d
    seen, done = set(), set()

    def visit(c, path):
        assert c not in path, f"causes hold each other back: {' -> '.join([*path, c])}"
        if c not in done:
            for d in pages[c]:
                visit(d, [*path, c])
            done.add(c)
    for c in pages:
        visit(c, [])


def test_markers_are_in_alertmanager_before_what_they_hold_back():
    """A cause's marker fires on the evaluation after the scrape that sees it (the probe's own timeout
    included); what depends on it holds its `for` and then group_wait before its first page. The margin
    between the two is what lets inhibition win, and it is stated here. Rules with no `for` are left out:
    each fires on a fact that comes later by nature (a flap once the carrier is back, a source silent
    for silent_after, a job or mail missing for its window)."""
    mon = inv.monitoring
    marker = mon["interval"] + 2 + monitoring.CAUSE_EVERY  # scrape, ping timeout (blackbox icmp 2 s), evaluation
    first_page = min(w for w in monitoring.WAIT.values() if w) + mon["group_wait"]
    assert first_page - marker >= 5, f"marker after {marker} s, first dependent page after {first_page} s"
    for r in monitoring.cause_rules(inv):
        assert r["for"] == "0s"
    groups = monitoring.rule_groups(inv)["groups"]
    assert groups[1]["interval"] == f"{monitoring.CAUSE_EVERY}s" and groups[1]["rules"] == monitoring.cause_rules(inv)


def test_a_cause_keeps_holding_back_through_the_slowest_recovery():
    """After a cause recovers, its marker keeps firing for a heartbeat and three intervals, the longest a
    dependent takes to clear (a log source's next heartbeat), so nothing pages late. No page keeps firing:
    h2's page, held behind r3, would outlast r3's hold whenever h2 answered a scrape after r3 did."""
    keep = f"{monitoring.keep_firing(inv)}s"
    assert monitoring.keep_firing(inv) >= inv.logging["heartbeat"] + 3 * inv.monitoring["interval"]
    assert monitoring.keep_firing(inv) > monitoring.FLAP_WINDOW + 2 * inv.monitoring["interval"]
    assert all(r["keep_firing_for"] == keep for r in monitoring.cause_rules(inv))
    assert [r["alert"] for r in monitoring.alert_rules(inv) if "keep_firing_for" in r] == []


def test_a_new_router_needs_no_hand_tuning(tmp_path):
    """Add r4 behind r3, with a server behind r4: their alerts list r3 and r4 with no other change."""
    raw = copy.deepcopy(yaml.safe_load(INVENTORY.read_text()))
    raw["routers"]["r4"] = {"owner": "campus NOC", "role": "core", "loopback": "10.255.0.4/32", "ospf": {"area": 0}}
    raw["hosts"]["h4"] = {"owner": "campus NOC", "interface": "eth1", "address": "10.40.40.10/24", "gateway": "10.40.40.1",
                          "segment": "LAN-D", "services": [22]}
    raw["links"] += [["r3:eth4@10.0.34.0/31", "r4:eth1@10.0.34.1/31"], ["h4:eth1@10.40.40.10/24", "r4:eth2@10.40.40.1/24"]]
    raw["scope"]["out_of_scope"] += ["r4", "h4"]  # every device needs a scope decision (decision 0013)
    raw["logging"]["budget"]["store_mb"] += 512  # and the store room for their two syslog budgets (decision 0026)
    (tmp_path / "net.yml").write_text(yaml.safe_dump(raw, sort_keys=False))
    bigger = load(tmp_path / "net.yml")
    by = {(r["alert"], r["labels"].get("node")): deps(r) for r in monitoring.alert_rules(bigger)}
    assert by[("NodeDown", "r4")] >= {"r2", "r3", "r3:eth4-r4:eth1"}
    assert by[("NodeDown", "h4")] >= {"r3", "r4", "h4:eth1-r4:eth2"}
    assert by[("SourceSilent", "h4")] >= {"r4", "h4"}
