"""OROS NOT-3, arrival proof per source: every log source has a last-seen check at the collector, a test
event sent over its real path reaches the central store, and a source whose export is blocked on the way,
while the device itself still counts the datagrams it sends, raises SourceSilent within twice its normal
gap. It comes back without a restart of anything."""
import time

import pytest

from netlab import access, monitoring, observe
from netlab.inventory import load
from netlab.monitoring import source_addresses

from ..conftest import ROOT, wait_for
from .conftest import quiet, wait_alert, wait_resolved


def test_every_source_has_a_last_seen_check(mon, noc):
    """Each source has its own SourceSilent rule, healthy and quiet, and its last line arrived within silent_after."""
    rules = {(r["labels"].get("node"), r["labels"].get("source")): r for r in noc.rules() if r["name"] == "SourceSilent"}
    seen = {(s["node"], s["source"]): s["value"] for s in noc.query("time() - log_last_seen_seconds")}
    for s in mon["sources"]:
        key = (s["node"], s["source"])
        assert key in rules, f"no SourceSilent rule for {key}"
        assert rules[key]["health"] == "ok" and rules[key]["state"] == "inactive", f"{key}: {rules[key]['health']}, {rules[key]['state']}"
        assert key in seen and seen[key] <= s["silent_after"], f"{key}: last line {seen.get(key)} s ago (silent after {s['silent_after']} s)"
    assert set(rules) == {(s["node"], s["source"]) for s in mon["sources"]}, "a SourceSilent rule for a source the inventory doesn't have"


def test_synthetic_event_from_every_source_reaches_the_store(lab_name, mon, noc):
    """`make testevent`: a marked line from each source, sent the way its real lines go, is searchable centrally, labelled with its node and source."""
    results = observe.testevent(load(ROOT / "inventory" / "network.yml"), lab_name)
    assert {(e["node"], e["source"]) for e in results} == {(s["node"], s["source"]) for s in mon["sources"]}
    missing = [f"{e['node']}/{e['source']}" for e in results if e["seconds"] is None]
    assert not missing, f"test events that never reached the central store: {missing}"


@pytest.fixture
def blocked_source(node, mon):
    """r1's syslog, dropped on r2 on its way to the NOC: r1 itself sees nothing wrong. And a rule on r1 with no
    target, which only counts what r1's syslogd sends the collector (the accounting proxy's records come from their
    own port and are left out): r1's own count that it is still sending."""
    inv = load(ROOT / "inventory" / "network.yml")
    addresses = sorted(a for a, n in source_addresses(inv).items() if n == "r1")
    rules = [["FORWARD", "-s", a, "-p", "udp", "--dport", "514", "-j", "DROP"] for a in addresses]
    counting = ["OUTPUT", "-p", "udp", "-d", monitoring.collector(inv), "--dport", "514", "!", "--sport", str(access.RECORD_PORT)]
    return "r1", "r2", rules, counting


def sent_to_collector(host, counting):
    """Packets r1's counting rule (always the first in its OUTPUT chain while the test runs) has matched."""
    first = host.run("iptables", "-vnxL", counting[0], "1").stdout.split()
    assert first and f"dpt:{counting[6]}" in first and f"spt:!{counting[-1]}" in first, f"the counting rule is not first: {first}"
    return int(first[0])


def test_blocked_source_raises_source_silent_and_comes_back_without_a_restart(node, lab_name, mon, noc, blocked_source):
    """While r1's syslog is dropped on the way, r1 keeps counting the datagrams its syslogd sends the collector, and
    logging on the box, and SourceSilent{r1} pages within 2x its heartbeat of its last line arriving; no other source pages.
    Unblocked, a test line arrives and the alert resolves with every process on r1 as it was."""
    source, on, rules, counting = blocked_source
    spec = next(s for s in mon["sources"] if s["node"] == source and s["source"] == "syslog")
    bound = spec["within"]
    assert bound == 2 * mon["heartbeat"], "syslog's bound is NOT-3's default, twice the source's normal gap"
    r1 = node(source)
    pids = r1.run("sh", "-c", "for p in /proc/[0-9]*; do echo ${p#/proc/} $(tr '\\0' ' ' < $p/cmdline); done").stdout
    started = r1.run("cat", "/proc/1/stat").stdout.split()[21]  # the container's first process: its start time
    quiet(noc, "SourceSilent", node=source, source="syslog")
    r1.run("iptables", "-I", *counting)
    since = time.time()
    for rule in rules:
        node(on).run("iptables", "-I", *rule)
    blocked = time.time()
    sent_before = sent_to_collector(r1, counting)
    try:
        # The last line that got through, read once the NOC has scraped the collector after the block: a line that
        # arrived just before it (the previous test's test event, say) is not yet in the value scraped before.
        seen = f'log_last_seen_seconds{{node="{source}",source="syslog"}}'
        assert wait_for(lambda: (noc.value(f"timestamp({seen})") or 0) > blocked + 1, timeout=3 * mon["interval"], interval=1), \
            "the NOC did not scrape the collector after the block"
        last = noc.value(seen)
        page = wait_alert(noc, "SourceSilent", since, bound + 15, node=source, source="syslog")
        assert page, f"no SourceSilent for {source} within {bound} s"
        assert page["received"] - last <= bound, f"paged {page['received'] - last:.0f} s after the last line arrived (bound {bound} s)"
        # r1's own count says its syslogd kept sending the collector, and it is logging: neither is proof of delivery.
        assert sent_to_collector(r1, counting) > sent_before, f"{source}'s syslogd stopped sending the collector, so this proves nothing"
        assert "heartbeat" in r1.run("sh", "-c", "tail -n 5 /var/log/messages").stdout
        others = [x["labels"] for x in noc.notifications(since, alertname="SourceSilent")
                  if x["status"] == "firing" and x["labels"]["node"] != source]
        assert not others, f"other sources paged as silent: {others}"
    finally:
        for rule in rules:
            node(on).run("iptables", "-D", *rule, check=False)
        r1.run("iptables", "-D", *counting, check=False)
    # Restored without a reboot: the next line goes through.
    marker = f"NOT3-restored-{int(since)}"
    r1.run("logger", "-t", "netlab-testevent", marker)
    assert wait_for(lambda: noc.logs(f'{{node="{source}"}} |= "{marker}"', since), timeout=30, interval=1), "the line after the unblock never arrived"
    assert wait_resolved(noc, "SourceSilent", since, 30, node=source, source="syslog"), "no resolved notification"
    after = r1.run("sh", "-c", "for p in /proc/[0-9]*; do echo ${p#/proc/} $(tr '\\0' ' ' < $p/cmdline); done").stdout
    long_lived = {l for l in pids.splitlines() if "syslogd" in l or "/usr/lib/frr/" in l}
    assert long_lived <= set(after.splitlines()), f"processes on {source} changed: {sorted(long_lived - set(after.splitlines()))}"
    assert r1.run("cat", "/proc/1/stat").stdout.split()[21] == started, f"{source} was restarted"
