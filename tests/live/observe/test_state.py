"""OROS NOT-1, state not ping: each object has its own check, and taking the object down while its host
still answers ping pages within the alert's stated bound (expected_state.json monitoring.alert_within).
Each test also shows the negative: the host kept answering, and no other object of the same kind alerted."""
import json
import re
import subprocess
import time
from datetime import datetime

import pytest

from ..conftest import wait_for
from .conftest import others_firing, quiet, wait_alert, wait_resolved


def vtysh_conf(node, *lines):
    node.run("vtysh", "-c", "conf t", *[a for line in lines for a in ("-c", line)])


def bgp_state(node, router, address):
    return node(router).vtysh_json("show bgp summary")["ipv4Unicast"]["peers"].get(address, {}).get("state")


def local_as(node, router):
    return node(router).vtysh_json("show bgp summary")["ipv4Unicast"]["as"]


def full(node, router, interface):
    nbrs = node(router).vtysh_json("show ip ospf neighbor")["neighbors"]
    return any(n["ifaceName"].startswith(interface + ":") and n["nbrState"].startswith("Full") for v in nbrs.values() for n in v)


def bfd_up(node, router, address):
    peers = json.loads(node(router).run("vtysh", "-c", "show bfd peers json").stdout)
    return any(p["peer"] == address and p["status"] == "up" for p in peers)


@pytest.fixture
def bgp_session(expected, mon):
    """Our end of the first BGP session the NOC watches, and the far end's view of it."""
    ours = mon["bgp_peers"][0]
    far = next(x for x in expected["bgp_sessions"] if x["router"] == ours["peer"] and x["peer"] == ours["node"])
    return ours, far


def shut(node, router, address):
    return lambda undo=False: vtysh_conf(node(router), f"router bgp {local_as(node, router)}",
                                         f"{'no ' if undo else ''}neighbor {address} shutdown")


def test_bgp_session_down_while_the_peer_pings(node, mon, noc, bgp_session):
    """The far end shuts the session (state 0): BGPSessionDown pages while the peer still answers r2's ping."""
    ours, far = bgp_session
    toggle = shut(node, far["router"], far["address"])
    quiet(noc, "BGPSessionDown", node=ours["node"], peer=ours["address"])
    since = time.time()
    toggle()
    try:
        assert wait_for(lambda: bgp_state(node, ours["node"], ours["address"]) != "Established", timeout=30, interval=0.5)
        down = time.time()
        page = wait_alert(noc, "BGPSessionDown", since, mon["alert_within"]["BGPSessionDown"] + 5, node=ours["node"], peer=ours["address"])
        assert page, f"no BGPSessionDown for {ours['node']} -> {ours['peer']} within {mon['alert_within']['BGPSessionDown']} s"
        assert page["received"] - down <= mon["alert_within"]["BGPSessionDown"], f"paged {page['received'] - down:.1f} s after the session went down"
        # From r2, across the link. (Not from the NOC: the carrier's only route back to the campus is the
        # aggregate it learns over this very session, so its replies to the NOC stop with it.)
        assert node(ours["node"]).ping(ours["address"]), f"{ours['peer']} stopped answering ping, so this proves nothing"
        assert noc.value(f'frr_bgp_peer_state{{node="{ours["node"]}",peer="{ours["address"]}"}}') == 0
    finally:
        toggle(undo=True)
    assert wait_for(lambda: bgp_state(node, ours["node"], ours["address"]) == "Established", timeout=90), "the session did not come back"
    assert wait_resolved(noc, "BGPSessionDown", since, 60, node=ours["node"], peer=ours["address"]), "no resolved notification"


def test_bgp_local_admin_shutdown_alerts_too(node, mon, noc, bgp_session):
    """Our own end shut (state 2, Idle (Admin)) pages as well: the rule is `!= 1`, and `== 0` would miss it."""
    ours, _ = bgp_session
    toggle = shut(node, ours["node"], ours["address"])
    quiet(noc, "BGPSessionDown", node=ours["node"], peer=ours["address"])
    since = time.time()
    toggle()
    try:
        page = wait_alert(noc, "BGPSessionDown", since, mon["alert_within"]["BGPSessionDown"] + 5, node=ours["node"], peer=ours["address"])
        assert page, "an administratively shut session did not page"
        assert page["received"] - since <= mon["alert_within"]["BGPSessionDown"] + 2
        assert noc.value(f'frr_bgp_peer_state{{node="{ours["node"]}",peer="{ours["address"]}"}}') == 2
        assert node(ours["node"]).ping(ours["address"]), "the peer stopped answering ping"
    finally:
        toggle(undo=True)
    assert wait_for(lambda: bgp_state(node, ours["node"], ours["address"]) == "Established", timeout=90), "the session did not come back"
    assert wait_resolved(noc, "BGPSessionDown", since, 60, node=ours["node"], peer=ours["address"]), "no resolved notification"


@pytest.fixture
def ospf_link(mon):
    """The first OSPF adjacency the inventory implies, and its other end."""
    a = mon["ospf_neighbors"][0]
    b = next(n for n in mon["ospf_neighbors"] if n["node"] == a["neighbor"] and n["neighbor"] == a["node"])
    return a, b


def test_ospf_neighbor_down_while_it_pings(node, expected, mon, noc, ospf_link):
    """OSPF dropped on one link (ping and BFD's packets untouched): OSPFNeighborDown pages for both ends of that
    adjacency and no other. (FRR then removes the link's BFD session, which OSPF owns, so BFDPeerDown may follow.)"""
    a, b = ospf_link
    rule = ["INPUT", "-i", a["interface"], "-p", "89", "-j", "DROP"]
    for end in (a, b):
        quiet(noc, "OSPFNeighborDown", node=end["node"], neighbor=end["neighbor"])
    since = time.time()
    node(a["node"]).run("iptables", "-I", *rule)
    try:
        # The adjacency ends when the dead interval runs out (40 s): nothing but OSPF's own hellos is lost.
        assert wait_for(lambda: not full(node, a["node"], a["interface"]), timeout=60, interval=1), "the adjacency never went down"
        down = time.time()
        for end in (a, b):
            page = wait_alert(noc, "OSPFNeighborDown", since, mon["alert_within"]["OSPFNeighborDown"] + 20,
                              node=end["node"], neighbor=end["neighbor"])
            assert page, f"no OSPFNeighborDown for {end['node']} -> {end['neighbor']}"
            assert page["received"] - down <= mon["alert_within"]["OSPFNeighborDown"] + 15, \
                f"{end['node']} paged {page['received'] - down:.1f} s after the adjacency went down"
        peer = next(p["address"] for p in mon["bfd_peers"] if p["node"] == a["node"] and p["neighbor"] == a["neighbor"])
        assert node(a["node"]).ping(peer), f"{a['neighbor']} stopped answering ping"
        link = {(a["node"], a["neighbor"]), (b["node"], b["neighbor"])}
        others = [x["labels"] for x in noc.notifications(since, alertname="OSPFNeighborDown")
                  if x["status"] == "firing" and (x["labels"]["node"], x["labels"]["neighbor"]) not in link]
        assert not others, f"adjacencies on other links paged: {others}"
    finally:
        node(a["node"]).run("iptables", "-D", *rule, check=False)
    assert wait_for(lambda: full(node, a["node"], a["interface"]), timeout=90), "the adjacency did not come back"
    assert wait_resolved(noc, "OSPFNeighborDown", since, 60, node=a["node"], neighbor=a["neighbor"]), "no resolved notification"


def test_bfd_peer_down_while_ospf_and_ping_stay_up(node, mon, noc, ospf_link):
    """BFD dropped on one link: BFDPeerDown pages for that peer while OSPF re-forms and the peer pings."""
    a, _ = ospf_link
    peer = next(p for p in mon["bfd_peers"] if p["node"] == a["node"] and p["neighbor"] == a["neighbor"])
    rule = ["INPUT", "-i", a["interface"], "-p", "udp", "--dport", "3784", "-j", "DROP"]
    # The OSPF test before this one takes the same link's BFD session down with its adjacency.
    quiet(noc, "BFDPeerDown", node=a["node"], peer=peer["address"])
    assert wait_for(lambda: bfd_up(node, a["node"], peer["address"]), timeout=30), "BFD was not up before the test"
    since = time.time()
    node(a["node"]).run("iptables", "-I", *rule)
    try:
        assert wait_for(lambda: not bfd_up(node, a["node"], peer["address"]), timeout=20, interval=0.5), "BFD never went down"
        down = time.time()
        page = wait_alert(noc, "BFDPeerDown", since, mon["alert_within"]["BFDPeerDown"] + 5, node=a["node"], peer=peer["address"])
        assert page, f"no BFDPeerDown for {a['node']} -> {peer['address']}"
        assert page["received"] - down <= mon["alert_within"]["BFDPeerDown"], f"paged {page['received'] - down:.1f} s after BFD went down"
        assert node(a["node"]).ping(peer["address"]), "the peer stopped answering ping"
        # FRR ends the adjacency once when BFD goes down, then OSPF hellos bring it straight back.
        assert wait_for(lambda: full(node, a["node"], a["interface"]), timeout=30), "OSPF did not re-form while BFD was down"
    finally:
        node(a["node"]).run("iptables", "-D", *rule, check=False)
    assert wait_for(lambda: bfd_up(node, a["node"], peer["address"]), timeout=30), "BFD did not come back"
    assert wait_resolved(noc, "BFDPeerDown", since, 60, node=a["node"], peer=peer["address"]), "no resolved notification"


def server_pid(host, port):
    ps = host.run("ps", "-o", "pid,args").stdout.splitlines()
    return next((l.split()[0] for l in ps if l.split()[1:] == ["python3", "-m", "http.server", str(port)]), None)


def test_web_page_with_the_wrong_content_alerts(node, mon, noc):
    """h2:80 still answers 200 with a directory listing, but of an empty folder: WebContentWrong pages; ping and the TCP port stay up."""
    check = mon["web"][0]
    host = node(check["host"])
    app = next((a for a in mon["apps"] if a["host"] == check["host"] and a["port"] == check["port"]), None)
    log = f"/applog/{app['name']}-{app['port']}.log" if app else "/dev/null"

    def serve(folder):
        old = server_pid(host, check["port"])
        if old:
            host.run("kill", old)
        assert wait_for(lambda: server_pid(host, check["port"]) is None, timeout=10, interval=0.2)
        # The way the topology starts it: from a folder, stdout away, the access log where the forwarder reads it.
        subprocess.run(["docker", "exec", "-d", host.container, "sh", "-c",
                        f"cd {folder} && exec python3 -m http.server {check['port']} >/dev/null 2>>{log}"], check=True)
        assert wait_for(lambda: host.tcp_open("127.0.0.1", check["port"]), timeout=10, interval=0.2), "the server did not start"

    host.run("mkdir", "-p", "/tmp/empty-docroot")
    quiet(noc, "WebContentWrong", node=check["host"])
    since = time.time()
    serve("/tmp/empty-docroot")
    try:
        page = wait_alert(noc, "WebContentWrong", since, mon["alert_within"]["WebContentWrong"] + 5, node=check["host"])
        assert page, "a page without the expected content did not page"
        assert page["received"] - since <= mon["alert_within"]["WebContentWrong"] + 2
        assert noc.value(f'probe_http_status_code{{job="web",node="{check["host"]}"}}') == 200, "the page should still answer 200"
        assert noc.value(f'probe_success{{job="icmp",node="{check["host"]}"}}') == 1, "h2 stopped answering ping"
    finally:
        serve("/")
    assert wait_resolved(noc, "WebContentWrong", since, 60, node=check["host"]), "no resolved notification"


def halfway_between_scrapes(noc, interval, **labels):
    """Sleep until halfway between two scrapes of this target. Prometheus scrapes a target at a fixed offset,
    so its last scrape says when the next ones come; a change made here is as far from both as it can be."""
    target = next(t for t in noc.targets() if all(t["labels"].get(k) == v for k, v in labels.items()))
    # Prometheus writes nanoseconds; Python reads at most microseconds.
    last = datetime.fromisoformat(re.sub(r"(\.\d{6})\d*", r"\1", target["lastScrape"]).replace("Z", "+00:00")).timestamp()
    time.sleep((last + interval / 2 - time.time()) % interval)


def test_sub_second_flap_alerts_although_no_scrape_saw_it_down(node, mon, noc):
    """An interface down for 0.3 s between two scrapes: InterfaceFlapped pages from the carrier-change counter,
    though every scrape saw the carrier up; no other interface or router pages."""
    # r1's link to fw1: no other live test takes it down.
    router, device = "r1", "eth3"
    assert router in mon["exporters"]
    quiet(noc, "InterfaceFlapped", node=router, device=device)
    # Timed, not left to chance: at a random moment a scrape lands inside the 0.3 s in about 1 run in 17.
    halfway_between_scrapes(noc, mon["interval"], job="node", node=router)
    since = time.time()
    node(router).run("sh", "-c", f"ip link set {device} down && sleep 0.3 && ip link set {device} up")
    page = wait_alert(noc, "InterfaceFlapped", since, mon["alert_within"]["InterfaceFlapped"] + 5, node=router, device=device)
    assert page, f"a 0.3 s flap on {router} {device} did not page"
    assert page["received"] - since <= mon["alert_within"]["InterfaceFlapped"] + 2
    window = f"{int(time.time() - since) + 5}s"
    assert noc.value(f'min_over_time(node_network_carrier{{node="{router}",device="{device}"}}[{window}])') == 1, \
        "a scrape saw the link down, so this flap was not shorter than the check interval"
    assert not others_firing(noc, "InterfaceFlapped", since, node=router, device=device)


def test_reboot_pending_past_its_window_alerts(node, mon, noc):
    """A newer kernel installed on r2: no alert inside the reboot window, PendingRebootOverdue once it is older than the window."""
    r2 = node("r2")
    running = r2.run("uname", "-r").stdout.strip()
    newer = f"{int(running.split('.')[0]) + 1}.0.0"  # the next major release: newer by netlab.kernel's rule
    quiet(noc, "PendingRebootOverdue", node="r2")
    since = time.time()
    r2.run("mkdir", "-p", f"/lib/modules/{running}", f"/lib/modules/{newer}")
    try:
        assert wait_for(lambda: noc.value('node_reboot_required{node="r2"}') == 1, timeout=mon["alert_within"]["PendingRebootOverdue"] + 5,
                        interval=1), "r2's pending reboot never reached the NOC"
        time.sleep(2 * mon["interval"])  # two more evaluations: still inside the window, so nothing fires
        assert not noc.alerts(state=None, alertname="PendingRebootOverdue", node="r2"), "alerted inside the reboot window"
        # Now make that kernel older than the window, as if nobody rebooted.
        old = time.time() - mon["reboot_window"] - 60
        r2.run("touch", "-d", f"@{old:.0f}", f"/lib/modules/{newer}")
        aged = time.time()
        page = wait_alert(noc, "PendingRebootOverdue", since, mon["alert_within"]["PendingRebootOverdue"] + 5, node="r2")
        assert page, "a reboot pending past its window did not page"
        assert page["received"] - aged <= mon["alert_within"]["PendingRebootOverdue"]
    finally:
        r2.run("rm", "-rf", "/lib/modules")
    assert wait_resolved(noc, "PendingRebootOverdue", since, 60, node="r2"), "no resolved notification"
