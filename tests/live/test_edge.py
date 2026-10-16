"""The edges we control (decision 0012): what the internet can reach, and who can forge a source address.

Counters are read before and after each probe, because other tests (and other runs) move them too.
"""
import ipaddress
import json
import shlex
import uuid
from contextlib import contextmanager
from pathlib import Path

from netlab.inventory import load

from .conftest import ROOT, wait_for
from .test_collection import playbook

TOOLS = Path(__file__).parent / "tools"
SCAN, SPOOF = (TOOLS / "scan.py").read_text(), (TOOLS / "spoof.py").read_text()
# What a management-port scan from the WAN side probes: SSH, telnet, HTTP, BGP, HTTPS, NETCONF,
# alternate HTTP and every FRR daemon's vty (2601 zebra ... 2617 bfdd). UDP is not scanned.
MANAGEMENT_PORTS = [22, 23, 80, 179, 443, 830, 8080, *range(2601, 2621)]
SCAN_TIMEOUT = 3  # seconds; a SYN that gets no answer in this time counts as filtered
FORGED = 5  # packets per probe


def scan(node, src, targets):
    """{"address:port": "open" | "closed" | "filtered"}, every target probed at once from src."""
    out = node.run("python3", "-", src, str(SCAN_TIMEOUT), json.dumps(targets), input=SCAN, timeout=30).stdout
    return json.loads(out)


def forge(node, src, dst, proto, port=0):
    node.run("python3", "-", src, dst, proto, str(port), str(FORGED), input=SPOOF)


def packets(node, table, chain, comment):
    """Exact packet count of the rule with this comment."""
    out = node.run("iptables", "-t", table, "-vnxL", chain).stdout
    counts = [int(line.split()[0]) for line in out.splitlines() if f"/* {comment} */" in line]
    assert counts, f"{node.name} has no rule '{comment}' in {table} {chain}"
    return counts[0]


def counted_since_now(node, table, chain, comment):
    """A function returning how many packets the rule has counted since this call."""
    start = packets(node, table, chain, comment)
    return lambda: packets(node, table, chain, comment) - start


@contextmanager
def arrivals(node, src):
    """Count the packets from src that reach node. A rule with no target only counts, so nothing changes."""
    mark = f"arrivals-{uuid.uuid4().hex[:8]}"
    rule = ["INPUT", "-s", src, "-m", "comment", "--comment", mark]
    node.run("iptables", "-I", *rule)
    try:
        yield lambda: packets(node, "filter", "INPUT", mark)
    finally:
        node.run("iptables", "-D", *rule, check=False)


def rp_filter_drops(node):
    """Packets this router dropped because their source failed the reverse-path check (TcpExt IPReversePathFilter)."""
    out = node.run("nstat", "-az", "TcpExtIPReversePathFilter").stdout
    return int(next(line.split()[1] for line in out.splitlines() if line.startswith("TcpExtIPReversePathFilter")))


def test_wan_scan_finds_only_published_ports(node, expected):
    """From the internet side nothing answers but the published web port, and from the peer's address r2's BGP port at most (allowed, not required); inside, the closed ports do answer."""
    wan = expected["wan_filter"]["r2"]
    targets = [[a, p] for addrs in expected["addresses"].values() for a in addrs for p in MANAGEMENT_PORTS]
    published = {f"{p['address']}:{p['port']}" for p in wan["published"]}
    sources = {s["peer"]: published | {f"{s['local']}:179"} for s in wan["bgp"]}  # the ISP's peer address
    sources[expected["loopbacks"]["isp"]] = published  # any other internet address: published ports only
    # The path works first (routing can still be settling right after a deploy), or a port missing
    # from the open set would prove nothing.
    first = wan["published"][0]
    assert wait_for(lambda: node("isp").tcp_open(first["address"], first["port"])), "the published port never answered"
    for src, allowed in sources.items():
        result = scan(node("isp"), src, targets)
        assert len(result) == len(targets), "the scan lost some targets"
        is_open = {t for t, state in result.items() if state == "open"}
        assert is_open <= allowed, f"from {src}, open beyond what is allowed: {sorted(is_open - allowed)}"
        # Published ports must answer. BGP from the peer's address may not: with a TCP-MD5 key on the
        # session, a SYN without the key gets no answer either, which is fine.
        assert published <= is_open, f"from {src}, published but not answering: {sorted(published - is_open)}"
    # Negative proof: from inside the campus (r3) the same scan finds h2's port 22 and r2's BGP on its
    # loopback open, so what the internet can't reach is filtered at the edge, not missing.
    inside = scan(node("r3"), "0.0.0.0", targets)
    must_answer = {f"{expected['hosts']['h2']}:22", f"{expected['loopbacks']['r2']}:179"}
    assert all(inside[t] == "open" for t in must_answer), f"not answering inside either: {[(t, inside[t]) for t in must_answer]}"


def test_lan_a_cannot_forge_its_source(node, expected):
    """fw1 drops what h1 sends as a server's address (TCP to the web port, ICMP to the internet); h1's real traffic passes."""
    fw1, h2, isp, forged = node("fw1"), node("h2"), node("isp"), "10.20.20.99"
    server, internet = expected["hosts"]["h2"], expected["loopbacks"]["isp"]
    # The path works first, or a missing packet would prove nothing.
    assert wait_for(lambda: node("h1").ping(internet, count=1)), "h1 can't reach the internet at all"
    dropped = counted_since_now(fw1, "raw", "PREROUTING", "anti-spoof-inside")
    with arrivals(h2, forged) as at_h2, arrivals(isp, forged) as at_isp:
        forge(node("h1"), forged, server, "tcp", 80)  # allow-web would forward this
        forge(node("h1"), forged, internet, "icmp")   # allow-icmp would forward this
        wait_for(lambda: dropped() + at_h2() + at_isp() >= 2 * FORGED, timeout=10, interval=0.5)
        assert (at_h2(), at_isp()) == (0, 0), f"forged packets arrived: h2 {at_h2()}, isp {at_isp()}"
    assert dropped() == 2 * FORGED, f"fw1's anti-spoof rule counted {dropped()}, expected {2 * FORGED}"
    assert wait_for(lambda: node("h1").tcp_open(server, 80) and node("h1").ping(internet, count=1), timeout=15), \
        "h1's real-source traffic should still pass"


def test_internet_cannot_forge_a_private_source(node, expected):
    """r2 drops what arrives from the ISP with a private source, even to the published port; the real source still connects."""
    r2, h2, isp = node("r2"), node("h2"), node("isp")
    server, wan = expected["hosts"]["h2"], expected["wan_filter"]["r2"]
    port = wan["published"][0]["port"]
    assert wait_for(lambda: isp.tcp_open(server, port)), "the published port doesn't answer the ISP at all"
    for bogon in wan["bogons"]:
        forged = str(ipaddress.ip_network(bogon).network_address + 99)
        dropped = counted_since_now(r2, "raw", "PREROUTING", f"bogon {bogon}")
        with arrivals(h2, forged) as at_h2:
            forge(isp, forged, server, "tcp", port)  # the published-port rule would forward this
            wait_for(lambda: dropped() + at_h2() >= FORGED, timeout=10, interval=0.5)
            assert at_h2() == 0, f"{at_h2()} packets from {forged} reached h2"
        assert dropped() == FORGED, f"r2's 'bogon {bogon}' rule counted {dropped()}, expected {FORGED}"
    assert wait_for(lambda: isp.tcp_open(server, port), timeout=15), "the ISP's real address should still reach the published port"


def test_server_lan_cannot_forge_its_source(node, expected):
    """r3's reverse-path filter drops what h2 sends as a LAN-A user; h2's real traffic to the internet passes."""
    r3, isp, forged = node("r3"), node("isp"), "10.10.10.99"
    internet = expected["loopbacks"]["isp"]
    # The kernel applies the higher of conf.all and conf.<interface>: 1 is strict, 2 loose, 0 off.
    mode = {i: max(int(r3.run("cat", f"/proc/sys/net/ipv4/conf/{c}/rp_filter").stdout) for c in ("all", i))
            for i in expected["rp_filter"]["r3"]}
    assert wait_for(lambda: node("h2").ping(internet, count=1)), "h2 can't reach the internet at all"
    before = rp_filter_drops(r3)
    with arrivals(isp, forged) as at_isp:
        forge(node("h2"), forged, internet, "icmp")  # nothing else on the way would stop it
        wait_for(lambda: rp_filter_drops(r3) - before + at_isp() >= FORGED, timeout=10, interval=0.5)
        assert at_isp() == 0, f"{at_isp()} packets from {forged} reached the ISP (r3 effective rp_filter: {mode})"
    assert rp_filter_drops(r3) - before >= FORGED, f"r3 didn't drop the forged packets (effective rp_filter: {mode})"
    assert mode == {i: 1 for i in mode}, f"r3's reverse-path filter is not strict everywhere it should be: {mode}"
    assert wait_for(lambda: node("h2").ping(internet, count=1), timeout=15), "h2's real-source traffic should still pass"


def rules_check(devices):
    """Only the iptables play of `make drift` for these devices; the routers' FRR checks are test_collection.py's job."""
    return playbook("drift.yml", "--limit", devices, "--start-at-task", "Pull the live ruleset")


def iptables_rules(node):
    return node.run("sh", "-c", "iptables -S; iptables -t raw -S; iptables -t nat -S").stdout


def delete_by_hand(node, table, chain, comment):
    """Delete the rule with this comment, as someone at the console would. Returns how to put it back where it was."""
    rules = [shlex.split(line) for line in node.run("iptables", "-t", table, "-S", chain).stdout.splitlines()
             if line.startswith("-A ")]
    found = [(i, r[2:]) for i, r in enumerate(rules, start=1) if comment in r]
    assert found, f"{node.name} has no rule '{comment}' in {table} {chain}"
    pos, spec = found[0]
    node.run("iptables", "-t", table, "-D", chain, *spec)
    return lambda: node.run("iptables", "-t", table, "-I", chain, str(pos), *spec, check=False)


def test_edge_filter_hand_change_is_flagged(node, expected):
    """A hole opened by hand in r2's internet filter, a translation added by hand to r2's NAT (the server LAN
    behind the users' address, decision 0031), and an anti-spoof rule deleted on r2 and on fw1, all fail the
    drift check, which names each."""
    edges = "r2,fw1"
    clean = rules_check(edges)
    assert clean.returncode == 0, "drift check fails on the clean lab, so a failure proves nothing:\n" + clean.stdout
    r2, fw1, mark = node("r2"), node("fw1"), f"hand-hole-{uuid.uuid4().hex[:8]}"
    wan = expected["wan_filter"]["r2"]
    bogon = f"bogon {wan['bogons'][0]}"
    rules_before = {n.name: iptables_rules(n) for n in (r2, fw1)}
    hole = ["FORWARD", "-i", wan["interface"], "-p", "tcp", "--dport", "22", "-j", "ACCEPT", "-m", "comment", "--comment", mark]
    translated = expected["nat"]["r2"]
    servers = str(ipaddress.IPv4Interface(load(ROOT / "inventory" / "network.yml").hosts["h2"]["address"]).network)
    widened = ["POSTROUTING", "-o", translated["interface"], "-s", servers, "-j", "SNAT", "--to-source", translated["address"]]
    named = f"+-A POSTROUTING -s {servers} -o {translated['interface']} -j SNAT --to-source {translated['address']}"
    put_back = []
    try:
        r2.run("iptables", "-I", *hole)
        r2.run("iptables", "-t", "nat", "-A", *widened)
        put_back.append(delete_by_hand(r2, "raw", "PREROUTING", bogon))
        put_back.append(delete_by_hand(fw1, "raw", "PREROUTING", "anti-spoof-inside"))
        drifted = rules_check(edges)
        assert drifted.returncode != 0, "drift check passed with a hole in r2's internet filter"
        unnamed = [change for change in (mark, named, bogon, "anti-spoof-inside") if change not in drifted.stdout]
        assert not unnamed, f"drift check failed but didn't name {unnamed}:\n" + drifted.stdout
    finally:
        r2.run("iptables", "-D", *hole, check=False)
        r2.run("iptables", "-t", "nat", "-D", *widened, check=False)
        for restore in put_back:
            restore()
    assert {n.name: iptables_rules(n) for n in (r2, fw1)} == rules_before, "the rules were not put back as they were"
