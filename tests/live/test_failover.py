"""Resilience: lose a core link and traffic should reroute on its own."""
import json
import time

from .conftest import wait_for

# A silent failure: r1's eth2 stays up but nothing crosses it in either direction, so OSPF
# alone only notices when its 40 s dead timer runs out. BFD (300 ms x 3) notices in 0.9 s.
SILENT = [("INPUT", "-i"), ("OUTPUT", "-o"), ("FORWARD", "-i"), ("FORWARD", "-o")]
# Measured from the first DROP rule to the new route: 0.80-1.20 s with BFD, 1.0-1.2 s with r1 and
# r3 capped at 0.2 CPU, 35.6-39.7 s without BFD. 3 s leaves room for a busy CI runner.
SILENT_REROUTE_BOUND = 3


def path_to(node, src, dst_prefix):
    route = node(src).vtysh_json(f"show ip route {dst_prefix}")[dst_prefix][0]
    return {hop["interfaceName"] for hop in route["nexthops"] if hop.get("active")}


def bfd_up(node, router):
    """BFD peers that are up, as {peer address: interface}. Empty when bfdd isn't running."""
    out = node(router).run("vtysh", "-c", "show bfd peers json", check=False)
    peers = json.loads(out.stdout) if out.returncode == 0 else []
    return {p["peer"]: p["interface"] for p in peers if p["status"] == "up"}


def test_traffic_survives_r1_r3_link_failure(node, expected):
    server = expected["hosts"]["h2"]
    assert wait_for(lambda: path_to(node, "r1", "10.20.20.0/24") == {"eth2"}), "r1 should normally reach LAN-B directly via r3"

    node("r1").run("ip", "link", "set", "eth2", "down")
    try:
        # OSPF reconverges through r2.
        assert wait_for(lambda: path_to(node, "r1", "10.20.20.0/24") == {"eth1"}, timeout=60), "r1 did not reroute via r2"
        assert wait_for(lambda: node("h1").ping(server)), "h1 lost the server after failover"
    finally:
        node("r1").run("ip", "link", "set", "eth2", "up")

    assert wait_for(lambda: path_to(node, "r1", "10.20.20.0/24") == {"eth2"}, timeout=90), "path did not fail back"


def test_bfd_sessions_up(node, expected):
    """Every OSPF link has a BFD session up, so a missing BFD config fails here rather than at the next silent failure."""
    for router, want in expected["bfd_peers"].items():
        assert wait_for(lambda: bfd_up(node, router) == want), f"{router}: BFD up with {bfd_up(node, router)}, expected {want}"


def test_silent_failure_reroutes_fast(node, expected):
    """A link that stays up but forwards nothing is routed around within seconds, not after the 40 s OSPF dead timer."""
    r1, server = node("r1"), expected["hosts"]["h2"]
    assert wait_for(lambda: path_to(node, "r1", "10.20.20.0/24") == {"eth2"}), "r1 should normally reach LAN-B directly via r3"

    start = time.monotonic()
    try:
        for chain, flag in SILENT:
            r1.run("iptables", "-I", chain, flag, "eth2", "-j", "DROP")
        # Still up, so this is the case link-down detection can't see.
        assert "state UP" in r1.run("ip", "link", "show", "eth2").stdout, "eth2 went down; this is no longer a silent failure"
        rerouted = wait_for(lambda: path_to(node, "r1", "10.20.20.0/24") == {"eth1"}, timeout=SILENT_REROUTE_BOUND, interval=0.1)
        took = time.monotonic() - start
        assert rerouted and took < SILENT_REROUTE_BOUND, f"r1 still sent LAN-B traffic into the silent link {took:.1f} s after it failed"
        print(f"rerouted in {took:.2f} s")
        assert wait_for(lambda: node("h1").ping(server), timeout=10), "h1 lost the server after the silent failure"
        # Web replies only pass fw1 as ESTABLISHED, so this shows the stateful path survived the reroute.
        assert node("h1").tcp_open(server, 80), "h1 lost the web server after the silent failure"
    finally:
        for chain, flag in SILENT:
            r1.run("iptables", "-D", chain, flag, "eth2", "-j", "DROP", check=False)
        # Wait even when the test failed, so the next test starts from a converged lab. Fail-back
        # needs the next OSPF hello (up to 10 s) and a fresh adjacency, then a new BFD session.
        failed_back = wait_for(lambda: path_to(node, "r1", "10.20.20.0/24") == {"eth2"}, timeout=90)

    assert failed_back, "path did not fail back"
    assert wait_for(lambda: bfd_up(node, "r1") == expected["bfd_peers"]["r1"]), "r1-r3 BFD session did not come back"
