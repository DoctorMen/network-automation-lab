"""Resilience: lose a core link and traffic should reroute on its own."""
from .conftest import wait_for


def path_to(node, src, dst_prefix):
    route = node(src).vtysh_json(f"show ip route {dst_prefix}")[dst_prefix][0]
    return {hop["interfaceName"] for hop in route["nexthops"] if hop.get("active")}


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
