"""Control plane: are the protocols up and carrying the routes they should?"""
import ipaddress

from .conftest import wait_for


def full_neighbors(node, router):
    data = node(router).vtysh_json("show ip ospf neighbor")
    ids = set()
    # FRR keys the neighbor table by router ID.
    for router_id, nbr_list in data.get("neighbors", {}).items():
        if any(n.get("nbrState", "").startswith("Full") for n in nbr_list):
            ids.add(router_id)
    return ids


def test_ospf_adjacencies_are_full(node, expected):
    for router, peers in expected["ospf_neighbors"].items():
        want = {expected["loopbacks"][p] for p in peers}
        got = wait_for(lambda: (ids := full_neighbors(node, router)) == want and ids) or full_neighbors(node, router)
        assert got == want, f"{router}: expected Full adjacencies with {sorted(want)}, got {sorted(got)}"


def test_bgp_sessions_established(node, expected):
    for s in expected["bgp_sessions"]:
        def state():
            peers = node(s["router"]).vtysh_json("show bgp summary")["ipv4Unicast"]["peers"]
            return peers.get(s["address"], {}).get("state")
        assert wait_for(lambda: state() == "Established"), f"{s['router']} -> {s['peer']} is {state()}"


def test_every_loopback_is_in_every_ospf_routers_table(node, expected):
    for router in expected["ospf_neighbors"]:
        for lo in expected["loopbacks"].values():
            if lo.startswith("10.255."):
                # Look the /32 up as a key: a text search for 10.255.0.1 would also match 10.255.0.10.
                assert wait_for(lambda: f"{lo}/32" in node(router).vtysh_json("show ip route")), f"{router} has no route to {lo}"


def test_host_lans_are_passive(node, expected):
    """Every router interface toward a host LAN is OSPF passive: advertised, but no hello goes out to hosts."""
    for router, interfaces in expected["passive_interfaces"].items():
        for ifname in interfaces:
            info = node(router).vtysh_json(f"show ip ospf interface {ifname}")["interfaces"][ifname]
            assert info.get("timerPassiveIface") is True, f"{router} {ifname} sends OSPF hellos toward hosts"
            # Passive must not mean missing: the LAN is still in every other core router's table.
            lan = str(ipaddress.ip_interface(f"{info['ipAddress']}/{info['ipAddressPrefixlen']}").network)
            for other in expected["passive_interfaces"]:
                if other != router:
                    assert wait_for(lambda: lan in node(other).vtysh_json("show ip route ospf")), \
                        f"{other} has no OSPF route to {lan}"
    assert any(expected["passive_interfaces"].values()), "the inventory implies no passive interface"


def test_isp_sees_only_the_aggregate(node):
    routes = wait_for(lambda: node("isp").vtysh_json("show ip route bgp"))
    assert "10.0.0.0/8" in routes, "campus aggregate not advertised to the ISP"
    leaked = [p for p in routes if p.startswith("10.") and p != "10.0.0.0/8"]
    assert not leaked, f"more-specific campus prefixes leaked to the ISP: {leaked}"


def test_default_route_reaches_core_via_ospf(node):
    for router in ("r1", "r3"):
        def selected():
            routes = node(router).vtysh_json("show ip route 0.0.0.0/0").get("0.0.0.0/0", [])
            return next((r["protocol"] for r in routes if r.get("selected")), None)
        # Selected, not just present: a stray kernel default would win and silently bypass the edge.
        assert wait_for(lambda: selected() == "ospf"), f"{router} forwards default traffic via {selected()}, not OSPF"
