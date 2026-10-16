"""The DDoS lever (OROS REC-7, decision 0012): a remote-triggered blackhole at the ISP for one
attacked host, pulled from our edge router alone. The trigger line comes from expected_state.json."""
import ipaddress

from .conftest import wait_for


def bgp_hosts(isp, aggregate):
    """Campus prefixes in the ISP's BGP routes other than the aggregate: what RTBH sent it."""
    campus = ipaddress.ip_network(aggregate)
    return [p for p in isp.vtysh_json("show ip route bgp") if ipaddress.ip_network(p).subnet_of(campus) and p != aggregate]


def blackholed(isp, address):
    return isp.run("ip", "route", "show", address).stdout.startswith(f"blackhole {address} proto bgp")


def test_rtbh_blackholes_only_the_attacked_host(node, expected):
    """Tagging h2's route on r2 makes the ISP drop traffic to h2 alone; the campus still reaches h2, and untagging restores it."""
    rtbh = expected["rtbh"]
    isp, r2 = node(rtbh["provider"]), node(rtbh["customer"])
    target, trigger = expected["hosts"]["h2"], rtbh["triggers"]["h2"]
    port = next(p["port"] for p in expected["wan_filter"][rtbh["customer"]]["published"] if p["host"] == "h2")
    # Before: the internet reaches h2's published port, and the ISP has nothing but the aggregate.
    assert wait_for(lambda: isp.tcp_open(target, port)), "the ISP can't reach the published port even before the trigger"
    assert bgp_hosts(isp, rtbh["aggregate"]) == [], "a host route is already blackholed at the ISP"
    try:
        r2.run("vtysh", "-c", "conf t", "-c", trigger)
        assert wait_for(lambda: blackholed(isp, target), timeout=30, interval=0.5), "the ISP never blackholed the attacked host"
        path = isp.vtysh_json(f"show bgp ipv4 unicast {target}/32")["paths"][0]
        assert rtbh["community"] in path["community"]["string"], path
        assert path["nexthops"][0]["ip"] == rtbh["discard"], path
        assert bgp_hosts(isp, rtbh["aggregate"]) == [f"{target}/32"], "more than the attacked host got past the aggregate"
        assert not isp.tcp_open(target, port), "the ISP still forwards traffic to the blackholed host"
        # Only that /32: the next address on h2's LAN still routes to r2, and r2 itself answers.
        neighbour = str(ipaddress.ip_address(target) + 1)
        r2_side = expected["wan_filter"][rtbh["customer"]]["bgp"][0]["local"]
        assert f"via {r2_side}" in isp.run("ip", "route", "get", neighbour).stdout, f"{neighbour} no longer routes to r2"
        assert isp.ping(expected["loopbacks"][rtbh["customer"]]), "the ISP lost the rest of the campus"
        # Our side is untouched: the trigger's next hop is h2's real gateway, not Null0.
        assert r2.ping(target) and node("h1").tcp_open(target, port), "the campus lost h2 too"
    finally:
        r2.run("vtysh", "-c", "conf t", "-c", f"no {trigger}", check=False)
        lifted = wait_for(lambda: not blackholed(isp, target) and bgp_hosts(isp, rtbh["aggregate"]) == [], timeout=30, interval=0.5)
    assert lifted, "the blackhole stayed at the ISP after the trigger was removed"
    assert wait_for(lambda: isp.tcp_open(target, port)), "the ISP still can't reach h2 after the trigger was removed"
