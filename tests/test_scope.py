"""The edges and the toy payments scope are rendered from the inventory, and the validator refuses a
register the topology contradicts (decisions 0012 and 0013)."""
from netlab.inventory import load
from netlab.render import expected_state, render_edge, render_firewall, render_router

from test_inventory import INVENTORY, problems

inv = load(INVENTORY)


def test_every_device_has_a_scope_decision():
    """The shipped register classifies all seven devices, and every in-scope one names a clause."""
    scope = inv.raw["scope"]
    assert set(scope["systems"]) | set(scope["out_of_scope"]) == set(inv.devices)
    assert all(entry["clause"] for entry in scope["systems"].values())


CONTRADICTIONS = [
    # A server on the payments LAN that nobody registered.
    (lambda raw: raw["scope"]["systems"].pop("h2"), "scope: h2 has no scope decision"),
    (lambda raw: raw["scope"]["systems"]["r2"].pop("clause"), "scope: r2 has no clause"),
    # Whatever sits on the segment is a CDE system, whatever filters is in scope: no talking them out of it.
    (lambda raw: raw["scope"]["systems"]["r3"].update(category="connected-to"), "scope: r3 is on LAN-B, so it must be in systems as cde"),
    (lambda raw: (raw["scope"]["systems"].pop("fw1"), raw["scope"]["out_of_scope"].append("fw1")),
     "scope: fw1 filters traffic into the segment, so it must be in systems"),
    (lambda raw: raw["scope"].update(acceptance=""), "scope: no acceptance"),
    # A flow into the segment beyond the published ports needs its reason written down.
    (lambda raw: raw["scope"]["exceptions"][0].pop("why"), "scope: exception h1 icmp: no why"),
]


def test_register_the_topology_contradicts_is_refused(tmp_path):
    """An unregistered server, a missing clause, a CDE router or a filter called out of scope, an exception with no reason, or no acceptance: each is refused."""
    for mutate, problem in CONTRADICTIONS:
        assert problem in problems(tmp_path, mutate)


def test_segmentation_probes_every_out_of_scope_device():
    """Each out-of-scope device probes every service and pings every device on the segment: open only where published or excepted.
    h2's node_exporter, the NOC's listener there, is closed to each of them and named as a sidecar."""
    tuples = expected_state(inv)["segmentation"]
    assert {(t["src"], t["dst"], t["proto"], t.get("port"), t["expect"]) for t in tuples} == {
        ("h1", "h2", "tcp", 80, "open"), ("h1", "h2", "tcp", 22, "closed"), ("h1", "h2", "tcp", 9100, "closed"),
        ("h1", "h2", "icmp", None, "open"), ("h1", "r3", "icmp", None, "open"),
        ("isp", "h2", "tcp", 80, "open"), ("isp", "h2", "tcp", 22, "closed"), ("isp", "h2", "tcp", 9100, "closed"),
        ("isp", "h2", "icmp", None, "closed"), ("isp", "r3", "icmp", None, "closed")}
    assert {t["dst"]: t["inside"] for t in tuples} == {"h2": "r3", "r3": "h2"}
    assert {(t["src"], t["port"]) for t in tuples if t.get("sidecar") == "h2-node-exporter"} == {("h1", 9100), ("isp", 9100)}


def test_published_port_needs_a_listener(tmp_path):
    def m(raw):
        raw["hosts"]["h2"]["published"] = [80, 443]
    assert "h2: published port(s) [443] have no listener in services" in problems(tmp_path, m)


def test_wan_filter_lets_in_only_replies_ping_bgp_and_published_ports():
    """r2's edge.sh: private sources dropped first, then each chain accepts its short list and drops the rest on eth3."""
    lines = [l for l in render_edge(inv, "r2").splitlines() if l.startswith("iptables -A") or l.startswith("iptables -t raw -A")]
    raw = [l for l in lines if "-t raw" in l]
    assert [l.split(" -s ")[1].split()[0] for l in raw] == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    chain = {c: [l.split("--comment ")[1].strip('"') for l in lines if l.startswith(f"iptables -A {c} ")] for c in ("INPUT", "FORWARD")}
    assert chain == {"INPUT": ["wan-established", "wan-icmp", "bgp 198.51.100.1", "wan-drop-local"],
                     "FORWARD": ["wan-established", "publish h2:80", "wan-drop"]}
    assert all(" -i eth3 " in l for l in lines), "every rule must be bound to the ISP link"
    assert "-s 198.51.100.1 -d 198.51.100.0 --dport 179" in next(l for l in lines if '"bgp ' in l)
    assert "--syn -d 10.20.20.10 --dport 80" in next(l for l in lines if '"publish ' in l)


def test_anti_spoof_on_every_edge_we_control():
    """fw1 drops non-LAN-A sources on its inside interface; host LANs get strict uRPF; only edge routers get a script."""
    fw = render_firewall(inv, "fw1")
    assert 'iptables -t raw -A PREROUTING -i eth1 ! -s 10.10.10.0/24 -j DROP -m comment --comment "anti-spoof-inside"' in fw
    assert '-A FORWARD -i eth1 -s 10.10.10.0/24 -d 203.0.113.0/24 -j ACCEPT -m comment --comment "allow-internet"' in fw
    assert "sysctl -qw net.ipv4.conf.eth3.rp_filter=1" in render_edge(inv, "r3")
    assert render_edge(inv, "r1") is None and render_edge(inv, "isp") is None


def test_rtbh_is_lined_up_at_both_ends():
    """r2 can send a tagged /32 past the aggregate; the ISP turns only campus /32s with its community into a blackhole."""
    r2 = render_router(inv, "r2")["frr.conf"]
    assert "  redistribute static route-map RTBH-TRIGGER\n  neighbor 198.51.100.1 unsuppress-map RTBH-TRIGGER" in r2
    assert "route-map RTBH-TRIGGER permit 10\n match tag 666\n set community 65100:666" in r2
    isp = render_router(inv, "isp")["frr.conf"]
    assert " neighbor 198.51.100.0 disable-connected-check" in isp
    assert "ip prefix-list RTBH-HOSTS seq 5 permit 10.0.0.0/8 ge 32" in isp
    assert " set ip next-hop 192.0.2.1" in isp and "ip route 192.0.2.1/32 Null0" in isp
    # The trigger points at h2's real gateway, so r2 keeps forwarding to h2 itself.
    assert expected_state(inv)["rtbh"]["triggers"] == {"h2": "ip route 10.20.20.10/32 10.20.20.1 tag 666"}
    assert "RTBH" not in render_router(inv, "r1")["frr.conf"]


def test_rtbh_community_must_be_the_providers(tmp_path):
    def m(raw):
        raw["rtbh"]["community"] = "65001:666"
    assert "rtbh: community '65001:666' is not in the provider's AS 65100" in problems(tmp_path, m)
