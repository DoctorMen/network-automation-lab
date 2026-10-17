"""The switch (decision 0032): rendered from the inventory and refused when the links contradict it; the where,
audit and trace tools, fed canned device tables, answer what the live tests then prove on the lab."""
import yaml

from netlab import audit, trace, where
from netlab.inventory import load
from netlab.render import _env, expected_state, render_all
from netlab.switch import render as render_switch
from netlab.switch import storm_commands

from test_inventory import INVENTORY, problems

inv = load(INVENTORY)
SW = next(iter(inv.switches))


def test_switch_renders_a_vlan_bridge_with_storm_control_on_edge_ports():
    """switch.sh bridges every port as an access port in its VLAN, falls back to a plain bridge only when the kernel refuses filtering, and polices broadcast on edge ports only, once per ingress frame."""
    script = render_switch(inv, SW, _env())
    assert "ip link add br0 type bridge vlan_filtering 1" in script and "ip link add br0 type bridge\n" in script
    for port, p in inv.switch_ports(SW).items():
        assert f"ip link set {port} master br0" in script
        assert f"bridge vlan add dev {port} vid {p['vlan']} pvid untagged" in script
    rules = [l for l in script.splitlines() if l.startswith("ebtables -t nat -A")]
    edge = [p for p, v in inv.switch_ports(SW).items() if v["role"] == "edge"]
    assert [l.split(" -i ")[1].split()[0] for l in rules] == [p for p in edge for _ in (0, 1)]
    assert all(" PREROUTING " in l and " -d ff:ff:ff:ff:ff:ff " in l for l in rules), "polices once per ingress frame, broadcast only"
    assert not [l for l in rules if " -i eth1 " in l], "the uplink carries the gateway's own broadcasts and is not policed"
    assert rules[0].endswith("--limit 100/sec --limit-burst 100 -j ACCEPT") and rules[1].endswith("-j DROP")
    assert [" ".join(c) for c in storm_commands(inv, SW, "eth3", "-A")] == rules[2:4], "make contain adds exactly what switch.sh renders"


def test_switch_ports_and_the_spare_port_come_from_the_links():
    """Each port's far end and role (edge toward a host, uplink otherwise) come from the links; h1's unaddressed second port is a spare the topology leaves down; the switch probes nothing in the scope test."""
    ports = inv.switch_ports(SW)
    assert ports["eth1"] == {"vlan": 10, "to": "fw1:eth1", "role": "uplink"}
    assert ports["eth2"] == {"vlan": 10, "to": "h1:eth1", "role": "edge"}
    assert ports["eth4"] == {"vlan": 10, "to": "h1:eth2", "role": "edge"}
    e = expected_state(inv)
    assert e["switches"][SW]["ports"] == ports and e["switches"][SW]["storm_control"] == {"broadcast_pps": 100}
    assert SW not in {t["src"] for t in e["segmentation"]} and "h3" in {t["src"] for t in e["segmentation"]}
    assert "h3" in e["hosts"] and e["owners"][SW] == inv.operator


def test_topology_starts_the_switch_and_leaves_the_spare_port_down(tmp_path):
    render_all(inv, tmp_path)
    nodes = yaml.safe_load((tmp_path / "topology.clab.yml").read_text())["topology"]["nodes"]
    assert nodes[SW]["exec"] == ["sh /switch.sh"] and nodes[SW]["binds"] == [f"{SW}/switch.sh:/switch.sh:ro"]
    assert nodes[SW]["entrypoint"] == "sh" and "image" not in nodes[SW], "the switch runs the one pinned image, like fw1"
    assert "ip link set eth2 down" in nodes["h1"]["exec"] and not [s for s in nodes["h3"]["exec"] if "link set" in s]
    assert (tmp_path / SW / "switch.sh").exists()


CONTRADICTIONS = [
    (lambda raw: raw["switches"]["sw1"]["ports"].update(eth9={"vlan": 10}), "sw1: port eth9 is on no link"),
    (lambda raw: raw["switches"]["sw1"]["ports"].pop("eth3"), "sw1: sw1:eth3 is on a link but not in its ports"),
    # Two subnets in one VLAN is one broadcast domain with two addressing plans: the addresses would lie about the domain.
    (lambda raw: raw["links"].__setitem__(7, ["h3:eth1@10.20.20.11/24", "sw1:eth3"]), "sw1: vlan 10 has ports in more than one subnet"),
    (lambda raw: raw["switches"]["sw1"]["ports"]["eth3"].update(vlan=20), "sw1: vlans 10 and 20 share a subnet, so they are one broadcast domain, not two"),
    (lambda raw: raw["switches"]["sw1"]["ports"]["eth3"].update(vlan=0), "sw1: port eth3 vlan 0 must be 1 to 4094"),
    (lambda raw: raw["links"].__setitem__(0, ["r1:eth1", "r2:eth1@10.0.12.1/31"]),
     "link r1<->r2: r1:eth1 has no address, and only a switch port, or a port into a switch, may go without"),
    (lambda raw: raw["links"].__setitem__(5, ["fw1:eth1@10.10.10.1/24", "sw1:eth1@10.10.10.2/24"]), "sw1:eth1 is a switch port, which has no address"),
    (lambda raw: raw["switches"]["sw1"].update(storm_control={"broadcast_pps": "fast"}),
     "sw1: storm_control broadcast_pps 'fast' must be a whole number of frames a second over 0"),
]


def test_a_switch_the_links_contradict_is_refused(tmp_path):
    """A port on no link, a link to no port, two subnets in a VLAN, two VLANs on one subnet, a bad VLAN, an address missing or present where it mustn't be, a storm limit that isn't a count: each is refused."""
    for mutate, problem in CONTRADICTIONS:
        assert problem in problems(tmp_path, mutate), problem


H1_MAC, H3_MAC, FW_MAC = "86:f5:5f:a5:b8:26", "e2:6e:fa:41:7b:44", "0a:11:22:33:44:55"
NEIGH = {"fw1": [{"dst": "10.10.10.10", "dev": "eth1", "lladdr": H1_MAC, "state": ["REACHABLE"]},
                 {"dst": "10.10.10.11", "dev": "eth1", "lladdr": H3_MAC, "state": ["STALE"]},
                 {"dst": "10.10.10.12", "dev": "eth1", "state": ["FAILED"]}],
         "r1": [{"dst": "10.0.12.1", "dev": "eth1", "lladdr": "0a:00:00:00:00:02", "state": ["REACHABLE"]}]}


def fdb(h1_port):
    return [{"mac": "01:00:5e:00:00:01", "ifname": "br0", "flags": ["self"], "state": "permanent"},
            {"mac": "aa:aa:aa:aa:aa:01", "ifname": "eth1", "flags": [], "master": "br0", "state": "permanent"},
            {"mac": FW_MAC, "ifname": "eth1", "flags": [], "master": "br0", "vlan": 10, "state": ""},
            {"mac": H1_MAC, "ifname": h1_port, "flags": [], "master": "br0", "vlan": 10, "state": ""},
            {"mac": H3_MAC, "ifname": "eth3", "flags": [], "master": "br0", "vlan": 10, "state": ""}]


def test_where_joins_the_neighbor_table_with_the_mac_table():
    """An address, a name or a MAC is answered with the switch, port, VLAN and role from the live tables and the record from the inventory; the same host learned on another port is flagged as moved; a FAILED neighbor entry, or a router's own address, has no MAC to find."""
    a = where.where(inv, "10.10.10.10", NEIGH, {SW: fdb("eth2")})
    assert a["mac"] == H1_MAC and [k["gateway"] for k in a["known_to"]] == ["fw1"]
    assert a["found"] == [{"switch": SW, "port": "eth2", "vlan": 10, "role": "edge", "to": "h1:eth1", "other_macs_on_port": 0}]
    assert a["inventory"] == {"device": "h1", "interface": "eth1", "port": "sw1:eth2", "owner": "campus NOC", "segment": "LAN-A"} and not a["moved"]
    assert where.where(inv, "h1", NEIGH, {SW: fdb("eth2")})["found"] == a["found"]
    assert where.where(inv, H1_MAC, NEIGH, {SW: fdb("eth2")})["address"] == "10.10.10.10"
    moved = where.where(inv, "h1.lab", NEIGH, {SW: fdb("eth4")})
    assert moved["found"][0]["port"] == "eth4" and moved["found"][0]["to"] == "h1:eth2" and moved["moved"]
    assert "MOVED" in where.summary(moved) and "uplink" in where.summary(where.where(inv, FW_MAC, NEIGH, {SW: fdb("eth2")}))
    assert "no router or firewall we own has 10.10.10.12" in where.where(inv, "10.10.10.12", NEIGH, {SW: fdb("eth2")})["error"]
    assert "no router or firewall" in where.where(inv, "r1", NEIGH, {SW: fdb("eth2")})["error"]
    assert "is not an address" in where.where(inv, "nothing", NEIGH, {})["error"]


SS = ('LISTEN 0      5      0.0.0.0:80 0.0.0.0:* users:(("python3",pid=7,fd=3))\n'
      'LISTEN 0      5      0.0.0.0:22 0.0.0.0:* users:(("python3",pid=8,fd=3))\n'
      'LISTEN 0      4096   10.20.20.10:9100 0.0.0.0:*\n'
      'LISTEN 0      5      0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=99,fd=3))\n'
      'LISTEN 0      128    127.0.0.1:9095 0.0.0.0:* users:(("python3",pid=9,fd=4))\n')


def test_audit_reports_what_the_record_lacks_and_what_is_missing():
    """Against the inventory's services and the sidecar ports it implies: an unrecorded listener and a recorded port with nothing behind it are mismatches, a sidecar's port is named by its sidecar, a loopback-only listener is reported and not judged, and the stand-in on port 22 is named as python3."""
    rows = audit.audit(inv, {"h2": audit.listeners(SS), "h1": {}})
    by = {(r["host"], r["port"]): r for r in rows}
    assert by[("h2", 8080)]["mismatch"] and by[("h2", 8080)]["recorded"] is None and by[("h2", 8080)]["program"] == "python3"
    assert by[("h2", 22)] == {"host": "h2", "port": 22, "recorded": "services", "listening": True, "program": "python3", "local": False, "mismatch": False}
    assert by[("h2", 9100)]["program"] == "h2-node-exporter (sidecar)" and not by[("h2", 9100)]["mismatch"]
    assert by[("h2", 9095)]["local"] and not by[("h2", 9095)]["mismatch"]
    assert ("h1", 80) not in by, "a host with no services and nothing listening has no rows"
    gone = audit.audit(inv, {"h2": audit.listeners(SS.splitlines()[0] + "\n")})
    assert [(r["port"], r["mismatch"], r["listening"]) for r in gone] == [(22, True, False), (80, False, True), (9100, True, False)]
    assert "MISMATCH h2 tcp/8080: listening (python3), not in the inventory" in audit.summary(rows)
    assert "MISMATCH h2 tcp/22: in the inventory (services), nothing listening" in audit.summary(gone)


def test_trace_names_the_port_the_storm_comes_in_on():
    """From two readings of the ports' frame counters, the port whose inbound rate is over the threshold is the source, named with its far end, role, learned MACs and the storm control's drop count; ports that only carry copies out are not."""
    before = {p: {"rx": 1000, "tx": 1000} for p in inv.switch_ports(SW)}
    after = {p: {"rx": 1000 + (40000 if p == "eth3" else 20), "tx": 1000 + (0 if p == "eth3" else 39800)} for p in before}
    rate = trace.rates(before, after, 2)
    assert rate["eth3"] == {"rx_pps": 20000, "tx_pps": 0} and rate["eth1"] == {"rx_pps": 10, "tx_pps": 19900}
    f = trace.trace(inv, SW, rate, fdb("eth2"), {"eth3": 59001, "eth2": 0}, trace.threshold(inv, SW, None))
    assert f["threshold_pps"] == 1000
    assert f["storm_from"] == [{"port": "eth3", "rx_pps": 20000, "tx_pps": 0, "role": "edge", "to": "h3:eth1", "vlan": 10, "macs": [H3_MAC], "dropped": 59001}]
    assert "STORM from sw1:eth3 (edge port to h3:eth1): 20000/s in; source MAC(s) " + H3_MAC in trace.summary({**f, "seconds": 2})
    quiet = trace.trace(inv, SW, trace.rates(before, before, 2), fdb("eth2"), {}, 1000)
    assert quiet["storm_from"] == [] and "no storm" in trace.summary({**quiet, "seconds": 2})
