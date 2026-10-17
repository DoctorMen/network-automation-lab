"""Where an address is, and what listens, against the inventory (OROS FND-4, decision 0032).

`netlab where` reads the gateways' neighbor tables and the switch's MAC table live, so one query is one
polling cycle; `netlab audit` reads each host's listeners. Both leave the lab as they found it."""
import json

import pytest

from netlab import audit as audit_tool
from netlab import where as where_tool
from netlab.inventory import load

from .conftest import ROOT, wait_for

INVENTORY = load(ROOT / "inventory" / "network.yml")


def ask(lab_name, query):
    neigh, fdbs = where_tool.tables(INVENTORY, lab_name)
    return where_tool.where(INVENTORY, query, neigh, fdbs)


def vlan_filtering(node, sw) -> bool:
    """switch.sh records whether this kernel gave the bridge VLAN filtering (V-033)."""
    return "vlan_filtering: on" in node(sw).run("cat", "/run/switch.state").stdout


def port_to(spec, far) -> str:
    return next(p for p, v in spec["ports"].items() if v["to"] == far)


def mac_of(node, host, iface) -> str:
    return json.loads(node(host).run("ip", "-j", "link", "show", iface).stdout)[0]["address"]


def test_moved_host_found_on_new_port(node, expected, lab_name):
    """h1 is found on its recorded edge port; moved to the spare port (its NIC, a new cable), the next query finds it there, flags the move against the record, and the old port no longer lists it."""
    sw, spec = next(iter(expected["switches"].items()))
    address, gateway = expected["hosts"]["h1"], INVENTORY.hosts["h1"]["gateway"]
    old, new = port_to(spec, "h1:eth1"), port_to(spec, "h1:eth2")
    assert wait_for(lambda: node("h1").ping(gateway, count=1)), "h1 can't reach its gateway, so no table can know it"
    before = ask(lab_name, address)
    assert not before.get("error"), before
    assert [(f["switch"], f["port"], f["role"], f["to"]) for f in before["found"]] == [(sw, old, "edge", "h1:eth1")], before
    assert before["inventory"]["port"] == f"{sw}:{old}" and not before["moved"]
    assert {k["gateway"] for k in before["known_to"]} == {"fw1"}, before["known_to"]
    if vlan_filtering(node, sw):
        assert before["found"][0]["vlan"] == spec["ports"][old]["vlan"]
    mac, spare_mac = mac_of(node, "h1", "eth1"), mac_of(node, "h1", "eth2")
    h1 = node("h1")
    try:
        # The move: the same machine (its MAC) on another port, as unplugging and plugging in elsewhere does.
        h1.run("ip", "link", "set", "eth1", "down")
        h1.run("ip", "link", "set", "eth2", "address", mac)
        h1.run("ip", "addr", "add", f"{address}/24", "dev", "eth2")
        h1.run("ip", "link", "set", "eth2", "up")
        h1.run("ip", "route", "replace", "default", "via", gateway)
        assert wait_for(lambda: h1.ping(gateway, count=1), timeout=30), "h1 can't reach its gateway from the new port"
        after = ask(lab_name, address)  # one query: the polling cycle
        assert [(f["switch"], f["port"], f["role"], f["to"]) for f in after["found"]] == [(sw, new, "edge", "h1:eth2")], after
        assert after["mac"] == mac and after["moved"], after
        if vlan_filtering(node, sw):
            assert after["found"][0]["vlan"] == spec["ports"][new]["vlan"]
        # A stale table would still show the old port: the bridge relearned the MAC where it now speaks from.
        fdb = where_tool.mac_table(INVENTORY, lab_name, sw)
        assert not [e for e in where_tool.learned(fdb) if e["mac"] == mac and e["ifname"] == old]
    finally:
        h1.run("ip", "link", "set", "eth2", "down", check=False)
        h1.run("ip", "addr", "flush", "dev", "eth2", check=False)
        h1.run("ip", "link", "set", "eth2", "address", spare_mac, check=False)
        h1.run("ip", "link", "set", "eth1", "up", check=False)
        h1.run("ip", "route", "replace", "default", "via", gateway, check=False)
        assert wait_for(lambda: h1.ping(gateway, count=1), timeout=30), "h1 did not come back on its own port"
    assert wait_for(lambda: [f["port"] for f in ask(lab_name, address)["found"]] == [old], timeout=30), "h1 is not back on its recorded port"


def test_the_answer_names_the_vlan(node, expected, lab_name):
    """With VLAN filtering on the bridge, the answer's VLAN is the port's VLAN from the inventory, and the port's pvid agrees; a kernel without it (V-033) skips this, the port and role are still proved above."""
    sw, spec = next(iter(expected["switches"].items()))
    if not vlan_filtering(node, sw):
        pytest.skip("this kernel refused `vlan_filtering 1` on the bridge (V-033); switch.sh fell back to a plain bridge, so no table has a VLAN to show")
    address = expected["hosts"]["h1"]
    port = port_to(spec, "h1:eth1")
    assert wait_for(lambda: node("h1").ping(INVENTORY.hosts["h1"]["gateway"], count=1))
    answer = ask(lab_name, address)
    assert [f["vlan"] for f in answer["found"]] == [spec["ports"][port]["vlan"]], answer
    vlans = json.loads(node(sw).run("bridge", "-j", "vlan", "show").stdout)
    pvid = next(v for e in vlans if e["ifname"] == port for v in e["vlans"] if "PVID" in v.get("flags", []))
    assert pvid["vlan"] == spec["ports"][port]["vlan"]


def run_audit(lab_name):
    hosts = audit_tool.hosts(INVENTORY)
    return audit_tool.audit(INVENTORY, {h: audit_tool.read(INVENTORY, lab_name, h) for h in hosts}, audit_tool.deployed(lab_name))


def test_unrecorded_service_on_next_audit(node, expected, lab_name):
    """A clean audit reports no mismatch and names the program behind each recorded port (h2:22 is python3, not an SSH server); a listener started on h2 without a record is in the next report, and gone from the one after it stops."""
    clean = run_audit(lab_name)
    assert not [r for r in clean if r["mismatch"]], [r for r in clean if r["mismatch"]]
    row = next(r for r in clean if r["host"] == "h2" and r["port"] == 22)
    assert row["recorded"] == "services" and row["program"] == "python3", row
    port = 8080
    assert not [r for r in clean if r["port"] == port], f"port {port} is already in use in the lab"
    pid = node("h2").run("sh", "-c", f"python3 -m http.server {port} >/dev/null 2>&1 & echo $!").stdout.strip()
    try:
        def reported():
            return next((r for r in run_audit(lab_name) if r["host"] == "h2" and r["port"] == port), None)
        found = wait_for(reported, timeout=30, interval=1)
        assert found and found["mismatch"] and found["listening"] and not found["recorded"], found
        assert found["program"] == "python3"
    finally:
        node("h2").run("kill", pid, check=False)
    assert wait_for(lambda: not [r for r in run_audit(lab_name) if r["mismatch"]], timeout=30, interval=1), "the audit still reports a mismatch after the listener stopped"
