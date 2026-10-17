"""Which switch port is this on? (OROS FND-4, decision 0032)

python -m netlab.where <address|mac|name> [--json]

One query joins the neighbor (ARP) tables of every router and firewall we own with the MAC tables of every
switch we own, read live and read-only (`ip -j neigh show`, `bridge -j fdb show`), and answers with the
switch, the port, the VLAN, whether the port is an edge port or an uplink, and what the inventory records
for that address: a host that has been moved shows on its new port with the recorded one beside it.
A polling cycle is one query: nothing is cached.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import switch
from .inventory import Inventory, load
from .locate import exec_on

ROOT = Path(__file__).resolve().parent.parent
MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def gateways(inv: Inventory) -> list[str]:
    """Where an address's MAC is known: every router and firewall we own."""
    return [d for d in [*inv.routers, *inv.firewalls] if inv.owner(d) == inv.operator]


def switches(inv: Inventory) -> list[str]:
    return [s for s in inv.switches if inv.owner(s) == inv.operator]


def read_json(inv: Inventory, lab: str, device: str, *cmd: str) -> list:
    out = subprocess.run(exec_on(inv, lab, device, *cmd), capture_output=True, text=True, timeout=30)
    try:
        return json.loads(out.stdout) if out.returncode == 0 else []
    except json.JSONDecodeError:
        return []


def neighbor_table(inv: Inventory, lab: str, gateway: str) -> list:
    """A gateway's ARP table: which MAC holds each address it has talked to."""
    return read_json(inv, lab, gateway, "ip", "-j", "neigh", "show")


def mac_table(inv: Inventory, lab: str, sw: str) -> list:
    """A switch's MAC table (FDB): the port, and with VLAN filtering the VLAN, each MAC was learned on."""
    return read_json(inv, lab, sw, "bridge", "-j", "fdb", "show", "br", inv.switches[sw]["bridge"])


def tables(inv: Inventory, lab: str) -> tuple[dict[str, list], dict[str, list]]:
    """({gateway: its neighbor table}, {switch: its MAC table}), every device read at once."""
    with ThreadPoolExecutor() as pool:
        neigh = {d: pool.submit(neighbor_table, inv, lab, d) for d in gateways(inv)}
        fdb = {s: pool.submit(mac_table, inv, lab, s) for s in switches(inv)}
        return {d: f.result() for d, f in neigh.items()}, {s: f.result() for s, f in fdb.items()}


def learned(fdb: list) -> list[dict]:
    """The MAC table's learned entries: not a port's own address (permanent) nor the bridge's (self)."""
    return [e for e in fdb if e.get("master") and e.get("state") != "permanent" and "self" not in (e.get("flags") or [])]


def recorded(inv: Inventory, address: str) -> dict | None:
    """What the inventory says about an address: the device and interface it is on, and the switch port
    the link puts that interface on (None when the interface is not on a switch)."""
    for link in inv.links:
        for ep, other in ((link.a, link.b), (link.b, link.a)):
            if ep.address and str(ep.address.ip) == address:
                port = f"{other.device}:{other.interface}" if other.device in inv.switches else None
                return {"device": ep.device, "interface": ep.interface, "port": port, "owner": inv.owner(ep.device),
                        "segment": inv.hosts.get(ep.device, {}).get("segment")}
    for r, v in inv.routers.items():
        if v["loopback"].split("/")[0] == address:
            return {"device": r, "interface": "lo", "port": None, "owner": inv.owner(r), "segment": None}
    return None


def resolve(inv: Inventory, query: str) -> tuple[str | None, str | None]:
    """(address, mac) for a query that is a name, an address or a MAC."""
    q = query.strip().lower()
    if MAC.match(q):
        return None, q
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", q):
        return q, None
    zone = (inv.raw.get("dns") or {}).get("zone")
    for fqdn, address in switch.names(inv).items():
        if q in (fqdn, fqdn.split(".")[0]) or (zone and q == f"{fqdn.split('.')[0]}.{zone}"):
            return address, None
    return None, None


def where(inv: Inventory, query: str, neigh: dict[str, list], fdbs: dict[str, list]) -> dict:
    """The answer, from the tables as read. Pure, so tests feed it canned tables."""
    address, mac = resolve(inv, query)
    answer = {"query": query, "address": address, "mac": mac, "known_to": [], "found": [], "inventory": None}
    if address is None and mac is None:
        answer["error"] = f"{query!r} is not an address, a MAC or a name the inventory knows"
        return answer
    # ARP: which MAC holds the address, and which gateway saw it. A FAILED or INCOMPLETE entry holds no MAC.
    for gateway, table in neigh.items():
        for e in table:
            if e.get("lladdr") and (address is None or e.get("dst") == address) and (mac is None or e["lladdr"].lower() == mac):
                answer["known_to"].append({"gateway": gateway, "interface": e.get("dev"), "state": " ".join(e.get("state") or [])})
                answer["mac"], answer["address"] = e["lladdr"].lower(), e.get("dst") if address is None else address
    if answer["mac"] is None:
        answer["error"] = (f"no router or firewall we own has {address} in its neighbor table: a router's own address has no "
                           f"ARP entry, and a host that hasn't spoken to its gateway lately has none either")
        return answer
    # The MAC tables: the port each switch learned that MAC on, with its VLAN and what the inventory says of the port.
    for s, fdb in fdbs.items():
        ports = inv.switch_ports(s)
        for e in learned(fdb):
            if e["mac"].lower() == answer["mac"]:
                spec = ports.get(e["ifname"], {})
                others = sorted({x["mac"] for x in learned(fdb) if x["ifname"] == e["ifname"]} - {e["mac"].lower()})
                answer["found"].append({"switch": s, "port": e["ifname"], "vlan": e.get("vlan"), "role": spec.get("role", "unknown"),
                                        "to": spec.get("to"), "other_macs_on_port": len(others)})
    if answer["address"]:
        answer["inventory"] = recorded(inv, answer["address"])
    rec = (answer["inventory"] or {}).get("port")
    answer["moved"] = bool(rec and answer["found"] and all(f"{f['switch']}:{f['port']}" != rec for f in answer["found"]))
    return answer


def summary(a: dict) -> str:
    if a.get("error"):
        return f"{a['query']}: {a['error']}"
    inv = a.get("inventory")
    lines = [f"{a['query']}: {a['address'] or '?'} is {a['mac']}" + (f", known to {', '.join(k['gateway'] + ' on ' + (k['interface'] or '?') for k in a['known_to'])}" if a["known_to"] else "")]
    for f in a["found"]:
        vlan = f"vlan {f['vlan']}" if f["vlan"] is not None else "vlan not filtered (plain bridge)"
        lines.append(f"  on {f['switch']} port {f['port']}, {vlan}, {f['role']} port" + (f" to {f['to']}" if f["to"] else "") +
                     (f", {f['other_macs_on_port']} other MAC(s) learned there" if f["other_macs_on_port"] else ""))
    if not a["found"]:
        lines.append("  on no switch port we own (not learned by any switch's MAC table)")
    if inv:
        lines.append(f"  inventory: {inv['device']}:{inv['interface']}" + (f" on {inv['port']}" if inv["port"] else "") +
                     (f", segment {inv['segment']}" if inv["segment"] else "") + f", owner {inv['owner']}" +
                     (" -- MOVED: not on its recorded port" if a.get("moved") else ""))
    else:
        lines.append("  inventory: nothing recorded for this address")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.where")
    p.add_argument("query", help="an address, a MAC or a device name")
    p.add_argument("--json", action="store_true")
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    inv = load(args.inventory)
    neigh, fdbs = tables(inv, switch.lab_name())
    answer = where(inv, args.query, neigh, fdbs)
    print(json.dumps(answer, indent=2) if args.json else summary(answer))
    return 1 if answer.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
