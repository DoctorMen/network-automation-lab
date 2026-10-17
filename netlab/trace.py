"""Trace a storm to its port before anything is blocked (OROS CON-1, decision 0033).

python -m netlab.trace [--seconds N] [--threshold PPS] [--json]

On every switch we own, the frame counters of every port are read twice, `seconds` apart (`ip -s -j link`),
and each port's inbound rate is compared with the threshold. The port the flood comes in on is the one
whose inbound rate is above it; the others only carry copies out. The report names that port, what the
inventory says hangs off it, the MACs the switch learned there (the source), and how many frames the
port's storm control has dropped so far (`ebtables -t nat -L PREROUTING --Lc`), and says why the frames
reach every port: a broadcast is flooded to every port of its VLAN by design. Exit 1 when a port is over
the threshold, so a script can tell. The stated time to a port is 15 minutes (docs/runbooks/broadcast-storm.md);
one run of this takes `seconds` plus a few.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

from . import switch
from .inventory import Inventory, load
from .locate import exec_on
from .where import learned, mac_table

ROOT = Path(__file__).resolve().parent.parent
SECONDS = 2
# Frames a second a port may take in before it is a storm: ten times the inventory's storm control limit, so a
# policed port under a storm (at the limit plus its burst) still reads as the one being stormed from (its counter
# counts frames before the policer drops them); a port with no limit gets 1000 a second.
THRESHOLD_FACTOR = 10
DEFAULT_THRESHOLD = 1000
DROPS = re.compile(r"^-d Broadcast -i (\S+) -j DROP , pcnt = (\d+)", re.M)


def counters(inv: Inventory, lab: str, sw: str) -> dict[str, dict]:
    """{port: {rx, tx}} frame counters of a switch's ports, from `ip -s -j link show`."""
    ports = inv.switch_ports(sw)
    out = subprocess.run(exec_on(inv, lab, sw, "ip", "-s", "-j", "link", "show"), capture_output=True, text=True, timeout=30, check=True)
    return {e["ifname"]: {"rx": e["stats64"]["rx"]["packets"], "tx": e["stats64"]["tx"]["packets"]}
            for e in json.loads(out.stdout) if e["ifname"] in ports}


def drops(inv: Inventory, lab: str, sw: str) -> dict[str, int]:
    """{port: frames its storm control dropped}, from the switch's ebtables counters; {} without storm control."""
    out = subprocess.run(exec_on(inv, lab, sw, "ebtables", "-t", "nat", "-L", "PREROUTING", "--Lc"), capture_output=True, text=True, timeout=30)
    return {port: int(n) for port, n in DROPS.findall(out.stdout)}


def rates(before: dict[str, dict], after: dict[str, dict], seconds: float) -> dict[str, dict]:
    """{port: {rx_pps, tx_pps}} from two readings of the counters."""
    return {p: {"rx_pps": round((after[p]["rx"] - before[p]["rx"]) / seconds), "tx_pps": round((after[p]["tx"] - before[p]["tx"]) / seconds)}
            for p in before if p in after}


def threshold(inv: Inventory, sw: str, given: int | None) -> int:
    storm = inv.switches[sw].get("storm_control")
    return given or (storm["broadcast_pps"] * THRESHOLD_FACTOR if storm else DEFAULT_THRESHOLD)


def trace(inv: Inventory, sw: str, rate: dict[str, dict], fdb: list, dropped: dict[str, int], limit: int) -> dict:
    """The finding for one switch: every port over the threshold, named with what the inventory says is there
    and the MACs learned on it. Pure, so tests feed it canned readings."""
    ports = inv.switch_ports(sw)
    found = []
    for port, r in sorted(rate.items(), key=lambda x: -x[1]["rx_pps"]):
        if r["rx_pps"] > limit:
            macs = sorted({e["mac"] for e in learned(fdb) if e["ifname"] == port})
            found.append({"port": port, **r, "role": ports[port]["role"], "to": ports[port]["to"], "vlan": ports[port]["vlan"],
                          "macs": macs, "dropped": dropped.get(port)})
    return {"switch": sw, "threshold_pps": limit, "storm_from": found,
            "ports": {p: {**r, "role": ports[p]["role"], "to": ports[p]["to"]} for p, r in rate.items()},
            "why": "a broadcast frame is flooded to every other port of its VLAN by design, so every port carries the storm out; "
                   "only the source port carries it in"}


def summary(f: dict) -> str:
    lines = [f"{f['switch']}: inbound frames a second per port over {f['seconds']} s (threshold {f['threshold_pps']}/s)"]
    for p, r in sorted(f["ports"].items()):
        lines.append(f"  {p:<6} in {r['rx_pps']:>8}/s  out {r['tx_pps']:>8}/s  {r['role']}" + (f" to {r['to']}" if r["to"] else ""))
    for s in f["storm_from"]:
        who = ", ".join(s["macs"]) or "no MAC learned yet"
        lines.append(f"STORM from {f['switch']}:{s['port']} ({s['role']} port" + (f" to {s['to']}" if s["to"] else "") + f"): {s['rx_pps']}/s in; "
                     f"source MAC(s) {who}" + (f"; storm control has dropped {s['dropped']} frames there" if s["dropped"] is not None else "; no storm control on this port"))
    if not f["storm_from"]:
        lines.append("  no port over the threshold: no storm")
    lines.append(f"  why every port sees it: {f['why']}")
    return "\n".join(lines)


def measure(inv: Inventory, lab: str, sw: str, seconds: float, limit: int | None) -> dict:
    """Two readings `seconds` apart, the MAC table and the drop counters, judged by trace()."""
    before = counters(inv, lab, sw)
    time.sleep(seconds)
    after = counters(inv, lab, sw)
    return {**trace(inv, sw, rates(before, after, seconds), mac_table(inv, lab, sw), drops(inv, lab, sw), threshold(inv, sw, limit)),
            "seconds": seconds}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.trace")
    p.add_argument("--seconds", type=float, default=SECONDS)
    p.add_argument("--threshold", type=int, help="frames a second in; default ten times the storm control limit, else 1000")
    p.add_argument("--json", action="store_true")
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    inv = load(args.inventory)
    lab = switch.lab_name()
    findings = [measure(inv, lab, sw, args.seconds, args.threshold) for sw in inv.switches if inv.owner(sw) == inv.operator]
    print(json.dumps(findings, indent=2) if args.json else "\n".join(summary(f) for f in findings))
    return 1 if any(f["storm_from"] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
