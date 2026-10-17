"""What is listening, against what the inventory records (OROS FND-4, decision 0032).

python -m netlab.audit [--json]

On every host we own, `ss -ltnpH` lists the TCP listeners and the program behind each. The report names
every mismatch with what the inventory implies for that host: its `services`, plus the ports the NOC's
sidecars open in its namespace (netlab.monitoring.listeners). A port listening that nothing recorded, and a
recorded port nothing listens on, are mismatches. For each recorded port it also names the program serving
it, so a stand-in (h2's port 22 is python3's http.server, not sshd) is in the report, not just in a footnote;
a sidecar's process is in another pid namespace, so ss names it "?" and the report names the sidecar.
Listeners on 127.0.0.1 alone can't be reached from the network and are reported, not judged. UDP is not
audited (RISK-69). Exit 1 on any mismatch. CI's lab job runs it on every run, nightly included: the schedule.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import monitoring, switch
from .inventory import Inventory, load
from .locate import exec_on

ROOT = Path(__file__).resolve().parent.parent
LISTENER = re.compile(r'^LISTEN\s+\d+\s+\d+\s+(\S+):(\d+)\s+\S+(?:\s+users:\(\("([^"]+)")?')


def hosts(inv: Inventory) -> list[str]:
    """Every host we own: the devices whose listeners the inventory records (`services`)."""
    return [h for h in inv.hosts if inv.owner(h) == inv.operator]


def listeners(text: str) -> dict[int, dict]:
    """{port: {address, program}} from `ss -ltnpH`; program '?' when ss could not name it."""
    out = {}
    for line in text.splitlines():
        m = LISTENER.match(line)
        if m:
            out[int(m[2])] = {"address": m[1], "program": m[3] or "?"}
    return out


def read(inv: Inventory, lab: str, host: str) -> dict[int, dict]:
    out = subprocess.run(exec_on(inv, lab, host, "ss", "-ltnpH"), capture_output=True, text=True, timeout=30)
    return listeners(out.stdout)


def audit(inv: Inventory, found: dict[str, dict[int, dict]]) -> list[dict]:
    """One row per port on each host, recorded or heard: {host, port, recorded, listening, program, local, mismatch}.
    recorded names what records it (services, or the sidecar). Pure, so tests feed it canned listings."""
    rows = []
    for host in sorted(found):
        recorded = {p: "services" for p in inv.hosts[host].get("services") or []}
        recorded.update(monitoring.listeners(inv, host))
        heard = found[host]
        for port in sorted(set(recorded) | set(heard)):
            local = port in heard and heard[port]["address"].startswith("127.")
            program = heard[port]["program"] if port in heard else None
            if program == "?" and port in recorded and recorded[port] != "services":
                program = f"{recorded[port]} (sidecar)"
            rows.append({"host": host, "port": port, "recorded": recorded.get(port), "listening": port in heard, "program": program,
                         "local": local, "mismatch": not local and (port in recorded) != (port in heard)})
    return rows


def summary(rows: list[dict]) -> str:
    lines = []
    for r in rows:
        if r["mismatch"] and r["listening"]:
            lines.append(f"MISMATCH {r['host']} tcp/{r['port']}: listening ({r['program']}), not in the inventory")
        elif r["mismatch"]:
            lines.append(f"MISMATCH {r['host']} tcp/{r['port']}: in the inventory ({r['recorded']}), nothing listening")
        elif r["local"]:
            lines.append(f"local    {r['host']} tcp/{r['port']}: on 127.0.0.1 only ({r['program']}), unreachable from the network")
        else:
            lines.append(f"ok       {r['host']} tcp/{r['port']}: recorded ({r['recorded']}), served by {r['program']}")
    n = sum(r["mismatch"] for r in rows)
    lines.append(f"{len(rows)} ports on {len({r['host'] for r in rows})} hosts, {n} mismatch(es)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.audit")
    p.add_argument("--json", action="store_true")
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    inv = load(args.inventory)
    lab = switch.lab_name()
    with ThreadPoolExecutor() as pool:
        found = dict(zip(hosts(inv), pool.map(lambda h: read(inv, lab, h), hosts(inv))))
    rows = audit(inv, found)
    print(json.dumps(rows, indent=2) if args.json else summary(rows))
    return 1 if any(r["mismatch"] for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
