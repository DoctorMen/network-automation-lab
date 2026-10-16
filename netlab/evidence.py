"""Evidence that outlives a reset (OROS FND-2, decision 0025).

python -m netlab.evidence take [--node r2]          each node's state dump and its own log, now
python -m netlab.evidence show --node r2 [--minutes 15]   a node's last lines in the central store

`take` is the step before a planned reset or rebuild (docs/runbooks/power-event.md and
restore-from-backup.md). A box keeps only a small rotated log of its own, and a reset loses it. Each node
runs the flight recorder's dump (sh /monitoring/agent.sh dump), which also sends it to the central store;
its own log is copied off as it stands. Both go into results/evidence/<UTC time>/<node>.txt, and `take`
fails unless every dump is also in the central store. `show` reads the central store, which keeps a
node's lines after the node itself has lost them.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .inventory import Inventory, load
from .locate import exec_on
from .observe import Noc, lab_name
from . import monitoring

ROOT = Path(__file__).resolve().parent.parent


def dump(inv: Inventory, lab: str, node: str, why: str) -> list[str]:
    """The node's state dump, as it printed it: the first line is '<id> begin <why>', the last '<id> end N lines'."""
    out = subprocess.run(exec_on(inv, lab, node, "sh", "/monitoring/agent.sh", "dump", why),
                         capture_output=True, text=True, timeout=60, check=True).stdout
    return out.splitlines()


def on_box_log(inv: Inventory, lab: str, node: str) -> str:
    """Everything the node's own syslogd still keeps, oldest file first."""
    return subprocess.run(exec_on(inv, lab, node, "sh", "-c", "cat /var/log/messages.0 /var/log/messages 2>/dev/null"),
                          capture_output=True, text=True, timeout=60).stdout


def in_store(noc: Noc, node: str, dump_id: str, since: float, timeout: float = 30) -> bool:
    """Has the dump's last line reached the central store, from that node?"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if noc.logs(f'{{node="{node}",source="syslog"}} |= "{dump_id} end"', since - 5):
            return True
        time.sleep(1)
    return False


def take(inv: Inventory, lab: str, nodes: list[str], why: str, out: Path = ROOT / "results" / "evidence") -> list[dict]:
    """[{node, id, dump_lines, log_lines, file, in_store}] for each node, saved under out/<UTC time>/."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = out / stamp
    folder.mkdir(parents=True, exist_ok=True)
    noc, since, taken = Noc(lab, monitoring.host(inv)), time.time(), []
    for node in nodes:
        log = on_box_log(inv, lab, node)  # first, so the dump's own lines push nothing out of it
        lines = dump(inv, lab, node, why)
        path = folder / f"{node}.txt"
        path.write_text(f"# {node}, {stamp}: {why}\n# The flight recorder's state dump\n" + "\n".join(lines) +
                        f"\n# The node's own log, as it stood\n{log}")
        taken.append({"node": node, "id": lines[0].split()[0], "dump_lines": len(lines), "log_lines": len(log.splitlines()),
                      "file": str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)})
    for t in taken:
        t["in_store"] = in_store(noc, t["node"], t["id"], since)
    return taken


def show(inv: Inventory, lab: str, node: str, minutes: float) -> list[tuple[float, dict, str]]:
    return Noc(lab, monitoring.host(inv)).logs(f'{{node="{node}"}}', time.time() - 60 * minutes, every=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.evidence")
    p.add_argument("command", choices=["take", "show"])
    p.add_argument("--node", help="one node; take: every log source if not given")
    p.add_argument("--minutes", type=float, default=15, help="show: how far back")
    p.add_argument("--why", default="make evidence, before a planned reset")
    p.add_argument("--out", default=str(ROOT / "results" / "evidence"), help="take: where the dated folder goes")
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    inv, lab = load(args.inventory), lab_name()
    sources = monitoring.syslog_sources(inv)
    if args.node and args.node not in sources:
        p.error(f"{args.node} is not a log source: {', '.join(sources)}")
    if args.command == "show":
        if not args.node:
            p.error("show needs --node")
        for t, labels, line in show(inv, lab, args.node, args.minutes):
            print(f"{datetime.fromtimestamp(t, timezone.utc):%H:%M:%S} {labels.get('source')} {line}")
        return 0
    taken = take(inv, lab, [args.node] if args.node else sources, args.why, Path(args.out))
    for t in taken:
        print(f"{t['node']:<4} dump {t['id']} ({t['dump_lines']} lines), own log {t['log_lines']} lines -> {t['file']}; "
              f"{'in the central store' if t['in_store'] else 'NOT in the central store'}")
    return 0 if all(t["in_store"] for t in taken) else 1


if __name__ == "__main__":
    sys.exit(main())
