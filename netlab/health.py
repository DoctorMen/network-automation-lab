"""Is the network healthy right now? The rollout gate in ansible/deploy.yml runs this after each batch.

python -m netlab.health [--known FILE] [--wait SECONDS]

It checks what the live tests check, from the same expected_state.json: every OSPF neighbor Full,
every BGP session Established, and every host reaching every other host, which no protocol state
shows. It prints one line per problem and exits 1 if there is any. The lines are stable, so a
gate can pass the problems that were there before the change in --known (a file, or - for
stdin) and fail only on new ones. --wait keeps checking, once a second, until no new problem is
left or the time is up: a network takes a few seconds to settle after a change.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def run_json(container: str, command: str) -> dict:
    """vtysh's JSON for a show command, or {} when the router or its daemon doesn't answer."""
    out = subprocess.run(["docker", "exec", container, "vtysh", "-c", command + " json"],
                         capture_output=True, text=True, timeout=30)
    try:
        return json.loads(out.stdout) if out.returncode == 0 else {}
    except json.JSONDecodeError:
        return {}


def reaches(container: str, address: str) -> bool:
    return subprocess.run(["docker", "exec", container, "ping", "-c", "3", "-i", "0.2", "-W", "1", address],
                          capture_output=True, timeout=30).returncode == 0


def problems(expected: dict, lab: str) -> list[str]:
    found = []
    for router, peers in expected["ospf_neighbors"].items():
        neighbors = run_json(f"clab-{lab}-{router}", "show ip ospf neighbor").get("neighbors", {})
        full = {rid for rid, adjs in neighbors.items() if any(a.get("nbrState", "").startswith("Full") for a in adjs)}
        found += [f"{router}: OSPF neighbor {p} is not Full" for p in peers if expected["loopbacks"][p] not in full]
    for s in expected["bgp_sessions"]:
        peers = run_json(f"clab-{lab}-{s['router']}", "show bgp summary").get("ipv4Unicast", {}).get("peers", {})
        if peers.get(s["address"], {}).get("state") != "Established":
            found.append(f"{s['router']}: BGP session to {s['peer']} is not Established")
    # Every host pair at once: with the NOC's host there are six, and the gate runs this every second.
    pairs = [(src, dst, address) for src in expected["hosts"] for dst, address in expected["hosts"].items() if dst != src]
    with ThreadPoolExecutor(max_workers=len(pairs) or 1) as pool:
        replies = list(pool.map(lambda p: reaches(f"clab-{lab}-{p[0]}", p[2]), pairs))
    found += [f"{src}: no reply from {dst} ({address})" for (src, dst, address), ok in zip(pairs, replies) if not ok]
    return found


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.health")
    p.add_argument("--known", type=argparse.FileType("r"), help="problems that were there before; only others count")
    p.add_argument("--wait", type=float, default=0, help="seconds to wait for new problems to clear")
    args = p.parse_args(argv)
    known = set(args.known.read().splitlines()) if args.known else set()
    build = ROOT / "build"
    expected = json.loads((build / "expected_state.json").read_text())
    lab = yaml.safe_load((build / "topology.clab.yml").read_text())["name"]
    deadline = time.monotonic() + args.wait
    while True:
        new = [x for x in problems(expected, lab) if x not in known]
        if not new or time.monotonic() >= deadline:
            break
        time.sleep(1)
    if new:
        print("\n".join(new))
    print(f"{len(new)} new problems" if new else "no new problems", file=sys.stderr)
    return 1 if new else 0


if __name__ == "__main__":
    raise SystemExit(main())
