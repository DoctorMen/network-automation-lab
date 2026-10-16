"""Is the change in effect, not just installed? Read from the live system, without disturbing it.

python -m netlab.verify [NODE ...] checks every router and every host with QoS, or only the nodes
named, prints a line per node and check, and exits 1 if anything is `not in effect`.

- kernel: the newest kernel installed under /lib/modules is the one running (`uname -r`), the test
  needrestart and needs-restarting -r use. A kernel patched without a reboot is not in effect. Lab
  nodes are containers on the host's kernel and install none, so there is nothing to compare
  until one is installed.
- daemons: every daemon /etc/frr/daemons enables is running, from the binary that is on disk. An
  upgrade replaces the file, and the process keeps running the old, deleted one until it restarts
  (/proc/<pid>/exe ends "(deleted)").
- qos: each class on the interface has the inventory's rates, and a handful of connections to a
  class's port (a few kilobytes, nowhere near the link's rate) are counted in that class.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PROBES = 5  # connections per QoS class: enough to see in the counters, far too few to load the link


def run(lab: str, node: str, *cmd: str) -> str:
    return subprocess.run(["docker", "exec", f"clab-{lab}-{node}", *cmd],
                          capture_output=True, text=True, timeout=60).stdout


def version_key(release: str) -> tuple[int, ...]:
    """'6.8.0-1017-azure' -> (6, 8, 0, 1017), so 6.10 sorts after 6.9."""
    return tuple(int(n) for n in re.findall(r"\d+", release))


def kernel_status(running: str, installed: list[str]) -> str:
    if not installed:
        return f"nothing to compare: no kernel installed on the node (it runs the host's {running})"
    newest = max(installed, key=version_key)
    if newest != running:
        return f"not in effect: {newest} is installed but {running} is running, reboot required"
    return f"in effect: {running} is the newest installed"


def daemons_status(exes: list[str], daemons_file: str) -> str:
    """exes: every process's /proc/<pid>/exe. daemons_file: /etc/frr/daemons, which says what should run."""
    frr = [e for e in exes if e.startswith("/usr/lib/frr/")]
    running = {Path(e.removesuffix(" (deleted)")).name for e in frr}
    wrong = []
    if stale := sorted({Path(e.removesuffix(" (deleted)")).name for e in frr if e.endswith(" (deleted)")}):
        wrong.append(f"{', '.join(stale)} still run a binary replaced on disk, restart required")
    # zebra=yes, bgpd=no, ...; vtysh_enable=yes is a setting, not a daemon.
    if missing := sorted(set(re.findall(r"^([a-z0-9]+)=yes$", daemons_file, re.M)) - running):
        wrong.append(f"{', '.join(missing)} enabled in /etc/frr/daemons but not running")
    if wrong:
        return "not in effect: " + "; ".join(wrong)
    return f"in effect: every enabled daemon runs its installed binary ({', '.join(sorted(running))})"


def tc_classes(show: str) -> dict[str, dict]:
    """`tc -s class show` -> {classid: {rate, ceil, bytes, packets, queued}}; queued is packets waiting now."""
    classes, current = {}, None
    for line in show.splitlines():
        if m := re.match(r"class htb (\S+) .*rate (\S+) ceil (\S+)", line):
            current = classes[m[1]] = {"rate": m[2].lower(), "ceil": m[3].lower()}
        elif current is not None and (m := re.match(r"\s*Sent (\d+) bytes (\d+) pkt", line)):
            current.update(bytes=int(m[1]), packets=int(m[2]))
        elif current is not None and (m := re.match(r"\s*backlog \S+ (\d+)p", line)):
            current["queued"] = int(m[1])
    return classes


def qos_status(lab: str, host: str, spec: dict, address: str) -> str:
    show = ("tc", "-s", "class", "show", "dev", spec["interface"])
    before = tc_classes(run(lab, host, *show))
    wrong = []
    for c in spec["classes"]:
        got = before.get(f"1:{c['id']}")
        if got is None:
            wrong.append(f"class 1:{c['id']} ({c['name']}) is not installed")
        elif (got["rate"], got["ceil"]) != (c["rate"], spec["rate"]):
            wrong.append(f"class 1:{c['id']} ({c['name']}) runs at {got['rate']} ceil {got['ceil']}, "
                         f"the inventory says {c['rate']} ceil {spec['rate']}")
    if wrong:
        return "not in effect: " + "; ".join(wrong)
    probed = [c for c in spec["classes"] if "sport" in c]
    for c in probed:
        run(lab, spec["probe_from"], "sh", "-c", f"for i in $(seq {PROBES}); do nc -z -w 2 {address} {c['sport']}; done")
    after = tc_classes(run(lab, host, *show))
    for c in probed:
        cid = f"1:{c['id']}"
        # Each connection makes the host send at least a SYN-ACK from the class's port.
        if after[cid]["packets"] - before[cid]["packets"] < PROBES:
            wrong.append(f"{PROBES} connections to :{c['sport']} from {spec['probe_from']} added "
                         f"{after[cid]['packets'] - before[cid]['packets']} packets to {cid} ({c['name']})")
    if wrong:
        return "not in effect: " + "; ".join(wrong)
    counted = "".join(f", {PROBES} connections to :{c['sport']} counted in 1:{c['id']} ({c['name']})" for c in probed)
    return f"in effect: rates as the inventory says{counted}"


def report(expected: dict, lab: str, nodes: list[str]) -> list[str]:
    lines = []
    for node in nodes:
        running = run(lab, node, "uname", "-r").strip()
        installed = run(lab, node, "sh", "-c", "ls /lib/modules 2>/dev/null").split()
        lines.append(f"{node} kernel: {kernel_status(running, installed)}")
        if node in expected["loopbacks"]:
            exes = run(lab, node, "sh", "-c", "for p in /proc/[0-9]*; do readlink $p/exe; done").splitlines()
            lines.append(f"{node} daemons: {daemons_status(exes, run(lab, node, 'cat', '/etc/frr/daemons'))}")
        if node in expected["qos"]:
            lines.append(f"{node} qos: {qos_status(lab, node, expected['qos'][node], expected['hosts'][node])}")
    return lines


def chosen(argv: list[str] | None, every: list[str]) -> list[str]:
    """The nodes named on the command line, or all of them when none is. The names are checked after
    parsing: before Python 3.12, argparse checks an empty nargs='*' list against choices= and refuses it."""
    p = argparse.ArgumentParser(prog="netlab.verify", description="Is each change in effect, not just installed?")
    p.add_argument("nodes", nargs="*", metavar="NODE", help=f"a router or a host with QoS: {', '.join(every)} (default: all of them)")
    nodes = p.parse_args(argv).nodes
    unknown = [n for n in nodes if n not in every]
    if unknown:
        p.error(f"not a router or a host with QoS: {', '.join(unknown)} (choose from {', '.join(every)})")
    return nodes or every


def main(argv: list[str] | None = None) -> int:
    build = ROOT / "build"
    expected = json.loads((build / "expected_state.json").read_text())
    lab = yaml.safe_load((build / "topology.clab.yml").read_text())["name"]
    lines = report(expected, lab, chosen(argv, [*expected["loopbacks"], *expected["qos"]]))
    print("\n".join(lines))
    return 1 if any("not in effect" in line for line in lines) else 0


if __name__ == "__main__":
    raise SystemExit(main())
