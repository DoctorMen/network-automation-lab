"""Find where packet loss starts on a path: clear our own segments first, then name the
segment and its owner. Runs only on devices the operator owns; the carrier is observed, not logged into."""
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .inventory import Inventory

PROBES = 200      # echo requests per hop; one lost reply is 0.5%
INTERVAL = 0.02   # 20 ms apart, so a hop takes 4 s and every hop is probed at once
# A hop is lossy above 2%, more than 4 of 200 replies lost. A healthy link with 0.5% background
# loss crosses that 0.4% of the time; a real 20% fault (40 +/- 6 lost) never falls under it. A 5%
# fault slips under it 3% of the time, so smaller faults need more probes than this.
THRESHOLD = 2.0


def exec_on(inv: Inventory, lab: str, device: str, *cmd: str, interactive: bool = False) -> list[str]:
    """The command line to run cmd on a device. Refused unless the operator owns that device.
    interactive passes this process's stdin through to cmd (docker exec -i)."""
    if inv.owner(device) != inv.operator:
        raise PermissionError(f"{device} belongs to {inv.owner(device) or 'nobody we know'}; "
                              f"{inv.operator} can only observe it, not log in")
    return ["docker", "exec", *(["-i"] if interactive else []), f"clab-{lab}-{device}", *cmd]


def discover(inv: Inventory, lab: str, src: str, dst: str, raw: list | None = None) -> list[str]:
    """Hop addresses from src to dst. ICMP traceroute, because the firewall drops UDP probes.
    raw, if given, collects every command run and its output as printed (a finding bundle keeps them)."""
    for _ in range(5):
        cmd = ["traceroute", "-I", "-n", "-q", "1", "-w", "1", dst]
        out = subprocess.run(exec_on(inv, lab, src, *cmd), capture_output=True, text=True, timeout=60).stdout
        if raw is not None:
            raw.append({"on": src, "cmd": " ".join(cmd), "output": out})
        answers = [line.split()[1] for line in out.splitlines()[1:] if len(line.split()) > 1]
        # A "*" is a probe nobody answered. Before the destination it may be one of our routers, and
        # skipping it would merge two segments and hand ours to the next owner. The loss we are
        # chasing causes exactly that, so trace again until every hop up to the destination answers.
        if dst not in answers or "*" not in answers[:answers.index(dst)]:
            break
    hops = []
    for hop in answers:
        if hop != "*" and hop not in hops:
            hops.append(hop)
    if dst not in hops:
        hops.append(dst)
    return hops


def loss_pct(ping_output: str) -> float:
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", ping_output)
    if not m or m[1] == "0":
        return 100.0
    sent, got = int(m[1]), int(m[2])
    return round(100 * (sent - got) / sent, 1)


def ping_cmd(address: str) -> list[str]:
    return ["ping", "-q", "-c", str(PROBES), "-i", str(INTERVAL), "-W", "1", address]


def probe(inv: Inventory, lab: str, targets: list[tuple[str, str]], raw: list | None = None) -> list[float]:
    """Loss % for each (from device, to address), all pinged at the same time. raw: as for discover."""
    procs = [subprocess.Popen(exec_on(inv, lab, device, *ping_cmd(address)), stdout=subprocess.PIPE, text=True)
             for device, address in targets]
    outputs = [p.communicate(timeout=60)[0] for p in procs]
    if raw is not None:
        raw.extend({"on": device, "cmd": " ".join(ping_cmd(address)), "output": out}
                   for (device, address), out in zip(targets, outputs))
    return [loss_pct(out) for out in outputs]


def loss_starts(losses: list[float]) -> int | None:
    """Index of the hop where loss starts and persists to the destination, or None if the destination
    is clean. A middle hop that loses replies while later hops don't is rate-limiting pings to
    itself, not dropping traffic through it, so it doesn't count."""
    start = None
    for i, loss in enumerate(losses):
        if loss <= THRESHOLD:
            start = None
        elif start is None:
            start = i
    return start


def locate(inv: Inventory, build: str | Path, src: str, dst: str) -> dict:
    build = Path(build)
    lab = yaml.safe_load((build / "topology.clab.yml").read_text())["name"]
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    raw: list[dict] = []
    hops = discover(inv, lab, src, dst, raw)
    path = [src] + [inv.device_at(h) or h for h in hops]
    ours = [inv.owner(d) == inv.operator for d in path]

    # Our edge is the last device we own before the path leaves our network. Pinging past it from
    # the edge itself takes every campus link out of the measurement.
    leaves = ours.index(False) if False in ours else None
    edge = path[leaves - 1] if leaves else None
    beyond = hops[leaves - 1:] if edge and edge != src else []

    losses = probe(inv, lab, [(src, h) for h in hops] + [(edge, h) for h in beyond], raw)
    from_src, from_edge = losses[:len(hops)], losses[len(hops):]
    start = loss_starts(from_src)

    segments = []
    for i, (hop, loss) in enumerate(zip(hops, from_src)):
        if start is not None and i > start:
            verdict = "behind the loss, can't be judged from here"
        elif i == start:
            verdict = "loss starts here"
        elif loss <= THRESHOLD:
            verdict = "clean"
        else:
            verdict = "not loss: later hops are clean, so this hop only rate-limits pings to itself"
        segments.append({"segment": f"{path[i]}-{path[i + 1]}", "far_end": hop,
                         # Our near end answered cleanly, so loss that starts here is on the far end's side.
                         "owner": inv.owner(path[i + 1]) or "unknown", "loss_pct": loss, "verdict": verdict})

    culprit = segments[start] if start is not None else None
    finding = {
        "src": src, "dst": dst, "operator": inv.operator, "started_utc": started,
        "path": path,  # devices from src on, one per hop; an address where the inventory knows no device
        "method": {
            "discover": f"traceroute -I -n -q 1 -w 1 {dst} (from {src}; again, up to 5 times, while a hop before {dst} is *)",
            "probe": f"ping -q -c {PROBES} -i {INTERVAL} -W 1 <hop>, every hop at once",
            "threshold_pct": THRESHOLD,
        },
        "segments": segments,
        "edge": {"device": edge, "loss_pct": dict(zip(beyond, from_edge))} if beyond else None,
        "segment": culprit["segment"] if culprit else None,
        "owner": culprit["owner"] if culprit else None,
        "raw": raw,  # every command's output, as printed
    }
    (build / "finding.json").write_text(json.dumps(finding, indent=2) + "\n")
    return finding


def summary(f: dict) -> str:
    lines = [f"{f['src']} -> {f['dst']}: {PROBES} probes per hop, a hop is lossy above {THRESHOLD:g}%"]
    for s in f["segments"]:
        lines.append(f"  {s['segment']:<10} {s['owner']:<22} {s['loss_pct']:5.1f}%  {s['verdict']}")
    if f["edge"]:
        seen = ", ".join(f"{a} {loss:.1f}%" for a, loss in f["edge"]["loss_pct"].items())
        lines.append(f"  from our edge {f['edge']['device']} directly: {seen}")
    if f["segment"]:
        lines.append(f"Loss starts on {f['segment']} and persists to {f['dst']}. Owner: {f['owner']}.")
    else:
        lines.append(f"No loss to {f['dst']} above {THRESHOLD:g}%.")
    return "\n".join(lines)
