"""Measure the running lab's RAM and save the raw samples, so sizing claims point at data.

python -m netlab.measure --env laptop --note "what this machine is, and what the lab was doing"
writes docs/sizing/data/<date>-<env>.json.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import time
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
# docker stats prints binary units: "23.89MiB", "404KiB". Longest suffix first, so "MiB" isn't read as "B".
UNITS = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "B": 1 / 1024**2}


def mib(text: str) -> float:
    for unit, factor in UNITS.items():
        if text.endswith(unit):
            return float(text[: -len(unit)]) * factor
    raise ValueError(f"unknown memory unit in {text!r}")


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


def version_of(*cmd: str) -> str:
    """A tool's version, or 'not installed': the environment is recorded as it is."""
    try:
        out = sh(*cmd)
    except (OSError, subprocess.CalledProcessError):
        return "not installed"
    found = re.search(r"version:\s*(\S+)", out)
    return found.group(1) if found else out


def sample(containers: dict[str, str]) -> dict[str, float]:
    """One `docker stats` reading, MiB per node. Fails if any lab container is missing."""
    out = sh("docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}", *containers)
    # "clab-netauto-r1 21.51MiB / 15.62GiB": usage, then the limit.
    return {containers[name]: round(mib(usage), 2) for name, usage, *_ in (line.split() for line in out.splitlines())}


def measure(build: Path, env: str, note: str, samples: int, interval: float) -> dict:
    topo = yaml.safe_load((build / "topology.clab.yml").read_text())
    containers = {f"clab-{topo['name']}-{n}": n for n in topo["topology"]["nodes"]}
    readings = []
    for i in range(samples):
        readings.append(sample(containers))
        if i < samples - 1:
            time.sleep(interval)
    per_node = {n: round(sum(r[n] for r in readings) / len(readings), 2) for n in containers.values()}
    # Containerlab labels every node it creates. A stand-in that only copies the names doesn't.
    labels = json.loads(sh("docker", "inspect", "-f", "{{json .Config.Labels}}", next(iter(containers)))) or {}
    return {
        "date": date.today().isoformat(),
        "env": env,
        "note": note,
        "method": f"docker stats --no-stream MemUsage, {samples} samples {interval:g} s apart; per node is the mean",
        "nodes": len(per_node),
        "total_mib": round(sum(per_node.values()), 1),
        "per_node_mib": dict(sorted(per_node.items(), key=lambda kv: -kv[1])),
        "kernel": platform.release(),
        "docker": version_of("docker", "version", "--format", "{{.Server.Version}}"),
        "cgroup": version_of("docker", "info", "--format", "{{.CgroupVersion}}"),
        "containerlab": version_of("containerlab", "version"),
        "deployed_by": "containerlab" if "clab-node-kind" in labels else "not containerlab (no clab-node-kind label)",
        "image": topo["topology"]["defaults"]["image"],
        "samples_mib": readings,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.measure")
    p.add_argument("--env", required=True, help="short name for where this ran, e.g. laptop or github-runner")
    p.add_argument("--note", default="", help="what the machine is and what the lab was doing")
    p.add_argument("--build", default=str(ROOT / "build"))
    p.add_argument("--out", default=str(ROOT / "docs" / "sizing" / "data"))
    p.add_argument("--samples", type=int, default=5)
    p.add_argument("--interval", type=float, default=2.0)
    args = p.parse_args(argv)
    data = measure(Path(args.build), args.env, args.note, args.samples, args.interval)
    out = Path(args.out) / f"{data['date']}-{args.env}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n")
    print(f"wrote {out}: {data['total_mib']} MiB for all {data['nodes']} nodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
