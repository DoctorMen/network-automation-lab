"""Restore drills: boot each router's backup on a throwaway router, and bring back one stanza on its own.

A backup nobody has restored is a hope. The drill restores from the destination (the restic
repository), never from backups/, into containers with no network, so it can't touch the live lab.
Each throwaway router is built like the real one from the rendered topology: same image, sysctls
and daemons file, with the restored backup as its startup config. (OROS 0.3 REC-3.)
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
import uuid
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path

import yaml

from .backup import err, restic, sha256

# The stated time for restoring one item (one router's stanza), from the start of `restic dump` to the
# stanza checked in a running config. OROS's default is 1 hour; measured here it is a few seconds.
SINGLE_ITEM_LIMIT = 300
# The newest backup must be younger than this. CI backs up nightly, so 36 hours allows for a late
# schedule but not for a missed night.
BACKUP_MAX_AGE_HOURS = 36
FRR_CONF = "/etc/frr/frr.conf"


def latest_snapshot(repo: Path, password_file: Path, host: str) -> dict:
    """The newest snapshot this lab wrote: {'id', 'time', 'paths', ...}."""
    r = restic(repo, password_file, "snapshots", "--json", "--latest", "1", "--host", host)
    if r.returncode:
        raise RuntimeError(f"can't list snapshots in {repo} (exit {r.returncode}): {err(r)}")
    snapshots = json.loads(r.stdout or b"[]")
    if not snapshots:
        raise RuntimeError(f"{repo} holds no snapshot from {host}")
    # --latest 1 means one per set of paths, so a repository with two sets returns two.
    return max(snapshots, key=snapshot_time)


def snapshot_time(snapshot: dict) -> datetime:
    # restic writes nanoseconds ("...12.982185967Z"); Python reads at most microseconds.
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d*", r"\1", snapshot["time"]).replace("Z", "+00:00"))


def dump(repo: Path, password_file: Path, snapshot: str, name: str) -> bytes:
    """One file straight out of the snapshot, without restoring the rest of it."""
    r = restic(repo, password_file, "dump", snapshot, f"/src/{name}")
    if r.returncode:
        raise RuntimeError(f"restic dump {name} failed (exit {r.returncode}): {err(r)}")
    return r.stdout


def stanza(config: str, start: str) -> str:
    """The top-level block that starts with `start` (e.g. 'router bgp'), up to its closing 'exit'."""
    lines = config.splitlines()
    first = next((i for i, line in enumerate(lines) if line.startswith(start)), None)
    if first is None:
        return ""
    last = next((i for i in range(first, len(lines)) if lines[i] == "exit"), len(lines) - 1)
    return "\n".join(lines[first:last + 1]) + "\n"


class Scratch:
    """A throwaway copy of one router, with no network, booted from a given startup config."""

    def __init__(self, build: Path, router: str, config: Path):
        topo = yaml.safe_load((build / "topology.clab.yml").read_text())
        node = topo["topology"]["nodes"][router]
        self.name = f"drill-{topo['name']}-{router}-{uuid.uuid4().hex[:6]}"
        cmd = ["docker", "run", "-d", "--rm", "--name", self.name, "--hostname", router, "--network", "none",
               # Enough for zebra and bgpd to start; without them only watchfrr and staticd run.
               "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--cap-add", "SYS_ADMIN"]
        for key, value in (node.get("sysctls") or {}).items():
            cmd += ["--sysctl", f"{key}={value}"]
        for bind in node.get("binds") or []:
            src, dst = bind.split(":")[:2]
            if dst != FRR_CONF:  # every bind as deployed, except the startup config: that is the restore
                cmd += ["--mount", f"type=bind,src={(build / src).resolve()},dst={dst},readonly"]
        cmd += ["--mount", f"type=bind,src={config.resolve()},dst={FRR_CONF},readonly"]
        self.cmd = [*cmd, node.get("image", topo["topology"]["defaults"]["image"])]

    def __enter__(self) -> "Scratch":
        subprocess.run(self.cmd, check=True, capture_output=True, timeout=60)
        return self

    def __exit__(self, *exc) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, timeout=60)

    def run(self, *cmd: str, input: str | None = None) -> subprocess.CompletedProcess:
        interactive = ["-i"] if input is not None else []
        return subprocess.run(["docker", "exec", *interactive, self.name, *cmd], input=input,
                              capture_output=True, text=True, timeout=60)

    def wait_booted(self, timeout: float = 120) -> None:
        """FRR has loaded its startup config: the zebra daemon runs, and the start script that
        launched it (watchfrr.sh, which ends with `vtysh -b`, the config load) has finished.
        Match zebra's own command line: watchfrr's arguments name zebra before zebra exists.
        120 s, not 60: in about 1 boot in 20 here zebra is gone a second after it starts, and
        watchfrr only starts it again after its minimum restart interval (60 s), booted at 62-67 s."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ps = self.run("ps", "-o", "args").stdout
            zebra = any(line.startswith("/usr/lib/frr/zebra ") for line in ps.splitlines())
            if zebra and "watchfrr.sh" not in ps and "vtysh -b" not in ps:
                return
            time.sleep(0.5)
        raise TimeoutError(f"{self.name} did not finish booting in {timeout:g} s")

    def differences(self) -> list[str]:
        """What frr-reload.py --test says differs between the running config and the startup file.
        Same reading as ansible/tasks/compare_frr.yml: listed lines, lines it only logs as
        'cannot be removed' (except the version stamp), and ipv6 forwarding ignored (V-009)."""
        r = self.run("/usr/lib/frr/frr-reload.py", "--test", FRR_CONF)
        if r.returncode:
            # frr-reload couldn't parse the file at all, which is the most useful thing to report.
            noise = re.compile(r"\x1b\[[0-9;]*m")
            return [noise.sub("", line).strip() for line in r.stderr.splitlines() if " INFO: " not in line]
        listed = [line.strip() for line in r.stdout.splitlines()
                  if line.strip() and not re.match(r"^(Lines To (Add|Delete)|=*|(no )?ipv6 forwarding)$", line.strip())]
        unremovable = [line for line in r.stderr.splitlines() if "cannot be removed" in line and '"frr version ' not in line]
        return listed + unremovable

    def isolated(self) -> list[str]:
        """The scratch router has no interface but loopback, so it can't reach the live lab."""
        links = [line.split(":")[1].strip() for line in self.run("ip", "-o", "link").stdout.splitlines()]
        return [] if links == ["lo"] else [f"{self.name} has network interfaces {links}"]


def boot_and_compare(build: Path, configs: dict[str, bytes]) -> dict[str, dict]:
    """Boot every router's config at once on throwaway routers. {router: {seconds, problems, sha256}}."""
    results = {}
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as boxes:
        start = time.monotonic()
        booting = {}
        for router, config in configs.items():
            path = Path(tmp) / f"{router}.conf"
            path.write_bytes(config)
            booting[router] = boxes.enter_context(Scratch(build, router, path))
        for router, box in booting.items():
            box.wait_booted()
            results[router] = {"seconds": round(time.monotonic() - start, 2),
                               "problems": box.differences() + box.isolated(),
                               "sha256": sha256(configs[router])}
    return results


def drill(build: Path, routers: list[str], repo: Path, password_file: Path, snapshot: str) -> dict[str, dict]:
    """Restore every router's backup from the destination and boot it."""
    return boot_and_compare(build, {r: dump(repo, password_file, snapshot, f"{r}.conf") for r in routers})


def restore_item(build: Path, router: str, start: str, repo: Path, password_file: Path, snapshot: str) -> dict:
    """Bring back one stanza of one router: dump only that router's file, then paste only that stanza
    into a throwaway router that booted empty. Timed from the dump to the stanza checked."""
    began = time.monotonic()
    item = stanza(dump(repo, password_file, snapshot, f"{router}.conf").decode(), start)
    if not item:
        raise RuntimeError(f"{router}'s backup has no '{start}' stanza")
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "frr.conf"
        empty.write_text("")
        with Scratch(build, router, empty) as box:
            box.wait_booted()
            box.run("sh", "-c", "cat > /tmp/item.conf", input=item)
            box.run("vtysh", "-f", "/tmp/item.conf")
            restored = stanza(box.run("vtysh", "-c", "show running-config no-header").stdout, start)
    return {"router": router, "item": item.splitlines()[0], "lines": len(item.splitlines()),
            "restored": restored == item, "seconds": round(time.monotonic() - began, 2),
            "limit_seconds": SINGLE_ITEM_LIMIT, "missing": sorted(set(item.splitlines()) - set(restored.splitlines()))}
