"""A finding bundle: what someone outside the team needs to check a `locate` finding without us and
re-run it (OROS PRV-3). `netlab finding` writes it, `netlab finding --verify DIR` checks it before
it is sent, and its reproduce.sh re-runs the measurement with nothing but sh and docker.

Everything in it comes from devices the operator owns (locate's exec_on rule). It never holds a BGP
password: build/ has none (decision 0016), and FRR's support bundle runs without `show running-config`."""
from __future__ import annotations

import io
import ipaddress
import json
import platform
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

import yaml

from .inventory import Inventory
from .locate import INTERVAL, PROBES, THRESHOLD, exec_on, locate, loss_pct, ping_cmd

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent / "bundle"
SUPPORT_COMMANDS = HERE / "support_bundle_commands.conf"
REQUIRED = ("FINDING.md", "METHOD.md", "finding.json", "finding.env", "reproduce.sh", "versions.txt",
            "time.txt", "raw/INDEX.txt", "lab/topology.clab.yml", "SHA256SUMS")
# Authorities a carrier already trusts, each for the one thing it backs. RFC 7680 (one-way loss) is
# not cited: ping measures the round trip, and we capture at our end only.
CITATIONS = {
    "RFC 792": "https://www.rfc-editor.org/rfc/rfc792 - ICMP Echo and Echo Reply: what each probe is, and that the far end must answer it",
    "RFC 6673": "https://www.rfc-editor.org/rfc/rfc6673 - Round-Trip Packet Loss Metrics: the loss figures here are round-trip loss of that kind",
    "RFC 1812": "https://www.rfc-editor.org/rfc/rfc1812#section-4.3.2.8 - routers may rate-limit the ICMP errors traceroute relies on, so a silent hop alone is not loss",
}
# Run inside a router with the image's own Python: FRR's support-bundle script, with our command file
# on stdin, writing into a temporary folder that is removed again; the logs come back as a tar stream.
SUPPORT = """import subprocess, sys, tarfile, tempfile
with tempfile.TemporaryDirectory() as d:
    subprocess.run(["python3", "/usr/lib/frr/generate_support_bundle.py", "-c", "/dev/stdin", "-l", d], check=True, stdout=subprocess.DEVNULL)
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as tar:
        tar.add(d, arcname=".")
"""
CLOCK = "import time; print(time.time())"
PASSWORD_LINE = re.compile(r"neighbor\s+\S+\s+password\s+(?!sha256:[0-9a-f]{64}\b)\S+")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


def support_procs() -> list[str]:
    """The daemons the vendored command file collects for: one log each."""
    return re.findall(r"^PROC_NAME:(\S+)", SUPPORT_COMMANDS.read_text(), re.M)


def handoff(inv: Inventory, edge: str, beyond: str) -> tuple[str, str, str] | None:
    """(our interface, our address, their address) on the link from our edge to the next device."""
    for local, remote in inv.neighbors(edge):
        if remote.device == beyond:
            return local.interface, str(local.address.ip), str(remote.address.ip)
    return None


def capture_at_edge(inv: Inventory, lab: str, edge: str, iface: str, target: str) -> tuple[bytes, str]:
    """A pcap of ICMP on our edge's hand-off port while the edge pings the far side, and ping's output."""
    seconds = PROBES * INTERVAL + 5  # the pings take about PROBES * INTERVAL + 1 s, starting 1 s in
    cap = subprocess.Popen(exec_on(inv, lab, edge, "python3", "-c", (HERE / "capture.py").read_text(), iface, str(seconds)),
                           stdout=subprocess.PIPE)
    time.sleep(1)  # the socket must be bound before the first probe leaves
    out = run(exec_on(inv, lab, edge, *ping_cmd(target))).stdout
    return cap.communicate(timeout=60)[0], out


def icmp_counts(pcap: bytes, address: str) -> tuple[int, int]:
    """(echo requests to address, echo replies from it) in a capture.py pcap."""
    if pcap[:4] != struct.pack("<I", 0xA1B2C3D4):
        return 0, 0
    target = ipaddress.IPv4Address(address).packed
    requests = replies = 0
    offset = 24  # past the file header
    while offset + 16 <= len(pcap):
        kept = struct.unpack_from("<IIII", pcap, offset)[2]
        ip = pcap[offset + 30: offset + 16 + kept]  # 16-byte record header, 14-byte Ethernet header
        offset += 16 + kept
        icmp_type = ip[(ip[0] & 15) * 4]
        if icmp_type == 8 and ip[16:20] == target:
            requests += 1
        elif icmp_type == 0 and ip[12:16] == target:
            replies += 1
    return requests, replies


def support_bundle(inv: Inventory, lab: str, router: str, dest: Path) -> None:
    cmd = exec_on(inv, lab, router, "python3", "-c", SUPPORT)  # refuses a router we don't own
    cmd[2:2] = ["-i"]  # docker exec passes stdin through only with -i; without it the list arrives empty
    out = subprocess.run(cmd, input=SUPPORT_COMMANDS.read_bytes(), capture_output=True, timeout=120, check=True).stdout
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(out), mode="r:") as tar:
        tar.extractall(dest, filter="data")


def versions(inv: Inventory, lab: str, images: list[str], routers: list[str]) -> str:
    lines = ["# What the finding ran on. reproduce.sh checks every `image` line against the lab it re-runs on."]
    for image in images:
        digests = run(["docker", "image", "inspect", "--format", "{{join .RepoDigests \" \"}}", image]).stdout.split()
        lines.append(f"image {image} {digests[0] if digests else 'none'}")
    for router in routers:
        first = run(exec_on(inv, lab, router, "vtysh", "-c", "show version")).stdout.strip().splitlines()
        lines.append(f"frr {router} {first[0] if first else 'unknown'}")
    clab = run(["sh", "-c", "containerlab version 2>/dev/null | sed -n 's/^ *version: *//p'"]).stdout.strip()
    commit = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.strip() or "unknown"
    dirty = len(run(["git", "-C", str(ROOT), "status", "--porcelain"]).stdout.splitlines())
    lines += [f"host {platform.system()} {platform.release()}",
              f"docker {run(['docker', 'version', '--format', '{{.Server.Version}}']).stdout.strip() or 'unknown'}",
              f"containerlab {clab or 'not installed on this host'}",
              f"python {platform.python_version()} (netlab, which wrote this bundle)",
              f"netlab {commit}" + (f" with {dirty} uncommitted changes" if dirty else "")]
    return "\n".join(lines) + "\n"


def clocks(inv: Inventory, lab: str, devices: list[str]) -> list[str]:
    """Each device's clock against this host's, read through docker exec."""
    lines = []
    for device in devices:
        before = time.time()
        theirs = float(run(exec_on(inv, lab, device, "python3", "-c", CLOCK)).stdout)
        after = time.time()
        lines.append(f"  {device:<5} {theirs - (before + after) / 2:+.3f} s (docker exec took {after - before:.3f} s)")
    return lines


def host_sync() -> str:
    for cmd in (["timedatectl", "show", "-p", "NTPSynchronized", "-p", "TimeUSec"], ["chronyc", "-n", "tracking"]):
        try:
            out = run(cmd)
        except FileNotFoundError:
            continue
        if out.returncode == 0 and out.stdout.strip():
            return f"$ {' '.join(cmd)}\n{out.stdout.strip()}"
    return "unknown: neither timedatectl nor chronyc answered on this host"


def copy_lab(topology: Path, dest: Path) -> list[str]:
    """The topology and every file it binds into a node, so the bundle can stand the lab up again."""
    topo = yaml.safe_load(topology.read_text())
    dest.mkdir(parents=True)
    shutil.copy(topology, dest / topology.name)
    sources = sorted({b.split(":", 1)[0] for node in topo["topology"]["nodes"].values() for b in node.get("binds") or []})
    for src in sources:
        (dest / src).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(topology.parent / src, dest / src)
    defaults = topo["topology"].get("defaults", {})
    return sorted({node.get("image", defaults.get("image")) for node in topo["topology"]["nodes"].values()})


def prepare(out: Path) -> None:
    """Start from an empty folder, but only ever delete an earlier bundle."""
    if out.exists() and any(out.iterdir()):
        if not (out / "finding.env").exists():
            raise FileExistsError(f"{out} is not empty and holds no finding bundle; not deleting it")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)


def write(inv: Inventory, build: str | Path, src: str, dst: str, out: str | Path, condition: str | Path | None = None) -> dict:
    """Locate, then write the bundle. Returns the finding as written to finding.json."""
    build, out = Path(build), Path(out)
    topology = build / "topology.clab.yml"
    lab = yaml.safe_load(topology.read_text())["name"]
    prepare(out)
    f = locate(inv, build, src, dst)
    ours = [d for d in f["path"] if inv.owner(d) == inv.operator]
    routers = [d for d in ours if d in inv.routers]

    # Every command locate ran, with its output exactly as printed.
    (out / "raw").mkdir()
    index = []
    for n, r in enumerate(f["raw"], start=1):
        name = f"{n:02d}-{r['on']}-{r['cmd'].split()[0]}-{r['cmd'].split()[-1]}.txt"
        (out / "raw" / name).write_text(r["output"])
        index.append(f"{name}: {r['on']}$ {r['cmd']}")

    # Our edge's hand-off port, captured while the edge pings the first address past it.
    capture = None
    edge = (f["edge"] or {}).get("device")
    if edge:
        nxt = f["path"][f["path"].index(edge) + 1]
        link = handoff(inv, edge, nxt)
        target = next(iter(f["edge"]["loss_pct"]))
        if link:
            iface, ours_ip, theirs_ip = link
            pcap, ping_out = capture_at_edge(inv, lab, edge, iface, target)
            (out / "pcap").mkdir()
            shutil.copy(HERE / "capture.py", out / "pcap" / "capture.py")  # how the capture was taken
            pcap_name = f"pcap/{edge}-{iface}.pcap"
            (out / pcap_name).write_bytes(pcap)
            name = f"{len(index) + 1:02d}-{edge}-ping-{target}-captured.txt"
            (out / "raw" / name).write_text(ping_out)
            index.append(f"{name}: {edge}$ {' '.join(ping_cmd(target))}   (while {pcap_name} was captured)")
            requests, replies = icmp_counts(pcap, target)
            capture = {"device": edge, "interface": iface, "filter": "IPv4 ICMP (protocol 1)", "file": pcap_name,
                       "target": target, "echo_requests": requests, "echo_replies": replies,
                       "ping_loss_pct": loss_pct(ping_out), "handoff": {"ours": ours_ip, "theirs": theirs_ip, "far_device": nxt}}
    (out / "raw" / "INDEX.txt").write_text("\n".join(index) + "\n")

    for router in routers:
        support_bundle(inv, lab, router, out / "support" / router)
    if routers:
        shutil.copy(SUPPORT_COMMANDS, out / "support" / SUPPORT_COMMANDS.name)
    images = copy_lab(topology, out / "lab")
    if condition:
        shutil.copy(condition, out / "lab" / "condition.sh")
    (out / "versions.txt").write_text(versions(inv, lab, images, routers))
    (out / "time.txt").write_text("\n".join([
        f"Finding started {f['started_utc']}, bundle finished {now()}. Every time in this bundle is UTC.",
        "Every device is a container on one host and reads that host's kernel clock, so the devices",
        "can't disagree with each other. Offsets read just now, which are docker exec latency, not clock error:",
        *clocks(inv, lab, ours),
        "This host's own sync to UTC:",
        host_sync(), ""]))

    f = {k: v for k, v in f.items() if k != "raw"} | {
        "raw": "raw/INDEX.txt", "capture": capture, "support": [f"support/{r}" for r in routers],
        "finished_utc": now(), "citations": CITATIONS}
    (out / "finding.json").write_text(json.dumps(f, indent=2) + "\n")
    (out / "finding.env").write_text(finding_env(f))
    shutil.copy(HERE / "reproduce.sh", out / "reproduce.sh")
    (out / "FINDING.md").write_text(finding_md(f, condition is not None))
    (out / "METHOD.md").write_text(method_md(f, edge, routers))
    write_sums(out)
    return f


def finding_env(f: dict) -> str:
    """What reproduce.sh needs, as shell variables: the path, the probes, the rule and the claim."""
    edge = f["edge"] or {}
    env = {"SRC": f["src"], "DST": f["dst"], "PROBES": PROBES, "INTERVAL": INTERVAL, "THRESHOLD": THRESHOLD,
           "HOPS": " ".join(s["far_end"] for s in f["segments"]), "PATH_DEVICES": " ".join(f["path"]),
           "OWNERS": "|".join(s["owner"] for s in f["segments"]),
           "EDGE": edge.get("device") or "", "BEYOND": " ".join(edge.get("loss_pct", {})),
           "SEGMENT": f["segment"] or "", "OWNER": f["owner"] or "", "OPERATOR": f["operator"]}
    return ("# Written by `netlab finding` and read by reproduce.sh. Nothing in it is secret.\n"
            + "".join(f"{k}={shlex.quote(str(v))}\n" for k, v in env.items()))


def write_sums(out: Path) -> None:
    lines = [f"{sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out)}" for p in sorted(out.rglob("*"))
             if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def finding_md(f: dict, has_condition: bool) -> str:
    rows = "\n".join(f"| {s['segment']} | {s['owner']} | {s['loss_pct']:.1f}% | {s['verdict']} |" for s in f["segments"])
    c = f["capture"]
    if f["segment"]:
        headline = f"Packet loss from {f['src']} to {f['dst']} starts on {f['segment']} ({f['owner']}) and persists to the destination."
    else:
        headline = f"No packet loss above {THRESHOLD:g}% from {f['src']} to {f['dst']}."
    edge = ""
    if f["edge"]:
        seen = ", ".join(f"{a} lost {loss:.1f}%" for a, loss in f["edge"]["loss_pct"].items())
        edge = f"\nFrom our edge router {f['edge']['device']} itself, with no campus link in the path: {seen}.\n"
    cap = ask = ""
    if c:
        cap = (f"Capture on {c['device']} {c['interface']}, our side of the hand-off ({c['file']}, ICMP only): "
               f"{c['echo_requests']} echo requests left for {c['target']} and {c['echo_replies']} echo replies came back.\n")
    if c and f["owner"] and f["owner"] != f["operator"]:  # the ask goes only to a counterparty we blame
        ask = (f"\n## What we ask you to check\n\nFrom your side of the hand-off ({c['handoff']['theirs']}), toward ours "
               f"({c['handoff']['ours']}):\n\n    ping -c {PROBES} -i {INTERVAL} -W 1 {c['handoff']['ours']}\n\n"
               f"More than {THRESHOLD:g}% lost (over {int(PROBES * THRESHOLD / 100)} of {PROBES}) from your side too confirms it. "
               "If you see none, send us your output and we will measure again.\n")
    lab = ("\n`lab/condition.sh` is for the lab only: it recreates on a fresh copy of the lab the fault this finding "
           "was taken under. On the real network, skip it: the fault is already there.\n") if has_condition else ""
    cites = "\n".join(f"- {name}: {text}" for name, text in f["citations"].items())
    return f"""# Finding: {f['segment'] or 'no loss'}{f' ({f["owner"]})' if f['owner'] else ''}

{headline} Measured by {f['operator']} from {f['started_utc']} to {f['finished_utc']} (UTC), {PROBES} probes per hop,
a hop counts as lossy above {THRESHOLD:g}%.

| Segment | Owner | Loss | Verdict |
|---|---|---|---|
{rows}
{edge}
{cap}{ask}
## Re-run it yourself

With this folder only: `sh reproduce.sh`. It checks SHA256SUMS and the image digests, re-runs the same
traceroute and pings, applies the same rule, and ends with `Reproduced: ...` (exit 0) or
`Did not reproduce: ...` (exit 1). Its raw output goes to `rerun-<UTC time>/`. To stand up the lab
copy first: `containerlab deploy -t lab/topology.clab.yml`.
{lab}
## Why this method holds

{cites}

How each figure was taken, with which versions and clock: METHOD.md, versions.txt, time.txt.
"""


def method_md(f: dict, edge: str | None, routers: list[str]) -> str:
    c = f["capture"]
    capture = (f"- Capture: pcap/capture.py on {c['device']} {c['interface']}, filter "
               f"{c['filter']}, 256-byte snap, while {c['device']} sent `{' '.join(ping_cmd(c['target']))}`. The router "
               "image has no tcpdump; the capture uses an AF_PACKET socket from the image's own Python, and "
               "timestamps are taken in userspace (about 1 ms).\n") if c else "- Capture: none (the path never left our network).\n"
    return f"""# Method

All commands ran on devices {f['operator']} owns, through `docker exec`. Nothing was run on, or
logged into, a device someone else owns.

- Path: `{f['method']['discover']}`.
- Loss: `{f['method']['probe']}`. Every hop is pinged from {f['src']} at the same time, so all hops see the
  same minutes. {"Every address past our edge is also pinged from " + edge + " itself, which takes every campus link out of that measurement." if edge else ""}
- Rule: a hop is lossy above {f['method']['threshold_pct']:g}% ({int(PROBES * THRESHOLD / 100)} of {PROBES} lost). Loss starts at the
  first hop from which every later hop is lossy too. A lossy hop with clean hops after it is a router
  rate-limiting replies to itself, and is never named. A healthy link with 0.5% background loss
  crosses the threshold 0.4% of the time; a 20% fault (40 +/- 6 lost) never falls under it.
- Loss is round-trip loss (RFC 6673): a lost request and a lost reply count the same.
{capture}- FRR support bundle from {', '.join(routers) or 'no router'} (support/): FRR's own `generate_support_bundle.py -c` with
  FRR 8.4.1's command list (support/{SUPPORT_COMMANDS.name}) minus `show running-config`, which prints BGP passwords in clear.
  The image ships the script but not the list, and without one it writes nothing and exits 0.
- Raw output of every command: raw/INDEX.txt. Versions: versions.txt. Clocks: time.txt.
- lab/: the rendered topology and configs the lab ran. They hold no BGP password (none is ever rendered),
  so a lab stood up from them runs its BGP session without TCP MD5, which ICMP probes don't depend on.
"""


def verify(out: str | Path) -> list[str]:
    """Every problem that would stop someone outside re-running or trusting the bundle."""
    out = Path(out)
    problems = [f"{name} is missing or empty" for name in REQUIRED if not (out / name).is_file() or not (out / name).stat().st_size]
    files = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file() and p.name != "SHA256SUMS"
             and not p.relative_to(out).parts[0].startswith("rerun-")}
    listed = {}
    if (out / "SHA256SUMS").is_file():
        listed = {rel: digest for digest, rel in (line.split("  ", 1) for line in (out / "SHA256SUMS").read_text().splitlines())}
    problems += [f"{rel} is not in SHA256SUMS" for rel in sorted(files - listed.keys())]
    for rel, digest in sorted(listed.items()):
        if rel not in files:
            problems.append(f"{rel} is in SHA256SUMS but missing")
        elif sha256((out / rel).read_bytes()).hexdigest() != digest:
            problems.append(f"{rel} changed after SHA256SUMS was written")
    if problems:
        return problems

    f = json.loads((out / "finding.json").read_text())
    for line in (out / "raw" / "INDEX.txt").read_text().splitlines():
        name = line.split(":", 1)[0]
        if not (out / "raw" / name).is_file() or not (out / "raw" / name).read_text().strip():
            problems.append(f"raw/{name} is missing or empty, so a figure has no raw output behind it")
    for folder in f["support"]:
        for proc in support_procs():
            log = out / folder / f"{proc}_support_bundle.log"
            if not log.is_file() or not log.read_text().strip():
                problems.append(f"{log.relative_to(out)} is missing or empty: the support bundle collected nothing")
    if f["edge"]:
        c = f.get("capture")
        if not c or not (out / c["file"]).is_file():
            problems.append("no capture from our edge's hand-off port (pcap/)")
        elif icmp_counts((out / c["file"]).read_bytes(), c["target"])[0] == 0:
            problems.append(f"{c['file']} holds no echo request to {c['target']}")
    finding_md = (out / "FINDING.md").read_text()
    problems += [f"FINDING.md cites no {name}" for name in CITATIONS if name not in finding_md]
    images = {line.split()[1]: line.split()[2] for line in (out / "versions.txt").read_text().splitlines() if line.startswith("image ")}
    topo = yaml.safe_load((out / "lab" / "topology.clab.yml").read_text())["topology"]
    for node in topo["nodes"].values():
        image = node.get("image", topo.get("defaults", {}).get("image"))
        if not images.get(image, "none").startswith(image.split(":")[0] + "@sha256:"):
            problems.append(f"versions.txt has no digest for {image}, and a tag can be re-pushed")
    for rel in sorted(files):
        text = (out / rel).read_bytes().decode(errors="replace")
        if PASSWORD_LINE.search(text):
            problems.append(f"{rel} holds a BGP password line")
    return sorted(set(problems), key=problems.index)
