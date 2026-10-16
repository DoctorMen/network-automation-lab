"""The finding bundle's checks, without a lab (OROS PRV-3): `netlab finding --verify` names every gap
that would stop someone outside re-running or trusting a bundle, and reproduce.sh says "Reproduced"
only when its own re-run agrees with the finding. reproduce.sh runs here against a stand-in for
docker that answers from canned traceroute and ping output."""
import ipaddress
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
import yaml

from netlab.finding import (CITATIONS, HERE, finding_env, finding_md, icmp_counts, method_md, prepare,
                            support_procs, verify, write_sums)

OURS, CARRIER = "campus NOC", "AS65100 carrier NOC"
HOPS = ["10.10.10.1", "10.0.100.1", "10.0.12.1", "203.0.113.1"]
DIGEST = "frrouting/frr@sha256:" + "0f8c" * 16


def icmp_frame(icmp_type, src, dst):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 1, 0,
                     ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return b"\x00" * 12 + b"\x08\x00" + ip + struct.pack("!BBHHH", icmp_type, 0, 0, 1, 1)


def pcap(*frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 256, 1)
    return out + b"".join(struct.pack("<IIII", 0, 0, len(f), len(f)) + f for f in frames)


def make_bundle(path):
    """A complete bundle for loss on r2-isp, written with the same functions `netlab finding` uses."""
    owners = [OURS, OURS, OURS, CARRIER]
    f = {"src": "h1", "dst": HOPS[-1], "operator": OURS, "started_utc": "2026-10-15T00:00:00+00:00",
         "finished_utc": "2026-10-15T00:00:15+00:00", "path": ["h1", "fw1", "r1", "r2", "isp"],
         "method": {"discover": "traceroute -I -n -q 1 -w 1 203.0.113.1", "probe": "ping -q -c 200 -i 0.02 -W 1 <hop>",
                    "threshold_pct": 2.0},
         "segments": [{"segment": f"{a}-{b}", "far_end": hop, "owner": owner, "loss_pct": 20.0 if owner == CARRIER else 0.0,
                       "verdict": "loss starts here" if owner == CARRIER else "clean"}
                      for a, b, hop, owner in zip(["h1", "fw1", "r1", "r2"], ["fw1", "r1", "r2", "isp"], HOPS, owners)],
         "edge": {"device": "r2", "loss_pct": {HOPS[-1]: 20.0}}, "segment": "r2-isp", "owner": CARRIER,
         "raw": "raw/INDEX.txt", "support": ["support/r2"], "citations": CITATIONS,
         "capture": {"device": "r2", "interface": "eth3", "filter": "IPv4 ICMP (protocol 1)", "file": "pcap/r2-eth3.pcap",
                     "target": HOPS[-1], "echo_requests": 1, "echo_replies": 0, "ping_loss_pct": 100.0,
                     "handoff": {"ours": "198.51.100.0", "theirs": "198.51.100.1", "far_device": "isp"}}}
    path.mkdir()
    (path / "finding.json").write_text(json.dumps(f))
    (path / "finding.env").write_text(finding_env(f))
    (path / "FINDING.md").write_text(finding_md(f, False))
    (path / "METHOD.md").write_text(method_md(f, "r2", ["r2"]))
    shutil.copy(HERE / "reproduce.sh", path / "reproduce.sh")
    (path / "versions.txt").write_text(f"image frrouting/frr:v8.4.1 {DIGEST}\n")
    (path / "time.txt").write_text("Every time in this bundle is UTC.\n")
    (path / "raw").mkdir()
    (path / "raw" / "01-h1-ping-203.0.113.1.txt").write_text("200 packets transmitted, 160 packets received\n")
    (path / "raw" / "INDEX.txt").write_text("01-h1-ping-203.0.113.1.txt: h1$ ping -q -c 200 -i 0.02 -W 1 203.0.113.1\n")
    (path / "lab").mkdir()
    topo = {"name": "lab", "topology": {"defaults": {"image": "frrouting/frr:v8.4.1"}, "nodes": {"r2": {"kind": "linux"}}}}
    (path / "lab" / "topology.clab.yml").write_text(yaml.safe_dump(topo))
    (path / "support" / "r2").mkdir(parents=True)
    for proc in support_procs():
        (path / "support" / "r2" / f"{proc}_support_bundle.log").write_text("r2# show version\nFRRouting 8.4.1\n")
    (path / "pcap").mkdir()
    (path / "pcap" / "r2-eth3.pcap").write_bytes(pcap(icmp_frame(8, "198.51.100.0", HOPS[-1])))
    write_sums(path)
    return path


def test_verify_names_every_gap_in_a_bundle(tmp_path):
    """A complete bundle passes. Each gap is named: a missing file, an edit after SHA256SUMS, an empty support log (FRR's script writes nothing without its command list), a capture with no probe in it, a missing citation, an image without a digest, and a BGP password."""
    assert verify(make_bundle(tmp_path / "good")) == []

    def broken(name, change, resum=True):
        path = make_bundle(tmp_path / name)
        change(path)
        if resum:
            write_sums(path)
        return verify(path)

    password = " ".join(["neighbor", "198.51.100.1", "password", "s3cret"])  # joined, so gitleaks doesn't flag this file
    assert "versions.txt is missing or empty" in broken("versions", lambda p: (p / "versions.txt").unlink())
    assert "METHOD.md changed after SHA256SUMS was written" in \
        broken("edited", lambda p: (p / "METHOD.md").write_text("trust us\n"), resum=False)
    assert "support/r2/zebra_support_bundle.log is missing or empty: the support bundle collected nothing" in \
        broken("support", lambda p: (p / "support" / "r2" / "zebra_support_bundle.log").write_text(""))
    assert "pcap/r2-eth3.pcap holds no echo request to 203.0.113.1" in \
        broken("pcap", lambda p: (p / "pcap" / "r2-eth3.pcap").write_bytes(pcap()))
    assert "FINDING.md cites no RFC 6673" in \
        broken("cite", lambda p: (p / "FINDING.md").write_text((p / "FINDING.md").read_text().replace("RFC 6673", "an RFC")))
    assert "versions.txt has no digest for frrouting/frr:v8.4.1, and a tag can be re-pushed" in \
        broken("digest", lambda p: (p / "versions.txt").write_text("image frrouting/frr:v8.4.1 none\n"))
    assert "support/r2/bgp_support_bundle.log holds a BGP password line" in \
        broken("password", lambda p: (p / "support" / "r2" / "bgp_support_bundle.log").write_text(f"router bgp 65001\n {password}\n"))
    # The tag backups carry instead of a password is not a password.
    tag = "neighbor 198.51.100.1 password sha256:" + "ab" * 32
    assert broken("tag", lambda p: (p / "support" / "r2" / "bgp_support_bundle.log").write_text(f"router bgp 65001\n {tag}\n")) == []


FAKE_DOCKER = """#!/bin/sh
# Stand-in for docker: answers reproduce.sh from FAKE_* variables instead of a lab.
if [ "$1" = image ]; then echo "$FAKE_DIGESTS"; exit 0; fi
shift; device=${1#clab-*-}; shift   # exec clab-<lab>-<device> <command...>
case $1 in
  traceroute)
    echo "traceroute to x, 30 hops max"; n=0
    for hop in $FAKE_TRACE; do n=$((n + 1)); echo " $n  $hop  0.1 ms"; done ;;
  ping)
    for arg; do address=$arg; done
    lost=0
    for rule in $FAKE_LOST; do [ "${rule%=*}" != "$device:$address" ] || lost=${rule#*=}; done
    echo "200 packets transmitted, $((200 - lost)) packets received" ;;
esac
"""


@pytest.fixture
def rerun(tmp_path):
    """Run a fresh copy of the bundle's reproduce.sh against the stand-in docker."""
    bundle = make_bundle(tmp_path / "bundle")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "docker").write_text(FAKE_DOCKER)
    (tmp_path / "bin" / "docker").chmod(0o755)

    def run(lost="", trace=" ".join(HOPS), digests=DIGEST, change=None):
        if change:
            change(bundle)
        env = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "WAIT": "0",
               "FAKE_LOST": lost, "FAKE_TRACE": trace, "FAKE_DIGESTS": digests}
        return subprocess.run(["sh", "reproduce.sh"], cwd=bundle, env=env, capture_output=True, text=True, timeout=60)
    return run


def test_reproduce_agrees_only_when_its_own_run_does(rerun, tmp_path):
    """reproduce.sh says Reproduced for carrier loss seen from h1 and from r2, and no to a clean path, a hop that only rate-limits, campus loss, or an edge that sees no loss; it won't judge a changed path, an edited bundle (without running the edit) or another image."""
    carrier = "h1:203.0.113.1=40 r2:203.0.113.1=41"
    ok = rerun(carrier)
    assert ok.returncode == 0 and f"Reproduced: loss starts on r2-isp (owner: {CARRIER})" in ok.stdout, ok.stdout + ok.stderr
    for lost, said in [("", "this run found no loss above 2.0%"),
                       ("h1:10.0.12.1=40", "this run found no loss above 2.0%"),  # r2 rate-limits pings to itself
                       ("h1:10.0.12.1=40 h1:203.0.113.1=40", f"this run found r1-r2 ({OURS})"),
                       ("h1:203.0.113.1=40", "our edge's direct view does not match the finding")]:
        no = rerun(lost)
        assert no.returncode == 1 and said in no.stdout, f"{lost!r}: {no.stdout}"
    for kw, said in [({"trace": "10.10.10.1 10.0.100.1 * 203.0.113.1"}, "Can't tell: h1's path to 203.0.113.1 is"),
                     ({"digests": "frrouting/frr@sha256:" + "ffff" * 16}, "Can't tell: frrouting/frr:v8.4.1 here is not"),
                     ({"change": lambda b: (b / "finding.env").write_text(f"SEGMENT=r1-r2\ntouch {tmp_path}/edited-env-ran\n")},
                      "Can't tell: files changed")]:
        unsure = rerun(carrier, **kw)
        assert unsure.returncode == 2 and said in unsure.stdout, f"{kw}: {unsure.stdout}"
    assert not (tmp_path / "edited-env-ran").exists(), "reproduce.sh ran an edited finding.env before checking SHA256SUMS"


def test_pcap_counts_only_echo_to_and_from_the_target():
    """The capture summary counts echo requests to the target and replies from it, nothing else."""
    target, other = "203.0.113.1", "10.0.12.1"
    data = pcap(icmp_frame(8, "198.51.100.0", target), icmp_frame(8, "198.51.100.0", target), icmp_frame(0, target, "198.51.100.0"),
                icmp_frame(8, "198.51.100.0", other), icmp_frame(0, other, "198.51.100.0"), icmp_frame(11, target, "198.51.100.0"))
    assert icmp_counts(data, target) == (2, 1)
    assert icmp_counts(b"not a pcap" + data, target) == (0, 0)


def test_only_an_earlier_bundle_is_ever_deleted(tmp_path):
    """`netlab finding` replaces a folder that holds a bundle, and refuses to empty any other folder."""
    old = make_bundle(tmp_path / "old")
    prepare(old)
    assert old.is_dir() and not any(old.iterdir())
    keep = tmp_path / "notes"
    keep.mkdir()
    (keep / "todo.txt").write_text("mine\n")
    with pytest.raises(FileExistsError, match="holds no finding bundle"):
        prepare(keep)
    assert (keep / "todo.txt").read_text() == "mine\n"
