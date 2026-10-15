"""A finding someone outside the team can re-run (OROS PRV-3). With loss on the carrier link,
`netlab finding` writes a bundle that passes its own check and holds no BGP password. Its
reproduce.sh, run from a copy away from the repo with nothing but sh and docker, names the same
segment and owner, and says it did not reproduce once the loss is gone. CI then re-runs the same
bundle on a clean runner (the `reproduce` job)."""
import json
import shlex
import shutil
import subprocess
import sys

from netlab import secrets
from netlab.finding import verify
from netlab.locate import PROBES, THRESHOLD, loss_pct, ping_cmd

from .conftest import ROOT
from .test_locate import converged, icmp_loss, icmp_loss_rule

BUNDLE = ROOT / "results" / "finding"  # CI uploads this folder for the reproduce job


def condition_script(device, interface):
    """lab/condition.sh: the same fault as icmp_loss, for a fresh copy of the lab."""
    rule = " ".join(shlex.quote(arg) for arg in icmp_loss_rule(interface))
    return f"""#!/bin/sh
# Lab only: recreates the fault this finding was taken under on a fresh copy of the lab.
# 20% of ICMP arriving on {device} {interface} is dropped, to {device} and through it, like a lossy link.
set -eu
cd "$(dirname "$0")"
LAB=${{LAB:-$(sed -n 's/^name: *//p' topology.clab.yml)}}
for chain in INPUT FORWARD; do
  docker exec "clab-$LAB-{device}" iptables -I "$chain" {rule}
done
"""


def reproduce(folder):
    return subprocess.run(["sh", "reproduce.sh"], cwd=folder, capture_output=True, text=True, timeout=300)


def test_carrier_finding_reproduces_from_the_bundle_alone(node, expected, tmp_path):
    """The bundle passes --verify and holds no BGP password; a copy of it re-run with reproduce.sh names r2-isp and the carrier, the ping we ask the carrier for shows their loss from their side, and with the loss gone reproduce.sh says it did not reproduce."""
    converged(node, expected)
    condition = tmp_path / "condition.sh"
    condition.write_text(condition_script("isp", "eth1"))
    sent = tmp_path / "sent"  # what the carrier receives: a copy, away from the repo
    with icmp_loss(node, "isp", "eth1"):
        made = subprocess.run([sys.executable, "-m", "netlab", "finding", "--src", "h1", "--dst", expected["loopbacks"]["isp"],
                               "--bundle", str(BUNDLE), "--condition", str(condition)],
                              cwd=ROOT, capture_output=True, text=True, timeout=300)
        assert made.returncode == 0, f"netlab finding failed or its bundle is incomplete:\n{made.stdout}{made.stderr}"
        shutil.copytree(BUNDLE, sent)
        rerun = reproduce(sent)
        f = json.loads((BUNDLE / "finding.json").read_text())
        ask = f["capture"]["handoff"]
        theirs = node(ask["far_device"]).run(*ping_cmd(ask["ours"]), check=False, timeout=60).stdout
    clean = reproduce(sent)

    assert f["segment"] == "r2-isp" and f["owner"] == expected["owners"]["isp"], f["segments"]
    assert verify(BUNDLE) == []
    values = [secrets.read(s["secret"]) for ends in expected.get("bgp_md5", {}).values() for s in ends]
    leaked = [str(p.relative_to(sent)) for p in sent.rglob("*") if p.is_file() and any(v.encode() in p.read_bytes() for v in values)]
    assert not leaked, f"a BGP password in clear in the bundle: {leaked}"
    # Our edge port sent every echo request; the replies that are missing went missing past it.
    assert f["capture"]["echo_requests"] == PROBES and f["capture"]["echo_replies"] < PROBES * (1 - THRESHOLD / 100), f["capture"]
    assert rerun.returncode == 0 and f"Reproduced: loss starts on r2-isp (owner: {f['owner']})" in rerun.stdout, rerun.stdout
    assert loss_pct(theirs) > THRESHOLD, f"the ping we ask the carrier to run shows no loss from their side:\n{theirs}"
    # The same script must be able to say no, or "Reproduced" would prove nothing.
    assert clean.returncode == 1 and "Did not reproduce" in clean.stdout, clean.stdout
