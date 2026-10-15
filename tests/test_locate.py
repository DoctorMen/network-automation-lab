"""locate's rules, checked without a lab: it only logs into devices we own, and it doesn't
mistake a router rate-limiting pings to itself for loss."""
import subprocess
from pathlib import Path

import pytest

from netlab.inventory import load
from netlab.locate import discover, exec_on, loss_pct, loss_starts

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "network.yml"


def test_never_logs_into_a_device_we_dont_own():
    """The carrier's router is refused before any command runs, because of who owns it."""
    inv = load(INVENTORY)
    assert exec_on(inv, "lab", "r2", "true") == ["docker", "exec", "clab-lab-r2", "true"]
    with pytest.raises(PermissionError, match="AS65100 carrier NOC"):
        exec_on(inv, "lab", "isp", "true")
    # The rule follows the owner field, not a device name.
    inv.raw["routers"]["r3"]["owner"] = "AS65100 carrier NOC"
    with pytest.raises(PermissionError):
        exec_on(inv, "lab", "r3", "true")


def test_loss_must_persist_to_the_destination():
    """Only loss that carries on to the destination is a fault; it starts where it begins to persist."""
    assert loss_starts([0, 0, 0, 20]) == 3
    assert loss_starts([0, 30, 0, 0]) is None
    assert loss_starts([0, 30, 0, 20, 21]) == 3


def test_traces_again_when_a_hop_did_not_answer(monkeypatch):
    """Skipping a silent r2 would merge r1-r2 into the carrier's segment, so locate traces again."""
    runs = iter([" 1  10.10.10.1\n 2  10.0.100.1\n 3  *\n 4  203.0.113.1\n",
                 " 1  10.10.10.1\n 2  10.0.100.1\n 3  10.0.12.1\n 4  203.0.113.1\n"])
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "traceroute to 203.0.113.1\n" + next(runs)))
    hops = discover(load(INVENTORY), "lab", "h1", "203.0.113.1")
    assert hops == ["10.10.10.1", "10.0.100.1", "10.0.12.1", "203.0.113.1"]


def test_reads_busybox_and_iputils_ping():
    """Loss comes from sent and received counts, and a ping that can't run at all counts as 100%."""
    assert loss_pct("200 packets transmitted, 160 packets received, 20% packet loss") == 20.0
    assert loss_pct("200 packets transmitted, 199 received, 0.5% packet loss, time 3982ms") == 0.5
    assert loss_pct("ping: sendto: Network unreachable") == 100.0
