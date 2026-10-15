"""Locating loss (OROS PRV-2): clear our own segments first, then name where loss starts and who
owns it, using only devices we own. Loss is injected for ICMP only, so OSPF, BGP and BFD stay up."""
import json
import subprocess
import sys
from contextlib import contextmanager

from netlab.locate import THRESHOLD

from .conftest import BUILD, ROOT, wait_for
from .test_routing import full_neighbors


def converged(node, expected):
    """Earlier tests may have just broken links. Probe only once OSPF is Full and the path works."""
    for router, peers in expected["ospf_neighbors"].items():
        want = {expected["loopbacks"][p] for p in peers}
        assert wait_for(lambda: full_neighbors(node, router) == want), f"{router} OSPF not Full"
    assert wait_for(lambda: node("h1").ping(expected["loopbacks"]["isp"], count=1)), "h1 can't reach the internet"


def locate(dst):
    subprocess.run([sys.executable, "-m", "netlab", "locate", "--src", "h1", "--dst", dst, "--out", str(BUILD)],
                   cwd=ROOT, check=True, timeout=120)
    return json.loads((BUILD / "finding.json").read_text())


def icmp_loss_rule(interface):
    return ["-i", interface, "-p", "icmp", "-m", "statistic", "--mode", "random", "--probability", "0.2", "-j", "DROP"]


@contextmanager
def icmp_loss(node, device, interface):
    """Drop 20% of ICMP arriving on one interface, to the device and through it, like a lossy link."""
    rule = icmp_loss_rule(interface)
    try:
        for chain in ("INPUT", "FORWARD"):
            node(device).run("iptables", "-I", chain, *rule)
        yield
    finally:
        for chain in ("INPUT", "FORWARD"):
            node(device).run("iptables", "-D", chain, *rule, check=False)


def test_clean_path_raises_no_alarm(node, expected):
    """No false alarm: on a healthy path every segment, ours and the carrier's, is clean."""
    converged(node, expected)
    f = locate(expected["loopbacks"]["isp"])
    assert f["segment"] is None, f"blamed {f['segment']} on a clean lab"
    assert all(s["loss_pct"] <= THRESHOLD for s in f["segments"]), f["segments"]


def test_carrier_loss_is_placed_on_the_carrier(node, expected):
    """Loss on the carrier link: every campus segment is cleared and r2-isp is handed to the carrier."""
    converged(node, expected)
    with icmp_loss(node, "isp", "eth1"):
        f = locate(expected["loopbacks"]["isp"])
    ours = [s for s in f["segments"] if s["owner"] == expected["operator"]]
    assert ours and all(s["verdict"] == "clean" for s in ours), f"our own segments not cleared: {ours}"
    assert f["segment"] == "r2-isp", f["segments"]
    assert f["owner"] == expected["owners"]["isp"]
    # From our edge router alone, with no campus link in the path, the carrier still loses packets.
    assert f["edge"]["device"] == "r2" and all(loss > THRESHOLD for loss in f["edge"]["loss_pct"].values()), f["edge"]


def test_campus_loss_is_not_blamed_on_the_carrier(node, expected):
    """Loss on the r1-r2 link: it's named as ours, and from our edge the carrier is clean."""
    converged(node, expected)
    # r2 eth1 is where h1's probes to r2 and beyond arrive from r1; FORWARD catches the ones r2 passes on.
    with icmp_loss(node, "r2", "eth1"):
        f = locate(expected["loopbacks"]["isp"])
    assert f["segment"] == "r1-r2", f["segments"]
    assert f["owner"] == expected["owners"]["r2"] == expected["operator"]
    assert all(loss <= THRESHOLD for loss in f["edge"]["loss_pct"].values()), f["edge"]
