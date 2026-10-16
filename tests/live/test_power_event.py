"""Power-event drill (OROS REC-6, docs/runbooks/power-event.md): the whole lab loses power and comes back
from startup config by itself. It redeploys every node, so it runs with `make power-drill` (weekly in
.github/workflows/drills.yml, on the full lab) and is skipped in a plain `make live`. On the full lab the
NOC must come back too: its sidecars share their nodes' network namespaces, so each is started again
after its node, and the NOC starts with no history (RISK-34)."""
import json
import os
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone

import pytest

from netlab.observe import Noc

from .conftest import ROOT, wait_for
from .test_collection import playbook
from .test_drift import intended_description

# The power cut: in CI `containerlab deploy --reconfigure`, which stops and recreates every node.
POWER_CYCLE = os.environ.get("POWER_CYCLE", "")
pytestmark = pytest.mark.skipif(not POWER_CYCLE, reason="power-event drill redeploys the whole lab: run it with make power-drill")


def routing_up(node, expected) -> bool:
    """Every OSPF adjacency Full, every BFD peer up and every BGP session Established, as the inventory expects."""
    for router, peers in expected["ospf_neighbors"].items():
        nbrs = node(router).vtysh_json("show ip ospf neighbor").get("neighbors", {})
        if sum(any(n.get("nbrState", "").startswith("Full") for n in v) for v in nbrs.values()) < len(peers):
            return False
    for router, peers in expected["bfd_peers"].items():
        up = {p["peer"] for p in node(router).vtysh_json("show bfd peers") if p.get("status") == "up"}
        if not set(peers) <= up:
            return False
    for s in expected["bgp_sessions"]:
        peers = node(s["router"]).vtysh_json("show bgp summary")["ipv4Unicast"]["peers"]
        if peers.get(s["address"], {}).get("state") != "Established":
            return False
    return True


def quietly(check, *args) -> bool:
    """A just-booted router refuses vtysh for a moment: a failed command or half-written JSON means "not yet"."""
    try:
        return check(*args)
    except (subprocess.CalledProcessError, ValueError):
        return False


def has_mark(r2, mark: str) -> bool:
    """Is the hand change in r2's running config? A bool, so a failed assert shows no config: pytest
    would otherwise print the whole running config into the JUnit file, any BGP password with it."""
    return mark in r2.run("vtysh", "-c", "show running-config", check=False).stdout


def noc_running(lab_name, expected) -> bool:
    """Is this the full lab (make deploy), with the NOC's sidecars, or the network alone (make deploy-network)?"""
    sidecars = expected.get("monitoring", {}).get("sidecars") or []
    return bool(sidecars) and subprocess.run(["docker", "inspect", f"clab-{lab_name}-{sidecars[0]}"],
                                             capture_output=True).returncode == 0


def test_power_event_recovers_from_startup_config(node, expected, lab_name):
    """After a whole-lab power cycle every node comes back by itself: an unsaved change is gone, OSPF, BFD and BGP are up; once make apply has set the BGP password again, users reach the web server, nothing has drifted, and on the full lab the NOC scrapes every target and hears every log source again, with nothing firing."""
    with_noc = noc_running(lab_name, expected)
    r2 = node("r2")
    mark = f"unsaved-{uuid.uuid4().hex[:8]}"
    r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {mark}")  # never saved
    try:
        assert has_mark(r2, mark), "the hand change on r2 didn't take"
        began = time.monotonic()
        subprocess.run(shlex.split(POWER_CYCLE), cwd=ROOT, check=True, capture_output=True, timeout=600)
        up = wait_for(lambda: quietly(routing_up, node, expected), timeout=240)
        recovered = round(time.monotonic() - began, 1)
        assert up, f"routing did not come back within {recovered} s of the power cycle"
        assert not has_mark(r2, mark), "the unsaved change survived: the lab was not power-cycled"
    finally:
        # Only if the power cut didn't take it away: put r2 back as the drift check expects it.
        if has_mark(r2, mark):
            r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {intended_description()}")
    # The BGP password is in no startup config (decision 0016), so the cut took it. Setting it again is
    # step 3 of the runbook: make apply. The session resets and comes back with it.
    applied = playbook("deploy.yml")
    assert applied.returncode == 0, "make apply failed after the power cycle:\n" + applied.stdout
    assert wait_for(lambda: quietly(routing_up, node, expected), timeout=120), "BGP did not come back once its password was set"
    # In the lab both ends lost the password, so the session could come back without it. It must not stay so.
    unauthenticated = [f"{router} -> {e['peer']}" for router, ends in expected.get("bgp_md5", {}).items() for e in ends
                       if not node(router).vtysh_json(f"show bgp neighbors {e['neighbor']}")[e["neighbor"]].get("authenticationEnabled")]
    assert unauthenticated == [], f"BGP came back without its password after make apply: {unauthenticated}"
    h2 = expected["hosts"]["h2"]
    # Polled: routes can still be going into the kernel, and h2's web server starting, when the
    # protocols already report up (failed once here, with another lab on the same CPUs).
    reached = wait_for(lambda: node("h1").tcp_open(h2, 80), timeout=60)
    assert reached, "h1 can't reach the web server through fw1 after the power cycle"
    drift = playbook("drift.yml")
    assert drift.returncode == 0, "a node came back different from its intended config:\n" + drift.stdout
    noc_back = None
    if with_noc:
        # A sidecar left in its node's old namespace would answer nothing, so its target stays down. The
        # first heartbeat can leave before OSPF has a route to the NOC; the next is a heartbeat later.
        mon = expected["monitoring"]
        noc = Noc(lab_name, mon["host"])
        assert noc_running(lab_name, expected), "the power cycle did not bring the NOC's sidecars back"
        settled = wait_for(lambda: noc.settled(mon["sources"]), timeout=mon["heartbeat"] + 60, interval=3)
        assert settled, "the NOC did not come back with every target up, every source heard and nothing firing (see make alerts)"
        noc_back = round(time.monotonic() - began, 1)
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "power-drill.json").write_text(json.dumps({
        "date": datetime.now(timezone.utc).isoformat(), "power_cycle": POWER_CYCLE,
        "seconds_to_routing_up": recovered, "seconds_to_noc_settled": noc_back}, indent=2) + "\n")
