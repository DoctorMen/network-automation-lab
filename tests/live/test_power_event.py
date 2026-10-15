"""Power-event drill (OROS REC-6, docs/runbooks/power-event.md): the whole lab loses power and comes back
from startup config by itself. It redeploys every node, so it runs with `make power-drill` (weekly in
.github/workflows/drills.yml) and is skipped in a plain `make live`."""
import json
import os
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone

import pytest

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


def test_power_event_recovers_from_startup_config(node, expected):
    """After a whole-lab power cycle every node comes back by itself: an unsaved change is gone, OSPF, BFD and BGP are up, users reach the web server and nothing has drifted."""
    r2 = node("r2")
    mark = f"unsaved-{uuid.uuid4().hex[:8]}"
    r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {mark}")  # never saved
    try:
        assert mark in r2.vtysh("show running-config")
        began = time.monotonic()
        subprocess.run(shlex.split(POWER_CYCLE), cwd=ROOT, check=True, capture_output=True, timeout=600)
        up = wait_for(lambda: quietly(routing_up, node, expected), timeout=240)
        recovered = round(time.monotonic() - began, 1)
        assert up, f"routing did not come back within {recovered} s of the power cycle"
        assert mark not in r2.vtysh("show running-config"), "the unsaved change survived: the lab was not power-cycled"
    finally:
        # Only if the power cut didn't take it away: put r2 back as the drift check expects it.
        if mark in r2.run("vtysh", "-c", "show running-config", check=False).stdout:
            r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {intended_description()}")
    h2 = expected["hosts"]["h2"]
    assert node("h1").tcp_open(h2, 80), "h1 can't reach the web server through fw1 after the power cycle"
    drift = playbook("drift.yml")
    assert drift.returncode == 0, "a node came back different from its intended config:\n" + drift.stdout
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "power-drill.json").write_text(json.dumps({
        "date": datetime.now(timezone.utc).isoformat(), "power_cycle": POWER_CYCLE,
        "seconds_to_routing_up": recovered}, indent=2) + "\n")
