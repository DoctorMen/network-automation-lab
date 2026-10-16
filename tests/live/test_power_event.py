"""Power-event drill (OROS REC-6, docs/runbooks/power-event.md): the whole lab loses power and comes back
from startup config by itself. It redeploys every node, so it runs with `make power-drill` (weekly in
.github/workflows/drills.yml) and is skipped in a plain `make live`."""
import json
import os
import re
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


def test_power_event_recovers_from_startup_config(node, expected):
    """After a whole-lab power cycle every node comes back by itself: an unsaved change is gone, OSPF, BFD and BGP are up; once make apply has set the BGP password again, users reach the web server and nothing has drifted."""
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
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "power-drill.json").write_text(json.dumps({
        "date": datetime.now(timezone.utc).isoformat(), "power_cycle": POWER_CYCLE,
        "seconds_to_routing_up": recovered}, indent=2) + "\n")



FACILITY = r"(?:kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|local[0-7])\.[a-z]+"


def message(line: str) -> str | None:
    """'HH:MM:SS tag: text' of a syslog line, as the box keeps it ('Oct 16 02:05:39 r2 user.notice tag: text') or
    as the collector got it ('<13>Oct 16 02:05:39 tag: text'), so the two copies of one line compare equal."""
    m = re.match(rf"(?:<\d+>)?\w{{3}} +\d+ (\d\d:\d\d:\d\d) (?:\S+ {FACILITY} )?(.*)$", line.strip())
    return f"{m[1]} {m[2].strip()}" if m else None


def age(key: str, now: float) -> int:
    """Seconds between a message() key's clock time and `now`, across midnight too (the boxes keep UTC)."""
    h, m, s = (int(x) for x in key[:8].split(":"))
    return int(now % 86400 - (h * 3600 + m * 60 + s)) % 86400


def test_evidence_outlives_a_power_cut(node, expected, lab_name):
    """OROS FND-2 (decision 0025): a link on r2 fails, its flight recorder sends a state dump, and then the power goes,
    the NOC's included. Afterwards the central store still has the dump, complete, and every line r2's own log held
    from its last five minutes, while r2 itself has lost them. Then the lab is put back as the other drill does."""
    mon = expected["monitoring"]
    if subprocess.run(["docker", "inspect", f"clab-{lab_name}-{mon['sidecars'][0]}"], capture_output=True).returncode:
        pytest.skip("the NOC is not running: this drill needs the full lab (make deploy)")
    noc, r2 = Noc(lab_name, mon["host"]), node("r2")
    assert wait_for(noc.ready, timeout=60), "Loki is not ready before the drill"
    mark = f"FND2-{uuid.uuid4().hex[:12]}"
    r2.run("logger", "-t", "netlab-drill", mark)
    since = time.time()
    # The brown-out before the cut: r2's link to r3 drops for a second, and the recorder fires.
    r2.run("sh", "-c", "ip link set eth2 down && sleep 1 && ip link set eth2 up")
    dump = wait_for(lambda: noc.logs('{node="r2",source="syslog"} |= "flightrec" |= "begin trigger: eth2 "', since),
                    timeout=mon["flightrec"]["delay"] + 15, interval=1)
    assert dump, "r2's flight recorder sent no dump"
    dump_id = dump[0][2].split("flightrec: ", 1)[1].split()[0]
    # What r2's own log holds from its last five minutes, once every line of it has reached the store.
    now = time.time()
    recent = {k for k in map(message, r2.run("sh", "-c", "cat /var/log/messages*").stdout.splitlines()) if k and age(k, now) <= 300}
    assert any(mark in k for k in recent) and any(dump_id in k for k in recent), "r2's own log lacks the marker or the dump"

    def stored(start, end=None):
        return noc.logs('{node="r2",source="syslog"}', start, end, every=True)
    assert wait_for(lambda: not recent - {message(l) for _, _, l in stored(now - 400)}, timeout=30, interval=2), \
        "r2's last lines never reached the central store"
    cut = time.time()
    subprocess.run(shlex.split(POWER_CYCLE), cwd=ROOT, check=True, capture_output=True, timeout=600)
    try:
        assert wait_for(noc.ready, timeout=180, interval=3), "Loki did not come back after the power cut"
        back = round(time.time() - cut, 1)
        kept = stored(cut - 400, cut + 1)
        missing = recent - {message(l) for _, _, l in kept}
        assert not missing, f"{len(missing)} of r2's last {len(recent)} lines are gone from the store: {sorted(missing)[:3]}"
        ours = [l for _, _, l in kept if dump_id in l]
        end = next(l for l in ours if f"{dump_id} end " in l)
        assert len(ours) == int(end.split(f"{dump_id} end ")[1].split()[0]) + 2, "the dump is not complete after the cut"
        assert mark not in r2.run("sh", "-c", "cat /var/log/messages* 2>/dev/null", check=False).stdout, \
            "r2 still has its own copy: it was not reset"
        (ROOT / "results").mkdir(exist_ok=True)
        (ROOT / "results" / "evidence-drill.json").write_text(json.dumps({
            "date": datetime.now(timezone.utc).isoformat(), "power_cycle": POWER_CYCLE, "dump": dump_id, "dump_lines": len(ours),
            "r2_lines_from_its_last_5_minutes": len(recent), "of_them_in_the_store_after_the_cut": len(recent) - len(missing),
            "seconds_from_cut_to_store_answering": back}, indent=2) + "\n")
    finally:
        # Put back as the other drill does: the BGP password, routing, and every scrape answering.
        applied = playbook("deploy.yml")
        assert applied.returncode == 0, "make apply failed after the power cycle:\n" + applied.stdout
        assert wait_for(lambda: quietly(routing_up, node, expected), timeout=240), "routing did not come back"
        assert wait_for(lambda: all(t["health"] == "up" for t in noc.targets()), timeout=120), "the NOC's scrapes did not come back"
