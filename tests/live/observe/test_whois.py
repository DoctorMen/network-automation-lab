"""Who did it behind the NAT (OROS FND-5, decision 0031): an outside complaint gives the NAT address, a port
and a time, and `make whois` names the inside host that held them, reading only the NOC's copy of r2's
translation log. That the NAT itself is narrow and holds is tests/live/test_nat.py."""
import ipaddress
import json
import random
import subprocess
import sys
import time

from netlab.who import SKEW

from ..conftest import ROOT, wait_for
from ..test_nat import connect, far_end

# Inside ports above the kernel's ephemeral range (32768 to 60999), picked at random each run, so no other
# connection in the lab has used one, and a run an hour before used another.
PORTS = range(61000, 65000)


def whois(address, port, at, remote=None, within=None):
    args = [sys.executable, "-m", "netlab.who", "--json", "flow", address, str(port), str(at),
            *(["--remote", remote] if remote else []), *(["--within", str(within)] if within else [])]
    out = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert out.returncode in (0, 1, 3), out.stdout + out.stderr
    return json.loads(out.stdout)


def logged(noc, router, local, port, since):
    """The translations this test made (its own inside port to this far-end port) that are in the central store.
    Matching the inside port too keeps a line from an earlier run of the test from counting."""
    return noc.logs(f'{{node="{router}",source="nat"}} |= "sport={local} dport={port} [UNREPLIED]"', since - 5)


def test_a_complaint_names_the_inside_host_from_the_noc_alone(node, expected, noc):
    """The far end sees only the NAT address and a port. From that, the time, and the NOC's store, the lookup
    names h1, its own address and the port it used; a port nobody held, or a time before the connection,
    names no one."""
    translated = expected["nat"]["r2"]
    carrier = expected["loopbacks"][translated["carrier"]]
    local = random.choice(PORTS[:-1])
    since = time.time()
    with far_end(node, translated["carrier"], carrier, 8083) as seen:
        connect(node, "h1", carrier, 8083, local_port=local)
        (address, port, at), = seen()
    assert address == translated["address"], f"the far end saw {address}, not the NAT address"
    assert wait_for(lambda: logged(noc, "r2", local, 8083, since), timeout=15, interval=1), "the translation never reached the store"
    found = whois(address, port, at)
    assert found["verdict"] == "one", found
    (h,) = found["holders"]
    assert (h["device"], h["inside"], h["inside_port"]) == ("h1", expected["hosts"]["h1"], local), h
    assert (h["remote"], h["remote_port"]) == (carrier, 8083), h
    # Since this test began, nothing held the next port; and in the minute before it, nothing held this one.
    assert whois(address, port + 1, at, within=at - since + 5)["verdict"] == "none"
    assert whois(address, port, since - SKEW - 1, within=60)["verdict"] == "none"


def test_the_same_inside_port_from_two_hosts_names_each_by_its_own_outside_port(node, expected, noc):
    """Two machines on LAN-A (h1 and a second address on h1's port, standing in for a second user) open the
    same inside port to the same far end. They leave on different outside ports, and each complaint names its
    own inside address, so the lookup follows the translation, not the port number."""
    translated = expected["nat"]["r2"]
    carrier = expected["loopbacks"][translated["carrier"]]
    h1 = node("h1")
    # An address on LAN-A no host owns (h3 has 10.10.10.11 since sw1), so the stand-in user collides with nobody.
    owned = set(expected["hosts"].values())
    second = next(str(a) for a in ipaddress.ip_network(f"{expected['hosts']['h1']}/24", strict=False).hosts()
                  if a.packed[-1] >= 20 and str(a) not in owned)
    local = random.choice(PORTS)
    since = time.time()
    try:
        h1.run("ip", "addr", "add", f"{second}/24", "dev", "eth1")
        with far_end(node, translated["carrier"], carrier, 8084, count=2) as seen:
            connect(node, "h1", carrier, 8084, local_port=local)
            connect(node, "h1", carrier, 8084, local_port=local, bind=second)
            complaints = seen()
    finally:
        h1.run("ip", "addr", "del", f"{second}/24", "dev", "eth1", check=False)
    assert len(complaints) == 2 and {a for a, _p, _t in complaints} == {translated["address"]}, complaints
    assert complaints[0][1] != complaints[1][1], "two inside hosts got the same outside port to the same far end"
    assert wait_for(lambda: len(logged(noc, "r2", local, 8084, since)) >= 2, timeout=15, interval=1)
    named = [whois(a, p, t, remote=f"{carrier}:8084") for a, p, t in complaints]
    assert [n["verdict"] for n in named] == ["one", "one"], named
    assert [(n["holders"][0]["inside"], n["holders"][0]["inside_port"]) for n in named] == \
        [(expected["hosts"]["h1"], local), (second, local)], named
