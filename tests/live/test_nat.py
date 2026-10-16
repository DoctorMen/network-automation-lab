"""Source NAT on r2 for the users (OROS FND-5, decision 0031), on the network alone: LAN-A reaches the internet
from the one address the carrier assigned, everything else keeps its own address, and nothing from outside
reaches an inside host through that address unasked. A translation added by hand fails the drift check
(tests/live/test_edge.py::test_edge_filter_hand_change_is_flagged, in the same drift run as the filter's
hand changes). That the translation log at the NOC names the inside host behind an outside complaint is
tests/live/observe/test_whois.py."""
import subprocess
from contextlib import contextmanager
from pathlib import Path

from .conftest import wait_for

COMPLAINT = (Path(__file__).parent / "tools" / "complaint.py").read_text()


@contextmanager
def far_end(node, device, address, port, count=1, timeout=20):
    """A server on the internet (tools/complaint.py on `device`) that notes who connects. Yields a function
    that returns [(peer address, peer port, time)] once `count` connections came or `timeout` passed."""
    # The script goes on python3's command line (-c), so the helper has no stdin to close: communicate() on
    # Python 3.12 flushes a stdin it was given even when it is closed, and fails.
    proc = subprocess.Popen(["docker", "exec", node(device).container, "python3", "-c", COMPLAINT, address, str(port), str(count), str(timeout)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "listening", proc.stderr.read()

        def seen():
            out, _ = proc.communicate(timeout=timeout + 10)
            return [(a, int(p), float(t)) for a, p, t in (l.split() for l in out.splitlines())]
        yield seen
    finally:
        proc.kill()


def connect(node, src, address, port, local_port=None, bind=None):
    """One TCP connection from src, from a chosen local port and address if given (busybox nc)."""
    args = ["nc", "-w", "2", *(["-p", str(local_port)] if local_port else []), *(["-s", bind] if bind else []), address, str(port)]
    node(src).run(*args, check=False, input="x\n")


def test_users_leave_from_the_assigned_address_and_nothing_else_is_translated(node, expected):
    """A connection from LAN-A arrives at the carrier from the NAT address; one from LAN-B (the servers) and
    one from r2 itself arrive from their own addresses."""
    translated = expected["nat"]["r2"]
    carrier = expected["loopbacks"][translated["carrier"]]
    assert wait_for(lambda: node("h1").ping(carrier, count=1)), "h1 can't reach the internet"
    with far_end(node, translated["carrier"], carrier, 8081, count=3) as seen:
        connect(node, "h1", carrier, 8081)
        connect(node, "h2", carrier, 8081)
        connect(node, "r2", carrier, 8081)
        peers = [a for a, _p, _t in seen()]
    wan = next(s["local"] for s in expected["wan_filter"]["r2"]["bgp"])
    assert peers == [translated["address"], expected["hosts"]["h2"], wan], peers


def test_nat_is_one_rule_for_lan_a_only(node, expected):
    """r2's nat table holds the one translation the inventory names, and no other device translates."""
    translated = expected["nat"]["r2"]
    rules = [l for l in node("r2").run("iptables", "-t", "nat", "-S").stdout.splitlines() if l.startswith("-A")]
    assert rules == [f'-A POSTROUTING -s {net} -o {translated["interface"]} -m comment --comment "nat {net}" '
                     f'-j SNAT --to-source {translated["address"]}' for net in translated["inside"]], rules
    for device in ("r1", "r3", "fw1", "isp"):
        assert not [l for l in node(device).run("iptables", "-t", "nat", "-S").stdout.splitlines() if l.startswith("-A")], device


def test_nothing_reaches_inside_through_the_nat_address_unasked(node, expected):
    """Connections from the internet to the NAT address, on the port a user just used and on others, reach
    no inside host. The three are tried at once, each for 2 s, while the inside host listens for 3 s."""
    translated = expected["nat"]["r2"]
    carrier = expected["loopbacks"][translated["carrier"]]
    with far_end(node, "h1", expected["hosts"]["h1"], 8082, count=1, timeout=3) as seen:
        node(translated["carrier"]).run("sh", "-c", 'for port in 8082 41998 22; do nc -z -w 2 "$0" $port & done; wait',
                                        translated["address"], check=False)
        assert seen() == [], "a connection from the internet reached h1"
    assert node("h1").tcp_open(carrier, 179), "the user's own way out stopped working"
