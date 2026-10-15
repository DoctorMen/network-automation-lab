"""Firewall controls, proved by trying to get past them: forged packets and an unlisted listener.

Counters are read before and after each probe, because other tests (and other runs) move them too.
"""
import random
import subprocess
from contextlib import contextmanager
from pathlib import Path

from .conftest import rule_counters, wait_for

FORGE_ACK = (Path(__file__).parent / "tools" / "forge_ack.py").read_text()
UNLISTED_PORT = 8080


def quiet_port() -> int:
    """A client port below Linux's ephemeral range (32768-60999), so no real connection in the lab uses it."""
    return random.randrange(20000, 32768)


def forged_ack_counts(node, src, dst, dport, sport):
    """Forge one mid-stream ACK from src and return {fw1 rule: (target, packets it matched meanwhile)}."""
    # The path must work first (ping crosses fw1 via allow-icmp), or a missing count would prove nothing.
    # It matters most right after deploy, when OSPF may still be filling in routes.
    assert wait_for(lambda: node(src).ping(dst, count=1)), f"{src} can't reach {dst} at all"
    fw = node("fw1")
    before = rule_counters(fw)

    def counts():
        return {name: (target, n - before.get(name, (target, 0))[1]) for name, (target, n) in rule_counters(fw).items()}

    node(src).run("python3", "-", dst, str(dport), str(sport), input=FORGE_ACK)
    wait_for(lambda: any(n for _, n in counts().values()), timeout=10, interval=0.5)
    return counts()


def assert_only_default_drop(counts):
    accepted = {name: n for name, (target, n) in counts.items() if target == "ACCEPT" and n}
    assert not accepted, f"forged ACK accepted by {accepted}"
    assert counts["default-drop"][1] == 1, f"expected exactly the forged packet at default-drop, got {counts}"


def test_unsolicited_inbound_ack_is_dropped(node, expected):
    """A forged 'reply' from the web server to a connection h1 never opened is dropped, not let in as return traffic."""
    counts = forged_ack_counts(node, "h2", expected["hosts"]["h1"], dport=quiet_port(), sport=80)
    assert_only_default_drop(counts)


def test_allow_web_requires_a_handshake(node, expected):
    """allow-web only matches a connection's opening SYN: a forged ACK to h2:80 is dropped, a real GET still works."""
    server = expected["hosts"]["h2"]
    counts = forged_ack_counts(node, "h1", server, dport=80, sport=quiet_port())
    assert counts["allow-web"][1] == 0, "allow-web forwarded a packet from a connection that never opened"
    assert_only_default_drop(counts)
    page = node("h1").run("wget", "-q", "-T", "5", "-O", "-", f"http://{server}/", check=False).stdout
    assert "Directory listing" in page, "a real HTTP GET through allow-web should still work"


@contextmanager
def listener(host, port):
    """Run a TCP listener on host for the block. Its sh parent waits on it, so killing it leaves no zombie."""
    # busybox nc: -lk with -e keeps accepting. Far lighter than another python3 http.server.
    proc = subprocess.Popen(["docker", "exec", host.container, "sh", "-c", f"nc -lk -p {port} -e true & echo $!; wait"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    pid = proc.stdout.readline().strip()
    try:
        yield
    finally:
        host.run("kill", pid, check=False)
        proc.wait(timeout=10)
        proc.stdout.close()


def test_default_drop_blocks_unlisted_port(node, expected):
    """A port no rule lists is dropped by policy: r3 reaches the listener on h2, h1 can't."""
    server, fw = expected["hosts"]["h2"], node("fw1")
    assert f"dpt:{UNLISTED_PORT}" not in fw.run("iptables", "-vnxL", "FORWARD").stdout, "pick a port no rule lists"
    with listener(node("h2"), UNLISTED_PORT):
        # Negative proof first: the listener answers from the server's own gateway, and h1 can reach
        # h2 at all, so a block below can only be policy.
        assert wait_for(lambda: node("r3").tcp_open(server, UNLISTED_PORT), timeout=10, interval=1), "listener never came up"
        assert wait_for(lambda: node("h1").ping(server, count=1)), "h1 can't reach h2 at all"
        before = rule_counters(fw)["default-drop"][1]
        assert not node("h1").tcp_open(server, UNLISTED_PORT), f"h1 reached unlisted port {UNLISTED_PORT}"
        assert rule_counters(fw)["default-drop"][1] > before, "h1's SYN never reached fw1's default drop"
