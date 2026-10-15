"""Data plane: can traffic actually get where policy says it can, and nowhere else?"""
from .conftest import rule_counters, wait_for


def test_lan_a_reaches_server_lan(node, expected):
    assert wait_for(lambda: node("h1").ping(expected["hosts"]["h2"]))


def test_lan_a_reaches_internet(node):
    assert wait_for(lambda: node("h1").ping("203.0.113.1"))
    # Ping passes through allow-icmp, so also open a TCP connection, which only allow-internet admits.
    # The ISP stand-in's one TCP listener is bgpd on 179; it closes the socket after the handshake.
    assert node("h1").tcp_open("203.0.113.1", 179), "h1 can ping the internet but not open a TCP connection to it"


def test_firewall_allows_web(node, expected):
    assert node("h1").tcp_open(expected["hosts"]["h2"], 80)


def test_firewall_blocks_ssh_to_servers(node, expected):
    assert not node("h1").tcp_open(expected["hosts"]["h2"], 22)
    # Prove it was the firewall and not a dead service: SSH port answers from the server's own subnet gateway side.
    assert node("r3").tcp_open(expected["hosts"]["h2"], 22)


def test_firewall_counts_the_drop(node, expected):
    before = rule_counters(node("fw1"))["deny-ssh-to-servers"][1]
    node("h1").tcp_open(expected["hosts"]["h2"], 22)
    assert rule_counters(node("fw1"))["deny-ssh-to-servers"][1] > before, "deny rule never matched"
