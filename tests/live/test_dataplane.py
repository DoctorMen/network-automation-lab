"""Data plane: can traffic actually get where policy says it can, and nowhere else?"""
from .conftest import wait_for


def test_lan_a_reaches_server_lan(node, expected):
    assert wait_for(lambda: node("h1").ping(expected["hosts"]["h2"]))


def test_lan_a_reaches_internet(node):
    assert wait_for(lambda: node("h1").ping("203.0.113.1"))


def test_firewall_allows_web(node, expected):
    assert node("h1").tcp_open(expected["hosts"]["h2"], 80)


def test_firewall_blocks_ssh_to_servers(node, expected):
    assert not node("h1").tcp_open(expected["hosts"]["h2"], 22)
    # Prove it was the firewall and not a dead service: SSH port answers from the server's own subnet gateway side.
    assert node("r3").tcp_open(expected["hosts"]["h2"], 22)


def test_firewall_counts_the_drop(node, expected):
    node("h1").tcp_open(expected["hosts"]["h2"], 22)
    rules = node("fw1").run("iptables", "-vnL", "FORWARD").stdout
    line = next(l for l in rules.splitlines() if "deny-ssh-to-servers" in l)
    assert int(line.split()[0]) > 0, "deny rule never matched"
