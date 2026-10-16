"""Toy payments segment (OROS ATT-1, decision 0013): out-of-scope devices reach it only where the
scope register says, probed from every one of them. The tuples come from the register in the inventory."""
from .conftest import wait_for


def answers(node, src, t):
    """Does t's target answer src: its TCP service, or a ping?"""
    if t["proto"] == "icmp":
        return node(src).ping(t["address"], count=1)
    return node(src).tcp_open(t["address"], t["port"])


def reachable(node, t):
    """Does t's source reach it? An open one gets a few tries, as routing may still be settling."""
    if t["expect"] == "open":
        return bool(wait_for(lambda: answers(node, t["src"], t), timeout=15))
    return answers(node, t["src"], t)


def what(t):
    return f"{t['dst']}:{t['port']}" if t["proto"] == "tcp" else f"ping {t['dst']}"


def test_out_of_scope_cannot_reach_in_scope(node, expected):
    """Every out-of-scope device reaches the segment only on published ports and the register's exceptions; every closed probe answers from inside, so the block is policy."""
    # A port only a sidecar serves (h2's node_exporter) runs only in the full lab: tests/live/observe/test_loss.py probes it.
    tuples = [t for t in expected["segmentation"] if not t.get("sidecar")]
    assert {t["src"] for t in tuples} and any(t["expect"] == "closed" for t in tuples), "the register implies nothing to probe"
    wrong = [f"{t['src']} -> {what(t)} {'closed' if t['expect'] == 'open' else 'open'}, expected {t['expect']}"
             for t in tuples if reachable(node, t) != (t["expect"] == "open")]
    assert not wrong, f"segmentation broken: {wrong}"
    # Negative proof: each probe that was closed to them answers from another device on the segment,
    # so the closure is a filter (fw1 for h1, r2 for isp), not a dead listener.
    dead = [what(t) for t in tuples if t["expect"] == "closed" and not answers(node, t["inside"], t)]
    assert not dead, f"not answering at all, so the test proves nothing about them: {dead}"
