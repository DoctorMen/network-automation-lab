"""Toy payments segment (OROS ATT-1, decision 0013): out-of-scope devices reach it only where the
scope register says, probed from every one of them. The tuples come from the register in the inventory."""
from .conftest import wait_for


def reachable(node, t):
    """Does t's source reach its service? An open one gets a few tries, as routing may still be settling."""
    if t["expect"] == "open":
        return bool(wait_for(lambda: node(t["src"]).tcp_open(t["address"], t["port"]), timeout=15))
    return node(t["src"]).tcp_open(t["address"], t["port"])


def test_out_of_scope_cannot_reach_in_scope(node, expected):
    """Every out-of-scope device reaches each CDE service only if it is published; every closed one answers from r3, so the block is policy."""
    tuples = expected["segmentation"]
    assert {t["src"] for t in tuples} and any(t["expect"] == "closed" for t in tuples), "the register implies nothing to probe"
    wrong = [f"{t['src']} -> {t['dst']}:{t['port']} {'closed' if t['expect'] == 'open' else 'open'}, expected {t['expect']}"
             for t in tuples if reachable(node, t) != (t["expect"] == "open")]
    assert not wrong, f"segmentation broken: {wrong}"
    # Negative proof: each service that was closed to them answers from the segment's own gateway,
    # so the closure is a filter (fw1 for h1, r2 for isp), not a dead listener.
    dead = [f"{t['dst']}:{t['port']}" for t in tuples if t["expect"] == "closed" and not node("r3").tcp_open(t["address"], t["port"])]
    assert not dead, f"not listening at all, so the test proves nothing about them: {dead}"
