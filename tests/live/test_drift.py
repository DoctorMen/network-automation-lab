"""Intent is read-only, so write memory can't hide a hand change from the drift check."""
import hashlib

from .conftest import BUILD

INTENT = BUILD / "r2" / "frr.conf"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def intended_description():
    lines = INTENT.read_text().splitlines()
    return next(l.split("description ", 1)[1] for l in lines[lines.index("interface eth1"):] if "description " in l)


def set_description(r2, text):
    r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {text}")


def test_write_memory_cannot_overwrite_intent(node):
    before = digest(INTENT)
    r2 = node("r2")
    try:
        set_description(r2, "drift-test")
        r2.run("vtysh", "-c", "write memory", check=False)
        assert digest(INTENT) == before, "write memory changed the intended config in build/"
        # A bool first: on failure pytest prints an assert's operands, and the running config holds a BGP password.
        live = "drift-test" in r2.vtysh("show running-config")
        assert live, "the hand change should still be live, for the drift check to catch"
    finally:
        set_description(r2, intended_description())

