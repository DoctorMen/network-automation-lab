"""Intent is read-only: a change saved on a router must not leak back into build/."""
import hashlib

from .conftest import BUILD


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_write_memory_cannot_overwrite_intent(node):
    intent = BUILD / "r2" / "frr.conf"
    before = digest(intent)
    r2 = node("r2")
    lines = intent.read_text().splitlines()
    desc = next(l.split("description ", 1)[1] for l in lines[lines.index("interface eth1"):] if "description " in l)
    try:
        r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", "description drift-test")
        r2.run("vtysh", "-c", "write memory", check=False)
        assert digest(intent) == before, "write memory changed the intended config in build/"
        assert "drift-test" in r2.vtysh("show running-config"), "the hand change should still be live, for the drift check to catch"
    finally:
        r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {desc}")
