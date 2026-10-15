"""Intent is read-only, and the drift check really catches a hand change."""
import hashlib
import subprocess

from .conftest import BUILD, ROOT

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
        assert "drift-test" in r2.vtysh("show running-config"), "the hand change should still be live, for the drift check to catch"
    finally:
        set_description(r2, intended_description())


def test_drift_check_catches_a_hand_change(node, tmp_path):
    """The drift check is a control too: after a hand change on r2, the playbook fails and shows the change."""
    r2 = node("r2")
    try:
        set_description(r2, "drift-test")
        # Backups go to tmp_path, so the drifted config never lands in backups/ (CI's evidence).
        run = subprocess.run(["ansible-playbook", "drift.yml", "--limit", "r2", "-e", f"backup_dir={tmp_path}"],
                             cwd=ROOT / "ansible", capture_output=True, text=True, timeout=180)
        assert run.returncode != 0, "drift check passed with a hand change on r2"
        assert "description drift-test" in run.stdout, run.stdout[-2000:]
    finally:
        set_description(r2, intended_description())
