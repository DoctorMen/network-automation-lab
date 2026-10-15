"""Collection pass (ansible/drift.yml): each check goes red when the thing it guards breaks,
and stays green on the clean lab, so a red run means something."""
import subprocess
import sys
import uuid
from pathlib import Path

from .conftest import BUILD, ROOT

# The ansible-playbook installed next to this Python, so the playbooks run with the same packages.
ANSIBLE_PLAYBOOK = Path(sys.executable).with_name("ansible-playbook")


def playbook(*args):
    return subprocess.run([str(ANSIBLE_PLAYBOOK), *args], cwd=ROOT / "ansible",
                          capture_output=True, text=True, timeout=300)


def unique(label):
    return f"{label}-{uuid.uuid4().hex[:8]}"


def test_unsaved_change_is_flagged(node):
    """A hand change on r2 that was never saved fails one run of the drift check, which names it."""
    clean = playbook("drift.yml", "--limit", "r2")
    assert clean.returncode == 0, "drift check fails on the clean lab, so a failure proves nothing:\n" + clean.stdout
    r2 = node("r2")
    lines = (BUILD / "r2" / "frr.conf").read_text().splitlines()
    desc = next(l.split("description ", 1)[1] for l in lines[lines.index("interface eth1"):] if "description " in l)
    mark = unique("unsaved")
    try:
        r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {mark}")  # no write memory
        drifted = playbook("drift.yml", "--limit", "r2")
        assert drifted.returncode != 0, "drift check passed with an unsaved hand change on r2"
        assert mark in drifted.stdout, "drift check failed but didn't name the changed line:\n" + drifted.stdout
    finally:
        r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {desc}")


def test_incomplete_capture_is_flagged(tmp_path):
    """A backup of r2 missing one real line fails the capture check, which names that line; the whole backup passes."""
    fresh = playbook("drift.yml", "--limit", "r2")  # takes a fresh backups/r2.conf
    assert fresh.returncode == 0, fresh.stdout
    capture = (ROOT / "backups" / "r2.conf").read_text()
    whole = tmp_path / "r2.conf"
    whole.write_text(capture)
    ok = playbook("verify_capture.yml", "--limit", "r2", "-e", f"capture={whole}")
    assert ok.returncode == 0, "the untouched backup should pass:\n" + ok.stdout
    # A routing line, and a line frr-reload.py only logs instead of listing.
    for keyword in ("aggregate-address", "service integrated-vtysh-config"):
        lost = next(l.strip() for l in capture.splitlines() if keyword in l)
        doctored = tmp_path / f"r2-without-{keyword.split()[0]}.conf"
        doctored.write_text("".join(l for l in capture.splitlines(keepends=True) if l.strip() != lost))
        # Through drift.yml, so this also proves `make drift` runs the capture check.
        bad = playbook("drift.yml", "--limit", "r2", "-e", f"capture={doctored}")
        assert bad.returncode != 0, f"a backup missing {lost!r} passed the capture check"
        assert lost in bad.stdout, f"capture check failed but didn't name {lost!r}:\n" + bad.stdout


def test_firewall_hand_change_is_flagged(node):
    """An ACCEPT rule added by hand on fw1 fails the firewall check, which names it and leaves the live rules alone."""
    clean = playbook("drift.yml", "--limit", "fw1")
    assert clean.returncode == 0, "firewall check fails on the clean lab, so a failure proves nothing:\n" + clean.stdout
    fw1 = node("fw1")
    mark = unique("hand-ssh")
    rule = ["FORWARD", "-p", "tcp", "--dport", "22", "-j", "ACCEPT", "-m", "comment", "--comment", mark]
    fw1.run("iptables", "-I", *rule)
    try:
        drifted = playbook("drift.yml", "--limit", "fw1")
        assert drifted.returncode != 0, "firewall check passed with a hand-added ACCEPT rule on fw1"
        assert mark in drifted.stdout, "firewall check failed but didn't name the added rule:\n" + drifted.stdout
        # Replaying firewall.sh in the live namespace would have flushed the chain and this rule with it.
        assert fw1.run("iptables", "-C", *rule, check=False).returncode == 0, "the check changed the live rules"
    finally:
        fw1.run("iptables", "-D", *rule, check=False)
