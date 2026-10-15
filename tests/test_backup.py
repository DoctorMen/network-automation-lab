"""The backup's destination check and the single-item restore's stanza cut, without a lab."""
import io
import os
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

from netlab import backup, restore, secrets
from netlab.render import render_all

ROOT = Path(__file__).resolve().parent.parent
R2 = """frr version 8.4.1_git
hostname r2
!
router bgp 65001
 neighbor 198.51.100.1 remote-as 65100
 !
 address-family ipv4 unicast
  aggregate-address 10.0.0.0/8 summary-only
 exit-address-family
exit
!
router ospf
exit
!
end
"""


def test_compare_names_every_difference():
    """A file missing at the destination, one with another sha256 and one nobody captured: all three are named."""
    captured = {"r1.conf": "a" * 64, "r2.conf": "b" * 64, "r3.conf": "c" * 64}
    at_destination = {"r1.conf": "a" * 64, "r2.conf": "d" * 64, "old.conf": "e" * 64}
    assert backup.compare(captured, at_destination) == [
        "r3.conf: not at the destination",
        "r2.conf: sha256 at the destination dddddddddddd, captured bbbbbbbbbbbb",
        "old.conf: at the destination but not in the capture",
    ]
    assert backup.compare(captured, dict(captured)) == []


def test_every_file_drift_collects_is_expected_in_a_backup(tmp_path):
    """Every file drift.yml writes, from the Ansible inventory it runs against: each router's config,
    each firewall's rules and each edge router's rules (r2's internet filter, r3's reverse-path filter)."""
    inv = backup.load(ROOT / "inventory" / "network.yml")
    render_all(inv, tmp_path)
    groups = yaml.safe_load((tmp_path / "ansible_inventory.yml").read_text())["all"]["children"]
    collected = ([f"{r}.conf" for r in groups["routers"]["hosts"]] + [f"{f}.rules" for f in groups["firewalls"]["hosts"]]
                 + [f"{r}.rules" for r in groups["edge_routers"]["hosts"]])
    assert sorted(backup.expected_files(inv)) == sorted(collected)
    assert {"r2.rules", "r3.rules"} <= set(collected)


def fake_capture(tmp_path, inv, extra: bytes = b""):
    """A destination that looks like a repository, a password file, a capture of every expected file,
    and a secret store. r2.conf gets `extra` appended."""
    repo, password, capture, store = (tmp_path / d for d in ("repo", "password", "capture", "secrets"))
    repo.mkdir(), capture.mkdir(), store.mkdir()
    (repo / "config").write_text("not a real repository\n")
    password.write_text("x\n")
    for name in backup.expected_files(inv):
        (capture / name).write_bytes(b"captured " + name.encode() + b"\n" + (extra if name == "r2.conf" else b""))
    for name in secrets.names(inv):
        (store / name).write_text(SECRET + "\n")
    return repo, password, capture, store


# A stand-in, made fresh each run like the real one: these tests never read the lab's real store,
# and a literal here would be a secret-shaped string in the repository.
SECRET = os.urandom(16).hex()


def test_a_capture_holding_a_password_is_never_sent(tmp_path, monkeypatch):
    """A capture whose r2.conf holds the BGP password in clear is refused, naming the file and the secret
    but not its value, before restic runs at all. One that holds only its sha256 tag is not refused."""
    inv = backup.load(ROOT / "inventory" / "network.yml")
    calls = []
    monkeypatch.setattr(backup, "restic", lambda *a, **k: calls.append(a) or pytest.fail("restic ran"))
    repo, password, capture, store = fake_capture(tmp_path, inv, f" neighbor 198.51.100.1 password {SECRET}\n".encode())
    with pytest.raises(backup.BackupError) as refused:
        backup.run(inv, "lab", repo, password, capture, secrets_dir=store)
    name = secrets.names(inv)[0]
    assert refused.value.problems == [f"r2.conf holds the {name} secret in clear; nothing was sent"]
    assert SECRET not in str(refused.value) and calls == []
    # Without the secret's file nothing could tell, so that is refused too.
    (store / name).unlink()
    with pytest.raises(backup.BackupError) as unchecked:
        backup.run(inv, "lab", repo, password, capture, secrets_dir=store)
    assert unchecked.value.problems == [f"no secret {name} in {store}, so the capture can't be checked for it; nothing was sent"]


def test_a_secret_at_the_destination_is_named(tmp_path, monkeypatch):
    """The snapshot read back is searched too: a password in a file there fails the backup, named by file and secret."""
    inv = backup.load(ROOT / "inventory" / "network.yml")
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as t:
        for name, data in {"r1.conf": b"clean\n", "r2.conf": f"password {SECRET}\n".encode()}.items():
            info = tarfile.TarInfo(f"src/{name}")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    done = subprocess.CompletedProcess([], 0, stdout=tar.getvalue(), stderr=b"")
    monkeypatch.setattr(backup, "restic", lambda *a, **k: done)
    captured = {"r1.conf": backup.sha256(b"clean\n"), "r2.conf": backup.sha256(f"password {SECRET}\n".encode())}
    name = secrets.names(inv)[0]
    assert backup.verify(Path("repo"), Path("pass"), "abcd1234", captured, {name: SECRET.encode()}) == [
        f"at the destination: r2.conf holds the {name} secret in clear"]
    assert backup.verify(Path("repo"), Path("pass"), "abcd1234", captured, {}) == []


def test_stanza_is_one_top_level_block():
    """The single item is the whole `router bgp` block, nested address-family included, and nothing after it."""
    item = restore.stanza(R2, "router bgp")
    assert item.splitlines()[0] == "router bgp 65001" and item.splitlines()[-1] == "exit"
    assert "  aggregate-address 10.0.0.0/8 summary-only" in item and "router ospf" not in item
    assert restore.stanza(R2, "router rip") == ""

