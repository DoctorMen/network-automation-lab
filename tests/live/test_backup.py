"""Backups judged at the destination (OROS REC-1): a missing target, a missing router and corrupt data
at the destination each fail the job loudly, and a good backup is read back whole."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from netlab import backup, secrets

from .conftest import BUILD, ROOT
from .test_collection import playbook


def run_backup(repo: Path, password: Path, capture: Path) -> subprocess.CompletedProcess:
    """`make backup`, as CI runs it."""
    return subprocess.run([sys.executable, "-m", "netlab.backup", "run", "--repo", str(repo),
                           "--password-file", str(password), "--capture", str(capture)],
                          cwd=ROOT, capture_output=True, text=True, timeout=300)


def snapshots(repo: Path, password: Path) -> list[str]:
    return backup.restic(repo, password, "list", "snapshots").stdout.decode().split()


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    """A fresh collection pass (make drift) of every router and the firewall, copied aside so later
    tests in this run can't change it underneath us."""
    collected = playbook("drift.yml")
    assert collected.returncode == 0, "the collection pass fails on the clean lab:\n" + collected.stdout
    copy = tmp_path_factory.mktemp("capture")
    for name in backup.expected_files(backup.load(ROOT / "inventory" / "network.yml")):
        shutil.copy(ROOT / "backups" / name, copy / name)
    return copy


@pytest.fixture(scope="module")
def destination(tmp_path_factory):
    """A destination created the way a person creates it, once, by hand (make backup-init)."""
    base = tmp_path_factory.mktemp("destination")
    repo, password = base / "repo", base / "password"
    backup.init(repo, password)
    return repo, password


def collected() -> list[str]:
    """The files drift.yml writes, from the Ansible inventory it runs against: <router>.conf,
    <firewall>.rules, and <router>.rules for each edge router (its edge.sh rules)."""
    groups = yaml.safe_load((BUILD / "ansible_inventory.yml").read_text())["all"]["children"]
    return sorted([f"{r}.conf" for r in groups["routers"]["hosts"]] + [f"{f}.rules" for f in groups["firewalls"]["hosts"]]
                  + [f"{r}.rules" for r in groups["edge_routers"]["hosts"]])


def data_packs(repo: Path, password: Path) -> list[str]:
    """Pack files that hold file contents only (restic keeps directory listings in separate packs)."""
    packs = []
    for index in backup.restic(repo, password, "list", "index").stdout.decode().split():
        for pack in json.loads(backup.restic(repo, password, "cat", "index", index).stdout)["packs"]:
            if all(blob["type"] == "data" for blob in pack["blobs"]):
                packs.append(pack["id"])
    return packs


def test_backup_is_verified_at_destination(destination, capture):
    """A backup lands with one file for each config and ruleset make drift collects, each with the
    capture's sha256, and no file at the destination holds the BGP password in clear."""
    repo, password = destination
    done = run_backup(repo, password, capture)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "restic check --read-data clean" in done.stdout
    # Look at the destination ourselves, without the job's own reading of it.
    listed = [json.loads(line) for line in backup.restic(repo, password, "ls", "--json", "latest").stdout.splitlines()]
    files = sorted(n["name"] for n in listed if n.get("type") == "file")
    assert files == collected()
    values = [(secrets.store() / n).read_bytes().strip() for n in secrets.names(backup.load(ROOT / "inventory" / "network.yml"))]
    assert values and all(values), "no BGP password in the secret store to search for"
    for name in files:
        restored = backup.restic(repo, password, "dump", "latest", f"/src/{name}").stdout
        assert backup.sha256(restored) == backup.sha256((capture / name).read_bytes()), f"{name} differs at the destination"
        # A bool, so a failure can't print the password into the JUnit file.
        assert not any(v in restored for v in values), f"{name} at the destination holds the BGP password in clear"


def test_missing_target_fails_loudly(tmp_path, capture, destination):
    """An unmounted target (an empty mountpoint) or a lost one (a cache miss) fails, and nothing is written anywhere."""
    _, password = destination
    mountpoint = tmp_path / "mnt"   # what an unmounted mountpoint looks like: an empty directory
    mountpoint.mkdir()
    gone = tmp_path / "not-there"   # what a cache miss looks like: nothing at all
    before = {p.name: p.read_bytes() for p in capture.iterdir()}
    for target in (mountpoint, gone):
        failed = run_backup(target, password, capture)
        assert failed.returncode != 0, f"backup to {target} reported success"
        assert f"no restic repository at {target}" in failed.stderr, failed.stderr
    assert list(mountpoint.iterdir()) == [], "the job wrote into the unmounted mountpoint"
    assert not gone.exists(), "the job created the missing target"
    assert {p.name: p.read_bytes() for p in capture.iterdir()} == before, "the job wrote next to the capture"


def test_missing_router_is_not_skipped(tmp_path, capture, destination):
    """A capture without r3 is refused, naming r3, and nothing reaches the destination."""
    repo, password = destination
    partial = tmp_path / "partial"
    shutil.copytree(capture, partial)
    (partial / "r3.conf").unlink()
    before = snapshots(repo, password)
    failed = run_backup(repo, password, partial)
    assert failed.returncode != 0, "a backup without r3 reported success"
    assert "r3.conf is missing" in failed.stderr and "r3 would not be backed up" in failed.stderr, failed.stderr
    assert snapshots(repo, password) == before, "a partial snapshot was written"


def test_corrupt_destination_fails_the_backup(tmp_path, capture):
    """Rotted data at the destination fails the job, although `restic backup` itself exits 0."""
    repo, password = tmp_path / "repo", tmp_path / "password"
    backup.init(repo, password)
    assert run_backup(repo, password, capture).returncode == 0
    # Flip one byte in every pack of file contents. The configs haven't changed, so the next backup
    # reuses those blobs without reading them back.
    packs = data_packs(repo, password)
    assert packs, "found no data pack to corrupt"
    for pack in packs:
        path = repo / "data" / pack[:2] / pack
        raw = bytearray(path.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        path.chmod(0o600)
        path.write_bytes(bytes(raw))
    rotted = run_backup(repo, password, capture)
    assert "restic backup exited 0" in rotted.stdout, "restic itself should report success here:\n" + rotted.stdout
    assert rotted.returncode != 0, "the job believed restic's exit status:\n" + rotted.stdout
    assert "reading snapshot" in rotted.stderr and "back failed" in rotted.stderr, rotted.stderr
