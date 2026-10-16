"""Restore drill (OROS REC-3): the latest backup at the destination boots cleanly on throwaway routers
without touching the live lab, a backup that doesn't load is named, and one stanza comes back on its
own within the stated time. It restores real backups, so it runs with `make restore-drill` (weekly in
.github/workflows/drills.yml) and is skipped in a plain `make live`."""
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from netlab import restore

from .conftest import BUILD, ROOT

pytestmark = pytest.mark.skipif(not os.environ.get("BACKUP_REPO"),
                                reason="restore drill: needs the backup destination, run it with make restore-drill")
RESULTS = ROOT / "results"


def record(name: str, data: dict) -> None:
    """A dated result, uploaded with the drill's JUnit file."""
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / name).write_text(json.dumps({"date": datetime.now(timezone.utc).isoformat(), **data}, indent=2) + "\n")


@pytest.fixture(scope="module")
def store(lab_name):
    """The real destination and its newest snapshot. A missing destination fails the drill; it is not skipped."""
    repo, password = Path(os.environ["BACKUP_REPO"]), Path(os.environ["BACKUP_PASSWORD"])
    assert (repo / "config").is_file(), f"no restic repository at {repo}: nothing to restore from"
    return repo, password, restore.latest_snapshot(repo, password, host=lab_name)


def test_latest_backup_is_recent(store):
    """The newest backup at the destination is under 36 hours old, so a backup job that stopped is noticed."""
    *_, snapshot = store
    age = datetime.now(timezone.utc) - restore.snapshot_time(snapshot)
    assert age < timedelta(hours=restore.BACKUP_MAX_AGE_HOURS), f"newest backup {snapshot['id'][:8]} is {age} old"


def test_every_router_restores_cleanly(store, expected, node):
    """Each router's latest backup boots on a throwaway router with no network, frr-reload finds no difference, and the live routers are untouched."""
    repo, password, snapshot = store
    routers = list(expected["loopbacks"])
    live_before = {r: hashlib.sha256(node(r).vtysh("show running-config").encode()).hexdigest() for r in routers}
    results = restore.drill(BUILD, routers, repo, password, snapshot["id"])
    record("restore-drill.json", {"snapshot": snapshot["id"], "snapshot_time": snapshot["time"], "routers": results})
    failed = {r: res["problems"] for r, res in results.items() if res["problems"]}
    assert sorted(results) == sorted(routers) and not failed, f"backups that don't restore cleanly: {failed}"
    live_after = {r: hashlib.sha256(node(r).vtysh("show running-config").encode()).hexdigest() for r in routers}
    assert live_after == live_before, "the drill changed a live router"


def test_drill_notices_a_bad_backup(store):
    """A backup that keeps the 'Building configuration...' header boots, but the drill names the line it can't load."""
    repo, password, snapshot = store
    good = restore.dump(repo, password, snapshot["id"], "r2.conf")
    # What `show running-config` prints, and what drift.yml saved before it used `no-header`.
    bad = b"Building configuration...\n\nCurrent configuration:\n!\n" + good
    assert restore.boot_and_compare(BUILD, {"r2": good})["r2"]["problems"] == [], "the untouched backup should pass"
    problems = "\n".join(restore.boot_and_compare(BUILD, {"r2": bad})["r2"]["problems"])
    assert "Unknown command: Building configuration..." in problems, f"the drill passed a backup that doesn't load:\n{problems}"


def test_single_item_restore_within_limit(store, expected):
    """r2's `router bgp` stanza comes back from one `restic dump`, on a throwaway router, inside the stated 5 minutes."""
    repo, password, snapshot = store
    router = expected["bgp_sessions"][0]["router"]
    result = restore.restore_item(BUILD, router, "router bgp", repo, password, snapshot["id"])
    record("single-item-restore.json", {"snapshot": snapshot["id"], **result})
    assert result["restored"], f"{result['item']} came back incomplete, missing {result['missing']}"
    assert result["seconds"] < restore.SINGLE_ITEM_LIMIT, f"took {result['seconds']} s, limit {restore.SINGLE_ITEM_LIMIT} s"
