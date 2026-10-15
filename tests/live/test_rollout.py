"""Canary rollout (ansible/deploy.yml): a change that breaks the canary is rolled back there and reaches
no other router; a good change waits for its window, then reaches them all. Decision 0010."""
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from .conftest import BUILD, ROOT, wait_for

ANSIBLE_PLAYBOOK = Path(sys.executable).with_name("ansible-playbook")


def deploy(*args):
    return subprocess.run([str(ANSIBLE_PLAYBOOK), "deploy.yml", *args], cwd=ROOT / "ansible",
                          capture_output=True, text=True, timeout=300)


def healthy():
    return subprocess.run([sys.executable, "-m", "netlab.health"], cwd=ROOT, capture_output=True).returncode == 0


def canary():
    return yaml.safe_load((BUILD / "ansible_inventory.yml").read_text())["all"]["children"]["routers"]["vars"]["canary"]


def intent(router):
    return BUILD / router / "frr.conf"


def running(node, router):
    return node(router).vtysh("show running-config no-header")


def with_marker(conf, marker):
    """A harmless line every router takes, to show which routers a change reached."""
    return conf.replace("interface lo\n", f"interface lo\n description {marker}\n", 1)


def without_first_ospf_link(conf):
    """The bad part of the change: the router's first core link leaves OSPF, so a neighbor is lost."""
    blocks = conf.split("\n!\n")
    i = next(i for i, b in enumerate(blocks) if "ip ospf network point-to-point" in b)
    blocks[i] = re.sub(r"\n ip ospf area \d+", "", blocks[i])
    return "\n!\n".join(blocks)


def change_intent(changes):
    # In place, as `make render` does: each router mounts its file, so a new file would go unseen.
    for router, text in changes.items():
        intent(router).write_text(text)


def put_back(node, originals):
    """The original intent back in build/ and on every router. True once the network has settled."""
    change_intent(originals)
    for router in originals:
        node(router).run("/usr/lib/frr/frr-reload.py", "--reload", "/etc/frr/frr.conf", check=False)
    return wait_for(healthy, timeout=90)


def test_failing_canary_rolls_back_and_blocks(node, expected):
    """A change that costs the canary an OSPF neighbor fails its gate: the canary is rolled back and no other router changes."""
    first, routers = canary(), list(expected["loopbacks"])
    assert healthy(), "the network is unhealthy before the change, so the gate would prove nothing"
    originals = {r: intent(r).read_text() for r in routers}
    before = running(node, first)
    marker = f"rollout-{uuid.uuid4().hex[:8]}"
    bad = {r: with_marker(text, marker) for r, text in originals.items()}
    bad[first] = without_first_ospf_link(bad[first])
    try:
        change_intent(bad)
        # 10 s, not the inventory's 20, to save CI time: the lost neighbor doesn't come back, so the gate fails either way.
        result = deploy("-e", "gate_timeout=10")
        assert result.returncode != 0, "the rollout carried on past a canary that failed its health gate:\n" + result.stdout
        assert f"{first} failed \"Health gate" in result.stdout, "the rollout stopped, but not at the canary's gate:\n" + result.stdout
        assert running(node, first) == before, f"{first} is not back on its pre-change config"
        reached = [r for r in routers if r != first and marker in running(node, r)]
        assert reached == [], f"the change reached {reached} although the canary failed"
    finally:
        settled = put_back(node, originals)
    assert settled, "the network did not settle after the test put the intent back"


def test_change_waits_for_window_then_reaches_every_router(node, expected):
    """Outside the change window nothing changes; inside it, a good change passes every gate and reaches every router."""
    routers = list(expected["loopbacks"])
    originals = {r: intent(r).read_text() for r in routers}
    marker = f"rollout-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    closed = {"start": (now + timedelta(hours=1)).strftime("%H:%M"), "end": (now + timedelta(hours=2)).strftime("%H:%M")}
    try:
        change_intent({r: with_marker(text, marker) for r, text in originals.items()})
        refused = deploy("-e", json.dumps({"change_window": closed}))
        assert refused.returncode != 0 and "outside the change window" in refused.stdout, refused.stdout
        assert not [r for r in routers if marker in running(node, r)], "a router changed outside the window"
        # 5 s, not the inventory's 10, to save CI time: a harmless change stays healthy either way.
        done = deploy("-e", "vetting_delay=5")
        assert done.returncode == 0, "a harmless change failed the rollout, so the failing-canary test proves nothing:\n" + done.stdout
        assert [r for r in routers if marker not in running(node, r)] == [], "the change did not reach every router"
    finally:
        settled = put_back(node, originals)
    assert settled, "the network did not settle after the test put the intent back"
