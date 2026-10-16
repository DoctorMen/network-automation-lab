"""Canary rollout (ansible/deploy.yml): a change that breaks the canary is rolled back there and reaches
no other router; a good change waits for its window, then reaches them all; a router with a BGP password
that fails its gate goes back with the password untouched and written nowhere. Decisions 0010 and 0016."""
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from netlab import secrets

from .conftest import BUILD, ROOT, wait_for
from .test_secrets import Watch

ANSIBLE_PLAYBOOK = Path(sys.executable).with_name("ansible-playbook")
# Where the playbooks put the redacting vtysh on each router (tasks/redacting_vtysh.yml).
VTYSH_DIR = yaml.safe_load((ROOT / "ansible" / "group_vars" / "routers.yml").read_text())["vtysh_dir"]
# The folder deploy.yml keeps each router's fallback in, and gives frr-reload.py as its --rundir.
ROLLBACK_DIR = str(Path(yaml.safe_load((ROOT / "ansible" / "deploy.yml").read_text())[0]["vars"]["fallback"]).parent)


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


def tagged(node, router):
    """The running config as backups see it: each BGP password as its sha256 tag, so it can be compared and printed."""
    return node(router).run(f"{VTYSH_DIR}/vtysh", "-c", "show running-config no-header").stdout


def md5_sessions(node, expected):
    """(state, MD5 on, times dropped) for each end of an authenticated BGP session. A deleted or
    re-set password resets the session, so its drop count moves."""
    found = {}
    for router, ends in expected.get("bgp_md5", {}).items():
        for e in ends:
            n = node(router).vtysh_json(f"show bgp neighbors {e['neighbor']}")[e["neighbor"]]
            found[f"{router} -> {e['peer']}"] = (n["bgpState"], n.get("authenticationEnabled"), n["connectionsDropped"])
    return found


def passwords(expected):
    return sorted({(secrets.store() / e["secret"]).read_text().strip() for ends in expected.get("bgp_md5", {}).values() for e in ends})


def files_with_a_password(node, expected):
    """Files in the rollback folder or FRR's logs, on each router with a BGP password, that hold it in
    clear. grep reads the passwords on stdin, so they are on no command line."""
    hits = []
    for router in expected.get("bgp_md5", {}):
        out = node(router).run("sh", "-c", "grep -rlsF -f - /tmp/rollback /var/log/frr",
                               input="\n".join(passwords(expected)), check=False).stdout
        hits += [f"{router}:{path}" for path in out.split()]
    return hits


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


def applier(router):
    """The account deploy.yml applies as on this router: its ansible_user (the CM tool's, on a router we own), or
    root when it has none (the carrier's isp)."""
    hosts = yaml.safe_load((BUILD / "ansible_inventory.yml").read_text())["all"]["children"]["routers"]["hosts"]
    return hosts[router].get("ansible_user")


def reload_intent(node, router, user=None):
    """frr-reload.py --reload of the router's intent, with deploy.yml's arguments: through the redacting vtysh with
    password lines dropped (plain frr-reload.py would delete r2's BGP password, with it on vtysh's command line and in
    its log), and the fallback's folder as its run folder, which the CM tool can write and FRR's own it can't."""
    return node(router).run("env", "NETLAB_PASSWORDS=drop", "/usr/lib/frr/frr-reload.py", "--reload", "--rundir", ROLLBACK_DIR,
                            "--bindir", VTYSH_DIR, "/etc/frr/frr.conf", check=False, user=user)


def put_back(node, originals):
    """The original intent back in build/ and on every router. Returns what went wrong: each router whose
    reload failed or didn't finish, and a network that didn't settle; empty when all is back. It doesn't
    raise: it runs in a finally, where an error would replace the test's own failure, so each error
    becomes one of its problems. It also prints them, so they show in the report of a test whose body
    already failed, where the assert after the finally never runs. Reloaded the way deploy.yml applies
    (reload_intent), as the account it applies as on each router (applier)."""
    problems = []
    # Each step catches everything, for the reason above. A hung frr-reload.py raises TimeoutExpired.
    try:
        change_intent(originals)
    except Exception as e:
        problems.append(f"build/ not put back: {type(e).__name__}: {e}")
    for router in originals:
        try:
            reload = reload_intent(node, router, user=applier(router))
            if reload.returncode:
                problems.append(f"{router}: frr-reload.py exited {reload.returncode} (its log: /var/log/frr/frr-reload.log on {router})")
        except Exception as e:
            problems.append(f"{router}: frr-reload.py did not finish: {type(e).__name__}: {e}")
    try:
        if not wait_for(healthy, timeout=90):
            problems.append("the network did not settle")
    except Exception as e:
        problems.append(f"the health check failed: {type(e).__name__}: {e}")
    if problems:
        print(f"putting the intent back failed, so later tests run on a changed lab: {problems}")
    return problems


def test_failing_canary_rolls_back_and_blocks(node, expected):
    """A change that costs the canary an OSPF neighbor fails its gate: the canary is rolled back and no other router changes."""
    first, routers = canary(), list(expected["loopbacks"])
    assert healthy(), "the network is unhealthy before the change, so the gate would prove nothing"
    originals = {r: intent(r).read_text() for r in routers}
    before, sessions = running(node, first), md5_sessions(node, expected)
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
        left = put_back(node, originals)
    assert not left, f"putting the intent back failed, so later tests run on a changed lab: {left}"
    assert md5_sessions(node, expected) == sessions, "a BGP session lost or reset its password during the failed rollout"


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
        sessions = md5_sessions(node, expected)
        done = deploy("-e", "vetting_delay=5")
        assert done.returncode == 0, "a harmless change failed the rollout, so the failing-canary test proves nothing:\n" + done.stdout
        assert [r for r in routers if marker not in running(node, r)] == [], "the change did not reach every router"
        # Every router saved a fallback, r2 and isp with a password set: none may be in it.
        assert files_with_a_password(node, expected) == [], "a BGP password in clear in a fallback or FRR's log"
        assert md5_sessions(node, expected) == sessions, "a BGP session lost or reset its password during the rollout"
    finally:
        left = put_back(node, originals)
    assert not left, f"putting the intent back failed, so later tests run on a changed lab: {left}"


def test_rollback_keeps_the_bgp_password_and_writes_it_nowhere(node, expected):
    """Our router with a BGP password fails its gate and goes back to its fallback: the password is neither deleted nor set, the session never drops, and neither the fallback nor FRR's log holds it."""
    ours = next(r for r in expected.get("bgp_md5", {}) if expected["owners"][r] == expected["operator"])
    assert healthy(), "the network is unhealthy before the change, so the gate would prove nothing"
    originals = {ours: intent(ours).read_text()}
    before, sessions = tagged(node, ours), md5_sessions(node, expected)
    try:
        change_intent({ours: without_first_ospf_link(originals[ours])})
        # This router alone (--limit), so it is the first batch and the canary is never touched. 5 s:
        # the lost neighbor doesn't come back, so the gate fails either way. test_secrets.py's sampler
        # watches every command line and environment while the save, the apply and the rollback run.
        watch = Watch(passwords(expected), [node(r).container for r in expected["bgp_md5"]])
        watch.start()
        try:
            result = deploy("--limit", ours, "-e", "gate_timeout=5")
        finally:
            watch.stop()
        assert watch.rounds > 10 and not watch.hits, f"a BGP password in clear in: {sorted(watch.hits)} ({watch.rounds} samples)"
        assert not any(v in result.stdout + result.stderr for v in passwords(expected)), "a BGP password in the playbook's output"
        assert result.returncode != 0 and f"{ours} failed \"Health gate" in result.stdout, \
            "the rollout did not stop at the gate:\n" + result.stdout[-3000:]
        assert tagged(node, ours) == before, f"{ours} is not back on its pre-change config with the same password"
        assert md5_sessions(node, expected) == sessions, "the rollback deleted or re-set a BGP password"
        assert files_with_a_password(node, expected) == [], "a BGP password in clear in the fallback or FRR's log"
    finally:
        left = put_back(node, originals)
    assert not left, f"putting the intent back failed, so later tests run on a changed lab: {left}"
