"""OROS FND-2, evidence that outlives the fault (decision 0025). The flight recorder on every log source is
armed for the next link failure: a one-second outage leaves a complete state dump from both ends in the
central store, taken while the link was still down. `make evidence`, the step before a planned reset,
copies each node's dump and its own log off the box, and fails unless every dump is in the central store.
tests/live/test_power_event.py's drill then cuts the power and finds the evidence still there."""
import re
import subprocess
import sys
import time

from netlab import secrets
from netlab.inventory import load

from ..conftest import ROOT, wait_for
from .conftest import wait_alert

inv = load(ROOT / "inventory" / "network.yml")


def dump_lines(noc, node, dump_id, since):
    return [line for _, _, line in noc.logs(f'{{node="{node}",source="syslog"}} |= "{dump_id}"', since)]


def complete(lines, dump_id):
    """Every line of the dump arrived: its end line names how many there are between begin and end."""
    end = next((l for l in lines if re.search(rf"{dump_id} end (\d+) lines", l)), None)
    return end is not None and len(lines) == int(re.search(r"end (\d+) lines", end)[1]) + 2


def triggered(noc, node, since, trigger):
    """The id of the first dump the node's flight recorder sent after `since` for this trigger, or None."""
    hits = noc.logs(f'{{node="{node}",source="syslog"}} |= "flightrec" |= "begin trigger: {trigger} "', since)
    return re.search(r"(fr-\S+) begin", hits[0][2])[1] if hits else None


def test_a_stopped_flight_recorder_is_armed_again(node, mon, noc):
    """r3's watcher (`ip monitor link`) is killed. agent.sh starts a new one within the recorder's delay plus 5 s, and
    a line saying so reaches the central store, so the recorder is armed for the next fault and its gap is on record.
    The flap test below then gets its dump from this new watcher."""
    router, delay = "r3", mon["flightrec"]["delay"]

    def watchers():
        return [l.split()[0] for l in node(router).run("ps", "-o", "pid,args").stdout.splitlines() if "ip monitor link" in l]
    old = watchers()
    assert len(old) == 1, f"{router} runs {len(old)} flight-recorder watchers, not one"
    since = time.time()
    node(router).run("kill", old[0])
    new = wait_for(lambda: (w := watchers()) and w != old and w, timeout=delay + 5, interval=0.5)
    assert new and len(new) == 1, f"{router}'s flight recorder was not armed again within {delay + 5} s: {new}"
    said = wait_for(lambda: noc.logs(f'{{node="{router}",source="syslog"}} |= "flightrec" |= "armed again"', since), timeout=15, interval=1)
    assert said, f"no line from {router} in the central store says its flight recorder stopped and was armed again"


def test_a_flap_leaves_a_state_dump_in_the_central_store(node, mon, noc, expected):
    """r3's port to h2 goes down for 1 s. Within the recorder's delay plus 10 s, r3's dump (taken while the port was
    down: its own line for eth3 says DOWN) and h2's dump (its eth1 lost carrier) are in the central store,
    complete. The carrier counter rose by exactly 2, one change down and one up, and InterfaceFlapped paged."""
    # r3's port to h2: the InterfaceFlapped test in test_state.py takes r1 eth3 instead.
    router, device = "r3", "eth3"
    far = next(remote for local, remote in inv.neighbors(router) if local.interface == device)
    server = far.device
    every, delay = mon["flightrec"]["every"], mon["flightrec"]["delay"]
    # The recorder takes at most one dump per `every` seconds; let an earlier one's quiet time pass.
    assert wait_for(lambda: not any(noc.logs(f'{{node="{n}",source="syslog"}} |= "flightrec" |= "begin trigger"', time.time() - every - 2)
                                    for n in (router, server)), timeout=every + 10, interval=2)
    changes = f'node_network_carrier_changes_total{{node="{router}",device="{device}"}}'
    before = noc.value(changes)
    since = time.time()
    node(router).run("sh", "-c", f"ip link set {device} down && sleep 1 && ip link set {device} up")
    try:
        ids = {}
        for n, trigger in ((router, device), (server, far.interface)):
            ids[n] = wait_for(lambda: triggered(noc, n, since, trigger), timeout=delay + 10, interval=1)
            assert ids[n], f"no flight-recorder dump from {n} within {delay + 10} s of the flap"
        for n, dump_id in ids.items():
            lines = wait_for(lambda: (got := dump_lines(noc, n, dump_id, since)) and complete(got, dump_id) and got, timeout=10, interval=1)
            assert lines, f"{n}'s dump {dump_id} did not arrive complete: {len(dump_lines(noc, n, dump_id, since))} lines"
            assert any(f"counters {device if n == router else far.interface} " in l for l in lines), f"{n}'s dump has no interface counters"
        # Taken at the fault: r3's own port, and h2's link, were down when the dump read them.
        lines = dump_lines(noc, router, ids[router], since)
        assert any(re.search(rf"{ids[router]} {device}@\S+\s+DOWN ", l) for l in lines), f"r3's dump doesn't show {device} down"
        assert any("Neighbor ID" in l for l in lines) and any("C>*" in l for l in lines), "r3's dump has no routing state"
        assert any(re.search(rf"{ids[server]} {far.interface}@\S+\s+DOWN\s.*NO-CARRIER", l) for l in dump_lines(noc, server, ids[server], since)), \
            f"{server}'s dump doesn't show its link without carrier"
        page = wait_alert(noc, "InterfaceFlapped", since, mon["alert_within"]["InterfaceFlapped"] + 5, node=router, device=device)
        assert page, "the flap did not page"
    finally:
        node(router).run("ip", "link", "set", device, "up")
    # DEC-2: the counter counts each change, so one flap is 2.
    assert wait_for(lambda: noc.value(changes) == before + 2, timeout=3 * mon["interval"], interval=1), \
        f"{changes} went from {before} to {noc.value(changes)}, not +2"
    assert wait_for(lambda: node(router).ping(expected["hosts"][server]), timeout=30), f"{server} did not come back"


def test_evidence_before_a_reset_is_kept_off_the_box(node, mon, noc, expected, tmp_path):
    """`make evidence` writes each log source's state dump and its own log into a dated folder, and every dump is
    also in the central store, line for line. No BGP password is in any of it."""
    since = time.time()
    out = subprocess.run([sys.executable, "-m", "netlab.evidence", "take", "--why", "test", "--out", str(tmp_path)],
                         cwd=ROOT, capture_output=True, text=True, timeout=180)
    assert out.returncode == 0, out.stdout + out.stderr
    nodes = sorted({s["node"] for s in mon["sources"] if s["source"] == "syslog"})
    folders = list(tmp_path.iterdir())
    assert len(folders) == 1 and sorted(p.stem for p in folders[0].iterdir()) == nodes
    values = {(secrets.store() / e["secret"]).read_text().strip() for ends in expected.get("bgp_md5", {}).values() for e in ends}
    assert values, "no BGP password to look for"
    for n in nodes:
        text = (folders[0] / f"{n}.txt").read_text()
        saved = [l for l in text.splitlines() if l.startswith("fr-")]
        dump_id = saved[0].split()[0]
        assert complete(saved, dump_id), f"{n}: the saved dump is not complete"
        assert text.split("# The node's own log, as it stood\n", 1)[1].strip(), f"{n}: the box's own log was not copied"
        stored = dump_lines(noc, n, dump_id, since)
        assert len(stored) == len(saved), f"{n}: {len(saved)} lines saved, {len(stored)} in the central store"
        assert not any(v in text for v in values), f"{n}: a BGP password is in the evidence"
