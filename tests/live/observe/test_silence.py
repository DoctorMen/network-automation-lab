"""OROS DEC-4, narrow silence (decision 0020): a silence that `make silence` would accept, on one router
interface's flap alert, holds back that one page while the same flap on another router still pages, and
once the silence has ended the same flap on the silenced interface pages again."""
import time
from datetime import datetime, timedelta, timezone

from netlab import monitoring, silence
from netlab.inventory import load

from ..conftest import ROOT, wait_for
from .conftest import quiet, wait_alert, wait_resolved

# Links to a host, not to a router: no routing adjacency rides on them, so a 0.3 s flap moves no route.
SILENCED, OTHER = ("r1", "eth3"), ("r3", "eth3")


def flap(node, router, device):
    node(router).run("sh", "-c", f"ip link set {device} down && sleep 0.3 && ip link set {device} up")


def test_a_silenced_flap_still_pages_on_another_router_and_after_the_silence_ends(node, mon, noc):
    inv = load(ROOT / "inventory" / "network.yml")
    within = mon["alert_within"]["InterfaceFlapped"]
    for r, d in (SILENCED, OTHER):
        quiet(noc, "InterfaceFlapped", node=r, device=d)
    # Long enough for the silenced alert to fire and resolve inside it (its window and two evaluations).
    now = datetime.now(timezone.utc)
    entry = {"alert": "InterfaceFlapped", "labels": {"node": SILENCED[0], "device": SILENCED[1]},
             "starts": now, "ends": now + timedelta(seconds=monitoring.FLAP_WINDOW + 4 * mon["interval"]),
             "reason": "a live test flaps this port on purpose and silences only it", "ref": "0020",
             "by": "tests/live/observe/test_silence.py"}
    assert silence.problems(entry, inv, silence.known_refs()) == [], "make silence would refuse this silence"
    [(_, sid)] = silence.apply([entry], noc)
    since = time.time()
    try:
        for r, d in (SILENCED, OTHER):
            flap(node, r, d)
        page = wait_alert(noc, "InterfaceFlapped", since, within + 5, node=OTHER[0], device=OTHER[1])
        assert page, f"the same flap on {OTHER[0]} {OTHER[1]}, which the silence doesn't cover, did not page"
        assert page["received"] - since <= within + 2
        held = wait_for(lambda: [a for a in noc.am_alerts(alertname="InterfaceFlapped", node=SILENCED[0], device=SILENCED[1])
                                 if sid in a["status"]["silencedBy"]], timeout=within, interval=1)
        assert held, "the silenced flap never reached Alertmanager, so the silence proves nothing"
        # The silenced alert fires and resolves while the silence holds; nothing about it pages.
        ends = silence.when(entry["ends"]).timestamp()
        assert wait_for(lambda: not noc.alerts(None, alertname="InterfaceFlapped", node=SILENCED[0], device=SILENCED[1]),
                        timeout=max(1, ends - time.time()), interval=1), "the silenced alert outlasted its silence"
        time.sleep(max(0, ends - time.time()) + 1)
        assert next(s for s in noc.silences() if s["id"] == sid)["status"]["state"] == "expired"
        assert not wait_alert(noc, "InterfaceFlapped", since, 1, node=SILENCED[0], device=SILENCED[1]), \
            "the silenced flap paged anyway"
        # Replayed after the silence ended, the same flap on the same interface pages.
        again = time.time()
        flap(node, *SILENCED)
        page = wait_alert(noc, "InterfaceFlapped", again, within + 5, node=SILENCED[0], device=SILENCED[1])
        assert page, f"after its silence ended, a flap on {SILENCED[0]} {SILENCED[1]} did not page"
        assert page["received"] - again <= within + 2
    finally:
        if next(s for s in noc.silences() if s["id"] == sid)["status"]["state"] != "expired":
            noc.expire_silence(sid)
    for r, d in (SILENCED, OTHER):
        assert wait_resolved(noc, "InterfaceFlapped", since, monitoring.FLAP_WINDOW + 30, node=r, device=d), f"{r} {d} never resolved"
