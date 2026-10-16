"""Attribution at the NOC (decisions 0029 and 0030): each command a person or the CM tool runs on a router we
own leaves the box as it runs, under the account the kernel names (OROS ACC-1), and a line any account forges
is not taken for a record; an account the inventory doesn't list pages (ACC-2); and `make drift` names who
set each line that differs from the intent, and no one when the line changed outside the proxy (CHG-6).
The accounts themselves, and the proxy on the network alone, are tests/live/test_access.py."""
import json
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from netlab import nat
from netlab.monitoring import ADMIN_WINDOW

from ..conftest import ROOT, wait_for
from ..test_access import on_box
from ..test_collection import playbook
from .conftest import others_firing, quiet, wait_alert, wait_resolved

INJECT = (Path(__file__).parent.parent / "tools" / "inject.py").read_text()


def people(expected):
    return [a for a in expected["access"]["accounts"] if a["kind"] == "person"]


def as_account(node, router, account, command, check=True):
    """A command run on the router as that account, the way a person at its console would after logging in."""
    return node(router).run("su", "-s", "/bin/sh", account, "-c", command, check=check)


def records(noc, router, needle, since, source="accounting"):
    """The proxy's records at the NOC: the lines the collector took from the proxy's own port."""
    return noc.logs(f'{{node="{router}",source="{source}"}} |= "vty-aaa" |= "{needle}"', since - 5)


def differing(node, router):
    """frr-reload.py --test against the intent on the router, as `make drift` runs it: the lines it lists, less
    the ones drift ignores (ansible/tasks/compare_frr.yml), and its whole output for netlab.who."""
    out = node(router).run("/usr/lib/frr/frr-reload.py", "--test", "/etc/frr/frr.conf").stdout
    lines = [l.strip() for l in out.splitlines()]
    return [l for l in lines if l and not re.fullmatch(r"Lines To (Add|Delete)|=*|(no )?ipv6 forwarding", l)], out


def who_set(router, diff):
    """What `make drift` adds to a failure: netlab.who's lookup for each differing line, as JSON."""
    out = subprocess.run([sys.executable, "-m", "netlab.who", "--json", "set", router], cwd=ROOT, input=diff,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    return {d["line"]: d for d in json.loads(out.stdout)}


def test_record_leaves_the_box_and_outlives_root_deleting_its_copy(node, expected, noc):
    """alice runs a command claiming to be bob (USER, LOGNAME). Its record is in the central store within
    seconds, naming alice and her uid. Root then deletes every accounting line from the router's own log, and
    the central copy is unchanged."""
    alice, bob = people(expected)[:2]
    router = expected["access"]["routers"][1]
    probe = f"show ip route 198.18.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}/32"
    since = time.time()
    as_account(node, router, alice["name"], f"USER={bob['name']} LOGNAME={bob['name']} vtysh -c '{probe}'")
    central = wait_for(lambda: records(noc, router, f"line={probe}", since), timeout=15, interval=1)
    assert central, f"the record of {probe!r} never reached the central store"
    assert central[0][0] - since <= 10, f"the record took {central[0][0] - since:.1f} s to arrive"
    assert all(f"command user={alice['name']} uid={alice['uid']} " in line for _t, _l, line in central), central
    assert on_box(node, router, f"line={probe}"), "the router's own copy should hold the record before root deletes it"
    node(router).run("sh", "-c", "for f in /var/log/messages*; do sed -i /vty-aaa/d $f; done")
    assert not on_box(node, router, "vty-aaa"), "root's delete left accounting lines on the box"
    assert records(noc, router, f"line={probe}", since) == central, "the central copy changed when the box's was deleted"


def test_a_record_an_account_forges_is_not_taken_for_one(node, expected, mon, noc):
    """alice, on the admin list, sets a line on r3 and then tries three ways to record it under an account that
    doesn't exist: the proxy's own words in the router's syslog, the same line sent straight to the collector,
    and a command to the proxy's socket whose text holds a newline and that line. Each arrives at the store, as
    syslog or inside alice's own one-line record, and none is taken for a record: the lookup `make drift` runs
    still names alice, and the forged account never counts toward UnexpectedAdmin. Sending from the proxy's
    own port is refused to her. On r2, a translation line she sends the same two ways names no one."""
    access = expected["access"]
    router, nat_router = access["routers"][-1], next(iter(expected["nat"]))
    alice = people(expected)[0]
    mark = uuid.uuid4().hex[:8]
    forger = f"forger{mark}"
    collector, port = mon["collector"], 514
    lines = (ROOT / "build" / router / "frr.conf").read_text().splitlines()
    interface = next(l.split()[1] for l in lines if l.startswith("interface eth"))
    intended = next(l.strip() for l in lines[lines.index(f"interface {interface}"):] if l.strip().startswith("description "))
    value = f"description forged-{mark}"
    forged = f"command user={forger} uid=2999 daemon=zebra pid=4242 line={value}"
    stamp = datetime.now().strftime("%b %d %H:%M:%S")
    since = time.time()
    try:
        as_account(node, router, alice["name"], f"vtysh -c 'conf t' -c 'interface {interface}' -c '{value}'")
        assert wait_for(lambda: records(noc, router, f"line={value}", since), timeout=15, interval=1), "alice's own record never arrived"
        as_account(node, router, alice["name"], f"logger -p authpriv.info -t 'vty-aaa[4242]' '{forged}'")
        as_account(node, router, alice["name"], f"printf '<86>{stamp} vty-aaa[4242]: {forged}' | nc -u -w 1 {collector} {port}")
        low = as_account(node, router, alice["name"], f"printf x | nc -u -w 1 -p {access['record_port']} {collector} {port}", check=False)
        assert low.returncode != 0 and "ermission denied" in low.stdout + low.stderr, f"alice sent from the proxy's port: {low}"
        node(router).run("python3", "-", str(alice["uid"]), f"{access['sockets']}/zebra.vty", f"vty-aaa[4242]: {forged}", input=INJECT)
        # Four lines name the forger, under whatever source the collector gave them: the two sent as syslog, and
        # alice's record of the injected command, in the box's syslog and from the proxy's port.
        anywhere = wait_for(lambda: len(noc.logs(f'{{node="{router}"}} |= "user={forger}"', since - 5)) >= 4
                            and records(noc, router, f"user={forger}", since), timeout=15, interval=1)
        assert anywhere, "the forged lines never reached the store, so their absence below proves nothing"
        assert all(f"command user={alice['name']} uid={alice['uid']} " in line and "\n" not in line
                   for _t, _l, line in records(noc, router, f"user={forger}", since)), "a forged line was taken for a record"
        diff = f"Lines To Delete\n===============\ninterface {interface}\n no {value}\n\nLines To Add\n============\ninterface {interface}\n {intended}\n"
        found = who_set(router, diff)
        assert found[value]["record"] and found[value]["record"]["user"] == alice["name"], found[value]
        time.sleep(2 * mon["interval"] + 1)  # two scrapes of the collector after the forged lines arrived
        assert noc.query(f'admin_last_seen_seconds{{user="{forger}"}}') == [], "a forged line counted toward UnexpectedAdmin"

        # The translation log: a line made to look like a translation to an outside port, sent by alice on r2.
        translated = expected["nat"][nat_router]
        fake_port = 61000 + int(mark, 16) % 4000
        at = time.time()
        line = (f"[{at:.6f}] [NEW] ipv4 2 tcp 6 120 SYN_SENT src=10.10.10.99 dst=203.0.113.1 sport=5555 dport=443 "
                f"[UNREPLIED] src=203.0.113.1 dst={translated['address']} sport=443 dport={fake_port}")
        as_account(node, nat_router, alice["name"], f"logger -t {nat.SOURCE} '{line}'")
        as_account(node, nat_router, alice["name"], f"printf '<14>{stamp} {nat.SOURCE}: {line}' | nc -u -w 1 {collector} {port}")
        assert wait_for(lambda: len(noc.logs(f'{{node="{nat_router}",source="syslog"}} |= "dport={fake_port}"', since - 5)) >= 2,
                        timeout=15, interval=1), "the forged translation lines never reached the store"
        named = subprocess.run([sys.executable, "-m", "netlab.who", "--json", "flow", translated["address"], str(fake_port),
                                str(at + 1)], cwd=ROOT, capture_output=True, text=True, timeout=120)
        assert json.loads(named.stdout)["verdict"] == "none", named.stdout
    finally:
        as_account(node, router, alice["name"], f"vtysh -c 'conf t' -c 'interface {interface}' -c '{intended}'", check=False)
    assert differing(node, router)[0] == [], "the intent was not put back"


def test_an_account_not_on_the_list_pages_and_a_listed_one_does_not(node, expected, mon, noc):
    """An account added by hand to the admin group (eve) and one outside it (mallory) each page as
    UnexpectedAdmin, naming the router and the account, within the rule's bound of their first command; alice,
    on the list, doesn't page. Each page clears once that account has been quiet for the rule's window."""
    access = expected["access"]
    router = access["routers"][-1]
    alice = people(expected)[0]["name"]
    within = mon["alert_within"]["UnexpectedAdmin"]
    strangers = {"eve": ["-G", access["group"]], "mallory": []}
    r = node(router)
    quiet(noc, "UnexpectedAdmin", node=router)
    since = time.time()
    try:
        for uid, (name, group) in enumerate(strangers.items(), start=2998):
            r.run("adduser", "-D", "-u", str(uid), *group, "-s", "/bin/sh", name)
        for account in (alice, *strangers):
            as_account(node, router, account, "vtysh -c 'show ip route'", check=False)
        for name in strangers:
            page = wait_alert(noc, "UnexpectedAdmin", since, within + 15, node=router, user=name)
            assert page, f"no UnexpectedAdmin for {name} on {router}"
            assert page["received"] - since <= within, f"{name}: paged {page['received'] - since:.0f} s after (bound {within} s)"
        assert not noc.notifications(since, alertname="UnexpectedAdmin", user=alice), f"{alice} is on the list and paged"
        assert not others_firing(noc, "UnexpectedAdmin", since, node=router), "another router paged"
    finally:
        for name in strangers:
            r.run("deluser", "--remove-home", name, check=False)
    for name in strangers:
        assert r.run("ls", "-d", f"/home/{name}", check=False).returncode != 0, f"{router}: /home/{name} was left behind"
        assert wait_resolved(noc, "UnexpectedAdmin", since, ADMIN_WINDOW + within + 15, node=router, user=name), \
            f"UnexpectedAdmin for {name} never resolved"


def make_apply():
    return subprocess.run(["make", "apply"], cwd=ROOT, capture_output=True, text=True, timeout=600)


def test_drift_names_whoever_set_the_running_value_last(node, expected, noc):
    """alice sets r3's interface description, then bob overwrites it. The drift check reports the running
    value and names bob, the last to set it, not alice; `make apply` puts the intent back, and its own
    commands are recorded under the CM tool's account. Root then sets bob's value again from the console,
    outside the proxy: the lookup names no one for either line, neither bob, whose value it is, nor the CM
    tool, which put the intent back."""
    access = expected["access"]
    router = access["routers"][-1]
    alice, bob = (p["name"] for p in people(expected)[:2])
    lines = (ROOT / "build" / router / "frr.conf").read_text().splitlines()
    interface = next(l.split()[1] for l in lines if l.startswith("interface eth"))
    intended = next(l.strip() for l in lines[lines.index(f"interface {interface}"):] if l.strip().startswith("description "))
    mark = uuid.uuid4().hex[:8]
    value = f"description set-by-{bob}-{mark}"
    assert differing(node, router)[0] == [], "the router differs from its intent already, so a failure proves nothing"
    since = time.time()
    try:
        for who in (alice, bob):
            as_account(node, router, who, f"vtysh -c 'conf t' -c 'interface {interface}' -c 'description set-by-{who}-{mark}'")
        assert wait_for(lambda: records(noc, router, f"line={value}", since), timeout=15, interval=1)
        drifted = playbook("drift.yml", "--limit", router)
        assert drifted.returncode != 0, "drift check passed with a changed description"
        report = drifted.stdout.split(f"Who set each line on {router}", 1)[-1]
        assert f"running: {value} (under interface {interface})" in report, drifted.stdout
        assert f"set by {bob} (uid {next(a['uid'] for a in access['accounts'] if a['name'] == bob)})" in report, drifted.stdout
        assert f"missing: {intended} (under interface {interface})" in report and f"replaced by {bob}" in report, drifted.stdout
        assert f"by {alice}" not in report, "alice's value was overwritten, so she must not be named"
    finally:
        applied = make_apply()
    assert applied.returncode == 0, applied.stdout[-3000:]
    assert differing(node, router)[0] == [], "make apply did not put the intent back"
    restored = wait_for(lambda: records(noc, router, f"line={intended}", since), timeout=15, interval=1)
    assert restored and all(f"command user={access['ansible_user']} " in line for _t, _l, line in restored), restored
    try:
        node(router).run("vtysh", "-c", "conf t", "-c", f"interface {interface}", "-c", value)  # root: FRR's own sockets
        listed, diff = differing(node, router)
        assert listed, "root's change made no difference, so the lookup below proves nothing"
        found = who_set(router, diff)
        assert found[value]["state"] == "running" and found[value]["record"] is None, found[value]
        assert found[intended]["state"] == "missing" and found[intended]["record"] is None, found[intended]
    finally:
        node(router).run("vtysh", "-c", "conf t", "-c", f"interface {interface}", "-c", intended)
    assert differing(node, router)[0] == [], "the intent was not put back"
