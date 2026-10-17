"""Attribution, offline (decisions 0029, 0030 and 0031): the accounts and the accounting proxy each router we
own gets, the page for an account nobody expects, who set a drifted line, and which inside host held a NAT
port. The live halves are tests/live/test_access.py, tests/live/test_nat.py and tests/live/observe/."""
import copy
import importlib.util
import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path
from secrets import token_hex

import pytest
import yaml

from netlab import access, monitoring, nat, who
from netlab.finding import copy_lab, live_folders
from netlab.inventory import load, validate
from netlab.render import render_all, render_edge, render_router

ROOT = Path(__file__).resolve().parent.parent
inv = load(ROOT / "inventory" / "network.yml")


def changed(edit):
    other = load(ROOT / "inventory" / "network.yml")
    other.raw = copy.deepcopy(inv.raw)
    edit(other.raw)
    return validate(other)


# --- accounts and the accounting proxy (ACC-1) ---------------------------------------------------------

def test_every_router_we_own_gets_each_account_and_the_proxy(tmp_path):
    """access.sh creates every person and agent with its own uid in the admin group, keeps the CM tool's scratch
    folders its own, installs the vtysh shim and starts the proxy; the carrier's isp gets none of it."""
    render_all(inv, tmp_path)
    script = (tmp_path / "access" / "access.sh").read_text()
    for a in access.accounts(inv):
        assert f"adduser -D -u {a['uid']} -G netadmin -s /bin/sh {a['name']}" in script, a
    assert "install -d -o netlab -g netadmin -m 0700 /tmp/netlab-bin /tmp/rollback" in script
    assert "install -d -o netlab -g netadmin -m 3775 /var/log/frr" in script  # the CM tool's, sticky (V-032)
    assert f"python3 /access/vty_aaa.py netadmin /run/netlab-vty {monitoring.collector(inv)}:514 601 " in script
    shim = (tmp_path / "access" / "vtysh").read_text()
    assert '[ "$(id -u)" -eq 0 ] && exec /usr/bin/vtysh "$@"' in shim and "--vty_socket /run/netlab-vty" in shim
    topo = (tmp_path / "topology.clab.yml").read_text()
    assert access.routers(inv) == ["r1", "r2", "r3"]
    assert topo.count("- sh /access/access.sh") == 3 and topo.count("- access:/access:ro") == 3
    # Only root may send from the proxy's port (and the translation log's): Docker would let any account.
    nodes = yaml.safe_load(topo)["topology"]["nodes"]
    assert {n for n, c in nodes.items() if (c.get("sysctls") or {}).get("net.ipv4.ip_unprivileged_port_start") == 1024} == {"r1", "r2", "r3"}
    assert access.RECORD_PORT < 1024 and nat.RECORD_PORT < 1024 and access.RECORD_PORT != nat.RECORD_PORT
    hosts = (tmp_path / "ansible_inventory.yml").read_text()
    assert hosts.count("ansible_user: netlab") == 3


@pytest.mark.parametrize("edit, problem", [
    (lambda raw: raw["access"]["people"].append({"name": "carol", "uid": 2001}), "access: person 'carol': uid 2001 is already someone else's"),
    (lambda raw: raw["access"]["people"].append({"name": "frr", "uid": 2003}), "access: person 'frr': that account already exists in the router image"),
    (lambda raw: raw["access"]["people"].append({"name": "dave", "uid": 100}), "access: person 'dave': uid 100 must be a number from 1000 to 65533"),
    (lambda raw: raw["access"].update(ansible_user="alice"), "access: ansible_user 'alice' must be one of the agents"),
])
def test_bad_accounts_are_refused(edit, problem):
    assert any(p.startswith(problem) for p in changed(edit)), changed(edit)


def proxy():
    spec = importlib.util.spec_from_file_location("vty_aaa", ROOT / "templates" / "access" / "vty_aaa.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def relayed(vty, sent):
    """Each command through the proxy's relay: what the daemon got, and what was recorded."""
    client, inbound = socket.socketpair()
    outbound, daemon = socket.socketpair()
    recorded = []
    t = threading.Thread(target=vty.relay, args=(inbound, outbound, recorded.append))
    t.start()
    client.sendall(b"\0".join(sent) + b"\0")
    client.shutdown(socket.SHUT_WR)
    t.join(5)
    got = b""
    while chunk := daemon.recv(65536):
        got += chunk
    return got, recorded


def test_a_secret_typed_into_vtysh_is_hidden_in_its_record():
    """The proxy relays each command unchanged and records it with whatever follows a secret keyword replaced by
    <hidden>: a BGP password, a key-string, an OSPF key in either form, RIP's authentication string, and each
    keyword abbreviated as FRR takes it. Other commands are recorded as typed, a keyword with nothing after it
    (removing a password) included."""
    secret = token_hex(8).encode()  # made here, so no secret is ever written in this file
    vty = proxy()
    sent = [f"neighbor 198.51.100.1 password {secret.decode()}".encode(),
            b"neighbor 192.0.2.250 passw " + secret, b"key-string " + secret,
            b"ip ospf message-digest-key 1 md5 " + secret, b"ip ospf message-digest-key 1 m " + secret,
            b"ip ospf authentication-key " + secret, b"ip ospf auth " + secret, b"ip rip authentication string " + secret,
            b"neighbor 198.51.100.1 description isp", b"no neighbor 198.51.100.1 password"]
    got, recorded = relayed(vty, sent)
    assert got == b"\0".join(sent) + b"\0", "the daemon must get the command as typed"
    assert recorded == ["neighbor 198.51.100.1 password <hidden>", "neighbor 192.0.2.250 passw <hidden>", "key-string <hidden>",
                        "ip ospf message-digest-key 1 md5 <hidden>", "ip ospf message-digest-key 1 m <hidden>",
                        "ip ospf authentication-key <hidden>", "ip ospf auth <hidden>", "ip rip authentication <hidden>",
                        "neighbor 198.51.100.1 description isp", "no neighbor 198.51.100.1 password"]
    assert not [r for r in recorded if secret.decode() in r]


def test_the_labs_own_config_is_recorded_as_typed(tmp_path):
    """Hiding fails closed, so it must not hide what the lab itself sends: every line of every router's intended
    config but its passwords is recorded as it is written, so `make drift` can match the CM tool's records."""
    vty = proxy()
    render_all(inv, tmp_path)
    for r in access.routers(inv):
        for line in (tmp_path / r / "frr.conf").read_text().splitlines():
            words = line.split()
            if words and not words[0].startswith("!") and "password" not in words:
                assert vty.record(line.encode()) == " ".join(words), f"{r}: {line}"


def test_no_command_puts_a_line_of_its_own_in_the_records(monkeypatch):
    """A command whose text holds a newline and a line made to look like another account's record is recorded
    on one line, under the account that sent it, and the lookup reads it as that account's; any other control
    character is written as an escape. The record goes to the collector framed as busybox syslogd frames a
    line, and the lookup reads it back from that frame."""
    vty = proxy()
    forged = b"vty-aaa[999]: command user=bob uid=2002 daemon=zebra pid=999 line=description forged"
    _got, recorded = relayed(vty, [b"show version\n" + forged, b"show version\x1b[2J"])
    assert recorded == ["show version " + forged.decode(), "show version\\x1b[2J"]
    collector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    collector.bind(("127.0.0.1", 0))
    collector.settimeout(5)
    out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out.bind(("127.0.0.1", 0))  # the proxy binds its own port below 1024; a test may not
    monkeypatch.setattr(vty, "COLLECTOR", collector.getsockname(), raising=False)
    monkeypatch.setattr(vty, "OUT", out, raising=False)
    monkeypatch.setattr(vty.syslog, "syslog", lambda *a: None)
    vty.log("command", "alice", 2001, "zebra", 42, f" line={recorded[0]}")
    frame = collector.recv(65536).decode()
    assert "\n" not in frame
    parsed = who.RECORD.match(frame)
    assert parsed and (parsed["user"], parsed["uid"], parsed["line"]) == ("alice", "2001", recorded[0]), frame
    assert who.RECORD.match(forged.decode()) is None, "a line without the syslog header is not a record"


def needs_docker():
    if shutil.which("docker") and subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
        return
    if os.environ.get("CI"):
        pytest.fail("Docker is missing, and CI must run this test")
    pytest.skip("Docker is not available")


def test_only_a_record_from_the_senders_own_port_counts(tmp_path):
    """`vector test` on the rendered collector: a command record from a router's proxy port is filed under
    accounting and counts toward UnexpectedAdmin, and a translation from r2's log port under nat. The same lines
    from any other port, or from another node, stay syslog and count for nothing, which is what any account on
    the router can send (a line to its syslog, or straight to the collector)."""
    needs_docker()
    render_all(inv, tmp_path)
    nodes = {n: a for a, n in sorted(monitoring.source_addresses(inv).items(), reverse=True)}
    record = "<86>Oct 16 11:37:25 vty-aaa[71]: command user=mallory uid=2999 daemon=zebra pid=4 line=show version"
    translation = "<14>Oct 16 11:37:25 nat: " + LOG[0].split(" nat: ", 1)[1]

    def case(name, line, node, port, source, counted):
        test = {"name": name, "inputs": [{"insert_at": "syslog_node", "type": "log",
                                          "log_fields": {"message": line, "host": nodes[node], "port": port}}],
                "outputs": [{"extract_from": "syslog_node", "conditions": [
                    {"type": "vrl", "source": f'.source == "{source}" && .node == "{node}"'}]}]}
        if counted:
            test["outputs"].append({"extract_from": "admin_seen", "conditions": [
                {"type": "vrl", "source": '.name == "admin_last_seen_seconds" && .tags.user == "mallory"'}]})
        else:
            test["no_outputs_from"] = ["admin_seen"]
        return test
    tests = [case("record from r3's proxy port", record, "r3", access.RECORD_PORT, access.SOURCE, True),
             case("the same record from another port", record, "r3", 40001, "syslog", False),
             case("the same record from the right port of a node with no proxy", record, "h2", access.RECORD_PORT, "syslog", False),
             case("a translation from r2's log port", translation, "r2", nat.RECORD_PORT, nat.SOURCE, False),
             case("the same translation from another port", translation, "r2", 40002, "syslog", False),
             case("the same translation from a router that translates nothing", translation, "r3", nat.RECORD_PORT, "syslog", False)]
    (tmp_path / "noc" / "tests.yaml").write_text(yaml.safe_dump({"tests": tests}))
    image = f"{inv.monitoring['images']['vector']}@{inv.monitoring['digests']['vector']}"
    out = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path / 'noc'}:/etc/vector:ro", image,
                          "test", "/etc/vector/vector.yaml", "/etc/vector/tests.yaml"], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0 and out.stdout.count("... passed") == len(tests), out.stdout + out.stderr


def test_the_finding_bundle_carries_the_routers_accounts_and_proxy(tmp_path):
    """make finding's copy of the lab (netlab/finding.py copy_lab) holds build/access/ whole, since every router
    we own runs access.sh from it at boot, and still recreates a folder a router writes into (run/) empty. The
    copied access/ is evidence like the configs, in SHA256SUMS; only the written folders are left out."""
    build = tmp_path / "build"
    render_all(inv, build)
    (build / "r1" / "run" / "zserv.api").write_text("")
    copy_lab(build / "topology.clab.yml", tmp_path / "bundle" / "lab")
    for f in ("access.sh", "vtysh", "vty_aaa.py"):
        assert (tmp_path / "bundle" / "lab" / "access" / f).read_bytes() == (build / "access" / f).read_bytes(), f
    assert [p.name for p in (tmp_path / "bundle" / "lab" / "r1" / "run").iterdir()] == ["EMPTY"]
    live = [str(f.relative_to((tmp_path / "bundle" / "lab").resolve())) for f in live_folders(tmp_path / "bundle")]
    assert "r1/run" in live and "access" not in live, live


# --- the page for an account nobody expects (ACC-2) ----------------------------------------------------

def test_unexpected_admin_rule_per_router_excludes_only_the_inventory_accounts():
    """One rule per router we own; every account but the inventory's people and agents pages, the moment its
    first accounting line arrives."""
    rules = [r for r in monitoring.alert_rules(inv) if r["alert"] == "UnexpectedAdmin"]
    assert sorted(r["labels"]["node"] for r in rules) == access.routers(inv)
    for r in rules:
        assert f'user!~"{"|".join(access.expected_admins(inv))}"' in r["expr"]
        # A login is an event: it pages at once, and for ADMIN_WINDOW seconds after the account's last line.
        assert r["expr"].endswith(f"< {monitoring.ADMIN_WINDOW})") and r["for"] == "0s"
    assert access.expected_admins(inv) == ["alice", "bob", "netlab"]


# --- who set each drifted line (CHG-6) ----------------------------------------------------------------

# frr-reload.py --test on r2 after alice and bob changed it (a recorded run, decision 0030).
DIFF = """Lines To Delete
===============
interface lo
 no description by-alice
router bgp 65001
 no neighbor 198.51.100.1 description set-by-bob

Lines To Add
============
no ip route 192.0.2.77/32 Null0
router bgp 65001
 neighbor 198.51.100.1 description isp
"""


def record(t, user, line, pid=1):
    return {"time": t, "user": user, "uid": {"alice": "2001", "bob": "2002", "netlab": "2100"}[user],
            "daemon": "bgpd", "pid": str(pid), "line": line}


def test_drift_lines_are_read_with_their_context_and_state():
    assert who.differences(DIFF) == [
        {"state": "running", "line": "description by-alice", "context": "interface lo"},
        {"state": "running", "line": "neighbor 198.51.100.1 description set-by-bob", "context": "router bgp 65001"},
        {"state": "running", "line": "ip route 192.0.2.77/32 Null0", "context": ""},
        {"state": "missing", "line": "neighbor 198.51.100.1 description isp", "context": "router bgp 65001"},
    ]


def test_the_newest_record_that_set_a_line_is_named():
    """A second agent overwrites the first: the running value is named with whoever set it last. Abbreviated
    keywords match, values must match in full, and a line no record explains says so."""
    history = [record(10, "netlab", "neighbor 198.51.100.1 description isp"),
               record(20, "alice", "neighbor 198.51.100.1 description set-by-bob"),
               record(30, "bob", "neighbor 198.51.100.1 description set-by-bob"),
               record(31, "alice", "desc by-alice"),
               record(32, "bob", "ip route 192.0.2.7/32 Null0")]
    found = {d["line"]: d for d in (dict(d, record=who.setter(d, history)) for d in who.differences(DIFF))}
    assert found["neighbor 198.51.100.1 description set-by-bob"]["record"]["user"] == "bob"
    assert found["description by-alice"]["record"]["user"] == "alice"
    assert found["neighbor 198.51.100.1 description isp"]["record"]["how"] == "replaced"
    assert found["neighbor 198.51.100.1 description isp"]["record"]["user"] == "bob"
    # 192.0.2.7 is not 192.0.2.77: no record explains the route.
    assert found["ip route 192.0.2.77/32 Null0"]["record"] is None
    assert "no command record" in who.report_set("r2", list(found.values()))
    # Nor does a record for the neighbor 198.51.100.1 explain a line about the neighbor 198.51.100.10.
    other = {"state": "running", "line": "neighbor 198.51.100.10 description peer", "context": "router bgp 65001"}
    assert who.setter(other, [record(40, "alice", "neighbor 198.51.100.1 description peer")]) is None


def test_a_removed_line_is_named_by_its_no_record():
    missing = {"state": "missing", "line": "neighbor 198.51.100.1 timers connect 10", "context": "router bgp 65001"}
    history = [record(5, "alice", "no neighbor 198.51.100.1 timers connect"), record(6, "bob", "neighbor 198.51.100.1 timers 3 9")]
    assert who.setter(missing, history)["user"] == "alice"


def test_a_line_changed_again_outside_the_proxy_names_no_one():
    """alice set a value, the CM tool put the intent back (as make apply does: `no`, then the intended line),
    and root set alice's value again from the console, which leaves no record. The newest record of the
    command is the CM tool's, which set neither the running value nor removed the intent: no one is named,
    neither alice nor the CM tool. Without the revert, alice is still named."""
    running = {"state": "running", "line": "description stale", "context": "interface eth1"}
    missing = {"state": "missing", "line": "description uplink", "context": "interface eth1"}
    reverted = [record(10, "alice", "description stale"), record(20, "netlab", "no description"),
                record(21, "netlab", "description uplink")]
    assert who.setter(running, reverted) is None and who.setter(missing, reverted) is None
    assert who.setter(running, reverted[:1] + reverted[2:]) is None, "a revert without the `no` hides alice's value too"
    assert who.setter(running, reverted[:1])["user"] == "alice" and who.setter(missing, reverted[:1])["how"] == "replaced"
    # An intended line root removed by hand: the newest record set it, so no record removed it.
    gone = {"state": "missing", "line": "neighbor 198.51.100.1 description isp", "context": "router bgp 65001"}
    assert who.setter(gone, [record(5, "netlab", "neighbor 198.51.100.1 description isp")]) is None
    assert who.setter(gone, [record(5, "netlab", "neighbor 198.51.100.1 description isp"),
                             record(6, "bob", "no neighbor 198.51.100.1 description isp")])["user"] == "bob"


def test_the_lookup_says_so_when_the_noc_does_not_answer(monkeypatch, capsys):
    """Without a NOC (CI's lab job runs none) the lookup prints that the actor is unknown and exits 2, which the
    drift play ignores (failed_when: false), so the difference itself still fails the check."""
    class Down:
        def __init__(self, *args):
            pass

        def logs(self, *args, **kwargs):
            raise RuntimeError("wget: can't connect to remote host")
    monkeypatch.setattr(who, "Noc", Down)
    monkeypatch.setattr(who, "lab_name", lambda: "lab")
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(DIFF))
    assert who.main(["set", "r2"]) == 2
    assert "did not answer, so who did it is not known" in capsys.readouterr().out
    compare = (ROOT / "ansible" / "tasks" / "compare_frr.yml").read_text()
    task = compare.split("- name: Name who set each differing line", 1)[1].split("\n- name:", 1)[0]
    assert "failed_when: false" in task and "delegate_to: localhost" in task


def test_a_password_line_is_matched_without_its_secret():
    """The diff shows a password as its tag and the record as <hidden>, so only the words before it count,
    abbreviated or not; a record for another neighbor's password is not a match."""
    running = {"state": "running", "line": "neighbor 198.51.100.1 password sha256:0a1b2c", "context": "router bgp 65001"}
    assert who.setter(running, [record(1, "netlab", "neighbor 198.51.100.1 password <hidden>")])["user"] == "netlab"
    assert who.setter(running, [record(1, "netlab", "neighbor 198.51.100.1 password <hidden>"),
                                record(2, "alice", "neighbor 198.51.100.1 passw <hidden>")])["user"] == "alice"
    assert who.setter(running, [record(1, "alice", "neighbor 198.51.100.10 password <hidden>")]) is None


# --- NAT and its translation log (FND-5) ---------------------------------------------------------------

def test_nat_is_one_rule_for_the_users_out_of_the_wan_only():
    """r2 translates LAN-A only, out of its ISP link only, to the carrier's address; nothing else translates,
    and the carrier routes that address to our end of the link."""
    edge = render_edge(inv, "r2")
    nat_lines = [l for l in edge.splitlines() if l.startswith("iptables -t nat")]
    assert nat_lines == ["iptables -t nat -F POSTROUTING",
                         'iptables -t nat -A POSTROUTING -o eth3 -s 10.10.10.0/24 -j SNAT --to-source 198.51.100.64 -m comment --comment "nat 10.10.10.0/24"']
    assert not [r for r in inv.routers if r != "r2" and "-t nat" in (render_edge(inv, r) or "")]
    assert "ip route 198.51.100.64/32 198.51.100.0" in render_router(inv, "isp")["frr.conf"]
    assert not [r for r in inv.routers if r != "isp" and "198.51.100.64" in render_router(inv, r)["frr.conf"]]


@pytest.mark.parametrize("edit, problem", [
    (lambda raw: raw["routers"]["r2"]["nat"].update(address="198.51.100.1"), "r2: nat: address 198.51.100.1 is already on a link"),
    (lambda raw: raw["routers"]["r2"]["nat"].update(address="10.9.9.9"), "r2: nat: address 10.9.9.9 is an RFC 1918 address"),
    (lambda raw: raw["routers"]["r2"]["nat"].update(inside=["10.10.0.0/16"]), "r2: nat: inside 10.10.0.0/16 is not one of the inventory's LANs"),
    (lambda raw: raw["routers"]["r2"].pop("wan_filter"), "r2: nat needs a wan_filter"),
])
def test_bad_nat_is_refused(edit, problem):
    assert any(p.startswith(problem) for p in changed(edit)), changed(edit)


# conntrack -E lines from r2's translation log (a recorded run, decision 0031).
LOG = [
    "<13>Oct 16 05:47:06 r2 nat: [1792129626.701000]\t    [NEW] ipv4     2 tcp      6 120 SYN_SENT src=10.10.10.10 dst=203.0.113.1 "
    "sport=41999 dport=8081 [UNREPLIED] src=203.0.113.1 dst=198.51.100.64 sport=8081 dport=41999",
    "<13>Oct 16 05:47:10 r2 nat: [1792129630.000000]\t    [NEW] ipv4     2 tcp      6 120 SYN_SENT src=10.10.10.11 dst=203.0.113.1 "
    "sport=41999 dport=8081 [UNREPLIED] src=203.0.113.1 dst=198.51.100.64 sport=8081 dport=1024",
    "<13>Oct 16 05:47:20 r2 nat: [1792129640.000000]\t    [NEW] ipv4     2 udp      17 30 src=10.10.10.10 dst=203.0.113.1 "
    "sport=1024 dport=53 [UNREPLIED] src=203.0.113.1 dst=198.51.100.64 sport=53 dport=1024",
    "<13>Oct 16 05:47:30 r2 nat: [1792129650.000000]\t    [NEW] ipv4     2 icmp     1 30 src=10.10.10.10 dst=203.0.113.1 type=8 "
    "code=0 id=110 [UNREPLIED] src=203.0.113.1 dst=198.51.100.64 type=0 code=0 id=110",
    "<13>Oct 16 05:47:40 r2 nat: heartbeat alive",
    "<13>Oct 16 05:46:50 r2 nat: [1792129610.000000]\t    [NEW] ipv4     2 tcp      6 120 SYN_SENT src=10.10.10.12 dst=203.0.113.1 "
    "sport=5000 dport=8081 [UNREPLIED] src=203.0.113.1 dst=198.51.100.64 sport=8081 dport=1024",
]


def test_translation_log_lines_parse():
    assert nat.parse(LOG[0]) == {"time": 1792129626.701, "proto": "tcp", "inside": "10.10.10.10", "inside_port": 41999,
                                 "remote": "203.0.113.1", "remote_port": 8081, "outside": "198.51.100.64", "outside_port": 41999}
    assert nat.parse(LOG[3])["outside_port"] is None and nat.parse(LOG[3])["inside"] == "10.10.10.10"
    assert nat.parse(LOG[4]) is None


def test_the_outside_port_names_the_inside_host_that_held_it_then():
    """The same inside port from two hosts leaves on two outside ports, and each names its own host; a port
    is held only from its translation on; to two far ends at once, both are named unless the far end is given;
    to one far end, only the newest translation counts, since the one before it had ended."""
    one = nat.holders(LOG, "198.51.100.64", 41999, 1792129700)
    assert [(h["inside"], h["inside_port"]) for h in one] == [("10.10.10.10", 41999)]
    other = nat.holders(LOG, "198.51.100.64", 1024, 1792129700)
    assert {h["inside"] for h in other} == {"10.10.10.10", "10.10.10.11"}  # tcp to 8081 and udp to 53
    assert [h["inside"] for h in nat.holders(LOG, "198.51.100.64", 1024, 1792129700, remote="203.0.113.1:8081")] == ["10.10.10.11"]
    assert nat.holders(LOG, "198.51.100.64", 1024, 1792129635) == [nat.parse(LOG[1])]  # before the udp one began
    assert [h["inside"] for h in nat.holders(LOG, "198.51.100.64", 1024, 1792129620)] == ["10.10.10.12"]  # before 10.10.10.11's
    assert nat.holders(LOG, "198.51.100.64", 41999, 1792129600) == []                 # before anything began
    # Stamped 0.7 s after the complaint's time: it counts only within the clocks' allowed skew.
    assert nat.holders(LOG, "198.51.100.64", 41999, 1792129626) == []
    assert len(nat.holders(LOG, "198.51.100.64", 41999, 1792129626, skew=who.SKEW)) == 1
    assert nat.holders(LOG, "198.51.100.65", 41999, 1792129700) == []


def test_a_password_keyword_the_routers_dont_run_yet_is_hidden_too():
    """isisd, which no router here starts, takes its secrets after area-password and domain-password: any word with
    password in it hides the rest of its command, so starting isisd one day leaks nothing into the records."""
    secret = token_hex(8)  # made here, so no secret is ever written in this file
    vty = proxy()
    for word in ("area-password", "domain-password"):
        assert vty.record(f"{word} clear {secret}".encode()) == f"{word} <hidden>"
        assert vty.record(f"{word} md5 {secret}".encode()) == f"{word} <hidden>"
