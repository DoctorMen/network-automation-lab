"""Named accounts and command accounting on the routers we own (OROS ACC-1, decision 0029), on the network
alone: the accounts exist with their uids, FRR answers each of them only through the accounting proxy, and
the proxy records the account the kernel names, not the one the shell claims. That each record leaves the
box at once, and survives root deleting the box's copy, is tests/live/observe/test_accounting.py."""
import uuid

from .conftest import wait_for


def on_box(node, router, needle):
    """The router's own syslog copy (busybox syslogd -L: /var/log/messages and its rotated file)."""
    return [l for l in node(router).run("sh", "-c", "cat /var/log/messages.0 /var/log/messages 2>/dev/null", check=False).stdout.splitlines()
            if needle in l]


def test_each_router_we_own_has_the_named_accounts(node, expected):
    """Every person and agent has its own uid in the admin group on each router we own, the CM tool owns its
    scratch folders and no one else may write there, only root may write the router's own log, and the
    carrier's router has none of these accounts."""
    access = expected["access"]
    for router in access["routers"]:
        r = node(router)
        for a in access["accounts"]:
            ids = r.run("id", a["name"]).stdout
            assert f"uid={a['uid']}({a['name']})" in ids and f"({access['group']})" in ids, f"{router}: {ids}"
        folders = r.run("ls", "-ld", "/tmp/netlab-bin", "/tmp/rollback").stdout.splitlines()
        # drwx------ or drwxr-xr-x: only the owner writes, so nobody plants the file a rollback loads.
        assert all(l[:4] == "drwx" and "w" not in l[4:10] and l.split()[2] == access["ansible_user"] for l in folders), f"{router}: {folders}"
        log = r.run("ls", "-l", "/var/log/messages").stdout
        assert log[:3] == "-rw" and "w" not in log[3:10] and log.split()[2] == "root", f"{router}: {log}"
    for a in access["accounts"]:
        assert node("isp").run("id", a["name"], check=False).returncode != 0, f"isp has {a['name']}"


def test_frr_answers_a_person_only_through_the_accounting_proxy(node, expected):
    """FRR's own sockets refuse a person; the vtysh every account gets goes through the proxy and works."""
    access = expected["access"]
    person = next(a["name"] for a in access["accounts"] if a["kind"] == "person")
    for router in access["routers"]:
        # show ip route is zebra's to answer; vtysh answers show version itself, daemons or not.
        direct = node(router).run("su", "-s", "/bin/sh", person, "-c", "/usr/bin/vtysh -c 'show ip route'", check=False)
        assert "Codes:" not in direct.stdout and "failed to connect to any daemons" in direct.stdout + direct.stderr, \
            f"{router}: {person} reached FRR without the proxy"
        proxied = node(router).run("su", "-s", "/bin/sh", person, "-c", "vtysh -c 'show ip route'")
        assert "Codes:" in proxied.stdout, proxied.stderr


def test_the_record_names_the_account_the_kernel_reports(node, expected):
    """A person who sets USER and LOGNAME to someone else's name is still recorded under their own account
    and uid, and the command is recorded as typed."""
    access = expected["access"]
    alice, bob = [a for a in access["accounts"] if a["kind"] == "person"][:2]
    router = access["routers"][0]
    probe = f"show ip route 198.18.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}/32"
    node(router).run("su", "-s", "/bin/sh", alice["name"], "-c",
                     f"USER={bob['name']} LOGNAME={bob['name']} vtysh -c '{probe}'")
    assert wait_for(lambda: on_box(node, router, f"line={probe}"), timeout=10, interval=1), "no record on the box"
    for line in on_box(node, router, f"line={probe}"):
        assert f"command user={alice['name']} uid={alice['uid']} " in line and f"user={bob['name']}" not in line, line


def test_an_account_outside_the_group_is_refused_and_recorded(node, expected):
    """An account the inventory doesn't list, added by hand and outside the admin group, gets FRR's error
    from the proxy instead of an answer, and the refusal is recorded under its name."""
    access = expected["access"]
    router = access["routers"][0]
    r = node(router)
    stranger = "mallory"
    try:
        r.run("adduser", "-D", "-u", "2998", "-s", "/bin/sh", stranger)
        out = r.run("su", "-s", "/bin/sh", stranger, "-c", "vtysh -c 'show ip route'", check=False)
        assert "Codes:" not in out.stdout and f"only the {access['group']} group may use FRR here" in out.stdout + out.stderr, out
        assert wait_for(lambda: on_box(node, router, f"refuse user={stranger} uid=2998"), timeout=10, interval=1)
    finally:
        r.run("deluser", "--remove-home", stranger, check=False)
    assert r.run("id", stranger, check=False).returncode != 0
    assert r.run("ls", "-d", f"/home/{stranger}", check=False).returncode != 0, f"{router}: /home/{stranger} was left behind"


def test_only_root_sends_from_the_ports_the_collector_trusts(node, expected):
    """The collector takes a command record only from the proxy's own UDP port, below 1024. On each router we
    own, a person can send from neither that port nor the highest port below 1024 (Docker would let any
    account bind one); root can, from the free one (the proxy holds its own)."""
    access = expected["access"]
    person = next(a["name"] for a in access["accounts"] if a["kind"] == "person")
    low = access["unprivileged_port_start"] - 1
    for router in access["routers"]:
        for port in (access["record_port"], low):
            send = f"printf x | nc -u -w 1 -p {port} 127.0.0.1 9"
            refused = node(router).run("su", "-s", "/bin/sh", person, "-c", send, check=False)
            assert refused.returncode != 0 and "ermission denied" in refused.stderr, f"{router}: {person} sent from port {port}: {refused}"
        sent = node(router).run("sh", "-c", f"printf x | nc -u -w 1 -p {low} 127.0.0.1 9", check=False)
        assert sent.returncode == 0, f"{router}: root couldn't send from port {low} either: {sent.stderr}"
