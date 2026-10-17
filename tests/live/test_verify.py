"""Verified in effect (netlab.verify, decision 0010): a patch installed but not yet running, and a QoS
class that isn't doing its job, are both reported `not in effect`, read from the live system."""
import subprocess
import sys

import yaml

from .conftest import BUILD, ROOT, wait_for


def verify(*nodes):
    return subprocess.run([sys.executable, "-m", "netlab.verify", *nodes], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)


def test_kernel_patch_without_reboot_is_not_in_effect(node):
    """A newer kernel installed on r2 but not booted is `not in effect`; the running one alone installed is in effect."""
    r2 = node("r2")
    running = r2.run("uname", "-r").stdout.strip()
    newer = f"{int(running.split('.')[0]) + 1}.0.0-patched"
    assert verify("r2").returncode == 0, "verify fails on the clean lab, so a failure proves nothing"
    try:
        # The node shares the host's kernel and installs none, so put the two module trees a kernel
        # package leaves behind in place: the one running, then a newer one waiting for a reboot.
        r2.run("mkdir", "-p", f"/lib/modules/{running}")
        current = verify("r2")
        assert current.returncode == 0 and f"in effect: {running} is the newest installed" in current.stdout, current.stdout
        r2.run("mkdir", "-p", f"/lib/modules/{newer}")
        pending = verify("r2")
        assert pending.returncode == 1, "a kernel installed without a reboot was not reported:\n" + pending.stdout
        assert f"r2 kernel: not in effect: {newer} is installed but {running} is running" in pending.stdout, pending.stdout
    finally:
        r2.run("rm", "-rf", "/lib/modules")
    assert verify("r2").returncode == 0


def test_daemon_patch_without_restart_is_not_in_effect(node):
    """staticd replaced on disk on r3 is `not in effect` until it restarts, though the installed file is current."""
    # r3's staticd holds no routes, so restarting it moves no traffic.
    r3, binary = node("r3"), "/usr/lib/frr/staticd"
    assert verify("r3").returncode == 0, "verify fails on the clean lab, so a failure proves nothing"
    try:
        # What a package upgrade does: write the new file beside the old one, then rename it over.
        r3.run("sh", "-c", f"cp -p {binary} {binary}.new && mv {binary}.new {binary}")
        patched = verify("r3")
        assert patched.returncode == 1, "a daemon still running its replaced binary was not reported:\n" + patched.stdout
        assert "r3 daemons: not in effect: staticd still run a binary replaced on disk" in patched.stdout, patched.stdout
    finally:
        # The way watchfrr restarts a daemon. Killing it and waiting for watchfrr works too, but slower:
        # watchfrr first waits its restart interval, 5 s, doubling for each restart in a row up to 60 s (V-011).
        r3.run("/usr/lib/frr/watchfrr.sh", "restart", "staticd", check=False)
    assert wait_for(lambda: verify("r3").returncode == 0, timeout=30, interval=1), verify("r3").stdout


def test_qos_change_confirmed_from_class_counters(node, expected):
    """h2's QoS is in effect only with the inventory's rates and with web connections counted in the web class."""
    spec, h2 = expected["qos"]["h2"], node("h2")
    web = next(c for c in spec["classes"] if "sport" in c)
    steps = [s for s in yaml.safe_load((BUILD / "topology.clab.yml").read_text())["topology"]["nodes"]["h2"]["exec"]
             if s.startswith("tc ")]

    def root_bytes():
        out = h2.run("tc", "-s", "class", "show", "dev", spec["interface"], "classid", "1:1").stdout
        return int(out.split("Sent ")[1].split()[0])
    sent = root_bytes()
    ok = verify("h2")
    assert ok.returncode == 0 and "h2 qos: in effect" in ok.stdout, ok.stdout
    # The probe is a handful of connections: kilobytes on a link of megabits per second.
    assert root_bytes() - sent < 20_000, f"verify sent {root_bytes() - sent} bytes through the shaped link"
    try:
        # The classes are all there at the right rates, but nothing sends web replies to the web class.
        h2.run("tc", "filter", "del", "dev", spec["interface"], "parent", "1:")
        unmatched = verify("h2")
        assert unmatched.returncode == 1 and f"added 0 packets to 1:{web['id']}" in unmatched.stdout, unmatched.stdout
        h2.run("tc", "class", "change", "dev", spec["interface"], "parent", "1:1", "classid", f"1:{web['id']}",
               "htb", "rate", "1mbit", "ceil", spec["rate"], "prio", str(web["prio"]))
        slow = verify("h2")
        assert slow.returncode == 1 and f"runs at 1mbit ceil {spec['rate']}, the inventory says {web['rate']}" in slow.stdout, slow.stdout
    finally:
        h2.run("tc", "qdisc", "del", "dev", spec["interface"], "root", check=False)
        for step in steps:
            h2.run(*step.split())
    assert verify("h2").returncode == 0
