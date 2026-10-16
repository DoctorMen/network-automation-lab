"""A routing daemon that crashes as it starts (FRR 8.4.1's zebra and bgpd do now and then, V-011) is back within
seconds, not minutes: every router's watchfrr runs with the options its daemons file sets, and a throwaway router
started the way the lab starts that router has zebra back within 30 s after each of two crashes in a row. The
throwaway needs only Docker and the router image, not the lab, so it costs least in the lab job, which already has
both and runs this file with the other live tests (make live)."""
import re
import time

from netlab import restore

from .conftest import BUILD, wait_for

# The router whose zebra crashed twice as it started in CI run 38972784804 and was still down when make apply's
# 120 s wait ran out.
ROUTER = "isp"
BACK_WITHIN = 30  # seconds, after each crash


def watchfrr_options(router):
    """watchfrr_options from the router's rendered daemons file, as words (none if it sets none)."""
    m = re.search(r'^watchfrr_options="(.*)"$', (BUILD / router / "daemons").read_text(), re.M)
    return m[1].split() if m else []


def test_every_router_runs_watchfrr_with_its_daemons_files_options(node, expected):
    """On every lab router, watchfrr's command line starts with the options its daemons file sets: the image's own
    start script leaves them out, so this shows each router was started with its own start command."""
    wrong = {}
    for router in expected["loopbacks"]:
        want = watchfrr_options(router)
        ps = node(router).run("ps", "-o", "args").stdout.splitlines()
        watchfrr = next((line.split() for line in ps if line.startswith("/usr/lib/frr/watchfrr ")), [])
        if not want or watchfrr[1:1 + len(want)] != want:
            wrong[router] = f"daemons file sets {want}, running: {' '.join(watchfrr) or 'no watchfrr'}"
    assert not wrong, f"watchfrr runs without its daemons file's options: {wrong}"


def zebra_pid(ps):
    """zebra's pid in `ps -o pid,args`, or None. A zebra that died and is not yet reaped shows as [zebra]."""
    return next((line.split()[0] for line in ps.splitlines() if line.split()[1:2] == ["/usr/lib/frr/zebra"]), None)


def kill_zebra_as_it_starts(box, last=None, timeout=60):
    """SIGSEGV to zebra the moment a zebra other than `last` exists, the way FRR 8.4.1's zebra crashes as it
    starts. Returns its pid."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pid = zebra_pid(box.run("ps", "-o", "pid,args").stdout)
        if pid and pid != last and box.run("kill", "-SEGV", pid).returncode == 0:
            return pid
        time.sleep(0.05)
    raise AssertionError(f"no new zebra started on {box.name} within {timeout} s")


def zebra_back(box, crashed):
    """A new zebra answers vtysh, and FRR's start script (watchfrr.sh, which ends with `vtysh -b`, the config
    load) is done, which is what make apply's first task waits for."""
    ps = box.run("ps", "-o", "pid,args").stdout
    pid = zebra_pid(ps)
    answering = box.run("vtysh", "-c", "show daemons").stdout.split()
    return pid not in (None, crashed) and "zebra" in answering and "watchfrr.sh" not in ps and "vtysh -b" not in ps


def test_zebra_crashing_as_it_starts_is_back_within_30_s():
    """A throwaway isp with its rendered config, started the way the lab starts isp (netlab.restore.Scratch, which
    runs the node's own start command), has zebra answering again, with its config loaded, within 30 s after
    each of two crashes in a row. With the image's own start it took 65.2 s, then 120.6 s (V-011)."""
    took = []
    with restore.Scratch(BUILD, ROUTER, BUILD / ROUTER / "frr.conf") as box:
        crashed = None
        for crash in (1, 2):
            crashed = kill_zebra_as_it_starts(box, last=crashed)
            began = time.monotonic()
            back = wait_for(lambda: zebra_back(box, crashed), timeout=BACK_WITHIN, interval=0.5)
            took.append(round(time.monotonic() - began, 1))
            assert back, f"zebra was not back {BACK_WITHIN} s after crash {crash} (seconds after each crash: {took})"
    print(f"zebra back {took} s after each crash")
