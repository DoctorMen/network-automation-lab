"""BGP MD5 on the ISP session (OROS ACC-4): the session really uses the per-run secret, and no step of
`make apply` or `make drift` puts that secret in clear in a file, a log, an environment or a command
line. A failure here says where a secret was found, never what it was."""
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from netlab import secrets

from .conftest import BUILD, ROOT, wait_for

ANSIBLE_PLAYBOOK = Path(sys.executable).with_name("ansible-playbook")


def secret(name):
    """A secret's value, from the store `make apply` reads it from."""
    return (secrets.store() / name).read_text().strip()


def sessions(expected):
    """Every authenticated session end: {router, asn, peer, neighbor, secret}, from the inventory."""
    found = [{"router": r, **s} for r, ends in expected.get("bgp_md5", {}).items() for s in ends]
    assert found, "the inventory authenticates no BGP session (bgp_auth in inventory/network.yml)"
    return found


def neighbor(node, end):
    return node(end["router"]).vtysh_json(f"show bgp neighbors {end['neighbor']}")[end["neighbor"]]


def established(node, end):
    return neighbor(node, end)["bgpState"] == "Established"


def set_password(node, end, password):
    """As deploy.yml does it: vtysh reads the config lines on stdin, never on its command line."""
    node(end["router"]).run("vtysh", "-f", "/dev/stdin",
                            input=f"router bgp {end['asn']}\n neighbor {end['neighbor']} password {password}\n")


def test_bgp_session_uses_its_secret_and_a_wrong_one_drops_it(node, expected):
    """Both ends of every MD5 session have a password and are Established; a wrong password on the carrier's end takes the session down."""
    ends = sessions(expected)
    for end in ends:
        assert neighbor(node, end).get("authenticationEnabled") == 1, \
            f"{end['router']} -> {end['peer']} has no MD5 password: run `make apply` (CI's `make deploy` does)"
        assert wait_for(lambda: established(node, end)), f"{end['router']} -> {end['peer']} is not Established"

    # Change it on the end we don't own, as a carrier-side mistake would, and watch from ours.
    far = next(e for e in ends if expected["owners"][e["router"]] != expected["operator"])
    near = next(e for e in ends if e["router"] == far["peer"])
    try:
        set_password(node, far, f"wrong-{uuid.uuid4().hex}")
        dropped = wait_for(lambda: not established(node, near), timeout=30, interval=1)
        time.sleep(5)  # and it stays down: a session that only reset would be back by now
        stayed_down = not established(node, near)
    finally:
        set_password(node, far, secret(far["secret"]))
        wait_for(lambda: established(node, near), timeout=90, interval=2)
    assert dropped and stayed_down, f"{near['router']} -> {near['peer']} stayed up with mismatched passwords: MD5 is not enforced"
    assert established(node, near), f"{near['router']} -> {near['peer']} did not come back with the right password"


class Watch(threading.Thread):
    """Until stopped: every process on this machine whose command line or environment we may read
    (in CI, other users' environments are closed to us, so each router's own processes are read with
    `docker exec` as well), and Ansible's temp folders here and on the routers."""

    def __init__(self, values, containers):
        super().__init__(daemon=True)
        self.needles = [v.encode() for v in values]
        self.containers = containers
        self.hits: set[str] = set()
        self.rounds = 0
        self.done = threading.Event()

    def run(self):
        last = 0.0
        while not self.done.is_set():
            self.scan_here()
            if time.time() - last > 0.5:
                self.scan_routers()
                last = time.time()
            self.rounds += 1
            self.done.wait(0.02)  # about 40 rounds a second: a vtysh call lives longer than that

    def found(self, data: bytes) -> bool:
        return any(n in data for n in self.needles)

    def scan_here(self):
        paths = [p / f for p in Path("/proc").iterdir() if p.name.isdigit() for f in ("cmdline", "environ")]
        paths += [p for p in (Path.home() / ".ansible" / "tmp").rglob("*") if p.is_file()]
        for path in paths:
            try:
                if self.found(path.read_bytes()):
                    self.hits.add(f"this machine: {path}")
            except OSError:  # the process ended, or it belongs to another user
                pass

    def scan_routers(self):
        for container in self.containers:
            # grep reads the secrets as patterns from stdin (-f -), so they never sit in its own argv.
            out = subprocess.run(["docker", "exec", "-i", container, "sh", "-c",
                                  "grep -rlsF -f - /proc/[0-9]*/cmdline /proc/[0-9]*/environ /root/.ansible"],
                                 input=b"\n".join(self.needles), capture_output=True).stdout.decode()
            self.hits.update(f"{container}: {line}" for line in out.split())

    def stop(self):
        self.done.set()
        self.join()


def files_holding(values, *folders):
    needles = [v.encode() for v in values]
    return [str(p.relative_to(ROOT)) for folder in folders if folder.exists()
            for p in folder.rglob("*") if p.is_file() and any(n in p.read_bytes() for n in needles)]


def playbook(name):
    return subprocess.run([str(ANSIBLE_PLAYBOOK), name], cwd=ROOT / "ansible", capture_output=True, text=True, timeout=300)


def test_no_secret_in_env_argv_logs_or_files(node, expected):
    """While `make apply` puts back a hand change on r2 and `make drift` runs, no command line, environment, FRR log, container log, playbook output, build/ or backups/ file holds a BGP password in clear; the session stays up."""
    ends = sessions(expected)
    values = [secret(name) for name in {e["secret"] for e in ends}]
    routers = sorted({e["router"] for e in ends})
    ours = next(e["router"] for e in ends if expected["owners"][e["router"]] == expected["operator"])
    r2 = node(ours)
    lines = (BUILD / ours / "frr.conf").read_text().splitlines()
    desc = next(l.split("description ", 1)[1] for l in lines[lines.index("interface eth1"):] if "description " in l)

    # A hand change, so `make apply` really reloads a router that holds a password: that is where
    # frr-reload.py would delete it, with the password on vtysh's command line and in its log.
    drops = {e["router"]: neighbor(node, e)["connectionsDropped"] for e in ends}
    r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {uuid.uuid4().hex[:8]}")
    watch = Watch(values, [node(r).container for r in routers])
    watch.start()
    try:
        runs = {name: playbook(name) for name in ("deploy.yml", "drift.yml")}
    finally:
        watch.stop()
        r2.run("vtysh", "-c", "conf t", "-c", "interface eth1", "-c", f"description {desc}")

    hits = set(watch.hits)
    hits.update(f"{name} output" for name, run in runs.items() if any(v in run.stdout + run.stderr for v in values))
    hits.update(files_holding(values, BUILD, ROOT / "backups"))
    for router in routers:
        container = node(router).container
        # FRR's own logs and scratch files: frr-reload.log, its reload-*.txt, the staged configs.
        out = subprocess.run(["docker", "exec", "-i", container, "sh", "-c", "grep -rlsF -f - /var/log/frr /var/run/frr /tmp"],
                             input="\n".join(values), capture_output=True, text=True).stdout
        hits.update(f"{container}: {line}" for line in out.split())
        logs = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
        if any(v in logs.stdout + logs.stderr for v in values):
            hits.add(f"docker logs {container}")
    assert watch.rounds > 10, f"only {watch.rounds} samples of /proc were taken while the playbooks ran"
    assert not hits, f"a BGP password in clear in: {sorted(hits)}"

    # Only now is the playbooks' output known to be clean enough to print.
    for name, run in runs.items():
        assert run.returncode == 0, f"{name} failed:\n{run.stdout[-3000:]}"
    for end in ends:
        state = neighbor(node, end)
        assert state["connectionsDropped"] == drops[end["router"]], \
            f"{end['router']} -> {end['peer']} went down during make apply: frr-reload removed the password"
        assert state["bgpState"] == "Established" and state.get("authenticationEnabled") == 1, \
            f"{end['router']} -> {end['peer']} lost its session or its password during make apply"
