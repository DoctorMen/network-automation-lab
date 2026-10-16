"""OROS NOT-7, one central store: the routers' own daemons log there (V-005), h2's web server's access log
reaches it through a forwarder that doesn't run as root while the app itself is left as it was, and the
store keeps a line the box's own small, rotated log has already lost. No secret is in it."""
import json
import subprocess
import time
import uuid

import yaml

from netlab import secrets

from ..conftest import BUILD, wait_for


def test_router_daemons_log_to_the_central_store(node, mon, noc):
    """An FRR daemon's own line (ospfd, from a log-adjacency-changes event) is searchable centrally (closes V-005)."""
    a = mon["ospf_neighbors"][0]
    since = time.time()
    # Clearing one neighbor makes ospfd log the adjacency going down and up again; routing heals in seconds.
    rid = node(a["neighbor"]).vtysh_json("show ip ospf")["routerId"]
    node(a["node"]).run("vtysh", "-c", f"clear ip ospf neighbor {rid}")
    lines = wait_for(lambda: noc.logs(f'{{node="{a["node"]}",source="syslog"}} |= "ospfd" |= "{rid}"', since), timeout=30, interval=1)
    assert lines, f"no ospfd line about {rid} from {a['node']} in the central store"
    assert wait_for(lambda: any(n["nbrState"].startswith("Full") for v in
                                node(a["node"]).vtysh_json("show ip ospf neighbor")["neighbors"].values() for n in v), timeout=60)


def test_app_log_forwarded_without_root_and_searchable(node, lab_name, mon, noc):
    """A request to h2's web server from h1 is searchable centrally within seconds. The forwarder runs as uid
    65534 and reads the log read-only; the web server is still the process the topology started."""
    app = mon["apps"][0]
    host = node(app["host"])
    topo = yaml.safe_load((BUILD / "topology.clab.yml").read_text())["topology"]["nodes"]
    forwarder = f"clab-{lab_name}-{app['host']}-{app['name']}-forwarder"
    marker = f"NOT7-{uuid.uuid4().hex[:12]}"
    since = time.time()
    address = json.loads((BUILD / "expected_state.json").read_text())["hosts"][app["host"]]
    node("h1").run("wget", "-q", "-T", "5", "-O", "/dev/null", f"http://{address}:{app['port']}/{marker}", check=False)
    lines = wait_for(lambda: noc.logs(f'{{node="{app["host"]}",source="{app["name"]}"}} |= "{marker}"', since), timeout=30, interval=1)
    assert lines, f"h1's request {marker} is not in the central store"
    assert lines[0][0] - since < 10, f"it took {lines[0][0] - since:.1f} s to arrive"
    # Not root: the forwarder's process, read from its own /proc.
    status = subprocess.run(["docker", "exec", forwarder, "cat", "/proc/1/status"], capture_output=True, text=True, check=True).stdout
    uids = next(l.split()[1:] for l in status.splitlines() if l.startswith("Uid:"))
    assert set(uids) == {"65534"}, f"the forwarder runs as uid {uids}"
    mounts = json.loads(subprocess.run(["docker", "inspect", "-f", "{{json .Mounts}}", forwarder], capture_output=True, text=True, check=True).stdout)
    assert all(not m["RW"] for m in mounts if m["Destination"] == "/applog"), "the forwarder can write the app's log"
    # The app as the topology started it: same command line, still a child of the container's first process.
    ps = host.run("ps", "-o", "pid,ppid,args").stdout.splitlines()
    server = [l.split() for l in ps if l.split()[2:] == ["python3", "-m", "http.server", str(app["port"])]]
    assert server, f"no http.server {app['port']} on {app['host']}"
    assert f"python3 -m http.server {app['port']} " in topo[app["host"]]["cmd"], "the topology no longer starts the app as it was"


def test_history_outlasts_on_box_rotation(node, mon, noc):
    """A line pushed out of r1's rotated on-box log by more than its size of later lines is still in the central store."""
    r1 = node("r1")
    marker = f"NOT7-rotated-{uuid.uuid4().hex[:12]}"
    since = time.time()
    r1.run("logger", "-t", "netlab-test", marker)
    keep = mon["on_box"]["size_kb"] * 1024 * (mon["on_box"]["rotated"] + 1)
    # Filler lines of about 200 bytes each, past everything the box keeps.
    filler = "x" * 180
    count = keep // 150 + 50
    r1.run("sh", "-c", f"for i in $(seq {count}); do logger -t netlab-filler {filler}; done", timeout=120)
    on_box = r1.run("sh", "-c", "cat /var/log/messages*").stdout
    assert marker not in on_box, "the box still has the line, so its rotation wasn't exercised"
    assert len(on_box.encode()) <= keep + 4096, f"the box kept {len(on_box)} bytes, more than its {keep} bytes"
    lines = wait_for(lambda: noc.logs(f'{{node="r1"}} |= "{marker}"', since - 1), timeout=30, interval=1)
    assert lines, "the central store lost the line too"


def test_no_secret_in_the_central_store(noc, expected):
    """Every line the store holds from the last day, searched here for each BGP password (never sent as a query)."""
    values = sorted({(secrets.store() / e["secret"]).read_text().strip() for ends in expected.get("bgp_md5", {}).values() for e in ends})
    assert values, "no BGP password to look for"
    start, hits, lines = time.time() - 86400, [], 0
    for source in {s["source"] for s in expected["monitoring"]["sources"]}:
        got = noc.logs(f'{{source="{source}"}}', start, every=True)
        lines += len(got)
        hits += [f"{labels['node']}/{labels['source']}" for _, labels, line in got if any(v in line for v in values)]
    assert lines, "the store returned no lines at all"
    assert not hits, f"a BGP password is in the central store: {sorted(set(hits))}"
