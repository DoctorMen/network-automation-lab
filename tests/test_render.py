"""Rendered configs should say exactly what the inventory says."""
import json
from pathlib import Path

import yaml

from netlab import monitoring
from netlab.backup import IMAGE as RESTIC_IMAGE
from netlab.inventory import load
from netlab.render import render_all, render_firewall, render_router

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "network.yml"
inv = load(INVENTORY)


class OneKeyLoader(yaml.SafeLoader):
    """YAML that refuses a key given twice in one mapping. PyYAML keeps the last one without a word, so
    a second `exec:` on a node would silently drop the first list."""


def _mapping(loader, node, deep=False):
    keys = [loader.construct_object(k, deep=deep) for k, _ in node.value]
    if twice := sorted({k for k in keys if keys.count(k) > 1}):
        raise yaml.constructor.ConstructorError(None, None, f"duplicate key(s) {twice}", node.start_mark)
    return loader.construct_mapping(node, deep=deep)


OneKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def test_core_router_runs_ospf_on_router_links_only():
    conf = render_router(inv, "r1")["frr.conf"]
    assert "router ospf\n ospf router-id 10.255.0.1" in conf
    assert "interface eth1\n description to-r2:eth1\n ip address 10.0.12.0/31\n ip ospf area 0\n ip ospf network point-to-point\n ip ospf bfd" in conf
    # The firewall link is not an OSPF adjacency; LAN-A arrives via a redistributed static route.
    eth3 = conf.split("interface eth3")[1].split("exit")[0]
    assert "ospf" not in eth3
    assert "ip route 10.10.10.0/24 10.0.100.2" in conf
    assert " redistribute static" in conf


def test_server_lan_is_passive():
    conf = render_router(inv, "r3")["frr.conf"]
    eth3 = conf.split("interface eth3")[1].split("exit")[0]
    assert "ip ospf passive" in eth3


def test_edge_router_bgp():
    conf = render_router(inv, "r2")["frr.conf"]
    assert "router bgp 65001" in conf
    assert "neighbor 198.51.100.1 remote-as 65100" in conf
    assert "aggregate-address 10.0.0.0/8 summary-only" in conf
    assert "default-information originate always" in conf


def test_daemons_match_protocols():
    assert "bgpd=no" in render_router(inv, "r1")["daemons"]
    assert "bgpd=yes" in render_router(inv, "r2")["daemons"]
    assert "ospfd=no" in render_router(inv, "isp")["daemons"]
    # bfdd only serves OSPF here, so it runs exactly where ospfd does.
    assert "bfdd=yes" in render_router(inv, "r1")["daemons"]
    assert "bfdd=no" in render_router(inv, "isp")["daemons"]


def test_firewall_default_drop_and_rule_order():
    script = render_firewall(inv, "fw1")
    assert "iptables -P FORWARD DROP" in script
    names = [line.split("--comment ")[1].strip('"') for line in script.splitlines() if line.startswith("iptables -A FORWARD")]
    assert names == ["allow-established", "allow-icmp", "allow-web", "deny-ssh-to-servers", "allow-internet", "default-drop"]


def test_web_rule_matches_only_connection_openers():
    script = render_firewall(inv, "fw1")
    line = next(l for l in script.splitlines() if '"allow-web"' in l)
    assert "-p tcp --syn " in line


def test_render_all_writes_a_consistent_lab(tmp_path):
    render_all(inv, tmp_path)
    topo = yaml.safe_load((tmp_path / "topology.clab.yml").read_text())
    # Every device, plus the NOC's sidecars (decision 0018), each in another node's network namespace.
    assert set(topo["topology"]["nodes"]) == set(inv.devices) | set(monitoring.sidecars(inv))
    for name, cfg in monitoring.sidecars(inv).items():
        assert topo["topology"]["nodes"][name]["network-mode"] == f"container:{cfg['netns']}"
    # conntrack reads the router's translations only with CAP_NET_ADMIN, which the topology asks for by name.
    caps = {name: n["cap-add"] for name, n in topo["topology"]["nodes"].items() if "cap-add" in n}
    assert caps == {f"{r}-nat-log": ["NET_ADMIN"] for r in monitoring.nat_logs(inv)} and caps, caps
    assert topo["topology"]["defaults"]["image"] == inv.platform["image"]
    assert len(topo["topology"]["links"]) == len(inv.links)
    for node in topo["topology"]["nodes"].values():
        for bind in node.get("binds", []):
            assert (tmp_path / bind.split(":")[0]).exists(), bind
    expected = json.loads((tmp_path / "expected_state.json").read_text())
    assert expected["ospf_neighbors"]["r2"] == ["r1", "r3"]
    assert expected["bfd_peers"]["r1"] == {"10.0.12.1": "eth1", "10.0.13.1": "eth2"}
    assert expected["passive_interfaces"] == {"r1": [], "r2": ["eth4"], "r3": ["eth3"]}  # r2 eth4: the NOC's LAN
    assert expected["platform"] == inv.platform
    assert expected["bgp_sessions"][0]["peer"] == "isp"


def test_render_is_deterministic(tmp_path):
    render_all(inv, tmp_path / "a")
    render_all(inv, tmp_path / "b")
    for f in (tmp_path / "a").rglob("*"):
        if f.is_file():
            assert f.read_text() == (tmp_path / "b" / f.relative_to(tmp_path / "a")).read_text()


def test_ci_pulls_the_image_the_inventory_names():
    """CI deploys the images the inventory records, so the live version checks test the real thing: the lab
    job the router image, each of the three NOC jobs every image the full lab runs (`netlab images`). The drills
    workflow, which runs on the full lab too, pulls the same list, and exactly the restic image
    netlab.backup runs."""
    ci = yaml.safe_load((INVENTORY.parents[1] / ".github" / "workflows" / "ci.yml").read_text())
    steps = [step for job in ci["jobs"].values() for step in job["steps"]]
    pulls = [step["run"].split()[-1] for step in steps if step.get("run", "").startswith("docker pull")]
    drills = yaml.safe_load((INVENTORY.parents[1] / ".github" / "workflows" / "drills.yml").read_text())["jobs"]
    drill_pulls = {job: [line.split()[-1] for step in drills[job]["steps"] for line in step.get("run", "").splitlines()
                         if line.strip().startswith("docker pull")] for job in drills}
    assert drill_pulls == {"backup-init": [RESTIC_IMAGE], "drills": [RESTIC_IMAGE]}
    assert pulls == [inv.platform["image"]]
    noc = [job for job in ci["jobs"] if job.startswith("observe")]
    assert noc == ["observe-1", "observe-2", "observe-3"]
    for job in noc:
        observe = [step["run"] for step in ci["jobs"][job]["steps"] if "netlab images" in step.get("run", "")]
        assert observe and "docker pull" in observe[0], f"{job} doesn't pull what `netlab images` lists"
    drill_images = [line for step in drills["drills"]["steps"] for line in step.get("run", "").splitlines() if "netlab images" in line]
    assert drill_images and "docker pull" in drill_images[0], "the drills job doesn't pull what `netlab images` lists"


def test_canary_goes_first_with_the_rollout_settings(tmp_path):
    """deploy.yml takes routers in inventory order, one and then the rest, so the canary must be first."""
    raw = yaml.safe_load(INVENTORY.read_text())
    raw["rollout"]["canary"] = "r3"  # not first in the inventory
    (tmp_path / "net.yml").write_text(yaml.safe_dump(raw, sort_keys=False))
    render_all(load(tmp_path / "net.yml"), tmp_path / "build")
    routers = yaml.safe_load((tmp_path / "build" / "ansible_inventory.yml").read_text())["all"]["children"]["routers"]
    assert list(routers["hosts"]) == ["r3", "r1", "r2", "isp"]
    assert routers["vars"] == raw["rollout"]


def test_h2_port_is_shaped_with_a_web_class(tmp_path):
    render_all(inv, tmp_path)
    steps = yaml.safe_load((tmp_path / "topology.clab.yml").read_text())["topology"]["nodes"]["h2"]["exec"]
    tc = [s for s in steps if s.startswith("tc ")]
    assert tc == [
        "tc qdisc add dev eth1 root handle 1: htb default 20",
        "tc class add dev eth1 parent 1: classid 1:1 htb rate 20mbit",
        "tc class add dev eth1 parent 1:1 classid 1:10 htb rate 15mbit ceil 20mbit prio 0",
        "tc class add dev eth1 parent 1:1 classid 1:20 htb rate 5mbit ceil 20mbit prio 1",
        "tc filter add dev eth1 parent 1: protocol ip prio 1 u32 match ip sport 80 0xffff flowid 1:10",
    ]
    assert not [s for s in yaml.safe_load((tmp_path / "topology.clab.yml").read_text())["topology"]["nodes"]["h1"]["exec"]
                if s.startswith("tc ")], "only hosts with a qos block are shaped"


def test_every_node_has_one_exec_list(tmp_path):
    """Each node's deploy steps are one exec list with no key given twice: h2's address, route and QoS, r2's and
    r3's edge.sh, fw1's firewall.sh, and last, on every log source, the NOC's agent (decision 0019)."""
    render_all(inv, tmp_path)
    nodes = yaml.load((tmp_path / "topology.clab.yml").read_text(), Loader=OneKeyLoader)["topology"]["nodes"]
    agent = "sh /monitoring/agent.sh"
    sources = monitoring.syslog_sources(inv)
    for n in sources:
        assert nodes[n]["exec"][-1] == agent and nodes[n]["exec"].count(agent) == 1, n
    assert not [n for n, v in nodes.items() if agent in v.get("exec", []) and n not in sources]
    # Routers we own also set up their accounts and accounting proxy, just before the agent (decision 0029).
    acct = ["sh /access/access.sh"]
    assert {n: v["exec"][:-1] for n, v in nodes.items() if n in inv.routers and n in sources} == {"r1": acct, "r2": ["sh /edge.sh", *acct], "r3": ["sh /edge.sh", *acct]}
    assert nodes["fw1"]["exec"][:-1] == ["sh /firewall.sh"]
    h2 = nodes["h2"]["exec"]
    assert h2[0].startswith("ip addr add ") and h2[1].startswith("ip route replace default ") and h2[2].startswith("tc qdisc add ")
