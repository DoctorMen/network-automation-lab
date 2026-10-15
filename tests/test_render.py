"""Rendered configs should say exactly what the inventory says."""
import json
from pathlib import Path

import yaml

from netlab.inventory import load
from netlab.render import render_all, render_firewall, render_router

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "network.yml"
inv = load(INVENTORY)


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
    names = [line.split("--comment ")[1].strip('"') for line in script.splitlines() if "--comment" in line]
    assert names == ["allow-established", "allow-icmp", "allow-web", "deny-ssh-to-servers", "allow-internet", "default-drop"]


def test_web_rule_matches_only_connection_openers():
    script = render_firewall(inv, "fw1")
    line = next(l for l in script.splitlines() if '"allow-web"' in l)
    assert "-p tcp --syn " in line


def test_render_all_writes_a_consistent_lab(tmp_path):
    render_all(inv, tmp_path)
    topo = yaml.safe_load((tmp_path / "topology.clab.yml").read_text())
    assert set(topo["topology"]["nodes"]) == set(inv.devices)
    assert topo["topology"]["defaults"]["image"] == inv.platform["image"]
    assert len(topo["topology"]["links"]) == len(inv.links)
    for node in topo["topology"]["nodes"].values():
        for bind in node.get("binds", []):
            assert (tmp_path / bind.split(":")[0]).exists(), bind
    expected = json.loads((tmp_path / "expected_state.json").read_text())
    assert expected["ospf_neighbors"]["r2"] == ["r1", "r3"]
    assert expected["bfd_peers"]["r1"] == {"10.0.12.1": "eth1", "10.0.13.1": "eth2"}
    assert expected["passive_interfaces"] == {"r1": [], "r2": [], "r3": ["eth3"]}
    assert expected["platform"] == inv.platform
    assert expected["bgp_sessions"][0]["peer"] == "isp"


def test_render_is_deterministic(tmp_path):
    render_all(inv, tmp_path / "a")
    render_all(inv, tmp_path / "b")
    for f in (tmp_path / "a").rglob("*"):
        if f.is_file():
            assert f.read_text() == (tmp_path / "b" / f.relative_to(tmp_path / "a")).read_text()


def test_ci_pulls_the_image_the_inventory_names():
    """CI deploys the image the inventory records, so the live version check tests the real thing."""
    ci = yaml.safe_load((INVENTORY.parents[1] / ".github" / "workflows" / "ci.yml").read_text())
    steps = [step for job in ci["jobs"].values() for step in job["steps"]]
    pulls = [step["run"].split()[-1] for step in steps if step.get("run", "").startswith("docker pull")]
    assert pulls == [inv.platform["image"]]
