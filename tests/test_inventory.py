"""The validator should catch the addressing mistakes that break real networks."""
import copy
from pathlib import Path

import pytest
import yaml

from netlab.inventory import InventoryError, load

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "network.yml"


def load_with(tmp_path, mutate):
    raw = yaml.safe_load(INVENTORY.read_text())
    raw = copy.deepcopy(raw)
    mutate(raw)
    p = tmp_path / "net.yml"
    p.write_text(yaml.safe_dump(raw))
    return load(p)


def problems(tmp_path, mutate) -> str:
    with pytest.raises(InventoryError) as exc:
        load_with(tmp_path, mutate)
    return "\n".join(exc.value.problems)


def test_shipped_inventory_is_valid():
    inv = load(INVENTORY)
    assert len(inv.devices) == 7
    assert inv.ospf_neighbors("r1") == ["r2", "r3"]
    assert inv.ospf_neighbors("isp") == []


def test_duplicate_ip(tmp_path):
    def m(raw):
        raw["links"][1][1] = "r3:eth1@10.0.12.1/31"
    out = problems(tmp_path, m)
    assert "10.0.12.1 is already used" in out


def test_duplicate_loopback(tmp_path):
    """Two routers with the same loopback would share an OSPF router-ID."""
    def m(raw):
        raw["routers"]["r3"]["loopback"] = raw["routers"]["r1"]["loopback"]
    assert "r3: loopback 10.255.0.1 collides with r1:lo" in problems(tmp_path, m)


def test_ends_in_different_subnets(tmp_path):
    def m(raw):
        raw["links"][0][1] = "r2:eth1@10.0.99.1/31"
    assert "different subnets" in problems(tmp_path, m)


def test_overlapping_subnets(tmp_path):
    def m(raw):
        raw["links"][2] = ["r1:eth2@10.0.12.4/29", "r3:eth2@10.0.12.5/29"]
    assert "overlaps" in problems(tmp_path, m)


def test_unknown_device(tmp_path):
    def m(raw):
        raw["links"].append(["r9:eth1@10.0.99.0/31", "r1:eth9@10.0.99.1/31"])
    assert "'r9' is not defined" in problems(tmp_path, m)


def test_interface_reused(tmp_path):
    def m(raw):
        raw["links"].append(["r1:eth1@10.0.99.0/31", "r3:eth9@10.0.99.1/31"])
    assert "r1:eth1 is used on more than one link" in problems(tmp_path, m)


def test_bgp_peer_address_must_match_link(tmp_path):
    def m(raw):
        raw["routers"]["r2"]["bgp"]["neighbors"][0]["address"] = "198.51.100.9"
    assert "does not match link address" in problems(tmp_path, m)


def test_host_gateway_must_be_on_subnet(tmp_path):
    def m(raw):
        raw["hosts"]["h1"]["gateway"] = "10.99.0.1"
    assert "gateway 10.99.0.1 is not on" in problems(tmp_path, m)


def test_network_address_rejected_on_lan(tmp_path):
    def m(raw):
        raw["links"][6] = ["h2:eth1@10.20.20.0/24", "r3:eth3@10.20.20.1/24"]
        raw["hosts"]["h2"]["address"] = "10.20.20.0/24"
    assert "network or broadcast" in problems(tmp_path, m)


def test_tcp_accept_rule_needs_syn(tmp_path):
    def m(raw):
        web = next(r for r in raw["firewalls"]["fw1"]["rules"] if r["name"] == "allow-web")
        del web["syn"]
        raw["firewalls"]["fw1"]["rules"].append({"name": "bad-syn", "proto": "icmp", "syn": True, "action": "accept"})
        raw["firewalls"]["fw1"]["rules"].append({"name": "new-only", "proto": "tcp", "state": ["NEW"], "dport": 443, "action": "accept"})
    out = problems(tmp_path, m)
    assert "fw1 rule allow-web: TCP accept needs syn: true" in out
    assert "fw1 rule bad-syn: syn: true needs proto: tcp" in out
    assert "fw1 rule new-only: TCP accept needs syn: true" in out, "--ctstate NEW still admits a forged ACK"


def test_platform_versions_must_be_text(tmp_path):
    def m(raw):
        raw["platform"]["alpine"] = 3.16
        del raw["platform"]["digest"]
    out = problems(tmp_path, m)
    assert "platform: alpine 3.16 must be quoted" in out and "platform: digest is missing" in out


def test_reports_every_problem_at_once(tmp_path):
    def m(raw):
        raw["links"][0][1] = "r2:eth1@10.0.99.1/31"
        raw["hosts"]["h1"]["gateway"] = "10.99.0.1"
    out = problems(tmp_path, m)
    assert "different subnets" in out and "gateway" in out


def test_every_device_needs_an_owner(tmp_path):
    def m(raw):
        del raw["routers"]["isp"]["owner"]
        del raw["hosts"]["h1"]["owner"]
    out = problems(tmp_path, m)
    assert "isp: no owner" in out and "h1: no owner" in out


def test_operator_must_own_a_device(tmp_path):
    def m(raw):
        raw["operator"] = "nobody"
    assert "operator 'nobody' owns no device" in problems(tmp_path, m)


def test_canary_must_be_a_router(tmp_path):
    def m(raw):
        raw["rollout"]["canary"] = "h1"
    assert "rollout: canary 'h1' is not a router" in problems(tmp_path, m)


def test_qos_classes_must_fit_the_link(tmp_path):
    """Class rates are what each class is promised, so together they can't exceed the link; one class takes the rest."""
    def m(raw):
        raw["qos"]["h2"]["classes"][0]["rate"] = "18mbit"
        raw["qos"]["h2"]["classes"][1]["default"] = False
    out = problems(tmp_path, m)
    assert "qos on h2: the class rates add up to more than the link's 20mbit" in out
    assert "qos on h2: exactly one class must be the default" in out
