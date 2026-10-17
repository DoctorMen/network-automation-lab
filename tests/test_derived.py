"""One record feeds DNS and monitoring (OROS FND-4, decision 0032): a host added to the inventory is in the
rendered hosts file, the NOC's probe targets and its alert rules on the next render, keyed in nowhere else."""
import copy
from pathlib import Path

import yaml

from netlab.inventory import load
from netlab.render import render_all

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "network.yml"


def rendered(tmp_path, mutate):
    raw = copy.deepcopy(yaml.safe_load(INVENTORY.read_text()))
    mutate(raw)
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "net.yml").write_text(yaml.safe_dump(raw, sort_keys=False))
    out = tmp_path / "build"
    render_all(load(tmp_path / "net.yml"), out)
    return out


def test_added_host_appears_in_dns_and_monitoring_without_being_keyed_in_again(tmp_path):
    """h9, a server on a new switch port, is in hosts.lab, in the icmp probe targets and the SourceSilent rules, in the expected DNS names, and in the switch's ports; the shipped render has none of it."""
    def add_h9(raw):
        raw["hosts"]["h9"] = {"owner": "campus NOC", "interface": "eth1", "address": "10.10.10.19/24", "gateway": "10.10.10.1",
                              "segment": "LAN-A", "services": [80]}
        raw["switches"]["sw1"]["ports"]["eth5"] = {"vlan": 10}
        raw["links"].append(["h9:eth1@10.10.10.19/24", "sw1:eth5"])
        raw["scope"]["out_of_scope"].append("h9")
        raw["logging"]["budget"]["store_mb"] += 1024  # one more log source needs its share of the store, or validate refuses it
    before, after = rendered(tmp_path / "a", lambda raw: None), rendered(tmp_path / "b", add_h9)
    assert "h9" not in (before / "noc" / "hosts.lab").read_text()
    assert "10.10.10.19 h9.lab h9" in (after / "noc" / "hosts.lab").read_text().splitlines()
    prom = yaml.safe_load((after / "noc" / "prometheus.yml").read_text())
    icmp = next(j for j in prom["scrape_configs"] if j["job_name"] == "icmp")
    assert {"targets": ["10.10.10.19"], "labels": {"node": "h9", "owner": "campus NOC"}} in icmp["static_configs"]
    rules = yaml.safe_load((after / "noc" / "rules.yml").read_text())
    assert [r for g in rules["groups"] for r in g["rules"] if r.get("alert") == "SourceSilent" and r["labels"].get("node") == "h9"]
    expected = yaml.safe_load((after / "expected_state.json").read_text())
    assert expected["dns"]["names"]["h9.lab"] == "10.10.10.19"
    assert expected["switches"]["sw1"]["ports"]["eth5"] == {"vlan": 10, "to": "h9:eth1", "role": "edge"}
    assert "h9" in (after / "topology.clab.yml").read_text() and "h9" not in (before / "topology.clab.yml").read_text()
    # The Corefile itself doesn't change: the names are data, the server's config is not touched per host.
    assert (after / "noc" / "Corefile").read_text() == (before / "noc" / "Corefile").read_text()
