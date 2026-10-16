"""The NOC's checks are generated from the inventory (decisions 0018 and 0019): one rule per object, each
source its own last-seen check, every config the sidecars read rendered, and nothing hand-written."""
import copy
import json
import re
from pathlib import Path

import pytest
import yaml

from netlab import kernel, monitoring
from netlab.inventory import InventoryError, load
from netlab.render import render_all

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "network.yml"
inv = load(INVENTORY)


def mutated(tmp_path, mutate):
    raw = copy.deepcopy(yaml.safe_load(INVENTORY.read_text()))
    mutate(raw)
    (tmp_path / "net.yml").write_text(yaml.safe_dump(raw, sort_keys=False))
    return tmp_path / "net.yml"


def problems(tmp_path, mutate) -> str:
    with pytest.raises(InventoryError) as exc:
        load(mutated(tmp_path, mutate))
    return "\n".join(exc.value.problems)


def rules_for(alert):
    return [r for r in monitoring.alert_rules(inv) if r["alert"] == alert]


def test_one_rule_per_object_the_inventory_implies():
    """A BGP rule per session on a router we own, an OSPF and a BFD rule per adjacency, a web rule per check, a
    flap rule per router interface, a SourceSilent rule per source: counted from the inventory, not written down."""
    owned = [r for r in inv.routers if inv.owner(r) == inv.operator]
    sessions = [(r, n["address"]) for r in owned for n in inv.routers[r].get("bgp", {}).get("neighbors", [])]
    adjacencies = [(r, remote.device) for r in owned for _, remote in inv.neighbors(r) if remote.device in inv.ospf_neighbors(r)]
    assert sorted((r["labels"]["node"], r["labels"]["peer"]) for r in rules_for("BGPSessionDown")) == sorted(sessions)
    assert sorted((r["labels"]["node"], r["labels"]["neighbor"]) for r in rules_for("OSPFNeighborDown")) == sorted(adjacencies)
    assert sorted((r["labels"]["node"], r["labels"]["neighbor"]) for r in rules_for("BFDPeerDown")) == sorted(adjacencies)
    assert len(rules_for("WebContentWrong")) == len(inv.monitoring["web"])
    assert sorted((r["labels"]["node"], r["labels"]["device"]) for r in rules_for("InterfaceFlapped")) == \
        sorted((r, ep.interface) for r in owned for ep in inv.interfaces(r))
    assert sorted((r["labels"]["node"], r["labels"]["source"]) for r in rules_for("SourceSilent")) == \
        sorted((s["node"], s["source"]) for s in monitoring.log_sources(inv))
    assert "isp" not in {r["labels"].get("node") for r in monitoring.alert_rules(inv)}, "the carrier's router is not ours to page on"


def test_state_rules_catch_admin_down_and_a_missing_series():
    """BGP is `!= 1` (0 down, 2 administratively down), and every per-object rule fires on absent() too, so a
    session deleted from the config pages like one that is down."""
    for r in rules_for("BGPSessionDown"):
        assert "!= 1) or absent(" in r["expr"], r["expr"]
    for alert in ("OSPFNeighborDown", "BFDPeerDown", "SourceSilent"):
        assert all(") or absent(" in r["expr"] for r in rules_for(alert)), alert


def test_an_alert_keeps_its_identity_while_its_series_comes_and_goes():
    """V-015: FRR deletes a BFD session when OSPF drops the adjacency, then adds it back still down. The
    absent() half and the series half must label the alert the same way, or Prometheus starts its `for`
    again and the page is late. Each per-object rule aggregates to exactly the labels absent() gives, and
    carries its node's owner and role itself, since neither half has the target's labels any more."""
    for r in monitoring.alert_rules(inv):
        if " or absent(" not in r["expr"]:
            continue
        by = re.match(r"max by \(([^)]*)\) \(", r["expr"])
        absent = re.search(r"absent\(\w+\{([^}]*)\}\)$", r["expr"])
        assert by and absent, r["expr"]
        assert by.group(1).split(", ") == re.findall(r'(\w+)="', absent.group(1)), r["expr"]
        node = r["labels"]["node"]
        assert r["labels"]["owner"] == inv.owner(node), r["alert"]
        if node in inv.routers:
            assert r["labels"]["role"] == inv.routers[node]["role"], r["alert"]


def test_flap_rule_uses_the_carrier_counter_on_the_routers_own_interfaces():
    """Each interface's rule reads its own carrier-change counter, and fires once the carrier is back up,
    unless its link was down long enough for LinkDown to have paged already."""
    causes = monitoring.causes(inv)
    for r in rules_for("InterfaceFlapped"):
        node, device = r["labels"]["node"], r["labels"]["device"]
        sel = f'{{node="{node}",device="{device}"}}'
        flap = f"(increase(node_network_carrier_changes_total{sel}[{monitoring.FLAP_WINDOW}s]) > 0 and node_network_carrier{sel} == 1)"
        link = monitoring.link_id(monitoring.link_at(inv, node, device))
        paged = (f' unless on() max_over_time(ALERTS{{alertname="LinkDown",alertstate="firing",cause="{link}"}}'
                 f'[{monitoring.after_link_down(inv)}s])') if link in causes else ""
        assert r["expr"] == flap + paged
    # The flap's counter stays raised FLAP_WINDOW after the carrier is back, and LinkDown's last firing
    # evaluation can be an interval before that.
    assert monitoring.after_link_down(inv) > monitoring.FLAP_WINDOW + inv.monitoring["interval"]


def test_every_scrape_job_has_a_target_down_rule():
    """A router's exporter pages per router; every other job, the NOC's own, pages when any of its targets
    stops answering. A job added to the scrape config gets its rule with no other change."""
    rules = rules_for("TargetDown")
    for job in {j["job_name"] for j in monitoring.prometheus_config(inv)["scrape_configs"]}:
        mine = [r for r in rules if r["labels"]["job"] == job]
        if job in monitoring.EXPORTERS:
            assert sorted(r["labels"]["node"] for r in mine) == sorted(monitoring.exporter_routers(inv)), job
        else:
            assert [r["expr"] for r in mine] == [f'min(up{{job="{job}"}}) == 0'], job


def test_source_silent_bound():
    """syslog's SourceSilent reaches the pager within twice the heartbeat (OROS NOT-3), and a healthy source
    with its heartbeat and two scrapes of jitter never trips it."""
    mon, logs = monitoring.expected(inv), inv.logging
    for s in mon["sources"]:
        if s["source"] == "syslog":
            assert logs["heartbeat"] + 2 * mon["interval"] < s["silent_after"]
            assert s["silent_after"] + mon["alert_within"]["SourceSilent"] <= s["within"] == 2 * logs["heartbeat"]
        else:
            assert s["within"] == s["silent_after"] + mon["alert_within"]["SourceSilent"]


def test_every_address_a_source_can_send_from_names_it():
    addresses = monitoring.source_addresses(inv)
    for d in monitoring.syslog_sources(inv):
        for ep in inv.interfaces(d):
            assert addresses[str(ep.address.ip)] == d
    assert monitoring.host(inv) not in addresses.values(), "the collector doesn't send to itself"


def test_exporters_listen_on_the_routers_loopback_only(tmp_path):
    render_all(inv, tmp_path)
    nodes = yaml.safe_load((tmp_path / "topology.clab.yml").read_text())["topology"]["nodes"]
    for r in monitoring.exporter_routers(inv):
        lo = monitoring.loopback(inv, r)
        for kind, port in (("frr", monitoring.PORTS["frr"]), ("node", monitoring.PORTS["node"])):
            assert f"--web.listen-address={lo}:{port}" in nodes[f"{r}-{kind}-exporter"]["cmd"]
        assert nodes[r]["sysctls"]["net.ipv4.ip_nonlocal_bind"] == 1, f"{r}: the exporter starts before zebra sets the loopback"
    for name, cfg in monitoring.sidecars(inv).items():
        if cfg["netns"] == monitoring.host(inv) and "listen-address" in cfg["cmd"]:
            assert "listen-address=127.0.0.1:" in cfg["cmd"], f"{name} answers beyond noc"


def test_rendered_configs_match_the_inventory(tmp_path):
    render_all(inv, tmp_path)
    noc = tmp_path / monitoring.host(inv)
    prom = yaml.safe_load((noc / "prometheus.yml").read_text())
    assert prom["global"]["scrape_interval"] == f"{inv.monitoring['interval']}s"
    assert {j["job_name"] for j in prom["scrape_configs"]} == {"frr", "node", "web", "icmp", "logs", "pushgateway"}
    assert yaml.safe_load((noc / "rules.yml").read_text()) == monitoring.rule_groups(inv)
    vector = yaml.safe_load((noc / "vector.yaml").read_text())
    remap = vector["transforms"]["syslog_node"]["source"]
    assert json.loads(remap.split("nodes = ", 1)[1].splitlines()[0]) == monitoring.source_addresses(inv)
    am = yaml.safe_load((noc / "alertmanager.yml").read_text())
    assert am["route"]["group_by"] == ["..."] and am["receivers"][0]["webhook_configs"][0]["send_resolved"] is True
    loki = yaml.safe_load((noc / "loki.yaml").read_text())
    assert loki["limits_config"]["retention_period"] == f"{inv.logging['retention']}h"
    agent = (tmp_path / "monitoring" / "agent.sh").read_text()
    assert f"syslogd -R {monitoring.collector(inv)}:514 -L -s {inv.logging['on_box']['size_kb']} -b {inv.logging['on_box']['rotated']}" in agent
    assert f"sleep {inv.logging['heartbeat']}" in agent
    assert (tmp_path / "monitoring" / "kernel.py").read_text() == Path(kernel.__file__).read_text()


def test_app_forwarder_runs_as_nobody_and_reads_the_log_read_only():
    for app in inv.logging["apps"]:
        f = monitoring.sidecars(inv)[f"{app['host']}-{app['name']}-forwarder"]
        assert f["user"] == "65534:65534" and f["netns"] == app["host"]
        assert f"{app['host']}/applog:/applog:ro" in f["binds"]


def test_targets_carry_the_routers_role_for_later_routing():
    """Every target's labels name its node, owner and, for a router, its role (the hook for OROS DEC-1 and DEC-4)."""
    prom = monitoring.prometheus_config(inv)
    for job in prom["scrape_configs"]:
        for sc in job["static_configs"]:
            labels = sc.get("labels")
            if labels:
                assert labels["owner"] == inv.owner(labels["node"])
                if labels["node"] in inv.routers:
                    assert labels["role"] == inv.routers[labels["node"]]["role"]


def test_pending_reboot_textfile():
    """The same rule as `make verify`: a newer installed kernel is a pending reboot, since it was installed."""
    assert "node_reboot_required 0" in kernel.textfile("6.1.0", {})
    assert "node_reboot_required 0" in kernel.textfile("6.1.0", {"6.1.0": 10.0})
    pending = kernel.textfile("6.1.0", {"6.1.0": 10.0, "6.10.0": 200.0})
    assert "node_reboot_required 1" in pending and "node_reboot_required_since_seconds 200" in pending


def test_unpinned_image_is_refused(tmp_path):
    def m(raw):
        raw["monitoring"]["images"]["loki"] = "grafana/loki:latest"
    assert "image loki 'grafana/loki:latest' needs a pinned version tag" in problems(tmp_path, m)


def test_silent_after_past_twice_the_heartbeat_is_refused(tmp_path):
    def m(raw):
        raw["logging"]["silent_after"] = 2 * raw["logging"]["heartbeat"]
    assert "logging: silent_after" in problems(tmp_path, m)


def test_silent_after_inside_the_heartbeat_is_refused(tmp_path):
    def m(raw):
        raw["logging"]["silent_after"] = raw["logging"]["heartbeat"]
    assert "logging: silent_after" in problems(tmp_path, m)


def test_web_check_on_a_port_nobody_listens_on_is_refused(tmp_path):
    def m(raw):
        raw["monitoring"]["web"][0]["port"] = 8080
    assert "web check h2:8080 has no listener in services" in problems(tmp_path, m)


def test_a_heartbeat_between_two_flushes_is_refused(tmp_path):
    """Alertmanager sends only on a flush, so a heartbeat period that is not a whole number of them can't be kept."""
    def m(raw):
        raw["monitoring"]["alert_path"]["every"] = raw["monitoring"]["group_interval"] * 2 + 2
    assert "must be a multiple of group_interval" in problems(tmp_path, m)


def test_monitoring_host_must_be_a_host(tmp_path):
    def m(raw):
        raw["monitoring"]["host"] = "r1"
    assert "monitoring: host 'r1' is not a host" in problems(tmp_path, m)


def test_noc_host_has_a_scope_decision():
    """The central log store holds the CDE's logs, so it is in scope (PCI DSS 10.3.3), not out of it."""
    assert monitoring.host(inv) in inv.raw["scope"]["systems"]
    assert monitoring.host(inv) not in inv.raw["scope"]["out_of_scope"]
