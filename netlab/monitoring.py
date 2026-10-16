"""The NOC's checks, generated from the inventory (decisions 0018 and 0019).

Nothing here is a hand-written expected value: the scrape targets, the alert rules (one per BGP
session, OSPF neighbor, BFD peer, web check, router and log source), the log sources with their
last-seen windows, the collector's map from source address to node, and the sidecars the topology
starts all come from inventory/network.yml. render() writes them into build/noc/ and build/monitoring/.

A later build extends it here: a label in target_labels() reaches every target and so every alert,
a rule appended in alert_rules() goes into rules.yml, a source in log_sources() gets its own
SourceSilent rule, and a sidecar in sidecars() is started by the topology.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

from .inventory import Inventory

ROOT = Path(__file__).resolve().parent.parent
# Where the services listen. Everything in noc's network namespace talks over 127.0.0.1, so from the
# campus only the collector's syslog (UDP 514) and forwarder (TCP 6000) ports answer on noc.
PORTS = {"frr": 9342, "node": 9100, "prometheus": 9090, "alertmanager": 9093, "blackbox": 9115,
         "loki": 3100, "collector_metrics": 9598, "syslog": 514, "forward": 6000, "sink": 9095}
# Each exporter job on a router we own: the image key in the inventory and its port.
EXPORTERS = {"frr": "frr_exporter", "node": "node_exporter"}
# Seconds a rule's condition must hold before it fires (Prometheus `for`). State checks wait two scrapes,
# so one lost scrape isn't a page; a flap, a pending reboot past its window and a silent source are
# already settled facts when their expression turns true.
WAIT = {"TargetDown": 15, "BGPSessionDown": 10, "OSPFNeighborDown": 10, "BFDPeerDown": 10, "WebContentWrong": 10,
        "InterfaceFlapped": 0, "PendingRebootOverdue": 0, "SourceSilent": 0}
# Seconds between each router's rewrites of its pending-reboot file (agent.sh), which node_exporter reads.
TEXTFILE_EVERY = 15
# node_exporter's own default netstat fields, plus TcpExt_IPReversePathFilter: the packets a strict
# reverse-path filter dropped, which tests/live/test_edge.py reads with nstat (monitoring/coverage.yml).
NETSTAT_FIELDS = ("^(.*_(InErrors|InErrs)|Ip_Forwarding|Ip(6|Ext)_(InOctets|OutOctets)|Icmp6?_(InMsgs|OutMsgs)|"
                  "TcpExt_(Listen.*|Syncookies.*|TCPSynRetrans|TCPTimeouts|TCPOFOQueue|IPReversePathFilter)|"
                  "Tcp_(ActiveOpens|InSegs|OutSegs|OutRsts|PassiveOpens|RetransSegs|CurrEstab)|"
                  "Udp6?_(InDatagrams|OutDatagrams|NoPorts|RcvbufErrors|SndbufErrors))")
# (No closing $: Containerlab expands $ in a topology file as an environment variable.)


def owned(inv: Inventory, device: str) -> bool:
    return inv.owner(device) == inv.operator


def host(inv: Inventory) -> str:
    return inv.monitoring["host"]


def collector(inv: Inventory) -> str:
    """The NOC's address, where every source sends its logs."""
    return inv.hosts[host(inv)]["address"].split("/")[0]


def loopback(inv: Inventory, router: str) -> str:
    return str(ipaddress.IPv4Interface(inv.routers[router]["loopback"]).ip)


def exporter_routers(inv: Inventory) -> list[str]:
    """Routers we own: each gets frr_exporter and node_exporter. The carrier's isp is watched from our side."""
    return [r for r in inv.routers if owned(inv, r)]


def syslog_sources(inv: Inventory) -> list[str]:
    """Every router, firewall and server (a host with services) we own, except the collector itself."""
    hosts = [h for h, v in inv.hosts.items() if v.get("services")]
    return [d for d in [*inv.routers, *inv.firewalls, *hosts] if owned(inv, d) and d != host(inv)]


def log_sources(inv: Inventory) -> list[dict]:
    """[{node, source, silent_after, within}]: syslog from each node above, and each app's own log. `within`
    is the stated bound on SourceSilent reaching the pager after the source's last line arrived: twice the
    heartbeat for syslog (OROS NOT-3's default, which the inventory check holds silent_after to). An app's
    normal gap is the NOC's own web check, one interval, too short to page on twice over without paging on
    one late scrape, so its bound is stated: its silent_after plus the time to evaluate and deliver."""
    detect = 3 * inv.monitoring["interval"] + 2
    syslog = [{"node": d, "source": "syslog", "silent_after": inv.logging["silent_after"], "within": 2 * inv.logging["heartbeat"]}
              for d in syslog_sources(inv)]
    apps = [{"node": a["host"], "source": a["name"], "silent_after": a["silent_after"], "within": a["silent_after"] + detect}
            for a in inv.logging.get("apps", [])]
    return syslog + apps


def source_addresses(inv: Inventory) -> dict[str, str]:
    """{address: node} for every address of each syslog source. busybox syslogd sends no hostname, so the
    collector names a line by its source address, and a router's follows its egress interface (r1 sends
    from 10.0.13.0 instead of 10.0.12.0 while the r1-r2 link is down)."""
    out = {}
    for d in syslog_sources(inv):
        for ep in inv.interfaces(d):
            out[str(ep.address.ip)] = d
        if d in inv.routers:
            out[loopback(inv, d)] = d
    return dict(sorted(out.items()))


def probe_address(inv: Inventory, device: str) -> str:
    """Where the NOC pings a device: a router's loopback, a host's address, and a firewall's inside
    address, because its outside /30 is not routed in the campus (only the LAN behind it is)."""
    if device in inv.routers:
        return loopback(inv, device)
    if device in inv.firewalls:
        return inv.firewalls[device]["inside"]["address"].split("/")[0]
    return inv.hosts[device]["address"].split("/")[0]


def target_labels(inv: Inventory, device: str) -> dict:
    """Labels every target, and so every alert about it, carries. A router's role comes along, so a
    later build can route or silence by role (OROS DEC-1)."""
    labels = {"node": device, "owner": inv.owner(device)}
    if device in inv.routers:
        labels["role"] = inv.routers[device]["role"]
    return labels


def bgp_peers(inv: Inventory) -> list[dict]:
    """Each BGP session on a router we own: the router, the peer's name and address."""
    return [{"node": r, "peer": n["peer"], "address": n["address"]}
            for r in exporter_routers(inv) for n in inv.routers[r].get("bgp", {}).get("neighbors", [])]


def ospf_neighbors(inv: Inventory) -> list[dict]:
    """Each OSPF adjacency the inventory implies on a router we own, by the local interface it forms on."""
    return [{"node": r, "neighbor": remote.device, "interface": local.interface}
            for r in exporter_routers(inv) for local, remote in inv.neighbors(r)
            if remote.device in inv.ospf_neighbors(r)]


def bfd_peers(inv: Inventory) -> list[dict]:
    """BFD runs on every OSPF link (frr.conf.j2), so there is one peer per adjacency, by its address."""
    return [{"node": r, "neighbor": remote.device, "address": str(remote.address.ip)}
            for r in exporter_routers(inv) for local, remote in inv.neighbors(r)
            if remote.device in inv.ospf_neighbors(r)]


def probe_targets(inv: Inventory) -> list[dict]:
    """What the NOC pings: every log source, and each BGP peer (whether the carrier's side of the hand-off
    answers the campus; its route back is the aggregate it learns from us)."""
    peers = [{"device": inv.device_at(p["address"]), "address": p["address"]} for p in bgp_peers(inv)]
    return [{"device": d, "address": probe_address(inv, d)} for d in syslog_sources(inv)] + peers


def selector(**labels) -> str:
    return "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}"


def rule(alert: str, expr: str, labels: dict, summary: str) -> dict:
    # Rule labels name the object, so each object is its own alert. `summary` is the only annotation for
    # now; a later build adds why_fired, baseline and changes here (OROS DEC-1).
    return {"alert": alert, "expr": expr, "for": f"{WAIT[alert]}s", "labels": labels, "annotations": {"summary": summary}}


def per_object(metric: str, keys: dict, test: str) -> str:
    """The object's series failing `test`, or missing. Both halves come out labelled with the object's own
    keys only, so the alert keeps one identity while its series comes and goes: FRR deletes a BFD session
    when OSPF drops the adjacency and adds it back still down, and an alert whose labels changed with that
    would start its `for` again (V-015)."""
    sel = selector(**keys)
    return f"max by ({', '.join(keys)}) ({metric}{sel} {test}) or absent({metric}{sel})"


def alert_rules(inv: Inventory) -> list[dict]:
    """One rule per object the inventory says should be up. Each also fires if its series is missing
    (absent), so a session or neighbor deleted from the config alerts too, not just one that is down.
    Each carries its node's owner and role as rule labels, so every alert about it has them, from either
    half of the rule (the hook for routing and silencing by role later, OROS DEC-1 and DEC-4)."""
    mon, rules = inv.monitoring, []
    rules.append(rule("TargetDown", "up == 0", {}, "{{ $labels.job }} on {{ $labels.node }} does not answer its scrape"))
    for s in bgp_peers(inv):
        # frr_exporter: 1 Established, 0 down, 2 administratively down. `== 0` would miss a local shutdown.
        rules.append(rule("BGPSessionDown", per_object("frr_bgp_peer_state", {"node": s["node"], "peer": s["address"]}, "!= 1"),
                          {**target_labels(inv, s["node"]), "peer": s["address"], "peer_name": s["peer"]},
                          f"BGP {s['node']} -> {s['peer']} ({s['address']}) is not Established: {{{{ $value }}}} (0 down, 2 admin down)"))
    for n in ospf_neighbors(inv):
        # Adjacencies (Full), not neighbors: a neighbor stuck in ExStart still counts as a neighbor.
        # The series' own iface label names the interface; the rule adds the neighbor's name.
        rules.append(rule("OSPFNeighborDown", per_object("frr_ospf_neighbor_adjacencies", {"node": n["node"], "iface": n["interface"]}, "< 1"),
                          {**target_labels(inv, n["node"]), "neighbor": n["neighbor"]},
                          f"OSPF {n['node']} has no Full adjacency with {n['neighbor']} on {n['interface']}"))
    for b in bfd_peers(inv):
        rules.append(rule("BFDPeerDown", per_object("frr_bfd_peer_state", {"node": b["node"], "peer": b["address"]}, "!= 1"),
                          {**target_labels(inv, b["node"]), "neighbor": b["neighbor"], "peer": b["address"]},
                          f"BFD {b['node']} -> {b['neighbor']} ({b['address']}) is not up"))
    for w in mon.get("web") or []:
        rules.append(rule("WebContentWrong", f"probe_success{selector(job='web', node=w['host'])} == 0",
                          {**target_labels(inv, w["host"]), "port": str(w["port"])},
                          f"{w['host']}:{w['port']} does not return a page matching {w['expect']}"))
    for r in exporter_routers(inv):
        # The carrier-change counter catches a flap shorter than a scrape, which a state poll misses.
        devices = "|".join(sorted(ep.interface for ep in inv.interfaces(r)))
        rules.append(rule("InterfaceFlapped",
                          f'increase(node_network_carrier_changes_total{{node="{r}",device=~"{devices}"}}[1m]) > 0',
                          target_labels(inv, r), f"{r} {{{{ $labels.device }}}} lost carrier in the last minute"))
    window = mon["reboot_window"]
    rules.append(rule("PendingRebootOverdue",
                      f"node_reboot_required == 1 and on(node) (time() - node_reboot_required_since_seconds > {window})",
                      {}, f"{{{{ $labels.node }}}} has run an older kernel than it has installed for over {window} s"))
    for s in log_sources(inv):
        sel = selector(node=s["node"], source=s["source"])
        rules.append(rule("SourceSilent", f"max by (node, source) (time() - log_last_seen_seconds{sel} > {s['silent_after']}) "
                                          f"or absent(log_last_seen_seconds{sel})",
                          {**target_labels(inv, s["node"]), "source": s["source"]},
                          f"no {s['source']} line from {s['node']} has reached the collector for over {s['silent_after']} s"))
    return rules


def blackbox_job(name: str, module: str, targets: list[dict]) -> dict:
    """A blackbox_exporter job: Prometheus asks the exporter to probe each target, the usual relabelling."""
    return {"job_name": name, "metrics_path": "/probe", "params": {"module": [module]},
            "static_configs": targets,
            "relabel_configs": [{"source_labels": ["__address__"], "target_label": "__param_target"},
                                {"source_labels": ["__param_target"], "target_label": "instance"},
                                {"target_label": "__address__", "replacement": f"127.0.0.1:{PORTS['blackbox']}"}]}


def web_module(check: dict) -> str:
    return f"web_{check['host']}_{check['port']}"


def prometheus_config(inv: Inventory) -> dict:
    interval = f"{inv.monitoring['interval']}s"
    jobs = [{"job_name": job, "static_configs": [{"targets": [f"{loopback(inv, r)}:{PORTS[job]}"], "labels": target_labels(inv, r)}
                                                for r in exporter_routers(inv)]} for job in EXPORTERS]
    web = [blackbox_job("web", web_module(w), [{"targets": [f"http://{probe_address(inv, w['host'])}:{w['port']}/"],
                                                "labels": target_labels(inv, w["host"])}])
           for w in inv.monitoring.get("web") or []]
    icmp = blackbox_job("icmp", "icmp", [{"targets": [t["address"]], "labels": target_labels(inv, t["device"])}
                                         for t in probe_targets(inv)])
    # The collector's own per-source metrics (log_last_seen_seconds{node,source}).
    logs = {"job_name": "logs", "static_configs": [{"targets": [f"127.0.0.1:{PORTS['collector_metrics']}"]}]}
    return {
        "global": {"scrape_interval": interval, "evaluation_interval": interval, "scrape_timeout": f"{inv.monitoring['interval'] - 1}s"},
        "rule_files": ["/etc/prometheus/rules.yml"],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [f"127.0.0.1:{PORTS['alertmanager']}"]}]}]},
        "scrape_configs": [*jobs, *web, icmp, logs],
    }


def blackbox_config(inv: Inventory) -> dict:
    modules = {"icmp": {"prober": "icmp", "timeout": "2s", "icmp": {"preferred_ip_protocol": "ip4"}}}
    for w in inv.monitoring.get("web") or []:
        modules[web_module(w)] = {"prober": "http", "timeout": "3s", "http": {
            "preferred_ip_protocol": "ip4", "valid_status_codes": [200],
            "fail_if_body_not_matches_regexp": [w["expect"]]}}
    return {"modules": modules}


def sidecars(inv: Inventory) -> dict[str, dict]:
    """Containers that share another node's network namespace (containerlab network-mode container:<node>).
    They change nothing the network does, so the lab job deploys without them (`make deploy-network`)."""
    if not inv.monitoring:
        return {}
    images, noc, out = inv.monitoring["images"], host(inv), {}
    for r in exporter_routers(inv):
        lo = loopback(inv, r)
        out[f"{r}-frr-exporter"] = {"netns": r, "image": images["frr_exporter"], "binds": [f"{r}/run:/var/run/frr:ro"],
                                    "cmd": f"--web.listen-address={lo}:{PORTS['frr']} --frr.socket.dir-path=/var/run/frr"}
        out[f"{r}-node-exporter"] = {"netns": r, "image": images["node_exporter"], "binds": [f"{r}/textfile:/textfile:ro"],
                                     "cmd": f"--web.listen-address={lo}:{PORTS['node']} --collector.disable-defaults "
                                            "--collector.netclass --collector.netdev --collector.netstat "
                                            f"--collector.netstat.fields={NETSTAT_FIELDS} "
                                            "--collector.textfile --collector.textfile.directory=/textfile"}
    out[f"{noc}-prometheus"] = {"netns": noc, "image": images["prometheus"],
                                "binds": [f"{noc}/prometheus.yml:/etc/prometheus/prometheus.yml:ro", f"{noc}/rules.yml:/etc/prometheus/rules.yml:ro"],
                                "cmd": f"--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus "
                                       f"--web.listen-address=127.0.0.1:{PORTS['prometheus']}"}
    # An empty cluster address turns off the gossip port Alertmanager would otherwise open on every address.
    out[f"{noc}-alertmanager"] = {"netns": noc, "image": images["alertmanager"],
                                  "binds": [f"{noc}/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro"],
                                  "cmd": f"--config.file=/etc/alertmanager/alertmanager.yml --storage.path=/alertmanager "
                                         f"--web.listen-address=127.0.0.1:{PORTS['alertmanager']} --cluster.listen-address="}
    out[f"{noc}-blackbox"] = {"netns": noc, "image": images["blackbox"], "binds": [f"{noc}/blackbox.yml:/etc/blackbox/blackbox.yml:ro"],
                              "cmd": f"--config.file=/etc/blackbox/blackbox.yml --web.listen-address=127.0.0.1:{PORTS['blackbox']}"}
    out[f"{noc}-loki"] = {"netns": noc, "image": images["loki"], "binds": [f"{noc}/loki.yaml:/etc/loki/loki.yaml:ro"],
                          "cmd": "-config.file=/etc/loki/loki.yaml"}
    out[f"{noc}-collector"] = {"netns": noc, "image": images["vector"], "binds": [f"{noc}/vector.yaml:/etc/vector/vector.yaml:ro"],
                               "cmd": "--config /etc/vector/vector.yaml"}
    for app in inv.logging.get("apps") or []:
        # Not root: the image's default user is, so the node sets nobody's uid and gid.
        out[f"{app['host']}-{app['name']}-forwarder"] = {
            "netns": app["host"], "image": images["vector"], "user": "65534:65534",
            "binds": [f"{app['host']}/applog:/applog:ro", f"{app['host']}/forwarder.yaml:/etc/vector/vector.yaml:ro"],
            "cmd": "--config /etc/vector/vector.yaml"}
    return out


def expected(inv: Inventory) -> dict:
    """What the live tests read back: exporters, sources, checks and the alerts the rules can raise."""
    if not inv.monitoring:
        return {}
    return {
        "host": host(inv),
        "collector": collector(inv),
        "interval": inv.monitoring["interval"],
        "exporters": {r: {"address": loopback(inv, r), "ports": [PORTS[j] for j in EXPORTERS]} for r in exporter_routers(inv)},
        "bgp_peers": bgp_peers(inv),
        "ospf_neighbors": ospf_neighbors(inv),
        "bfd_peers": bfd_peers(inv),
        "web": inv.monitoring.get("web") or [],
        "reboot_window": inv.monitoring["reboot_window"],
        "sources": log_sources(inv),
        "heartbeat": inv.logging["heartbeat"],
        "on_box": inv.logging["on_box"],
        "apps": inv.logging.get("apps") or [],
        "sidecars": sorted(sidecars(inv)),
        # Each sidecar image's tag and the digest it must resolve to.
        "digests": {inv.monitoring["images"][k]: inv.monitoring["digests"][k] for k in inv.monitoring["images"]},
        "alerts": sorted({r["alert"] for r in alert_rules(inv)}),
        # How long after the object changes its alert may take to reach the pager: up to one scrape and one
        # evaluation to see it, `for` to hold, one more evaluation, and Alertmanager's group_wait (1 s).
        # The pending-reboot file is rewritten every TEXTFILE_EVERY seconds on top of that.
        "alert_within": {a: w + 3 * inv.monitoring["interval"] + 2 + (TEXTFILE_EVERY if a == "PendingRebootOverdue" else 0)
                         for a, w in WAIT.items()},
    }


def dump(doc: dict) -> str:
    return "# Generated by netlab from inventory/network.yml (netlab/monitoring.py). Do not edit by hand.\n" + \
        yaml.safe_dump(doc, sort_keys=False, width=200)


def render(inv: Inventory, env, write, out: Path) -> None:
    """Every config the NOC and the watched nodes need, into build/."""
    if not inv.monitoring:
        return
    noc, logs = host(inv), inv.logging
    write(f"{noc}/prometheus.yml", dump(prometheus_config(inv)))
    write(f"{noc}/rules.yml", dump({"groups": [{"name": "netlab", "rules": alert_rules(inv)}]}))
    write(f"{noc}/blackbox.yml", dump(blackbox_config(inv)))
    ctx = dict(inv=inv, ports=PORTS, collector=collector(inv), logs=logs, addresses=source_addresses(inv),
               textfile_every=TEXTFILE_EVERY)
    for name in ("alertmanager.yml", "loki.yaml", "vector.yaml"):
        write(f"{noc}/{name}", env.get_template(f"monitoring/{name}.j2").render(**ctx))
    write(f"{noc}/sink.py", (ROOT / "templates" / "monitoring" / "sink.py").read_text())
    write("monitoring/agent.sh", env.get_template("monitoring/agent.sh.j2").render(**ctx))
    # The same kernel rule `make verify` uses, run on each router for its pending-reboot metric.
    write("monitoring/kernel.py", (ROOT / "netlab" / "kernel.py").read_text())
    for app in logs.get("apps") or []:
        write(f"{app['host']}/forwarder.yaml", env.get_template("monitoring/forwarder.yaml.j2").render(app=app, **ctx))
    # Folders the nodes share with their sidecars. Created here because Containerlab refuses a bind whose
    # source is missing; never emptied here, because a running router's sockets live in its run/.
    for r in exporter_routers(inv):
        for d in ("run", "textfile"):
            (out / r / d).mkdir(parents=True, exist_ok=True)
    for app in logs.get("apps") or []:
        (out / app["host"] / "applog").mkdir(parents=True, exist_ok=True)
