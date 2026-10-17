"""The NOC's checks, generated from the inventory (decisions 0018 to 0023, 0025, 0026, 0029 and 0031).

Nothing here is a hand-written expected value: the scrape targets, the alert rules (one per BGP
session, OSPF neighbor, BFD peer, web check, router interface, log source and unattended job), the log
sources with their last-seen windows, the collector's map from source address to node, what each alert
depends on, and the sidecars the topology starts all come from inventory/network.yml. render() writes
them into build/noc/ and build/monitoring/.

A later build extends it here: a label in target_labels() reaches every target and so every alert,
a rule appended in alert_rules() goes into rules.yml, a source in log_sources() gets its own
SourceSilent rule, and a sidecar in sidecars() is started by the topology.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from pathlib import Path

import yaml

from . import access, nat
from .inventory import Inventory

ROOT = Path(__file__).resolve().parent.parent
# Where the services listen. Everything in noc's network namespace talks over 127.0.0.1, so from the
# campus only the collector's syslog (UDP 514) and forwarder (TCP 6000) ports answer on noc.
PORTS = {"frr": 9342, "node": 9100, "prometheus": 9090, "alertmanager": 9093, "blackbox": 9115,
         "loki": 3100, "collector_metrics": 9598, "syslog": 514, "forward": 6000, "sink": 9095,
         "pushgateway": 9091, "smtp": 1025, "mailbox": 8025, "mail_hook": 9596, "dns": 53}
# Each exporter job on a router we own: the image key in the inventory and its port.
EXPORTERS = {"frr": "frr_exporter", "node": "node_exporter"}
# Seconds a rule's condition must hold before it fires (Prometheus `for`). State checks wait two scrapes,
# so one lost scrape isn't a page; a flap, a pending reboot past its window and a silent source are
# already settled facts when their expression turns true.
# A cause's page (NodeDown, LinkDown) waits like a state check; its marker (CauseSeen) fires at once, because
# it only has to be in Alertmanager before what depends on it (decision 0021). A missed job and a silent alert
# path are settled facts too, and Watchdog always fires.
WAIT = {"TargetDown": 15, "BGPSessionDown": 10, "OSPFNeighborDown": 10, "BFDPeerDown": 10, "WebContentWrong": 10,
        "InterfaceFlapped": 0, "PendingRebootOverdue": 0, "SourceSilent": 0, "QueueDrops": 0, "LogIngestOverBudget": 0,
        "NodeDown": 10, "LinkDown": 10, "CauseSeen": 0, "JobMissed": 0, "AlertPathSilent": 0, "Watchdog": 0,
        "UnexpectedAdmin": 0}
# Seconds InterfaceFlapped looks back over the carrier-change counter: six scrapes.
FLAP_WINDOW = 30
# Seconds Prometheus waits before it sends a firing alert to Alertmanager again (its --rules.alert.resend-delay,
# left at the default). An alert sent before Alertmanager answers, at the NOC's start, is dropped and arrives
# this much later.
RESEND_DELAY = 60
# Seconds between evaluations of the cause markers (their own rule group), so a cause reaches Alertmanager
# well inside group_wait of what depends on it.
CAUSE_EVERY = 1
# Seconds UnexpectedAdmin stays firing after the account's last accounting line arrived. A login is an event,
# not a state: the page goes out once, and the alert resolves when that account has been quiet this long.
ADMIN_WINDOW = 60
# Seconds between each router's rewrites of its pending-reboot file (agent.sh), which node_exporter reads.
TEXTFILE_EVERY = 15
# The flight recorder on every log source (agent.sh, decision 0025): seconds between two triggered dumps at
# most, seconds it waits before sending one, and the longest line it sends.
FLIGHTREC = {"every": 30, "delay": 3, "width": 200}
# node_exporter's own default netstat fields, plus TcpExt_IPReversePathFilter: the packets a strict
# reverse-path filter dropped, which tests/live/test_edge.py reads with nstat, and the three TCP MD5
# counters the BGP-down runbook reads to tell a wrong password from a missing one (monitoring/coverage.yml).
NETSTAT_FIELDS = ("^(.*_(InErrors|InErrs)|Ip_Forwarding|Ip(6|Ext)_(InOctets|OutOctets)|Icmp6?_(InMsgs|OutMsgs)|"
                  "TcpExt_(Listen.*|Syncookies.*|TCPSynRetrans|TCPTimeouts|TCPOFOQueue|IPReversePathFilter|"
                  "TCPMD5Failure|TCPMD5NotFound|TCPMD5Unexpected)|"
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


def servers(inv: Inventory) -> list[str]:
    """Hosts with services we own, except the NOC: each gets a node_exporter for its own interfaces and
    queues (decision 0023). h2's HTB is where a burst into LAN-B's server is queued and dropped."""
    return [h for h, v in inv.hosts.items() if v.get("services") and owned(inv, h) and h != host(inv)]


def exporter_nodes(inv: Inventory) -> list[str]:
    """Every node with a node_exporter: the routers we own and the servers."""
    return [*exporter_routers(inv), *servers(inv)]


def node_exporter_address(inv: Inventory, device: str) -> str:
    """Where a node's node_exporter listens: a router's loopback, a server's own address."""
    return loopback(inv, device) if device in inv.routers else probe_address(inv, device)


def listeners(inv: Inventory, device: str) -> dict[int, str]:
    """{tcp port: sidecar} the NOC's sidecars open toward the network in a host's namespace, so `make audit`
    expects them beside the host's own services: a server's node_exporter, and on the NOC the forwarders'
    input and the DNS. Everything else on the NOC listens on 127.0.0.1 only."""
    if not inv.monitoring:
        return {}
    out = {}
    if device in servers(inv):
        out[PORTS["node"]] = f"{device}-node-exporter"
    if device == host(inv):
        out[PORTS["forward"]] = f"{device}-collector"
        if inv.raw.get("dns"):
            out[PORTS["dns"]] = f"{device}-dns"
    return out


def syslog_sources(inv: Inventory) -> list[str]:
    """Every router, firewall and server (a host with services) we own, except the collector itself."""
    hosts = [h for h, v in inv.hosts.items() if v.get("services")]
    return [d for d in [*inv.routers, *inv.firewalls, *hosts] if owned(inv, d) and d != host(inv)]


def log_sources(inv: Inventory) -> list[dict]:
    """[{node, source, silent_after, within, budget}]: syslog from each node above, each app's own log, and each
    NAT router's translation log.
    `within` is the stated bound on SourceSilent reaching the pager after the source's last line arrived:
    twice the heartbeat for syslog (OROS NOT-3's default, which the inventory check holds silent_after to).
    An app's is its silent_after plus the time to evaluate and deliver. `budget` is the bytes a day the
    source may send the store (OROS NOT-5, decision 0026)."""
    detect = deliver(inv)
    budget = inv.logging.get("budget") or {}
    syslog = [{"node": d, "source": "syslog", "silent_after": inv.logging["silent_after"], "within": 2 * inv.logging["heartbeat"],
               "budget": budget.get("syslog_kb", 0) * 1024}
              for d in syslog_sources(inv)]
    apps = [{"node": a["host"], "source": a["name"], "silent_after": a["silent_after"], "within": a["silent_after"] + detect,
             "budget": a.get("budget_kb", 0) * 1024}
            for a in inv.logging.get("apps", [])]
    # A NAT router's translation log has a heartbeat of its own, so it counts as syslog does (decision 0031).
    translations = [{"node": r, "source": nat.SOURCE, "silent_after": inv.logging["silent_after"], "within": 2 * inv.logging["heartbeat"],
                     "budget": budget.get("nat_kb", 0) * 1024}
                    for r in nat_logs(inv)]
    return syslog + apps + translations


def ingest_sources(inv: Inventory) -> list[dict]:
    """[{node, source, budget}]: every source whose lines reach the store, each with its daily budget (OROS
    NOT-5): the log sources above, and each router's command records (decision 0029), which have no heartbeat
    and so no SourceSilent, but whose lines the store keeps like any other."""
    budget = inv.logging.get("budget") or {}
    records = [{"node": r, "source": access.SOURCE, "budget": budget.get("accounting_kb", 0) * 1024}
               for r in senders(inv)[access.RECORD_PORT]["nodes"]]
    return [{k: s[k] for k in ("node", "source", "budget")} for s in log_sources(inv)] + records


def nat_logs(inv: Inventory) -> list[str]:
    """Routers we own that translate, each with a translation log at the NOC."""
    return [r for r in nat.routers(inv) if owned(inv, r)] if inv.monitoring else []


def senders(inv: Inventory) -> dict[int, dict]:
    """{source port: {source, nodes}}: the sources the collector takes only from that port of those nodes, where
    only root can send from it (decisions 0029 and 0031). Anything else from those nodes is syslog."""
    return {access.RECORD_PORT: {"source": access.SOURCE, "nodes": [r for r in access.routers(inv) if r in syslog_sources(inv)]},
            nat.RECORD_PORT: {"source": nat.SOURCE, "nodes": nat_logs(inv)}}


def deliver(inv: Inventory) -> int:
    """Seconds from a rule's condition holding (after its `for`) to the page: up to one scrape and one
    evaluation to see it, one more evaluation, Alertmanager's group_wait, and a second for the webhook."""
    return 3 * inv.monitoring["interval"] + inv.monitoring["group_wait"] + 1


# Kinds of line an app's own forwarder may cut before they leave the host (inventory logging.apps[].cut).
CUT_KINDS = {"web-check": "the NOC's web check's request line, from the NOC's address, answered with a status the check accepts"}


def literal(text: str) -> str:
    """text as a regex that matches only itself, for Vector's (Rust) regex: Python's re.escape also escapes
    spaces, which Rust's regex refuses."""
    return re.sub(r"([.\[\](){}*+?^$|\\])", r"\\\1", text)


def cuts(inv: Inventory, app: dict) -> list[dict]:
    """[{name, client, request, status, pattern}] for each kind the app's forwarder cuts. web-check is each
    web check on the app's host and port: the request line of the URL its scrape job has blackbox get, from
    the NOC's address, answered with a status its blackbox module accepts (200). The pattern is anchored on
    all three, so the same request from a user, another page, or one answered with another status still goes
    through. A check that fails on content still answers 200, so it is cut too (RISK-55). It matches the
    access-log line Python's http.server writes: `10.30.30.10 - - [16/Oct/2026 04:35:43] "GET / HTTP/1.1" 200 -`."""
    out = []
    for name in app.get("cut") or []:
        for w in inv.monitoring.get("web") or []:
            if name == "web-check" and (w["host"], w["port"]) == (app["host"], app["port"]):
                job = next(j for j in prometheus_config(inv)["scrape_configs"] if j.get("params", {}).get("module") == [web_module(w)])
                path = urllib.parse.urlsplit(job["static_configs"][0]["targets"][0]).path or "/"
                codes = blackbox_config(inv)["modules"][web_module(w)]["http"]["valid_status_codes"]
                client, request, status = collector(inv), f"GET {path} HTTP/1.1", "|".join(str(c) for c in codes)
                pattern = f'^{literal(client)} - - \\[[^\\]]*\\] "{literal(request)}" ({status}) '
                out.append({"name": name, "client": client, "request": request, "status": status, "pattern": pattern})
    return out


def source_addresses(inv: Inventory) -> dict[str, str]:
    """{address: node} for every address of each syslog source. busybox syslogd sends no hostname, so the
    collector names a line by its source address, and a router's follows its egress interface (r1 sends
    from 10.0.13.0 instead of 10.0.12.0 while the r1-r2 link is down)."""
    out = {}
    for d in syslog_sources(inv):
        for ep in inv.interfaces(d):
            if ep.address:
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


# --- What each alert depends on (OROS DEC-5, decision 0021) -------------------------------------------------

def link_id(link) -> str:
    return f"{link.a.device}:{link.a.interface}-{link.b.device}:{link.b.interface}"


def link_at(inv: Inventory, device: str, interface: str):
    return next(l for l in inv.links if (device, interface) in ((l.a.device, l.a.interface), (l.b.device, l.b.interface)))


def graph(inv: Inventory) -> dict[str, set[str]]:
    """Devices and links as one graph. Each link is a vertex of its own between its two ends, so a link can
    be what everything behind it depends on, the way a router can."""
    adj = {d: set() for d in inv.devices}
    for link in inv.links:
        adj[link_id(link)] = {link.a.device, link.b.device}
        for ep in (link.a, link.b):
            adj[ep.device].add(link_id(link))
    return adj


def dominators(inv: Inventory) -> dict[str, set[str]]:
    """{vertex: every device and link the NOC can't reach it without}. Each vertex is taken out in turn and
    whatever the NOC then no longer reaches depends on it: one breadth-first search per vertex, a fraction
    of a second for hundreds of nodes, and nothing to keep up by hand when a node or link is added."""
    adj, root = graph(inv), host(inv)

    def reach(without):
        seen, todo = {root}, [root]
        while todo:
            for n in adj[todo.pop()]:
                if n != without and n not in seen:
                    seen.add(n)
                    todo.append(n)
        return seen
    everything, dom = reach(None), {v: set() for v in adj}
    for u in adj:
        if u != root:
            for v in everything - reach(u) - {u}:
                dom[v].add(u)
    return dom


def causes(inv: Inventory, dom: dict | None = None) -> dict[str, dict]:
    """Every failure the NOC can see for itself, each of which pages once and holds back what depends on it:
    - each device it pings (each log source): it stops answering;
    - each link with an end whose node_exporter the NOC still reaches without that link: an end's
      operstate is not up (the NOC's own uplink has no such end, so its failure pages as its first hop);
    - each collector other alerts are read through, whose rules fire on absent() when it stops answering:
      frr_exporter on each router, and the log collector.
    {id: {signal, expr, condition, normal, labels, summary}}."""
    dom = dom if dom is not None else dominators(inv)
    out = {}
    for d in syslog_sources(inv):
        signal = f"probe_success{selector(job='icmp', node=d)}"
        out[d] = {"signal": signal, "expr": f"{signal} == 0", "condition": "== 0", "normal": "1 (answers ping)",
                  "labels": target_labels(inv, d), "summary": f"{d} does not answer the NOC's ping"}
    routers = exporter_routers(inv)
    for link in inv.links:
        ends = [ep for ep in (link.a, link.b) if ep.device in routers and link_id(link) not in dom[ep.device]]
        if ends:
            signal = " or ".join(f"node_network_up{selector(node=ep.device, device=ep.interface)}" for ep in ends)
            out[link_id(link)] = {"signal": signal, "expr": f"min({signal}) == 0", "condition": "== 0 on either end",
                                  "normal": "1 on every end", "labels": {**target_labels(inv, ends[0].device), "link": link_id(link)},
                                  "summary": f"link {link_id(link)} is down"}
    for r in routers:
        signal = f"up{selector(job='frr', node=r)}"
        out[f"frr@{r}"] = {"signal": signal, "expr": f"{signal} == 0", "condition": "== 0", "normal": "1",
                           "labels": {**target_labels(inv, r), "job": "frr"}, "summary": f"frr_exporter on {r} does not answer its scrape"}
    signal = "up{job=\"logs\"}"
    out[f"logs@{host(inv)}"] = {"signal": signal, "expr": f"{signal} == 0", "condition": "== 0", "normal": "1",
                                "labels": {"job": "logs"}, "summary": "the log collector does not answer its scrape"}
    return out


class Dependencies:
    """The deps label each alert carries: every cause its objects can't be seen without, themselves included,
    written /a/b/c/ so one regex finds any one of them. Alertmanager holds back an alert while a cause in its
    deps fires (one inhibit rule per cause, templates/monitoring/alertmanager.yml.j2)."""

    def __init__(self, inv: Inventory):
        self.inv, self.dom = inv, dominators(inv)
        self.causes = causes(inv, self.dom)

    def link_objects(self, link) -> set[str]:
        """A link, and each of its ends that doesn't depend on it. An end behind the link (h2 behind r3's
        eth3) is lost because the link is: its own failure is the link's consequence, not a cause of it."""
        lid = link_id(link)
        return {lid} | {ep.device for ep in (link.a, link.b) if lid not in self.dom[ep.device]}

    def label(self, objects, own: str | None = None, extra=()) -> str:
        """A cause's own page leaves itself out, and so everything it covers is held back by something else
        first: two causes never hold each other's page back (tests/test_monitoring.py checks)."""
        found = {c for x in objects for c in ({x} | self.dom[x]) if c in self.causes} | set(extra)
        found.discard(own)
        return "/" + "".join(f"{c}/" for c in sorted(found))


# --- Every alert says why it fired, what is normal and what changed (OROS DEC-1, decision 0020) -----------

# Pushed by `make apply` after a router's change passes its gate (ansible/deploy.yml): the commit applied.
APPLIED = "netlab_config_applied_timestamp_seconds"


def graph_link(expr: str) -> str:
    """This expression over the last 7 days on the NOC's Prometheus (its --web.external-url)."""
    return "{{ $externalURL }}/graph?" + urllib.parse.urlencode({"g0.expr": expr, "g0.tab": "0", "g0.range_input": "7d"})


def context(inv: Inventory, signal: str, condition: str, normal: str, node: str | None) -> dict:
    """Three annotations, which Prometheus fills in each time it evaluates the alert: the rule's condition and
    the signal's value now, the value it normally has with a link to its last 7 days, and the last config
    commit applied to the node (to any router, for a node `make apply` doesn't change) with a link to every
    apply in 7 days."""
    now = "{{ with query `" + signal + "` }}{{ range . }}{{ .Value }} {{ end }}{{ else }}no series{{ end }}"
    sel = selector(node=node) if node in inv.routers else ""
    scope = f"to {node}" if sel else "to the lab's routers"
    # A time, not an age: Prometheus resends a firing alert's annotations only once a minute.
    last = ("{{ with query `topk(1, " + APPLIED + sel + ")` }}{{ range . }}commit {{ .Labels.commit }} "
            "({{ .Labels.subject }}) applied to {{ .Labels.node }} at {{ .Value | humanizeTimestamp }}{{ end }}"
            "{{ else }}no config apply recorded " + scope + "{{ end }}")
    return {"why_fired": f"{signal} {condition}; now: {now}",
            "baseline": f"normally {normal}; this signal over the last 7 days: {graph_link(signal)}",
            "changes": f"last config change {scope}: {last}; every apply in the last 7 days: {graph_link(APPLIED + sel)}"}


def rule(inv: Inventory, alert: str, expr: str, labels: dict, summary: str, signal: str, condition: str,
         normal: str, keep: int | None = None) -> dict:
    """Rule labels name the object, so each object is its own alert, and carry what it depends on (deps)."""
    out = {"alert": alert, "expr": expr, "for": f"{WAIT[alert]}s"}
    if keep:
        out["keep_firing_for"] = f"{keep}s"
    return {**out, "labels": labels,
            "annotations": {"summary": summary, **context(inv, signal, condition, normal, labels.get("node"))}}


def per_object(metric: str, keys: dict, test: str) -> str:
    """The object's series failing `test`, or missing. Both halves come out labelled with the object's own
    keys only, so the alert keeps one identity while its series comes and goes: FRR deletes a BFD session
    when OSPF drops the adjacency and adds it back still down, and an alert whose labels changed with that
    would start its `for` again (V-015)."""
    sel = selector(**keys)
    return f"max by ({', '.join(keys)}) ({metric}{sel} {test}) or absent({metric}{sel})"


def after_link_down(inv: Inventory) -> int:
    """Seconds after LinkDown last fired that the flap ending its outage stays quiet: the counter keeps the
    change for FLAP_WINDOW after the carrier is back, LinkDown's last firing evaluation can be an interval
    before that, and one interval of margin."""
    return FLAP_WINDOW + 2 * inv.monitoring["interval"]


def keep_firing(inv: Inventory) -> int:
    """Seconds a cause's marker keeps firing after its signal recovers, still holding back what depends on
    it: the slowest dependent to recover is a log source's SourceSilent, which clears on its next heartbeat.
    The marker holds, not the page: a page that kept firing would outlast its parent's hold whenever it
    recovered a scrape later than its parent, and page then (the h2 behind r3 in a live run)."""
    return inv.logging["heartbeat"] + 3 * inv.monitoring["interval"]


def cause_rules(inv: Inventory) -> list[dict]:
    """A marker per cause, CauseSeen, which fires the moment its signal does (no `for`), in a rule group of
    its own evaluated every CAUSE_EVERY seconds. It never pages (Alertmanager routes it nowhere); it only has
    to be in Alertmanager before the alerts that depend on it are first sent, group_wait after they fire,
    and keep firing until the slowest of them has recovered (keep_firing)."""
    keep = keep_firing(inv)
    return [rule(inv, "CauseSeen", c["expr"], {**c["labels"], "cause": cid}, f"cause marker: {c['summary']}",
                 c["signal"], c["condition"], c["normal"], keep)
            for cid, c in causes(inv).items()]


def alert_rules(inv: Inventory) -> list[dict]:
    """One rule per object the inventory says should be up. Each also fires if its series is missing
    (absent), so a session or neighbor deleted from the config alerts too, not just one that is down.
    Each carries its node's owner and role as rule labels, so every alert about it has them, from either
    half of the rule (the hook for routing and silencing by role, OROS DEC-1 and DEC-4), and the causes
    it depends on (deps, OROS DEC-5)."""
    mon, rules, model = inv.monitoring, [], Dependencies(inv)
    noc = host(inv)
    logs = f"logs@{noc}"
    # A cause's own page: what it covers is held back while it fires, and by its marker for a while after.
    for cid, c in model.causes.items():
        if cid in inv.devices:
            rules.append(rule(inv, "NodeDown", c["expr"], {**c["labels"], "cause": cid, "deps": model.label({cid}, own=cid)},
                              c["summary"], c["signal"], c["condition"], c["normal"]))
        elif "link" in c["labels"]:
            link = next(l for l in inv.links if link_id(l) == cid)
            rules.append(rule(inv, "LinkDown", c["expr"], {**c["labels"], "cause": cid, "deps": model.label(model.link_objects(link), own=cid)},
                              c["summary"], c["signal"], c["condition"], c["normal"]))
    # Each exporter: both on a router we own, node_exporter alone on a server (decision 0023).
    for r in exporter_nodes(inv):
        for job in (EXPORTERS if r in inv.routers else ["node"]):
            cid = f"{job}@{r}"
            signal = f"up{selector(job=job, node=r)}"
            labels = {**target_labels(inv, r), "job": job, **({"cause": cid} if cid in model.causes else {}), "deps": model.label({r})}
            rules.append(rule(inv, "TargetDown", f"{signal} == 0", labels, f"{job} on {r} does not answer its scrape",
                              signal, "== 0", "1"))
    # The NOC's own services: one rule per scrape job besides the routers' exporters, since every target of a
    # blackbox job is one exporter. Read from the scrape config, so a job added there gets its rule too.
    for job in dict.fromkeys(j["job_name"] for j in prometheus_config(inv)["scrape_configs"] if j["job_name"] not in EXPORTERS):
        signal = f"min(up{selector(job=job)})"
        labels = {"job": job, **({"cause": logs} if job == "logs" else {}), "deps": "/"}
        rules.append(rule(inv, "TargetDown", f"{signal} == 0", labels, f"the NOC's {job} job does not answer its scrape",
                          signal, "== 0", "1"))
    for s in bgp_peers(inv):
        # frr_exporter: 1 Established, 0 down, 2 administratively down. `== 0` would miss a local shutdown.
        keys = {"node": s["node"], "peer": s["address"]}
        link = next(l for l in inv.links if l.a.address and l.b.address and {str(l.a.address.ip), str(l.b.address.ip)} >= {s["address"]}
                    and s["node"] in (l.a.device, l.b.device))
        rules.append(rule(inv, "BGPSessionDown", per_object("frr_bgp_peer_state", keys, "!= 1"),
                          {**target_labels(inv, s["node"]), "peer": s["address"], "peer_name": s["peer"],
                           "deps": model.label({s["node"], *model.link_objects(link)}, extra={f"frr@{s['node']}"})},
                          f"BGP {s['node']} -> {s['peer']} ({s['address']}) is not Established: {{{{ $value }}}} (0 down, 2 admin down)",
                          f"frr_bgp_peer_state{selector(**keys)}", "!= 1, or missing", "1 (Established)"))
    for n in ospf_neighbors(inv):
        # Adjacencies (Full), not neighbors: a neighbor stuck in ExStart still counts as a neighbor.
        # The series' own iface label names the interface; the rule adds the neighbor's name.
        keys = {"node": n["node"], "iface": n["interface"]}
        link = link_at(inv, n["node"], n["interface"])
        rules.append(rule(inv, "OSPFNeighborDown", per_object("frr_ospf_neighbor_adjacencies", keys, "< 1"),
                          {**target_labels(inv, n["node"]), "neighbor": n["neighbor"],
                           "deps": model.label({n["node"], *model.link_objects(link)}, extra={f"frr@{n['node']}"})},
                          f"OSPF {n['node']} has no Full adjacency with {n['neighbor']} on {n['interface']}",
                          f"frr_ospf_neighbor_adjacencies{selector(**keys)}", "< 1, or missing", "1 (Full)"))
    for b in bfd_peers(inv):
        keys = {"node": b["node"], "peer": b["address"]}
        link = next(l for l in inv.links if l.a.address and l.b.address and b["address"] in (str(l.a.address.ip), str(l.b.address.ip)))
        rules.append(rule(inv, "BFDPeerDown", per_object("frr_bfd_peer_state", keys, "!= 1"),
                          {**target_labels(inv, b["node"]), "neighbor": b["neighbor"], "peer": b["address"],
                           "deps": model.label({b["node"], *model.link_objects(link)}, extra={f"frr@{b['node']}"})},
                          f"BFD {b['node']} -> {b['neighbor']} ({b['address']}) is not up",
                          f"frr_bfd_peer_state{selector(**keys)}", "!= 1, or missing", "1 (up)"))
    for w in mon.get("web") or []:
        signal = f"probe_success{selector(job='web', node=w['host'])}"
        rules.append(rule(inv, "WebContentWrong", f"{signal} == 0",
                          {**target_labels(inv, w["host"]), "port": str(w["port"]), "deps": model.label({w["host"]})},
                          f"{w['host']}:{w['port']} does not return a page matching {w['expect']}",
                          signal, "== 0", f"1 (a page matching {w['expect']})"))
    for r in exporter_routers(inv):
        for ep in inv.interfaces(r):
            # The carrier-change counter catches a flap shorter than a scrape, which a state poll misses. It
            # fires once the carrier is back: a link still down is LinkDown's page, not a flap.
            # Its deps are the router and what is in front of it, never its own link: a scrape that sees the
            # flap fires the link's marker, which would hold back the only page a short outage raises. A link
            # down long enough for LinkDown to fire has had its page, so the flap that ends it adds none.
            keys = {"node": r, "device": ep.interface}
            signal = f"increase(node_network_carrier_changes_total{selector(**keys)}[{FLAP_WINDOW}s])"
            expr, condition = f"({signal} > 0 and node_network_carrier{selector(**keys)} == 1)", "> 0 with the carrier back up"
            lid = link_id(link_at(inv, r, ep.interface))
            if lid in model.causes:
                linkdown = f"ALERTS{selector(alertname='LinkDown', alertstate='firing', cause=lid)}"
                expr += f" unless on() max_over_time({linkdown}[{after_link_down(inv)}s])"
                condition += f", and no LinkDown for its link in the last {after_link_down(inv)} s"
            rules.append(rule(inv, "InterfaceFlapped", expr, {**target_labels(inv, r), "device": ep.interface, "deps": model.label({r})},
                              f"{r} {ep.interface} lost carrier in the last {FLAP_WINDOW} s", signal, condition, "0"))
    for d in exporter_nodes(inv):
        # A queue's drop counter catches a burst far shorter than a scrape, which a 5-minute average of the
        # interface's traffic hides, and which the interface's own drop counter never sees (decision 0023).
        # Its deps are what is in front of the node, never the node itself: a burst that fills h2's queue drops
        # the NOC's ping of h2 too, and that marker holds back for 75 s, longer than this keeps firing (decision
        # 0021). It can't fire without a scrape of the node's own exporter, so the node's cause adds nothing else.
        signal = f"increase(node_qdisc_drops_total{selector(node=d)}[1m])"
        rules.append(rule(inv, "QueueDrops", f"{signal} > 0", {**target_labels(inv, d), "deps": model.label({d}, own=d)},
                          f"{d} {{{{ $labels.device }}}} ({{{{ $labels.kind }}}} queue) dropped packets in the last minute",
                          signal, "> 0", "0"))
    window = mon["reboot_window"]
    for r in exporter_routers(inv):
        signal = f"time() - node_reboot_required_since_seconds{selector(node=r)}"
        rules.append(rule(inv, "PendingRebootOverdue", f"node_reboot_required{selector(node=r)} == 1 and on(node) ({signal} > {window})",
                          {**target_labels(inv, r), "deps": model.label({r})},
                          f"{r} has run an older kernel than it has installed for over {window} s",
                          signal, f"> {window} while node_reboot_required is 1", "node_reboot_required 0"))
    for r in access.routers(inv):
        # Every accept, refuse and command line the router's accounting proxy logs sets its account's last-seen
        # time at the collector (decision 0029). Anyone not on the inventory's list pages, in the group or not.
        # A shell login that never opens FRR's CLI logs nothing here (RISK-61). Nothing holds it back: a cause
        # that starts after the login (the router going down) must not hide it.
        expected = "|".join(access.expected_admins(inv))
        signal = f'time() - admin_last_seen_seconds{{node="{r}",user!~"{expected}"}}'
        rules.append(rule(inv, "UnexpectedAdmin", f"max by (node, user) ({signal} < {ADMIN_WINDOW})",
                          {**target_labels(inv, r), "deps": model.label(set())},
                          f"{{{{ $labels.user }}}} opened FRR's CLI or ran a command on {r}, and is not an expected admin",
                          signal, f"< {ADMIN_WINDOW}", "no series: only expected accounts have opened FRR's CLI"))
    for s in log_sources(inv):
        sel = selector(node=s["node"], source=s["source"])
        rules.append(rule(inv, "SourceSilent", f"max by (node, source) (time() - log_last_seen_seconds{sel} > {s['silent_after']}) "
                                               f"or absent(log_last_seen_seconds{sel})",
                          {**target_labels(inv, s["node"]), "source": s["source"], "deps": model.label({s["node"]}, extra={logs})},
                          f"no {s['source']} line from {s['node']} has reached the collector for over {s['silent_after']} s",
                          f"time() - log_last_seen_seconds{sel}", f"> {s['silent_after']}, or missing",
                          f"under {s['silent_after']} s"))
    for s in ingest_sources(inv):
        # The licence or storage budget is a day's bytes, so this is the last 24 h's, not a projection: a burst
        # pages only if it really spends the day's budget (decision 0026). It is counted at the collector, so
        # it can't be seen without it.
        sel = selector(node=s["node"], source=s["source"])
        signal = f"increase(log_bytes_total{sel}[1d])"
        rules.append(rule(inv, "LogIngestOverBudget", f"max by (node, source) ({signal}) > {s['budget']}",
                          {**target_labels(inv, s["node"]), "source": s["source"], "deps": model.label(set(), extra={logs})},
                          f"{s['node']} {s['source']} sent {{{{ $value | humanize1024 }}}}B in the last 24 h, over its "
                          f"{s['budget'] // 1024} KB budget", signal, f"> {s['budget']} bytes", f"under {s['budget']} bytes a day"))
    rules += deadman_rules(inv, logs)
    return rules


# --- Dead-man's switch: jobs and the alert path itself (OROS NOT-4, decision 0022) -------------------------

def since_start(expr: str, after: int = 0) -> str:
    """expr, or the NOC's start time (plus `after` seconds) when nothing has arrived since it started (the
    pushgateway starts with it): `time() - since_start(last)` then grows from the start, so something that
    never ran pages too."""
    start = f"max(process_start_time_seconds{selector(job='pushgateway')})"
    return f"({expr} or on() {f'({start} + {after})' if after else start})"


def deadman_rules(inv: Inventory, logs: str) -> list[dict]:
    """JobMissed per unattended job, Watchdog, and AlertPathSilent. A job's success is what it pushes as its
    last step, so a job that failed, hung or never started looks the same: no success in its window.
    Watchdog always fires and goes out by mail; AlertPathSilent reads where that mail arrives (Mailpit's
    webhook into the collector) and pages over the webhook, the other channel."""
    out, mon = [], inv.monitoring
    for j in mon.get("jobs") or []:
        window = j["every"] + j["grace"]
        metric = f"netlab_job_last_success_timestamp_seconds{selector(job=j['name'])}"
        out.append(rule(inv, "JobMissed", f"time() - {since_start(f'max({metric})')} > {window}",
                        {"job": j["name"], "deps": "/"},
                        f"{j['name']} has not reported a success for over {window} s (it runs every {j['every']} s)",
                        f"time() - {metric}", f"> {window} ({j['every']} s plus {j['grace']} s grace), or no success since the NOC started",
                        f"under {j['every']} s"))
    path, mail = mon["alert_path"], f"log_last_seen_seconds{selector(node=host(inv), source='mail')}"
    out.append(rule(inv, "Watchdog", "vector(1)", {}, f"always firing: the alert path's heartbeat, mailed every {path['every']} s",
                    f"time() - {mail}", "(Watchdog itself always fires: vector(1))", f"under {path['every']} s since the last mail"))
    # At the NOC's start Prometheus can send Watchdog before Alertmanager answers. That send is dropped, and
    # it sends again only RESEND_DELAY later, so the first mail is not due before then.
    out.append(rule(inv, "AlertPathSilent", f"time() - {since_start(f'max({mail})', RESEND_DELAY)} > {path['silent_after']}",
                    {"channel": "mail", "deps": f"/{logs}/"},
                    f"no alert mail has reached the NOC's mailbox for over {path['silent_after']} s: the mail path is broken",
                    f"time() - {mail}", f"> {path['silent_after']}, or no mail in the {RESEND_DELAY + path['silent_after']} s since the NOC started",
                    f"under {path['every']} s"))
    return out


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
    jobs = [{"job_name": job, "static_configs": [{"targets": [f"{node_exporter_address(inv, d)}:{PORTS[job]}"], "labels": target_labels(inv, d)}
                                                for d in (exporter_nodes(inv) if job == "node" else exporter_routers(inv))]}
            for job in EXPORTERS]
    web = [blackbox_job("web", web_module(w), [{"targets": [f"http://{probe_address(inv, w['host'])}:{w['port']}/"],
                                                "labels": target_labels(inv, w["host"])}])
           for w in inv.monitoring.get("web") or []]
    icmp = blackbox_job("icmp", "icmp", [{"targets": [t["address"]], "labels": target_labels(inv, t["device"])}
                                         for t in probe_targets(inv)])
    # The collector's own per-source metrics (log_last_seen_seconds{node,source}).
    logs = {"job_name": "logs", "static_configs": [{"targets": [f"127.0.0.1:{PORTS['collector_metrics']}"]}]}
    # What jobs and `make apply` push (decisions 0020 and 0022). honor_labels keeps the job label each push
    # names (drift, backup), not this scrape's.
    pushed = {"job_name": "pushgateway", "honor_labels": True,
              "static_configs": [{"targets": [f"127.0.0.1:{PORTS['pushgateway']}"]}]}
    return {
        "global": {"scrape_interval": interval, "evaluation_interval": interval, "scrape_timeout": f"{inv.monitoring['interval'] - 1}s"},
        "rule_files": ["/etc/prometheus/rules.yml"],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [f"127.0.0.1:{PORTS['alertmanager']}"]}]}]},
        "scrape_configs": [*jobs, *web, icmp, logs, pushed],
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
                                            "--collector.netclass --collector.netdev --collector.netstat --collector.qdisc "
                                            f"--collector.netstat.fields={NETSTAT_FIELDS} "
                                            "--collector.textfile --collector.textfile.directory=/textfile"}
    for h in servers(inv):
        # Only what the server's own interfaces and queues count: no process, file or other host data.
        out[f"{h}-node-exporter"] = {"netns": h, "image": images["node_exporter"], "binds": [],
                                     "cmd": f"--web.listen-address={node_exporter_address(inv, h)}:{PORTS['node']} "
                                            "--collector.disable-defaults --collector.netdev --collector.qdisc"}
    out[f"{noc}-prometheus"] = {"netns": noc, "image": images["prometheus"],
                                "binds": [f"{noc}/prometheus.yml:/etc/prometheus/prometheus.yml:ro", f"{noc}/rules.yml:/etc/prometheus/rules.yml:ro"],
                                "cmd": f"--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus "
                                       f"--web.listen-address=127.0.0.1:{PORTS['prometheus']} "
                                       f"--web.external-url=http://127.0.0.1:{PORTS['prometheus']}"}
    # An empty cluster address turns off the gossip port Alertmanager would otherwise open on every address.
    out[f"{noc}-alertmanager"] = {"netns": noc, "image": images["alertmanager"],
                                  "binds": [f"{noc}/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro"],
                                  "cmd": f"--config.file=/etc/alertmanager/alertmanager.yml --storage.path=/alertmanager "
                                         f"--web.listen-address=127.0.0.1:{PORTS['alertmanager']} --cluster.listen-address="}
    out[f"{noc}-blackbox"] = {"netns": noc, "image": images["blackbox"], "binds": [f"{noc}/blackbox.yml:/etc/blackbox/blackbox.yml:ro"],
                              "cmd": f"--config.file=/etc/blackbox/blackbox.yml --web.listen-address=127.0.0.1:{PORTS['blackbox']}"}
    # Loki's data is on the lab host's disk (build/noc/loki), not in the container, so the store outlives a
    # power cut or a redeploy of noc itself (decision 0025).
    out[f"{noc}-loki"] = {"netns": noc, "image": images["loki"], "binds": [f"{noc}/loki.yaml:/etc/loki/loki.yaml:ro", f"{noc}/loki:/loki"],
                          "cmd": "-config.file=/etc/loki/loki.yaml"}
    out[f"{noc}-collector"] = {"netns": noc, "image": images["vector"], "binds": [f"{noc}/vector.yaml:/etc/vector/vector.yaml:ro"],
                               "cmd": "--config /etc/vector/vector.yaml"}
    # Where unattended jobs and `make apply` push their success (decisions 0020 and 0022).
    out[f"{noc}-pushgateway"] = {"netns": noc, "image": images["pushgateway"], "binds": [],
                                 "cmd": f"--web.listen-address=127.0.0.1:{PORTS['pushgateway']}"}
    # The NOC's mailbox, where Alertmanager's mail arrives; it tells the collector of each new mail (decision 0022).
    out[f"{noc}-mailbox"] = {"netns": noc, "image": images["mailpit"], "binds": [],
                             "cmd": f"--smtp 127.0.0.1:{PORTS['smtp']} --listen 127.0.0.1:{PORTS['mailbox']} "
                                    f"--webhook-url http://127.0.0.1:{PORTS['mail_hook']}/ --quiet"}
    if inv.raw.get("dns"):
        # The lab's DNS (decision 0032): CoreDNS serving the hosts file netlab renders from the inventory, on the
        # NOC's address, UDP and TCP 53. No forwarding: a name it doesn't have is NXDOMAIN.
        out[f"{noc}-dns"] = {"netns": noc, "image": images["coredns"],
                             "binds": [f"{noc}/Corefile:/Corefile:ro", f"{noc}/hosts.lab:/hosts.lab:ro", f"{noc}/root.db:/root.db:ro"],
                             "cmd": "-conf /Corefile"}
    for r in nat_logs(inv):
        # conntrack needs CAP_NET_ADMIN in the router's namespace, so this one runs as root (decision 0031), and
        # the topology asks for that capability by name. Containerlab 0.68.0 starts every node privileged, a
        # node sharing another's namespace included (its runtime/docker/docker.go), so there it has it anyway.
        out[f"{r}-nat-log"] = {"netns": r, "image": images["netshoot"], "binds": [f"{r}/natlog.sh:/natlog.sh:ro"],
                               "cmd": "sh /natlog.sh", "cap_add": ["NET_ADMIN"]}
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
    deps = Dependencies(inv)
    return {
        "host": host(inv),
        "collector": collector(inv),
        "interval": inv.monitoring["interval"],
        "exporters": {r: {"address": loopback(inv, r), "ports": [PORTS[j] for j in EXPORTERS]} for r in exporter_routers(inv)},
        "servers": {h: {"address": node_exporter_address(inv, h), "port": PORTS["node"]} for h in servers(inv)},
        "bgp_peers": bgp_peers(inv),
        "ospf_neighbors": ospf_neighbors(inv),
        "bfd_peers": bfd_peers(inv),
        "web": inv.monitoring.get("web") or [],
        "reboot_window": inv.monitoring["reboot_window"],
        "sources": log_sources(inv),
        # Every source the store keeps with its daily budget: the heartbeat sources and each router's command records.
        "ingest": ingest_sources(inv),
        "heartbeat": inv.logging["heartbeat"],
        "flightrec": FLIGHTREC,
        "on_box": inv.logging["on_box"],
        "apps": inv.logging.get("apps") or [],
        # What each app's forwarder cuts at the source, by kind (decision 0026), and how many cut lines it
        # sums into each count line it sends instead: a heartbeat's worth of the NOC's checks.
        "cuts": {f"{a['host']}/{a['name']}": cuts(inv, a) for a in inv.logging.get("apps") or []},
        "cut_per_line": cut_per_line(inv),
        "store_mb": (inv.logging.get("budget") or {}).get("store_mb"),
        "sidecars": sorted(sidecars(inv)),
        # Each sidecar image's tag and the digest it must resolve to.
        "digests": {inv.monitoring["images"][k]: inv.monitoring["digests"][k] for k in inv.monitoring["images"]},
        "alerts": sorted({r["alert"] for r in [*alert_rules(inv), *cause_rules(inv)]}),
        # How long after the object changes its alert may take to reach the pager: `for` to hold, plus
        # deliver() (scrape, evaluations, group_wait). The pending-reboot file is rewritten every
        # TEXTFILE_EVERY seconds on top of that.
        "alert_within": {a: w + deliver(inv) + (TEXTFILE_EVERY if a == "PendingRebootOverdue" else 0)
                         for a, w in WAIT.items()},
        "group_wait": inv.monitoring["group_wait"],
        # One page per cause (decision 0021): each cause with what depends on it, and how long its marker
        # keeps holding that back after it recovers.
        "causes": {cid: {"labels": c["labels"], "covers": sorted(v for v in deps.dom if cid in deps.dom[v])}
                   for cid, c in deps.causes.items()},
        "keep_firing": keep_firing(inv),
        "jobs": inv.monitoring.get("jobs") or [],
        "alert_path": inv.monitoring["alert_path"],
    }


def rule_groups(inv: Inventory) -> dict:
    """rules.yml: the alerts, and the cause markers in a group of their own evaluated every CAUSE_EVERY s."""
    return {"groups": [{"name": "netlab", "rules": alert_rules(inv)},
                       {"name": "causes", "interval": f"{CAUSE_EVERY}s", "rules": cause_rules(inv)}]}


def cut_per_line(inv: Inventory) -> int:
    """Cut lines summed into one count line: a heartbeat's worth of the NOC's checks, so a forwarder that
    cuts them still sends a line every heartbeat, its source's proof of life."""
    return inv.logging["heartbeat"] // inv.monitoring["interval"]


def dump(doc: dict) -> str:
    return "# Generated by netlab from inventory/network.yml (netlab/monitoring.py). Do not edit by hand.\n" + \
        yaml.safe_dump(doc, sort_keys=False, width=200)


def render(inv: Inventory, env, write, out: Path) -> None:
    """Every config the NOC and the watched nodes need, into build/."""
    if not inv.monitoring:
        return
    noc, logs = host(inv), inv.logging
    write(f"{noc}/prometheus.yml", dump(prometheus_config(inv)))
    write(f"{noc}/rules.yml", dump(rule_groups(inv)))
    write(f"{noc}/blackbox.yml", dump(blackbox_config(inv)))
    ctx = dict(inv=inv, ports=PORTS, collector=collector(inv), logs=logs, addresses=source_addresses(inv),
               textfile_every=TEXTFILE_EVERY, mon=inv.monitoring, causes=sorted(causes(inv)), flightrec=FLIGHTREC,
               senders=senders(inv), accounting_source=access.SOURCE)
    for name in ("alertmanager.yml", "loki.yaml", "vector.yaml"):
        write(f"{noc}/{name}", env.get_template(f"monitoring/{name}.j2").render(**ctx))
    write(f"{noc}/sink.py", (ROOT / "templates" / "monitoring" / "sink.py").read_text())
    write("monitoring/agent.sh", env.get_template("monitoring/agent.sh.j2").render(**ctx))
    # The same kernel rule `make verify` uses, run on each router for its pending-reboot metric.
    write("monitoring/kernel.py", (ROOT / "netlab" / "kernel.py").read_text())
    for r in nat_logs(inv):
        write(f"{r}/natlog.sh", env.get_template("monitoring/natlog.sh.j2").render(
            name=r, address=inv.routers[r]["nat"]["address"], tag=nat.SOURCE, heartbeat=logs["heartbeat"],
            collector=collector(inv), port=PORTS["syslog"], own_port=nat.RECORD_PORT))
    for app in logs.get("apps") or []:
        write(f"{app['host']}/forwarder.yaml", env.get_template("monitoring/forwarder.yaml.j2").render(
            app=app, cuts=cuts(inv, app), cut_per_line=cut_per_line(inv), **ctx))
    # Folders the nodes share with their sidecars. Created here because Containerlab refuses a bind whose
    # source is missing; never emptied here, because a running router's sockets live in its run/.
    for r in exporter_routers(inv):
        for d in ("run", "textfile"):
            (out / r / d).mkdir(parents=True, exist_ok=True)
    for app in logs.get("apps") or []:
        (out / app["host"] / "applog").mkdir(parents=True, exist_ok=True)
    # Loki runs as its image's user (uid 10001), not as whoever rendered, so its folder must be writable by
    # any user. It is on the lab host only, and never emptied here: it is the central store's history.
    store = out / noc / "loki"
    store.mkdir(parents=True, exist_ok=True)
    store.chmod(0o777)
