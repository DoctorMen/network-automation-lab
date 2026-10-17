"""Load the inventory and catch addressing mistakes before anything is deployed."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class InventoryError(ValueError):
    """Raised with every problem found, not just the first."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("Inventory has problems:\n  - " + "\n  - ".join(problems))


@dataclass(frozen=True)
class Endpoint:
    device: str
    interface: str
    address: ipaddress.IPv4Interface

    @classmethod
    def parse(cls, raw: str) -> "Endpoint":
        # "r1:eth1@10.0.12.0/31"
        try:
            dev_if, addr = raw.split("@")
            device, interface = dev_if.split(":")
        except ValueError as exc:
            raise InventoryError([f"bad endpoint {raw!r}, expected device:interface@address/len"]) from exc
        return cls(device, interface, ipaddress.IPv4Interface(addr))


@dataclass
class Link:
    a: Endpoint
    b: Endpoint

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.a.address.network


@dataclass
class Inventory:
    raw: dict
    links: list[Link] = field(default_factory=list)

    @property
    def lab_name(self) -> str:
        return self.raw["lab_name"]

    @property
    def operator(self) -> str | None:
        return self.raw.get("operator")

    @property
    def platform(self) -> dict:
        return self.raw.get("platform", {})

    @property
    def routers(self) -> dict:
        return self.raw.get("routers", {})

    @property
    def firewalls(self) -> dict:
        return self.raw.get("firewalls", {})

    @property
    def hosts(self) -> dict:
        return self.raw.get("hosts", {})

    @property
    def qos(self) -> dict:
        return self.raw.get("qos", {})

    @property
    def rollout(self) -> dict:
        return self.raw.get("rollout", {})

    @property
    def monitoring(self) -> dict:
        return self.raw.get("monitoring", {})

    @property
    def logging(self) -> dict:
        return self.raw.get("logging", {})

    @property
    def devices(self) -> list[str]:
        return [*self.routers, *self.firewalls, *self.hosts]

    def owner(self, device: str) -> str | None:
        for group in (self.routers, self.firewalls, self.hosts):
            if device in group:
                return group[device].get("owner")
        return None

    def device_at(self, address: str) -> str | None:
        """Which device answers on this address (link end or loopback)."""
        for link in self.links:
            for ep in (link.a, link.b):
                if str(ep.address.ip) == address:
                    return ep.device
        for name, r in self.routers.items():
            if str(ipaddress.IPv4Interface(r["loopback"]).ip) == address:
                return name
        return None

    def asn(self, name_or_number) -> int:
        if isinstance(name_or_number, int):
            return name_or_number
        return int(self.raw["asn"][name_or_number])

    def interfaces(self, device: str) -> list[Endpoint]:
        eps = [ep for link in self.links for ep in (link.a, link.b) if ep.device == device]
        return sorted(eps, key=lambda ep: ep.interface)

    def neighbors(self, device: str) -> list[tuple[Endpoint, Endpoint]]:
        """(local endpoint, remote endpoint) for every link the device is on."""
        out = []
        for link in self.links:
            if link.a.device == device:
                out.append((link.a, link.b))
            elif link.b.device == device:
                out.append((link.b, link.a))
        return out

    def ospf_neighbors(self, router: str) -> list[str]:
        """Routers this router should form an OSPF adjacency with."""
        if "ospf" not in self.routers.get(router, {}):
            return []
        return sorted(
            remote.device
            for _, remote in self.neighbors(router)
            if remote.device in self.routers and "ospf" in self.routers[remote.device]
        )


def load(path: str | Path) -> Inventory:
    raw = yaml.safe_load(Path(path).read_text())
    inv = Inventory(raw=raw)
    problems: list[str] = []
    for pair in raw.get("links", []):
        try:
            inv.links.append(Link(Endpoint.parse(pair[0]), Endpoint.parse(pair[1])))
        except InventoryError as exc:
            problems.extend(exc.problems)
    problems.extend(validate(inv))
    if problems:
        raise InventoryError(problems)
    return inv


PLATFORM_FIELDS = ("image", "digest", "frr", "alpine", "busybox")


def validate(inv: Inventory) -> list[str]:
    problems: list[str] = []
    known = set(inv.devices)

    # tests/live/test_platform.py compares these, as text, with what the nodes report.
    for key in PLATFORM_FIELDS:
        value = inv.platform.get(key)
        if value is None:
            problems.append(f"platform: {key} is missing")
        elif not isinstance(value, str):
            problems.append(f"platform: {key} {value!r} must be quoted, or YAML reads it as a number")

    seen_ips: dict[ipaddress.IPv4Address, str] = {}
    seen_ifaces: set[tuple[str, str]] = set()
    seen_nets: dict[ipaddress.IPv4Network, int] = {}

    for i, link in enumerate(inv.links):
        label = f"link {link.a.device}<->{link.b.device}"
        for ep in (link.a, link.b):
            if ep.device not in known:
                problems.append(f"{label}: device {ep.device!r} is not defined")
            if (ep.device, ep.interface) in seen_ifaces:
                problems.append(f"{label}: {ep.device}:{ep.interface} is used on more than one link")
            seen_ifaces.add((ep.device, ep.interface))
            ip = ep.address.ip
            if ip in seen_ips:
                problems.append(f"{label}: {ip} is already used by {seen_ips[ip]}")
            seen_ips[ip] = f"{ep.device}:{ep.interface}"
            if ep.address.network.prefixlen < 31 and ip in (ep.address.network.network_address, ep.address.network.broadcast_address):
                problems.append(f"{label}: {ep.address} is the network or broadcast address")
        if link.a.address.network != link.b.address.network:
            problems.append(f"{label}: ends are in different subnets ({link.a.address.network} vs {link.b.address.network})")
        for other, j in seen_nets.items():
            if other != link.network and other.overlaps(link.network):
                problems.append(f"{label}: subnet {link.network} overlaps link #{j + 1} ({other})")
        seen_nets.setdefault(link.network, i)

    for name, r in inv.routers.items():
        lo = ipaddress.IPv4Interface(r["loopback"]).ip
        if lo in seen_ips:
            problems.append(f"{name}: loopback {lo} collides with {seen_ips[lo]}")
        seen_ips[lo] = f"{name}:lo"
        for nbr in r.get("bgp", {}).get("neighbors", []):
            peer_eps = [remote for _, remote in inv.neighbors(name) if remote.device == nbr["peer"]]
            if not peer_eps:
                problems.append(f"{name}: BGP peer {nbr['peer']} has no direct link")
            elif str(peer_eps[0].address.ip) != nbr["address"]:
                problems.append(f"{name}: BGP peer {nbr['peer']} address {nbr['address']} does not match link address {peer_eps[0].address.ip}")

    for name, h in inv.hosts.items():
        eps = inv.interfaces(name)
        if not eps or str(eps[0].address) != h["address"]:
            problems.append(f"{name}: host address {h['address']} does not match its link")
        elif ipaddress.IPv4Address(h["gateway"]) not in eps[0].address.network:
            problems.append(f"{name}: gateway {h['gateway']} is not on {eps[0].address.network}")

    for name, fw in inv.firewalls.items():
        by_if = {ep.interface: ep for ep in inv.interfaces(name)}
        for side in ("inside", "outside"):
            ep = by_if.get(fw[side]["interface"])
            if ep is None or str(ep.address) != fw[side]["address"]:
                problems.append(f"{name}: {side} address {fw[side]['address']} does not match its link")
        for rule in fw.get("rules", []):
            label = f"{name} rule {rule['name']}"
            if rule.get("syn") and rule.get("proto") != "tcp":
                problems.append(f"{label}: syn: true needs proto: tcp")
            # Without a SYN match, a TCP accept also forwards mid-stream packets that belong to no
            # connection fw1 has seen, such as a forged ACK. A state match only helps if it leaves
            # out NEW: with nf_conntrack_tcp_loose=1, conntrack calls a forged ACK NEW.
            if rule.get("proto") == "tcp" and rule["action"] == "accept" and not rule.get("syn") and "NEW" in rule.get("state", ["NEW"]):
                problems.append(f"{label}: TCP accept needs syn: true, or it forwards forged mid-stream packets")

    # tc reads "15mbit"; netlab verify compares the installed rates with these as text.
    for name, q in inv.qos.items():
        label = f"qos on {name}"
        if name not in inv.hosts:
            problems.append(f"{label}: {name} is not a host")
        elif q["interface"] != inv.hosts[name]["interface"]:
            problems.append(f"{label}: {q['interface']} is not {name}'s interface ({inv.hosts[name]['interface']})")
        rates = [q["rate"]] + [c["rate"] for c in q["classes"]]
        if not all(re.fullmatch(r"\d+mbit", str(r)) for r in rates):
            problems.append(f"{label}: write every rate in whole mbit, like 20mbit")
        elif sum(int(r[:-4]) for r in rates[1:]) > int(rates[0][:-4]):
            problems.append(f"{label}: the class rates add up to more than the link's {q['rate']}")
        if [c.get("default", False) for c in q["classes"]].count(True) != 1:
            problems.append(f"{label}: exactly one class must be the default, for traffic no filter matches")
        if q.get("probe_from") not in inv.hosts:
            problems.append(f"{label}: probe_from {q.get('probe_from')!r} is not a host")

    if inv.routers and inv.rollout.get("canary") not in inv.routers:
        problems.append(f"rollout: canary {inv.rollout.get('canary')!r} is not a router")
    window = inv.rollout.get("change_window", {})
    if not all(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d|24:00", str(window.get(k))) for k in ("start", "end")):
        problems.append(f"rollout: change_window {window} needs a start and an end as quoted HH:MM (UTC)")
    for name, h in inv.hosts.items():
        unknown = set(h.get("published", [])) - set(h.get("services", []))
        if unknown:
            problems.append(f"{name}: published port(s) {sorted(unknown)} have no listener in services")
    for name, r in inv.routers.items():
        wan = r.get("wan_filter")
        if wan and wan["interface"] not in {ep.interface for ep in inv.interfaces(name)}:
            problems.append(f"{name}: wan_filter interface {wan['interface']} is not on any link")
    problems.extend(rtbh_problems(inv))
    problems.extend(scope_problems(inv))
    problems.extend(monitoring_problems(inv))
    from .access import problems as access_problems  # access.py imports this module
    problems.extend(access_problems(inv))
    from .nat import problems as nat_problems  # so does nat.py
    problems.extend(nat_problems(inv))
    # A TCP MD5 entry names the two ends of one BGP session, and a secret by file name (not its value).
    for i, auth in enumerate(inv.raw.get("bgp_auth", [])):
        label = f"bgp_auth #{i + 1}"
        ends = auth.get("routers") or []
        if len(ends) != 2:
            problems.append(f"{label}: routers must name the two ends of one BGP session")
        else:
            for local, remote in (ends, ends[::-1]):
                peers = [n["peer"] for n in inv.routers.get(local, {}).get("bgp", {}).get("neighbors", [])]
                if remote not in peers:
                    problems.append(f"{label}: {local} has no BGP session with {remote}")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", str(auth.get("secret") or "")):
            problems.append(f"{label}: secret must be a file name such as bgp-r2-isp, not a password")

    # Someone has to act when a device breaks, and tools may log in only where the operator owns it.
    for name in inv.devices:
        if not inv.owner(name):
            problems.append(f"{name}: no owner (who must act when it breaks?)")
    if inv.operator not in {inv.owner(d) for d in inv.devices}:
        problems.append(f"operator {inv.operator!r} owns no device, so no tool may log in anywhere")

    return problems


def bgp_peer_address(inv: Inventory, router: str, peer: str) -> str | None:
    """The address `router` uses for its BGP session with `peer`, from its neighbor list."""
    return next((n["address"] for n in inv.routers.get(router, {}).get("bgp", {}).get("neighbors", [])
                 if n["peer"] == peer), None)


def rtbh_problems(inv: Inventory) -> list[str]:
    """The blackhole lever only works if both ends peer and the community is the provider's to define."""
    rtbh = inv.raw.get("rtbh")
    if not rtbh:
        return []
    problems = []
    provider, customer = rtbh.get("provider"), rtbh.get("customer")
    if not (bgp_peer_address(inv, provider, customer) and bgp_peer_address(inv, customer, provider)):
        problems.append(f"rtbh: {provider} and {customer} must be BGP neighbors of each other")
    else:
        # A community is <AS>:<value>; the blackhole community belongs to the AS that acts on it.
        asn = inv.asn(inv.routers[provider]["bgp"]["local_as"])
        if str(rtbh.get("community", "")).split(":")[0] != str(asn):
            problems.append(f"rtbh: community {rtbh.get('community')!r} is not in the provider's AS {asn}")
    if not isinstance(rtbh.get("tag"), int):
        problems.append(f"rtbh: tag {rtbh.get('tag')!r} must be a number")
    return problems


def segment_members(inv: Inventory, segment: str | None) -> dict[str, str]:
    """Every device with an address on the segment, and that address: its hosts and the router ports facing them."""
    hosts = {h: v["address"].split("/")[0] for h, v in inv.hosts.items() if v.get("segment") == segment}
    return {**hosts, **{remote.device: str(remote.address.ip) for h in hosts for _, remote in inv.neighbors(h)}}


SCOPE_CATEGORIES = {"cde", "connected-to", "security-impacting"}
SCOPE_DESIGNS = {"tokenisation", "p2pe", "segmentation", "truncation", "holding less"}


def scope_problems(inv: Inventory) -> list[str]:
    """Every device has a scope decision, and the topology can't contradict it (OROS ATT-1)."""
    scope = inv.raw.get("scope")
    if not scope:
        return []
    problems = [f"scope: no {key}" for key in ("framework", "segment", "design", "acceptance") if not scope.get(key)]
    if scope.get("design") and scope["design"] not in SCOPE_DESIGNS:
        problems.append(f"scope: design {scope['design']!r} is not one of {sorted(SCOPE_DESIGNS)}")
    systems, out = scope.get("systems") or {}, scope.get("out_of_scope") or []
    for name in [*systems, *out]:
        if name not in inv.devices:
            problems.append(f"scope: {name} is not a device")
    for name in inv.devices:
        if name not in systems and name not in out:
            problems.append(f"scope: {name} has no scope decision (list it under systems or out_of_scope)")
        elif name in systems and name in out:
            problems.append(f"scope: {name} is both in and out of scope")
    for name, entry in systems.items():
        problems += [f"scope: {name} has no {key}" for key in ("category", "clause", "why") if not (entry or {}).get(key)]
        if (entry or {}).get("category") and entry["category"] not in SCOPE_CATEGORIES:
            problems.append(f"scope: {name} category {entry['category']!r} is not one of {sorted(SCOPE_CATEGORIES)}")
    for exc in scope.get("exceptions") or []:
        label = f"scope: exception {exc.get('src')} {exc.get('proto')}"
        if exc.get("src") not in out:
            problems.append(f"{label}: {exc.get('src')} is not out of scope")
        # TCP into the segment is decided by each host's `published` list, so only ICMP needs an exception.
        if exc.get("proto") != "icmp":
            problems.append(f"{label}: only icmp can be an exception (TCP is what `published` decides)")
        if not exc.get("why"):
            problems.append(f"{label}: no why")
    # Some of it is decided by the topology: everything on the segment is a CDE system, and
    # everything that filters traffic is in scope, whatever the register says.
    on_segment = segment_members(inv, scope.get("segment"))
    if not on_segment:
        problems.append(f"scope: no host is on segment {scope.get('segment')}")
    for name in on_segment:
        if (systems.get(name) or {}).get("category") != "cde":
            problems.append(f"scope: {name} is on {scope.get('segment')}, so it must be in systems as cde")
    filters = [*inv.firewalls, *(r for r, v in inv.routers.items() if "wan_filter" in v)]
    for name in filters:
        if name not in systems:
            problems.append(f"scope: {name} filters traffic into the segment, so it must be in systems")
    return problems


def monitoring_problems(inv: Inventory) -> list[str]:
    """The NOC's checks can only be generated from what the inventory really has (decisions 0018, 0019)."""
    mon, logs = inv.monitoring, inv.logging
    if not mon:
        return []
    problems = []
    if mon.get("host") not in inv.hosts:
        problems.append(f"monitoring: host {mon.get('host')!r} is not a host")
    # A floating tag (or none) lets an upgrade in without a commit; the selection records name a version.
    for name, image in (mon.get("images") or {}).items():
        if not re.fullmatch(r"[a-z0-9./_-]+:v?\d[\w.-]*", str(image)):
            problems.append(f"monitoring: image {name} {image!r} needs a pinned version tag")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str((mon.get("digests") or {}).get(name))):
            problems.append(f"monitoring: image {name} has no digest (sha256:...) under digests")
    path = mon.get("alert_path") or {}
    for key, value in (("interval", mon.get("interval")), ("reboot_window", mon.get("reboot_window")),
                       ("group_wait", mon.get("group_wait")), ("group_interval", mon.get("group_interval")),
                       ("heartbeat", logs.get("heartbeat")), ("silent_after", logs.get("silent_after")),
                       ("alert_path every", path.get("every")), ("alert_path silent_after", path.get("silent_after"))):
        if not (isinstance(value, int) and value > 0):
            problems.append(f"monitoring: {key} {value!r} must be a whole number of seconds")
    # Unattended jobs (decision 0022): each name is a pushgateway group and a JobMissed rule.
    names = [j.get("name") for j in mon.get("jobs") or []]
    for j in mon.get("jobs") or []:
        if not re.fullmatch(r"[a-z][a-z0-9-]*", str(j.get("name"))) or names.count(j.get("name")) > 1:
            problems.append(f"monitoring: job name {j.get('name')!r} must be unique, lower case letters, digits and -")
        if not all(isinstance(j.get(k), int) and j[k] > 0 for k in ("every", "grace")):
            problems.append(f"monitoring: job {j.get('name')}: every and grace must be whole numbers of seconds")
    for check in mon.get("web") or []:
        host = inv.hosts.get(check.get("host"), {})
        if check.get("port") not in host.get("services", []):
            problems.append(f"monitoring: web check {check.get('host')}:{check.get('port')} has no listener in services")
    if problems:
        return problems
    # A source is silent when its last line is older than silent_after. Shorter than the heartbeat plus two
    # scrapes and a healthy source would trip it. NOT-3's bound is twice the heartbeat, and the alert needs
    # up to three intervals, Alertmanager's group_wait and a second on top of silent_after to reach the pager.
    beat, silent, interval, wait = logs["heartbeat"], logs["silent_after"], mon["interval"], mon["group_wait"]
    if not beat + 2 * interval < silent <= 2 * beat - 3 * interval - wait - 1:
        problems.append(f"logging: silent_after {silent} must be over heartbeat + 2 x interval ({beat + 2 * interval}) "
                        f"and at most twice the heartbeat less 3 x interval, group_wait and 1 s ({2 * beat - 3 * interval - wait - 1})")
    # Watchdog's mail goes out on Alertmanager's flushes, group_interval apart, so its period is a whole
    # number of them; one late mail must not page.
    if path["every"] % mon["group_interval"]:
        problems.append(f"monitoring: alert_path every {path['every']} must be a multiple of group_interval "
                        f"({mon['group_interval']}), since Alertmanager sends only on a flush")
    if not path["silent_after"] > 2 * path["every"] + interval:
        problems.append(f"monitoring: alert_path silent_after {path['silent_after']} must be over twice its every "
                        f"plus one interval ({2 * path['every'] + interval})")
    for app in logs.get("apps") or []:
        label = f"logging: app {app.get('host')}/{app.get('name')}"
        if app.get("port") not in inv.hosts.get(app.get("host"), {}).get("services", []):
            problems.append(f"{label}: port {app.get('port')} has no listener in services")
        checked = any((w.get("host"), w.get("port")) == (app.get("host"), app.get("port")) for w in mon.get("web") or [])
        for kind in app.get("cut") or []:
            if kind != "web-check":
                problems.append(f"{label}: cut {kind!r} is not a kind netlab knows (web-check)")
            elif not checked:
                problems.append(f"{label}: cut web-check, but no web check watches {app.get('host')}:{app.get('port')}")
        if app.get("cut"):
            # Its forwarder sends one count line per heartbeat's worth of the checks it cuts: syslog's margin.
            if not (isinstance(app.get("silent_after"), int) and beat + 2 * interval < app["silent_after"] <= 2 * beat - 3 * interval - 1):
                problems.append(f"{label}: with a cut, its normal gap is the heartbeat, so silent_after must be over "
                                f"{beat + 2 * interval} and at most {2 * beat - 3 * interval - 1}")
        # Otherwise its normal gap is the web check's interval, so the same margin applies.
        elif not (isinstance(app.get("silent_after"), int) and app["silent_after"] > 3 * interval):
            problems.append(f"{label}: silent_after must be over 3 x interval ({3 * interval})")
    return problems + budget_problems(inv)


def budget_problems(inv: Inventory) -> list[str]:
    """Every source has a daily ingest budget, and all of them together, for the whole retention, fit the
    disk the NOC sets aside for raw lines (OROS NOT-5, decision 0026)."""
    logs = inv.logging
    budget = logs.get("budget")
    if not budget:
        return ["logging: no budget (store_mb, syslog_kb): every source needs an ingest budget"]
    problems = [f"logging: budget {k} {budget.get(k)!r} must be a whole number over 0" for k in ("store_mb", "syslog_kb")
                if not (isinstance(budget.get(k), int) and budget[k] > 0)]
    problems += [f"logging: app {a.get('host')}/{a.get('name')} needs a budget_kb over 0" for a in logs.get("apps") or []
                 if not (isinstance(a.get("budget_kb"), int) and a["budget_kb"] > 0)]
    if problems:
        return problems
    from . import access, nat  # they import this module, so not at the top
    from .monitoring import ingest_sources
    sources = ingest_sources(inv)
    # The translation log and the command records take their budget from nat_kb and accounting_kb.
    problems = [f"logging: {s['node']}/{s['source']} needs a budget: set logging.budget.{s['source']}_kb over 0"
                for s in sources if s["source"] in (nat.SOURCE, access.SOURCE) and s["budget"] <= 0]
    if problems:
        return problems
    daily_kb = sum(s["budget"] for s in sources) // 1024
    days = logs["retention"] / 24
    if daily_kb * days > budget["store_mb"] * 1024:
        problems.append(f"logging: the sources' budgets ({daily_kb} KB a day) for {days:g} days of retention need "
                        f"{daily_kb * days / 1024:.0f} MB, over store_mb {budget['store_mb']}")
    return problems
