"""Load the inventory and catch addressing mistakes before anything is deployed."""
from __future__ import annotations

import ipaddress
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
    # Some of it is decided by the topology: everything on the segment is a CDE system, and
    # everything that filters traffic is in scope, whatever the register says.
    hosts = [h for h, v in inv.hosts.items() if v.get("segment") == scope.get("segment")]
    if not hosts:
        problems.append(f"scope: no host is on segment {scope.get('segment')}")
    on_segment = hosts + [remote.device for h in hosts for _, remote in inv.neighbors(h)]
    for name in on_segment:
        if (systems.get(name) or {}).get("category") != "cde":
            problems.append(f"scope: {name} is on {scope.get('segment')}, so it must be in systems as cde")
    filters = [*inv.firewalls, *(r for r, v in inv.routers.items() if "wan_filter" in v)]
    for name in filters:
        if name not in systems:
            problems.append(f"scope: {name} filters traffic into the segment, so it must be in systems")
    return problems
