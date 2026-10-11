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


def validate(inv: Inventory) -> list[str]:
    problems: list[str] = []
    known = set(inv.devices)

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

    return problems
