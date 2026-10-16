"""Source NAT for the users, and the translation log that undoes it (OROS FND-5, decision 0031).

A router's `nat` block in the inventory names the inside networks it translates and the one outside address
the carrier assigned for them. Connections those networks open out of the router's WAN interface (its
wan_filter interface) leave from that address; nothing else is translated. The carrier routes the address
to our end of the link, as a carrier routes any address it assigns (frr.conf.j2).

Each new translation is logged to the NOC by a sidecar in the router's network namespace (conntrack -E,
templates/monitoring/natlog.sh.j2). `holders()` reads those lines back: which inside host held an outside
address and port at a given time, which is what an abuse complaint from outside gives us.
"""
from __future__ import annotations

import ipaddress
import re

from .inventory import Inventory

# The tag every line of the translation log carries, at the collector and in the central store.
SOURCE = "nat"
# The UDP port the translation log is sent from. Below 1024, like the accounting proxy's (netlab/access.py), so
# the collector files under SOURCE only what root in the router's namespace sent, not a line any account forged.
RECORD_PORT = 602
RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
# One `conntrack -E -o timestamp,extended` line for a new translated connection, for example:
# [1760000000.123456]	    [NEW] ipv4     2 tcp      6 120 SYN_SENT src=10.10.10.10 dst=203.0.113.1 sport=41000
# dport=8080 [UNREPLIED] src=203.0.113.1 dst=198.51.100.64 sport=8080 dport=41000
# The first src/dst/sport/dport are the connection as the inside host sent it, the second as the reply
# comes back: its dst and dport are the outside address and port the far end saw.
LINE = re.compile(r"\[(?P<time>\d+\.\d+)\]\s+\[NEW\] ipv4\s+\d+ (?P<proto>\w+)\s+\d+ .*?"
                  r"src=(?P<inside>\S+) dst=(?P<remote>\S+) (?:sport=(?P<inside_port>\d+) dport=(?P<remote_port>\d+) )?"
                  r".*?src=\S+ dst=(?P<outside>\S+)(?: sport=\d+ dport=(?P<outside_port>\d+))?")


def routers(inv: Inventory) -> list[str]:
    return [r for r, v in inv.routers.items() if v.get("nat")]


def config(inv: Inventory, router: str) -> dict | None:
    """{inside, address, interface} for edge.sh, or None if the router translates nothing."""
    nat = inv.routers[router].get("nat")
    if not nat:
        return None
    return {"inside": list(nat["inside"]), "address": nat["address"], "interface": inv.routers[router]["wan_filter"]["interface"]}


def carrier_routes(inv: Inventory, device: str) -> list[dict]:
    """The routes `device` needs because it sits across the WAN link of a router that translates: the outside
    address, to our end of that link."""
    out = []
    for r in routers(inv):
        wan = inv.routers[r]["wan_filter"]["interface"]
        for local, remote in inv.neighbors(r):
            if local.interface == wan and remote.device == device:
                out.append({"customer": r, "prefix": f"{inv.routers[r]['nat']['address']}/32", "next_hop": str(local.address.ip)})
    return out


def expected(inv: Inventory) -> dict:
    """What the live tests read back: each translating router's config and the device that routes its address."""
    out = {}
    for r in routers(inv):
        c = config(inv, r)
        carrier = next(remote.device for local, remote in inv.neighbors(r) if local.interface == c["interface"])
        out[r] = {**c, "carrier": carrier}
    return out


def problems(inv: Inventory) -> list[str]:
    out = []
    used = {str(ep.address.ip) for link in inv.links for ep in (link.a, link.b)}
    used |= {str(ipaddress.IPv4Interface(v["loopback"]).ip) for v in inv.routers.values()}
    lans = {str(link.network) for link in inv.links}
    for r in routers(inv):
        nat, label = inv.routers[r]["nat"], f"{r}: nat"
        if not inv.routers[r].get("wan_filter"):
            out.append(f"{label} needs a wan_filter, whose interface is the one it translates out of")
            continue
        try:
            address = ipaddress.IPv4Address(str(nat.get("address")))
        except ValueError:
            out.append(f"{label}: address {nat.get('address')!r} is not an IPv4 address")
            continue
        if str(address) in used or any(address in link.network for link in inv.links):
            out.append(f"{label}: address {address} is already on a link or a loopback, so its replies would not come back to the NAT")
        if any(address in ipaddress.IPv4Network(n) for n in RFC1918):
            out.append(f"{label}: address {address} is an RFC 1918 address, which a carrier drops as a source (BCP 38)")
        for net in nat.get("inside") or []:
            if str(net) not in lans:
                out.append(f"{label}: inside {net} is not one of the inventory's LANs, so nothing would match it")
        if not nat.get("inside"):
            out.append(f"{label}: inside must list the networks it translates")
        wan = inv.routers[r]["wan_filter"]["interface"]
        across = [remote.device for local, remote in inv.neighbors(r) if local.interface == wan]
        if not across or across[0] not in inv.routers:
            out.append(f"{label}: the device across {wan} must be a router, to route {address} back to us")
    return out


def parse(line: str) -> dict | None:
    """One translation log line as {time, proto, inside, inside_port, remote, remote_port, outside, outside_port},
    or None for anything else (the heartbeat)."""
    m = LINE.search(line)
    if not m:
        return None
    d = m.groupdict()
    return {**d, "time": float(d["time"]),
            **{k: int(d[k]) if d[k] else None for k in ("inside_port", "remote_port", "outside_port")}}


def holders(lines: list[str], address: str, port: int, at: float, remote: str | None = None, skew: float = 0) -> list[dict]:
    """The translations that could be the one a complaint names: outside `address` and `port`, begun at or
    before `at` (or up to `skew` seconds after it), newest first, and if `remote` is given (the complainant's
    own address, or address:port) only to it.

    One outside port can be in use to several far ends at once, so without `remote` more than one inside host
    can match; each is returned, and the caller says so. For each far end only the newest translation counts:
    an older one on the same outside port to the same far end ended before the newer one could begin."""
    far, far_port = (remote.rsplit(":", 1) + [None])[:2] if remote else (None, None)
    found = [t for t in map(parse, lines) if t and t["outside"] == address and t["outside_port"] == port and t["time"] <= at + skew
             and (far is None or t["remote"] == far) and (far_port is None or t["remote_port"] == int(far_port))]
    found.sort(key=lambda t: t["time"], reverse=True)
    newest = {}
    for t in found:
        newest.setdefault((t["remote"], t["remote_port"]), t)
    return sorted(newest.values(), key=lambda t: t["time"], reverse=True)
