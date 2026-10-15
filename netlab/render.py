"""Render FRR configs, firewall scripts and the Containerlab topology from the inventory."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .inventory import Inventory, bgp_peer_address, segment_members

ROOT = Path(__file__).resolve().parent.parent


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(ROOT / "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=False,
        keep_trailing_newline=True,
    )


def render_router(inv: Inventory, name: str, env: Environment | None = None) -> dict[str, str]:
    env = env or _env()
    router = inv.routers[name]
    bgp = router.get("bgp", {})
    bgp_neighbors = [
        {**n, "remote_as": inv.asn(n["remote_as"])} for n in bgp.get("neighbors", [])
    ]
    # LANs with hosts behind a router are advertised into OSPF but never form adjacencies.
    passive_lans = [d for d in inv.hosts]
    ctx = dict(
        name=name,
        router=router,
        neighbors=inv.neighbors(name),
        ospf_peers=inv.ospf_neighbors(name),
        passive_lans=passive_lans,
        router_id=str(ipaddress.IPv4Interface(router["loopback"]).ip),
        local_as=inv.asn(bgp["local_as"]) if bgp else None,
        bgp_neighbors=bgp_neighbors,
        rtbh=rtbh_role(inv, name),
    )
    return {
        "frr.conf": env.get_template("frr.conf.j2").render(**ctx),
        "daemons": env.get_template("daemons.j2").render(bgp=bool(bgp), ospf="ospf" in router),
    }


def rtbh_role(inv: Inventory, router: str) -> dict | None:
    """This router's side of the blackhole lever (decision 0012): the customer sends the trigger,
    the provider acts on it."""
    rtbh = inv.raw.get("rtbh")
    if not rtbh or router not in (rtbh["provider"], rtbh["customer"]):
        return None
    role = "provider" if router == rtbh["provider"] else "customer"
    other = rtbh["customer"] if role == "provider" else rtbh["provider"]
    # The provider only blackholes host routes inside what this customer announces.
    aggregate = inv.routers[rtbh["customer"]]["bgp"].get("aggregate")
    return {**rtbh, "role": role, "peer": bgp_peer_address(inv, router, other), "customer_prefix": aggregate}


def rtbh_triggers(inv: Inventory) -> dict | None:
    """The one line an operator adds on the customer router to blackhole each published host
    (docs/runbooks/ddos-rtbh.md). Its next hop is the host's own gateway, not Null0, so the campus
    keeps reaching the host; only the ISP drops it."""
    rtbh = inv.raw.get("rtbh")
    if not rtbh:
        return None
    triggers = {h: f"ip route {v['address'].split('/')[0]}/32 {v['gateway']} tag {rtbh['tag']}"
                for h, v in inv.hosts.items() if v.get("published")}
    # What the customer announces normally; a trigger is the only more-specific the provider should see.
    aggregate = inv.routers[rtbh["customer"]]["bgp"].get("aggregate")
    return {**rtbh, "aggregate": aggregate, "triggers": triggers}


def render_firewall(inv: Inventory, name: str, env: Environment | None = None) -> str:
    env = env or _env()
    inside = str(ipaddress.IPv4Interface(inv.firewalls[name]["inside"]["address"]).network)
    return env.get_template("firewall.sh.j2").render(name=name, fw=inv.firewalls[name], inside_net=inside)


def rp_filter_interfaces(inv: Inventory, router: str) -> list[str]:
    """Interfaces toward a host LAN. Each LAN sits behind one router interface, so strict reverse-path
    filtering there can't drop real traffic (RFC 3704 section 2.2), only forged sources."""
    return [local.interface for local, remote in inv.neighbors(router) if remote.device in inv.hosts]


def wan_filter(inv: Inventory, router: str) -> dict | None:
    """What the router lets in on its ISP link: BGP from each peer on that link, and every published host port."""
    wan = inv.routers[router].get("wan_filter")
    if not wan:
        return None
    peers = {n["address"] for n in inv.routers[router].get("bgp", {}).get("neighbors", [])}
    bgp = [{"peer": str(remote.address.ip), "local": str(local.address.ip)}
           for local, remote in inv.neighbors(router)
           if local.interface == wan["interface"] and str(remote.address.ip) in peers]
    published = [{"host": h, "address": v["address"].split("/")[0], "port": port}
                 for h, v in inv.hosts.items() for port in v.get("published", [])]
    return {**wan, "bgp": bgp, "published": published}


def render_edge(inv: Inventory, name: str, env: Environment | None = None) -> str | None:
    """build/<router>/edge.sh: what the router enforces at its edges, beyond routing. None if nothing."""
    env = env or _env()
    rp_filter, wan = rp_filter_interfaces(inv, name), wan_filter(inv, name)
    if not (rp_filter or wan):
        return None
    return env.get_template("edge.sh.j2").render(name=name, rp_filter=rp_filter, wan=wan)


def owned_addresses(inv: Inventory) -> dict[str, list[str]]:
    """Every address (link ends and loopbacks) on each device the operator owns."""
    out = {}
    for d in inv.devices:
        if inv.owner(d) == inv.operator:
            addrs = {str(ep.address.ip) for ep in inv.interfaces(d)}
            if d in inv.routers:
                addrs.add(str(ipaddress.IPv4Interface(inv.routers[d]["loopback"]).ip))
            out[d] = sorted(addrs)
    return out


def segmentation(inv: Inventory) -> list[dict]:
    """The reachability the scope register promises (ATT-1): from every out-of-scope device, each
    device on the segment answers a service only if it is published, and a ping only if the register
    lists that as an exception. `inside` is another device on the segment, which a closed one must answer."""
    scope = inv.raw.get("scope")
    if not scope:
        return []
    members = segment_members(inv, scope["segment"])
    excepted = {(e["src"], e["proto"]) for e in scope.get("exceptions") or []}
    tuples = []
    for src in scope.get("out_of_scope", []):
        for dst, address in members.items():
            host, inside = inv.hosts.get(dst, {}), next(d for d in members if d != dst)
            tuples += [{"src": src, "dst": dst, "address": address, "proto": "tcp", "port": port, "inside": inside,
                        "expect": "open" if port in host.get("published", []) else "closed"}
                       for port in host.get("services", [])]
            tuples.append({"src": src, "dst": dst, "address": address, "proto": "icmp", "inside": inside,
                           "expect": "open" if (src, "icmp") in excepted else "closed"})
    return tuples


def bfd_peers(inv: Inventory, router: str) -> dict[str, str]:
    """BFD runs on every OSPF link (frr.conf.j2), so its peers come from the same links: address -> interface."""
    ospf = inv.ospf_neighbors(router)
    return {str(remote.address.ip): local.interface for local, remote in inv.neighbors(router) if remote.device in ospf}


def expected_state(inv: Inventory) -> dict:
    """What a healthy lab looks like. The live tests compare against this."""
    bgp_sessions = []
    for name, r in inv.routers.items():
        for n in r.get("bgp", {}).get("neighbors", []):
            bgp_sessions.append({"router": name, "peer": n["peer"], "address": n["address"]})
    return {
        "ospf_neighbors": {r: inv.ospf_neighbors(r) for r in inv.routers if inv.ospf_neighbors(r)},
        "bfd_peers": {r: bfd_peers(inv, r) for r in inv.routers if inv.ospf_neighbors(r)},
        # Interfaces toward a host LAN, rendered `ip ospf passive` (frr.conf.j2).
        "passive_interfaces": {r: [local.interface for local, remote in inv.neighbors(r) if remote.device in inv.hosts]
                               for r in inv.routers if inv.ospf_neighbors(r)},
        "bgp_sessions": bgp_sessions,
        "loopbacks": {r: str(ipaddress.IPv4Interface(v["loopback"]).ip) for r, v in inv.routers.items()},
        "hosts": {h: v["address"].split("/")[0] for h, v in inv.hosts.items()},
        # Every address on a device we own: what a scan from the internet side has to find closed.
        "addresses": owned_addresses(inv),
        "wan_filter": {r: f for r in inv.routers if (f := wan_filter(inv, r))},
        "rp_filter": {r: ifs for r in inv.routers if (ifs := rp_filter_interfaces(inv, r))},
        "segmentation": segmentation(inv),
        "rtbh": rtbh_triggers(inv),
        "operator": inv.operator,
        "owners": {d: inv.owner(d) for d in inv.devices},
        "platform": inv.platform,
    }


def ansible_inventory(inv: Inventory) -> str:
    """Ansible reaches each node through the Docker connection plugin, no SSH needed."""
    hosts = {
        "routers": {r: {"ansible_host": f"clab-{inv.lab_name}-{r}"} for r in inv.routers},
        "firewalls": {f: {"ansible_host": f"clab-{inv.lab_name}-{f}"} for f in inv.firewalls},
        # Routers with an edge.sh: drift.yml compares their iptables rules the way it does the firewall's.
        "edge_routers": {r: {"ansible_host": f"clab-{inv.lab_name}-{r}", "rules_script": "edge.sh"}
                         for r in inv.routers if render_edge(inv, r)},
    }
    doc = {
        "all": {
            "vars": {"ansible_connection": "community.docker.docker", "ansible_python_interpreter": "/usr/bin/python3"},
            "children": {group: {"hosts": members} for group, members in hosts.items()},
        }
    }
    return "# Generated by netlab.\n" + yaml.safe_dump(doc, sort_keys=False)


def render_all(inv: Inventory, out_dir: str | Path) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    env = _env()
    written: list[Path] = []

    def write(rel: str, text: str) -> None:
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        written.append(p)

    for name in inv.routers:
        for fname, text in render_router(inv, name, env).items():
            write(f"{name}/{fname}", text)
    for name in inv.firewalls:
        write(f"{name}/firewall.sh", render_firewall(inv, name, env))
    edge = {name: script for name in inv.routers if (script := render_edge(inv, name, env))}
    for name, script in edge.items():
        write(f"{name}/edge.sh", script)
    write("vtysh.conf", "service integrated-vtysh-config\n")
    write("topology.clab.yml", env.get_template("topology.clab.yml.j2").render(inv=inv, image=inv.platform["image"], edge=edge))
    write("expected_state.json", json.dumps(expected_state(inv), indent=2) + "\n")
    write("ansible_inventory.yml", ansible_inventory(inv))
    return written
