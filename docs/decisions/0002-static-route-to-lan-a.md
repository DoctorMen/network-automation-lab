---
id: "0002"
title: Reach LAN-A with a static route redistributed into OSPF, not OSPF on the firewall
date: 2026-10-11
status: accepted
decider: DoctorMen
constraint: fw1 is a plain Linux node that runs only iptables, and its whole policy should fit in one generated script a reviewer can read top to bottom
alternatives:
  - name: do nothing
    why_not: the core has no route to 10.10.10.0/24, so replies to users die at r1
  - name: run OSPF on fw1
    why_not: puts a routing daemon on the security device, and a misconfigured or compromised firewall could then inject routes into the core
  - name: NAT LAN-A behind fw1's outside address
    why_not: hides which user did what from the servers and their logs, and a private campus doesn't need it
sources:
  - https://docs.frrouting.org/en/stable-8.4/static.html (ip route NETWORK GATEWAY)
  - https://docs.frrouting.org/en/stable-8.4/ospfd.html (redistribute static)
stake: the static route doesn't follow fw1's health; if fw1 hangs with its link up, r1 keeps sending LAN-A traffic into it (with one firewall there is no other path anyway)
---

## Context

LAN-A (10.10.10.0/24) sits behind fw1, which connects to r1 on a /30. The core needs a route to LAN-A, and someone has to decide whether the firewall takes part in routing.

## Decision

r1 carries `ip route 10.10.10.0/24 10.0.100.2` and redistributes it into OSPF (`static_routes` with `redistribute: true` in the inventory). fw1 has a single default route to r1. The firewall stays out of the routing protocol. That is the owner's judgement for a security device, not something the sources above say.

## Consequences

- The firewall's job is filtering only, and its config is one iptables script.
- A second subnet behind fw1 needs a second static route in the inventory.
- The r1 to fw1 link is not an OSPF adjacency, and `test_core_router_runs_ospf_on_router_links_only` checks that it stays that way.
