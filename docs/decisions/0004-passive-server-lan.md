---
id: "0004"
title: Make host LAN interfaces OSPF passive
date: 2026-10-11
status: accepted
decider: DoctorMen
constraint: the server LAN holds hosts, not routers; its subnet must be in OSPF, but nothing on it should be able to form an adjacency
alternatives:
  - name: do nothing
    why_not: r3 sends hellos onto the server LAN, and any host running an OSPF daemon could form an adjacency and inject routes, a default route included, into the core
  - name: keep the LAN out of OSPF and redistribute connected
    why_not: the subnet becomes an external route, and every router with a LAN needs a redistribute line
  - name: OSPF authentication on the LAN
    why_not: still sends hellos to hosts, and adds keys to manage, when no router should ever live there
sources:
  - https://docs.frrouting.org/en/stable-8.4/ospfd.html (ip ospf passive)
stake: wrong the other way round, a router added to that LAN later won't peer until passive is removed; left active, one rogue host can pull campus traffic towards itself
---

## Context

h2's LAN (10.20.20.0/24) hangs off r3:eth3. The routers need its prefix. Hosts never speak OSPF.

## Decision

`netlab render` marks every interface that faces a host from `hosts:` as `ip ospf passive` in area 0. The subnet is advertised as an internal route, and no hellos are sent there.

## Consequences

- `test_server_lan_is_passive` checks the rendered config.
- A new host LAN is passive automatically, because the rule comes from the inventory's `hosts:` section, not from a per-router list.
