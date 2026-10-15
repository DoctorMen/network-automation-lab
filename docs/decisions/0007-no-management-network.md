---
id: "0007"
title: Run every node without a management network
date: 2026-10-11
status: accepted
decider: DoctorMen
constraint: Containerlab puts every node's eth0 on a Docker management network by default, and FRR gives the kernel default route that comes with it distance 0
alternatives:
  - name: do nothing
    why_not: the Docker default route beats the OSPF default (distance 110), so internet-bound traffic leaves through Docker instead of the ISP (CI run 38159498719 failed its live tests on this)
  - name: keep eth0 but delete its default route in an exec step
    why_not: one more startup step that races the daemons, and the route is back after any container restart
  - name: a management VRF
    why_not: the production answer, but much more to build and explain for a lab that is reached with docker exec anyway
sources:
  - https://containerlab.dev/manual/nodes/#network-mode (network-mode none)
  - https://containerlab.dev/manual/network/ (every node is connected to the management network by default)
  - https://docs.frrouting.org/en/stable-8.4/zebra.html#administrative-distance (kernel routes have distance 0)
stake: nodes can't be reached over IP from the host (no SSH, SNMP or scrapes over a management LAN); every tool has to use docker exec or sit inside the lab
---

## Context

The first CI run (38159498719, 2026-10-11) failed its live tests. Commit ed58c1e gives the cause: on Containerlab, eth0 carried a kernel default route that beat the OSPF default from the edge. Reproduced on 2026-10-15 in a throwaway FRR 8.4.1 container on Docker's bridge: `show ip route 0.0.0.0/0` says `Known via "kernel", distance 0, metric 0, best` via 172.17.0.1. In the lab, r1 shows `Known via "ospf", distance 110`.

## Decision

`network-mode: none` in the topology defaults (commit ed58c1e). Nodes have only their lab links. Tests and Ansible reach them with `docker exec`.

## Consequences

- `test_default_route_reaches_core_via_ospf` checks the selected default route, not just that one exists.
- Anything that wants to reach a node over IP (monitoring, SSH) needs an in-band host in the lab.
- Logged as V-001 in [docs/verdicts.yml](../verdicts.yml).
