---
kind: selection
id: containerlab
title: Containerlab to stand the lab up
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "Headless and scriptable on a GitHub ubuntu-24.04 runner inside a 20-minute job; free; the topology is a text file netlab can generate from the inventory; point-to-point links between containers without a management network (decision 0007)"
choice: Containerlab 0.68.0, installed by its install script in CI
uses: [containerlab]
alternatives:
  - name: docker compose plus scripts
    why_not: Compose gives every container a bridge network, not point-to-point links, so the veth pairs and their names would be ours to script and maintain
  - name: GNS3 or EVE-NG
    why_not: Built around a GUI and a server or VM to run it on; neither fits a headless 20-minute CI job, and EVE-NG's Pro edition is paid
  - name: do nothing (render and unit-test the configs only)
    why_not: No routing protocol would ever run, so none of the live drills (failover, BFD, carrier loss, drift) could prove anything
no_purchase: Docker alone, plus our own script to create the veth links. The lab already does exactly that where Containerlab won't start (a kernel with no /proc/modules, such as the sandbox these records were written in); it works, but then we own the link plumbing.
staffing: k alone; nothing to hire or buy. The topology file is generated, so there is little to learn beyond `deploy` and `destroy`.
vendor_domains: [containerlab.dev, github.com/srl-labs, netdevops.me]
independent_sources:
  - "docs/sizing/data/2026-10-15-github-runner.json (our measurement: the 7-node lab deployed by Containerlab 0.68.0 on a GitHub runner, 90.5 MiB)"
  - "tests/live/test_routing.py::test_ospf_adjacencies_are_full (every CI run deploys with Containerlab and checks the links it made carry OSPF)"
  - "https://netlab.tools/_sources/labs/clab.md.txt (ipSpace's netlab, a separate project, uses Containerlab as one of its lab providers)"
---

## Context

The routers, firewall and hosts are containers. Something has to start them with the right images, binds and point-to-point links, the same way on a laptop and in CI.

## Decision

Containerlab, from a topology file netlab renders. CI installs a pinned version.

## Consequences

Containerlab runs every `linux` node privileged (accepted as RISK-2 in docs/risks.yml). Where it can't run, a short stand-in script that makes the same containers and links is enough to run the tests.
