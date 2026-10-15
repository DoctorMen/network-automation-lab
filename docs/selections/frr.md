---
kind: selection
id: frr
title: FRR for every router in the lab
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "No money and no vendor account: the image must pull anonymously in CI and run as a container on a 4-CPU GitHub runner; it must speak OSPF, BGP and BFD; its running config must be readable as text, so `make drift` can diff it; one person maintains the lab"
choice: frrouting/frr:v8.4.1, pinned by digest in inventory/network.yml
uses: [frrouting/frr]
alternatives:
  - name: vendor images (Cisco IOL or XRd, Arista cEOS)
    why_not: Each is downloaded behind a vendor login or licence, so CI can't pull it from a public registry and nobody can re-run the lab cold
  - name: BIRD
    why_not: Routes well, but keeps no running config apart from its file, so the drift check (running against intended, through frr-reload.py) would have to be rebuilt around a different model
  - name: VyOS
    why_not: Its routing is FRR underneath, with a second config layer on top to learn and to diff
  - name: no purchase, plain Linux static routes
    why_not: Free and already in every image, but no OSPF, BGP or BFD, so the failover, BFD and carrier drills could not exist
no_purchase: Linux static routes (`ip route`) cost nothing and need no new software, and they are what the hosts use. They can't reroute around a failure, which is the thing the lab exists to test.
staffing: "k alone. vtysh reads like Cisco IOS, so existing skills carry over: nothing to hire, retask or buy. Help, if needed, is FRR's public issue tracker and mailing list, free."
vendor_domains: [frrouting.org, github.com/frrouting]
independent_sources:
  - "tests/live/test_failover.py::test_silent_failure_reroutes_fast (our measurement on this image: BFD reroutes a silent link failure in about 0.9 s, against 35.6 to 39.7 s for OSPF alone)"
  - "docs/sizing/data/2026-10-15-github-runner.json (our measurement: all 7 nodes in 90.5 MiB on a GitHub runner)"
  - "tests/live/test_platform.py::test_running_version_matches_inventory (every CI run checks the image still reports the FRR, Alpine and BusyBox versions the inventory records)"
  - "https://containerlab.dev/lab-examples/frr01 (Containerlab, a separate project, ships an FRR OSPF lab as an example)"
  - "https://en.wikipedia.org/wiki/FRRouting (an encyclopedia entry: a GPLv2 fork of Quagga with OSPF, BGP and BFD among its protocols)"
---

## Context

The lab needs real routing protocols that anyone can run for free, in CI and on a laptop, from a public image.

## Decision

FRR 8.4.1 on all four routers, from the public `frrouting/frr` image, pinned by digest.

## Consequences

The image is Alpine 3.15.6, which left security support on 2023-11-01 (accepted as RISK-5 in docs/risks.yml). FRR prints BGP passwords in clear in its running config, which decision 0016 works around.
