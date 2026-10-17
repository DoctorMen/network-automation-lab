---
id: "0034"
title: Broadcast storm control per switch port, policed once where the frames come in, that drops only the excess and keeps the port up
date: 2026-10-17
status: accepted
decider: DoctorMen
constraint: "OROS CON-2: containment drops or rate-limits only the excess, per port, is reversible, and never err-disables or shuts a shared port; during a lab broadcast storm the port stays up and the other hosts on the VLAN keep their service level. The switch is a Linux bridge in the one pinned image: ebtables (the nf_tables build) is there, tc police and flower are not in the sandbox kernel"
alternatives:
  - name: do nothing
    why_not: A broadcast storm from one user reaches every port of the VLAN at the source's rate; the only lever left is shutting the port, which CON-2 forbids
  - name: an ebtables limit in the FORWARD chain
    why_not: Measured on a throwaway bridge with three ports, 1,000 frames from one port under a FORWARD limit of 10/s were evaluated 2,000 times (one per flooded copy), so one token bucket was spent across every egress port and each other host got about limit divided by the number of ports; nat PREROUTING saw each frame once, 10 accepted and 990 dropped. Storm control polices the ingress frame
  - name: tc ingress police on the port
    why_not: The right tool on a kernel that has it; this sandbox kernel has no police action or flower classifier (`tc filter add ... police` fails), and the runner's was not checked. ebtables works in both, and is what the firewall's drift check already understands (iptables family)
  - name: shut the port, or bridge link set ... flood off
    why_not: Shutting is what the requirement rules out; `flood off` stops unknown-unicast and broadcast flooding to that port entirely, so the host behind it loses ARP, not just the excess
sources:
  - https://ebtables.netfilter.org/documentation/bridge-nf.html (where the bridge's nat PREROUTING and FORWARD chains run: once per ingress frame, once per forwarded copy)
  - https://man7.org/linux/man-pages/man8/ebtables-nft.8.html (--limit, --limit-burst, the nat table's PREROUTING chain)
stake: Containment that shuts the port takes the user down with the storm, and a limit shared across every egress port changes what each host gets every time a port is added
failure_modes:
  - mode: the limit shuts the port or blocks the host's own traffic
    mitigation: Only frames to ff:ff:ff:ff:ff:ff above the limit are dropped; the port's state and unicast are untouched, and the test checks both under the storm
    test: tests/live/test_storm.py::test_storm_contained_not_shut
  - mode: the other hosts lose their service level anyway
    mitigation: h1 receives at most about the limit while h3 floods, and fetches h2's page during it
    test: tests/live/test_storm.py::test_storm_contained_not_shut
  - mode: the policer is there but the storm never was
    mitigation: The test first releases the port's rules and shows h1 receiving far more than the limit, then puts them back
    test: tests/live/test_storm.py::test_storm_contained_not_shut
  - mode: it can't be undone, or undoing it takes the rest down
    mitigation: make release PORT=sw1:eth3 deletes that port's two rules and nothing else; make contain adds exactly what switch.sh renders
    test: tests/test_switch.py::test_switch_renders_a_vlan_bridge_with_storm_control_on_edge_ports
  - mode: the limit is on the wrong ports
    mitigation: Rendered for edge ports only; the uplink carries the gateway's own broadcasts and is never policed
    test: tests/test_switch.py::test_switch_renders_a_vlan_bridge_with_storm_control_on_edge_ports
  - mode: multicast or unknown-unicast floods are not policed
    mitigation: Accepted. Broadcast only, which is the lab storm; a real switch's storm control covers all three
    test: none (accepted risk RISK-68 in docs/risks.yml)
---

## Context

With sw1 and a traceable storm (decisions 0032 and 0033), CON-2 asks that the storm be contained at its port without shutting the port, and without the other users noticing.

## Decision

`storm_control: {broadcast_pps: 100}` on sw1 in the inventory renders, in switch.sh, for every edge port:
`ebtables -t nat -A PREROUTING -i <port> -d ff:ff:ff:ff:ff:ff --limit 100/sec --limit-burst 100 -j ACCEPT` followed by the same match `-j DROP`. The nat table's PREROUTING chain runs once per frame as it comes in, before the bridge floods it, so each port has its own bucket and the other ports get at most the limit from it. `make release PORT=sw1:eth3` and `make contain PORT=sw1:eth3` (netlab/switch.py) delete and add one port's two rules. `make trace` shows each port's drop count.

## Consequences

The port stays up and forwarding; the flooding host's unicast still works; the others see at most about the limit (measured here: 20k frames a second in, about 100 a second out to h1). The rules are intent set at deploy and not read back by `make drift` (RISK-65); on a kernel with tc police the same limit could move to the port's ingress qdisc. On this sandbox kernel ebtables is the nf_tables build (xtables-nft-multi) and its counters are read with `--Lc`.
