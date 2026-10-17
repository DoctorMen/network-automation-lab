---
id: "0033"
title: Trace a broadcast storm to its switch port from per-port frame rates before anything is blocked
date: 2026-10-17
status: accepted
decider: DoctorMen
constraint: "OROS CON-1: the containment runbook traces disruptive traffic through aggregation points to a specific port or host within a stated time, and records why it floods. The lab's only aggregation point is sw1, which has no flow export, no SNMP and no exporter; the trace must work from what the switch already counts, read-only, and the storm source must not starve a shared CI runner"
alternatives:
  - name: do nothing
    why_not: A storm on LAN-A would show as every port busy and every host slow; nothing would say which cable to follow
  - name: a packet capture on the switch
    why_not: Capturing a storm at 20k frames a second is the storm again, in a file; the per-port counters already say which port takes frames in and which only send copies out. A capture is the second step, once the port is known
  - name: an exporter on sw1 and a Prometheus rate rule
    why_not: Right for a real network (node_exporter's netdev on the switch), and the natural next step; but CON-1 asks for the trace, not the alert, and the trace reads the same counters the exporter would, without a fourth sidecar on the lab job's network-only lab
  - name: an unthrottled storm source
    why_not: A plain AF_PACKET loop reached about 400k frames a second here; on a shared runner that starves OSPF, BGP and the other tests. The source is capped at 20k a second and stops by itself
sources:
  - https://www.kernel.org/doc/html/latest/networking/statistics.html (interface rx and tx packet counters, as `ip -s link` reads them)
  - https://www.rfc-editor.org/rfc/rfc2863 (ifInUcastPkts and the interface counters a switch exports; here read locally)
stake: A storm that can't be traced gets contained by shutting ports until it stops, which is the outage, not the fix
failure_modes:
  - mode: the trace names a port that only carries copies out
    mitigation: "Only inbound frames count; every port but the source carries the storm out, and the source alone takes it in above the threshold (ten times the storm control limit, so a policed port still shows: the counter is before the policer)"
    test: tests/live/test_storm.py::test_storm_traced_to_port
  - mode: the trace names a fixed port, or the wrong host
    mitigation: Run with h3 and then h1 as the source, the answer follows the source, and names the MAC the switch learned there, which is the source's
    test: tests/live/test_storm.py::test_storm_traced_to_port
  - mode: a quiet LAN is reported as a storm
    mitigation: The threshold is a rate, read over two seconds; the test asserts no port is over it before and after each storm
    test: tests/live/test_storm.py::test_storm_traced_to_port
  - mode: the trace takes longer than the stated time
    mitigation: One run is two seconds of counting plus a few docker execs; the test holds it to 60 s against the runbook's 15 minutes
    test: tests/live/test_storm.py::test_storm_traced_to_port
---

## Context

CON-1's Pass line is a lab storm traced to its port within a stated time. With sw1 (decision 0032) LAN-A has three ports and a spare, and a storm from one host reaches the other and the firewall.

## Decision

`make trace` (netlab/trace.py): on every switch we own, read every port's frame counters twice (`ip -s -j link show`), two seconds apart, and name each port whose inbound rate is over the threshold (ten times the storm control limit, 1000 a second with none), with its far end and role from the inventory, the MACs learned on it (`bridge fdb show`) and how many frames its storm control has dropped (`ebtables -t nat -L PREROUTING --Lc`). It says why every port sees the frames: a broadcast is flooded to every port of its VLAN by design. The runbook (docs/runbooks/broadcast-storm.md) states 15 minutes to a port; the tool takes seconds. The storm source for the tests (tests/live/tools/storm.py) sends broadcast ARP at a capped 20k frames a second and stops by itself.

## Consequences

The trace is on demand, not an alert: nothing pages on a storm (the natural next step is node_exporter on sw1 and a rate rule; RISK-65). It reads the switch; a storm from behind the uplink would be traced to the uplink, which is correct and the end of what this switch can say. There is no NAT, load balancer or shared server to trace through.
