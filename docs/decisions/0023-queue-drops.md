---
id: "0023"
title: Count every queue's drops at the NOC, and tell a ping rate limit from loss on the path
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS FND-1: collect per-queue drop counters wherever the platform has them, so a burst shorter than the polling interval is still seen; trace a microburst that a 5-minute average hides to its queue or interface; never report a hop that only rate-limits ICMP as path loss, while injected loss is; the lab's only shaped port is h2's (HTB, decision 0011); no new image; free"
alternatives:
  - name: do nothing
    why_not: A burst into h2's bulk class drops packets that no NOC graph, ping or interface counter shows. The test holds h2 eth1's own drop counter at 0 and its 5-minute average under 5% of the link while the queue drops what the burst lost (1902 packets in one run here)
  - name: alert on the interface drop counters (node_network_transmit_drop_total)
    why_not: They count drops in the driver after the queue, and a veth's only when its peer refuses a packet. A queue's drops never reach them (V-025)
  - name: poll faster to see the burst
    why_not: The burst in the test lasts about 10 ms. No scrape interval catches it as a rate; a counter that counts every drop does
  - name: a per-class exporter for HTB (tc -s class, scraped)
    why_not: No exporter in the pinned set reads classes, and one written here is one more service on the payments server. The root qdisc's drops page; which class dropped is one `tc -s class show` on h2 (docs/runbooks/hidden-loss.md)
sources:
  - https://github.com/prometheus/node_exporter/blob/v1.8.2/collector/qdisc_linux.go (the qdisc collector reports each interface's root qdisc only)
  - https://man7.org/linux/man-pages/man8/tc-htb.8.html (HTB's classes, and the default leaf queue each one gets)
  - https://www.kernel.org/doc/html/latest/networking/statistics.html (what the interface counters count, and that a queue's drops are not among them)
stake: Users see slow pages and retransmits while every graph says the link is idle, and the team chases the application or the carrier for a fault that is our own queue
failure_modes:
  - mode: a burst between two scrapes overflows h2's queue and nothing shows it
    mitigation: node_exporter's qdisc collector on h2 and on every router we own; QueueDrops pages on any increase of a queue's drop counter in the last minute
    test: tests/live/observe/test_loss.py::test_a_microburst_the_average_hides_is_traced_to_its_queue
  - mode: the page names the port but not the class
    mitigation: The runbook reads `tc -s class show` on the server; the test checks the bulk class took every drop and the web class none
    test: tests/live/observe/test_loss.py::test_a_microburst_the_average_hides_is_traced_to_its_queue
  - mode: a router that rate-limits pings to itself is blamed for loss
    mitigation: make locate counts loss only where it starts at a hop and carries on to the destination
    test: tests/live/test_locate.py::test_a_hop_that_rate_limits_pings_is_not_loss_while_real_loss_is_placed
  - mode: loss is injected with netem as OROS asks, and this kernel has no netem
    mitigation: The loss is injected with iptables' statistic match (random drop of 20% of ICMP), which drops packets the same way to a ping; the difference is stated in docs/LAB_PARITY.md
    test: tests/live/test_locate.py::test_carrier_loss_is_placed_on_the_carrier
  - mode: a router's own queue drops packets
    mitigation: Each router's veth ports run noqueue, so there is no queue to drop in; their drops would show in node_network_transmit_drop_total. The router's qdisc collector is on anyway, so a queue added later pages
    test: tests/test_monitoring.py::test_queue_drop_rule_for_every_node_with_a_node_exporter
---

## Context

h2's port is shaped with HTB at 20 Mbit (decision 0011), with web replies in their own class and everything else in a 5 Mbit bulk class that may borrow up to the link's rate. Each class has the default leaf queue, a FIFO of 1000 packets. The NOC scraped only the routers' interface counters, which a queue's drops never reach, and a burst of a few milliseconds is invisible in any rate. The routers' ports are veth pairs with no queue (noqueue).

## Decision

- h2, the one server we own, gets its own node_exporter sidecar listening on h2's address, with only the netdev and qdisc collectors. h2 sets `net.ipv4.ip_nonlocal_bind`, as the routers do, because the exporter starts before the exec step adds the address. The routers' node_exporter adds the qdisc collector.
- One QueueDrops rule per node with a node_exporter: `increase(node_qdisc_drops_total{node="X"}[1m]) > 0`, `for: 0s`. A drop is already a settled fact, and the counter counts every one, however short the burst.
- `make locate` keeps its rule that loss counts only where it starts and carries on to the destination; a live test now shows it with a hop that answers 10 pings a second while the carrier link loses 20%.
- docs/runbooks/hidden-loss.md says how to go from the page to the class, and how to tell a queue's drops from a rate-limited ping.

## Consequences

QueueDrops pages within 17 s of a burst (`for` 0, then up to three 5 s intervals and Alertmanager's group wait), and stays firing for about a minute, until the burst leaves the `increase` window. The value it shows is increase()'s estimate, which extrapolates to the window's edges: 2029 for 1902 drops in one run here. The count to trust is the counter itself, or `tc -s qdisc` on the box. Only the root qdisc is exported, so the class is read on h2. h2, on the toy payments segment, now answers HTTP on port 9100 to the campus; the test shows it closed to h1 and to the internet side (RISK-31). The lab cannot inject loss with netem, so iptables' statistic match stands in for it.
