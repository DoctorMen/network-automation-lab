---
id: "0024"
title: Write down what every metric counts, check it against bytes sent on purpose, and never let a rule read a counter raw
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS DEC-2: every metric, counter or log field used for alerting documents what it counts, with its known artifacts (wraps, resets, discontinuities, double counting); the pipeline flags a discontinuity instead of graphing it as a spike; a known byte count through each interface type in use matches the graph within 5%, and an agent restart or a 32-bit wrap raises no spike alert; the lab's interfaces are all veth pairs; free"
alternatives:
  - name: do nothing
    why_not: The names mislead. frr_exporter's prefix counts end in _total and are gauges; node_exporter's netstat counters are exported untyped; a veth's byte counters include the Ethernet header; a queue's drops are in no interface counter
  - name: a wiki page of metric notes
    why_not: Nothing would fail when a metric is added without one, or when a rule starts reading a counter raw. monitoring/coverage.yml is already linted by make test
  - name: alert on raw counter values or their difference
    why_not: A reset (an interface or qdisc recreated) or a 32-bit wrap is a fall of the value; a rule on the difference pages on it, and a graph of it shows a cliff. increase(), rate() and irate() treat any fall as a reset and count from the new value
  - name: check against SNMP ifHCInOctets the way a real NOC would
    why_not: No node runs an SNMP agent, and adding one is an image change. node_exporter reads the same kernel counters
sources:
  - https://prometheus.io/docs/prometheus/2.53/querying/functions/#increase (increase and rate adjust for counter resets, and extrapolate to the window's edges)
  - https://www.kernel.org/doc/html/latest/networking/statistics.html (rtnl_link_stats64: the 64-bit interface counters, and where each is counted)
  - https://github.com/prometheus/node_exporter/blob/v1.8.2/collector/netstat_linux.go (netstat values are exported as untyped)
  - https://man7.org/linux/man-pages/man7/udp.7.html (ENOBUFS and the send-buffer errors counter)
stake: An engineer reads a counter as something it isn't, and a reset or a wrap pages the shift for a spike that never happened
failure_modes:
  - mode: a metric is collected with no note of what it counts
    mitigation: Every metric any collector in monitoring/coverage.yml lists has a counts entry; make test fails on one without
    test: tests/test_coverage.py::test_every_metric_says_what_it_counts
  - mode: a counter's note leaves out when it wraps or resets
    mitigation: The lint requires both for every counter
    test: tests/test_coverage.py::test_every_metric_says_what_it_counts
  - mode: an alert rule reads a counter raw, so a reset or a wrap pages
    mitigation: The lint fails a rule that reads a counter outside increase(), rate(), irate() or resets()
    test: tests/test_coverage.py::test_a_rule_reading_a_counter_raw_fails
  - mode: the note says counter or gauge and the exporter says otherwise
    mitigation: Checked against the TYPE lines Prometheus read from the exporters
    test: tests/live/observe/test_loss.py::test_each_metric_is_the_type_its_exporter_declares
  - mode: the interface counters don't match the traffic
    mitigation: 4000 datagrams of 100 bytes from h1 to the carrier's address; r1's receive and r2's transmit counters, as Prometheus stored them, each within 5% of the bytes on the wire (+0.03% in one run here)
    test: tests/live/observe/test_loss.py::test_a_known_byte_count_matches_the_counters_across_an_exporter_restart
  - mode: the note on a byte counter says the wrong thing about headers, or about before and after the queue
    mitigation: The same count within 1%, where the Ethernet header is 9.9% of each frame and a checksum would be 2.8%; and h2 eth1's transmit bytes across a burst are at least what arrived and less than what the queue was offered
    test: tests/live/observe/test_loss.py::test_a_microburst_the_average_hides_is_traced_to_its_queue
  - mode: an exporter restart shows as a reset or pages
    mitigation: The counters are the kernel's, so a node_exporter restart is only a scrape gap; resets() stays 0 across it and TargetDown's 15 s `for` outlasts it
    test: tests/live/observe/test_loss.py::test_a_known_byte_count_matches_the_counters_across_an_exporter_restart
  - mode: a counter reset, or a 32-bit wrap, pages as a spike
    mitigation: Rules read counters through increase() only. A replaced queue's counters fall to 0, resets() flags it, rate() stays at 0 and QueueDrops stays quiet. A wrap of the 32-bit queue drop counter is the same fall
    test: tests/live/observe/test_loss.py::test_a_reset_queue_counter_is_flagged_and_pages_nobody
  - mode: the 32-bit queue drop counter wraps past 4294967295
    mitigation: increase() reads the wrap as a reset. promtool, in the pinned Prometheus image, runs the rendered QueueDrops rule over a made-up counter that wraps after 14 drops; the rule shows 13 at most, never a jump of about 4.29e9, and the alert clears once the wrap leaves its window. The 64-bit interface counters never wrap in a lab's life
    test: tests/live/observe/test_loss.py::test_a_32_bit_wrap_of_the_queue_counter_shows_no_spike
---

## Context

The NOC alerts on node_exporter's interface and queue counters, frr_exporter's state gauges, blackbox's probe results and the collector's last-seen time. Some names mislead, the netstat collector declares no type, and nothing checked a counter against traffic of a known size. The lab's interfaces are all veth pairs: no physical port, no LAG and no sub-interface exists to test.

## Decision

- monitoring/coverage.yml gets a `counts:` entry for every metric a collector lists: what one unit is, counter or gauge, and for interface and queue counters the direction and where they count (before or after the queue). Each counter says when it wraps and when it resets, and names the live test that checks it where there is one. `make coverage` fails on a missing entry, a counter without its wrap or reset, a counter a rule reads raw, and a proof that doesn't exist.
- The known-byte test sends paced UDP from h1 to the carrier's loopback, counts what arrives there, and compares r1's receive and r2's transmit counters against the arrivals times payload plus 42 bytes of UDP, IP and Ethernet headers. The payloads are 100 bytes, so the Ethernet header alone is 9.9% of a frame: the 5% check is OROS's tolerance, and a 1% check tells whether the header is counted. r2's node_exporter is restarted in the middle.
- A discontinuity is flagged with resets(), and no rule can read a counter without increase(), rate(), irate() or resets(). The reset test makes one by replacing h2's queue.

## Consequences

Two pieces of normal behaviour are in docs/verdicts.yml: a queue's drops are in no interface counter (V-025), and a datagram the sender's own queue dropped still counts as sent by send() and as SndbufErrors, not OutDatagrams (V-026). increase() extrapolates to the window's edges, so QueueDrops' value can read higher than the drops counted; the counter itself is exact. The byte test covers veth, the only interface type in the lab; a LAG would need its members and the bundle compared, a sub-interface its parent, and a real NIC's offloads a check of their own. The 32-bit wrap is driven only as a made-up series through promtool, against the real rule; no queue here drops four billion packets. resets() flags a discontinuity when someone queries it; no rule pages on one.
