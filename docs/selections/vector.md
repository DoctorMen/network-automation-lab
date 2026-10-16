---
kind: selection
id: vector
title: Vector as the NOC's collector and h2's unprivileged log forwarder
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "Free, one small static binary in a public image; take busybox syslogd's UDP lines as sent (they carry no hostname) and name each by its source address; follow an app's log file without root and without changing the app; turn every source's arrival into a last-seen metric the alert reads (OROS NOT-3), counted at the collector, not at the sender; one person runs it"
choice: timberio/vector:0.40.1-alpine twice, as the collector on noc (UDP 514 and TCP 6000 in, Loki and a Prometheus endpoint out) and as h2's forwarder (uid 65534, reading /applog read-only)
uses: [timberio/vector]
alternatives:
  - name: rsyslog or syslog-ng as the collector
    why_not: Both receive syslog well, but neither exposes a per-source last-seen metric without plugins and scripts of our own, and pushing to Loki needs another module
  - name: Promtail (Loki's own agent) for h2's file
    why_not: Would do the file, but not the collector's syslog-to-metric job; two tools for one pipeline, and Grafana now steers new users to Alloy instead
  - name: Grafana Alloy
    why_not: Does both, but a larger image and a config language of its own; Vector's remap language and log_to_metric cover what is needed here
  - name: no purchase, busybox syslogd -R straight to a file on noc
    why_not: Free and already in every image, but no per-source arrival metric, so a silent source is noticed only when someone looks
no_purchase: "busybox syslogd already forwards (-R) and is what every node sends with; the do-nothing collector is a file on noc with no arrival metric. Vector is free (MPL 2.0)."
staffing: "k alone. Both configs are rendered from the inventory (templates/monitoring/); the remap is a few lines of VRL. Help: the project's public issue tracker and discussions, free."
vendor_domains: [vector.dev, datadoghq.com, github.com/vectordotdev]
independent_sources:
  - "tests/live/observe/test_arrival.py::test_blocked_source_raises_source_silent_and_comes_back_without_a_restart (our measurement: with r1's syslog dropped on the way, the collector's last-seen time pages within twice the heartbeat while r1's own counter says it is sending)"
  - "tests/live/observe/test_central_store.py::test_app_log_forwarded_without_root_and_searchable (the forwarder runs as uid 65534 with the log mounted read-only, and h1's request is searchable within seconds)"
  - "https://prometheus.io/docs/instrumenting/exporters/ (Prometheus' list of software exposing Prometheus metrics includes Vector)"
---

## Context

NOT-3 asks for a last-seen check per source at the collector, never the sender's own counters. NOT-7 asks for an app's log forwarded without root, the app untouched.

## Decision

One Vector on noc receives every syslog line (UDP 514) and every forwarder's (TCP 6000), names each by node and source from a map rendered from the inventory, sends it to Loki, and exports log_last_seen_seconds{node,source} for SourceSilent. A second Vector, in h2's network namespace as nobody, follows h2's web server's access log (decision 0019).

## Consequences

The collector's last-seen time is the arrival proof, so it must not be the sender's: Vector stamps it on arrival. Its own Prometheus endpoint keeps a series for a day after its last line (flush_period_secs), so a silent source's age keeps growing instead of the series vanishing. Syslog stays UDP from busybox, with no queue or authentication (accepted as RISK-28 in docs/risks.yml); the forwarder to collector link is plain TCP (RISK-26).
