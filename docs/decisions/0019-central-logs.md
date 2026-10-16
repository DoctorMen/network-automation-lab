---
id: "0019"
title: Send every log source's lines to one store on the NOC, and prove each source is still arriving
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "OROS NOT-3 and NOT-7: a last-seen check per source counted at the collector, never the sender's own counters, a synthetic event per source over its real path, and a dead source back without a reboot; one central searchable store for every source, an app whose code and config can't change, forwarded without root, keeping history past the boxes' own rotation; V-005 (router daemons logged nowhere); the router image must not change; free; no secret in any log"
alternatives:
  - name: do nothing
    why_not: Each box keeps its own log (and FRR's daemons, with `log stdout` and -d, kept none, V-005); it rotates away in minutes, dies with the box, and nobody knows when a box stops logging
  - name: FRR `log file` on each router
    why_not: Fixes V-005 on the box only; the file rotates with nothing reading it, and it is one more place to search instead of one
  - name: syslog over TCP or TLS (RFC 5425) from every node
    why_not: busybox syslogd, the only syslog daemon in the image, sends UDP only; anything else is a package added to the router image
  - name: count the sender's sent datagrams as proof it is logging
    why_not: NOT-3 rules it out, and the lab shows why. With r1's syslog dropped on r2, r1's Udp_OutDatagrams keeps rising
  - name: run the forwarder as root, or change the app to log to syslog
    why_not: NOT-7's case is the app nobody may change, on a host without root; a sidecar as nobody reading the file the app already writes is that case
sources:
  - https://www.rfc-editor.org/rfc/rfc5426 (syslog over UDP has no way to detect a lost datagram, and no sender authentication)
  - https://grafana.com/docs/loki/latest/operations/storage/retention/ (retention needs the compactor with retention_enabled)
  - https://docs.frrouting.org/en/stable-8.4/basic.html (`log syslog`)
stake: A router, firewall or server that stopped logging is found during the incident that needed its logs, and the line that explains it rotated off the box hours ago
failure_modes:
  - mode: a source goes silent and nobody notices
    mitigation: SourceSilent per source from the collector's own last-seen time; a heartbeat line every 60 s sets the normal gap, and silent_after 90 s pages within 120 s, twice the gap
    test: tests/live/observe/test_arrival.py::test_blocked_source_raises_source_silent_and_comes_back_without_a_restart
  - mode: the sender's counters say it is sending while nothing arrives
    mitigation: The alert reads only the collector; the test shows r1's sent-datagram counter rising and its on-box log growing while SourceSilent pages
    test: tests/live/observe/test_arrival.py::test_blocked_source_raises_source_silent_and_comes_back_without_a_restart
  - mode: a source's path works for heartbeats but a real event takes another way
    mitigation: "`make testevent` sends a marked line from every source the way its real lines go (logger on the node, a request to the app) and finds each in Loki"
    test: tests/live/observe/test_arrival.py::test_synthetic_event_from_every_source_reaches_the_store
  - mode: the router daemons' own lines never leave the daemon (V-005)
    mitigation: frr.conf says `log syslog informational`, ospfd logs adjacency changes and bgpd neighbor changes, and busybox syslogd forwards them
    test: tests/live/observe/test_central_store.py::test_router_daemons_log_to_the_central_store
  - mode: forwarding the app's log needs root or a change to the app
    mitigation: The forwarder runs as uid 65534 in h2's namespace, reading the log through a read-only mount; the app is started as before, its stderr (where http.server writes each request) into that file instead of /dev/null
    test: tests/live/observe/test_central_store.py::test_app_log_forwarded_without_root_and_searchable
  - mode: the store loses what the box has rotated away
    mitigation: Loki keeps 720 h; the boxes keep 16 KB and one rotated file
    test: tests/live/observe/test_central_store.py::test_history_outlasts_on_box_rotation
  - mode: a BGP password reaches the store
    mitigation: The password goes to vtysh on stdin under no_log, so Ansible's own syslog line for that task is suppressed; FRR's `log commands` stays off, because it would log the password line. The test reads every stored line back
    test: tests/live/observe/test_central_store.py::test_no_secret_in_the_central_store
  - mode: lines are lost or forged on the way (UDP, no authentication, no queue)
    mitigation: Accepted. A lost stream pages as SourceSilent; single lost lines and forged ones are not detected
    test: none (accepted risk RISK-34 in docs/risks.yml)
  - mode: the store itself is lost (one copy)
    mitigation: Accepted. Since decision 0025 it is on the lab host's disk and outlives a redeploy; nothing backs it up
    test: none (accepted risk RISK-35 in docs/risks.yml)
  - mode: a user's machine sends nothing
    mitigation: Accepted. h1 sends no logs; fw1's are the only view of LAN-A
    test: none (accepted risk RISK-36 in docs/risks.yml)
---

## Context

V-005: FRR's daemons run with -d and stdout on /dev/null, so `log stdout` went nowhere. Every node already runs busybox, whose syslogd can forward. NOT-3 wants arrival proven at the collector for each source; NOT-7 one central store, including an app forwarded without root, keeping history past on-box rotation.

## Decision

- Every router, firewall and server we own (r1, r2, r3, fw1, h2) runs busybox `syslogd -R 10.30.30.10:514 -L -s 16 -b 1` and a heartbeat (`logger -t heartbeat alive` every 60 s) from build/monitoring/agent.sh, its last deploy step. FRR logs to syslog. isp, the carrier's, logs only on its own box; h1, a user's machine, sends nothing.
- h2's web server writes its access log (stderr) to /applog/http-80.log, which a Vector sidecar running as nobody follows read-only and sends to the collector over TCP 6000.
- The collector (Vector on noc) names each syslog line by its source address, from a map netlab renders from the inventory (a router's address follows its egress interface), sends every line to Loki labelled node and source, and exports log_last_seen_seconds{node,source}, stamped on arrival. Prometheus' SourceSilent{node,source} fires when that is older than silent_after (90 s; the inventory check holds it under twice the heartbeat less the evaluation time) or missing.
- h2's web log's normal gap is the NOC's own web check, one 5 s interval. Twice that can't be met without paging on one late scrape, so its bound is stated: silent_after 30 s, paging within 47 s (expected_state.json, monitoring.sources[].within).
- Loki keeps 720 h on noc's own disk, with the compactor.

## Consequences

Every node's syslog crosses the campus in clear UDP (RISK-34): a dead link loses the lines behind it, which page as silent but are not recovered. The store is one copy (RISK-35), which went with a redeploy until decision 0025 moved it to the lab host's disk; 720 h is also short of PCI DSS 10.5.1's 12 months, which matters only if the toy scope were real (decision 0013). Lines are kept exactly as sent, with busybox's local time and no hostname; Loki's own timestamp is the arrival time. NOT-5's volume budget, NOT-6's coverage table, FND-2's flight recorder and change attribution build on this store later.
