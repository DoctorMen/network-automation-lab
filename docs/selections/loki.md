---
kind: selection
id: loki
title: Loki as the one central, searchable log store
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "Free; one container that runs on a GitHub runner beside the lab within its RAM; searchable by node and source from a script (the tests search it); keeps history past the boxes' 16 KB rotation for a stated retention; the same place every source's lines land, routers, firewall, server and app alike (OROS NOT-7); one person runs it"
choice: grafana/loki:3.1.1, single binary, filesystem storage, retention 720 h with the compactor, listening on 127.0.0.1 inside noc's network namespace
uses: [grafana/loki]
alternatives:
  - name: Elasticsearch or OpenSearch
    why_not: A JVM wanting gigabytes of heap on a runner that holds the whole lab in a few hundred MiB; it indexes every word, which this volume doesn't need
  - name: rsyslog writing files on noc
    why_not: Central, but searchable only with grep on that box, with its own rotation to manage; no API for the tests or for a later build's change attribution
  - name: Wazuh (as the standard's lab suggests)
    why_not: A manager, an indexer and a dashboard, several GB of RAM; its detections belong to the SOC builds (NOT-6), not to the store
  - name: no purchase, the boxes' own logs
    why_not: Free, and each node already keeps one (busybox syslogd), but 16 KB plus one rotated file is gone in minutes, and it dies with the box
no_purchase: "The do-nothing option is each box's own busybox syslogd file, which rotates away within minutes and goes with the box. Loki is free (AGPLv3, run unmodified), so the choice costs only RAM."
staffing: "k alone. The config is rendered from the inventory; queries are LogQL, the same strings the tests use. Help: Grafana's public community forum and issue tracker, free."
vendor_domains: [grafana.com, github.com/grafana]
independent_sources:
  - "tests/live/observe/test_central_store.py::test_history_outlasts_on_box_rotation (our measurement: a line r1's rotated on-box log has already lost is still found)"
  - "tests/live/observe/test_central_store.py::test_no_secret_in_the_central_store (every stored line is read back and searched for the BGP password)"
  - "docs/sizing/data/2026-10-16-sandbox.json (our measurement: Loki at 60.6 MiB, the largest container in the full lab, idle with about half an hour of logs)"
  - "https://en.wikipedia.org/wiki/Grafana (an encyclopedia entry: Loki indexes metadata rather than full log text; Grafana Labs' projects relicensed to AGPLv3 in 2021)"
---

## Context

V-005: router daemons logged to nowhere. NOT-7 asks for one central searchable store for every source, apps without root included, keeping history longer than the boxes do.

## Decision

Loki on noc, fed only by the collector (Vector), with each stream labelled by node and source and nothing else (decision 0019).

## Consequences

Its store is the noc container's own filesystem: it outlasts the boxes' rotation but not a redeploy of the lab, and there is one copy (accepted as RISK-29 in docs/risks.yml). AGPLv3 matters only if Loki is changed and offered to others; the lab runs it unmodified. Loki answers on 127.0.0.1 only, so searching it means a shell on noc.
