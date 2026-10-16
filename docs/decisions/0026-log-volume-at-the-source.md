---
id: "0026"
title: Cut the NOC's own successful web check at h2's forwarder, count what is cut, and give every log source a daily ingest budget that pages
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS NOT-5: known-benign, high-volume lines cut at the device or its own forwarder by a named kind, never a whole source or severity, while wanted lines of the same source still arrive; each source's ingest reported against a storage budget, and a page when it is over; decision 0019's last-seen checks, test events and central store must keep working; the app may not change (NOT-7) and the router image must not change; free"
alternatives:
  - name: do nothing
    why_not: The NOC's own web check writes a line in h2's access log every 5 s, most of that log, and every one crosses the campus to the store; nothing says how much each source sends or when one sends more than the store was sized for
  - name: drop the check's lines at the collector on noc
    why_not: NOT-5 asks for the cut at the source; by then each line has crossed the campus and been counted, and the collector's count is the one SourceSilent and the budget read
  - name: cut by source or severity (all of h2's access log, or every 200 line)
    why_not: Loses the lines we want with the noise, a user's request for the very same page among them; NOT-5 rules it out
  - name: rate-limit h2's log at its forwarder (Vector's throttle)
    why_not: A limit drops whatever comes over it, wanted lines in a burst included, and says nothing about which lines were dropped
  - name: change the app or the check so the check is not logged
    why_not: The app is the one nobody may change (NOT-7); a check that stops looking like a user's request also stops proving what a user gets
  - name: cut lines on the routers too (Ansible's module lines, the largest share of their syslog)
    why_not: busybox syslogd, the image's only syslog daemon, can't filter by message, and the router image must not change; those lines are also the record of every command the operator's playbooks ran on a router (V-030)
  - name: a budget as a pace (bytes a second over a few minutes)
    why_not: Pages on a busy hour that the day absorbs (make drift and make apply every five minutes are bursts); a licence or a store's size counts a day's total
  - name: Loki's own per-stream ingestion limits
    why_not: Enforces by refusing lines at the store, so wanted lines are lost and nobody is paged
sources:
  - https://vector.dev/docs/reference/configuration/transforms/route/ (a line no route matches goes to `_unmatched`)
  - https://vector.dev/docs/reference/configuration/transforms/reduce/ (max_events, expire_after_ms and merge strategies)
  - https://vector.dev/docs/reference/configuration/transforms/log_to_metric/ (a counter with increment_by_value)
  - https://prometheus.io/docs/prometheus/latest/querying/functions/#increase (increase over a range, with counter resets handled)
  - https://docs.python.org/3/library/http.server.html (the access line http.server writes for each request)
stake: The store fills with the NOC's own check while nobody knows which source is spending its disk, or a cut meant for noise drops the line that explains an incident
failure_modes:
  - mode: a wanted line of the same log is cut with the noise
    mitigation: The cut names one kind of line, web-check, as one pattern built from the inventory, the check's own client address, request and a 200 status; a user's same request, the check failing, another page and another client on the NOC's LAN all pass
    test: tests/test_volume.py::test_forwarder_cuts_the_named_kind_and_nothing_else
  - mode: the cut is not really at the source, so the lines still cross the campus
    mitigation: The live test sends three count lines' worth of the check's own request, sees h2's own log grow by every one, and sees the collector's count of h2's lines rise by fewer than half of them, while h1's same request and a failed check from the NOC arrive
    test: tests/live/observe/test_volume.py::test_noisy_kind_cut_at_the_source_while_wanted_lines_arrive
  - mode: a source with nothing named to cut is filtered anyway
    mitigation: With no `cut` in the inventory the forwarder renders no match at all and sends every line
    test: tests/test_volume.py::test_an_unnamed_kind_is_never_cut
  - mode: cutting the check's lines makes h2's log look silent
    mitigation: >-
      The forwarder sends one count line per heartbeat's worth of cut lines ("netlab-cut: 12 web-check lines"), and netlab validate holds a cut source's silent_after over the heartbeat plus two check intervals (70 s) and at most twice the heartbeat less three intervals and a second (104 s); h2's is 90 s
    test: tests/test_volume.py::test_a_cut_source_must_wait_a_heartbeat_before_it_is_silent
  - mode: a cut kind nobody defined, or one with no check behind it
    mitigation: netlab validate refuses a kind netlab doesn't know, and web-check on an app the NOC doesn't check
    test: tests/test_volume.py::test_a_cut_kind_netlab_does_not_know_is_refused
  - mode: a source sends more than the store was sized for and nobody knows
    mitigation: The collector counts each line's bytes per source (log_bytes_total); LogIngestOverBudget pages once a source's last 24 h passes its budget, and `make ingest` prints each source against its budget
    test: tests/test_volume.py::test_budget_rule_pages_once_a_source_passes_its_day
  - mode: a source has no budget, or the budgets together don't fit the store
    mitigation: netlab validate refuses an app with no budget_kb and budgets whose total over the retention is over store_mb; every source has a rule with its own budget
    test: tests/test_volume.py::test_budgets_the_store_cannot_hold_are_refused
  - mode: a budget the running NOC never loaded, or one a normal day already spends
    mitigation: The live test reads each source's rule back from Prometheus with its budget, quiet, and each source's last 24 h within it; the false-positive review (decision 0027) records each source's pace over the benign workload and fails make test if one is over
    test: tests/live/observe/test_volume.py::test_every_source_within_its_budget
  - mode: a request from the NOC's own address that looks exactly like the check is cut too
    mitigation: Accepted. Only a successful GET / from that one address is cut, and each cut line is counted
    test: none (accepted risk RISK-55 in docs/risks.yml)
  - mode: the budget counts what the collector hands the store, not the disk the store uses, and stops nothing
    mitigation: Accepted. It pages; it does not drop
    test: none (accepted risk RISK-56 in docs/risks.yml)
  - mode: once a source's day is over budget its page stays up until that day is out, so a second flood on it does not page again
    mitigation: Accepted. The page carries the day's total, and `make ingest` shows the current pace
    test: none (accepted risk RISK-57 in docs/risks.yml)
---

## Context

h2's web server writes one access line per request (decision 0019), and the NOC's own content check (WebContentWrong, decision 0018) requests its page every 5 s. That check is most of the log, and every line crossed the campus to the store. Nothing reported how much each source sent, or against what. busybox syslogd on the routers and the firewall can't filter by message, and the router image must not change; h2's log is forwarded by its own Vector sidecar, which can.

## Decision

- The inventory names, per app, the kinds of line its forwarder cuts (`cut: [web-check]` on h2's http). netlab knows one kind, web-check: the NOC's successful check of that app, a GET / from the collector's address answered 200. netlab/monitoring.py builds its pattern from the inventory, and the forwarder's remap marks a matching line; a route sends marked lines to a reduce, everything else straight on.
- The reduce sends one line per heartbeat's worth of cut lines (12, at a 5 s check and a 60 s heartbeat), or after 30 s: `netlab-cut: 12 web-check lines`. So the store still holds, as a count, every check that succeeded, and h2's log has a line at least every heartbeat. Its silent_after goes from 30 s to 90 s, inside the bounds netlab validate holds a cut source to (over 70 s, at most 104 s).
- The collector counts the bytes of each line's message per source, `log_bytes_total{node,source}`. The inventory gives each source a daily budget (`logging.budget.syslog_kb` for every syslog source, `budget_kb` for each app) and the disk set aside for raw lines (`store_mb`). netlab validate refuses budgets whose total over the retention (720 h) would not fit it.
- `LogIngestOverBudget{node,source}` fires when `increase(log_bytes_total[1d])` passes the source's budget, with no wait: a day's total, as a licence or a store counts it. `make ingest` prints each source's last 24 h and pace against its budget.
- The budgets are sized from the benign workload of the false-positive review (decision 0027), in which the operator runs make drift and make apply every five minutes: each syslog budget is 8 MiB a day, 2.8 times the busiest router's pace there (r2, 3.0 MB a day); h2's http log's is 512 KiB a day, about twice its 259 KB a day there. Uncut, the checks alone would spend about twice that budget: the review's forwarder cut 372 check lines of about 61 bytes in 30 minutes.

## Consequences

The store no longer holds the NOC's successful checks as lines, only as counts; a check that fails is logged as written. A request from the NOC's own address that looks exactly like the check is cut too (RISK-55). The budget counts the bytes the collector hands Loki, not Loki's disk with its index and compression, and it only pages (RISK-56); once a source's day passes its budget the page stays up for that day (RISK-57). Routers' syslog, mostly the lines Ansible writes for each module it runs (V-030), is not cut. h2's http log now proves it is alive through the NOC's checks: if they stop, it goes silent while the app may be fine, a blind spot docs/detections.md lists. Decision 0019's stated 47 s bound for that log no longer holds; it now pages within 107 s, its 90 s silent_after plus evaluation, as expected_state.json states.
