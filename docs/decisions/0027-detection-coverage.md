---
id: "0027"
title: Generate the detection coverage table from the deployed rules, and measure each detection's pages over a stated benign workload every quarter
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS NOT-6: each detection lists the log sources and sensor placement it depends on, its known blind spots and its measured false-positive load; no blank cell, and each figure from the current review cycle (quarterly by default); a test so the table can't drift from what is deployed; nothing typed twice that the rules or monitoring/coverage.yml already say; free"
alternatives:
  - name: do nothing
    why_not: The rules exist only as build/noc/rules.yml; nobody can say what a quiet NOC does not see, and there is no false-positive figure at all
  - name: a table written by hand in the README
    why_not: It is right the day it is written and wrong the first time a rule, a source or a scrape job changes, with nothing to say so
  - name: count false positives from the pager's history
    why_not: This lab has no history of normal days; it is rebuilt for every CI run, and its live tests break things on purpose, so every page there was caused by a test
  - name: count false positives while the live tests run
    why_not: The tests fail a link, a session or a source on purpose; which pages a test caused and which it did not is guesswork, and a guess is not a measurement
  - name: review for a day instead of 30 minutes
    why_not: A day holds far more of the normal work and would be the better figure; it ties up a lab for a day each cycle. 30 minutes runs each of the operator's five-minute tasks six times (RISK-58)
sources:
  - https://prometheus.io/docs/prometheus/latest/querying/api/#rules (the rules API the live test reads the loaded rules from)
  - https://prometheus.io/docs/alerting/latest/configuration/#webhook_config (what the pager receives, one notification per alert)
  - https://attack.mitre.org/datasources/ (detections described by the data sources they need)
stake: A quiet NOC read as cover for what it never sees, or a detection that pages on normal work until people stop reading its pages
failure_modes:
  - mode: a rule is deployed with no row, or a row stays for a rule that is gone
    mitigation: The table's rows are the rules netlab/monitoring.py renders, grouped by alert; a rule with no entry in monitoring/detections.yml, or an entry no rule raises, fails make test
    test: tests/test_detections.py::test_a_rule_without_a_row_fails
  - mode: a cell is blank
    mitigation: make detections and make test fail naming the detection and the column
    test: tests/test_detections.py::test_a_blank_blind_spot_fails
  - mode: a detection the review never measured is shown without a figure
    mitigation: Its false-positive cell is blank, so it fails like any blank cell
    test: tests/test_detections.py::test_a_detection_the_review_never_measured_has_a_blank_cell
  - mode: docs/detections.md is edited by hand, or not regenerated after a change
    mitigation: make test regenerates the table from the files it is made from and fails if the committed one differs
    test: tests/test_detections.py::test_a_hand_edited_table_fails
  - mode: the table's rows are not what the running NOC has loaded
    mitigation: The live test reads every alerting rule back from Prometheus and compares them, rule for rule, with the table
    test: tests/live/observe/test_detections.py::test_table_rows_are_the_rules_the_running_noc_has_loaded
  - mode: a false-positive figure is older than the review cycle
    mitigation: monitoring/detections.yml states a 92-day cycle; make test fails the day after it runs out
    test: tests/test_detections.py::test_a_review_older_than_its_cycle_fails
  - mode: a figure was measured on rules that have since changed
    mitigation: The review records a fingerprint of each detection's expressions and waits; a changed rule makes its figure stale and make test fails
    test: tests/test_detections.py::test_a_review_of_other_rules_fails
  - mode: a review shorter than the stated workload is passed off as one
    mitigation: The review records how long it ran; under the stated 30 minutes fails
    test: tests/test_detections.py::test_a_review_shorter_than_the_stated_workload_fails
  - mode: a review counts as benign although part of its workload failed, so the normal work never ran
    mitigation: Each step's runs and failures are recorded; one failure fails make test
    test: tests/test_detections.py::test_a_review_with_a_failed_step_fails
  - mode: a source spends more than its budget on a normal day
    mitigation: The review is also NOT-5's measured day; a source whose pace there is over its budget fails make test (decision 0026)
    test: tests/test_detections.py::test_a_source_over_its_budget_during_the_review_fails
  - mode: the stated workload is not the campus's real normal work
    mitigation: Accepted. It is stated in the table, and every figure is read as pages over that workload only
    test: none (accepted risk RISK-58 in docs/risks.yml)
---

## Context

The NOC runs nine kinds of alert rule, rendered from the inventory into build/noc/rules.yml (decisions 0018, 0019, 0026). What each reads is in the rules and in monitoring/coverage.yml; what each misses was written nowhere, and no detection had a false-positive figure. NOT-6 asks for both, with no blank cell and a figure from the current cycle.

## Decision

- `make detections` (netlab/detections.py) writes docs/detections.md, one row per alert: what it detects and its blind spots from monitoring/detections.yml; the metrics it reads, their collector and where that sits, from the rules and monitoring/coverage.yml; the objects it watches from the rules' own labels; its false positives from monitoring/fp-review.yml. The file also lists the threats no detection here sees.
- `make fp-review`, on a full lab with nothing broken, runs a stated benign workload for 30 minutes: a user loading h2's page every 30 s and pinging h2 and the carrier every 10 s, and the operator's make drift, make apply, make verify, make testevent and make locate every five minutes. Every page the NOC's pager receives in that window, and in the longest alert bound after it, is a false positive. It writes each detection's pages with a fingerprint of the rules they were counted on, each step's runs and failures, each log source's bytes as a day against its budget, and the lines cut at the source.
- tests/test_detections.py fails make test on a deployed rule with no row, a blank cell, a committed table that is not what the files give now, a review older than 92 days, shorter than stated, with a failed step, run on other rules, or with a source over its budget. tests/live/observe/test_detections.py compares the table with the rules the running NOC has loaded.

## Consequences

Any change to a rule's expression or wait, including another build adding an alert, fails make test until someone runs make fp-review again, which takes a lab for about 31 minutes. A page from a real fault during the review is counted as false, so a figure can only overstate. The workload is this lab's normal work, stated in the table; a campus with other normal work (maintenance windows, a carrier that flaps) needs its own (RISK-58). Blind spots are written by hand, so a new rule needs its entry before make test passes, and its entry is only as good as whoever writes it.
