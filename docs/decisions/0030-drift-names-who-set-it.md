---
id: "0030"
title: Have the drift check name who set each differing line, from the command records at the NOC
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS CHG-6: for a managed setting, report the effective value and which actor set it (a person or the CM tool); when a second agent overwrites a lab setting, the report shows the effective value and names that agent. Read only what the NOC holds, never the router, so a record root deleted on the box still counts; the drift check must still fail on the difference itself when the NOC can't answer (CI's lab job runs without it)"
alternatives:
  - name: do nothing
    why_not: "`make drift` names the line and its running value, and someone then asks around for who changed it"
  - name: git blame on the intended config
    why_not: Names who changed the intent, which is the CM tool's input; the running value someone typed by hand is exactly what git never saw
  - name: read the router's own log at drift time
    why_not: Root on the box can delete it (decision 0029's test does), and it rotates away within minutes (16 KB)
  - name: name everyone who touched the router since the last clean check
    why_not: Says who might have done it, not who set the value now running; the Pass line wants the agent whose value is in effect
sources:
  - https://github.com/FRRouting/frr/blob/frr-8.4.1/tools/frr-reload.py (with --test, the script lists the lines a reload would delete and add, and changes nothing)
  - https://grafana.com/docs/loki/latest/query/log_queries/ (LogQL line filters, which the lookup uses to find a router's command records)
stake: A drifted line that took a session down is found by the nightly check, and the time spent finding who typed it is time the session stays down
failure_modes:
  - mode: the report names someone whose value was overwritten
    mitigation: For each line, the newest record on that router of the same command (the same words before the value) decides, so an earlier person who set another value is not named
    test: tests/live/observe/test_accounting.py::test_drift_names_whoever_set_the_running_value_last
  - mode: an abbreviated command is not matched, or an address matches a longer one
    mitigation: A typed keyword matches any running keyword it starts, as FRR's parser takes it; a word with a digit (an address, a number) must match in full
    test: tests/test_attribution.py::test_the_newest_record_that_set_a_line_is_named
  - mode: a removed line is reported with no name
    mitigation: For a line the intent has and the running config lacks, the newest record of the same command is named if it ran `no` and the line's start, or set the command to another value
    test: tests/test_attribution.py::test_a_removed_line_is_named_by_its_no_record
  - mode: a password line can't be matched, or its secret is printed
    mitigation: Records hold <hidden> and the diff a sha256 tag, so only the words up to `password` are compared, and neither secret is ever printed
    test: tests/test_attribution.py::test_a_password_line_is_matched_without_its_secret
  - mode: the NOC is down and the drift check stops working
    mitigation: The lookup runs on the control node and never fails the play; without an answer it says the actor is unknown, and the difference still fails the check
    test: tests/test_attribution.py::test_the_lookup_says_so_when_the_noc_does_not_answer
  - mode: a change root made outside the proxy is pinned on someone else
    mitigation: The newest record of the same command is named only if it set the running value, or for a missing line removed or replaced the intended one. A value root set again after `make apply` put the intent back meets the CM tool's record first, so it names no one, and the report says the line was changed outside the accounting proxy
    test: tests/test_attribution.py::test_a_line_changed_again_outside_the_proxy_names_no_one
  - mode: a forged record names the wrong person
    mitigation: The lookup reads only the records the collector took from the proxy's own port, which no account on the router but root can send from (decision 0029)
    test: tests/live/observe/test_accounting.py::test_a_record_an_account_forges_is_not_taken_for_one
  - mode: a record matches by text in the wrong stanza, or for a command that failed
    mitigation: Accepted. Records carry neither the context nor the daemon's answer
    test: none (accepted risk RISK-62 in docs/risks.yml)
---

## Context

Decision 0029 sends every FRR command a person or the CM tool runs to the NOC, under their own account. The drift check (ansible/drift.yml through tasks/compare_frr.yml) already runs frr-reload.py --test against the intent and fails with its list of differences.

## Decision

- When the intended-config comparison finds a difference, compare_frr.yml (with name_actors, which only drift.yml sets) runs `python -m netlab.who set <router>` on the control node with frr-reload.py's list on stdin, and adds what it prints to the failure.
- netlab/who.py reads each listed line, with its stanza: a line the reload would run as `no X` means X is running and not intended, any other is intended and not running. It fetches the router's command records (source accounting, decision 0029) from Loki for the store's whole retention and takes, for each line, the newest record of the same command: the same words before the value, or `no` and the line's start. If that record set the running value, or removed or replaced the intended one, it names its account, uid and time; otherwise it says no record explains the line.
- `make apply` puts the intent back as the CM tool's account, so its commands are recorded like anyone's.

## Consequences

A drifted line comes with the name of whoever set the value now running, and a value set again outside the proxy names no one rather than the last person who typed it. The lookup trusts the records' text: a command typed in another stanza with the same words can be named wrongly or hide the record that did set the line, and one the daemon refused can be named (RISK-62). A change from root outside the proxy names no one (RISK-60). Without a NOC (CI's lab job), the report says the actor is unknown and the check fails as before.
