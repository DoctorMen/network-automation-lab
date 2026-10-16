---
id: "0020"
title: Every alert says why it fired, what is normal and what changed, and a silence covers one object for a set time
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS DEC-1 and DEC-4: whoever is on shift decides from the alert alone, without logging in to the router, and a silence leaves the check live everywhere else, ends, and keeps a reason that survives the next audit; every rule is generated from the inventory (decision 0018), so the context has to be generated too; free; nothing to configure in a UI"
alternatives:
  - name: do nothing
    why_not: Alerts carry a one-line summary; the reader has to open Prometheus, guess the query for the normal value and ask who changed what, and a silence is whatever amtool was typed with
  - name: a runbook link per alert instead of context
    why_not: A runbook says what to do in general; it can't show this object's value now, its own history or the commit applied to it an hour ago
  - name: Grafana dashboards linked from each alert
    why_not: Another service to run and keep in step with the rules; Prometheus' own graph page shows the same signal with nothing more installed
  - name: silences by hand with amtool, reviewed afterwards
    why_not: Nothing stops a silence on a whole router or a whole rule, or one that never ends, and its reason lives only in Alertmanager's state, which a redeploy loses
sources:
  - https://prometheus.io/docs/prometheus/latest/configuration/template_reference/ (query, humanizeTimestamp and $externalURL in alert annotations)
  - https://prometheus.io/docs/prometheus/latest/configuration/template_examples/ (annotations that query other series when the alert fires)
  - https://prometheus.io/docs/alerting/latest/alertmanager/#silences (silences match by equality or regex and run between a start and an end)
stake: An engineer on shift silences a whole router to stop one flapping port, or acts on an alert without knowing a change went out an hour ago
failure_modes:
  - mode: an alert carries no context, or a template that fails and shows an error instead
    mitigation: rule() adds why_fired, baseline and changes to every rule; a live outage of 20 or more alerts checks each one filled in by Prometheus, with no template error
    test: tests/live/observe/test_outage.py::test_every_alert_says_why_what_is_normal_and_what_changed
  - mode: the baseline link points at some other series than the alert's
    mitigation: The link is built from the same signal the rule's condition reads, and the live test queries its expression for that object's own history
    test: tests/test_alert_context.py::test_every_rule_says_why_it_fired_what_is_normal_and_what_changed
  - mode: the changes field names an old commit, or none, after a change went out
    mitigation: make apply pushes the commit it applied, per router, as its last step; the live test checks an alert raised after the apply names HEAD
    test: tests/live/observe/test_outage.py::test_every_alert_says_why_what_is_normal_and_what_changed
  - mode: a silence covers more than the one object, so the same failure elsewhere stays quiet
    mitigation: netlab/silence.py refuses any silence whose labels pick out more than one of the rule's objects, or a device beyond a 4-hour maintenance window; matchers are equality only
    test: tests/test_silence.py::test_a_silence_wider_than_one_object_is_refused
  - mode: a silence outlives its reason
    mitigation: Every silence ends at most 7 days after it starts and names a record (risk, decision, verdict or ticket); the live test checks the same flap pages once it has ended
    test: tests/live/observe/test_silence.py::test_a_silenced_flap_still_pages_on_another_router_and_after_the_silence_ends
  - mode: a silence added by hand bypasses the file and its checks
    mitigation: make silence reports every active silence the file doesn't hold
    test: tests/test_silence.py::test_a_silence_added_by_hand_is_reported
---

## Context

OROS DEC-1 asks each alert for the matched condition and its values, a link to the asset's normal baseline for that signal, and a link to its recent changes. DEC-4 asks that a silence cover one rule, host or window, end where it can, and carry a reason that holds up when the finding comes back. The base NOC's rules carried a summary only, and Alertmanager accepts any silence.

## Decision

- netlab/monitoring.py `rule()` gives every rule three annotations, which Prometheus fills in from queries when it sends the alert:
  - `why_fired`: the signal, the condition, and the signal's value now (or "no series");
  - `baseline`: the value it normally has, and a link to that signal over the last 7 days on the NOC's Prometheus (`--web.external-url`);
  - `changes`: the last commit `make apply` applied to the router (to any router, for a host or the NOC's own checks), with its time, and a link to every apply in 7 days.
- `make apply` pushes `netlab_config_applied_timestamp_seconds{node,commit,subject}` to the NOC's pushgateway after each batch passes its gate (ansible/deploy.yml). The commit is `git describe --always --dirty`.
- Silences live in monitoring/silences.yml. `make silence` (and `make deploy`) checks each entry and adds it through Alertmanager's API:
  - one object of one rule, by that rule's own labels, or one device for at most 4 hours;
  - equality matchers only;
  - an end at most 7 days after the start;
  - a reason, who set it, and a reference: a risk, a decision, a verdict or an https ticket.

## Consequences

Annotations are what Prometheus last sent, and it resends a firing alert about once a minute, so a value can be up to a minute old; the changes line gives a time, not an age, for that reason. An alert about fw1 or h2 shows the lab's last router apply, because their config comes from the topology at deploy, not from `make apply`. Silences live in Alertmanager's state: a redeploy starts empty, so `make deploy` adds the file's silences again, and a silence added by hand shows up in `make silence` as one the file doesn't hold (RISK-41). Silencing by role is refused: only one object or one device's window.
