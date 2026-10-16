---
id: "0021"
title: One page per cause, from dependencies worked out of the inventory's graph and held back by Alertmanager
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS DEC-5: a failed router, link or collector pages once while everything that follows from it waits behind it, and a failure elsewhere in the same minutes still pages; the model must keep up with hundreds of nodes with no check tuned by hand; the NOC is in band (decision 0018), so a failure blinds it to everything behind; Alertmanager's own inhibition, nothing new to run"
alternatives:
  - name: do nothing
    why_not: Cutting r3 off pages about twenty times (each session, adjacency, BFD peer, exporter, h2 and its web page), and the cause is one page among many (RISK-31)
  - name: a hand-written parent list per check (Nagios-style parents)
    why_not: Someone has to keep it right as links are added; the inventory already says how everything connects
  - name: group everything by node in Alertmanager
    why_not: One notification per node, but a dead r3 still pages for r1's and r2's sessions with it and for h2 behind it, and a real second failure on the same node is folded into the first
  - name: an event-correlation product
    why_not: Paid, another service, and it learns what the inventory can state
sources:
  - https://prometheus.io/docs/alerting/latest/configuration/#inhibit_rule (an alert matching a firing source's matchers is held back)
  - https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/ (`for`, `keep_firing_for`, rule group interval)
  - https://doi.org/10.1145/357062.357071 (Lengauer and Tarjan, dominators in a flowgraph: a vertex dominates another when every path from the root to it passes through it)
stake: The page that names the cause is lost among twenty, or a real second failure in the same minutes is folded into the first and nobody looks at it
failure_modes:
  - mode: a failed router pages for everything behind it and every session with it
    mitigation: Each alert's deps label lists the causes it can't be seen without (dominators of its objects in the graph of devices and links, from the NOC); one inhibit rule per cause holds back every alert that lists it
    test: tests/live/observe/test_outage.py::test_a_parent_failure_pages_once_and_a_killed_service_pages_again
  - mode: an independent failure in the same window is held back with the rest
    mitigation: Only alerts that list a firing cause are held; the live test kills frr_exporter beside a healthy router during the outage and it pages
    test: tests/live/observe/test_outage.py::test_a_parent_failure_pages_once_and_a_killed_service_pages_again
  - mode: a dependent alert reaches the pager before its cause is in Alertmanager
    mitigation: Each cause has a marker (CauseSeen, no `for`) evaluated every second, and group_wait holds every new alert 5 s; the margin is checked offline
    test: tests/test_dependencies.py::test_markers_are_in_alertmanager_before_what_they_hold_back
  - mode: a short outage that a scrape sees fires its link's marker but not LinkDown, which needs 10 s, so the flap, the only alert it raises, is held back and nothing pages
    mitigation: A flap lists its router and what is in front of it, never its own link. Once LinkDown has fired for that link, the flap that ends the outage stays quiet for 40 s, so a long outage still pages once
    test: tests/live/observe/test_outage.py::test_a_link_down_for_seconds_pages_once_as_a_flap
  - mode: dependents still recovering page after the cause clears
    mitigation: A cause's marker keeps firing for a heartbeat and three intervals (75 s) after it recovers, the slowest dependent's recovery; no page keeps firing, so a page held behind another cause can't outlast that cause's hold
    test: tests/test_dependencies.py::test_a_cause_keeps_holding_back_through_the_slowest_recovery
  - mode: two causes hold each other back and nothing pages
    mitigation: A cause's page leaves itself and whatever depends on it out of its deps; the offline test checks the causes form no loop
    test: tests/test_dependencies.py::test_no_two_causes_hold_each_other_back
  - mode: a new node or link needs its dependencies written by hand
    mitigation: deps are computed from the inventory on every render; the offline test adds a router and a server and finds them listed
    test: tests/test_dependencies.py::test_a_new_router_needs_no_hand_tuning
  - mode: the NOC's own uplink fails and pages as r2, its first hop, and the NOC's own services (blackbox, Prometheus, Alertmanager) are outside the model
    mitigation: Accepted. A dead uplink still gives one page, with r2's name; blackbox down pages once per job it serves
    test: none (accepted risk RISK-43 in docs/risks.yml)
  - mode: a real failure behind a cause waits until the cause clears, up to 75 s more, and a short one behind a cause seen for one scrape (a lost ping) can go unpaged
    mitigation: Accepted. It pages once the cause clears if it is still true
    test: none (accepted risk RISK-42 in docs/risks.yml)
---

## Context

OROS DEC-5 asks that dependent alerts sit behind the causal one (host, uplink, shared service, the monitor's own uplink), that independent failures on healthy parts still page, and that the model stays maintainable across hundreds of nodes. The NOC is in band behind r2 (decision 0018), so when r3 is cut off, everything about r3, h2 behind it, and r1's and r2's sessions with it all fire (RISK-31).

## Decision

- netlab/monitoring.py builds one graph from the inventory: devices, and each link as a vertex between its two ends. A vertex depends on every vertex the NOC can't reach it without (its dominators). One breadth-first search is run per vertex taken out.
- The causes are what the NOC can see fail for itself:
  - each device it pings: NodeDown;
  - each link with an end whose node_exporter the NOC still reaches without that link: LinkDown;
  - each collector other alerts are read through: TargetDown for frr_exporter, and for the log collector.
- Every alert carries `deps`, written `/a/b/`: the causes its objects depend on, themselves included, plus the collector it is read through. A cause's own page leaves itself, and what depends on it, out.
- Each cause has a marker, CauseSeen, with no `for`, in a rule group evaluated every second and routed nowhere. Alertmanager has one inhibit rule per cause: while anything labelled `cause=X` fires, every alert whose deps list X is held back.
- group_wait is 5 s, so a dependent waits its `for` (10 s or more) plus 5 s, while its cause's marker is in Alertmanager within about 8 s.
- A cause's marker keeps firing 75 s after it recovers, so dependents that clear late stay held back. A log source's SourceSilent clears only on its next heartbeat, the slowest. The marker holds, not the page: in a full live run, h2's page (itself a cause, behind r3) kept firing as long as r3's and answered one scrape later, so it outlasted r3's hold and paged (V-020).
- InterfaceFlapped is now one rule per interface, firing once the carrier is back. A link still down is LinkDown's page.
- A flap's deps are its router and what is in front of it, never its own link. A scrape that sees a short outage fires the link's marker at once, while LinkDown needs 10 s: a flap behind its own link would be held back with no page for the outage at all. For the same reason a flap stays quiet for 40 s after LinkDown for its link fired (its 30 s window, an interval, and an interval of margin), so a long outage still pages once. Review found the first case live: r1's link to fw1 down for 7 s paged nothing (V-021).

## Consequences

- One page per cause, measured live: r3 cut off, frr_exporter killed beside r1 and r1's link to fw1 cut page exactly three times, and the test requires ten or more alerts held back. r1's link to fw1 down for 7 s pages once, as a flap.
- Every state alert's bound grows by 4 s (group_wait 1 s to 5 s): 31 s instead of 27 s.
- A cause's page resolves when its signal does; what depends on it stays held back 75 s more.
- A real failure behind a cause pages only when the cause clears, and a short one behind a cause seen for one scrape can go unpaged (RISK-42).
- The NOC's own uplink has no end the NOC can watch past, so its failure pages as r2, the first hop. The NOC's own services are not in the model (RISK-43).
