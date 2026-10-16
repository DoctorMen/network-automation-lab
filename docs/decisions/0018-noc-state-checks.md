---
id: "0018"
title: Watch every object's state from a NOC on its own LAN, with checks generated from the inventory
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "OROS NOT-1 and NOT-2: a check per object (each BGP session, OSPF adjacency, BFD peer, web page, interface flap, pending reboot) that pages while the host still pings, and every value we read from a device in the tool we run, from a documented pollable object rather than a screen-scrape; the routers run a pinned image that must not change (tests/live/test_platform.py); no management network (decision 0007); free; the lab job's CI time stays about the same; nothing hand-written that the inventory can say"
alternatives:
  - name: do nothing
    why_not: The live tests read every one of these values, but only when CI runs, nightly; a session that drops at 03:00 pages nobody, and nothing says which values are read only by a test
  - name: ping each device (Smokeping-style up/down)
    why_not: Exactly what NOT-1 rules out; the BGP and OSPF failures it names leave every host answering ping
  - name: agents installed in the router image
    why_not: Changes the image the platform test pins and every finding bundle's version line; sidecars in the router's network namespace see the same kernel and FRR without touching it
  - name: a management network for the NOC
    why_not: Decision 0007 removed eth0 because Docker's default route leaked traffic; a second LAN only for monitoring would also hide in-band failures the NOC should share with users
  - name: SNMP polling
    why_not: The FRR image has no SNMP agent or module; adding one changes the image, and BFD state would still be missing
sources:
  - https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/ (rules, `for`, labels)
  - https://prometheus.io/docs/alerting/latest/configuration/ (group_by '...' passes every alert through on its own; send_resolved, webhook receivers)
  - https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net (carrier_changes counts every change from up to down and back, the counter a sub-second flap moves)
  - https://docs.frrouting.org/en/stable-8.4/basic.html (FRR 8.4's logging and vty commands; `json` on show commands)
stake: A BGP session or an OSPF adjacency down for hours while every ping is green, found only when users call or the next nightly run fails
failure_modes:
  - mode: a session shut on our own end is missed by a rule that only checks for down (0)
    mitigation: BGPSessionDown is `!= 1`; frr_exporter reports 2 for an admin shutdown, and absent() catches a session deleted from the config
    test: tests/live/observe/test_state.py::test_bgp_local_admin_shutdown_alerts_too
  - mode: the check reads ping, so a protocol failure with the host still up stays green
    mitigation: Each rule reads the object's own state; each live test proves the host still answered ping while it paged
    test: tests/live/observe/test_state.py::test_bgp_session_down_while_the_peer_pings
  - mode: one adjacency failing pages as many, or a different one pages
    mitigation: One rule per adjacency the inventory implies, labelled with its node and neighbor; the test checks no other link paged
    test: tests/live/observe/test_state.py::test_ospf_neighbor_down_while_it_pings
  - mode: an alert starts its wait again when its object's series disappears and comes back (FRR deletes a BFD session with its OSPF adjacency and adds it back down), so the page is late (V-015)
    mitigation: Each per-object rule is aggregated to the object's own labels on both halves, `max by (node, peer) (... != 1) or absent(...)`, and owner and role are rule labels, so the alert keeps one identity
    test: tests/test_monitoring.py::test_an_alert_keeps_its_identity_while_its_series_comes_and_goes
  - mode: a flap shorter than a scrape is never seen
    mitigation: InterfaceFlapped reads the kernel's carrier_changes counter, not the carrier state
    test: tests/live/observe/test_state.py::test_sub_second_flap_alerts_although_no_scrape_saw_it_down
  - mode: a web server answering 200 with the wrong page looks healthy
    mitigation: The probe matches an entry only the real docroot has (href="etc/"); every directory listing has the same title, so the title is not the check
    test: tests/live/observe/test_state.py::test_web_page_with_the_wrong_content_alerts
  - mode: a reboot left pending pages inside its window, or never
    mitigation: The router's textfile comes from netlab/kernel.py, the rule `make verify` already tests; the alert waits for reboot_window
    test: tests/live/observe/test_state.py::test_reboot_pending_past_its_window_alerts
  - mode: a check depends on a scraper nobody vetted, or a read has no metric and nobody knows
    mitigation: monitoring/coverage.yml lists every read the tests, tools, playbooks and runbooks make, as exported, derived or gap, and every collector; the lint fails on anything unlisted
    test: tests/test_coverage.py::test_an_unlisted_read_fails
  - mode: the NOC goes blind with the network, because its checks travel the campus links they watch
    mitigation: Accepted. An unreachable exporter raises TargetDown, and per-object rules fire on absent(); dependency inhibition (one page per cause) is a later build (OROS DEC-5)
    test: none (accepted risk RISK-30 in docs/risks.yml)
  - mode: anyone on the campus reads the exporters or the NOC's endpoints
    mitigation: Accepted. Exporters answer only on the router's loopback and the NOC's services on 127.0.0.1; neither has TLS or a password
    test: none (accepted risk RISK-31 in docs/risks.yml)
  - mode: frr_exporter, holding FRR's vty sockets, changes the router's config
    mitigation: Accepted. The image is pinned by digest and the drift check would see a change
    test: none (accepted risk RISK-32 in docs/risks.yml)
---

## Context

The lab's live tests read each object's state, but only when CI runs. OROS NOT-1 asks for every object to have its own check that pages while its host still pings, including page content, sub-second flaps and a reboot pending past its window. NOT-2 asks for every value an operator reads from a device to reach the tool already run, and a per-platform, per-version list of what isn't exported.

## Decision

A NOC host (`noc`, 10.30.30.0/24 on r2 eth4, passive in OSPF) joins the inventory like any host. It is in scope (PCI DSS 10.3.3, 10.7.2): it holds the CDE's logs, and segmentation from out-of-scope devices would otherwise flag h2's port 22 open from it. Its services and every exporter run as sidecars that share a node's network namespace (Containerlab `network-mode: container:<node>`), so no image changes and no link is added:

- frr_exporter and node_exporter in each router we own, on the router's loopback (net.ipv4.ip_nonlocal_bind lets them start before zebra adds it). The router's /var/run/frr is a folder shared with frr_exporter; the router empties it and gives it to FRR's user before FRR starts, because a stale pid file there survives a restart and FRR's start script would `kill` whatever process has that number now (V-007).
- Prometheus, Alertmanager and blackbox_exporter on noc, on 127.0.0.1.

netlab/monitoring.py writes every scrape target and rule into build/noc/ from the inventory: one rule per BGP session (`!= 1 or absent()`, both halves labelled by the session alone), OSPF adjacency, BFD peer, web check, router (InterfaceFlapped from carrier_changes) and log source, plus TargetDown and PendingRebootOverdue. Each target, and each per-object rule, carries node, owner and role labels, the hook for routing and silencing by role later (OROS DEC-1, DEC-4). Alertmanager sends each alert, and its resolution, as its own notification to a webhook sink on noc, which the tests read back. expected_state.json's `monitoring` block states each alert's bound (alert_within: one scrape, one evaluation, `for`, one more evaluation, group_wait).

monitoring/coverage.yml is the NOT-2 list, for FRR 8.4.1, frr_exporter 1.3.1 and node_exporter 1.8.2: every read found in tests/live, netlab, ansible and docs/runbooks, marked exported, derived or gap. `make coverage` (and `make test`) fail on a read, a scrape job or a rule metric it doesn't list. FRR values come from FRR's JSON over its vty sockets, the documented machine interface; nothing parses CLI text.

CI's lab job deploys the network alone (`make deploy-network`: containerlab --node-filter with the inventory's devices), so it pulls one image and runs the tests it ran before. A new observe job, in parallel, deploys the full lab and runs only tests/live/observe (`make observe`), then `make testevent`, `make drift` and the RAM measurement.

## Consequences

Seven more images on the observe runner, and the RAM they take (docs/sizing/README.md). The pager is a sink, not a person: a real NOC points the webhook at its pager. Checks travel the campus links, so a dead link blinds the NOC to whatever is behind it (RISK-30): each check fires on its own, and grouping them into one page per cause is DEC-5's job. The carrier's isp is watched only from r2's side of the session. Interval 5 s suits CI; a real NOC would run 30 to 60 s and longer `for`.
