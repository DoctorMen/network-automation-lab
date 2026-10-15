---
id: "0009"
title: Detect silent link failures with BFD
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: Only what the FRR 8.4.1 image already ships, and `make drift` must stay green
alternatives:
  - name: do nothing
    why_not: A link that stays up but passes nothing blackholed LAN-A to LAN-B traffic for 35.6-39.7 s (measured) until the OSPF dead timer ran out
  - name: faster OSPF hellos (ip ospf dead-interval minimal)
    why_not: Hello and dead timers must match on both ends or the adjacency never forms, and they protect OSPF only; BFD timers are negotiated per session and BGP can use BFD too
  - name: a bfd profile that writes out 300/300/3
    why_not: FRR hides default values in running-config, so frr-reload reports those three lines as missing on every run and drift is red forever (checked in a throwaway FRR 8.4.1 container)
sources:
  - https://www.rfc-editor.org/rfc/rfc5880 (BFD)
  - https://www.rfc-editor.org/rfc/rfc5881 (BFD for single-hop IPv4)
  - https://www.rfc-editor.org/rfc/rfc2328#appendix-C.3 (OSPF RouterDeadInterval)
  - https://docs.frrouting.org/en/latest/bfd.html
stake: If BFD is quietly not running, a dead-but-up core link drops LAN-A to LAN-B traffic for up to 40 s and nothing says why
failure_modes:
  - mode: clean link failure (link goes down)
    mitigation: OSPF drops the adjacency as soon as the interface goes down and reroutes through r2
    test: tests/live/test_failover.py::test_traffic_survives_r1_r3_link_failure
  - mode: silent forwarding failure (link up, nothing forwarded)
    mitigation: BFD (300 ms x 3) on every OSPF point-to-point link tears the adjacency down in about 0.9 s
    test: tests/live/test_failover.py::test_silent_failure_reroutes_fast
  - mode: BFD configured but not running (bfdd off, session never comes up), so detection falls back to the 40 s dead timer without any error
    mitigation: Every BFD peer the inventory implies must be up; `make drift` catches a removed `ip ospf bfd`
    test: tests/live/test_failover.py::test_bfd_sessions_up
  - mode: BFD false positive (a busy router misses 3 packets in 0.9 s and drops a healthy adjacency)
    mitigation: Accepted risk. FRR's default timers are kept rather than tightened, and nothing alerts on a BFD flap yet
    test: none (accepted risk, measured by hand, see Consequences)
  - mode: duplicate router-ID
    mitigation: The router-ID is the loopback, and `netlab validate` rejects a loopback that collides with another loopback or link address
    test: tests/test_inventory.py::test_duplicate_loopback
  - mode: hand config change on a router, including one saved with write memory
    mitigation: "`make drift` (ansible/drift.yml) diffs running against intended config on every CI run; intended config is mounted read-only (0008) so write memory can't overwrite it, which tests/live/test_drift.py::test_write_memory_cannot_overwrite_intent proves"
    test: tests/live/test_collection.py::test_unsaved_change_is_flagged
  - mode: single edge router (r2) or single ISP link fails
    mitigation: "Accepted risk, manual step: there is no second edge router or ISP to fail over to. LAN-A to LAN-B traffic only needs r2 while the r1-r3 link is down, so normally only internet access is lost. An engineer checks `show bgp summary` on r2 and `make drift`, then restores with `make apply` or redeploys r2"
    test: none (accepted risk)
  - mode: asymmetric return through the stateful fw1
    mitigation: By design. fw1 is single-homed on r1:eth3 and LAN-A is reached only through r1's static route, so both directions of every flow cross the same fw1 whichever core link is in use. The test opens a new web connection after the reroute, and its replies pass fw1 only as ESTABLISHED
    test: tests/live/test_failover.py::test_silent_failure_reroutes_fast
  - mode: split-brain
    mitigation: Not applicable. OSPF elects no master, and the /31 point-to-point links have no DR, so no two nodes can both claim a role. Revisit when a VRRP pair exists, with an alert for both routers claiming Master
    test: none (not applicable)
---

## Context

OSPF on the /31 point-to-point core links already reroutes a clean failure: the interface goes down, the adjacency drops at once, and traffic moves through r2. A link that stays up but passes nothing is different. A one-way fibre fault, a hung switch or media converter in the path, or a wrong ACL all look like that, and OSPF only notices when its 40 s dead timer runs out. With iptables dropping everything on r1 eth2 while the link stayed UP, r1 kept routing LAN-B traffic into it for 35.6 to 39.7 s (six runs).

## Decision

- `bfdd=yes` on the OSPF routers only (r1, r2, r3), with `-A 127.0.0.1` like the other daemons. Without it, bfdd's vty listens on 0.0.0.0:2617 on every lab link.
- ` ip ospf bfd` on every OSPF point-to-point interface, with FRR's default timers (300 ms transmit and receive, multiplier 3, so 0.9 s to detect). No `bfd` profile, because one that restates the defaults shows as drift forever.
- `expected_state.json` lists the BFD peers from the same links as the OSPF neighbors, and `test_bfd_sessions_up` checks every one is up.
- The drill runs on every push to main, every pull request, and nightly on a schedule so it still runs when nobody pushes.

## Consequences

- Measured in this lab, from the first DROP rule to r1's new route: 0.80-0.99 s over 15 runs of a polling script and 0.90-1.20 s over 7 runs of the test, 1.00-1.18 s with r1 and r3 capped at 0.2 CPU, and 2.0-2.6 s at 0.05 CPU. Without BFD: 35.6-39.7 s. The test allows 3 s.
- In those few minutes at 0.2 and 0.05 CPU, the r1-r2 BFD session logged no down events, so the default timers held up on a starved router. Tighter timers were not tried.
- Fail-back is slower than failover: 4.5-16.8 s, up to 19.1 s when CPU-capped. It waits for OSPF hellos (every 10 s) and a fresh adjacency before BFD comes back. Traffic keeps flowing through r2 in the meantime.
- r2 originates the default route with `always`, so if the ISP link fails it keeps attracting internet traffic and drops it. With one ISP there is no better exit. Remove `always` when a second ISP is added.
- fw1 and r1 are single points of failure for LAN-A. That is the price of keeping the stateful firewall single-homed.
- REC-4's split-brain alert cannot be test-fired, because there is no active/standby pair to split.
- GitHub runs scheduled workflows only on the default branch, and turns them off after 60 days with no repository activity.
