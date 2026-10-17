---
id: "0031"
title: Translate the users to one carrier-assigned address on r2, and log every translation to the NOC
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS FND-5: activity tied to one actor from logs the systems produce, including the real client behind NAT; given an outside complaint (public address, port, time), the collected logs alone name the internal host. The NAT must be no wider than needed, and must leave the WAN filter, the RTBH lever, the r2-isp MD5 session, make locate, the finding bundle, the backups and the NOC's tests working; the router image must not change"
alternatives:
  - name: do nothing
    why_not: LAN-A reaches the internet from its own 10.10.10.0/24, which only works because the stand-in carrier routes our aggregate back; a real carrier drops it (BCP 38), and there is no NAT for FND-5 to see through
  - name: translate to r2's own BGP address on the link (masquerade)
    why_not: Puts users' connections on the address r2's BGP session and the carrier's MD5 key use; a user's connection to the carrier's port 179 would come from the peer address. One address the carrier assigns and routes, beside the link, keeps the two apart
  - name: translate every inside network, servers included
    why_not: Wider than needed. The published server must keep its address for the WAN filter's published port and the RTBH trigger, and r2's own traffic must keep its own for BGP and the NOC's probes
  - name: iptables LOG on the NAT rule
    why_not: A container's network namespace gets no netfilter log lines while the host keeps net.netfilter.nf_log_all_netns at 0, its default (measured here; docs/selections/netshoot.md)
sources:
  - https://www.rfc-editor.org/rfc/rfc6302 (a server logging for abuse reports behind NAT needs the source port and an accurate time, not just the address)
  - https://www.rfc-editor.org/rfc/rfc2827 (BCP 38: a carrier drops traffic from addresses it did not assign)
stake: An abuse complaint about our address goes unanswered, or the wrong user is blamed, because nothing records which inside host held that port at that time
failure_modes:
  - mode: the NAT is wider than needed
    mitigation: One SNAT rule for LAN-A out of r2's ISP link only; the servers, r2 itself and every other device keep their addresses, and no other device has a NAT rule
    test: tests/live/test_nat.py::test_users_leave_from_the_assigned_address_and_nothing_else_is_translated
  - mode: someone widens it by hand and nobody notices
    mitigation: make drift compares r2's nat table with the intent, as it does the filter and raw tables
    test: tests/live/test_edge.py::test_edge_filter_hand_change_is_flagged
  - mode: the NAT address lets the internet in
    mitigation: Only replies to connections a user opened come back through it; anything else to it reaches no inside host
    test: tests/live/test_nat.py::test_nothing_reaches_inside_through_the_nat_address_unasked
  - mode: a complaint can't be tied to an inside host
    mitigation: A sidecar in r2's namespace sends every new translation (time, inside address and port, far end, outside port) to the NOC; `make whois` reads them back from Loki alone
    test: tests/live/observe/test_whois.py::test_a_complaint_names_the_inside_host_from_the_noc_alone
  - mode: an account on r2 forges a translation that names someone
    mitigation: The sidecar sends each line from UDP port 602, which no account in r2's namespace but root can send from (decision 0029), and the collector files a line under source nat only when it comes from that port of a router that translates; the same words sent any other way stay syslog
    test: tests/live/observe/test_accounting.py::test_a_record_an_account_forges_is_not_taken_for_one
  - mode: the lookup goes by port number and names the wrong host
    mitigation: It matches the outside address and port in each translation's reply direction, begun at or before the complaint's time, so two inside hosts on the same inside port are told apart by the outside port each got
    test: tests/live/observe/test_whois.py::test_the_same_inside_port_from_two_hosts_names_each_by_its_own_outside_port
  - mode: the translation log dies and nobody notices
    mitigation: It is a log source of its own (node r2, source nat) with its own SourceSilent rule and a heartbeat in the same pipe; with the sidecar stopped by hand, SourceSilent paged 93 s after its last line arrived (bound 120 s, twice the heartbeat; measured once here). `make testevent` makes a real translation and finds it
    test: tests/live/observe/test_arrival.py::test_synthetic_event_from_every_source_reaches_the_store
  - mode: a translation is lost on the way, or its end is unknown
    mitigation: Accepted. A complaint giving the far end's address and port narrows a reused outside port to one translation
    test: none (accepted risk RISK-63 in docs/risks.yml)
---

## Context

LAN-A (h1) reached the internet with its own private address, which the stand-in carrier routed back because it learns our 10.0.0.0/8 aggregate. A real carrier would drop it. FND-5 needs the real client behind NAT named from logs alone, and conntrack's table on r2 is the only place that knows the mapping, until the connection ends.

## Decision

- r2's `nat` block in the inventory: inside [10.10.10.0/24], address 198.51.100.64, out of its wan_filter interface (eth3). edge.sh renders one SNAT rule in the nat table's POSTROUTING. The carrier's isp gets a static route to 198.51.100.64/32 via our end of the link, as a carrier routes an address it assigns; it is not announced in BGP.
- The r2-nat-log sidecar (nicolaka/netshoot:v0.13, docs/selections/netshoot.md) runs build/r2/natlog.sh in r2's network namespace: `conntrack -E -e NEW --src-nat 198.51.100.64 -o timestamp,extended` and a heartbeat into one sender, the image's Python, which sends each line as syslog tagged nat to the collector's UDP 514 from port 602. The topology sets net.ipv4.ip_unprivileged_port_start to 1024 in r2's namespace, so only root there can send from that port. The collector files a line under source nat only when it comes from that port of a router that translates, and that source has its own SourceSilent rule.
- `make whois ADDR= PORT= AT= [REMOTE=]` (netlab/who.py flow) reads source nat from Loki around the time and names the inside host, its port and the far end for each translation that matches. More than one inside host on that outside port is reported as such, and the far end narrows it.
- `make drift` compares the nat table too. The lab job (no NOC) deploys without the sidecar; NAT itself is in edge.sh, so it runs there.

## Consequences

Users leave from one address, the published server and r2 keep theirs, and the WAN filter, RTBH trigger and MD5 session are unchanged, since none of their traffic is translated. The log records each translation's start only, as clear UDP (RISK-63, RISK-34). A translation line an account on r2 forges names no one; one forged on the campus from r2's address and port 602, or by root on r2 (RISK-60), would be taken. The other two parts of FND-5's Pass line, naming a host that saturates the uplink and per-tenant monthly volume, are not built here.
