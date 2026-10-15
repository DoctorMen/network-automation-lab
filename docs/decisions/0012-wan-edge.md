---
id: "0012"
title: Publish only h2:80, filter the internet edge on r2, refuse forged sources at every edge, blackhole at the ISP on demand
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: The routers and fw1 are the only enforcement points we own, iptables in the FRR image is the only filtering tool, and the DDoS lever must cost nothing until it is pulled
alternatives:
  - name: do nothing
    why_not: Measured before this change, from the isp node with nc and the scan tool in tests/live/tools/scan.py, from 198.51.100.1 and 203.0.113.1 alike - h2:22, h2:80, r2's 179 on 198.51.100.0 and on its loopback all answered; 5 of 5 SYNs h1 forged as 10.20.20.99 reached h2 through allow-web, and 5 of 5 forged pings reached the ISP through allow-icmp
  - name: publish nothing (h2:80 closed to the internet too)
    why_not: Tightest, but the toy payment page then has no customers, and the DDoS lever has nothing realistic to protect; the blackhole test needs a host the internet can reach
  - name: publish h2 entirely, or forward everything and rely on host firewalls
    why_not: h2:22 is an admin port; PCI DSS 1.4.2 allows inbound only to authorised public services and replies, and every host's own firewall would be one more thing to drift
  - name: strict uRPF (rp_filter=1) on r2's ISP link instead of the RFC 1918 list
    why_not: Works only while r2 is single-homed and has no default route; with a second ISP or a full table it drops real traffic (RFC 3704 section 2.4), and it has no named counter to read
  - name: a Null0 trigger route for RTBH (the textbook trigger)
    why_not: r2 would blackhole the host for the campus too, including LAN-A's traffic to h2 on the failover path through r2; pointing the trigger at the host's real gateway drops it only at the ISP
  - name: a scrubbing service or CDN in front of h2
    why_not: Keeps the host up under attack, but needs a contract and usually an always-on fee; OROS REC-7 asks for on-demand mitigation sized to an occasional threat
sources:
  - https://www.rfc-editor.org/rfc/rfc2827 (BCP 38, ingress filtering of forged source addresses)
  - https://www.rfc-editor.org/rfc/rfc3704 (BCP 84, strict and loose reverse-path filtering, and where each fits)
  - https://www.rfc-editor.org/rfc/rfc1918 (private address space that never comes from the internet)
  - https://www.rfc-editor.org/rfc/rfc7999 (BLACKHOLE community; the receiver keeps blackholes local with NO_EXPORT)
  - https://www.rfc-editor.org/rfc/rfc5635 (remote-triggered blackhole filtering)
  - https://docs.frrouting.org/en/stable-8.4/bgp.html (unsuppress-map, disable-connected-check, community lists)
  - https://wazuh.com/resources/WAZUH-PCI_DSS-V4.0-guide-V2.0.pdf (quotes PCI DSS v4.0 1.4.2 and 1.4.3 word for word)
stake: If the edge filter is wrong, either the internet reaches management ports and h2:22 again, or a return path breaks and users lose the internet (test_lan_a_reaches_internet) or r2 loses BGP; a blackhole left on keeps the host off the internet after the attack
failure_modes:
  - mode: a management port or unpublished service answers from the internet
    mitigation: r2's INPUT and FORWARD on eth3 accept only replies, ping to r2 itself, BGP from the peer's address to ours, and the hosts' published ports; everything else there is dropped and counted
    test: tests/live/test_edge.py::test_wan_scan_finds_only_published_ports
  - mode: a forged source address gets past an edge we control
    mitigation: fw1 drops non-LAN-A sources on eth1 in the raw table (the test below), r3 runs strict rp_filter on its LAN-B interface (tests/live/test_edge.py::test_server_lan_cannot_forge_its_source), r2 drops RFC 1918 sources from the ISP in the raw table (tests/live/test_edge.py::test_internet_cannot_forge_a_private_source)
    test: tests/live/test_edge.py::test_lan_a_cannot_forge_its_source
  - mode: the internet edge filter or an anti-spoof rule is changed or flushed by hand
    mitigation: "`make drift` replays r2's edge.sh and fw1's firewall.sh in an empty network namespace and diffs filter and raw tables with the live ones"
    test: tests/live/test_edge.py::test_edge_filter_hand_change_is_flagged
  - mode: the blackhole lever doesn't work when it's needed
    mitigation: The whole path (trigger on r2, community, ISP next-hop rewrite, kernel blackhole, lift) runs in every CI run
    test: tests/live/test_rtbh.py::test_rtbh_blackholes_only_the_attacked_host
  - mode: a blackhole left on after the attack
    mitigation: The trigger is never in the intent, so `make drift` fails and names it while it is on (checked by hand on 2026-10-15)
    test: none (accepted risk RISK-20 in docs/risks.yml; no test leaves a trigger on, and the drift check's own tests prove it flags unsaved lines)
  - mode: something on r2 answers the ISP over IPv6
    mitigation: Accepted risk. Nothing filters IPv6 and the scan is IPv4 only. Under real containerlab the links may get IPv6 link-local addresses, so bgpd may also listen on [::]:179; only the directly attached ISP can reach a link-local address, and BGP from it is allowed anyway
    test: none (accepted risk RISK-21 in docs/risks.yml; this sandbox kernel has no IPv6 to test with)
  - mode: a host on LAN-A forges another LAN-A address
    mitigation: Accepted risk. Subnet-level checks can't see it; that needs per-port binding on a switch (OROS CON-1), and the lab has no switch
    test: none (accepted risk RISK-22 in docs/risks.yml; no switch to bind ports on)
---

## Context

fw1 filtered only LAN-A. Nothing filtered the ISP link, so from the internet side (the isp node, from
its link address 198.51.100.1 and from 203.0.113.1 on its loopback) h2:22, h2:80 and r2's BGP port on
both its link address and its loopback all answered. No edge checked source addresses: fw1's
allow-icmp and allow-web have no source match, rp_filter was 0 everywhere, so h1 could send as a
server, h2 as a user, and the internet as a campus address.

Two scoring designs disagreed on whether h2:80 is published to the internet. The scope register
(0013) wanted LAN-B closed, the management-plane design wanted the web port open, and the DDoS lever
needs an attacked host the internet can reach.

## Decision

- **h2:80 is published; nothing else is.** It is the toy payment page, so customers on the internet
  must reach it. h2:22 is an admin port and stays inside. `published: [80]` on h2 in the inventory is
  the one place this is decided: r2's filter, the scope register's reachability tuples, the WAN scan's
  expected result and the blackhole trigger are all generated from it.
- **r2 filters what arrives on eth3**, rendered to `build/r2/edge.sh` and run by the topology's exec
  step, the PCI DSS 1.4.2 shape: replies to what the campus started (ESTABLISHED,RELATED), ping to r2
  itself so the carrier can test the link, BGP from the peer's address to ours only, and a SYN to each
  published port. Everything else on eth3 is dropped and counted (`wan-drop`, `wan-drop-local`). The
  campus links are not filtered.
- **Forged sources are refused at every edge we control** (BCP 38). fw1's raw table drops anything on
  its inside interface that isn't from LAN-A, before any FORWARD rule, so it covers allow-icmp and
  allow-web too; allow-internet is also bound to `-i eth1`. r3's interface toward LAN-B runs strict
  reverse-path filtering: a LAN sits behind exactly one router interface, so that can't drop real
  traffic (RFC 3704 2.2). Every router interface toward a host LAN gets it, from the inventory's links.
  r2's raw table drops RFC 1918 sources arriving from the ISP, before routing.
- **The DDoS lever is a customer-triggered blackhole at the ISP** (`rtbh:` in the inventory). r2
  redistributes static routes tagged 666 into BGP with community 65100:666, and `unsuppress-map` lets
  that /32 past the summary-only aggregate (0003). The ISP turns a /32 inside our aggregate with that
  community into a route to 192.0.2.1, which it sends to Null0, adds no-export, and needs
  `disable-connected-check` because that next hop is not on the link. The trigger route's next hop is
  the host's own gateway, so r2 keeps forwarding to it. It is pulled by hand during an attack
  ([runbook](../runbooks/ddos-rtbh.md)).

## Consequences

- From the isp node, a scan of every campus address on 27 TCP management ports finds only h2:80
  open, plus 198.51.100.0:179 from the peer's address; from 203.0.113.1, only h2:80. UDP is not
  scanned (nothing in the lab speaks SNMP).
- conntrack now runs on r2. It tracks every flow through r2, the campus links included.
- A BGP session that came up before edge.sh ran: if the ISP opened it, the BGP rule (no `--syn`)
  matches its packets by address and port; if r2 opened it, the ISP's packets are dropped until r2's
  next keepalive (at most 60 s, inside the 180 s hold time) lets conntrack pick the flow up as r2's.
  Reasoned, not measured: in every deploy here the session came up after edge.sh (the rule had
  counted the ISP's SYN).
- The ISP stand-in now carries the carrier's side of the RTBH service. A real carrier publishes its
  own community and rules; ours copies the common shape.
- While the blackhole is on, the ISP sees one /32 besides the aggregate. test_isp_sees_only_the_aggregate
  runs with no trigger on; the RTBH test checks that the /32 is the only extra route.
- Outbound traffic from LAN-B is not restricted anywhere (PCI DSS 1.3.2, a gap 0013 records).
- r2's reverse-path filter is left off on purpose; the RFC 1918 list does that job and keeps working
  with a second ISP.
- IPv6 is not filtered (no ip6tables rule) and not scanned. This sandbox's kernel has no IPv6 at all
  (no /proc/sys/net/ipv6), so nothing here could show it open or prove a fix closed it. Under real
  containerlab the veths may get IPv6 link-local addresses, and bgpd may then also listen on [::]:179,
  reachable from the ISP's link-local address on eth3. Only the directly attached ISP can reach a
  link-local address, BGP from it is allowed over IPv4 anyway, and no IPv6 route exists to forward
  anything into the campus (all reasoned, not measured). Disabling IPv6 on eth3 (one sysctl in
  edge.sh) would close it, but here it could be neither run nor tested, so it is recorded instead.
