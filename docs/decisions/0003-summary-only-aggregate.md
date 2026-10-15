---
id: "0003"
title: Send the ISP one summary-only aggregate
date: 2026-10-11
status: accepted
decider: DoctorMen
constraint: one ISP uplink on r2, and the ISP should see one stable route however the campus changes inside
alternatives:
  - name: do nothing
    why_not: with `redistribute ospf` alone, every /31 and LAN goes to the ISP, and every internal link flap becomes a BGP update there
  - name: aggregate without summary-only
    why_not: the /8 goes out, but so does every more-specific route, so nothing is hidden
  - name: network 10.0.0.0/8 with a blackhole static route
    why_not: common and fine, but it stays advertised even when r2 has lost the whole campus; the aggregate is withdrawn when no component route is left
  - name: outbound prefix-list allowing only the /8
    why_not: same result with more lines to keep in step with the address plan
sources:
  - https://docs.frrouting.org/en/stable-8.4/bgp.html#route-aggregation-ipv4-address-family (summary-only suppresses the more-specific routes)
  - https://www.rfc-editor.org/rfc/rfc4632 (CIDR; section 5.4 on advertising aggregates instead of internal more-specifics)
stake: if the suppression breaks, campus /31s and LANs leak to the ISP (test_isp_sees_only_the_aggregate fails); and the aggregate hides failures, so traffic for a dead campus subnet still arrives at r2 and is dropped there
---

## Context

r2 is the edge router with the only eBGP session (AS 65001 to AS 65100). It learns the campus from OSPF.

## Decision

r2 redistributes OSPF into BGP and announces `aggregate-address 10.0.0.0/8 summary-only` (`bgp.aggregate` in the inventory). The ISP gets one prefix.

## Consequences

- Internal changes, like the r1 to r3 link failure in `test_failover.py`, never reach the ISP.
- A real ISP would drop RFC 1918 space. In production the aggregate would be the campus's public block, with NAT at the edge. The lab keeps 10.0.0.0/8 so the behaviour is visible without a public block.
- `no bgp ebgp-requires-policy` is set because the lab has no route maps. That is a separate shortcut (RFC 8212 expects policy on eBGP), not part of this decision.
