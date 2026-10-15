---
id: "0006"
title: Use documentation address ranges for the ISP side
date: 2026-10-11
status: accepted
decider: DoctorMen
constraint: the lab's "internet" must never collide with real addresses that a laptop or CI runner running the lab might route to
alternatives:
  - name: do nothing
    why_not: picking any public-looking block (say 8.8.8.0/24) would shadow a real destination if a lab route ever reached the host, and confuses readers
  - name: RFC 1918 space for the ISP side
    why_not: collides with the campus's own 10.0.0.0/8, or with the 192.168.x.x of a home or office network
  - name: shared address space 100.64.0.0/10 (RFC 6598)
    why_not: reserved for carrier-grade NAT, and some VPN products use it on the very machines the lab runs on
sources:
  - https://www.rfc-editor.org/rfc/rfc5737 (192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are for documentation)
  - https://www.rfc-editor.org/rfc/rfc1918 (private address space, used for the campus)
stake: low; the cost of getting it wrong is a lab route hiding a real destination on someone's machine, which is hard to spot
---

## Context

The ISP node needs a peering /31 and an "internet" prefix that h1 can ping.

## Decision

The eBGP link is 198.51.100.0/31 (TEST-NET-2) and the ISP originates 203.0.113.0/24 (TEST-NET-3). RFC 5737 says these "SHOULD NOT appear on the public Internet".

## Consequences

- Nothing in the lab can be mistaken for, or routed instead of, a real address.
- The ASNs (65001, 65100) are from the private-use range (RFC 6996), not the documentation ASNs (64496-64511, RFC 5398). They never leave the lab either, so this was left as it is.
