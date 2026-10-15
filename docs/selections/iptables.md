---
kind: selection
id: iptables
title: iptables for the lab firewall
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "Every node runs the one FRR 8.4.1 image (inventory platform:), so the firewall can use only what that Alpine 3.15.6 image ships; rules are rendered from the inventory and must be readable as one shell script"
choice: iptables 1.8.7 (legacy backend), from the FRR image, in fw1/firewall.sh
uses: [iptables]
alternatives:
  - name: nftables
    why_not: The kernel side is there, but the image has no `nft` command (checked with `which nft` on a lab node), and adding a package breaks the one-image rule the platform test enforces
  - name: a separate firewall appliance image (pfSense, OPNsense, a vendor firewall)
    why_not: A second image to pull and pin, and most are VMs rather than containers, so they don't fit the runner
  - name: do nothing (no firewall)
    why_not: LAN-A would be open to the server LAN and the internet stand-in, and the firewall drills would have nothing to test
no_purchase: iptables is already in the image, so the choice costs nothing; doing without a firewall is the only cheaper option, and the alternatives above say why not.
staffing: k alone; iptables rules are the most widely documented Linux firewall syntax.
vendor_domains: [netfilter.org]
independent_sources:
  - "tests/live/test_controls.py::test_unsolicited_inbound_ack_is_dropped (our test: the rendered rules drop a forged mid-stream packet)"
  - "tests/live/test_dataplane.py::test_firewall_blocks_ssh_to_servers (our test: the deny rule really drops)"
  - "https://en.wikipedia.org/wiki/Nftables (nftables replaces the legacy iptables component of Netfilter, with syntax-compatible iptables commands for the transition)"
---

## Context

fw1 sits between LAN-A and r1 and needs a stateful, default-drop policy rendered from the inventory.

## Decision

iptables from the FRR image, rendered into fw1/firewall.sh and run at deploy.

## Consequences

iptables is the legacy interface that nftables replaces. When the image moves to one that ships `nft`, iptables-translate can turn these rules into nftables rules.
