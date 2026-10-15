---
id: "0013"
title: Treat LAN-B as a toy payments segment and keep its scope small by segmentation
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: A seven-node lab with no assessor, no card data and no budget; the only scope-reducing design it can really demonstrate is segmentation, enforced on the devices we own
alternatives:
  - name: do nothing
    why_not: No system had a recorded scope decision, and nothing proved the segment was kept apart; before 0012 the isp node reached h2:22 and h2:80 straight through r2 and r3
  - name: everything in scope (no segmentation)
    why_not: The honest default ("everything is in scope until proven otherwise"), but it makes the user LAN and every router carry the full requirement set, which is what segmentation is for
  - name: a three-legged fw1 with LAN-B behind it
    why_not: Cleaner, one firewall in front of the segment from every side, but it rewires r1 and r3, the static route to LAN-A and the failover tests; r2's edge filter (0012) closes the internet side with no topology change
  - name: close ICMP from LAN-A to LAN-B on fw1
    why_not: The dataplane, failover and firewall tests ping h2 from h1 and would all have to move to TCP:80; the pings are recorded as an exception instead, and whether that is acceptable is left to an assessor
  - name: tokenisation or outsourcing the payment page
    why_not: The real answer for a small shop (the card data never touches its network), but there is nothing in a lab to tokenise; recorded as the design to prefer in production
sources:
  - https://www.usd.de/en/pci-dss-new-guidance-on-scoping-and-network-segmentation/ (summary of the PCI SSC scoping guidance's categories - CDE, connected-to and security-impacting, out of scope)
  - https://wazuh.com/resources/WAZUH-PCI_DSS-V4.0-guide-V2.0.pdf (quotes PCI DSS v4.0 1.3.1, 1.3.2, 1.4.1-1.4.3 and 11.4.5 word for word)
  - https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/11/04/05/ (11.4.5 in v4.0.1)
  - https://www.pcisecuritystandards.org/document_library/ (the standard itself, behind a licence click-through; not read for this record)
stake: If segmentation leaks, every out-of-scope system is in scope after all and the register is wrong; if the register misses a system on the segment, that system goes untested and unfiltered
failure_modes:
  - mode: an out-of-scope device reaches a CDE service it shouldn't
    mitigation: fw1 (LAN-A) and r2 (internet) filter; the published port and the register's one exception (pings from h1) are the only ways in, and the test probes TCP and ICMP
    test: tests/live/test_scope.py::test_out_of_scope_cannot_reach_in_scope
  - mode: a new system lands on the segment, or a filtering device is called out of scope, without a register entry
    mitigation: netlab validate refuses an inventory where a device has no scope decision, anything on LAN-B is not a cde system, anything that filters is out of scope, or an exception gives no reason
    test: tests/test_scope.py::test_register_the_topology_contradicts_is_refused
---

## Context

OROS ATT-1 asks for a recorded scope decision for every system touching regulated data, naming the
framework clause, the scope-reducing design and the assessor's acceptance or the open question, plus
an automated test that the segmentation keeps out-of-scope systems out. The lab holds no card data,
so this is a toy: LAN-B plays the payments segment (the cardholder data environment, CDE), and h2's
web port plays the payment page.

## Decision

- **The register is the `scope:` block in `inventory/network.yml`**, next to the devices it talks
  about, so a change to either goes through the same review. Every device is either in `systems`
  (with a category, the PCI DSS v4.0.1 clause that governs it and why) or in `out_of_scope`.
- **Categories follow the PCI SSC scoping guidance.** h2 and r3 are on LAN-B, so they are CDE systems.
  r2 and fw1 filter traffic into the segment, so they are security-impacting. r1 routes LAN-A's
  traffic to it and filters nothing: connected-to. h1 and isp are out of scope. `netlab validate`
  enforces the parts the topology decides: what is on the segment is CDE, and whatever filters is in
  scope.
- **The design is segmentation**, enforced on fw1 for LAN-A and on r2 for the internet (0012).
  Out-of-scope systems may reach only the published port, h2:80, and the register's exceptions.
- **One exception: h1 may ping the segment** (`exceptions:` in the register), for monitoring and
  troubleshooting from the user LAN through fw1's allow-icmp. The lab's dataplane, failover and
  firewall tests ping h2 from h1; closing ICMP on fw1 would mean moving all of them to TCP:80, and the
  operator would lose ping as a first check toward the servers. The internet gets no such exception:
  r2 drops pings forwarded from the ISP. An exception must name an out-of-scope source, be ICMP (TCP
  into the segment is what `published` decides) and say why, or `netlab validate` refuses it.
- **Acceptance is open.** No assessor has looked at this; the register says so.
- **The reachability tuples are generated** (`segmentation` in `expected_state.json`): for every
  out-of-scope device, every service of every host on LAN-B (open if published) and a ping to every
  device on LAN-B, h2 and r3's LAN-B address (open if the register has an exception for that
  source). So every listed service and every ping into the segment is either in the register or
  refused. The live test probes each one, and proves each closed one answers from another device on
  LAN-B, so the block is policy.
- **Clause wording** (1.3.1 inbound to the CDE restricted to what is necessary, 1.4.1-1.4.3 controls
  between trusted and untrusted networks and anti-spoofing, 11.4.5 penetration tests of segmentation
  controls) was checked against the sources above, which quote the standard, not against the PCI SSC
  document itself.

## Consequences

- The open question an assessor would ask first: LAN-A reaches the segment on h2:80 and on ICMP
  (h2 and r3). The lab treats LAN-A like any internet client of the payment page, plus the recorded
  ping exception, but a strict reading of "connected-to" could pull LAN-A into scope. Nobody has made
  that call. If an assessor does, the fix is a fw1 rule (and the ping-based tests move to TCP), and
  the tuples change with it.
- The exception is wider than its reason: allow-icmp passes every ICMP type, and the test probes
  echo only.
- Outbound from LAN-B is not restricted (1.3.2 is not met): h2 can open connections anywhere.
- 11.4.5 wants segmentation tested at least every 12 months by a qualified, independent tester. The
  nightly test is the operator's own check between those, not a substitute.
- The test probes the services the inventory lists. Ports nothing listens on are covered from the
  internet side by the WAN scan (0012) and from LAN-A by fw1's default drop.
