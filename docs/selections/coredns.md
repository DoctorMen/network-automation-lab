---
kind: selection
id: coredns
title: CoreDNS for the lab's DNS, serving names generated from the inventory
date: 2026-10-17
status: accepted
decider: DoctorMen
constraint: "Free, in a public image pinned by digest; serve A and PTR records from one file netlab renders from inventory/network.yml, re-read when the file changes, from a sidecar in the NOC's network namespace with no change to the NOC's image; no forwarder, so a lab name can never leave the lab; one person runs it"
choice: coredns/coredns:1.11.3 as the noc-dns sidecar, with the hosts plugin on the root zone reading /hosts.lab (build/noc/hosts.lab, rendered by netlab/switch.py), `reload 5s`, errors to stderr, no forward plugin
uses: [coredns/coredns]
alternatives:
  - name: dnsmasq (4km3/dnsmasq:2.90-r3-alpine-3.22, pulled)
    why_not: Does the same job from a hosts file, but is also a DHCP server and a forwarder by default, so the config would have to switch things off rather than on; CoreDNS serves only what its Corefile names
  - name: busybox's own /etc/hosts on every node, rendered and bound in
    why_not: No query to make, so nothing to prove a record was served, and a node's Docker-managed resolv.conf and hosts file are the runtime's, not ours; a server answers one question from one place
  - name: BIND (bind9)
    why_not: Zone files, SOA serials and rndc for nine A records; a hosts file re-read on change is enough here, and no pulled image has it
  - name: no purchase, no DNS
    why_not: Free either way; but then the inventory feeds configs and monitoring and not DNS, which is the clause FND-4 names (sf:N8)
no_purchase: "The do-nothing option is addresses everywhere and no names, which is what the lab had. CoreDNS (Apache 2.0) is free; the cost is one more image to pull (85 MB, docker image inspect) and one sidecar's RAM (docs/sizing)."
staffing: "One person. The hosts file and the Corefile are rendered (netlab/switch.py, templates/monitoring/Corefile.j2); a host added to the inventory is in DNS on the next render with nothing typed twice (tests/test_derived.py). Help: CoreDNS's public issue tracker and docs, free."
vendor_domains: [coredns.io, github.com/coredns, hub.docker.com/r/coredns]
independent_sources:
  - "tests/live/observe/test_dns.py::test_every_inventory_name_resolves_to_its_address (our measurement: every name the inventory implies resolves at the NOC's server to that device's address, and back)"
  - "tests/live/observe/test_dns.py::test_a_name_the_inventory_lacks_is_refused (our measurement: a name no inventory entry implies is NXDOMAIN, so the zone is the inventory and nothing else)"
  - "tests/test_derived.py::test_added_host_appears_in_dns_and_monitoring_without_being_keyed_in_again (our measurement: a host added to the inventory is in hosts.lab, the probe targets and the alert rules on the next render)"
---

## Context

FND-4 says DNS, monitoring and IPAM entries are generated from, or checked against, one fleet record. The inventory already fed every config and the NOC's checks; nothing served names. The lab's nodes keep Docker's own resolv.conf, so the server is queried by address, and LAN-A's firewall admits only the web and the internet, so users on LAN-A can't ask it (RISK-67).

## Decision

CoreDNS in the NOC's network namespace, serving the root zone from one hosts file: every device's own address (a router's loopback, the firewall's inside address, a host's address) as `<device>.lab`, with PTR records from the same lines (V-034). No forwarder. The file is rendered on every `netlab render` and re-read by the server within 5 s of a change.

## Consequences

One server, plain UDP and TCP, on the NOC only: a lab convenience and a proof of generation, not a resolver the nodes use. Its listener is one more port the audit (`make audit`) expects on noc, named from the same inventory.
