---
id: "0032"
title: A Linux-bridge switch on LAN-A, and one query that says where an address is, what listens, and what the lab's names are
date: 2026-10-17
status: accepted
decider: DoctorMen
constraint: "OROS FND-4: one query answers which switch port and VLAN an address, MAC or name is on, edge port or uplink, from ARP and per-VLAN MAC tables over read-only access; discovery compares what is listening with the record; DNS and monitoring are generated from the one record. The lab's nodes must stay plain Containerlab linux nodes on the one pinned image, and every existing test must keep passing with a switch between LAN-A's hosts and their firewall"
alternatives:
  - name: do nothing
    why_not: LAN-A was one veth pair, h1 to fw1. There is no port to find a host on, no second host to move it next to, and FND-4's first clause has nothing to answer
  - name: Containerlab's bridge or ovs node kinds
    why_not: "Those are the lab host's own bridges, outside any node: no node to run `bridge fdb show` on, no owner, and the sandbox stand-in deploys only plain containers. A linux node that runs `ip link add br0 type bridge` is a switch the inventory can own"
  - name: Open vSwitch in a container
    why_not: A second image and a daemon for one access switch; the kernel bridge keeps a MAC table per VLAN already (vlan_filtering), which is the table the query joins
  - name: a port scan from the NOC instead of ss on each host
    why_not: "A scan sees what a filter lets through, not what listens: fw1 hides h2's port 22 from LAN-A, and the record is about the host. `ss -ltnp` on the host names the program too, which a scan can't"
  - name: hand-written DNS and target files
    why_not: The second place to key a host in is the one that drifts; FND-4's third clause is that there is none (sf:N8)
sources:
  - https://www.kernel.org/doc/html/latest/networking/switchdev.html (the bridge's per-VLAN FDB and vlan_filtering, as the kernel's switch model)
  - https://man7.org/linux/man-pages/man8/bridge.8.html (bridge fdb show, bridge vlan show)
  - https://coredns.io/plugins/hosts/ (A and PTR records served from a hosts file, reloaded on change)
stake: A host nobody can find on a port takes a walk with a cable tracer at 3 a.m.; a service nobody recorded is the one the next audit, or the next attacker, finds first; a name keyed in twice is wrong in one place
failure_modes:
  - mode: the table says where a host was, not where it is
    mitigation: Nothing is cached. A query reads the gateways' neighbor tables and the switch's MAC table at that moment; the bridge relearns a MAC on the port it last spoke from
    test: tests/live/test_where.py::test_moved_host_found_on_new_port
  - mode: a port's VLAN is reported from the inventory, not from the switch
    mitigation: The VLAN in the answer is the one the MAC table learned the address in; where the kernel has no VLAN filtering the answer says so (plain bridge), and the test skips the VLAN rather than reading it from the record
    test: tests/live/test_where.py::test_the_answer_names_the_vlan
  - mode: a listener nobody recorded stays unknown
    mitigation: make audit lists every TCP listener on every host we own against its services and the sidecar ports the inventory implies, on every CI run; a stand-in on a recorded port is named by its program
    test: tests/live/test_where.py::test_unrecorded_service_on_next_audit
  - mode: a host added to the record is missing from DNS or monitoring
    mitigation: hosts.lab, the probe targets and the alert rules are rendered from the same inventory; a host added there is in all three on the next render
    test: tests/test_derived.py::test_added_host_appears_in_dns_and_monitoring_without_being_keyed_in_again
  - mode: the DNS answers more than the inventory
    mitigation: "No forwarder, the root zone served from the one file: anything else is NXDOMAIN"
    test: tests/live/observe/test_dns.py::test_a_name_the_inventory_lacks_is_refused
  - mode: the inventory and the links disagree about the switch
    mitigation: netlab validate refuses a port on no link, a link to no port, two subnets in one VLAN, two VLANs on one subnet, an address on a switch port or missing elsewhere
    test: tests/test_switch.py::test_a_switch_the_links_contradict_is_refused
  - mode: the switch's own config is not read back
    mitigation: Accepted. switch.sh is read-only intent like firewall.sh, but make drift doesn't collect sw1
    test: none (accepted risk RISK-65 in docs/risks.yml)
---

## Context

Every LAN in the lab was one veth pair, so "which port is this on" had no answer and nothing could move. The inventory fed configs, topology and the NOC's checks, but not names, and nothing compared what listened on a host with what the inventory said should.

## Decision

- `switches:` in the inventory: sw1 (owner, bridge br0, ports each with a VLAN, storm control). Links to a switch port carry no address (`sw1:eth2`); so does a host's spare port into the switch (`h1:eth2`), which the topology leaves down. A port is an edge port when a host hangs off it, an uplink otherwise, from the links alone.
- build/sw1/switch.sh, rendered: `ip link add br0 type bridge vlan_filtering 1`, each port an access port in its VLAN (pvid, untagged, VLAN 1 removed). A kernel that refuses VLAN filtering (the sandbox, V-033) gets a plain bridge and the fact in /run/switch.state. sw1 runs the one pinned image with `sleep infinity`, like fw1.
- `make where Q=` (netlab/where.py): `ip -j neigh show` on every router and firewall we own and `bridge -j fdb show` on every switch we own, joined; the answer names the gateway that knows the MAC, the switch, port, VLAN, role, far end, the inventory's record and whether the host has moved from it.
- `make audit` (netlab/audit.py): `ss -ltnpH` on every host we own against `services` plus the sidecar ports the inventory implies (netlab.monitoring.listeners); listeners on 127.0.0.1 only are reported, not judged. CI's lab job runs it on every run.
- `dns:` in the inventory and CoreDNS as the noc-dns sidecar (docs/selections/coredns.md), serving build/noc/hosts.lab: `<device>.lab` for every device's own address, PTR from the same lines.

## Consequences

LAN-A is a real broadcast domain with three ports and a spare, which CON-1 and CON-2 build on (decisions 0033 and 0034). h3 joins h1 as an out-of-scope user and gets the same ICMP exception; the segmentation test probes from it too. The switch has no address, so it probes nothing and is in no DNS. Only hosts are audited, only TCP (RISK-69); nothing points its resolver at the DNS (RISK-67); sw1 is not collected by `make drift` (RISK-65). VLAN filtering is proved only where the kernel has it (RISK-66).
