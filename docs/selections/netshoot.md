---
kind: selection
id: netshoot
title: conntrack from the netshoot image for r2's translation log
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "Free, in a public image already pinned by digest; print each new NAT translation as the kernel makes it, with its time and both the inside and the outside address and port, from a sidecar in the router's network namespace without changing the router image; send each line to the collector the way the router's own syslog goes; one person runs it"
choice: nicolaka/netshoot:v0.13 (Alpine 3.19.1) as the r2-nat-log sidecar, running conntrack-tools 1.4.8 (`conntrack -E -e NEW --src-nat 198.51.100.64 -o timestamp,extended`) piped to the image's Python 3.12.3, which sends each line over UDP 514 from port 602, tagged nat
uses: [nicolaka/netshoot]
alternatives:
  - name: iptables LOG on the NAT rule
    why_not: A container's network namespace gets no netfilter log lines unless the host turns on net.netfilter.nf_log_all_netns, which only the host can set, and the lines would land in the host's kernel log, not the router's. Measured here with the sysctl at 0, its default, a LOG rule on r2 counted a packet and the kernel log got no line
  - name: a poller of /proc/net/nf_conntrack on r2 itself
    why_not: The router image has python3 and the file, but a poll sees a connection only if it outlives the interval, and reads the whole table each time; conntrack's event mode is told of each one by the kernel
  - name: ulogd2 with NFLOG
    why_not: The standard daemon for this, but in no image the lab has, and it needs a config and plugins of its own for a job one conntrack command does
  - name: no purchase, no translation log
    why_not: Free, and NAT works without it, but then an outside complaint about the NAT address names nobody inside, which is the requirement (OROS FND-5)
no_purchase: "The do-nothing option is NAT without its log, which leaves every LAN-A user hidden behind one address. conntrack-tools (GPLv2) and netshoot (Apache 2.0) are free; the cost is one more image to pull (775 MB unpacked, docker image inspect) and about 1 MiB of RAM while it runs (docker stats, measured here)."
staffing: "One person. The script is rendered from the inventory (templates/monitoring/natlog.sh.j2) and is one pipeline; the lookup is netlab/who.py. Help: the netfilter project's public mailing list and the image's public issue tracker, free."
vendor_domains: [github.com/nicolaka, hub.docker.com/r/nicolaka, netfilter.org]
independent_sources:
  - "tests/live/observe/test_whois.py::test_the_same_inside_port_from_two_hosts_names_each_by_its_own_outside_port (our measurement: the same inside port from two inside addresses to one far end leaves on two outside ports, and the log at the NOC names each)"
  - "tests/live/observe/test_whois.py::test_a_complaint_names_the_inside_host_from_the_noc_alone (the translation is searchable at the NOC within seconds of the connection, and names h1 and its port)"
  - "tests/live/observe/test_arrival.py::test_synthetic_event_from_every_source_reaches_the_store (the translation log is a source with its own last-seen check, and a real translation reaches the store on every observe run)"
---

## Context

FND-5 asks that a complaint from outside (an address, a port, a time) map to one inside host. r2 now translates LAN-A to one address (decision 0031), so the mapping exists only in r2's connection tracking table, which forgets each entry when the connection ends. It has to be written down, off the box, as each translation is made.

## Decision

A sidecar in r2's network namespace runs conntrack in event mode, filtered to connections translated to the NAT address, and sends each line to the collector from UDP port 602, tagged nat, with a few lines of the image's Python; util-linux logger can't choose its source port. Only root in r2's namespace can send from that port (decision 0029), and the collector files those lines as their own source (node r2, source nat) only when they come from it, with its own heartbeat and SourceSilent check. `make whois` reads them back from Loki.

## Consequences

The image is far larger than the one tool used from it; a smaller image with only conntrack-tools would need building, which this lab doesn't do (it pulls only pinned public images). The lines travel as clear UDP like the rest of syslog (RISK-34), so one can be lost, or forged by a host on the campus from r2's address and that port; a dead log pages as SourceSilent within twice its heartbeat (with the sidecar stopped by hand, 93 s after its last line arrived, against a bound of 120 s; measured once here). Outside pages about conntrack could not be opened from the sandbox this was built in, so the sources above are our own runs only.
