---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead updates the service desk at the start, every 15 minutes and at close
last_reviewed: 2026-10-17
hosts: [sw1, h1, h3, fw1]
written_by: Claude (AI assistant)
---
# Runbook: a broadcast storm on a user LAN

Every host on LAN-A is slow or unreachable at once, the firewall's inside port is busy, and nothing is down.
A host is flooding broadcast frames, and the switch floods each one to every port of the VLAN. The job is to
name the port the storm comes in on before anything is blocked (OROS CON-1), then contain it at that port
without shutting it (CON-2). **Stated time to the port: 15 minutes.** The tool below takes seconds; the
rest is finding the room. `<lab>` is the `name:` in `build/topology.clab.yml`.

## Who does what

- **Responder** (on-call network engineer): steps 1 to 5. The only person who changes anything on the switch.
- **Coordinator** (NOC shift lead): owns the incident and its timeline, keeps anyone else off sw1, and
  escalates at 15 minutes without a port, or at once if the flood reaches a second VLAN.
- **Comms** (NOC shift lead): tells the service desk which LAN is affected and when the next update is.

## Steps

1. **Is it a storm, and from which port?** `make trace`. It reads every port's frames in and out twice,
   two seconds apart, and names the port whose inbound rate is over the threshold (ten times the storm
   control limit): `STORM from sw1:eth3 (edge port to h3:eth1): 19800/s in; source MAC(s) ...`. Every
   other port shows the same rate out and nearly nothing in: those only carry the copies. No port over the
   threshold means no storm; look elsewhere (hidden-loss, link-failure). Note the time: this is the
   trace the stated time counts to.
2. **Who is on that port?** `make where Q=<the MAC the trace printed>` names the address, the host the
   inventory records on that port, its owner and segment. A MAC the inventory doesn't know is an
   unrecorded machine: tell the coordinator, it goes in the incident record.
3. **Is storm control holding it?** The trace's line ends with how many frames the port's storm control
   has dropped. Rising means the other hosts already get at most the limit (100 frames a second) and
   their service holds; check from the user side: `docker exec clab-<lab>-h1 wget -q -O /dev/null -T 5 http://10.20.20.10/`.
   If the port has no storm control (the line says so), put it on: `make contain PORT=sw1:<port>`.
   Never `ip link set <port> down` on sw1: the host behind it loses everything, not just the excess, and
   the requirement is that the port stays up.
4. **Stop the source.** The host's owner stops what floods (in the lab: the storm script ends by itself).
   The port's own unicast was never blocked, so the host is reachable throughout:
   `docker exec clab-<lab>-h3 ping -c 2 10.10.10.1`.
5. **Confirm and record.** `make trace` reports no port over the threshold. Record the port, the MAC, the
   host, the time from the first symptom to step 1's answer, and whether storm control was already on.
   `make release PORT=sw1:<port>` only if the containment was added by hand in step 3 and the port is
   meant to run without it; the inventory's intent is storm control on every edge port.

## Why it floods

A broadcast frame (ARP's who-has, DHCP discover) is addressed to every host, so the switch sends a copy
out of every other port of the VLAN by design. One host sending them at thousands a second is a storm;
the switch does nothing wrong. The same happens to multicast and to unicast for a MAC the switch has not
learned (RISK-68 says only broadcast is policed here). A loop between two switches makes any single
broadcast into a storm; this LAN has one switch, so a loop can't be the cause.

## Done when

`make trace` shows no port over the threshold, h1 fetches h2's page, and h3 answers a ping on its own
port, which was never shut.

## Drill it in the lab

Helper, from h3: `docker exec -i clab-<lab>-h3 python3 - eth1 20000 60 < tests/live/tools/storm.py`
(60 s of broadcast at 20k frames a second, then it stops by itself). To see it uncontained first:
`make release PORT=sw1:eth3` before, `make contain PORT=sw1:eth3` after. Runner: from step 1.
