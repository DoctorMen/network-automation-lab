---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead updates the service desk at the start, every 30 minutes and at close
last_reviewed: 2026-10-15
hosts: [r1, r2, r3, fw1, h1]
written_by: Claude (AI assistant)
---
# Runbook: a core link has failed

A link between two core routers has gone down, or stays up and passes nothing. OSPF (with BFD for the
silent case) should already have moved traffic to the other path, so users may see nothing. The job is
to confirm that, find the link, fix it and see traffic fail back. `<lab>` below is the `name:` in
`build/topology.clab.yml` (`netauto` unless you renamed it).

## Who does what

- **Responder** (on-call network engineer): steps 1 to 6. The only person who changes anything on a router.
- **Coordinator** (NOC shift lead): owns the incident and its timeline, makes sure nobody else is
  changing the same routers, and escalates after 30 minutes, or at once if the link has no backup path.
- **Comms** (NOC shift lead): tells the service desk what is affected and when it will be updated next.

## Steps

1. **Find the link.** On each core router, `show ip ospf neighbor` should list two neighbors `Full`
   and `show bfd peers brief` two peers `up`:
   `docker exec clab-<lab>-r1 vtysh -c "show ip ospf neighbor" -c "show bfd peers brief"`,
   then the same on `clab-<lab>-r2` and `clab-<lab>-r3`. The link is the one whose neighbor is
   missing at both ends. `show interface description` on either end names the far side
   (`to-r3:eth2`).
2. **Check users still get through.** The server LAN from LAN-A, through the firewall:
   `docker exec clab-<lab>-h1 nc -z -w 3 10.20.20.10 80 && echo web ok`. And the path taken:
   `docker exec clab-<lab>-r1 vtysh -c "show ip route 10.20.20.0/24"`. With r1-r3 down it goes
   via 10.0.12.1 (r2). If the dead link is fw1-r1 or r3-h2 there is no other path: that LAN is down,
   tell the coordinator now.
3. **Down or silent?** On both ends: `docker exec clab-<lab>-r1 ip -s link show eth2`.
   - `state DOWN`, or `NO-CARRIER`: the link is down. Physical layer: cable, optic, port, or the far
     router. In the lab, someone ran `ip link set eth2 down`.
   - `state UP` at both ends but the BFD peer down: the link is up and passes nothing in at least
     one direction (one-way fibre, a bad media converter, a filter). Read `ip -s link` at both ends
     twice, 5 s apart. TX rising at one end while RX stays flat at the other: lost on the wire. TX
     flat while the router is sending: discarded on the box itself. In the lab that is a drop rule,
     shown by `docker exec clab-<lab>-r1 iptables -vnL INPUT` and the same with `OUTPUT`.
4. **Fix it.** In the lab: `docker exec clab-<lab>-r1 ip link set eth2 up`, or delete the drop rule
   with the same `iptables` line and `-D`. In a real network: a ticket to whoever owns the cable
   or the far end, with the interface, both ends' counters from step 3, and the time it started.
5. **See it fail back.** Step 1 again: both neighbors `Full`, both BFD peers `up`. OSPF needs a
   few hello intervals (measured 4.5 to 16.8 s). `show ip route 10.20.20.0/24` on r1 goes back to
   its own eth2 (via 10.0.13.1).
6. **Prove nothing else changed.** `make drift` passes. If it names a line, follow
   [config-drift.md](config-drift.md) before closing.

## Done when

Every core router has two `Full` neighbors and two BFD peers `up`, h1 reaches 10.20.20.10:80, and
`make drift` passes. Comms tells the service desk it is closed and what failed.

## Drill it in the lab

Have someone else break one of these without telling you which, then follow the steps from 1:
`docker exec clab-<lab>-r1 ip link set eth2 down` (down), or
`docker exec clab-<lab>-r1 iptables -I INPUT -i eth2 -j DROP` plus the same with `-I OUTPUT -o eth2`
(silent). Record the run in [dry-runs.yml](dry-runs.yml).
