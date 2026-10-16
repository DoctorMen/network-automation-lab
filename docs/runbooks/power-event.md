---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead tells the service desk the site is down, when power is back, and when service is confirmed
last_reviewed: 2026-10-16
hosts: [r1, r2, r3, isp, fw1, h1, h2, noc]
written_by: Claude (AI assistant)
---
# Runbook: power came back after an outage

Every node lost power and has restarted. A router comes back with its startup config only; anything
typed by hand and never put into the inventory is gone. The firewall keeps no config at all: its rules
come back only because its start script runs. In the lab the power event is a whole-lab redeploy,
`sudo containerlab deploy -t build/topology.clab.yml --reconfigure`: every node is stopped and started
again from the rendered files. Not `make deploy`, which also sets the BGP password again at the end
and so skips what a real power cut does. `<lab>` below is the `name:` in `build/topology.clab.yml`.

## Who does what

- **Responder** (on-call network engineer): steps 2 to 8.
- **Coordinator** (NOC shift lead): step 1, decides when to start (not while power is still
  flapping), keeps the list of checks done, and escalates any node that doesn't come back.
- **Comms** (NOC shift lead): tells the service desk when power is back and again when step 6 passes.
  Not before: "power is back" is not "service is back".

## Steps

1. **Power is stable.** No restart in the last 10 minutes. Starting checks during a flap wastes them.
2. **Every node is running.** `docker ps --filter name=clab-<lab>- --format '{{.Names}} {{.Status}}'`
   lists the network's 8 nodes, and on a lab with the NOC (`make deploy`) its 16 sidecars too, all
   `Up`. A missing one: `make deploy` brings the whole lab back. A sidecar shares its node's network
   namespace ([decision 0018](../decisions/0018-noc-state-checks.md)), so it has to start after its
   node, and again each time its node does: one left running from before its node restarted has no
   network at all. A whole-lab redeploy starts them in that order.
3. **Routing is back.** First `make apply`: the r2–isp BGP password is in no startup config
   ([decision 0016](../decisions/0016-secrets-guardrails.md)), so the power cut took it, and against a
   real carrier the session stays down until it is set again. In the lab isp loses it too, so the
   session can come back with no password at all; after `make apply`,
   `docker exec clab-<lab>-r2 vtysh -c "show bgp neighbors 198.51.100.1"` says `Peer Authentication Enabled`.
   Then on r1, r2 and r3:
   `docker exec clab-<lab>-r1 vtysh -c "show ip ospf neighbor" -c "show bfd peers brief"`
   (two `Full`, two `up` each), and the same on `clab-<lab>-r2` and `clab-<lab>-r3`.
   On r2, `docker exec clab-<lab>-r2 vtysh -c "show bgp summary"`: 198.51.100.1 shows a prefix count.
   OSPF needs about 10 to 20 s after the nodes start (routing was back 10.8 to 20.2 s after the cut over four drills here).
   A router whose zebra or bgpd crashed as it started (V-011 in [verdicts.yml](../verdicts.yml): `ps` lists
   no zebra or bgpd, and its `docker logs` may say `crashed in startup` or nothing) is back seconds
   later, when watchfrr starts the daemon again: it waits 5 s, doubling for each restart in a row up to
   60 s, as the router's daemons file sets it. On a throwaway router zebra was back 5.8 to 15.7 s after
   one crash and 10.7 to 20.9 s after the next, over 15 runs. Wait for it. Before the daemons file set
   this, watchfrr waited 60 s, and on the full lab routing was back 73.9 and 83.7 s after the cut over
   two drills here.
4. **The firewall loaded its policy.** `docker exec clab-<lab>-fw1 iptables -vnL FORWARD`: policy
   `DROP`, five rules and `default-drop`. If the chain is empty with policy `ACCEPT`, the start
   script didn't run: `docker exec clab-<lab>-fw1 sh /firewall.sh`.
5. **Hosts are on their LANs.** `docker exec clab-<lab>-h1 ip route` shows `default via 10.10.10.1`,
   and `docker exec clab-<lab>-h2 ip route` shows `default via 10.20.20.1`.
6. **Users get through.** `docker exec clab-<lab>-h1 nc -z -w 3 10.20.20.10 80 && echo web ok`
   and `docker exec clab-<lab>-h1 ping -c 3 203.0.113.1`.
7. **Nothing came back different.** `make drift` passes. If someone reports "my fix disappeared",
   it was never in the inventory; it goes in through a pull request, not by typing it again.
8. **The NOC sees everything again** (a lab with the NOC). `make alerts` lists nothing firing but
   Watchdog, the alert path's heartbeat, which always fires ([decision 0022](../decisions/0022-dead-mans-switch.md)),
   once every source has sent its next heartbeat (up to 60 s): every scrape answers and every log source is
   heard from. Expect pages from the restart itself that resolve by themselves: in the drill here
   TargetDown, SourceSilent, OSPFNeighborDown, BFDPeerDown, BGPSessionDown and WebContentWrong.
   Prometheus and the pushgateway start empty in the lab, because their data is inside their
   containers, so the NOC's metric history from before the cut is gone. So are the commit `make apply`
   last applied, which step 3 records again, and each job's last success, which comes back when the job
   next runs ([RISK-44](../risks.yml)). The central log store keeps its data on the lab host's disk
   ([decision 0025](../decisions/0025-flight-recorder.md)), one copy ([RISK-35](../risks.yml)).

## Done when

Steps 2 to 8 pass. `make live` runs every check at once, if there is time, and `make observe` the
NOC's on a lab with the NOC.

## What happened before the cut

A node's own log went with the power, but every line it sent before the cut is in the central store,
which keeps its data on the lab host's disk ([decision 0025](../decisions/0025-flight-recorder.md)).
`make logs NODE=r2 MINUTES=15` prints r2's last 15 minutes from there. Each link that failed on the
way down left a flight-recorder dump (its interfaces, queues, filters and routing at that moment):
search the store for `{source="syslog"} |= "flightrec"`. For a power-down that is planned, run
`make evidence` first: it copies every node's dump and own log into `results/evidence/`. If the power
went twice within about a minute, the store may have lost some of what it took in between the two cuts
([V-027](../verdicts.yml), RISK-46), and a node's lines from before its route to the NOC came up at
boot never left it.

## If the lab host itself is gone

Rebuild on a new host: clone the repo, `make deploy`, `make drift`. The routers' last running
configs are in the backup repository ([docs/backups.md](../backups.md)), and `make restore-drill`
shows they boot. To load them instead of the inventory's: [restore-from-backup.md](restore-from-backup.md).

## Drill it in the lab

`make power-drill` does steps 2 to 8 by itself after a whole-lab redeploy (step 8 on a lab with
the NOC), and first makes a hand change on r2 that must be gone afterwards. Run by a person: the `containerlab deploy ... --reconfigure`
above is the power cut, then follow the steps from 1 and record the run in [dry-runs.yml](dry-runs.yml).
