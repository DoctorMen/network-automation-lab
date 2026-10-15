---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead tells the service desk the site is down, when power is back, and when service is confirmed
last_reviewed: 2026-10-15
hosts: [r1, r2, r3, isp, fw1, h1, h2]
written_by: Claude (AI assistant)
---
# Runbook: power came back after an outage

Every node lost power and has restarted. A router comes back with its startup config only; anything
typed by hand and never put into the inventory is gone. The firewall keeps no config at all: its rules
come back only because its start script runs. In the lab the power event is a whole-lab redeploy,
`make deploy` (`containerlab deploy --reconfigure`): every node is stopped and started again from
the rendered files. `<lab>` below is the `name:` in `build/topology.clab.yml`.

## Who does what

- **Responder** (on-call network engineer): steps 2 to 7.
- **Coordinator** (NOC shift lead): step 1, decides when to start (not while power is still
  flapping), keeps the list of checks done, and escalates any node that doesn't come back.
- **Comms** (NOC shift lead): tells the service desk when power is back and again when step 6 passes.
  Not before: "power is back" is not "service is back".

## Steps

1. **Power is stable.** No restart in the last 10 minutes. Starting checks during a flap wastes them.
2. **Every node is running.** `docker ps --filter name=clab-<lab>- --format '{{.Names}} {{.Status}}'`
   lists 7 nodes, all `Up`. A missing one: `make deploy` brings the whole lab back.
3. **Routing is back.** On r1, r2 and r3:
   `docker exec clab-<lab>-r1 vtysh -c "show ip ospf neighbor" -c "show bfd peers brief"`
   (two `Full`, two `up` each), and the same on `clab-<lab>-r2` and `clab-<lab>-r3`.
   On r2, `docker exec clab-<lab>-r2 vtysh -c "show bgp summary"`: 198.51.100.1 shows a prefix count.
   OSPF needs about 10 to 20 s after the nodes start (measured 19.6 s for the whole drill here).
4. **The firewall loaded its policy.** `docker exec clab-<lab>-fw1 iptables -vnL FORWARD`: policy
   `DROP`, five rules and `default-drop`. If the chain is empty with policy `ACCEPT`, the start
   script didn't run: `docker exec clab-<lab>-fw1 sh /firewall.sh`.
5. **Hosts are on their LANs.** `docker exec clab-<lab>-h1 ip route` shows `default via 10.10.10.1`,
   and `docker exec clab-<lab>-h2 ip route` shows `default via 10.20.20.1`.
6. **Users get through.** `docker exec clab-<lab>-h1 nc -z -w 3 10.20.20.10 80 && echo web ok`
   and `docker exec clab-<lab>-h1 ping -c 3 203.0.113.1`.
7. **Nothing came back different.** `make drift` passes. If someone reports "my fix disappeared",
   it was never in the inventory; it goes in through a pull request, not by typing it again.

## Done when

Steps 2 to 7 pass. `make live` runs every check at once, if there is time.

## If the lab host itself is gone

Rebuild on a new host: clone the repo, `make deploy`, `make drift`. The routers' last running
configs are in the backup repository ([docs/backups.md](../backups.md)), and `make restore-drill`
shows they boot.

## Drill it in the lab

`make power-drill` does steps 2 to 7 by itself after a whole-lab redeploy, and first makes a hand
change on r2 that must be gone afterwards. Run by a person: `make deploy` is the power cut, then
follow the steps from 1 and record the run in [dry-runs.yml](dry-runs.yml).
