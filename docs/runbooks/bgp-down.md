---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead updates the service desk at the start, every 30 minutes and at close; the carrier gets a ticket only with the evidence from step 4
last_reviewed: 2026-10-15
hosts: [r1, r2, h1]
written_by: Claude (AI assistant)
---
# Runbook: the BGP session to the ISP is down

Users can reach the server LAN but nothing on the internet (203.0.113.0/24). The eBGP session from
r2 to the carrier (198.51.100.1, AS 65100) is not `Established`. r2 still sends a default route into
OSPF (`default-information originate always`), so the core keeps sending internet traffic to r2,
which now has nowhere to send it. `<lab>` below is the `name:` in `build/topology.clab.yml`.

## Who does what

- **Responder** (on-call network engineer): steps 1 to 6. Only the responder changes r2.
- **Coordinator** (NOC shift lead): owns the incident, decides when it is the carrier's (step 4) and
  opens that ticket, and stops anyone "trying things" on r2 while the responder works.
- **Comms** (NOC shift lead): tells the service desk the internet is down and the internal network is
  not, and when the next update is.

## Steps

1. **Confirm it.** `docker exec clab-<lab>-r2 vtysh -c "show bgp summary"`. The 198.51.100.1 line
   shows a state such as `Idle`, `Active` or `Connect` instead of a prefix count.
   `docker exec clab-<lab>-h1 ping -c 3 203.0.113.1` fails; `ping -c 3 10.20.20.10` works.
2. **Read why.** `docker exec clab-<lab>-r2 vtysh -c "show bgp neighbors 198.51.100.1"`, the
   `BGP state` and `Last reset` lines:
   - `Idle (Admin)`, `Admin. shutdown`: someone shut the session on our side. Go to step 3.
   - `Hold Timer Expired`: we stopped hearing the carrier for 180 s. Go to step 4.
   - `Peer closed the session`, or a notification about AS or capability: their side, or a
     mismatch. Step 3 first, then step 4.
3. **Is it our config?** `cd ansible && ansible-playbook drift.yml --limit r2`. A failure names
   the line, for example `no neighbor 198.51.100.1 shutdown` under Lines To Delete, which means the
   live router has `neighbor 198.51.100.1 shutdown` and the intent does not. Before reverting, ask
   in the team channel whether it was deliberate (planned maintenance). If not: `make apply` puts
   r2 back to its intended config (measured 3.5 s here) and the session comes up within seconds.
4. **Is it the link or the carrier?** Our config matches intent, so check our edge:
   `docker exec clab-<lab>-r2 ip -s link show eth3` (state UP, no TX errors) and
   `docker exec clab-<lab>-r2 ping -c 20 198.51.100.1`. Loss or no answer there is the carrier's
   side of the hand-off: follow [carrier-loss.md](carrier-loss.md) for the evidence they need. We
   can't log into their router and don't try.
5. **See it recover.** `show bgp summary` shows 198.51.100.1 with a prefix count (1) instead of a
   state. `docker exec clab-<lab>-h1 ping -c 3 203.0.113.1` works.
   `docker exec clab-<lab>-r1 vtysh -c "show ip route 0.0.0.0/0"` still points to r2 (it never moved).
6. **Prove nothing else changed.** `make drift` passes.

## Done when

The session is `Established`, r2 sends the aggregate
(`show bgp ipv4 unicast neighbors 198.51.100.1 advertised-routes` lists 10.0.0.0/8), h1 reaches
203.0.113.1, and `make drift` passes. Comms closes with the cause: our change, our link, or the carrier.

## Drill it in the lab

Someone else shuts the session: `docker exec clab-<lab>-r2 vtysh -c "conf t" -c "router bgp 65001" -c "neighbor 198.51.100.1 shutdown"`.
Then follow the steps from 1. Record the run in [dry-runs.yml](dry-runs.yml).
