---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead tells the change board what was found and whether it was reverted; security is told at once if step 3 finds an unexplained opening
last_reviewed: 2026-10-15
hosts: [r1, r2, r3, isp, fw1]
written_by: Claude (AI assistant)
---
# Runbook: the drift check failed

`make drift` (nightly in CI, or by hand) says a router or the firewall no longer matches its intended
config. Someone changed a live device outside the inventory: a quick fix, a mistake, or an intruder.
Nothing may be "fixed" until we know which. `<lab>` below is the `name:` in `build/topology.clab.yml`.

## Who does what

- **Responder** (on-call network engineer): steps 1, 2, 4 and 5. Only the responder reverts anything.
- **Coordinator** (NOC shift lead): step 3, the decision: keep the change (it goes into the inventory)
  or revert it. Talks to whoever made it.
- **Comms** (NOC shift lead): tells the change board what changed, who did it, and what was decided.

## Steps

1. **Read what drifted.** The failure names the device and the lines. For a router, frr-reload's
   view: `Lines To Delete` are live lines the intent doesn't have (they would be removed),
   `Lines To Add` are intended lines the router is missing. For fw1, a diff: `-` intended, `+` live.
   Re-run one device to see it on its own: `cd ansible && ansible-playbook drift.yml --limit r2`.
2. **Keep the evidence** before anything changes, in the ticket:
   `docker exec clab-<lab>-r2 vtysh -c "show running-config"`, or for the firewall
   `docker exec clab-<lab>-fw1 iptables-save -c` (rules with their packet counters, which show
   whether the rule has been used). `backups/` holds the same capture from the last drift run.
3. **Decide.** Ask the team and check the change log. There is no per-person command log on the
   nodes yet, so "who did it" is a question, not a lookup.
   - Planned and wanted: it goes into `inventory/network.yml` (or a template) through a reviewed
     pull request, then `make render apply`. The live change stays until then.
   - Not planned, or nobody owns it: revert it (step 4).
   - It opens access (an `ACCEPT` on fw1, a removed filter) and nobody owns it: treat it as a possible
     compromise. Stop here, keep step 2's evidence, and hand over to security.
4. **Revert.** Routers: `make apply` puts every router back to intent, changing only the differing
   lines (`frr-reload.py --reload`, no restart). The firewall: delete the hand-added rule by number,
   `docker exec clab-<lab>-fw1 iptables -L FORWARD --line-numbers` then
   `docker exec clab-<lab>-fw1 iptables -D FORWARD <number>`; or rebuild the whole chain with
   `docker exec clab-<lab>-fw1 sh /firewall.sh` (this resets the counters, so do step 2 first).
5. **Prove it.** `make drift` passes.

## Done when

`make drift` passes, and the ticket holds the evidence, who made the change and what was decided.

## Drill it in the lab

Someone else makes one hand change, for example
`docker exec clab-netauto-r2 vtysh -c "conf t" -c "router ospf" -c "passive-interface eth2"`, or
`docker exec clab-netauto-fw1 iptables -I FORWARD -p tcp --dport 22 -j ACCEPT`. Then run `make drift`
and follow the steps. Record the run in [dry-runs.yml](dry-runs.yml).
