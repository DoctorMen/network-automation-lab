---
id: "0015"
title: Drill a power event as a whole-lab redeploy, in its own weekly job
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: Containerlab links are veth pairs that die with the container, the FRR container's main process is watchfrr, and the main CI job has about 2 minutes to spare
alternatives:
  - name: do nothing
    why_not: nothing shows the lab comes back from its startup config, or that fw1's rules (kernel only) come back at all
  - name: docker restart one router
    why_not: a restarted container comes back without its lab links, on both ends, so the drill would fail on lost links rather than on config (verified with two alpine containers and a veth pair; after docker restart neither end has it)
  - name: restart FRR inside the container (frrinit.sh restart)
    why_not: it stops watchfrr, the container's main process, so the container exits (verified; the exec returns 137 and the container stops)
  - name: containerlab tools veth create after a restart
    why_not: unverified on Containerlab 0.68, and it is a repair step a real power event doesn't have
sources:
  - https://containerlab.dev/cmd/deploy/#reconfigure (--reconfigure removes the lab's nodes and deploys them again)
  - https://docs.docker.com/reference/cli/docker/container/restart/
  - https://docs.frrouting.org/en/stable-8.4/setup.html#daemons-configuration-file (watchfrr starts and watches the daemons)
stake: if the redeploy is gentler or harsher than a real power cut, the drill proves the wrong thing; it is harsher (every node gets a fresh filesystem), so a pass is conservative, but one node returning alone is never drilled
failure_modes:
  - mode: a node returns without its config, or with a hand change that was never saved
    mitigation: intent is mounted read-only and fw1's start script runs at deploy; the drill makes an unsaved change first and checks it is gone, then routing, the web path through fw1 and drift
    test: tests/live/test_power_event.py::test_power_event_recovers_from_startup_config
  - mode: the drill passes while the BGP session runs without its password, which no startup config holds (decision 0016)
    mitigation: the drill runs make apply after the cut, as the runbook's step 3 says, and checks authentication is enabled on both ends of the session
    test: tests/live/test_power_event.py::test_power_event_recovers_from_startup_config
  - mode: one node restarts while its neighbours stay up
    mitigation: none drilled; containers lose their links on restart in this lab
    test: none (accepted risk RISK-27 in docs/risks.yml, docker restart cannot keep a Containerlab node's links)
---

## Context

REC-6 asks for a power-event runbook that someone else can carry out, and the lab needs a power event
to carry it out on. A router container can't be power-cycled on its own without losing its links, and
FRR can't be restarted inside its container without the container exiting.

## Decision

The power event is the whole lab redeployed: `containerlab deploy --reconfigure` in CI (`make
power-drill`, `POWER_CYCLE` in the Makefile), and on the development sandbox, where Containerlab can't run,
a stand-in script kept outside this repo that redeploys every node ([LAB_PARITY.md](../LAB_PARITY.md)).
`tests/live/test_power_event.py` makes a hand change on r2 that is never saved, cuts the power, waits
for every OSPF adjacency, BFD peer and BGP session the inventory expects, then checks the change is
gone. It runs `make apply`, because the BGP password is in no startup config ([decision
0016](0016-secrets-guardrails.md), accepted risk RISK-28), checks the session is back with
authentication on both ends, then that h1 reaches h2:80 through fw1 and `drift.yml` passes. It redeploys every node, so it is skipped in
`make live` and runs weekly in `.github/workflows/drills.yml`, after the restore drill. Measured here:
36.5 s for the test before it ran `make apply`, 70 to 80 s with it (four runs on 2026-10-15; `make
apply` takes about 40 s with the canary rollout); routing back 10.8 to 20.2 s after the cut. On the
full lab with the NOC (two runs on 2026-10-16), where the drill also waits for the NOC to settle:
148.3 and 187.3 s for the test, routing back 73.9 and 83.7 s after the cut, about a minute later,
as when a daemon crashes as it starts and watchfrr starts it again (V-011).

## Consequences

- The person's version is [docs/runbooks/power-event.md](../runbooks/power-event.md): `containerlab
  deploy --reconfigure` is the cut (not `make deploy`, which sets the password again itself), then the
  runbook's steps. A run by someone other than its author goes in
  `docs/runbooks/dry-runs.yml`.
- On a GitHub runner the power-event drill's step took 133 s (07:48:58 to 07:51:11 UTC) in drills.yml run
  38869378128 (main, 3d3770c), inside the drills job's own 20-minute limit. The restore drill in that
  run failed in 2 s, because the backup repository then held no snapshot; the backup start order's
  step 1, which creates the repository, ran next, in run 38869409916.
