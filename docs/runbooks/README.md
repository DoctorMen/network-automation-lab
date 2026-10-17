# Runbooks

| Runbook | When |
|---|---|
| [link-failure](link-failure.md) | A core link is down, or up and passing nothing |
| [bgp-down](bgp-down.md) | The eBGP session to the ISP is down: no internet |
| [config-drift](config-drift.md) | `make drift` failed: a device differs from its intended config |
| [restore-from-backup](restore-from-backup.md) | A router must go back to the config it last ran, from the backup |
| [power-event](power-event.md) | Every node restarted after a power outage |
| [carrier-loss](carrier-loss.md) | Loss toward the internet: ours or the carrier's? |
| [ddos-rtbh](ddos-rtbh.md) | A flood on a published host fills the ISP link: blackhole that host at the ISP |
| [hidden-loss](hidden-loss.md) | Users see loss that graphs, ping and interface counters don't: a queue, or a ping rate limit? |
| [broadcast-storm](broadcast-storm.md) | Every host on a user LAN is slow at once and nothing is down: trace the storm to its switch port, contain it there without shutting the port |

Each one starts with YAML front matter: `owner` (keeps it right), `coordinator` (runs the incident),
`comms` (updates stakeholders), `last_reviewed`, `hosts` (every device it acts on) and `written_by`.
Each body has a "Who does what" section, so two people never work the same router at once.
`make test` fails if a runbook is missing a field, was last reviewed more than 180 days ago, or
names a host that isn't in `inventory/network.yml` or isn't in its own `hosts:` list
([`tests/test_runbooks.py`](../../tests/test_runbooks.py)). So a renamed or removed device breaks
the build until its runbooks are updated.

Access: the repository is public, so runbooks hold nothing that isn't already public. No passwords,
no real phone numbers; roles, not names.

## Run one cold

These runbooks were written by an AI assistant (`written_by`). So the owner running one alone, without
help, is the test OROS REC-6 asks for: someone who did not write it carries it out in the lab. It
takes two people, a helper who breaks the lab and a runner who doesn't know how.

1. Runner, from the repo root on a machine with Docker and Containerlab:
   `git pull && make deploy && make live` (a clean lab: every live test passes).
2. Helper: pick one fault from the "Drill it in the lab" sections at the end of the runbooks and run
   it. Don't say which. Tell the runner only what an alert or a user would ("users can't reach the
   internet", "the nightly drift check failed", "power is back", "r2 lost its config, put it back
   from the backup"). `<lab>` in those commands is the `name:` in `build/topology.clab.yml`.
3. Runner: pick the runbook from the table above by that symptom, and follow it from step 1 with
   nothing else: no chat, no reading the code, no asking the helper or the author. Time it.
4. Runner: `make live && make drift` afterwards. Is the lab really back?

Then record it at the end of [`dry-runs.yml`](dry-runs.yml), even if it failed (the wrong runbook
picked is a fail too), and commit. `runbook` is the one the helper's fault belongs to:

```yaml
  - date: 2026-10-20
    runbook: link-failure
    by: DoctorMen
    help_needed: false
    result: pass
    notes: 12 minutes. Step 3 didn't say which end to check first.
```

(`runs: []` becomes `runs:` followed by the entry.) Fix whatever the notes say was unclear, and bump
that runbook's `last_reviewed`. `make test` checks the entry names a runbook that exists, a past date
and a result.
