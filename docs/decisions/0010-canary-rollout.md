---
id: "0010"
title: Roll router changes out canary first, behind a health gate, with an automatic rollback
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: Ansible and what the FRR 8.4.1 image already ships, intent mounted read-only (0008), and every run of the test has to fit the CI lab job
alternatives:
  - name: do nothing
    why_not: deploy.yml changed all four routers at once, so a change that broke one broke them all, and nothing put a router back
  - name: roll back by rendering the previous commit's intent
    why_not: CI checks out one commit (it would need fetch-depth 2), it assumes the previous commit is what the routers run, and it rewrites build/ in the middle of a failure. The router's own running config, saved just before the change, is what it really ran
  - name: a block/rescue that rolls back and stops there
    why_not: a rescue that succeeds marks the router "rescued", not failed, and Ansible carries on to the next batch (reproduced with ansible-core 2.21.5 and four mock hosts); the rescue has to end in ansible.builtin.fail
  - name: a gate that needs a fully healthy network
    why_not: the canary's gate would then fail on a fault some other router already had, so `make apply` could no longer repair it. The gate fails only on problems the batch added
  - name: run the gate once per batch (run_once)
    why_not: when it fails, only the first router of the batch counts as failed and goes to rescue; the other two keep the change (reproduced with mock hosts)
sources:
  - https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_strategies.html (serial, max_fail_percentage)
  - https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_error_handling.html (any_errors_fatal)
  - https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_blocks.html (block, rescue)
  - https://sre.google/workbook/canarying-releases/ (canarying)
  - https://github.com/liske/needrestart (deleted binaries and the running kernel, the checks netlab.verify copies)
stake: if the gate misses a fault, the change reaches every router at once, as before; if it fails good changes, nobody can deploy
failure_modes:
  - mode: the change breaks the canary (it loses an OSPF neighbor)
    mitigation: the health gate fails, the canary goes back to the running config it saved before the change, and the rollout stops before any other router
    test: tests/live/test_rollout.py::test_failing_canary_rolls_back_and_blocks
  - mode: a rescue that doesn't fail, so the rollout carries on past a rolled-back canary
    mitigation: the rescue ends in ansible.builtin.fail; the test sees the change on no other router
    test: tests/live/test_rollout.py::test_failing_canary_rolls_back_and_blocks
  - mode: the rollback itself fails (frr-reload.py runs `write` after reloading a file outside its confdir, and the intent is read-only)
    mitigation: the fallback is saved with vtysh.conf in its own folder and reloaded with --confdir pointing there; the test checks the canary's running config is exactly what it was
    test: tests/live/test_rollout.py::test_failing_canary_rolls_back_and_blocks
  - mode: saving the fallback fails, so a rollback would reload an empty or half-written file and delete the router's config
    mitigation: the save runs before the block, with set -e, so a failed save stops the play before anything changes and the rescue never runs
    test: none (checked by hand with an unwritable fallback path; the play stopped at the save with rescued=0)
  - mode: a change starts outside the change window
    mitigation: the play refuses before it touches any router
    test: tests/live/test_rollout.py::test_change_waits_for_window_then_reaches_every_router
  - mode: a gate that fails good changes, which would make the rollback test pass for the wrong reason
    mitigation: the same rollout with only a harmless change passes every gate and reaches all four routers
    test: tests/live/test_rollout.py::test_change_waits_for_window_then_reaches_every_router
  - mode: a fault that shows only after the gate passed
    mitigation: the canary is checked again after the vetting delay (10 s). Accepted risk past that, so a fault that takes longer, like a neighbor lost only at the 40 s OSPF dead timer, reaches production
    test: none (accepted risk, the vetting delay is a lab value)
  - mode: a production router fails the gate
    mitigation: every router of the batch runs the gate, so all of them roll back, and any_errors_fatal stops the play
    test: none (checked by hand in the lab once, not in the suite to save CI time. r2 lost its OSPF link to r1, and r2, r3 and isp all went back to their exact pre-change config)
  - mode: a patch is installed but not running (a daemon replaced on disk, a kernel not rebooted into)
    mitigation: netlab.verify runs after each batch and fails the rollout on `not in effect`. The test proves the check; that the rollout stops on it is not tested
    test: tests/live/test_verify.py::test_daemon_patch_without_restart_is_not_in_effect
  - mode: a rolled-back router restarts and boots into the bad intent, which build/ still holds
    mitigation: by design. The intent is the change; it has to be reverted in the inventory, and make drift reports the router until it is
    test: none (by design, the failure message says so)
---

## Context

`make apply` ran `ansible/deploy.yml` on every router at once. It applied only the lines that differ (`frr-reload.py`), but a change that broke one router broke them all, and nothing checked the network afterwards or put a router back.

## Decision

- `serial: [1, "100%"]`: the canary named in the inventory's `rollout:` block goes alone, then the other three. netlab renders it first in the Ansible inventory.
- Before a batch: refuse outside the change window, and note the network's problems (`python -m netlab.health`).
- Each router saves `show running-config` (its fallback), applies the difference, and is compared with intent again, so a line frr-reload.py didn't take fails the batch.
- The health gate: every OSPF neighbor Full and every BGP session Established (from `expected_state.json`), every host pinging every other host, waiting up to `gate_timeout` (20 s) for any problem the batch added to clear. The canary waits out `vetting_delay` (10 s) and is checked again.
- Rescue: reload the fallback, then fail. `any_errors_fatal` and `max_fail_percentage: 0` stop the play.
- After each batch, `python -m netlab.verify` checks that its routers run what is installed: the newest installed kernel, and every enabled FRR daemon from its binary on disk (`tests/live/test_verify.py`).
- A change reaches main as a pull request whose description says which risks the lab couldn't cover ([LAB_PARITY.md](../LAB_PARITY.md)); the change-record check fails while that section is empty.

## Consequences

- A rollout with nothing to change takes about 35 s here (34.7 and 35.5 s measured), most of it the vetting delay and the health checks (about 1.7 s each). The failing-canary test takes 39-44 s, 20 s of it the gate waiting before it gives up.
- After a rollback the router runs its old config while build/ holds the new intent, so `make drift` is red until the change is reverted. That is on purpose: the bad change is still in the source of truth.
- frr-reload.py never restarts a daemon, so no reboot or restart happens inside or outside the window. A patch that needs one is reported by netlab.verify, not done.
- The window is open all day in the lab so CI can run at any hour; the test closes it with `-e change_window=...`.
- Branch protection, so that main only changes through a pull request with the change-record check green, is a repository setting this repo can't turn on by itself.
