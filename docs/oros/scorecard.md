# This lab against OROS 0.3

Every requirement in [the standard](standard.md), scored against this repository and its running lab on 2026-10-15.

**6 pass, 10 partial, 45 fail.** Before the BFD, collection, locate, firewall-control and records work went in, the same scoring gave 0 pass, 13 partial and 48 fail.

How each requirement is scored:

- **pass**: the requirement's *Pass* test is demonstrated in this lab by a test or lint in this repo, and that test fails when the requirement isn't met. Each one was checked by breaking what it guards (removing the config line, truncating the backup, injecting the fault) and watching the test go red.
- **partial**: real pieces of the requirement are in place, and the row names them, but the *Pass* test is not demonstrated. The row says what is missing. The before figures used the same rule.
- **fail**: nothing here demonstrates the *Pass* test.

Each first score was then checked again, independently, against the code and the live lab, and several were marked down on that check. Both passes were AI-assisted, like the coding behind the standard ([how OROS was made](README.md)). The lab is seven containers, so a pass shows the method works at lab scale, not that a production network meets the requirement. `make test` checks that this page lists all 61 requirements, that the totals add up, and that every test it names exists.

## 1 Notice

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| NOT-1 | State, not ping | partial | The tests read per-object state from FRR's JSON (OSPF Full per expected neighbor, BGP Established, BFD up), not ping. But only when the tests run: nothing re-checks between runs or raises an alert, and there is no pending-reboot check. |
| NOT-2 | Into the tool you already run | fail | No monitoring tool runs. Values are read by the tests only, and there is no per-platform coverage list. |
| NOT-3 | Arrival proof per source | fail | No log collector, so no last-seen time per source and no "source went silent" alert. |
| NOT-4 | Dead-man's switch | fail | No job sends a success signal, so a job that never runs raises nothing. GitHub turns the nightly run off after 60 days without repository activity, and nothing would notice. |
| NOT-5 | Precise volume at the source | fail | No filtering or rate limit at a log source, and no ingest budget. |
| NOT-6 | Detection coverage table | fail | No table of detections with their sources, blind spots and false-positive rate. |
| NOT-7 | One central store | fail | No central log store. The routing daemons' logs go to /dev/null ([V-005](../verdicts.yml)). |

## 2 Decide

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| DEC-1 | Why it fired, what is normal, what changed | fail | There are no alerts to carry that context. |
| DEC-2 | Know what the number counts | fail | No metric is documented or checked against a known byte count. |
| DEC-3 | Vulnerability triage | fail | No scanner, and no triage against the exact running build (Alpine 3.15 is past end of life). |
| DEC-4 | Narrow silence | fail | No alerting, so nothing to silence narrowly. |
| DEC-5 | One alert per cause | fail | No alerting, so no dependency model. |

## 3 Find

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| FND-1 | Loss the averages hide | partial | `make locate` does not call a middle hop that only rate-limits pings to itself loss, and does report injected loss (`tests/test_locate.py::test_loss_must_persist_to_the_destination`, `tests/live/test_locate.py::test_carrier_loss_is_placed_on_the_carrier`). No queue or qdisc drop counters are collected, so a microburst can't be traced. |
| FND-2 | Evidence survives recovery | fail | Daemon logs go to /dev/null, and nothing is copied off a node before it is reset. |
| FND-3 | Version-exact verdict | pass | `tests/live/test_platform.py::test_running_version_matches_inventory` checks the image digest, FRR, Alpine and busybox on every node against the inventory. `tests/test_verdicts.py::test_verdict_log_lints_clean` holds each odd behaviour in [the verdict log](../verdicts.yml) to one verdict, its version and a fix or workaround, and `tests/test_verdicts.py::test_unclassified_entry_gets_five_working_days` enforces the limit. No upgrade has happened yet, so the post-upgrade clause has nothing to check. |
| FND-4 | Where it is, and what is running | partial | One record that scripts can query (the inventory) names an owner for every device, and configs, topology and expected state are generated from it. No where-is query, no L2 layer, no discovery of unrecorded listeners, and no DNS or monitoring generated from it. |
| FND-5 | Who did it | fail | No NAT or connection log to map an outside complaint to an inside host. |
| FND-6 | Layer-by-layer bottleneck | fail | No per-layer performance runbook or measurements. |

## 4 Prove

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| PRV-1 | Capture where SPAN can't reach | fail | No capture method or make target. |
| PRV-2 | Clear yourself, then place it | pass | `tests/live/test_locate.py::test_carrier_loss_is_placed_on_the_carrier` injects 20% loss on the carrier's side. `make locate` clears every campus segment, names `r2-isp` and the carrier from our own edge, and is refused if asked to run a command on the carrier's router. `tests/live/test_locate.py::test_campus_loss_is_not_blamed_on_the_carrier` is the other half. The steps are in [the carrier-loss runbook](../runbooks/carrier-loss.md). |
| PRV-3 | Meet their standard of proof | fail | `build/finding.json` records the commands, probe count and threshold, but nobody has re-run a finding cold from the file alone. |
| PRV-4 | Interop: fault side and a safe workaround | fail | One routing stack and no IPsec, so no interop fault to name. |

## 5 Contain

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| CON-1 | Trace before you block | fail | No shared L2 segment to trace a flood on. |
| CON-2 | Narrowest scope, reversible | fail | No switch, so no per-port policing. |
| CON-3 | Measured false-block rate | fail | No blocking rule with a measured false-block rate. |
| CON-4 | Enforce where you control | partial | fw1 enforces LAN-A's boundary: a forged mid-stream TCP packet is refused while real web traffic passes (`tests/live/test_controls.py::test_allow_web_requires_a_handshake`). Nothing refuses a forged source address: allow-icmp and allow-web have no source match, and reverse-path filtering is off. |
| CON-5 | Allow by name, not by moving IPs | fail | Egress is allowed by address range, not by name. |
| CON-6 | Bulk work yields | fail | No bulk job and no throttling. |
| CON-7 | Guardrails, not requests | fail | No pre-commit or CI secret scanning. |

## 6 Change safely

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| CHG-1 | Dependents found from observed use | fail | No precheck finds who still uses what a change removes. |
| CHG-2 | Staged with a fallback | fail | `make apply` changes every router in one run, with no canary, health gate or rollback. |
| CHG-3 | Verified in effect | partial | After deploy, `make drift` checks every router's and fw1's running state against intent, without touching it. No "installed but not in effect" check, no QoS to confirm, and CI never runs `make apply`. |
| CHG-4 | Honest lab parity | fail | No written gap between this lab and a production network. |
| CHG-5 | One channel, every box | partial | Ansible over Docker reaches every router and fw1 and reports per host, and every node boots into its intended config with no login. fw1 is configured at boot, not through that channel; all nodes run one image; no forced failure is named. |
| CHG-6 | Effective state and its actor | partial | The drift check reports the running value, not just the configured one, but never who set a drifted value. |
| CHG-7 | Local changes carried forward | fail | No local patches carried across upstream releases. |

## 7 Recover

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| REC-1 | Backups that cannot lie | fail | Router backups are proven complete (REC-2), but they land in `backups/` and a CI artifact, with no destination check, no read-back at the destination and no alert on a missing backup. |
| REC-2 | Saved state matches running | pass | `tests/live/test_collection.py::test_unsaved_change_is_flagged` and `tests/live/test_collection.py::test_incomplete_capture_is_flagged`. fw1 has its own method, and `tests/live/test_collection.py::test_firewall_hand_change_is_flagged` proves it. Every method is listed in [collection-methods.md](../collection-methods.md). CI runs it nightly on a fresh lab; a lab that stays up needs the cron line in that page. h1 and h2 are not collected, and fw1's backup is not loaded back. |
| REC-3 | Restore drills, including one item | fail | No scheduled restore drill. |
| REC-4 | Failover drilled, failure modes owned | partial | Failover is drilled on every CI run, a silent failure included (`tests/live/test_failover.py::test_silent_failure_reroutes_fast`), and [decision 0009](../decisions/0009-failover.md) lists each failure mode with its mitigation. There is no active/standby pair, so no split-brain alert to test-fire. |
| REC-5 | Compromise closure | fail | No compromise runbook and no planted-persistence drill. |
| REC-6 | Runbooks someone else can run | fail | One runbook (carrier loss), with no review date and no CI check, and nobody but its author has run it. |
| REC-7 | Outside levers listed | fail | The inventory names the carrier's NOC as an owner, but there is no contact sheet or evidence list. |

## 8 Account for access

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| ACC-1 | Per-person, tamper-resistant trail | fail | No named accounts or command log. Everything is root over `docker exec`. |
| ACC-2 | Unexpected-admin alert | fail | No expected-admin list and no login alert. |
| ACC-3 | Per-holder credentials, revocable | fail | No per-person credentials. |
| ACC-4 | No plaintext secrets for automation | fail | There is no secret to protect yet (no OSPF or BGP authentication), and no scan. |
| ACC-5 | Directory-driven lifecycle | fail | No directory. |
| ACC-6 | Scoped delegation and sanctioned exceptions | fail | No scoped accounts. |
| ACC-7 | Management plane closed but recoverable | partial | Every routing daemon's vty listens on 127.0.0.1 only (`tests/live/test_management_plane.py::test_router_daemons_listen_on_localhost_only`), and there is no management network. From the ISP side h2:22, h2:80 and r2:179 still answer, and there is no primary management path to cut for a fallback test. |
| ACC-8 | Usable authentication rules | fail | No user authentication to tune. |

## 9 Account to gatekeepers

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| ATT-1 | Scope register | fail | No scope register. |
| ATT-2 | Finding dispute record | fail | No scanner findings to dispute. |
| ATT-3 | One artifact first | fail | No request log and no shareable evidence pack. |
| ATT-4 | Control works as claimed | partial | Every claimed control is in [the control register](../controls.yml) with its test and a 31-day period, and CI keeps dated JUnit results for 90 days. Nothing yet checks that each control's last green run is inside its period, and GitHub runs the nightly schedule only on `main`, so it starts once this is merged. |
| ATT-5 | Scored baseline | fail | No benchmark scoring of the nodes. |

## 10 Justify the decision

| ID | Requirement | Status | Proof, or what's missing |
|---|---|---|---|
| JUS-1 | Decision record | pass | [docs/decisions/](../decisions/) holds 9 records, and `tests/test_decisions.py::test_decision_records_lint_clean` finds no missing field, no record without a 'do nothing' option and none without an outside source. |
| JUS-2 | Measured sizing | pass | [docs/sizing/](../sizing/README.md) links its raw data, and `tests/test_sizing.py::test_ram_figures_match_the_newest_data` and `tests/test_sizing.py::test_sizing_doc_links_all_its_data` hold every RAM figure to it. Figures are committed for a GitHub runner with real Containerlab and for the sandbox. |
| JUS-3 | Evidence not from the seller | fail | No selection record with an independent source and a no-purchase option. |
| JUS-4 | Recorded risk acceptance | fail | Accepted risks are written in decision 0009 and the control register, but there is no risk register with an owner, a review date and a record of who it was shown to. |
| JUS-5 | What the control really does | pass | Every control in [the control register](../controls.yml) states its threat and how it fails. `tests/test_controls.py::test_register_lints_clean` rejects an entry without them, and `tests/test_controls.py::test_every_readme_claim_has_an_entry` and `tests/test_controls.py::test_every_firewall_rule_has_an_entry` keep the register complete. The lint checks the fields are there, not that the reasoning is right. |
