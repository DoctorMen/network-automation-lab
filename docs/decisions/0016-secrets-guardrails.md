---
id: "0016"
title: Block secrets at commit, push and in CI, and set the BGP password with no plaintext copy
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "No GitHub secret, no vault and no paid secret scanning (personal public repo); FRR 8.4.1 prints BGP passwords in clear in `show running-config` and offers only TCP MD5; routers are reached only through docker exec; backups/ and results/ are uploaded as CI artifacts"
alternatives:
  - name: do nothing
    why_not: With no BGP password there is nothing to leak and nothing proved. Once one exists it lands in backups/r2.conf, drift's failure message, frr-reload.log and Ansible's temp files on the routers (each seen in this build before the fix), and gitleaks' default rules miss every one of them
  - name: render the password into build/r2/frr.conf
    why_not: build/ is the intent every tool reads and the router mounts; the password would be a plaintext file in the one folder that must be safe to print, diff and upload
  - name: a GitHub Actions secret
    why_not: None exists and none can be created from here. A random password made per run, 0600 under $RUNNER_TEMP and masked in the log, does the same job and never outlives the job
  - name: vtysh -c with the password on the command line
    why_not: It shows in /proc/<pid>/cmdline of the docker exec process on the runner, where the live test finds it
  - name: let frr-reload.py apply the password with the rest of the config
    why_not: frr-reload.py runs `vtysh -c` with each line it changes, password lines included, and logs them to /var/log/frr/frr-reload.log at INFO. It also deletes a password the intended file doesn't hold, which drops the session (both measured)
  - name: GitHub secret scanning custom patterns
    why_not: Custom patterns need an organization-owned repository with paid Secret Protection; recorded as refused spend RISK-9
sources:
  - https://www.rfc-editor.org/rfc/rfc2385 (Protection of BGP Sessions via the TCP MD5 Signature Option)
  - https://www.rfc-editor.org/rfc/rfc5925 (TCP-AO, which obsoletes RFC 2385; FRR 8.4.1 has no command for it, only `password`)
  - https://github.com/gitleaks/gitleaks/tree/v8.21.2
  - https://docs.github.com/enterprise-cloud@latest/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns
stake: A password in a pushed commit or a public CI artifact is public for good, and someone else finds it first. A guardrail that only exists as advice fails OROS CON-7
failure_modes:
  - mode: a secret staged in a commit
    mitigation: The pre-commit hook runs gitleaks on the staged diff and refuses the commit, printing the rule but not the secret
    test: tests/test_secrets.py::test_staged_secret_is_blocked_at_commit
  - mode: a secret committed with --no-verify, then deleted again
    mitigation: The CI `secrets` job (.github/workflows/secrets.yml) scans every commit (fetch-depth 0) on every push to any branch, every pull request and nightly
    test: tests/test_secrets.py::test_history_scan_finds_a_secret_committed_with_no_verify
  - mode: a file carrying the confidential marker pushed to the public repo
    mitigation: The pre-push hook refuses it; pushed anyway with --no-verify, the CI scan of the pushed history goes red and names the rule
    test: tests/test_secrets.py::test_marked_file_is_blocked_at_push_and_alerted_by_ci
  - mode: a BGP password in clear in a backup or drift output, which gitleaks' default rules miss
    mitigation: The redacting vtysh on each router prints a sha256 tag instead; the frr-bgp-neighbor-password rule catches any line still in clear, and the lab job scans backups/, results/ and build/ after drift
    test: tests/test_secrets.py::test_frr_password_rule_catches_what_default_rules_miss
  - mode: the password on a command line, in an environment, a log or a temp file while make apply or make drift runs
    mitigation: vtysh reads it on stdin; the task is no_log; pipelining keeps the module and its arguments off disk on both ends; frr-reload.py never sees a password line
    test: tests/live/test_secrets.py::test_no_secret_in_env_argv_logs_or_files
  - mode: a playbook change moves the password onto a command line or into an environment, for a process too short for the live test to sample
    mitigation: Only stdin may carry a lookup of the secret store; every task in ansible/ is checked offline, on every run
    test: tests/test_secrets.py::test_secrets_reach_a_router_only_on_stdin
  - mode: frr-reload.py deletes the password on a reload and the session drops
    mitigation: The redacting vtysh drops password lines from what frr-reload.py reads (NETLAB_PASSWORDS=drop), so there is nothing for it to delete; the password is set in its own task afterwards
    test: tests/live/test_secrets.py::test_no_secret_in_env_argv_logs_or_files
  - mode: the rollout's rollback (decision 0010) deletes the password, sets its tag as the password, or saves it in clear on the router
    mitigation: The fallback is saved and reloaded through the redacting vtysh with password lines dropped, like the apply; every task in ansible/ that reads or reloads a running config is checked offline for that
    test: tests/live/test_rollout.py::test_rollback_keeps_the_bgp_password_and_writes_it_nowhere
  - mode: MD5 configured on one end only, or not enforced
    mitigation: Both ends must report authentication enabled, and a wrong password on the carrier end must take the session down and keep it down
    test: tests/live/test_secrets.py::test_bgp_session_uses_its_secret_and_a_wrong_one_drops_it
  - mode: the sha256 tag in a published backup is reversed by guessing
    mitigation: The password is 128 random bits from `secrets.token_hex`, never chosen by a person, so its tag can't be brute-forced
    test: tests/test_secrets.py::test_secret_store_is_private_and_never_overwritten
  - mode: root on a router prints the key with ss -tnie, or reads the 0600 store
    mitigation: Accepted. Anyone with root on a lab node already controls the session
    test: none (accepted risk RISK-8 in docs/risks.yml)
  - mode: hooks not installed, or a red secrets job merged anyway
    mitigation: CI scans regardless of hooks; making the check block a merge needs branch protection, a repository setting outside the repo
    test: none (accepted risk RISK-10 in docs/risks.yml until branch protection requires the secrets check)
---

## Context

OROS CON-7 wants the secret rule enforced, not written down: a seeded secret blocked at commit and found by the history scan, and a marked file pushed to a public repo blocked or alerted. ACC-4 wants an unattended job to get a real secret with no plaintext in files, logs, environment or arguments. The lab had no secret at all, so the first step was to add one that matters: TCP MD5 on the r2-isp BGP session.

FRR makes that hard. It prints the password in clear in `show running-config`, which is what backups, the drift check and the capture check read. frr-reload.py, which `make apply` uses to change only the difference, passes every changed line to `vtysh -c` and logs it, and it deletes any line the intended file lacks.

## Decision

- **Guardrails.** gitleaks v8.21.2 with the default rules plus two of ours in `.gitleaks.toml`: `frr-bgp-neighbor-password` (FRR's line, which has no `=` for the generic rule to anchor on) and `netauto-confidential-marker`. A pre-commit hook scans the staged diff, a pre-push hook scans the history, and the CI `secrets` job scans every commit. Backups' sha256 tags are allowlisted.
- **The secret.** `bgp_auth` in the inventory names the session and a secret file, never the password. `make secrets` creates 128 random bits, 0600, in `.secrets/` (gitignored) or `$NETLAB_SECRETS`; CI points that at `$RUNNER_TEMP` and masks the value. Nothing renders it.
- **Delivery.** `make apply` sets it with `vtysh -f /dev/stdin` under `no_log`, with Ansible pipelining on, so it is in no argv, no environment and no file on either end.
- **Redaction.** A small vtysh wrapper (ansible/files/vtysh_redacted.py) on each router replaces password lines in `show running-config` with `sha256:<hex>` for backups, drift and the capture check, and drops them for frr-reload.py and for the fallback the rollout saves and reloads (decision 0010). Drift compares tags, so a wrong or missing password still shows as drift.

## Consequences

`make deploy` now ends with `make apply`, because only `make apply` sets the password; after any deploy that doesn't go through `make deploy`, run `make apply` once. The secret store itself is a plaintext 0600 file, the stand-in for a vault (RISK-8). FRR's own support bundle runs `show running-config`, so `netlab finding` vendors its command list without that command (decision 0017).
