---
id: "0014"
title: Back up to restic, judge each backup at the destination, never create the target in the job
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: GitHub-hosted runners keep nothing between runs and there are no repository secrets, and a job that creates its target when none is found can't tell an unmounted disk from a first run
alternatives:
  - name: do nothing
    why_not: backups/ is recreated on every run and uploaded with if-no-files-found ignore, so a run that backed up nothing still goes green, and nothing ever reads a backup back
  - name: restic, creating the repository when it is missing
    why_not: on an unmounted mountpoint or a cache miss it makes a new, empty repository on the local disk and exits 0, which is the failure REC-1 is about (verified, rc 0)
  - name: Oxidized
    why_not: a long-running service with its own config and git store; the lab has no always-on host to run it, and it still needs a destination check
  - name: the run artifact as the backup
    why_not: kept 90 days at most, written whether or not anything was captured, and nothing reads it back
sources:
  - https://restic.readthedocs.io/en/v0.16.4/045_working_with_repos.html#checking-integrity-and-consistency (check --read-data reads every pack)
  - https://restic.readthedocs.io/en/v0.16.4/050_restore.html#printing-files-to-stdout (dump, --archive tar)
  - https://docs.docker.com/engine/storage/bind-mounts/#differences-between--v-and---mount-behavior (--mount errors on a missing source; -v creates it)
  - https://github.com/actions/cache/blob/main/restore/README.md (fail-on-cache-miss, lookup-only)
  - https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#usage-limits-and-eviction-policy (7 days without access, 10 GB)
stake: if the destination check is wrong, the lab reports good backups it doesn't have; if the cache is evicted, CI goes red until someone re-creates the repository and the history before it is gone
failure_modes:
  - mode: target unmounted, or the CI cache missed
    mitigation: the job checks for a restic repository first and never creates one; Docker gets --mount, which refuses a missing path; actions/cache fail-on-cache-miss
    test: tests/live/test_backup.py::test_missing_target_fails_loudly
  - mode: a device missing from the capture
    mitigation: the capture must hold every inventory router and firewall before anything is sent
    test: tests/live/test_backup.py::test_missing_router_is_not_skipped
  - mode: data rotted at the destination while restic backup exits 0 (deduplication trusts it)
    mitigation: read the snapshot back, sha256 against the capture, restic check --read-data
    test: tests/live/test_backup.py::test_corrupt_destination_fails_the_backup
  - mode: a backup that doesn't load on a router
    mitigation: weekly restore drill boots every backup on a throwaway router
    test: tests/live/test_restore.py::test_drill_notices_a_bad_backup
  - mode: backups stop running
    mitigation: the weekly drill fails when the newest snapshot is 36 hours old
    test: tests/live/test_restore.py::test_latest_backup_is_recent
  - mode: GitHub disables the schedules (60 days without activity), so backups, drills and checks all stop
    mitigation: none in the repo; it needs a dead-man's switch outside GitHub
    test: none (accepted risk, no outside monitor in a lab with no always-on host)
  - mode: two runs at once each save their own copy of the repository
    mitigation: the newest cache wins; the other run's snapshot is lost, the rest is intact
    test: none (accepted risk, a lost snapshot of configs the next night replaces)
---

## Context

REC-1's Pass test is that an unmounted target makes the job report failure instead of quietly writing
to local disk. Before this, the only backup was `backups/`, written by `make drift` on the runner and
uploaded as an artifact. Checked with restic 0.16.4 in throwaway containers on 2026-10-15:

- `restic backup` into an empty directory: `Fatal: unable to open config file ... Is there a repository
  at the following location?`, exit 1, and the directory stays empty. After `restic init` in the same
  directory, the same backup exits 0. So the init is what hides a lost target.
- `docker run -v /missing:/repo` creates `/missing` on the host; `--mount type=bind,src=/missing` fails
  with `bind source path does not exist`, exit 125.
- One byte flipped in a data pack, then the same files backed up again: `restic backup` exits 0
  (`files_unmodified: 2`, nothing re-read), `restic dump` fails with `ciphertext verification failed`,
  `restic check --read-data` exits 1.

## Decision

`make backup` (`netlab/backup.py`) runs restic in a one-shot container with `--mount` and `--no-cache`,
never runs `init`, refuses a capture missing an inventory device, and reads every snapshot back:
names, sha256 and `check --read-data`. `make backup-init` is the only way to create a repository, run
once by hand. In CI the repository lives in the Actions cache, restored with `fail-on-cache-miss` and
saved under a new key after each verified backup; `drills.yml`'s `init_backup_repo` input creates it
and refuses if one exists. No repository secret can be set from here, so the init job writes a random
password (16 bytes, 0600) into the cache beside the repository.

## Consequences

- The password beside the repository protects nothing from someone who can read the cache, and any
  workflow run in this repository can restore it, a pull request's included (it runs the pull
  request's own copy of the workflow). That is acceptable because the repository holds nothing secret.
  `make backup` sends exactly the files the collection pass (`make drift`, `ansible/drift.yml`) wrote
  to `backups/`, and never reads a router itself, so a secret can reach the repository only through
  that capture. The collection pass reads each running config through the redacting vtysh of
  [decision 0016](0016-secrets-guardrails.md), which writes the r2–isp BGP password as its sha256
  tag. A new kind of secret in a config needs the same redaction in the capture before it is backed up.
- After merge, CI is red at the backup step until the repository is created once. That is the design:
  the first run and a lost target look the same, so a person decides. The order to start it is in
  [docs/backups.md](../backups.md#starting-it-on-github-and-again-after-the-cache-is-lost).
- A cache unused for 7 days is evicted, and the next run fails loudly. Re-create it the same way; the
  history before it is lost.
- How it works, with the restore drill: [docs/backups.md](../backups.md).
