---
kind: selection
id: restic
title: restic for router config backups, checked at the destination
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "GitHub-hosted runners keep nothing between runs and the repo has no secrets; a backup must be read back and checked where it landed, and the job must never create its own target (OROS REC-1); one pinned image run as a one-shot container, like gitleaks; free"
choice: restic/restic:0.16.4 as a one-shot container, writing to a restic repository on a disk or share (BACKUP_REPO), kept between CI runs in the Actions cache (decision 0014)
uses: [restic/restic]
alternatives:
  - name: Oxidized
    why_not: A long-running service with its own config and git store; the lab has no always-on host to run it, and it still needs a destination check
  - name: the CI run's artifact as the backup
    why_not: Kept 90 days at most, written whether or not anything was captured, and nothing reads it back
  - name: a plain copy (cp, rsync or tar) to the target
    why_not: Free and already installed, but it keeps no earlier copies and no encryption, and has nothing like `restic check --read-data`; reading every copy back would be ours to write and test
  - name: do nothing (backups/ on the runner only)
    why_not: backups/ is recreated on every run, so a run that backed up nothing still goes green
no_purchase: restic is free (BSD 2-clause) and its image is public, so the choice costs nothing. The cheaper-still option is the plain copy above, which gives up history, encryption and the read-back check.
staffing: one person, the repository owner; the backup and its checks run from make targets, and restoring one router's config is a single `restic dump`.
vendor_domains: [restic.net, restic.readthedocs.io, github.com/restic]
independent_sources:
  - "tests/live/test_backup.py::test_corrupt_destination_fails_the_backup (our measurement: with a byte flipped at the destination, `restic backup` still exits 0, so the job reads every backup back and runs check --read-data; decision 0014)"
  - "tests/live/test_backup.py::test_missing_target_fails_loudly (our test: an unmounted target fails the job instead of a new, empty repository being made on local disk)"
  - "https://repology.org/project/restic/versions (most Linux distributions package restic, a second install route if the image went away)"
---

## Context

Router configs have to survive the runner that captured them, and a backup only counts if it can be read back from where it was sent.

## Decision

restic 0.16.4, run from its public image by `make backup`, with the repository's existence checked first and every snapshot read back (decision 0014).

## Consequences

restic deduplicates and trusts what is already at the destination, so a damaged repository can look healthy to `restic backup`; the job's read-back and `check --read-data` are what catch it. In CI the repository lives in the Actions cache, which GitHub evicts after 7 days without use.
