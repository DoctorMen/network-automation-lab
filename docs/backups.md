# Backups and restores

`make drift` collects every router's running config and fw1's rules into `backups/`
([collection-methods.md](collection-methods.md)). That folder is staging, on the machine that ran the
check, and gitignored. The backup is the next step: `make backup` sends that capture to a restic
repository that outlives the machine, and judges the result there. The weekly restore drill then
boots each backup on a throwaway router. This covers OROS REC-1 and REC-3; the design is
[decision 0014](decisions/0014-backups-judged-at-destination.md).

## The destination

`BACKUP_REPO`, a restic repository (restic 0.16.4, run as a one-shot container, `restic/restic:0.16.4`).
On your own machine it belongs on a disk or share that is not the lab's: default
`/mnt/backup/netlab-restic`. Its password is in `BACKUP_PASSWORD` (default
`~/.config/netlab/restic-password`), a 0600 file that `make backup-init` fills with 16 random bytes.
restic reads it with `RESTIC_PASSWORD_FILE`, so it is never on a command line or in the environment.

Create it once, by hand: `make backup-init`. `make backup` never creates one. If the job created its
repository whenever it found none, an unmounted disk would look like a first run: the job would
make a new repository in the empty mountpoint, on the local disk, and report success every night.

In CI the repository and its password live in the Actions cache (`$RUNNER_TEMP/backup`), restored at
the start of the backup step with `fail-on-cache-miss` and saved under a new key after a verified
backup. Create it once with **Actions > Drills > Run workflow > init_backup_repo**, in the order
below. That job refuses if a repository already exists. Pull requests don't back up: their caches
are scoped to the PR, so main could never restore them.

## Starting it on GitHub, and again after the cache is lost

Until these four runs have happened in this order on `main`, the lab job's backup step and the
control-status job are red. Wait for each run to finish before starting the next: each one restores
the cache the one before saved. Each can be started from the Actions tab (Run workflow, branch
`main`), with `gh`, or with the REST API (`POST /repos/OWNER/NAME/actions/workflows/<file>/dispatches`).

1. **Create the repository.** Drills with `init_backup_repo` ticked:
   `gh workflow run drills.yml --ref main -f init_backup_repo=true`, or the API with
   `{"ref": "main", "inputs": {"init_backup_repo": "true"}}`. It must show: job *Create the backup
   repository* green, its *Refuse to replace it* step skipped, `created a restic repository at ...`,
   and a cache `restic-<run id>` under Actions > Caches. The drill job is skipped.
2. **One CI run with a backup.** `gh workflow run ci.yml --ref main`, or the API with
   `{"ref": "main"}` (the nightly run does the same). It must show, in the lab job: *Restore the
   backup repository* finds `restic-<run id of step 1>`, *Back up configs* ends with `verified
   snapshot ...: 5 files, every inventory device, restic check --read-data clean`, and *Keep the
   repository* saves a new `restic-<run id>`. Its control-status job is still red, naming only the
   drill tests (`has no result in the evidence`): no drill has run yet.
3. **One drill run.** `gh workflow run drills.yml --ref main`, or the API with `{"ref": "main"}` and
   no inputs (`init_backup_repo` defaults to false). It must show: job *Restore drill and power-event
   drill* green, `4 passed` for the restore drill and `1 passed` for the power drill, and a
   `drill-results` artifact holding `restore-drill.xml`, `power-drill.xml` and
   `single-item-restore.json` (its `seconds` under `limit_seconds`, 300).
4. **One more CI run**, as in step 2. Its control-status job must be green and end with `every
   control in docs/controls.yml: latest test green and inside its period (N control tests)`.

After a lost cache, do the same four steps. If a broken `restic-` cache is still listed, delete it
first (Actions > Caches, or `gh cache delete <key>`), or step 1 refuses. The snapshots in the lost
repository are gone; each CI run's `results-and-backups` artifact still holds that night's
`backups/` for 90 days.

## What `make backup` checks

1. `BACKUP_REPO` holds a restic repository (its `config` file). If not: fail, write nothing. Docker
   gets the paths with `--mount`, which refuses a missing source; `-v` would create it on the host.
2. The capture has a non-empty file for every router (`<router>.conf`) and firewall (`<fw>.rules`)
   in the inventory. If one is missing: fail, naming it, and send nothing. A partial backup would
   look like a good one.
3. `restic backup` of exactly those files, with the lab's name as the snapshot's host (`--host`), which
   is how the restore drill finds this lab's newest snapshot.
4. Read the new snapshot back from the destination as one tar (`restic dump --archive tar`): every
   file present, nothing extra, each with the capture's sha256. Then `restic check --read-data`,
   which reads every pack.

Why step 4: restic deduplicates. Back up the same configs twice and the second run sends nothing; it
trusts the blobs already there. Measured here: with one byte flipped in every data pack, `restic
backup` still exited 0, and only the read-back showed `ciphertext verification failed`.
`test_corrupt_destination_fails_the_backup` proves the job fails there.

## The restore drill (`make restore-drill`, weekly)

For each router, `restic dump` its file from the newest snapshot (from the destination, not from
`backups/`) and boot it as the startup config of a throwaway FRR container: same image, sysctls and
daemons file as the real node (read from `build/topology.clab.yml`), `--network none`, and only the
capabilities zebra and bgpd need (`NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`; without them only watchfrr and
staticd start). When FRR has finished loading, `frr-reload.py --test` must find no difference, and
`ip -o link` must show only `lo`. The live routers' running configs are hashed before and after.
Measured here: about 7 s for all four routers, 16 s for the whole drill. About 1 boot in 20, zebra or
bgpd crashes as it starts and watchfrr starts it again 60 s later; that drill takes about 75 s. So the
drill waits until every daemon on watchfrr's command line runs, for up to 120 s, not only for zebra
(V-011 in [verdicts.yml](verdicts.yml)).

`test_drill_notices_a_bad_backup` boots a copy of r2's backup that kept `show running-config`'s header,
the format the collection pass used to save. FRR starts and loads the lines after the header, so a
drill that only checked the container came up would pass it. frr-reload can't parse it, and the drill
names `Unknown command: Building configuration...`.

## One item on its own

`test_single_item_restore_within_limit` restores r2's `router bgp` stanza: one `restic dump` of one
file (no snapshot restore), the stanza cut out (from `router bgp` to its `exit`), pasted with
`vtysh -f` into a throwaway router that booted with an empty config, and compared line for line with
the backup. Timed from the dump to the comparison: 2.25 to 2.39 s measured here. The stated limit is
5 minutes (`SINGLE_ITEM_LIMIT` in `netlab/restore.py`); OROS's default is 1 hour. The lab has no
database, so "one table" is one router's stanza.

By hand, from the same repository:

```bash
export RESTIC_REPOSITORY=/mnt/backup/netlab-restic RESTIC_PASSWORD_FILE=~/.config/netlab/restic-password
restic snapshots                                   # or run it in restic/restic:0.16.4
restic dump latest /src/r2.conf | sed -n '/^router bgp/,/^exit/p' > /tmp/bgp.conf
```

## How fresh, and who notices

- The drill fails if the newest snapshot is 36 hours old or more (`test_latest_backup_is_recent`):
  CI backs up nightly, so that is one missed night plus slack for a late schedule.
- The register gives the restore drill a 90-day period (OROS REC-3's default) and the rest 31 days,
  and the control-status job in CI fails when a drill's latest result is red or older.
- A failed scheduled run emails the person who last changed the schedule (GitHub's default).
- Not covered: all of this runs on GitHub's scheduler. If GitHub disables the repository's schedules
  (after 60 days without activity in a public repo), backups, drills and the checks stop together and
  nothing says so. Catching that needs a dead-man's switch outside GitHub.
