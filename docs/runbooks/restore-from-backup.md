---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead tells the service desk which router is being restored and when service is confirmed, and the change board afterwards that a backup, not the inventory, was loaded
last_reviewed: 2026-10-15
hosts: [r1, r2, r3, isp, fw1, h1]
written_by: Claude (AI assistant)
---
# Runbook: restore a router from its backup

A router has to go back to the config it last ran, and the intended config can't be used for that: a
bad change was merged and deployed, the inventory isn't at hand, or someone needs a router as it was
on a given night. Normally `make apply` from the inventory is the fix ([config-drift.md](config-drift.md));
this runbook is for when the backup is the source. The backups are restic snapshots of what
`make drift` captured, one file per device ([docs/backups.md](../backups.md)). `<lab>` below is the
`name:` in `build/topology.clab.yml`.

## Who does what

- **Responder** (on-call network engineer): steps 1 to 6. The only person who loads anything on a router.
- **Coordinator** (NOC shift lead): decides which snapshot to restore (step 2), and that nobody
  deploys from the inventory until step 6 is done, which would undo the restore.
- **Comms** (NOC shift lead): tells the service desk which router is affected and when step 5 passes.

## Steps

1. **Reach the backup.** `BACKUP_REPO` and `BACKUP_PASSWORD` as in [docs/backups.md](../backups.md)
   (defaults `/mnt/backup/netlab-restic` and `~/.config/netlab/restic-password`). restic runs in its
   pinned image, the same way `make backup` runs it:
   ```bash
   restic() { docker run --rm --network none --user "$(id -u):$(id -g)" \
     --mount type=bind,src="$BACKUP_REPO",dst=/repo \
     --mount type=bind,src="$BACKUP_PASSWORD",dst=/pass,readonly \
     -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD_FILE=/pass restic/restic:0.16.4 --no-cache "$@"; }
   ```
   CI's repository is in the Actions cache, which only a workflow can read; each CI run's
   `results-and-backups` artifact holds the same files for 90 days.
2. **Pick the snapshot.** `restic snapshots --host <lab>` lists them, newest last, each with seven
   files: every router's config, fw1's rules, and r2's and r3's edge rules. Use `latest` unless the coordinator names an older ID.
3. **Put the router's backup where it boots from.** `build/<router>/frr.conf` is the router's startup
   config (bind-mounted read-only as `/etc/frr/frr.conf`) and what `make apply` loads:
   `restic dump --host <lab> latest /src/r2.conf | grep -v ' password sha256:' > build/r2/frr.conf`.
   The backup holds r2's BGP password only as its sha256 tag
   ([decision 0016](../decisions/0016-secrets-guardrails.md)); kept, the tag would become the key and
   the session would drop. Overwrite the file in place like this; don't delete it first, or the
   running container keeps the old one.
4. **Load it.**
   - The router is running: `make apply`. frr-reload changes only the lines that differ, without
     restarting daemons; the other routers' files are unchanged, so nothing happens on them.
     Measured here, after the drill below: dump and `make apply` of r2 in 39 s, most of it the canary's
     checks; BGP was up with its password when it ended, and both OSPF neighbors `Full` 5 s later.
   - The router or the whole lab host is gone: on a new host run `make render` first (topology and
     daemons files), then step 3 for every router, then
     `sudo containerlab deploy -t build/topology.clab.yml --reconfigure`. Not `make deploy`: it renders
     `build/` again from the inventory, over the restored files. Then `make apply`: step 3 left the
     password out, so a router booted from its backup has none until `make apply` sets it from the
     secret store (the running-router path above does that already).
   - fw1: its start script loads its rules from `firewall.sh` on every deploy. To load the backed-up
     rules instead: `restic dump --host <lab> latest /src/fw1.rules | docker exec -i clab-<lab>-fw1 iptables-restore`.
5. **See it work.** `docker exec clab-<lab>-r2 vtysh -c "show ip ospf neighbor" -c "show bgp summary"`:
   two `Full`, and 198.51.100.1 with a prefix count. `docker exec clab-<lab>-h1 ping -c 3 203.0.113.1`.
   `ansible-playbook drift.yml --limit r2` (from `ansible/`) passes: r2 runs exactly the restored file.
6. **Back to the inventory.** `make render` puts `build/` back to intent, then `make drift`. Any line
   it names is where the backup differs from the inventory: the coordinator decides it with
   [config-drift.md](config-drift.md) before anyone runs `make apply`.

## Done when

The router runs its restored backup (step 5), users get through, and `make drift` against the
inventory passes or its differences are in the ticket with a decision.

## Drill it in the lab

Take a backup first (`make drift && make backup`). Someone else wipes one router's routing, for example
`docker exec clab-<lab>-r2 vtysh -c "conf t" -c "no router bgp 65001" -c "no router ospf"`, and tells
you only "r2 lost its config, put it back as it last ran, from the backup". Then follow the steps from 1
and record the run in [dry-runs.yml](dry-runs.yml). `make restore-drill` checks, without the live lab,
that every router's latest backup boots and one stanza comes back on its own.
