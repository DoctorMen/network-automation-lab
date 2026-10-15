# Collection methods

`make drift` ([`ansible/drift.yml`](../ansible/drift.yml)) is the collection pass. For each router
and the firewall it copies the running state off the box into `backups/` and checks the device
against its intended config. For the routers it also checks the copy against the device. This page
lists the method for each device type, the devices that need a method of their own, and what isn't
collected. It covers OROS REC-2.

| Device type | Nodes | How it's collected | Off-box copy | Checked against running |
|---|---|---|---|---|
| Router (FRR 8.4.1) | r1, r2, r3, isp (see below) | `vtysh -c "show running-config no-header"` over `docker exec` (Ansible's Docker connection) | `backups/<router>.conf` | Intent and startup: `frr-reload.py --test` with `build/<router>/frr.conf`. The copy: `frr-reload.py --test` with the copy itself ([`verify_capture.yml`](../ansible/verify_capture.yml)) |
| Firewall (iptables) | fw1 | `iptables-save` over `docker exec` | `backups/fw1.rules` | Intent and startup: `firewall.sh`'s iptables lines replayed in a new network namespace, then `iptables -S` diffed with the live `iptables -S` |
| Host | h1, h2 | Not collected | none | none (gap, below) |

## Routers

- `show running-config` in FRR 8.4.1 starts with four lines that aren't config: `Building configuration...`,
  a blank line, `Current configuration:` and `!`. vtysh refuses a file that starts with them
  (`line 1: % Unknown command: Building configuration...`), so a backup that kept them couldn't be
  restored, and the capture check fails on it. `no-header` leaves them out. It's how `frr-reload.py`
  reads the running config too.
- Startup config is `/etc/frr/frr.conf`, which is `build/<router>/frr.conf` mounted read-only. So the
  intent check is also the startup-versus-running check, and `write memory` can't change either.
- The capture check copies `backups/<router>.conf` back to the router as `/tmp/captured.conf` and runs
  `frr-reload.py --test` on it. That parses the copy the way a restore would. Under "Lines To Delete" is
  running config the copy is missing; under "Lines To Add" is copied config that isn't running.
- Watch the tool's own normalisation. `frr-reload.py` never lists lines it refuses to remove
  (`frr defaults`, `username`, `password`, `line vty`, `service integrated-vtysh-config`); it only logs
  them. The check counts those log lines as differences, so a copy that lost
  `service integrated-vtysh-config` still fails (the capture test checks this), and so would one that
  lost a `password` line (same code path; the lab routers have no password to test it with). The one
  exception is `frr version`, a stamp FRR adds itself.
- `ipv6 forwarding` is ignored in both checks. It mirrors a kernel sysctl that varies by host (GitHub
  runners turn it on), and the lab runs no IPv6. `ip forwarding` is not ignored: a router with IPv4
  forwarding off is broken, so the check should fail ([V-009](verdicts.yml)).

- isp stands in for the carrier. It is collected only because this lab builds it; a real carrier's
  router is out of reach, and only `make locate` enforces the inventory's ownership rule.

## The firewall: an awkward device

- fw1 has no config CLI and no config file of its own. Its policy lives only in the kernel's netfilter
  tables. `iptables-save` is the kernel's own dump, in the format `iptables-restore` reads back, so that
  is the backup.
- Its startup config is the rendered `firewall.sh`, run once by the topology's `exec` step and mounted
  read-only for the same reason as the routers' `frr.conf`.
- To compare with intent you can't just run `firewall.sh` again: it starts with `iptables -F FORWARD`,
  so it would wipe a hand change before anything could see it, and reset the counters.
  `unshare -n` starts a shell in a new, empty network namespace with its own iptables tables.
  The play replays only the iptables lines of `firewall.sh` there (the other lines set addresses and
  routes, and the new namespace has no interfaces) and diffs its `iptables -S` with the live one.
  It's a line diff, because rule order is policy.
- Checked in the FRR image (busybox `unshare`, iptables 1.8.7 legacy): the new namespace has a
  different `net:[...]` inode and starts with empty ACCEPT chains; after the replay, the live
  `iptables-save -c`, counters included, was the same as before apart from its timestamp comments.
- Limits: `iptables -S` lists the filter table only. `firewall.sh` only writes that table, but a hand
  change to the nat, mangle or raw table would only show in `backups/fw1.rules`, not fail the check.
  Counters aren't compared. `backups/fw1.rules` itself isn't loaded back and compared with the live
  rules, the way the router backups are.

## Router kernel state: not collected (a stated gap)

The router checks compare FRR's config, not the Linux kernel underneath it. An iptables rule on a
router (say, a DROP left behind by an interrupted failover test), an interface set down by hand, or a
kernel route added outside FRR is not flagged. The live tests notice the effect on traffic, not the
change itself. `/etc/frr/daemons`, which says which routing daemons start, is mounted read-only like
`frr.conf`, so it can't drift on the router, but nothing checks that every daemon it lists is running.

## Hosts: not collected (a stated gap)

h1 and h2 have no config of their own. Their whole state is the topology's `exec` lines (address,
default route) and its `cmd` (the listeners), applied again on every deploy. Nothing reads it back, so a
hand change on a host, for example an extra route, isn't flagged. The data-plane tests check what the
hosts can reach, not how they're configured.

## Collection cycle

- CI runs `make drift` nightly, on every push to `main` and on every pull request, after the live tests, and uploads
  `backups/` in the `results-and-backups` artifact, kept for 90 days.
- For a lab that stays up, run it from cron. Daily keeps it inside REC-2's 24-hour cycle. The cron user
  needs Docker access, and cron's PATH has to include the venv:

  ```
  # m h dom mon dow  command
  17 3 * * *  cd $HOME/network-automation-lab && PATH=$PWD/.venv/bin:$PATH make drift >> $HOME/netlab-drift.log 2>&1 || logger -t netlab "make drift failed"
  ```

- `backups/` keeps only the latest copy. Each CI run's copy is kept as that run's artifact.
- The tests in [`tests/live/test_collection.py`](../tests/live/test_collection.py) prove each check turns
  red: an unsaved change on r2, a copy of r2's backup with one line removed, and an ACCEPT rule added
  by hand on fw1. Each also proves the check is green on the clean lab first.
