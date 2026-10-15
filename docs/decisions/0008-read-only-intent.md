---
id: "0008"
title: Mount each router's intended config read-only
date: 2026-10-13
status: accepted
decider: DoctorMen
constraint: the drift check compares each router's running config with build/<router>/frr.conf, and Containerlab binds are read-write unless marked :ro
alternatives:
  - name: do nothing
    why_not: a hand change saved with `write memory` overwrites build/<router>/frr.conf, so the drift check compares the router with its own drift and passes
  - name: copy the config into the container at deploy instead of binding it
    why_not: write memory then stays inside the container, but `make apply` needs a copy step, and the file on the router is no longer the rendered intent
  - name: "no service integrated-vtysh-config"
    why_not: write memory then saves per-daemon files beside frr.conf, which is harder to reason about and doesn't stop the save
sources:
  - https://docs.docker.com/engine/storage/bind-mounts/#considerations-and-constraints (bind mounts are writable by default; ro prevents writes)
  - https://containerlab.dev/manual/nodes/#binds (bind format, :ro)
  - https://docs.frrouting.org/en/stable-8.4/vtysh.html#integrated-configuration-mode (vtysh writes the single frr.conf)
stake: write memory now fails on every router with "Read-only file system"; a change saved on the box during an outage is lost on restart, by design, and has to go into the inventory
---

## Context

Each router's `/etc/frr/frr.conf` is its rendered file from `build/`. Reproduced on 2026-10-15 with two throwaway FRR 8.4.1 containers holding a copy of r3's config. With a writable bind, `write memory` after a hand change printed `Integrated configuration saved` and the host file then held the change. With `:ro` it printed `Read-only file system` and the host file was unchanged.

## Decision

Bind `frr.conf` read-only. `ansible/deploy.yml` reloads from the mounted file and no longer runs `write memory`. This came in with PR #1. `daemons` and `vtysh.conf` are bound read-only too, so an edit on the router can't reach `build/` either.

## Consequences

- `test_write_memory_cannot_overwrite_intent` proves `build/` is untouched after `write memory` and the hand change is still in the running config, where `make drift` catches it.
- The `Error renaming /etc/frr/frr.conf to /etc/frr/frr.conf.sav: Resource busy` line shows up in both modes. A bind-mounted file can't be renamed. With a writable bind, vtysh then wrote the file in place.
- Logged as V-004 in [docs/verdicts.yml](../verdicts.yml).
