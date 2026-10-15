---
kind: selection
id: ansible
title: Ansible to apply config and check drift
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "Routers are reached only through docker exec (no management network, decision 0007), so no agent and no SSH; apply only the difference, with a dry run; keep secrets off command lines and out of logs (decision 0016); k reads and reviews YAML"
choice: Ansible (ansible>=10, with the community.docker connection), playbooks in ansible/
uses: [ansible]
alternatives:
  - name: Python only, through netlab
    why_not: No new tool, since netlab already runs docker exec for locate and finding, but check mode, per-host runs, no_log and readable diffs would all be ours to write and test
  - name: Nornir
    why_not: A Python framework too, so the same work as above with another dependency on top
  - name: Salt or Puppet
    why_not: Built around agents or a server, which a container reached only by docker exec has no place for
  - name: do nothing (change routers by hand with vtysh)
    why_not: That is the drift the drift check exists to catch
no_purchase: Plain Python in netlab, with no new dependency. It is the fallback if Ansible's footprint ever outweighs what its modules save.
staffing: k alone; Ansible is free and widely known, so a second person could pick it up without training.
vendor_domains: [ansible.com, redhat.com, github.com/ansible]
independent_sources:
  - "tests/live/test_collection.py::test_unsaved_change_is_flagged (our check: drift.yml catches a hand change on a router)"
  - "tests/live/test_secrets.py::test_no_secret_in_env_argv_logs_or_files (our measurement: with no_log, stdin and pipelining, a full apply and drift run puts the BGP password on no command line, in no environment and in no file; without pipelining it lands in a module file on the routers)"
  - "https://en.wikipedia.org/wiki/Ansible_(software) (agentless by design; owned by Red Hat since October 2015)"
---

## Context

Intended config is rendered into build/. Something has to push the difference to running routers, back their config up, and say when running and intended disagree.

## Decision

Ansible playbooks: deploy.yml (diff-only reload), drift.yml (back up and compare), over the Docker connection.

## Consequences

`host_key_checking = False` in ansible.cfg is moot with the Docker connection but stays on the risk register (RISK-6). Pipelining is required, not tuning: it is what keeps a password out of files on the routers.
