---
id: "0029"
title: Give each person and the CM tool an account on the routers we own, and record every FRR command at the NOC
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS ACC-1: every privileged command tied to a named person and sent to a store the acting admin can't alter, so that after root deletes the local record the central copy is whole and names the real user. ACC-2: a successful or failed login by anyone outside the expected admin set raises an alert. The router image must not change (no sudo, sshd, auditd or TACACS+ client in it), the carrier's isp stays as it is, and no BGP password may reach a log. A later build adds sshd certificates and a directory (OROS ACC-3, ACC-5, ACC-6, ACC-8), so nothing here may stand in their way"
alternatives:
  - name: do nothing
    why_not: Everyone works as root through `docker exec`, so no record can say who did what, and `make drift` can only say that a line changed
  - name: FRR's own `log commands`
    why_not: It logs each vtysh line with the vty's name, not the account, and it would log the BGP password lines `make apply` sends (decision 0019 keeps it off for that reason)
  - name: VTYSH_LOG, vtysh's own command log
    why_not: vtysh writes it as the user who runs it, to a file that user can edit, and names whatever $USER says; a person who sets USER=bob is logged as bob
  - name: tac_plus or FreeRADIUS accounting
    why_not: FRR 8.4's vtysh has no TACACS+ or RADIUS client, and the routers' only login is the host's console, so there is nothing for such a server to account
  - name: auditd with execve rules
    why_not: Not in the router image, and the containers share the host's kernel audit, which a lab container should not take over; it would also see vtysh start, not the commands typed into it
  - name: the proxy's records sent through the router's syslog only
    why_not: Every account can write to /dev/log and send to the collector, so a line in the proxy's words from any of them reaches the store as syslog (test_a_record_an_account_forges_is_not_taken_for_one sends two), and records read from there could be in anyone's name
  - name: each record signed with a key only root can read, checked by the collector
    why_not: Needs a key per router kept from every other account, and a check of it at the collector. A port only root can send from keeps the other accounts out with one kernel setting, and neither stops root (RISK-60)
sources:
  - https://man7.org/linux/man-pages/man7/unix.7.html (SO_PEERCRED returns the credentials of the peer process of a connected Unix socket, as the kernel recorded them at connect time)
  - https://docs.frrouting.org/en/stable-8.4/vtysh.html (vtysh talks to each daemon over its vty socket; --vty_socket names the folder to find them in)
  - https://docs.kernel.org/networking/ip-sysctl.html (ip_unprivileged_port_start, the first port an account without CAP_NET_BIND_SERVICE may bind)
stake: A config change that took a session down is found in the drift check with no name on it, and the person who made it can deny it, or delete the only record from the box
failure_modes:
  - mode: a person runs FRR commands that no record names
    mitigation: FRR's own sockets stay root and frrvty only, and no account is in frrvty. Every other account reaches FRR through the accounting proxy, which the vtysh shim points it at; a direct /usr/bin/vtysh fails to connect
    test: tests/live/test_access.py::test_frr_answers_a_person_only_through_the_accounting_proxy
  - mode: the record names whoever the shell claims to be
    mitigation: The proxy takes the uid from the kernel (SO_PEERCRED) at each connection, never from $USER or LOGNAME
    test: tests/live/test_access.py::test_the_record_names_the_account_the_kernel_reports
  - mode: an account writes a record in someone else's name
    mitigation: The proxy sends each record to the collector itself, from UDP port 601. The topology sets net.ipv4.ip_unprivileged_port_start to 1024 on every router we own (Docker sets it to 0 in a container), so only root may send from that port there, and the collector files a line as a record (source accounting) only when it comes from that port of a router we own. A line in the proxy's words that an account writes to syslog, or sends to the collector from any other port, stays syslog, and the drift lookup and UnexpectedAdmin read records only
    test: tests/live/observe/test_accounting.py::test_a_record_an_account_forges_is_not_taken_for_one
  - mode: a command's text makes a record of its own
    mitigation: The proxy joins a command's words with single spaces and writes any other character that doesn't print as an escape, so each command is one line
    test: tests/test_attribution.py::test_no_command_puts_a_line_of_its_own_in_the_records
  - mode: root deletes the record from the box
    mitigation: The proxy's own copy is at the NOC as it is written; the box's copy is a convenience
    test: tests/live/observe/test_accounting.py::test_record_leaves_the_box_and_outlives_root_deleting_its_copy
  - mode: any account rewrites the box's copy
    mitigation: busybox syslogd starts under umask 027, so only root can write /var/log/messages
    test: tests/live/test_access.py::test_each_router_we_own_has_the_named_accounts
  - mode: a secret reaches the records
    mitigation: The proxy relays each command unchanged and records it with everything after the first word that starts password, key-string, authentication-key or md5 replaced by <hidden>, so every abbreviation FRR accepts is covered too
    test: tests/test_attribution.py::test_a_secret_typed_into_vtysh_is_hidden_in_its_record
  - mode: an account nobody expects uses FRR and nobody notices
    mitigation: UnexpectedAdmin, per router we own, pages on any account outside the inventory's people and agents whose accept, refuse or command line arrived in the last 60 s; an account outside the admin group is refused and still pages
    test: tests/live/observe/test_accounting.py::test_an_account_not_on_the_list_pages_and_a_listed_one_does_not
  - mode: an account outside the admin group gets in
    mitigation: The proxy refuses it at every connection, answering each command with an error instead of closing (vtysh would retry), and records the refusal
    test: tests/live/test_access.py::test_an_account_outside_the_group_is_refused_and_recorded
  - mode: the CM tool's changes have no name either
    mitigation: Ansible logs in to the routers we own as its own agent account (ansible_user netlab), so `make apply` and `make drift` go through the proxy; its scratch folders are its own, so no one else can plant the file a rollback loads
    test: tests/live/observe/test_accounting.py::test_drift_names_whoever_set_the_running_value_last
  - mode: root bypasses all of it
    mitigation: Accepted. Root keeps FRR's own sockets, can stop the proxy and can send from its port, as root in the router's sidecars can; what already left the box stays at the NOC
    test: none (accepted risk RISK-60 in docs/risks.yml)
  - mode: a shell login that never opens FRR's CLI pages nobody
    mitigation: Accepted until the routers get sshd. Without root an account can't change routing, filters or FRR (measured on r1 as alice, iptables -S and ip route add both refused)
    test: none (accepted risk RISK-61 in docs/risks.yml)
---

## Context

Every change to a router was made as root through `docker exec`, so the drift check (decision 0008) could say a line had changed but never who changed it, and nothing in the lab could tell one person from another. The router image has busybox, python3 and FRR 8.4.1, and no sudo, sshd or auditd. FRR's vty sockets in /var/run/frr are srwxrwx--- frr:frrvty, so vtysh works only for root and the frrvty group.

## Decision

- The inventory's `access` block lists the people (alice, bob) and the agents (netlab, the CM tool) with a uid each, in one admin group (netadmin, gid 2000). Each router we own runs build/access/access.sh at deploy, just before the NOC agent: it creates the group and the accounts, gives /var/log/frr to the group (frr-reload.py writes there), makes the CM tool's scratch folders its own, so only it can write them, installs the vtysh shim as /usr/local/bin/vtysh and starts the proxy.
- The proxy (templates/access/vty_aaa.py, standard library only, running as root) offers one socket per running daemon in /run/netlab-vty. For each connection it reads the peer's uid from the kernel, refuses anyone outside the admin group, and otherwise relays to the daemon's own socket, recording `accept`, `refuse` and each `command` as one line, secrets hidden. It writes each record to syslog (authpriv) for the box's copy, which busybox syslogd, started under umask 027, keeps where only root can change it, and sends it to the collector itself from UDP port 601. The topology sets net.ipv4.ip_unprivileged_port_start to 1024 on every router we own, so only root may send from that port.
- The shim leaves root on FRR's own sockets and sends every other account through the proxy. Ansible logs in to the routers we own as netlab; the edge routers' iptables play stays root (RISK-64), and so does the carrier's isp.
- The collector files a line as a record (source accounting) only when it comes from port 601 of a router we own; the same words from any other port stay syslog. It turns each record into admin_last_seen_seconds{node,user,event}, and UnexpectedAdmin fires, per router, for any user outside the inventory's list seen in the last 60 s. r2's translation log is sent the same way, from port 602 (decision 0031).

## Consequences

Every FRR command a person or the CM tool runs is at the NOC within seconds, under the account the kernel names, and a person not in the inventory pages when they touch FRR, whatever group they are in. A record that an account other than root forges on the router, through syslog, straight to the collector or inside a command, is not taken for one. Root still bypasses all of it and can send from the proxy's port (RISK-60). A shell login that never opens FRR's CLI is recorded nowhere until the routers get sshd (RISK-61). The records travel as clear UDP like the rest of syslog (RISK-34), so one can be lost, or forged by a host on the campus from a router's address and the proxy's port. The sshd certificates and directory a later build adds can reuse the same accounts and group; the proxy only needs the group to exist.
