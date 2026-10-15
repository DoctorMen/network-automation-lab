---
id: "0011"
title: Shape h2's port with HTB so a backup yields to web traffic
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: only tc and the qdiscs the kernel already has (no netem, fq_codel, sfq or cake in the sandbox), no new images, and the limit must come from outside the backup job
alternatives:
  - name: do nothing
    why_not: on the same 20 Mbit port with one queue, a 15 MB backup from h2 pushed h1's web p95 to 110-126 ms (measured), against 2.7-6.3 ms with the classes
  - name: rate-limit the backup job itself (rsync --bwlimit, a flag in the job)
    why_not: the job has to be written to cooperate, every job needs its own limit, and it still queues in front of web at full speed between bursts
  - name: cap the backup's disk with cgroup v2 io.max
    why_not: limits disk reads, not the network queue the web replies wait in; the lab's backup reads nothing from disk
  - name: one tbf or flat htb class for the whole port
    why_not: caps bulk and web alike, and web replies still wait behind the backup in the one FIFO (that is the control in the test)
  - name: fq_codel or cake on the port
    why_not: not in the sandbox kernel ("No such file or directory", checked in a throwaway FRR 8.4.1 container), so the lab couldn't test it; it shares fairly between flows rather than putting web first
sources:
  - https://man7.org/linux/man-pages/man8/tc-htb.8.html (HTB classes, rate, ceil, prio)
  - https://man7.org/linux/man-pages/man8/tc-u32.8.html (u32 match ip sport)
  - https://www.rfc-editor.org/rfc/rfc7567 (a full FIFO in front of interactive traffic is the bufferbloat problem)
stake: if the web class doesn't match (wrong port, filter missing), web replies fall into the bulk class and a backup slows users down again, with nothing in the backup job to show it
failure_modes:
  - mode: a backup fills the link and web replies queue behind it
    mitigation: web replies (source port 80) have their own HTB class with priority 0 and 15 Mbit guaranteed; everything else is the bulk class
    test: tests/live/test_qos.py::test_backup_yields_to_web
  - mode: the classes are installed but don't do their job (filter missing, wrong rates)
    mitigation: netlab.verify compares the installed rates with the inventory and checks a few connections to :80 land in the web class
    test: tests/live/test_verify.py::test_qos_change_confirmed_from_class_counters
  - mode: the backup never finishes because it is starved
    mitigation: the bulk class is guaranteed 5 Mbit and may borrow the whole 20 Mbit when web is idle; the test checks every byte arrived
    test: tests/live/test_qos.py::test_backup_yields_to_web
  - mode: bulk traffic that leaves h2 from port 80 (or web on another port) lands in the wrong class
    mitigation: Accepted risk. The filter matches the source port only, and h2 serves web on port 80 only
    test: none (accepted risk, one web port in the lab)
---

## Context

Nothing in the lab was shaped: every interface ran `noqueue`, so a bulk copy from h2 and users' web replies left through the same queue at whatever speed the veth gave them. Real server ports and WAN links have a fixed capacity, and a backup that fills one puts every user's reply behind it.

## Decision

h2's eth1 (the server LAN port) gets an HTB root capped at 20 Mbit, the stand-in for a link that can't be upgraded, with a parent class so the children lend each other what they don't use:

- `1:10` web, `u32 match ip sport 80`: rate 15 Mbit, ceil 20 Mbit, prio 0.
- `1:20` bulk, the default for everything else: rate 5 Mbit, ceil 20 Mbit, prio 1.

The numbers are the inventory's `qos:` block, rendered as tc commands in h2's exec steps. The limit is applied to the port, so the backup job knows nothing about it.

## Consequences

- Measured here with a 15 MB copy from h2 to the ISP and 40 web requests from h1, 50 ms apart: web p95 2.7-4.3 ms with the classes and 110-126 ms on a flat queue of the same rate, 6.2-6.3 ms and 117-125 ms with four CPU-bound processes running on the host. The copy takes 6.2 s either way: the link is full. Earlier runs with a 30 MB copy and 100 ms spacing gave 3.9-6.7 ms against 121-129 ms.
- The test's target is 50 ms: about 8 times the worst classed p95 seen, and less than half the best flat one.
- Each class's own queue is a plain FIFO. fq_codel, sfq and cake would be better there but aren't in the sandbox kernel; GitHub's Ubuntu runner kernel should have them (not checked), so CI numbers may differ ([LAB_PARITY.md](../LAB_PARITY.md)).
- The veth MTU is 9500, so packets in the queue are large. A 1500-byte link would queue more, smaller packets at the same rate.
- Only h2's egress is shaped. Requests to h2, and traffic that crosses other links, are not.
