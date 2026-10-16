---
id: "0025"
title: Dump a node's state the moment a link fails, and keep the central store on the lab host's disk
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS FND-2: logs shipped off the box continuously, not at a clean shutdown; a trigger-based capture armed for the next occurrence, so a transient fault leaves evidence of its cause; after a hard reset of a node, its last minutes of logs and the triggered capture are in the collector; the reset happens in the power-event drill and before a restore; the router image must not change; free; no secret in the evidence"
alternatives:
  - name: do nothing
    why_not: Each line already reaches the store as it is written (decision 0019), but the store lived inside the noc container, so the power cut that reset the node reset the store too, and nothing recorded the node's state at the fault
  - name: a rolling packet capture on every node
    why_not: tcpdump is not in the router image, and a capture of every link costs disk and CPU on four shared cores. A state dump answers what the box thought at the fault; make finding still captures packets for a carrier on demand (decision 0017)
  - name: poll each node's state from the NOC every few seconds
    why_not: A one-second outage falls between two polls, and the poll crosses the link that just failed. The node sees its own carrier change at once
  - name: dump at boot instead
    why_not: After a reset the state of the fault is gone; only what was sent before it remains
  - name: keep Loki's data in a Docker volume
    why_not: The Containerlab stand-in here and the real Containerlab bind folders by path; a folder under build/ is the same in both, and shows up in a plain ls
sources:
  - https://man7.org/linux/man-pages/man8/ip-monitor.8.html (ip monitor link prints each link change as it happens)
  - https://grafana.com/docs/loki/v3.1.x/operations/storage/wal/ (the write-ahead log replays unflushed lines after a crash)
  - https://www.busybox.net/downloads/BusyBox.html (logger reads lines from stdin; syslogd -R forwards each)
  - https://github.com/grafana/loki/blob/v3.1.1/pkg/ingester/recovery.go (after a replay, every stream's count of lines starts again)
stake: A link flaps at 3 a.m., a router is rebooted to fix it, and nothing is left to say why it flapped
failure_modes:
  - mode: a link fails and nothing records the node's state at that moment
    mitigation: agent.sh on every log source runs `ip monitor link`; on a carrier loss or a link going down it dumps the interfaces and their counters, queues, filter counters and the router's OSPF, BFD and routes at once, and sends the dump 3 s later
    test: tests/live/observe/test_evidence.py::test_a_flap_leaves_a_state_dump_in_the_central_store
  - mode: the watcher stops, and the next fault leaves no dump
    mitigation: agent.sh runs `ip monitor link` in a loop that starts it again 3 s after it stops and logs a line saying so; nothing watches that loop itself
    test: tests/live/observe/test_evidence.py::test_a_stopped_flight_recorder_is_armed_again
  - mode: the dump is sent over the link that just failed
    mitigation: It is taken at once and sent 3 s later; a one-second flap of r3's port to h2 leaves complete dumps from both ends
    test: tests/live/observe/test_evidence.py::test_a_flap_leaves_a_state_dump_in_the_central_store
  - mode: a flapping link floods the collector
    mitigation: At most one triggered dump every 30 s per node
    test: tests/test_monitoring.py::test_flight_recorder_is_armed_on_a_link_failure_and_only_reads
  - mode: the dump carries a secret
    mitigation: It runs only commands that read, never the running config, and the test searches every saved dump for the BGP password
    test: tests/live/observe/test_evidence.py::test_evidence_before_a_reset_is_kept_off_the_box
  - mode: a planned reset loses what only the box had
    mitigation: make evidence, a step in the power-event and restore runbooks, copies each node's dump and its own log into results/evidence/ and fails unless every dump is also in the store
    test: tests/live/observe/test_evidence.py::test_evidence_before_a_reset_is_kept_off_the_box
  - mode: the power cut that resets the node resets the store too
    mitigation: Loki's /loki is build/noc/loki on the lab host, so a redeploy of noc finds it, and the write-ahead log replays what was not yet flushed
    test: tests/live/test_power_event.py::test_evidence_outlives_a_power_cut
  - mode: the power goes twice, and the second cut loses what the store took in after the first
    mitigation: At its next replay Loki 3.1.1 can drop lines it took in since its last replay, until it writes a checkpoint (V-027). It checkpoints every 30 s here instead of every 5 minutes, and the drill restarts the store first and cuts only after that checkpoint, 57 s after the restart in one run here
    test: tests/live/test_power_event.py::test_evidence_outlives_a_power_cut
  - mode: the second cut comes before that first checkpoint
    mitigation: Accepted. Lines the store took in between the two cuts can be lost
    test: none (accepted risk RISK-46 in docs/risks.yml)
  - mode: the lab host's disk is lost
    mitigation: Accepted. There is one copy, on the lab host's disk, and nothing backs it up
    test: none (accepted risk RISK-34 in docs/risks.yml)
  - mode: anyone on the lab host can write into the store's folder
    mitigation: Accepted. The folder is world-writable because Loki runs as its image's user, not as whoever rendered
    test: none (accepted risk RISK-45 in docs/risks.yml)
---

## Context

Since decision 0019 every log source sends each syslog line to the NOC as it is written. Two things were missing for FND-2. Nothing captured a node's state when a fault happened, and the store was a folder inside the noc-loki container, so the whole-lab power cut that resets a node (decision 0015) started it empty. A single node can't be reset on its own here: restarting a container deletes its links on both ends (decision 0015), so the drill cuts every node, the NOC's included.

## Decision

- agent.sh, already the last exec step of every log source, also runs the flight recorder. `ip monitor link` reports each link change; on NO-CARRIER, LOWERLAYERDOWN or `state DOWN` it dumps state into a file at once and sends it 3 s later with `logger -t flightrec`, at most once every 30 s. If `ip monitor link` stops, it is started again 3 s later, with a line that says so. Each line carries the dump's id, and the last says how many lines there were. Lines are cut at 200 characters, below busybox syslogd's own limit.
- `sh /monitoring/agent.sh dump WHY` takes the same dump on demand. `make evidence` runs it on every source (or `NODE=`), copies each node's own log, writes results/evidence/<UTC time>/<node>.txt and checks every dump reached the store. `make logs NODE= MINUTES=` reads a node's lines back from the store.
- Loki's /loki is bound from build/noc/loki on the lab host, which render creates and never empties. Loki checkpoints its write-ahead log every 30 s, because a replay starts each stream's count again and the lines since are only safe from the next crash once a checkpoint is written (V-027).
- The power-event drill gets a second test: the store is killed and started, as after an earlier cut; r2's link to r3 fails for a second; the dump and r2's last five minutes of its own log are confirmed in the store; once the store has written its first checkpoint since the restart, the whole lab is cut, and afterwards all of it is still in the store while r2's own copy is gone. If r2 booted within those five minutes, the lines it wrote before its route to the NOC was up never left it (RISK-33), so the count starts at its first line the store has.

## Consequences

A router's dump is about 85 lines, about 11 KB, which is a third of the 32 KB a box keeps of its own log, so a triggered dump pushes older lines off the box sooner; the store has them. The dump travels over the same clear UDP syslog as every other line (RISK-33), so a dump sent while the node's path to the NOC is down is lost; the 3 s delay covers a short flap, not a long outage. The store now outlives a redeploy but is still one copy (RISK-34), in a world-writable folder (RISK-45), and a second cut within about a minute of the first can lose what came in between (RISK-46). The drill runs in the weekly drills workflow, not on every push, because it redeploys the whole lab.
