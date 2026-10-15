---
id: "0005"
title: Generate the tests' expected state from the inventory
date: 2026-10-11
status: accepted
decider: DoctorMen
constraint: one person keeps the configs and the tests; any fact typed in two places will sooner or later disagree with itself
alternatives:
  - name: do nothing
    why_not: hand-written expected values in each test; adding a router means editing tests too, and a test can pass against an old picture of the network
  - name: snapshot the live network once and compare later runs to it
    why_not: proves only that nothing changed, not that the network matches the intent; a broken first deploy becomes the baseline
  - name: model the configs offline with Batfish instead
    why_not: checks the configs, not the running lab, and adds a tool and a container; it stays on the roadmap as an addition, not a replacement
sources:
  - https://www.rfc-editor.org/rfc/rfc9315 (intent-based networking; intent assurance checks the network really complies with intent)
stake: a bug in netlab's generator would break the configs and the expectations the same way, so they could agree on something wrong; tests/test_render.py keeps hand-written checks for that reason
---

## Context

The live tests need to know which OSPF neighbors, BGP sessions, loopbacks and host addresses a healthy lab has.

## Decision

`netlab render` writes `build/expected_state.json` from the same `inventory/network.yml` that produced the configs. The live tests read only that file, never literals. The platform block (image, digest, FRR, Alpine and busybox versions) goes in the same file for `test_running_version_matches_inventory`.

## Consequences

- Adding a router to the YAML adds it to the tests with no test edits.
- The offline render tests deliberately keep literal strings (`router-id 10.255.0.1`, `summary-only`), so a generator bug can't hide behind generated expectations.
