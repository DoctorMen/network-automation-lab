---
kind: selection
id: docker
title: Docker Engine to run the lab's nodes and one-shot tools
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "Containerlab needs a container runtime; the one pinned FRR image must run the same way on a laptop and on a GitHub ubuntu-24.04 runner; the hooks and CI run tools such as gitleaks as one-shot images; free, with no service of our own to keep running"
choice: Docker Engine, as GitHub's ubuntu-24.04 runner image ships it (28.0.4 when the lab was measured there), or whatever Docker Engine a laptop has
uses: [docker]
alternatives:
  - name: Podman
    why_not: Free and daemonless, and Containerlab 0.68.0 can drive it (`--runtime podman`), but the runner ships Docker, pre-commit's docker_image hooks call docker, and nothing here has been run on Podman
  - name: Docker Desktop
    why_not: Not needed on Linux, and Docker's terms make it paid for larger companies; the engine alone is free
  - name: do nothing (Linux network namespaces with FRR installed on the host)
    why_not: No image to pull, but FRR would have to be installed on every host in the exact version, with no digest to pin, and the nodes would share the host's files
no_purchase: Docker Engine is free and already on the runner image and in most Linux distributions. If that changed, Podman is the free fallback, at the cost of re-testing the lab and the hooks on it.
staffing: k alone; the lab uses `docker run`, `docker exec` and `docker inspect`, nothing more.
vendor_domains: [docker.com, docker.io, mobyproject.org, github.com/docker, github.com/moby]
independent_sources:
  - "docs/sizing/data/2026-10-15-github-runner.json (our measurement: on Docker 28.0.4 with cgroup v2 on a GitHub runner, the 7 nodes took 90.5 MiB, read with docker stats)"
  - "tests/live/test_platform.py::test_running_version_matches_inventory (every CI run reads each node through docker exec and checks it runs the exact pinned image)"
  - "tests/test_secrets.py::test_staged_secret_is_blocked_at_commit (our test: the pre-commit hook really runs the pinned gitleaks image through Docker)"
  - "https://en.wikipedia.org/wiki/Docker_(software) (an encyclopedia entry: the engine's source is under the Apache License 2.0)"
---

## Context

Every node of the lab is a container, and so are the secret scanner and, later, the backup tool. Something has to run them, the same way on a laptop and in CI.

## Decision

Docker Engine, the runtime Containerlab uses by default and the one the GitHub runner already has.

## Consequences

Root on the host's Docker socket is root on the host, and Containerlab starts every node privileged (RISK-2). The lab reaches nodes only with `docker exec`, so it needs no management network (decision 0007).
