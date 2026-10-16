# Sizing

What the lab costs to run, taken from measurements rather than rules of thumb. Each data file holds the raw `docker stats` samples its figure was computed from, plus the kernel, Docker and Containerlab versions of the machine.

## RAM, per environment

- **sandbox**: measured at 338.2 MiB for all 21 nodes in the `sandbox` environment, the full lab: the 8 network nodes (100.9 MiB, the NOC's host among them) and the NOC's 13 sidecars (237.3 MiB; Loki 76.38 and Prometheus 42.2 the most, each router's frr_exporter 9 to 12, each router's node_exporter about 7.5 and h2's 7.2). Data: [2026-10-16-sandbox.json](data/2026-10-16-sandbox.json). The lab was idle after one full live run, a second `make observe` run, `make power-drill` (which restarts every container), a third `make observe` run and `make drift`. So Prometheus held about a quarter of an hour of data, and Loki its store's whole history, which it keeps on the lab host's disk across the cut (decision 0025).
  Before the NOC, the 7-node network took 88.5 MiB here: [2026-10-15-sandbox.json](data/2026-10-15-sandbox.json), idle right after a fresh deploy, two `make live` runs and one `make drift`.
  This is a cloud VM: kernel 6.18.44, Docker 29.8.2, cgroup v1, 4 CPUs, shared with other work at the time. Containerlab 0.68.0 is installed but can't deploy there (no `/proc/modules`), so a stand-in script created the same containers, binds, sysctls and veth links. The file's `deployed_by` field says so too. BFD was on.
- **github-runner**: measured at 90.5 MiB for all 7 nodes in the `github-runner` environment, deployed by real Containerlab 0.68.0. Data: [2026-10-15-github-runner.json](data/2026-10-15-github-runner.json), copied from the log of [CI run 38756410669](https://github.com/DoctorMen/network-automation-lab/actions/runs/38756410669).
  GitHub's Ubuntu 24.04 runner (CI now pins `ubuntu-24.04`): kernel 6.17.0-1022-azure, Docker 28.0.4, cgroup v2. BFD was on, and the lab was idle right after `make live` and `make drift`. That figure is the network alone, from before the NOC. CI's third NOC job (observe-3) now measures the full lab on every run that gets that far and uploads the file as the `sizing-data` artifact; to update the figure, copy a newer one into `data/` and quote it here and in the README.

In the network, the four FRR nodes use most of it, r2 (zebra, bgpd, ospfd, staticd, bfdd) the most; in the full lab, Loki and Prometheus take a third of the total, and grow with what they keep (720 h of logs, Prometheus' default 15 days). h2 runs two `python3 -m http.server` listeners. fw1 and h1 run only `sh` and `sleep`. The `per_node_mib` field in the file has the numbers.

## Re-measure

```bash
make measure LAB_ENV=laptop NOTE="what the machine is, and what the lab was doing"
```

It takes about 20 s: five `docker stats --no-stream` readings, 2 s apart, of every container in `build/topology.clab.yml`. A node's figure is the mean of its five readings, and the total is their sum. `docker stats` counts the container's memory cgroup minus inactive page cache ([Docker docs](https://docs.docker.com/reference/cli/docker/container/stats/)). Re-running on the same day in the same environment replaces that day's file.

Then update the figure here and in the README. `make test` ([`tests/test_sizing.py`](../../tests/test_sizing.py)) fails until both are within 1 MiB of the newest file for that environment, and until every data file is linked from this page.

Measure again after anything that adds a daemon or a node.
