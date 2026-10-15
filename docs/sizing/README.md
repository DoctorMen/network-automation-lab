# Sizing

What the lab costs to run, taken from measurements rather than rules of thumb. Each data file holds the raw `docker stats` samples its figure was computed from, plus the kernel, Docker and Containerlab versions of the machine.

## RAM, per environment

- **sandbox**: measured at 88.5 MiB for all 7 nodes in the `sandbox` environment. Data: [2026-10-15-sandbox.json](data/2026-10-15-sandbox.json).
  This is a cloud VM: kernel 6.18.44, Docker 29.8.2, cgroup v1, 4 CPUs, shared with other work at the time. Containerlab 0.68.0 is installed but can't deploy there (no `/proc/modules`), so a stand-in script created the same containers, binds, sysctls and veth links. The file's `deployed_by` field says so too. BFD was on. The lab was idle, right after a fresh deploy, two `make live` runs and one `make drift`.
- **github-runner**: measured at 90.5 MiB for all 7 nodes in the `github-runner` environment, deployed by real Containerlab 0.68.0. Data: [2026-10-15-github-runner.json](data/2026-10-15-github-runner.json), copied from the log of [CI run 38756410669](https://github.com/DoctorMen/network-automation-lab/actions/runs/38756410669).
  GitHub's Ubuntu 24.04 runner (CI now pins `ubuntu-24.04`): kernel 6.17.0-1022-azure, Docker 28.0.4, cgroup v2. BFD was on, and the lab was idle right after `make live` and `make drift`. Every CI run that gets that far measures again and uploads the file as the `sizing-data` artifact; to update the figure, copy a newer one into `data/` and quote it here and in the README.

The four FRR nodes use most of it, r2 (zebra, bgpd, ospfd, staticd, bfdd) the most. h2 runs two `python3 -m http.server` listeners. fw1 and h1 run only `sh` and `sleep`. The `per_node_mib` field in the file has the numbers.

## Re-measure

```bash
make measure LAB_ENV=laptop NOTE="what the machine is, and what the lab was doing"
```

It takes about 20 s: five `docker stats --no-stream` readings, 2 s apart, of every container in `build/topology.clab.yml`. A node's figure is the mean of its five readings, and the total is their sum. `docker stats` counts the container's memory cgroup minus inactive page cache ([Docker docs](https://docs.docker.com/reference/cli/docker/container/stats/)). Re-running on the same day in the same environment replaces that day's file.

Then update the figure here and in the README. `make test` ([`tests/test_sizing.py`](../../tests/test_sizing.py)) fails until both are within 1 MiB of the newest file for that environment, and until every data file is linked from this page.

Measure again after anything that adds a daemon or a node.
