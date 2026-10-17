---
kind: selection
id: pushgateway
title: The Prometheus pushgateway for the success of unattended jobs and the commit each router runs
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "Free, a public image that pulls anonymously; a job that runs for a minute and exits (make drift, a backup, a drill) must leave a value Prometheus can read after it is gone, so a missing success can page (OROS NOT-4); `make apply` must leave the commit it applied where every alert's annotation can query it (OROS DEC-1); nothing else to run or learn; one person runs it"
choice: prom/pushgateway:v1.9.0, pinned by tag and digest in inventory/network.yml, as a sidecar in noc's network namespace on 127.0.0.1, scraped with honor_labels; the host pushes through noc's own python3 (netlab/observe.py)
uses: [prom/pushgateway]
alternatives:
  - name: node_exporter's textfile collector on noc
    why_not: Works for a job that runs on the NOC's own box, but these jobs run on the host or a CI runner and would need write access to a folder inside noc; noc runs no node_exporter either
  - name: a job writing a file into the repository or the CI artifacts
    why_not: Nothing reads it between runs, so a job that never starts is noticed only by someone looking
  - name: no purchase, failure-only alerting (CI marks the run red)
    why_not: Free and already there, but a job that never starts produces no red run; OROS NOT-4 says failure-only alerting does not pass
no_purchase: "Doing it with what is already here is CI's own red run, which says nothing when the run never happens. The pushgateway is free (Apache 2.0) and takes about 10 MiB here (docs/sizing/)."
staffing: "One person. Two make lines call `python -m netlab.observe success JOB` and the rule is generated from the inventory's jobs list. Help: the project's public issue tracker, free."
vendor_domains: [prometheus.io, github.com/prometheus]
independent_sources:
  - "tests/live/observe/test_deadman.py::test_a_job_whose_last_success_is_a_window_old_pages (our test: a real make drift reports its success, then a success older than its window pages JobMissed on the webhook)"
  - "tests/live/observe/test_outage.py::test_every_alert_says_why_what_is_normal_and_what_changed (our test: alerts about a router name the commit make apply pushed for it)"
  - "https://www.robustperception.io/monitoring-batch-jobs-in-python/ (Robust Perception, a consultancy, not the project: push a last-success time only when the job succeeds, and alert on time() minus it)"
---

## Context

OROS NOT-4 wants every scheduled job to send a success signal, and an alert when it is missing. Prometheus pulls, and a job that ran for a minute is gone before the next scrape.

## Decision

Each job's last make line pushes netlab_job_last_success_timestamp_seconds to the pushgateway on noc, so make sends it only when everything before it succeeded. `make apply` pushes the commit it applied per router the same way (decision 0020). JobMissed reads the first (decision 0022).

## Consequences

The pushgateway keeps what was pushed in memory: a redeploy starts it empty, and its start time then stands in for a last success, so a job that never ran since pages one window after the NOC started (RISK-44). A pushed value is the job's own word that it succeeded (RISK-44).
