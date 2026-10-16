---
id: "0022"
title: A dead-man's switch for unattended jobs and for the alert mail path itself
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "OROS NOT-4: every scheduled job, every feed and the alert path send an expected success signal, and a missing one pages, failure-only alerting does not pass; a job that never starts must page; a broken mail path must be caught through a second channel; the lab's jobs run on GitHub's schedules, in a lab that exists only for the run; no always-on host in the repository; free"
alternatives:
  - name: do nothing
    why_not: A job that fails turns its run red, but a job that never runs turns nothing red, and GitHub disables schedules after 60 quiet days (RISK-25)
  - name: alert on Alertmanager's own notification failures
    why_not: Counts only what Alertmanager notices failing; a mail accepted and never delivered, or a route that stops sending, counts nothing
  - name: an outside heartbeat service only
    why_not: Catches a nightly run that never happens, but not the lab's own alert path, and nothing in the repo can show it working; it is kept as the outside half (HEARTBEAT_URL)
sources:
  - https://prometheus.io/docs/practices/pushing/ (the pushgateway is for service-level batch jobs; push a last-success time)
  - https://www.robustperception.io/monitoring-batch-jobs-in-python/ (push the last success only on success, alert on time() minus it)
  - https://prometheus.io/docs/alerting/latest/configuration/#email_config (Alertmanager's email notifier)
stake: The nightly backup stops for a month and nobody hears of it until a restore is needed, or every page goes to a mail path that silently stopped
failure_modes:
  - mode: a job that never starts raises nothing
    mitigation: Each job pushes its last success as make's last line; JobMissed pages when it is older than every plus grace, or when none has arrived since the NOC started
    test: tests/live/observe/test_deadman.py::test_a_job_whose_last_success_is_a_window_old_pages
  - mode: a job reports success after a step failed
    mitigation: make runs the success line only when every line before it succeeded
    test: tests/test_jobs.py::test_every_job_reports_success_as_its_last_step
  - mode: a job's window drifts from its schedule
    mitigation: every is checked against the workflow's cron
    test: tests/test_jobs.py::test_every_window_matches_the_jobs_schedule
  - mode: the alert mail path breaks and the alarm goes by the same broken path
    mitigation: Watchdog always fires and is mailed every 10 s, the gaps measured live; its arrival at the mailbox, not its sending, is the signal, and AlertPathSilent pages over the webhook
    test: tests/live/observe/test_deadman.py::test_a_broken_mail_path_pages_on_the_second_channel
  - mode: AlertPathSilent pages at every NOC start, because Prometheus sends Watchdog before Alertmanager answers, that send is dropped, and it resends only a minute later
    mitigation: AlertPathSilent counts from a minute after the NOC's start (Prometheus' resend delay); a fresh deploy left the pager empty (V-023)
    test: tests/test_jobs.py::test_the_alert_path_is_not_due_before_the_first_resend
  - mode: an outside check that can't be reached fails a job whose work is done, and CI then skips saving the backup it just verified
    mitigation: A failed ping only warns; the outside check alerts by itself when no ping reaches it
    test: tests/test_jobs.py::test_a_failed_heartbeat_warns_and_the_job_still_passes
  - mode: GitHub stops running the nightly workflow, and the lab's NOC, which exists only during a run, can't notice
    mitigation: With HEARTBEAT_URL set, each job and the nightly run ping an outside check that alerts when a ping is late, from scheduled runs only; until someone sets it up, nothing does
    test: tests/test_jobs.py::test_only_a_scheduled_run_that_passed_pings_the_outside_check
  - mode: the NOC itself stops (Prometheus, Alertmanager or the whole host), so neither JobMissed nor AlertPathSilent can fire
    mitigation: Accepted. Only an outside receiver expecting the Watchdog or the heartbeat pings would notice
    test: none (accepted risk RISK-40 in docs/risks.yml)
---

## Context

OROS NOT-4's pass test: a job that never starts raises an alert, and a broken alert mail path is caught through a second channel. The lab's unattended jobs are `make drift` and `make backup` (nightly, ci.yml) and the restore and power drills (weekly, drills.yml). Data feeds already have theirs: SourceSilent for each log source (decision 0019) and TargetDown for each scrape.

## Decision

- Each job's make target ends with `python -m netlab.observe success JOB`. It pushes `netlab_job_last_success_timestamp_seconds{job}` to a pushgateway on noc. Without a NOC, as in the lab job's `make deploy-network`, it only warns.
- The jobs and their windows (every, grace) are listed in the inventory. JobMissed per job is generated from that list.
- Alertmanager mails every page, and Watchdog every 10 s, to Mailpit on noc. Alertmanager sends only on its 5 s flushes, and mails a firing group again on the first flush after repeat_interval has passed, so repeat_interval is 6 s: 10 s, as it was, mailed every 15 s (V-022). Mailpit's webhook tells the collector of each mail, so the mail path has a last-seen time like any log source.
- AlertPathSilent pages over the webhook sink when no mail has arrived for 30 s. At the NOC's start it counts from a minute after the start: Prometheus can send Watchdog before Alertmanager answers, and resends a dropped alert only a minute later (V-023).
- When HEARTBEAT_URL is set, `success` also pings `$HEARTBEAT_URL/JOB`. That is a check URL at an outside service such as healthchecks.io. A last ci.yml job pings `$HEARTBEAT_URL/nightly` when a scheduled run passed. Only scheduled runs get the URL, so a push or a pull request never stands in for a night that didn't run. A failed ping only warns, since the outside check alerts by itself when pings stop. Creating those checks and the secret is a person's job: nothing in the repository can.

## Consequences

- In the lab, a missed job pages and a refused SMTP port pages on the webhook, both measured live.
- The live test can't wait a day, so it moves the last success back by a window. The rule's arithmetic is real; the time is the test's.
- A NOC built for one CI run can't see a nightly run that never happens: only the outside check can (RISK-40, and RISK-25's gap).
- The pushgateway keeps successes in memory. After a redeploy, the window counts from its start (RISK-44).
- Everything in the alert path, mailbox included, is inside the NOC. The NOC's own death is caught only from outside (RISK-40).
