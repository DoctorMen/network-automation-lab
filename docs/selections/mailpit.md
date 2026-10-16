---
kind: selection
id: mailpit
title: Mailpit as the NOC's mailbox, where the alert mail path's heartbeat arrives
date: 2026-10-16
status: accepted
decider: DoctorMen
constraint: "Free, a public image that pulls anonymously; a real SMTP server Alertmanager's email notifier talks to, on 127.0.0.1 inside noc; it must say when each mail arrives, so the arrival, not the sending, is what the NOC checks (OROS NOT-4); no account, no outside mail service the lab could leak to; one person runs it"
choice: axllent/mailpit:v1.20, pinned by tag and digest in inventory/network.yml, as a sidecar in noc's network namespace (SMTP 127.0.0.1:1025, API 127.0.0.1:8025), with its webhook posting each new mail to the collector
uses: [axllent/mailpit]
alternatives:
  - name: MailHog
    why_not: Does the same job, but has had no release since 2020 and has no webhook, so arrival would need polling its API with a script of our own
  - name: a real mail provider (a mailbox at a hosted service)
    why_not: Needs an account and a password in CI, and sends lab traffic out of the lab; the lab would test the provider, not its own path
  - name: no purchase, alertmanager_notifications_failed_total from Alertmanager itself
    why_not: Free and already there, but it counts only the failures Alertmanager notices; a mail that is accepted and never delivered, or a route that stops sending, counts nothing, which is failure-only alerting
no_purchase: "Doing it with what is already here is Alertmanager's own failure counter, which catches a refused connection but not mail that silently stops arriving. Mailpit is free (MIT) and takes about 15 MiB here (docs/sizing/)."
staffing: "One person. Its flags are in netlab/monitoring.py's sidecars(); nothing is configured in its UI. Help: the project's public issue tracker, free."
vendor_domains: [mailpit.axllent.org, github.com/axllent]
independent_sources:
  - "tests/live/observe/test_deadman.py::test_a_broken_mail_path_pages_on_the_second_channel (our test: with SMTP refused on noc, no mail arrives and AlertPathSilent reaches the webhook pager)"
  - "https://laravel.com/docs/11.x/sail (Laravel's own docs, not the maker's: Sail's default docker-compose.yml runs Mailpit on port 1025 to capture an app's mail)"
---

## Context

OROS NOT-4 wants the alert-delivery path itself to send a success signal, and a broken mail path caught through a second channel. That needs a mail server whose arrivals the NOC can see.

## Decision

Alertmanager mails every page, and Watchdog every 10 s, to Mailpit on noc. Mailpit's webhook tells the collector of each mail, which sets log_last_seen_seconds{source="mail"}; AlertPathSilent pages over the webhook sink when that is older than 30 s (decision 0022).

## Consequences

Mailpit stands in for the NOC's real mail server, inside the NOC itself, so a mail path broken outside the NOC (a relay, a provider) is not in the lab (RISK-40). It keeps mail in memory only; a redeploy starts it empty.
