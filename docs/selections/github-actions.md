---
kind: selection
id: github-actions
title: GitHub Actions to run every test on every change and nightly
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "A personal public repo on GitHub with no paid plan and no always-on machine; CI must start privileged containers with Containerlab (root and a real kernel), finish the lab job inside 20 minutes, keep its results and backups as artifacts, and run nightly so every control in docs/controls.yml has a dated result inside its 31-day period"
choice: GitHub Actions on GitHub-hosted ubuntu-24.04 runners (.github/workflows/), using only GitHub's own actions (actions/checkout, actions/upload-artifact and the like)
uses: [github-actions]
alternatives:
  - name: another hosted CI (GitLab CI, CircleCI)
    why_not: The code lives on GitHub, so it means a second account and a mirror or webhook, and its token would need a repository secret, which this repo has none of
  - name: a self-hosted runner
    why_not: Needs a machine that is always on and that someone patches, which the lab doesn't have; and on a public repo a fork's pull request could run code on it, which GitHub's own docs warn against
  - name: do nothing (run `make all` by hand before merging)
    why_not: No nightly run and no dated, public result, so the control register's 31-day periods would rest on memory
no_purchase: GitHub-hosted standard runners cost nothing for a public repo. If that ended, the fallback is `make all` by hand on a laptop, which keeps the tests but loses the dated, public record.
staffing: one person, the repository owner; the workflows are short YAML files and almost every step is a make target that runs the same way locally.
vendor_domains: [github.com, docs.github.com, github.blog, githubusercontent.com]
independent_sources:
  - "docs/sizing/data/2026-10-15-github-runner.json (our measurement on a GitHub-hosted runner: kernel 6.17.0-1022-azure, Docker 28.0.4, the 7-node lab deployed by Containerlab 0.68.0 in 90.5 MiB)"
  - "tests/test_render.py::test_ci_pulls_the_image_the_inventory_names (our check: the workflow pulls exactly the image the inventory pins)"
  - "https://en.wikipedia.org/wiki/GitHub (an encyclopedia entry: GitHub has been owned by Microsoft since 2018)"
---

## Context

The tests only prove something if they run on every change, and on a schedule, somewhere other than the author's laptop, with a result anyone can look up.

## Decision

GitHub Actions, on GitHub-hosted runners pinned to ubuntu-24.04, because the repo already lives on GitHub and public repos run there free.

## Consequences

The lab job depends on GitHub's runner image (its kernel and Docker), which is why `runs-on` is pinned. GitHub disables a public repo's schedules after 60 days with no activity, and a red job only blocks a merge if branch protection requires it (RISK-10). A third-party action would bring in another maker's code; none is used.
