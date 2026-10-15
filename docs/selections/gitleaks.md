---
kind: selection
id: gitleaks
title: gitleaks for secret scanning at commit, push and in CI
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "Free, and cheaper than enterprise DLP (OROS CON-7); runs offline on a laptop and in CI from one pinned image; custom rules for FRR's password line and a confidential-file marker; the repo is a personal public one with no paid GitHub plan"
choice: zricethezav/gitleaks:v8.21.2 in the pre-commit and pre-push hooks and in the CI `secrets` job, with .gitleaks.toml
uses: [zricethezav/gitleaks]
alternatives:
  - name: GitHub secret scanning and push protection only
    why_not: Free on a public repo for known token formats, but custom patterns need an organization-owned repo on GitHub Team or Enterprise with Secret Protection, so it can't see an FRR password or the marker here
  - name: TruffleHog or detect-secrets
    why_not: Also free; not measured here, and the measurements below already show gitleaks does what the constraint needs from one image
  - name: do nothing (rely on review)
    why_not: A rule that exists only as written policy fails CON-7, and a reviewer can't see what was committed and deleted again
no_purchase: GitHub's free default push protection for known token formats, plus review. It costs nothing and stays on as a backstop, but it misses the two things this repo most needs caught.
staffing: k alone; the hooks install with `pre-commit install` and the rules are two regexes in one file.
vendor_domains: [gitleaks.io, github.com/gitleaks, github.com/zricethezav]
independent_sources:
  - "tests/test_secrets.py::test_frr_password_rule_catches_what_default_rules_miss (our benchmark: gitleaks' default rules miss an FRR BGP password in a backup; the custom rule catches it)"
  - "tests/test_secrets.py::test_history_scan_finds_a_secret_committed_with_no_verify (our test: the history scan still finds a secret that was committed past the hook and deleted)"
  - "https://docs.github.com/enterprise-cloud@latest/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns (GitHub's own docs, for the alternative: custom patterns are for organization-owned repositories with Secret Protection)"
---

## Context

OROS CON-7 wants secret scanning enforced at commit and over the whole history, and a marked file pushed to a public repo blocked or alerted. ACC-4 adds a BGP password that FRR prints in clear.

## Decision

gitleaks v8.21.2 with the default rules plus two of ours, in a pre-commit hook, a pre-push hook and a full-history CI job (decision 0016).

## Consequences

`--no-verify` skips both hooks; the CI job is what still catches it, and it only blocks a merge if branch protection requires it.
