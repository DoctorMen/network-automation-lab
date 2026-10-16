---
id: "0017"
title: Send a carrier a bundle they can re-run, not a summary they have to believe
date: 2026-10-15
status: accepted
decider: DoctorMen
constraint: "We can't log into the carrier's router, the carrier's own test usually says clean, and the counterparty has neither our repo nor our Python; the router image has no tcpdump, and its FRR support-bundle script ships without its command list"
alternatives:
  - name: do nothing
    why_not: Send build/finding.json and a description, as today. It holds our figures but none of the raw output, versions, clock or capture behind them, so the carrier has to take our word for it, which is the argument PRV-3 exists to avoid
  - name: a screenshot or pasted ping output
    why_not: One sample, no method, nothing to re-run, and a middle hop's rate-limited replies look exactly like loss in one
  - name: reproduce.sh that calls netlab
    why_not: The counterparty would need our repo, Python and inventory; sh, awk, sha256sum and docker are on any Linux box
  - name: install tcpdump on the edge router for the capture
    why_not: Changes the device under test and needs a package pull; the image's own Python can capture with an AF_PACKET socket in about twenty lines
  - name: run FRR's generate_support_bundle.py as shipped
    why_not: Without /etc/frr/support_bundle_commands.conf (not in the image) it logs CRITICAL, exits 0 and writes nothing; and upstream's list includes `show running-config`, which prints the BGP password
sources:
  - https://www.rfc-editor.org/rfc/rfc792 (ICMP Echo and Echo Reply)
  - https://www.rfc-editor.org/rfc/rfc6673 (Round-Trip Packet Loss Metrics)
  - https://www.rfc-editor.org/rfc/rfc1812#section-4.3.2.8 (routers rate-limit the ICMP errors traceroute relies on)
  - https://raw.githubusercontent.com/FRRouting/frr/frr-8.4.1/tools/etc/frr/support_bundle_commands.conf
  - https://www.tcpdump.org/manpages/pcap-savefile.5.txt (the pcap file format capture.py writes)
stake: A carrier that can't check our evidence closes the ticket as "no fault found", and users keep losing packets while both sides argue
failure_modes:
  - mode: the re-run says Reproduced whatever it measures
    mitigation: reproduce.sh compares its own segment, owner and edge view with the finding's; CI first runs it on a healthy lab and requires Did not reproduce
    test: tests/test_finding.py::test_reproduce_agrees_only_when_its_own_run_does
  - mode: the bundle reproduces on our lab only because it reads our repo
    mitigation: The test re-runs a copy away from the repo, and the CI reproduce job has no checkout at all
    test: tests/live/test_finding.py::test_carrier_finding_reproduces_from_the_bundle_alone
  - mode: a bundle sent with a file missing, edited after it was written, or an empty support log
    mitigation: "`netlab finding` runs --verify before it reports the bundle complete: SHA256SUMS, every raw output, every support log non-empty, the capture, citations and image digests"
    test: tests/test_finding.py::test_verify_names_every_gap_in_a_bundle
  - mode: the bundle carries the BGP password
    mitigation: lab/ holds only rendered files (never a password), the support bundle omits `show running-config`, and --verify rejects any clear password line
    test: tests/live/test_finding.py::test_carrier_finding_reproduces_from_the_bundle_alone
  - mode: the re-run runs another image, or a different path, and agrees by luck
    mitigation: reproduce.sh checks every image digest in versions.txt and the traced path, and says it can't tell (exit 2) instead of guessing
    test: tests/test_finding.py::test_reproduce_agrees_only_when_its_own_run_does
  - mode: nobody outside the team has ever re-run one
    mitigation: A clean CI runner stands in; a real outsider's cold re-run still has to be recorded
    test: none (needs a person outside the team; see the scorecard row for PRV-3)
---

## Context

`make locate` already names the segment where loss starts and its owner (PRV-2), and writes the figures to build/finding.json. OROS PRV-3 asks for more: raw evidence and method (commands, capture filters, versions, time source), an authority the counterparty already trusts, and someone outside the team reproducing the finding from the bundle alone.

## Decision

`make finding` (netlab/finding.py) runs locate and writes results/finding/:

- FINDING.md (one page: the verdict, the segment table, the edge capture, the ping we ask the carrier to run from their side, RFC 792, RFC 6673 and RFC 1812 for what backs the method) and METHOD.md;
- raw/ (every command and its output as printed), pcap/ (ICMP on our hand-off port while the edge pings the far side, with the capture script), support/ (FRR's support bundle from each router we own on the path, with the vendored command list minus `show running-config`);
- versions.txt (image digests, FRR, kernel, Docker, what deployed the lab (read from Containerlab's labels on the nodes) and the Containerlab installed on this host, netlab commit), time.txt (UTC, each device's clock against the host's, the host's sync state);
- lab/ (the rendered topology and configs) and, in a lab run, lab/condition.sh to recreate the fault;
- finding.env and reproduce.sh, and SHA256SUMS over all of it.

reproduce.sh is plain sh. CI's `reproduce` job downloads the bundle on a runner that never checks out the repo, stands the lab up from lab/, requires "Did not reproduce" on the healthy lab, recreates the fault, and requires "Reproduced" with the same segment and owner.

## Consequences

The CI job runs in its own job after the lab job. It was estimated at 2 to 3 minutes; its first three runs on GitHub, pull-request runs 38831606745, 38834167787 and 38837283633, passed in 110, 59 and 112 s. The bundle's lab copy has no BGP password, so the re-run's r2-isp session runs without TCP MD5; ICMP probes don't depend on it. The clean runner is a stand-in: PRV-3's Pass needs a person outside the team to re-run a bundle cold, and that is recorded only when it happens.
