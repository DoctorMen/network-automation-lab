# Operator-Ready Operations Standard (OROS) 0.3: notice to account

In these posts, what operators, analysts and sysadmins need is usually proof, taken from the side they control, rather than a new feature: proof that signals still arrive, that a fault sits where they say it does, that a change or backup actually took effect, and that a control works. They also need actions scoped so narrowly that nothing else breaks. OROS 0.3 turns that into 61 pass/fail requirements in 10 families. Seven follow the on-shift job loop (notice, decide, find, prove, contain, change safely, recover) and three cover accounting (for access, to gatekeepers, and to the person who decides). It is built from 3,087 mapped posts out of 3,785 relevant Stack Exchange posts, plus 103 unchecked pass-1 posts. Every code with enough posts (112 site codes) was checked twice; 20 small codes (50 posts) were not checked. Several pass-1 ORAS features did not survive the checked corpus (owner on every alert, listable suppressions, impact-named incidents, timeline packs, shift handover, an API-first source of truth); SLA clocks and honest metrics were too rare to check. They are listed as unproven, not required.

**How to use it.** Score each requirement pass or fail against a tool, runbook or team practice. Codes in brackets, such as (ne:N18, sf:N18), are need codes from the coding pass: ne = Network Engineering SE, sec = Security SE, sf = Server Fault. The coded rows behind them are not in this repository; each family quotes and links its strongest posts. Where a pass test says "stated", the team writes its own number down. The bracketed defaults are suggested starting values, not findings from the evidence.

## Evidence base

| Source | Coded | Relevant | Who is asking | Checks |
|---|---|---|---|---|
| Pass 1: NANOG, cisco-nsp, vendor forums, tool trackers, SANS/USENIX surveys | 103 | 103 (33 NOC, 28 SOC, 42 tool requests) | Older, senior people in smaller self-managed shops (pass 1's own bias note) | None. Counts are approximate (~) |
| Network Engineering SE | 1,500 | 939 | Network engineers 566, sysadmins 156, ISP 42, NOC 15 | Evidence and depth check on every code |
| Security SE | 1,500 | 1,112 | Developers 311, sysadmins 281, security engineers 138, GRC 102, IT managers 64, SOC 37 | Two checks; 10 small codes (22 posts) not checked |
| Server Fault | 1,800 | 1,734 | Sysadmins 1,388, developers 172, network engineers 71, SOC 3 | Two checks; 10 small codes (28 posts) not checked |
| **SE total** | **4,800** | **3,785** | | |

**Reliability, in plain terms.** Every SE code with enough posts was rechecked twice on a sample of its posts: an evidence check (do the posts say this?) and a depth check (is this the real need behind the ask?). Individual codes were often flawed. Across both checks the checkers logged 1,246 problems against 2,411 checked items (52%; NE 311/676, Security 407/771, Server Fault 528/964). The files do not define the unit, and some denominators exceed a code's post count, so read this as a problem rate per checked item, not a share of posts. The families held. 106 of the 112 checked site codes passed at least one check, and the checkers mostly corrected the wording rather than rejecting the need. So treat the counts as a ranking of themes, not as population statistics. Requirement wording follows the checkers' corrected wording, not the original labels.

**Counting rules.**
- Each relevant SE post carries exactly one primary code. Per-site code counts add up to exactly 939, 1,112 and 1,734, so nothing is double-counted within a site.
- A family's count is the sum of the checked SE codes mapped to it. Pass-1 approximate counts are shown beside it, never added.
- Excluded: N13 "make this specific config or feature work" (576 posts: ne 104, sec 48, sf 424); site codes where both checks failed (60 posts: ne:N22 26, ne:N8 10, ne:N10 4, sf:N2 10, sf:F8 5, sf:F5 5); unchecked small codes (50 posts); and supported codes outside the operator loop (12 posts: sf:F6 7, sf:F25 5).
- sec:S11 (18) is mapped to Gatekeepers (ATT-1, scope-reducing design) and sec:S16 (13) to Justify (JUS-3, how security work is sourced).
- sec:N7 (81) is mapped to Gatekeepers because its corrected wording is about auditors, QSAs and scan vendors. Mapped to Prove, it would give Prove 339 and Gatekeepers 281.
- Mapped: 3,087 of the 3,209 posts outside N13 (96.2%).

## How the families rank

| Family | Checked SE posts | NE | Sec | SF | Sites |
|---|---|---|---|---|---|
| 1 Notice | 315 | 153 | 40 | 122 | 3 |
| 2 Decide | 259 | 84 | 91 | 84 | 3 |
| 3 Find | 480 | 217 | 31 | 232 | 3 |
| 4 Prove | 258 | 143 | 25 | 90 | 3 |
| 5 Contain | 274 | 34 | 126 | 114 | 3 |
| 6 Change safely | 246 | 76 | 18 | 152 | 3 |
| 7 Recover | 322 | 20 | 49 | 253 | 3 |
| 8 Account for access | 190 | 23 | 93 | 74 | 3 |
| 9 Account to gatekeepers | 362 | 0 | 347 | 15 | 2 |
| 10 Justify the decision | 381 | 45 | 222 | 114 | 3 |

Ranking by raw post count (Server Fault is 46% of relevant posts and 40% of the posts mapped here; NOC and SOC askers are 55 of 3,785):
1. **Find** (480). Largest count, confirmed on all three sites, and includes posts that state days of lost time ("After four working days wasted", "TAC for a week").
2. **Recover and Notice** (322 and 315). They are 7 posts apart, inside the coding noise, so treat them as a tie. Recover covers backups and failover that fail silently, found only when the data is needed; it is 79% Server Fault (253 of 322) and has 20 NE posts, 9th of 10 families there. Notice is spread across all three sites (NE 153, Security 40, Server Fault 122).
3. **Contain, Decide, Prove and Change safely** (274, 259, 258, 246). These are within 30 posts of each other, which is inside the coding noise, so treat them as a tie. Pass 1's largest theme, about 30 "Too many alerts" posts, sits in Decide, which argues for doing Decide early.

Justify (381) and Account to gatekeepers (362) are large but come mostly from Security SE (222 and 347 posts). Security SE's largest groups of askers are developers (311) and sysadmins (281); the files do not break roles down by code, so who asks Gatekeepers and Justify questions is unknown. They decide whether operator work is accepted, but they are off-shift jobs. Account for access (190) is spread across all three sites.

---

## OROS-1 Notice: see the state that matters, and know when the signal itself dies

**They say:** Which OID gives me this counter; how do I send a test trap; the devices randomly stop sending traps; forward syslog to Splunk but cut the noise; Nagios only checks ping, disk and memory; which logs and rules actually catch attacks.
**They need:** Every state that matters reaches the tool they already run, and every source, job and alert path proves it is still delivering, at a volume the licence allows, with each detection's blind spots known.

**Posts:** 315 (NE 153, Security 40, Server Fault 122). Codes: ne:N16 76, ne:N17 49, ne:N4 19, ne:N18 9; sec:S9 23, sec:N17 12, sec:N16 5; sf:N17 46, sf:N18 36, sf:N16 30, sf:N4 10. Pass 1 adds about 9 unchecked "My rule stopped firing" posts (N4).

**Requirements**
1. **NOT-1 State, not ping.** Every logical or subordinate object the team relies on has its own check: a BGP session, a policy-based IPsec tunnel, a controller-managed AP, a stack member, a degraded RAID array, a page returning the right content, each webapp, and interface flaps down to sub-second. Maintenance that slips also alerts: an alert fires when patches or a pending reboot exceed their window (sf:N18). *Pass:* taking the object down while its host still answers ping raises an alert within the check interval [default: 5 minutes], and a lab host left with a pending reboot past its window raises an alert. (ne:N18, sf:N18)
2. **NOT-2 Into the tool you already run.** Every value an operator reads from a device or service to make a decision reaches the monitoring or log tool the team already runs, in a form that tool ingests, without adding another monitoring silo (sf:N16). Where analysts cannot reach the source system, the detail it holds (IDS payloads, audit logs) is forwarded into the tool they are allowed to change (sec:N16). On network gear the value comes from a documented pollable object, not a CLI screen-scraper. Where a platform or OS version does not export it, a per-platform, per-version coverage list records the gap and the fallback, such as deriving it from other OIDs (ne:N16). *Pass:* no production check depends on an unlisted scraper, and every value in the coverage list is marked exported, derived or gap. (ne:N16, sf:N16, sec:N16)
3. **NOT-3 Arrival proof per source.** Each log, trap and flow source has a last-seen check at the collector (on NE this rests on confirmed arrival, ne:N17 depth), and an on-demand synthetic test event (a test trap, a test syslog line, a deliberately triggered detection such as a MAC move) that exercises the real path end to end (ne:N4). The device's own send counters are never taken as proof of delivery. A dead source can be restored without rebooting production gear (ne:N4 depth). *Pass:* blocking one source's export while the device still reports "sending" raises a `source silent` alert within the stated interval [default: twice the source's normal gap, at most 15 minutes], and the silenced lab source is brought back without a reboot. (ne:N4, ne:N17, sec:N17)
4. **NOT-4 Dead-man's switch.** Every scheduled job, every data feed and the alert-delivery path itself sends an expected success signal, read from channels already in place (email, HTTP POST). When the signal is missing past its window, an alert fires. Failure-only alerting does not pass. *Pass:* a job that never starts raises an alert, and a broken alert mail path is caught through a second channel. (sf:N4)
5. **NOT-5 Precise volume at the source.** Known-benign, high-volume messages are cut at the device or emitting daemon by named message, source or rate limit, while named low-severity messages that are wanted still get through. Ingest per source is reported against the licence or storage budget. *Pass:* a filtered noisy message type disappears at the collector while a chosen low-severity message still arrives, and every source's ingest is within budget. (ne:N17, sec:N17, sf:N17)
6. **NOT-6 Detection coverage table.** Each SOC detection lists the log sources and sensor placement it depends on, its known blind spots (traffic that never crosses a tap, remote logons, logs not worth the budget) and its measured false-positive load. *Pass:* the table has no blank cells, and each false-positive figure is from the current review cycle [default: quarterly]. (sec:S9)
7. **NOT-7 One central store.** Every log, flow and trap source, including third-party apps that cannot be changed and hosts without root, reaches one central searchable store, and history outlasts on-box rotation. *Pass:* a line from a lab app whose code and config are left untouched, forwarded without root, is searchable centrally, and an event older than the source's on-box rotation can still be found. (ne:N17, sec:N17, sf:N17)

**Unsaid constraint.** Vendor is the main one (ne:N16 25, ne:N17 14, sf:N17 7): the same MIB works on one platform and not another, and the NMS is rigid. Budget (ne:N17 5, sf:N17 6, sec:N17 4): licensed volume limits. Skill (ne:N16 10, sec:S9 6, sf:N18 4). SLA (ne:N4 3): the client calls before the monitor does. Underneath, silent pipeline failures are found by accident or late (ne:N4 depth check), so nobody knows to ask. **How OROS neutralises it:** NOT-2's coverage list makes vendor gaps known before they bite. NOT-5 fits volume to the licence at the source. NOT-3 and NOT-4 make silence itself an alert, so the failure nobody knew to ask about surfaces on its own.

**Evidence**
- https://networkengineering.stackexchange.com/q/6784 "I have a screen scraper in place currently, but that is really not ideal in terms of scaling"
- https://networkengineering.stackexchange.com/q/77044 "The device will say that it generates a trap, but the tcpdump does not ever see the trap come in."
- https://serverfault.com/q/496172 "like a heartbeat that is being actually checked instead of passively waiting for failures"

**Prove it in your lab:** In Containerlab, run FRR routers and a Linux collector (rsyslog, snmptrapd, Prometheus with Alertmanager, Wazuh). Export BGP state from `show bgp summary json` as a metric and shut the session while the peer still pings (NOT-1, NOT-2), then drop one router's syslog with nftables and disable the nightly backup job, asserting in CI that both alerts fire (NOT-3, NOT-4). Forward one app's log file into the collector with an unprivileged forwarder and keep it longer than the app's own rotation (NOT-7). Extend a detection test suite (one known-bad event per rule) into the NOT-6 coverage table.

---

## OROS-2 Decide: is this signal real, here, and does it need me?

**They say:** Is this normal or a threat; the LAG graph shows impossible values; the scanner says we are vulnerable, but it is intranet-only; one down host gives 1 + n alerts; how do I exempt this one file without disabling the rule.
**They need:** A fast, defensible verdict on one signal (what matched, what is normal here, what changed, whether the number is an artifact, whether the finding applies to this build), and a way to quiet noise without going blind.

**Posts:** 259 (NE 84, Security 91, Server Fault 84). Codes: ne:N15 62, ne:N1 22; sec:N1 36, sec:S3 29, sec:N15 16, sec:N2 10; sf:N15 40, sf:N1 35, sf:N3 9. Pass 1's top three themes sit here (about 30 "Too many alerts", 17 "Mute it", 10 "Router down = 80 alerts", all unchecked), but their owner, listable and impact-naming parts did not survive (see Unproven).

**Requirements**
1. **DEC-1 Why it fired, what is normal, what changed.** Every alert carries the matched rule or condition and the values that matched, a link to the asset's known-normal baseline for that signal, and a link to its recent changes (deploys, package or kernel updates, config commits, scans). Where the asset's role or criticality is known (server vs user port, trunk, transit peer or circuit), alerts can be scoped by it, so noise on one role can be quieted without losing history (ne:N1, sf:N1; a smaller sub-need). *Pass:* in a sample of [default: 20 alerts] all three are filled, and an alert raised within [default: 1 hour] of a lab config commit shows that commit. (ne:N1, sec:N1, sf:N1)
2. **DEC-2 Know what the number counts.** Every metric, counter or log field used for alerting documents what it counts. That includes normal OS behaviour that looks alarming (cache and standby memory, load average versus CPU%) and known collection artifacts: poll caching, counter wraps, resets and discontinuities, LAG or ingress+egress double counting, a missing sampling multiplier, NIC offload, a sensor that sits after TLS termination. The pipeline flags discontinuities instead of graphing them as spikes. *Pass:* a known byte count pushed through each interface type in use (physical, LAG, sub-interface) matches the graph within a stated tolerance [default: 5%], and an SNMP agent restart or a 32-bit wrap raises no spike alert. (ne:N15, sec:N15, sf:N15)
3. **DEC-3 Vulnerability triage.** Each scanner or advisory finding is judged against the exact running build (backport-aware, not the version banner; sf:N14 depth), its exposure (internet-facing or internal) and its exploitability. It is given a severity, and an interim mitigation is recorded when the fix is blocked (EOL OS, dev time, performance cost). *Pass:* a host with a backported fix is not reported vulnerable, or the false positive is documented with changelog evidence. (sec:S3, sf:N14 depth)
4. **DEC-4 Narrow silence.** A suppression covers one rule, field, host, file, process or maintenance window and leaves the control live everywhere else. It is time-boxed where the case allows, and it carries a reason that will hold up when an auditor or a later scan raises the finding again. *Pass:* the suppressed event replayed on a second host still alerts, and replayed after the expiry still alerts. (sec:N2)
5. **DEC-5 One alert per cause.** Dependent alerts sit behind the causal alert (host, proxy, uplink, shared service, the monitor's own uplink), while independent failures on healthy components still page. The dependency model stays maintainable across hundreds of nodes without hand-tuning each check. *Pass:* failing a parent gives one page, and a service killed on a healthy node in the same window gives a second. (sf:N3)

**Unsaid constraint.** Skill (sf:N1 7, ne:N1 4, sec:N1 4, ne:N15 4); pass 1 adds that L1 staff often lack the rights or skill to tune (pass 1, unchecked and unlinked). Vendor (ne:N15 8, sec:N15 5): counter and field semantics vary by platform. Rights (ne:N15 3, sf:N15 3, sec:S3 3): analysts often cannot touch the host and must go through its owner (sec:N1 depth check). Time (sec:N1 4, sec:S3 5). Politics (sec:S3 3, sec:N2 2): an exception must hold up when an auditor or later scan raises it again. **How OROS neutralises it:** DEC-1 and DEC-2 put the context a senior engineer would bring into the alert itself, so a junior on shift can decide without host access. DEC-3 and DEC-4 make each call a written, defensible record that survives the next audit.

**Evidence**
- https://security.stackexchange.com/q/255388 "Is it normal or anormal activity?"
- https://networkengineering.stackexchange.com/q/18976 "give incorrect (way too large and unrealistic) values for the octets transferred"
- https://serverfault.com/q/601728 "I only want to see one alert for a down host instead of 1 (down) + n"

**Prove it in your lab:** Keep each alert rule as YAML with why_fired, a baseline query and a link to the node's config git log, and fail CI on any rule missing them. Then push an exact iperf3 byte count through a port, a Linux bond and a VLAN sub-interface, restart snmpd, cut a core link, replay a suppressed Wazuh event on a second agent, and scan a Debian host with a backported OpenSSH fix, asserting each DEC pass test in pytest.

---

## OROS-3 Find: localize the fault, the cause and the actor before the evidence disappears

**They say:** No drops on any interface, but users see loss; TAC can't find it; it hangs and a reboot fixes it; is it a firmware bug or my config; which port is this IP on; which workstation is eating our bandwidth; nothing I tune helps.
**They need:** Evidence of where and why that survives the reboot, a version-exact verdict, a reliable where-and-who answer from gear they already own, and a layer-by-layer verdict on performance ceilings.

**Posts:** 480 (NE 217, Security 31, Server Fault 232). Codes: ne:N6 55, ne:N14 43, ne:N20 43, ne:N32 41, ne:N31 35; sec:N14 14, sec:N31 12, sec:N20 5; sf:N6 53, sf:N14 52, sf:N32 42, sf:F1 34, sf:N20 34, sf:N8 10, sf:N31 7. Pass 1 adds about 6 unchecked microburst and loss posts (N6).

**Requirements**
1. **FND-1 Loss the averages hide.** Wherever the platform exposes them, the toolset collects per-queue, buffer or ASIC drop counters and rates finer than the polling interval. The runbook tells real path loss from ICMP rate-limiting at intermediate mtr hops, and finds the hop or layer where traffic dies when ping, interface counters and app logs all look clean. *Pass:* a microburst that a 5-minute average hides is traced to its queue or interface, and a hop that only rate-limits ICMP is not reported as path loss, while loss injected with netem is. (ne:N6, sf:N6)
2. **FND-2 Evidence survives recovery.** Logs are flushed and shipped off-box continuously, not only at clean shutdown, and a trigger-based capture (state dump, rolling pcap) is armed for the next occurrence. A transient fault then leaves evidence of its cause. *Pass:* after a hard reset of a lab node, its last minutes of logs and the triggered capture are in the collector. (ne:N32, sf:N32)
3. **FND-3 Version-exact verdict.** Inventory holds the exact running version of every device and host. Each odd-behaviour ticket ends with one verdict: own config, documented or undocumented behaviour or default change, interaction with another vendor, or known defect (ne:N14, sec:N14, sf:N14). For network gear and servers, the fixed release, build or workaround is also recorded against that version (ne:N14, sf:N14; Security SE askers do not ask for it). *Pass:* no odd-behaviour ticket stays unclassified past the stated time [default: 5 working days], and every post-upgrade ticket carries a verdict. (ne:N14, sec:N14, sf:N14)
4. **FND-4 Where it is, and what is running.** One query answers which switch port and VLAN an IP, MAC or hostname is on, and what it is. It joins ARP tables with per-VLAN MAC tables across vendors over read-only access, and tells edge ports apart from uplinks. Scheduled discovery compares the inventory (IPAM, port spreadsheet, CMDB) against live state, including what is listening, and lists the mismatches (ne:N31 and sf:N31 depth checks). The inventory is one authoritative fleet record that can be queried by script, and DNS, monitoring and IPAM entries are generated from, or checked against, that record (sf:N8 depth). *Pass:* a host moved between lab ports is found on its new port within one polling cycle, a service started without being recorded appears on the next mismatch report, and a host added to the inventory record appears in DNS and monitoring without being keyed in again. (ne:N31, sec:N31, sf:N31, sf:N8)
5. **FND-5 Who did it.** Activity (logons, lockouts, traffic, mail relay, CPU or I/O load) can be tied to a specific host, account, VLAN or tenant from logs the systems already produce or can be set to produce. The identifiers resolve to one actor: an FQDN rather than a short name, the real client behind NAT or a load balancer, the authenticated account. Per-host or per-VLAN usage is available on gear without flow export, with an alert on sustained use before users complain. Where usage is billed, per-VLAN, per-IP or per-tenant volumes in GB per month are accurate enough to hold up as a bill, and per-link utilisation and peaks are kept over time to right-size circuits (ne:N20). *Pass:* given an outside complaint (public IP, port, time), the collected logs alone name the internal host, a lab host saturating the uplink is named by the alert, and a known lab transfer appears in that tenant's monthly volume within a stated tolerance [default: 5%]. (ne:N20, sec:N20, sf:N20)
6. **FND-6 Layer-by-layer bottleneck.** The performance runbook measures each layer (app, DB, OS/kernel, network or storage protocol, VM, host) against a known-good reference before any tuning copied from the web is applied. It ends with a verdict: a fixable setting or a hard limit. *Pass:* every performance ticket has per-layer measurements and a verdict attached. (sf:F1)

**Unsaid constraint.** Vendor (N14: ne 19, sf 12, sec 7; ne:N6 7; sf:N6 6; sf:F1 4): the bug database, release notes and TAC did not surface the problem in time (ne:N14 depth check). Skill (ne:N32 11, ne:N31 11, ne:N20 8, ne:N6 6, sf:N32 5, sf:F1 5): the gear was inherited or the asker is not a network specialist. Rights (ne:N6 9, ne:N31 7, sf:N6 5, sf:N32 4): SNMP read-only, no physical access, remote sites. Budget (ne:N20 7, sf:N20 8): old or cheap gear with no flow export, and no money for a collector. SLA (sf:N32 4). **How OROS neutralises it:** FND-2 and FND-3 replace waiting on the vendor with the team's own evidence and a recorded verdict per version. FND-4 works over read-only access, and FND-5 starts from the logs the gear already produces. Switching on extra logging for FND-5 needs config rights, but neither needs new hardware.

**Evidence**
- https://networkengineering.stackexchange.com/q/2457 "We have a case open with TAC for a week and they cannot find packet loss on any interface."
- https://serverfault.com/q/705862 "all the logs between the unexpected power down and the previous clean shut down were missing"
- https://networkengineering.stackexchange.com/q/41660 "After four working days wasted, it was a bug on the NX-OS firmware 7.0(3)I2(2d)."

**Prove it in your lab:** Put a tc qdisc with a tiny limit between two FRR nodes and fire a 50 ms burst, and rate-limit ICMP on a middle hop so mtr shows false loss beside real netem loss (FND-1). Add a flight-recorder script triggered on flaps, an ip2port tool joining FRR ARP with bridge FDB tables, conntrack logging on the SNAT gateway, and the same functional test suite run on two FRR releases to classify the difference (FND-2 to FND-5).

---

## OROS-4 Prove: evidence the other owner accepts, taken from the vantage point you have

**They say:** I have no access, so I have to prove the port is not open; how do I prove to the link provider the problem is theirs; I'm not allowed to install Wireshark; I only have CLI, so TFTP is out; who is at fault.
**They need:** Measurements from their own side, using only the access they hold, strong enough to clear themselves and make the owner of the other segment act, plus an own-side workaround that keeps security. They ask for proof and localization, not a timeline document.

**Posts:** 258 (NE 143, Security 25, Server Fault 90). Codes: ne:N19 51, ne:N7 46, ne:N25 46; sec:N19 14, sec:N25 11; sf:N7 39, sf:N25 33, sf:N19 18. Pass 1 adds about 3 unchecked "prove it's not the network" posts (N7).

**Requirements**
1. **PRV-1 Capture where SPAN can't reach.** The team has a written method to get packets from routed ports, single LAG members, remote sites, firewalls and routers that only offer on-box capture, and CLI-only devices behind jump hosts. Captures are kept as pcap beyond the on-box buffer (a rolling last-N window), with no installs on client or server and no risk to production. On hosts, the same goes for what a black-box program sends, observed from the one machine the team controls. *Pass:* a pcap from a routed port and one from a CLI-only lab router both reach the collector without TFTP. (ne:N19, sec:N19, sf:N19)
2. **PRV-2 Clear yourself, then place it.** For a suspected fault in a segment the operator does not control, the runbook takes observations from the operator's own edge and every point it controls (ne:N7 depth, sf:N19 depth), clears the operator's own segment first, and ends in a finding that names the segment and the owner who must act. *Pass:* with loss injected in a lab "carrier" segment, the procedure names that segment from edge observations alone. (ne:N7, sf:N7, sf:N19)
3. **PRV-3 Meet their standard of proof.** Every escalation to a carrier, vendor or other team carries the raw evidence and the method (commands, capture filters, versions, time source). Where possible it also cites an authority the counterparty already trusts (vendor documentation, an RFC or standard, a canonical test artifact). *Pass:* someone outside the team reproduces the finding from the bundle alone. (ne:N7, sf:N7, sf:N25)
4. **PRV-4 Interop: fault side and a safe workaround.** Every cross-vendor or cross-party failure records the parameters at both ends (proposals, PFS group, timers, versions), taken from the peer or decoded from a capture when the far side can't be reached. It names which side's capability or config causes the failure. Any workaround is applied only on the side the operator controls and states which security property it keeps; a silent fallback to RC4, plaintext or skipped validation fails. *Pass:* a PFS-group mismatch between two different lab IPsec stacks is found by the parameter diff, and the own-side fix keeps PFS. (ne:N25, sec:N25, sf:N25)

**Unsaid constraint.** Politics (sf:N7 18, ne:N7 10, sf:N25 4): the network team is the default suspect, and the evidence has to move the other party without making enemies (sf:N7 depth check). Rights (ne:N7 9, sf:N19 8, ne:N19 6, sf:N25 5, sec:N19 4): no access to the core switch, the hypervisor or the other team's firewall. Vendor (ne:N25 18, ne:N7 8, ne:N19 6): platforms that cannot SPAN a routed port, and providers whose own test says "clean". Policy (ne:N19 3): endpoint installs are forbidden and the client's change control blocks new config. **How OROS neutralises it:** PRV-1 and PRV-2 need only the access the operator already has. PRV-3 makes the evidence re-runnable by the other side, which turns an argument into a check and keeps the relationship intact.

**Evidence**
- https://networkengineering.stackexchange.com/q/26541 "I don't have access so I have to prove that the port is not open"
- https://networkengineering.stackexchange.com/q/640 "it's not allowed to install a packet analyzer, such as Wireshark or tcpdump, on client or server"
- https://serverfault.com/q/894740 "Sonicwall blames the other end"

**Prove it in your lab:** Build own-edge FRR, a "carrier" node you may not log into with tc netem loss, and a far end; capture at your own edge and the far end with synced clocks (time sync is an OROS method choice, not an evidenced need), have a script write a one-page finding with pcaps and commands attached, and ask someone outside to re-run it cold (PRV-2, PRV-3). Stream a rotating pcap from a CLI-only router over an SSH jump host, and pair strongSwan with Libreswan using mismatched PFS groups (PRV-1, PRV-4); REA's pcap analysis from pass 1 can feed the finding.

---

## OROS-5 Contain: stop the one source, hold the boundary, keep legitimate traffic flowing

**They say:** Drop the excess broadcast without shutting the port; infected clients are flooding SMTP; I'm afraid of blocking legitimate users; attackers spoof our app traffic; customers keep opening their files to other customers; the vendor's IP changes several times a day; backups tank the whole server; nobody follows the policy.
**They need:** Trace to the true source, contain at the narrowest reversible scope, enforce on components they control rather than on goodwill, and keep default-deny working when the far side moves.

**Posts:** 274 (NE 34, Security 126, Server Fault 114). Codes: ne:N21 22, ne:N29 12; sec:N29 77, sec:N21 20, sec:S14 18, sec:S17 11; sf:N29 59, sf:N21 39, sf:F3 10, sf:F19 6.

**Requirements**
1. **CON-1 Trace before you block.** The containment runbook traces disruptive traffic or load through aggregation points (NAT, load balancer, shared mail, web or file server) to a specific port, host, tenant or job. Where known, it records why the traffic is flooded or punted to the CPU (edge ports, MAC aging, IGMP snooping, CoPP). *Pass:* a lab storm source is traced to its port within the stated time [default: 15 minutes]. (ne:N21, sf:N21)
2. **CON-2 Narrowest scope, reversible.** Containment drops or rate-limits only the excess, per port, VLAN, service instance or IP. It can be reversed and does not err-disable or shut shared ports. *Pass:* during a lab broadcast storm the port stays up and other hosts on the same VLAN keep their service level. (ne:N21, sf:N21)
3. **CON-3 Measured false-block rate.** Before blocking of abusers who rotate IPs or identities is switched on, the rule is tested against a set of legitimate and roaming clients and its false-block rate is recorded. *Pass:* the recorded rate is under the stated threshold [default: 0.1% of legitimate requests]. (sec:N21)
4. **CON-4 Enforce where you control.** Trust boundaries are enforced server-side or in the network or system layer (802.1X or NAC, private VLANs, tenant isolation, server-side verification), not on identifiers the other party holds or can forge (embedded app keys, Origin headers, hostnames, source IPs). The legitimate work that party needs still passes. Where full enforcement is impossible, the record says how much the control raises the attacker's cost. *Pass:* a client presenting a spoofed identifier is refused while the normal workflow succeeds. (ne:N29, sec:N29, sf:N29)
5. **CON-5 Allow by name, not by moving IPs.** Default-deny egress lets needed vendor destinations through by name (FQDN-aware rules) or through a relay, mirror or proxy the operator controls, instead of hand-kept IP lists or brittle DNS-to-IP scripts. *Pass:* changing the lab "vendor" IP keeps the allowed flow working while all other egress stays blocked. (sec:S17, sf:F19)
6. **CON-6 Bulk work yields.** Backups, AV scans, bulk copies and other jobs that cannot be skipped run under a priority, throttle or bandwidth limit applied from outside the job. Production stays responsive on fixed hardware and the job still finishes. *Pass:* during a lab bulk copy the web service's p95 latency stays under target and the copy completes. (sf:F3)
7. **CON-7 Guardrails, not requests.** Where staff must follow a security rule, the secure behaviour is enforced or automated (forced screen lock, pre-commit and repository-history secret scanning), using controls cheaper than enterprise DLP. The same controls stop staff, accidentally or on purpose, moving proprietary code or confidential data out through public GitHub, cloud uploads, USB or misdirected email (sec:S10 evidence). Phishing simulations are run in a form users accept as fair, and incentives do not create a snitching culture (sec:S14 evidence; the failed depth check disputes the incentives clause). A rule that exists only as written policy fails. *Pass:* a seeded secret is blocked at commit and found by the history scan, and a test push of a marked file to a public repository is blocked or alerted. (sec:S14, sec:S10)

**Unsaid constraint.** Policy (sf:N29 12, sec:N29 10, ne:N29 4, sec:S17 3). Vendor (sec:N29 12, sf:N21 7, sf:N29 6). Budget (sf:N29 8, sec:N29 7, sf:N21 4, sf:F3 3): no enterprise scrubbing or DLP, and hardware that cannot be upgraded. Time (sf:N21 6), skill (ne:N21 6), SLA (sec:N21 3): blocking must not turn away customers, and the upstream ISP or datacenter may cut service if the noise continues (sec:N21 depth check). Underneath, asking, educating or policing the other party has already failed or can't scale (sf:N29 depth check). **How OROS neutralises it:** CON-4 and CON-7 move enforcement onto components the operator controls, so nobody's goodwill is needed. CON-2, CON-3 and CON-6 bound the collateral damage, so the containment does not become the outage.

**Evidence**
- https://networkengineering.stackexchange.com/q/87107 "I just want to drop or discard the excess broadcast/multicast traffic."
- https://security.stackexchange.com/q/262096 "I'm afraid of false positives - i.e. legitimate users getting denied access."
- https://serverfault.com/q/611884 "users can't be educated that easily, they don't want to read instructions or manuals."

**Prove it in your lab:** On a Linux-bridge VLAN, flood broadcast from one host with scapy and police it per port with tc while a second host's checks hold, and hit nginx from 50 rotating IPs plus a fixed legitimate set to record each blocking rule's false-block rate (CON-1 to CON-3). Refuse a spoofed Origin header, build an FQDN egress allowlist and change the "vendor" IP mid-test, cap a backup with cgroup v2 io.max, and run gitleaks as a pre-commit hook on a repo seeded with a secret (CON-4 to CON-7).

---

## OROS-6 Change safely: know the dependents, stage with a fallback, verify it took, push fleet-wide

**They say:** What should we watch for before this change; is the old SNMP community still used; staging doesn't have SSL like production; do I have to log into every device; the scan still flags the host after yum update; the GPO setting comes back, then disappears again.
**They need:** Know what silently depends on a setting, stage with a fallback, verify the change is in effect, state the lab's gaps honestly, push from one channel, and know which actor set each value.

**Posts:** 246 (NE 76, Security 18, Server Fault 152). Codes: ne:N26 32, ne:N23 31, ne:N24 13; sec:N23 10, sec:N24 8; sf:N26 74, sf:N24 23, sf:F7 23, sf:N23 22, sf:F10 5, sf:F23 5.

**Requirements**
1. **CHG-1 Dependents found from observed use.** Every production change record lists the dependents checked and how: collector, AAA or firewall logs showing who still uses the old community, credential, TLS version or rule; accounts still authenticating; sessions still open; linked config objects the platform will not update. A removal or tightening with an empty list does not pass review. *Pass:* a lab change that removes an SNMP community while a poller still uses it is blocked. (ne:N23, sec:N23, sf:N23)
2. **CHG-2 Staged with a fallback.** Changes and patches go to a canary or test ring first, then to production after a vetting delay and inside set windows, with a defined fallback. Reboots happen only inside the window. *Pass:* a failing canary health check triggers rollback and blocks the rest of the rollout. (ne:N23, sf:F7, sf:N26)
3. **CHG-3 Verified in effect.** After a change, verification uses non-disruptive evidence from the live system (class counters, CPU and memory, health checks). A patch counts as done only when it is in effect, for example when the host has rebooted into the new kernel. *Pass:* a kernel patch installed without a reboot is reported as `not in effect`, and a QoS change is confirmed from class counters without saturating the link. (ne:N24, sf:F7)
4. **CHG-4 Honest lab parity.** The test environment has a written parity statement listing where it differs from production (platform and OS features, L2 and STP behaviour, SSL setup, patch levels, load and impairment), and each change notes which risks the lab could not cover. Where no test environment exists, the record says so and names what limits the risk instead (one change at a time, snapshot and rollback). *Pass:* no change record leaves the parity field empty. (ne:N24, sec:N24, sf:N24)
5. **CHG-5 One channel, every box.** Repeated config changes and state reads reach every device or host from one central channel the team already runs (SSH, NETCONF, Ansible, GPO, ipmitool). The channel handles per-model quirks and reports success or failure per device, so no box needs a hands-on login. A new device comes up configured from the central channel with no hands-on login (ne:N26 evidence). *Pass:* one command changes every node in a lab fleet with at least two different NOS images or models, one forced failure is named, and a new lab node boots into its intended config with no hands-on login. (ne:N26, sf:N26)
6. **CHG-6 Effective state and its actor.** For a managed setting, tooling reports the effective value (not just the configured one), which actor set or enforces it (a person, the CM tool, GPO, an RMM or patch agent) and why. *Pass:* when a second agent overwrites a lab setting, the report shows the effective value and names that agent. (sf:F10)
7. **CHG-7 Local changes carried forward.** Local patches and modifications to upstream or vendor software are kept as a tracked change set that a build re-applies on each upstream release. *Pass:* a new upstream release is built with the local change set applied and no manual step. (sf:F23)

**Unsaid constraint.** Skill (sf:N26 11, ne:N26 7, ne:N23 5, sf:N23 3): the setup was inherited, copied or never documented, so there is no dependency inventory (sf:N23 depth check). Time (sf:N26 9, sf:N23 4). SLA (ne:N23 6, sf:F7 3): live subscribers, remote sites with no technician on site. Policy (sf:F7 4, ne:N26 3, sec:N23 2): an outside mandate such as a PCI scan or audit finding forces the change (sec:N23 depth check). Politics (sf:N23 4). Vendor (sf:N26 6, ne:N26 5, sf:F23 3): each model has its own quirks. Budget (N24: ne 2, sec 2, sf 3): no lab that matches production. **How OROS neutralises it:** CHG-1 finds dependents from observed use rather than from documentation nobody wrote. CHG-4 makes the lab gap explicit instead of pretending it away. CHG-2 and CHG-3 let a mandated change go out without betting the SLA on it.

**Evidence**
- https://networkengineering.stackexchange.com/q/24359 "Is there a way to monitor that the old community is not used anymore?"
- https://serverfault.com/q/495241 "Our staging environment doesn't have SSL set up the same way as production so I'm unable to test this"
- https://serverfault.com/q/1081061 "I did yum update --security command but the problem is still there after another scan from security team."

**Prove it in your lab:** Extend this lab with a precheck that lists pollers still using the old SNMP community and refuses to proceed, and a Nornir or Ansible rollout that changes one FRR canary, gates on BGP state and rolls back automatically (CHG-1, CHG-2, CHG-5). Commit a LAB_PARITY.md, a running-versus-installed kernel check, a report of a setting's effective value and the actor that set it (git author or AAA record), and one local FRR patch re-applied in CI against a new upstream release (CHG-3, CHG-4, CHG-6, CHG-7).

---

## OROS-7 Recover: restores proven before they are needed, failover that adds no outages, incidents closed defensibly

**They say:** The status says the backup succeeded, but no backup happens; it was never restored in almost 5 years; the switch lost its config when it lost power; I need one table back now; route traffic to the live server if one goes down; Pacemaker without fencing; we were hacked and there is no IR team.
**They need:** Know before the loss that restore and failover will work, close the entry vector before restoring, and have written steps a non-specialist can follow.

**Posts:** 322 (NE 20, Security 49, Server Fault 253). Codes: ne:N9 20; sec:S8 36, sec:N10 13; sf:N9 107, sf:N22 90, sf:F4 29, sf:F17 14, sf:N10 8, sf:F18 5. Pass 1 adds about 4 unchecked "Running ≠ startup" and "did backups run?" posts (N9).

**Requirements**
1. **REC-1 Backups that cannot lie.** Every backup job checks its own output at the destination (target mounted, file counts or checksums against the source, nothing silently skipped) and alerts on failure or absence, whatever the job's own exit status says. *Pass:* an unmounted target makes the job report failure instead of quietly writing to local disk. (sf:N9)
2. **REC-2 Saved state matches running.** Every device's configuration is captured off-box automatically. Devices that resist scripting (odd banners, menu-only or web-only interfaces, multi-context firewalls) are listed, each with its own method. Each device's saved or startup config, and the captured off-box copy, are compared with its running config, so a reported backup success or a tool's normalisation cannot silently lose config (ne:N9 depth). *Pass:* an unsaved change on a lab router is flagged within one collection cycle [default: 24 hours], and a captured copy that is missing part of the running config is flagged. (ne:N9)
3. **REC-3 Restore drills, including one item.** Restores run on a schedule into a separate environment. The drills include a single-item restore (one table, mailbox or file) that needs no whole-store restore and does not touch the live system. *Pass:* the last successful drill is within the stated period [default: 90 days], and the one-table restore meets its stated time [default: 1 hour]. (sf:N9, sf:F4)
4. **REC-4 Failover drilled, failure modes owned.** Each failover mechanism is exercised on a schedule by failing the primary. The drill passes when clients reach the surviving server with no hidden breakage after the switch (ARP reverting, the resolver not failing over). The design record lists the mechanism's own failure modes (split-brain, missing fencing, hand configuration) and the mitigation chosen, including deliberate manual steps where automation would add risk. *Pass:* the latest drill passed, every listed failure mode has a mitigation, and the split-brain alert has been test-fired. (sf:N22)
5. **REC-5 Compromise closure.** After a confirmed compromise the runbook requires five things. First, the entry vector is found and closed before restore. Second, a recorded decision on cleaning in place versus rebuilding from a known-good source. Third, checks for what was changed or taken and whether it spread to other systems. Fourth, the impact on customers is judged and the decision on whom to notify (legal, police, people affected) is recorded. Fifth, an account of what happened that clients and the hosting provider accept. *Pass:* a lab tabletop with planted persistence completes every step with evidence. (sec:S8, sf:F17)
6. **REC-6 Runbooks someone else can run.** The top incident, DR and power-event types each have a written runbook naming who does what (so work does not overlap), who coordinates and who updates stakeholders. Each runbook has a last-reviewed date, is updated when systems change, and access to it matches who may see it (sf:N10 depth). *Pass:* someone who did not write a runbook carries it out in the lab without help, and a CI check finds no runbook missing a review date, or referencing hosts that are not in the inventory. (sec:N10, sf:N10)
7. **REC-7 Outside levers listed.** For outside threats (a DDoS threat, a lookalike domain, probing of unpublished hosts), a contact sheet names who holds each lever (registrar, host, ISP, scrubbing or CDN vendor, payment processor, police) and what evidence each one needs. On-demand mitigation sized to an occasional threat is lined up, without always-on fees. *Pass:* every entry has a contact and an evidence list, both checked this cycle. (sf:F18)

**Unsaid constraint.** Budget is the main one (sf:N9 29, sf:N22 29, sf:F4 3, sf:F18 2): no SAN, fencing, commercial load balancer, BGP or /22, and no always-on DDoS fees. SLA (sf:N22 10, sf:F17 2): client pressure and litigation if the server stays down. Vendor (sf:N9 11, sf:N22 8, sec:S8 4, ne:N9 3). Skill (sf:N9 10, sec:S8 6, sec:N10 5, sf:F4 4): little IR experience and no IR function. Policy (ne:N9 5, sec:S8 4). Politics (sf:F4 3, sec:N10 2, sf:N10 2): gaps left by an outsourced provider, a predecessor or an intern (sf:F4 depth check), and "Don't tell my boss" (quote from an sf:N9 post, which is not politics-coded). **How OROS neutralises it:** REC-1 to REC-3 surface silent failures on a schedule, before a loss forces the conversation with the boss. REC-4 accepts manual steps where automation would cost more than the budget allows. REC-6 and REC-7 let non-specialists act without an IR team.

**Evidence**
- https://serverfault.com/q/14371 "the backup never actually got restored for almost 5 years. Don't tell my boss about that!"
- https://serverfault.com/q/218724 "in my experience Pacemaker lowers availability without fencing"
- https://security.stackexchange.com/q/121320 "There is no incident response team or dedicated security analysis team in place."

**Prove it in your lab:** Back up FRR configs with Oxidized and data with restic, restore nightly into a scratch container that diffs against the source, unmount the target to prove the job fails loudly, add a startup-versus-running check (this lab's drift check once missed a hand change saved with `write memory`), and time a one-table Postgres restore (REC-1 to REC-3). Drill a keepalived pair with an alert when both nodes claim MASTER, and run a tabletop on a host with planted cron persistence where someone who did not write the runbook follows it and the contact sheet (REC-4 to REC-7).

---

## OROS-8 Account for access: every privileged action tied to a person, every credential revocable

**They say:** Is there a way to log all commands to syslog; notify me when someone else logs into the switches; my auditor wants the hostname and address captured; once a team member has the key there is no way to revoke it; we create accounts by hand on each server; we can't do our job without admin; a daemon needs to SSH to another machine; I want SSH without a trip to site.
**They need:** Every privileged action tied to a person in a record the admin cannot erase, credentials that can be revoked per person, secrets that automation can use without plaintext, rights scoped to the task, and a management plane that is closed but recoverable.

**Posts:** 190 (NE 23, Security 93, Server Fault 74). Codes: ne:N27 18, ne:N28 5; sec:N27 25, sec:S12 24, sec:S10 19, sec:N28 14, sec:S13 11; sf:N27 36, sf:N28 15, sf:F15 10, sf:F16 7, sf:F14 6.

**Requirements**
1. **ACC-1 Per-person, tamper-resistant trail.** Every privileged login and command (exec and config mode, including through sudo -i, shared application or DBA accounts and shared root keys) is tied to a named person and shipped to a store the acting admin cannot read, alter or erase. *Pass:* after root on a lab host deletes the local record, the central copy is intact and names the real user. (ne:N28, sec:N28, sf:N28, sf:F14)
2. **ACC-2 Unexpected-admin alert.** A successful or failed login by anyone outside the expected admin set raises an alert. *Pass:* a login with an unlisted account raises the alert. (ne:N28)
3. **ACC-3 Per-holder credentials, revocable.** Every privileged secret (SSH key, admin password, API secret, certificate) belongs to one person or system. It can be revoked per person, rotated en masse after a compromise, and is issued and renewed automatically where the platform allows. *Pass:* a revoked person is refused by every host within the stated time [default: 15 minutes]. (sec:N27, sf:N27)
4. **ACC-4 No plaintext secrets for automation.** Unattended jobs get their secrets without plaintext in files, logs, environment variables or process arguments, and a scheduled scan of repositories and logs finds none. *Pass:* a grep of env, argv and logs during a lab job run finds no secret, and the repository scan is clean. (sf:N27, sec:S10)
5. **ACC-5 Directory-driven lifecycle.** Accounts are created from and removed through the central directory across servers and apps, including apps without native directory integration. Leftover default or shared credentials are found and retired. After a departed or hostile admin, accounts, credentials and remote-access paths are checked against a trusted baseline (sf:F14 evidence). *Pass:* disabling a leaver in the directory leaves no lab system that still accepts them, and after a lab admin leaves, a baseline check lists every account, key and remote-access path with none unaccounted for. (sf:F16, sf:F14)
6. **ACC-6 Scoped delegation and sanctioned exceptions.** Delegated and service-account rights are no wider than the task (read-all/write-none for backups, own database only, one region). Where a blanket control blocks legitimate work, there is a pre-agreed scoped alternative (a developer admin group, a VM, a masked copy, an approved card vault) instead of a workaround. Broad-access admins are kept out of business data their task does not need (mailboxes, other users' tmux or screen sessions), and agreed sensitive actions need a second person (four-eyes) (sf:F14 evidence). *Pass:* the delegated lab account completes its task and is refused one action outside it, and a lab admin account is refused when it tries to attach to another user's tmux session. (sf:F15, sec:S13, sf:F14)
7. **ACC-7 Management plane closed but recoverable.** Management services (SSH, SNMP, BMC/IPMI, web) accept connections only from management sources (SNMPv3, ACLs, a management VRF). A tested fallback path (console, bastion) regains admin access without a site visit or a disruptive reload. *Pass:* a scan from the WAN side shows every management port closed, and the fallback works with the primary path cut. (ne:N27, sf:N27)
8. **ACC-8 Usable authentication rules.** Password, recovery, session and MFA rules fit the real user base (users without email) and the failures actually seen (password guessing, constant reset requests). The number of admin accounts is known and cut to need. Personal or unmanaged devices are kept off corporate access (sec:S12 evidence). *Pass:* a recovery drill works for a user with no email address, admin-group membership matches the approved list, and an unmanaged lab device is refused VPN access. (sec:S12)

**Unsaid constraint.** Policy (sf:N28 5, sf:N27 5, sec:N28 4, sec:S12 4, ne:N27 3, sec:S13 3, sf:F14 2, sf:F15 2): company policy and audit findings drive this. Politics (sec:S13 5, sec:N28 4, sec:N27 3, sf:F14 2): distrust of whoever holds root, and contractors or vendors who must be given access. Budget (sec:S10 4, sf:N27 3, sf:F16 2): it has to be built on little budget with few staff (sec:N28 depth check) and cost less than enterprise DLP (sec:S10). Rights (sec:S10 3, sf:F16 2): the LDAP or HR leaver feed belongs to another department (sf:F16 depth check). Opsec (ne:N27 3, sec:S10 2). **How OROS neutralises it:** ACC-1 puts the record out of the admin's reach, so trust in one person stops being the control. ACC-3 and ACC-5 make a leaver's exit a technical event that does not wait on HR. ACC-6 gives people a sanctioned path, so they stop working around the lockdown.

**Evidence**
- https://serverfault.com/q/470755 "Is there a way to log ALL commands within syslog"
- https://security.stackexchange.com/q/87480 "there is no way to revoke access; a single leak compromises security of all systems"
- https://networkengineering.stackexchange.com/q/2393 "notify me when someone logs into the switches. Since I am the only one who logs into them"

**Prove it in your lab:** Run tac_plus or FreeRADIUS accounting for the lab nodes and sudo I/O logging plus auditd forwarded to an append-only store, wipe the local logs as root to show the central record still names the real user, and alert on any login outside expected_admins (ACC-1, ACC-2). Issue short-lived SSH certificates from an OpenSSH CA with a timed revocation drill, give a backup job a vault-fetched secret with a grep test, disable an LDAP user and confirm every host refuses them, and nmap the management VRF from a "WAN" container with a tested console fallback (ACC-3 to ACC-7).

---

## OROS-9 Account to gatekeepers: scope, disputes and control evidence the assessor accepts

**They say:** Does PCI DSS, HIPAA or FIPS apply to this flow, and which SAQ; the QSA says everything is still in scope; does SOC 2 really require password rotation; a customer wants copies of all our policies before buying; I need to verify our firewalls do stateful inspection; is there an authoritative hardening checklist, and how do I check every server against it.
**They need:** A scope and dispute position that holds up with the enforcer, one recognised artifact for outsiders, and independent, dated proof that each claimed control works.

**Posts:** 362 (NE 0, Security 347, Server Fault 15). Codes: sec:S1 180, sec:N7 81, sec:S6 27, sec:S2 26, sec:S11 18, sec:S7 15; sf:F9 15.

**Requirements**
1. **ATT-1 Scope register.** Every system or data flow touching regulated data has a recorded scope decision naming the framework clause, the scope-reducing design chosen (tokenisation, P2PE, segmentation, truncation, or holding less of the data by hashing, tokenising or outsourcing it, sec:S11), and the enforcer's acceptance or the open question. Data that must stay is encrypted without locking out legitimate users or breaking business processes (sec:S11 evidence). *Pass:* every in-scope system appears in the register with its clause, and an automated reachability test proves the segmentation that keeps out-of-scope systems out. (sec:S1, sec:S11)
2. **ATT-2 Finding dispute record.** Before disputing a scanner or audit finding, the team records a private check that its own position is correct. The dispute then cites version-exact technical evidence and the relevant section of the standard. *Pass:* every finding closed as a false positive has a self-check and evidence the assessor accepted. (sec:N7)
3. **ATT-3 One artifact first.** Outside due-diligence requests are answered first with a recognised third-party attestation (SOC 2 report, ISO 27001 certificate, AOC) or with evidence that can be shared, never with internal-classified documents. *Pass:* the request log shows which artifact answered each request, and no internal policy document left the company. (sec:S2)
4. **ATT-4 Control works as claimed.** Every control claimed to an auditor, client or stakeholder (stateful filtering, egress blocking, WAF, IDS coverage) has a scheduled, non-disruptive test that proves it works as specified, by a method the recipient accepts, with dated results. *Pass:* every claimed control's latest test is green and within its period [default: monthly]. (sec:S7)
5. **ATT-5 Scored baseline.** Every host and network device is scored automatically and regularly against a recognised benchmark (CIS, STIG, SCAP), with no false failures from default values. Results go to a central report for the boss or insurer. The controls applied to each server are chosen for its role and exposure from a trusted source that says which checklist items are required or worth it and which are theatre (sf:F9 evidence). Recording findings that do not apply as exceptions is recommended, but evidence for it is thin (one post). *Pass:* the report is within its schedule, covers every host, a host whose default value already meets the benchmark is not reported as failing, and each server's applied baseline names its role, exposure and source. (sec:S6, sf:F9)

**Unsaid constraint.** Budget (sec:S1 40, sec:S2 8, sf:F9 3): small firms with no in-house compliance staff (sec:S1 evidence check) want the cheapest variant that passes. Policy (sec:S1 28, sec:N7 15, sec:S2 5, sec:S11 3, sf:F9 3). Politics (sec:N7 32, sec:S11 5, sec:S7 3): the gatekeeper holds the decision, and several askers are partly wrong (sec:N7 depth check). Skill (sec:S1 16, sec:S6 6, sec:S7 5, sf:F9 4). Vendor (sec:N7 13): the scan vendor's tooling. Opsec (sec:S2 3): sharing internal documents may be forbidden. **How OROS neutralises it:** ATT-1 and ATT-3 answer the gate with a recorded, reusable decision or artifact instead of a new argument each time. ATT-2's self-check stops the team arguing a position that is wrong. ATT-4 and ATT-5 turn claims into dated test results, so the assessor checks evidence instead of trusting a person.

**Evidence**
- https://security.stackexchange.com/q/21338 "The QSA that works with out company is telling us that everything is still in scope"
- https://security.stackexchange.com/q/229763 "Our SOC 2 auditor seems to still require them. Does SOC 2 actually require password rotation in 2020?"
- https://serverfault.com/q/355680 "if its not being regularly tested, then its not in compliance"

**Prove it in your lab:** Run a scheduled OpenSCAP or Lynis CIS scan of the lab hosts plus config checks on the FRR nodes, published as a dated report, alongside nightly CI tests that prove each claimed control (blocked egress ports fail, unsolicited TCP ACKs through the lab firewall are dropped) (ATT-4, ATT-5). Write a dispute record with a self-check block for a Greenbone finding on a backported package, and a toy scope register showing segmentation keeping a lab "payments" segment small (ATT-1, ATT-2).

---

## OROS-10 Justify the decision: outside, citable backing for a choice someone else controls

**They say:** Tell me where I'm making mistakes before I present to the CEO; I must explain to my managers why this is a bad idea; I had an argument with a superior; everything I can find is marketing; how do I turn weeks of perfmon data into array requirements; is the cheaper option acceptable.
**They need:** Borrowed, outside authority for a decision someone else controls: a cited source, their own measured numbers, evidence not from the seller, and a written case for each accepted risk or refused spend.

**Posts:** 381 (NE 45, Security 222, Server Fault 114). Codes: ne:N30 45; sec:N30 138, sec:S5 27, sec:S15 25, sec:S4 19, sec:S16 13; sf:N30 67, sf:F11 30, sf:F2 17.

**Requirements**
1. **JUS-1 Decision record.** Each significant design or purchase decision has a record naming the constraint (budget, owned hardware, building or cabling), the alternatives considered, at least one outside source (a standard, vendor documentation, peer review), the concrete stake (outage, support calls, rebuild cost) and the person who decides. *Pass:* a decision-record lint finds no missing fields. (ne:N30, sec:N30, sf:N30)
2. **JUS-2 Measured sizing.** Capacity and performance requirements come from measurements of the actual workload, not generic IOPS or latency rules of thumb, and the raw data is attached. *Pass:* each sizing document links its data. (sf:F2)
3. **JUS-3 Evidence not from the seller.** Each product, provider or assessor choice is backed by at least one source independent of the seller (peer practitioner experience, a benchmark the team ran, a deliverable it can check). It is judged against the specific constraint (compliance regime, cost ceiling, the skills the team has, overlap with tools already owned) and includes a no-purchase option. That includes sizing security work to the staff and budget a small firm has: hire, retask existing staff, or buy outside help (consultant, contractor, MSSP) (sec:S16 evidence). *Pass:* every selection record has a non-vendor source and a no-purchase line. (sec:S15, sf:F11, sec:S16)
4. **JUS-4 Recorded risk acceptance.** Each accepted residual risk or refused security spend is recorded with its likelihood and impact (or cost) reasoning, and that record has been presented to management or the board. *Pass:* every accepted gap has a record management has seen. (sec:S4)
5. **JUS-5 What the control really does.** For each security control in a design, the record states what it defends against and how it fails, so it can be trusted, changed or challenged instead of kept as theatre. *Pass:* no control in the design record lacks a threat and a failure mode. (sec:S5)

**Unsaid constraint.** Politics is the main one (sec:N30 76, sf:N30 21, ne:N30 4, sec:S5 3): a named skeptic or decision-maker must be persuaded, and the asker's own word won't carry it because they are self-taught, a contractor or not a security expert (sec:N30 depth check). Budget (sf:F11 14, sf:N30 13, sec:N30 12, ne:N30 10, sf:F2 9, sec:S4 7, sec:S15 5, sec:S16 5): money is tight or one-shot, so buying the wrong thing is costly (sf:F2 depth check). Skill (ne:N30 7, sf:F11 7). Vendor (sec:N30 11). Policy (sf:N30 10, sec:S15 5, sec:S5 5). **How OROS neutralises it:** JUS-1 to JUS-3 lend the asker outside authority (a cited source, their own measurements, non-seller evidence), so the case stands without depending on their standing. JUS-4 turns each accepted risk into a reasoned record that management has seen.

**Evidence**
- https://networkengineering.stackexchange.com/q/1328 "I still need to pull together a final shopping list and present it to the ceo for budget approval."
- https://security.stackexchange.com/q/72866 "I must first be able to explain to my managers why this is a bad idea"
- https://serverfault.com/q/138256 "hearsay and 'black magic' have taken over for cold, hard fact"

**Prove it in your lab:** Keep ADRs in the repo from a template (constraint, alternatives, citations, stake, decider, threat and failure mode per control) with a CI lint, plus a sizing note built from node_exporter and iostat data committed beside it (JUS-1, JUS-2, JUS-5). Back one tool choice with a benchmark you ran yourself, for example Suricata against Zeek on the same pcap set, and record one deliberate lab shortcut as an accepted risk with its likelihood and impact reasoning, presented to someone playing management (JUS-3, JUS-4).

---

## Cross-cutting findings

1. **The constraint is written down, just not asked about.** 2,355 of the 3,785 relevant SE posts (62.2%) carry a primary unsaid constraint, and 1,611 of those (68.4%) state it outright in the body. A tool or answer that only addresses the literal question misses a limit the person already wrote. That is why every OROS family names its constraint and says how it is neutralised.
2. **Each community has a different main constraint.** Stated outright: on Network Engineering, vendor 89, skill 87, rights 39. On Server Fault, vendor 132, budget 126, skill 120, policy 106. On Security SE, politics 126, policy 116, budget 82. Across all three sites, stated or inferred: vendor 419, skill 403, budget 382, policy 321, politics 312, rights 221, time 152, SLA 104, opsec 41. On Server Fault, budget leads when inferred constraints are counted (199 vs vendor 160), while vendor leads among stated ones (132 vs 126). Network-engineer pain is vendor opacity (TAC, MIBs, bug databases), and security pain is persuading gatekeepers. A standard built from one site would miss the others' main constraint.
3. **Silent success is the common enemy, so measure where the data lands.** Examples:
   - A backup job reports "success" while nothing is backed up (ne:N9).
   - Robocopy "displays as though they copied successfully even though they don't appear on the destination" (https://serverfault.com/q/224442).
   - Devices say they send traps that never arrive (ne:N4).
   - yum reports the update while the security team's scan still flags the host (sf:F7).
   - A poster notes "it would be easy enough to configure a system to look like it is logging all of the security stuff" (https://security.stackexchange.com/q/105152).

   One principle covers NOT-3, NOT-4, CHG-3, REC-1, REC-2 and ATT-4: never take the sender's word for it.
4. **Work from the side you control.** Missing rights is a top-three constraint for ne:N6, ne:N7, N19 on all three sites, sf:N25 and ne:N31: the fault, host or control belongs to someone else. The sf:N19 depth check calls restricted tooling "a modifier, not the need". So Prove is its own job. Find and Decide requirements should work with read-only access where possible; FND-2 and parts of FND-5 need config rights.
5. **Politics attaches to proof, not to configuration.** Depth checks that passed repeatedly recoded technical needs as evidence that the owner or gatekeeper will accept: sf:N19, sf:N7, sec:N7, sec:S7 and sec:N17. Any tool that produces evidence should produce it for a third party, which is why PRV-3, ATT-2 and ATT-4 require evidence that the other side can re-run or accept.
6. **Compliance pressure reaches operators, not only GRC.** S1 (180 posts) is the largest checked code after N13. Policy is the leading constraint for sf:N29, sf:N28 and sf:N27, and tied-leading for sec:N28 (policy 4, politics 4). The sec:N23 depth check found security changes forced by an outside mandate (a PCI scan, an audit finding) while the asker fears breakage. The sec:N17 depth check found complete log feeds wanted as evidence for an assessor. Operator requirements therefore produce audit-ready evidence as a side effect (ACC-1, NOT-3, CHG-1).
7. **Developers ask the security questions.** Developers are Security SE's largest group of askers (311 of 1,112), ahead of sysadmins (281), security engineers (138) and GRC staff (102). SOC analysts are 37. Server Fault adds 172 developers. The files do not break roles down by code, so who asks Gatekeepers and Justify questions is unknown. OROS keeps those families because operators feed them evidence, but ranks them behind the shift loop.
8. **Narrowest scope beats on and off.** In sec:N2, the N21 and N29 posts, sec:S13, sec:S17, sf:F15 and sf:F3, people want to change one rule, port, right or job rather than switch a control off. The repeated failure is an action too broad to accept: disabling the rule, shutting the port, granting full admin. DEC-4, CON-2, CON-6 and ACC-6 test that the control still works everywhere else.
9. **Workarounds must not quietly drop a security property.** The sec:N13 evidence check (keep the security property they will not give up), and the sec:N25 and sf:N25 depth checks (no RC4, plaintext fallback, per-host NTLM exceptions), show the trade-off between compatibility and security limiting many of these fixes, even though people seldom name it. PRV-4 makes the trade-off explicit.
10. **SLA is the stake, not the constraint.** SLA is the primary unsaid constraint in only 104 of 3,785 posts (69 of them on Server Fault). It shows up as the reason behind other constraints: "I don't like it when my client rings me to tell me their web site doesn't work!" (https://serverfault.com/q/282215), and "can't wait another 23 hours" (https://serverfault.com/q/289368). OROS treats it as the reason for positive proof and staged change, not as a family of its own.
11. **The ask is the need (N13) is the largest single code and is excluded.** It has 576 posts: NE 104, Security 48, Server Fault 424. Even there, the checks that passed found the fix shaped by constraints: "client-side only, change only this server's config, the installed version, no reboot" (sf:N13 evidence check). The ne:N13 depth check, which failed, read the hidden question as whether the cause is my own config, normal protocol behaviour, or a vendor bug. That question is covered by FND-3 anyway.
12. **Role and venue bias.** Only 15 of 939 NE posts come from NOC roles, 37 of 1,112 Security SE posts from SOC roles, and 3 of 1,734 Server Fault posts from SOC roles. The shift-process needs from pass 1 (handover, SLA clocks, escalation, honest metrics) cannot be confirmed or refuted from Q&A sites. Q&A sites draw people who are stuck on a how-to, while process pain may go to vendor forums and mailing lists. That is an untested inference. Absence here is not evidence of absence, and the next pass needs checked samples from GitHub issues or surveys.
13. **Small-shop reality.** Many askers work on gear and budgets already in place: N20 gear has no flow export; sf:N22 shops have no SAN, fencing or BGP; S1 firms have no compliance staff; sf:F3 hardware cannot be upgraded. Most OROS requirements can be met with free or open-source tools and proven in a home lab; ATT-3's attestations and REC-7's on-demand mitigation depend on paid third parties.
14. **How this lab scores.** [scorecard.md](scorecard.md) scores this repository against all 61 requirements, with the test or file that proves each pass.

## Unproven or thin

**Both checks failed (no requirement rests on these):**
- ne:N22 failover that just works (26 posts). Automatic WAN failover and failback through health tracking, with existing sessions moving over, is not proven on NE. sf:N22 supports reliable, automatic failover without manual DNS edits (evidence check). Its depth check adds that "just works" means predictable and low-touch, sometimes deliberately manual (REC-4).
- ne:N8 trustworthy source of truth (10). Only "API-first" is unevidenced; ne:N8 failed both checks. sf:N8 (10 posts, both checks passed) supports one authoritative fleet record from which DNS, monitoring, CMDB and IPAM are derived (FND-4).
- ne:N10 shift handover and NOC operating process (4). See the handover item below.
- sf:N2 accountable silence (10).
- sf:F8 vulnerability exposure mapped to the fleet inventory (5). Triage of a single finding survives through sec:S3 (DEC-3). Mapping advisories across the whole fleet is unproven.
- sf:F5 verified data movement and decade-scale archives (5).

**Pass-1 ORAS clauses that did not survive the checked corpus:**
- Owner on every alert (ORAS 1). The ne:N1 evidence check: "The posts do not show a need for an 'owner' field". On Security SE, criticality and owner are inferred, not stated. On Server Fault, evidence for the owner is thin. Asset role or criticality survives as a smaller sub-need on NE and Server Fault (DEC-1).
- Impact named on the root-cause incident (ORAS 2). The sf:N3 checks found it only weakly (an occurrence count, one tracked ticket). Posts want dependents suppressed, not described.
- Owned, listable, explained-afterwards suppressions (ORAS 3). sf:N2 failed both checks. The sec:N2 checks found "listable" in no sampled post, and "owned" barely appears. DEC-4 keeps scoped, time-boxed where possible, and justifiable.
- Ownership, SLA clock and escalation of unacknowledged alerts (ORAS 5, N5). About 9 pass-1 posts. sec:N5 (2) and sf:N5 (4) were too few to check.
- One-click timeline or evidence pack (ORAS 6). Both ne:N7 checks found no post asking for a timeline or handoff document, only for proof and localization (PRV-2, PRV-3).
- Drift alerts with diffs (ORAS 7). The ne:N9 depth check: "Detecting changes with diffs is at most implied. No poster asks for it." The saved-versus-running mismatch is supported (REC-2).
- Shift handover as structured state (ORAS 8). No N10 post on any SE site mentions shifts or handover, and the Server Fault checker adds that its whole corpus has no shift-handover posts. Only written runbooks and IR coordination survive (REC-6).
- Metrics that reward accuracy over closure speed (ORAS 9, N11). About 4 pass-1 posts. sec:N11 (3) and sf:N11 (1) were not checked.
- Machine-readable carrier maintenance notices matched to circuits (N12). 2 pass-1 posts and no SE code.
- Vendor auto-updates silently changing rules in production (a pass-1 N4 constraint). No SE code tests it.

**Thin clauses inside supported needs (kept out of requirements, or flagged where used):**
- N16 "without screen-scraping": supported only on NE. The sf:N16 and sec:N16 checkers say no post mentions scraping. NOT-2 applies the no-scraping clause to network gear only.
- N14 "which release fixes it": not supported on Security SE (sec:N14 evidence check). FND-3 requires it for NE and SF only.
- N15 on Server Fault: the high-view posts are mostly normal OS behaviour rather than collection artifacts (sf:N15 depth check failed). DEC-2 covers both.
- N17: "attributable, normalized form" is not supported on NE, and "confirmed" delivery is not asked for by any high-view SF post. NOT-3 rests on ne:N4, ne:N17 and sec:N17.
- N4 on NE: a recurring heartbeat is suggested only by a commenter (ne:N4 evidence check); ne:N17 depth supports confirmed arrival, which is what NOT-3's last-seen check rests on there.
- N6 on Server Fault: observations on both sides of each boundary (sf:N6 failed depth check). PRV-2 uses observations from the operator's own edge and controlled points instead.
- N21: the "automatically" part and per-user bandwidth fairness are weakly supported (ne:N21 evidence check).
- N26: a single vendor-neutral management interface is a minority aspiration (2 of 8, ne:N26 depth check).
- N27: certificate and secret lifecycle and fleet-wide exposure checking are not supported on NE. "Always-reachable management plane" rests on one Security SE post.
- S2: "Reuse instead of redoing every year" and signed acknowledgements.
- S4: compensating controls and an outside reference point (from the failed depth check). JUS-4 keeps the reasoning and its presentation to management.
- Management formally owns residual risk (sec:S4 and sec:S16 failed depth checks).
- S6: a versioned baseline with recorded exceptions (one post). ATT-5 marks it as recommended.
- S7: "prioritized findings" and "response plan actually works".
- S8: live containment, evidence preservation and vendor breaches rest on canonical or hypothetical posts. Proportionate credential rotation and the "are we clean?" answer come from the failed depth check.
- S10: "departing staff" and "directory reads".
- S13: "risk owned by whoever demands them" (one low-view post).
- S14: compliance metrics and protection for high-value targets (one post each). The failed depth check also disputes the incentives clause (one post), but the passed evidence check keeps it, so CON-7 uses it.
- S17: a TLS-certificate allow anchor (from the failed depth check). CON-5 keeps name-based rules and relays.
- F2: failure blast radius (1 of 8 sampled posts).
- F3: load-balancer draining and an over-capacity page (one post each).
- F7: "Clears on rescan" rests mainly on one post. CHG-3 uses the running-kernel test, and a rescan is supporting evidence only.
- F10: detecting out-of-band changes against a CM baseline (one post about a tool not yet deployed; evidence check failed). CHG-6 keeps the effective value and its actor.
- F14: M-of-N control (one post).
- F16: second-factor login.
- F18: impersonation takedown and attack-surface discovery (one post each); the DDoS clause is the best supported.
- F19: customers' allowlists surviving our own IP changes (one tentative post).
- F23: fully unattended image builds.
- sec:N10: "who gets called, what gets captured" comes from the failed depth check. REC-6 keeps who does what, coordination and stakeholder updates.

**Too few posts to check (not run):**
- Server Fault: F21 alerts that actually reach a person (3), F22 service status for users and management (3), F26 make a silent component show its real error (2), F24 take over inherited systems (4), F27 team upskilling (3), F20 air-gapped segments (3), F13 central web and email content control (3), F12 licensing and vendor support (2), N5 (4), N11 (1).
- Security SE: N9 (4), N8 (3), N6 (3), N11 (3), N5 (2), N4 (2), N26 (2), N22 (1), N18 (1), N32 (1).

**Supported but outside the operator loop (not mapped; candidates for 0.4):** sf:F6 refreshing non-production from production data (7), sf:F25 physical facility (5). sec:S11 data minimisation by design (18) and sec:S16 sizing the security function (13) are now mapped to Gatekeepers (ATT-1) and Justify (JUS-3).

**Pass 1 as a whole:** no verification checks were run, its counts are approximate, and its sample leans toward mailing lists and vendor forums. Its specific anecdotes (a log source silent for about 2 weeks, the Zabbix ZBXNEXT-8339 and Icinga rights and skill statements, the LibreNMS user scraping the web UI) have no links in these files and cannot be cited here.

## Checklist

| ID | Requirement | Families |
|---|---|---|
| NOT-1 | Each logical object (BGP, tunnel, AP, RAID, page content) has its own check, not ping; overdue patches and reboots alert | Notice |
| NOT-2 | Decision values reach the tool already run; no unlisted scrapers on network gear; per-version gap list | Notice |
| NOT-3 | Per-source last-seen check plus synthetic end-to-end test event; dead source restored without reboot | Notice; Recover |
| NOT-4 | Dead-man's switch on jobs, feeds and the alert path | Notice; Recover |
| NOT-5 | Noise cut at source by name, wanted messages pass, ingest within licence | Notice |
| NOT-6 | Detection coverage table: sources, placement, blind spots, false-positive load | Notice; Gatekeepers |
| NOT-7 | Every source, including unchangeable apps and hosts without root, reaches one central searchable store; history outlasts on-box rotation | Notice; Find |
| DEC-1 | Alert carries why it fired, baseline and recent changes; scoped by asset role where known | Decide |
| DEC-2 | Each metric documents what it counts; artifacts flagged, not graphed as spikes | Decide |
| DEC-3 | Findings judged by exact build, exposure, exploitability; interim mitigation | Decide; Gatekeepers |
| DEC-4 | Suppression scoped, time-boxed where possible, reason that survives audit | Decide; Gatekeepers |
| DEC-5 | One page per cause; independent failures still page | Decide |
| FND-1 | Queue and burst drops visible; ICMP rate-limit told from real loss | Find |
| FND-2 | Logs off-box continuously; capture armed for the next occurrence | Find; Prove |
| FND-3 | Version-exact verdict per odd behaviour; fix release recorded (NE, SF) | Find; Change safely |
| FND-4 | IP/MAC to port and VLAN; one fleet record feeds DNS, monitoring and IPAM; reconciled against live state | Find |
| FND-5 | Activity tied to one host, account or tenant from existing logs; billing-grade usage and link trends | Find; Contain; Access |
| FND-6 | Each layer measured against a reference; verdict: setting or hard limit | Find; Justify |
| PRV-1 | Packet capture where SPAN can't reach, with the access you have | Prove |
| PRV-2 | Observations from own edge and controlled points; own segment cleared first; segment and owner named | Prove |
| PRV-3 | Escalation bundle the other side can re-run | Prove; Gatekeepers; Justify |
| PRV-4 | Interop fault side named; own-side workaround keeps security | Prove |
| CON-1 | Trace the source through NAT, LB or shared servers before blocking | Contain; Find |
| CON-2 | Rate-limit only the excess, reversibly; no shared-port shutdown | Contain |
| CON-3 | False-block rate measured before blocking rotating abusers | Contain |
| CON-4 | Enforce on components you control, not forgeable identifiers | Contain; Access |
| CON-5 | Default-deny egress allows by name or own relay, not moving IPs | Contain |
| CON-6 | Bulk jobs throttled from outside; production stays responsive | Contain; Recover |
| CON-7 | Secure behaviour enforced or automated, not just written; data egress controlled; phishing tests users accept as fair | Contain; Access |
| CHG-1 | Dependents found from observed use before removal or tightening | Change safely |
| CHG-2 | Canary or test ring first, fallback defined, reboots in window | Change safely |
| CHG-3 | Change verified in effect from the live system | Change safely; Gatekeepers |
| CHG-4 | Written lab-to-production gap on every change | Change safely |
| CHG-5 | One central channel reaches every box, per-device results; new devices provisioned with no hands-on login | Change safely |
| CHG-6 | Effective value and the actor that set it are reported | Change safely; Recover |
| CHG-7 | Local patches re-applied automatically on each upstream release | Change safely |
| REC-1 | Backup success judged at the destination; failure is loud | Recover; Notice |
| REC-2 | Configs off-box; awkward devices listed; startup and captured copy compared with running | Recover; Change safely |
| REC-3 | Scheduled restore drills, including a single-item restore | Recover |
| REC-4 | Failover drilled; its own failure modes listed and mitigated | Recover |
| REC-5 | Entry vector closed before restore; clean-or-rebuild recorded | Recover |
| REC-6 | Runbooks with review date and matched access that a non-author can run | Recover |
| REC-7 | Contact sheet of outside levers and the evidence each needs | Recover |
| ACC-1 | Privileged actions tied to a person, stored out of the admin's reach | Access; Gatekeepers |
| ACC-2 | Alert on logins outside the expected admin set | Access; Notice |
| ACC-3 | Credentials per holder, revocable and rotatable | Access |
| ACC-4 | Automation secrets with no plaintext; scans find none | Access |
| ACC-5 | Accounts created and removed from the directory everywhere; trusted baseline checked after an admin leaves | Access |
| ACC-6 | Rights scoped to the task; sanctioned exceptions replace workarounds; admins kept out of data | Access |
| ACC-7 | Management plane closed to the WAN, with a tested fallback path | Access |
| ACC-8 | Auth rules fit real users; admin count known and cut; unmanaged devices kept off | Access |
| ATT-1 | Scope register with clause and scope-reducing design, including holding less data | Gatekeepers |
| ATT-2 | Self-check recorded before disputing a finding | Gatekeepers |
| ATT-3 | Outside requests answered with one recognised artifact | Gatekeepers |
| ATT-4 | Each claimed control has a scheduled, dated test | Gatekeepers; Prove |
| ATT-5 | Controls chosen for role and exposure; fleet scored against a recognised benchmark on schedule | Gatekeepers |
| JUS-1 | Decision record: constraint, alternatives, outside source, stake, decider | Justify |
| JUS-2 | Sizing from measured workload with raw data attached | Justify |
| JUS-3 | Non-seller evidence and a no-purchase option for every choice | Justify |
| JUS-4 | Accepted risk or refused spend recorded with reasoning and shown to management | Justify; Gatekeepers |
| JUS-5 | Each control's threat and failure mode recorded | Justify |
