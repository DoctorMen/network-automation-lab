---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead updates the service desk; the carrier ticket goes out only with the finding bundle from make finding (results/finding/)
last_reviewed: 2026-10-15
hosts: [h1, r1, r2, isp]
written_by: Claude (AI assistant)
---
# Runbook: loss toward the internet, ours or the carrier's?

Users report loss to something outside. The network team is the first suspect and the carrier's own
test usually says "clean". So clear our own segments first, then hand the carrier a finding they can
re-run, using only devices we own. We can't log into the carrier's router and don't need to.
(OROS 0.3 PRV-2.)

## Who does what

- **Responder** (on-call network engineer): steps 1 to 4, from devices we own only, then `make finding`
  for the bundle the carrier gets (below).
- **Coordinator** (NOC shift lead): reads the verdict, and opens the carrier ticket with that bundle or
  keeps it ours.
- **Comms** (NOC shift lead): tells the service desk whose fault it looks like, and when that is confirmed.

## Steps

1. **Wait for routing to settle.** Every core router `Full` in `show ip ospf neighbor`, r2's BGP
   session `Established` in `show bgp summary`. Loss measured during a reconvergence is our own.
2. **Run it from a host behind the complaint:** `make locate SRC=h1 DST=203.0.113.1`. It
   - finds the hops with `traceroute -I -n -q 1 -w 1` from SRC (ICMP: fw1 drops UDP traceroute), and
     traces again (up to 5 times) while a hop before the destination shows `*`: the loss we're chasing
     also eats traceroute probes, and skipping a silent r2 would fold r1-r2 into the carrier's segment,
   - pings every hop at once from SRC, 200 echo requests 20 ms apart, so the whole run takes about 4 s,
   - pings everything past our edge (r2) from r2 itself, which takes every campus link out of that measurement,
   - clears our segments in path order: a segment is clean if its far end loses 2% or less (4 of 200),
   - names the first segment where loss starts and carries on to the destination, with its owner from
     `inventory/network.yml`,
   - writes `build/finding.json` and prints a summary.

   It only ever runs commands on devices whose `owner:` is the inventory's `operator:`. Asking it to
   run from the carrier's router fails before anything is sent.
3. **Read the verdict.**
   - Loss starts on one of our segments: it's ours. Fix it, don't open a carrier ticket.
   - Loss starts on `r2-isp` and r2's own view of the far side shows it too: it's the carrier's.
     Check our edge port before calling, because they will ask:
     `docker exec clab-<lab>-r2 ip -s link show eth3`. TX errors and dropped at 0 means our port sent
     everything.
   - Nothing above 2%: no loss on this path right now. Run it again while users see the problem.
4. **Run it twice, a few minutes apart.** One run is a sample. Two that agree is a pattern.

Why 2% at 200 probes: a healthy link with 0.5% background loss crosses it 0.4% of the time, and a
20% fault (40 +/- 6 replies lost) never falls under it. A 5% fault slips under it 3% of the time, so
for small loss send more probes (`PROBES` in `netlab/locate.py`) rather than lowering the threshold.

## The ICMP rate-limit trap

A router answering a ping to itself is its control plane doing you a favour. Hardware routers
police or deprioritise those replies (control-plane policing), and a busy one drops them. Linux
rate-limits the time-exceeded replies traceroute relies on (`net.ipv4.icmp_ratelimit`), which is
why a `*` in a traceroute means nothing on its own. So a middle hop can show 20% loss while every hop after it shows 0%. Traffic *through* that
router is fine; only its replies to you are lost.

**Loss counts only if it starts at a hop and carries on to the destination.** locate marks a middle
hop like that "not loss" and never names it. Lab run with 20% of ICMP dropped on r2's INPUT chain
only (pings to r2 lost, pings through r2 untouched):

```
  r1-r2      campus NOC              20.0%  not loss: later hops are clean, so this hop only rate-limits pings to itself
  r2-isp     AS65100 carrier NOC      0.0%  clean
No loss to 203.0.113.1 above 2%.
```

Sending a carrier a screenshot of loss on one of their middle hops is the quickest way to lose the
argument. Pings also measure the round trip: if the reply comes back a different way, the loss can
be on the return path. In this lab the return path is the same one.

## What to send the carrier

`make finding SRC=h1 DST=203.0.113.1` runs the same measurement and writes all of it to
`results/finding/`, checked before it says it is complete ([decision 0017](../decisions/0017-finding-bundle.md)).
Send that folder. FINDING.md is the one page to read first; `sh reproduce.sh` in any copy of the folder
re-runs the measurement with nothing but sh and docker and says `Reproduced` or `Did not reproduce`.
It holds:

- `build/finding.json`'s figures, plus every command's raw output (raw/), the method (METHOD.md),
  versions (versions.txt) and clocks (time.txt), and RFC 792, RFC 6673 and RFC 1812 for what backs it.
  They can run the same pings from their side and compare.
- The edge view: loss from our own edge router to their side, with no campus link in between, and a
  capture of ICMP on our hand-off port (pcap/) while r2 pings past it: every echo request leaves, and
  the replies that are missing went missing beyond our port.
- Our edge port counters (`ip -s link show eth3` on r2): zero errors, zero drops.
- The circuit ID, both ends of the hand-off (198.51.100.0 ours, 198.51.100.1 theirs), and when it started.
- The ask: test from their side of the hand-off toward 198.51.100.0, 200 pings at 20 ms.

## In the lab

The "carrier fault" is iptables on isp dropping 20% of ICMP arriving on eth1, in INPUT (to isp) and
FORWARD (through isp), so it behaves like a lossy link. ICMP only, so BGP, OSPF and BFD stay up. The
campus fault is the same rule on r2 eth1, the r1-r2 link. INPUT alone there would only hit pings to r2
and look like the rate-limit trap above. See `tests/live/test_locate.py`.
