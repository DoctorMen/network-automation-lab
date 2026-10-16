---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead tells the service desk and h2's service owner that h2 is dark to the internet while the blackhole is on, and again when it is lifted
last_reviewed: 2026-10-15
hosts: [r2, isp]
written_by: Claude (AI assistant)
---
# Runbook: DDoS on a published host, blackhole it at the ISP

A flood aimed at a published host (today only h2:80, decision 0012) fills the ISP link, and then
everything behind r2 suffers, not just the target. Nothing on our side can help once the link is
full: the packets have already crossed it. The lever is at the ISP. A remote-triggered blackhole
(RTBH) tells it to drop traffic to the one attacked address inside its own network. The host goes
dark to the internet, which is the price; the link, every other host and the campus's own access to
the target stay up. No contract, no always-on fee. (OROS REC-7; the contact sheet is
[docs/outside-levers.yml](../outside-levers.yml).)

## Who does what

- **Responder** (on-call network engineer): steps 1 to 3 and 5, on r2 only. Nobody else changes r2
  while the blackhole is on.
- **Coordinator** (NOC shift lead): decides to pull the lever, because it takes the host off the
  internet, and decides when to lift it.
- **Comms** (NOC shift lead): step 4 to the ISP NOC, and the service desk and the host's service owner
  when it goes on and when it comes off.

## How it is wired

- r2 sends any static route tagged `666` to the ISP with community `65100:666`, past the
  `summary-only` aggregate (`unsuppress-map`). Nothing carries the tag until an operator adds one.
- The ISP accepts a `/32` inside our `10.0.0.0/8` with that community, points it at `192.0.2.1`, which
  it routes to Null0, and marks it `no-export` so it goes no further (RFC 7999).
- The trigger's next hop is the host's real gateway, not Null0, so r2 keeps forwarding to the host.
  The exact line for each published host is generated into `build/expected_state.json` (`rtbh.triggers`).
- All of it comes from the `rtbh:` block in `inventory/network.yml`.

## Steps

1. **Confirm it is a flood on one address.** On r2, `ip -s link show eth3` twice, a minute apart: RX
   bytes and packets jumping. Note the time in UTC and the target address.
2. **Pull the lever** (one line, for h2):

   ```
   docker exec clab-<lab>-r2 vtysh -c 'conf t' -c 'ip route 10.20.20.10/32 10.20.20.1 tag 666'
   ```

3. **Check the ISP took it.** From our side: `show bgp ipv4 unicast 10.20.20.10/32` on r2 lists the
   ISP under "Advertised to". In the lab you can also look at the ISP: `ip route show 10.20.20.10` on
   isp prints `blackhole 10.20.20.10 proto bgp metric 20`. Expect seconds, not minutes:
   tests/live/test_rtbh.py fails every night if it takes more than 30 s (the whole test, trigger to
   lift, takes about 6 s here).
4. **Tell the ISP NOC** with the evidence the contact sheet lists, including when you will lift it.
5. **Lift it** when the attack stops: the same line with `no` in front. The ISP removes the route and
   the host is back.

   ```
   docker exec clab-<lab>-r2 vtysh -c 'conf t' -c 'no ip route 10.20.20.10/32 10.20.20.1 tag 666'
   ```

## Don't forget it

The trigger lives only in r2's running config, never in the intent. While it is on, `make drift` fails
and names the line, so a blackhole left on after the attack turns the nightly run red. A restart of
r2 also drops it, which ends the blackhole: re-add it if the attack is still running.

## Limits

- It completes the attack for that one host: the internet can't reach it while the blackhole is on.
  Keeping the host up under attack needs a scrubbing service, which this lab has no contract for.
- Only a `/32` inside what we announce is blackholed. Anything else carrying the community is
  treated as an ordinary route, so a mistyped prefix can't blackhole someone else's network, or all of ours.
- It is the ISP's service. A real ISP publishes its own community and rules; check them before the
  day you need them.
