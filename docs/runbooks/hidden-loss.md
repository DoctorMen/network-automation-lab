---
owner: campus NOC
coordinator: NOC shift lead
comms: NOC shift lead tells the service desk whether the loss is a queue of ours, a rate-limited ping, or real loss on the path, and who fixes it
last_reviewed: 2026-10-16
hosts: [h1, h2, r1, r2, r3, isp]
written_by: AI assistant
---
# Runbook: loss that the graphs, ping and interface counters don't show

Users report slow pages, stalls or retransmits, and every graph looks idle. Two things hide loss
from the usual checks: a queue that overflows for a few milliseconds (no average, ping or interface
counter shows it), and a router that drops pings to itself while it forwards everything (mtr and
ping show loss that isn't there). This runbook tells them apart. (OROS 0.3 FND-1; decision
[0023](../decisions/0023-queue-drops.md).) `<lab>` below is the `name:` in `build/topology.clab.yml`.

## Who does what

- **Responder** (on-call network engineer): steps 1 to 5.
- **Coordinator** (NOC shift lead): decides whether a queue's drops need a change (a bigger queue, a
  class with more rate, or the sender paced) or are accepted, and who makes it.
- **Comms** (NOC shift lead): tells the service desk which of the three it is, and when it is fixed.

## Steps

1. **Is a queue dropping?** `make alerts`. A `QueueDrops` alert names the node, the interface and the
   queue's kind (`htb` on h2's port). It fires on any drop in the last minute, however short the burst,
   because it reads the queue's drop counter, which counts every packet the queue refused. Its value is
   Prometheus' estimate (increase() extrapolates); the exact count is the box's own.
2. **Which class?** On the node it names: `docker exec clab-<lab>-h2 tc -s class show dev eth1`. Each
   class has its own `dropped` count. On h2, class `1:20` is bulk (everything but web replies) and
   `1:10` is web (source port 80). Drops in bulk while web shows none is the shaping doing its job: a
   burst bigger than bulk's queue of 1000 packets. Drops in web is a real problem for users.
3. **Rule out the interface itself.** `docker exec clab-<lab>-h2 ip -s link show dev eth1`. TX `dropped`
   counts the driver's drops after the queue. 0 here and drops in the class is the queue, not the port
   ([V-025](../verdicts.yml)). On a router, whose ports have no queue (`qdisc noqueue`), the same
   command is where any drop would show.
4. **Why the averages miss it.** A 5-minute average of a burst under a second is nothing. The
   microburst test holds the port's 5-minute average under 5% of its 20 Mbit while h2's queue drops part
   of a burst of 3000 datagrams (1887 of them in one run here, [V-026](../verdicts.yml)). Don't
   use the traffic graph to close this; use the counters in steps 1 and 2.
5. **Loss in ping or mtr at one hop only?** `make locate SRC=h1 DST=203.0.113.1`. A hop with loss
   whose later hops are clean is marked `not loss: later hops are clean, so this hop only rate-limits
   pings to itself`: the router polices pings to its own address, and traffic through it is fine. Loss
   that starts at a hop and carries on to the destination is real, and locate names that segment and
   its owner. Then follow [carrier-loss.md](carrier-loss.md) if it is the carrier's.

## Done when

The coordinator knows which of the three it is: our queue (and in which class), a ping rate limit
(no action), or loss on the path (locate's segment and owner).

## Drill it in the lab

Helper, for a queue: run from the repo root
`docker exec clab-<lab>-h2 python3 -c "$(cat tests/live/tools/burst.py)" send 10.20.20.1 9399 3000 200 16`.
QueueDrops for h2 eth1 pages within its bound, 21 s (expected_state.json monitoring.alert_within). For a rate limit: on r1,
`docker exec clab-<lab>-r1 iptables -I INPUT -i eth3 -p icmp --icmp-type echo-request -j DROP` and
`docker exec clab-<lab>-r1 iptables -I INPUT -i eth3 -p icmp --icmp-type echo-request -m limit --limit 10/second -j ACCEPT`;
the same two lines with `-D` take it away. The tests do both: `tests/live/observe/test_loss.py` and
`tests/live/test_locate.py`.
