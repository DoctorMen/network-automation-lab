"""OROS FND-1 and DEC-2 at the NOC (decisions 0023 and 0024). A microburst that the 5-minute average, the
interface's own drop counter, the web check and ping all miss is traced to h2's queue and its class. A byte
count sent on purpose matches the counters the NOC stored, within 5%, while one of the exporters restarts.
A queue counter that falls to zero is flagged by resets() and pages nobody, and one that wraps at 2^32 shows
no spike. Every metric's documented type is the one its exporter declares.

Every interface in the lab is a veth pair, so that is the only interface type the byte count covers: there is
no physical port, LAG or sub-interface to push one through."""
import json
import re
import shlex
import subprocess
import time
from pathlib import Path

import yaml

from netlab import monitoring
from netlab.inventory import load

from ..conftest import BUILD, ROOT, wait_for
from .conftest import others_firing, quiet, wait_alert

BURST = (Path(__file__).resolve().parent.parent / "tools" / "burst.py").read_text()
inv = load(ROOT / "inventory" / "network.yml")
PORT = 9399  # nothing listens on it, so only the test's own receiver counts what arrives
# Each datagram on the wire: its payload, the UDP (8) and IP (20) headers, and the Ethernet header (14) a veth counts.
HEADERS = 8 + 20 + 14
WRAP = 2 ** 32  # node_qdisc_drops_total is the kernel's gnet_stats_queue.drops, a 32-bit count


def burst_tool(container, *args, timeout=120):
    out = subprocess.run(["docker", "exec", container, "python3", "-c", BURST, *args],
                         capture_output=True, text=True, timeout=timeout, check=True)
    return json.loads(out.stdout.splitlines()[-1])


def receive(container, idle):
    """A receiver counting what reaches PORT on the node, already listening when this returns."""
    p = subprocess.Popen(["docker", "exec", container, "python3", "-c", BURST, "recv", str(PORT), str(idle)],
                         stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "listening", "the receiver did not start"
    return p


def received(p):
    try:
        return json.loads(p.communicate(timeout=120)[0].splitlines()[-1])
    finally:
        if p.poll() is None:
            p.kill()


def sample(noc, expr, after, timeout=30):
    """The value Prometheus stored for one series from a scrape later than `after` (Unix seconds)."""
    def fresh():
        stamp = noc.query(f"timestamp({expr})")
        return stamp and stamp[0]["value"] > after and noc.query(expr)
    got = wait_for(fresh, timeout=timeout, interval=1)
    assert got and len(got) == 1, f"no single fresh sample of {expr}: {got}"
    return got[0]["value"]


def facing(router, neighbor):
    """The router's interface toward a neighbor, from the inventory's links."""
    return next(local.interface for local, remote in inv.neighbors(router) if remote.device == neighbor)


def bits(rate):
    """'20mbit' -> 20000000.0, tc's units."""
    number, unit = re.fullmatch(r"([\d.]+)([kmg]?)bit", rate).groups()
    return float(number) * {"": 1, "k": 1e3, "m": 1e6, "g": 1e9}[unit]


def class_drops(host, interface):
    """{class id: packets dropped} for each HTB class on the interface, read on the host."""
    out = host.run("tc", "-s", "class", "show", "dev", interface).stdout
    return {int(m[1]): int(m[2]) for m in re.finditer(r"class htb 1:(\d+) .*?\n\s*Sent \d+ bytes \d+ pkt \(dropped (\d+),", out)}


def burst(node, server, gateway, count=3000, size=200, sockets=16):
    """`count` datagrams from the server to its gateway in a few milliseconds, as many as it can queue at
    once: (what the sender sent and how long it took, what reached the gateway)."""
    rx = receive(node(gateway).container, 2)
    sent = burst_tool(node(server).container, "send", inv.hosts[server]["gateway"], str(PORT), str(count), str(size), str(sockets))
    return sent, received(rx)


SERVER = "h2"
SHAPED = inv.qos[SERVER]
GATEWAY = inv.device_at(inv.hosts[SERVER]["gateway"])
QUEUE = f'{{node="{SERVER}",device="{SHAPED["interface"]}",kind="htb"}}'
LINK = f'{{node="{SERVER}",device="{SHAPED["interface"]}"}}'


def test_a_microburst_the_average_hides_is_traced_to_its_queue(node, mon, noc):
    """3000 datagrams from h2 to its gateway in a few milliseconds overflow the bulk class of h2's HTB. QueueDrops
    pages for h2's queue, and its drop count is exactly what was sent and never arrived; `tc -s class` names the
    bulk class. h2 eth1's byte counter counts after the queue: what arrived, not what the queue dropped. Meanwhile
    the 5-minute average of h2's traffic stays under 5% of the link, the interface's own drop counter stays at 0,
    and the web check and the ping from the NOC never fail."""
    size, web = 200, next(c["id"] for c in SHAPED["classes"] if c.get("sport") == 80)
    bulk = next(c["id"] for c in SHAPED["classes"] if c.get("default"))
    quiet(noc, "QueueDrops", node=SERVER)
    start = time.time()
    drops, link_drops = sample(noc, f"node_qdisc_drops_total{QUEUE}", start), sample(noc, f"node_network_transmit_drop_total{LINK}", start)
    out_bytes = sample(noc, f"node_network_transmit_bytes_total{LINK}", start)
    rcvbuf = sample(noc, f'node_netstat_Udp_RcvbufErrors{{node="{GATEWAY}"}}', start)
    classes = class_drops(node(SERVER), SHAPED["interface"])
    since = time.time()
    sent, got = burst(node, SERVER, GATEWAY, size=size)
    done = time.time()
    lost = sent["sent"] - got["received"]
    assert lost > 0, f"the burst lost nothing ({sent}, {got}), so there is nothing to trace"
    # A microburst: over in a fraction of one scrape interval, and offered far above the link's rate.
    assert sent["seconds"] < mon["interval"] / 5, f"the burst took {sent['seconds']} s"
    assert sent["sent"] * (size + HEADERS) * 8 / sent["seconds"] > bits(SHAPED["rate"]), "the burst was not faster than the link"
    page = wait_alert(noc, "QueueDrops", since, mon["alert_within"]["QueueDrops"] + 5, node=SERVER, device=SHAPED["interface"])
    assert page, f"no QueueDrops for {SERVER} {SHAPED['interface']} within {mon['alert_within']['QueueDrops']} s"
    assert page["received"] - done <= mon["alert_within"]["QueueDrops"], f"paged {page['received'] - done:.1f} s after the burst"
    assert page["labels"]["kind"] == "htb"
    # The queue's own count, as the NOC stored it, is exactly the loss; the receiver itself dropped nothing.
    assert sample(noc, f"node_qdisc_drops_total{QUEUE}", done) - drops == lost
    assert sample(noc, f'node_netstat_Udp_RcvbufErrors{{node="{GATEWAY}"}}', done) == rcvbuf, "the receiver dropped some itself"
    # Which class: the bulk class took all of it, and the web class none.
    after = class_drops(node(SERVER), SHAPED["interface"])
    assert after[bulk] - classes[bulk] == lost and after[web] == classes[web], f"class drops before {classes}, after {after}"
    # After the queue: h2 eth1 counted at least every frame that arrived, and less than the burst offered to the
    # queue, so none of the dropped ones. h2's other traffic in the meantime (scrapes, probes) is far below what was dropped.
    left, frame = sample(noc, f"node_network_transmit_bytes_total{LINK}", done) - out_bytes, size + HEADERS
    assert got["received"] * frame <= left < sent["sent"] * frame, \
        f"h2 eth1 counted {left:.0f} bytes out: {got['received'] * frame} arrived, {sent['sent'] * frame} were offered to its queue"
    # What hides it: the interface's own drop counter, the 5-minute average, the web check and ping.
    assert sample(noc, f"node_network_transmit_drop_total{LINK}", done) == link_drops, "the interface counted the queue's drops"
    average = noc.value(f"rate(node_network_transmit_bytes_total{LINK}[5m]) * 8")
    assert average < 0.05 * bits(SHAPED["rate"]), f"the 5-minute average is {average:.0f} bit/s, not hiding anything"
    window = f"{int(time.time() - since) + 5}s"
    for job in ("web", "icmp"):
        assert noc.value(f'min_over_time(probe_success{{job="{job}",node="{SERVER}"}}[{window}])') == 1, f"the {job} check failed"
    assert not others_firing(noc, "QueueDrops", since, node=SERVER, device=SHAPED["interface"])


def test_a_known_byte_count_matches_the_counters_across_an_exporter_restart(node, mon, noc, lab_name, expected):
    """4000 datagrams of 100 bytes from h1 to the carrier's address, paced over 5 s: what r1 received from fw1 and
    what r2 sent the carrier, as the NOC stored them, match the bytes on the wire within 5%, and within 1%, which
    tells what a frame counts: with its 14-byte Ethernet header (9.9% of these frames) and without a 4-byte checksum
    (2.8%). r2's node_exporter restarts in the middle; its counter carries on (the kernel keeps it), Prometheus sees
    no reset, and nothing about r1 or r2 pages."""
    # Small datagrams, so that each header is a large share of a frame and a count without it is far outside 1%.
    count, size, rate = 4000, 100, 800
    counters = {"r1": f'node_network_receive_bytes_total{{node="r1",device="{facing("r1", "fw1")}"}}',
                "r2": f'node_network_transmit_bytes_total{{node="r2",device="{facing("r2", "isp")}"}}'}
    exporter = f"clab-{lab_name}-r2-node-exporter"
    assert wait_for(lambda: not [a for r in counters for a in noc.alerts(None, node=r)], timeout=90, interval=2), \
        f"r1 or r2 had an alert before the test: {[a['labels'] for r in counters for a in noc.alerts(None, node=r)]}"
    started = noc.value('process_start_time_seconds{job="node",node="r2"}')
    assert started, "r2's node_exporter reports no start time"
    since = time.time()
    before = {r: sample(noc, q, since) for r, q in counters.items()}
    rx = receive(node("isp").container, 3)
    sender = subprocess.Popen(["docker", "exec", node("h1").container, "python3", "-c", BURST, "pace", expected["loopbacks"]["isp"],
                               str(PORT), str(count), str(size), str(rate)], stdout=subprocess.PIPE, text=True)
    try:
        time.sleep(count / rate / 3)
        subprocess.run(["docker", "restart", "-t", "2", exporter], check=True, capture_output=True, timeout=60)
        sent = json.loads(sender.communicate(timeout=120)[0].splitlines()[-1])
    finally:
        if sender.poll() is None:
            sender.kill()
    got = received(rx)
    done = time.time()
    assert sent["sent"] == got["received"] == count, f"sent {sent}, received {got}: the count is not known"
    wire = count * (size + HEADERS)
    for r, q in counters.items():
        seen = sample(noc, q, done) - before[r]
        what = f"{r}: the NOC counted {seen:.0f} bytes, {wire} were sent ({100 * (seen - wire) / wire:+.2f}%)"
        print(what)
        assert abs(seen - wire) <= 0.05 * wire, what  # OROS DEC-2's tolerance
        # The two links' other traffic in the meantime (BGP keepalives, the NOC's probes, fw1's syslog) is well inside 1%.
        assert abs(seen - wire) <= 0.01 * wire, f"{what}: not each frame with its Ethernet header and nothing else"
    # The exporter really restarted, Prometheus saw no reset of the kernel's counter, and nothing paged.
    assert wait_for(lambda: (noc.value('process_start_time_seconds{job="node",node="r2"}') or 0) > started, timeout=30), \
        "Prometheus never scraped a restarted node_exporter on r2"
    window = f"{int(time.time() - since) + 5}s"
    assert noc.value(f"resets({counters['r2']}[{window}])") == 0, "Prometheus saw r2's counter reset"
    fired = [x["labels"] for x in noc.notifications(since) if x["status"] == "firing" and x["labels"].get("node") in counters]
    assert not fired, f"r1 or r2 paged: {fired}"
    assert wait_for(lambda: all(t["health"] == "up" for t in noc.targets() if t["labels"].get("node") == "r2"), timeout=30)


def test_a_reset_queue_counter_is_flagged_and_pages_nobody(node, mon, noc):
    """h2's HTB is deleted and added again from the rendered tc lines, so its counters start again at 0. The stored
    series falls, resets() flags it, rate() over it never rises above 0, and QueueDrops stays quiet past its bound."""
    host = node(SERVER)
    quiet(noc, "QueueDrops", node=SERVER)
    if not sample(noc, f"node_qdisc_drops_total{QUEUE}", time.time()):
        # Run alone, without the burst test before it: make a count to reset, and let its page pass first.
        since = time.time()
        burst(node, SERVER, GATEWAY)
        assert wait_alert(noc, "QueueDrops", since, mon["alert_within"]["QueueDrops"] + 5, node=SERVER)
        quiet(noc, "QueueDrops", node=SERVER)
    drops = sample(noc, f"node_qdisc_drops_total{QUEUE}", time.time())
    sent = sample(noc, f"node_qdisc_bytes_total{QUEUE}", time.time())
    assert drops > 0 and sent > 0
    topo = yaml.safe_load((BUILD / "topology.clab.yml").read_text())["topology"]["nodes"]
    shaped = [step for step in topo[SERVER]["exec"] if step.startswith("tc ")]
    since = time.time()
    try:
        host.run("tc", "qdisc", "del", "dev", SHAPED["interface"], "root")
        for step in shaped:
            host.run(*shlex.split(step))
    finally:
        if "htb" not in host.run("tc", "qdisc", "show", "dev", SHAPED["interface"]).stdout:
            host.run("tc", "qdisc", "del", "dev", SHAPED["interface"], "root", check=False)
            for step in shaped:
                host.run(*shlex.split(step))
    assert {c["id"] for c in SHAPED["classes"]} <= set(class_drops(host, SHAPED["interface"])), "the QoS classes did not come back"
    fell = sample(noc, f"node_qdisc_drops_total{QUEUE}", time.time())
    assert fell < drops, f"the stored count did not fall ({drops} -> {fell})"
    # Past QueueDrops' bound, plus 10 s of margin: a rule that read the fall as a change would have paged by now.
    time.sleep(mon["alert_within"]["QueueDrops"] + 10)
    window = f"{int(time.time() - since) + 5}s"
    assert noc.value(f"resets(node_qdisc_drops_total{QUEUE}[{window}])") >= 1, "resets() did not flag the drop counter"
    assert noc.value(f"resets(node_qdisc_bytes_total{QUEUE}[{window}])") >= 1, "resets() did not flag the byte counter"
    assert noc.value(f"max_over_time(rate(node_qdisc_drops_total{QUEUE}[30s])[{window}:5s])") == 0, "rate() showed the fall as drops"
    assert not noc.alerts(None, alertname="QueueDrops", node=SERVER), "QueueDrops is pending or firing after a reset"
    assert not [x for x in noc.notifications(since, alertname="QueueDrops", node=SERVER) if x["status"] == "firing"], "a reset paged"


def test_a_32_bit_wrap_of_the_queue_counter_shows_no_spike(mon, noc):
    """promtool, Prometheus' own rule tester in the NOC's pinned image, runs the rendered QueueDrops rule for h2 over a
    queue drop counter that goes 4294967290, 4294967295, 3, 8: 14 drops, with the wrap at 2^32 between the second
    and third. The rule shows 13 (increase() reads the wrap as a reset, so the one drop before it is lost), and 13 is
    the most it ever shows: no jump of about 4.29e9. The alert is quiet before the wrap and clears once it leaves the window.
    No queue here drops four billion packets, so the counter is made up; the rule and the engine are the real ones.
    The rule runs with its summary as its only annotation: the other three (why it fired, what is normal, what
    changed) query the NOC's own series and are checked by tests/test_alert_context.py."""
    rules = yaml.safe_load((BUILD / mon["host"] / "rules.yml").read_text())["groups"][0]["rules"]
    rule = next(r for r in rules if r["alert"] == "QueueDrops" and r["labels"]["node"] == SERVER)
    series = {"node": SERVER, "device": SHAPED["interface"], "kind": "htb"}
    labels = "{" + ",".join(f'{k}="{v}"' for k, v in series.items()) + "}"
    step = mon["interval"]
    # A minute at 4294967290, then one value a scrape: 4294967295, 3 and 8, and 8 from then on. At `full` the rule's
    # one-minute window holds the whole wrap and starts on a sample, so increase() has nothing to extrapolate.
    values, full = f"{WRAP - 6}x{60 // step} {WRAP - 1} 3 8 8x{300 // step}", 60 + 4 * step
    summary = re.sub(r"\{\{ \$labels\.(\w+) \}\}", lambda m: series[m[1]], rule["annotations"]["summary"])
    case = {"evaluation_interval": f"{step}s", "tests": [{
        "interval": f"{step}s",
        "input_series": [{"series": f"node_qdisc_drops_total{labels}", "values": values}],
        "promql_expr_test": [
            {"expr": rule["expr"], "eval_time": f"{full}s", "exp_samples": [{"labels": labels, "value": 13}]},
            # The most the rule's expression ever shows, over the whole series: no spike.
            {"expr": f"max_over_time(({rule['expr']})[6m:{step}s])", "eval_time": "6m", "exp_samples": [{"labels": labels, "value": 13}]}],
        "alert_rule_test": [
            {"eval_time": "60s", "alertname": "QueueDrops", "exp_alerts": []},
            {"eval_time": f"{full}s", "alertname": "QueueDrops",
             "exp_alerts": [{"exp_labels": {**series, **rule["labels"]}, "exp_annotations": {"summary": summary}}]},
            {"eval_time": f"{full + 60 + step}s", "alertname": "QueueDrops", "exp_alerts": []}]}]}
    out = noc.rule_test(case, rules=[{**rule, "annotations": {"summary": rule["annotations"]["summary"]}}])
    assert out.returncode == 0 and "SUCCESS" in out.stdout, out.stdout + out.stderr


def test_the_servers_exporter_answers_the_noc_and_nobody_out_of_scope(node, mon, expected):
    """h2's node_exporter, on the toy payments segment, answers the NOC. The scope register's segmentation tuples close
    its port to every out-of-scope device (h1 behind fw1, the carrier's router behind r2's WAN filter), as every port h2
    doesn't publish; each finds it closed, and the segment's other device reaches it, so the closure is a filter."""
    probes = [t for t in expected["segmentation"] if t.get("sidecar")]
    assert {(t["dst"], t["port"]) for t in probes} == {(s, e["port"]) for s, e in mon["servers"].items()} and probes
    assert {t["src"] for t in probes} == {t["src"] for t in expected["segmentation"]} and all(t["expect"] == "closed" for t in probes)
    for server, e in mon["servers"].items():
        assert node(mon["host"]).tcp_open(e["address"], e["port"]), f"the NOC can't reach {server}'s exporter"
    reached = [f"{t['src']} -> {t['dst']}:{t['port']}" for t in probes if node(t["src"]).tcp_open(t["address"], t["port"])]
    assert not reached, f"out of scope, and the exporter answers: {reached}"
    dead = [f"{t['inside']} -> {t['dst']}:{t['port']}" for t in probes if not node(t["inside"]).tcp_open(t["address"], t["port"])]
    assert not dead, f"not answering from inside the segment either, so the closed probes prove nothing: {dead}"


def test_each_metric_is_the_type_its_exporter_declares(noc):
    """monitoring/coverage.yml says each metric is a counter or a gauge; the exporters' own TYPE lines, as Prometheus
    read them, agree. node_exporter's netstat collector declares its kernel counters untyped, and the file says so."""
    cov = yaml.safe_load((ROOT / "monitoring" / "coverage.yml").read_text())
    counts = cov["counts"]
    # Only there once a job has pushed it since the NOC started; its type is checked whenever it is.
    after_push = {m for c in cov["collectors"].values() for m in c.get("after_push") or []}
    declared = noc.get(monitoring.PORTS["prometheus"], "/api/v1/metadata")["data"]
    wrong = []
    for metric, c in counts.items():
        if metric in ("up", "ALERTS"):
            continue  # Prometheus' own, with no TYPE line to compare
        if metric in after_push and metric not in declared:
            continue
        types = {m["type"] for m in declared.get(metric, [])}
        # Prometheus' metadata calls an untyped metric "unknown".
        want = {"untyped": "unknown"}.get(c.get("exported_as"), c.get("exported_as")) or c["type"]
        if types != {want}:
            wrong.append(f"{metric}: coverage.yml says {want}, the exporter declares {sorted(types) or 'nothing'}")
    assert not wrong, "\n".join(wrong)
