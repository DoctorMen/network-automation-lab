"""Bulk work yields (decision 0011): while a backup fills h2's capped link, users' web requests stay fast
and the backup still completes. The test first shows the same backup on a flat queue does slow them."""
import json
import math
import subprocess
import time

import yaml

from netlab.verify import tc_classes

from .conftest import BUILD, ROOT

TOOLS = ROOT / "tests" / "live" / "tools"
BACKUP_BYTES = 15_000_000  # 6 s at the 20 Mbit cap, longer than the web probe
PORT = 9000
# Web p95 during the backup, sandbox lab: 2.7-6.3 ms with the classes (6.3 with four CPU-bound
# processes on the host), 110-126 ms on a flat queue of the same rate (decision 0011). 50 ms leaves
# room for a busy CI runner and is still under half of what the flat queue gives.
WEB_P95_TARGET_MS = 50


def p95(result):
    """A failed request counts as slower than any target: it is never left out."""
    times = sorted(result["ms"]) + [math.inf] * result["failed"]
    return times[math.ceil(0.95 * len(times)) - 1]


def classes(h2, interface):
    return tc_classes(h2.run("tc", "-s", "class", "show", "dev", interface).stdout)


def backup_during_web_probe(node, expected, interface):
    """Copy BACKUP_BYTES from h2 to the ISP while h1 times 40 web requests to h2. -> (web, received, seconds, classes)."""
    def tool(container, name, *args):
        return subprocess.Popen(["docker", "exec", "-i", container, "python3", "-", *args],
                                stdin=(TOOLS / name).open(), stdout=subprocess.PIPE, text=True)
    receiver = tool(node("isp").container, "backup.py", "recv", str(PORT))
    start = time.monotonic()
    sender = tool(node("h2").container, "backup.py", "send", expected["loopbacks"]["isp"], str(PORT), str(BACKUP_BYTES))
    try:
        time.sleep(1)  # the copy's queue builds up first
        web = tool(node("h1").container, "web_latency.py", f"http://{expected['hosts']['h2']}/", "40", "0.05")
        result = json.loads(web.communicate(timeout=60)[0])
        during = classes(node("h2"), interface)  # read while the copy is still running
        sender.communicate(timeout=120)
        took = time.monotonic() - start
        received = int(receiver.communicate(timeout=30)[0])
    finally:
        for p in (sender, receiver):
            p.kill()
    return result, received, took, during


def test_backup_yields_to_web(node, expected):
    """During a 15 MB backup that fills h2's 20 Mbit link, h1's web p95 stays under 50 ms, and the backup completes."""
    spec, h2 = expected["qos"]["h2"], node("h2")
    bulk = next(f"1:{c['id']}" for c in spec["classes"] if c.get("default"))
    shaped = [step for step in yaml.safe_load((BUILD / "topology.clab.yml").read_text())["topology"]["nodes"]["h2"]["exec"]
              if step.startswith("tc ")]
    try:
        # Control: the same capped link with one queue for everything.
        h2.run("tc", "qdisc", "del", "dev", spec["interface"], "root")
        h2.run("tc", "qdisc", "add", "dev", spec["interface"], "root", "handle", "1:", "htb", "default", "1")
        h2.run("tc", "class", "add", "dev", spec["interface"], "parent", "1:", "classid", "1:1", "htb", "rate", spec["rate"])
        flat, *_ = backup_during_web_probe(node, expected, spec["interface"])
        assert p95(flat) > WEB_P95_TARGET_MS, \
            f"web p95 {p95(flat):.1f} ms with no priority, so the backup didn't load the link and this test proves nothing"
    finally:
        # Back to the rendered config: the topology's own tc lines, in order.
        h2.run("tc", "qdisc", "del", "dev", spec["interface"], "root", check=False)
        for step in shaped:
            h2.run(*step.split())

    before = classes(h2, spec["interface"])
    web, received, took, during = backup_during_web_probe(node, expected, spec["interface"])
    after = classes(h2, spec["interface"])
    print(f"web p95 {p95(flat):.1f} ms flat, {p95(web):.1f} ms with classes; backup {took:.1f} s")
    assert received == BACKUP_BYTES, f"the backup did not complete: the receiver counted {received} of {BACKUP_BYTES} bytes"
    assert after[bulk]["bytes"] - before[bulk]["bytes"] >= BACKUP_BYTES, "the backup did not go through the bulk class"
    # p95 first: when web is slow, the probe outlasts the copy, so the queue below reads empty.
    assert p95(web) < WEB_P95_TARGET_MS, f"web p95 {p95(web):.1f} ms during the backup, target {WEB_P95_TARGET_MS} ms"
    assert during[bulk]["queued"] > 0, "the bulk class had no queue during the probe, so the link wasn't full"
