"""A broadcast storm on LAN-A: traced to its port before anything is blocked (OROS CON-1, decision 0033), and
contained per port without shutting the port (CON-2, decision 0034).

h3 is the storm source, h1 the user who must keep working. The source sends at a capped rate (tools/storm.py)
and stops by itself; each test puts the switch back as it found it."""
import json
import threading
import time
from pathlib import Path

from netlab import switch as switch_tool
from netlab import trace as trace_tool
from netlab.inventory import load

from .conftest import ROOT, wait_for

INVENTORY = load(ROOT / "inventory" / "network.yml")
STORM = (Path(__file__).parent / "tools" / "storm.py").read_text()
PPS = 20000       # frames a second the source sends; about 400k would be possible, and would starve the lab of CPU
SAMPLE = 2        # seconds each rate is measured over
TRACE_WITHIN = 60  # seconds the trace may take; the runbook's stated time is 15 minutes


def storm(node, host, seconds):
    """Start the flood from host's LAN port; returns the thread to join once it has stopped by itself."""
    iface = INVENTORY.hosts[host]["interface"]
    t = threading.Thread(target=lambda: node(host).run("python3", "-", iface, str(PPS), str(seconds), input=STORM, timeout=seconds + 30))
    t.start()
    time.sleep(1)  # the first frames are on the wire before anything is measured
    return t


def rx_pps(node, host, iface, seconds=SAMPLE) -> float:
    def packets():
        return json.loads(node(host).run("ip", "-s", "-j", "link", "show", iface).stdout)[0]["stats64"]["rx"]["packets"]
    before = packets()
    time.sleep(seconds)
    return (packets() - before) / seconds


def port_to(spec, far) -> str:
    return next(p for p, v in spec["ports"].items() if v["to"] == far)


def trace(lab_name, sw):
    return trace_tool.measure(INVENTORY, lab_name, sw, SAMPLE, None)


def test_storm_traced_to_port(node, expected, lab_name):
    """Quiet, no port is over the threshold. While h3 floods broadcast, one trace names the switch port h3 hangs off, an edge port, with h3's MAC, within 60 s (stated time 15 minutes); from h1 instead it names h1's port, so the answer follows the source, not a fixed port."""
    sw, spec = next(iter(expected["switches"].items()))
    quiet = trace(lab_name, sw)
    assert quiet["storm_from"] == [], quiet
    for source in ("h3", "h1"):
        port = port_to(spec, f"{source}:{INVENTORY.hosts[source]['interface']}")
        mac = json.loads(node(source).run("ip", "-j", "link", "show", INVENTORY.hosts[source]["interface"]).stdout)[0]["address"]
        t = storm(node, source, seconds=SAMPLE + 6)
        try:
            started = time.time()
            found = trace(lab_name, sw)
            took = time.time() - started
        finally:
            t.join()
        assert took < TRACE_WITHIN, f"the trace took {took:.0f} s"
        assert [(s["port"], s["role"], s["to"]) for s in found["storm_from"]] == [(port, "edge", f"{source}:eth1")], found
        assert mac in found["storm_from"][0]["macs"], found["storm_from"][0]
        assert found["storm_from"][0]["rx_pps"] > found["threshold_pps"] >= 10 * spec["storm_control"]["broadcast_pps"]
        # The other ports only carry copies out, so none of them is named.
        assert all(r["rx_pps"] <= found["threshold_pps"] for p, r in found["ports"].items() if p != port), found["ports"]
    assert wait_for(lambda: trace(lab_name, sw)["storm_from"] == [], timeout=30), "a storm is still being reported after the sources stopped"


def port_up(node, sw, port) -> bool:
    link = json.loads(node(sw).run("ip", "-j", "link", "show", port).stdout)[0]
    bridge = next(e for e in json.loads(node(sw).run("bridge", "-j", "link", "show").stdout) if e["ifname"] == port)
    return link["operstate"] == "UP" and bridge["state"] == "forwarding"


def test_storm_contained_not_shut(node, expected, lab_name):
    """With h3's port's storm control released, h1 receives the flood far above the limit (the storm is real). Put back, h1 gets at most about the limit while h3's port stays up and forwarding, h3's own unicast still works, h1 still fetches h2's page, and the port's DROP counter has counted the excess."""
    sw, spec = next(iter(expected["switches"].items()))
    limit = spec["storm_control"]["broadcast_pps"]
    port, gateway = port_to(spec, "h3:eth1"), INVENTORY.hosts["h3"]["gateway"]
    h1_iface, h2 = INVENTORY.hosts["h1"]["interface"], expected["hosts"]["h2"]
    assert port in trace_tool.drops(INVENTORY, lab_name, sw), f"{sw}:{port} has no storm control to start with"
    try:
        # Released: the flood reaches h1 unpoliced. Without this the limit below would prove nothing.
        switch_tool.contain(INVENTORY, lab_name, sw, port, on=False)
        assert port not in trace_tool.drops(INVENTORY, lab_name, sw)
        t = storm(node, "h3", seconds=SAMPLE + 4)
        try:
            unpoliced = rx_pps(node, "h1", h1_iface)
        finally:
            t.join()
        assert unpoliced > 10 * limit, f"h1 received only {unpoliced:.0f} frames/s with no policer: no storm to contain"
        # Contained: only the excess is dropped, where it comes in.
        switch_tool.contain(INVENTORY, lab_name, sw, port, on=True)
        dropped_before = trace_tool.drops(INVENTORY, lab_name, sw)[port]
        t = storm(node, "h3", seconds=SAMPLE + 10)
        try:
            policed = rx_pps(node, "h1", h1_iface)
            assert policed <= 2 * limit, f"h1 received {policed:.0f} frames/s against a limit of {limit}/s"
            assert port_up(node, sw, port), f"{sw}:{port} is not up and forwarding during the storm"
            assert node("h3").ping(gateway, count=2), "h3's unicast is blocked too: the containment is wider than the excess"
            assert node("h1").run("wget", "-q", "-O", "/dev/null", "-T", "5", f"http://{h2}/", check=False).returncode == 0, \
                "h1 can't fetch h2's page during the contained storm"
            assert trace_tool.drops(INVENTORY, lab_name, sw)[port] > dropped_before, "the DROP rule counted nothing"
        finally:
            t.join()
    finally:
        switch_tool.contain(INVENTORY, lab_name, sw, port, on=True)  # as found
    assert port_up(node, sw, port) and node("h3").ping(gateway, count=1)
    assert wait_for(lambda: trace(lab_name, sw)["storm_from"] == [], timeout=30)
