"""What the NOC sees, read from the host (decisions 0018 and 0019).

python -m netlab.observe alerts       what Prometheus has firing, and what the pager (the sink) received
python -m netlab.observe testevent    a marked line from every log source over its real path, and when
                                      each reached the central store (OROS NOT-3's synthetic event)

Prometheus, Alertmanager, Loki and the webhook sink listen on 127.0.0.1 inside noc's network
namespace only, so every request here goes through `docker exec` into noc, the way an operator on the
NOC's own box would make it. The live tests in tests/live/observe/ use the same client.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

import yaml

from .inventory import Inventory, load
from . import monitoring

ROOT = Path(__file__).resolve().parent.parent
TAG = "netlab-testevent"


class Noc:
    def __init__(self, lab: str, host: str = "noc"):
        self.lab = lab
        self.container = f"clab-{lab}-{host}"

    def get(self, port: int, path: str, **params) -> object:
        url = f"http://127.0.0.1:{port}{path}" + (f"?{urllib.parse.urlencode(params)}" if params else "")
        out = subprocess.run(["docker", "exec", self.container, "wget", "-qO-", url],
                             capture_output=True, text=True, timeout=30)
        if out.returncode:
            raise RuntimeError(f"GET {url} on {self.container}: {out.stderr.strip() or out.returncode}")
        return json.loads(out.stdout)

    # Prometheus
    def query(self, expr: str) -> list[dict]:
        """[{labels..., "value": float}] for an instant query."""
        data = self.get(monitoring.PORTS["prometheus"], "/api/v1/query", query=expr)["data"]["result"]
        return [{**r["metric"], "value": float(r["value"][1])} for r in data]

    def value(self, expr: str) -> float | None:
        result = self.query(expr)
        return result[0]["value"] if result else None

    def alerts(self, state: str | None = "firing", **labels) -> list[dict]:
        """Prometheus' alerts (each {labels, state, activeAt, value}) whose labels include these."""
        alerts = self.get(monitoring.PORTS["prometheus"], "/api/v1/alerts")["data"]["alerts"]
        return [a for a in alerts if (state is None or a["state"] == state)
                and all(a["labels"].get(k) == v for k, v in labels.items())]

    def rules(self) -> list[dict]:
        groups = self.get(monitoring.PORTS["prometheus"], "/api/v1/rules")["data"]["groups"]
        return [r for g in groups for r in g["rules"]]

    def targets(self) -> list[dict]:
        return self.get(monitoring.PORTS["prometheus"], "/api/v1/targets")["data"]["activeTargets"]

    def rule_test(self, case: dict) -> subprocess.CompletedProcess:
        """`promtool test rules` with this case (series made up for it, the expected results), run in the Prometheus
        sidecar against the rules it has loaded, with the promtool of its own pinned image."""
        return subprocess.run(["docker", "exec", "-i", f"{self.container}-prometheus", "promtool", "test", "rules", "/dev/stdin"],
                              input=yaml.safe_dump(case), capture_output=True, text=True, timeout=60)

    # The pager
    def notifications(self, since: float = 0, **labels) -> list[dict]:
        """Each alert the sink received after `since`, as {received, status, labels}: one entry per alert in
        each notification Alertmanager sent."""
        out = []
        for n in self.get(monitoring.PORTS["sink"], "/"):
            if n["received"] < since:
                continue
            for a in n["notification"]["alerts"]:
                if all(a["labels"].get(k) == v for k, v in labels.items()):
                    out.append({"received": n["received"], "status": a["status"], "labels": a["labels"]})
        return out

    # The central store
    def logs(self, logql: str, start: float, end: float | None = None, limit: int = 1000,
             every: bool = False) -> list[tuple[float, dict, str]]:
        """(time, stream labels, line) for each line matching logql between start and end (Unix seconds),
        oldest first. every: page through all of them, not just the first `limit`."""
        out, end_ns, start_ns = [], int((end or time.time() + 1) * 1e9), int(start * 1e9)
        while True:
            data = self.get(monitoring.PORTS["loki"], "/loki/api/v1/query_range", query=logql, limit=limit,
                            start=str(start_ns), end=str(end_ns), direction="forward")["data"]["result"]
            page = sorted((int(ts), s["stream"], line) for s in data for ts, line in s["values"])
            out += [(ts / 1e9, labels, line) for ts, labels, line in page]
            if not every or len(page) < limit:
                return out
            start_ns = page[-1][0] + 1

    def metric(self, port: int, name: str) -> float | None:
        """An unlabelled metric from a service's own /metrics page, such as Loki's, which nothing scrapes."""
        out = subprocess.run(["docker", "exec", self.container, "wget", "-qO-", f"http://127.0.0.1:{port}/metrics"],
                             capture_output=True, text=True, timeout=30).stdout
        hit = re.search(rf"^{re.escape(name)} (\S+)$", out, re.M)
        return float(hit[1]) if hit else None

    def ready(self) -> bool:
        try:
            return subprocess.run(["docker", "exec", self.container, "wget", "-qO-",
                                   f"http://127.0.0.1:{monitoring.PORTS['loki']}/ready"],
                                  capture_output=True, text=True, timeout=10).stdout.strip() == "ready"
        except subprocess.TimeoutExpired:
            return False


def lab_name(build: Path = ROOT / "build") -> str:
    return yaml.safe_load((build / "topology.clab.yml").read_text())["name"]


def send_testevent(inv: Inventory, lab: str, source: dict, marker: str) -> None:
    """One marked line from one source, the way its real lines travel: logger on the node itself, which
    busybox syslogd sends on; for an app, a request the app writes into its own access log."""
    if source["source"] == "syslog":
        subprocess.run(["docker", "exec", f"clab-{lab}-{source['node']}", "logger", "-t", TAG, marker],
                       check=True, capture_output=True, timeout=30)
        return
    app = next(a for a in inv.logging["apps"] if a["host"] == source["node"] and a["name"] == source["source"])
    address = monitoring.probe_address(inv, app["host"])
    # A 404 is still an access line. From the NOC, the client a real check would come from.
    subprocess.run(["docker", "exec", f"clab-{lab}-{monitoring.host(inv)}", "wget", "-q", "-O", "/dev/null",
                    f"http://{address}:{app['port']}/{marker}"], capture_output=True, timeout=30)


def testevent(inv: Inventory, lab: str, timeout: float = 60) -> list[dict]:
    """[{node, source, marker, seconds}]: seconds from sending to the line being searchable, or None."""
    noc, start = Noc(lab, monitoring.host(inv)), time.time()
    sent = []
    for s in monitoring.log_sources(inv):
        marker = f"NOT3-{s['node']}-{s['source']}-{uuid.uuid4().hex[:12]}"
        sent.append({**{k: s[k] for k in ("node", "source")}, "marker": marker, "sent": time.time(), "seconds": None})
        send_testevent(inv, lab, s, marker)
    while time.time() < start + timeout and any(e["seconds"] is None for e in sent):
        lines = noc.logs('{node=~".+"} |= "NOT3-"', start - 5)
        for e in sent:
            hit = next((t for t, labels, line in lines if e["marker"] in line
                        and labels.get("node") == e["node"] and labels.get("source") == e["source"]), None)
            if hit is not None and e["seconds"] is None:
                # The collector stamps a line when it arrives; docker exec itself takes a few tenths.
                e["seconds"] = round(hit - e["sent"], 3)
        time.sleep(1)
    return sent


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.observe")
    p.add_argument("command", choices=["alerts", "testevent"])
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    inv, lab = load(args.inventory), lab_name()
    noc = Noc(lab, monitoring.host(inv))
    if args.command == "alerts":
        firing = noc.alerts()
        for a in firing:
            labels = ", ".join(f"{k}={v}" for k, v in sorted(a["labels"].items()) if k != "alertname")
            print(f"firing  {a['labels']['alertname']}  {labels}  since {a['activeAt']}")
        received = noc.notifications()
        print(f"{len(firing)} firing; the sink has received {len(received)} alert notifications "
              f"({sum(n['status'] == 'resolved' for n in received)} of them resolved)")
        return 0
    results = testevent(inv, lab)
    for e in results:
        where = f"arrived in {e['seconds']} s" if e["seconds"] is not None else "NOT FOUND in the central store"
        print(f"{e['node']:<5} {e['source']:<7} {e['marker']}  {where}")
    return 1 if any(e["seconds"] is None for e in results) else 0


if __name__ == "__main__":
    sys.exit(main())
