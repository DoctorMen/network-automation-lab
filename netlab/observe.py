"""What the NOC sees, read from the host (decisions 0018 to 0022).

python -m netlab.observe alerts         what Prometheus has firing, and what the pager (the sink) received
python -m netlab.observe testevent      a marked line from every log source over its real path, and when
                                        each reached the central store (OROS NOT-3's synthetic event)
python -m netlab.observe ingest         each log source's bytes at the collector in the last 24 h, or since the
                                        lab started if that is less, against its daily budget (OROS NOT-5);
                                        exits 1 if one is over
python -m netlab.observe success JOB    an unattended job's last step: its success, pushed to the NOC's
                                        pushgateway, and to $HEARTBEAT_URL/JOB when that is set (NOT-4)
python -m netlab.observe applied NODE   `make apply`'s last step: the commit now applied to each router (DEC-1)

Prometheus, Alertmanager, Loki, the pushgateway, the mailbox and the webhook sink listen on 127.0.0.1
inside noc's network namespace only, so every request here goes through `docker exec` into noc, the way an
operator on the NOC's own box would make it. The live tests in tests/live/observe/ use the same client.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import yaml

from .inventory import Inventory, load
from . import monitoring

ROOT = Path(__file__).resolve().parent.parent
TAG = "netlab-testevent"
SUCCESS = "netlab_job_last_success_timestamp_seconds"
# busybox wget on noc can only GET, so anything that writes goes through the node's own python3.
SEND = ("import sys, urllib.request\n"
        "req = urllib.request.Request(sys.argv[1], data=sys.stdin.buffer.read(), method=sys.argv[2],"
        " headers={'Content-Type': sys.argv[3]})\n"
        "print(urllib.request.urlopen(req, timeout=20).read().decode())\n")


def exposition(metric: str, samples: list[tuple[dict, float]]) -> str:
    """Prometheus' text format for one gauge, what a pushgateway takes."""
    def esc(v):
        return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    lines = [f"# TYPE {metric} gauge"]
    for labels, value in samples:
        inner = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
        lines.append(f"{metric}{{{inner}}} {value}" if inner else f"{metric} {value}")
    return "\n".join(lines) + "\n"


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

    def send(self, port: int, path: str, body: str, method: str = "POST", content_type: str = "text/plain") -> str:
        url = f"http://127.0.0.1:{port}{path}"
        out = subprocess.run(["docker", "exec", "-i", self.container, "python3", "-c", SEND, url, method, content_type],
                             input=body, capture_output=True, text=True, timeout=30)
        if out.returncode:
            raise RuntimeError(f"{method} {url} on {self.container}: {(out.stderr.strip().splitlines() or [out.returncode])[-1]}")
        return out.stdout

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

    def firing(self, state: str | None = "firing") -> list[dict]:
        """Every alert Prometheus has in this state (None: pending too), except Watchdog, the alert path's
        heartbeat, which always fires (decision 0022)."""
        return [a for a in self.alerts(state) if a["labels"]["alertname"] != "Watchdog"]

    def rules(self) -> list[dict]:
        groups = self.get(monitoring.PORTS["prometheus"], "/api/v1/rules")["data"]["groups"]
        return [r for g in groups for r in g["rules"]]

    def targets(self) -> list[dict]:
        return self.get(monitoring.PORTS["prometheus"], "/api/v1/targets")["data"]["activeTargets"]

    # Alertmanager
    def am_alerts(self, **labels) -> list[dict]:
        """Every alert Alertmanager holds, silenced and inhibited ones included: {labels, annotations,
        status: {state, silencedBy, inhibitedBy}, ...}."""
        return [a for a in self.get(monitoring.PORTS["alertmanager"], "/api/v2/alerts")
                if all(a["labels"].get(k) == v for k, v in labels.items())]

    def silences(self) -> list[dict]:
        return self.get(monitoring.PORTS["alertmanager"], "/api/v2/silences")

    def add_silence(self, matchers: dict, starts: str, ends: str, by: str, comment: str) -> str:
        """An equality-only silence (RFC 3339 times); returns its id."""
        body = {"matchers": [{"name": k, "value": v, "isRegex": False, "isEqual": True} for k, v in matchers.items()],
                "startsAt": starts, "endsAt": ends, "createdBy": by, "comment": comment}
        return json.loads(self.send(monitoring.PORTS["alertmanager"], "/api/v2/silences", json.dumps(body),
                                    content_type="application/json"))["silenceID"]

    def expire_silence(self, silence_id: str) -> None:
        self.send(monitoring.PORTS["alertmanager"], f"/api/v2/silence/{silence_id}", "", method="DELETE")

    # The pushgateway and the mailbox
    def push(self, group: dict, body: str) -> None:
        """Replace one pushgateway group (job=..., then any other key) with this text-format body."""
        path = "/metrics/" + "/".join(f"{k}/{urllib.parse.quote(str(v), safe='')}" for k, v in group.items())
        self.send(monitoring.PORTS["pushgateway"], path, body, method="PUT")

    def mail(self) -> list[dict]:
        """The mailbox's newest messages first: {ID, Created (RFC 3339), Subject, ...}."""
        return self.get(monitoring.PORTS["mailbox"], "/api/v1/messages", limit=200)["messages"]
    def rule_test(self, case: dict) -> subprocess.CompletedProcess:
        """`promtool test rules` with this case (series made up for it, the expected results), run in the Prometheus
        sidecar against the rules it has loaded, with the promtool of its own pinned image."""
        return subprocess.run(["docker", "exec", "-i", f"{self.container}-prometheus", "promtool", "test", "rules", "/dev/stdin"],
                              input=yaml.safe_dump(case), capture_output=True, text=True, timeout=60)

    # The pager
    def notifications(self, since: float = 0, **labels) -> list[dict]:
        """Each alert the sink received after `since`, as {received, status, labels, annotations}: one entry
        per alert in each notification Alertmanager sent."""
        out = []
        for n in self.get(monitoring.PORTS["sink"], "/"):
            if n["received"] < since:
                continue
            for a in n["notification"]["alerts"]:
                if all(a["labels"].get(k) == v for k, v in labels.items()):
                    out.append({"received": n["received"], "status": a["status"], "labels": a["labels"],
                                "annotations": a.get("annotations", {})})
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

    def settled(self, sources: list[dict]) -> bool:
        """The NOC as a fresh deploy leaves it: Loki ready, every scrape answering, every log source
        (expected_state.json's monitoring.sources) heard from, and nothing firing but Watchdog. A NOC still
        starting (Prometheus not answering yet) is not settled."""
        try:
            targets = self.targets()
            heard = {(s["node"], s["source"]) for s in self.query("log_last_seen_seconds")}
            return bool(self.ready() and targets and all(t["health"] == "up" for t in targets)
                        and all((s["node"], s["source"]) in heard for s in sources) and not self.firing())
        except (RuntimeError, ValueError, subprocess.TimeoutExpired):
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


def success(inv: Inventory, lab: str, job: str, at: float | None = None) -> int:
    """A job's success, as its last step: so a job that failed, hung or never started sends none, and
    JobMissed pages once its window passes. Without a NOC (the lab job's make deploy-network) only a
    warning; a NOC that should have got it pages instead. HEARTBEAT_URL, when set, is an outside check
    (a healthchecks.io-style ping URL) that alerts on its own when the ping stops, the NOC included. A
    failed ping only warns too: that check pages when the ping is late, and failing here would fail a job
    whose work is done (CI then skips saving the backup it just verified)."""
    if job not in [j["name"] for j in inv.monitoring.get("jobs") or []]:
        print(f"{job} is not a job inventory/network.yml lists under monitoring.jobs", file=sys.stderr)
        return 2
    at = time.time() if at is None else at
    try:
        Noc(lab, monitoring.host(inv)).push({"job": job}, exposition(SUCCESS, [({}, at)]))
        print(f"{job}: success recorded on the NOC")
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"warning: {job}'s success did not reach the NOC ({exc}). Expected when no NOC runs; "
              "otherwise JobMissed will page", file=sys.stderr)
    url = os.environ.get("HEARTBEAT_URL")
    if url:
        try:
            urllib.request.urlopen(f"{url.rstrip('/')}/{job}", timeout=10).read()
            print(f"{job}: heartbeat sent")  # never the URL: its key is the secret
        except OSError as exc:
            print(f"warning: {job}: the heartbeat ping failed ({type(exc).__name__}); the outside check will alert "
                  "if no later ping reaches it", file=sys.stderr)
    return 0


def git(*args: str) -> str:
    out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else ""


def commit() -> str:
    """What this checkout is: the commit, marked -dirty when the tree has changes not committed."""
    return git("describe", "--always", "--dirty", "--abbrev=12") or "unknown"


def applied(inv: Inventory, lab: str, nodes: list[str]) -> int:
    """The commit `make apply` just applied, one pushgateway group per router, for the changes annotation
    on every alert about it (OROS DEC-1). Its history stays in Prometheus, one series per commit."""
    labels, now, noc = {"commit": commit(), "subject": git("log", "-1", "--format=%s")[:80]}, time.time(), Noc(lab, monitoring.host(inv))
    try:
        for n in nodes:
            noc.push({"job": "netlab_apply", "node": n}, exposition(monitoring.APPLIED, [(labels, now)]))
        print(f"applied {labels['commit']} recorded on the NOC for {' '.join(nodes)}")
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"warning: the applied commit did not reach the NOC ({exc}). Expected when no NOC runs", file=sys.stderr)
    return 0


def ingest(inv: Inventory, noc: Noc, pace_window: str = "10m") -> list[dict]:
    """[{node, source, bytes, budget, pace}] per log source: bytes the collector received from it in the last
    24 h (what LogIngestOverBudget compares with its budget; on a lab up less than a day, its bytes since the
    lab started), and the last pace_window's rate as bytes a day.
    The pace is shown, not judged: a test's burst inflates it for a while (decision 0026)."""
    day = {(r["node"], r["source"]): r["value"] for r in noc.query("increase(log_bytes_total[1d])")}
    pace = {(r["node"], r["source"]): r["value"] for r in noc.query(f"rate(log_bytes_total[{pace_window}]) * 86400")}
    return [{"node": s["node"], "source": s["source"], "bytes": day.get((s["node"], s["source"])),
             "budget": s["budget"], "pace": pace.get((s["node"], s["source"]))} for s in monitoring.log_sources(inv)]


def kb(value: float | None) -> str:
    return "none" if value is None else f"{value / 1024:.1f} KB"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.observe")
    p.add_argument("command", choices=["alerts", "testevent", "ingest", "success", "applied"])
    p.add_argument("names", nargs="*", help="success: the job; applied: the routers")
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    inv, lab = load(args.inventory), lab_name()
    if args.command == "success":
        if len(args.names) != 1:
            p.error("success takes one job name")
        return success(inv, lab, args.names[0])
    if args.command == "applied":
        return applied(inv, lab, args.names)
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
    if args.command == "ingest":
        rows = ingest(inv, noc)
        print(f"{'source':<11} {'last 24 h':>11} {'budget':>9} {'used':>5}  pace (last 10 min, as a day)")
        for r in rows:
            used = "-" if r["bytes"] is None else f"{100 * r['bytes'] / r['budget']:.0f}%"
            print(f"{r['node'] + '/' + r['source']:<11} {kb(r['bytes']):>11} {r['budget'] // 1024:>6} KB {used:>5}  {kb(r['pace'])}")
        over = [f"{r['node']}/{r['source']}" for r in rows if r["bytes"] is None or r["bytes"] > r["budget"]]
        print(f"over budget or not counted: {', '.join(over)}" if over else "every source is within its daily budget")
        return 1 if over else 0
    results = testevent(inv, lab)
    for e in results:
        where = f"arrived in {e['seconds']} s" if e["seconds"] is not None else "NOT FOUND in the central store"
        print(f"{e['node']:<5} {e['source']:<7} {e['marker']}  {where}")
    return 1 if any(e["seconds"] is None for e in results) else 0


if __name__ == "__main__":
    sys.exit(main())
