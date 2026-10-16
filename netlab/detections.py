"""The detection coverage table (OROS NOT-6, decision 0027).

python -m netlab.detections                    write docs/detections.md from the rules the NOC runs; exit 1 on
                                               a problem (a rule with no row, a blank cell, a stale review)
python -m netlab.detections review [--minutes N] [--env NAME]
                                               on a running full lab: run the benign workload, count every
                                               page the NOC's pager gets meanwhile, and write the result to
                                               monitoring/fp-review.yml, then the table

Every row is one detection: an alert rule as netlab/monitoring.py renders it into build/noc/rules.yml, the
file Prometheus loads. The table takes what each one reads, where its sensor sits and which objects it
watches from the rules and monitoring/coverage.yml, what it detects and misses from
monitoring/detections.yml, and its false positives from the last review. Nothing in a cell is typed twice.

The review runs a stated benign workload (WORKLOAD below): the users' and the operator's normal work, and
nothing broken. So every page in its window is a false positive, and the figure is pages per hour of it.
Each detection's figure is tied to its rules by a fingerprint: change a rule and its figure no longer counts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import monitoring
from .coverage import COVERAGE, PROMQL_WORDS
from .inventory import Inventory, load
from .observe import Noc, lab_name

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "monitoring" / "detections.yml"
REVIEW = ROOT / "monitoring" / "fp-review.yml"
TABLE = ROOT / "docs" / "detections.md"
COLUMNS = ("Detection", "Detects", "Data it reads", "Sensor, and where it sits", "Watches", "Blind spots",
           "False positives over the benign workload")


def rules_by_detection(inv: Inventory) -> dict[str, list[dict]]:
    """{alert name: its rules}, in the order the rules file has them."""
    out: dict[str, list[dict]] = {}
    for r in monitoring.alert_rules(inv):
        out.setdefault(r["alert"], []).append(r)
    return out


def fingerprint(rules: list[dict]) -> str:
    """What a false-positive figure was measured on: every expression and wait of the detection's rules."""
    return hashlib.sha256(json.dumps([[r["expr"], r["for"]] for r in rules]).encode()).hexdigest()[:12]


def metrics(expr: str) -> set[str]:
    """Metric names in an expression (the same reading as the coverage lint's)."""
    expr = re.sub(r'\{[^}]*\}|\[[^\]]*\]|"[^"]*"|\b(by|on|without|ignoring)\s*\([^)]*\)', " ", expr)
    return {w for w in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", expr) if w not in PROMQL_WORDS} - {"node"}


def reads_of(collector: dict) -> list[str]:
    """A collector's metrics, with those it has only once a job pushed them (after_push)."""
    return [*(collector.get("metrics") or []), *(collector.get("after_push") or [])]


def collectors(rules: list[dict], coverage: dict) -> list[str]:
    """The collectors (monitoring/coverage.yml) whose metrics the rules read. A metric two collectors share
    (blackbox's probe_success) belongs to the job the expression names."""
    out = []
    for r in rules:
        jobs = set(re.findall(r'job="([^"]+)"', r["expr"]))
        for m in sorted(metrics(r["expr"])):
            have = [c for c, v in coverage["collectors"].items() if m in reads_of(v)]
            out += [c for c in (have if len(have) == 1 else [c for c in have if c in jobs]) if c not in out]
    return out


def scraped_nodes(inv: Inventory, jobs: list[str]) -> list[str]:
    """The nodes the given scrape jobs target; "up" stands for every job. The collector's own job is noc's.
    For "up", so is each probe job's: a probe's scrape is answered by blackbox on noc, whether the probe
    itself failed or not, so `up` says nothing about the probed device."""
    nodes = []
    for job in monitoring.prometheus_config(inv)["scrape_configs"]:
        if "up" in jobs and job.get("metrics_path") == "/probe":
            nodes.append(monitoring.host(inv))
        elif "up" in jobs or job["job_name"] in jobs:
            nodes += [sc.get("labels", {}).get("node") or monitoring.host(inv) for sc in job["static_configs"]]
    return sorted(set(nodes))


def answered_on(inv: Inventory, job: dict) -> list[str]:
    """The nodes whose own process answers this scrape job: blackbox on noc for a probe job, noc for a job
    with no node label (the NOC's own services), else each target's node."""
    if job.get("metrics_path") == "/probe":
        return [monitoring.host(inv)]
    return sorted({sc.get("labels", {}).get("node") or monitoring.host(inv) for sc in job["static_configs"]})


def watches(inv: Inventory, rules: list[dict], used: list[str]) -> str:
    """Each object a detection watches, by the labels that name it (owner and role describe it, deps and cause
    say what it depends on and what it holds back). A rule with no object of its own watches every target of
    the jobs it reads; a TargetDown rule for one of the NOC's own jobs watches that job's scrapes."""
    config = {j["job_name"]: j for j in monitoring.prometheus_config(inv)["scrape_configs"]}
    named = [r["labels"] for r in rules if r["labels"].get("node")]
    jobs = [r["labels"]["job"] for r in rules if not r["labels"].get("node") and r["labels"].get("job") in config]
    if not named and not jobs:
        if not used:
            return ""  # no object and no metric (Watchdog): its entry in monitoring/detections.yml says what it watches
        if "up" in used:
            return (f"every scrape target, on {', '.join(scraped_nodes(inv, used))}: each probe's scrape is "
                    f"blackbox's own answer, on {monitoring.host(inv)}, not the probed device's")
        return f"every {', '.join(used)} target, on {', '.join(scraped_nodes(inv, used))}"
    each = []
    for labels in named:
        rest = ", ".join(f"{k} {v}" for k, v in labels.items() if k not in ("node", "owner", "role", "deps", "cause"))
        each.append(f"{labels['node']} ({rest})" if rest else labels["node"])
    out = [f"{len(each)}: " + "; ".join(each)] if each else []
    if jobs:
        on = sorted({n for j in jobs for n in answered_on(inv, config[j])})
        out.append(f"and each of the NOC's own jobs ({', '.join(jobs)}), whose scrapes are answered on {', '.join(on)}: "
                   f"a probe's scrape is blackbox's own answer, not the probed device's")
    return "; ".join(out)


def data(rules: list[dict], used: list[str], coverage: dict) -> str:
    """The metrics the rules read, each with its collector."""
    names = sorted({m for r in rules for m in metrics(r["expr"])})
    return ", ".join(f"`{m}` ({c})" for m in names for c in used if m in reads_of(coverage["collectors"][c]))


def sensor(used: list[str], coverage: dict) -> str:
    return "; ".join(f"{coverage['collectors'][c]['exporter']}, reading {coverage['collectors'][c]['reads']}" for c in used)


SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def looks_back(rules: list[dict]) -> int:
    """Seconds a detection looks back before it can page: the longest of its waits (`for`), the ranges it
    reads (`[1d]`) and the ages it compares with the clock (`time() - x > 3600`)."""
    spans = []
    for r in rules:
        spans.append(int(r["for"].removesuffix("s")))
        spans += [int(n) * SECONDS[u] for n, u in re.findall(r"\[(\d+)([smhd])\]", r["expr"])]
        # An age: time() minus a series, or minus a bracketed expression (JobMissed's last success or the NOC's start).
        spans += [int(n) for n in re.findall(r"time\(\) - (?:\w+(?:\{[^}]*\})?|\(.*\)) > (\d+)", r["expr"])]
    return max(spans)


def span(seconds: int) -> str:
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds % n == 0:
            return f"{seconds // n} {unit}"
    return f"{seconds} s"


def false_positives(name: str, rules: list[dict], entry: dict, review: dict | None) -> str:
    """Its pages over the review. A detection that looks back further than the review could not have paged
    on its workload at all, so the cell says so, and what its entry in monitoring/detections.yml gives instead."""
    measured = (review or {}).get("detections", {}).get(name)
    if not measured:
        return ""
    minutes = review["minutes"]
    text = (f"{measured['pages']} pages in {minutes} min ({60 * measured['pages'] / minutes:.1f} an hour), "
            f"reviewed {review['reviewed']}")
    if looks_back(rules) > 60 * minutes:
        text += f". Not a measure of it: it looks back {span(looks_back(rules))}, longer than the review"
        text += f"; {entry['beyond_review']}" if entry.get("beyond_review") else ""
    return text


def rows(inv: Inventory, spec: dict, review: dict | None, coverage: dict) -> list[list[str]]:
    out = []
    for name, rules in rules_by_detection(inv).items():
        entry = spec["detections"].get(name) or {}
        used = collectors(rules, coverage)
        out.append([
            name,
            str(entry.get("detects") or ""),
            data(rules, used, coverage) or str(entry.get("reads") or ""),
            sensor(used, coverage) or str(entry.get("sensor") or ""),
            watches(inv, rules, used) or str(entry.get("watches") or ""),
            "<br>".join(str(b) for b in entry.get("blind_spots") or [] if str(b).strip()),
            false_positives(name, rules, entry, review),
        ])
    return out


def cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def table(inv: Inventory, spec: dict, review: dict | None, coverage: dict) -> str:
    """docs/detections.md, from the rules, the coverage list, the spec and the review."""
    lines = ["# Detection coverage", "",
             "Generated by `make detections` ([netlab/detections.py](../netlab/detections.py)) from the alert rules the NOC "
             "runs (`build/noc/rules.yml`, rendered from the inventory), [monitoring/coverage.yml](../monitoring/coverage.yml), "
             "[monitoring/detections.yml](../monitoring/detections.yml) and the last false-positive review, "
             "[monitoring/fp-review.yml](../monitoring/fp-review.yml). Do not edit it by hand: `make test` fails when it is not "
             "what those files give now. OROS NOT-6, [decision 0027](decisions/0027-detection-coverage.md).", "",
             "| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    lines += ["| " + " | ".join(cell(c) for c in row) + " |" for row in rows(inv, spec, review, coverage)]
    lines += ["", "## What no detection here sees", ""]
    lines += [f"- {cell(item)}" for item in spec.get("not_detected") or []]
    lines += ["", "## The false-positive review", ""]
    if review:
        due = review["reviewed"] + timedelta(days=spec["review"]["cycle_days"])
        lines += [f"Reviewed {review['reviewed']} in the `{review['environment']}` environment, on commit {review['commit']}: "
                  f"{review['minutes']} minutes of the benign workload below, on a lab with nothing broken, so every page in "
                  f"that window is false. Pages are what the NOC's pager (the webhook sink) received from the workload's start "
                  f"until {review.get('settle')} s after its end, the longest a page it caused could take to arrive. "
                  f"The next review is due by {due}; `make test` fails after that, and for any detection whose rules "
                  "have changed since. Run `make fp-review` on a full lab (`make deploy`).", "",
                  "The workload:", ""]
        lines += [f"- {w}" for w in review["workload"]]
        lines += ["", "What each log source sent the store over the same window, as a day, against its budget "
                  "([decision 0026](decisions/0026-log-volume-at-the-source.md)):", "",
                  "| Source | Bytes in the window | As a day | Budget a day |", "|---|---|---|---|"]
        lines += [f"| {k} | {v['bytes']} | {v['per_day']} | {v['budget']} |" for k, v in review["ingest"].items()]
        lines += ["", "Lines cut at the source over the same window: " +
                  "; ".join(f"{k}: {n} {kind} lines" for k, kinds in review["cut"].items() for kind, n in kinds.items()) + "."]
    else:
        lines.append("No review yet: run `make fp-review` on a full lab.")
    return "\n".join(lines) + "\n"


def detections_in(text: str) -> list[str]:
    """The detections a written docs/detections.md lists: the first cell of each row of its table."""
    return [line.split(" | ")[0].removeprefix("| ") for line in text.split("\n## ")[0].splitlines()
            if line.startswith("| ") and not line.startswith(f"| {COLUMNS[0]} ")]


def check(inv: Inventory, spec: dict, review: dict | None, coverage: dict, written: str | None,
          today: date) -> list[str]:
    """Every problem with the table: a deployed rule with no row, a row for no rule, a blank cell, a review that
    is missing, too short, older than one cycle, run on a tree with uncommitted changes, stopped counting
    before its slowest page could arrive, ran a step fewer times than the workload says or had one fail, or
    was run on other rules, a detection that looks back further than the review with nothing said in its
    place, a source over its budget during the review, and a docs/detections.md that is not what the rules
    give now."""
    problems = []
    deployed = rules_by_detection(inv)
    problems += [f"{n} is deployed (build/noc/rules.yml) but monitoring/detections.yml has no entry for it"
                 for n in deployed if n not in spec["detections"]]
    problems += [f"monitoring/detections.yml has {n}, which no deployed rule raises" for n in spec["detections"] if n not in deployed]
    for row in rows(inv, spec, review, coverage):
        problems += [f"{row[0]}: the {col} cell is blank" for col, value in zip(COLUMNS, row) if not str(value).strip()]
    if not review:
        return problems + ["no false-positive review (monitoring/fp-review.yml): run make fp-review on a full lab"]
    cycle = spec["review"]["cycle_days"]
    if not isinstance(review.get("reviewed"), date) or today - review["reviewed"] > timedelta(days=cycle):
        problems.append(f"the false-positive review of {review.get('reviewed')} is older than its {cycle}-day cycle: run make fp-review")
    if review.get("minutes", 0) < spec["review"]["minutes"]:
        problems.append(f"the review ran {review.get('minutes')} minutes of the workload, not the stated {spec['review']['minutes']}")
    if "uncommitted" in str(review.get("commit")):
        problems.append(f"the review ran on {review.get('commit')}, so no commit holds what it measured: commit, then run make fp-review")
    if not isinstance(review.get("settle"), int) or review["settle"] < settle(inv):
        problems.append(f"the review counted pages until {review.get('settle')} s after its workload, before the slowest page "
                        f"it could cause ({settle(inv)} s): run make fp-review")
    steps = review.get("steps", {})
    planned = {what: runs_due(every, first, review.get("minutes", 0)) for every, first, what, _ in workload(inv)}
    problems += [f"review step ran {steps.get(what, {}).get('runs', 0)} of its {n} times: {what}"
                 for what, n in planned.items() if steps.get(what, {}).get("runs") != n]
    problems += [f"the review ran a step the workload does not have: {what}" for what in steps if what not in planned]
    problems += [f"review step failed {s['failed']} of {s['runs']} times: {what}" for what, s in steps.items() if s["failed"]]
    for name, rules in deployed.items():
        entry = review.get("detections", {}).get(name)
        if entry and entry.get("rules") != fingerprint(rules):
            problems.append(f"{name}'s rules have changed since the review of {review['reviewed']}: run make fp-review")
        if looks_back(rules) > 60 * review.get("minutes", 0) and not spec["detections"].get(name, {}).get("beyond_review"):
            problems.append(f"{name} looks back {span(looks_back(rules))}, longer than the review, so its figure measures "
                            "nothing: say what stands for it (beyond_review in monitoring/detections.yml)")
    problems += [f"{k} sent {v['per_day']} bytes a day during the review, over its {v['budget']} byte budget"
                 for k, v in review.get("ingest", {}).items() if v["per_day"] > v["budget"]]
    if written is not None and written != table(inv, spec, review, coverage):
        problems.append("docs/detections.md is not what the deployed rules give now: run make detections")
    return problems


# --- The review: a stated benign workload on a running full lab ---------------------------------------

def on(lab: str, node: str, *cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", f"clab-{lab}-{node}", *cmd], capture_output=True, text=True, timeout=60)


def make(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["make", "-s", *args], cwd=ROOT, capture_output=True, text=True, timeout=600)


def workload(inv: Inventory, lab: str = "") -> list[tuple[int, int, str, object]]:
    """(every seconds, first after seconds, what, run): the users' and the operator's normal work on this
    campus, and nothing that breaks anything. The operator's tasks are spread over each five minutes."""
    user = next(h for h, v in inv.hosts.items() if not v.get("services") and h != monitoring.host(inv))
    server = inv.monitoring["web"][0]
    page = f"http://{monitoring.probe_address(inv, server['host'])}:{server['port']}/"
    carrier = monitoring.loopback(inv, inv.device_at(monitoring.bgp_peers(inv)[0]["address"]))
    return [
        (30, 0, f"every 30 s, a user on {user} loads {server['host']}'s page",
         lambda: on(lab, user, "wget", "-q", "-T", "5", "-O", "/dev/null", page)),
        (10, 2, f"every 10 s, {user} pings {server['host']}",
         lambda: on(lab, user, "ping", "-c", "1", "-W", "2", monitoring.probe_address(inv, server["host"]))),
        (10, 7, f"every 10 s, {user} pings the carrier's {carrier}", lambda: on(lab, user, "ping", "-c", "1", "-W", "2", carrier)),
        (300, 30, "every 5 min, the operator runs make drift: a backup of every router and the firewall, compared with intent",
         lambda: make("drift")),
        (300, 90, "every 5 min, the operator runs make apply with nothing to change: the canary, its health gate, then the rest",
         lambda: make("apply")),
        (300, 150, "every 5 min, make verify: kernels, daemons and h2's QoS classes in effect", lambda: make("verify")),
        (300, 210, "every 5 min, make testevent: a marked line from every log source", lambda: make("testevent")),
        (300, 270, f"every 5 min, make locate from {user} to {carrier}", lambda: make("locate", f"SRC={user}", f"DST={carrier}")),
    ]


# FRR's OSPF dead interval (frr.conf sets no ospf timers): an adjacency the workload broke ends this long
# after its last hello, and only then does OSPFNeighborDown's own bound start.
OSPF_DEAD = 40
# Every notification the pager received during the review, as the sink stored it: the raw record behind
# each page the review counted (and uploaded by the fp-review workflow).
NOTIFICATIONS = ROOT / "results" / "fp-review-notifications.json"


def settle(inv: Inventory) -> int:
    """Seconds after the workload ends that a page it caused can still arrive: the slowest of every alert's
    bound, every log source's (SourceSilent pages up to its `within` after the source's last line), and
    OSPF's dead interval plus OSPFNeighborDown's bound."""
    mon = monitoring.expected(inv)
    return max(*mon["alert_within"].values(), *(s["within"] for s in mon["sources"]),
               OSPF_DEAD + mon["alert_within"]["OSPFNeighborDown"])


def runs_due(every: float, first: float, minutes: int) -> int:
    """How many times a step every `every` seconds, first at `first`, runs in `minutes` of the workload."""
    return len(range(int(first), 60 * minutes, int(every)))


def run_steps(steps: list[tuple], start: float, end: float) -> dict:
    """Each step at its own times from start until end, each in its own thread: {what: {runs, failed}}. A
    step that raises (a timeout, a docker error) failed, and its loop goes on to its next time."""
    results = {what: {"runs": 0, "failed": 0} for _, _, what, _ in steps}

    def loop(every, first, what, run):
        due = start + first
        while due < end:
            time.sleep(max(0, due - time.time()))
            results[what]["runs"] += 1
            try:
                failed = run().returncode != 0
            except Exception:
                failed = True
            results[what]["failed"] += failed
            due += every

    threads = [threading.Thread(target=loop, args=s, daemon=True) for s in steps]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def review(inv: Inventory, lab: str, minutes: int, environment: str) -> dict:
    """Run the workload for `minutes` and count what the pager got: one entry per detection, with the
    fingerprint of the rules it ran on, plus the ingest of every source the store keeps (each router's command
    records too) and the lines cut at the source over the workload's window. Pages are counted until settle()
    seconds after the workload ends."""
    noc, mon = Noc(lab, monitoring.host(inv)), monitoring.expected(inv)
    # Start on a quiet NOC, or a page from before would count. Watchdog is no reason to wait: the alert path's
    # heartbeat always fires, and Alertmanager sends it only to the mailbox, never to the pager (decision 0022).
    deadline = time.time() + 300
    while noc.firing(None) and time.time() < deadline:
        time.sleep(5)
    if noc.firing(None):
        raise SystemExit(f"the NOC is not quiet, so a review would count this: {[a['labels'] for a in noc.firing(None)]}")
    # What the review runs on: the commit as it starts, since the workload runs the worktree's own make targets.
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    steps, start = workload(inv, lab), time.time()
    results = run_steps(steps, start, start + 60 * minutes)
    # Ingest and cut lines over the workload's own window, before the wait for late pages.
    window = round(time.time() - start)
    sent = {(r["node"], r["source"]): r["value"] for r in noc.query(f"increase(log_bytes_total[{window}s])")}
    cut = {}
    for app in mon["apps"]:
        for kind in mon["cuts"][f"{app['host']}/{app['name']}"]:
            got = noc.logs(f'{{node="{app["host"]}",source="{app["name"]}"}} |= "netlab-cut: " |= " {kind["name"]} lines"', start, every=True)
            cut.setdefault(f"{app['host']}/{app['name']}", {})[kind["name"]] = sum(int(l.split()[1]) for _, _, l in got)
    # A page the last minutes caused can still be on its way: wait out the slowest one.
    wait = settle(inv)
    time.sleep(wait)
    NOTIFICATIONS.parent.mkdir(exist_ok=True)
    NOTIFICATIONS.write_text(json.dumps([n for n in noc.get(monitoring.PORTS["sink"], "/") if n["received"] >= start], indent=1))
    pages = [n for n in noc.notifications(start) if n["status"] == "firing"]
    return {
        "reviewed": date.today(),
        "started": datetime.fromtimestamp(start, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minutes": minutes,
        "settle": wait,
        "environment": environment,
        "commit": commit + (" with uncommitted changes" if dirty else ""),
        "workload": [what for _, _, what, _ in steps],
        "steps": results,
        "detections": {name: {"objects": len(rules), "rules": fingerprint(rules),
                              "pages": sum(p["labels"]["alertname"] == name for p in pages)}
                       for name, rules in rules_by_detection(inv).items()},
        "pages": [{"alert": p["labels"]["alertname"], "labels": {k: v for k, v in p["labels"].items() if k != "alertname"},
                   "at": datetime.fromtimestamp(p["received"], timezone.utc).strftime("%H:%M:%SZ")} for p in pages],
        "ingest": {f"{s['node']}/{s['source']}": {"bytes": round(sent.get((s["node"], s["source"]), 0)),
                                                  "per_day": round(sent.get((s["node"], s["source"]), 0) * 86400 / window),
                                                  "budget": s["budget"]} for s in mon["ingest"]},
        "cut": cut,
    }


def load_all(path_spec: Path = SPEC, path_review: Path = REVIEW) -> tuple[dict, dict | None, dict]:
    review_doc = yaml.safe_load(path_review.read_text()) if path_review.exists() else None
    return yaml.safe_load(path_spec.read_text()), review_doc, yaml.safe_load(COVERAGE.read_text())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.detections")
    p.add_argument("command", nargs="?", choices=["table", "review"], default="table")
    p.add_argument("--minutes", type=int, help="review: how long to run the workload (default: monitoring/detections.yml)")
    p.add_argument("--env", default="local", help="review: where it runs (sandbox, github-runner, laptop)")
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    inv = load(args.inventory)
    spec, last, coverage = load_all()
    if args.command == "review":
        last = review(inv, lab_name(), args.minutes or spec["review"]["minutes"], args.env)
        REVIEW.write_text("# Written by `make fp-review` (netlab/detections.py, decision 0027). Do not edit by hand.\n"
                          + yaml.safe_dump(last, sort_keys=False, width=200))
        print(f"{sum(d['pages'] for d in last['detections'].values())} pages in {last['minutes']} min of the benign workload")
    TABLE.write_text(table(inv, spec, last, coverage))
    problems = check(inv, spec, last, coverage, None, date.today())
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"{len(rules_by_detection(inv))} detections in {TABLE.relative_to(ROOT)}" + (f"; {len(problems)} problems" if problems else ""))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
