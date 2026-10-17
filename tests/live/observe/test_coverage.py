"""OROS NOT-2, into the tool you already run: every metric monitoring/coverage.yml names is in the NOC's
Prometheus, every log query there runs against the central store, and nothing scrapes that the list
doesn't name."""
import re
import time

import yaml

from netlab.coverage import COVERAGE


def coverage():
    return yaml.safe_load(COVERAGE.read_text())


def test_every_listed_metric_is_on_the_noc(noc):
    """Each collector's metrics and each exported or derived entry's metric has at least one series."""
    cov = coverage()
    names = {m for c in cov["collectors"].values() for m in c.get("metrics") or []}
    for e in cov["reads"]:
        if e["status"] in ("exported", "derived") and e.get("metric"):
            names |= set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", re.sub(r"\{[^}]*\}", "", e["metric"])))
    missing = sorted(m for m in names if not noc.query(f"count({m})"))
    assert not missing, f"listed in monitoring/coverage.yml but not on the NOC: {missing}"


def test_every_listed_log_query_runs(noc):
    for e in coverage()["reads"]:
        if e.get("logql"):
            noc.logs(e["logql"], time.time() - 3600, limit=1)  # raises if Loki refuses the query


def test_nothing_scrapes_that_the_list_does_not_name(noc):
    """Every target Prometheus scrapes belongs to a collector in monitoring/coverage.yml, and every rule evaluates."""
    jobs = {t["labels"]["job"] for t in noc.targets()}
    assert jobs <= set(coverage()["collectors"]), f"unlisted scrapers: {sorted(jobs - set(coverage()['collectors']))}"
    broken = [(r["name"], r.get("lastError")) for r in noc.rules() if r["health"] != "ok"]
    assert not broken, f"rules that don't evaluate: {broken}"
