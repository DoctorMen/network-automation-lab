"""OROS NOT-6 (decision 0027): the detection coverage table is the rules the NOC really runs."""
from collections import Counter

from netlab import monitoring
from netlab.detections import ROOT, TABLE, detections_in, rules_by_detection
from netlab.inventory import load


def test_table_rows_are_the_rules_the_running_noc_has_loaded(noc):
    """The running Prometheus has every detection in docs/detections.md, with as many rules as the table's
    source says, and no alerting rule the table lacks but the cause markers, which Alertmanager routes nowhere
    (decision 0021)."""
    inv = load(ROOT / "inventory" / "network.yml")
    deployed = {name: len(rules) for name, rules in rules_by_detection(inv).items()}
    markers = {r["alert"] for r in monitoring.cause_rules(inv)}
    loaded = Counter(r["name"] for r in noc.rules() if r.get("type") == "alerting" and r["name"] not in markers)
    assert dict(loaded) == deployed
    assert detections_in(TABLE.read_text()) == list(deployed)
