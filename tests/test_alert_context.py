"""Every alert says why it fired, what is normal and what changed (OROS DEC-1, decision 0020): three
annotations on every rule, each filled in by Prometheus from the rule's own signal when the alert fires."""
import urllib.parse
from pathlib import Path

from netlab import monitoring
from netlab.inventory import load

inv = load(Path(__file__).resolve().parent.parent / "inventory" / "network.yml")
ALL = [r for g in monitoring.rule_groups(inv)["groups"] for r in g["rules"]]


def links(text):
    """The graph links in an annotation, each as its decoded expression."""
    out = []
    for part in text.split("{{ $externalURL }}/graph?")[1:]:
        q = urllib.parse.parse_qs(part.split(" ")[0].split(";")[0])
        assert q["g0.range_input"] == ["7d"]
        out.append(q["g0.expr"][0])
    return out


def test_every_rule_says_why_it_fired_what_is_normal_and_what_changed():
    for r in ALL:
        a = r["annotations"]
        assert a.get("summary") and a.get("why_fired") and a.get("baseline") and a.get("changes"), r["alert"]
        # why_fired: the condition, and the signal's value now, queried when the alert fires.
        signal = a["why_fired"].split("{{ with query `", 1)[1].split("`", 1)[0]
        assert a["why_fired"].startswith(signal) and "{{ else }}no series{{ end }}" in a["why_fired"]
        # baseline: the value it normally has, and a link to that same signal over 7 days.
        assert a["baseline"].startswith("normally ") and links(a["baseline"]) == [signal], r["alert"]
        # changes: the last commit `make apply` pushed, for this router when the alert is about one.
        node = r["labels"].get("node")
        sel = f'{{node="{node}"}}' if node in inv.routers else ""
        assert f"query `bottomk(1, time() - {monitoring.APPLIED}{sel})`" in a["changes"], r["alert"]
        assert links(a["changes"]) == [monitoring.APPLIED + sel]


def test_the_signal_is_what_the_rule_tests():
    """The value shown is the one the rule's expression is built from, not some other metric."""
    for r in ALL:
        signal = r["annotations"]["why_fired"].split("{{ with query `", 1)[1].split("`", 1)[0]
        core = signal.removeprefix("time() - ").removeprefix("min(").removesuffix(")")
        if r["alert"] != "Watchdog":
            assert core.split(" or ")[0] in r["expr"], (r["alert"], signal, r["expr"])
