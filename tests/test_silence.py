"""Narrow silences (OROS DEC-4, decision 0020): a silence covers one object of one rule, or one device for a
short maintenance window, ends within a week, and carries a reason and a record that justifies it."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from netlab import silence
from netlab.inventory import load

ROOT = Path(__file__).resolve().parent.parent
inv = load(ROOT / "inventory" / "network.yml")
REFS = silence.known_refs()
T0 = datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc)


def entry(**over):
    e = {"alert": "InterfaceFlapped", "labels": {"node": "r1", "device": "eth3"}, "starts": T0, "ends": T0 + timedelta(hours=2),
         "reason": "fw1's outside port is being recabled during the change", "ref": "RISK-30", "by": "on-call"}
    return {**e, **over}


def test_the_silences_file_is_clean():
    entries = yaml.safe_load((ROOT / "monitoring" / "silences.yml").read_text())["silences"] or []
    assert silence.check(entries, inv, REFS) == []


def test_one_object_for_two_hours_with_its_reason_passes():
    assert silence.problems(entry(), inv, REFS) == []
    assert silence.problems(entry(ref="0020"), inv, REFS) == []
    assert silence.problems(entry(ref="https://tickets.example.org/NOC-1"), inv, REFS) == []
    assert silence.matchers(entry()) == {"alertname": "InterfaceFlapped", "node": "r1", "device": "eth3"}


def test_a_silence_wider_than_one_object_is_refused():
    """r1 alone matches all three of r1's interfaces, and a role matches every core router."""
    assert "picks out 3 of InterfaceFlapped's 10 objects" in silence.problems(entry(labels={"node": "r1"}), inv, REFS)[0]
    assert "picks out 0" in silence.problems(entry(labels={"role": "core", "device": "eth9"}), inv, REFS)[0]
    assert "picks out" in silence.problems(entry(labels={"role": "core"}), inv, REFS)[0]


def test_a_silence_that_does_not_end_soon_is_refused():
    assert "lasts over 7 days" in silence.problems(entry(ends=T0 + timedelta(days=8)), inv, REFS)[0]
    assert "ends before it starts" in silence.problems(entry(ends=T0), inv, REFS)[0]
    assert "starts and ends must both be" in silence.problems(entry(ends="soon"), inv, REFS)[0]
    window = {"maintenance": "r3", "starts": T0, "ends": T0 + timedelta(hours=5), "reason": entry()["reason"],
              "ref": "RISK-30", "by": "on-call"}
    assert "a maintenance window lasts at most 4 h" in silence.problems(window, inv, REFS)[0]
    assert silence.problems({**window, "ends": T0 + timedelta(hours=3)}, inv, REFS) == []


def test_a_silence_without_a_reason_or_a_record_is_refused():
    assert "needs a reason" in silence.problems(entry(reason="flappy"), inv, REFS)[0]
    assert "ref 'JIRA' is not" in silence.problems(entry(ref="JIRA"), inv, REFS)[0]
    assert "ref 'RISK-999' is not" in silence.problems(entry(ref="RISK-999"), inv, REFS)[0]
    assert "needs `by`" in silence.problems(entry(by=""), inv, REFS)[0]


def test_the_alert_path_heartbeat_cannot_be_silenced():
    assert "is not an alert that pages" in silence.problems(entry(alert="Watchdog", labels={}), inv, REFS)[0]


class FakeNoc:
    def __init__(self):
        self.added, self.store = [], []

    def silences(self):
        return self.store

    def add_silence(self, matchers, starts, ends, by, comment):
        self.added.append(matchers)
        self.store.append({"id": f"s{len(self.added)}", "comment": comment, "status": {"state": "active"}})
        return f"s{len(self.added)}"


def test_apply_adds_each_current_silence_once_and_skips_ended_ones():
    noc, old = FakeNoc(), entry(starts=T0 - timedelta(days=2), ends=T0 - timedelta(days=1))
    assert [sid for _, sid in silence.apply([entry(), old], noc, now=T0)] == ["s1"]
    assert [sid for _, sid in silence.apply([entry(), old], noc, now=T0)] == ["s1"], "added again"
    assert noc.added == [{"alertname": "InterfaceFlapped", "node": "r1", "device": "eth3"}]
    assert "[RISK-30]" in noc.store[0]["comment"] and noc.store[0]["comment"].startswith(entry()["reason"])
