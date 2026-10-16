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
         "reason": "fw1's outside port is being recabled during the change", "ref": "RISK-31", "by": "on-call"}
    return {**e, **over}


def problem(e):
    """The first problem make silence finds with this entry: there has to be one."""
    found = silence.problems(e, inv, REFS)
    assert found, f"make silence accepts {e}"
    return found[0]


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
    assert "picks out 3 of InterfaceFlapped's 10 objects" in problem(entry(labels={"node": "r1"}))
    assert "picks out 0" in problem(entry(labels={"role": "core", "device": "eth9"}))
    assert "picks out" in problem(entry(labels={"role": "core"}))


def test_a_silence_that_does_not_end_soon_is_refused():
    assert "lasts over 7 days" in problem(entry(ends=T0 + timedelta(days=8)))
    assert "ends before it starts" in problem(entry(ends=T0))
    assert "starts and ends must both be" in problem(entry(ends="soon"))
    window = {"maintenance": "r3", "starts": T0, "ends": T0 + timedelta(hours=5), "reason": entry()["reason"],
              "ref": "RISK-31", "by": "on-call"}
    assert "a maintenance window lasts at most 4 h" in problem(window)
    assert silence.problems({**window, "ends": T0 + timedelta(hours=3)}, inv, REFS) == []


def test_a_silence_without_a_reason_or_a_record_is_refused():
    assert "needs a reason" in problem(entry(reason="flappy"))
    assert "ref 'JIRA' is not" in problem(entry(ref="JIRA"))
    assert "ref 'RISK-999' is not" in problem(entry(ref="RISK-999"))
    assert "needs `by`" in problem(entry(by=""))


def test_the_alert_path_heartbeat_cannot_be_silenced():
    assert "is not an alert that pages" in problem(entry(alert="Watchdog", labels={}))


class FakeNoc:
    def __init__(self):
        self.added, self.store = [], []

    def silences(self):
        return self.store

    def add_silence(self, matchers, starts, ends, by, comment):
        self.added.append(matchers)
        self.store.append({"id": f"s{len(self.added)}", "comment": comment, "createdBy": by, "endsAt": ends, "status": {"state": "active"},
                           "matchers": [{"name": k, "value": v, "isRegex": False, "isEqual": True} for k, v in matchers.items()]})
        return f"s{len(self.added)}"


def test_apply_adds_each_current_silence_once_and_skips_ended_ones():
    noc, old = FakeNoc(), entry(starts=T0 - timedelta(days=2), ends=T0 - timedelta(days=1))
    assert [sid for _, sid in silence.apply([entry(), old], noc, now=T0)] == ["s1"]
    assert [sid for _, sid in silence.apply([entry(), old], noc, now=T0)] == ["s1"], "added again"
    assert noc.added == [{"alertname": "InterfaceFlapped", "node": "r1", "device": "eth3"}]
    assert "[RISK-31]" in noc.store[0]["comment"] and noc.store[0]["comment"].startswith(entry()["reason"])


def test_a_silence_added_by_hand_is_reported(tmp_path, monkeypatch, capsys):
    """One added with amtool, on a whole router, isn't in the file: make silence names it and fails."""
    noc = FakeNoc()
    [(_, mine)] = silence.apply([entry()], noc, now=T0)
    noc.store.append({"id": "by-hand", "comment": "r1 is noisy", "createdBy": "someone", "endsAt": "2026-10-27T08:00:00Z",
                      "matchers": [{"name": "node", "value": "r1", "isRegex": False, "isEqual": True}],
                      "status": {"state": "active"}})
    noc.store.append({"id": "old", "comment": "long gone", "status": {"state": "expired"}})
    assert [s["id"] for s in silence.strays([entry()], noc)] == ["by-hand"]
    assert {s["id"] for s in silence.strays([], noc)} == {mine, "by-hand"}, "a silence whose entry was removed is a stray too"
    held = tmp_path / "silences.yml"
    held.write_text("silences: []\n")
    monkeypatch.setattr(silence, "Noc", lambda *_: noc)
    assert silence.main(["--file", str(held)]) == 1
    err = capsys.readouterr().err
    assert "by-hand  node='r1'" in err and "not in monitoring/silences.yml" in err and "old" not in err
