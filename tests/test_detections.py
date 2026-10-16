"""OROS NOT-6, the detection coverage table (decision 0027): one row per deployed rule with no blank cell,
docs/detections.md exactly what the rules give now, and every false-positive figure from the current
review cycle, measured on the rules that run now."""
import copy
import subprocess
import time
from datetime import date, timedelta

import pytest

from netlab import detections, monitoring
from netlab.inventory import load
from netlab.detections import TABLE, check, fingerprint, load_all, rows, rules_by_detection

inv = load(detections.ROOT / "inventory" / "network.yml")
SPEC, REVIEW, COVERAGE = load_all()


def problems(spec=SPEC, review=REVIEW, written=None, today=None):
    return check(inv, spec, review, COVERAGE, TABLE.read_text() if written is None else written,
                 today or REVIEW["reviewed"])


def test_table_has_a_full_row_for_every_deployed_rule_and_a_current_review():
    """make detections' own check, on the committed files: no problem at all."""
    assert REVIEW, "no false-positive review: run make fp-review on a full lab"
    assert problems(today=date.today()) == []


def test_every_alert_the_rules_raise_is_a_row():
    assert detections.detections_in(TABLE.read_text()) == list(rules_by_detection(inv))
    # Every alert the rules raise but the cause markers, which Alertmanager routes nowhere (decision 0021).
    markers = {r["alert"] for r in monitoring.cause_rules(inv)}
    assert markers == {"CauseSeen"}
    assert sorted(detections.detections_in(TABLE.read_text())) == [a for a in monitoring.expected(inv)["alerts"] if a not in markers]


def test_a_rule_without_a_row_fails():
    spec = copy.deepcopy(SPEC)
    del spec["detections"]["BFDPeerDown"]
    assert "BFDPeerDown is deployed (build/noc/rules.yml) but monitoring/detections.yml has no entry for it" in problems(spec)


def test_a_blank_blind_spot_fails():
    spec = copy.deepcopy(SPEC)
    spec["detections"]["SourceSilent"]["blind_spots"] = [" "]
    assert "SourceSilent: the Blind spots cell is blank" in problems(spec)


def test_a_review_older_than_its_cycle_fails():
    late = REVIEW["reviewed"] + timedelta(days=SPEC["review"]["cycle_days"] + 1)
    assert any("is older than its 92-day cycle" in p for p in problems(today=late))
    assert not any("older than" in p for p in problems(today=late - timedelta(days=1)))


def test_a_review_of_other_rules_fails():
    """A figure counts only for the rules it was measured on: change one rule's wait and its figure is stale."""
    review = copy.deepcopy(REVIEW)
    review["detections"]["OSPFNeighborDown"]["rules"] = fingerprint([{"expr": "up == 0", "for": "1s"}])
    assert any(p.startswith("OSPFNeighborDown's rules have changed since the review") for p in problems(review=review))


def test_a_change_of_wait_alone_stales_a_figure():
    """A figure is measured on each rule's `for` as well as its expression: one second more and it no longer counts."""
    for name, rules in rules_by_detection(inv).items():
        waited = [{**r, "for": f"{int(r['for'].removesuffix('s')) + 1}s"} for r in rules]
        assert fingerprint(waited) != fingerprint(rules), name


def test_a_review_on_a_tree_with_uncommitted_changes_fails():
    """No commit holds what such a review measured, so its figures are nobody's."""
    review = {**REVIEW, "commit": f"{REVIEW['commit']} with uncommitted changes"}
    assert any(p.startswith("the review ran on ") and "no commit holds" in p for p in problems(review=review))


def test_a_review_that_stopped_counting_before_its_slowest_page_fails():
    """A page the workload's last minutes caused can arrive up to the slowest bound after it (SourceSilent's
    twice the heartbeat): a review that counted for less could have missed it."""
    review = {**REVIEW, "settle": detections.settle(inv) - 1}
    assert any(p.startswith("the review counted pages until") for p in problems(review=review))
    assert detections.settle(inv) >= max(s["within"] for s in monitoring.expected(inv)["sources"])


def test_a_step_that_raises_counts_as_failed_and_runs_on():
    """A step that times out is a step that did not run as stated: it counts as failed, and it still runs at
    each of its later times, so the review's check sees every one."""
    def hangs():
        raise subprocess.TimeoutExpired("make apply", 600)
    # Quarter seconds add up exactly, so a second holds exactly four runs of each.
    steps = [(0.25, 0, "hangs", hangs), (0.25, 0, "works", lambda: subprocess.CompletedProcess([], 0))]
    start = time.time()
    results = detections.run_steps(steps, start, start + 1)
    assert results == {"hangs": {"runs": 4, "failed": 4}, "works": {"runs": 4, "failed": 0}}


def test_a_review_step_that_ran_fewer_times_than_planned_fails():
    """Each step runs a known number of times in the review's minutes (every 5 min for 30 min is 6): fewer
    means part of the workload never ran."""
    review = copy.deepcopy(REVIEW)
    step = next(iter(review["steps"]))
    review["steps"][step]["runs"] -= 1
    assert any(p.startswith("review step ran ") and p.endswith(step) for p in problems(review=review))


def test_a_detection_that_looks_back_longer_than_the_review_says_so():
    """PendingRebootOverdue waits 1 h and LogIngestOverBudget reads a day: a 30-minute review can't show either
    paging falsely, so their cells say so, and an entry that says nothing in its place fails."""
    cells = {row[0]: row[-1] for row in rows(inv, SPEC, REVIEW, COVERAGE)}
    assert "Not a measure of it: it looks back 1 h" in cells["PendingRebootOverdue"]
    assert "Not a measure of it: it looks back 1 d" in cells["LogIngestOverBudget"]
    assert "Not a measure" not in cells["SourceSilent"]
    spec = copy.deepcopy(SPEC)
    del spec["detections"]["PendingRebootOverdue"]["beyond_review"]
    assert any(p.startswith("PendingRebootOverdue looks back 1 h, longer than the review") for p in problems(spec))


def test_target_down_watches_only_what_answers_its_own_scrape():
    """A probe's scrape is blackbox's own answer on noc, so TargetDown can't page for a device only a probe reaches."""
    cell = next(row[4] for row in rows(inv, SPEC, REVIEW, COVERAGE) if row[0] == "TargetDown")
    per_node, _, noc_jobs = cell.partition("; and each of the NOC's own jobs (")
    listed = {e.split(" (")[0] for e in per_node.split(": ", 1)[1].split("; ")}
    assert listed == set(monitoring.exporter_nodes(inv)), cell
    jobs = {j["job_name"] for j in monitoring.prometheus_config(inv)["scrape_configs"]} - set(monitoring.EXPORTERS)
    named, _, rest = noc_jobs.partition("), ")
    assert set(named.split(", ")) == jobs and rest.startswith(f"whose scrapes are answered on {monitoring.host(inv)}:"), cell


def test_a_review_shorter_than_the_stated_workload_fails():
    review = {**REVIEW, "minutes": SPEC["review"]["minutes"] - 1}
    assert any(p.startswith("the review ran") for p in problems(review=review))


def test_a_review_with_a_failed_step_fails():
    """A step that failed means part of the normal work never ran, so the window was not the stated workload."""
    review = copy.deepcopy(REVIEW)
    step = next(iter(review["steps"]))
    review["steps"][step]["failed"] = 1
    assert f"review step failed 1 of {review['steps'][step]['runs']} times: {step}" in problems(review=review)


def test_a_detection_the_review_never_measured_has_a_blank_cell():
    review = copy.deepcopy(REVIEW)
    del review["detections"]["WebContentWrong"]
    assert "WebContentWrong: the False positives over the benign workload cell is blank" in problems(review=review)


def test_a_hand_edited_table_fails():
    assert "docs/detections.md is not what the deployed rules give now: run make detections" in \
        problems(written=TABLE.read_text().replace("TargetDown", "TargetGone", 1))


def test_a_source_over_its_budget_during_the_review_fails():
    """The review is also NOT-5's measured day: every source's pace there must be within its budget."""
    review = copy.deepcopy(REVIEW)
    source = next(iter(review["ingest"]))
    review["ingest"][source]["per_day"] = review["ingest"][source]["budget"] + 1
    assert any(p.startswith(f"{source} sent") for p in problems(review=review))


class Clock:
    """The review's clock in the tests below: each reading is a second after the last, and a sleep returns at once."""
    def __init__(self):
        self.now = time.time()

    def time(self):
        self.now += 1
        return self.now

    def sleep(self, seconds):
        pass


class FakeNoc(detections.Noc):
    """A NOC with these alerts and nothing else: no series, no line in the store, no page at the pager."""
    def __init__(self, alerts):
        super().__init__("test")
        self.now = alerts

    def get(self, port, path, **params):
        if path == "/api/v1/alerts":
            return {"data": {"alerts": self.now}}
        if path in ("/api/v1/query", "/loki/api/v1/query_range"):
            return {"data": {"result": []}}
        return []  # the pager (the webhook sink) has received nothing


def review_on(alerts, monkeypatch, tmp_path):
    """make fp-review's review, at once: a workload with no steps, on a NOC with these alerts."""
    monkeypatch.setattr(detections, "Noc", lambda lab, host: FakeNoc(alerts))
    monkeypatch.setattr(detections, "workload", lambda inv, lab="": [])
    monkeypatch.setattr(detections, "time", Clock())
    monkeypatch.setattr(detections, "NOTIFICATIONS", tmp_path / "notifications.json")
    return detections.review(inv, "test", REVIEW["minutes"], "test")


WATCHDOG = {"labels": {"alertname": "Watchdog"}, "state": "firing"}


def test_the_review_starts_while_the_watchdog_fires(monkeypatch, tmp_path):
    """Watchdog always fires, and Alertmanager sends it only to the mailbox, never to the pager (decision 0022), so it
    is no reason for the review to wait or to refuse to start."""
    assert review_on([WATCHDOG], monkeypatch, tmp_path)["pages"] == []


def test_the_review_does_not_start_while_another_alert_is_pending(monkeypatch, tmp_path):
    """Any other alert, pending or firing, could page during the review and be counted as false: the review waits for
    it, then refuses to start and names it."""
    pending = {"labels": {"alertname": "BGPSessionDown", "node": "r2"}, "state": "pending"}
    with pytest.raises(SystemExit, match="BGPSessionDown"):
        review_on([WATCHDOG, pending], monkeypatch, tmp_path)


def test_the_review_measures_every_source_the_store_keeps(monkeypatch, tmp_path):
    """The review is NOT-5's measured day for every source with a budget, so each router's command records are in its
    ingest too, though they have no heartbeat and so are not among the log sources SourceSilent watches."""
    mon = monitoring.expected(inv)
    assert len(mon["ingest"]) > len(mon["sources"])
    got = review_on([WATCHDOG], monkeypatch, tmp_path)["ingest"]
    assert sorted(got) == sorted(f"{s['node']}/{s['source']}" for s in mon["ingest"])
