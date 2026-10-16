"""OROS NOT-6, the detection coverage table (decision 0027): one row per deployed rule with no blank cell,
docs/detections.md exactly what the rules give now, and every false-positive figure from the current
review cycle, measured on the rules that run now."""
import copy
import subprocess
import time
from datetime import date, timedelta

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
    assert sorted(detections.detections_in(TABLE.read_text())) == monitoring.expected(inv)["alerts"]


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
    listed = cell.split(":")[0].removeprefix("every scrape target, on ").split(", ")
    exporters = set(monitoring.expected(inv)["exporters"]) | {monitoring.host(inv)}
    assert set(listed) == exporters, cell


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
