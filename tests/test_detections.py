"""OROS NOT-6, the detection coverage table (decision 0027): one row per deployed rule with no blank cell,
docs/detections.md exactly what the rules give now, and every false-positive figure from the current
review cycle, measured on the rules that run now."""
import copy
from datetime import date, timedelta

from netlab import detections, monitoring
from netlab.inventory import load
from netlab.detections import TABLE, check, fingerprint, load_all, rules_by_detection

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
