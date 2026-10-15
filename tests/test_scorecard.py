"""The OROS scorecard covers every requirement, adds up, and only names tests that exist."""
import re
from pathlib import Path

from netlab.records import names_a_test

ROOT = Path(__file__).resolve().parent.parent
OROS = ROOT / "docs" / "oros"
STATUSES = ("pass", "partial", "fail")


def requirement_ids() -> list[str]:
    return re.findall(r"^\d+\. \*\*([A-Z]{3}-\d+) ", (OROS / "standard.md").read_text(), re.M)


def scorecard_rows() -> list[list[str]]:
    """[id, title, status, proof] for each table row of the scorecard."""
    rows = [line.strip("| ").split(" | ") for line in (OROS / "scorecard.md").read_text().splitlines()
            if re.match(r"\| [A-Z]{3}-\d+ \|", line)]
    assert all(len(r) == 4 for r in rows), [r for r in rows if len(r) != 4]
    return rows


def test_scorecard_scores_every_requirement_once():
    ids = [r[0] for r in scorecard_rows()]
    assert len(requirement_ids()) == 61
    assert ids == requirement_ids(), "the scorecard must list every requirement once, in the standard's order"


def test_scorecard_totals_add_up():
    statuses = [r[2] for r in scorecard_rows()]
    assert set(statuses) <= set(STATUSES), set(statuses) - set(STATUSES)
    totals = ", ".join(f"{statuses.count(s)} {s}" for s in STATUSES)
    for doc in (OROS / "scorecard.md", ROOT / "README.md"):
        assert f"**{totals}.**" in doc.read_text(), f"{doc.relative_to(ROOT)} should say **{totals}.**"


def test_every_pass_names_a_test_that_exists():
    """A pass is only a pass with a test behind it, and no row may name a test that isn't there."""
    for id_, _, status, proof in scorecard_rows():
        tests = re.findall(r"`(tests/[\w/]+\.py::\w+)`", proof)
        if status == "pass":
            assert tests, f"{id_} passes without naming a test"
        missing = [t for t in tests if not names_a_test(t)]
        assert not missing, f"{id_} names tests that don't exist: {missing}"
