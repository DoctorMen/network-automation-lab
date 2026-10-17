"""The OROS scorecard covers every requirement, adds up, and only names tests that exist."""
import re
from pathlib import Path

import yaml

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


def test_the_risk_register_row_counts_the_register():
    """JUS-4's figures are the register's own: its entries and accepted risks, which name a compensating test and
    which say why there is none, which a detector ties to config lines and which it can't (in the row and in the
    risk-register control), and how many `make risks` lists as not yet presented. A new entry fails this until the
    row says so."""
    register = yaml.safe_load((ROOT / "docs" / "risks.yml").read_text())
    row = next(r[3] for r in scorecard_rows() if r[0] == "JUS-4")
    untested = [e["id"] for e in register if str(e["compensating_control"]).startswith("none (")]
    untied = [e["id"] for e in register if not e.get("detectors")]
    pending = [e["id"] for e in register if e["presented_to"] == "pending"]
    figures = re.search(r"records (\d+) entries, (\d+) accepted risks .*? (\d+) name a compensating test; (.*?) say why there is "
                        r"none\. (\d+) are tied by a detector to the config lines they accept; (.*?) have no config line to tie\.", row)
    assert figures, "JUS-4 no longer states the register's figures in the form this test reads"
    entries, accepted, tested, no_test, tied, no_line = figures.groups()
    assert (int(entries), int(accepted)) == (len(register), sum(e["kind"] == "accepted-risk" for e in register))
    assert (int(tested), re.findall(r"RISK-\d+", no_test)) == (len(register) - len(untested), untested)
    assert (int(tied), re.findall(r"RISK-\d+", no_line)) == (len(register) - len(untied), untied)
    assert re.search(rf"`make risks` lists all {len(pending)} as not yet presented", row) and pending == [e["id"] for e in register]
    control = next(c for c in yaml.safe_load((ROOT / "docs" / "controls.yml").read_text())["controls"] if c["id"] == "risk-register")
    assert re.findall(r"RISK-\d+", re.search(r"a gap with no config line \((.*?)\)", control["fails_when"])[1]) == untied
