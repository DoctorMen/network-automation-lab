"""Decision records name their constraint, alternatives, outside source, stake and decider."""
import re
from pathlib import Path

from netlab.records import lint

ROOT = Path(__file__).resolve().parent.parent
DECISIONS = ROOT / "docs" / "decisions"
RECORD = DECISIONS / "0001-p2p-31-links.md"


def record_with(tmp_path, old, new):
    """A copy of a real record with one change, so each test breaks exactly one thing."""
    text = RECORD.read_text()
    assert re.search(old, text), old
    path = tmp_path / RECORD.name
    path.write_text(re.sub(old, new, text, count=1))
    return path


def test_decision_records_lint_clean():
    """Every record in docs/decisions has all fields, a 'do nothing' option and an outside source."""
    assert lint(DECISIONS) == []


def test_record_without_decider_is_reported(tmp_path):
    problems = lint(record_with(tmp_path, r"decider: .*\n", ""))
    assert "0001-p2p-31-links.md: missing decider" in problems


def test_record_citing_only_the_repo_is_reported(tmp_path):
    in_repo = ("sources:\n  - README.md\n"
               "  - https://github.com/DoctorMen/network-automation-lab/commit/ed58c1e\n")
    problems = lint(record_with(tmp_path, r"sources:\n(  - .*\n)+", in_repo))
    assert any("no outside source" in p for p in problems)


def test_failure_modes_are_optional_but_complete(tmp_path):
    """A failover record may list failure modes; each needs a mitigation and a test that exists."""
    good = ("failure_modes:\n  - mode: r1-r3 link goes down\n    mitigation: OSPF reroutes via r2\n"
            "    test: tests/live/test_failover.py::test_traffic_survives_r1_r3_link_failure\nstake:")
    assert lint(record_with(tmp_path, r"stake:", good)) == []
    vague = "failure_modes:\n  - mode: link goes down\n    test: tests/live/test_failover.py::test_made_up\nstake:"
    problems = lint(record_with(tmp_path, r"stake:", vague))
    assert any("missing mitigation" in p for p in problems)


def test_untested_failure_mode_must_say_why(tmp_path):
    """A failure mode without a test is allowed only as a stated decision, and a test it names must exist."""
    def modes(test):
        return f"failure_modes:\n  - mode: m\n    mitigation: accepted\n    test: {test}\nstake:"
    assert lint(record_with(tmp_path, r"stake:", modes("none (accepted risk, no second ISP)"))) == []
    assert any("say why" in p for p in lint(record_with(tmp_path, r"stake:", modes("none"))))
    made_up = "tests/live/test_failover.py::test_made_up"
    assert any(f"{made_up} does not exist" in p for p in lint(record_with(tmp_path, r"stake:", modes(made_up))))


def test_readme_design_decisions_link_their_records():
    """Each bullet under the README's 'Design decisions' links a decision record that exists."""
    section = (ROOT / "README.md").read_text().split("## Design decisions")[1].split("\n## ")[0]
    bullets = [line for line in section.splitlines() if line.startswith("- ")]
    assert bullets
    for bullet in bullets:
        links = re.findall(r"\]\((docs/decisions/\d{4}-[\w-]+\.md)\)", bullet)
        assert links and all((ROOT / link).exists() for link in links), f"no record linked: {bullet[:60]}"


def test_misnamed_record_is_reported(tmp_path):
    """A record whose file name lint can't parse is reported, not skipped."""
    (tmp_path / RECORD.name).write_text(RECORD.read_text())
    (tmp_path / "009-typo.md").write_text(RECORD.read_text())
    assert lint(tmp_path) == ["009-typo.md: not named NNNN-slug.md, so it is not linted"]
