"""A pull request can't pass the change-record check with its lab-parity section empty, filler or missing."""
import json
import subprocess
import sys
from pathlib import Path

import yaml

from netlab.changerecord import parity_problems

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = (ROOT / ".github" / "pull_request_template.md").read_text()
FILLED = TEMPLATE.replace("-->\n", "-->\nThe lab has no switches, so the VLAN side of this change is untested.\n")


def test_a_filled_section_passes():
    assert parity_problems(FILLED) == []
    assert parity_problems("## Risks the lab could not cover\nNone: no device config changes, docs only.") == []


def test_the_untouched_template_fails():
    """The template's guidance is a comment, so leaving it as it is counts as empty."""
    assert parity_problems(TEMPLATE) != []


def test_an_empty_or_filler_section_fails():
    for answer in ("", "   \n\n", "N/A", "- none", "TBD.", "n/a\n"):
        body = f"## How it was tested\nmake live\n\n## Risks the lab could not cover\n{answer}\n## Notes\nlater"
        assert parity_problems(body) != [], f"{answer!r} passed"


def test_a_missing_section_fails():
    assert parity_problems("## What changes\nBumped OSPF cost on r1.") != []
    assert parity_problems(None) != [], "a pull request with no description passed"
    # A heading inside the guidance comment is not a section.
    assert parity_problems("<!--\n## Risks the lab could not cover\nhidden\n-->") != []


def test_an_issue_number_does_not_end_the_section():
    """Only a Markdown heading ends the section, so an answer that starts with '#42' still counts."""
    body = "## Risks the lab could not cover\n#42 has the same risk: the lab has no switches.\n## Notes\nlater"
    assert parity_problems(body) == []


def test_the_check_reads_the_github_event(tmp_path):
    """The CI job passes $GITHUB_EVENT_PATH; the exit code is what turns the check red."""
    def check(body):
        event = tmp_path / "event.json"
        event.write_text(json.dumps({"action": "edited", "pull_request": {"number": 7, "body": body}}))
        return subprocess.run([sys.executable, "-m", "netlab.changerecord", str(event)], cwd=ROOT,
                              capture_output=True, text=True).returncode
    assert check(FILLED) == 0
    assert check(TEMPLATE) == 1
    assert check(None) == 1


def test_ci_runs_the_check_when_the_description_changes():
    """Editing the description re-runs the check, so a record fixed after review turns green."""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "change-record.yml").read_text())
    # YAML 1.1 reads the key `on` as True.
    assert "edited" in workflow[True]["pull_request"]["types"]
    steps = [s.get("run", "") for job in workflow["jobs"].values() for s in job["steps"]]
    assert any("netlab.changerecord" in s and "$GITHUB_EVENT_PATH" in s for s in steps)
