"""Tool selection records (OROS JUS-3): every tool the lab runs has one, and each names a source its
maker didn't write, a measurement of our own, and what doing it without buying anything would be."""
import re
from pathlib import Path

import yaml

from netlab.records import COMMENT, IMAGE, TOOLS, lint_selections, tools_in_use

ROOT = Path(__file__).resolve().parent.parent
SELECTIONS = ROOT / "docs" / "selections"


def copy_with(tmp_path, old, new):
    text = (SELECTIONS / "frr.md").read_text()
    assert re.search(old, text, re.S), old
    folder = tmp_path / "selections"
    folder.mkdir()
    (folder / "frr.md").write_text(re.sub(old, new, text, count=1, flags=re.S))
    return lint_selections(folder)


def test_every_selection_record_lints_clean():
    """Every record has its constraint, alternatives, a no-purchase line, staffing, and a source independent of the seller."""
    assert lint_selections(SELECTIONS) == []


def test_sources_from_the_seller_alone_are_rejected(tmp_path):
    """A record backed only by the maker's own pages has no independent source."""
    problems = copy_with(tmp_path, r"independent_sources:\n.*?\n---",
                         "independent_sources:\n  - https://docs.frrouting.org/en/latest/about.html\n"
                         "  - https://github.com/FRRouting/frr\n---")
    assert "frr.md: https://docs.frrouting.org/en/latest/about.html is the seller's own site, not an independent source" in problems
    assert "frr.md: no independent source" in problems


def test_outside_pages_alone_are_not_enough(tmp_path):
    """Independent reading without a measurement of our own is still reported."""
    problems = copy_with(tmp_path, r"independent_sources:\n.*?\n---",
                         "independent_sources:\n  - https://en.wikipedia.org/wiki/FRRouting\n---")
    assert problems == ["frr.md: no measurement of our own (a test or data file in this repo)"]


def test_missing_no_purchase_line_is_reported(tmp_path):
    """A record with no no_purchase line is reported, and nothing else is."""
    problems = copy_with(tmp_path, r"no_purchase: [^\n]*\n", "")
    assert problems == ["frr.md: missing no_purchase"]


def test_every_tool_has_a_selection_record():
    """Every image the lab, the hooks or CI run, and every other tool the repo uses (TOOLS in netlab/records.py), is covered by a record's `uses`."""
    covered = [u for p in SELECTIONS.glob("*.md") for u in yaml.safe_load(p.read_text().split("---\n")[1])["uses"]]
    for tool, (where, text) in TOOLS.items():
        assert text in (ROOT / where).read_text(), f"{where} no longer has {text!r} for {tool}; update TOOLS"
    missing = sorted(t for t in tools_in_use() if t not in covered)
    assert not missing, f"no selection record in docs/selections/ for: {missing}"


def test_image_names_are_found_with_or_without_a_namespace():
    """alpine:3.20 and python:3.12 count as images; a digest, a host and port, a time or a comment doesn't."""
    text = ("image: frrouting/frr:v8.4.1@sha256:0f8c17\n  - run: docker run --rm alpine:3.20 sh\n  python:3.12\n"
            "digest: sha256:0f8c174d\ncurl http://localhost:8080/x\nlocalhost:8080\nstart: \"04:00\"\n"
            "10.0.0.1:80\n# h2:22 stays inside\n")
    assert sorted(IMAGE.findall(COMMENT.sub("", text))) == ["alpine", "frrouting/frr", "python"]


def test_a_record_may_cite_tests_that_arrive_with_its_tool(tmp_path):
    """Until the lab runs a tool, its record may cite a test that comes with the tool; once the tool runs, that test must exist."""
    text = (SELECTIONS / "frr.md").read_text()
    text = re.sub(r"independent_sources:\n.*?\n---", "independent_sources:\n  - tests/live/test_future.py::test_it\n---", text, flags=re.S)
    (tmp_path / "frr.md").write_text(text)
    assert lint_selections(tmp_path, in_use=set()) == []
    assert lint_selections(tmp_path, in_use={"frrouting/frr"}) == [
        "frr.md: source tests/live/test_future.py::test_it is neither a URL nor a test or file in this repo",
        "frr.md: no independent source"]
