"""Tool selection records (OROS JUS-3): every tool the lab runs has one, and each names a source its
maker didn't write, a measurement of our own, and what doing it without buying anything would be."""
import re
from pathlib import Path

import yaml

from netlab.records import lint_selections

ROOT = Path(__file__).resolve().parent.parent
SELECTIONS = ROOT / "docs" / "selections"
# Tools that aren't images, and the file that shows the lab really uses each one.
TOOLS = {"containerlab": ".github/workflows/ci.yml", "ansible": "requirements-ansible.txt",
         "iptables": "templates/firewall.sh.j2"}
IMAGE = re.compile(r"\b([a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*):v?\d")


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
    """Every image the lab, the hooks or CI run, and every tool CI installs, is covered by a record's `uses`."""
    covered = [u for p in SELECTIONS.glob("*.md") for u in yaml.safe_load(p.read_text().split("---\n")[1])["uses"]]
    files = [ROOT / f for f in ("inventory/network.yml", "Makefile", ".pre-commit-config.yaml")]
    images = {m for f in files + sorted((ROOT / ".github" / "workflows").glob("*.yml")) for m in IMAGE.findall(f.read_text())}
    for tool, where in TOOLS.items():
        assert tool in (ROOT / where).read_text(), f"{where} no longer mentions {tool}; update TOOLS"
    missing = sorted(t for t in images | set(TOOLS) if not any(u == t for u in covered))
    assert not missing, f"no selection record in docs/selections/ for: {missing}"
