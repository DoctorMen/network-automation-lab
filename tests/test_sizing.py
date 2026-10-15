"""Sizing claims quote measured data, and that data is committed next to them."""
import json
import re
from pathlib import Path

from netlab.measure import mib

ROOT = Path(__file__).resolve().parent.parent
SIZING = ROOT / "docs" / "sizing"
# The one phrasing both docs use, so a test can hold each figure to its data.
CLAIM = re.compile(r"measured at ([\d.]+) MiB for all (\d+) nodes in the `([\w-]+)` environment")


def newest(env: str) -> dict:
    runs = [d for d in (json.loads(p.read_text()) for p in (SIZING / "data").glob("*.json")) if d["env"] == env]
    assert runs, f"no data for environment {env!r} in docs/sizing/data/"
    return max(runs, key=lambda d: d["date"])


def test_ram_figures_match_the_newest_data():
    """Each RAM figure in the README and the sizing doc is within 1 MiB of that environment's newest data file."""
    for doc in (ROOT / "README.md", SIZING / "README.md"):
        claims = CLAIM.findall(doc.read_text())
        assert claims, f"{doc.relative_to(ROOT)} quotes no measured RAM figure"
        for mib, nodes, env in claims:
            data = newest(env)
            assert abs(float(mib) - data["total_mib"]) <= 1, \
                f"{doc.relative_to(ROOT)} says {mib} MiB in {env}, the newest data says {data['total_mib']} MiB"
            assert int(nodes) == data["nodes"], f"{doc.relative_to(ROOT)} says {nodes} nodes, the data has {data['nodes']}"
    assert "](docs/sizing/README.md)" in (ROOT / "README.md").read_text(), "README's RAM figure should link the sizing doc"


def test_sizing_doc_links_all_its_data():
    """The sizing doc links every data file, and every file it links exists."""
    linked = set(re.findall(r"\]\((data/[^)]+\.json)\)", (SIZING / "README.md").read_text()))
    on_disk = {f"data/{p.name}" for p in (SIZING / "data").glob("*.json")}
    assert linked, "docs/sizing/README.md links no data"
    assert not linked - on_disk, f"linked but missing: {sorted(linked - on_disk)}"
    assert not on_disk - linked, f"data nobody links: {sorted(on_disk - linked)}"


def test_docker_stats_units_are_read_as_binary():
    """make measure reads docker stats' KiB/MiB/GiB correctly, so the committed figures are right."""
    assert mib("23.89MiB") == 23.89
    assert mib("512KiB") == 0.5
    assert mib("1.5GiB") == 1536
    assert mib("0B") == 0
