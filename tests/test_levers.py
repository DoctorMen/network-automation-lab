"""The outside-levers contact sheet is complete and fresh: every lever has a contact and an evidence
list, checked within the sheet's cycle (OROS REC-7). The DDoS lever is the blackhole the lab configures."""
from datetime import timedelta
from pathlib import Path

import yaml

from netlab import levers
from netlab.inventory import load

ROOT = Path(__file__).resolve().parent.parent
SHEET = yaml.safe_load(levers.SHEET.read_text())


def sheet_with(tmp_path, change):
    """A copy of the real sheet with one entry changed, so each test breaks exactly one thing."""
    doc = yaml.safe_load(levers.SHEET.read_text())
    change(doc["levers"][0])
    path = tmp_path / "levers.yml"
    path.write_text(yaml.safe_dump(doc))
    return path


def test_contact_sheet_lints_clean():
    """Every entry has a holder, a contact and an evidence list, checked within cycle_days of today."""
    assert levers.lint() == []


def test_entry_without_evidence_or_contact_is_reported(tmp_path):
    threat = SHEET["levers"][0]["threat"]
    assert levers.lint(sheet_with(tmp_path, lambda e: e.update(evidence=[]))) == [f"{threat}: no evidence"]
    assert levers.lint(sheet_with(tmp_path, lambda e: e.pop("contact"))) == [f"{threat}: no contact"]


def test_stale_check_is_reported():
    """The day after the cycle runs out, every entry checked on the oldest date goes red."""
    oldest = min(e["checked"] for e in SHEET["levers"])
    late = oldest + timedelta(days=SHEET["cycle_days"] + 1)
    assert levers.lint(today=late - timedelta(days=1)) == []
    assert any("last checked" in p for p in levers.lint(today=late))


def test_ddos_lever_is_the_blackhole_the_lab_configures():
    """The sheet's DDoS lever names the community the inventory renders, and its runbook exists."""
    rtbh = load(ROOT / "inventory" / "network.yml").raw["rtbh"]
    ddos = next(e for e in SHEET["levers"] if e["threat"].startswith("DDoS"))
    assert rtbh["community"] in ddos["lever"]
    assert "docs/runbooks/ddos-rtbh.md" in ddos["lever"] and (ROOT / "docs/runbooks/ddos-rtbh.md").exists()
