"""The risk register (OROS JUS-4) stays tied to the config: every risky line the lab really has is
covered by an entry with its reasoning, compensating test, owner and review date, and an entry whose
lines are gone is flagged for closing. Whether management has seen an entry can't be checked here,
only that the record has a place for it."""
import copy
from datetime import date

import pytest
import yaml

from netlab.inventory import load
from netlab.render import render_all
from netlab import risks
from netlab.risks import DECISIONS, REGISTER, ROOT, SELECTIONS, check, summary, scan

ENTRIES = yaml.safe_load(REGISTER.read_text())


@pytest.fixture(scope="module")
def build(tmp_path_factory):
    out = tmp_path_factory.mktemp("build")
    render_all(load(ROOT / "inventory" / "network.yml"), out)
    return out


def without(risk_id):
    return [e for e in ENTRIES if e["id"] != risk_id]


@pytest.mark.review
def test_every_risky_config_line_has_a_risk_record(build):
    """Each risky line in the rendered configs, the Ansible files and the inventory maps to a register entry, every entry is complete, and no review is overdue."""
    assert check(ENTRIES, build, today=date.today()) == []


def test_a_deleted_risk_names_its_config_line(build):
    """Take RISK-1 out of the register and the scan names r2's frr.conf line it accepted."""
    problems = check(without("RISK-1"), build)
    line = next(n for n, text in enumerate((build / "r2" / "frr.conf").read_text().splitlines(), 1)
                if text.strip() == "no bgp ebgp-requires-policy")
    assert (f"build/r2/frr.conf:{line}: `no bgp ebgp-requires-policy`: eBGP accepts every route, with no inbound policy "
            "required, and no entry in docs/risks.yml covers it (detector ebgp-no-policy)") in problems


def test_fixing_the_config_flags_the_risk_as_stale(build, tmp_path):
    """Fix the firewall line without closing RISK-4 and the register says to close it."""
    fixed = tmp_path / "build"
    render_all(load(ROOT / "inventory" / "network.yml"), fixed)
    script = fixed / "fw1" / "firewall.sh"
    script.write_text(script.read_text().replace("-p icmp -j ACCEPT", "-p icmp --icmp-type echo-request -j ACCEPT"))
    assert check(ENTRIES, fixed) == ["RISK-4: no config line matches icmp-any-type any more; close the risk, or fix the detector"]


def test_an_edge_router_line_is_scanned_like_a_firewall_line(build, tmp_path):
    """r2's edge.sh is scanned too: take RISK-23 out and the scan names its every-ICMP-type line; give that line an --icmp-type and RISK-23 is flagged to close."""
    line = next(n for n, text in enumerate((build / "r2" / "edge.sh").read_text().splitlines(), 1) if '"wan-icmp"' in text)
    assert [p for p in check(without("RISK-23"), build) if "(detector edge-icmp-any-type)" in p] == [
        f"build/r2/edge.sh:{line}: `iptables -A INPUT -i eth3 -p icmp -j ACCEPT -m comment --comment \"wan-icmp\"`: the "
        "internet edge lets every ICMP type in to the router itself, and no entry in docs/risks.yml covers it (detector edge-icmp-any-type)"]
    fixed = tmp_path / "build"
    render_all(load(ROOT / "inventory" / "network.yml"), fixed)
    script = fixed / "r2" / "edge.sh"
    script.write_text(script.read_text().replace("-p icmp -j ACCEPT", "-p icmp --icmp-type echo-request -j ACCEPT"))
    assert check(ENTRIES, fixed) == ["RISK-23: no config line matches edge-icmp-any-type any more; close the risk, or fix the detector"]


def test_every_risk_a_decision_record_accepts_is_in_the_register(build, tmp_path):
    """A decision record that accepts a risk must name its register entry, and that entry must exist: take
    the name off 0009's BFD mode, or take RISK-12 out of the register, and both are reported."""
    decisions = tmp_path / "decisions"
    decisions.mkdir()
    for record in DECISIONS.glob("*.md"):
        (decisions / record.name).write_text(record.read_text().replace("accepted risk RISK-11 in docs/risks.yml, ", "accepted risk, "))
    problems = check(without("RISK-12"), build, decisions=decisions)
    assert ("0009-failover.md: accepts the risk 'BFD false positive (a busy router misses 3 packets in 0.9 s and drops a "
            "healthy adjacency)' but names no entry in docs/risks.yml (write it as: none (accepted risk RISK-n in "
            "docs/risks.yml))") in problems
    assert any(p.startswith("0009-failover.md: accepts the risk 'single edge router (r2) or single ISP link fails' as "
                            "RISK-12, which docs/risks.yml doesn't hold") for p in problems)


def test_a_selection_record_cites_only_risks_in_the_register(build, tmp_path):
    """A selection record that points at a RISK id the register doesn't hold is reported: frr.md citing RISK-50 for its Alpine risk."""
    selections = tmp_path / "selections"
    selections.mkdir()
    for record in SELECTIONS.glob("*.md"):
        (selections / record.name).write_text(record.read_text().replace("RISK-5 ", "RISK-50 "))
    assert check(ENTRIES, build, selections=selections) == ["frr.md: cites RISK-50, which docs/risks.yml doesn't hold"]


def test_every_risk_record_is_complete():
    """A record without its presentation field, with a likelihood off the scale, a missing test, or a presentation with no date or link, is reported."""
    bad = copy.deepcopy(ENTRIES)
    del bad[0]["presented_to"]
    bad[1]["likelihood"] = 7
    bad[2]["compensating_control"] = "tests/live/test_routing.py::test_that_does_not_exist"
    bad[3].update(presented_to="the CTO", presented_on=None, presented_evidence="in the hallway")
    problems = check(bad, ROOT / "build-that-does-not-exist")  # no config to scan: lint problems only, plus stale
    assert "RISK-1: missing presented_to (pending until management has seen it)" in problems
    assert "RISK-2: likelihood 7 is not 1 to 5" in problems
    assert "RISK-3: compensating_control tests/live/test_routing.py::test_that_does_not_exist is not a test that exists, or none (reason)" in problems
    assert "RISK-4: presented to the CTO but presented_on is not a date" in problems
    assert "RISK-4: presented to the CTO but presented_evidence is not a link" in problems


def test_summary_lists_what_management_has_not_seen(build):
    """`make risks` ends with every entry still waiting to be presented, so pending is never silent."""
    text = summary(ENTRIES, scan(build))
    pending = [e["id"] for e in ENTRIES if e["presented_to"] == "pending"]
    assert f"Not yet presented to management: {', '.join(pending)}" in text


def test_make_risks_names_an_incomplete_entry_instead_of_crashing(tmp_path, monkeypatch, capsys):
    """An entry with no likelihood is reported as a PROBLEM line and `make risks` exits 1, with no traceback from the summary."""
    bad = copy.deepcopy(ENTRIES)
    del bad[0]["likelihood"]
    register = tmp_path / "risks.yml"
    register.write_text(yaml.safe_dump(bad))
    monkeypatch.setattr(risks, "REGISTER", register)
    assert risks.main() == 1
    assert f"PROBLEM: {bad[0]['id']}: missing likelihood" in capsys.readouterr().err
