"""OROS NOT-2: every value a test, a tool or a runbook reads from a device is in monitoring/coverage.yml as
exported, derived or gap, and the lint fails when one isn't (netlab/coverage.py)."""
import copy
import shutil
from pathlib import Path

import yaml

from netlab import coverage
from netlab.inventory import load

ROOT = Path(__file__).resolve().parent.parent
inv = load(ROOT / "inventory" / "network.yml")


def listed():
    return yaml.safe_load(coverage.COVERAGE.read_text())


def test_every_read_is_listed():
    reads, odd = coverage.found()
    assert reads, "the lint found no reads at all"
    assert coverage.check(listed(), reads, odd, inv) == []


def test_an_unlisted_read_fails(tmp_path):
    """A new live test that reads the ARP table from r1, which nothing lists: the lint names it and where."""
    for rel in ("tests/live", "netlab", "ansible", "docs/runbooks"):
        shutil.copytree(ROOT / rel, tmp_path / rel, ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / "tests/live/test_arp.py").write_text(
        'def test_arp(node):\n    assert "10.0.12.1" in node("r1").run("ip", "neigh", "show").stdout\n')
    reads, odd = coverage.found(tmp_path)
    problems = coverage.check(listed(), reads, odd, inv)
    assert problems == ["tests/live/test_arp.py:2 (test_arp) reads `ip neigh show`, which monitoring/coverage.yml does not list"]


def test_a_read_nobody_makes_any_more_fails():
    reads, odd = coverage.found()
    cov = listed()
    cov["reads"].append({"read": "vtysh show ip nht", "value": "x", "status": "gap", "fallback": "y"})
    assert "monitoring/coverage.yml lists `vtysh show ip nht`, which nothing reads any more" in coverage.check(cov, reads, odd, inv)


def test_every_entry_is_exported_derived_or_gap_with_its_evidence():
    reads, odd = coverage.found()
    for change, expect in ((dict(status="unknown"), "is not one of"), (dict(status="exported", metric=None), "names no metric"),
                           (dict(status="gap", fallback=None), "a gap needs its fallback"),
                           (dict(status="derived", how=None, metric="up"), "derived needs a metric or logql, and how")):
        cov = copy.deepcopy(listed())
        cov["reads"][0].update(change)
        assert any(expect in p for p in coverage.check(cov, reads, odd, inv)), change


def test_an_unlisted_scraper_fails():
    """A Prometheus job coverage.yml doesn't name is a scraper nobody has vetted."""
    reads, odd = coverage.found()
    cov = listed()
    del cov["collectors"]["frr"]
    problems = coverage.check(cov, reads, odd, inv)
    assert "Prometheus job frr is a scraper monitoring/coverage.yml does not list" in problems
    assert any("alert rules use frr_bgp_peer_state" in p for p in problems)


def test_a_new_command_program_must_be_placed(tmp_path):
    """A program the rules don't know is neither a read nor an action until coverage.yml says which."""
    for rel in ("tests/live", "netlab", "ansible", "docs/runbooks"):
        shutil.copytree(ROOT / rel, tmp_path / rel, ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / "tests/live/test_ethtool.py").write_text('def test_x(node):\n    node("r1").run("ethtool", "-S", "eth1")\n')
    reads, odd = coverage.found(tmp_path)
    assert any("runs `ethtool`" in p for p in coverage.check(listed(), reads, odd, inv))


def test_reads_are_told_from_writes():
    assert coverage.classify(["vtysh", "-c", "show bgp neighbors 198.51.100.1 json"]) == [("read", "vtysh show bgp neighbors <arg>")]
    assert coverage.classify(["vtysh", "-c", "conf t", "-c", "router bgp 65001"]) == [("action", "vtysh conf"), ("action", "vtysh router")]
    assert coverage.classify(["iptables", "-I", "INPUT", "-j", "DROP"]) == [("action", "iptables write")]
    assert coverage.classify(["iptables", "-t", "raw", "-vnxL", "PREROUTING"]) == [("read", "iptables -L")]
    assert coverage.classify(["ip", "link", "set", "eth2", "down"]) == [("action", "ip link set")]
    assert coverage.classify(["sh", "-c", "iptables -S; iptables -t raw -S"]) == [("read", "iptables -S")] * 2
    assert coverage.classify(["sh", "-ec", "ls /lib/modules 2>/dev/null"]) == [("read", "ls /lib/modules")]
