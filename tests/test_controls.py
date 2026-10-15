"""The control register is complete: every claim and every fw1 rule has a threat, a failure mode and a real test."""
import subprocess
import sys
from pathlib import Path

import pytest

from netlab import controls
from netlab.inventory import load as load_inventory

ROOT = Path(__file__).resolve().parent.parent
REGISTER = controls.load()
GOOD = {"id": "demo", "claim": "c", "test": "tests/test_controls.py::test_register_lints_clean",
        "period": "P31D", "threat": "t", "fails_when": "f"}


@pytest.fixture(scope="module")
def known_tests() -> set[str]:
    """Every pytest node id under tests/, live ones included. Collecting them needs no lab."""
    out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "tests"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return {line for line in out.splitlines() if "::" in line}


def readme_claims() -> list[str]:
    """The Behaviour column of the README's 'What it proves' table, header row skipped."""
    table = (ROOT / "README.md").read_text().split("## What it proves")[1].split("\n## ")[0]
    rows = [line for line in table.splitlines() if line.startswith("| ")]
    return [row.split(" | ")[0].removeprefix("| ") for row in rows[1:]]


def test_register_lints_clean(known_tests):
    assert controls.lint(REGISTER, known_tests) == []


def test_every_readme_claim_has_an_entry():
    claims = {c["claim"] for c in REGISTER}
    missing = [row for row in readme_claims() if row not in claims]
    assert readme_claims() and not missing, f"README claims with no register entry (copy the row word for word): {missing}"


def test_every_firewall_rule_has_an_entry():
    inv = load_inventory(ROOT / "inventory" / "network.yml")
    ids = {c["id"] for c in REGISTER}
    # Every rendered firewall script ends with the default-drop rule, which isn't in the inventory list.
    rules = [f"{fw}:{r['name']}" for fw, spec in inv.firewalls.items() for r in spec["rules"]]
    rules += [f"{fw}:default-drop" for fw in inv.firewalls]
    missing = [r for r in rules if r not in ids]
    assert not missing, f"firewall rules with no register entry: {missing}"


def test_lint_rejects_an_entry_without_a_failure_mode(known_tests):
    assert controls.lint([GOOD], known_tests) == []
    no_failure_mode = {k: v for k, v in GOOD.items() if k != "fails_when"}
    assert controls.lint([no_failure_mode], known_tests) == ["demo: no fails_when"]


def test_lint_rejects_an_entry_naming_a_missing_test(known_tests):
    missing = "tests/live/test_controls.py::test_that_does_not_exist"
    assert controls.lint([{**GOOD, "test": missing}], known_tests) == [f"demo: unknown test {missing}"]
