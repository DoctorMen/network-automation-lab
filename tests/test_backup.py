"""The backup's destination check and the single-item restore's stanza cut, without a lab."""
from pathlib import Path

from netlab import backup, restore

ROOT = Path(__file__).resolve().parent.parent
R2 = """frr version 8.4.1_git
hostname r2
!
router bgp 65001
 neighbor 198.51.100.1 remote-as 65100
 !
 address-family ipv4 unicast
  aggregate-address 10.0.0.0/8 summary-only
 exit-address-family
exit
!
router ospf
exit
!
end
"""


def test_compare_names_every_difference():
    """A file missing at the destination, one with another sha256 and one nobody captured: all three are named."""
    captured = {"r1.conf": "a" * 64, "r2.conf": "b" * 64, "r3.conf": "c" * 64}
    at_destination = {"r1.conf": "a" * 64, "r2.conf": "d" * 64, "old.conf": "e" * 64}
    assert backup.compare(captured, at_destination) == [
        "r3.conf: not at the destination",
        "r2.conf: sha256 at the destination dddddddddddd, captured bbbbbbbbbbbb",
        "old.conf: at the destination but not in the capture",
    ]
    assert backup.compare(captured, dict(captured)) == []


def test_every_inventory_device_is_expected_in_a_backup():
    inv = backup.load(ROOT / "inventory" / "network.yml")
    assert backup.expected_files(inv) == [f"{r}.conf" for r in inv.routers] + [f"{f}.rules" for f in inv.firewalls]


def test_stanza_is_one_top_level_block():
    """The single item is the whole `router bgp` block, nested address-family included, and nothing after it."""
    item = restore.stanza(R2, "router bgp")
    assert item.splitlines()[0] == "router bgp 65001" and item.splitlines()[-1] == "exit"
    assert "  aggregate-address 10.0.0.0/8 summary-only" in item and "router ospf" not in item
    assert restore.stanza(R2, "router rip") == ""

