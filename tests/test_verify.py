"""netlab.verify's rules, offline: the newest kernel by version, not by spelling, and a replaced or missing daemon is caught."""
from netlab.verify import daemons_status, kernel_status, tc_classes

DAEMONS = "zebra=yes\nbgpd=no\nospfd=yes\nstaticd=yes\nvtysh_enable=yes\n"
RUNNING = ["/sbin/tini", "/usr/lib/frr/watchfrr", "/usr/lib/frr/zebra", "/usr/lib/frr/ospfd", "/usr/lib/frr/staticd"]


def test_newest_kernel_is_found_by_version():
    """6.8.0-1020 is newer than 6.8.0-1017, and 6.10 than 6.9, though text sorting says otherwise for the second."""
    assert kernel_status("6.8.0-1017-azure", ["6.8.0-1017-azure", "6.8.0-1020-azure"]).startswith("not in effect")
    assert kernel_status("6.10.0-1-generic", ["6.9.0-5-generic", "6.10.0-1-generic"]).startswith("in effect")
    assert kernel_status("6.8.0-1017-azure", []).startswith("nothing to compare")


def test_replaced_or_stopped_daemon_is_not_in_effect():
    assert daemons_status(RUNNING, DAEMONS).startswith("in effect")
    replaced = [e + " (deleted)" if e.endswith("staticd") else e for e in RUNNING]
    assert "staticd still run a binary replaced on disk" in daemons_status(replaced, DAEMONS)
    stopped = [e for e in RUNNING if not e.endswith("ospfd")]
    assert "ospfd enabled in /etc/frr/daemons but not running" in daemons_status(stopped, DAEMONS)


def test_tc_class_counters_are_parsed():
    show = ("class htb 1:10 parent 1:1 prio 0 rate 15Mbit ceil 20Mbit burst 1597b cburst 1600b \n"
            " Sent 58960 bytes 240 pkt (dropped 0, overlimits 0 requeues 0) \n backlog 0b 0p requeues 0\n\n"
            "class htb 1:20 parent 1:1 prio 1 rate 5Mbit ceil 20Mbit burst 1600b cburst 1600b \n"
            " Sent 30210430 bytes 3187 pkt (dropped 0, overlimits 651 requeues 0) \n backlog 37600b 4p requeues 0\n")
    assert tc_classes(show) == {
        "1:10": {"rate": "15mbit", "ceil": "20mbit", "bytes": 58960, "packets": 240, "queued": 0},
        "1:20": {"rate": "5mbit", "ceil": "20mbit", "bytes": 30210430, "packets": 3187, "queued": 4},
    }
