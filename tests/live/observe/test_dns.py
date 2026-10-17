"""The lab's DNS is the inventory (OROS FND-4, decision 0032): CoreDNS on the NOC serves the names netlab
renders from inventory/network.yml, and nothing else. It is a sidecar, so only the full lab has it."""
import re
import subprocess

import pytest

from ..conftest import wait_for

NAME = re.compile(r"^Name:\s+(\S+)\s+Address:\s+(\S+)", re.M)
PTR = re.compile(r"name = (\S+)")


@pytest.fixture(scope="module")
def dns(expected, lab_name, mon):
    d = expected.get("dns")
    if not d:
        pytest.skip("the inventory has no dns block")
    sidecar = f"clab-{lab_name}-{mon['host']}-dns"
    if subprocess.run(["docker", "inspect", sidecar], capture_output=True).returncode:
        pytest.skip(f"{sidecar} is not running: the DNS is a sidecar, so only the full lab (make deploy) has it")
    return d


def lookup(node, src, name, server):
    """(rc, stdout) of a query from src to the server; busybox nslookup."""
    out = node(src).run("nslookup", name, server, check=False, timeout=15)
    return out.returncode, out.stdout + out.stderr


def test_every_inventory_name_resolves_to_its_address(node, dns):
    """From LAN-B, every device name the inventory implies resolves at the NOC's server to that device's own address, and the address resolves back to the name."""
    # fw1 lets LAN-A reach only the web and the internet, so a user on LAN-A can't ask (RISK-67); h2 can.
    assert wait_for(lambda: lookup(node, "h2", next(iter(dns["names"])), dns["server"])[0] == 0, timeout=60, interval=2), \
        "the NOC's DNS answers nothing"
    wrong = []
    for fqdn, address in dns["names"].items():
        rc, out = lookup(node, "h2", fqdn, dns["server"])
        got = dict(NAME.findall(out)).get(fqdn)
        if rc or got != address:
            wrong.append(f"{fqdn}: got {got!r} (rc {rc}), inventory says {address}")
        rc, out = lookup(node, "h2", address, dns["server"])
        back = [n.rstrip(".") for n in PTR.findall(out)]  # the hosts file's line gives the name and its short form
        if rc or fqdn not in back:
            wrong.append(f"{address}: reverse got {back!r} (rc {rc}), inventory says {fqdn}")
    assert not wrong, "\n".join(wrong)


def test_a_name_the_inventory_lacks_is_refused(node, dns):
    """A name no inventory entry implies gets NXDOMAIN, not an answer from anywhere else: the zone is the inventory and there is no forwarder."""
    rc, out = lookup(node, "h2", f"nothere.{dns['zone']}", dns["server"])
    assert rc != 0 and "NXDOMAIN" in out, out
