"""Named accounts and command accounting on the routers we own (OROS ACC-1, ACC-2; decision 0029).

Everything here comes from the inventory's `access` block. render() writes build/access/: access.sh, which
each router we own runs once at deploy, just before the NOC agent (accounts, the admin group, the CM
tool's scratch folders and frr-reload.py's log file, the accounting proxy), the proxy itself (templates/access/vty_aaa.py) and the vtysh shim that
sends every account but root through it.
"""
from __future__ import annotations

import re

from .inventory import Inventory

# Where the proxy offers each daemon's socket; the vtysh shim points every account but root at it.
SOCKETS = "/run/netlab-vty"
# The proxy's records reach the collector from this UDP port, and the collector files only what comes from it
# under SOURCE. Below 1024, so only root on the router can send from it: the routers we own set
# net.ipv4.ip_unprivileged_port_start to 1024 (Docker sets it to 0 in a container).
RECORD_PORT = 601
SOURCE = "accounting"
UNPRIVILEGED_PORT_START = 1024
NAME = re.compile(r"[a-z][a-z0-9-]{0,30}")


def routers(inv: Inventory) -> list[str]:
    """Routers we own get accounts and the proxy. The carrier's isp is administered as it was (root)."""
    if not inv.raw.get("access"):
        return []
    return [r for r in inv.routers if inv.owner(r) == inv.operator]


def accounts(inv: Inventory) -> list[dict]:
    """[{name, uid, kind}], people first, then agents (tools)."""
    a = inv.raw.get("access") or {}
    return ([{"name": p["name"], "uid": p["uid"], "kind": "person"} for p in a.get("people") or []]
            + [{"name": t["name"], "uid": t["uid"], "kind": "agent", "what": t.get("what", "")} for t in a.get("agents") or []])


def expected_admins(inv: Inventory) -> list[str]:
    """Every account an FRR session or a command may come from without paging (OROS ACC-2's expected set)."""
    return [a["name"] for a in accounts(inv)]


def problems(inv: Inventory) -> list[str]:
    """Inventory checks, all reported at once like the rest of netlab validate."""
    a = inv.raw.get("access")
    if not a:
        return []
    out = []
    group = a.get("group") or {}
    if not NAME.fullmatch(str(group.get("name", ""))) or not isinstance(group.get("gid"), int):
        out.append("access: group needs a name (lower case) and a numeric gid")
    seen_names, seen_uids = set(), set()
    for acct in accounts(inv):
        label = f"access: {acct['kind']} {acct['name']!r}"
        if not NAME.fullmatch(str(acct["name"])):
            out.append(f"{label}: a name must be lower case letters, digits and -, starting with a letter")
        if acct["name"] in ("root", "frr", "nobody"):
            out.append(f"{label}: that account already exists in the router image, so nobody could tell it from the image's own")
        # Below 1000 are the image's system accounts (frr is 100); 65534 is nobody.
        if not (isinstance(acct["uid"], int) and 1000 <= acct["uid"] < 65534):
            out.append(f"{label}: uid {acct['uid']!r} must be a number from 1000 to 65533")
        if acct["name"] in seen_names:
            out.append(f"{label}: listed twice")
        if acct["uid"] in seen_uids:
            out.append(f"{label}: uid {acct['uid']} is already someone else's")
        seen_names.add(acct["name"])
        seen_uids.add(acct["uid"])
    if a.get("ansible_user") not in [x["name"] for x in accounts(inv) if x["kind"] == "agent"]:
        out.append(f"access: ansible_user {a.get('ansible_user')!r} must be one of the agents")
    return out


def render(inv: Inventory, env, write, root) -> None:
    """build/access/: what each router we own runs to get its accounts and the proxy."""
    if not routers(inv):
        return
    from . import monitoring  # monitoring imports this module for its alert rule
    a = inv.raw["access"]
    to = f"{monitoring.collector(inv)}:{monitoring.PORTS['syslog']}" if inv.monitoring else "-"
    write("access/access.sh", env.get_template("access/access.sh.j2").render(
        group=a["group"], accounts=accounts(inv), cm=a["ansible_user"], sockets=SOCKETS, to=to, record_port=RECORD_PORT))
    write("access/vtysh", env.get_template("access/vtysh.j2").render(sockets=SOCKETS))
    write("access/vty_aaa.py", (root / "templates" / "access" / "vty_aaa.py").read_text())


def expected(inv: Inventory) -> dict:
    """What the live tests read back: who exists, who is expected, and where the proxy listens."""
    if not routers(inv):
        return {}
    a = inv.raw["access"]
    return {"routers": routers(inv), "group": a["group"]["name"], "accounts": accounts(inv),
            "expected": expected_admins(inv), "ansible_user": a["ansible_user"], "sockets": SOCKETS,
            "source": SOURCE, "record_port": RECORD_PORT, "unprivileged_port_start": UNPRIVILEGED_PORT_START}
