"""Who did it, from the NOC's copy of the logs alone (decisions 0030 and 0031).

python -m netlab.who set <router> < diff     who set each line `frr-reload.py --test` lists as differing
                                             (OROS CHG-6); `make drift` runs it on every router that drifted
python -m netlab.who flow <address> <port> <time> [--remote ADDRESS]
                                             which inside host held an outside address and port at a time,
                                             as an abuse complaint gives them (OROS FND-5); `make whois`

Both read Loki on the NOC only, never the router: a record the router's root deleted on the box is still
there, and one that never left the box is not (RISK-60). `set` reads the accounting proxy's command records
(templates/access/vty_aaa.py); `flow` reads the translation log (templates/monitoring/natlog.sh.j2).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import access, monitoring, nat
from .inventory import Inventory, load
from .observe import Noc, lab_name

ROOT = Path(__file__).resolve().parent.parent
# conntrack stamps a translation when it reads the kernel's event, a few milliseconds after the first packet
# left, and a complaint's time comes from someone else's clock: a translation stamped up to this many
# seconds after the complaint's time still counts.
SKEW = 2.0
# One command record as the proxy sends it: the syslog header, then the record. Anchored at the start, so text
# typed into a command (which the proxy keeps on its own line) can't pass for a record of its own.
RECORD = re.compile(r"^<\d+>\w{3} [ \d]\d [\d:]{8} vty-aaa\[\d+\]: command user=(?P<user>\S+) uid=(?P<uid>\d+) "
                    r"daemon=(?P<daemon>\S+) pid=(?P<pid>\d+) line=(?P<line>.*)$")


def iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def when(text: str) -> float:
    """Unix seconds, or an ISO 8601 time (UTC unless it says otherwise)."""
    try:
        return float(text)
    except ValueError:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp()


# --- set: who set each differing config line ---------------------------------------------------------

def differences(diff: str) -> list[dict]:
    """Each line `frr-reload.py --test` would run, as {state, line, context}. A line it would run as `no X`
    means X is running and not intended (state running); any other line is intended and not running
    (state missing). An unindented line followed by indented ones is only their context."""
    out, context, section = [], "", None
    lines = diff.splitlines()
    for i, raw in enumerate(lines):
        text = raw.strip()
        if text in ("Lines To Delete", "Lines To Add"):
            section = text
            continue
        if not text or set(text) == {"="} or section is None:
            continue
        indented = raw.startswith(" ")
        following = lines[i + 1] if i + 1 < len(lines) else ""
        if not indented and following.startswith(" "):
            context = text
            continue
        if not indented:
            context = ""
        state, line = ("running", text[3:]) if text.startswith("no ") else ("missing", text)
        out.append({"state": state, "line": line, "context": context})
    return out


def records(noc: Noc, router: str, since: float) -> list[dict]:
    """Every command record from the router's accounting proxy since `since`, oldest first, once each: vtysh
    sends a command to every daemon it concerns, and each connection logs it. Only the records the collector
    took from the proxy's own port (source accounting): a line that only looks like one is syslog."""
    newest = {}
    for t, _labels, text in noc.logs(f'{{node="{router}",source="{access.SOURCE}"}} |= " command user="', since, every=True):
        if m := RECORD.match(text):
            newest[(m["pid"], m["line"])] = {"time": t, **m.groupdict()}
    return sorted(newest.values(), key=lambda r: r["time"])


def same(typed: list[str], running: list[str]) -> bool:
    """FRR takes any unambiguous start of a keyword (`desc` for `description`), so a typed keyword matches a
    running one it starts. A value (any word with a digit: an address, a number) must match in full, or
    10.0.0.1 would match 10.0.0.10. The word count must agree."""
    return len(typed) == len(running) and all(
        t == r or (re.fullmatch(r"[a-z-]+", t) is not None and r.startswith(t)) for t, r in zip(typed, running))


def setter(diff: dict, history: list[dict]) -> dict | None:
    """The record that explains one difference, or None. Walking back from the newest, the first record that
    touched the line's command decides: one that set it (the same words, the last perhaps another value), or
    ran `no` and its start (`no neighbor X` removes the whole neighbor). A running line is explained only if
    that record set this very line, and a missing line only if it removed the line or set the command to
    another value. Otherwise the line changed after that record, outside the proxy, and no record explains it.
    A secret shows as <hidden> in a record and as its tag in the diff, so only the words before it are compared."""
    words = diff["line"].split()
    for r in reversed(history):
        typed = r["line"].split()
        if typed[:1] == ["no"] and len(typed) >= 2:
            start = typed[1:]
            if same(start, words[:len(start)]) or (len(start) == len(words) > 1 and same(start[:-1], words[:-1])):
                return {**r, "how": "removed"} if diff["state"] == "missing" else None
            continue
        if "<hidden>" in typed:
            shown = typed[:typed.index("<hidden>")]
            if len(words) > len(shown) and same(shown, words[:len(shown)]):
                return {**r, "how": "set"} if diff["state"] == "running" else None
            continue
        if same(typed, words):
            return {**r, "how": "set"} if diff["state"] == "running" else None
        if len(words) > 1 and len(typed) == len(words) and same(typed[:-1], words[:-1]):
            return {**r, "how": "replaced"} if diff["state"] == "missing" else None
    return None


def who_set(inv: Inventory, router: str, diff: str, noc: Noc, now: float | None = None) -> list[dict]:
    """Each difference with the record that explains it (None: no record does)."""
    since = (now or time.time()) - inv.logging["retention"] * 3600
    history = records(noc, router, since)
    return [{**d, "record": setter(d, history)} for d in differences(diff)]


def report_set(router: str, found: list[dict]) -> str:
    lines = [f"Who set each line on {router}, from the NOC's copy of its command accounting (decision 0030):"]
    for d in found:
        where = f" (under {d['context']})" if d["context"] else ""
        lines.append(f"  {d['state']}: {d['line']}{where}")
        r = d["record"]
        if r:
            lines.append(f"    {r['how']} by {r['user']} (uid {r['uid']}) at {iso(r['time'])}: {r['line']}")
        else:
            lines.append("    no command record: changed outside the accounting proxy (root on the router, RISK-60) "
                         "or before the store's oldest line")
    return "\n".join(lines)


# --- flow: which inside host held an outside address and port -----------------------------------------

def inside_device(inv: Inventory, address: str) -> dict:
    for h, v in inv.hosts.items():
        if v["address"].split("/")[0] == address:
            return {"device": h, "segment": v.get("segment"), "owner": inv.owner(h)}
    return {"device": inv.device_at(address), "segment": None, "owner": None}


def flow(inv: Inventory, noc: Noc, address: str, port: int, at: float, remote: str | None = None,
         within: float = 3600, skew: float = SKEW) -> dict:
    """Which inside host held `address`:`port` at `at`, from the translation log of the router that
    translates to `address`. `within`: how far before `at` a translation may have begun; `skew`: how far
    after."""
    router = next((r for r, c in nat.expected(inv).items() if c["address"] == address), None)
    if router is None:
        return {"address": address, "port": port, "at": at, "router": None, "holders": [], "verdict": "not-ours"}
    # Loki holds a line by its arrival, a few seconds after the translation it records.
    lines = [text for _t, _l, text in noc.logs(
        f'{{node="{router}",source="{nat.SOURCE}"}} |= "dst={address} " |~ "dport={port}( |$)"', at - within, at + 60, every=True)]
    holders = [{**h, **inside_device(inv, h["inside"])} for h in nat.holders(lines, address, port, at, remote, skew)
               if at - h["time"] <= within]
    inside = {h["inside"] for h in holders}
    verdict = "none" if not inside else "one" if len(inside) == 1 else "several"
    return {"address": address, "port": port, "at": at, "within": within, "router": router, "holders": holders, "verdict": verdict}


def report_flow(found: dict) -> str:
    head = f"{found['address']}:{found['port']} at {iso(found['at'])}"
    if found["verdict"] == "not-ours":
        return f"{head}: not an address any router of ours translates to"
    if found["verdict"] == "none":
        return (f"{head}: no translation in {found['router']}'s log at the NOC began in the {found['within']:.0f} s before (--within "
                f"looks further back), or its line never arrived (SourceSilent for {found['router']}/{nat.SOURCE})")
    lines = [f"{head}, from {found['router']}'s translation log at the NOC (decision 0031):"]
    for h in found["holders"]:
        name = f"{h['device']} ({h['segment']}, owner {h['owner']})" if h["device"] else "no device in the inventory"
        lines.append(f"  {h['inside']}:{h['inside_port']} {name}, {h['proto']} to {h['remote']}:{h['remote_port']}, "
                     f"translated at {iso(h['time'])}")
    if found["verdict"] == "several":
        lines.append("  More than one inside host used that port, to different far ends: give the complainant's own address with --remote.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.who")
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("set", help="who set each differing line; reads frr-reload.py --test output on stdin")
    s.add_argument("router")
    f = sub.add_parser("flow", help="which inside host held an outside address and port at a time")
    f.add_argument("address")
    f.add_argument("port", type=int)
    f.add_argument("time", help="Unix seconds, or ISO 8601 (UTC unless it says otherwise)")
    f.add_argument("--remote", help="the complainant's own address, or address:port, if the complaint gives it")
    f.add_argument("--within", type=float, default=3600, help="seconds before the time a translation may have begun")
    f.add_argument("--skew", type=float, default=SKEW, help="seconds after the time a translation may be stamped")
    args = p.parse_args(argv)
    inv = load(args.inventory)
    noc = Noc(lab_name(), monitoring.host(inv))
    try:
        if args.command == "set":
            found = who_set(inv, args.router, sys.stdin.read(), noc)
            print(json.dumps(found, indent=1) if args.json else report_set(args.router, found))
            return 0
        ipaddress.IPv4Address(args.address)
        found = flow(inv, noc, args.address, args.port, when(args.time), args.remote, args.within, args.skew)
    except RuntimeError as e:  # the NOC didn't answer: say so, and let the caller's own check stand
        print(f"the NOC's log store did not answer, so who did it is not known: {e}")
        return 2
    print(json.dumps(found, indent=1) if args.json else report_flow(found))
    return {"one": 0, "none": 1, "several": 3}.get(found["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
