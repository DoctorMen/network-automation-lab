"""The risk register (docs/risks.yml, OROS JUS-4), tied to the config lines it accepts.

Each detector below is a risky kind of config line. The scan renders the configs from the inventory
(so it never reads a stale build/), reads the repo files the lab runs on, and reports:
  - a risky line that no register entry covers, by file and line number,
  - an entry whose detector matches nothing any more, so the risk is gone and the entry should close,
  - an entry missing its reasoning, compensating test, owner, review date or presentation record,
  - a decision record that accepts a risk (docs/decisions/) without naming its entry here.
`python -m netlab.risks` (make risks) prints the one-page summary and exits 1 on any problem."""
from __future__ import annotations

import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

from .inventory import load
from .records import names_a_test
from .render import render_all

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "docs" / "risks.yml"
DECISIONS = ROOT / "docs" / "decisions"
FIELDS = ("id", "kind", "title", "likelihood", "impact", "reasoning", "compensating_control", "owner", "review_by")
KINDS = {"accepted-risk", "refused-spend"}


@dataclass(frozen=True)
class Detector:
    where: str          # "build" (rendered from the inventory) or "repo"
    files: str          # glob under that root
    line: str           # regex for the risky line
    unless: str | None  # regex that, found anywhere in the same file, makes the line safe
    what: str


DETECTORS = {
    "ebgp-no-policy": Detector("build", "*/frr.conf", r"^\s*no bgp ebgp-requires-policy$", None,
                               "eBGP accepts every route, with no inbound policy required"),
    "ospf-no-auth": Detector("build", "*/frr.conf", r"^router ospf$", r"ip ospf (authentication|message-digest-key)",
                             "OSPF with no authentication"),
    "privileged-node": Detector("build", "topology.clab.yml", r"^\s+kind: linux$", None,
                                "a node Containerlab starts as a privileged container"),
    "icmp-any-type": Detector("build", "*/firewall.sh", r"-p icmp\b(?!.*--icmp-type).*-j ACCEPT", None,
                              "the firewall forwards every ICMP type"),
    "eosl-base": Detector("repo", "inventory/network.yml", r"^\s*alpine:\s*\"?3\.15\.", None,
                          "the base OS is past its end of security support"),
    "host-key-checking-off": Detector("repo", "ansible/ansible.cfg", r"^host_key_checking\s*=\s*False", None,
                                      "Ansible would accept any SSH host key"),
    "drift-filter": Detector("repo", "ansible/tasks/compare_frr.yml", r"reject\(.*ipv6 forwarding", None,
                             "the drift check ignores a config line"),
    "secret-file": Detector("repo", "inventory/network.yml", r"^\s*- \{ routers: \[.*\], secret: ", None,
                            "a BGP password kept in a file, and set as TCP MD5"),
    "bfd-default-timers": Detector("build", "*/frr.conf", r"^\s*ip ospf bfd$", r"^\s*(detect-multiplier|receive-interval|transmit-interval)\s",
                                   "BFD at FRR's default 300 ms x 3, with no alert on a flap"),
}


@dataclass(frozen=True)
class Hit:
    detector: str
    file: str
    number: int
    text: str

    def __str__(self) -> str:
        return f"{self.file}:{self.number}: `{self.text.strip()}`"


def scan(build: Path, repo: Path = ROOT) -> list[Hit]:
    roots = {"build": build, "repo": repo}
    hits = []
    for name, d in DETECTORS.items():
        root = roots[d.where]
        for path in sorted(root.glob(d.files)):
            text = path.read_text()
            if d.unless and re.search(d.unless, text, re.M):
                continue
            label = f"{'build/' if d.where == 'build' else ''}{path.relative_to(root)}"
            hits += [Hit(name, label, n, line) for n, line in enumerate(text.splitlines(), 1) if re.search(d.line, line)]
    return hits


def lint(entries: list, today: date | None = None) -> list[str]:
    problems = []
    seen = set()
    for i, e in enumerate(entries):
        name = e.get("id") or f"entry #{i + 1}"
        problems += [f"{name}: missing {f}" for f in FIELDS if not e.get(f)]
        if name in seen:
            problems.append(f"{name}: id is used more than once")
        seen.add(name)
        if e.get("kind") and e["kind"] not in KINDS:
            problems.append(f"{name}: kind {e['kind']!r} is not one of {sorted(KINDS)}")
        for scale in ("likelihood", "impact"):
            if e.get(scale) is not None and e[scale] not in (1, 2, 3, 4, 5):
                problems.append(f"{name}: {scale} {e[scale]!r} is not 1 to 5")
        test = str(e.get("compensating_control") or "")
        if test and not (re.match(r"none \(.+\)$", test) or names_a_test(test.split()[0])):
            problems.append(f"{name}: compensating_control {test} is not a test that exists, or none (reason)")
        if e.get("review_by") and not isinstance(e["review_by"], date):
            problems.append(f"{name}: review_by {e['review_by']!r} is not YYYY-MM-DD")
        elif e.get("review_by") and today and e["review_by"] < today:
            problems.append(f"{name}: review was due {e['review_by']}")
        for d in e.get("detectors") or []:
            if d not in DETECTORS:
                problems.append(f"{name}: unknown detector {d!r}")
        # Who it was shown to. "pending" is allowed and listed by the summary, because only a person
        # in a management role can make it true; once set, the date and a link to the record must be too.
        if "presented_to" not in e:
            problems.append(f"{name}: missing presented_to (pending until management has seen it)")
        elif e["presented_to"] != "pending":
            if not isinstance(e.get("presented_on"), date):
                problems.append(f"{name}: presented to {e['presented_to']} but presented_on is not a date")
            if not re.match(r"https?://", str(e.get("presented_evidence") or "")):
                problems.append(f"{name}: presented to {e['presented_to']} but presented_evidence is not a link")
    return problems


def accepted_in_decisions(folder: Path = DECISIONS) -> list[tuple[str, str, str]]:
    """(record, mode, the text naming its register entry) for each failure mode a decision record accepts."""
    found = []
    for path in sorted(folder.glob("[0-9][0-9][0-9][0-9]-*.md")):
        parts = path.read_text().split("---\n", 2)
        meta = yaml.safe_load(parts[1]) if len(parts) == 3 else None
        for fm in (meta or {}).get("failure_modes") or []:
            text = f"{fm.get('mitigation', '')} {fm.get('test', '')}"
            if str(fm.get("test", "")).startswith("none (accepted risk") or str(fm.get("mitigation", "")).startswith("Accepted"):
                found.append((path.name, str(fm.get("mode")), text))
    return found


def check(entries: list, build: Path, repo: Path = ROOT, today: date | None = None, decisions: Path = DECISIONS) -> list[str]:
    """Every problem: incomplete entries, risky lines nobody accepted, entries whose lines are gone, and
    risks a decision record accepts that the register doesn't hold."""
    hits = scan(build, repo)
    covered = {d for e in entries for d in e.get("detectors") or []}
    problems = lint(entries, today)
    problems += [f"{h}: {DETECTORS[h.detector].what}, and no entry in docs/risks.yml covers it (detector {h.detector})"
                 for h in hits if h.detector not in covered]
    found = {h.detector for h in hits}
    problems += [f"{e['id']}: no config line matches {d} any more; close the risk, or fix the detector"
                 for e in entries for d in e.get("detectors") or [] if d in DETECTORS and d not in found]
    ids = {e.get("id") for e in entries}
    for record, mode, text in accepted_in_decisions(decisions):
        named = re.findall(r"\bRISK-\d+\b", text)
        if not named:
            problems.append(f"{record}: accepts the risk {mode!r} but names no entry in docs/risks.yml "
                            "(write it as: none (accepted risk RISK-n in docs/risks.yml))")
        problems += [f"{record}: accepts the risk {mode!r} as {r}, which docs/risks.yml doesn't hold" for r in named if r not in ids]
    return problems


def summary(entries: list, hits: list[Hit]) -> str:
    lines = ["Risk register (docs/risks.yml): likelihood x impact, owner, review date, who has seen it"]
    for e in sorted(entries, key=lambda e: -e["likelihood"] * e["impact"]):
        shown = "NOT YET PRESENTED" if e.get("presented_to") == "pending" else f"shown to {e['presented_to']} on {e['presented_on']}"
        lines.append(f"  {e['id']:<8} {e['likelihood']}x{e['impact']}={e['likelihood'] * e['impact']:<3} {e['title']}")
        lines.append(f"           owner {e['owner']}, review by {e['review_by']}, {shown}")
        lines += [f"           {h}" for h in hits if h.detector in (e.get("detectors") or [])]
    pending = [e["id"] for e in entries if e.get("presented_to") == "pending"]
    if pending:
        lines.append(f"Not yet presented to management: {', '.join(pending)}")
    return "\n".join(lines)


def main() -> int:
    entries = yaml.safe_load(REGISTER.read_text())
    with tempfile.TemporaryDirectory() as tmp:
        render_all(load(ROOT / "inventory" / "network.yml"), tmp)
        problems = check(entries, Path(tmp), today=date.today())
        print(summary(entries, scan(Path(tmp))))
    for p in problems:
        print(f"PROBLEM: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
