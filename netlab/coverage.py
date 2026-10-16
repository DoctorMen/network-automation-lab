"""Does every value we read from a device reach the NOC? (OROS NOT-2, decision 0018)

python -m netlab.coverage [--list]

Finds every command the live tests, netlab's own tools, the Ansible playbooks and the runbooks run on a
device (`docker exec`, vtysh, the live tests' node().run) and checks that monitoring/coverage.yml lists
what each one reads, marked exported, derived or gap:

- exported: an exporter the NOC scrapes carries the value (metric:);
- derived: the NOC computes it from other metrics or a log query (metric: or logql:, and how:);
- gap: this platform and version exports nothing for it, and fallback: says what the NOC does instead.

It fails on a read the list doesn't have, an entry nothing reads any more, an entry without its metric,
query or fallback, a Prometheus job that coverage.yml doesn't name as a collector (an unlisted scraper),
and a metric an alert rule uses that no collector lists. Under `counts` it fails on a collector's metric
that doesn't say what it counts, a counter that doesn't say when it wraps and resets, a counter an alert
rule reads outside increase(), rate(), irate() or resets() (where a reset or a wrap would read as a fall),
and a proven_by test that doesn't exist (OROS DEC-2, decision 0024). A command that only changes the device is
named in `actions` (its program) or recognised as a write (vtysh conf t, iptables -I, ip link set).
A command built at run time that can't be read from the source is listed under `opaque` by file and
function, with why. tests/live/observe/test_coverage.py checks the listed metrics exist on the NOC.
--list prints every read found and where, for writing the list.
"""
from __future__ import annotations

import argparse
import ast
import re
import shlex
import sys
from pathlib import Path

import yaml

from .inventory import load
from . import monitoring

ROOT = Path(__file__).resolve().parent.parent
COVERAGE = ROOT / "monitoring" / "coverage.yml"
# Where reads are looked for: everything that runs a command on a device. The NOC's own code (this file,
# monitoring.py, observe.py) reads the NOC, not a device.
PYTHON = ["tests/live/**/*.py", "netlab/*.py"]
SKIP = {"netlab/coverage.py", "netlab/monitoring.py", "netlab/observe.py"}
YAML = ["ansible/*.yml", "ansible/tasks/*.yml"]
RUNBOOKS = ["docs/runbooks/*.md"]
STATUSES = {"exported", "derived", "gap"}
ARG = "<arg>"
# Programs that read the device (a runbook's inline code is only a command when it starts with one).
DEVICE_PROGRAMS = {"vtysh", "show", "ip", "iptables", "iptables-save", "tc", "ping", "traceroute", "netstat", "nstat"}
PROMQL_WORDS = {"absent", "and", "or", "unless", "on", "by", "without", "increase", "rate", "time", "sum", "count", "max", "min",
                "min_over_time", "max_over_time", "ignoring", "group_left", "group_right", "bool", "offset", "vector",
                "topk", "bottomk", "irate", "resets"}
# The only functions an alert rule may read a counter through: each reads a fall as a reset, not a drop.
COUNTER_SAFE = ("increase", "rate", "irate", "resets")


def normalize(text: str) -> str:
    """One spelling per read: no f-string fields, addresses, numbers or `json`, so `show bgp neighbors
    198.51.100.1 json` and `show bgp neighbors {peer}` are the same read."""
    text = re.sub(r"\{[^{}]*\}", ARG, text)
    text = re.sub(r"\b\d+(\.\d+){3}(/\d+)?\b", ARG, text)
    text = re.sub(r"(?<![\w\[-])\d+(?![\w\]])", ARG, text).replace(f"{ARG}/{ARG}", ARG)
    words = [w for w in text.split() if w not in ("json", "no-header")]
    return " ".join(words)


def classify(tokens: list[str]) -> list[tuple[str, str]]:
    """[(kind, key)] for one command line: kind is read, action, or unknown (a program the rules don't know)."""
    while tokens and (tokens[0] in ("do", "then", "else", "exec", "!") or re.match(r"[A-Za-z_]\w*=", tokens[0])):
        tokens = tokens[1:]  # shell keywords, and VAR=value before a command or on its own
    if not tokens or tokens[0] in ("for", "while", "if", "done", "fi", "echo", "exit", "set", "cd", "true", "false", "wait"):
        return []
    prog = tokens[0].rsplit("/", 1)[-1]
    args = tokens[1:]
    if prog in ("sh", "bash") and len(args) >= 2 and args[0].startswith("-") and "c" in args[0]:
        return script(args[1])
    if prog == "sh" and args[:2] == ["/monitoring/agent.sh", "dump"]:
        return [("read", "sh /monitoring/agent.sh dump")]  # the flight recorder's state dump, on demand
    if prog == "su" and "-c" in args[:-1]:  # su ACCOUNT -c '...': the script runs as that account
        return script(args[args.index("-c") + 1])
    if prog in ("unshare", "env", "timeout"):
        rest = [i for i, a in enumerate(args) if not a.startswith("-") and "=" not in a and not a.isdigit()]
        return classify(args[rest[0]:]) if rest else [("action", prog)]
    if prog == "show":  # a runbook's `show ...`, typed into vtysh
        return [("read", normalize("vtysh " + " ".join(tokens)))]
    if prog == "vtysh":
        cmds = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-c"]
        if not cmds:
            return [("action", "vtysh -f")]  # commands on stdin: the BGP password lines
        return [("read", normalize("vtysh " + c)) if c.startswith("show ") else ("action", "vtysh " + c.split()[0])
                for c in cmds]
    if prog == "iptables":
        flags = [a for a in args if a.startswith("-") and not a.startswith("--")]
        if any(f in ("-I", "-A", "-D", "-R", "-N", "-X", "-F", "-P", "-Z") for f in flags):
            return [("action", "iptables write")]
        for flag, key in (("-S", "iptables -S"), ("-C", "iptables -C")):
            if flag in flags:
                return [("read", key)]
        if any("L" in f for f in flags):
            return [("read", "iptables -L")]
        return [("unknown", "iptables " + " ".join(flags))]
    if prog == "ip":
        words = [a for a in args if not a.startswith("-")]
        stats = "-s " if "-s" in args else ""
        if len(words) >= 2 and words[1] in ("show", "get", "list"):
            return [("read", f"ip {stats}{words[0]} {words[1]}")]
        if len(words) == 1:
            return [("read", f"ip {stats}{words[0]} show")]
        return [("action", " ".join(["ip", *words[:2]]))]
    if prog == "tc":
        words = [a for a in args if not a.startswith("-")]
        return [("read", f"tc {words[0]} show")] if "show" in words else [("action", " ".join(["tc", *words[:1]]))]
    if prog in ("ping", "traceroute", "wget", "uname", "iptables-save", "apk", "readlink", "ps", "id"):
        return [("read", prog)]
    if prog == "nc":
        return [("read", "nc -z")] if "-z" in args else [("action", "nc listener")]
    if prog in ("netstat", "nstat"):
        return [("read", normalize(" ".join([prog, *args])))]
    if prog == "sed" and any(a == "--in-place" or re.fullmatch(r"-[a-zE]*i\S*", a) for a in args):
        return [("action", "sed -i")]  # edits the file in place; any other sed reads it, like cat
    if prog in ("cat", "grep", "ls", "head", "tail", "sed"):
        paths = [a for a in args if a.startswith("/")]
        return [("read", normalize(f"{prog} {' '.join(paths)}"))] if paths else [("action", prog)]
    if prog == ".":  # sourcing a file: reads it, unless it is a script being run
        return [("action", ". script")] if args[:1] and args[0].endswith(".sh") else [("read", normalize(". " + " ".join(args[:1])))]
    if prog in ("python3", "python"):
        if len(args) > 1 and args[0] == "-m":
            return [("action", "python3 -m")]  # starting a module: a server, not a read
        return [("read", "python3 " + args[1])] if len(args) > 1 and args[0] in ("-", "-c") else [("unknown", "python3")]
    return [("unknown", prog)]


def script(text: str) -> list[tuple[str, str]]:
    """Each command of a shell script (sh -c '...'), split where the shell splits it (; && || | ( ) and new
    lines, outside quotes), without its redirections."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        tokens = list(lexer)
    except ValueError:
        tokens = text.split()
    out, words, skip = [], [], False
    for i, tok in enumerate(tokens):
        if skip:
            skip = False
            continue
        if tok in (";", "&&", "||", "|", "(", ")", "&", ";;"):
            out += classify(words)
            words = []
        elif set(tok) <= set("<>&") and tok:
            skip = True  # the redirection's target
            if words and words[-1].isdigit():
                words.pop()  # 2>/dev/null
        else:
            words.append(tok)
    out += classify(words)
    return out


# --- Python: the commands a call runs, read from the code itself ---------------------------------------

def _literal(node, names: dict) -> list[str] | None:
    """The tokens an argument stands for: a string, an f-string (fields become {}), a list of them, or a
    name or call the module defines as one. None when it can't be told from the source."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return ["".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)]
    if isinstance(node, (ast.List, ast.Tuple)):
        return _args(node.elts, names)
    if isinstance(node, ast.Name) and node.id in names:
        return names[node.id]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in names:
        return names[node.func.id]
    return None


def _args(nodes: list, names: dict) -> list[str] | None:
    """The command a list of arguments runs. None if even its program can't be told; an argument that
    can't be (a variable) stays as <arg>."""
    out = []
    for n in nodes:
        got = _literal(n.value if isinstance(n, ast.Starred) else n, names)
        if got is None:
            if not out:
                return None
            got = [ARG]
        out += got
    return out


def _script_name(call: ast.Call) -> str:
    """For python3 - or -c: the script, by the name it is kept under (input=SCAN, a -c NAME, or a file named
    in the expression that reads it)."""
    for k in call.keywords:
        if k.arg in ("input", "stdin") and isinstance(k.value, ast.Name):
            return k.value.id
    for a in call.args:
        if isinstance(a, ast.Name) and a.id.isupper():
            return a.id
        if isinstance(a, (ast.List, ast.Tuple)):  # [..., "python3", "-c", BURST, ...]
            for flag, name in zip(a.elts, a.elts[1:]):
                if isinstance(flag, ast.Constant) and flag.value == "-c" and isinstance(name, ast.Name) and name.id.isupper():
                    return name.id
        for c in ast.walk(a):
            if isinstance(c, ast.Constant) and isinstance(c.value, str) and c.value.endswith(".py"):
                return c.value
    return ARG


def _functions(trees: dict) -> dict:
    """Functions anywhere in the scanned code that only return a command list (locate.ping_cmd)."""
    out = {}
    for tree in trees.values():
        for f in ast.walk(tree):
            if isinstance(f, ast.FunctionDef) and f.body and isinstance(f.body[-1], ast.Return) and \
                    isinstance(f.body[-1].value, (ast.List, ast.Tuple)):
                got = _literal(f.body[-1].value, {})
                if got and got[0] != "docker":  # exec_on itself is handled as the call it is
                    out[f.name] = got
    return out


def _params(func: ast.FunctionDef) -> list[str]:
    a = func.args
    return [x.arg for x in [*a.posonlyargs, *a.args]] + ([a.vararg.arg] if a.vararg else [])


def _exec_part(call: ast.Call):
    """The argument nodes of the command a call runs on a device, or None if it runs none: exec_on's after
    (inv, lab, device), and a docker exec list's after its flags and container."""
    f = call.func
    name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
    if name == "exec_on" and len(call.args) > 3:
        return call.args[3:]
    if call.args and isinstance(call.args[0], (ast.List, ast.Tuple)):
        elts = call.args[0].elts
        head = [_literal(e, {}) for e in elts[:2]]
        if head == [["docker"], ["exec"]]:
            rest = elts[2:]
            while rest and (isinstance(rest[0], ast.Starred) or
                            isinstance(rest[0], ast.Constant) and str(rest[0].value).startswith("-")):
                rest = rest[1:]
            return rest[1:]
    return None


def _wrappers(trees: dict) -> dict:
    """{(module or None, function): index}: functions that run their own arguments on a device (Node.run,
    verify.run), and where in a call the command starts. A method (self) is called from other modules, a
    plain function from its own. Their callers are scanned; their own body isn't a read."""
    out = {}
    for path, tree in trees.items():
        for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            params = _params(func)
            for call in [n for n in ast.walk(func) if isinstance(n, ast.Call)]:
                part = _exec_part(call)
                first = part[0] if part else None
                first = first.value if isinstance(first, ast.Starred) else first
                if isinstance(first, ast.Name) and first.id in params:
                    plain = [p for p in params if p != "self"]
                    out[(None if params[:1] == ["self"] else path, func.name)] = plain.index(first.id)
    return out


def _commands(path: Path, tree: ast.AST, functions: dict, wrappers: dict):
    """(line, function, tokens or None) for every command a call in this module runs on a device."""
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        params = _params(func)
        names = dict(functions)
        for stmt in [s for b in func.body for s in ast.walk(b)]:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name) \
                    and isinstance(stmt.value, (ast.List, ast.Tuple)):
                got = _literal(stmt.value, functions)
                if got:
                    names[stmt.targets[0].id] = got
        for call in [n for n in ast.walk(func) if isinstance(n, ast.Call)]:
            f = call.func
            attr = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if attr in ("vtysh", "vtysh_json", "run_json") and call.args:
                arg = call.args[-1]
                if any(isinstance(n, ast.Name) and n.id in params for n in ast.walk(arg)):
                    continue  # the helper itself
                got = _literal(arg, names)
                yield call.lineno, func.name, ["vtysh", "-c", got[0]] if got else None
                continue
            part = _exec_part(call)
            method = isinstance(f, ast.Attribute) and not (isinstance(f.value, ast.Name) and f.value.id == "subprocess")
            key = (None, attr) if method else (path, attr)
            if part is None and key in wrappers:
                part = call.args[wrappers[key]:]
            if not part:
                continue
            first = part[0].value if isinstance(part[0], ast.Starred) else part[0]
            if isinstance(first, ast.Name) and first.id in params and first.id not in names:
                continue  # a wrapper's own body: its callers are what is read
            tokens = _args(part, names)
            if tokens and tokens[0] in ("python3", "python") and len(tokens) > 1 and tokens[1] in ("-", "-c"):
                tokens = [tokens[0], tokens[1], _script_name(call)]
            yield call.lineno, func.name, tokens


def python_reads(files: list[Path]):
    trees = {p: ast.parse(p.read_text(), str(p)) for p in files}
    functions, wrappers = _functions(trees), _wrappers(trees)
    for path, tree in trees.items():
        for line, where, tokens in _commands(path, tree, functions, wrappers):
            yield path, line, where, tokens


# --- Ansible and runbooks ------------------------------------------------------------------------------

def _tasks(node):
    if isinstance(node, list):
        for item in node:
            yield from _tasks(item)
    elif isinstance(node, dict):
        if any(k in node for k in ("ansible.builtin.command", "ansible.builtin.shell", "ansible.builtin.raw")):
            yield node
        for k in ("tasks", "block", "rescue", "always", "pre_tasks", "post_tasks"):
            if k in node:
                yield from _tasks(node[k])


def yaml_reads(files: list[Path]):
    for path in files:
        text = path.read_text()
        for task in _tasks(yaml.safe_load(text)):
            if task.get("delegate_to") == "localhost":
                continue  # runs on the control host (netlab's own tools, scanned as Python)
            mod = next(k for k in ("ansible.builtin.command", "ansible.builtin.shell", "ansible.builtin.raw") if k in task)
            spec = task[mod]
            line = next((i for i, l in enumerate(text.splitlines(), 1) if task["name"] in l), 0)
            if isinstance(spec, dict) and "argv" in spec:  # already split, as the command module runs it
                yield path, line, task["name"], classify([re.sub(r"\{\{[^}]*\}\}", ARG, str(a)) for a in spec["argv"]])
                continue
            cmd = re.sub(r"\{\{[^}]*\}\}", ARG, str(spec["cmd"] if isinstance(spec, dict) else spec))
            yield path, line, task["name"], script(cmd) if "shell" in mod else classify(shlex.split(cmd))


def runbook_reads(files: list[Path]):
    for path in files:
        lines = path.read_text().splitlines()
        fenced = False
        for n, line in enumerate(lines, 1):
            if line.strip().startswith("```"):
                fenced = not fenced
                continue
            spans = [line.strip()] if fenced else re.findall(r"`([^`]+)`", line)
            for span in spans:
                try:
                    words = shlex.split(span)
                except ValueError:
                    words = span.split()
                if words[:2] == ["docker", "exec"]:
                    words = words[3:]  # after the container
                if words and words[0] in DEVICE_PROGRAMS:
                    yield path, n, "runbook", classify(words)


# --- The check -----------------------------------------------------------------------------------------

def found(root: Path = ROOT) -> tuple[dict, list]:
    """{read key: [where]}, and [(where, problem)] for commands the rules can't place."""
    reads, odd = {}, []

    def glob(patterns):
        return sorted({p for pat in patterns for p in root.glob(pat) if str(p.relative_to(root)) not in SKIP})

    for path, line, where, tokens in python_reads(glob(PYTHON)):
        loc = f"{path.relative_to(root)}:{line} ({where})"
        if tokens is None or not tokens or tokens[0] == ARG:
            odd.append((f"{path.relative_to(root)}::{where}", loc))
            continue
        for kind, key in classify(tokens):
            (reads.setdefault(key, []).append(loc) if kind == "read" else
             odd.append((f"unknown:{key}", loc)) if kind == "unknown" else None)
    for path, line, where, results in [*yaml_reads(glob(YAML)), *runbook_reads(glob(RUNBOOKS))]:
        loc = f"{path.relative_to(root)}:{line} ({where})"
        for kind, key in results:
            (reads.setdefault(key, []).append(loc) if kind == "read" else
             odd.append((f"unknown:{key}", loc)) if kind == "unknown" else None)
    return reads, odd


def rule_metrics(inv) -> set[str]:
    """Every metric a rule's expression, or a query in its annotations (the DEC-1 context), reads."""
    names = set()
    for g in monitoring.rule_groups(inv)["groups"]:
        for r in g["rules"]:
            queries = [r["expr"], *(q for a in r["annotations"].values() for q in re.findall(r"query `([^`]*)`", a))]
            for q in queries:
                expr = re.sub(r'\{[^}]*\}|\[[^\]]*\]|"[^"]*"|\b(by|on|without|ignoring)\s*\([^)]*\)', " ", q)
                names |= {w for w in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", expr) if w not in PROMQL_WORDS}
    return names - {"node"}


def counts_problems(coverage: dict, inv, root: Path = ROOT) -> list[str]:
    """What each metric counts (OROS DEC-2): every collector's metric says so, a counter says when it wraps and
    resets, no alert rule reads a counter raw, and every test named as proof exists."""
    problems, counts = [], coverage.get("counts") or {}
    # A metric only there once a job pushed it (after_push) says what it counts like any other.
    listed = {m for c in (coverage.get("collectors") or {}).values() for m in [*(c.get("metrics") or []), *(c.get("after_push") or [])]}
    problems += [f"metric {m} says nothing under counts in monitoring/coverage.yml about what it counts"
                 for m in sorted(listed - set(counts))]
    problems += [f"counts: {m} is in no collector's metrics" for m in sorted(set(counts) - listed)]
    for m, c in counts.items():
        if not c.get("counts"):
            problems.append(f"counts: {m} says nothing about what it counts")
        if c.get("type") not in ("counter", "gauge"):
            problems.append(f"counts: {m} is neither a counter nor a gauge")
        if c.get("type") == "counter":
            problems += [f"counts: {m} is a counter, and doesn't say when it {k}" for k in ("wraps", "resets") if not c.get(k)]
        for test in c.get("proven_by") or []:
            path, _, name = test.partition("::")
            f = root / path
            if not name or not f.is_file() or not re.search(rf"^def {re.escape(name)}\(", f.read_text(), re.M):
                problems.append(f"counts: {m} is proven by {test}, which does not exist")
    counters = sorted(m for m, c in counts.items() if c.get("type") == "counter")
    raw = set()
    for r in monitoring.alert_rules(inv):
        for m in counters:
            for hit in re.finditer(rf"(?<![\w:]){re.escape(m)}(?!\w)", r["expr"]):
                if not r["expr"][:hit.start()].rstrip().endswith(tuple(f + "(" for f in COUNTER_SAFE)):
                    raw.add((r["alert"], m))
    problems += [f"alert {a} reads the counter {m} outside {', '.join(COUNTER_SAFE)}: a reset or a wrap would read as a fall"
                 for a, m in sorted(raw)]
    return problems


def check(coverage: dict, reads: dict, odd: list, inv) -> list[str]:
    problems = []
    entries = {e["read"]: e for e in coverage.get("reads") or []}
    # One entry per read: a second one for the same read would hide the first's status from this check.
    listed = [e["read"] for e in coverage.get("reads") or []]
    problems += [f"monitoring/coverage.yml lists `{key}` {listed.count(key)} times" for key in sorted(set(listed)) if listed.count(key) > 1]
    actions = set(coverage.get("actions") or [])
    opaque = {o["where"]: o for o in coverage.get("opaque") or []}
    for key, where in sorted(reads.items()):
        if key not in entries:
            problems.append(f"{where[0]} reads `{key}`, which monitoring/coverage.yml does not list")
    for key in sorted(set(entries) - set(reads)):
        problems.append(f"monitoring/coverage.yml lists `{key}`, which nothing reads any more")
    for key, e in entries.items():
        status = e.get("status")
        if status not in STATUSES:
            problems.append(f"`{key}`: status {status!r} is not one of {sorted(STATUSES)}")
        elif status == "exported" and not e.get("metric"):
            problems.append(f"`{key}`: exported, but names no metric")
        elif status == "derived" and not (e.get("metric") or e.get("logql")) or status == "derived" and not e.get("how"):
            problems.append(f"`{key}`: derived needs a metric or logql, and how")
        elif status == "gap" and not e.get("fallback"):
            problems.append(f"`{key}`: a gap needs its fallback")
        if not e.get("value"):
            problems.append(f"`{key}`: says no value (what the reader decides on)")
    seen_opaque = set()
    for what, loc in odd:
        if what.startswith("unknown:"):
            prog = what.split(":", 1)[1].split()[0]
            if prog not in actions:
                problems.append(f"{loc} runs `{what.split(':', 1)[1]}`: list it as a read or its program under actions")
        elif what in opaque:
            seen_opaque.add(what)
        else:
            problems.append(f"{loc} runs a command built at run time: list {what} under opaque, with why")
    problems += [f"monitoring/coverage.yml: opaque {w} no longer runs such a command" for w in sorted(set(opaque) - seen_opaque)]
    problems += [f"monitoring/coverage.yml: opaque {w} says no why" for w, o in opaque.items() if not o.get("why")]
    collectors = coverage.get("collectors") or {}
    for job in monitoring.prometheus_config(inv)["scrape_configs"]:
        if job["job_name"] not in collectors:
            problems.append(f"Prometheus job {job['job_name']} is a scraper monitoring/coverage.yml does not list")
    # after_push: a metric that exists only once a job has pushed it (its JobMissed fires without it).
    listed = {m for c in collectors.values() for m in [*(c.get("metrics") or []), *(c.get("after_push") or [])]}
    for c, v in collectors.items():
        if not v.get("reads"):
            problems.append(f"collector {c}: says nothing about what it reads")
    for m in sorted(rule_metrics(inv) - listed):
        problems.append(f"alert rules use {m}, which no collector in monitoring/coverage.yml lists")
    for key, e in entries.items():
        for m in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", re.sub(r"\{[^}]*\}", "", str(e.get("metric") or ""))):
            if m.startswith(("frr_", "node_", "probe_", "log_")) and m not in listed:
                problems.append(f"`{key}`: metric {m} is not in its collector's metrics")
    return problems + counts_problems(coverage, inv)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.coverage")
    p.add_argument("--list", action="store_true", help="print every read found and where")
    p.add_argument("--inventory", default=str(ROOT / "inventory" / "network.yml"))
    args = p.parse_args(argv)
    reads, odd = found()
    if args.list:
        for key, where in sorted(reads.items()):
            print(f"{key}\n    " + "\n    ".join(where))
        for what, loc in odd:
            print(f"? {what}  {loc}")
        return 0
    coverage = yaml.safe_load(COVERAGE.read_text())
    problems = check(coverage, reads, odd, load(args.inventory))
    for problem in problems:
        print(problem, file=sys.stderr)
    counts = {s: sum(e.get("status") == s for e in coverage.get("reads") or []) for s in sorted(STATUSES)}
    print(f"{len(reads)} reads found, {len(coverage.get('reads') or [])} listed: "
          + ", ".join(f"{n} {s}" for s, n in counts.items()) + (f"; {len(problems)} problems" if problems else "; complete"))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
