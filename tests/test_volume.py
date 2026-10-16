"""OROS NOT-5, precise volume at the source (decision 0026), offline: the forwarder cuts one named kind of
line and nothing else, every source has a daily budget that the store can hold, and the budget rule pages
once a source's last 24 h passes it. The forwarder and the rules are the rendered ones, run by the pinned
Vector and Prometheus images themselves (`vector test`, `promtool test rules`), so these need Docker."""
import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from netlab import monitoring
from netlab.inventory import InventoryError, load
from netlab.render import render_all

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "inventory" / "network.yml"
inv = load(INVENTORY)
APP = inv.logging["apps"][0]
CHECK = monitoring.cuts(inv, APP)[0]


def needs(ok, what):
    if not ok:
        if os.environ.get("CI"):
            pytest.fail(f"{what} is missing, and CI must run this test")
        pytest.skip(f"{what} is not available")


@pytest.fixture(scope="module")
def docker():
    needs(shutil.which("docker") and subprocess.run(["docker", "info"], capture_output=True).returncode == 0, "Docker")


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    out = tmp_path_factory.mktemp("build")
    render_all(inv, out)
    return out


def access_line(client, request, status):
    """A line as Python's http.server writes it to h2's access log."""
    return f'{client} - - [16/Oct/2026 04:35:43] "{request}" {status} -'


def vector_test(rendered, tests: list) -> subprocess.CompletedProcess:
    """`vector test` on the rendered forwarder: each case inserts lines where the app's lines enter."""
    folder = rendered / APP["host"]
    (folder / "tests.yaml").write_text(yaml.safe_dump({"tests": tests}, width=200))
    return subprocess.run(["docker", "run", "--rm", "-v", f"{folder}:/cfg:ro", inv.monitoring["images"]["vector"],
                           "test", "/cfg/forwarder.yaml", "/cfg/tests.yaml"], capture_output=True, text=True, timeout=120)


def case(name, lines, output, condition, silent=None):
    return {"name": name, "inputs": [{"insert_at": "label", "type": "log", "log_fields": {"message": l}} for l in lines],
            "outputs": [{"extract_from": output, "conditions": [{"type": "vrl", "source": condition}]}],
            **({"no_outputs_from": [silent]} if silent else {})}


def passes(line):
    return case(f"passes: {line}", [line], "kind._unmatched", f"!exists(.cut) && .message == {json.dumps(line)}", "kind.cut")


def test_forwarder_cuts_the_named_kind_and_nothing_else(docker, rendered):
    """The NOC's successful check is cut; the same request from a user, the check failing, another page
    and another client from the NOC's segment all go on exactly as written; twelve cut lines become one count line."""
    noc, request = CHECK["client"], CHECK["request"]
    user = inv.hosts["h1"]["address"].split("/")[0]
    cases = [
        case("the NOC's check is cut", [access_line(noc, request, 200)], "kind.cut", f'.cut == "{CHECK["name"]}"', "kind._unmatched"),
        passes(access_line(user, request, 200)),
        passes(access_line(noc, request, 500)),
        passes(access_line(noc, "GET /etc/ HTTP/1.1", 200)),
        passes(access_line("10.30.30.11", request, 200)),
        case("a heartbeat's worth of cut lines becomes one count line",
             [access_line(noc, request, 200)] * monitoring.cut_per_line(inv), "counted",
             f'.message == "netlab-cut: {monitoring.cut_per_line(inv)} {CHECK["name"]} lines"'),
    ]
    out = vector_test(rendered, cases)
    assert out.returncode == 0 and out.stdout.count("... passed") == len(cases), out.stdout + out.stderr


def test_an_unnamed_kind_is_never_cut(docker, rendered, tmp_path):
    """Negative: with no `cut` in the inventory the forwarder has no cut at all, so the check's own line passes."""
    raw = copy.deepcopy(yaml.safe_load(INVENTORY.read_text()))
    raw["logging"]["apps"][0].pop("cut")
    raw["logging"]["apps"][0]["silent_after"] = 30
    (tmp_path / "net.yml").write_text(yaml.safe_dump(raw, sort_keys=False))
    out = tmp_path / "build"
    render_all(load(tmp_path / "net.yml"), out)
    text = (out / APP["host"] / "forwarder.yaml").read_text()
    assert "match(" not in text and "inputs: [label]" in text, "a forwarder with nothing named to cut still filters"


def humanize1024(value: float) -> str:
    """Prometheus' humanize1024 template function, for the alert's expected summary."""
    for prefix in ("", "ki", "Mi", "Gi", "Ti"):
        if abs(value) < 1024:
            break
        value /= 1024
    return f"{value:.4g}{prefix}"


def promtool(rendered, tests: list) -> subprocess.CompletedProcess:
    folder = rendered / monitoring.host(inv)
    (folder / "rules_test.yml").write_text(yaml.safe_dump(
        {"rule_files": ["rules.yml"], "evaluation_interval": "1m", "tests": tests}, sort_keys=False, width=200))
    return subprocess.run(["docker", "run", "--rm", "-v", f"{folder}:/rules:ro", "-w", "/rules", "--entrypoint", "promtool",
                           inv.monitoring["images"]["prometheus"], "test", "rules", "rules_test.yml"],
                          capture_output=True, text=True, timeout=120)


def over_budget(source, value):
    labels = {**monitoring.target_labels(inv, source["node"]), "source": source["source"]}
    return {"exp_labels": labels, "exp_annotations": {"summary": f"{source['node']} {source['source']} sent {humanize1024(value)}B "
                                                                 f"in the last 24 h, over its {source['budget'] // 1024} KB budget"}}


def test_budget_rule_pages_once_a_source_passes_its_day(docker, rendered):
    """The rendered rule, in Prometheus' own evaluator: a source sending a fiftieth of its budget a minute is quiet
    at 49 minutes and pages at 51; a burst under its budget never pages; one over it pages at once; both still page
    hours after they stopped sending (a rule over the last hour would not), and a day after the spending stops nothing pages."""
    syslog = next(s for s in monitoring.log_sources(inv) if s["source"] == "syslog")
    app = next(s for s in monitoring.log_sources(inv) if s["source"] != "syslog")
    quiet = next(s for s in monitoring.log_sources(inv) if s["source"] == "syslog" and s["node"] != syslog["node"])
    # Whole bytes: a float sum can end a hair above the flat value after it, which reads as a counter reset.
    step = syslog["budget"] // 50

    def series(s, values):
        return {"series": f'log_bytes_total{{node="{s["node"]}",source="{s["source"]}"}}', "values": values}

    burst = app["budget"] + 1000
    tests = [{
        "interval": "1m",
        "input_series": [
            # A fiftieth of its budget a minute for an hour, then nothing.
            series(syslog, f"0+{step}x60 {60 * step}+0x1440"),
            # Most of a day's budget in one minute, then nothing: under it, so never a page.
            series(quiet, f"0 {quiet['budget'] - 1000}+0x1500"),
            # Over it in one minute: a page until the burst is more than a day old.
            series(app, f"0 {burst}+0x1500"),
        ],
        "alert_rule_test": [
            {"eval_time": "49m", "alertname": "LogIngestOverBudget", "exp_alerts": [over_budget(app, burst)]},
            {"eval_time": "51m", "alertname": "LogIngestOverBudget", "exp_alerts": [over_budget(syslog, 51 * step),
                                                                                   over_budget(app, burst)]},
            # Hours after both stopped sending, their day is still over: a day's total, not a pace.
            {"eval_time": "300m", "alertname": "LogIngestOverBudget", "exp_alerts": [over_budget(syslog, 60 * step),
                                                                                    over_budget(app, burst)]},
            # A day after the hour that spent it, nothing in the last 24 h is over any budget.
            {"eval_time": "1500m", "alertname": "LogIngestOverBudget", "exp_alerts": []},
        ],
    }]
    out = promtool(rendered, tests)
    assert out.returncode == 0, out.stdout + out.stderr


def test_every_source_has_a_budget_and_a_rule():
    rules = {(r["labels"]["node"], r["labels"]["source"]): r for r in monitoring.alert_rules(inv) if r["alert"] == "LogIngestOverBudget"}
    for s in monitoring.log_sources(inv):
        assert s["budget"] > 0, s
        assert rules[(s["node"], s["source"])]["expr"].endswith(f"[1d])) > {s['budget']}")
    assert set(rules) == {(s["node"], s["source"]) for s in monitoring.log_sources(inv)}


def problems(tmp_path, mutate) -> str:
    raw = copy.deepcopy(yaml.safe_load(INVENTORY.read_text()))
    mutate(raw)
    (tmp_path / "net.yml").write_text(yaml.safe_dump(raw, sort_keys=False))
    with pytest.raises(InventoryError) as exc:
        load(tmp_path / "net.yml")
    return "\n".join(exc.value.problems)


def test_budgets_the_store_cannot_hold_are_refused(tmp_path):
    def m(raw):
        raw["logging"]["budget"]["syslog_kb"] = 100 * 1024
    assert "over store_mb" in problems(tmp_path, m)


def test_a_source_without_a_budget_is_refused(tmp_path):
    def m(raw):
        raw["logging"]["apps"][0].pop("budget_kb")
    assert "needs a budget_kb over 0" in problems(tmp_path, m)


def test_a_cut_kind_netlab_does_not_know_is_refused(tmp_path):
    def m(raw):
        raw["logging"]["apps"][0]["cut"] = ["errors"]
    assert "cut 'errors' is not a kind netlab knows" in problems(tmp_path, m)


def test_a_cut_source_must_wait_a_heartbeat_before_it_is_silent(tmp_path):
    """Its forwarder sends a count line per heartbeat's worth of checks, so the old 30 s would page all the time."""
    def m(raw):
        raw["logging"]["apps"][0]["silent_after"] = 30
    assert "with a cut, its normal gap is the heartbeat" in problems(tmp_path, m)
