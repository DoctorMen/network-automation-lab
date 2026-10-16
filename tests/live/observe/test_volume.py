"""OROS NOT-5, precise volume at the source (decision 0026): h2's own forwarder cuts one named kind of line,
the NOC's own web check, before it leaves h2, and counts it; every other line of the same log, the very
same request from a user included, still reaches the store. Every source's last 24 h at the collector is
within its daily budget."""
import time
import uuid

from ..conftest import wait_for


def test_noisy_kind_cut_at_the_source_while_wanted_lines_arrive(node, expected, mon, noc):
    """The NOC's check, sent three count lines' worth more, is written to h2's log but never reaches the collector,
    and is counted in the forwarder's count lines; the same request from h1, and a failed one from the NOC, arrive as written."""
    app = mon["apps"][0]
    kinds = mon["cuts"].get(f"{app['host']}/{app['name']}")
    assert kinds, f"{app['host']}'s {app['name']} log names no kind to cut, so there is no cut to prove"
    host, kind = node(app["host"]), kinds[0]
    labels = f'{{node="{app["host"]}",source="{app["name"]}"}}'
    url = f"http://{expected['hosts'][app['host']]}:{app['port']}/"
    noise, users, marker = 3 * mon["cut_per_line"], 3, f"NOT5-{uuid.uuid4().hex[:12]}"

    def written():
        """Lines in h2's own access log, as the app wrote them."""
        return host.run("cat", f"/applog/{app['name']}-{app['port']}.log").stdout.count("\n")
    before = written()
    received = noc.value(f"log_lines_total{labels}")
    since = time.time()
    # The noise: exactly the check's own request, from the NOC.
    node(mon["host"]).run("sh", "-c", f"for i in $(seq {noise}); do wget -q -O /dev/null {url}; done", timeout=60)
    # Wanted lines from the same log: the same request from a user, and one from the NOC that fails (404).
    node("h1").run("sh", "-c", f"for i in $(seq {users}); do wget -q -O /dev/null {url}; done")
    node(mon["host"]).run("wget", "-q", "-O", "/dev/null", url + marker, check=False)

    # Everything happened at the source: the app wrote every request.
    assert written() - before >= noise + users + 1, "h2's own log did not get every request, so this proves nothing"
    user = expected["hosts"]["h1"]
    same = f'{labels} |= "{user} - - " |= `"{kind["request"]}" 200 `'
    assert wait_for(lambda: len(noc.logs(same, since)) >= users, timeout=30, interval=1), \
        f"h1's {users} requests for the same page did not all reach the store"
    assert wait_for(lambda: noc.logs(f'{labels} |= "{marker}" |= " 404 "', since), timeout=30, interval=1), \
        "the NOC's failed request did not reach the store"
    # The noise never left h2: not one check line in the store, and the collector's count of h2's lines rose by
    # the wanted lines and a few count lines, not by the noise.
    assert not noc.logs(f"{labels} |~ `{kind['pattern']}`", since), "the NOC's check lines reached the store"
    # What was cut is counted: "netlab-cut: 12 web-check lines". The last count may still be filling.
    def cut():
        return sum(int(line.split()[1]) for _, _, line in noc.logs(f'{labels} |= "netlab-cut: " |= " {kind["name"]} lines"', since))
    assert wait_for(lambda: cut() > noise - mon["cut_per_line"], timeout=30, interval=1), \
        f"the forwarder's count lines account for {cut()} of the {noise} lines it cut"
    time.sleep(2 * mon["interval"])  # two scrapes, so the collector's counter is current
    rose = noc.value(f"log_lines_total{labels}") - received
    assert rose < noise / 2, f"the collector received {rose:.0f} lines from {app['host']}, so the cut is not at the source"


def test_every_source_within_its_budget(mon, noc):
    """Each source's last 24 h at the collector is under its daily budget, and its LogIngestOverBudget rule is loaded with that budget and quiet."""
    rules = {(r["labels"].get("node"), r["labels"].get("source")): r for r in noc.rules() if r["name"] == "LogIngestOverBudget"}
    day = {(r["node"], r["source"]): r["value"] for r in noc.query("increase(log_bytes_total[1d])")}
    for s in mon["sources"]:
        key = (s["node"], s["source"])
        # Prometheus prints the expression back in its own form (1.048576e+06), so the budget is compared as a number.
        assert key in rules and float(rules[key]["query"].rsplit("> ", 1)[1]) == s["budget"], f"{key}: no budget rule for {s['budget']} bytes"
        assert rules[key]["health"] == "ok" and rules[key]["state"] == "inactive", f"{key}: {rules[key]['health']}, {rules[key]['state']}"
        assert key in day, f"{key}: the collector has counted none of its bytes"
        assert day[key] <= s["budget"], f"{key}: {day[key]:.0f} bytes in the last 24 h, over its {s['budget']} byte budget"
