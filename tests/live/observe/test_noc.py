"""The NOC's platform (decision 0018): each sidecar runs its pinned image in its node's network namespace,
every target answers, every rule the inventory implies is loaded, and the NOC listens on the campus only
where sources send to it."""
import json
import os
import subprocess

import yaml

from ..conftest import BUILD


def inspect(target, fmt):
    return subprocess.run(["docker", "inspect", "-f", fmt, target], capture_output=True, text=True, check=True).stdout.strip()


def netns(container):
    """The container's network namespace as the kernel names it (net:[inode]). Another user's /proc/<pid>/ns is
    closed to an unprivileged reader (the CI runner), so there it is read through sudo."""
    link = f"/proc/{inspect(container, '{{.State.Pid}}')}/ns/net"
    if os.geteuid() == 0:
        return os.readlink(link)
    return subprocess.run(["sudo", "-n", "readlink", link], capture_output=True, text=True, check=True).stdout.strip()


def test_sidecars_run_their_pinned_image_in_their_nodes_namespace(lab_name, mon):
    """Each sidecar runs the inventory's tag, resolved to the inventory's digest, in its node's network namespace."""
    nodes = yaml.safe_load((BUILD / "topology.clab.yml").read_text())["topology"]["nodes"]
    wrong = []
    for name in mon["sidecars"]:
        c, target = f"clab-{lab_name}-{name}", nodes[name]["network-mode"].split(":", 1)[1]
        image = inspect(c, "{{.Config.Image}}")
        if image != nodes[name]["image"] or image not in mon["digests"]:
            wrong.append(f"{name}: runs {image}, topology says {nodes[name]['image']}")
            continue
        digests = json.loads(inspect(inspect(c, "{{.Image}}"), "{{json .RepoDigests}}"))
        if not any(d.endswith("@" + mon["digests"][image]) for d in digests):
            wrong.append(f"{name}: {image} is {digests}, the inventory says {mon['digests'][image]}")
        ns = {netns(x) for x in (c, f"clab-{lab_name}-{target}")}
        if len(ns) != 1:
            wrong.append(f"{name}: not in {target}'s network namespace ({ns})")
    assert not wrong, "\n".join(wrong)


def test_every_target_answers_and_every_rule_is_loaded(noc):
    down = [(t["labels"]["job"], t["labels"].get("node"), t["lastError"]) for t in noc.targets() if t["health"] != "up"]
    assert not down, f"targets not answering: {down}"
    rendered = yaml.safe_load((BUILD / "noc" / "rules.yml").read_text())["groups"][0]["rules"]
    loaded = noc.rules()
    # Prometheus prints each expression back in its own form, so the rules are compared by name and labels.
    assert sorted((r["alert"], sorted(r["labels"].items())) for r in rendered) == \
        sorted((r["name"], sorted(r.get("labels", {}).items())) for r in loaded)


def test_noc_listens_on_the_campus_only_for_its_sources(node, mon):
    """Everything on noc answers on 127.0.0.1 only, except the collector's syslog (UDP) and forwarder (TCP) ports."""
    noc = node(mon["host"])
    listeners = []
    for proto in ("t", "u"):
        for line in noc.run("netstat", f"-ln{proto}").stdout.splitlines():
            if line.startswith(("tcp", "udp")):
                listeners.append((line.split()[0], line.split()[3]))
    exposed = sorted({(p, a) for p, a in listeners if not a.startswith("127.0.0.1:")})
    rendered = yaml.safe_load((BUILD / "noc" / "vector.yaml").read_text())["sources"]
    allowed = {("udp", rendered["syslog"]["address"]), ("tcp", rendered["forwarders"]["address"])}
    assert set(exposed) <= allowed, f"noc answers on the campus beyond its sources' ports: {sorted(set(exposed) - allowed)}"
