"""Live tests run against a deployed lab. They talk to nodes with `docker exec`,
which is exactly how you'd poke at a Containerlab node by hand."""
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILD = Path(os.environ.get("NETLAB_BUILD", ROOT / "build"))


def pytest_collection_modifyitems(items):
    for item in items:
        item.add_marker(pytest.mark.live)


@pytest.fixture(scope="session")
def expected():
    path = BUILD / "expected_state.json"
    if not path.exists():
        pytest.skip("lab not rendered; run `make deploy` first")
    return json.loads(path.read_text())


@pytest.fixture(scope="session")
def lab_name():
    import yaml
    return yaml.safe_load((BUILD / "topology.clab.yml").read_text())["name"]


class Node:
    def __init__(self, lab, name):
        self.name = name
        self.container = f"clab-{lab}-{name}"

    def run(self, *cmd, check=True, timeout=30, input=None) -> subprocess.CompletedProcess:
        # -i passes stdin through, e.g. a script for `python3 -`. Without input, stdin stays closed.
        interactive = ["-i"] if input is not None else []
        return subprocess.run(["docker", "exec", *interactive, self.container, *cmd], input=input,
                              capture_output=True, text=True, check=check, timeout=timeout)

    def vtysh(self, command: str) -> str:
        return self.run("vtysh", "-c", command).stdout

    def vtysh_json(self, command: str):
        return json.loads(self.vtysh(command + " json"))

    def ping(self, target: str, count: int = 3) -> bool:
        return self.run("ping", "-c", str(count), "-W", "2", target, check=False).returncode == 0

    def tcp_open(self, host: str, port: int) -> bool:
        return self.run("nc", "-z", "-w", "3", host, str(port), check=False).returncode == 0


def rule_counters(fw: Node) -> dict[str, tuple[str, int]]:
    """{rule name: (target, packets)} for the FORWARD chain, named by each rule's comment.

    -x prints exact packet counts; without it iptables abbreviates big ones to '101K'.
    A rule with no comment (say, one added by hand) is named by its position, so it still shows up.
    """
    counters = {}
    for pos, line in enumerate(fw.run("iptables", "-vnxL", "FORWARD").stdout.splitlines()[2:], start=1):
        cols = line.split()
        name = line.split("/* ")[1].split(" */")[0] if "/* " in line else f"rule {pos}"
        counters[name] = (cols[2], int(cols[0]))
    return counters


@pytest.fixture(scope="session")
def node(lab_name):
    cache = {}

    def get(name):
        if name not in cache:
            cache[name] = Node(lab_name, name)
        return cache[name]
    return get


def wait_for(predicate, timeout=90, interval=3):
    """Routing protocols converge in seconds, not instantly. Poll instead of sleeping blindly."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    return last
