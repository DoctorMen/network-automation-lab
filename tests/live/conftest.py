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

    def run(self, *cmd, check=True, timeout=30) -> subprocess.CompletedProcess:
        return subprocess.run(["docker", "exec", self.container, *cmd],
                              capture_output=True, text=True, check=check, timeout=timeout)

    def vtysh(self, command: str) -> str:
        return self.run("vtysh", "-c", command).stdout

    def vtysh_json(self, command: str):
        return json.loads(self.vtysh(command + " json"))

    def ping(self, target: str, count: int = 3) -> bool:
        return self.run("ping", "-c", str(count), "-W", "2", target, check=False).returncode == 0

    def tcp_open(self, host: str, port: int) -> bool:
        return self.run("nc", "-z", "-w", "3", host, str(port), check=False).returncode == 0


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
