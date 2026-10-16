"""Is a newer kernel installed than the one running? One rule for `make verify`, CI's check of the
runner, and each router's pending-reboot metric (decision 0018).

Standard library only: render copies this file into build/monitoring/, and each router we own runs it
every few seconds (`python3 kernel.py > kernel.prom`) for node_exporter's textfile collector."""
from __future__ import annotations

import os
import platform
import re

MODULES = "/lib/modules"


def version_key(release: str) -> tuple[int, ...]:
    """'6.8.0-1017-azure' -> (6, 8, 0, 1017), so 6.10 sorts after 6.9."""
    return tuple(int(n) for n in re.findall(r"\d+", release))


def kernel_status(running: str, installed: list[str]) -> str:
    if not installed:
        return f"nothing to compare: no kernel installed on the node (it runs the host's {running})"
    newest = max(installed, key=version_key)
    if newest != running:
        return f"not in effect: {newest} is installed but {running} is running, reboot required"
    return f"in effect: {running} is the newest installed"


def textfile(running: str, installed: dict[str, float]) -> str:
    """Prometheus text format for {installed release: when its modules folder appeared (mtime)}.
    The reboot has been pending since the newest kernel was installed (0 when none is pending): the
    alert rule compares that with the inventory's reboot_window."""
    status = kernel_status(running, list(installed))
    pending = status.startswith("not in effect")
    since = installed[max(installed, key=version_key)] if pending else 0
    return "\n".join([
        "# HELP node_reboot_required 1 if a newer kernel is installed than the one running (netlab.kernel).",
        "# TYPE node_reboot_required gauge",
        f"node_reboot_required {int(pending)}",
        "# HELP node_reboot_required_since_seconds When the kernel waiting for a reboot was installed; 0 if none is.",
        "# TYPE node_reboot_required_since_seconds gauge",
        f"node_reboot_required_since_seconds {since:.0f}"]) + "\n"


if __name__ == "__main__":
    found = {}
    if os.path.isdir(MODULES):
        found = {name: os.stat(os.path.join(MODULES, name)).st_mtime for name in os.listdir(MODULES)}
    print(textfile(platform.release(), found), end="")
