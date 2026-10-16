"""Version-exact: every node runs exactly what the inventory's platform block says."""
import json
import re
import subprocess


def inspect(target: str, fmt: str) -> str:
    return subprocess.run(["docker", "inspect", "-f", fmt, target],
                          capture_output=True, text=True, check=True).stdout.strip()


def test_running_version_matches_inventory(node, expected):
    """Every node runs the recorded image tag and digest, Alpine, busybox and FRR; routers' FRR reports that version."""
    want = expected["platform"]
    # The inventory's devices: the NOC's sidecars run images of their own (tests/live/observe/test_noc.py).
    nodes = expected["owners"]
    wrong = []
    for name in nodes:
        n = node(name)
        image = inspect(n.container, "{{.Config.Image}}")
        if image != want["image"]:
            wrong.append(f"{name}: created from {image}, inventory says {want['image']}")
        # A tag can be re-pushed upstream; the digest pins the exact build.
        digests = json.loads(inspect(inspect(n.container, "{{.Image}}"), "{{json .RepoDigests}}"))
        if not any(d.endswith("@" + want["digest"]) for d in digests):
            wrong.append(f"{name}: image digests {digests}, inventory says {want['digest']}")
        alpine = n.run("sh", "-c", ". /etc/os-release && echo $VERSION_ID").stdout.strip()
        if alpine != want["alpine"]:
            wrong.append(f"{name}: Alpine {alpine}, inventory says {want['alpine']}")
        packages = n.run("apk", "info", "-v").stdout.split()
        for pkg in ("frr", "busybox"):
            have = next((p for p in packages if re.match(rf"{pkg}-\d", p)), f"{pkg} not installed")
            if have != f"{pkg}-{want[pkg]}":
                wrong.append(f"{name}: {have}, inventory says {pkg}-{want[pkg]}")
    for router in expected["loopbacks"]:
        # "FRRouting 8.4.1_git (r1) on Linux(...)": the running daemons, not just the installed package.
        running = node(router).vtysh("show version").split()[1]
        packaged = want["frr"].rsplit("-r", 1)[0]  # apk adds a package release, "-r0"
        if running != packaged:
            wrong.append(f"{router}: show version says FRR {running}, inventory says {packaged}")
    assert not wrong, "lab does not match the inventory's platform:\n" + "\n".join(wrong)
