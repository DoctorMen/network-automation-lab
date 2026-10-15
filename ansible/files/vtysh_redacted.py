#!/usr/bin/env python3
"""vtysh for the playbooks: the router's own vtysh, except that `show running-config` never prints a
BGP neighbor password in clear. Each playbook copies it to the router as /tmp/netlab-bin/vtysh, and
frr-reload.py uses it through --bindir. So no password leaves the router, and frr-reload never sees
one, which also keeps it out of frr-reload's log and off vtysh's command line (decision 0016).

NETLAB_PASSWORDS=tag (the default) replaces each password with its sha256 tag: for backups and diffs.
NETLAB_PASSWORDS=drop leaves the line out: for frr-reload --reload, which then neither deletes a
password the intended config doesn't hold nor tries to add one.
"""
import hashlib
import os
import re
import subprocess
import sys

VTYSH = "/usr/bin/vtysh"
# FRR 8.4: `neighbor <peer> password <line>`, and the line may contain spaces, so take the rest of it.
PASSWORD = re.compile(r"^(\s*neighbor\s\S+\spassword)\s(.+?)\s*$")


def redact(config: str, mode: str = "tag") -> str:
    out = []
    for line in config.splitlines(keepends=True):
        m = PASSWORD.match(line)
        if not m:
            out.append(line)
        elif mode != "drop":
            out.append(f"{m[1]} sha256:{hashlib.sha256(m[2].encode()).hexdigest()}\n")
    return "".join(out)


def main(argv: list[str]) -> int:
    if not any("show running-config" in arg for arg in argv):
        os.execv(VTYSH, [VTYSH, *argv])  # everything else goes to the real vtysh untouched
    run = subprocess.run([VTYSH, *argv], stdout=subprocess.PIPE, text=True)
    sys.stdout.write(redact(run.stdout, os.environ.get("NETLAB_PASSWORDS", "tag")))
    return run.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
