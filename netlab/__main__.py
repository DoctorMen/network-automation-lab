"""python -m netlab {validate,render,locate,finding,secrets,nodes,images} [--inventory PATH] [--out DIR] [--src DEVICE --dst ADDRESS]
          finding [--bundle DIR] [--condition FILE] | finding --verify DIR

nodes prints the network's own nodes, comma-separated, for `containerlab deploy --node-filter` (the
lab without the NOC's sidecars); images prints every image the full lab runs, one per line."""
from __future__ import annotations

import argparse
import sys

from .inventory import InventoryError, load
from .locate import locate, summary
from .render import render_all
from . import monitoring, secrets
from .finding import verify as verify_bundle, write as write_bundle


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab")
    p.add_argument("command", choices=["validate", "render", "locate", "finding", "secrets", "nodes", "images"])
    p.add_argument("--inventory", default="inventory/network.yml")
    p.add_argument("--out", default="build")
    p.add_argument("--src", help="locate: a device we own to probe from")
    p.add_argument("--dst", help="locate: the address that is losing packets")
    p.add_argument("--bundle", default="results/finding", help="finding: the folder to write the bundle to")
    p.add_argument("--condition", help="finding, lab only: a script that recreates the fault on a fresh lab, kept in the bundle")
    p.add_argument("--verify", metavar="DIR", help="finding: only check an existing bundle")
    args = p.parse_args(argv)
    try:
        inv = load(args.inventory)
    except InventoryError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.command == "validate":
        print(f"OK: {len(inv.devices)} devices, {len(inv.links)} links, no addressing problems")
        return 0
    if args.command == "nodes":
        print(",".join(inv.devices))
        return 0
    if args.command == "images":
        print("\n".join(dict.fromkeys([inv.platform["image"], *(s["image"] for s in monitoring.sidecars(inv).values())])))
        return 0
    if args.command == "locate":
        if not (args.src and args.dst):
            p.error("locate needs --src and --dst")
        try:
            finding = locate(inv, args.out, args.src, args.dst)
        except PermissionError as exc:
            print(exc, file=sys.stderr)
            return 1
        print(summary(finding))
        print(f"wrote {args.out}/finding.json")
        return 0
    if args.command == "finding":
        if not args.verify:
            if not (args.src and args.dst):
                p.error("finding needs --src and --dst, or --verify DIR")
            try:
                f = write_bundle(inv, args.out, args.src, args.dst, args.bundle, args.condition)
            except (PermissionError, FileExistsError) as exc:
                print(exc, file=sys.stderr)
                return 1
            print(summary(f))
        bundle = args.verify or args.bundle
        problems = verify_bundle(bundle)
        for problem in problems:
            print(f"{bundle}: {problem}", file=sys.stderr)
        print(f"{bundle}: {'NOT ready to send' if problems else 'complete; re-run it with sh reproduce.sh'}")
        return 1 if problems else 0
    if args.command == "secrets":
        # Names and paths only: a value printed here would end up in a terminal or CI log.
        created = secrets.ensure(inv)
        for name in secrets.names(inv):
            print(f"{secrets.store() / name}: {'created (0600)' if secrets.store() / name in created else 'kept'}")
        return 0
    for path in render_all(inv, args.out):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
