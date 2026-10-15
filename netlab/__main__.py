"""python -m netlab {validate,render,locate} [--inventory PATH] [--out DIR] [--src DEVICE --dst ADDRESS]"""
from __future__ import annotations

import argparse
import sys

from .inventory import InventoryError, load
from .locate import locate, summary
from .render import render_all


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab")
    p.add_argument("command", choices=["validate", "render", "locate"])
    p.add_argument("--inventory", default="inventory/network.yml")
    p.add_argument("--out", default="build")
    p.add_argument("--src", help="locate: a device we own to probe from")
    p.add_argument("--dst", help="locate: the address that is losing packets")
    args = p.parse_args(argv)
    try:
        inv = load(args.inventory)
    except InventoryError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.command == "validate":
        print(f"OK: {len(inv.devices)} devices, {len(inv.links)} links, no addressing problems")
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
    for path in render_all(inv, args.out):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
