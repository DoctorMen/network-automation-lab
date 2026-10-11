"""python -m netlab {validate,render} [--inventory PATH] [--out DIR]"""
from __future__ import annotations

import argparse
import sys

from .inventory import InventoryError, load
from .render import render_all


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab")
    p.add_argument("command", choices=["validate", "render"])
    p.add_argument("--inventory", default="inventory/network.yml")
    p.add_argument("--out", default="build")
    args = p.parse_args(argv)
    try:
        inv = load(args.inventory)
    except InventoryError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.command == "validate":
        print(f"OK: {len(inv.devices)} devices, {len(inv.links)} links, no addressing problems")
        return 0
    for path in render_all(inv, args.out):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
