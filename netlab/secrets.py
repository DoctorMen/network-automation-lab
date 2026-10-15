"""The lab's secret store: one file per secret, readable only by its owner, never rendered into build/.

Where it is: $NETLAB_SECRETS, or .secrets/ in the repo (gitignored). CI points NETLAB_SECRETS at a
fresh directory under $RUNNER_TEMP, so every run gets new passwords. Nothing here prints a value."""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from .inventory import Inventory

ROOT = Path(__file__).resolve().parent.parent


def store() -> Path:
    return Path(os.environ.get("NETLAB_SECRETS") or ROOT / ".secrets")


def names(inv: Inventory) -> list[str]:
    """Every secret the inventory refers to, by name."""
    return [auth["secret"] for auth in inv.raw.get("bgp_auth", [])]


def ensure(inv: Inventory, where: Path | None = None) -> list[Path]:
    """Create each secret the inventory names that doesn't exist yet. Returns the files it created."""
    where = where or store()
    where.mkdir(mode=0o700, parents=True, exist_ok=True)
    created = []
    for name in names(inv):
        path = where / name
        if path.exists():
            continue
        # 0600 from the moment it exists, and O_EXCL so an existing secret is never overwritten.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(16) + "\n")  # 128 random bits, as 32 hex characters
        created.append(path)
    return created


def read(name: str, where: Path | None = None) -> str:
    return ((where or store()) / name).read_text().strip()


def tag(value: str) -> str:
    """What backups and drift output show instead of a password. Safe to publish only because the
    password is random: the sha256 of a guessable password could be brute-forced."""
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()
