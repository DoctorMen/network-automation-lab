"""Back up the captured configs to a restic repository, and judge the backup where it lands.

A backup job that trusts its own exit status can lie. `restic backup` exits 0 when the data it
deduplicates against is already corrupt at the destination, and a job that creates its repository
when none is found writes happily into an unmounted mountpoint. So this job never creates the
repository, refuses a capture that is missing any inventory device or holds a lab secret in clear,
and then reads the snapshot back from the destination: every file there, each with the sha256 of the
capture and no secret in it, and `restic check --read-data` clean. Any problem fails the job.
(OROS 0.3 REC-1.)

python -m netlab.backup init --repo PATH --password-file FILE   once, by hand
python -m netlab.backup run  --repo PATH --password-file FILE   after `make drift`
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import secrets
import subprocess
import sys
import tarfile
from pathlib import Path

import yaml

from . import secrets as lab_secrets
from .inventory import Inventory, load
from .render import render_edge

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "restic/restic:0.16.4"


class BackupError(RuntimeError):
    """Raised with every problem found, not just the first."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("Backup failed:\n  - " + "\n  - ".join(problems))


def expected_files(inv: Inventory) -> list[str]:
    """What `make drift` captures into backups/: one running config per router, one ruleset per
    firewall, and one ruleset per router with an edge.sh (drift.yml's edge_routers: r2's internet
    filter, r3's reverse-path filter)."""
    return ([f"{r}.conf" for r in inv.routers] + [f"{f}.rules" for f in inv.firewalls]
            + [f"{r}.rules" for r in inv.routers if render_edge(inv, r)])


def secret_values(inv: Inventory, where: Path | None = None) -> tuple[dict[str, bytes], list[str]]:
    """({secret name: value}, problems) for every secret the inventory names. A secret whose file is
    missing is a problem: the capture could hold it and nobody could tell."""
    where = where or lab_secrets.store()
    values, problems = {}, []
    for name in lab_secrets.names(inv):
        path = where / name
        if path.is_file() and path.read_bytes().strip():
            values[name] = path.read_bytes().strip()
        else:
            problems.append(f"no secret {name} in {where}, so the capture can't be checked for it; nothing was sent")
    return values, problems


def holding_a_secret(files: dict[str, bytes], values: dict[str, bytes]) -> list[str]:
    """`<file> holds the <name> secret in clear` for each pair, naming the secret, never its value."""
    return [f"{f} holds the {name} secret in clear" for f, data in files.items() for name, v in values.items() if v in data]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def restic(repo: Path, password_file: Path, *args: str, src: Path | None = None) -> subprocess.CompletedProcess:
    """One restic command in a throwaway container. stdout stays bytes, because `dump` writes a tar.

    --mount, not -v: given a host path that doesn't exist, -v creates it, which is exactly the
    "quietly write to local disk" this job must not do. --mount refuses a missing source.
    --no-cache: otherwise restic keeps a copy of the repository's metadata on local disk.
    --user: the files restic writes belong to whoever runs the job, so CI can cache them.
    """
    cmd = ["docker", "run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
           "--mount", f"type=bind,src={repo.resolve()},dst=/repo",
           "--mount", f"type=bind,src={password_file.resolve()},dst=/pass,readonly",
           "-e", "RESTIC_REPOSITORY=/repo", "-e", "RESTIC_PASSWORD_FILE=/pass"]
    if src is not None:
        cmd += ["--mount", f"type=bind,src={src.resolve()},dst=/src,readonly"]
    return subprocess.run([*cmd, IMAGE, "--no-cache", *args], capture_output=True, timeout=300)


def err(r: subprocess.CompletedProcess) -> str:
    return r.stderr.decode(errors="replace").strip()


def init(repo: Path, password_file: Path) -> None:
    """Create the repository and a random password for it. A person runs this once; `run` never does."""
    if repo.exists() and any(repo.iterdir()):
        raise BackupError([f"{repo} is not empty; not creating a repository there"])
    repo.mkdir(parents=True, exist_ok=True)
    if not password_file.exists():
        password_file.parent.mkdir(parents=True, exist_ok=True)
        # Opened 0600 from the start, so the password is never readable by others, even briefly.
        fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(16) + "\n")
    r = restic(repo, password_file, "init")
    if r.returncode:
        raise BackupError([f"restic init failed (exit {r.returncode}): {err(r)}"])


def compare(captured: dict[str, str], at_destination: dict[str, str]) -> list[str]:
    """Every difference between the capture and what the destination holds, by file name and sha256."""
    problems = [f"{f}: not at the destination" for f in captured if f not in at_destination]
    problems += [f"{f}: sha256 at the destination {at_destination[f][:12]}, captured {captured[f][:12]}"
                 for f in captured if f in at_destination and at_destination[f] != captured[f]]
    problems += [f"{f}: at the destination but not in the capture" for f in at_destination if f not in captured]
    return problems


def verify(repo: Path, password_file: Path, snapshot: str, captured: dict[str, str],
           values: dict[str, bytes] | None = None) -> list[str]:
    """Read the snapshot back from the destination, compare it with the capture, and search every
    file there for each secret's value."""
    dump = restic(repo, password_file, "dump", "--archive", "tar", snapshot, "/src")
    if dump.returncode:
        return [f"reading snapshot {snapshot[:8]} back failed (exit {dump.returncode}): {err(dump)}"]
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(dump.stdout)) as tar:
        for member in tar.getmembers():
            if member.isfile():
                contents[Path(member.name).name] = tar.extractfile(member).read()
    problems = compare(captured, {f: sha256(data) for f, data in contents.items()})
    problems += [f"at the destination: {p}" for p in holding_a_secret(contents, values or {})]
    check = restic(repo, password_file, "check", "--read-data")
    if check.returncode:
        problems.append(f"restic check --read-data failed (exit {check.returncode}): {(err(check).splitlines() or [''])[-1]}")
    return problems


def run(inv: Inventory, lab: str, repo: Path, password_file: Path, capture: Path,
        secrets_dir: Path | None = None) -> dict[str, str]:
    """Back up the capture and verify it at the destination. Returns {file: sha256}; raises BackupError."""
    # The destination first, before anything is read or sent.
    if not (repo / "config").is_file():
        raise BackupError([f"no restic repository at {repo}: the target is not mounted, or was never created. "
                           "This job never creates one, because a new repository on an unmounted mountpoint "
                           "would hide exactly that. Create it once by hand: make backup-init"])
    if not password_file.is_file():
        raise BackupError([f"no password file at {password_file}"])
    files = expected_files(inv)
    missing = [f for f in files if not (capture / f).is_file() or (capture / f).stat().st_size == 0]
    if missing:
        raise BackupError([f"{f} is missing or empty in {capture}, so {f.split('.')[0]} would not be backed up; "
                           "nothing was sent (run make drift first)" for f in missing])
    # The capture goes through the redacting vtysh (decision 0016), so a password in it means that
    # broke. Checked before sending: a snapshot can't be taken back out of the repository quietly.
    values, problems = secret_values(inv, secrets_dir)
    problems += [f"{p}; nothing was sent" for p in holding_a_secret({f: (capture / f).read_bytes() for f in files}, values)]
    if problems:
        raise BackupError(problems)
    captured = {f: sha256((capture / f).read_bytes()) for f in files}

    r = restic(repo, password_file, "backup", "--json", "--host", lab, *[f"/src/{f}" for f in files], src=capture)
    if r.returncode:
        raise BackupError([f"restic backup failed (exit {r.returncode}): {err(r)}"])
    snapshot = json.loads(r.stdout.splitlines()[-1])["snapshot_id"]
    print(f"restic backup exited 0: snapshot {snapshot[:8]} of {len(files)} files. Reading it back from {repo}")

    problems = verify(repo, password_file, snapshot, captured, values)
    if problems:
        raise BackupError(problems)
    for f, digest in captured.items():
        print(f"  {f:<10} sha256 {digest[:16]}  same at the destination")
    print(f"verified snapshot {snapshot[:8]}: {len(files)} files, every inventory device, no secret in clear "
          f"({len(values)} searched for), restic check --read-data clean")
    return captured


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netlab.backup")
    p.add_argument("command", choices=["init", "run"])
    p.add_argument("--repo", required=True, type=Path, help="the restic repository (the backup destination)")
    p.add_argument("--password-file", required=True, type=Path)
    p.add_argument("--capture", default=ROOT / "backups", type=Path, help="what make drift collected")
    p.add_argument("--inventory", default=ROOT / "inventory" / "network.yml")
    p.add_argument("--build", default=ROOT / "build", type=Path)
    args = p.parse_args(argv)
    try:
        if args.command == "init":
            init(args.repo, args.password_file)
            print(f"created a restic repository at {args.repo}; its password is in {args.password_file}")
        else:
            lab = yaml.safe_load((args.build / "topology.clab.yml").read_text())["name"]
            run(load(args.inventory), lab, args.repo, args.password_file, args.capture)
    except BackupError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
