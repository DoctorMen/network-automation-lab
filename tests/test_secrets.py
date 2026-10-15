"""Secret guardrails (OROS CON-7, ACC-4), offline: gitleaks blocks a seeded secret at commit and a
marked file at push, the history scan CI runs still finds a secret committed with --no-verify and
then deleted, this repo's rules catch an FRR BGP password the default rules miss, and the lab's own
secrets are created, stored and redacted without ever being printed.

The gitleaks tests run the pinned image the hooks and CI use, so they need Docker and pre-commit.
Without them they skip on a laptop and fail in CI (CI=true), so they can't quietly stop running."""
import copy
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from secrets import token_hex

import pytest
import yaml

from netlab import secrets
from netlab.inventory import InventoryError, load
from netlab.render import render_all

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "inventory" / "network.yml"
IMAGE = "zricethezav/gitleaks:v8.21.2"
MARKER = "NETAUTO-" + "CONFIDENTIAL"  # split, so this file isn't a marked file itself


def needs(ok, what):
    if not ok:
        if os.environ.get("CI"):
            pytest.fail(f"{what} is missing, and CI must run this test")
        pytest.skip(f"{what} is not available")


@pytest.fixture(scope="module")
def docker():
    needs(shutil.which("docker") and subprocess.run(["docker", "info"], capture_output=True).returncode == 0, "Docker")


@pytest.fixture(scope="module")
def pre_commit(docker):
    exe = Path(sys.executable).with_name("pre-commit")
    needs(exe.exists(), "pre-commit (pip install -r requirements.txt)")
    return exe


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def token():
    """A GitHub token gitleaks' default rules know, made up for each run so none is ever committed."""
    return "ghp_" + token_hex(18)


@pytest.fixture
def repo(tmp_path, pre_commit):
    """A new repo with this repo's hook config and gitleaks rules, and the hooks installed."""
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "test")
    for name in (".pre-commit-config.yaml", ".gitleaks.toml"):
        shutil.copy(ROOT / name, path / name)
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "guardrails")
    subprocess.run([pre_commit, "install"], cwd=path, check=True, capture_output=True)
    return path


def commit(repo, name, text, *flags):
    (repo / name).write_text(text)
    git(repo, "add", name)
    return git(repo, "commit", "-m", f"add {name}", *flags)


def history_scan(repo):
    """What the CI `secrets` job runs: `make gitleaks`, here on another repo."""
    return subprocess.run(["make", "-s", "-f", str(ROOT / "Makefile"), "gitleaks"], cwd=repo, capture_output=True, text=True)


def test_staged_secret_is_blocked_at_commit(repo):
    """The commit hook lets a clean commit through and stops one that stages a token, without printing it."""
    assert commit(repo, "notes.txt", "nothing secret\n").returncode == 0, "the hook blocks a clean commit"
    secret = token()
    blocked = commit(repo, "app.py", f'TOKEN = "{secret}"\n')
    assert blocked.returncode != 0, "a commit with a GitHub token went through"
    output = blocked.stdout + blocked.stderr
    assert "github-pat" in output and secret not in output
    assert "app.py" not in git(repo, "log", "--name-only", "--format=").stdout


def test_history_scan_finds_a_secret_committed_with_no_verify(repo):
    """--no-verify skips the hook, and deleting the file afterwards doesn't help: the history scan still names the commit."""
    assert history_scan(repo).returncode == 0, "the history scan fails on a clean repo, so a failure proves nothing"
    assert commit(repo, "app.py", f'TOKEN = "{token()}"\n', "--no-verify").returncode == 0
    leaked = git(repo, "rev-parse", "HEAD").stdout.strip()
    git(repo, "rm", "-q", "app.py")
    git(repo, "commit", "-q", "-m", "remove it again")
    scan = history_scan(repo)
    assert scan.returncode != 0, "the history scan missed a token deleted after it was committed"
    assert "github-pat" in scan.stdout and leaked in scan.stdout


def test_marked_file_is_blocked_at_push_and_alerted_by_ci(repo, tmp_path):
    """A file carrying the confidential marker is refused by the push hook; pushed anyway with --no-verify, the CI scan of the pushed repo goes red and names it."""
    remote = tmp_path / "public.git"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    git(repo, "remote", "add", "origin", str(remote))
    assert git(repo, "push", "-q", "origin", "main").returncode == 0, "the push hook blocks a clean push"
    pushed = git(remote, "rev-parse", "main").stdout

    assert commit(repo, "plan.md", f"{MARKER}\nnext year's prices\n", "--no-verify").returncode == 0
    refused = git(repo, "push", "origin", "main")
    assert refused.returncode != 0, "the push hook let a marked file out"
    assert "netauto-confidential-marker" in refused.stdout + refused.stderr
    assert git(remote, "rev-parse", "main").stdout == pushed, "the marked commit reached the remote"

    # --no-verify skips the push hook too. CI checks out what was pushed, with its whole history.
    assert git(repo, "push", "-q", "--no-verify", "origin", "main").returncode == 0
    clone = tmp_path / "ci-checkout"
    git(tmp_path, "clone", "-q", str(remote), str(clone))
    alert = history_scan(clone)
    assert alert.returncode != 0 and "netauto-confidential-marker" in alert.stdout, "CI's scan didn't flag the marked file"


def test_frr_password_rule_catches_what_default_rules_miss(tmp_path, docker):
    """A router backup with a BGP password in clear passes gitleaks' default rules and fails this repo's; the sha256 tag backups really carry passes both."""
    password = token_hex(16)
    clear = f"router bgp 65001\n neighbor 198.51.100.1 remote-as 65100\n neighbor 198.51.100.1 password {password}\n"

    def scan(text, config):
        folder = tmp_path / f"scan-{token_hex(4)}"
        folder.mkdir()
        (folder / "r2.conf").write_text(text)
        args = ["--config", "/scan/.gitleaks.toml"] if config else []
        if config:
            shutil.copy(ROOT / ".gitleaks.toml", folder / ".gitleaks.toml")
        return subprocess.run(["docker", "run", "--rm", "-v", f"{folder}:/scan", IMAGE, "dir", "/scan", *args,
                               "--redact", "--verbose", "--no-banner"], capture_output=True, text=True)

    assert scan(clear, config=False).returncode == 0, "gitleaks' default rules now catch FRR passwords; the custom rule may be redundant"
    caught = scan(clear, config=True)
    assert caught.returncode != 0 and "frr-bgp-neighbor-password" in caught.stdout and password not in caught.stdout
    tagged = clear.replace(password, secrets.tag(password))
    assert scan(tagged, config=True).returncode == 0, "the redacted backup is flagged, so every drift run would be red"


def vtysh_redacted():
    spec = importlib.util.spec_from_file_location("vtysh_redacted", ROOT / "ansible" / "files" / "vtysh_redacted.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_redacting_vtysh_tags_or_drops_passwords():
    """The router-side vtysh swaps a password for the same tag netlab computes, or drops the line, and leaves every other line alone."""
    password = token_hex(16)
    config = f"router bgp 65001\n neighbor 198.51.100.1 remote-as 65100\n neighbor 198.51.100.1 password {password}\nexit\n"
    redact = vtysh_redacted().redact
    assert redact(config) == config.replace(password, secrets.tag(password))
    assert redact(config, "drop") == config.replace(f" neighbor 198.51.100.1 password {password}\n", "")
    assert redact("interface lo\n description password reset desk\n") == "interface lo\n description password reset desk\n"


def test_secret_store_is_private_and_never_overwritten(tmp_path):
    """`make secrets` creates each missing secret 0600 in a 0700 folder, keeps an existing one, and prints names, never values."""
    inv = load(INVENTORY)
    store = tmp_path / "store"
    created = secrets.ensure(inv, store)
    assert [p.name for p in created] == secrets.names(inv) == ["bgp-r2-isp"]
    assert stat.S_IMODE(store.stat().st_mode) == 0o700 and stat.S_IMODE(created[0].stat().st_mode) == 0o600
    value = secrets.read("bgp-r2-isp", store)
    assert len(value) == 32 and secrets.ensure(inv, store) == [] and secrets.read("bgp-r2-isp", store) == value
    out = subprocess.run([sys.executable, "-m", "netlab", "secrets"], cwd=ROOT, capture_output=True, text=True,
                         env={**os.environ, "NETLAB_SECRETS": str(store)}, check=True)
    assert "bgp-r2-isp" in out.stdout and value not in out.stdout + out.stderr


def test_no_rendered_file_holds_a_password(tmp_path):
    """build/ names each session's secret and never holds a password line: the routers get it from `make apply` only."""
    render_all(load(INVENTORY), tmp_path)
    leaks = [str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_file() and " password " in p.read_text()]
    assert not leaks, f"rendered files with a password line: {leaks}"
    hostvars = yaml.safe_load((tmp_path / "ansible_inventory.yml").read_text())["all"]["children"]["routers"]["hosts"]
    assert hostvars["r2"]["bgp_md5"] == [{"asn": 65001, "peer": "isp", "neighbor": "198.51.100.1", "secret": "bgp-r2-isp"}]


def test_bgp_auth_names_a_real_session_and_a_secret_file(tmp_path):
    """An MD5 entry for two routers that don't peer, or with a password where the secret's name belongs, fails validation."""
    raw = yaml.safe_load(INVENTORY.read_text())
    bad = copy.deepcopy(raw)
    bad["bgp_auth"] = [{"routers": ["r1", "isp"], "secret": "bgp-r1-isp"}, {"routers": ["r2", "isp"], "secret": "Hunter2!"}]
    path = tmp_path / "net.yml"
    path.write_text(yaml.safe_dump(bad))
    with pytest.raises(InventoryError) as exc:
        load(path)
    assert "bgp_auth #1: r1 has no BGP session with isp" in exc.value.problems
    assert "bgp_auth #2: secret must be a file name such as bgp-r2-isp, not a password" in exc.value.problems
