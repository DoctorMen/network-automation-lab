"""Secret guardrails (OROS CON-7, ACC-4), offline: gitleaks blocks a seeded secret at commit and a
marked file at push, the history scan CI runs still finds a secret committed with --no-verify and
then deleted, this repo's rules catch an FRR BGP password the default rules miss, and the lab's own
secrets are created, stored and redacted without ever being printed, and reach a router only on stdin.

The gitleaks tests run the pinned image the hooks and CI use, so they need Docker and pre-commit.
Without them they skip on a laptop and fail in CI (CI=true), so they can't quietly stop running."""
import copy
import hashlib
import importlib.util
import os
import re
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


def tag(value):
    """What backups and drift output show instead of a password, as the redacting vtysh and the
    playbooks' password_tags compute it."""
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


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
    tagged = clear.replace(password, tag(password))
    assert scan(tagged, config=True).returncode == 0, "the redacted backup is flagged, so every drift run would be red"


def test_only_containerlabs_lab_ca_key_passes_the_build_scan(repo):
    """containerlab writes a new root CA key to build/clab-netauto/.tls/ca/ca.key on every deploy, and
    CI runs `make gitleaks` over build/ while the lab is up. That exact file passes; the same key
    anywhere else fails, another lab's CA key included, and the scan names the file and the rule
    without printing the key."""
    pem = "-----{} RSA PRIVATE KEY-----"  # filled in below, so this file holds no key
    body = [token_hex(32) for _ in range(12)]
    key = "\n".join([pem.format("BEGIN"), *body, pem.format("END"), ""])
    ca = repo / "build" / "clab-netauto" / ".tls" / "ca" / "ca.key"
    ca.parent.mkdir(parents=True)
    ca.write_text(key)
    assert history_scan(repo).returncode == 0, "containerlab's lab CA key fails the scan, so every CI deploy is red"

    for elsewhere in ("build/clab-other/.tls/ca/ca.key", "build/clab-netauto/.tls/r2/r2.key",
                      "build/clab-netauto/.tls/ca/ca.key.bak", "build/configs/r2/ca.key",
                      "results/clab-netauto/.tls/ca/ca.key"):
        stray = repo / elsewhere
        stray.parent.mkdir(parents=True, exist_ok=True)
        stray.write_text(key)
        scan = history_scan(repo)
        stray.unlink()
        assert scan.returncode != 0, f"a private key at {elsewhere} passed the scan"
        assert "private-key" in scan.stdout and elsewhere in scan.stdout, "the scan failed without naming the rule and the file"
        assert not any(line in scan.stdout for line in body), "the scan printed the key"


def vtysh_redacted():
    spec = importlib.util.spec_from_file_location("vtysh_redacted", ROOT / "ansible" / "files" / "vtysh_redacted.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_redacting_vtysh_tags_or_drops_passwords():
    """The router-side vtysh swaps a password for its sha256 tag, or drops the line, and leaves every other line alone."""
    password = token_hex(16)
    config = f"router bgp 65001\n neighbor 198.51.100.1 remote-as 65100\n neighbor 198.51.100.1 password {password}\nexit\n"
    redact = vtysh_redacted().redact
    assert redact(config) == config.replace(password, tag(password))
    assert redact(config, "drop") == config.replace(f" neighbor 198.51.100.1 password {password}\n", "")
    assert redact("interface lo\n description password reset desk\n") == "interface lo\n description password reset desk\n"


def test_secret_store_is_private_and_never_overwritten(tmp_path):
    """`make secrets` creates each missing secret 0600 in a 0700 folder, keeps an existing one, and prints names, never values."""
    inv = load(INVENTORY)
    store = tmp_path / "store"
    created = secrets.ensure(inv, store)
    assert [p.name for p in created] == secrets.names(inv) == ["bgp-r2-isp"]
    assert stat.S_IMODE(store.stat().st_mode) == 0o700 and stat.S_IMODE(created[0].stat().st_mode) == 0o600
    value = (store / "bgp-r2-isp").read_text().strip()
    assert len(value) == 32 and secrets.ensure(inv, store) == [] and (store / "bgp-r2-isp").read_text().strip() == value
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


ANSIBLE = ROOT / "ansible"
# A process's command line and environment are in /proc/<pid>/cmdline and environ, which other
# processes on the machine can read. These are the parts of a task that end up there.
EXPOSED = ("cmd", "argv", "_raw_params")


def tasks(items):
    """Every task in a list of plays or tasks, inside blocks too."""
    for item in items or []:
        nested = [k for k in ("tasks", "pre_tasks", "post_tasks", "handlers", "block", "rescue", "always") if k in item]
        if nested:
            for k in nested:
                yield from tasks(item[k])
        else:
            yield item


def levels(items):
    """Every play, block and task in a list of plays or tasks, each before what it holds. Ansible hands a
    play's or a block's environment and vars down to every task in it, so each level counts."""
    for item in items or []:
        yield item
        for k in ("tasks", "pre_tasks", "post_tasks", "handlers", "block", "rescue", "always"):
            if k in item:
                yield from levels(item[k])


def exposed(task):
    """(where, value) for each part of a task that becomes a command line or an environment, and stdin."""
    found = [("environment", task.get("environment"))]
    found += [(f"args.{k}", v) for k, v in (task.get("args") or {}).items() if k != "stdin"]
    stdin = (task.get("args") or {}).get("stdin")
    for module, params in task.items():
        if "." not in module and module not in ("command", "shell", "raw", "script"):
            continue  # a task keyword (name, when, loop...), not the module
        if isinstance(params, str):
            found.append(("_raw_params", params))  # free form: the whole string is the command line
        elif isinstance(params, dict):
            found += [(k, params[k]) for k in EXPOSED if k in params]
            stdin = params.get("stdin", stdin)
    return found, stdin


def secret_leaks(folder):
    """(leaks, tasks with a secret on stdin) for the playbooks in folder: each play, block or task that
    puts a secret-store lookup, or a variable built from one, where /proc shows it."""
    files = sorted(folder.glob("*.yml")) + sorted((folder / "tasks").glob("*.yml"))
    plays = {path: yaml.safe_load(path.read_text()) for path in files}
    defined = {}
    for path in sorted((folder / "group_vars").glob("*.yml")):
        defined.update(yaml.safe_load(path.read_text()) or {})
    for items in plays.values():
        for level in levels(items):  # plays', blocks' and tasks' vars
            defined.update(level.get("vars") or {})
    # secrets_dir is the store; anything whose value reads from it, directly or through another such
    # variable (password_tags), carries a secret too.
    names = {"secrets_dir"}
    while more := {k for k, v in defined.items() if k not in names and re.search(rf"\b({'|'.join(names)})\b", str(v))}:
        names |= more
    secret = re.compile(rf"\b({'|'.join(sorted(names))})\b")

    leaks, on_stdin = [], []
    for path, items in plays.items():
        for level in levels(items):
            found, stdin = exposed(level)
            leaks += [f"{path.relative_to(folder.parent)}: {level.get('name', 'unnamed')} ({where})"
                      for where, value in found if value and secret.search(str(value))]
            if stdin and secret.search(str(stdin)):
                on_stdin.append(level.get("name"))
    return leaks, on_stdin


def test_secrets_reach_a_router_only_on_stdin():
    """No play, block or task puts a secret-store lookup, or a variable built from one, in cmd, argv, free-form arguments, args or environment, where /proc shows it; stdin is the one way in."""
    leaks, on_stdin = secret_leaks(ANSIBLE)
    assert not leaks, f"a secret reaches a command line or an environment: {leaks}"
    assert on_stdin, "no task reads the secret store any more, so this check sees nothing"


def test_a_secret_in_a_play_or_block_environment_is_found(tmp_path):
    """A lookup in a play's or a block's environment reaches every task in it, and a block var built from one can be used on a command line: all three are named."""
    copy = tmp_path / "ansible"
    shutil.copytree(ANSIBLE, copy)
    path = copy / "deploy.yml"
    plays = yaml.safe_load(path.read_text())
    lookup = "{{ lookup('file', secrets_dir ~ '/bgp-r2-isp') }}"
    plays[0]["environment"] = {"PLAY_PW": lookup}
    block = next(t for t in plays[0]["tasks"] if "block" in t)
    block.update(environment={"BLOCK_PW": lookup}, vars={"pw_in_block": lookup})
    block["block"].append({"name": "Echo it", "ansible.builtin.command": "echo {{ pw_in_block }}"})
    path.write_text(yaml.safe_dump(plays, sort_keys=False))
    assert sorted(secret_leaks(copy)[0]) == [
        f"ansible/deploy.yml: {block['name']} (environment)",
        "ansible/deploy.yml: Echo it (_raw_params)",
        f"ansible/deploy.yml: {plays[0]['name']} (environment)",
    ]


def test_every_running_config_read_goes_through_the_redacting_vtysh():
    """Every task that reads a router's running config (a plan, a backup, the rollout's fallback) or reloads one uses the redacting vtysh, and a reload or a fallback saved on the router leaves the password lines out, so a rollback neither deletes nor sets a password."""
    problems = []
    for path in sorted(ANSIBLE.glob("*.yml")) + sorted((ANSIBLE / "tasks").glob("*.yml")):
        for task in tasks(yaml.safe_load(path.read_text())):
            found, _ = exposed(task)
            command = "\n".join(str(v) for where, v in found if where != "environment" and v)
            drop = (task.get("environment") or {}).get("NETLAB_PASSWORDS") == "drop"
            name = f"{path.relative_to(ROOT)}: {task.get('name', 'unnamed task')}"
            if "frr-reload.py" in command and "--bindir {{ vtysh_dir }}" not in command:
                problems.append(f"{name}: frr-reload.py reads the running config with the real vtysh")
            if "frr-reload.py" in command and "--reload" in command and not drop:
                problems.append(f"{name}: a reload that sees password lines deletes a password it doesn't expect")
            for line in command.splitlines():
                if "show running-config" in line and "{{ vtysh_dir }}/vtysh" not in line:
                    problems.append(f"{name}: reads the running config with the real vtysh, password in clear")
                elif "show running-config" in line and ">" in line and not drop:
                    problems.append(f"{name}: saves the running config on the router with its password lines")
    assert not problems, problems


def test_a_failed_password_command_never_prints_the_password(tmp_path):
    """When setting a BGP password fails (docker exec exits 1 here), pytest's report names the failed
    command, but neither the terminal output nor the JUnit file holds the password: the repo's pytest.ini
    keeps tracebacks short, and the long style would print the helper's arguments."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "docker").write_text("#!/bin/sh\ncat >/dev/null\nexit 1\n")
    (bindir / "docker").chmod(0o755)
    case = tmp_path / "test_case.py"
    case.write_text("import os\nfrom tests.live.conftest import Node\nfrom tests.live.test_secrets import set_password\n\n\n"
                    "def test_set():\n    end = {'router': 'isp', 'asn': 65100, 'neighbor': '198.51.100.0'}\n"
                    "    set_password(lambda name: Node('lab', name), end, os.environ['THE_PASSWORD'])\n")
    password = token_hex(16)
    run = subprocess.run([sys.executable, "-m", "pytest", "-c", str(ROOT / "pytest.ini"), "--rootdir", str(tmp_path),
                          "-p", "no:cacheprovider", str(case), f"--junitxml={tmp_path / 'case.xml'}"],
                         cwd=tmp_path, capture_output=True, text=True, timeout=120,
                         env={**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
                              "PYTHONPATH": str(ROOT), "THE_PASSWORD": password})
    assert run.returncode == 1 and "CalledProcessError" in run.stdout, run.stdout[-2000:]
    assert password not in run.stdout + run.stderr, "the password is in pytest's terminal output"
    assert password not in (tmp_path / "case.xml").read_text(), "the password is in the JUnit file CI uploads"
