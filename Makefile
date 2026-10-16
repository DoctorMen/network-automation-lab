# Common tasks. Run `make help` to list them.
PY      ?= python3
CLAB    ?= sudo containerlab
TOPO    := build/topology.clab.yml
LAB_ENV ?= local
NOTE    ?=

.PHONY: help validate render test deploy live drift apply locate measure destroy all
.PHONY: secrets gitleaks finding risks deploy-network observe coverage testevent alerts

help:            ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

validate:        ## Check the inventory for addressing mistakes
	$(PY) -m netlab validate

render: validate ## Generate configs, topology and expected state into build/
	$(PY) -m netlab render

test:            ## Offline tests (no lab needed)
	$(PY) -m pytest -q tests --ignore=tests/live --junitxml=results/offline.xml

deploy: render secrets ## Render, start the lab with Containerlab, then set what isn't rendered (BGP passwords)
	$(CLAB) deploy -t $(TOPO) --reconfigure
	$(MAKE) apply

deploy-network: render secrets ## As deploy, but the network's own nodes only: no NOC sidecars (CI's lab job)
	$(CLAB) deploy -t $(TOPO) --reconfigure --node-filter $$($(PY) -m netlab nodes)
	$(MAKE) apply

live:            ## Test the running lab: routing, firewall, failover, drift checks, locate (JUnit in results/)
	$(PY) -m pytest -v tests/live --ignore=tests/live/observe --junitxml=results/live.xml

observe:         ## Test the NOC on a full lab (make deploy): alerts, log arrival, central store (JUnit in results/)
	$(PY) -m pytest -v tests/live/observe --junitxml=results/observe.xml

coverage:        ## Every value a test or runbook reads from a device has a metric or log query (monitoring/coverage.yml)
	$(PY) -m netlab.coverage

testevent:       ## Send a marked line from every log source and show where it arrived: make testevent
	$(PY) -m netlab.observe testevent

alerts:          ## What is firing now, and what the NOC's pager (the webhook sink) has received
	$(PY) -m netlab.observe alerts

NODE    ?=
MINUTES ?= 15
.PHONY: evidence logs
evidence:        ## Before a planned reset: each node's state dump and own log, into results/evidence/ and the central store (NODE=r2 for one)
	$(PY) -m netlab.evidence take $(if $(NODE),--node $(NODE))

logs:            ## A node's last lines from the central store, also after a reset: make logs NODE=r2 MINUTES=15
	$(PY) -m netlab.evidence show --node "$(NODE)" --minutes "$(MINUTES)"

drift:           ## Back up routers and firewall, fail on drift or on a backup missing running config
	cd ansible && ansible-playbook drift.yml

apply:           ## Roll intended config out, canary first; roll back and stop on a failed health gate (diff only, no restarts)
	cd ansible && ansible-playbook deploy.yml

.PHONY: verify
verify:          ## Is each change in effect, not just installed: kernels, FRR daemons, h2's QoS classes (read-only)
	$(PY) -m netlab.verify

locate:          ## Find where loss starts on a path and who owns it: make locate SRC=h1 DST=203.0.113.1
	$(PY) -m netlab locate --src "$(SRC)" --dst "$(DST)"

finding:         ## Locate, then write and check a bundle anyone can re-run (results/finding/): make finding SRC=h1 DST=203.0.113.1
	$(PY) -m netlab finding --src "$(SRC)" --dst "$(DST)"

measure:         ## Record the running lab's RAM in docs/sizing/data/ (LAB_ENV=laptop NOTE="...")
	$(PY) -m netlab.measure --env $(LAB_ENV) --note "$(NOTE)"

risks:           ## Print the risk register with the config lines each risk covers; fail on an uncovered or stale one
	$(PY) -m netlab.risks

secrets:         ## Create any missing lab secret (BGP MD5 passwords) in NETLAB_SECRETS or .secrets/; never printed
	$(PY) -m netlab secrets

GITLEAKS ?= docker run --rm -v "$(CURDIR)":/repo zricethezav/gitleaks:v8.21.2
gitleaks:        ## Scan every commit, then backups/, results/ and build/ if present, for secrets (gitleaks)
	$(GITLEAKS) git /repo --config /repo/.gitleaks.toml --redact --verbose --no-banner
	for d in backups results build; do [ ! -d $$d ] || $(GITLEAKS) dir /repo/$$d --config /repo/.gitleaks.toml --redact --verbose --no-banner || exit 1; done

destroy:         ## Tear the lab down
	$(CLAB) destroy -t $(TOPO) --cleanup

all: test deploy live observe drift ## Everything CI does (CI's lab job runs live on deploy-network, its observe job observe)

# Backups (OROS REC-1, REC-3). BACKUP_REPO is the destination: a restic repository on a disk or share
# that outlives this machine. If it isn't mounted, `make backup` fails; it never creates one.
BACKUP_REPO     ?= /mnt/backup/netlab-restic
BACKUP_PASSWORD ?= $(HOME)/.config/netlab/restic-password
# The power cut for `make power-drill`: every node stopped and started again from its rendered files.
POWER_CYCLE     ?= $(CLAB) deploy -t $(TOPO) --reconfigure

.PHONY: backup backup-init restore-drill power-drill control-status

backup:          ## Send backups/ (from make drift) to BACKUP_REPO and verify it there; fails if the repo is missing
	$(PY) -m netlab.backup run --repo "$(BACKUP_REPO)" --password-file "$(BACKUP_PASSWORD)"

backup-init:     ## Create the restic repository at BACKUP_REPO, once, by hand (make backup never does)
	$(PY) -m netlab.backup init --repo "$(BACKUP_REPO)" --password-file "$(BACKUP_PASSWORD)"

restore-drill:   ## Boot every router's latest backup on throwaway routers, and restore one stanza on its own
	BACKUP_REPO="$(BACKUP_REPO)" BACKUP_PASSWORD="$(BACKUP_PASSWORD)" $(PY) -m pytest -v tests/live/test_restore.py --junitxml=results/restore-drill.xml

power-drill:     ## Power-cycle the whole lab: it comes back by itself from startup config, and r2's evidence is still in the store
	POWER_CYCLE="$(POWER_CYCLE)" $(PY) -m pytest -v tests/live/test_power_event.py --junitxml=results/power-drill.xml

control-status:  ## Fail if any control's latest test is red or older than its period (reads CI runs with gh)
	$(PY) -m netlab.control_status
