# Common tasks. Run `make help` to list them.
PY      ?= python3
CLAB    ?= sudo containerlab
TOPO    := build/topology.clab.yml
LAB_ENV ?= local
NOTE    ?=

.PHONY: help validate render test deploy live drift apply locate measure destroy all

help:            ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

validate:        ## Check the inventory for addressing mistakes
	$(PY) -m netlab validate

render: validate ## Generate configs, topology and expected state into build/
	$(PY) -m netlab render

test:            ## Offline tests (no lab needed)
	$(PY) -m pytest -q tests --ignore=tests/live --junitxml=results/offline.xml

deploy: render   ## Render and start the lab with Containerlab
	$(CLAB) deploy -t $(TOPO) --reconfigure

live:            ## Test the running lab: routing, firewall, failover, drift checks, locate (JUnit in results/)
	$(PY) -m pytest -v tests/live --junitxml=results/live.xml

drift:           ## Back up routers and firewall, fail on drift or on a backup missing running config
	cd ansible && ansible-playbook drift.yml

apply:           ## Push intended config to routers (diff only, no restarts)
	cd ansible && ansible-playbook deploy.yml

locate:          ## Find where loss starts on a path and who owns it: make locate SRC=h1 DST=203.0.113.1
	$(PY) -m netlab locate --src "$(SRC)" --dst "$(DST)"

measure:         ## Record the running lab's RAM in docs/sizing/data/ (LAB_ENV=laptop NOTE="...")
	$(PY) -m netlab.measure --env $(LAB_ENV) --note "$(NOTE)"

destroy:         ## Tear the lab down
	$(CLAB) destroy -t $(TOPO) --cleanup

all: test deploy live drift ## Everything CI does

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

power-drill:     ## Power-cycle the whole lab and check it comes back by itself from startup config
	POWER_CYCLE="$(POWER_CYCLE)" $(PY) -m pytest -v tests/live/test_power_event.py --junitxml=results/power-drill.xml

control-status:  ## Fail if any control's latest test is red or older than its period (reads CI runs with gh)
	$(PY) -m netlab.control_status
