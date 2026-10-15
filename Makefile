# Common tasks. Run `make help` to list them.
PY      ?= python3
CLAB    ?= sudo containerlab
TOPO    := build/topology.clab.yml
LAB_ENV ?= local
NOTE    ?=

.PHONY: help validate render test deploy live drift apply locate measure destroy all
.PHONY: secrets gitleaks finding risks

help:            ## List targets
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

validate:        ## Check the inventory for addressing mistakes
	$(PY) -m netlab validate

render: validate ## Generate configs, topology and expected state into build/
	$(PY) -m netlab render

test:            ## Offline tests (no lab needed)
	$(PY) -m pytest -q tests --ignore=tests/live

deploy: render secrets ## Render, start the lab with Containerlab, then set what isn't rendered (BGP passwords)
	$(CLAB) deploy -t $(TOPO) --reconfigure
	$(MAKE) apply

live:            ## Test the running lab: routing, firewall, failover, drift checks, locate (JUnit in results/)
	$(PY) -m pytest -v tests/live --junitxml=results/live.xml

drift:           ## Back up routers and firewall, fail on drift or on a backup missing running config
	cd ansible && ansible-playbook drift.yml

apply:           ## Push intended config to routers (diff only, no restarts)
	cd ansible && ansible-playbook deploy.yml

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
	for d in backups results build; do [ ! -d $$d ] || $(GITLEAKS) dir /repo/$$d --config /repo/.gitleaks.toml --redact --no-banner || exit 1; done

destroy:         ## Tear the lab down
	$(CLAB) destroy -t $(TOPO) --cleanup

all: test deploy live drift ## Everything CI does
