# Common tasks. Run `make help` to list them.
PY      ?= python3
CLAB    ?= sudo containerlab
TOPO    := build/topology.clab.yml

.PHONY: help validate render test deploy live drift apply locate destroy all

help:            ## List targets
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

validate:        ## Check the inventory for addressing mistakes
	$(PY) -m netlab validate

render: validate ## Generate configs, topology and expected state into build/
	$(PY) -m netlab render

test:            ## Offline tests (no lab needed)
	$(PY) -m pytest -q tests --ignore=tests/live

deploy: render   ## Render and start the lab with Containerlab
	$(CLAB) deploy -t $(TOPO) --reconfigure

live:            ## Test the running lab: OSPF, BGP, reachability, firewall, failover, drift checks
	$(PY) -m pytest -v tests/live

drift:           ## Back up routers and firewall, fail on drift or on a backup missing running config
	cd ansible && ansible-playbook drift.yml

apply:           ## Push intended config to routers (diff only, no restarts)
	cd ansible && ansible-playbook deploy.yml

locate:          ## Find where loss starts on a path and who owns it: make locate SRC=h1 DST=203.0.113.1
	$(PY) -m netlab locate --src "$(SRC)" --dst "$(DST)"

destroy:         ## Tear the lab down
	$(CLAB) destroy -t $(TOPO) --cleanup

all: test deploy live drift ## Everything CI does
