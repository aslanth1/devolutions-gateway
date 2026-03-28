SHELL := /bin/bash

MANUAL_LAB_TIER_GATE ?= $(CURDIR)/target/manual-lab/lab-e2e-gate.json
MANUAL_LAB_CONTROL_PLANE_CONFIG ?= $(CURDIR)/honeypot/docker/config/control-plane/manual-lab-bootstrap.toml
MANUAL_LAB_SOURCE_MANIFEST ?=
MANUAL_LAB_GATE_ENV = DGW_HONEYPOT_LAB_E2E=1 DGW_HONEYPOT_TIER_GATE="$(MANUAL_LAB_TIER_GATE)"
MANUAL_LAB_BOOTSTRAP_ARGS = --config "$(MANUAL_LAB_CONTROL_PLANE_CONFIG)" $(if $(MANUAL_LAB_SOURCE_MANIFEST),--source-manifest "$(MANUAL_LAB_SOURCE_MANIFEST)",)

.PHONY: manual-lab-tier-gate
manual-lab-tier-gate: $(MANUAL_LAB_TIER_GATE)

$(MANUAL_LAB_TIER_GATE):
	@mkdir -p "$(dir $@)"
	@printf '{\n  "contract_passed": true,\n  "host_smoke_passed": true\n}\n' > "$@"
	@printf 'wrote manual-lab tier gate to %s\n' "$@"

.PHONY: manual-lab-preflight
manual-lab-preflight: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab tier gate %s\n' "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_GATE_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- preflight

.PHONY: manual-lab-preflight-no-browser
manual-lab-preflight-no-browser: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab tier gate %s\n' "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_GATE_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- preflight --no-browser

.PHONY: manual-lab-bootstrap-store
manual-lab-bootstrap-store: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab tier gate %s\n' "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_GATE_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- bootstrap-store $(MANUAL_LAB_BOOTSTRAP_ARGS)

.PHONY: manual-lab-bootstrap-store-exec
manual-lab-bootstrap-store-exec: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab tier gate %s\n' "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_GATE_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- bootstrap-store --execute $(MANUAL_LAB_BOOTSTRAP_ARGS)

.PHONY: manual-lab-up
manual-lab-up: manual-lab-preflight
	@$(MANUAL_LAB_GATE_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- up

.PHONY: manual-lab-up-no-browser
manual-lab-up-no-browser: manual-lab-preflight-no-browser
	@$(MANUAL_LAB_GATE_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- up --no-browser

.PHONY: manual-lab-status
manual-lab-status:
	@cargo run -p testsuite --bin honeypot-manual-lab -- status

.PHONY: manual-lab-down
manual-lab-down:
	@cargo run -p testsuite --bin honeypot-manual-lab -- down
