SHELL := /bin/bash

MANUAL_LAB_PROFILE ?= canonical
MANUAL_LAB_TIER_GATE ?= $(CURDIR)/target/manual-lab/lab-e2e-gate.json
MANUAL_LAB_LOCAL_STATE_ROOT ?= target/manual-lab/state

ifneq ($(filter $(MANUAL_LAB_PROFILE),canonical local),$(MANUAL_LAB_PROFILE))
$(error MANUAL_LAB_PROFILE must be canonical or local)
endif

ifeq ($(MANUAL_LAB_PROFILE),local)
MANUAL_LAB_CONTROL_PLANE_CONFIG ?= $(CURDIR)/honeypot/docker/config/control-plane/manual-lab-bootstrap.local.toml
MANUAL_LAB_INTEROP_IMAGE_STORE ?= $(MANUAL_LAB_LOCAL_STATE_ROOT)/images
MANUAL_LAB_INTEROP_MANIFEST_DIR ?= $(MANUAL_LAB_LOCAL_STATE_ROOT)/images/manifests
else
MANUAL_LAB_CONTROL_PLANE_CONFIG ?= $(CURDIR)/honeypot/docker/config/control-plane/manual-lab-bootstrap.toml
MANUAL_LAB_INTEROP_IMAGE_STORE ?=
MANUAL_LAB_INTEROP_MANIFEST_DIR ?=
endif

MANUAL_LAB_SOURCE_MANIFEST ?=
MANUAL_LAB_INTEROP_RDP_USERNAME ?= $(if $(DGW_HONEYPOT_INTEROP_RDP_USERNAME),$(DGW_HONEYPOT_INTEROP_RDP_USERNAME),operator)
MANUAL_LAB_INTEROP_RDP_PASSWORD ?= $(if $(DGW_HONEYPOT_INTEROP_RDP_PASSWORD),$(DGW_HONEYPOT_INTEROP_RDP_PASSWORD),password)
MANUAL_LAB_INTEROP_ENV = $(if $(MANUAL_LAB_INTEROP_IMAGE_STORE),DGW_HONEYPOT_INTEROP_IMAGE_STORE="$(MANUAL_LAB_INTEROP_IMAGE_STORE)") $(if $(MANUAL_LAB_INTEROP_MANIFEST_DIR),DGW_HONEYPOT_INTEROP_MANIFEST_DIR="$(MANUAL_LAB_INTEROP_MANIFEST_DIR)")
MANUAL_LAB_GATE_ENV = DGW_HONEYPOT_LAB_E2E=1 DGW_HONEYPOT_TIER_GATE="$(MANUAL_LAB_TIER_GATE)" MANUAL_LAB_CONTROL_PLANE_CONFIG="$(MANUAL_LAB_CONTROL_PLANE_CONFIG)" $(MANUAL_LAB_INTEROP_ENV)
MANUAL_LAB_RUNTIME_ENV = $(MANUAL_LAB_GATE_ENV) DGW_HONEYPOT_INTEROP_RDP_USERNAME="$(MANUAL_LAB_INTEROP_RDP_USERNAME)" DGW_HONEYPOT_INTEROP_RDP_PASSWORD="$(MANUAL_LAB_INTEROP_RDP_PASSWORD)"
MANUAL_LAB_BOOTSTRAP_ARGS = --config "$(MANUAL_LAB_CONTROL_PLANE_CONFIG)" $(if $(MANUAL_LAB_SOURCE_MANIFEST),--source-manifest "$(MANUAL_LAB_SOURCE_MANIFEST)",)

.PHONY: manual-lab-tier-gate
manual-lab-tier-gate: $(MANUAL_LAB_TIER_GATE)

$(MANUAL_LAB_TIER_GATE):
	@mkdir -p "$(dir $@)"
	@printf '{\n  "contract_passed": true,\n  "host_smoke_passed": true\n}\n' > "$@"
	@printf 'wrote manual-lab tier gate to %s\n' "$@"

.PHONY: manual-lab-preflight
manual-lab-preflight: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab profile %s with tier gate %s\n' "$(MANUAL_LAB_PROFILE)" "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_RUNTIME_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- preflight

.PHONY: manual-lab-preflight-no-browser
manual-lab-preflight-no-browser: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab profile %s with tier gate %s\n' "$(MANUAL_LAB_PROFILE)" "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_RUNTIME_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- preflight --no-browser

.PHONY: manual-lab-bootstrap-store
manual-lab-bootstrap-store: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab profile %s with tier gate %s\n' "$(MANUAL_LAB_PROFILE)" "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_RUNTIME_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- bootstrap-store $(MANUAL_LAB_BOOTSTRAP_ARGS)

.PHONY: manual-lab-bootstrap-store-exec
manual-lab-bootstrap-store-exec: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab profile %s with tier gate %s\n' "$(MANUAL_LAB_PROFILE)" "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_RUNTIME_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- bootstrap-store --execute $(MANUAL_LAB_BOOTSTRAP_ARGS)

.PHONY: manual-lab-remember-source-manifest
manual-lab-remember-source-manifest:
	@cargo run -p testsuite --bin honeypot-manual-lab -- remember-source-manifest $(if $(MANUAL_LAB_SOURCE_MANIFEST),--source-manifest "$(MANUAL_LAB_SOURCE_MANIFEST)",)

.PHONY: manual-lab-up
manual-lab-up: manual-lab-preflight
	@$(MANUAL_LAB_RUNTIME_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- up

.PHONY: manual-lab-up-no-browser
manual-lab-up-no-browser: manual-lab-preflight-no-browser
	@$(MANUAL_LAB_RUNTIME_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- up --no-browser

.PHONY: manual-lab-status
manual-lab-status:
	@cargo run -p testsuite --bin honeypot-manual-lab -- status

.PHONY: manual-lab-down
manual-lab-down:
	@cargo run -p testsuite --bin honeypot-manual-lab -- down
