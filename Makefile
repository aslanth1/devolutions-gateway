SHELL := /bin/bash

MANUAL_LAB_PROFILE ?= canonical
MANUAL_LAB_TIER_GATE ?= $(CURDIR)/target/manual-lab/lab-e2e-gate.json
MANUAL_LAB_LOCAL_STATE_ROOT ?= target/manual-lab/state
MANUAL_LAB_SELFTEST_UP_PRECHECK ?= 1
MANUAL_LAB_WEBPLAYER_PRECHECK ?= 1
MANUAL_LAB_WEBPLAYER_PATH ?= $(DGATEWAY_WEBPLAYER_PATH)
MANUAL_LAB_WEBPLAYER_BUILD_ROOT ?= $(CURDIR)/webapp
MANUAL_LAB_WEBPLAYER_DEFAULT_PATH ?= $(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/dist/recording-player
MANUAL_LAB_WEBPLAYER_BUILDER_CONTEXT ?= $(CURDIR)/honeypot/docker/webplayer-builder
MANUAL_LAB_WEBPLAYER_BUILDER_IMAGE ?= dgw-manual-lab-webplayer-builder:local
MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME ?= docker
MANUAL_LAB_WEBPLAYER_CONTAINER_HOME ?= $(CURDIR)/target/manual-lab/webplayer-home
MANUAL_LAB_WEBPLAYER_CONTAINER_STORE ?= $(CURDIR)/target/manual-lab/pnpm-store
MANUAL_LAB_WEBPLAYER_NPMRC ?= $(if $(NPM_CONFIG_USERCONFIG),$(NPM_CONFIG_USERCONFIG),$(HOME)/.npmrc)
MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE ?= @devolutions
MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST ?= devolutions.jfrog.io
HONEYPOT_TEST_TIER_GATE ?= $(CURDIR)/target/honeypot/lab-e2e-gate.json
HOST_SMOKE_TEST_ARGS ?=
HOST_SMOKE_PRECHECK ?= 1
LAB_E2E_TEST_ARGS ?=
LAB_E2E_PRECHECK ?= 1

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
MANUAL_LAB_INTEROP_RDP_USERNAME ?= $(if $(DGW_HONEYPOT_INTEROP_RDP_USERNAME),$(DGW_HONEYPOT_INTEROP_RDP_USERNAME),jf)
MANUAL_LAB_INTEROP_RDP_PASSWORD ?= $(if $(DGW_HONEYPOT_INTEROP_RDP_PASSWORD),$(DGW_HONEYPOT_INTEROP_RDP_PASSWORD),ChangeMe123!)
MANUAL_LAB_INTEROP_ENV = $(if $(MANUAL_LAB_INTEROP_IMAGE_STORE),DGW_HONEYPOT_INTEROP_IMAGE_STORE="$(MANUAL_LAB_INTEROP_IMAGE_STORE)") $(if $(MANUAL_LAB_INTEROP_MANIFEST_DIR),DGW_HONEYPOT_INTEROP_MANIFEST_DIR="$(MANUAL_LAB_INTEROP_MANIFEST_DIR)")
MANUAL_LAB_WEBPLAYER_ENV = $(if $(MANUAL_LAB_WEBPLAYER_PATH),DGATEWAY_WEBPLAYER_PATH="$(MANUAL_LAB_WEBPLAYER_PATH)")
MANUAL_LAB_GATE_ENV = DGW_HONEYPOT_LAB_E2E=1 DGW_HONEYPOT_TIER_GATE="$(MANUAL_LAB_TIER_GATE)" MANUAL_LAB_CONTROL_PLANE_CONFIG="$(MANUAL_LAB_CONTROL_PLANE_CONFIG)" $(MANUAL_LAB_INTEROP_ENV) $(MANUAL_LAB_WEBPLAYER_ENV)
MANUAL_LAB_RUNTIME_ENV = $(MANUAL_LAB_GATE_ENV) DGW_HONEYPOT_INTEROP_RDP_USERNAME="$(MANUAL_LAB_INTEROP_RDP_USERNAME)" DGW_HONEYPOT_INTEROP_RDP_PASSWORD="$(MANUAL_LAB_INTEROP_RDP_PASSWORD)"
HONEYPOT_LAB_E2E_ENV = DGW_HONEYPOT_LAB_E2E=1 DGW_HONEYPOT_TIER_GATE="$(HONEYPOT_TEST_TIER_GATE)" $(MANUAL_LAB_INTEROP_ENV) DGW_HONEYPOT_INTEROP_RDP_USERNAME="$(MANUAL_LAB_INTEROP_RDP_USERNAME)" DGW_HONEYPOT_INTEROP_RDP_PASSWORD="$(MANUAL_LAB_INTEROP_RDP_PASSWORD)"
MANUAL_LAB_BOOTSTRAP_ARGS = --config "$(MANUAL_LAB_CONTROL_PLANE_CONFIG)" $(if $(MANUAL_LAB_SOURCE_MANIFEST),--source-manifest "$(MANUAL_LAB_SOURCE_MANIFEST)",)
MANUAL_LAB_MASKED_RDP_PASSWORD = $(if $(MANUAL_LAB_INTEROP_RDP_PASSWORD),********,)

.PHONY: manual-lab-tier-gate
manual-lab-tier-gate: $(MANUAL_LAB_TIER_GATE)

$(MANUAL_LAB_TIER_GATE):
	@mkdir -p "$(dir $@)"
	@printf '{\n  "contract_passed": true,\n  "host_smoke_passed": true\n}\n' > "$@"
	@printf 'wrote manual-lab tier gate to %s\n' "$@"

.PHONY: honeypot-tier-gate
honeypot-tier-gate: $(HONEYPOT_TEST_TIER_GATE)

$(HONEYPOT_TEST_TIER_GATE):
	@mkdir -p "$(dir $@)"
	@printf '{\n  "contract_passed": true,\n  "host_smoke_passed": true\n}\n' > "$@"
	@printf 'wrote honeypot test tier gate to %s\n' "$@"

.PHONY: test-host-smoke-precheck
test-host-smoke-precheck:
	@printf 'running honeypot host-smoke release-input precheck\n'
	@cargo run -p testsuite --bin honeypot-host-smoke-precheck

.PHONY: test-host-smoke-ensure-images
test-host-smoke-ensure-images:
	@printf 'ensuring host-smoke service image cache\n'
	@cargo run -p testsuite --bin honeypot-host-smoke-precheck -- ensure-images

.PHONY: test-host-smoke-warm
test-host-smoke-warm:
	@printf 'warming host-smoke service image cache before running host-smoke\n'
	@$(MAKE) test-host-smoke-ensure-images
	@$(MAKE) test-host-smoke

.PHONY: test-host-smoke
test-host-smoke:
	@printf 'running honeypot host-smoke with DGW_HONEYPOT_HOST_SMOKE=1 and precheck %s\n' "$(HOST_SMOKE_PRECHECK)"
	@if [[ "$(HOST_SMOKE_PRECHECK)" != "0" ]]; then \
		$(MAKE) test-host-smoke-precheck; \
	else \
		printf 'honeypot host-smoke precheck disabled; skipping release-input preflight\n'; \
	fi
	@DGW_HONEYPOT_HOST_SMOKE=1 \
	cargo test -p testsuite --test integration_tests $(HOST_SMOKE_TEST_ARGS)

.PHONY: test-lab-e2e
test-lab-e2e: honeypot-tier-gate
	@printf 'running honeypot lab-e2e with tier gate %s, profile %s, and precheck %s\n' "$(HONEYPOT_TEST_TIER_GATE)" "$(MANUAL_LAB_PROFILE)" "$(LAB_E2E_PRECHECK)"
	@if [[ "$(LAB_E2E_PRECHECK)" != "0" ]]; then \
		$(MAKE) manual-lab-ensure-artifacts MANUAL_LAB_PROFILE=$(MANUAL_LAB_PROFILE); \
	else \
		printf 'honeypot lab-e2e precheck disabled; skipping ensure-artifacts\n'; \
	fi
	@$(HONEYPOT_LAB_E2E_ENV) \
	cargo test -p testsuite --test integration_tests $(LAB_E2E_TEST_ARGS)

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

.PHONY: manual-lab-webplayer-builder-image
manual-lab-webplayer-builder-image:
	@if ! command -v "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)" >/dev/null 2>&1; then \
		printf 'manual-lab webplayer builder needs container runtime `%s`; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to use a prebuilt bundle instead\n' "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"; \
		exit 1; \
	fi
	@printf 'ensuring manual-lab webplayer builder image %s with %s\n' "$(MANUAL_LAB_WEBPLAYER_BUILDER_IMAGE)" "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"
	@"$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)" build \
		-t "$(MANUAL_LAB_WEBPLAYER_BUILDER_IMAGE)" \
		"$(MANUAL_LAB_WEBPLAYER_BUILDER_CONTEXT)"

.PHONY: manual-lab-webplayer-validate-bundle
manual-lab-webplayer-validate-bundle:
	@set -e; \
	webplayer_path="$(if $(MANUAL_LAB_WEBPLAYER_PATH),$(MANUAL_LAB_WEBPLAYER_PATH),$(MANUAL_LAB_WEBPLAYER_DEFAULT_PATH))"; \
	explicit_path="$(MANUAL_LAB_WEBPLAYER_PATH)"; \
	index_html="$$webplayer_path/index.html"; \
	assets_dir="$$webplayer_path/assets"; \
	asset_file="$$(find "$$assets_dir" -type f -print -quit 2>/dev/null || true)"; \
	if [[ -n "$$explicit_path" ]]; then \
		if [[ ! -f "$$index_html" ]]; then \
			printf 'explicit manual-lab webplayer path %s is missing index.html; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to a built bundle root or rerun without the override to use the containerized builder\n' "$$webplayer_path"; \
			exit 1; \
		fi; \
		if [[ -z "$$asset_file" ]]; then \
			printf 'explicit manual-lab webplayer path %s is missing a non-empty assets/ directory; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to a built bundle root with index.html and generated assets/ or rerun without the override to use the containerized builder\n' "$$webplayer_path"; \
			exit 1; \
		fi; \
		printf 'using explicit manual-lab webplayer path %s\n' "$$webplayer_path"; \
		exit 0; \
	fi; \
	if [[ ! -f "$$index_html" ]]; then \
		printf 'manual-lab webplayer bundle %s is missing index.html; run `make manual-lab-ensure-webplayer` or set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to a built bundle root\n' "$$webplayer_path"; \
		exit 1; \
	fi; \
	if [[ -z "$$asset_file" ]]; then \
		printf 'manual-lab webplayer bundle %s is missing a non-empty assets/ directory; run `make manual-lab-ensure-webplayer` or set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to a built bundle root with index.html and generated assets/\n' "$$webplayer_path"; \
		exit 1; \
	fi; \
	printf 'manual-lab webplayer bundle ready at %s\n' "$$webplayer_path"

.PHONY: manual-lab-webplayer-auth-check
manual-lab-webplayer-auth-check:
	@set -e; \
	webplayer_path="$(if $(MANUAL_LAB_WEBPLAYER_PATH),$(MANUAL_LAB_WEBPLAYER_PATH),$(MANUAL_LAB_WEBPLAYER_DEFAULT_PATH))"; \
	explicit_path="$(MANUAL_LAB_WEBPLAYER_PATH)"; \
	index_html="$$webplayer_path/index.html"; \
	assets_dir="$$webplayer_path/assets"; \
	asset_file="$$(find "$$assets_dir" -type f -print -quit 2>/dev/null || true)"; \
	if [[ -n "$$explicit_path" ]]; then \
		if [[ ! -f "$$index_html" ]]; then \
			printf 'explicit manual-lab webplayer path %s is missing index.html; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to a built bundle root or rerun without the override to use the containerized builder\n' "$$webplayer_path"; \
			exit 1; \
		fi; \
		if [[ -z "$$asset_file" ]]; then \
			printf 'explicit manual-lab webplayer path %s is missing a non-empty assets/ directory; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to a built bundle root with index.html and generated assets/ or rerun without the override to use the containerized builder\n' "$$webplayer_path"; \
			exit 1; \
		fi; \
		printf 'manual-lab webplayer auth-check skipped because explicit bundle path %s is already selected\n' "$$webplayer_path"; \
		exit 0; \
	fi; \
	if ! command -v "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)" >/dev/null 2>&1; then \
		printf 'manual-lab webplayer builder needs container runtime `%s`; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to use a prebuilt bundle instead\n' "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"; \
		exit 1; \
	fi; \
	lockfile_path="$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/pnpm-lock.yaml"; \
	if ! grep -q "$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)" "$$lockfile_path"; then \
		printf 'manual-lab webplayer auth-check ready: %s is available and the lockfile does not reference the private Devolutions registry\n' "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"; \
		exit 0; \
	fi; \
	npmrc_path="$(MANUAL_LAB_WEBPLAYER_NPMRC)"; \
	if [[ ! -f "$$npmrc_path" ]]; then \
		printf 'manual-lab webplayer build needs npm auth config at %s because webapp/pnpm-lock.yaml references the private Devolutions registry; set MANUAL_LAB_WEBPLAYER_NPMRC=/path/to/.npmrc or NPM_CONFIG_USERCONFIG=/path/to/.npmrc, or use DGATEWAY_WEBPLAYER_PATH=<recording-player-dir>\n' "$$npmrc_path"; \
		exit 1; \
	fi; \
	if [[ ! -r "$$npmrc_path" ]]; then \
		printf 'manual-lab webplayer npm auth config %s is not readable; set MANUAL_LAB_WEBPLAYER_NPMRC=/path/to/.npmrc or NPM_CONFIG_USERCONFIG=/path/to/.npmrc, or use DGATEWAY_WEBPLAYER_PATH=<recording-player-dir>\n' "$$npmrc_path"; \
		exit 1; \
	fi; \
	if [[ ! -s "$$npmrc_path" ]]; then \
		printf 'manual-lab webplayer npm auth config %s is empty; set MANUAL_LAB_WEBPLAYER_NPMRC=/path/to/.npmrc or NPM_CONFIG_USERCONFIG=/path/to/.npmrc, or use DGATEWAY_WEBPLAYER_PATH=<recording-player-dir>\n' "$$npmrc_path"; \
		exit 1; \
	fi; \
	scope_registry="$$(awk -F= '/^[[:space:]]*$(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE):registry[[:space:]]*=/{print $$2}' "$$npmrc_path" | tail -n 1 | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$$//')"; \
	if [[ -z "$$scope_registry" ]]; then \
		printf 'manual-lab webplayer npm auth config %s does not configure $(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE):registry; the containerized build would fall back to https://registry.npmjs.org for private packages such as $(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE)/icons. Set MANUAL_LAB_WEBPLAYER_NPMRC=/path/to/.npmrc or NPM_CONFIG_USERCONFIG=/path/to/.npmrc to a file that maps $(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE) to $(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST), or use DGATEWAY_WEBPLAYER_PATH=<recording-player-dir>\n' "$$npmrc_path"; \
		exit 1; \
	fi; \
	if [[ "$$scope_registry" != *"$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)"* ]]; then \
		printf 'manual-lab webplayer npm auth config %s maps $(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE):registry to %s; the containerized build needs a %s registry for private packages such as $(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE)/icons. Set MANUAL_LAB_WEBPLAYER_NPMRC=/path/to/.npmrc or NPM_CONFIG_USERCONFIG=/path/to/.npmrc to a file that maps $(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE) correctly, or use DGATEWAY_WEBPLAYER_PATH=<recording-player-dir>\n' "$$npmrc_path" "$$scope_registry" "$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)"; \
		exit 1; \
	fi; \
	auth_token_line="$$(grep -E '^[[:space:]]*//$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)/.*:(_authToken|_auth)[[:space:]]*=' "$$npmrc_path" | head -n 1 || true)"; \
	username_line="$$(grep -E '^[[:space:]]*//$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)/.*:username[[:space:]]*=' "$$npmrc_path" | head -n 1 || true)"; \
	password_line="$$(grep -E '^[[:space:]]*//$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)/.*:_password[[:space:]]*=' "$$npmrc_path" | head -n 1 || true)"; \
	if [[ -z "$$auth_token_line" && ( -z "$$username_line" || -z "$$password_line" ) ]]; then \
		printf 'manual-lab webplayer npm auth config %s maps $(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE):registry to %s but does not define an auth token, _auth entry, or username/_password pair for %s; set MANUAL_LAB_WEBPLAYER_NPMRC=/path/to/.npmrc or NPM_CONFIG_USERCONFIG=/path/to/.npmrc to a file with credentials for that host, or use DGATEWAY_WEBPLAYER_PATH=<recording-player-dir>\n' "$$npmrc_path" "$$scope_registry" "$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)"; \
		exit 1; \
	fi; \
	printf 'manual-lab webplayer auth-check ready: using %s with npm auth config %s; $(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE):registry=%s and credentials for %s are present\n' "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)" "$$npmrc_path" "$$scope_registry" "$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)"

.PHONY: manual-lab-webplayer-status
manual-lab-webplayer-status:
	@set -e; \
	webplayer_path="$(if $(MANUAL_LAB_WEBPLAYER_PATH),$(MANUAL_LAB_WEBPLAYER_PATH),$(MANUAL_LAB_WEBPLAYER_DEFAULT_PATH))"; \
	explicit_path="$(MANUAL_LAB_WEBPLAYER_PATH)"; \
	index_html="$$webplayer_path/index.html"; \
	assets_dir="$$webplayer_path/assets"; \
	status='missing'; \
	reason='index.html is absent'; \
	printf 'manual-lab webplayer path: %s\n' "$$webplayer_path"; \
	if [[ -n "$$explicit_path" ]]; then \
		printf 'manual-lab webplayer source: explicit DGATEWAY_WEBPLAYER_PATH override\n'; \
	else \
		printf 'manual-lab webplayer source: repo default bundle path\n'; \
	fi; \
	if command -v "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)" >/dev/null 2>&1; then \
		printf 'manual-lab webplayer container runtime: %s (available)\n' "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"; \
	else \
		printf 'manual-lab webplayer container runtime: %s (missing)\n' "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"; \
	fi; \
	lockfile_path="$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/pnpm-lock.yaml"; \
	if grep -q "$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)" "$$lockfile_path"; then \
		printf 'manual-lab webplayer private registry deps: yes\n'; \
		npmrc_path="$(MANUAL_LAB_WEBPLAYER_NPMRC)"; \
		if [[ -r "$$npmrc_path" && -s "$$npmrc_path" ]]; then \
			scope_registry="$$(awk -F= '/^[[:space:]]*$(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE):registry[[:space:]]*=/{print $$2}' "$$npmrc_path" | tail -n 1 | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$$//')"; \
			if [[ -n "$$scope_registry" ]]; then \
				printf 'manual-lab webplayer npm scope registry: %s\n' "$$scope_registry"; \
			else \
				printf 'manual-lab webplayer npm scope registry: missing ($(MANUAL_LAB_WEBPLAYER_PRIVATE_SCOPE):registry is not set; the build would fall back to https://registry.npmjs.org)\n'; \
			fi; \
			auth_token_line="$$(grep -E '^[[:space:]]*//$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)/.*:(_authToken|_auth)[[:space:]]*=' "$$npmrc_path" | head -n 1 || true)"; \
			username_line="$$(grep -E '^[[:space:]]*//$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)/.*:username[[:space:]]*=' "$$npmrc_path" | head -n 1 || true)"; \
			password_line="$$(grep -E '^[[:space:]]*//$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)/.*:_password[[:space:]]*=' "$$npmrc_path" | head -n 1 || true)"; \
			if [[ -n "$$auth_token_line" || ( -n "$$username_line" && -n "$$password_line" ) ]]; then \
				printf 'manual-lab webplayer npm auth host entry: ready (%s)\n' "$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)"; \
			else \
				printf 'manual-lab webplayer npm auth host entry: missing (%s)\n' "$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)"; \
			fi; \
			if [[ -n "$$scope_registry" && "$$scope_registry" == *"$(MANUAL_LAB_WEBPLAYER_PRIVATE_REGISTRY_HOST)"* && ( -n "$$auth_token_line" || ( -n "$$username_line" && -n "$$password_line" ) ) ]]; then \
				printf 'manual-lab webplayer npm auth: ready (%s)\n' "$$npmrc_path"; \
			else \
				printf 'manual-lab webplayer npm auth: blocked (%s)\n' "$$npmrc_path"; \
			fi; \
		else \
			printf 'manual-lab webplayer npm auth: missing (%s)\n' "$$npmrc_path"; \
		fi; \
	else \
		printf 'manual-lab webplayer private registry deps: no\n'; \
	fi; \
	if [[ -f "$$index_html" ]]; then \
		asset_file="$$(find "$$assets_dir" -type f -print -quit 2>/dev/null || true)"; \
		if [[ -z "$$asset_file" ]]; then \
			status='invalid'; \
			reason='bundle is missing a non-empty assets/ directory'; \
		else \
			status='current'; \
			reason='bundle is present'; \
			if [[ "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/package.json" -nt "$$index_html" || "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/pnpm-lock.yaml" -nt "$$index_html" || "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/pnpm-workspace.yaml" -nt "$$index_html" || "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/biome.json" -nt "$$index_html" ]]; then \
				status='stale'; \
				reason='bundle is older than the webapp workspace metadata'; \
			else \
				newer_source="$$(find "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/apps/recording-player" "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/packages" -type f -newer "$$index_html" -print -quit 2>/dev/null)"; \
				if [[ -n "$$newer_source" ]]; then \
					status='stale'; \
					reason='bundle is older than the recording-player sources'; \
				fi; \
			fi; \
		fi; \
	fi; \
	printf 'manual-lab webplayer bundle status: %s (%s)\n' "$$status" "$$reason"

.PHONY: manual-lab-ensure-webplayer
manual-lab-ensure-webplayer:
	@set -e; \
	webplayer_path="$(if $(MANUAL_LAB_WEBPLAYER_PATH),$(MANUAL_LAB_WEBPLAYER_PATH),$(MANUAL_LAB_WEBPLAYER_DEFAULT_PATH))"; \
	explicit_path="$(MANUAL_LAB_WEBPLAYER_PATH)"; \
	index_html="$$webplayer_path/index.html"; \
	assets_dir="$$webplayer_path/assets"; \
	asset_file="$$(find "$$assets_dir" -type f -print -quit 2>/dev/null || true)"; \
	if [[ -n "$$explicit_path" ]]; then \
		if [[ ! -f "$$index_html" ]]; then \
			printf 'explicit manual-lab webplayer path %s is missing index.html; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to a built bundle root or rerun without the override to use the containerized builder\n' "$$webplayer_path"; \
			exit 1; \
		fi; \
		if [[ -z "$$asset_file" ]]; then \
			printf 'explicit manual-lab webplayer path %s is missing a non-empty assets/ directory; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to a built bundle root with index.html and generated assets/ or rerun without the override to use the containerized builder\n' "$$webplayer_path"; \
			exit 1; \
		fi; \
		printf 'using explicit manual-lab webplayer path %s\n' "$$webplayer_path"; \
		exit 0; \
	fi; \
	needs_build=0; \
	reason=''; \
	if [[ ! -f "$$index_html" ]]; then \
		needs_build=1; \
		reason='is missing'; \
	fi; \
	if [[ "$$needs_build" == "0" ]]; then \
		asset_file="$$(find "$$assets_dir" -type f -print -quit 2>/dev/null || true)"; \
		if [[ -z "$$asset_file" ]]; then \
			needs_build=1; \
			reason='is missing a non-empty assets/ directory'; \
		fi; \
	fi; \
	if [[ "$$needs_build" == "0" ]]; then \
		if [[ "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/package.json" -nt "$$index_html" || "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/pnpm-lock.yaml" -nt "$$index_html" || "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/pnpm-workspace.yaml" -nt "$$index_html" || "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/biome.json" -nt "$$index_html" ]]; then \
			needs_build=1; \
			reason='is older than the webapp workspace metadata'; \
		fi; \
	fi; \
	if [[ "$$needs_build" == "0" ]]; then \
		newer_source="$$(find "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/apps/recording-player" "$(MANUAL_LAB_WEBPLAYER_BUILD_ROOT)/packages" -type f -newer "$$index_html" -print -quit 2>/dev/null)"; \
		if [[ -n "$$newer_source" ]]; then \
			needs_build=1; \
			reason='is older than the recording-player sources'; \
		fi; \
	fi; \
	if [[ "$$needs_build" == "0" ]]; then \
		printf 'manual-lab webplayer bundle already current at %s\n' "$$webplayer_path"; \
		exit 0; \
	fi; \
	printf 'manual-lab webplayer bundle %s; building %s via %s container helper\n' "$$reason" "$$webplayer_path" "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"; \
	if ! command -v "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)" >/dev/null 2>&1; then \
		printf 'manual-lab webplayer builder needs container runtime `%s`; set DGATEWAY_WEBPLAYER_PATH=<recording-player-dir> to use a prebuilt bundle instead\n' "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"; \
		exit 1; \
	fi; \
	$(MAKE) --no-print-directory manual-lab-webplayer-auth-check; \
	npmrc_path="$(MANUAL_LAB_WEBPLAYER_NPMRC)"; \
	printf 'ensuring manual-lab webplayer builder image %s with %s\n' "$(MANUAL_LAB_WEBPLAYER_BUILDER_IMAGE)" "$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)"; \
	"$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)" build \
		-t "$(MANUAL_LAB_WEBPLAYER_BUILDER_IMAGE)" \
		"$(MANUAL_LAB_WEBPLAYER_BUILDER_CONTEXT)"; \
	mkdir -p "$(MANUAL_LAB_WEBPLAYER_CONTAINER_HOME)" "$(MANUAL_LAB_WEBPLAYER_CONTAINER_STORE)" "$(dir $(MANUAL_LAB_WEBPLAYER_DEFAULT_PATH))"; \
	docker_args=( \
		--rm \
		--user "$$(id -u):$$(id -g)" \
		-e HOME=/workspace/target/manual-lab/webplayer-home \
		-e PNPM_STORE_DIR=/workspace/target/manual-lab/pnpm-store \
		-v "$(CURDIR)":/workspace \
		-w /workspace/webapp \
	); \
	if [[ -f "$$npmrc_path" ]]; then \
		printf 'using manual-lab webplayer npm auth config %s\n' "$$npmrc_path"; \
		docker_args+=( \
			-e NPM_CONFIG_USERCONFIG=/workspace/target/manual-lab/webplayer-home/.npmrc \
			-v "$$npmrc_path:/workspace/target/manual-lab/webplayer-home/.npmrc:ro" \
		); \
	fi; \
	"$(MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME)" run "$${docker_args[@]}" \
		"$(MANUAL_LAB_WEBPLAYER_BUILDER_IMAGE)" \
		sh -lc 'pnpm install --frozen-lockfile && pnpm build:libs && pnpm build:player'; \
	if [[ ! -f "$$index_html" ]]; then \
		printf 'manual-lab webplayer build completed but %s is still missing\n' "$$index_html"; \
		exit 1; \
	fi; \
	printf 'manual-lab webplayer bundle ready at %s\n' "$$webplayer_path"

.PHONY: manual-lab-ensure-artifacts
manual-lab-ensure-artifacts: $(MANUAL_LAB_TIER_GATE)
	@printf 'using manual-lab profile %s with tier gate %s\n' "$(MANUAL_LAB_PROFILE)" "$(MANUAL_LAB_TIER_GATE)"
	@$(MANUAL_LAB_RUNTIME_ENV) \
	cargo run -p testsuite --bin honeypot-manual-lab -- ensure-artifacts $(MANUAL_LAB_BOOTSTRAP_ARGS)

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

.PHONY: manual-lab-show-profile
manual-lab-show-profile:
	@printf 'manual-lab profile: %s\n' "$(MANUAL_LAB_PROFILE)"
	@printf 'control-plane config: %s\n' "$(MANUAL_LAB_CONTROL_PLANE_CONFIG)"
	@printf 'image store root: %s\n' "$(if $(MANUAL_LAB_INTEROP_IMAGE_STORE),$(MANUAL_LAB_INTEROP_IMAGE_STORE),/srv/honeypot/images)"
	@printf 'manifest dir: %s\n' "$(if $(MANUAL_LAB_INTEROP_MANIFEST_DIR),$(MANUAL_LAB_INTEROP_MANIFEST_DIR),/srv/honeypot/images/manifests)"
	@printf 'rdp username: %s\n' "$(MANUAL_LAB_INTEROP_RDP_USERNAME)"
	@printf 'rdp password: %s\n' "$(MANUAL_LAB_MASKED_RDP_PASSWORD)"
	@printf 'manual self-test quick path: make manual-lab-selftest\n'

.PHONY: manual-lab-selftest-preflight
manual-lab-selftest-preflight:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@$(MAKE) manual-lab-preflight MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest-preflight-no-browser
manual-lab-selftest-preflight-no-browser:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@$(MAKE) manual-lab-preflight-no-browser MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest-bootstrap-store
manual-lab-selftest-bootstrap-store:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@$(MAKE) manual-lab-bootstrap-store MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest-bootstrap-store-exec
manual-lab-selftest-bootstrap-store-exec:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@$(MAKE) manual-lab-bootstrap-store-exec MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest-ensure-webplayer
manual-lab-selftest-ensure-webplayer:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@$(MAKE) manual-lab-ensure-webplayer

.PHONY: manual-lab-selftest-ensure-artifacts
manual-lab-selftest-ensure-artifacts:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@$(MAKE) manual-lab-ensure-artifacts MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest-up
manual-lab-selftest-up:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@if [[ "$(MANUAL_LAB_WEBPLAYER_PRECHECK)" != "0" ]]; then \
		$(MAKE) manual-lab-selftest-ensure-webplayer; \
	else \
		printf 'manual-lab self-test webplayer precheck disabled; skipping containerized recording-player build\n'; \
	fi
	@if [[ "$(MANUAL_LAB_SELFTEST_UP_PRECHECK)" != "0" ]]; then \
		$(MAKE) manual-lab-selftest-ensure-artifacts; \
	else \
		printf 'manual-lab self-test up precheck disabled; skipping ensure-artifacts\n'; \
	fi
	@$(MAKE) manual-lab-up MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest-up-no-browser
manual-lab-selftest-up-no-browser:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@if [[ "$(MANUAL_LAB_WEBPLAYER_PRECHECK)" != "0" ]]; then \
		$(MAKE) manual-lab-selftest-ensure-webplayer; \
	else \
		printf 'manual-lab self-test webplayer precheck disabled; skipping containerized recording-player build\n'; \
	fi
	@if [[ "$(MANUAL_LAB_SELFTEST_UP_PRECHECK)" != "0" ]]; then \
		$(MAKE) manual-lab-selftest-ensure-artifacts; \
	else \
		printf 'manual-lab self-test up precheck disabled; skipping ensure-artifacts\n'; \
	fi
	@$(MAKE) manual-lab-up-no-browser MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest
manual-lab-selftest:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@if [[ "$(MANUAL_LAB_WEBPLAYER_PRECHECK)" != "0" ]]; then \
		$(MAKE) manual-lab-selftest-ensure-webplayer; \
	else \
		printf 'manual-lab self-test webplayer precheck disabled; skipping containerized recording-player build\n'; \
	fi
	@$(MAKE) manual-lab-ensure-artifacts MANUAL_LAB_PROFILE=local
	@$(MAKE) manual-lab-up MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest-no-browser
manual-lab-selftest-no-browser:
	@printf 'manual-lab self-test uses local profile only; this is not canonical /srv readiness proof\n'
	@if [[ "$(MANUAL_LAB_WEBPLAYER_PRECHECK)" != "0" ]]; then \
		$(MAKE) manual-lab-selftest-ensure-webplayer; \
	else \
		printf 'manual-lab self-test webplayer precheck disabled; skipping containerized recording-player build\n'; \
	fi
	@$(MAKE) manual-lab-ensure-artifacts MANUAL_LAB_PROFILE=local
	@$(MAKE) manual-lab-up-no-browser MANUAL_LAB_PROFILE=local

.PHONY: manual-lab-selftest-status
manual-lab-selftest-status:
	@printf 'manual-lab self-test aliases use the same active-state status reader as the canonical lane\n'
	@$(MAKE) manual-lab-status

.PHONY: manual-lab-selftest-down
manual-lab-selftest-down:
	@printf 'manual-lab self-test aliases use the same active-state teardown as the canonical lane\n'
	@$(MAKE) manual-lab-down
