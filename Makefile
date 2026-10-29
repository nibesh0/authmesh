# authmesh - developer entrypoints.
#
#   make help              list every target
#   make proto build dev-up smoke
#   make kind-up deploy k8s-smoke

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

REGISTRY      ?= authmesh
TAG           ?= dev
KIND_CLUSTER  ?= authmesh
NAMESPACE     ?= authmesh
RELEASE       ?= authmesh
CHART         ?= deploy/helm/authmesh
HELM          ?= helm
KUBECTL       ?= kubectl
COMPOSE       ?= docker compose

IMAGES := gateway auth-service user-service

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | sort \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- code generation -------------------------------------------------------

.PHONY: proto
proto: ## Regenerate gRPC stubs from proto/ (runs in a container)
	./scripts/gen-proto.sh

# --- images ----------------------------------------------------------------

.PHONY: build
build: ## Build all three service images
	docker build -f services/user/Dockerfile    -t $(REGISTRY)/user-service:$(TAG) .
	docker build -f services/auth/Dockerfile    -t $(REGISTRY)/auth-service:$(TAG) .
	docker build -f services/gateway/Dockerfile -t $(REGISTRY)/gateway:$(TAG) .

# --- local stack -----------------------------------------------------------

.env:
	@cp .env.example .env
	@echo "created .env from .env.example (development secrets)"

.PHONY: dev-up
dev-up: .env ## Start the stack with Docker Compose
	$(COMPOSE) up -d --build
	@echo "gateway:  http://localhost:$${GATEWAY_PORT:-8080}"
	@echo "api docs: http://localhost:$${GATEWAY_PORT:-8080}/docs"

.PHONY: dev-up-observability
dev-up-observability: .env ## Start the stack plus Prometheus and Grafana
	$(COMPOSE) --profile observability up -d --build
	@echo "prometheus: http://localhost:$${PROMETHEUS_PORT:-9090}"
	@echo "grafana:    http://localhost:$${GRAFANA_PORT:-3000} (admin/admin)"

.PHONY: dev-down
dev-down: ## Stop the stack, keep volumes
	$(COMPOSE) --profile observability down

.PHONY: dev-clean
dev-clean: ## Stop the stack and delete volumes
	$(COMPOSE) --profile observability down -v

.PHONY: dev-logs
dev-logs: ## Tail service logs
	$(COMPOSE) logs -f --tail=100 gateway auth-service user-service

.PHONY: dev-ps
dev-ps: ## Show container status
	$(COMPOSE) ps

# --- tests -----------------------------------------------------------------

.PHONY: test
test: ## Run unit tests in a container
	./scripts/run-tests.sh unit

.PHONY: test-integration
test-integration: ## Run integration tests against the Compose stack
	./scripts/run-tests.sh integration

.PHONY: smoke
smoke: ## End-to-end smoke test against the local gateway
	./scripts/smoke-test.sh

.PHONY: lint
lint: ## Ruff lint + format check
	./scripts/lint.sh

# --- kubernetes ------------------------------------------------------------

.PHONY: kind-up
kind-up: ## Create the local kind cluster
	./scripts/kind-up.sh

.PHONY: kind-down
kind-down: ## Delete the local kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

.PHONY: kind-load
kind-load: build ## Load freshly built images into the kind cluster
	kind load docker-image --name $(KIND_CLUSTER) \
	  $(REGISTRY)/gateway:$(TAG) \
	  $(REGISTRY)/auth-service:$(TAG) \
	  $(REGISTRY)/user-service:$(TAG)

.PHONY: helm-lint
helm-lint: ## Lint the chart against both value sets
	$(HELM) lint $(CHART)
	$(HELM) lint $(CHART) -f $(CHART)/values-dev.yaml

.PHONY: helm-template
helm-template: ## Render the chart to stdout
	$(HELM) template $(RELEASE) $(CHART) -f $(CHART)/values-dev.yaml --namespace $(NAMESPACE)

.PHONY: deploy
deploy: ## Install/upgrade the release on the current cluster
	./scripts/deploy.sh

.PHONY: undeploy
undeploy: ## Uninstall the release
	$(HELM) uninstall $(RELEASE) --namespace $(NAMESPACE) || true
	$(KUBECTL) delete namespace $(NAMESPACE) --ignore-not-found

.PHONY: k8s-smoke
k8s-smoke: ## Run the smoke test inside the cluster
	./scripts/k8s-smoke.sh

.PHONY: k8s-status
k8s-status: ## Show workloads, HPAs and endpoints
	$(KUBECTL) get pods,svc,hpa,pdb -n $(NAMESPACE) -o wide

.PHONY: k8s-logs
k8s-logs: ## Tail logs from all authmesh pods
	$(KUBECTL) logs -n $(NAMESPACE) -l app.kubernetes.io/part-of=authmesh --all-containers --tail=50 -f

.PHONY: port-forward
port-forward: ## Forward the gateway to localhost:8080
	$(KUBECTL) port-forward -n $(NAMESPACE) svc/$(RELEASE)-gateway 8080:8080

# --- housekeeping ----------------------------------------------------------

.PHONY: clean
clean: ## Remove caches and generated stubs
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .logs libs/common/src/authmesh
