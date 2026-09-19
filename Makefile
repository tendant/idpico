.PHONY: build run test test-flow clean fmt vet lint help seed docker-build docker-push docker-run compose-up ci

# Binary name
BINARY := idpico

# Default target
all: help

## Build
build: ## Build the server and idpicoctl binaries
	go build -o $(BINARY) ./cmd/idpico
	go build -o idpicoctl ./cmd/idpicoctl

## Run
run: build ## Build and run the server
	./$(BINARY)

run-dev: build ## Run with debug logging
	IDPICO_LOG_LEVEL=debug IDPICO_LOG_FORMAT=text ./$(BINARY)

seed: ## Create test users (test@example.com admin, alice@example.com; password123), groups and clients
	go run ./cmd/seed

## Test
test: ## Run all tests
	go test -v ./...

test-cover: ## Run tests with coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Container
IMAGE     ?= wang/idpico
TAG       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORMS ?= linux/amd64,linux/arm64

docker-build: ## Build the container image for this machine as $(IMAGE):$(TAG) and :latest
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

# A multi-platform build cannot be loaded into the local daemon, so it goes
# straight to the registry as one manifest list.
docker-push: ## Build $(IMAGE):$(TAG) and :latest for $(PLATFORMS) and push the manifest list
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE):$(TAG) -t $(IMAGE):latest --push .

docker-run: docker-build ## Run the image locally on :8080
	docker run --rm -p 8080:8080 -e IDPICO_BOOTSTRAP_USERS="admin@example.com:password123:Admin" -e IDPICO_ADMIN_EMAILS=admin@example.com $(IMAGE):$(TAG)

compose-up: ## Start via docker compose
	docker compose up --build

## Code quality
fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

lint: fmt vet ## Run all linters

ci: ## What CI runs: gofmt check, vet, race tests, OIDC flow, static build
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...
	go test -race -count=1 ./...
	$(MAKE) test-flow
	CGO_ENABLED=0 GOOS=linux go build -o /dev/null ./cmd/idpico
	CGO_ENABLED=0 GOOS=linux go build -o /dev/null ./cmd/idpicoctl

## Clean
clean: ## Clean build artifacts
	rm -f $(BINARY) idpicoctl coverage.out coverage.html

## Example: full OIDC flow test
TEST_FLOW_PORT ?= 28080
test-flow: build ## Start a throwaway server and run scripts/test-client.sh (full Authorization Code + PKCE flow as an external client)
	@tmp=$$(mktemp -d); \
	IDPICO_HOST=127.0.0.1 IDPICO_PORT=$(TEST_FLOW_PORT) IDPICO_ISSUER_URL=http://localhost:$(TEST_FLOW_PORT) \
	IDPICO_DATA_DIR=$$tmp IDPICO_LOG_FORMAT=text IDPICO_LOG_LEVEL=warn \
	IDPICO_CLIENT_ID=test-app IDPICO_CLIENT_SECRET=test-secret \
	IDPICO_CLIENT_REDIRECT_URI="http://localhost:3000/callback" \
	IDPICO_BOOTSTRAP_CLIENTS="test-spa||http://localhost:3000/callback" \
	IDPICO_BOOTSTRAP_USERS="test@example.com:password123:Test User" \
	./$(BINARY) & pid=$$!; \
	trap "kill $$pid 2>/dev/null; rm -rf $$tmp" EXIT; \
	for i in $$(seq 1 50); do curl -sf -o /dev/null http://localhost:$(TEST_FLOW_PORT)/healthz && break; sleep 0.1; done; \
	echo "### confidential client (test-app)"; \
	IDPICO_URL=http://localhost:$(TEST_FLOW_PORT) ./scripts/test-client.sh && \
	echo && echo "### public client (test-spa, PKCE only)"; \
	IDPICO_URL=http://localhost:$(TEST_FLOW_PORT) CLIENT_ID=test-spa CLIENT_SECRET= ./scripts/test-client.sh

## Help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
