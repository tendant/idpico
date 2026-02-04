.PHONY: build run test clean fmt vet lint help

# Binary name
BINARY := idp

# Default target
all: help

## Build
build: ## Build the binary
	go build -o $(BINARY) ./cmd/idp

## Run
run: build ## Build and run the server
	./$(BINARY)

run-dev: build ## Run with debug logging
	IDP_LOG_LEVEL=debug IDP_LOG_FORMAT=text ./$(BINARY)

## Test
test: ## Run all tests
	go test -v ./...

test-cover: ## Run tests with coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Code quality
fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

lint: fmt vet ## Run all linters

## Clean
clean: ## Clean build artifacts
	rm -f $(BINARY) coverage.out coverage.html

## Example: full OIDC flow test
test-flow: build ## Test the full OIDC authorization code flow
	@echo "Starting server in background..."
	@IDP_CLIENT_ID=test-app IDP_CLIENT_SECRET=test-secret \
		IDP_CLIENT_REDIRECT_URI="http://localhost:3000/callback" \
		IDP_BOOTSTRAP_USERS="test@example.com:password123:Test User" \
		./$(BINARY) &
	@sleep 1
	@echo "\n=== Testing OIDC Discovery ==="
	@curl -s http://localhost:8080/.well-known/openid-configuration | head -20
	@echo "\n\n=== Testing JWKS ==="
	@curl -s http://localhost:8080/.well-known/jwks.json
	@echo "\n\n=== Testing Health ==="
	@curl -s http://localhost:8080/healthz
	@echo "\n\nServer running at http://localhost:8080"
	@echo "Login at http://localhost:8080/login"
	@echo "Press Ctrl+C to stop"
	@wait

## Help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
