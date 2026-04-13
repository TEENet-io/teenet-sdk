.PHONY: build run run-dev run-port clean tidy test gotest help

# WebAuthn / Passkey defaults. The mock-server requires PASSKEY_RP_ID
# and PASSKEY_RP_ORIGIN to be set before it will start; these defaults
# let `make run` work out of the box for local development.
export PASSKEY_RP_ID ?= localhost
export PASSKEY_RP_ORIGIN ?= http://localhost:8080
export PASSKEY_RP_NAME ?= TEENet Mock
export PASSKEY_REQUIRE_UV ?= true
export PASSKEY_PLATFORM_ONLY ?= false

# Build the mock server
build:
	go build -o mock-server .

# Run the mock server (builds first)
run: build
	./mock-server

# Run without building a binary
run-dev:
	go run .

# Clean build artifacts
clean:
	rm -f mock-server

# Update dependencies
tidy:
	go mod tidy

# Run the Go test suite with the race detector
gotest:
	go test -race ./...

# Smoke-test a running server (server must be running)
test:
	@echo "Testing health endpoint..."
	curl -s http://localhost:8089/api/health | jq .
	@echo ""
	@echo "Testing public keys endpoint..."
	curl -s http://localhost:8089/api/publickeys/test-ecdsa-secp256k1 | jq .

# Run with a custom port: make run-port PORT=9000
run-port: build
	MOCK_SERVER_PORT=$(PORT) ./mock-server

# Help
help:
	@echo "TEENet SDK Mock Server"
	@echo ""
	@echo "Available targets:"
	@echo "  build    - Build the mock server binary"
	@echo "  run      - Build and run the server"
	@echo "  run-dev  - Run directly with 'go run'"
	@echo "  run-port - Run on a custom port (make run-port PORT=9000)"
	@echo "  gotest   - Run the Go test suite (go test -race)"
	@echo "  test     - Smoke-test a running server via curl"
	@echo "  clean    - Remove build artifacts"
	@echo "  tidy     - Update go.mod dependencies"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Environment variables (with defaults):"
	@echo "  MOCK_SERVER_PORT      - Server port (default: 8089)"
	@echo "  PASSKEY_RP_ID         - WebAuthn RP id (default: localhost)"
	@echo "  PASSKEY_RP_ORIGIN     - WebAuthn RP origin (default: http://localhost:8080)"
	@echo "  PASSKEY_RP_NAME       - WebAuthn RP display name (default: TEENet Mock)"
	@echo "  PASSKEY_REQUIRE_UV    - Require user verification (default: true)"
	@echo "  PASSKEY_PLATFORM_ONLY - Platform authenticators only (default: false)"
