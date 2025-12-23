.PHONY: build run clean tidy test

# Build the mock server
build:
	go build -o mock-server .

# Run the mock server
run: build
	./mock-server

# Run without building
run-dev:
	go run .

# Clean build artifacts
clean:
	rm -f mock-server

# Update dependencies
tidy:
	go mod tidy

# Test the server is running
test:
	@echo "Testing health endpoint..."
	curl -s http://localhost:8089/api/health | jq .
	@echo ""
	@echo "Testing public key endpoint..."
	curl -s http://localhost:8089/api/publickey/test-ecdsa-secp256k1 | jq .

# Run with custom port
run-port:
	MOCK_SERVER_PORT=$(PORT) ./mock-server

# Help
help:
	@echo "TEENet SDK Mock Server"
	@echo ""
	@echo "Available targets:"
	@echo "  build    - Build the mock server binary"
	@echo "  run      - Build and run the server"
	@echo "  run-dev  - Run directly with 'go run'"
	@echo "  clean    - Remove build artifacts"
	@echo "  tidy     - Update go.mod dependencies"
	@echo "  test     - Test server endpoints (server must be running)"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  MOCK_SERVER_PORT - Server port (default: 8089)"
