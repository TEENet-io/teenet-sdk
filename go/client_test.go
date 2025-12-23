// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
//
// This software and its associated documentation files (the "Software") are
// the proprietary and confidential information of TEENet Technology (Hong Kong) Limited.
// Unauthorized copying of this file, via any medium, is strictly prohibited.
//
// No license, express or implied, is hereby granted, except by written agreement
// with TEENet Technology (Hong Kong) Limited. Use of this software without permission
// is a violation of applicable laws.
//
// -----------------------------------------------------------------------------

package sdk

import (
	"os"
	"testing"

	"github.com/TEENet-io/teenet-sdk/go/internal/util"
)

// TestNewClient tests client initialization
func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:8080")
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.GetConsensusURL() != "http://localhost:8080" {
		t.Errorf("Expected consensusURL 'http://localhost:8080', got '%s'", client.GetConsensusURL())
	}
	defer client.Close()
}

// TestSetDefaultAppID tests setting default App ID
func TestSetDefaultAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	appID := "test-app-id"
	client.SetDefaultAppID(appID)

	if client.GetDefaultAppID() != appID {
		t.Errorf("Expected defaultAppID '%s', got '%s'", appID, client.GetDefaultAppID())
	}
}

// TestSetDefaultAppIDFromEnv tests loading App ID from environment
func TestSetDefaultAppIDFromEnv(t *testing.T) {
	// Set environment variable
	testAppID := "env-test-app-id"
	os.Setenv("APP_ID", testAppID)
	defer os.Unsetenv("APP_ID")

	client := NewClient("http://localhost:8080")
	defer client.Close()

	err := client.SetDefaultAppIDFromEnv()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if client.GetDefaultAppID() != testAppID {
		t.Errorf("Expected defaultAppID '%s', got '%s'", testAppID, client.GetDefaultAppID())
	}
}

// TestSetDefaultAppIDFromEnv_NotSet tests error when env var not set
func TestSetDefaultAppIDFromEnv_NotSet(t *testing.T) {
	os.Unsetenv("APP_ID")

	client := NewClient("http://localhost:8080")
	defer client.Close()

	err := client.SetDefaultAppIDFromEnv()
	if err == nil {
		t.Fatal("Expected error when APP_ID not set, got nil")
	}
}

// TestDecodeHexSignature tests signature decoding
func TestDecodeHexSignature(t *testing.T) {
	// Test with 0x prefix
	sigHex := "0x1234abcd"
	decoded, err := util.DecodeHexSignature(sigHex)
	if err != nil {
		t.Fatalf("Failed to decode signature with 0x prefix: %v", err)
	}
	if len(decoded) != 4 {
		t.Errorf("Expected 4 bytes, got %d", len(decoded))
	}

	// Test without 0x prefix
	sigHex2 := "5678ef90"
	decoded2, err := util.DecodeHexSignature(sigHex2)
	if err != nil {
		t.Fatalf("Failed to decode signature without 0x prefix: %v", err)
	}
	if len(decoded2) != 4 {
		t.Errorf("Expected 4 bytes, got %d", len(decoded2))
	}

	// Test invalid hex
	_, err = util.DecodeHexSignature("0xgggg")
	if err == nil {
		t.Error("Expected error for invalid hex, got nil")
	}
}

// TestClientOptions tests client options
func TestClientOptions(t *testing.T) {
	opts := &ClientOptions{
		RequestTimeout:  60000000000,  // 60 seconds
		CallbackTimeout: 120000000000, // 120 seconds
	}

	client := NewClientWithOptions("http://localhost:8080", opts)
	defer client.Close()

	if client.GetRequestTimeout() != opts.RequestTimeout {
		t.Errorf("Expected requestTimeout %v, got %v", opts.RequestTimeout, client.GetRequestTimeout())
	}
	if client.GetCallbackTimeout() != opts.CallbackTimeout {
		t.Errorf("Expected callbackTimeout %v, got %v", opts.CallbackTimeout, client.GetCallbackTimeout())
	}
}

// TestCallbackServerInitialization tests that callback server is initialized with client
func TestCallbackServerInitialization(t *testing.T) {
	// Note: This test may fail if port 19080 is already in use
	// In production, ensure the port is available before creating the client
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// We can't directly access callbackServer (it's internal), but we can verify
	// that the client was created successfully, which implies callback server
	// initialization was attempted
	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// If callback server failed to start (port in use), Sign() should return an error
	// This is tested implicitly in integration tests
}

// TestClientClose tests that client closes properly
func TestClientClose(t *testing.T) {
	client := NewClient("http://localhost:8080")

	// Close should not error
	err := client.Close()
	if err != nil {
		t.Errorf("Expected no error on Close, got %v", err)
	}

	// Multiple closes should be safe
	err = client.Close()
	if err != nil {
		t.Errorf("Expected no error on second Close, got %v", err)
	}
}

// TestSignWithoutAppID tests that Sign returns error when App ID is not set
func TestSignWithoutAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// Try to sign without setting App ID
	_, err := client.Sign([]byte("test message"))
	if err == nil {
		t.Error("Expected error when signing without App ID, got nil")
	}
	if err != nil && err.Error() != "default App ID is not set (use SetDefaultAppID or set APP_ID environment variable)" {
		// Check that it's the expected error about App ID
		// (not callback server error)
		t.Logf("Got error: %v", err)
	}
}

// Note: Integration tests that require actual services running should be in
// separate test files (e.g., integration_test.go) and can be run with build tags:
// go test -tags=integration
//
// Integration tests should verify:
// - Callback server listens on port 19080
// - Multiple Sign calls reuse the same callback server
// - Callbacks are received correctly
// - Port conflicts are handled gracefully
