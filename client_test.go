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

	"github.com/TEENet-io/teenet-sdk/internal/util"
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

// TestHashMessage tests message hashing
func TestHashMessage(t *testing.T) {
	message := []byte("test message")
	hash := util.HashMessage(message)

	// Should start with 0x
	if len(hash) < 2 || hash[:2] != "0x" {
		t.Errorf("Expected hash to start with '0x', got '%s'", hash)
	}

	// Should be consistent
	hash2 := util.HashMessage(message)
	if hash != hash2 {
		t.Errorf("Hash not consistent: '%s' != '%s'", hash, hash2)
	}

	// Different messages should produce different hashes
	hash3 := util.HashMessage([]byte("different message"))
	if hash == hash3 {
		t.Error("Different messages produced same hash")
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

// TestParseProtocol tests protocol parsing
func TestParseProtocol(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
		hasError bool
	}{
		{"ECDSA", ProtocolECDSA, false},
		{"ecdsa", ProtocolECDSA, false},
		{"Schnorr", ProtocolSchnorr, false},
		{"schnorr", ProtocolSchnorr, false},
		{"SCHNORR", ProtocolSchnorr, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		result, err := ParseProtocol(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("Expected error for input '%s', got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("Expected no error for input '%s', got %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("For input '%s', expected %d, got %d", tt.input, tt.expected, result)
			}
		}
	}
}

// TestParseCurve tests curve parsing
func TestParseCurve(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
		hasError bool
	}{
		{"ED25519", CurveED25519, false},
		{"ed25519", CurveED25519, false},
		{"SECP256K1", CurveSECP256K1, false},
		{"secp256k1", CurveSECP256K1, false},
		{"SECP256R1", CurveSECP256R1, false},
		{"secp256r1", CurveSECP256R1, false},
		{"P256", CurveSECP256R1, false},
		{"p256", CurveSECP256R1, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		result, err := ParseCurve(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("Expected error for input '%s', got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("Expected no error for input '%s', got %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("For input '%s', expected %d, got %d", tt.input, tt.expected, result)
			}
		}
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

// Note: Integration tests that require actual services running should be in
// separate test files (e.g., integration_test.go) and can be run with build tags:
// go test -tags=integration
