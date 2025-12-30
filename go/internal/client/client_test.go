// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
// -----------------------------------------------------------------------------

package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

// mockServer creates a mock HTTP server for testing
func mockServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:8080")
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	defer client.Close()

	if client.consensusURL != "http://localhost:8080" {
		t.Errorf("Expected consensusURL 'http://localhost:8080', got '%s'", client.consensusURL)
	}
	if client.requestTimeout != 30*time.Second {
		t.Errorf("Expected default requestTimeout 30s, got %v", client.requestTimeout)
	}
	if client.callbackTimeout != 60*time.Second {
		t.Errorf("Expected default callbackTimeout 60s, got %v", client.callbackTimeout)
	}
}

func TestNewClientWithOptions(t *testing.T) {
	opts := &types.ClientOptions{
		RequestTimeout:  45 * time.Second,
		CallbackTimeout: 120 * time.Second,
	}
	client := NewClientWithOptions("http://localhost:8080", opts)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	defer client.Close()

	if client.requestTimeout != 45*time.Second {
		t.Errorf("Expected requestTimeout 45s, got %v", client.requestTimeout)
	}
	if client.callbackTimeout != 120*time.Second {
		t.Errorf("Expected callbackTimeout 120s, got %v", client.callbackTimeout)
	}
}

func TestNewClientWithOptions_Nil(t *testing.T) {
	client := NewClientWithOptions("http://localhost:8080", nil)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	defer client.Close()

	// Should use defaults
	if client.requestTimeout != 30*time.Second {
		t.Errorf("Expected default requestTimeout 30s, got %v", client.requestTimeout)
	}
}

func TestSetDefaultAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	client.SetDefaultAppID("test-app-id")
	if client.GetDefaultAppID() != "test-app-id" {
		t.Errorf("Expected 'test-app-id', got '%s'", client.GetDefaultAppID())
	}
}

func TestSetDefaultAppIDFromEnv(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// Set env var
	os.Setenv("APP_INSTANCE_ID", "env-app-id")
	defer os.Unsetenv("APP_INSTANCE_ID")

	err := client.SetDefaultAppIDFromEnv()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if client.GetDefaultAppID() != "env-app-id" {
		t.Errorf("Expected 'env-app-id', got '%s'", client.GetDefaultAppID())
	}
}

func TestSetDefaultAppIDFromEnv_NotSet(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	os.Unsetenv("APP_INSTANCE_ID")

	err := client.SetDefaultAppIDFromEnv()
	if err == nil {
		t.Error("Expected error when env var not set")
	}
}

func TestInit(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	os.Setenv("APP_INSTANCE_ID", "init-app-id")
	defer os.Unsetenv("APP_INSTANCE_ID")

	err := client.Init()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if client.GetDefaultAppID() != "init-app-id" {
		t.Errorf("Expected 'init-app-id', got '%s'", client.GetDefaultAppID())
	}
}

func TestInit_NoEnvVar(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	os.Unsetenv("APP_INSTANCE_ID")

	// Init should not return error even if env var not set
	err := client.Init()
	if err != nil {
		t.Errorf("Init should not return error: %v", err)
	}
}

func TestGetConsensusURL(t *testing.T) {
	client := NewClient("http://test-url:8089")
	defer client.Close()

	if client.GetConsensusURL() != "http://test-url:8089" {
		t.Errorf("Expected 'http://test-url:8089', got '%s'", client.GetConsensusURL())
	}
}

func TestGetRequestTimeout(t *testing.T) {
	opts := &types.ClientOptions{RequestTimeout: 45 * time.Second}
	client := NewClientWithOptions("http://localhost:8080", opts)
	defer client.Close()

	if client.GetRequestTimeout() != 45*time.Second {
		t.Errorf("Expected 45s, got %v", client.GetRequestTimeout())
	}
}

func TestGetCallbackTimeout(t *testing.T) {
	opts := &types.ClientOptions{CallbackTimeout: 90 * time.Second}
	client := NewClientWithOptions("http://localhost:8080", opts)
	defer client.Close()

	if client.GetCallbackTimeout() != 90*time.Second {
		t.Errorf("Expected 90s, got %v", client.GetCallbackTimeout())
	}
}

func TestClose(t *testing.T) {
	client := NewClient("http://localhost:8080")

	err := client.Close()
	if err != nil {
		t.Errorf("Close should not return error: %v", err)
	}

	// Second close should also be safe
	err = client.Close()
	if err != nil {
		t.Errorf("Second close should not return error: %v", err)
	}
}

func TestGenerateSchnorrKey_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GenerateSchnorrKey("secp256k1")
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestGenerateSchnorrKey_InvalidCurve(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppID("test-app")

	_, err := client.GenerateSchnorrKey("invalid-curve")
	if err == nil {
		t.Error("Expected error for invalid curve")
	}
}

func TestGenerateECDSAKey_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GenerateECDSAKey("secp256k1")
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestGenerateECDSAKey_InvalidCurve(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppID("test-app")

	// ed25519 is not valid for ECDSA
	_, err := client.GenerateECDSAKey("ed25519")
	if err == nil {
		t.Error("Expected error for ed25519 with ECDSA")
	}
}

func TestGetAPIKey_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GetAPIKey("test-key")
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestGetAPIKey_EmptyName(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppID("test-app")

	_, err := client.GetAPIKey("")
	if err == nil {
		t.Error("Expected error for empty name")
	}
}

func TestSignWithAPISecret_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.SignWithAPISecret("test-secret", []byte("message"))
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestSignWithAPISecret_EmptyName(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppID("test-app")

	_, err := client.SignWithAPISecret("", []byte("message"))
	if err == nil {
		t.Error("Expected error for empty name")
	}
}

func TestSignWithAPISecret_EmptyMessage(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppID("test-app")

	_, err := client.SignWithAPISecret("test-secret", []byte{})
	if err == nil {
		t.Error("Expected error for empty message")
	}
}

// Integration-style tests with mock server

func TestGenerateSchnorrKey_WithMockServer(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate-key" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Key generated",
			"public_key": map[string]interface{}{
				"id":       123,
				"name":     "test-key",
				"key_data": "0xabcdef",
				"curve":    "secp256k1",
				"protocol": "schnorr",
			},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.GenerateSchnorrKey("secp256k1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if result.PublicKey == nil {
		t.Fatal("Expected PublicKey")
	}
	if result.PublicKey.ID != 123 {
		t.Errorf("Expected ID 123, got %d", result.PublicKey.ID)
	}
}

func TestGenerateECDSAKey_WithMockServer(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Key generated",
			"public_key": map[string]interface{}{
				"id":       456,
				"name":     "ecdsa-key",
				"key_data": "0x123456",
				"curve":    "secp256k1",
				"protocol": "ecdsa",
			},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.GenerateECDSAKey("secp256k1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if result.PublicKey.Protocol != "ecdsa" {
		t.Errorf("Expected protocol 'ecdsa', got '%s'", result.PublicKey.Protocol)
	}
}

func TestGenerateKey_ServerError(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Key generation failed",
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.GenerateSchnorrKey("secp256k1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure")
	}
}

func TestGetAPIKey_WithMockServer(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"app_instance_id": "test-app",
			"name":            "my-key",
			"api_key":         "secret-value-123",
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.GetAPIKey("my-key")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if result.APIKey != "secret-value-123" {
		t.Errorf("Expected APIKey 'secret-value-123', got '%s'", result.APIKey)
	}
}

func TestGetAPIKey_NotFound(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "API key not found",
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.GetAPIKey("nonexistent")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure")
	}
	if result.Error != "API key not found" {
		t.Errorf("Expected error message, got '%s'", result.Error)
	}
}

func TestSignWithAPISecret_WithMockServer(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"app_instance_id": "test-app",
			"name":            "my-secret",
			"signature":       "abcdef123456",
			"algorithm":       "HMAC-SHA256",
			"message_length":  12,
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.SignWithAPISecret("my-secret", []byte("test message"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if result.Signature != "abcdef123456" {
		t.Errorf("Expected signature 'abcdef123456', got '%s'", result.Signature)
	}
	if result.Algorithm != "HMAC-SHA256" {
		t.Errorf("Expected algorithm 'HMAC-SHA256', got '%s'", result.Algorithm)
	}
}

func TestSignWithAPISecret_Failure(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Secret not found",
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.SignWithAPISecret("nonexistent", []byte("message"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure")
	}
}

func TestGenerateSchnorrKey_ValidCurves(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Key generated",
			"public_key": map[string]interface{}{
				"id":       1,
				"key_data": "0xtest",
			},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	validCurves := []string{"ed25519", "secp256k1", "secp256r1"}
	for _, curve := range validCurves {
		result, err := client.GenerateSchnorrKey(curve)
		if err != nil {
			t.Errorf("Unexpected error for curve %s: %v", curve, err)
		}
		if !result.Success {
			t.Errorf("Expected success for curve %s", curve)
		}
	}
}

func TestGenerateECDSAKey_ValidCurves(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Key generated",
			"public_key": map[string]interface{}{
				"id":       1,
				"key_data": "0xtest",
			},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	// Only secp256k1 and secp256r1 are valid for ECDSA
	validCurves := []string{"secp256k1", "secp256r1"}
	for _, curve := range validCurves {
		result, err := client.GenerateECDSAKey(curve)
		if err != nil {
			t.Errorf("Unexpected error for curve %s: %v", curve, err)
		}
		if !result.Success {
			t.Errorf("Expected success for curve %s", curve)
		}
	}
}
