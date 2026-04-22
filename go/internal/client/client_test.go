// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// -----------------------------------------------------------------------------

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

	if client.serviceURL != "http://localhost:8080" {
		t.Errorf("Expected serviceURL 'http://localhost:8080', got '%s'", client.serviceURL)
	}
	if client.requestTimeout != 30*time.Second {
		t.Errorf("Expected default requestTimeout 30s, got %v", client.requestTimeout)
	}
	if client.pendingWaitTimeout != 10*time.Second {
		t.Errorf("Expected default pendingWaitTimeout 10s, got %v", client.pendingWaitTimeout)
	}
}

func TestNewClientWithOptions(t *testing.T) {
	opts := &types.ClientOptions{
		RequestTimeout:     45 * time.Second,
		PendingWaitTimeout: 3 * time.Second,
		Debug:              true,
	}
	client := NewClientWithOptions("http://localhost:8080", opts)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	defer client.Close()

	if client.requestTimeout != 45*time.Second {
		t.Errorf("Expected requestTimeout 45s, got %v", client.requestTimeout)
	}
	if client.pendingWaitTimeout != 3*time.Second {
		t.Errorf("Expected pendingWaitTimeout 3s, got %v", client.pendingWaitTimeout)
	}
	if !client.debug {
		t.Errorf("Expected debug true, got false")
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

func TestSetDefaultAppInstanceID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	client.SetDefaultAppInstanceID("test-app-id")
	if client.GetDefaultAppInstanceID() != "test-app-id" {
		t.Errorf("Expected 'test-app-id', got '%s'", client.GetDefaultAppInstanceID())
	}
}

func TestSetDefaultAppInstanceIDFromEnv(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// Set env var
	t.Setenv("APP_INSTANCE_ID", "env-app-id")

	err := client.SetDefaultAppInstanceIDFromEnv()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if client.GetDefaultAppInstanceID() != "env-app-id" {
		t.Errorf("Expected 'env-app-id', got '%s'", client.GetDefaultAppInstanceID())
	}
}

func TestSetDefaultAppInstanceIDFromEnv_NotSet(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	os.Unsetenv("APP_INSTANCE_ID")

	err := client.SetDefaultAppInstanceIDFromEnv()
	if err == nil {
		t.Error("Expected error when env var not set")
	}
}

func TestNewClient_AutoEnv(t *testing.T) {
	t.Setenv("SERVICE_URL", "http://auto-env:8089")
	t.Setenv("APP_INSTANCE_ID", "auto-env-id")

	client := NewClient()
	defer client.Close()

	if client.GetServiceURL() != "http://auto-env:8089" {
		t.Errorf("Expected 'http://auto-env:8089', got '%s'", client.GetServiceURL())
	}
	if client.GetDefaultAppInstanceID() != "auto-env-id" {
		t.Errorf("Expected 'auto-env-id', got '%s'", client.GetDefaultAppInstanceID())
	}
}

func TestNewClient_ExplicitOverridesEnv(t *testing.T) {
	t.Setenv("SERVICE_URL", "http://from-env:8089")

	client := NewClient("http://explicit:8089")
	defer client.Close()

	if client.GetServiceURL() != "http://explicit:8089" {
		t.Errorf("Expected 'http://explicit:8089', got '%s'", client.GetServiceURL())
	}
}

func TestGetServiceURL(t *testing.T) {
	client := NewClient("http://test-url:8089")
	defer client.Close()

	if client.GetServiceURL() != "http://test-url:8089" {
		t.Errorf("Expected 'http://test-url:8089', got '%s'", client.GetServiceURL())
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

func TestGetPendingWaitTimeout(t *testing.T) {
	opts := &types.ClientOptions{PendingWaitTimeout: 2 * time.Second}
	client := NewClientWithOptions("http://localhost:8080", opts)
	defer client.Close()

	if client.GetPendingWaitTimeout() != 2*time.Second {
		t.Errorf("Expected 2s, got %v", client.GetPendingWaitTimeout())
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

func TestGenerateKey_SchnorrInvalidCurve(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.GenerateKey(ctx, "schnorr", "invalid-curve")
	if err == nil {
		t.Error("Expected error for invalid curve")
	}
}

func TestGenerateKey_ECDSARejectsEd25519(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.GenerateKey(ctx, "ecdsa", "ed25519")
	if err == nil {
		t.Error("Expected error for ed25519 with ECDSA")
	}
}

func TestGenerateKey_SchnorrBIP340RejectsNonSecp256k1(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.GenerateKey(ctx, "schnorr-bip340", "ed25519")
	if err == nil {
		t.Error("Expected error for SchnorrBIP340 + ed25519")
	}
}

func TestGenerateKey_EdDSARejectsNonEd25519(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.GenerateKey(ctx, "eddsa", "secp256k1")
	if err == nil {
		t.Error("Expected error for EdDSA + secp256k1")
	}
}

func TestGenerateKey_InvalidProtocol(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.GenerateKey(ctx, "rsa", "secp256k1")
	if err == nil {
		t.Error("Expected error for unsupported protocol")
	}
}

func TestGenerateKey_NoAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// Valid combo but no app ID — underlying generateKey should fail.
	_, err := client.GenerateKey(ctx, "schnorr", "secp256k1")
	if err == nil {
		t.Error("Expected error when no App Instance ID set")
	}
}

func TestGenerateKey_EdDSAWithMockServer(t *testing.T) {
	ctx := context.Background()
	var gotCurve, gotProtocol string
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		// Decode request body to assert backend still receives "schnorr"+"ed25519"
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			if v, ok := body["curve"].(string); ok {
				gotCurve = v
			}
			if v, ok := body["protocol"].(string); ok {
				gotProtocol = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Key generated",
			"public_key": map[string]interface{}{
				"id":       789,
				"name":     "eddsa-key",
				"key_data": "0xdeadbeef",
				"curve":    "ed25519",
				"protocol": "schnorr",
			},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.GenerateKey(ctx, "eddsa", "ed25519")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	if gotCurve != "ed25519" {
		t.Errorf("Expected backend curve 'ed25519', got '%s'", gotCurve)
	}
	if gotProtocol != "schnorr" {
		t.Errorf("Expected backend protocol 'schnorr' (EdDSA routes to Schnorr), got '%s'", gotProtocol)
	}
}

func TestGenerateKey_SchnorrBIP340WithMockServer(t *testing.T) {
	ctx := context.Background()
	var gotCurve, gotProtocol string
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			if v, ok := body["curve"].(string); ok {
				gotCurve = v
			}
			if v, ok := body["protocol"].(string); ok {
				gotProtocol = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Key generated",
			"public_key": map[string]interface{}{
				"id":       91,
				"name":     "taproot-key",
				"key_data": "0xcafe",
				"curve":    "secp256k1",
				"protocol": "schnorr",
			},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.GenerateKey(ctx, "schnorr-bip340", "secp256k1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
	// SchnorrBIP340 is a semantic alias — backend still receives "schnorr".
	if gotCurve != "secp256k1" {
		t.Errorf("Expected backend curve 'secp256k1', got '%s'", gotCurve)
	}
	if gotProtocol != "schnorr" {
		t.Errorf("Expected backend protocol 'schnorr', got '%s'", gotProtocol)
	}
}

func TestGenerateKey_EcdsaSecp256k1WithMockServer(t *testing.T) {
	ctx := context.Background()
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "ok",
			"public_key": map[string]interface{}{
				"id":       42,
				"name":     "eth-key",
				"key_data": "0x00",
				"curve":    "secp256k1",
				"protocol": "ecdsa",
			},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.GenerateKey(ctx, "ecdsa", "secp256k1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestGetAPIKey_NoAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GetAPIKey(ctx, "test-key")
	if err == nil {
		t.Error("Expected error when no App Instance ID set")
	}
}

func TestGetAPIKey_EmptyName(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.GetAPIKey(ctx, "")
	if err == nil {
		t.Error("Expected error for empty name")
	}
}

func TestSignWithAPISecret_NoAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.SignWithAPISecret(ctx, "test-secret", []byte("message"))
	if err == nil {
		t.Error("Expected error when no App Instance ID set")
	}
}

func TestSignWithAPISecret_EmptyName(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.SignWithAPISecret(ctx, "", []byte("message"))
	if err == nil {
		t.Error("Expected error for empty name")
	}
}

func TestSignWithAPISecret_EmptyMessage(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.SignWithAPISecret(ctx, "test-secret", []byte{})
	if err == nil {
		t.Error("Expected error for empty message")
	}
}

// Integration-style tests with mock server

func TestGenerateKey_SchnorrWithMockServer(t *testing.T) {
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.GenerateKey(ctx, "schnorr", "secp256k1")
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

func TestGenerateKey_ECDSAWithMockServer(t *testing.T) {
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.GenerateKey(ctx, "ecdsa", "secp256k1")
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
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.GenerateKey(ctx, "schnorr", "secp256k1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure")
	}
}

func TestGetAPIKey_WithMockServer(t *testing.T) {
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.GetAPIKey(ctx, "my-key")
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
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.GetAPIKey(ctx, "nonexistent")
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
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.SignWithAPISecret(ctx, "my-secret", []byte("test message"))
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
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	result, err := client.SignWithAPISecret(ctx, "nonexistent", []byte("message"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure")
	}
}

func TestGenerateKey_SchnorrValidCurves(t *testing.T) {
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	validCurves := []string{"ed25519", "secp256k1", "secp256r1"}
	for _, curve := range validCurves {
		result, err := client.GenerateKey(ctx, "schnorr", curve)
		if err != nil {
			t.Errorf("Unexpected error for curve %s: %v", curve, err)
		}
		if !result.Success {
			t.Errorf("Expected success for curve %s", curve)
		}
	}
}

func TestGenerateKey_ECDSAValidCurves(t *testing.T) {
	ctx := context.Background()
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
	client.SetDefaultAppInstanceID("test-app")

	// Only secp256k1 and secp256r1 are valid for ECDSA
	validCurves := []string{"secp256k1", "secp256r1"}
	for _, curve := range validCurves {
		result, err := client.GenerateKey(ctx, "ecdsa", curve)
		if err != nil {
			t.Errorf("Unexpected error for curve %s: %v", curve, err)
		}
		if !result.Success {
			t.Errorf("Expected success for curve %s", curve)
		}
	}
}

func TestInvalidateKeyCache(t *testing.T) {
	ctx := context.Background()
	callCount := 0
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"public_keys": []map[string]interface{}{},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	client.GetPublicKeys(ctx)
	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}

	client.GetPublicKeys(ctx)
	if callCount != 1 {
		t.Fatalf("expected still 1 call (cached), got %d", callCount)
	}

	client.InvalidateKeyCache()

	client.GetPublicKeys(ctx)
	if callCount != 2 {
		t.Fatalf("expected 2 calls after invalidation, got %d", callCount)
	}
}

func TestNoLogOutputWhenDebugDisabled(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	client := NewClientWithOptions("http://localhost:8080", nil)
	client.SetDefaultAppInstanceID("test-app")
	client.Close()

	output := buf.String()
	if strings.Contains(output, "SDK client initialized") {
		t.Error("Expected no lifecycle log when debug=false")
	}
	if strings.Contains(output, "APP_INSTANCE_ID set to") {
		t.Error("Expected no App Instance ID log when debug=false")
	}
}

func TestGetPublicKeys_Singleflight(t *testing.T) {
	ctx := context.Background()
	var callCount int64
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		// Simulate slow response
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"public_keys": []map[string]interface{}{},
		})
	})
	defer server.Close()

	client := NewClientWithOptions(server.URL, &types.ClientOptions{
		KeyCacheTTL: -1, // disable cache to test singleflight
	})
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	// Launch 10 concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.GetPublicKeys(ctx)
		}()
	}
	wg.Wait()

	// Singleflight should collapse to 1 (or maybe 2 if timing is unlucky)
	count := atomic.LoadInt64(&callCount)
	if count > 2 {
		t.Fatalf("expected at most 2 server calls (singleflight), got %d", count)
	}
}
