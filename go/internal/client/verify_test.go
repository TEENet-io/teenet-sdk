// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// -----------------------------------------------------------------------------

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func singleKeyResponse(keyData, protocol, curve string) map[string]interface{} {
	return map[string]interface{}{
		"success": true,
		"public_keys": []map[string]interface{}{
			{
				"id":       1,
				"name":     "pk1",
				"key_data": keyData,
				"protocol": protocol,
				"curve":    curve,
			},
		},
	}
}

func TestGetPublicKeys_NoAppID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GetPublicKeys(ctx)
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestGetPublicKeys_Success(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"public_keys": []map[string]interface{}{
				{
					"id":       1,
					"name":     "pk1",
					"key_data": "0x04abcdef1234",
					"protocol": "ecdsa",
					"curve":    "secp256k1",
				},
			},
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	keys, err := client.GetPublicKeys(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(keys))
	}
	if keys[0].KeyData != "0x04abcdef1234" {
		t.Errorf("Expected key_data '0x04abcdef1234', got '%s'", keys[0].KeyData)
	}
}

func TestGetPublicKeys_ServerError(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "App not found",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.GetPublicKeys(ctx)
	if err == nil {
		t.Error("Expected error for server error")
	}
}

func TestVerify_NoAppID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.Verify(ctx, []byte("message"), []byte("signature"), "pk1")
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestVerify_EmptyPublicKeyName(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singleKeyResponse("0x0102", "ecdsa", "secp256k1"))
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.Verify(ctx, []byte("message"), []byte("sig"), " ")
	if err == nil {
		t.Fatal("Expected error for empty public key name")
	}
}

func TestVerify_PublicKeyNameNotFound(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singleKeyResponse("0x0102", "ecdsa", "secp256k1"))
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.Verify(ctx, []byte("message"), []byte("sig"), "missing-key")
	if err == nil {
		t.Fatal("Expected error for missing public key name")
	}
}

func TestVerify_ED25519(t *testing.T) {
	ctx := context.Background()
	// Generate a real ED25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("test message for verification")
	signature := ed25519.Sign(privateKey, message)

	// Create mock server that returns the public key
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singleKeyResponse("0x"+hex.EncodeToString(publicKey), "schnorr", "ed25519"))
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	valid, err := client.Verify(ctx, message, signature, "pk1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	ctx := context.Background()
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	invalidSignature := make([]byte, 64) // All zeros

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singleKeyResponse("0x"+hex.EncodeToString(publicKey), "schnorr", "ed25519"))
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	valid, err := client.Verify(ctx, message, invalidSignature, "pk1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if valid {
		t.Error("Expected signature to be invalid")
	}
}

func TestVerify_InvalidPublicKeyHex(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singleKeyResponse("0xGGGGGG", "schnorr", "ed25519")) // Invalid hex
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.Verify(ctx, []byte("message"), []byte("signature"), "pk1")
	if err == nil {
		t.Error("Expected error for invalid public key hex")
	}
}

func TestVerify_GetPublicKeysError(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to get public key",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	_, err := client.Verify(ctx, []byte("message"), []byte("signature"), "pk1")
	if err == nil {
		t.Error("Expected error when GetPublicKeys fails")
	}
}

func TestVerify_PublicKeyWith0xPrefix(t *testing.T) {
	ctx := context.Background()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	signature := ed25519.Sign(privateKey, message)

	// Server returns key with 0x prefix
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singleKeyResponse("0x"+hex.EncodeToString(publicKey), "schnorr", "ed25519"))
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	valid, err := client.Verify(ctx, message, signature, "pk1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}
}

func TestVerify_PublicKeyWithout0xPrefix(t *testing.T) {
	ctx := context.Background()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	signature := ed25519.Sign(privateKey, message)

	// Server returns key without 0x prefix
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singleKeyResponse(hex.EncodeToString(publicKey), "schnorr", "ed25519")) // No 0x prefix
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppInstanceID("test-app")

	valid, err := client.Verify(ctx, message, signature, "pk1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}
}
