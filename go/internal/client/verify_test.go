// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
// -----------------------------------------------------------------------------

package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetPublicKey_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, _, _, err := client.GetPublicKey()
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestGetPublicKey_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"public_key": "0x04abcdef1234",
			"protocol":   "ecdsa",
			"curve":      "secp256k1",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	pubKey, protocol, curve, err := client.GetPublicKey()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if pubKey != "0x04abcdef1234" {
		t.Errorf("Expected pubKey '0x04abcdef1234', got '%s'", pubKey)
	}
	if protocol != "ecdsa" {
		t.Errorf("Expected protocol 'ecdsa', got '%s'", protocol)
	}
	if curve != "secp256k1" {
		t.Errorf("Expected curve 'secp256k1', got '%s'", curve)
	}
}

func TestGetPublicKey_ServerError(t *testing.T) {
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
	client.SetDefaultAppID("test-app")

	_, _, _, err := client.GetPublicKey()
	if err == nil {
		t.Error("Expected error for server error")
	}
}

func TestVerify_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.Verify([]byte("message"), []byte("signature"))
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestVerify_ED25519(t *testing.T) {
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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"public_key": "0x" + hex.EncodeToString(publicKey),
			"protocol":   "schnorr",
			"curve":      "ed25519",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	valid, err := client.Verify(message, signature)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	invalidSignature := make([]byte, 64) // All zeros

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"public_key": "0x" + hex.EncodeToString(publicKey),
			"protocol":   "schnorr",
			"curve":      "ed25519",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	valid, err := client.Verify(message, invalidSignature)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if valid {
		t.Error("Expected signature to be invalid")
	}
}

func TestVerify_InvalidPublicKeyHex(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"public_key": "0xGGGGGG", // Invalid hex
			"protocol":   "schnorr",
			"curve":      "ed25519",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	_, err := client.Verify([]byte("message"), []byte("signature"))
	if err == nil {
		t.Error("Expected error for invalid public key hex")
	}
}

func TestVerify_GetPublicKeyError(t *testing.T) {
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
	client.SetDefaultAppID("test-app")

	_, err := client.Verify([]byte("message"), []byte("signature"))
	if err == nil {
		t.Error("Expected error when GetPublicKey fails")
	}
}

func TestVerifyWithPublicKey_ED25519(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	signature := ed25519.Sign(privateKey, message)

	client := NewClient("http://localhost:8080")
	defer client.Close()

	valid, err := client.VerifyWithPublicKey(message, signature, publicKey, "schnorr", "ed25519")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}
}

func TestVerifyWithPublicKey_InvalidSignature(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	invalidSignature := make([]byte, 64)

	client := NewClient("http://localhost:8080")
	defer client.Close()

	valid, err := client.VerifyWithPublicKey(message, invalidSignature, publicKey, "schnorr", "ed25519")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if valid {
		t.Error("Expected signature to be invalid")
	}
}

func TestVerifyWithPublicKey_InvalidCurve(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.VerifyWithPublicKey([]byte("msg"), []byte("sig"), []byte("key"), "ecdsa", "invalid_curve")
	if err == nil {
		t.Error("Expected error for invalid curve")
	}
}

func TestVerifyWithPublicKey_WrongKeySize(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// ED25519 expects 32-byte public key
	wrongSizeKey := make([]byte, 16)
	signature := make([]byte, 64)

	_, err := client.VerifyWithPublicKey([]byte("msg"), signature, wrongSizeKey, "schnorr", "ed25519")
	if err == nil {
		t.Error("Expected error for wrong key size")
	}
}

func TestVerify_PublicKeyWith0xPrefix(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	signature := ed25519.Sign(privateKey, message)

	// Server returns key with 0x prefix
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"public_key": "0x" + hex.EncodeToString(publicKey),
			"protocol":   "schnorr",
			"curve":      "ed25519",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	valid, err := client.Verify(message, signature)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}
}

func TestVerify_PublicKeyWithout0xPrefix(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	signature := ed25519.Sign(privateKey, message)

	// Server returns key without 0x prefix
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"public_key": hex.EncodeToString(publicKey), // No 0x prefix
			"protocol":   "schnorr",
			"curve":      "ed25519",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	valid, err := client.Verify(message, signature)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}
}
