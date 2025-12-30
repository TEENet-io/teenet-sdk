// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
// -----------------------------------------------------------------------------

package network

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPClient(t *testing.T) {
	client := NewHTTPClient("http://localhost:8080", &http.Client{})
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.baseURL != "http://localhost:8080" {
		t.Errorf("Expected baseURL 'http://localhost:8080', got '%s'", client.baseURL)
	}
}

func TestSubmitRequest_Success(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/submit-request" {
			t.Errorf("Expected path '/api/submit-request', got '%s'", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got '%s'", r.Method)
		}

		// Verify request body
		var payload submitRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		if payload.AppInstanceID != "test-app-id" {
			t.Errorf("Expected AppInstanceID 'test-app-id', got '%s'", payload.AppInstanceID)
		}

		// Send response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(submitRequestResponse{
			Success:       true,
			Message:       "Request submitted",
			Hash:          "0x1234",
			Status:        "pending",
			NeedsVoting:   true,
			CurrentVotes:  1,
			RequiredVotes: 2,
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	result, err := client.SubmitRequest("test-app-id", []byte("test message"), nil)
	if err != nil {
		t.Fatalf("SubmitRequest failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.Hash != "0x1234" {
		t.Errorf("Expected Hash '0x1234', got '%s'", result.Hash)
	}
	if !result.NeedsVoting {
		t.Error("Expected NeedsVoting to be true")
	}
}

func TestSubmitRequest_WithPublicKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload submitRequestPayload
		json.NewDecoder(r.Body).Decode(&payload)

		if len(payload.PublicKey) == 0 {
			t.Error("Expected PublicKey to be set")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(submitRequestResponse{
			Success: true,
			Status:  "signed",
			Signature: "abcdef",
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	pubKey := []byte{0x04, 0x01, 0x02, 0x03}
	result, err := client.SubmitRequest("test-app-id", []byte("test"), pubKey)
	if err != nil {
		t.Fatalf("SubmitRequest failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
}

func TestSubmitRequest_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	_, err := client.SubmitRequest("test-app-id", []byte("test"), nil)
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

func TestGetPublicKey_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET method, got '%s'", r.Method)
		}
		expectedPath := "/api/publickey/test-app-id"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path '%s', got '%s'", expectedPath, r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(publicKeyResponse{
			Success:   true,
			AppID:     "test-app-id",
			PublicKey: "0x04abcdef",
			Protocol:  "ecdsa",
			Curve:     "secp256k1",
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	pubKey, protocol, curve, err := client.GetPublicKey("test-app-id")
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}
	if pubKey != "0x04abcdef" {
		t.Errorf("Expected publicKey '0x04abcdef', got '%s'", pubKey)
	}
	if protocol != "ecdsa" {
		t.Errorf("Expected protocol 'ecdsa', got '%s'", protocol)
	}
	if curve != "secp256k1" {
		t.Errorf("Expected curve 'secp256k1', got '%s'", curve)
	}
}

func TestGetPublicKey_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(publicKeyResponse{
			Success: false,
			Error:   "App not found",
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	_, _, _, err := client.GetPublicKey("nonexistent")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

func TestGenerateKey_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate-key" {
			t.Errorf("Expected path '/api/generate-key', got '%s'", r.URL.Path)
		}

		var payload generateKeyPayload
		json.NewDecoder(r.Body).Decode(&payload)

		if payload.Curve != "secp256k1" {
			t.Errorf("Expected curve 'secp256k1', got '%s'", payload.Curve)
		}
		if payload.Protocol != "schnorr" {
			t.Errorf("Expected protocol 'schnorr', got '%s'", payload.Protocol)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(generateKeyResponse{
			Success: true,
			Message: "Key generated",
			PublicKey: &GeneratedKeyInfo{
				ID:        123,
				Name:      "my-key",
				KeyData:   "0xabcdef",
				Curve:     "secp256k1",
				Protocol:  "schnorr",
			},
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	result, err := client.GenerateKey("test-app-id", "secp256k1", "schnorr")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.PublicKey == nil {
		t.Fatal("Expected PublicKey to be non-nil")
	}
	if result.PublicKey.ID != 123 {
		t.Errorf("Expected ID 123, got %d", result.PublicKey.ID)
	}
}

func TestGetAPIKey_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET method, got '%s'", r.Method)
		}

		// Check query parameter
		appID := r.URL.Query().Get("app_instance_id")
		if appID != "test-app-id" {
			t.Errorf("Expected app_instance_id 'test-app-id', got '%s'", appID)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiKeyResponse{
			Success:       true,
			AppInstanceID: "test-app-id",
			Name:          "my-key",
			APIKey:        "secret-value-123",
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	result, err := client.GetAPIKey("test-app-id", "my-key")
	if err != nil {
		t.Fatalf("GetAPIKey failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.APIKey != "secret-value-123" {
		t.Errorf("Expected APIKey 'secret-value-123', got '%s'", result.APIKey)
	}
}

func TestGetAPIKey_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiKeyResponse{
			Success: false,
			Error:   "API key not found",
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	result, err := client.GetAPIKey("test-app-id", "nonexistent")
	if err != nil {
		t.Fatalf("GetAPIKey failed: %v", err)
	}
	if result.Success {
		t.Error("Expected Success to be false")
	}
}

func TestSignWithAPISecret_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got '%s'", r.Method)
		}

		var payload signWithAPISecretPayload
		json.NewDecoder(r.Body).Decode(&payload)

		if payload.AppInstanceID != "test-app-id" {
			t.Errorf("Expected app_instance_id 'test-app-id', got '%s'", payload.AppInstanceID)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiSignResponse{
			Success:       true,
			AppInstanceID: "test-app-id",
			Name:          "my-secret",
			Signature:     "abcdef123456",
			Algorithm:     "HMAC-SHA256",
			MessageLength: 12,
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	result, err := client.SignWithAPISecret("test-app-id", "my-secret", []byte("test message"))
	if err != nil {
		t.Fatalf("SignWithAPISecret failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.Signature != "abcdef123456" {
		t.Errorf("Expected Signature 'abcdef123456', got '%s'", result.Signature)
	}
	if result.Algorithm != "HMAC-SHA256" {
		t.Errorf("Expected Algorithm 'HMAC-SHA256', got '%s'", result.Algorithm)
	}
}

func TestVerifyWithAPISecret_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got '%s'", r.Method)
		}

		var payload verifyWithAPISecretPayload
		json.NewDecoder(r.Body).Decode(&payload)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiVerifyResponse{
			Success:       true,
			AppInstanceID: "test-app-id",
			Name:          "my-secret",
			Valid:         true,
			Algorithm:     "HMAC-SHA256",
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	result, err := client.VerifyWithAPISecret("test-app-id", "my-secret", []byte("message"), []byte("signature"))
	if err != nil {
		t.Fatalf("VerifyWithAPISecret failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if !result.Valid {
		t.Error("Expected Valid to be true")
	}
}

func TestVerifyWithAPISecret_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiVerifyResponse{
			Success:       true,
			AppInstanceID: "test-app-id",
			Name:          "my-secret",
			Valid:         false,
			Algorithm:     "HMAC-SHA256",
		})
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	result, err := client.VerifyWithAPISecret("test-app-id", "my-secret", []byte("message"), []byte("wrong-sig"))
	if err != nil {
		t.Fatalf("VerifyWithAPISecret failed: %v", err)
	}
	if result.Valid {
		t.Error("Expected Valid to be false")
	}
}

func TestHTTPClient_ConnectionError(t *testing.T) {
	// Use invalid URL to trigger connection error
	client := NewHTTPClient("http://localhost:99999", &http.Client{})

	_, err := client.SubmitRequest("test", []byte("msg"), nil)
	if err == nil {
		t.Error("Expected error for connection failure")
	}

	_, _, _, err = client.GetPublicKey("test")
	if err == nil {
		t.Error("Expected error for connection failure")
	}

	_, err = client.GenerateKey("test", "secp256k1", "schnorr")
	if err == nil {
		t.Error("Expected error for connection failure")
	}

	_, err = client.GetAPIKey("test", "key")
	if err == nil {
		t.Error("Expected error for connection failure")
	}

	_, err = client.SignWithAPISecret("test", "secret", []byte("msg"))
	if err == nil {
		t.Error("Expected error for connection failure")
	}

	_, err = client.VerifyWithAPISecret("test", "secret", []byte("msg"), []byte("sig"))
	if err == nil {
		t.Error("Expected error for connection failure")
	}
}

func TestHTTPClient_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())

	_, err := client.SubmitRequest("test", []byte("msg"), nil)
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}

	_, _, _, err = client.GetPublicKey("test")
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}

	_, err = client.GenerateKey("test", "secp256k1", "schnorr")
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
}
