// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// -----------------------------------------------------------------------------

package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 1, -1},
		{100, 50, 50},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("min(%d, %d) = %d, expected %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestSign_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.Sign([]byte("test message"))
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestSign_EmptyMessage(t *testing.T) {
	client := NewClientWithOptions("http://localhost:8080", nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.Sign(nil)
	if err == nil {
		t.Fatal("Expected error for empty message")
	}
	if result == nil || result.Success {
		t.Fatalf("Expected failed result, got %#v", result)
	}
	if result.ErrorCode != types.ErrorCodeInvalidInput {
		t.Fatalf("Expected error code %s, got %s", types.ErrorCodeInvalidInput, result.ErrorCode)
	}
}

func TestSign_PollingOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"status":    "signed",
			"signature": "0xabcdef",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, &types.ClientOptions{
		RequestTimeout:     5 * time.Second,
		PendingWaitTimeout: 500 * time.Millisecond,
	})
	defer client.Close()

	client.SetDefaultAppID("test-app")

	result, err := client.Sign([]byte("test message"))
	if err != nil {
		t.Fatalf("Unexpected error in polling mode: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got error: %s", result.Error)
	}
}

func TestSign_DirectSigning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        true,
			"status":         "signed",
			"signature":      "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			"current_votes":  1,
			"required_votes": 1,
			"needs_voting":   false,
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, &types.ClientOptions{
		RequestTimeout:     5 * time.Second,
		PendingWaitTimeout: 500 * time.Millisecond,
	})
	defer client.Close()

	client.SetDefaultAppID("test-app")

	result, err := client.Sign([]byte("test message"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got error: %s", result.Error)
	}
	if len(result.Signature) == 0 {
		t.Error("Expected non-empty signature")
	}
	if result.VotingInfo == nil {
		t.Fatal("Expected VotingInfo")
	}
	if result.VotingInfo.NeedsVoting {
		t.Error("Expected NeedsVoting to be false for direct signing")
	}
}

func TestSign_WithPublicKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify public key is passed
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)

		if _, ok := payload["public_key"]; !ok {
			t.Error("Expected public_key in request")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"status":    "signed",
			"signature": "0xabcdef",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()

	client.SetDefaultAppID("test-app")

	pubKey := []byte{0x04, 0x01, 0x02, 0x03}
	result, err := client.Sign([]byte("test"), pubKey)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success: %s", result.Error)
	}
}

func TestSign_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Internal server error",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()

	client.SetDefaultAppID("test-app")

	result, err := client.Sign([]byte("test"))
	if err == nil {
		t.Error("Expected error for server error")
	}
	if result.Success {
		t.Error("Expected failure")
	}
	if result.ErrorCode != types.ErrorCodeSignRequestRejected {
		t.Errorf("Expected error code %s, got %s", types.ErrorCodeSignRequestRejected, result.ErrorCode)
	}
}

func TestSign_InvalidSignatureHex(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"status":    "signed",
			"signature": "0xGGGG", // Invalid hex
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()

	client.SetDefaultAppID("test-app")

	result, err := client.Sign([]byte("test"))
	if err == nil {
		t.Error("Expected error for invalid hex signature")
	}
	if result.Success {
		t.Error("Expected failure")
	}
	if result.ErrorCode != types.ErrorCodeSignatureDecode {
		t.Errorf("Expected error code %s, got %s", types.ErrorCodeSignatureDecode, result.ErrorCode)
	}
}

func TestSign_UnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"status":  "unknown_status",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()

	client.SetDefaultAppID("test-app")

	result, err := client.Sign([]byte("test"))
	if err == nil {
		t.Error("Expected error for unexpected status")
	}
	if result.Success {
		t.Error("Expected failure")
	}
	if result.ErrorCode != types.ErrorCodeUnexpectedStatus {
		t.Errorf("Expected error code %s, got %s", types.ErrorCodeUnexpectedStatus, result.ErrorCode)
	}
}

func TestSign_VotingPendingTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/submit-request":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":        true,
				"hash":           "0xvotehash",
				"status":         "pending",
				"current_votes":  1,
				"required_votes": 3,
				"needs_voting":   true,
			})
		case "/api/cache/0xvotehash":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"found":   true,
				"entry": map[string]interface{}{
					"hash":           "0xvotehash",
					"status":         "pending",
					"required_votes": 3,
					"requests": map[string]interface{}{
						"app1": map[string]interface{}{"approved": true},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, &types.ClientOptions{
		RequestTimeout:     5 * time.Second,
		PendingWaitTimeout: 100 * time.Millisecond,
	})
	defer client.Close()

	client.SetDefaultAppID("test-app")

	result, err := client.Sign([]byte("test"))
	if err == nil {
		t.Fatal("Expected timeout error")
	}
	if result.Success {
		t.Errorf("Expected failure for timeout, got success")
	}
	if result.VotingInfo == nil {
		t.Fatal("Expected VotingInfo")
	}
	if result.VotingInfo.Status != "pending" {
		t.Errorf("Expected status 'pending', got '%s'", result.VotingInfo.Status)
	}
	if result.ErrorCode != types.ErrorCodeThresholdTimeout {
		t.Errorf("Expected error code %s, got %s", types.ErrorCodeThresholdTimeout, result.ErrorCode)
	}
}

func TestSign_NetworkError(t *testing.T) {
	// Use invalid URL to trigger network error
	client := NewClientWithOptions("http://localhost:99999", nil)
	defer client.Close()

	client.SetDefaultAppID("test-app")

	result, err := client.Sign([]byte("test"))
	if err == nil {
		t.Error("Expected network error")
	}
	if result.Success {
		t.Error("Expected failure")
	}
	if result.ErrorCode != types.ErrorCodeSignRequestFailed {
		t.Errorf("Expected error code %s, got %s", types.ErrorCodeSignRequestFailed, result.ErrorCode)
	}
}

func TestSign_UsesServerHash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"hash":      "0xserverhash",
			"status":    "signed",
			"signature": "0xabcdef",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.Sign([]byte("test message"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.VotingInfo == nil {
		t.Fatal("expected voting info")
	}
	if result.VotingInfo.Hash != "0xserverhash" {
		t.Fatalf("expected server hash to be used, got %s", result.VotingInfo.Hash)
	}
}
