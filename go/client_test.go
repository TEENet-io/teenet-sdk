// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// TestSetDefaultAppInstanceID tests setting APP_INSTANCE_ID
func TestSetDefaultAppInstanceID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	appID := "test-app-id"
	client.SetDefaultAppInstanceID(appID)

	if client.GetDefaultAppInstanceID() != appID {
		t.Errorf("Expected APP_INSTANCE_ID '%s', got '%s'", appID, client.GetDefaultAppInstanceID())
	}
}

// TestSetDefaultAppInstanceIDFromEnv tests loading APP_INSTANCE_ID from environment
func TestSetDefaultAppInstanceIDFromEnv(t *testing.T) {
	// Set environment variable (uses APP_INSTANCE_ID, not APP_ID)
	testAppID := "env-test-app-id"
	t.Setenv("APP_INSTANCE_ID", testAppID)

	client := NewClient("http://localhost:8080")
	defer client.Close()

	err := client.SetDefaultAppInstanceIDFromEnv()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if client.GetDefaultAppInstanceID() != testAppID {
		t.Errorf("Expected APP_INSTANCE_ID '%s', got '%s'", testAppID, client.GetDefaultAppInstanceID())
	}
}

// TestSetDefaultAppIDFromEnv_NotSet tests error when env var not set
func TestSetDefaultAppIDFromEnv_NotSet(t *testing.T) {
	os.Unsetenv("APP_INSTANCE_ID")

	client := NewClient("http://localhost:8080")
	defer client.Close()

	err := client.SetDefaultAppInstanceIDFromEnv()
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
		RequestTimeout:     60000000000, // 60 seconds
		PendingWaitTimeout: 3000000000,  // 3 seconds
	}

	client := NewClientWithOptions("http://localhost:8080", opts)
	defer client.Close()

	if client.GetRequestTimeout() != opts.RequestTimeout {
		t.Errorf("Expected requestTimeout %v, got %v", opts.RequestTimeout, client.GetRequestTimeout())
	}
	if client.GetPendingWaitTimeout() != opts.PendingWaitTimeout {
		t.Errorf("Expected pendingWaitTimeout %v, got %v", opts.PendingWaitTimeout, client.GetPendingWaitTimeout())
	}
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
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// Try to sign without setting APP_INSTANCE_ID
	_, err := client.Sign(ctx, []byte("test message"), "pk1")
	if err == nil {
		t.Error("Expected error when signing without APP_INSTANCE_ID, got nil")
	}
	if err != nil && err.Error() != "default App ID is not set (use SetDefaultAppInstanceID or set APP_INSTANCE_ID environment variable)" {
		// Check that it's the expected error about APP_INSTANCE_ID.
		t.Logf("Got error: %v", err)
	}
}

// TestInit tests client initialization
func TestInit(t *testing.T) {
	t.Setenv("APP_INSTANCE_ID", "init-test-id")

	client := NewClient("http://localhost:8080")
	defer client.Close()

	err := client.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if client.GetDefaultAppInstanceID() != "init-test-id" {
		t.Errorf("Expected 'init-test-id', got '%s'", client.GetDefaultAppInstanceID())
	}
}

// TestInit_NoEnvVar tests Init when env var is not set
func TestInit_NoEnvVar(t *testing.T) {
	os.Unsetenv("APP_INSTANCE_ID")

	client := NewClient("http://localhost:8080")
	defer client.Close()

	// Init should not fail even without env var
	err := client.Init()
	if err != nil {
		t.Errorf("Init should not fail: %v", err)
	}
}

// TestVerify_NoAppID tests Verify without APP_INSTANCE_ID
func TestVerify_NoAppID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.Verify(ctx, []byte("message"), []byte("signature"), "pk1")
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestConstants tests that constants are exported correctly
func TestConstants(t *testing.T) {
	// Protocol constants
	if ProtocolECDSA != "ecdsa" {
		t.Errorf("Expected ProtocolECDSA 'ecdsa', got '%s'", ProtocolECDSA)
	}
	if ProtocolSchnorr != "schnorr" {
		t.Errorf("Expected ProtocolSchnorr 'schnorr', got '%s'", ProtocolSchnorr)
	}

	// Curve constants
	if CurveED25519 != "ed25519" {
		t.Errorf("Expected CurveED25519 'ed25519', got '%s'", CurveED25519)
	}
	if CurveSECP256K1 != "secp256k1" {
		t.Errorf("Expected CurveSECP256K1 'secp256k1', got '%s'", CurveSECP256K1)
	}
	if CurveSECP256R1 != "secp256r1" {
		t.Errorf("Expected CurveSECP256R1 'secp256r1', got '%s'", CurveSECP256R1)
	}
}

// TestClientOptions_NilOptions tests NewClientWithOptions with nil options
func TestClientOptions_NilOptions(t *testing.T) {
	client := NewClientWithOptions("http://localhost:8080", nil)
	defer client.Close()

	// Should use defaults
	if client.GetRequestTimeout() == 0 {
		t.Error("Expected non-zero default request timeout")
	}
	if client.GetPendingWaitTimeout() == 0 {
		t.Error("Expected non-zero default pending wait timeout")
	}
}

// TestGenerateSchnorrKey_NoAppID tests GenerateSchnorrKey without APP_INSTANCE_ID
func TestGenerateSchnorrKey_NoAppID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GenerateSchnorrKey(ctx, CurveSECP256K1)
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestGenerateECDSAKey_NoAppID tests GenerateECDSAKey without APP_INSTANCE_ID
func TestGenerateECDSAKey_NoAppID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GenerateECDSAKey(ctx, CurveSECP256K1)
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestGetAPIKey_NoAppID tests GetAPIKey without APP_INSTANCE_ID
func TestGetAPIKey_NoAppID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GetAPIKey(ctx, "test-key")
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestSignWithAPISecret_NoAppID tests SignWithAPISecret without APP_INSTANCE_ID
func TestSignWithAPISecret_NoAppID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.SignWithAPISecret(ctx, "test-secret", []byte("message"))
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestGetPublicKeys_NoAppID tests GetPublicKeys without APP_INSTANCE_ID
func TestGetPublicKeys_NoAppID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GetPublicKeys(ctx)
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestPasskeyLoginWithCredential(t *testing.T) {
	ctx := context.Background()
	var callCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch r.URL.Path {
		case "/api/auth/passkey/options":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login_session_id":77,"options":{"challenge":"abc"}}`))
		case "/api/auth/passkey/verify":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode verify body failed: %v", err)
			}
			if uint64(body["login_session_id"].(float64)) != 77 {
				t.Fatalf("unexpected login_session_id: %v", body["login_session_id"])
			}
			cred, ok := body["credential"].(map[string]interface{})
			if !ok || cred["id"] != "cred-1" {
				t.Fatalf("unexpected credential payload: %#v", body["credential"])
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"tok.login.flow"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	defer client.Close()

	res, err := client.PasskeyLoginWithCredential(ctx, func(options interface{}) ([]byte, error) {
		opts, ok := options.(map[string]interface{})
		if !ok || opts["challenge"] != "abc" {
			t.Fatalf("unexpected options passed to provider: %#v", options)
		}
		return []byte(`{"id":"cred-1"}`), nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success=true, got error=%s", res.Error)
	}
	if callCount != 2 {
		t.Fatalf("expected 2 API calls, got %d", callCount)
	}
}

func TestApprovalRequestConfirmWithCredential(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/approvals/request/12/challenge":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"challenge":"request-12"}`))
		case "/api/approvals/request/12/confirm":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode confirm body failed: %v", err)
			}
			cred, ok := body["credential"].(map[string]interface{})
			if !ok || cred["id"] != "confirm-cred" {
				t.Fatalf("unexpected credential payload: %#v", body["credential"])
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"task_id":88}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	defer client.Close()

	res, err := client.ApprovalRequestConfirmWithCredential(ctx, 12, func(options interface{}) ([]byte, error) {
		opts, ok := options.(map[string]interface{})
		if !ok || opts["challenge"] != "request-12" {
			t.Fatalf("unexpected options passed to provider: %#v", options)
		}
		return []byte(`{"id":"confirm-cred"}`), nil
	}, "tok.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success=true, got error=%s", res.Error)
	}
	if uint64(res.Data["task_id"].(float64)) != 88 {
		t.Fatalf("unexpected task_id: %v", res.Data["task_id"])
	}
}

func TestApprovalActionWithCredential(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/approvals/99/challenge":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"options":{"challenge":"task-99"}}`))
		case "/api/approvals/99/action":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode action body failed: %v", err)
			}
			if body["action"] != "APPROVE" {
				t.Fatalf("unexpected action: %v", body["action"])
			}
			cred, ok := body["credential"].(map[string]interface{})
			if !ok || cred["id"] != "action-cred" {
				t.Fatalf("unexpected credential payload: %#v", body["credential"])
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"APPROVED"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	defer client.Close()

	res, err := client.ApprovalActionWithCredential(ctx, 99, "APPROVE", func(options interface{}) ([]byte, error) {
		opts, ok := options.(map[string]interface{})
		if !ok || opts["challenge"] != "task-99" {
			t.Fatalf("unexpected options passed to provider: %#v", options)
		}
		return []byte(`{"id":"action-cred"}`), nil
	}, "tok.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success=true, got error=%s", res.Error)
	}
	if got := res.Data["status"]; got != "APPROVED" {
		t.Fatalf("unexpected status: %v", got)
	}
}

// Note: Integration tests that require actual services running should be in
// separate test files (e.g., integration_test.go) and can be run with build tags:
// go test -tags=integration
//
// Integration tests should verify end-to-end signing against live services.
