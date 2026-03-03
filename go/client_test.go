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
	// Set environment variable (uses APP_INSTANCE_ID, not APP_ID)
	testAppID := "env-test-app-id"
	os.Setenv("APP_INSTANCE_ID", testAppID)
	defer os.Unsetenv("APP_INSTANCE_ID")

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
	os.Unsetenv("APP_INSTANCE_ID")

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
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// Try to sign without setting App ID
	_, err := client.Sign([]byte("test message"))
	if err == nil {
		t.Error("Expected error when signing without App ID, got nil")
	}
	if err != nil && err.Error() != "default App ID is not set (use SetDefaultAppID or set APP_ID environment variable)" {
		// Check that it's the expected error about App ID.
		t.Logf("Got error: %v", err)
	}
}

// TestInit tests client initialization
func TestInit(t *testing.T) {
	os.Setenv("APP_INSTANCE_ID", "init-test-id")
	defer os.Unsetenv("APP_INSTANCE_ID")

	client := NewClient("http://localhost:8080")
	defer client.Close()

	err := client.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if client.GetDefaultAppID() != "init-test-id" {
		t.Errorf("Expected 'init-test-id', got '%s'", client.GetDefaultAppID())
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

// TestVerifyWithPublicKey tests signature verification with provided public key
func TestVerifyWithPublicKey(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// This tests the public API wrapper
	// The actual crypto is tested in internal/crypto tests

	// Test with wrong key size (ED25519 expects 32-byte key, give 16)
	_, err := client.VerifyWithPublicKey(
		[]byte("message"),
		make([]byte, 64), // signature (correct size for ED25519)
		make([]byte, 16), // public key (wrong size - should be 32)
		ProtocolSchnorr,
		CurveED25519,
	)
	if err == nil {
		t.Error("Expected error for wrong key size")
	}

	// Test with valid sizes but invalid signature (should return false, not error)
	valid, err := client.VerifyWithPublicKey(
		[]byte("message"),
		make([]byte, 64), // signature (all zeros = invalid)
		make([]byte, 32), // public key (correct size)
		ProtocolSchnorr,
		CurveED25519,
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if valid {
		t.Error("Expected invalid signature")
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

// TestGenerateSchnorrKey_NoAppID tests GenerateSchnorrKey without App ID
func TestGenerateSchnorrKey_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GenerateSchnorrKey(CurveSECP256K1)
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestGenerateECDSAKey_NoAppID tests GenerateECDSAKey without App ID
func TestGenerateECDSAKey_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GenerateECDSAKey(CurveSECP256K1)
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestGetAPIKey_NoAppID tests GetAPIKey without App ID
func TestGetAPIKey_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GetAPIKey("test-key")
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestSignWithAPISecret_NoAppID tests SignWithAPISecret without App ID
func TestSignWithAPISecret_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.SignWithAPISecret("test-secret", []byte("message"))
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestGetPublicKey_NoAppID tests GetPublicKey without App ID
func TestGetPublicKey_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, _, _, err := client.GetPublicKey()
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

// TestVerify_NoAppID tests Verify without App ID
func TestVerify_NoAppID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.Verify([]byte("message"), []byte("signature"))
	if err == nil {
		t.Error("Expected error when no App ID set")
	}
}

func TestPasskeyLoginWithCredential(t *testing.T) {
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

	res, err := client.PasskeyLoginWithCredential(func(options interface{}) ([]byte, error) {
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

	res, err := client.ApprovalRequestConfirmWithCredential(12, func(options interface{}) ([]byte, error) {
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

	res, err := client.ApprovalActionWithCredential(99, "APPROVE", func(options interface{}) ([]byte, error) {
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
