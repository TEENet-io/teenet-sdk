// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

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
	if client.GetServiceURL() != "http://localhost:8080" {
		t.Errorf("Expected serviceURL 'http://localhost:8080', got '%s'", client.GetServiceURL())
	}
	defer client.Close()
}

// TestSetDefaultAppInstanceID tests setting APP_INSTANCE_ID
func TestSetDefaultAppInstanceID(t *testing.T) {
	client := NewClient("http://localhost:8080")
	defer client.Close()

	appInstanceID := "test-app-id"
	client.SetDefaultAppInstanceID(appInstanceID)

	if client.GetDefaultAppInstanceID() != appInstanceID {
		t.Errorf("Expected APP_INSTANCE_ID '%s', got '%s'", appInstanceID, client.GetDefaultAppInstanceID())
	}
}

// TestSetDefaultAppInstanceIDFromEnv tests loading APP_INSTANCE_ID from environment
func TestSetDefaultAppInstanceIDFromEnv(t *testing.T) {
	// Set environment variable (uses APP_INSTANCE_ID, not APP_INSTANCE_ID)
	testAppInstanceID := "env-test-app-id"
	t.Setenv("APP_INSTANCE_ID", testAppInstanceID)

	client := NewClient("http://localhost:8080")
	defer client.Close()

	err := client.SetDefaultAppInstanceIDFromEnv()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if client.GetDefaultAppInstanceID() != testAppInstanceID {
		t.Errorf("Expected APP_INSTANCE_ID '%s', got '%s'", testAppInstanceID, client.GetDefaultAppInstanceID())
	}
}

// TestSetDefaultAppInstanceIDFromEnv_NotSet tests error when env var not set
func TestSetDefaultAppInstanceIDFromEnv_NotSet(t *testing.T) {
	os.Unsetenv("APP_INSTANCE_ID")

	client := NewClient("http://localhost:8080")
	defer client.Close()

	err := client.SetDefaultAppInstanceIDFromEnv()
	if err == nil {
		t.Fatal("Expected error when APP_INSTANCE_ID not set, got nil")
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

// TestSignWithoutAppInstanceID tests that Sign returns error when App Instance ID is not set
func TestSignWithoutAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	// Try to sign without setting APP_INSTANCE_ID
	_, err := client.Sign(ctx, []byte("test message"), "pk1")
	if err == nil {
		t.Error("Expected error when signing without APP_INSTANCE_ID, got nil")
	}
	if err != nil && err.Error() != "default App Instance ID is not set (use SetDefaultAppInstanceID or set APP_INSTANCE_ID environment variable)" {
		// Check that it's the expected error about APP_INSTANCE_ID.
		t.Logf("Got error: %v", err)
	}
}

// TestNewClient_AutoEnv tests that NewClient auto-reads SERVICE_URL and APP_INSTANCE_ID
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

// TestNewClient_ExplicitOverridesEnv tests that explicit serviceURL overrides env
func TestNewClient_ExplicitOverridesEnv(t *testing.T) {
	t.Setenv("SERVICE_URL", "http://from-env:8089")

	client := NewClient("http://explicit:8089")
	defer client.Close()

	if client.GetServiceURL() != "http://explicit:8089" {
		t.Errorf("Expected 'http://explicit:8089', got '%s'", client.GetServiceURL())
	}
}

// TestVerify_NoAppInstanceID tests Verify without APP_INSTANCE_ID
func TestVerify_NoAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.Verify(ctx, []byte("message"), []byte("signature"), "pk1")
	if err == nil {
		t.Error("Expected error when no App Instance ID set")
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

// TestGenerateKey_NoAppInstanceID tests GenerateKey without APP_INSTANCE_ID
func TestGenerateKey_NoAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GenerateKey(ctx, ProtocolSchnorr, CurveSECP256K1)
	if err == nil {
		t.Error("Expected error when no App Instance ID set (Schnorr)")
	}

	_, err = client.GenerateKey(ctx, ProtocolECDSA, CurveSECP256K1)
	if err == nil {
		t.Error("Expected error when no App Instance ID set (ECDSA)")
	}
}

// TestGetAPIKey_NoAppInstanceID tests GetAPIKey without APP_INSTANCE_ID
func TestGetAPIKey_NoAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GetAPIKey(ctx, "test-key")
	if err == nil {
		t.Error("Expected error when no App Instance ID set")
	}
}

// TestSignWithAPISecret_NoAppInstanceID tests SignWithAPISecret without APP_INSTANCE_ID
func TestSignWithAPISecret_NoAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.SignWithAPISecret(ctx, "test-secret", []byte("message"))
	if err == nil {
		t.Error("Expected error when no App Instance ID set")
	}
}

// TestGetPublicKeys_NoAppInstanceID tests GetPublicKeys without APP_INSTANCE_ID
func TestGetPublicKeys_NoAppInstanceID(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://localhost:8080")
	defer client.Close()

	_, err := client.GetPublicKeys(ctx)
	if err == nil {
		t.Error("Expected error when no App Instance ID set")
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

// TestCheckInit_NilClient verifies that calling methods on a nil *Client returns
// errNilClient instead of panicking.
func TestCheckInit_NilClient(t *testing.T) {
	var c *Client // nil pointer

	// Methods returning (result, error) must return a non-nil error.
	_, err := c.Sign(context.Background(), []byte("msg"), "key")
	if err == nil {
		t.Error("Sign on nil client should return error")
	}

	_, err = c.Verify(context.Background(), []byte("msg"), []byte("sig"), "key")
	if err == nil {
		t.Error("Verify on nil client should return error")
	}

	_, err = c.GetPublicKeys(context.Background())
	if err == nil {
		t.Error("GetPublicKeys on nil client should return error")
	}

	_, err = c.GetStatus(context.Background(), "hash")
	if err == nil {
		t.Error("GetStatus on nil client should return error")
	}

	_, err = c.GenerateKey(context.Background(), ProtocolEdDSA, CurveED25519)
	if err == nil {
		t.Error("GenerateKey on nil client should return error")
	}

	_, err = c.GetAPIKey(context.Background(), "key")
	if err == nil {
		t.Error("GetAPIKey on nil client should return error")
	}

	// Void/getter methods must not panic on nil receiver.
	c.SetDefaultAppInstanceID("test")
	c.InvalidateKeyCache()
	_ = c.GetDefaultAppInstanceID()
	_ = c.GetServiceURL()
	_ = c.GetRequestTimeout()
	_ = c.GetPendingWaitTimeout()

	// Close on nil should return nil, not panic.
	err = c.Close()
	if err != nil {
		t.Error("Close on nil client should return nil")
	}
}

// TestCheckInit_ZeroValueClient verifies that a zero-value *Client (impl == nil)
// returns errNilClient from methods that call checkInit().
func TestCheckInit_ZeroValueClient(t *testing.T) {
	c := &Client{} // zero value: impl is nil

	_, err := c.Sign(context.Background(), []byte("msg"), "key")
	if err == nil {
		t.Error("Sign on zero-value client should return error")
	}
}

// Note: Integration tests that require actual services running should be in
// separate test files (e.g., integration_test.go) and can be run with build tags:
// go test -tags=integration
//
// Integration tests should verify end-to-end signing against live services.
