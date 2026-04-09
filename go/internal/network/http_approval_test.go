// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

package network

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

func TestApprovalRequestInit_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/approvals/request/init" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"request_id":123}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.ApprovalRequestInit(context.Background(), []byte(`{"tx_id":"tx-1"}`), "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if got, ok := resp.Data["request_id"].(float64); !ok || got != 123 {
		t.Fatalf("unexpected request_id: %#v", resp.Data["request_id"])
	}
}

func TestApprovalRequestChallenge_Path(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/approvals/request/22/challenge" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"challenge":"abc"}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.ApprovalRequestChallenge(context.Background(), 22, "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestApprovalActionChallenge_Path(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/approvals/77/challenge" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.ApprovalActionChallenge(context.Background(), 77, "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestApprovalPending_SendsBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/approvals/pending" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Fatalf("unexpected auth header: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"approvals":[]}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.ApprovalPending(context.Background(), "tok-123", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestApprovalPending_WithFilterQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/approvals/pending" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("application_id"); got != "42" {
			t.Fatalf("unexpected application_id query: %s", got)
		}
		if got := r.URL.Query().Get("public_key_name"); got != "pk-alpha" {
			t.Fatalf("unexpected public_key_name query: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"approvals":[]}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.ApprovalPending(context.Background(), "tok-123", &types.ApprovalPendingFilter{
		ApplicationID: 42,
		PublicKeyName: "pk-alpha",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestApprovalPending_FilterValidation(t *testing.T) {
	client := NewHTTPClient("http://127.0.0.1:1", &http.Client{})
	_, err := client.ApprovalPending(context.Background(), "tok-123", &types.ApprovalPendingFilter{
		PublicKeyName: "pk-alpha",
	})
	if err == nil || !strings.Contains(err.Error(), "application_id is required when public_key_name is provided") {
		t.Fatalf("expected validation error, got: %v", err)
	}
}

func TestApprovalRequestConfirm_PropagatesHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/approvals/request/5/confirm" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusConflict)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"already used"}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.ApprovalRequestConfirm(context.Background(), 5, []byte(`{"passkey_user_id":1}`), "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", resp.StatusCode)
	}
}

func TestApprovalAction_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{bad json`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	_, err := client.ApprovalAction(context.Background(), 1, []byte(`{"action":"APPROVE"}`), "tok-1")
	if err == nil || !strings.Contains(err.Error(), "failed to decode approval response") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}

func TestGetMyRequests_SendsBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/requests/mine" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-xyz" {
			t.Fatalf("unexpected auth header: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"requests":[]}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.GetMyRequests(context.Background(), "tok-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPasskeyLoginOptions_NilBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				t.Error("Expected nil/empty body for GET request via doRawRequest")
			}
		}
		if r.Header.Get("Content-Type") == "application/json" {
			t.Error("GET request should not set Content-Type: application/json")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"options":{}}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	_, err := client.PasskeyLoginOptions(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetSignatureByTx_PathAndBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/signature/by-tx/tx-abc-123" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-sig" {
			t.Fatalf("unexpected auth header: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"signature":"0xdeadbeef"}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.GetSignatureByTx(context.Background(), "tx-abc-123", "tok-sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Data["signature"] != "0xdeadbeef" {
		t.Fatalf("unexpected signature: %v", resp.Data["signature"])
	}
}
