package network

import (
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
	resp, err := client.ApprovalRequestInit([]byte(`{"tx_id":"tx-1"}`), "tok-1")
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
	resp, err := client.ApprovalRequestChallenge(22, "tok-1")
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
	resp, err := client.ApprovalActionChallenge(77, "tok-1")
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
	resp, err := client.ApprovalPending("tok-123", nil)
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
	resp, err := client.ApprovalPending("tok-123", &types.ApprovalPendingFilter{
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
	_, err := client.ApprovalPending("tok-123", &types.ApprovalPendingFilter{
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
	resp, err := client.ApprovalRequestConfirm(5, []byte(`{"passkey_user_id":1}`), "tok-1")
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
	_, err := client.ApprovalAction(1, []byte(`{"action":"APPROVE"}`), "tok-1")
	if err == nil || !strings.Contains(err.Error(), "failed to decode approval response") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}
