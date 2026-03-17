package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TEENet-io/teenet-sdk/go/internal/network"
)

func TestToApprovalResult_Success(t *testing.T) {
	result, err := toApprovalResult(http.StatusOK, map[string]interface{}{"task_id": 1}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success=true")
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", result.StatusCode)
	}
}

func TestToApprovalResult_ErrorFromResponse(t *testing.T) {
	result, err := toApprovalResult(http.StatusBadRequest, map[string]interface{}{"error": "bad req"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected success=false")
	}
	if result.Error != "bad req" {
		t.Fatalf("unexpected error message: %s", result.Error)
	}
}

func TestToApprovalResult_TransportError(t *testing.T) {
	result, err := toApprovalResult(0, nil, assertErr("network down"))
	if err == nil {
		t.Fatal("expected transport error")
	}
	if result.Success {
		t.Fatal("expected success=false")
	}
	if !strings.Contains(result.Error, "network down") {
		t.Fatalf("unexpected error message: %s", result.Error)
	}
}

func TestClientApprovalRequestInit_Success(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/approvals/request/init" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"request_id":1}`))
	}))
	defer server.Close()

	c := &Client{
		httpClient: network.NewHTTPClient(server.URL, server.Client()),
		pkCache:    make(map[string]pkCacheEntry),
	}

	result, err := c.ApprovalRequestInit(ctx, []byte(`{"tx_id":"tx-1"}`), "tok.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", result.StatusCode)
	}
}

func TestClientApprovalAction_Non2xxMapsToFailure(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"not in policy"}`))
	}))
	defer server.Close()

	c := &Client{
		httpClient: network.NewHTTPClient(server.URL, server.Client()),
		pkCache:    make(map[string]pkCacheEntry),
	}

	result, err := c.ApprovalAction(ctx, 99, []byte(`{"action":"APPROVE"}`), "tok.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected success=false")
	}
	if result.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", result.StatusCode)
	}
	if result.Error != "not in policy" {
		t.Fatalf("unexpected error message: %s", result.Error)
	}
}

func TestClientApprovalActionChallenge_TransportError(t *testing.T) {
	ctx := context.Background()
	c := &Client{
		httpClient: network.NewHTTPClient("http://localhost:99999", &http.Client{}),
		pkCache:    make(map[string]pkCacheEntry),
	}

	result, err := c.ApprovalActionChallenge(ctx, 1, "tok.1")
	if err == nil {
		t.Fatal("expected error")
	}
	if result.Success {
		t.Fatal("expected success=false")
	}
	if result.StatusCode != 0 {
		t.Fatalf("expected status 0, got %d", result.StatusCode)
	}
}

func TestClientPasskeyLoginVerify_SetsToken(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/passkey/verify" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"abc.def"}`))
	}))
	defer server.Close()

	c := &Client{
		httpClient: network.NewHTTPClient(server.URL, server.Client()),
		pkCache:    make(map[string]pkCacheEntry),
	}
	res, err := c.PasskeyLoginVerify(ctx, 123, []byte(`{"id":"cred"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
