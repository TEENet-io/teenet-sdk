package client

import (
	"context"
	"encoding/json"
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

func TestPasskeyLoginVerifyAs_Match(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"passkey_user_id": 42, "display_name": "Alice"}`))
	}))
	defer server.Close()

	c := &Client{
		httpClient: network.NewHTTPClient(server.URL, server.Client()),
		pkCache:    make(map[string]pkCacheEntry),
	}
	res, err := c.PasskeyLoginVerifyAs(ctx, 1, []byte(`{"id":"cred"}`), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
}

func TestPasskeyLoginVerifyAs_Mismatch(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"passkey_user_id": 99, "display_name": "Eve"}`))
	}))
	defer server.Close()

	c := &Client{
		httpClient: network.NewHTTPClient(server.URL, server.Client()),
		pkCache:    make(map[string]pkCacheEntry),
	}
	res, err := c.PasskeyLoginVerifyAs(ctx, 1, []byte(`{"id":"cred"}`), 42)
	if err == nil {
		t.Fatal("expected error for mismatched passkey user")
	}
	if res.Success {
		t.Fatal("expected failure result")
	}
	if !strings.Contains(res.Error, "does not belong") {
		t.Fatalf("expected mismatch error, got: %s", res.Error)
	}
}

func TestPasskeyLoginVerifyAs_MissingID(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token": "abc"}`)) // no passkey_user_id
	}))
	defer server.Close()

	c := &Client{
		httpClient: network.NewHTTPClient(server.URL, server.Client()),
		pkCache:    make(map[string]pkCacheEntry),
	}
	res, err := c.PasskeyLoginVerifyAs(ctx, 1, []byte(`{"id":"cred"}`), 42)
	if err == nil {
		t.Fatal("expected error when passkey_user_id missing")
	}
	if res.Success {
		t.Fatal("expected failure result")
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }

// TestToUint64 tests the toUint64 helper with various input types.
func TestToUint64(t *testing.T) {
	tests := []struct {
		name   string
		input  interface{}
		wantV  uint64
		wantOK bool
	}{
		{"positive float64", float64(42), 42, true},
		{"negative float64", float64(-1), 0, false},
		{"zero float64", float64(0), 0, false},
		{"fractional float64", float64(1.5), 0, false},
		{"positive int", int(10), 10, true},
		{"negative int", int(-5), 0, false},
		{"positive int64", int64(99), 99, true},
		{"uint64", uint64(7), 7, true},
		{"zero uint64", uint64(0), 0, false},
		{"json.Number valid", json.Number("123"), 123, true},
		{"json.Number zero", json.Number("0"), 0, false},
		{"json.Number negative", json.Number("-1"), 0, false},
		{"string valid", "456", 456, true},
		{"string zero", "0", 0, false},
		{"string invalid", "abc", 0, false},
		{"nil", nil, 0, false},
		{"bool", true, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := toUint64(tt.input)
			if ok != tt.wantOK {
				t.Errorf("toUint64(%v) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && v != tt.wantV {
				t.Errorf("toUint64(%v) = %d, want %d", tt.input, v, tt.wantV)
			}
		})
	}
}
