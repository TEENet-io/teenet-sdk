package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TEENet-io/teenet-sdk/go/internal/network"
	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

func newAdminClient(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	c := &Client{
		defaultAppID: "app-test",
		httpClient:   network.NewHTTPClient(server.URL, server.Client()),
	}
	return c, server.Close
}

// ─── InvitePasskeyUser ────────────────────────────────────────────────────────

func TestClientInvitePasskeyUser_Success(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"invite_token":"tok-1","register_url":"/register?invite=tok-1","expires_at":"2099-01-01T00:00:00Z"}`))
	})
	defer close()

	res, err := c.InvitePasskeyUser(types.PasskeyInviteRequest{DisplayName: "Alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	if res.InviteToken != "tok-1" {
		t.Fatalf("unexpected token: %s", res.InviteToken)
	}
	if res.RegisterURL != "/register?invite=tok-1" {
		t.Fatalf("unexpected URL: %s", res.RegisterURL)
	}
}

func TestClientInvitePasskeyUser_NoAppID(t *testing.T) {
	c := &Client{httpClient: network.NewHTTPClient("http://localhost:1", &http.Client{})}
	_, err := c.InvitePasskeyUser(types.PasskeyInviteRequest{DisplayName: "Bob"})
	if err == nil {
		t.Fatal("expected error when no App ID configured")
	}
}

func TestClientInvitePasskeyUser_ServerError(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"display_name required"}`))
	})
	defer close()

	res, err := c.InvitePasskeyUser(types.PasskeyInviteRequest{})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false")
	}
	if res.Error == "" {
		t.Fatal("expected non-empty Error")
	}
}

// ─── ListPasskeyUsers ─────────────────────────────────────────────────────────

func TestClientListPasskeyUsers_Success(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"display_name":"Alice"}],"total":1,"page":1,"limit":10}`))
	})
	defer close()

	res, err := c.ListPasskeyUsers(1, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	if len(res.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(res.Users))
	}
	if res.Total != 1 {
		t.Fatalf("expected total=1, got %d", res.Total)
	}
}

func TestClientListPasskeyUsers_EmptyList(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[],"total":0}`))
	})
	defer close()

	res, err := c.ListPasskeyUsers(0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success")
	}
	if len(res.Users) != 0 {
		t.Fatalf("expected empty users")
	}
}

// ─── DeletePasskeyUser ────────────────────────────────────────────────────────

func TestClientDeletePasskeyUser_Success(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	defer close()

	res, err := c.DeletePasskeyUser(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success")
	}
}

func TestClientDeletePasskeyUser_NotFound(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"passkey user not found"}`))
	})
	defer close()

	res, err := c.DeletePasskeyUser(99)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false")
	}
	if res.Error != "passkey user not found" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
}

// ─── ListAuditRecords ─────────────────────────────────────────────────────────

func TestClientListAuditRecords_Success(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"records":[{"id":1,"action":"APPROVE"}],"total":1,"page":1,"limit":10}`))
	})
	defer close()

	res, err := c.ListAuditRecords(1, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success")
	}
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(res.Records))
	}
}

// ─── UpsertPermissionPolicy ───────────────────────────────────────────────────

func TestClientUpsertPermissionPolicy_Success(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("expected PUT, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"policy_id":5}`))
	})
	defer close()

	res, err := c.UpsertPermissionPolicy(types.PolicyRequest{
		PublicKeyName: "my-key",
		Enabled:       true,
		Levels: []types.PolicyLevel{
			{LevelIndex: 1, Threshold: 1, MemberIDs: []uint{1}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
}

func TestClientUpsertPermissionPolicy_ServerRejectsEmpty(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"public_key_name required"}`))
	})
	defer close()

	res, err := c.UpsertPermissionPolicy(types.PolicyRequest{})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false")
	}
}

// ─── GetPermissionPolicy ──────────────────────────────────────────────────────

func TestClientGetPermissionPolicy_Success(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policy":{
			"id":3,
			"application_id":1,
			"public_key_id":2,
			"public_key_name":"my-key",
			"enabled":true,
			"timeout_seconds":120,
			"levels":[{"level_index":1,"threshold":1,"member_ids":[7]}]
		}}`))
	})
	defer close()

	res, err := c.GetPermissionPolicy("my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.Error)
	}
	if res.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}
	if !res.Policy.Enabled {
		t.Fatal("expected policy.Enabled=true")
	}
	if len(res.Policy.Levels) != 1 {
		t.Fatalf("expected 1 level, got %d", len(res.Policy.Levels))
	}
	if res.Policy.Levels[0].MemberIDs[0] != 7 {
		t.Fatalf("unexpected member_id: %v", res.Policy.Levels[0].MemberIDs)
	}
}

func TestClientGetPermissionPolicy_NotFound(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"policy not found"}`))
	})
	defer close()

	res, err := c.GetPermissionPolicy("missing-key")
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false")
	}
	if res.Error != "policy not found" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
}

// ─── DeletePermissionPolicy ───────────────────────────────────────────────────

func TestClientDeletePermissionPolicy_Success(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	defer close()

	res, err := c.DeletePermissionPolicy("my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success")
	}
}

func TestClientDeletePermissionPolicy_NotFound(t *testing.T) {
	c, close := newAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"policy not found"}`))
	})
	defer close()

	res, err := c.DeletePermissionPolicy("ghost-key")
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res.Success {
		t.Fatal("expected success=false")
	}
}

// ─── transport errors ─────────────────────────────────────────────────────────

func TestClientAdminMethods_TransportError(t *testing.T) {
	c := &Client{
		defaultAppID: "app-x",
		httpClient:   network.NewHTTPClient("http://localhost:1", &http.Client{}),
	}

	if res, err := c.ListPasskeyUsers(0, 0); err == nil || res.Success {
		t.Fatal("expected error from ListPasskeyUsers")
	}
	if res, err := c.DeletePasskeyUser(1); err == nil || res.Success {
		t.Fatal("expected error from DeletePasskeyUser")
	}
	if res, err := c.ListAuditRecords(0, 0); err == nil || res.Success {
		t.Fatal("expected error from ListAuditRecords")
	}
	if res, err := c.GetPermissionPolicy("k"); err == nil || res.Success {
		t.Fatal("expected error from GetPermissionPolicy")
	}
	if res, err := c.DeletePermissionPolicy("k"); err == nil || res.Success {
		t.Fatal("expected error from DeletePermissionPolicy")
	}
}
