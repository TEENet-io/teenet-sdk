package network

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── AdminInvitePasskeyUser ───────────────────────────────────────────────────

func TestAdminInvitePasskeyUser_MethodAndPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/admin/passkey/invite" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		// Verify app_instance_id is injected into body.
		body, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("failed to parse request body: %v", err)
		}
		if m["app_instance_id"] != "app-1" {
			t.Fatalf("expected app_instance_id=app-1, got %v", m["app_instance_id"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"invite_token":"tok-abc","register_url":"/register?invite=tok-abc"}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.AdminInvitePasskeyUser(context.Background(), "app-1", map[string]interface{}{
		"display_name": "Alice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Data["invite_token"] != "tok-abc" {
		t.Fatalf("unexpected invite_token: %v", resp.Data["invite_token"])
	}
}

func TestAdminInvitePasskeyUser_Non2xxPropagated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"display_name required"}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.AdminInvitePasskeyUser(context.Background(), "app-1", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// ─── AdminListPasskeyUsers ────────────────────────────────────────────────────

func TestAdminListPasskeyUsers_QueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		q := r.URL.Query()
		if q.Get("app_instance_id") != "app-2" {
			t.Fatalf("expected app_instance_id=app-2, got %s", q.Get("app_instance_id"))
		}
		if q.Get("page") != "2" {
			t.Fatalf("expected page=2, got %s", q.Get("page"))
		}
		if q.Get("limit") != "5" {
			t.Fatalf("expected limit=5, got %s", q.Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[],"total":0}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.AdminListPasskeyUsers(context.Background(), "app-2", 2, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAdminListPasskeyUsers_NoPageLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("page") != "" {
			t.Fatalf("expected no page param, got %s", q.Get("page"))
		}
		if q.Get("limit") != "" {
			t.Fatalf("expected no limit param, got %s", q.Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[]}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	_, err := client.AdminListPasskeyUsers(context.Background(), "app-3", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── AdminDeletePasskeyUser ───────────────────────────────────────────────────

func TestAdminDeletePasskeyUser_PathAndQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/api/admin/passkey/users/42") {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("app_instance_id") != "app-4" {
			t.Fatalf("expected app_instance_id=app-4 in query")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.AdminDeletePasskeyUser(context.Background(), "app-4", 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── AdminListAuditRecords ────────────────────────────────────────────────────

func TestAdminListAuditRecords_QueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/admin/audit-records" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("app_instance_id") != "app-5" {
			t.Fatalf("expected app_instance_id=app-5, got %s", q.Get("app_instance_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"records":[],"total":0}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.AdminListAuditRecords(context.Background(), "app-5", 1, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── AdminUpsertPolicy ────────────────────────────────────────────────────────

func TestAdminUpsertPolicy_MethodAndBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/api/admin/policy" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("failed to parse body: %v", err)
		}
		if m["app_instance_id"] != "app-6" {
			t.Fatalf("expected app_instance_id=app-6, got %v", m["app_instance_id"])
		}
		if m["public_key_name"] != "my-key" {
			t.Fatalf("expected public_key_name=my-key, got %v", m["public_key_name"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"policy_id":7}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.AdminUpsertPolicy(context.Background(), "app-6", map[string]interface{}{
		"public_key_name": "my-key",
		"enabled":         true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── AdminGetPolicy ───────────────────────────────────────────────────────────

func TestAdminGetPolicy_QueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		q := r.URL.Query()
		if q.Get("app_instance_id") != "app-7" {
			t.Fatalf("unexpected app_instance_id: %s", q.Get("app_instance_id"))
		}
		if q.Get("public_key_name") != "k1" {
			t.Fatalf("unexpected public_key_name: %s", q.Get("public_key_name"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policy":{"id":1,"enabled":true}}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.AdminGetPolicy(context.Background(), "app-7", "k1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── AdminDeletePolicy ────────────────────────────────────────────────────────

func TestAdminDeletePolicy_MethodAndQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		q := r.URL.Query()
		if q.Get("app_instance_id") != "app-8" {
			t.Fatalf("unexpected app_instance_id: %s", q.Get("app_instance_id"))
		}
		if q.Get("public_key_name") != "k2" {
			t.Fatalf("unexpected public_key_name: %s", q.Get("public_key_name"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	resp, err := client.AdminDeletePolicy(context.Background(), "app-8", "k2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── transport error ──────────────────────────────────────────────────────────

func TestAdminRequest_TransportError(t *testing.T) {
	client := NewHTTPClient("http://localhost:1", &http.Client{})
	_, err := client.AdminGetPolicy(context.Background(), "app-x", "k")
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !strings.Contains(err.Error(), "admin request failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestAdminRequest_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{bad json`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client())
	_, err := client.AdminListAuditRecords(context.Background(), "app-y", 1, 10)
	if err == nil || !strings.Contains(err.Error(), "failed to decode admin response") {
		t.Fatalf("expected decode error, got: %v", err)
	}
}
