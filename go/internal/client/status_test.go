// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// -----------------------------------------------------------------------------

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetStatus_Found(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cache/0xabc" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"found":   true,
			"entry": map[string]interface{}{
				"hash":           "0xabc",
				"status":         "signed",
				"signature":      "0xabcdef",
				"required_votes": 2,
				"requests": map[string]interface{}{
					"app1": map[string]interface{}{"approved": true},
					"app2": map[string]interface{}{"approved": false},
				},
				"error_message": "",
			},
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()

	status, err := client.GetStatus(ctx, "0xabc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Found {
		t.Fatal("expected Found=true")
	}
	if status.Status != "signed" {
		t.Errorf("expected status signed, got %s", status.Status)
	}
	if status.CurrentVotes != 1 {
		t.Errorf("expected current votes 1, got %d", status.CurrentVotes)
	}
	if status.RequiredVotes != 2 {
		t.Errorf("expected required votes 2, got %d", status.RequiredVotes)
	}
	if len(status.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestGetStatus_NotFound(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"found":   false,
			"message": "Cache entry not found",
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()

	status, err := client.GetStatus(ctx, "0xmissing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Found {
		t.Fatal("expected Found=false")
	}
	if status.ErrorMessage == "" {
		t.Error("expected error message for not found")
	}
}
