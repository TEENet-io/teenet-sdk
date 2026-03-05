package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

func TestSignAndWait_FinalSigned(t *testing.T) {
	statusCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/publickeys/test-app":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"public_keys": []map[string]interface{}{
					{"id": 1, "name": "pk1", "key_data": "0x04010203", "protocol": "ecdsa", "curve": "secp256k1"},
				},
			})
		case "/api/submit-request":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":        true,
				"hash":           "0xwait-hash",
				"status":         "pending",
				"current_votes":  1,
				"required_votes": 2,
				"needs_voting":   true,
			})
		case "/api/cache/0xwait-hash":
			statusCalls++
			if statusCalls < 2 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"found":   true,
					"entry": map[string]interface{}{
						"hash":           "0xwait-hash",
						"status":         "pending",
						"required_votes": 2,
						"requests": map[string]interface{}{
							"app1": map[string]interface{}{"approved": true},
						},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"found":   true,
				"entry": map[string]interface{}{
					"hash":           "0xwait-hash",
					"status":         "signed",
					"signature":      "0xabcdef",
					"required_votes": 2,
					"requests": map[string]interface{}{
						"app1": map[string]interface{}{"approved": true},
						"app2": map[string]interface{}{"approved": true},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, &types.ClientOptions{
		PendingWaitTimeout: 1 * time.Millisecond,
	})
	defer client.Close()
	client.SetDefaultAppID("test-app")

	result, err := client.SignAndWait([]byte("wait-message"), 2*time.Second, "pk1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success=true, got error=%s", result.Error)
	}
	if result.VotingInfo == nil || result.VotingInfo.Status != "signed" {
		t.Fatalf("expected signed voting info, got %#v", result.VotingInfo)
	}
	if len(result.Signature) == 0 {
		t.Fatal("expected signature bytes")
	}
}

func TestWaitForSignResult_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/cache/0xtimeout" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"found":   true,
			"entry": map[string]interface{}{
				"hash":           "0xtimeout",
				"status":         "pending",
				"required_votes": 3,
				"requests": map[string]interface{}{
					"app1": map[string]interface{}{"approved": true},
				},
			},
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(server.URL, nil)
	defer client.Close()

	result, err := client.WaitForSignResult("0xtimeout", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if result == nil || result.Success {
		t.Fatalf("expected failure result, got %#v", result)
	}
	if !strings.Contains(result.Error, "threshold not met before timeout") {
		t.Fatalf("expected threshold timeout error, got: %s", result.Error)
	}
	if result.VotingInfo == nil || result.VotingInfo.Status != "pending" {
		t.Fatalf("expected pending voting info on timeout, got %#v", result.VotingInfo)
	}
	if result.ErrorCode != types.ErrorCodeThresholdTimeout {
		t.Fatalf("expected error code %s, got %s", types.ErrorCodeThresholdTimeout, result.ErrorCode)
	}
}

func TestNextPollInterval_Bounds(t *testing.T) {
	for attempt := 1; attempt <= 10; attempt++ {
		got := nextPollInterval(attempt)
		if got < 10*time.Millisecond {
			t.Fatalf("attempt %d: interval too small: %v", attempt, got)
		}
		if got > maxPollInterval {
			t.Fatalf("attempt %d: interval too large: %v", attempt, got)
		}
	}
}
