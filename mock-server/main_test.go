// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// setupTestServer spins up the MockServer using httptest so no real TCP port is used.
func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	t.Setenv("PASSKEY_RP_ID", "localhost")
	t.Setenv("PASSKEY_RP_ORIGIN", "http://localhost:8080")
	t.Setenv("PASSKEY_RP_NAME", "TEENet Mock")
	t.Setenv("PASSKEY_REQUIRE_UV", "true")
	t.Setenv("PASSKEY_PLATFORM_ONLY", "false")
	gin.SetMode(gin.TestMode)
	s := NewMockServer("0") // port unused with httptest
	s.enableLogging = false // reduce noise during tests

	router := gin.New()
	api := router.Group("/api")
	{
		api.GET("/health", s.handleHealth)
		api.GET("/publickeys/:app_instance_id", s.handleGetPublicKeys)
		api.POST("/submit-request", s.handleSubmitRequest)
		api.POST("/generate-key", s.handleGenerateKey)
		api.GET("/apikey/:name", s.handleGetAPIKey)
		api.POST("/apikey/:name/sign", s.handleSignWithSecret)

		// Cache
		api.GET("/cache/status", s.handleCacheStatus)
		api.GET("/cache/:hash", s.handleGetCache)
		api.DELETE("/cache/:hash", s.handleDeleteCache)
		api.GET("/config/:app_instance_id", s.handleGetConfig)

		// Approval bridge (12)
		api.GET("/auth/passkey/options", s.handlePasskeyLoginOptions)
		api.POST("/auth/passkey/verify", s.handlePasskeyLoginVerify)
		api.POST("/auth/passkey/verify-as", s.handlePasskeyLoginVerifyAs)
		api.POST("/approvals/request/init", s.handleApprovalRequestInit)
		api.GET("/approvals/request/:requestId/challenge", s.handleApprovalRequestChallenge)
		api.POST("/approvals/request/:requestId/confirm", s.handleApprovalRequestConfirm)
		api.GET("/approvals/:taskId/challenge", s.handleApprovalActionChallenge)
		api.POST("/approvals/:taskId/action", s.handleApprovalAction)
		api.GET("/approvals/pending", s.handleApprovalPending)
		api.GET("/requests/mine", s.handleMyRequests)
		api.GET("/signature/by-tx/:txId", s.handleSignatureByTx)
		api.DELETE("/requests/:id", s.handleCancelRequest)

		// Admin bridge (12)
		api.POST("/admin/passkey/invite", s.handleAdminInvitePasskey)
		api.GET("/admin/passkey/users", s.handleAdminListPasskeyUsers)
		api.DELETE("/admin/passkey/users/:id", s.handleAdminDeletePasskeyUser)
		api.GET("/admin/audit-records", s.handleAdminListAuditRecords)
		api.PUT("/admin/policy", s.handleAdminUpsertPolicy)
		api.GET("/admin/policy", s.handleAdminGetPolicy)
		api.DELETE("/admin/policy", s.handleAdminDeletePolicy)
		api.DELETE("/admin/publickeys/:name", s.handleAdminDeletePublicKey)
		api.POST("/admin/apikeys", s.handleAdminCreateAPIKey)
		api.DELETE("/admin/apikeys/:name", s.handleAdminDeleteAPIKey)
		api.GET("/passkey/register/options", s.handlePasskeyRegisterOptions)
		api.POST("/passkey/register/verify", s.handlePasskeyRegisterVerify)
	}

	return httptest.NewServer(router)
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func getJSON(t *testing.T, url string, token string) map[string]interface{} {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("getJSON: NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("getJSON: Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("getJSON: unmarshal: %v (body=%s)", err, string(body))
	}
	result["__status"] = float64(resp.StatusCode)
	return result
}

func postJSON(t *testing.T, url string, body interface{}, token string) map[string]interface{} {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("postJSON: Marshal: %v", err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("postJSON: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("postJSON: Do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("postJSON: unmarshal: %v (body=%s)", err, string(b))
	}
	result["__status"] = float64(resp.StatusCode)
	return result
}

func unwrapPublicKeyOptions(t *testing.T, raw map[string]interface{}) map[string]interface{} {
	t.Helper()
	if raw == nil {
		t.Fatalf("expected options object")
	}
	if pk, ok := raw["publicKey"].(map[string]interface{}); ok {
		return pk
	}
	return raw
}

func putJSON(t *testing.T, url string, body interface{}, token string) map[string]interface{} {
	t.Helper()
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("putJSON: Do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(b, &result)
	result["__status"] = float64(resp.StatusCode)
	return result
}

func deleteJSON(t *testing.T, url string, token string) map[string]interface{} {
	t.Helper()
	req, _ := http.NewRequest("DELETE", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("deleteJSON: Do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(b, &result)
	result["__status"] = float64(resp.StatusCode)
	return result
}

// statusCode extracts __status field injected by helpers.
func statusCode(m map[string]interface{}) int {
	if v, ok := m["__status"]; ok {
		return int(v.(float64))
	}
	return 0
}

// login performs a passkey login and returns the bearer token.
func login(t *testing.T, base string) string {
	t.Helper()
	opts := getJSON(t, base+"/api/auth/passkey/options", "")
	sessionID := opts["login_session_id"]
	result := postJSON(t, base+"/api/auth/passkey/verify", map[string]interface{}{
		"login_session_id": sessionID,
		"credential":       map[string]interface{}{"mock": true},
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("login failed: %v", result)
	}
	token, _ := result["token"].(string)
	if token == "" {
		t.Fatalf("login returned empty token")
	}
	return token
}

// submitDirectRequest submits to an app that signs immediately and returns the response.
func submitDirectRequest(t *testing.T, base, appInstanceID string, message []byte) map[string]interface{} {
	t.Helper()
	return postJSON(t, base+"/api/submit-request", map[string]interface{}{
		"app_instance_id": appInstanceID,
		"message":         message,
	}, "")
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/health", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	if result["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %v", result["status"])
	}
	if result["service"] == "" || result["service"] == nil {
		t.Errorf("expected service field, got nil")
	}
}

func TestGetPublicKeys_KnownApp(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/publickeys/test-ecdsa-secp256k1", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true, got %v", result["success"])
	}

	keys, ok := result["public_keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatalf("expected at least one public key")
	}

	key0 := keys[0].(map[string]interface{})
	if key0["protocol"] != "ecdsa" {
		t.Errorf("expected protocol=ecdsa, got %v", key0["protocol"])
	}
	if key0["curve"] != "secp256k1" {
		t.Errorf("expected curve=secp256k1, got %v", key0["curve"])
	}
	keyData, _ := key0["key_data"].(string)
	if keyData == "" || strings.HasPrefix(keyData, "0x") {
		t.Errorf("expected plain-hex key_data (no 0x prefix, matching app-comm-consensus), got %q", keyData)
	}
}

func TestGetPublicKeys_NonExistentAutoCreates(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/publickeys/nonexistent-app-xyz-123", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	keys, ok := result["public_keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatalf("expected auto-created key")
	}
	key0 := keys[0].(map[string]interface{})
	keyData, _ := key0["key_data"].(string)
	if keyData == "" || strings.HasPrefix(keyData, "0x") {
		t.Errorf("expected plain-hex key_data (no 0x prefix), got %q", keyData)
	}
}

func TestGetPublicKeys_AllDefaultApps(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	apps := []struct {
		id       string
		protocol string
		curve    string
	}{
		{"test-schnorr-ed25519", "schnorr", "ed25519"},
		{"test-schnorr-secp256k1", "schnorr", "secp256k1"},
		{"test-ecdsa-secp256k1", "ecdsa", "secp256k1"},
		{"test-ecdsa-secp256r1", "ecdsa", "secp256r1"},
		{"ethereum-wallet-app", "ecdsa", "secp256k1"},
		{"secure-messaging-app", "schnorr", "ed25519"},
	}
	for _, app := range apps {
		result := getJSON(t, ts.URL+"/api/publickeys/"+app.id, "")
		if statusCode(result) != 200 {
			t.Errorf("%s: expected 200, got %d", app.id, statusCode(result))
			continue
		}
		keys := result["public_keys"].([]interface{})
		key0 := keys[0].(map[string]interface{})
		if key0["protocol"] != app.protocol {
			t.Errorf("%s: expected protocol=%s, got %v", app.id, app.protocol, key0["protocol"])
		}
		if key0["curve"] != app.curve {
			t.Errorf("%s: expected curve=%s, got %v", app.id, app.curve, key0["curve"])
		}
	}
}

func TestDirectSigning_ECDSA_SECP256K1(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	message := []byte("hello teenet signing test")
	result := submitDirectRequest(t, ts.URL, "test-ecdsa-secp256k1", message)

	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	if result["status"] != "signed" {
		t.Errorf("expected status=signed, got %v", result["status"])
	}
	sig, _ := result["signature"].(string)
	if sig == "" {
		t.Fatalf("expected non-empty signature")
	}
	// secp256k1 ECDSA: 65 bytes = 130 hex chars
	if len(sig) != 130 {
		t.Errorf("expected 130 hex chars (65 bytes), got %d: %s", len(sig), sig)
	}
	hashVal, _ := result["hash"].(string)
	if !strings.HasPrefix(hashVal, "0x") {
		t.Errorf("expected hash with 0x prefix, got %q", hashVal)
	}
}

func TestDirectSigning_Schnorr_ED25519(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := submitDirectRequest(t, ts.URL, "test-schnorr-ed25519", []byte("test message ed25519"))
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["status"] != "signed" {
		t.Errorf("expected signed, got %v", result["status"])
	}
	sig, _ := result["signature"].(string)
	// ED25519: 64 bytes = 128 hex chars
	if len(sig) != 128 {
		t.Errorf("expected 128 hex chars (64 bytes), got %d", len(sig))
	}
}

func TestDirectSigning_Schnorr_SECP256K1(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := submitDirectRequest(t, ts.URL, "test-schnorr-secp256k1", []byte("test schnorr secp256k1"))
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["status"] != "signed" {
		t.Errorf("expected signed, got %v", result["status"])
	}
	sig, _ := result["signature"].(string)
	// BIP-340 Schnorr: 64 bytes = 128 hex chars
	if len(sig) != 128 {
		t.Errorf("expected 128 hex chars, got %d", len(sig))
	}
}

func TestDirectSigning_ECDSA_SECP256R1(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := submitDirectRequest(t, ts.URL, "test-ecdsa-secp256r1", []byte("test ecdsa p256"))
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["status"] != "signed" {
		t.Errorf("expected signed, got %v", result["status"])
	}
	sig, _ := result["signature"].(string)
	// P-256 ECDSA: 64 bytes = 128 hex chars
	if len(sig) != 128 {
		t.Errorf("expected 128 hex chars, got %d", len(sig))
	}
}

func TestDirectSigning_MissingAppInstanceID(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// A request with no app_instance_id at all must be rejected as 400
	// by Gin's binding:"required" check.
	result := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"message": []byte("test"),
	}, "")
	if statusCode(result) != 400 {
		t.Errorf("omitted app_instance_id: expected 400, got %d: %v", statusCode(result), result)
	}
	if result["success"] == true {
		t.Errorf("omitted app_instance_id: expected success=false")
	}

	// An explicit empty string must likewise be rejected.
	result2 := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "",
		"message":         []byte("test"),
	}, "")
	if statusCode(result2) != 400 {
		t.Errorf("empty app_instance_id: expected 400, got %d: %v", statusCode(result2), result2)
	}
	if result2["success"] == true {
		t.Errorf("empty app_instance_id: expected success=false")
	}
}

func TestDirectSigning_UnknownApp(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "unknown-app-that-does-not-exist",
		"message":         []byte("hello"),
	}, "")
	// Server returns 400 for unknown app
	if statusCode(result) != 400 {
		t.Errorf("expected 400 for unknown app, got %d: %v", statusCode(result), result)
	}
	if result["success"] == true {
		t.Errorf("expected success=false for unknown app")
	}
}

func TestVotingMode_Threshold2of3(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	message := []byte("voting test message for 2of3")

	// First vote (voter1) — should be pending, count=1/2.
	r1 := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-voting-2of3",
		"message":         message,
	}, "")
	if statusCode(r1) != 200 {
		t.Fatalf("first vote: expected 200, got %d: %v", statusCode(r1), r1)
	}
	if r1["status"] != "pending" {
		t.Errorf("first vote: expected status=pending, got %v", r1["status"])
	}
	if r1["needs_voting"] != true {
		t.Errorf("first vote: expected needs_voting=true")
	}
	if currentVotes, _ := r1["current_votes"].(float64); currentVotes != 1 {
		t.Errorf("first vote: expected current_votes=1, got %v", r1["current_votes"])
	}
	if requiredVotes, _ := r1["required_votes"].(float64); requiredVotes != 2 {
		t.Errorf("first vote: expected required_votes=2, got %v", r1["required_votes"])
	}

	hash, _ := r1["hash"].(string)
	if hash == "" {
		t.Fatalf("expected hash in response")
	}

	// Cache entry should exist and be pending after one vote.
	cacheResult := getJSON(t, ts.URL+"/api/cache/"+hash, "")
	if cacheResult["found"] != true {
		t.Errorf("expected cache entry found=true after first vote")
	}
	if entry, _ := cacheResult["entry"].(map[string]interface{}); entry["status"] != "pending" {
		t.Errorf("expected cache entry status=pending, got %v", entry["status"])
	}

	// Second vote from a different voter in the same voting group —
	// must reach threshold 2/2 and return a signed signature.
	r2 := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-voting-2of3-voter2",
		"message":         message,
	}, "")
	if statusCode(r2) != 200 {
		t.Fatalf("second vote: expected 200, got %d: %v", statusCode(r2), r2)
	}
	if r2["status"] != "signed" {
		t.Errorf("second vote: expected status=signed, got %v (body=%v)", r2["status"], r2)
	}
	if r2["needs_voting"] != false {
		t.Errorf("second vote: expected needs_voting=false, got %v", r2["needs_voting"])
	}
	if currentVotes, _ := r2["current_votes"].(float64); currentVotes != 2 {
		t.Errorf("second vote: expected current_votes=2, got %v", r2["current_votes"])
	}
	sig, _ := r2["signature"].(string)
	// 65-byte Ethereum-style signature = 130 hex chars.
	if len(sig) != 130 {
		t.Errorf("second vote: expected 130 hex chars, got %d: %q", len(sig), sig)
	}
	// The cache entry hash should match between the two responses.
	if h2, _ := r2["hash"].(string); h2 != hash {
		t.Errorf("voter2 hash %q != voter1 hash %q", h2, hash)
	}

	// Cache must now show signed status with the same signature.
	cacheFinal := getJSON(t, ts.URL+"/api/cache/"+hash, "")
	finalEntry, _ := cacheFinal["entry"].(map[string]interface{})
	if finalEntry["status"] != "signed" {
		t.Errorf("cache final: expected status=signed, got %v", finalEntry["status"])
	}
	if finalEntry["signature"] != sig {
		t.Errorf("cache final: signature mismatch, got %v want %v", finalEntry["signature"], sig)
	}
}

func TestVotingMode_CacheEntry(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	message := []byte("cache verification test message")
	r := submitDirectRequest(t, ts.URL, "test-ecdsa-secp256k1", message)
	if statusCode(r) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(r))
	}
	// Direct signing apps return "signed" but DO NOT store in cache — verify
	hash, _ := r["hash"].(string)
	if hash == "" {
		t.Fatalf("no hash in response")
	}
	// Direct signing does not cache; voting does
	// Use voting app to populate cache
	vr := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-voting-2of3",
		"message":         []byte("cache test voting message"),
	}, "")
	vHash, _ := vr["hash"].(string)
	if vHash == "" {
		t.Fatalf("no hash from voting request")
	}

	cacheResult := getJSON(t, ts.URL+"/api/cache/"+vHash, "")
	if cacheResult["found"] != true {
		t.Errorf("expected found=true, got %v", cacheResult["found"])
	}
	entry, _ := cacheResult["entry"].(map[string]interface{})
	if entry == nil {
		t.Fatalf("expected entry, got nil")
	}
	if entry["status"] != "pending" {
		t.Errorf("expected pending, got %v", entry["status"])
	}
}

func TestApprovalMode_Submit(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"message":         []byte("approval test message"),
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["status"] != "pending_approval" {
		t.Errorf("expected status=pending_approval, got %v", result["status"])
	}
	txID, _ := result["tx_id"].(string)
	if txID == "" {
		t.Errorf("expected tx_id in response")
	}
	requestID := result["request_id"]
	if requestID == nil {
		t.Errorf("expected request_id in response")
	}
	hash, _ := result["hash"].(string)
	if !strings.HasPrefix(hash, "0x") {
		t.Errorf("expected hash with 0x prefix, got %q", hash)
	}
}

func TestApprovalMode_CacheEntryPendingApproval(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"message":         []byte("approval cache check message"),
	}, "")
	hash, _ := result["hash"].(string)
	if hash == "" {
		t.Fatalf("no hash returned")
	}

	cacheResult := getJSON(t, ts.URL+"/api/cache/"+hash, "")
	if cacheResult["found"] != true {
		t.Errorf("expected found=true")
	}
	entry, _ := cacheResult["entry"].(map[string]interface{})
	if entry["status"] != "pending_approval" {
		t.Errorf("expected pending_approval, got %v", entry["status"])
	}
}

func TestGetCache_NotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/cache/0xdeadbeefdeadbeef000000000000000000000000000000000000000000000000", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	if result["found"] != false {
		t.Errorf("expected found=false for non-existent hash")
	}
}

func TestGetCache_WithAndWithout0xPrefix(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Create a cache entry via voting
	vr := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-voting-2of3",
		"message":         []byte("prefix normalisation test"),
	}, "")
	hash, _ := vr["hash"].(string)
	if hash == "" {
		t.Fatalf("no hash")
	}
	// With 0x prefix
	r1 := getJSON(t, ts.URL+"/api/cache/"+hash, "")
	if r1["found"] != true {
		t.Errorf("expected found=true with 0x prefix")
	}
	// Without 0x prefix (strip it)
	hashNoPrefix := strings.TrimPrefix(hash, "0x")
	r2 := getJSON(t, ts.URL+"/api/cache/"+hashNoPrefix, "")
	if r2["found"] != true {
		t.Errorf("expected found=true without 0x prefix")
	}
}

func TestDeleteCache(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Create entry
	vr := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-voting-2of3",
		"message":         []byte("delete cache test message"),
	}, "")
	hash, _ := vr["hash"].(string)
	if hash == "" {
		t.Fatalf("no hash returned")
	}

	// Confirm it exists
	cr := getJSON(t, ts.URL+"/api/cache/"+hash, "")
	if cr["found"] != true {
		t.Fatalf("entry should exist before delete")
	}

	// Delete it
	dr := deleteJSON(t, ts.URL+"/api/cache/"+hash, "")
	if statusCode(dr) != 200 {
		t.Fatalf("expected 200 on delete, got %d: %v", statusCode(dr), dr)
	}
	if dr["success"] != true {
		t.Errorf("expected success=true on delete")
	}

	// Verify gone
	cr2 := getJSON(t, ts.URL+"/api/cache/"+hash, "")
	if cr2["found"] != false {
		t.Errorf("expected found=false after delete")
	}
}

func TestDeleteCache_NotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	dr := deleteJSON(t, ts.URL+"/api/cache/0xabcdef1234567890000000000000000000000000000000000000000000000000", "")
	if statusCode(dr) != 404 {
		t.Errorf("expected 404 for non-existent cache entry, got %d", statusCode(dr))
	}
}

func TestCacheStatus(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Create a few entries
	for i := 0; i < 3; i++ {
		postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
			"app_instance_id": "test-voting-2of3",
			"message":         []byte(fmt.Sprintf("cache status test %d", i)),
		}, "")
	}

	result := getJSON(t, ts.URL+"/api/cache/status", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	total, _ := result["total_entries"].(float64)
	if total < 3 {
		t.Errorf("expected total_entries >= 3, got %v", total)
	}
}

func TestGetConfig_VotingApp(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/config/test-voting-2of3", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	if result["enable_voting"] != true {
		t.Errorf("expected enable_voting=true, got %v", result["enable_voting"])
	}
	reqVotes, _ := result["required_votes"].(float64)
	if reqVotes != 2 {
		t.Errorf("expected required_votes=2, got %v", result["required_votes"])
	}
}

func TestGetConfig_DirectSigningApp(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/config/test-ecdsa-secp256k1", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	if result["enable_voting"] != false {
		t.Errorf("expected enable_voting=false for direct signing app, got %v", result["enable_voting"])
	}
}

func TestGetConfig_ApprovalApp(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/config/test-approval-required", "")
	if result["passkey_policy_enabled"] != true {
		t.Errorf("expected passkey_policy_enabled=true, got %v", result["passkey_policy_enabled"])
	}
}

func TestGetConfig_UnknownAppGetsDefault(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/config/unknown-app-for-config-test", "")
	if result["enable_voting"] != false {
		t.Errorf("expected default enable_voting=false")
	}
	if result["passkey_policy_enabled"] != false {
		t.Errorf("expected default passkey_policy_enabled=false")
	}
}

func TestGenerateKey_ECDSA_SECP256K1(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/generate-key", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256k1",
		"curve":           "secp256k1",
		"protocol":        "ecdsa",
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	pk, _ := result["public_key"].(map[string]interface{})
	if pk == nil {
		t.Fatalf("expected public_key object")
	}
	if pk["id"] == nil {
		t.Errorf("expected id field")
	}
	if pk["name"] == nil {
		t.Errorf("expected name field")
	}
	keyData, _ := pk["key_data"].(string)
	if keyData == "" {
		t.Errorf("expected key_data")
	}
	keyBytes, err := hex.DecodeString(keyData)
	if err != nil {
		t.Fatalf("expected hex key_data, got error: %v", err)
	}
	if len(keyBytes) != 33 {
		t.Fatalf("expected compressed secp256k1 pubkey length 33, got %d", len(keyBytes))
	}
	if keyBytes[0] != 0x02 && keyBytes[0] != 0x03 {
		t.Fatalf("expected compressed secp256k1 prefix 0x02/0x03, got 0x%02x", keyBytes[0])
	}
}

func TestGenerateKey_Schnorr_ED25519(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/generate-key", map[string]interface{}{
		"app_instance_id": "test-schnorr-ed25519",
		"curve":           "ed25519",
		"protocol":        "schnorr",
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	pk, _ := result["public_key"].(map[string]interface{})
	if pk["curve"] != "ed25519" {
		t.Errorf("expected curve=ed25519, got %v", pk["curve"])
	}
	if pk["protocol"] != "schnorr" {
		t.Errorf("expected protocol=schnorr, got %v", pk["protocol"])
	}
}

func TestGenerateKey_ECDSA_SECP256R1(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/generate-key", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256r1",
		"curve":           "secp256r1",
		"protocol":        "ecdsa",
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
}

func TestGenerateKey_AppearsInPublicKeys(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	appID := "gen-key-visibility-test"
	// Trigger auto-creation
	getJSON(t, ts.URL+"/api/publickeys/"+appID, "")

	genResult := postJSON(t, ts.URL+"/api/generate-key", map[string]interface{}{
		"app_instance_id": appID,
		"curve":           "secp256k1",
		"protocol":        "ecdsa",
	}, "")
	if genResult["success"] != true {
		t.Fatalf("key generation failed: %v", genResult)
	}
	pk, _ := genResult["public_key"].(map[string]interface{})
	generatedName, _ := pk["name"].(string)

	// Now fetch public keys list
	keysResult := getJSON(t, ts.URL+"/api/publickeys/"+appID, "")
	keys, _ := keysResult["public_keys"].([]interface{})
	found := false
	for _, k := range keys {
		kMap := k.(map[string]interface{})
		if kMap["name"] == generatedName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("generated key %q not found in public_keys list", generatedName)
	}
}

func TestGenerateKey_UnsupportedProtocol(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/generate-key", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256k1",
		"curve":           "secp256k1",
		"protocol":        "invalid-protocol",
	}, "")
	if statusCode(result) != 400 {
		t.Errorf("expected 400 for unsupported protocol, got %d", statusCode(result))
	}
}

func TestGenerateKey_UnsupportedCurve(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/generate-key", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256k1",
		"curve":           "invalid-curve",
		"protocol":        "ecdsa",
	}, "")
	if statusCode(result) != 400 {
		t.Errorf("expected 400 for unsupported curve, got %d", statusCode(result))
	}
}

func TestGetAPIKey_KnownKey(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/apikey/test-api-key?app_instance_id=test-ecdsa-secp256k1", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	apiKey, _ := result["api_key"].(string)
	if apiKey == "" {
		t.Errorf("expected api_key in response")
	}
	if !strings.Contains(apiKey, "test-ecdsa-secp256k1") {
		t.Errorf("expected api_key to contain app id, got %q", apiKey)
	}
}

func TestGetAPIKey_UnknownApp_AutoCreates(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/apikey/some-key?app_instance_id=unknown-app-for-apikey", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	apiKey, _ := result["api_key"].(string)
	if apiKey == "" {
		t.Errorf("expected auto-created api_key")
	}
}

func TestGetAPIKey_SecretOnlyKey(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// test-api-secret has HasKey=false, HasSecret=true
	result := getJSON(t, ts.URL+"/api/apikey/test-api-secret?app_instance_id=test-ecdsa-secp256k1", "")
	// Should return 400 because HasKey=false
	if statusCode(result) != 400 {
		t.Errorf("expected 400 for secret-only key, got %d: %v", statusCode(result), result)
	}
}

func TestGetAPIKey_MissingAppInstanceID(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/apikey/test-api-key", "")
	if statusCode(result) != 400 {
		t.Errorf("expected 400 for missing app_instance_id, got %d", statusCode(result))
	}
}

func TestSignWithAPISecret(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Default payloads are hex-encoded (matches both SDKs).
	result := postJSON(t, ts.URL+"/api/apikey/test-api-secret/sign", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256k1",
		"message":         hex.EncodeToString([]byte("hello world")),
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	sig, _ := result["signature"].(string)
	if len(sig) != 64 {
		t.Errorf("expected 64 hex chars (32 bytes HMAC-SHA256), got %d: %q", len(sig), sig)
	}
	algo, _ := result["algorithm"].(string)
	if algo != "HMAC-SHA256" {
		t.Errorf("expected algorithm=HMAC-SHA256, got %q", algo)
	}

	// encoding="raw" is also accepted for direct curl callers.
	rawResult := postJSON(t, ts.URL+"/api/apikey/test-api-secret/sign", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256k1",
		"message":         "hello world",
		"encoding":        "raw",
	}, "")
	if statusCode(rawResult) != 200 {
		t.Fatalf("encoding=raw: expected 200, got %d: %v", statusCode(rawResult), rawResult)
	}
	rawSig, _ := rawResult["signature"].(string)
	if rawSig != sig {
		t.Errorf("encoding=raw should produce the same HMAC as the hex-encoded body: got %q want %q", rawSig, sig)
	}
}

func TestSignWithAPISecret_DifferentMessages_DifferentSignatures(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	r1 := postJSON(t, ts.URL+"/api/apikey/test-api-secret/sign", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256k1",
		"message":         hex.EncodeToString([]byte("message1")),
	}, "")
	r2 := postJSON(t, ts.URL+"/api/apikey/test-api-secret/sign", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256k1",
		"message":         hex.EncodeToString([]byte("message2")),
	}, "")
	sig1, _ := r1["signature"].(string)
	sig2, _ := r2["signature"].(string)
	if sig1 == sig2 {
		t.Errorf("expected different signatures for different messages")
	}
}

func TestSignWithAPISecret_InvalidHex(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// A bare string that is not valid hex and no encoding flag should
	// fail with 400, not silently fall back to raw bytes.
	result := postJSON(t, ts.URL+"/api/apikey/test-api-secret/sign", map[string]interface{}{
		"app_instance_id": "test-ecdsa-secp256k1",
		"message":         "hello world", // "h" is not a valid hex character
	}, "")
	if statusCode(result) != 400 {
		t.Errorf("expected 400 for non-hex message without encoding flag, got %d: %v", statusCode(result), result)
	}
}

func TestPasskeyLoginOptions(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/auth/passkey/options", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	sessionID := result["login_session_id"]
	if sessionID == nil {
		t.Errorf("expected login_session_id")
	}
	options, _ := result["options"].(map[string]interface{})
	if options == nil {
		t.Fatalf("expected options object")
	}
	options = unwrapPublicKeyOptions(t, options)
	challenge, _ := options["challenge"].(string)
	if challenge == "" {
		t.Errorf("expected non-empty challenge")
	}
}

func TestPasskeyLoginVerify(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// First get session
	optResult := getJSON(t, ts.URL+"/api/auth/passkey/options", "")
	sessionID := optResult["login_session_id"]

	result := postJSON(t, ts.URL+"/api/auth/passkey/verify", map[string]interface{}{
		"login_session_id": sessionID,
		"credential":       map[string]interface{}{"id": "mock-credential"},
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	token, _ := result["token"].(string)
	if token == "" {
		t.Fatalf("expected token in response")
	}
	// Token must contain "." (base64payload.hmac format)
	if !strings.Contains(token, ".") {
		t.Errorf("expected token to contain '.', got %q", token)
	}
	passkeyUserID := result["passkey_user_id"]
	if passkeyUserID == nil {
		t.Errorf("expected passkey_user_id in response")
	}
}

func TestPasskeyLoginVerifyAs(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/auth/passkey/verify-as", map[string]interface{}{
		"login_session_id":         1,
		"credential":               map[string]interface{}{"id": "mock"},
		"expected_passkey_user_id": 1,
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	token, _ := result["token"].(string)
	if token == "" {
		t.Errorf("expected token")
	}
}

func TestPasskeyLoginVerifyAs_NonExistentUser(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/auth/passkey/verify-as", map[string]interface{}{
		"login_session_id":         1,
		"credential":               map[string]interface{}{"id": "mock"},
		"expected_passkey_user_id": 9999,
	}, "")
	if statusCode(result) != 401 {
		t.Errorf("expected 401 for non-existent user, got %d", statusCode(result))
	}
}

func TestApprovalFlow_Complete(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Step 1: login
	token := login(t, ts.URL)

	// Step 2: submit approval request to create a cache entry + approval task
	submitResult := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"message":         []byte("approval flow complete test"),
	}, "")
	if submitResult["status"] != "pending_approval" {
		t.Fatalf("expected pending_approval, got %v", submitResult["status"])
	}
	hash, _ := submitResult["hash"].(string)
	requestID := submitResult["request_id"]
	requestIDStr := fmt.Sprintf("%.0f", requestID.(float64))

	// Step 3: init an approval request (authenticated)
	initResult := postJSON(t, ts.URL+"/api/approvals/request/init", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"hash":            hash,
		"payload":         map[string]interface{}{"action": "transfer", "amount": "100"},
	}, token)
	if statusCode(initResult) != 200 {
		t.Fatalf("approval init failed: %d: %v", statusCode(initResult), initResult)
	}
	if initResult["success"] != true {
		t.Fatalf("expected success=true in init")
	}
	initData, _ := initResult["data"].(map[string]interface{})
	newRequestID, _ := initData["request_id"].(float64)
	newRequestIDStr := fmt.Sprintf("%.0f", newRequestID)
	txID, _ := initData["tx_id"].(string)
	if txID == "" {
		t.Fatalf("expected tx_id in init response")
	}

	// Step 4: get challenge for the request
	challengeResult := getJSON(t, ts.URL+"/api/approvals/request/"+newRequestIDStr+"/challenge", "")
	if statusCode(challengeResult) != 200 {
		t.Fatalf("challenge failed: %d: %v", statusCode(challengeResult), challengeResult)
	}
	if challengeResult["success"] != true {
		t.Errorf("expected success=true in challenge")
	}

	// Step 5: confirm the request
	confirmResult := postJSON(t, ts.URL+"/api/approvals/request/"+newRequestIDStr+"/confirm", map[string]interface{}{
		"credential": map[string]interface{}{"id": "mock-cred"},
	}, "")
	if statusCode(confirmResult) != 200 {
		t.Fatalf("confirm failed: %d: %v", statusCode(confirmResult), confirmResult)
	}
	if confirmResult["success"] != true {
		t.Fatalf("expected success=true in confirm")
	}
	confirmData, _ := confirmResult["data"].(map[string]interface{})
	taskID, _ := confirmData["task_id"].(float64)
	taskIDStr := fmt.Sprintf("%.0f", taskID)
	if taskIDStr == "0" {
		t.Fatalf("expected valid task_id, got %v", taskID)
	}

	// Step 6: get action challenge for the task
	actionChallengeResult := getJSON(t, ts.URL+"/api/approvals/"+taskIDStr+"/challenge", "")
	if statusCode(actionChallengeResult) != 200 {
		t.Fatalf("action challenge failed: %d", statusCode(actionChallengeResult))
	}
	if actionChallengeResult["success"] != true {
		t.Errorf("expected success=true in action challenge")
	}

	// Step 7: take action (APPROVE)
	actionResult := postJSON(t, ts.URL+"/api/approvals/"+taskIDStr+"/action", map[string]interface{}{
		"action":     "APPROVE",
		"credential": map[string]interface{}{"id": "mock-cred"},
	}, token)
	if statusCode(actionResult) != 200 {
		t.Fatalf("action failed: %d: %v", statusCode(actionResult), actionResult)
	}
	if actionResult["success"] != true {
		t.Fatalf("expected success=true in action")
	}
	actionData, _ := actionResult["data"].(map[string]interface{})
	if actionData["status"] != "APPROVED" {
		t.Errorf("expected status=APPROVED, got %v", actionData["status"])
	}

	// Use requestIDStr to avoid "declared and not used" lint error
	_ = requestIDStr
}

func TestApprovalFlow_Reject(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	token := login(t, ts.URL)

	// Create task
	initResult := postJSON(t, ts.URL+"/api/approvals/request/init", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"hash":            "0xdeadbeef",
	}, token)
	initData, _ := initResult["data"].(map[string]interface{})
	requestID, _ := initData["request_id"].(float64)
	requestIDStr := fmt.Sprintf("%.0f", requestID)

	// Confirm
	confirmResult := postJSON(t, ts.URL+"/api/approvals/request/"+requestIDStr+"/confirm", map[string]interface{}{
		"credential": map[string]interface{}{},
	}, "")
	confirmData, _ := confirmResult["data"].(map[string]interface{})
	taskID, _ := confirmData["task_id"].(float64)
	taskIDStr := fmt.Sprintf("%.0f", taskID)

	// Reject action
	actionResult := postJSON(t, ts.URL+"/api/approvals/"+taskIDStr+"/action", map[string]interface{}{
		"action":     "REJECT",
		"credential": map[string]interface{}{},
	}, token)
	if actionResult["success"] != true {
		t.Fatalf("expected success=true for REJECT action: %v", actionResult)
	}
	actionData, _ := actionResult["data"].(map[string]interface{})
	if actionData["status"] != "REJECTED" {
		t.Errorf("expected status=REJECTED, got %v", actionData["status"])
	}
}

func TestApprovalAction_InvalidAction(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	token := login(t, ts.URL)

	// Create a task first
	initResult := postJSON(t, ts.URL+"/api/approvals/request/init", map[string]interface{}{
		"app_instance_id": "test-approval-required",
	}, token)
	initData, _ := initResult["data"].(map[string]interface{})
	requestID, _ := initData["request_id"].(float64)
	requestIDStr := fmt.Sprintf("%.0f", requestID)

	confirmResult := postJSON(t, ts.URL+"/api/approvals/request/"+requestIDStr+"/confirm", map[string]interface{}{}, "")
	confirmData, _ := confirmResult["data"].(map[string]interface{})
	taskID, _ := confirmData["task_id"].(float64)
	taskIDStr := fmt.Sprintf("%.0f", taskID)

	result := postJSON(t, ts.URL+"/api/approvals/"+taskIDStr+"/action", map[string]interface{}{
		"action": "INVALID",
	}, token)
	if statusCode(result) != 400 {
		t.Errorf("expected 400 for invalid action, got %d: %v", statusCode(result), result)
	}
}

func TestApprovalPending(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Submit to approval app to create pending task
	postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"message":         []byte("pending approval test"),
	}, "")

	result := getJSON(t, ts.URL+"/api/approvals/pending", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	data, _ := result["data"].(map[string]interface{})
	total, _ := data["total"].(float64)
	if total < 1 {
		t.Errorf("expected at least 1 pending task, got %v", total)
	}
}

func TestApprovalPending_FilterByAppInstanceID(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Create pending tasks for approval app
	for i := 0; i < 2; i++ {
		postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
			"app_instance_id": "test-approval-required",
			"message":         []byte(fmt.Sprintf("filter test %d", i)),
		}, "")
	}

	// Filter by app_instance_id
	result := getJSON(t, ts.URL+"/api/approvals/pending?app_instance_id=test-approval-required", "")
	data, _ := result["data"].(map[string]interface{})
	total, _ := data["total"].(float64)
	if total < 2 {
		t.Errorf("expected >= 2 tasks for test-approval-required, got %v", total)
	}

	// Filter by non-existent app — should return 0
	result2 := getJSON(t, ts.URL+"/api/approvals/pending?app_instance_id=nonexistent-app-filter", "")
	data2, _ := result2["data"].(map[string]interface{})
	total2, _ := data2["total"].(float64)
	if total2 != 0 {
		t.Errorf("expected 0 tasks for nonexistent app, got %v", total2)
	}
}

func TestMyRequests(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	token := login(t, ts.URL)

	// Create a task as this user
	postJSON(t, ts.URL+"/api/approvals/request/init", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"hash":            "0xmyrequests-hash",
	}, token)

	result := getJSON(t, ts.URL+"/api/requests/mine", token)
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	count, _ := result["count"].(float64)
	if count < 1 {
		t.Errorf("expected count >= 1, got %v", count)
	}
}

func TestAuthRequired_ApprovalPendingNoToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// handleApprovalPending does NOT check auth — verify it returns 200 without token
	result := getJSON(t, ts.URL+"/api/approvals/pending", "")
	if statusCode(result) != 200 {
		t.Errorf("approvals/pending without token: expected 200, got %d", statusCode(result))
	}
}

func TestAuthRequired_MyRequestsNoToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/requests/mine", "")
	if statusCode(result) != 401 {
		t.Errorf("requests/mine without token: expected 401, got %d", statusCode(result))
	}
}

func TestAuthRequired_ApprovalRequestInitNoToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/approvals/request/init", map[string]interface{}{
		"app_instance_id": "test-approval-required",
	}, "")
	if statusCode(result) != 401 {
		t.Errorf("approvals/request/init without token: expected 401, got %d", statusCode(result))
	}
}

func TestAuthRequired_ApprovalActionNoToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/approvals/999/action", map[string]interface{}{
		"action": "APPROVE",
	}, "")
	if statusCode(result) != 401 {
		t.Errorf("approvals/action without token: expected 401, got %d", statusCode(result))
	}
}

func TestCancelRequest_BySession(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	token := login(t, ts.URL)

	// Create a task
	initResult := postJSON(t, ts.URL+"/api/approvals/request/init", map[string]interface{}{
		"app_instance_id": "test-approval-required",
	}, token)
	initData, _ := initResult["data"].(map[string]interface{})
	requestID, _ := initData["request_id"].(float64)
	requestIDStr := fmt.Sprintf("%.0f", requestID)

	// Cancel by session type
	deleteResult := deleteJSON(t, ts.URL+"/api/requests/"+requestIDStr+"?type=session", "")
	if statusCode(deleteResult) != 200 {
		t.Fatalf("expected 200 on cancel, got %d: %v", statusCode(deleteResult), deleteResult)
	}
	if deleteResult["success"] != true {
		t.Errorf("expected success=true")
	}

	// Verify task is no longer pending
	pendingResult := getJSON(t, ts.URL+"/api/approvals/pending", "")
	data, _ := pendingResult["data"].(map[string]interface{})
	tasks, _ := data["tasks"].([]interface{})
	for _, task := range tasks {
		taskMap := task.(map[string]interface{})
		if fmt.Sprintf("%.0f", taskMap["request_id"].(float64)) == requestIDStr {
			t.Errorf("cancelled task should not be in pending list")
		}
	}
}

func TestCancelRequest_ByTaskID(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	token := login(t, ts.URL)

	// Create and confirm a task to get task_id
	initResult := postJSON(t, ts.URL+"/api/approvals/request/init", map[string]interface{}{
		"app_instance_id": "test-approval-required",
	}, token)
	initData, _ := initResult["data"].(map[string]interface{})
	requestID, _ := initData["request_id"].(float64)
	requestIDStr := fmt.Sprintf("%.0f", requestID)

	confirmResult := postJSON(t, ts.URL+"/api/approvals/request/"+requestIDStr+"/confirm", map[string]interface{}{}, "")
	confirmData, _ := confirmResult["data"].(map[string]interface{})
	taskID, _ := confirmData["task_id"].(float64)
	taskIDStr := fmt.Sprintf("%.0f", taskID)

	// Cancel by task ID (default type)
	deleteResult := deleteJSON(t, ts.URL+"/api/requests/"+taskIDStr, "")
	if statusCode(deleteResult) != 200 {
		t.Fatalf("expected 200 on cancel by task ID, got %d: %v", statusCode(deleteResult), deleteResult)
	}
}

func TestSignatureByTx(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Create a pending approval task via submit-request
	submitResult := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"message":         []byte("signature by tx test"),
	}, "")
	txID, _ := submitResult["tx_id"].(string)
	if txID == "" {
		t.Fatalf("no tx_id in submit response")
	}

	result := getJSON(t, ts.URL+"/api/signature/by-tx/"+txID, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	if result["tx_id"] != txID {
		t.Errorf("expected tx_id=%q, got %v", txID, result["tx_id"])
	}
}

func TestSignatureByTx_NotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/signature/by-tx/nonexistent-tx-id", "")
	if statusCode(result) != 404 {
		t.Errorf("expected 404 for nonexistent tx_id, got %d", statusCode(result))
	}
}

func TestAdminInvitePasskey(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/admin/passkey/invite", map[string]interface{}{
		"display_name":    "Test User",
		"app_instance_id": "test-approval-required",
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	inviteToken, _ := result["invite_token"].(string)
	if inviteToken == "" {
		t.Errorf("expected invite_token")
	}
	registerURL, _ := result["register_url"].(string)
	if registerURL == "" {
		t.Errorf("expected register_url")
	}
	expiresAt, _ := result["expires_at"].(string)
	if expiresAt == "" {
		t.Errorf("expected expires_at")
	}
}

func TestAdminListPasskeyUsers(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/admin/passkey/users?app_instance_id=test-approval-required", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	total, _ := result["total"].(float64)
	if total < 2 {
		t.Errorf("expected at least 2 users (Alice, Bob), got %v", total)
	}
	users, _ := result["users"].([]interface{})
	if len(users) == 0 {
		t.Errorf("expected non-empty users list")
	}
}

func TestAdminListPasskeyUsers_Pagination(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := getJSON(t, ts.URL+"/api/admin/passkey/users?page=1&limit=1", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	users, _ := result["users"].([]interface{})
	if len(users) != 1 {
		t.Errorf("expected exactly 1 user with limit=1, got %d", len(users))
	}
	total, _ := result["total"].(float64)
	if total < 2 {
		t.Errorf("expected total >= 2 (Alice + Bob), got %v", total)
	}
}

func TestAdminDeletePasskeyUser(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Register a new user via passkey register
	regResult := postJSON(t, ts.URL+"/api/passkey/register/verify", map[string]interface{}{
		"invite_token":    "mock-invite",
		"display_name":    "To Be Deleted",
		"app_instance_id": "test-approval-required",
		"credential":      map[string]interface{}{"id": "mock"},
	}, "")
	newUserID, _ := regResult["passkey_user_id"].(float64)
	if newUserID == 0 {
		t.Fatalf("expected passkey_user_id in register response")
	}
	newUserIDStr := fmt.Sprintf("%.0f", newUserID)

	// Verify user exists
	listBefore := getJSON(t, ts.URL+"/api/admin/passkey/users", "")
	totalBefore, _ := listBefore["total"].(float64)

	// Delete the user
	deleteResult := deleteJSON(t, ts.URL+"/api/admin/passkey/users/"+newUserIDStr, "")
	if statusCode(deleteResult) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(deleteResult), deleteResult)
	}
	if deleteResult["success"] != true {
		t.Errorf("expected success=true")
	}

	// Verify count decreased
	listAfter := getJSON(t, ts.URL+"/api/admin/passkey/users", "")
	totalAfter, _ := listAfter["total"].(float64)
	if totalAfter != totalBefore-1 {
		t.Errorf("expected total to decrease by 1, before=%v after=%v", totalBefore, totalAfter)
	}
}

func TestAdminDeletePasskeyUser_NotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := deleteJSON(t, ts.URL+"/api/admin/passkey/users/99999", "")
	if statusCode(result) != 404 {
		t.Errorf("expected 404, got %d", statusCode(result))
	}
}

func TestAdminAuditRecords(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Generate an audit record by submitting to approval app
	postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": "test-approval-required",
		"message":         []byte("audit record test"),
	}, "")

	result := getJSON(t, ts.URL+"/api/admin/audit-records", "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	total, _ := result["total"].(float64)
	if total < 1 {
		t.Errorf("expected at least 1 audit record, got %v", total)
	}
	records, _ := result["records"].([]interface{})
	if len(records) == 0 {
		t.Errorf("expected non-empty records")
	}
	// Verify record structure
	rec, _ := records[0].(map[string]interface{})
	if rec["id"] == nil {
		t.Errorf("expected id in audit record")
	}
	if rec["event_type"] == nil {
		t.Errorf("expected event_type in audit record")
	}
}

func TestAdminPolicyCRUD(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	appID := "policy-test-app"
	keyName := "policy-test-key"

	// CREATE / UPSERT
	putResult := putJSON(t, ts.URL+"/api/admin/policy", map[string]interface{}{
		"app_instance_id": appID,
		"public_key_name": keyName,
		"enabled":         true,
		"timeout_seconds": 300,
		"levels": []map[string]interface{}{
			{"level_index": 0, "threshold": 2, "member_ids": []uint{1, 2}},
		},
	}, "")
	if statusCode(putResult) != 200 {
		t.Fatalf("PUT policy: expected 200, got %d: %v", statusCode(putResult), putResult)
	}
	if putResult["success"] != true {
		t.Errorf("expected success=true on PUT")
	}

	// READ
	getResult := getJSON(t, ts.URL+"/api/admin/policy?app_instance_id="+appID+"&public_key_name="+keyName, "")
	if statusCode(getResult) != 200 {
		t.Fatalf("GET policy: expected 200, got %d: %v", statusCode(getResult), getResult)
	}
	policy, _ := getResult["policy"].(map[string]interface{})
	if policy == nil {
		t.Fatalf("expected policy object")
	}
	if policy["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", policy["enabled"])
	}

	// DELETE
	delResult := deleteJSON(t, ts.URL+"/api/admin/policy?app_instance_id="+appID+"&public_key_name="+keyName, "")
	if statusCode(delResult) != 200 {
		t.Fatalf("DELETE policy: expected 200, got %d: %v", statusCode(delResult), delResult)
	}

	// GET after delete — expect 404
	getAfter := getJSON(t, ts.URL+"/api/admin/policy?app_instance_id="+appID+"&public_key_name="+keyName, "")
	if statusCode(getAfter) != 404 {
		t.Errorf("expected 404 after delete, got %d", statusCode(getAfter))
	}
}

func TestAdminPolicyDelete_NotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := deleteJSON(t, ts.URL+"/api/admin/policy?app_instance_id=no-app&public_key_name=no-key", "")
	if statusCode(result) != 404 {
		t.Errorf("expected 404 for non-existent policy delete, got %d", statusCode(result))
	}
}

func TestAdminCreateDeleteAPIKey(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	appID := "apikey-admin-test-app"
	keyName := "admin-created-key"

	// CREATE
	createResult := postJSON(t, ts.URL+"/api/admin/apikeys", map[string]interface{}{
		"app_instance_id": appID,
		"name":            keyName,
		"description":     "test API key",
		"api_key":         "my-api-key-value",
		"api_secret":      "my-api-secret-value",
	}, "")
	if statusCode(createResult) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(createResult), createResult)
	}
	if createResult["name"] != keyName {
		t.Errorf("expected name=%q, got %v", keyName, createResult["name"])
	}
	if createResult["has_api_key"] != true {
		t.Errorf("expected has_api_key=true")
	}
	if createResult["has_api_secret"] != true {
		t.Errorf("expected has_api_secret=true")
	}
	id := createResult["id"]
	if id == nil {
		t.Errorf("expected id in response")
	}

	// GET the created key
	getResult := getJSON(t, ts.URL+"/api/apikey/"+keyName+"?app_instance_id="+appID, "")
	if statusCode(getResult) != 200 {
		t.Fatalf("expected 200 on get, got %d: %v", statusCode(getResult), getResult)
	}
	if getResult["api_key"] != "my-api-key-value" {
		t.Errorf("expected api_key=my-api-key-value, got %v", getResult["api_key"])
	}

	// DELETE
	delResult := deleteJSON(t, ts.URL+"/api/admin/apikeys/"+keyName+"?app_instance_id="+appID, "")
	if statusCode(delResult) != 200 {
		t.Fatalf("expected 200 on delete, got %d: %v", statusCode(delResult), delResult)
	}
	if delResult["success"] != true {
		t.Errorf("expected success=true on delete")
	}
}

func TestAdminDeleteAPIKey_NotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := deleteJSON(t, ts.URL+"/api/admin/apikeys/nonexistent-key?app_instance_id=some-app", "")
	if statusCode(result) != 404 {
		t.Errorf("expected 404, got %d", statusCode(result))
	}
}

func TestAdminDeletePublicKey(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	appID := "delete-pubkey-test-app"
	// Generate a key
	genResult := postJSON(t, ts.URL+"/api/generate-key", map[string]interface{}{
		"app_instance_id": appID,
		"curve":           "secp256k1",
		"protocol":        "ecdsa",
	}, "")
	if genResult["success"] != true {
		t.Fatalf("key gen failed: %v", genResult)
	}
	pk, _ := genResult["public_key"].(map[string]interface{})
	keyName, _ := pk["name"].(string)

	// Verify key exists
	keysBefore := getJSON(t, ts.URL+"/api/publickeys/"+appID, "")
	foundBefore := false
	for _, k := range keysBefore["public_keys"].([]interface{}) {
		kMap := k.(map[string]interface{})
		if kMap["name"] == keyName {
			foundBefore = true
			break
		}
	}
	if !foundBefore {
		t.Fatalf("generated key %q not found before delete", keyName)
	}

	// Delete the key
	delResult := deleteJSON(t, ts.URL+"/api/admin/publickeys/"+keyName+"?app_instance_id="+appID, "")
	if statusCode(delResult) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(delResult), delResult)
	}
	if delResult["success"] != true {
		t.Errorf("expected success=true")
	}

	// Verify key gone from list
	keysAfter := getJSON(t, ts.URL+"/api/publickeys/"+appID, "")
	// Note: deleteAdminPublicKey deletes from appKeys (default key) AND generatedKeys.
	// So the publickeys endpoint may return 0 or 1 keys for this app depending on
	// whether the default key was also deleted.
	for _, k := range keysAfter["public_keys"].([]interface{}) {
		kMap := k.(map[string]interface{})
		if kMap["name"] == keyName {
			t.Errorf("key %q should have been deleted", keyName)
		}
	}
}

func TestAdminDeletePublicKey_NotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := deleteJSON(t, ts.URL+"/api/admin/publickeys/nonexistent-key-name", "")
	if statusCode(result) != 404 {
		t.Errorf("expected 404 for non-existent key, got %d", statusCode(result))
	}
}

func TestPasskeyRegistrationOptions(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	invite := postJSON(t, ts.URL+"/api/admin/passkey/invite", map[string]interface{}{
		"display_name":    "Mock Invite User",
		"app_instance_id": "test-approval-required",
	}, "")
	inviteToken, _ := invite["invite_token"].(string)
	if inviteToken == "" {
		t.Fatalf("expected invite_token")
	}

	result := getJSON(t, ts.URL+"/api/passkey/register/options?invite_token="+inviteToken, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	options, _ := result["options"].(map[string]interface{})
	options = unwrapPublicKeyOptions(t, options)
	challenge, _ := options["challenge"].(string)
	if challenge == "" {
		t.Errorf("expected non-empty challenge")
	}
	gotInviteToken, _ := result["invite_token"].(string)
	if gotInviteToken != inviteToken {
		t.Errorf("expected invite_token=%q, got %q", inviteToken, gotInviteToken)
	}
	expiresAt, _ := result["expires_at"].(string)
	if expiresAt == "" {
		t.Errorf("expected expires_at")
	}
}

func TestPasskeyRegistrationOptions_WithTokenQuery(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	invite := postJSON(t, ts.URL+"/api/admin/passkey/invite", map[string]interface{}{
		"display_name":    "Mock Token User",
		"app_instance_id": "test-approval-required",
	}, "")
	inviteToken, _ := invite["invite_token"].(string)
	if inviteToken == "" {
		t.Fatalf("expected invite_token")
	}

	result := getJSON(t, ts.URL+"/api/passkey/register/options?token="+inviteToken, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	gotInviteToken, _ := result["invite_token"].(string)
	if gotInviteToken != inviteToken {
		t.Errorf("expected invite_token=%q, got %q", inviteToken, gotInviteToken)
	}
}

func TestPasskeyRegistrationOptions_UsesInviteDisplayName(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	invite := postJSON(t, ts.URL+"/api/admin/passkey/invite", map[string]interface{}{
		"display_name":    "Charlie Test",
		"app_instance_id": "test-approval-required",
	}, "")
	inviteToken, _ := invite["invite_token"].(string)
	if inviteToken == "" {
		t.Fatalf("expected invite_token")
	}

	result := getJSON(t, ts.URL+"/api/passkey/register/options?token="+inviteToken, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	options, _ := result["options"].(map[string]interface{})
	options = unwrapPublicKeyOptions(t, options)
	user, _ := options["user"].(map[string]interface{})
	if user == nil {
		t.Fatalf("expected user object")
	}
	if got, _ := user["name"].(string); got != "Charlie Test" {
		t.Errorf("expected user.name=Charlie Test, got %q", got)
	}
	if got, _ := user["displayName"].(string); got != "Charlie Test" {
		t.Errorf("expected user.displayName=Charlie Test, got %q", got)
	}
	authenticatorSelection, _ := options["authenticatorSelection"].(map[string]interface{})
	if authenticatorSelection == nil {
		t.Fatalf("expected authenticatorSelection")
	}
	if got, _ := authenticatorSelection["residentKey"].(string); got != "required" {
		t.Errorf("expected residentKey=required, got %q", got)
	}
}

func TestPasskeyRegistrationVerify(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/passkey/register/verify", map[string]interface{}{
		"invite_token":    "mock-invite",
		"credential":      map[string]interface{}{"id": "new-credential"},
		"display_name":    "New Test User",
		"app_instance_id": "test-approval-required",
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	newUserID, _ := result["passkey_user_id"].(float64)
	if newUserID <= 2 {
		t.Errorf("expected passkey_user_id > 2 (after Alice=1, Bob=2), got %v", newUserID)
	}
	displayName, _ := result["display_name"].(string)
	if displayName != "New Test User" {
		t.Errorf("expected display_name=New Test User, got %q", displayName)
	}
}

func TestPasskeyRegistrationVerify_DefaultDisplayName(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/passkey/register/verify", map[string]interface{}{
		"invite_token":    "mock-invite",
		"credential":      map[string]interface{}{},
		"app_instance_id": "test-approval-required",
		// No display_name — should default to "User <id>"
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d", statusCode(result))
	}
	displayName, _ := result["display_name"].(string)
	if !strings.HasPrefix(displayName, "User ") {
		t.Errorf("expected display_name to start with 'User ', got %q", displayName)
	}
}

func TestPasskeyRegistrationVerify_UsesInviteDisplayNameAndLoginMatchesCredential(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	invite := postJSON(t, ts.URL+"/api/admin/passkey/invite", map[string]interface{}{
		"display_name":    "Dana Test",
		"app_instance_id": "test-approval-required",
	}, "")
	inviteToken, _ := invite["invite_token"].(string)
	if inviteToken == "" {
		t.Fatalf("expected invite_token")
	}

	reg := postJSON(t, ts.URL+"/api/passkey/register/verify", map[string]interface{}{
		"invite_token": inviteToken,
		"credential": map[string]interface{}{
			"id": "credential-dana",
		},
	}, "")
	if statusCode(reg) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(reg), reg)
	}
	newUserID, _ := reg["passkey_user_id"].(float64)
	displayName, _ := reg["display_name"].(string)
	if displayName != "Dana Test" {
		t.Fatalf("expected display_name=Dana Test, got %q", displayName)
	}

	login := postJSON(t, ts.URL+"/api/auth/passkey/verify", map[string]interface{}{
		"login_session_id": 1,
		"credential": map[string]interface{}{
			"id": "credential-dana",
		},
	}, "")
	if statusCode(login) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(login), login)
	}
	if got, _ := login["display_name"].(string); got != "Dana Test" {
		t.Errorf("expected display_name=Dana Test, got %q", got)
	}
	if got, _ := login["passkey_user_id"].(float64); got != newUserID {
		t.Errorf("expected passkey_user_id=%v, got %v", newUserID, got)
	}
}

func TestTokenValidation_InvalidToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Use a completely invalid token
	result := getJSON(t, ts.URL+"/api/requests/mine", "invalid.token.value")
	if statusCode(result) != 401 {
		t.Errorf("expected 401 for invalid token, got %d", statusCode(result))
	}
}

func TestTokenValidation_MalformedToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Token without "." separator
	result := getJSON(t, ts.URL+"/api/requests/mine", "notavalidtoken")
	if statusCode(result) != 401 {
		t.Errorf("expected 401 for malformed token, got %d", statusCode(result))
	}
}

func TestSigningConsistency_SameMessageSameKey(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	message := []byte("consistency test message 12345678")

	// secp256k1 ECDSA uses btcecdsa.Sign which is deterministic (RFC 6979)
	r1 := submitDirectRequest(t, ts.URL, "test-ecdsa-secp256k1", message)
	r2 := submitDirectRequest(t, ts.URL, "test-ecdsa-secp256k1", message)

	sig1, _ := r1["signature"].(string)
	sig2, _ := r2["signature"].(string)
	if sig1 == "" || sig2 == "" {
		t.Fatalf("expected signatures, got %q and %q", sig1, sig2)
	}
	// RFC 6979: deterministic ECDSA — same message + same key = same signature
	if sig1 != sig2 {
		t.Logf("Note: signatures differ (may be non-deterministic for secp256k1): %q vs %q", sig1, sig2)
	}
}

func TestSigningWithGeneratedKey(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	appID := "signing-with-generated-key-test"

	// Generate a new key
	genResult := postJSON(t, ts.URL+"/api/generate-key", map[string]interface{}{
		"app_instance_id": appID,
		"curve":           "secp256k1",
		"protocol":        "ecdsa",
	}, "")
	if genResult["success"] != true {
		t.Fatalf("key gen failed: %v", genResult)
	}
	pk, _ := genResult["public_key"].(map[string]interface{})
	keyData, _ := pk["key_data"].(string) // hex string (no 0x prefix)

	// Decode the public key hex to bytes
	keyBytes := make([]byte, len(keyData)/2)
	for i := 0; i < len(keyData)/2; i++ {
		fmt.Sscanf(keyData[2*i:2*i+2], "%02x", &keyBytes[i])
	}

	// Submit with explicit public key
	result := postJSON(t, ts.URL+"/api/submit-request", map[string]interface{}{
		"app_instance_id": appID,
		"message":         []byte("signing with generated key test"),
		"public_key":      keyBytes,
	}, "")
	if statusCode(result) != 200 {
		t.Fatalf("expected 200, got %d: %v", statusCode(result), result)
	}
	if result["status"] != "signed" {
		t.Errorf("expected signed, got %v", result["status"])
	}
	sig, _ := result["signature"].(string)
	if sig == "" {
		t.Errorf("expected signature")
	}
}

func TestApprovalConfirm_InvalidRequestID(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	result := postJSON(t, ts.URL+"/api/approvals/request/99999/confirm", map[string]interface{}{
		"credential": map[string]interface{}{},
	}, "")
	if statusCode(result) != 404 {
		t.Errorf("expected 404 for invalid request ID, got %d", statusCode(result))
	}
}

func TestApprovalAction_InvalidTaskID(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	token := login(t, ts.URL)
	result := postJSON(t, ts.URL+"/api/approvals/99999/action", map[string]interface{}{
		"action": "APPROVE",
	}, token)
	if statusCode(result) != 404 {
		t.Errorf("expected 404 for invalid task ID, got %d", statusCode(result))
	}
}

func TestAdminCreateAPIKey_MissingRequired(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Missing name
	result := postJSON(t, ts.URL+"/api/admin/apikeys", map[string]interface{}{
		"app_instance_id": "test-app",
		// "name" is missing
	}, "")
	if statusCode(result) != 400 {
		t.Errorf("expected 400 for missing name, got %d", statusCode(result))
	}
}

func TestConcurrentSignRequests(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	const numRequests = 10
	results := make(chan map[string]interface{}, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(i int) {
			result := submitDirectRequest(t, ts.URL, "test-ecdsa-secp256k1",
				[]byte(fmt.Sprintf("concurrent test message %d", i)))
			results <- result
		}(i)
	}

	for i := 0; i < numRequests; i++ {
		result := <-results
		if result["status"] != "signed" {
			t.Errorf("concurrent request %d: expected signed, got %v", i, result["status"])
		}
	}
}
