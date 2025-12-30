// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
// -----------------------------------------------------------------------------

package network

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestCallbackPayload_JSON(t *testing.T) {
	payload := CallbackPayload{
		Hash:      "0x1234",
		Status:    "signed",
		Signature: "abcdef",
		Error:     "",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var restored CallbackPayload
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if restored.Hash != payload.Hash {
		t.Errorf("Hash mismatch: got '%s', expected '%s'", restored.Hash, payload.Hash)
	}
	if restored.Status != payload.Status {
		t.Errorf("Status mismatch: got '%s', expected '%s'", restored.Status, payload.Status)
	}
	if restored.Signature != payload.Signature {
		t.Errorf("Signature mismatch: got '%s', expected '%s'", restored.Signature, payload.Signature)
	}
}

func TestCallbackPayload_WithError(t *testing.T) {
	payload := CallbackPayload{
		Hash:   "0x1234",
		Status: "error",
		Error:  "signing failed",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify error field is included
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	if _, ok := m["error"]; !ok {
		t.Error("Expected 'error' field in JSON")
	}
}

func TestNewCallbackServer(t *testing.T) {
	// Note: This test may fail if port 19080 is already in use
	cs, err := NewCallbackServer()
	if err != nil {
		t.Skipf("Could not create callback server (port may be in use): %v", err)
	}
	defer cs.Stop()

	if cs.port != DefaultCallbackPort {
		t.Errorf("Expected port %d, got %d", DefaultCallbackPort, cs.port)
	}
	if cs.listener == nil {
		t.Error("Expected listener to be non-nil")
	}
}

func TestCallbackServer_StartStop(t *testing.T) {
	cs, err := NewCallbackServer()
	if err != nil {
		t.Skipf("Could not create callback server: %v", err)
	}

	// Start server
	if err := cs.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Starting again should fail
	if err := cs.Start(); err == nil {
		t.Error("Expected error when starting already started server")
	}

	// Stop server
	if err := cs.Stop(); err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}

	// Stopping again should be safe
	if err := cs.Stop(); err != nil {
		t.Errorf("Second stop should not error: %v", err)
	}
}

func TestCallbackServer_RegisterUnregister(t *testing.T) {
	cs, err := NewCallbackServer()
	if err != nil {
		t.Skipf("Could not create callback server: %v", err)
	}
	defer cs.Stop()

	// Register a callback
	hash := "0xtest1234"
	ch := cs.RegisterCallback(hash)
	if ch == nil {
		t.Fatal("Expected non-nil channel")
	}

	// Verify it's stored
	if _, ok := cs.callbacks.Load(hash); !ok {
		t.Error("Expected callback to be stored")
	}

	// Unregister
	cs.UnregisterCallback(hash)

	// Verify it's removed
	if _, ok := cs.callbacks.Load(hash); ok {
		t.Error("Expected callback to be removed")
	}
}

func TestCallbackServer_HandleCallback(t *testing.T) {
	cs, err := NewCallbackServer()
	if err != nil {
		t.Skipf("Could not create callback server: %v", err)
	}

	if err := cs.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cs.Stop()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Register a callback
	hash := "test-hash-123"
	ch := cs.RegisterCallback(hash)

	// Send a callback request
	payload := CallbackPayload{
		Hash:      hash,
		Status:    "signed",
		Signature: "abcdef123456",
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(
		"http://localhost:19080/callback/"+hash,
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to send callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Wait for callback
	select {
	case received := <-ch:
		if received.Hash != hash {
			t.Errorf("Expected hash '%s', got '%s'", hash, received.Hash)
		}
		if received.Status != "signed" {
			t.Errorf("Expected status 'signed', got '%s'", received.Status)
		}
		if received.Signature != "abcdef123456" {
			t.Errorf("Expected signature 'abcdef123456', got '%s'", received.Signature)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for callback")
	}

	cs.UnregisterCallback(hash)
}

func TestCallbackServer_HandleCallback_MissingHash(t *testing.T) {
	cs, err := NewCallbackServer()
	if err != nil {
		t.Skipf("Could not create callback server: %v", err)
	}

	if err := cs.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cs.Stop()

	time.Sleep(50 * time.Millisecond)

	// Send callback with empty hash
	resp, err := http.Post(
		"http://localhost:19080/callback/",
		"application/json",
		bytes.NewReader([]byte("{}")),
	)
	if err != nil {
		t.Fatalf("Failed to send callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing hash, got %d", resp.StatusCode)
	}
}

func TestCallbackServer_HandleCallback_InvalidJSON(t *testing.T) {
	cs, err := NewCallbackServer()
	if err != nil {
		t.Skipf("Could not create callback server: %v", err)
	}

	if err := cs.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cs.Stop()

	time.Sleep(50 * time.Millisecond)

	// Send invalid JSON
	resp, err := http.Post(
		"http://localhost:19080/callback/test-hash",
		"application/json",
		bytes.NewReader([]byte("invalid json")),
	)
	if err != nil {
		t.Fatalf("Failed to send callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestCallbackServer_HandleCallback_UnregisteredHash(t *testing.T) {
	cs, err := NewCallbackServer()
	if err != nil {
		t.Skipf("Could not create callback server: %v", err)
	}

	if err := cs.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cs.Stop()

	time.Sleep(50 * time.Millisecond)

	// Send callback for unregistered hash - should still return 200
	payload := CallbackPayload{
		Hash:   "unregistered",
		Status: "signed",
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(
		"http://localhost:19080/callback/unregistered",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to send callback: %v", err)
	}
	defer resp.Body.Close()

	// Should return OK even for unregistered hash (logged as warning)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestCallbackServer_HandleCallback_ChannelFull(t *testing.T) {
	cs, err := NewCallbackServer()
	if err != nil {
		t.Skipf("Could not create callback server: %v", err)
	}

	if err := cs.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cs.Stop()

	time.Sleep(50 * time.Millisecond)

	// Register callback but don't read from it
	hash := "full-channel-test"
	ch := cs.RegisterCallback(hash)

	// Fill the channel (buffer size is 1)
	payload := CallbackPayload{Hash: hash, Status: "signed"}
	body, _ := json.Marshal(payload)

	// First request should succeed
	resp1, _ := http.Post("http://localhost:19080/callback/"+hash, "application/json", bytes.NewReader(body))
	resp1.Body.Close()

	// Second request should also succeed (but message is dropped)
	resp2, err := http.Post("http://localhost:19080/callback/"+hash, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to send second callback: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp2.StatusCode)
	}

	// Drain the channel
	<-ch
	cs.UnregisterCallback(hash)
}

func TestDefaultCallbackPort(t *testing.T) {
	if DefaultCallbackPort != 19080 {
		t.Errorf("Expected DefaultCallbackPort to be 19080, got %d", DefaultCallbackPort)
	}
}
