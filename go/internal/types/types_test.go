// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
// -----------------------------------------------------------------------------

package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClientOptions_Defaults(t *testing.T) {
	opts := ClientOptions{}

	// Zero values should be defaults
	if opts.RequestTimeout != 0 {
		t.Errorf("Expected zero RequestTimeout, got %v", opts.RequestTimeout)
	}
	if opts.CallbackTimeout != 0 {
		t.Errorf("Expected zero CallbackTimeout, got %v", opts.CallbackTimeout)
	}
}

func TestClientOptions_CustomValues(t *testing.T) {
	opts := ClientOptions{
		RequestTimeout:  45 * time.Second,
		CallbackTimeout: 120 * time.Second,
	}

	if opts.RequestTimeout != 45*time.Second {
		t.Errorf("Expected RequestTimeout 45s, got %v", opts.RequestTimeout)
	}
	if opts.CallbackTimeout != 120*time.Second {
		t.Errorf("Expected CallbackTimeout 120s, got %v", opts.CallbackTimeout)
	}
}

func TestSignResult_Success(t *testing.T) {
	result := SignResult{
		Signature: []byte{0x01, 0x02, 0x03},
		Success:   true,
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if len(result.Signature) != 3 {
		t.Errorf("Expected signature length 3, got %d", len(result.Signature))
	}
	if result.Error != "" {
		t.Errorf("Expected empty error, got %s", result.Error)
	}
}

func TestSignResult_Error(t *testing.T) {
	result := SignResult{
		Success: false,
		Error:   "signing failed",
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}
	if result.Error != "signing failed" {
		t.Errorf("Expected error 'signing failed', got %s", result.Error)
	}
	if result.Signature != nil {
		t.Error("Expected nil signature")
	}
}

func TestSignResult_WithVotingInfo(t *testing.T) {
	result := SignResult{
		Success: true,
		Signature: []byte{0x01, 0x02},
		VotingInfo: &VotingInfo{
			NeedsVoting:   true,
			CurrentVotes:  2,
			RequiredVotes: 3,
			Status:        "signed",
			Hash:          "0xabc123",
		},
	}

	if result.VotingInfo == nil {
		t.Fatal("Expected non-nil VotingInfo")
	}
	if !result.VotingInfo.NeedsVoting {
		t.Error("Expected NeedsVoting to be true")
	}
	if result.VotingInfo.CurrentVotes != 2 {
		t.Errorf("Expected CurrentVotes 2, got %d", result.VotingInfo.CurrentVotes)
	}
	if result.VotingInfo.RequiredVotes != 3 {
		t.Errorf("Expected RequiredVotes 3, got %d", result.VotingInfo.RequiredVotes)
	}
	if result.VotingInfo.Status != "signed" {
		t.Errorf("Expected Status 'signed', got %s", result.VotingInfo.Status)
	}
}

func TestSignResult_JSONSerialization(t *testing.T) {
	original := SignResult{
		Signature: []byte{0xab, 0xcd},
		Success:   true,
		VotingInfo: &VotingInfo{
			NeedsVoting:   true,
			CurrentVotes:  2,
			RequiredVotes: 3,
			Status:        "pending",
			Hash:          "0x1234",
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal back
	var restored SignResult
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if restored.Success != original.Success {
		t.Error("Success field mismatch")
	}
	if string(restored.Signature) != string(original.Signature) {
		t.Error("Signature mismatch")
	}
	if restored.VotingInfo == nil {
		t.Fatal("VotingInfo is nil after unmarshal")
	}
	if restored.VotingInfo.Status != original.VotingInfo.Status {
		t.Error("VotingInfo.Status mismatch")
	}
}

func TestVotingInfo_States(t *testing.T) {
	states := []string{"pending", "signed", "error"}

	for _, state := range states {
		vi := VotingInfo{
			NeedsVoting: true,
			Status:      state,
		}
		if vi.Status != state {
			t.Errorf("Expected status %s, got %s", state, vi.Status)
		}
	}
}

func TestGenerateKeyResult_Success(t *testing.T) {
	result := GenerateKeyResult{
		Success: true,
		Message: "Key generated successfully",
		PublicKey: &PublicKeyInfo{
			ID:                  1,
			Name:                "my-key",
			KeyData:             "0xabcdef123456",
			Curve:               "secp256k1",
			Protocol:            "schnorr",
			Threshold:           2,
			ParticipantCount:    3,
			MaxParticipantCount: 5,
			ApplicationID:       100,
			CreatedByInstanceID: "app-instance-123",
		},
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.PublicKey == nil {
		t.Fatal("Expected non-nil PublicKey")
	}
	if result.PublicKey.ID != 1 {
		t.Errorf("Expected ID 1, got %d", result.PublicKey.ID)
	}
	if result.PublicKey.Name != "my-key" {
		t.Errorf("Expected Name 'my-key', got %s", result.PublicKey.Name)
	}
	if result.PublicKey.Curve != "secp256k1" {
		t.Errorf("Expected Curve 'secp256k1', got %s", result.PublicKey.Curve)
	}
	if result.PublicKey.Protocol != "schnorr" {
		t.Errorf("Expected Protocol 'schnorr', got %s", result.PublicKey.Protocol)
	}
}

func TestGenerateKeyResult_Error(t *testing.T) {
	result := GenerateKeyResult{
		Success:   false,
		Message:   "Key generation failed: invalid curve",
		PublicKey: nil,
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}
	if result.PublicKey != nil {
		t.Error("Expected nil PublicKey on error")
	}
}

func TestGenerateKeyOptions(t *testing.T) {
	opts := GenerateKeyOptions{
		Name:     "test-key",
		Curve:    "ed25519",
		Protocol: "schnorr",
	}

	if opts.Name != "test-key" {
		t.Errorf("Expected Name 'test-key', got %s", opts.Name)
	}
	if opts.Curve != "ed25519" {
		t.Errorf("Expected Curve 'ed25519', got %s", opts.Curve)
	}
	if opts.Protocol != "schnorr" {
		t.Errorf("Expected Protocol 'schnorr', got %s", opts.Protocol)
	}
}

func TestAPIKeyResult_Success(t *testing.T) {
	result := APIKeyResult{
		Success:       true,
		AppInstanceID: "app-123",
		Name:          "my-api-key",
		APIKey:        "secret-key-value",
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.APIKey != "secret-key-value" {
		t.Errorf("Expected APIKey 'secret-key-value', got %s", result.APIKey)
	}
	if result.Error != "" {
		t.Errorf("Expected empty error, got %s", result.Error)
	}
}

func TestAPIKeyResult_Error(t *testing.T) {
	result := APIKeyResult{
		Success:       false,
		Error:         "API key not found",
		AppInstanceID: "app-123",
		Name:          "nonexistent-key",
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}
	if result.Error != "API key not found" {
		t.Errorf("Expected error 'API key not found', got %s", result.Error)
	}
	if result.APIKey != "" {
		t.Errorf("Expected empty APIKey, got %s", result.APIKey)
	}
}

func TestAPISignResult_Success(t *testing.T) {
	result := APISignResult{
		Success:       true,
		AppInstanceID: "app-123",
		Name:          "my-secret",
		Signature:     "abcdef123456",
		SignatureHex:  "abcdef123456",
		Algorithm:     "HMAC-SHA256",
		MessageLength: 32,
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.Algorithm != "HMAC-SHA256" {
		t.Errorf("Expected Algorithm 'HMAC-SHA256', got %s", result.Algorithm)
	}
	if result.MessageLength != 32 {
		t.Errorf("Expected MessageLength 32, got %d", result.MessageLength)
	}
	if result.Signature != result.SignatureHex {
		t.Error("Expected Signature and SignatureHex to match")
	}
}

func TestAPISignResult_Error(t *testing.T) {
	result := APISignResult{
		Success: false,
		Error:   "Secret not found",
		Name:    "nonexistent-secret",
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}
	if result.Error != "Secret not found" {
		t.Errorf("Expected error 'Secret not found', got %s", result.Error)
	}
	if result.Signature != "" {
		t.Errorf("Expected empty Signature, got %s", result.Signature)
	}
}

func TestPublicKeyInfo_JSONTags(t *testing.T) {
	info := PublicKeyInfo{
		ID:                  123,
		Name:                "test-key",
		KeyData:             "0x123abc",
		Curve:               "secp256k1",
		Protocol:            "ecdsa",
		Threshold:           2,
		ParticipantCount:    3,
		MaxParticipantCount: 5,
		ApplicationID:       456,
		CreatedByInstanceID: "instance-789",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Check that JSON contains expected keys
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	expectedKeys := []string{
		"id", "name", "key_data", "curve", "protocol",
		"threshold", "participant_count", "max_participant_count",
		"application_id", "created_by_instance_id",
	}

	for _, key := range expectedKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("Expected JSON key '%s' not found", key)
		}
	}
}

func TestVotingInfo_JSONOmitEmpty(t *testing.T) {
	// Test that empty VotingInfo doesn't produce unnecessary fields
	vi := VotingInfo{
		NeedsVoting: false,
		Status:      "pending",
	}

	data, err := json.Marshal(vi)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	// These fields should still be present as they don't have omitempty
	if _, ok := m["needs_voting"]; !ok {
		t.Error("Expected 'needs_voting' field")
	}
	if _, ok := m["status"]; !ok {
		t.Error("Expected 'status' field")
	}
}
