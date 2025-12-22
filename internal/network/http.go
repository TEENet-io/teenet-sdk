// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
//
// This software and its associated documentation files (the "Software") are
// the proprietary and confidential information of TEENet Technology (Hong Kong) Limited.
// Unauthorized copying of this file, via any medium, is strictly prohibited.
//
// No license, express or implied, is hereby granted, except by written agreement
// with TEENet Technology (Hong Kong) Limited. Use of this software without permission
// is a violation of applicable laws.
//
// -----------------------------------------------------------------------------

// Package network provides HTTP communication for TEENet SDK.
//
// This internal package handles HTTP requests to the consensus service.
package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// HTTPClient wraps HTTP operations for the SDK.
// This is exported so it can be used by the main SDK package.
type HTTPClient struct {
	baseURL string
	client  *http.Client
}

// NewHTTPClient creates a new HTTP client.
func NewHTTPClient(baseURL string, client *http.Client) *HTTPClient {
	return &HTTPClient{
		baseURL: baseURL,
		client:  client,
	}
}

// submitRequestPayload is the request body for submitting a signature request
type submitRequestPayload struct {
	AppInstanceID string `json:"app_instance_id"`
	Message       []byte `json:"message"`             // Raw message bytes (JSON auto-encodes to base64)
	PublicKey     []byte `json:"public_key,omitempty"` // Optional: raw public key bytes to use for signing
}

// submitRequestResponse is the response from submitting a signature request
type submitRequestResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	Hash          string `json:"hash"`           // Hash returned by server
	Status        string `json:"status"`         // pending/signed/failed
	Signature     string `json:"signature,omitempty"`
	CurrentVotes  int    `json:"current_votes,omitempty"`
	RequiredVotes int    `json:"required_votes,omitempty"`
	NeedsVoting   bool   `json:"needs_voting"`
}

// publicKeyResponse is the response from getting public key
type publicKeyResponse struct {
	Success   bool   `json:"success"`
	AppID     string `json:"app_id"`
	PublicKey string `json:"public_key"`
	Protocol  string `json:"protocol"`
	Curve     string `json:"curve"`
	Error     string `json:"error,omitempty"`
}

// SubmitRequest submits a signature request to the consensus module.
// publicKey is optional - pass nil to use the default key, or provide raw public key bytes to use a specific key.
func (c *HTTPClient) SubmitRequest(appID string, message []byte, publicKey []byte) (*submitRequestResponse, error) {
	payload := submitRequestPayload{
		AppInstanceID: appID,
		Message:       message,
		PublicKey:     publicKey,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := c.client.Post(
		c.baseURL+"/api/submit-request",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to submit request: %w", err)
	}
	defer resp.Body.Close()

	var result submitRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetPublicKey retrieves public key information for an App ID.
func (c *HTTPClient) GetPublicKey(appID string) (publicKey, protocol, curve string, err error) {
	resp, err := c.client.Get(c.baseURL + "/api/publickey/" + appID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get public key: %w", err)
	}
	defer resp.Body.Close()

	var result publicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.Success {
		return "", "", "", fmt.Errorf("failed to get public key: %s", result.Error)
	}

	return result.PublicKey, result.Protocol, result.Curve, nil
}

// generateKeyPayload is the request body for generating a key
type generateKeyPayload struct {
	AppInstanceID string `json:"app_instance_id"`
	Curve         string `json:"curve"`
	Protocol      string `json:"protocol"`
}

// generateKeyResponse is the response from generating a key
type generateKeyResponse struct {
	Success   bool                `json:"success"`
	Message   string              `json:"message"`
	PublicKey *GeneratedKeyInfo   `json:"public_key,omitempty"`
}

// GeneratedKeyInfo contains the public key information returned from key generation
type GeneratedKeyInfo struct {
	ID                  uint32 `json:"id"`
	Name                string `json:"name"`
	KeyData             string `json:"key_data"`
	Curve               string `json:"curve"`
	Protocol            string `json:"protocol"`
	Threshold           uint32 `json:"threshold,omitempty"`
	ParticipantCount    uint32 `json:"participant_count,omitempty"`
	MaxParticipantCount uint32 `json:"max_participant_count,omitempty"`
	ApplicationID       uint32 `json:"application_id"`
	CreatedByInstanceID string `json:"created_by_instance_id"`
}

// GenerateKey generates a new cryptographic key for an App ID.
func (c *HTTPClient) GenerateKey(appID, curve, protocol string) (*generateKeyResponse, error) {
	payload := generateKeyPayload{
		AppInstanceID: appID,
		Curve:         curve,
		Protocol:      protocol,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := c.client.Post(
		c.baseURL+"/api/generate-key",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer resp.Body.Close()

	var result generateKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// apiKeyResponse is the response from getting an API key
type apiKeyResponse struct {
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
	AppInstanceID string `json:"app_instance_id"`
	Name          string `json:"name"`
	APIKey        string `json:"api_key,omitempty"`
}

// GetAPIKey retrieves an API key value by name for an App ID.
func (c *HTTPClient) GetAPIKey(appID, name string) (*apiKeyResponse, error) {
	url := fmt.Sprintf("%s/api/apikey/%s?app_instance_id=%s", c.baseURL, name, appID)

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}
	defer resp.Body.Close()

	var result apiKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// signWithAPISecretPayload is the request body for signing with API secret
type signWithAPISecretPayload struct {
	AppInstanceID string `json:"app_instance_id"`
	Message       string `json:"message"` // Hex-encoded or plain text message
}

// apiSignResponse is the response from signing with API secret
type apiSignResponse struct {
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
	AppInstanceID string `json:"app_instance_id"`
	Name          string `json:"name"`
	Signature     string `json:"signature,omitempty"`
	SignatureHex  string `json:"signature_hex,omitempty"`
	Algorithm     string `json:"algorithm,omitempty"`
	MessageLength int    `json:"message_length"`
}

// SignWithAPISecret signs a message using an API secret stored in TEE.
func (c *HTTPClient) SignWithAPISecret(appID, name string, message []byte) (*apiSignResponse, error) {
	// Convert message to hex string for JSON transport
	messageHex := fmt.Sprintf("%x", message)

	payload := signWithAPISecretPayload{
		AppInstanceID: appID,
		Message:       messageHex,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/apikey/%s/sign", c.baseURL, name)
	resp, err := c.client.Post(
		url,
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with API secret: %w", err)
	}
	defer resp.Body.Close()

	var result apiSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}
