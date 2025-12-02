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
	AppID       string `json:"app_id"`
	Message     []byte `json:"message"`      // Raw message bytes (JSON auto-encodes to base64)
	RequestorID string `json:"requestor_id"`
	CallbackURL string `json:"callback_url,omitempty"`
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
func (c *HTTPClient) SubmitRequest(appID string, message []byte, requestorID, callbackURL string) (*submitRequestResponse, error) {
	payload := submitRequestPayload{
		AppID:       appID,
		Message:     message,
		RequestorID: requestorID,
		CallbackURL: callbackURL,
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
