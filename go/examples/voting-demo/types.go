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

package main

import sdk "github.com/TEENet-io/teenet-sdk/go"

// ConfigResponse contains the configuration for the current app instance
type ConfigResponse struct {
	AppInstanceID string `json:"app_instance_id"`
	ConsensusURL  string `json:"consensus_url"`
}

// SignRequest is the request payload for direct signing (without voting)
type SignRequest struct {
	Message string `json:"message" binding:"required"`
}

// SignResponse is the response after direct signing
type SignResponse struct {
	Success       bool   `json:"success"`
	AppInstanceID string `json:"app_instance_id,omitempty"`
	Message       string `json:"message,omitempty"`
	Signature     string `json:"signature,omitempty"` // Hex-encoded signature
	Error         string `json:"error,omitempty"`
}

// VoteRequest is the request payload for submitting a vote
type VoteRequest struct {
	Message string `json:"message" binding:"required"`
}

// VoteResponse is the response after submitting a vote
type VoteResponse struct {
	Success       bool            `json:"success"`
	AppInstanceID string          `json:"app_instance_id,omitempty"`
	Message       string          `json:"message,omitempty"`
	VotingInfo    *sdk.VotingInfo `json:"voting_info,omitempty"`
	Signature     string          `json:"signature,omitempty"` // Hex-encoded signature
	Error         string          `json:"error,omitempty"`
}

// HealthResponse for health check endpoint
type HealthResponse struct {
	Status        string `json:"status"`
	Service       string `json:"service"`
	AppInstanceID string `json:"app_instance_id"`
}

// VerifyRequest is the request payload for signature verification
type VerifyRequest struct {
	Message   string `json:"message" binding:"required"`
	Signature string `json:"signature" binding:"required"` // Hex-encoded signature
}

// VerifyResponse is the response after signature verification
type VerifyResponse struct {
	Success   bool   `json:"success"`
	Valid     bool   `json:"valid,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Curve     string `json:"curve,omitempty"`
	Error     string `json:"error,omitempty"`
}

// GetAPIKeyRequest is the request payload for retrieving an API key
type GetAPIKeyRequest struct {
	Name string `json:"name" binding:"required"`
}

// GetAPIKeyResponse is the response after retrieving an API key
type GetAPIKeyResponse struct {
	Success bool   `json:"success"`
	Name    string `json:"name,omitempty"`
	APIKey  string `json:"api_key,omitempty"`
	Error   string `json:"error,omitempty"`
}

// SignWithSecretRequest is the request payload for signing with API secret
type SignWithSecretRequest struct {
	Name    string `json:"name" binding:"required"`
	Message string `json:"message" binding:"required"`
}

// SignWithSecretResponse is the response after signing with API secret
type SignWithSecretResponse struct {
	Success       bool   `json:"success"`
	Name          string `json:"name,omitempty"`
	Message       string `json:"message,omitempty"`
	Signature     string `json:"signature,omitempty"` // Hex-encoded signature
	Algorithm     string `json:"algorithm,omitempty"`
	MessageLength int    `json:"message_length,omitempty"`
	Error         string `json:"error,omitempty"`
}
