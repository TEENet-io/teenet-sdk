// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
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
	"net/url"
	"strconv"
	"strings"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
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
	Message       []byte `json:"message"`              // Raw message bytes (JSON auto-encodes to base64)
	PublicKey     []byte `json:"public_key,omitempty"` // Optional: raw public key bytes to use for signing
}

// submitRequestResponse is the response from submitting a signature request
type submitRequestResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	Hash          string `json:"hash"`   // Hash returned by server
	Status        string `json:"status"` // pending/pending_approval/signed/failed
	Signature     string `json:"signature,omitempty"`
	TxID          string `json:"tx_id,omitempty"`
	RequestID     uint64 `json:"request_id,omitempty"`
	CurrentVotes  int    `json:"current_votes,omitempty"`
	RequiredVotes int    `json:"required_votes,omitempty"`
	NeedsVoting   bool   `json:"needs_voting"`
	NeedsApproval bool   `json:"needs_approval,omitempty"`
}

// cacheDetailResponse is the response from fetching cache status for a hash
type cacheDetailResponse struct {
	Success bool        `json:"success"`
	Found   bool        `json:"found"`
	Entry   *cacheEntry `json:"entry,omitempty"`
	Message string      `json:"message,omitempty"`
}

type cacheEntry struct {
	Hash          string                   `json:"hash"`
	Status        string                   `json:"status"`
	Signature     string                   `json:"signature,omitempty"`
	RequiredVotes int                      `json:"required_votes"`
	Requests      map[string]*cacheRequest `json:"requests,omitempty"`
	ErrorMessage  string                   `json:"error_message,omitempty"`
}

type cacheRequest struct {
	Approved bool `json:"approved"`
}

// publicKeyResponse is the response from getting public key
type publicKeyResponse struct {
	ID       uint32 `json:"id"`
	Name     string `json:"name"`
	KeyData  string `json:"key_data"`
	Protocol string `json:"protocol"`
	Curve    string `json:"curve"`
}

type publicKeysResponse struct {
	Success    bool                `json:"success"`
	AppID      string              `json:"app_instance_id"`
	PublicKeys []publicKeyResponse `json:"public_keys"`
	Error      string              `json:"error,omitempty"`
}

// SubmitRequest submits a signature request to the consensus module.
// publicKey must be provided as raw key bytes.
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

// GetCacheDetail retrieves the cache entry for a specific hash.
func (c *HTTPClient) GetCacheDetail(hash string) (*cacheDetailResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/api/cache/" + hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache entry: %w", err)
	}
	defer resp.Body.Close()

	var result cacheDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetPublicKeys retrieves bound public key information for an App ID.
func (c *HTTPClient) GetPublicKeys(appID string) ([]publicKeyResponse, error) {
	resp, err := c.client.Get(c.baseURL + "/api/publickeys/" + appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}
	defer resp.Body.Close()

	var result publicKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("failed to get public keys: %s", result.Error)
	}

	return result.PublicKeys, nil
}

// generateKeyPayload is the request body for generating a key
type generateKeyPayload struct {
	AppInstanceID string `json:"app_instance_id"`
	Curve         string `json:"curve"`
	Protocol      string `json:"protocol"`
}

// generateKeyResponse is the response from generating a key
type generateKeyResponse struct {
	Success   bool              `json:"success"`
	Message   string            `json:"message"`
	PublicKey *GeneratedKeyInfo `json:"public_key,omitempty"`
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

// verifyWithAPISecretPayload is the request body for verifying with API secret
type verifyWithAPISecretPayload struct {
	AppInstanceID string `json:"app_instance_id"`
	Message       string `json:"message"`   // Hex-encoded or plain text message
	Signature     string `json:"signature"` // Hex-encoded signature
}

// apiVerifyResponse is the response from verifying with API secret
type apiVerifyResponse struct {
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
	AppInstanceID string `json:"app_instance_id"`
	Name          string `json:"name"`
	Valid         bool   `json:"valid"`
	Algorithm     string `json:"algorithm,omitempty"`
}

// VerifyWithAPISecret verifies an HMAC-SHA256 signature using an API secret stored in TEE.
func (c *HTTPClient) VerifyWithAPISecret(appID, name string, message, signature []byte) (*apiVerifyResponse, error) {
	// Convert to hex strings for JSON transport
	messageHex := fmt.Sprintf("%x", message)
	signatureHex := fmt.Sprintf("%x", signature)

	payload := verifyWithAPISecretPayload{
		AppInstanceID: appID,
		Message:       messageHex,
		Signature:     signatureHex,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/apikey/%s/verify", c.baseURL, name)
	resp, err := c.client.Post(
		url,
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify with API secret: %w", err)
	}
	defer resp.Body.Close()

	var result apiVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// approvalBridgeResponse is a generic parsed response from passkey approval endpoints.
type approvalBridgeResponse struct {
	StatusCode int
	Data       map[string]interface{}
}

func (c *HTTPClient) doApprovalRequest(method, path string, approvalToken string, payload []byte) (*approvalBridgeResponse, error) {
	urlStr := c.baseURL + path
	var body *bytes.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	} else {
		body = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("failed to build approval request: %w", err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if approvalToken != "" {
		req.Header.Set("Authorization", "Bearer "+approvalToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("approval request failed: %w", err)
	}
	defer resp.Body.Close()

	decoded := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("failed to decode approval response: %w", err)
	}

	return &approvalBridgeResponse{
		StatusCode: resp.StatusCode,
		Data:       decoded,
	}, nil
}

func (c *HTTPClient) doAuthRequest(method, path string, payload []byte) (*approvalBridgeResponse, error) {
	return c.doApprovalRequest(method, path, "", payload)
}

func (c *HTTPClient) PasskeyLoginOptions() (*approvalBridgeResponse, error) {
	return c.doAuthRequest(http.MethodGet, "/api/auth/passkey/options", nil)
}

func (c *HTTPClient) PasskeyLoginVerify(payload []byte) (*approvalBridgeResponse, error) {
	return c.doAuthRequest(http.MethodPost, "/api/auth/passkey/verify", payload)
}

func (c *HTTPClient) ApprovalPending(approvalToken string, filter *types.ApprovalPendingFilter) (*approvalBridgeResponse, error) {
	path := "/api/approvals/pending"
	if filter != nil {
		publicKeyName := strings.TrimSpace(filter.PublicKeyName)
		if publicKeyName != "" && filter.ApplicationID == 0 {
			return nil, fmt.Errorf("application_id is required when public_key_name is provided")
		}

		query := url.Values{}
		if filter.ApplicationID > 0 {
			query.Set("application_id", strconv.FormatUint(filter.ApplicationID, 10))
		}
		if publicKeyName != "" {
			query.Set("public_key_name", publicKeyName)
		}
		if encoded := query.Encode(); encoded != "" {
			path += "?" + encoded
		}
	}
	return c.doApprovalRequest(http.MethodGet, path, approvalToken, nil)
}

func (c *HTTPClient) ApprovalRequestInit(payload []byte, approvalToken string) (*approvalBridgeResponse, error) {
	return c.doApprovalRequest(http.MethodPost, "/api/approvals/request/init", approvalToken, payload)
}

func (c *HTTPClient) ApprovalRequestChallenge(requestID uint64, approvalToken string) (*approvalBridgeResponse, error) {
	path := fmt.Sprintf("/api/approvals/request/%d/challenge", requestID)
	return c.doApprovalRequest(http.MethodGet, path, approvalToken, nil)
}

func (c *HTTPClient) ApprovalRequestConfirm(requestID uint64, payload []byte, approvalToken string) (*approvalBridgeResponse, error) {
	path := fmt.Sprintf("/api/approvals/request/%d/confirm", requestID)
	return c.doApprovalRequest(http.MethodPost, path, approvalToken, payload)
}

func (c *HTTPClient) ApprovalActionChallenge(taskID uint64, approvalToken string) (*approvalBridgeResponse, error) {
	path := fmt.Sprintf("/api/approvals/%d/challenge", taskID)
	return c.doApprovalRequest(http.MethodGet, path, approvalToken, nil)
}

func (c *HTTPClient) ApprovalAction(taskID uint64, payload []byte, approvalToken string) (*approvalBridgeResponse, error) {
	path := fmt.Sprintf("/api/approvals/%d/action", taskID)
	return c.doApprovalRequest(http.MethodPost, path, approvalToken, payload)
}
