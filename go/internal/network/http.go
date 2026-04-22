// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

// Package network provides HTTP communication for TEENet SDK.
//
// This internal package handles HTTP requests to the TEENet service.
package network

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

const (
	sdkUserAgent    = "teenet-sdk-go/1.0"
	maxResponseSize = 10 * 1024 * 1024 // 10 MB
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

// submitRequestPayload is the request body for submitting a signature request.
// Note: Message is []byte which Go's json.Marshal encodes as base64.
// This differs from SignWithAPISecret which sends hex-encoded strings.
// Both encodings are expected by the signing service.
type submitRequestPayload struct {
	AppInstanceID string `json:"app_instance_id"`
	Message       []byte `json:"message"`              // Raw message bytes (JSON auto-encodes to base64)
	PublicKey     []byte `json:"public_key,omitempty"` // Optional: raw public key bytes to use for signing
	PasskeyToken  string `json:"passkey_token,omitempty"` // Passkey auth token; required when approval policy is enabled
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
	AppInstanceID      string              `json:"app_instance_id"`
	PublicKeys []publicKeyResponse `json:"public_keys"`
	Error      string              `json:"error,omitempty"`
}

// SubmitRequest submits a signature request to the signing service.
// publicKey must be provided as raw key bytes.
func (c *HTTPClient) SubmitRequest(ctx context.Context, appInstanceID string, message []byte, publicKey []byte, passkeyToken string) (*submitRequestResponse, error) {
	payload := submitRequestPayload{
		AppInstanceID: appInstanceID,
		Message:       message,
		PublicKey:     publicKey,
		PasskeyToken:  passkeyToken,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/submit-request", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build submit request: %w", err)
	}
	req.Header.Set("User-Agent", sdkUserAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit request: %w", err)
	}
	defer resp.Body.Close()

	var result submitRequestResponse
	if err := c.decodeJSON(resp, &result, "submit request"); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetCacheDetail retrieves the cache entry for a specific hash.
func (c *HTTPClient) GetCacheDetail(ctx context.Context, hash string) (*cacheDetailResponse, error) {
	reqURL := c.baseURL + "/api/cache/" + url.PathEscape(hash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build cache request: %w", err)
	}
	req.Header.Set("User-Agent", sdkUserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache entry: %w", err)
	}
	defer resp.Body.Close()

	var result cacheDetailResponse
	if err := c.decodeJSON(resp, &result, "cache detail"); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetPublicKeys retrieves bound public key information for an APP_INSTANCE_ID.
func (c *HTTPClient) GetPublicKeys(ctx context.Context, appInstanceID string) ([]publicKeyResponse, error) {
	reqURL := c.baseURL + "/api/publickeys/" + url.PathEscape(appInstanceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build public keys request: %w", err)
	}
	req.Header.Set("User-Agent", sdkUserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}
	defer resp.Body.Close()

	var result publicKeysResponse
	if err := c.decodeJSON(resp, &result, "public keys"); err != nil {
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

// GenerateKey generates a new cryptographic key for an APP_INSTANCE_ID.
func (c *HTTPClient) GenerateKey(ctx context.Context, appInstanceID, curve, protocol string) (*generateKeyResponse, error) {
	payload := generateKeyPayload{
		AppInstanceID: appInstanceID,
		Curve:         curve,
		Protocol:      protocol,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate-key", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build generate key request: %w", err)
	}
	req.Header.Set("User-Agent", sdkUserAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer resp.Body.Close()

	var result generateKeyResponse
	if err := c.decodeJSON(resp, &result, "generate key"); err != nil {
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

// GetAPIKey retrieves an API key value by name for an APP_INSTANCE_ID.
func (c *HTTPClient) GetAPIKey(ctx context.Context, appInstanceID, name string) (*apiKeyResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	reqURL := fmt.Sprintf("%s/api/apikey/%s?%s", c.baseURL, url.PathEscape(name), q.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build API key request: %w", err)
	}
	req.Header.Set("User-Agent", sdkUserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}
	defer resp.Body.Close()

	var result apiKeyResponse
	if err := c.decodeJSON(resp, &result, "API key"); err != nil {
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
func (c *HTTPClient) SignWithAPISecret(ctx context.Context, appInstanceID, name string, message []byte) (*apiSignResponse, error) {
	// Convert message to hex string for JSON transport
	messageHex := hex.EncodeToString(message)

	payload := signWithAPISecretPayload{
		AppInstanceID: appInstanceID,
		Message:       messageHex,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	reqURL := fmt.Sprintf("%s/api/apikey/%s/sign", c.baseURL, url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build sign request: %w", err)
	}
	req.Header.Set("User-Agent", sdkUserAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with API secret: %w", err)
	}
	defer resp.Body.Close()

	var result apiSignResponse
	if err := c.decodeJSON(resp, &result, "API secret sign"); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// ApprovalBridgeResponse is the unified parsed response for both approval and admin endpoints.
type ApprovalBridgeResponse struct {
	StatusCode int
	Data       map[string]interface{}
}

// doRawRequest performs an HTTP request and decodes the JSON response body.
// errContext is used as a prefix for error messages (e.g., "approval", "admin").
// If token is non-empty, an Authorization: Bearer header is added.
// Content-Type: application/json is set when payload is non-empty.
func (c *HTTPClient) doRawRequest(ctx context.Context, method, path, token string, payload []byte, errContext string) (*ApprovalBridgeResponse, error) {
	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to build %s request: %w", errContext, err)
	}
	req.Header.Set("User-Agent", sdkUserAgent)
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request failed: %w", errContext, err)
	}
	defer resp.Body.Close()

	decoded := map[string]interface{}{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("failed to decode %s response (status %d): %w", errContext, resp.StatusCode, err)
	}
	return &ApprovalBridgeResponse{StatusCode: resp.StatusCode, Data: decoded}, nil
}

// decodeJSON decodes an HTTP response body as JSON into out.
// For non-2xx responses it attempts JSON decode but returns a clear error if the body is non-JSON.
func (c *HTTPClient) decodeJSON(resp *http.Response, out interface{}, errContext string) error {
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		if err := json.Unmarshal(bodyBytes, out); err != nil {
			return fmt.Errorf("%s: server returned status %d with non-JSON body", errContext, resp.StatusCode)
		}
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(out)
}

func (c *HTTPClient) doApprovalRequest(ctx context.Context, method, path, approvalToken string, payload []byte) (*ApprovalBridgeResponse, error) {
	return c.doRawRequest(ctx, method, path, approvalToken, payload, "approval")
}

func (c *HTTPClient) PasskeyLoginOptions(ctx context.Context) (*ApprovalBridgeResponse, error) {
	return c.doRawRequest(ctx, http.MethodGet, "/api/auth/passkey/options", "", nil, "approval")
}

func (c *HTTPClient) PasskeyLoginVerify(ctx context.Context, payload []byte) (*ApprovalBridgeResponse, error) {
	return c.doRawRequest(ctx, http.MethodPost, "/api/auth/passkey/verify", "", payload, "approval")
}

func (c *HTTPClient) ApprovalPending(ctx context.Context, approvalToken string, filter *types.ApprovalPendingFilter) (*ApprovalBridgeResponse, error) {
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
	return c.doApprovalRequest(ctx, http.MethodGet, path, approvalToken, nil)
}

func (c *HTTPClient) ApprovalRequestInit(ctx context.Context, payload []byte, approvalToken string) (*ApprovalBridgeResponse, error) {
	return c.doApprovalRequest(ctx, http.MethodPost, "/api/approvals/request/init", approvalToken, payload)
}

func (c *HTTPClient) ApprovalRequestChallenge(ctx context.Context, requestID uint64, approvalToken string) (*ApprovalBridgeResponse, error) {
	path := fmt.Sprintf("/api/approvals/request/%d/challenge", requestID)
	return c.doApprovalRequest(ctx, http.MethodGet, path, approvalToken, nil)
}

func (c *HTTPClient) ApprovalRequestConfirm(ctx context.Context, requestID uint64, payload []byte, approvalToken string) (*ApprovalBridgeResponse, error) {
	path := fmt.Sprintf("/api/approvals/request/%d/confirm", requestID)
	return c.doApprovalRequest(ctx, http.MethodPost, path, approvalToken, payload)
}

func (c *HTTPClient) ApprovalActionChallenge(ctx context.Context, taskID uint64, approvalToken string) (*ApprovalBridgeResponse, error) {
	path := fmt.Sprintf("/api/approvals/%d/challenge", taskID)
	return c.doApprovalRequest(ctx, http.MethodGet, path, approvalToken, nil)
}

func (c *HTTPClient) ApprovalAction(ctx context.Context, taskID uint64, payload []byte, approvalToken string) (*ApprovalBridgeResponse, error) {
	path := fmt.Sprintf("/api/approvals/%d/action", taskID)
	return c.doApprovalRequest(ctx, http.MethodPost, path, approvalToken, payload)
}

func (c *HTTPClient) GetMyRequests(ctx context.Context, approvalToken string) (*ApprovalBridgeResponse, error) {
	return c.doApprovalRequest(ctx, http.MethodGet, "/api/requests/mine", approvalToken, nil)
}

func (c *HTTPClient) CancelRequest(ctx context.Context, id uint64, idType string, approvalToken string) (*ApprovalBridgeResponse, error) {
	path := fmt.Sprintf("/api/requests/%d?type=%s", id, url.QueryEscape(idType))
	return c.doApprovalRequest(ctx, http.MethodDelete, path, approvalToken, nil)
}

func (c *HTTPClient) GetSignatureByTx(ctx context.Context, txID string, approvalToken string) (*ApprovalBridgeResponse, error) {
	path := fmt.Sprintf("/api/signature/by-tx/%s", url.PathEscape(txID))
	return c.doApprovalRequest(ctx, http.MethodGet, path, approvalToken, nil)
}

// CloseIdleConnections closes idle connections in the HTTP transport.
func (c *HTTPClient) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}
