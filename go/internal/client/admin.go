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

package client

import (
	"encoding/json"
	"fmt"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

func toAdminError(data map[string]interface{}, status int) string {
	if msg, ok := data["message"].(string); ok && msg != "" {
		return msg
	}
	if msg, ok := data["error"].(string); ok && msg != "" {
		return msg
	}
	return fmt.Sprintf("admin request failed with status %d", status)
}

func (c *Client) requireAppID() error {
	if c.defaultAppID == "" {
		return fmt.Errorf("no App ID configured: call SetDefaultAppID first")
	}
	return nil
}

// decodeAdminData unmarshals an admin response Data map into a typed result T.
func decodeAdminData[T any](data map[string]interface{}) (*T, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var result T
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// InvitePasskeyUser invites a new passkey user via the admin bridge.
func (c *Client) InvitePasskeyUser(req types.PasskeyInviteRequest) (*types.PasskeyInviteResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	payload := map[string]interface{}{
		"display_name": req.DisplayName,
	}
	if req.ApplicationID > 0 {
		payload["application_id"] = req.ApplicationID
	}
	if req.ExpiresInSeconds > 0 {
		payload["expires_in_seconds"] = req.ExpiresInSeconds
	}

	resp, err := c.httpClient.AdminInvitePasskeyUser(c.defaultAppID, payload)
	if err != nil {
		return &types.PasskeyInviteResult{Success: false, Error: err.Error()}, err
	}
	result, err := decodeAdminData[types.PasskeyInviteResult](resp.Data)
	if err != nil {
		return &types.PasskeyInviteResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result.Success = ok
	if !ok && result.Error == "" {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// ListPasskeyUsers returns all registered passkey users via the admin bridge.
func (c *Client) ListPasskeyUsers(page, limit int) (*types.PasskeyUsersResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminListPasskeyUsers(c.defaultAppID, page, limit)
	if err != nil {
		return &types.PasskeyUsersResult{Success: false, Error: err.Error()}, err
	}
	result, err := decodeAdminData[types.PasskeyUsersResult](resp.Data)
	if err != nil {
		return &types.PasskeyUsersResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result.Success = ok
	if !ok && result.Error == "" {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// DeletePasskeyUser deletes a passkey user by ID via the admin bridge.
func (c *Client) DeletePasskeyUser(userID uint) (*types.AdminResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminDeletePasskeyUser(c.defaultAppID, userID)
	if err != nil {
		return &types.AdminResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result := &types.AdminResult{Success: ok}
	if !ok {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// ListAuditRecords returns audit records for the application via the admin bridge.
func (c *Client) ListAuditRecords(page, limit int) (*types.AuditRecordsResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminListAuditRecords(c.defaultAppID, page, limit)
	if err != nil {
		return &types.AuditRecordsResult{Success: false, Error: err.Error()}, err
	}
	result, err := decodeAdminData[types.AuditRecordsResult](resp.Data)
	if err != nil {
		return &types.AuditRecordsResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result.Success = ok
	if !ok && result.Error == "" {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// UpsertPermissionPolicy creates or replaces a permission policy for a key via the admin bridge.
func (c *Client) UpsertPermissionPolicy(req types.PolicyRequest) (*types.AdminResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return &types.AdminResult{Success: false, Error: err.Error()}, err
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return &types.AdminResult{Success: false, Error: err.Error()}, err
	}

	resp, netErr := c.httpClient.AdminUpsertPolicy(c.defaultAppID, payload)
	if netErr != nil {
		return &types.AdminResult{Success: false, Error: netErr.Error()}, netErr
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result := &types.AdminResult{Success: ok}
	if !ok {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// GetPermissionPolicy retrieves the permission policy for a named key via the admin bridge.
func (c *Client) GetPermissionPolicy(publicKeyName string) (*types.PolicyResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminGetPolicy(c.defaultAppID, publicKeyName)
	if err != nil {
		return &types.PolicyResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !ok {
		return &types.PolicyResult{Success: false, Error: toAdminError(resp.Data, resp.StatusCode)}, nil
	}
	result, err := decodeAdminData[types.PolicyResult](resp.Data)
	if err != nil {
		return &types.PolicyResult{Success: false, Error: err.Error()}, err
	}
	result.Success = true
	return result, nil
}

// PasskeyRegistrationOptions begins WebAuthn registration for the given invite token.
// The browser should pass the returned Options to navigator.credentials.create().
func (c *Client) PasskeyRegistrationOptions(inviteToken string) (*types.PasskeyRegistrationOptionsResult, error) {
	resp, err := c.httpClient.AdminPasskeyRegistrationOptions(inviteToken)
	if err != nil {
		return &types.PasskeyRegistrationOptionsResult{Success: false, Error: err.Error()}, err
	}
	result, err := decodeAdminData[types.PasskeyRegistrationOptionsResult](resp.Data)
	if err != nil {
		return &types.PasskeyRegistrationOptionsResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result.Success = ok
	if !ok && result.Error == "" {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// PasskeyRegistrationVerify completes WebAuthn registration using the credential returned
// by navigator.credentials.create().
func (c *Client) PasskeyRegistrationVerify(inviteToken string, credential interface{}) (*types.PasskeyRegistrationVerifyResult, error) {
	resp, err := c.httpClient.AdminPasskeyRegistrationVerify(inviteToken, credential)
	if err != nil {
		return &types.PasskeyRegistrationVerifyResult{Success: false, Error: err.Error()}, err
	}
	result, err := decodeAdminData[types.PasskeyRegistrationVerifyResult](resp.Data)
	if err != nil {
		return &types.PasskeyRegistrationVerifyResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result.Success = ok
	if !ok && result.Error == "" {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// DeletePermissionPolicy deletes the permission policy for a named key via the admin bridge.
func (c *Client) DeletePermissionPolicy(publicKeyName string) (*types.AdminResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminDeletePolicy(c.defaultAppID, publicKeyName)
	if err != nil {
		return &types.AdminResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result := &types.AdminResult{Success: ok}
	if !ok {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// DeletePublicKey deletes a public key by name via the admin bridge.
func (c *Client) DeletePublicKey(keyName string) (*types.AdminResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminDeletePublicKey(c.defaultAppID, keyName)
	if err != nil {
		return &types.AdminResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result := &types.AdminResult{Success: ok}
	if !ok {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// CreateAPIKey creates a new API key via the admin bridge.
func (c *Client) CreateAPIKey(req types.CreateAPIKeyRequest) (*types.CreateAPIKeyResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return &types.CreateAPIKeyResult{Success: false, Error: err.Error()}, err
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return &types.CreateAPIKeyResult{Success: false, Error: err.Error()}, err
	}
	resp, netErr := c.httpClient.AdminCreateAPIKey(c.defaultAppID, payload)
	if netErr != nil {
		return &types.CreateAPIKeyResult{Success: false, Error: netErr.Error()}, netErr
	}
	result, err := decodeAdminData[types.CreateAPIKeyResult](resp.Data)
	if err != nil {
		return &types.CreateAPIKeyResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result.Success = ok
	if !ok && result.Error == "" {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}

// DeleteAPIKey deletes an API key by name via the admin bridge.
func (c *Client) DeleteAPIKey(keyName string) (*types.AdminResult, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminDeleteAPIKey(c.defaultAppID, keyName)
	if err != nil {
		return &types.AdminResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result := &types.AdminResult{Success: ok}
	if !ok {
		result.Error = toAdminError(resp.Data, resp.StatusCode)
	}
	return result, nil
}
