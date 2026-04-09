// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/TEENet-io/teenet-sdk/go/internal/network"
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

func (c *Client) getAppInstanceID() (string, error) {
	c.mu.RLock()
	appInstanceID := c.defaultAppInstanceID
	c.mu.RUnlock()
	if appInstanceID == "" {
		return "", fmt.Errorf("default App ID is not set (use SetDefaultAppInstanceID or set APP_INSTANCE_ID environment variable)")
	}
	return appInstanceID, nil
}


// adminSimpleResult converts an admin HTTP response into an AdminResult.
func adminSimpleResult(resp *network.ApprovalBridgeResponse, err error) (*types.AdminResult, error) {
	if err != nil {
		return &types.AdminResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result := &types.AdminResult{Success: ok}
	if !ok {
		errMsg := toAdminError(resp.Data, resp.StatusCode)
		result.Error = errMsg
		return result, fmt.Errorf("%s", errMsg)
	}
	return result, nil
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

// convertJSON marshals src to JSON then unmarshals it into T.
func convertJSON[T any](src interface{}) (*T, error) {
	raw, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	var result T
	return &result, json.Unmarshal(raw, &result)
}

// InvitePasskeyUser invites a new passkey user via the admin bridge.
func (c *Client) InvitePasskeyUser(ctx context.Context, req types.PasskeyInviteRequest) (*types.PasskeyInviteResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminInvitePasskeyUser(ctx, appID, req)
	if err != nil {
		return &types.PasskeyInviteResult{Success: false, Error: err.Error()}, err
	}
	result, err := decodeAdminData[types.PasskeyInviteResult](resp.Data)
	if err != nil {
		return &types.PasskeyInviteResult{Success: false, Error: err.Error()}, err
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	result.Success = ok
	if !ok {
		if result.Error == "" {
			result.Error = toAdminError(resp.Data, resp.StatusCode)
		}
		return result, fmt.Errorf("%s", result.Error)
	}
	return result, nil
}

// ListPasskeyUsers returns all registered passkey users via the admin bridge.
func (c *Client) ListPasskeyUsers(ctx context.Context, page, limit int) (*types.PasskeyUsersResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminListPasskeyUsers(ctx, appID, page, limit)
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
func (c *Client) DeletePasskeyUser(ctx context.Context, userID uint) (*types.AdminResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminDeletePasskeyUser(ctx, appID, userID)
	return adminSimpleResult(resp, err)
}

// ListAuditRecords returns audit records for the application via the admin bridge.
func (c *Client) ListAuditRecords(ctx context.Context, page, limit int) (*types.AuditRecordsResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminListAuditRecords(ctx, appID, page, limit)
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
func (c *Client) UpsertPermissionPolicy(ctx context.Context, req types.PolicyRequest) (*types.AdminResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminUpsertPolicy(ctx, appID, req)
	return adminSimpleResult(resp, err)
}

// GetPermissionPolicy retrieves the permission policy for a named key via the admin bridge.
func (c *Client) GetPermissionPolicy(ctx context.Context, publicKeyName string) (*types.PolicyResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminGetPolicy(ctx, appID, publicKeyName)
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
func (c *Client) PasskeyRegistrationOptions(ctx context.Context, inviteToken string) (*types.PasskeyRegistrationOptionsResult, error) {
	resp, err := c.httpClient.AdminPasskeyRegistrationOptions(ctx, inviteToken)
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
func (c *Client) PasskeyRegistrationVerify(ctx context.Context, inviteToken string, credential interface{}) (*types.PasskeyRegistrationVerifyResult, error) {
	resp, err := c.httpClient.AdminPasskeyRegistrationVerify(ctx, inviteToken, credential)
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
func (c *Client) DeletePermissionPolicy(ctx context.Context, publicKeyName string) (*types.AdminResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminDeletePolicy(ctx, appID, publicKeyName)
	return adminSimpleResult(resp, err)
}

// DeletePublicKey deletes a public key by name via the admin bridge.
func (c *Client) DeletePublicKey(ctx context.Context, keyName string) (*types.AdminResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminDeletePublicKey(ctx, appID, keyName)
	return adminSimpleResult(resp, err)
}

// CreateAPIKey creates a new API key via the admin bridge.
func (c *Client) CreateAPIKey(ctx context.Context, req types.CreateAPIKeyRequest) (*types.CreateAPIKeyResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, netErr := c.httpClient.AdminCreateAPIKey(ctx, appID, req)
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
func (c *Client) DeleteAPIKey(ctx context.Context, keyName string) (*types.AdminResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.AdminDeleteAPIKey(ctx, appID, keyName)
	return adminSimpleResult(resp, err)
}
