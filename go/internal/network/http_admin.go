// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

func (c *HTTPClient) doAdminRequest(ctx context.Context, method, path string, payload []byte) (*ApprovalBridgeResponse, error) {
	return c.doRawRequest(ctx, method, path, "", payload, "admin")
}

// marshalWithAppInstanceID marshals payload to JSON and injects "app_instance_id" into the top-level object.
func marshalWithAppInstanceID(appInstanceID string, payload interface{}) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("failed to re-decode payload: %w", err)
	}
	body["app_instance_id"] = appInstanceID
	return json.Marshal(body)
}

// AdminInvitePasskeyUser calls POST /api/admin/passkey/invite.
func (c *HTTPClient) AdminInvitePasskeyUser(ctx context.Context, appInstanceID string, payload interface{}) (*ApprovalBridgeResponse, error) {
	encoded, err := marshalWithAppInstanceID(appInstanceID, payload)
	if err != nil {
		return nil, err
	}
	return c.doAdminRequest(ctx, http.MethodPost, "/api/admin/passkey/invite", encoded)
}

// AdminListPasskeyUsers calls GET /api/admin/passkey/users.
func (c *HTTPClient) AdminListPasskeyUsers(ctx context.Context, appInstanceID string, page, limit int) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return c.doAdminRequest(ctx, http.MethodGet, "/api/admin/passkey/users?"+q.Encode(), nil)
}

// AdminDeletePasskeyUser calls DELETE /api/admin/passkey/users/:id.
func (c *HTTPClient) AdminDeletePasskeyUser(ctx context.Context, appInstanceID string, userID uint) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	path := fmt.Sprintf("/api/admin/passkey/users/%d?%s", userID, q.Encode())
	return c.doAdminRequest(ctx, http.MethodDelete, path, nil)
}

// AdminListAuditRecords calls GET /api/admin/audit-records.
func (c *HTTPClient) AdminListAuditRecords(ctx context.Context, appInstanceID string, page, limit int) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return c.doAdminRequest(ctx, http.MethodGet, "/api/admin/audit-records?"+q.Encode(), nil)
}

// AdminGetDeploymentLogs calls GET /api/admin/deployment-logs.
// All filter parameters are optional. The server clamps the time window
// (default last 1h, max 24h) and caps limit at 500.
func (c *HTTPClient) AdminGetDeploymentLogs(ctx context.Context, appInstanceID string, startTime, endTime int64, level, keyword string, limit int) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	if startTime > 0 {
		q.Set("start_time", strconv.FormatInt(startTime, 10))
	}
	if endTime > 0 {
		q.Set("end_time", strconv.FormatInt(endTime, 10))
	}
	if level != "" {
		q.Set("level", level)
	}
	if keyword != "" {
		q.Set("keyword", keyword)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return c.doAdminRequest(ctx, http.MethodGet, "/api/admin/deployment-logs?"+q.Encode(), nil)
}

// AdminUpsertPolicy calls PUT /api/admin/policy.
func (c *HTTPClient) AdminUpsertPolicy(ctx context.Context, appInstanceID string, payload interface{}) (*ApprovalBridgeResponse, error) {
	encoded, err := marshalWithAppInstanceID(appInstanceID, payload)
	if err != nil {
		return nil, err
	}
	return c.doAdminRequest(ctx, http.MethodPut, "/api/admin/policy", encoded)
}

// AdminGetPolicy calls GET /api/admin/policy.
func (c *HTTPClient) AdminGetPolicy(ctx context.Context, appInstanceID, publicKeyName string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	q.Set("public_key_name", publicKeyName)
	return c.doAdminRequest(ctx, http.MethodGet, "/api/admin/policy?"+q.Encode(), nil)
}

// AdminDeletePolicy calls DELETE /api/admin/policy.
func (c *HTTPClient) AdminDeletePolicy(ctx context.Context, appInstanceID, publicKeyName string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	q.Set("public_key_name", publicKeyName)
	return c.doAdminRequest(ctx, http.MethodDelete, "/api/admin/policy?"+q.Encode(), nil)
}

// AdminPasskeyRegistrationOptions calls GET /api/passkey/register/options?token=...
func (c *HTTPClient) AdminPasskeyRegistrationOptions(ctx context.Context, inviteToken string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("token", inviteToken)
	return c.doAdminRequest(ctx, http.MethodGet, "/api/passkey/register/options?"+q.Encode(), nil)
}

// AdminPasskeyRegistrationVerify calls POST /api/passkey/register/verify.
func (c *HTTPClient) AdminPasskeyRegistrationVerify(ctx context.Context, inviteToken string, credential interface{}) (*ApprovalBridgeResponse, error) {
	body := map[string]interface{}{
		"invite_token": inviteToken,
		"credential":   credential,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration verify payload: %w", err)
	}
	return c.doAdminRequest(ctx, http.MethodPost, "/api/passkey/register/verify", encoded)
}

// AdminDeletePublicKey calls DELETE /api/admin/publickeys/:name.
func (c *HTTPClient) AdminDeletePublicKey(ctx context.Context, appInstanceID, keyName string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	path := fmt.Sprintf("/api/admin/publickeys/%s?%s", url.PathEscape(keyName), q.Encode())
	return c.doAdminRequest(ctx, http.MethodDelete, path, nil)
}

// AdminCreateAPIKey calls POST /api/admin/apikeys.
func (c *HTTPClient) AdminCreateAPIKey(ctx context.Context, appInstanceID string, payload interface{}) (*ApprovalBridgeResponse, error) {
	encoded, err := marshalWithAppInstanceID(appInstanceID, payload)
	if err != nil {
		return nil, err
	}
	return c.doAdminRequest(ctx, http.MethodPost, "/api/admin/apikeys", encoded)
}

// AdminDeleteAPIKey calls DELETE /api/admin/apikeys/:name.
func (c *HTTPClient) AdminDeleteAPIKey(ctx context.Context, appInstanceID, keyName string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	path := fmt.Sprintf("/api/admin/apikeys/%s?%s", url.PathEscape(keyName), q.Encode())
	return c.doAdminRequest(ctx, http.MethodDelete, path, nil)
}
