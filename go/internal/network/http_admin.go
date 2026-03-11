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

package network

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

func (c *HTTPClient) doAdminRequest(method, path string, payload []byte) (*ApprovalBridgeResponse, error) {
	return c.doRawRequest(method, path, "", payload, "admin")
}

// AdminInvitePasskeyUser calls POST /api/admin/passkey/invite.
func (c *HTTPClient) AdminInvitePasskeyUser(appInstanceID string, payload map[string]interface{}) (*ApprovalBridgeResponse, error) {
	body := make(map[string]interface{}, len(payload)+1)
	for k, v := range payload {
		body[k] = v
	}
	body["app_instance_id"] = appInstanceID

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal invite payload: %w", err)
	}
	return c.doAdminRequest(http.MethodPost, "/api/admin/passkey/invite", encoded)
}

// AdminListPasskeyUsers calls GET /api/admin/passkey/users.
func (c *HTTPClient) AdminListPasskeyUsers(appInstanceID string, page, limit int) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return c.doAdminRequest(http.MethodGet, "/api/admin/passkey/users?"+q.Encode(), nil)
}

// AdminDeletePasskeyUser calls DELETE /api/admin/passkey/users/:id.
func (c *HTTPClient) AdminDeletePasskeyUser(appInstanceID string, userID uint) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	path := fmt.Sprintf("/api/admin/passkey/users/%d?%s", userID, q.Encode())
	return c.doAdminRequest(http.MethodDelete, path, nil)
}

// AdminListAuditRecords calls GET /api/admin/audit-records.
func (c *HTTPClient) AdminListAuditRecords(appInstanceID string, page, limit int) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return c.doAdminRequest(http.MethodGet, "/api/admin/audit-records?"+q.Encode(), nil)
}

// AdminUpsertPolicy calls PUT /api/admin/policy.
func (c *HTTPClient) AdminUpsertPolicy(appInstanceID string, payload map[string]interface{}) (*ApprovalBridgeResponse, error) {
	body := make(map[string]interface{}, len(payload)+1)
	for k, v := range payload {
		body[k] = v
	}
	body["app_instance_id"] = appInstanceID

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy payload: %w", err)
	}
	return c.doAdminRequest(http.MethodPut, "/api/admin/policy", encoded)
}

// AdminGetPolicy calls GET /api/admin/policy.
func (c *HTTPClient) AdminGetPolicy(appInstanceID, publicKeyName string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	q.Set("public_key_name", publicKeyName)
	return c.doAdminRequest(http.MethodGet, "/api/admin/policy?"+q.Encode(), nil)
}

// AdminDeletePolicy calls DELETE /api/admin/policy.
func (c *HTTPClient) AdminDeletePolicy(appInstanceID, publicKeyName string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	q.Set("public_key_name", publicKeyName)
	return c.doAdminRequest(http.MethodDelete, "/api/admin/policy?"+q.Encode(), nil)
}

// AdminPasskeyRegistrationOptions calls GET /api/passkey/register/options?token=...
func (c *HTTPClient) AdminPasskeyRegistrationOptions(inviteToken string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("token", inviteToken)
	return c.doAdminRequest(http.MethodGet, "/api/passkey/register/options?"+q.Encode(), nil)
}

// AdminPasskeyRegistrationVerify calls POST /api/passkey/register/verify.
func (c *HTTPClient) AdminPasskeyRegistrationVerify(inviteToken string, credential interface{}) (*ApprovalBridgeResponse, error) {
	body := map[string]interface{}{
		"invite_token": inviteToken,
		"credential":   credential,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration verify payload: %w", err)
	}
	return c.doAdminRequest(http.MethodPost, "/api/passkey/register/verify", encoded)
}

// AdminDeletePublicKey calls DELETE /api/admin/publickeys/:name.
func (c *HTTPClient) AdminDeletePublicKey(appInstanceID, keyName string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	path := fmt.Sprintf("/api/admin/publickeys/%s?%s", url.PathEscape(keyName), q.Encode())
	return c.doAdminRequest(http.MethodDelete, path, nil)
}

// AdminCreateAPIKey calls POST /api/admin/apikeys.
func (c *HTTPClient) AdminCreateAPIKey(appInstanceID string, payload map[string]interface{}) (*ApprovalBridgeResponse, error) {
	body := make(map[string]interface{}, len(payload)+1)
	for k, v := range payload {
		body[k] = v
	}
	body["app_instance_id"] = appInstanceID
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal create API key payload: %w", err)
	}
	return c.doAdminRequest(http.MethodPost, "/api/admin/apikeys", encoded)
}

// AdminDeleteAPIKey calls DELETE /api/admin/apikeys/:name.
func (c *HTTPClient) AdminDeleteAPIKey(appInstanceID, keyName string) (*ApprovalBridgeResponse, error) {
	q := url.Values{}
	q.Set("app_instance_id", appInstanceID)
	path := fmt.Sprintf("/api/admin/apikeys/%s?%s", url.PathEscape(keyName), q.Encode())
	return c.doAdminRequest(http.MethodDelete, path, nil)
}
