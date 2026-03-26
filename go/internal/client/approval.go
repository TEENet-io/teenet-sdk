package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/TEENet-io/teenet-sdk/go/internal/network"
	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

func toApprovalResult(respStatus int, data map[string]interface{}, err error) (*types.ApprovalResult, error) {
	if err != nil {
		return &types.ApprovalResult{
			Success:    false,
			StatusCode: respStatus,
			Error:      err.Error(),
		}, err
	}

	result := &types.ApprovalResult{
		Success:    respStatus >= 200 && respStatus < 300,
		StatusCode: respStatus,
		Data:       data,
	}
	if !result.Success {
		if msg, ok := data["error"].(string); ok && msg != "" {
			result.Error = msg
		} else if msg, ok := data["message"].(string); ok && msg != "" {
			result.Error = msg
		} else {
			result.Error = fmt.Sprintf("approval request failed with status %d", respStatus)
		}
	}
	return result, nil
}

// approvalCall is a generic helper that wraps the nil-check pattern for all approval methods.
func approvalCall(fn func() (*network.ApprovalBridgeResponse, error)) (*types.ApprovalResult, error) {
	resp, err := fn()
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
}

func (c *Client) ApprovalRequestInit(ctx context.Context, payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	if len(payload) > 0 && !json.Valid(payload) {
		err := fmt.Errorf("invalid payload json")
		return &types.ApprovalResult{Success: false, Error: err.Error()}, err
	}
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalRequestInit(ctx, payload, approvalToken)
	})
}

func (c *Client) PasskeyLoginOptions(ctx context.Context) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.PasskeyLoginOptions(ctx)
	})
}

func (c *Client) PasskeyLoginVerify(ctx context.Context, loginSessionID uint64, credential []byte) (*types.ApprovalResult, error) {
	if len(credential) > 0 && !json.Valid(credential) {
		err := fmt.Errorf("invalid credential json")
		return &types.ApprovalResult{Success: false, Error: err.Error()}, err
	}
	payload := struct {
		LoginSessionID uint64          `json:"login_session_id"`
		Credential     json.RawMessage `json:"credential,omitempty"`
	}{
		LoginSessionID: loginSessionID,
		Credential:     json.RawMessage(credential),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &types.ApprovalResult{
			Success: false,
			Error:   "failed to build login verify payload",
		}, err
	}
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.PasskeyLoginVerify(ctx, body)
	})
}

// PasskeyLoginVerifyAs verifies passkey assertion and confirms the verified PasskeyUserID
// matches expectedPasskeyUserID. Returns error if they don't match.
func (c *Client) PasskeyLoginVerifyAs(ctx context.Context, loginSessionID uint64, credential []byte, expectedPasskeyUserID uint) (*types.ApprovalResult, error) {
	res, err := c.PasskeyLoginVerify(ctx, loginSessionID, credential)
	if err != nil {
		return res, err
	}
	if !res.Success {
		return res, nil
	}

	// Extract verified passkey_user_id from response data.
	if res.Data == nil {
		return &types.ApprovalResult{
			Success: false,
			Error:   "passkey verification response missing user identity",
		}, fmt.Errorf("passkey_user_id not returned by server")
	}

	var verifiedID uint64
	switch v := res.Data["passkey_user_id"].(type) {
	case float64:
		verifiedID = uint64(v)
	case json.Number:
		i, _ := v.Int64()
		verifiedID = uint64(i)
	}

	if verifiedID == 0 {
		return &types.ApprovalResult{
			Success: false,
			Error:   "passkey verification response missing passkey_user_id",
		}, fmt.Errorf("passkey_user_id not returned or zero")
	}

	if verifiedID != uint64(expectedPasskeyUserID) {
		return &types.ApprovalResult{
			Success: false,
			Error:   "passkey does not belong to the expected user",
		}, fmt.Errorf("passkey user mismatch: expected %d, got %d", expectedPasskeyUserID, verifiedID)
	}

	return res, nil
}

func (c *Client) ApprovalPending(ctx context.Context, approvalToken string, filter *types.ApprovalPendingFilter) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalPending(ctx, approvalToken, filter)
	})
}

func (c *Client) ApprovalRequestChallenge(ctx context.Context, requestID uint64, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalRequestChallenge(ctx, requestID, approvalToken)
	})
}

func (c *Client) ApprovalRequestConfirm(ctx context.Context, requestID uint64, payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalRequestConfirm(ctx, requestID, payload, approvalToken)
	})
}

func (c *Client) ApprovalActionChallenge(ctx context.Context, taskID uint64, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalActionChallenge(ctx, taskID, approvalToken)
	})
}

func (c *Client) ApprovalAction(ctx context.Context, taskID uint64, payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalAction(ctx, taskID, payload, approvalToken)
	})
}

func (c *Client) GetMyRequests(ctx context.Context, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.GetMyRequests(ctx, approvalToken)
	})
}

// CancelRequest cancels a pending approval request or session.
// idType should be "session" (default) to cancel a request session by ID,
// or "task" to cancel a pending approval task by ID.
func (c *Client) CancelRequest(ctx context.Context, id uint64, idType string, approvalToken string) (*types.ApprovalResult, error) {
	if idType == "" {
		idType = "session"
	}
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.CancelRequest(ctx, id, idType, approvalToken)
	})
}

func (c *Client) GetSignatureByTx(ctx context.Context, txID string, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.GetSignatureByTx(ctx, txID, approvalToken)
	})
}

// toUint64 converts various numeric representations to uint64.
func toUint64(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n <= 0 || n != float64(uint64(n)) {
			return 0, false
		}
		return uint64(n), true
	case int:
		if n <= 0 {
			return 0, false
		}
		return uint64(n), true
	case int64:
		if n <= 0 {
			return 0, false
		}
		return uint64(n), true
	case uint64:
		return n, n > 0
	case json.Number:
		parsed, err := n.Int64()
		if err != nil || parsed <= 0 {
			return 0, false
		}
		return uint64(parsed), true
	case string:
		parsed, err := strconv.ParseUint(n, 10, 64)
		if err != nil || parsed == 0 {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

// getAndValidateCredential calls provider(options), ensures the result is valid JSON,
// and returns either the raw credential bytes or a ready-to-return ApprovalResult + error.
func getAndValidateCredential(provider types.PasskeyCredentialProvider, options interface{}) ([]byte, *types.ApprovalResult, error) {
	credential, credErr := provider(options)
	if credErr != nil {
		return nil, &types.ApprovalResult{Success: false, Error: "credential provider failed: " + credErr.Error()}, credErr
	}
	if !json.Valid(credential) {
		err := errors.New("invalid credential json")
		return nil, &types.ApprovalResult{Success: false, Error: err.Error()}, err
	}
	return credential, nil, nil
}

// extractChallengeOptions extracts the options field from a challenge data map,
// falling back to the whole map if no "options" key is present.
func extractChallengeOptions(data map[string]interface{}) interface{} {
	if data == nil {
		return nil
	}
	if options, ok := data["options"]; ok && options != nil {
		return options
	}
	return data
}

// PasskeyLoginWithCredential orchestrates the multi-step passkey login flow:
// LoginOptions → credential provider → LoginVerify.
func (c *Client) PasskeyLoginWithCredential(ctx context.Context, getCredential types.PasskeyCredentialProvider) (*types.ApprovalResult, error) {
	if getCredential == nil {
		return &types.ApprovalResult{
			Success: false,
			Error:   "credential provider is required",
		}, errors.New("credential provider is required")
	}
	loginOpts, err := c.PasskeyLoginOptions(ctx)
	if err != nil || loginOpts == nil || !loginOpts.Success {
		return loginOpts, err
	}
	loginSessionID, ok := toUint64(loginOpts.Data["login_session_id"])
	if !ok || loginSessionID == 0 {
		return &types.ApprovalResult{
			Success:    false,
			StatusCode: 500,
			Error:      "invalid login_session_id in login options response",
		}, nil
	}
	options, ok := loginOpts.Data["options"]
	if !ok {
		return &types.ApprovalResult{
			Success:    false,
			StatusCode: 500,
			Error:      "missing options in login options response",
		}, nil
	}
	credential, credErr := getCredential(options)
	if credErr != nil {
		return &types.ApprovalResult{
			Success: false,
			Error:   "credential provider failed: " + credErr.Error(),
		}, credErr
	}
	return c.PasskeyLoginVerify(ctx, loginSessionID, credential)
}

// ApprovalRequestConfirmWithCredential orchestrates the multi-step request confirmation flow:
// RequestChallenge → credential provider → RequestConfirm.
func (c *Client) ApprovalRequestConfirmWithCredential(ctx context.Context, requestID uint64, getCredential types.PasskeyCredentialProvider, approvalToken string) (*types.ApprovalResult, error) {
	if getCredential == nil {
		return &types.ApprovalResult{
			Success: false,
			Error:   "credential provider is required",
		}, errors.New("credential provider is required")
	}
	challenge, err := c.ApprovalRequestChallenge(ctx, requestID, approvalToken)
	if err != nil || challenge == nil || !challenge.Success {
		return challenge, err
	}
	options := extractChallengeOptions(challenge.Data)
	credential, errResult, credErr := getAndValidateCredential(getCredential, options)
	if errResult != nil {
		return errResult, credErr
	}
	payload, marshalErr := json.Marshal(struct {
		Credential json.RawMessage `json:"credential"`
	}{
		Credential: json.RawMessage(credential),
	})
	if marshalErr != nil {
		return &types.ApprovalResult{
			Success: false,
			Error:   "failed to build request confirm payload",
		}, marshalErr
	}
	return c.ApprovalRequestConfirm(ctx, requestID, payload, approvalToken)
}

// ApprovalActionWithCredential orchestrates the multi-step approval action flow:
// ActionChallenge → credential provider → ApprovalAction.
func (c *Client) ApprovalActionWithCredential(ctx context.Context, taskID uint64, action string, getCredential types.PasskeyCredentialProvider, approvalToken string) (*types.ApprovalResult, error) {
	if getCredential == nil {
		return &types.ApprovalResult{
			Success: false,
			Error:   "credential provider is required",
		}, errors.New("credential provider is required")
	}
	challenge, err := c.ApprovalActionChallenge(ctx, taskID, approvalToken)
	if err != nil || challenge == nil || !challenge.Success {
		return challenge, err
	}
	options := extractChallengeOptions(challenge.Data)
	credential, errResult, credErr := getAndValidateCredential(getCredential, options)
	if errResult != nil {
		return errResult, credErr
	}
	payload, marshalErr := json.Marshal(struct {
		Action     string          `json:"action"`
		Credential json.RawMessage `json:"credential"`
	}{
		Action:     action,
		Credential: json.RawMessage(credential),
	})
	if marshalErr != nil {
		return &types.ApprovalResult{
			Success: false,
			Error:   "failed to build action payload",
		}, marshalErr
	}
	return c.ApprovalAction(ctx, taskID, payload, approvalToken)
}
