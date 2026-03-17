package client

import (
	"context"
	"encoding/json"
	"fmt"

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
