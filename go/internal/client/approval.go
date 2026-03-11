package client

import (
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

func (c *Client) ApprovalRequestInit(payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalRequestInit(payload, approvalToken)
	})
}

func (c *Client) PasskeyLoginOptions() (*types.ApprovalResult, error) {
	return approvalCall(c.httpClient.PasskeyLoginOptions)
}

func (c *Client) PasskeyLoginVerify(loginSessionID uint64, credential []byte) (*types.ApprovalResult, error) {
	payload := map[string]interface{}{
		"login_session_id": loginSessionID,
	}
	if len(credential) > 0 {
		var decoded interface{}
		if err := json.Unmarshal(credential, &decoded); err != nil {
			return &types.ApprovalResult{
				Success:    false,
				StatusCode: 0,
				Error:      "invalid credential json",
			}, err
		}
		payload["credential"] = decoded
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &types.ApprovalResult{
			Success:    false,
			StatusCode: 0,
			Error:      "failed to build login verify payload",
		}, err
	}
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.PasskeyLoginVerify(body)
	})
}

func (c *Client) ApprovalPending(approvalToken string, filter *types.ApprovalPendingFilter) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalPending(approvalToken, filter)
	})
}

func (c *Client) ApprovalRequestChallenge(requestID uint64, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalRequestChallenge(requestID, approvalToken)
	})
}

func (c *Client) ApprovalRequestConfirm(requestID uint64, payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalRequestConfirm(requestID, payload, approvalToken)
	})
}

func (c *Client) ApprovalActionChallenge(taskID uint64, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalActionChallenge(taskID, approvalToken)
	})
}

func (c *Client) ApprovalAction(taskID uint64, payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.ApprovalAction(taskID, payload, approvalToken)
	})
}

func (c *Client) GetMyRequests(approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.GetMyRequests(approvalToken)
	})
}

// CancelRequest cancels a pending approval request or session.
// idType should be "session" (default) to cancel a request session by ID,
// or "task" to cancel a pending approval task by ID.
func (c *Client) CancelRequest(id uint64, idType string, approvalToken string) (*types.ApprovalResult, error) {
	if idType == "" {
		idType = "session"
	}
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.CancelRequest(id, idType, approvalToken)
	})
}

func (c *Client) GetSignatureByTx(txID string, approvalToken string) (*types.ApprovalResult, error) {
	return approvalCall(func() (*network.ApprovalBridgeResponse, error) {
		return c.httpClient.GetSignatureByTx(txID, approvalToken)
	})
}
