package client

import (
	"encoding/json"
	"fmt"

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

func (c *Client) ApprovalRequestInit(payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	resp, err := c.httpClient.ApprovalRequestInit(payload, approvalToken)
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
}

func (c *Client) PasskeyLoginOptions() (*types.ApprovalResult, error) {
	resp, err := c.httpClient.PasskeyLoginOptions()
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
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
	resp, err := c.httpClient.PasskeyLoginVerify(body)
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
}

func (c *Client) ApprovalPending(approvalToken string, filter *types.ApprovalPendingFilter) (*types.ApprovalResult, error) {
	resp, err := c.httpClient.ApprovalPending(approvalToken, filter)
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
}

func (c *Client) ApprovalRequestChallenge(requestID uint64, approvalToken string) (*types.ApprovalResult, error) {
	resp, err := c.httpClient.ApprovalRequestChallenge(requestID, approvalToken)
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
}

func (c *Client) ApprovalRequestConfirm(requestID uint64, payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	resp, err := c.httpClient.ApprovalRequestConfirm(requestID, payload, approvalToken)
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
}

func (c *Client) ApprovalActionChallenge(taskID uint64, approvalToken string) (*types.ApprovalResult, error) {
	resp, err := c.httpClient.ApprovalActionChallenge(taskID, approvalToken)
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
}

func (c *Client) ApprovalAction(taskID uint64, payload []byte, approvalToken string) (*types.ApprovalResult, error) {
	resp, err := c.httpClient.ApprovalAction(taskID, payload, approvalToken)
	if resp == nil {
		return toApprovalResult(0, nil, err)
	}
	return toApprovalResult(resp.StatusCode, resp.Data, err)
}
