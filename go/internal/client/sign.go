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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
	"github.com/TEENet-io/teenet-sdk/go/internal/util"
)

// Sign generates a cryptographic signature for a message using TEENet consensus.
//
// This method automatically handles both direct signing and M-of-N threshold voting
// scenarios based on how the App ID is configured in the consensus service:
//
//   - Direct Signing: If the app is configured for single-key signing, the signature
//     is returned immediately after the consensus service processes it.
//
//   - Threshold Voting: If the app requires M-of-N approval, this method waits up to
//     ClientOptions.PendingWaitTimeout (default 10s) for threshold completion by polling
//     voting status from the consensus service.
//
// The method performs these steps:
//  1. Computes SHA256 hash of the message for tracking
//  2. Submits the signing request to the consensus service
//  3. For voting requests, polls status until signed/failed/timeout
//  4. Returns final signature or error
//
// Parameters:
//   - message: The raw bytes to sign (will be hashed with SHA256 internally)
//   - publicKeyName: Bound public key name to use for signing (required)
//
// Returns:
//   - SignResult: Contains the signature bytes and success status
//   - error: Non-nil if the signing operation failed
//
// The returned SignResult.VotingInfo field will contain voting metadata if threshold
// signing was used, or nil for direct signatures.
//
// Timeout Behavior:
//   - HTTP request timeout: Uses Client.requestTimeout (default 30s)
//
// Error Conditions:
//   - Default App ID not set
//   - Network errors communicating with consensus service
//   - Insufficient votes received
//
// Example (Direct Signing):
//
//	result, err := client.Sign([]byte("important message"), "my-key")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Signature: %x\n", result.Signature)
//
// Example (Threshold Voting):
//
//	// If App ID is configured for 2-of-3 voting, this will:
//	// 1. Submit the signing request
//	// 2. Wait up to PendingWaitTimeout (default 10s) for threshold completion
//	// 3. Return final signed/failed result
//	result, err := client.Sign(message, "my-key")
//	if result.VotingInfo != nil {
//	    fmt.Printf("Votes: %d/%d\n",
//	        result.VotingInfo.CurrentVotes,
//	        result.VotingInfo.RequiredVotes)
//	}
func (c *Client) Sign(message []byte, publicKeyName string, passkeyToken ...string) (*types.SignResult, error) {
	// Check if default App ID is set
	if c.defaultAppID == "" {
		return nil, fmt.Errorf("default App ID is not set (use SetDefaultAppID or set APP_INSTANCE_ID environment variable)")
	}
	if len(message) == 0 {
		msg := "message must not be empty"
		return signFailure(types.ErrorCodeInvalidInput, msg, nil), errors.New(msg)
	}
	var token string
	if len(passkeyToken) > 0 {
		token = passkeyToken[0]
	}
	// Calculate message hash for status tracking (SHA256)
	hash := sha256.Sum256(message)
	messageHash := "0x" + hex.EncodeToString(hash[:])

	if strings.TrimSpace(publicKeyName) == "" {
		msg := "public key name is required"
		return signFailure(types.ErrorCodeInvalidInput, msg, nil), errors.New(msg)
	}

	selectedKey, err := c.getBoundPublicKeyByName(publicKeyName)
	if err != nil {
		if errors.Is(err, ErrPublicKeyNameNotFound) {
			msg := fmt.Sprintf("public key name '%s' is not bound to this application", publicKeyName)
			return signFailure(types.ErrorCodeInvalidInput, msg, nil), errors.New(msg)
		}
		msg := fmt.Sprintf("failed to resolve public key '%s': %v", publicKeyName, err)
		return signFailure(types.ErrorCodeSignRequestFailed, msg, nil), errors.New(msg)
	}
	pubKeyHex := strings.TrimPrefix(selectedKey.KeyData, "0x")
	pubKey, decodeErr := hex.DecodeString(pubKeyHex)
	if decodeErr != nil {
		msg := fmt.Sprintf("invalid public key data for '%s': %v", publicKeyName, decodeErr)
		return signFailure(types.ErrorCodeInvalidInput, msg, nil), errors.New(msg)
	}

	log.Printf("Signing message (length: %d bytes, hash: %s), app_id: %s, with public key name '%s' (%d bytes)",
		len(message), truncateForLog(messageHash), c.defaultAppID, publicKeyName, len(pubKey))
	c.debugf("sign.submit app_id=%s hash=%s pending_wait_ms=%d poll_base_ms=%d",
		c.defaultAppID, messageHash, c.pendingWaitTimeout.Milliseconds(), defaultStatusPollInterval.Milliseconds())
	resp, err := c.httpClient.SubmitRequest(c.defaultAppID, message, pubKey, token)
	if err != nil {
		return signFailure(types.ErrorCodeSignRequestFailed, fmt.Sprintf("Failed to submit request: %v", err), nil), err
	}

	// Check if request was successful
	if !resp.Success {
		return signFailure(types.ErrorCodeSignRequestRejected, fmt.Sprintf("Server returned error: %s", resp.Message), nil), fmt.Errorf("server error: %s", resp.Message)
	}
	if resp.Hash != "" {
		messageHash = resp.Hash
	}

	// Check if signing completed immediately (direct signing mode)
	if resp.Status == "signed" && resp.Signature != "" {
		log.Printf("Direct signing completed, signature: %s", truncateForLog(resp.Signature))

		// Decode signature
		signature, err := util.DecodeHexSignature(resp.Signature)
		if err != nil {
			return signFailure(types.ErrorCodeSignatureDecode, fmt.Sprintf("Failed to decode signature: %v", err), nil), err
		}

		return &types.SignResult{
			Signature: signature,
			Success:   true,
			VotingInfo: &types.VotingInfo{
				NeedsVoting:   false,
				CurrentVotes:  resp.CurrentVotes,
				RequiredVotes: resp.RequiredVotes,
				Status:        resp.Status,
				Hash:          messageHash,
			},
		}, nil
	}

	// Voting mode - wait for final result via status polling
	if resp.Status == "pending" {
		log.Printf("Voting mode: request accepted (%d/%d votes), waiting up to %s",
			resp.CurrentVotes, resp.RequiredVotes, c.pendingWaitTimeout)
		c.debugf("sign.pending hash=%s votes=%d/%d", messageHash, resp.CurrentVotes, resp.RequiredVotes)
		return c.WaitForSignResult(messageHash, c.pendingWaitTimeout)
	}

	// Approval mode - request is created and waiting for human approval.
	if resp.Status == "pending_approval" {
		log.Printf("Approval mode: request initialized (tx_id=%s request_id=%d hash=%s)",
			resp.TxID, resp.RequestID, truncateForLog(messageHash))
		return &types.SignResult{
			Success:   false,
			Error:     "approval required",
			ErrorCode: types.ErrorCodeApprovalPending,
			VotingInfo: &types.VotingInfo{
				NeedsVoting:   false,
				CurrentVotes:  0,
				RequiredVotes: 0,
				Status:        resp.Status,
				Hash:          messageHash,
				TxID:          resp.TxID,
				RequestID:     resp.RequestID,
			},
		}, nil
	}

	// Unknown status
	return signFailure(types.ErrorCodeUnexpectedStatus, fmt.Sprintf("Unexpected response status: %s", resp.Status), nil), fmt.Errorf("unexpected status: %s", resp.Status)
}

func truncateForLog(s string) string {
	if len(s) <= 20 {
		return s
	}
	return s[:20] + "..."
}
