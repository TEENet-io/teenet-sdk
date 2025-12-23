// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
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
	"fmt"
	"log"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
	"github.com/TEENet-io/teenet-sdk/go/internal/util"
)

// min returns the minimum of two integers.
// This is a utility function used internally for vote counting.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Sign generates a cryptographic signature for a message using TEENet consensus.
//
// This method automatically handles both direct signing and M-of-N threshold voting
// scenarios based on how the App ID is configured in the consensus service:
//
//   - Direct Signing: If the app is configured for single-key signing, the signature
//     is returned immediately after the consensus service processes it.
//
//   - Threshold Voting: If the app requires M-of-N approval, this method will wait
//     for sufficient votes before returning. The client's fixed-port callback server
//     (port 19080) receives the final signature once the threshold is reached.
//
// The method performs these steps:
//  1. Computes SHA256 hash of the message for tracking
//  2. Registers a callback handler for this message hash
//  3. Submits the signing request to the consensus service
//  4. Waits for either immediate response or voting result (up to CallbackTimeout)
//  5. Returns the signature or error
//
// Parameters:
//   - message: The raw bytes to sign (will be hashed with SHA256 internally)
//   - publicKey: Optional public key bytes to use for signing. If not provided, uses default key.
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
//   - Voting callback timeout: Uses Client.callbackTimeout (default 60s)
//   - If voting times out, an error is returned but the voting may still complete
//     server-side. The consensus service does not currently support cancellation.
//
// Error Conditions:
//   - Default App ID not set
//   - Callback server not available (port 19080 may be in use)
//   - Network errors communicating with consensus service
//   - Voting timeout exceeded
//   - Insufficient votes received
//
// Example (Direct Signing):
//
//	result, err := client.Sign([]byte("important message"))
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Signature: %x\n", result.Signature)
//
// Example (Threshold Voting - handled automatically):
//
//	// If App ID is configured for 2-of-3 voting, this will:
//	// 1. Submit the signing request
//	// 2. Wait for 2 parties to vote
//	// 3. Return the signature once threshold is reached
//	result, err := client.Sign(message)
//	if result.VotingInfo != nil {
//	    fmt.Printf("Votes: %d/%d\n",
//	        result.VotingInfo.CurrentVotes,
//	        result.VotingInfo.RequiredVotes)
//	}
func (c *Client) Sign(message []byte, publicKey ...[]byte) (*types.SignResult, error) {
	// Check if default App ID is set
	if c.defaultAppID == "" {
		return nil, fmt.Errorf("default App ID is not set (use SetDefaultAppID or set APP_INSTANCE_ID environment variable)")
	}

	// Check if callback server is available
	if c.callbackServer == nil {
		return nil, fmt.Errorf("callback server not available (port 19080 may be in use by another application)")
	}

	// Calculate message hash for callback tracking (SHA256)
	hash := sha256.Sum256(message)
	messageHash := "0x" + hex.EncodeToString(hash[:])

	// Extract public key from optional parameter if provided
	var pubKey []byte
	if len(publicKey) > 0 && len(publicKey[0]) > 0 {
		pubKey = publicKey[0]
		log.Printf("Signing message (length: %d bytes, hash: %s), app_id: %s, with provided public key (%d bytes)",
			len(message), messageHash[:20]+"...", c.defaultAppID, len(pubKey))
	} else {
		log.Printf("Signing message (length: %d bytes, hash: %s), app_id: %s (using default key)",
			len(message), messageHash[:20]+"...", c.defaultAppID)
	}

	// Register callback for this message hash
	callbackChan := c.callbackServer.RegisterCallback(messageHash)
	defer c.callbackServer.UnregisterCallback(messageHash)

	log.Printf("Submitting request to %s", c.consensusURL)
	resp, err := c.httpClient.SubmitRequest(c.defaultAppID, message, pubKey)
	if err != nil {
		return &types.SignResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to submit request: %v", err),
		}, err
	}

	// Check if request was successful
	if !resp.Success {
		return &types.SignResult{
			Success: false,
			Error:   fmt.Sprintf("Server returned error: %s", resp.Message),
		}, fmt.Errorf("server error: %s", resp.Message)
	}

	// Check if signing completed immediately (direct signing mode)
	if resp.Status == "signed" && resp.Signature != "" {
		log.Printf("Direct signing completed, signature: %s", resp.Signature[:20]+"...")

		// Decode signature
		signature, err := util.DecodeHexSignature(resp.Signature)
		if err != nil {
			return &types.SignResult{
				Success: false,
				Error:   fmt.Sprintf("Failed to decode signature: %v", err),
			}, err
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

	// Voting mode - wait for callback
	if resp.Status == "pending" {
		log.Printf("Voting mode: waiting for threshold (%d/%d votes)", resp.CurrentVotes, resp.RequiredVotes)

		// Wait for callback with timeout
		select {
		case payload := <-callbackChan:
			// Received callback
			log.Printf("Received callback: status=%s", payload.Status)

			if payload.Status == "signed" && payload.Signature != "" {
				// Decode signature
				signature, err := util.DecodeHexSignature(payload.Signature)
				if err != nil {
					return &types.SignResult{
						Success: false,
						Error:   fmt.Sprintf("Failed to decode signature from callback: %v", err),
					}, err
				}

				return &types.SignResult{
					Signature: signature,
					Success:   true,
					VotingInfo: &types.VotingInfo{
						NeedsVoting:   true,
						CurrentVotes:  resp.RequiredVotes, // Threshold met
						RequiredVotes: resp.RequiredVotes,
						Status:        "signed",
						Hash:          messageHash,
					},
				}, nil
			} else {
				// Signing failed
				errorMsg := payload.Error
				if errorMsg == "" {
					errorMsg = "Signing failed"
				}

				return &types.SignResult{
					Success: false,
					Error:   errorMsg,
					VotingInfo: &types.VotingInfo{
						NeedsVoting:   true,
						CurrentVotes:  resp.CurrentVotes,
						RequiredVotes: resp.RequiredVotes,
						Status:        payload.Status,
						Hash:          messageHash,
					},
				}, fmt.Errorf("%s", errorMsg)
			}

		case <-time.After(c.callbackTimeout):
			// Timeout waiting for callback
			return &types.SignResult{
				Success: false,
				Error:   fmt.Sprintf("Timeout waiting for voting completion (%v)", c.callbackTimeout),
				VotingInfo: &types.VotingInfo{
					NeedsVoting:   true,
					CurrentVotes:  resp.CurrentVotes,
					RequiredVotes: resp.RequiredVotes,
					Status:        "pending",
					Hash:          messageHash,
				},
			}, fmt.Errorf("timeout waiting for callback")
		}
	}

	// Unknown status
	return &types.SignResult{
		Success: false,
		Error:   fmt.Sprintf("Unexpected response status: %s", resp.Status),
	}, fmt.Errorf("unexpected status: %s", resp.Status)
}
