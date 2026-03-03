// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// -----------------------------------------------------------------------------

package client

import (
	"fmt"

	"github.com/TEENet-io/teenet-sdk/go/internal/types"
	"github.com/TEENet-io/teenet-sdk/go/internal/util"
)

// GetStatus retrieves voting status for a specific hash from the consensus service.
func (c *Client) GetStatus(hash string) (*types.VoteStatus, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}

	resp, err := c.httpClient.GetCacheDetail(hash)
	if err != nil {
		return nil, err
	}

	if resp == nil || !resp.Found || resp.Entry == nil {
		status := &types.VoteStatus{
			Found:        false,
			Hash:         hash,
			ErrorMessage: "",
		}
		if resp != nil {
			status.ErrorMessage = resp.Message
		}
		return status, nil
	}

	entry := resp.Entry
	currentVotes := 0
	for _, req := range entry.Requests {
		if req != nil && req.Approved {
			currentVotes++
		}
	}

	var signature []byte
	if entry.Signature != "" {
		sig, err := util.DecodeHexSignature(entry.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature: %w", err)
		}
		signature = sig
	}

	return &types.VoteStatus{
		Found:         true,
		Hash:          entry.Hash,
		Status:        entry.Status,
		CurrentVotes:  currentVotes,
		RequiredVotes: entry.RequiredVotes,
		Signature:     signature,
		ErrorMessage:  entry.ErrorMessage,
	}, nil
}
