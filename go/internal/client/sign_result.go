package client

import "github.com/TEENet-io/teenet-sdk/go/internal/types"

func signFailure(code, msg string, voting *types.VotingInfo) *types.SignResult {
	return &types.SignResult{
		Success:    false,
		Error:      msg,
		ErrorCode:  code,
		VotingInfo: voting,
	}
}
