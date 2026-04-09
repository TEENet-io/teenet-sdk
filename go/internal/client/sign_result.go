// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

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
