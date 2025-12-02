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


package types

import (
	"time"

	"github.com/TEENet-io/teenet-sdk/internal/network"
)

// ClientOptions holds optional configuration for the Client.
//
// These options allow customization of timeout behaviors for both
// HTTP requests and callback waiting periods.
type ClientOptions struct {
	// RequestTimeout specifies the timeout for HTTP requests to the consensus service.
	// Default is 30 seconds if not specified.
	RequestTimeout time.Duration

	// CallbackTimeout specifies how long to wait for voting callbacks.
	// This should be set longer than expected voting duration.
	// Default is 60 seconds if not specified.
	CallbackTimeout time.Duration
}

// SignOptions contains optional parameters for sign operations.
//
// Currently reserved for future extensions. Pass nil or empty options
// to use default behavior.
type SignOptions struct {
	// Reserved for future options such as:
	// - Custom callback URLs
	// - Vote timeout overrides
	// - Metadata attachment
}

// SignResult contains the result of a sign operation.
//
// This structure is returned by the Sign method and contains either
// a successful signature or error information. For voting scenarios,
// additional voting details are included in VotingInfo.
type SignResult struct {
	// Signature contains the raw signature bytes on success.
	// For ECDSA signatures, this is typically 64 bytes (r || s).
	// For Schnorr, it's 64 bytes. For EdDSA, it's 64 bytes.
	Signature []byte `json:"signature,omitempty"`

	// Success indicates whether the signing operation succeeded.
	Success bool `json:"success"`

	// Error contains the error message if Success is false.
	Error string `json:"error,omitempty"`

	// VotingInfo contains additional information when M-of-N voting was used.
	// This field is nil for direct (non-voting) signatures.
	VotingInfo *VotingInfo `json:"voting_info,omitempty"`
}

// VotingInfo contains metadata about M-of-N threshold voting.
//
// When an application is configured for threshold signing, multiple
// parties must vote to approve a signature. This structure tracks
// the voting progress and final status.
type VotingInfo struct {
	// NeedsVoting indicates whether this signature required voting.
	// If false, the signature was generated directly without voting.
	NeedsVoting bool `json:"needs_voting"`

	// CurrentVotes is the number of votes received so far.
	CurrentVotes int `json:"current_votes"`

	// RequiredVotes is the threshold (M) needed for signature generation.
	// For example, in a 2-of-3 scheme, RequiredVotes would be 2.
	RequiredVotes int `json:"required_votes"`

	// Status indicates the current state of the voting process.
	// Possible values: "pending", "signed", "error"
	Status string `json:"status"`

	// Hash is the message hash (0x-prefixed hex) used for tracking this request.
	Hash string `json:"hash"`
}

// CallbackPayload is the structure sent by consensus nodes to callback URLs.
//
// When a voting operation completes, the consensus service sends this
// payload to the callback URL that was registered with the sign request.
// This is an internal structure used by the callback server.
//
// This is a re-export of network.CallbackPayload for public API compatibility.
type CallbackPayload = network.CallbackPayload
