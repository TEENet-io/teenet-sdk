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

package sdk

import (
	"github.com/TEENet-io/teenet-sdk/go/internal/crypto"
	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

// ErrApprovalPending is returned by Sign when the request requires human passkey approval.
// Use errors.Is(err, sdk.ErrApprovalPending) to detect this condition.
var ErrApprovalPending = types.ErrApprovalPending

// Re-export all types from internal/types for public API.

type (
	ClientOptions         = types.ClientOptions
	SignResult            = types.SignResult
	VotingInfo            = types.VotingInfo
	VoteStatus            = types.VoteStatus
	ApprovalResult        = types.ApprovalResult
	ApprovalPendingFilter = types.ApprovalPendingFilter
	GenerateKeyResult     = types.GenerateKeyResult
	PublicKeyInfo         = types.PublicKeyInfo
	APIKeyResult          = types.APIKeyResult
	APISignResult         = types.APISignResult

	// Admin management types.
	PasskeyRegistrationOptionsResult = types.PasskeyRegistrationOptionsResult
	PasskeyRegistrationVerifyResult  = types.PasskeyRegistrationVerifyResult
	PasskeyInviteRequest             = types.PasskeyInviteRequest
	PasskeyInviteResult              = types.PasskeyInviteResult
	PasskeyUser          = types.PasskeyUser
	PasskeyUsersResult   = types.PasskeyUsersResult
	AuditRecord          = types.AuditRecord
	AuditRecordsResult   = types.AuditRecordsResult
	PolicyLevel          = types.PolicyLevel
	PolicyRequest        = types.PolicyRequest
	Policy               = types.Policy
	PolicyResult         = types.PolicyResult
	AdminResult          = types.AdminResult
	CreateAPIKeyRequest  = types.CreateAPIKeyRequest
	CreateAPIKeyResult   = types.CreateAPIKeyResult
)

// PasskeyCredentialProvider returns credential JSON bytes for WebAuthn options.
type PasskeyCredentialProvider func(options interface{}) ([]byte, error)

// Re-export constants from internal/crypto.

// Protocol constants
const (
	ProtocolECDSA   = crypto.ProtocolECDSA
	ProtocolSchnorr = crypto.ProtocolSchnorr
)

// Curve constants
const (
	CurveED25519   = crypto.CurveED25519
	CurveSECP256K1 = crypto.CurveSECP256K1
	CurveSECP256R1 = crypto.CurveSECP256R1
)
