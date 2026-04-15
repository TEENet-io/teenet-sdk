// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

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
	DeploymentLogEntry   = types.DeploymentLogEntry
	DeploymentLogsQuery  = types.DeploymentLogsQuery
	DeploymentLogsResult = types.DeploymentLogsResult
	PolicyLevel          = types.PolicyLevel
	PolicyRequest        = types.PolicyRequest
	Policy               = types.Policy
	PolicyResult         = types.PolicyResult
	AdminResult          = types.AdminResult
	CreateAPIKeyRequest  = types.CreateAPIKeyRequest
	CreateAPIKeyResult   = types.CreateAPIKeyResult
)

// PasskeyCredentialProvider returns credential JSON bytes for WebAuthn options.
// Pass an implementation of this type to PasskeyLoginWithCredential,
// ApprovalRequestConfirmWithCredential, and ApprovalActionWithCredential.
type PasskeyCredentialProvider = types.PasskeyCredentialProvider

// Re-export constants from internal/crypto.

// Protocol constants
const (
	ProtocolECDSA   = crypto.ProtocolECDSA
	ProtocolSchnorr = crypto.ProtocolSchnorr
	// ProtocolEdDSA is a semantic alias for Schnorr+Ed25519. Use it with
	// CurveED25519 in GenerateKey when you want RFC 8032 EdDSA naming.
	ProtocolEdDSA = crypto.ProtocolEdDSA
	// ProtocolSchnorrBIP340 is a semantic alias for Schnorr+secp256k1 that
	// matches BIP-340 (Bitcoin Taproot). Use it with CurveSECP256K1 in
	// GenerateKey when generating keys for Bitcoin Taproot (P2TR) outputs.
	ProtocolSchnorrBIP340 = crypto.ProtocolSchnorrBIP340
)

// Curve constants
const (
	CurveED25519   = crypto.CurveED25519
	CurveSECP256K1 = crypto.CurveSECP256K1
	CurveSECP256R1 = crypto.CurveSECP256R1
)
