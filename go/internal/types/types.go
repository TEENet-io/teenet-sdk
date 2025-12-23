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

	"github.com/TEENet-io/teenet-sdk/go/internal/network"
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

// GenerateKeyOptions contains optional parameters for key generation operations.
//
// This structure allows customization of the key generation process,
// such as specifying the cryptographic protocol and curve.
type GenerateKeyOptions struct {
	// Name is the human-readable name for the generated key.
	// This will be used to identify the key in the user management system.
	Name string

	// Curve specifies the elliptic curve to use.
	// Supported values: "ed25519", "secp256k1", "secp256r1"
	// Default is "secp256k1" if not specified.
	Curve string

	// Protocol specifies the signing protocol to use.
	// Supported values: "schnorr", "ecdsa"
	// Default is "schnorr" if not specified.
	Protocol string
}

// GenerateKeyResult contains the result of a key generation operation.
//
// This structure is returned by the GenerateKey method and contains
// the newly generated public key information.
type GenerateKeyResult struct {
	// Success indicates whether the key generation succeeded.
	Success bool `json:"success"`

	// Message contains a success or error message.
	Message string `json:"message"`

	// PublicKey contains the generated public key information.
	// This field is nil if Success is false.
	PublicKey *PublicKeyInfo `json:"public_key,omitempty"`
}

// PublicKeyInfo contains detailed information about a generated public key.
type PublicKeyInfo struct {
	// ID is the unique identifier for this key in the database.
	ID uint32 `json:"id"`

	// Name is the human-readable name of the key.
	Name string `json:"name"`

	// KeyData is the hex-encoded public key data.
	KeyData string `json:"key_data"`

	// Curve is the elliptic curve used (e.g., "secp256k1", "ed25519").
	Curve string `json:"curve"`

	// Protocol is the signing protocol (e.g., "schnorr", "ecdsa").
	Protocol string `json:"protocol"`

	// Threshold is the DKG threshold value (for threshold signatures).
	Threshold uint32 `json:"threshold,omitempty"`

	// ParticipantCount is the number of participants in the DKG.
	ParticipantCount uint32 `json:"participant_count,omitempty"`

	// MaxParticipantCount is the maximum number of participants.
	MaxParticipantCount uint32 `json:"max_participant_count,omitempty"`

	// ApplicationID is the ID of the application this key belongs to.
	ApplicationID uint32 `json:"application_id"`

	// CreatedByInstanceID is the app_instance_id that generated this key.
	CreatedByInstanceID string `json:"created_by_instance_id"`
}

// APIKeyResult contains the result of a GetAPIKey operation.
//
// This structure is returned by the GetAPIKey method and contains
// the retrieved API key value and metadata.
type APIKeyResult struct {
	// Success indicates whether the API key retrieval succeeded.
	Success bool `json:"success"`

	// Error contains the error message if Success is false.
	Error string `json:"error,omitempty"`

	// AppInstanceID is the application instance ID.
	AppInstanceID string `json:"app_instance_id"`

	// Name is the name of the API key.
	Name string `json:"name"`

	// APIKey is the retrieved API key value.
	// This field is empty if Success is false.
	APIKey string `json:"api_key,omitempty"`
}

// APISignResult contains the result of a SignWithAPISecret operation.
//
// This structure is returned by the SignWithAPISecret method and contains
// the HMAC-SHA256 signature and metadata.
type APISignResult struct {
	// Success indicates whether the signing operation succeeded.
	Success bool `json:"success"`

	// Error contains the error message if Success is false.
	Error string `json:"error,omitempty"`

	// AppInstanceID is the application instance ID.
	AppInstanceID string `json:"app_instance_id"`

	// Name is the name of the API key/secret used for signing.
	Name string `json:"name"`

	// Signature is the hex-encoded HMAC-SHA256 signature.
	// This field is empty if Success is false.
	Signature string `json:"signature,omitempty"`

	// SignatureHex is an alias for Signature (for compatibility).
	SignatureHex string `json:"signature_hex,omitempty"`

	// Algorithm is the signing algorithm used (always "HMAC-SHA256").
	Algorithm string `json:"algorithm,omitempty"`

	// MessageLength is the length of the input message in bytes.
	MessageLength int `json:"message_length"`
}
