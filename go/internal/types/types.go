// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

package types

import (
	"errors"
	"time"
)

// ErrApprovalPending is returned by Sign when a human passkey approval is required.
// Use errors.Is(err, ErrApprovalPending) to detect this case. The SignResult still
// contains VotingInfo with the RequestID and TxID needed to drive the approval flow.
var ErrApprovalPending = errors.New("approval pending: human approval required")

// ClientOptions holds optional configuration for the Client.
//
// These options allow customization of timeout behaviors.
type ClientOptions struct {
	// RequestTimeout specifies the timeout for HTTP requests to the consensus service.
	// Default is 30 seconds if not specified.
	RequestTimeout time.Duration

	// PendingWaitTimeout specifies how long Sign waits for voting completion
	// after receiving a pending response.
	// Default is 10 seconds if not specified.
	PendingWaitTimeout time.Duration

	// Debug enables verbose SDK logs for sign and polling trace.
	// Default is false.
	Debug bool

	// KeyCacheTTL specifies how long public key lists are cached.
	// Default is 60 seconds if not specified. Set to -1 to disable caching.
	KeyCacheTTL time.Duration
}

const (
	ErrorCodeInvalidInput        = "INVALID_INPUT"
	ErrorCodeSignRequestFailed   = "SIGN_REQUEST_FAILED"
	ErrorCodeSignRequestRejected = "SIGN_REQUEST_REJECTED"
	ErrorCodeSignatureDecode     = "SIGNATURE_DECODE_FAILED"
	ErrorCodeUnexpectedStatus    = "UNEXPECTED_STATUS"
	ErrorCodeMissingHash         = "MISSING_HASH"
	ErrorCodeStatusQueryFailed   = "STATUS_QUERY_FAILED"
	ErrorCodeSignFailed          = "SIGN_FAILED"
	ErrorCodeThresholdTimeout    = "THRESHOLD_TIMEOUT"
	ErrorCodeApprovalPending     = "APPROVAL_PENDING"
)

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

	// Success indicates whether signing completed successfully.
	Success bool `json:"success"`

	// Error contains the error message if Success is false.
	Error string `json:"error,omitempty"`

	// ErrorCode contains a stable machine-readable error code when Success is false.
	ErrorCode string `json:"error_code,omitempty"`

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
	// Possible values: "pending", "signed", "failed"
	Status string `json:"status"`

	// Hash is the message hash (0x-prefixed hex) used for tracking this request.
	Hash string `json:"hash"`

	// TxID is the approval transaction id when status is pending_approval.
	TxID string `json:"tx_id,omitempty"`

	// RequestID is the approval request id when status is pending_approval.
	RequestID uint64 `json:"request_id,omitempty"`
}

// VoteStatus contains the current status of a voting request.
type VoteStatus struct {
	Found         bool   `json:"found"`
	Hash          string `json:"hash"`
	Status        string `json:"status"`
	CurrentVotes  int    `json:"current_votes"`
	RequiredVotes int    `json:"required_votes"`
	Signature     []byte `json:"signature,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

// PasskeyCredentialProvider returns credential JSON bytes for a WebAuthn options object.
// The options parameter is the decoded JSON options map from the server challenge response.
// The returned bytes must be valid JSON (the serialized PublicKeyCredential assertion).
type PasskeyCredentialProvider func(options interface{}) ([]byte, error)

// ApprovalResult is a generic response wrapper for passkey approval APIs.
type ApprovalResult struct {
	Success    bool                   `json:"success"`
	StatusCode int                    `json:"status_code"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// ApprovalPendingFilter specifies optional query filters for pending approvals.
type ApprovalPendingFilter struct {
	// ApplicationID narrows pending approvals to one application.
	ApplicationID uint64 `json:"application_id,omitempty"`

	// PublicKeyName narrows pending approvals to one bound key name.
	// Requires ApplicationID > 0.
	PublicKeyName string `json:"public_key_name,omitempty"`
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

// PasskeyInviteRequest contains the parameters for inviting a passkey user.
type PasskeyInviteRequest struct {
	// DisplayName is the human-readable name for the invited user.
	DisplayName string `json:"display_name"`

	// ApplicationID optionally scopes the user to a specific application.
	ApplicationID uint `json:"application_id,omitempty"`

	// ExpiresInSeconds sets invite link TTL (0 = server default).
	ExpiresInSeconds int `json:"expires_in_seconds,omitempty"`
}

// PasskeyInviteResult is returned by InvitePasskeyUser.
type PasskeyInviteResult struct {
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	InviteToken string `json:"invite_token,omitempty"`
	RegisterURL string `json:"register_url,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// PasskeyRegistrationOptionsResult is returned by PasskeyRegistrationOptions.
type PasskeyRegistrationOptionsResult struct {
	Success     bool        `json:"success"`
	Error       string      `json:"error,omitempty"`
	InviteToken string      `json:"invite_token,omitempty"`
	Options     interface{} `json:"options,omitempty"`
	ExpiresAt   string      `json:"expires_at,omitempty"`
}

// PasskeyRegistrationVerifyResult is returned by PasskeyRegistrationVerify.
type PasskeyRegistrationVerifyResult struct {
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
	PasskeyUserID uint   `json:"passkey_user_id,omitempty"`
	DisplayName   string `json:"display_name,omitempty"`
}

// PasskeyUser describes a registered passkey user.
type PasskeyUser struct {
	ID            uint   `json:"id"`
	DisplayName   string `json:"display_name"`
	UserHandle    string `json:"user_handle,omitempty"`
	ApplicationID *uint  `json:"application_id,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
}

// PasskeyUsersResult is returned by ListPasskeyUsers.
type PasskeyUsersResult struct {
	Success bool          `json:"success"`
	Error   string        `json:"error,omitempty"`
	Users   []PasskeyUser `json:"users,omitempty"`
	Total   int           `json:"total,omitempty"`
	Page    int           `json:"page,omitempty"`
	Limit   int           `json:"limit,omitempty"`
}

// AuditRecord describes one audit log entry returned by ListAuditRecords.
// Field names match the audit_records table in UMS.
type AuditRecord struct {
	ID                 uint   `json:"id"`
	TaskID             *uint  `json:"task_id,omitempty"`
	RequestSessionID   *uint  `json:"request_session_id,omitempty"`
	EventType          string `json:"event_type,omitempty"`           // REQUEST_INIT | REQUEST_CONFIRMED | ACTION | SIGN_RESULT | INVITE_PASSKEY | …
	Action             string `json:"action,omitempty"`               // APPROVE | REJECT (only for ACTION events)
	Status             string `json:"status,omitempty"`               // PENDING | APPROVED | REJECTED | SIGNED | FAILED
	ActorPasskeyUserID uint   `json:"actor_passkey_user_id,omitempty"`
	ActorDisplayName   string `json:"actor_display_name,omitempty"`
	TxID               string `json:"tx_id,omitempty"`
	Hash               string `json:"hash,omitempty"`
	Signature          string `json:"signature,omitempty"`
	AppInstanceID      string `json:"app_instance_id,omitempty"`
	Details            string `json:"details,omitempty"`
	ErrorMessage       string `json:"error_message,omitempty"`
	CreatedAt          string `json:"created_at,omitempty"`
}

// AuditRecordsResult is returned by ListAuditRecords.
type AuditRecordsResult struct {
	Success bool          `json:"success"`
	Error   string        `json:"error,omitempty"`
	Records []AuditRecord `json:"records,omitempty"`
	Total   int           `json:"total,omitempty"`
	Page    int           `json:"page,omitempty"`
	Limit   int           `json:"limit,omitempty"`
}

// PolicyLevel describes one approval level in a permission policy.
type PolicyLevel struct {
	LevelIndex int    `json:"level_index"`
	Threshold  int    `json:"threshold"`
	MemberIDs  []uint `json:"member_ids"`
}

// PolicyRequest contains the parameters for creating/updating a permission policy.
type PolicyRequest struct {
	// PublicKeyName is the name of the public key this policy applies to.
	PublicKeyName string `json:"public_key_name"`

	// Enabled enables or disables the policy.
	Enabled bool `json:"enabled"`

	// TimeoutSeconds sets how long the approval request stays open (0 = server default).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`

	// Levels defines the ordered approval levels. Each level must be satisfied in order.
	Levels []PolicyLevel `json:"levels"`
}

// Policy describes a stored permission policy.
type Policy struct {
	ID             uint          `json:"id"`
	ApplicationID  uint          `json:"application_id"`
	PublicKeyID    uint          `json:"public_key_id"`
	PublicKeyName  string        `json:"public_key_name,omitempty"`
	Enabled        bool          `json:"enabled"`
	TimeoutSeconds int           `json:"timeout_seconds"`
	Levels         []PolicyLevel `json:"levels,omitempty"`
}

// PolicyResult is returned by GetPermissionPolicy.
type PolicyResult struct {
	Success bool    `json:"success"`
	Error   string  `json:"error,omitempty"`
	Policy  *Policy `json:"policy,omitempty"`
}

// AdminResult is returned by admin operations that produce no specific payload.
type AdminResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// CreateAPIKeyRequest contains parameters for creating an API key via the admin bridge.
type CreateAPIKeyRequest struct {
	// Name is the unique name for this API key.
	Name string `json:"name"`

	// Description is an optional human-readable description.
	Description string `json:"description,omitempty"`

	// APIKey is the key value to store (optional if APISecret is set).
	APIKey string `json:"api_key,omitempty"`

	// APISecret is the HMAC signing secret to store (optional if APIKey is set).
	APISecret string `json:"api_secret,omitempty"`
}

// CreateAPIKeyResult is returned by CreateAPIKey.
type CreateAPIKeyResult struct {
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
	ID           uint   `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	HasAPIKey    bool   `json:"has_api_key,omitempty"`
	HasAPISecret bool   `json:"has_api_secret,omitempty"`
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

	// Algorithm is the signing algorithm used (always "HMAC-SHA256").
	Algorithm string `json:"algorithm,omitempty"`

	// MessageLength is the length of the input message in bytes.
	MessageLength int `json:"message_length"`
}
