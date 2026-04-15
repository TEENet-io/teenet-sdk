// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

// Package sdk provides a Go client for TEENet consensus signing services.
//
// This SDK enables applications to request cryptographic signatures from TEENet's
// Trusted Execution Environment (TEE) consensus nodes. It supports both direct
// signing and M-of-N threshold voting scenarios, handling the complexity of
// multi-party signing automatically.
//
// Features:
//   - Direct signing for single-node scenarios
//   - Automatic M-of-N threshold voting support
//   - Multiple cryptographic curves (ED25519, SECP256K1, SECP256R1)
//   - Multiple signing protocols (ECDSA, Schnorr, EdDSA)
//   - Signature verification with automatic format detection
//   - Automatic polling for threshold voting completion
//
// Basic Usage:
//
//	client := sdk.NewClient("http://service-url:8089")
//	client.SetDefaultAppInstanceID("your-app-instance-id")
//	defer client.Close()
//
//	// Sign a message
//	result, err := client.Sign(ctx, []byte("message to sign"), "my-key")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//
//	// Verify a signature
//	valid, err := client.Verify(ctx, message, result.Signature, "my-key")
//
// For more examples, see the examples/ directory.
package sdk

import (
	"context"
	"errors"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/client"
)

// Client is a facade for the internal client implementation.
// It provides the public API for TEENet SDK.
type Client struct {
	impl *client.Client
}

var errNilClient = errors.New("teenet-sdk: client not initialized, use NewClient() or NewClientWithOptions()")

// checkInit returns an error if the Client is nil or uninitialized.
// Methods that return (T, error) use checkInit(). Methods that return void,
// string, or Duration use an inline nil guard and silently return a zero value
// instead — this ensures SetDefaultAppInstanceID, Close, InvalidateKeyCache,
// and getter methods never panic on a nil receiver.
func (c *Client) checkInit() error {
	if c == nil || c.impl == nil {
		return errNilClient
	}
	return nil
}

// NewClient creates a new SDK client with default settings.
//
// This is the recommended way to create a client. It uses sensible defaults:
//   - Request timeout: 30 seconds
//   - Pending wait timeout: 10 seconds
//
// The client is created in an uninitialized state. Call Init() to load
// APP_INSTANCE_ID from the environment (containers deployed by the App
// Lifecycle Manager have it injected automatically), or call
// SetDefaultAppInstanceID() to set it explicitly.
//
// Parameters:
//   - serviceURL: Base URL of the TEENet service (e.g., "http://localhost:8089")
//
// Returns:
//   - A new Client instance
//
// Example (deployed — APP_INSTANCE_ID is in env):
//
//	client := sdk.NewClient("http://localhost:8089")
//	client.Init()
//	defer client.Close()
//
// Example (local dev):
//
//	client := sdk.NewClient("http://localhost:8089")
//	client.SetDefaultAppInstanceID("your-app-instance-id")
//	defer client.Close()
func NewClient(serviceURL string) *Client {
	return &Client{
		impl: client.NewClient(serviceURL),
	}
}

// NewClientWithOptions creates a new SDK client with custom configuration options.
//
// Use this when you need to customize timeout values or other client behavior.
//
// Parameters:
//   - serviceURL: Base URL of the TEENet service
//   - opts: Optional configuration (nil for defaults)
//
// Returns:
//   - A new Client instance with the specified options
//
// Example:
//
//	opts := &sdk.ClientOptions{
//	    RequestTimeout:  45 * time.Second,
//	    PendingWaitTimeout: 10 * time.Second,
//	}
//	client := sdk.NewClientWithOptions("http://localhost:8089", opts)
func NewClientWithOptions(serviceURL string, opts *ClientOptions) *Client {
	return &Client{
		impl: client.NewClientWithOptions(serviceURL, opts),
	}
}

// Init initializes the client by attempting to load configuration from the environment.
//
// This method tries to read the APP_INSTANCE_ID environment variable and set it as the
// default instance ID. If the environment variable is not set, a warning is logged
// but no error is returned.
//
// Returns:
//   - Always returns nil (errors are logged as warnings)
//
// Example:
//
//	client := sdk.NewClient("http://localhost:8089")
//	client.Init() // Reads APP_INSTANCE_ID from environment
//	defer client.Close()
func (c *Client) Init() error {
	if err := c.checkInit(); err != nil {
		return err
	}
	return c.impl.Init()
}

// SetDefaultAppInstanceID sets the APP_INSTANCE_ID for signing operations.
//
// The APP_INSTANCE_ID identifies your application instance to the TEENet service
// and determines which key material is used for signing.
//
// When deployed via the App Lifecycle Manager, APP_INSTANCE_ID is automatically
// injected as an environment variable — use Init() instead.
//
// Parameters:
//   - appInstanceID: Your TEENet APP_INSTANCE_ID
//
// Example:
//
//	client.SetDefaultAppInstanceID("f5a8f44238cd6112b9f02f7f63a12533")
func (c *Client) SetDefaultAppInstanceID(appInstanceID string) {
	if c == nil || c.impl == nil {
		return
	}
	c.impl.SetDefaultAppInstanceID(appInstanceID)
}

// SetDefaultAppInstanceIDFromEnv loads the APP_INSTANCE_ID from the environment variable.
//
// Returns:
//   - Error if the APP_INSTANCE_ID environment variable is not set or empty
//
// Example:
//
//	if err := client.SetDefaultAppInstanceIDFromEnv(); err != nil {
//	    log.Fatal("APP_INSTANCE_ID not set in environment")
//	}
func (c *Client) SetDefaultAppInstanceIDFromEnv() error {
	if err := c.checkInit(); err != nil {
		return err
	}
	return c.impl.SetDefaultAppInstanceIDFromEnv()
}

// GetDefaultAppInstanceID returns the currently configured APP_INSTANCE_ID.
//
// Returns:
//   - The APP_INSTANCE_ID string, or empty string if not set
func (c *Client) GetDefaultAppInstanceID() string {
	if c == nil || c.impl == nil {
		return ""
	}
	return c.impl.GetDefaultAppInstanceID()
}

// Sign generates a cryptographic signature for a message using TEENet consensus.
//
// This method automatically handles both direct signing and M-of-N threshold voting
// scenarios based on the APP_INSTANCE_ID configuration. For voting flows, it waits until
// final signed/failed result (or timeout) so application code only needs one Sign call.
//
// Parameters:
//   - ctx: Context for the request
//   - message: The raw bytes to sign
//   - publicKeyName: Bound public key name to use for signing (required)
//
// Returns:
//   - SignResult: Contains the signature bytes and success status
//   - error: Non-nil if the signing operation failed
//
// Example (using specific generated key):
//
//	result, err := client.Sign(ctx, []byte("important message"), "my-key")
func (c *Client) Sign(ctx context.Context, message []byte, publicKeyName string, passkeyToken ...string) (*SignResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.Sign(ctx, message, publicKeyName, passkeyToken...)
}

// GetStatus retrieves voting status for a specific hash.
//
// This can be used to check whether a pending vote has reached threshold.
//
// Returns:
//   - VoteStatus: Current status and vote counts
//   - error: Error if the request fails
func (c *Client) GetStatus(ctx context.Context, hash string) (*VoteStatus, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.GetStatus(ctx, hash)
}

// ApprovalRequestInit starts a passkey approval request session.
// payload should match user-management-system approval init JSON body.
func (c *Client) ApprovalRequestInit(ctx context.Context, payload []byte, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ApprovalRequestInit(ctx, payload, approvalToken)
}

// PasskeyLoginOptions starts passkey login challenge generation.
func (c *Client) PasskeyLoginOptions(ctx context.Context) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.PasskeyLoginOptions(ctx)
}

// PasskeyLoginVerify verifies passkey assertion and stores returned bearer token in client.
func (c *Client) PasskeyLoginVerify(ctx context.Context, loginSessionID uint64, credential []byte) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.PasskeyLoginVerify(ctx, loginSessionID, credential)
}

// PasskeyLoginVerifyAs verifies passkey assertion AND confirms the verified PasskeyUserID
// matches expectedPasskeyUserID. Returns an error if the passkey belongs to a different user.
// Use this instead of PasskeyLoginVerify when you need to ensure the assertion comes from
// a specific user, not just any valid PasskeyUser in the system.
func (c *Client) PasskeyLoginVerifyAs(ctx context.Context, loginSessionID uint64, credential []byte, expectedPasskeyUserID uint) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.PasskeyLoginVerifyAs(ctx, loginSessionID, credential, expectedPasskeyUserID)
}

// PasskeyLoginWithCredential executes login options -> WebAuthn credential provider -> verify.
func (c *Client) PasskeyLoginWithCredential(ctx context.Context, getCredential PasskeyCredentialProvider) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.PasskeyLoginWithCredential(ctx, getCredential)
}

// GetMyRequests returns all approval requests initiated by the authenticated user.
func (c *Client) GetMyRequests(ctx context.Context, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.GetMyRequests(ctx, approvalToken)
}

// CancelRequest cancels a pending approval request initiated by the caller.
// Set idType to "session" (or "") to cancel by request session ID,
// or "task" to cancel a pending approval task by task ID.
func (c *Client) CancelRequest(ctx context.Context, id uint64, idType string, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.CancelRequest(ctx, id, idType, approvalToken)
}

// GetSignatureByTx retrieves a completed signature by its transaction ID.
func (c *Client) GetSignatureByTx(ctx context.Context, txID string, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.GetSignatureByTx(ctx, txID, approvalToken)
}

// ApprovalPending returns pending approvals accessible by the provided approval token.
func (c *Client) ApprovalPending(ctx context.Context, approvalToken string, filter *ApprovalPendingFilter) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ApprovalPending(ctx, approvalToken, filter)
}

// ApprovalRequestChallenge fetches WebAuthn assertion challenge options for request confirmation.
func (c *Client) ApprovalRequestChallenge(ctx context.Context, requestID uint64, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ApprovalRequestChallenge(ctx, requestID, approvalToken)
}

// ApprovalRequestConfirm submits passkey assertion and creates an approval task.
func (c *Client) ApprovalRequestConfirm(ctx context.Context, requestID uint64, payload []byte, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ApprovalRequestConfirm(ctx, requestID, payload, approvalToken)
}

// ApprovalRequestConfirmWithCredential executes challenge -> WebAuthn credential provider -> confirm.
func (c *Client) ApprovalRequestConfirmWithCredential(ctx context.Context, requestID uint64, getCredential PasskeyCredentialProvider, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ApprovalRequestConfirmWithCredential(ctx, requestID, getCredential, approvalToken)
}

// ApprovalActionChallenge fetches WebAuthn assertion challenge options for task action.
func (c *Client) ApprovalActionChallenge(ctx context.Context, taskID uint64, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ApprovalActionChallenge(ctx, taskID, approvalToken)
}

// ApprovalAction submits an APPROVE/REJECT action with passkey assertion.
func (c *Client) ApprovalAction(ctx context.Context, taskID uint64, payload []byte, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ApprovalAction(ctx, taskID, payload, approvalToken)
}

// ApprovalActionWithCredential executes challenge -> WebAuthn credential provider -> action.
func (c *Client) ApprovalActionWithCredential(ctx context.Context, taskID uint64, action string, getCredential PasskeyCredentialProvider, approvalToken string) (*ApprovalResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ApprovalActionWithCredential(ctx, taskID, action, getCredential, approvalToken)
}

// GetPublicKeys retrieves all bound public keys for the default APP_INSTANCE_ID.
func (c *Client) GetPublicKeys(ctx context.Context) ([]PublicKeyInfo, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.GetPublicKeys(ctx)
}

// InvalidateKeyCache clears the in-memory public key cache, forcing the next
// GetPublicKeys call to fetch fresh data from the TEENet service.
// Use this after key rotation to ensure stale cached keys are not used.
func (c *Client) InvalidateKeyCache() {
	if c == nil || c.impl == nil {
		return
	}
	c.impl.InvalidateKeyCache()
}

// Verify verifies a cryptographic signature against a message using a bound key name.
//
// Parameters:
//   - ctx: Context for the request
//   - message: The original message that was signed
//   - signature: The signature to verify (raw bytes)
//   - publicKeyName: Bound public key name to use for verification
//
// Returns:
//   - bool: true if the signature is valid
//   - error: Error if verification cannot be performed
//
// Example:
//
//	valid, err := client.Verify(ctx, message, signature, "my-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if valid {
//	    fmt.Println("Signature is valid")
//	}
func (c *Client) Verify(ctx context.Context, message, signature []byte, publicKeyName string) (bool, error) {
	if err := c.checkInit(); err != nil {
		return false, err
	}
	return c.impl.Verify(ctx, message, signature, publicKeyName)
}

// Close gracefully shuts down the client and releases resources.
//
// Returns:
//   - Always returns nil
//
// Example:
//
//	client := sdk.NewClient("http://localhost:8089")
//	defer client.Close()
func (c *Client) Close() error {
	if c == nil || c.impl == nil {
		return nil
	}
	return c.impl.Close()
}

// PasskeyRegistrationOptions begins WebAuthn registration for an invited user.
// Pass the returned Options to navigator.credentials.create() in the browser,
// then call PasskeyRegistrationVerify with the resulting credential.
func (c *Client) PasskeyRegistrationOptions(ctx context.Context, inviteToken string) (*PasskeyRegistrationOptionsResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.PasskeyRegistrationOptions(ctx, inviteToken)
}

// PasskeyRegistrationVerify completes WebAuthn registration.
// credential should be the JSON-serialized PublicKeyCredential from navigator.credentials.create().
func (c *Client) PasskeyRegistrationVerify(ctx context.Context, inviteToken string, credential interface{}) (*PasskeyRegistrationVerifyResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.PasskeyRegistrationVerify(ctx, inviteToken, credential)
}

// InvitePasskeyUser invites a new passkey user to the application.
//
// The returned PasskeyInviteResult contains a register_url that the invited
// user should visit to register their passkey device.
//
// Example:
//
//	result, err := client.InvitePasskeyUser(ctx, sdk.PasskeyInviteRequest{
//	    DisplayName:      "Alice",
//	    ExpiresInSeconds: 86400,
//	})
func (c *Client) InvitePasskeyUser(ctx context.Context, req PasskeyInviteRequest) (*PasskeyInviteResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.InvitePasskeyUser(ctx, req)
}

// ListPasskeyUsers returns registered passkey users for the application.
//
// page and limit are optional (pass 0 for server defaults).
func (c *Client) ListPasskeyUsers(ctx context.Context, page, limit int) (*PasskeyUsersResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ListPasskeyUsers(ctx, page, limit)
}

// DeletePasskeyUser removes a passkey user by their ID.
func (c *Client) DeletePasskeyUser(ctx context.Context, userID uint) (*AdminResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.DeletePasskeyUser(ctx, userID)
}

// ListAuditRecords returns audit records for the application.
//
// page and limit are optional (pass 0 for server defaults).
func (c *Client) ListAuditRecords(ctx context.Context, page, limit int) (*AuditRecordsResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.ListAuditRecords(ctx, page, limit)
}

// GetDeploymentLogs fetches container logs for the calling application from UMS.
//
// All filters in query are optional. The server defaults the time window to the
// last hour and caps it at 24 hours; Limit defaults to 200 and is capped at 500.
// The query is automatically scoped to this client's app_instance_id.
//
// Example:
//
//	res, err := client.GetDeploymentLogs(ctx, sdk.DeploymentLogsQuery{
//	    Level:   "error",
//	    Keyword: "panic",
//	    Limit:   100,
//	})
func (c *Client) GetDeploymentLogs(ctx context.Context, query DeploymentLogsQuery) (*DeploymentLogsResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.GetDeploymentLogs(ctx, query)
}

// UpsertPermissionPolicy creates or replaces the permission policy for a public key.
//
// Example:
//
//	result, err := client.UpsertPermissionPolicy(ctx, sdk.PolicyRequest{
//	    PublicKeyName:  "my-key",
//	    Enabled:        true,
//	    TimeoutSeconds: 3600,
//	    Levels: []sdk.PolicyLevel{
//	        {LevelIndex: 1, Threshold: 2, MemberIDs: []uint{1, 2, 3}},
//	    },
//	})
func (c *Client) UpsertPermissionPolicy(ctx context.Context, req PolicyRequest) (*AdminResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.UpsertPermissionPolicy(ctx, req)
}

// GetPermissionPolicy retrieves the permission policy for a named public key.
func (c *Client) GetPermissionPolicy(ctx context.Context, publicKeyName string) (*PolicyResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.GetPermissionPolicy(ctx, publicKeyName)
}

// DeletePermissionPolicy removes the permission policy for a named public key.
func (c *Client) DeletePermissionPolicy(ctx context.Context, publicKeyName string) (*AdminResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.DeletePermissionPolicy(ctx, publicKeyName)
}

// DeletePublicKey deletes a public key by name for the application.
func (c *Client) DeletePublicKey(ctx context.Context, keyName string) (*AdminResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.DeletePublicKey(ctx, keyName)
}

// CreateAPIKey creates a new API key entry via the admin bridge.
func (c *Client) CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.CreateAPIKey(ctx, req)
}

// DeleteAPIKey deletes an API key by name for the application.
func (c *Client) DeleteAPIKey(ctx context.Context, keyName string) (*AdminResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.DeleteAPIKey(ctx, keyName)
}

// GetServiceURL returns the TEENet service URL.
// This method is primarily for testing purposes.
func (c *Client) GetServiceURL() string {
	if c == nil || c.impl == nil {
		return ""
	}
	return c.impl.GetServiceURL()
}

// GetRequestTimeout returns the request timeout duration.
// This method is primarily for testing purposes.
func (c *Client) GetRequestTimeout() time.Duration {
	if c == nil || c.impl == nil {
		return 0
	}
	return c.impl.GetRequestTimeout()
}

// GetPendingWaitTimeout returns how long Sign waits for pending voting completion.
// This method is primarily for testing purposes.
func (c *Client) GetPendingWaitTimeout() time.Duration {
	if c == nil || c.impl == nil {
		return 0
	}
	return c.impl.GetPendingWaitTimeout()
}

// GenerateKey generates a key for a given (protocol, curve) combination.
//
// This is the sole key-generation entry point. Pick the row that matches
// your target chain or use case:
//
//	ProtocolEdDSA         + CurveED25519   → EdDSA (Ed25519) — Solana, SSH
//	ProtocolSchnorrBIP340 + CurveSECP256K1 → BIP-340 Schnorr — Bitcoin Taproot
//	ProtocolECDSA         + CurveSECP256K1 → ECDSA/secp256k1 — Bitcoin legacy, Ethereum
//	ProtocolECDSA         + CurveSECP256R1 → ECDSA/P-256 — WebAuthn, TLS
//	ProtocolSchnorr       + any curve      → generic Schnorr escape hatch
//
// ProtocolEdDSA only accepts CurveED25519. ProtocolSchnorrBIP340 only
// accepts CurveSECP256K1. Both route to the same Schnorr backend path.
//
// Parameters:
//   - ctx: Context for the request
//   - protocol: One of ProtocolEdDSA, ProtocolSchnorr, ProtocolECDSA
//   - curve: One of CurveED25519, CurveSECP256K1, CurveSECP256R1
//
// Returns:
//   - GenerateKeyResult: Contains the generated public key information
//   - error: Non-nil on invalid combination or backend failure
//
// Example:
//
//	// Bitcoin Taproot
//	result, err := client.GenerateKey(ctx, sdk.ProtocolSchnorrBIP340, sdk.CurveSECP256K1)
//
//	// Ed25519 / Solana
//	result, err := client.GenerateKey(ctx, sdk.ProtocolEdDSA, sdk.CurveED25519)
func (c *Client) GenerateKey(ctx context.Context, protocol, curve string) (*GenerateKeyResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.GenerateKey(ctx, protocol, curve)
}

// GetAPIKey retrieves an API key value by name from the TEENet service.
//
// This method queries the TEENet service to retrieve an API key that was previously
// stored in the TEE (Trusted Execution Environment). The API key must have been created
// with an API key value (not just a secret) for this operation to succeed.
//
// Parameters:
//   - ctx: Context for the request
//   - name: The name of the API key to retrieve
//
// Returns:
//   - APIKeyResult: Contains the retrieved API key value and metadata
//   - error: Non-nil if the retrieval fails
//
// Example:
//
//	result, err := client.GetAPIKey(ctx, "my-api-key")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("API Key: %s\n", result.APIKey)
func (c *Client) GetAPIKey(ctx context.Context, name string) (*APIKeyResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.GetAPIKey(ctx, name)
}

// SignWithAPISecret signs a message using an API secret stored in the TEE.
//
// This method signs a message using HMAC-SHA256 with an API secret that was previously
// stored in the TEE. The API secret never leaves the TEE, ensuring secure signing operations.
// The API key must have been created with an API secret (not just an API key) for this
// operation to succeed.
//
// Parameters:
//   - ctx: Context for the request
//   - name: The name of the API key/secret to use for signing
//   - message: The message bytes to sign
//
// Returns:
//   - APISignResult: Contains the HMAC-SHA256 signature and metadata
//   - error: Non-nil if the signing operation fails
//
// Example:
//
//	result, err := client.SignWithAPISecret(ctx, "my-api-key", []byte("important message"))
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Signature: %s\n", result.Signature)
func (c *Client) SignWithAPISecret(ctx context.Context, name string, message []byte) (*APISignResult, error) {
	if err := c.checkInit(); err != nil {
		return nil, err
	}
	return c.impl.SignWithAPISecret(ctx, name, message)
}
