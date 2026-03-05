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
//	client := types.NewClient("http://consensus-url:8089")
//	client.SetDefaultAppID("your-app-id")
//	defer client.Close()
//
//	// Sign a message
//	result, err := client.Sign([]byte("message to sign"), "my-key")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//
//	// Verify a signature
//	valid, err := client.Verify(message, result.Signature, "my-key")
//
// For more examples, see the examples/ directory.
package client

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/crypto"
	"github.com/TEENet-io/teenet-sdk/go/internal/network"
	"github.com/TEENet-io/teenet-sdk/go/internal/types"
)

const (
	defaultPendingWaitTimeout = 10 * time.Second
	defaultStatusPollInterval = 200 * time.Millisecond
)

// Client is the main interface for interacting with TEENet consensus signing services.
//
// A Client instance manages HTTP connections to the consensus service and handles
// both direct signing and M-of-N threshold voting operations. It maintains configuration
// such as the default App ID and timeout settings.
//
// The Client is safe for concurrent use, though typically one client per application
// is sufficient.
type Client struct {
	httpClient         *network.HTTPClient // HTTP client for consensus service communication
	consensusURL       string              // Base URL of the consensus service
	defaultAppID       string              // Default application ID for operations
	requestTimeout     time.Duration       // Timeout for HTTP requests (default: 30s)
	pendingWaitTimeout time.Duration       // Max wait in Sign for pending voting completion (default: 10s)
	debug              bool                // Enable verbose SDK trace logs
}

// NewClient creates a new SDK client with default settings.
//
// This is the recommended way to create a client. It uses sensible defaults:
//   - Request timeout: 30 seconds
//   - Pending wait timeout: 10 seconds
//
// The client is created in an uninitialized state. You must call SetDefaultAppID()
// before performing signing operations, or use Init() to load the App ID from
// the environment.
//
// Parameters:
//   - consensusURL: Base URL of the consensus service (e.g., "http://localhost:8089")
//
// Returns:
//   - A new Client instance
//
// Example:
//
//	client := types.NewClient("http://localhost:8089")
//	client.SetDefaultAppID("your-app-id")
//	defer client.Close()
func NewClient(consensusURL string) *Client {
	return NewClientWithOptions(consensusURL, nil)
}

// NewClientWithOptions creates a new SDK client with custom configuration options.
//
// Use this when you need to customize timeout values or other client behavior.
// Pass nil for opts to use default values.
//
// Parameters:
//   - consensusURL: Base URL of the consensus service
//   - opts: Optional configuration (nil for defaults)
//
// Returns:
//   - A new Client instance with the specified options
//
// Example:
//
//	opts := &types.ClientOptions{
//	    RequestTimeout:  45 * time.Second,
//	    PendingWaitTimeout: 10 * time.Second,
//	}
//	client := types.NewClientWithOptions("http://localhost:8089", opts)
func NewClientWithOptions(consensusURL string, opts *types.ClientOptions) *Client {
	// Set defaults
	requestTimeout := 30 * time.Second
	pendingWaitTimeout := defaultPendingWaitTimeout
	debug := false

	if opts != nil {
		if opts.RequestTimeout > 0 {
			requestTimeout = opts.RequestTimeout
		}
		if opts.PendingWaitTimeout > 0 {
			pendingWaitTimeout = opts.PendingWaitTimeout
		}
		debug = opts.Debug
	}

	// Create standard HTTP client
	stdHTTPClient := &http.Client{
		Timeout: requestTimeout,
	}

	return &Client{
		httpClient:         network.NewHTTPClient(consensusURL, stdHTTPClient),
		consensusURL:       consensusURL,
		requestTimeout:     requestTimeout,
		pendingWaitTimeout: pendingWaitTimeout,
		debug:              debug,
	}
}

func (c *Client) debugf(format string, args ...interface{}) {
	if !c.debug {
		return
	}
	log.Printf("[teenet-sdk] "+format, args...)
}

// Init initializes the client by attempting to load configuration from the environment.
//
// This method is optional. It tries to read the APP_ID environment variable and
// set it as the default App ID. If the environment variable is not set, a warning
// is logged but no error is returned.
//
// This is useful for applications that configure the App ID via environment variables
// rather than explicitly in code.
//
// Returns:
//   - Always returns nil (errors are logged as warnings)
//
// Example:
//
//	client := types.NewClient("http://localhost:8089")
//	client.Init() // Reads APP_ID from environment
//	defer client.Close()
func (c *Client) Init() error {
	// Try to read default App ID from environment
	if c.defaultAppID == "" {
		if err := c.SetDefaultAppIDFromEnv(); err != nil {
			// Not an error if APP_INSTANCE_ID env var is not set
			log.Printf("APP_INSTANCE_ID environment variable not set, you can set it later with SetDefaultAppID()")
		}
	}

	log.Printf("SDK client initialized successfully")
	return nil
}

// SetDefaultAppID sets the default application ID for signing operations.
//
// The App ID identifies your application to the consensus service and determines
// which key material is used for signing. This must be set before calling Sign(),
// GetPublicKeys(), or Verify().
//
// Parameters:
//   - appID: Your TEENet application ID (typically a UUID or hex string)
//
// Example:
//
//	client.SetDefaultAppID("f5a8f44238cd6112b9f02f7f63a12533")
func (c *Client) SetDefaultAppID(appID string) {
	c.defaultAppID = appID
	log.Printf("Default App ID set to: %s", appID)
}

// SetDefaultAppIDFromEnv loads the default App ID from the APP_ID environment variable.
//
// This is a convenience method for applications that configure the App ID via
// environment variables. It's called automatically by Init().
//
// Returns:
//   - Error if the APP_ID environment variable is not set or empty
//
// Example:
//
//	if err := client.SetDefaultAppIDFromEnv(); err != nil {
//	    log.Fatal("APP_ID not set in environment")
//	}
func (c *Client) SetDefaultAppIDFromEnv() error {
	appID := os.Getenv("APP_INSTANCE_ID")
	if appID == "" {
		return fmt.Errorf("APP_INSTANCE_ID environment variable is not set")
	}
	c.SetDefaultAppID(appID)
	return nil
}

// GetDefaultAppID returns the currently configured default application ID.
//
// Returns:
//   - The default App ID string, or empty string if not set
//
// Example:
//
//	appID := client.GetDefaultAppID()
//	if appID == "" {
//	    log.Println("No App ID configured")
//	}
func (c *Client) GetDefaultAppID() string {
	return c.defaultAppID
}

// Close gracefully shuts down the client and releases resources.
//
// This method releases resources held by the client. It should always be called
// when the client is no longer needed.
//
// Returns:
//   - Always returns nil (errors are logged as warnings)
//
// Example:
//
//	client := types.NewClient("http://localhost:8089")
//	defer client.Close()
func (c *Client) Close() error {
	return nil
}

// GetConsensusURL returns the consensus service URL.
// This method is primarily for testing purposes.
func (c *Client) GetConsensusURL() string {
	return c.consensusURL
}

// GetRequestTimeout returns the request timeout duration.
// This method is primarily for testing purposes.
func (c *Client) GetRequestTimeout() time.Duration {
	return c.requestTimeout
}

// GetPendingWaitTimeout returns the pending wait timeout duration.
// This method is primarily for testing purposes.
func (c *Client) GetPendingWaitTimeout() time.Duration {
	return c.pendingWaitTimeout
}

// GenerateSchnorrKey generates a new Schnorr signature key for the application.
//
// This method generates a key using the Schnorr signature protocol, which supports
// multiple elliptic curves. The key is generated via TEE consensus and stored in
// the user management system, associated with the current application.
//
// Supported curves:
//   - "ed25519": Edwards curve (recommended for EdDSA-style Schnorr)
//   - "secp256k1": Bitcoin/Ethereum curve
//   - "secp256r1": NIST P-256 curve
//
// Parameters:
//   - name: Human-readable name for the key (e.g., "signing-key-1")
//   - curve: Elliptic curve to use (see supported curves above)
//
// Returns:
//   - GenerateKeyResult: Contains the generated public key information
//   - error: Non-nil if key generation fails
//
// Example:
//
//	result, err := client.GenerateSchnorrKey("my-signing-key", "secp256k1")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated key ID: %d\n", result.PublicKey.ID)
//	fmt.Printf("Public key: %s\n", result.PublicKey.KeyData)
func (c *Client) GenerateSchnorrKey(curve string) (*types.GenerateKeyResult, error) {
	// Validate that we have an App ID
	if c.defaultAppID == "" {
		return nil, fmt.Errorf("no App ID configured, call SetDefaultAppID() first")
	}

	// Validate curve for Schnorr
	validCurves := map[string]bool{
		crypto.CurveED25519:   true,
		crypto.CurveSECP256K1: true,
		crypto.CurveSECP256R1: true,
	}
	if !validCurves[curve] {
		return nil, fmt.Errorf("invalid curve '%s' for Schnorr protocol, supported: %s, %s, %s", curve, crypto.CurveED25519, crypto.CurveSECP256K1, crypto.CurveSECP256R1)
	}

	log.Printf("Generating Schnorr key: curve=%s, app_id=%s", curve, c.defaultAppID)

	// Call HTTP API
	resp, err := c.httpClient.GenerateKey(c.defaultAppID, curve, crypto.ProtocolSchnorr)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Schnorr key: %w", err)
	}

	if !resp.Success {
		return &types.GenerateKeyResult{
			Success: false,
			Message: resp.Message,
		}, nil
	}

	// Convert network response to SDK result
	result := &types.GenerateKeyResult{
		Success: true,
		Message: resp.Message,
		PublicKey: &types.PublicKeyInfo{
			ID:                  resp.PublicKey.ID,
			Name:                resp.PublicKey.Name,
			KeyData:             resp.PublicKey.KeyData,
			Curve:               resp.PublicKey.Curve,
			Protocol:            resp.PublicKey.Protocol,
			Threshold:           resp.PublicKey.Threshold,
			ParticipantCount:    resp.PublicKey.ParticipantCount,
			MaxParticipantCount: resp.PublicKey.MaxParticipantCount,
			ApplicationID:       resp.PublicKey.ApplicationID,
			CreatedByInstanceID: resp.PublicKey.CreatedByInstanceID,
		},
	}

	log.Printf("Successfully generated Schnorr key (ID: %d)", result.PublicKey.ID)
	return result, nil
}

// GenerateECDSAKey generates a new ECDSA signature key for the application.
//
// This method generates a key using the ECDSA (Elliptic Curve Digital Signature Algorithm)
// protocol. The key is generated via TEE consensus and stored in the user management system,
// associated with the current application.
//
// Supported curves:
//   - "secp256k1": Bitcoin/Ethereum curve (recommended for blockchain applications)
//   - "secp256r1": NIST P-256 curve (recommended for general use)
//
// Note: ed25519 is NOT supported for ECDSA (use GenerateSchnorrKey for ed25519)
//
// Parameters:
//   - name: Human-readable name for the key (e.g., "signing-key-1")
//   - curve: Elliptic curve to use (see supported curves above)
//
// Returns:
//   - GenerateKeyResult: Contains the generated public key information
//   - error: Non-nil if key generation fails
//
// Example:
//
//	result, err := client.GenerateECDSAKey("my-ecdsa-key", "secp256k1")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated key ID: %d\n", result.PublicKey.ID)
//	fmt.Printf("Public key: %s\n", result.PublicKey.KeyData)
func (c *Client) GenerateECDSAKey(curve string) (*types.GenerateKeyResult, error) {
	// Validate that we have an App ID
	if c.defaultAppID == "" {
		return nil, fmt.Errorf("no App ID configured, call SetDefaultAppID() first")
	}

	// Validate curve for ECDSA
	validCurves := map[string]bool{
		crypto.CurveSECP256K1: true,
		crypto.CurveSECP256R1: true,
	}
	if !validCurves[curve] {
		return nil, fmt.Errorf("invalid curve '%s' for ECDSA protocol, supported: %s, %s", curve, crypto.CurveSECP256K1, crypto.CurveSECP256R1)
	}

	log.Printf("Generating ECDSA key: curve=%s, app_id=%s", curve, c.defaultAppID)

	// Call HTTP API
	resp, err := c.httpClient.GenerateKey(c.defaultAppID, curve, crypto.ProtocolECDSA)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	if !resp.Success {
		return &types.GenerateKeyResult{
			Success: false,
			Message: resp.Message,
		}, nil
	}

	// Convert network response to SDK result
	result := &types.GenerateKeyResult{
		Success: true,
		Message: resp.Message,
		PublicKey: &types.PublicKeyInfo{
			ID:                  resp.PublicKey.ID,
			Name:                resp.PublicKey.Name,
			KeyData:             resp.PublicKey.KeyData,
			Curve:               resp.PublicKey.Curve,
			Protocol:            resp.PublicKey.Protocol,
			Threshold:           resp.PublicKey.Threshold,
			ParticipantCount:    resp.PublicKey.ParticipantCount,
			MaxParticipantCount: resp.PublicKey.MaxParticipantCount,
			ApplicationID:       resp.PublicKey.ApplicationID,
			CreatedByInstanceID: resp.PublicKey.CreatedByInstanceID,
		},
	}

	log.Printf("Successfully generated ECDSA key (ID: %d)", result.PublicKey.ID)
	return result, nil
}

// GetAPIKey retrieves an API key value by name from the consensus service.
//
// This method queries the consensus service to retrieve an API key that was previously
// stored in the TEE (Trusted Execution Environment). The API key must have been created
// with an API key value (not just a secret) for this operation to succeed.
//
// Parameters:
//   - name: The name of the API key to retrieve
//
// Returns:
//   - APIKeyResult: Contains the retrieved API key value and metadata
//   - error: Non-nil if the retrieval fails
//
// Example:
//
//	result, err := client.GetAPIKey("my-api-key")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("API Key: %s\n", result.APIKey)
func (c *Client) GetAPIKey(name string) (*types.APIKeyResult, error) {
	// Validate that we have an App ID
	if c.defaultAppID == "" {
		return nil, fmt.Errorf("no App ID configured, call SetDefaultAppID() first")
	}

	// Validate name
	if name == "" {
		return nil, fmt.Errorf("API key name cannot be empty")
	}

	log.Printf("Retrieving API key: name=%s, app_id=%s", name, c.defaultAppID)

	// Call HTTP API
	resp, err := c.httpClient.GetAPIKey(c.defaultAppID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	if !resp.Success {
		return &types.APIKeyResult{
			Success:       false,
			Error:         resp.Error,
			AppInstanceID: c.defaultAppID,
			Name:          name,
		}, nil
	}

	// Convert network response to SDK result
	result := &types.APIKeyResult{
		Success:       true,
		AppInstanceID: resp.AppInstanceID,
		Name:          resp.Name,
		APIKey:        resp.APIKey,
	}

	log.Printf("Successfully retrieved API key: name=%s", name)
	return result, nil
}

// SignWithAPISecret signs a message using an API secret stored in the TEE.
//
// This method signs a message using HMAC-SHA256 with an API secret that was previously
// stored in the TEE. The API secret never leaves the TEE, ensuring secure signing operations.
// The API key must have been created with an API secret (not just an API key) for this
// operation to succeed.
//
// Parameters:
//   - name: The name of the API key/secret to use for signing
//   - message: The message bytes to sign
//
// Returns:
//   - APISignResult: Contains the HMAC-SHA256 signature and metadata
//   - error: Non-nil if the signing operation fails
//
// Example:
//
//	result, err := client.SignWithAPISecret("my-api-key", []byte("important message"))
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Signature: %s\n", result.Signature)
func (c *Client) SignWithAPISecret(name string, message []byte) (*types.APISignResult, error) {
	// Validate that we have an App ID
	if c.defaultAppID == "" {
		return nil, fmt.Errorf("no App ID configured, call SetDefaultAppID() first")
	}

	// Validate name
	if name == "" {
		return nil, fmt.Errorf("API key name cannot be empty")
	}

	// Validate message
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	log.Printf("Signing with API secret: name=%s, app_id=%s, message_len=%d", name, c.defaultAppID, len(message))

	// Call HTTP API
	resp, err := c.httpClient.SignWithAPISecret(c.defaultAppID, name, message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with API secret: %w", err)
	}

	if !resp.Success {
		return &types.APISignResult{
			Success:       false,
			Error:         resp.Error,
			AppInstanceID: c.defaultAppID,
			Name:          name,
			MessageLength: len(message),
		}, nil
	}

	// Convert network response to SDK result
	result := &types.APISignResult{
		Success:       true,
		AppInstanceID: resp.AppInstanceID,
		Name:          resp.Name,
		Signature:     resp.Signature,
		Algorithm:     resp.Algorithm,
		MessageLength: resp.MessageLength,
	}

	log.Printf("Successfully signed message with API secret: name=%s, signature_len=%d", name, len(result.Signature))
	return result, nil
}
