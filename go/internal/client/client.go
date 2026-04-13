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
//	client := types.NewClient("http://consensus-url:8089")
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
package client

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/crypto"
	"github.com/TEENet-io/teenet-sdk/go/internal/network"
	"github.com/TEENet-io/teenet-sdk/go/internal/types"
	"golang.org/x/sync/singleflight"
)

const (
	defaultPendingWaitTimeout = 10 * time.Second
	defaultStatusPollInterval = 200 * time.Millisecond
)

// Client is the main interface for interacting with TEENet consensus signing services.
//
// A Client instance manages HTTP connections to the consensus service and handles
// both direct signing and M-of-N threshold voting operations. It maintains configuration
// such as the default APP_INSTANCE_ID and timeout settings.
//
// The Client is safe for concurrent use, though typically one client per application
// is sufficient.
type Client struct {
	mu                 sync.RWMutex           // Protects defaultAppInstanceID and pkCache
	httpClient         *network.HTTPClient    // HTTP client for consensus service communication
	consensusURL       string                 // Base URL of the consensus service
	defaultAppInstanceID string                 // Default APP_INSTANCE_ID for operations
	pkCache              map[string]pkCacheEntry // Public key cache keyed by APP_INSTANCE_ID
	pkGroup            singleflight.Group     // Deduplicates concurrent GetPublicKeys calls
	requestTimeout     time.Duration          // Timeout for HTTP requests (default: 30s)
	pendingWaitTimeout time.Duration          // Max wait in Sign for pending voting completion (default: 10s)
	debug              bool                   // Enable verbose SDK trace logs
	keyCacheTTL        time.Duration          // TTL for public key cache (default: 60s, -1 to disable)
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
//   - consensusURL: Base URL of the consensus service (e.g., "http://localhost:8089")
//
// Returns:
//   - A new Client instance
//
// Example:
//
//	client := types.NewClient("http://localhost:8089")
//	client.SetDefaultAppInstanceID("your-app-instance-id")
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
	// Validate the URL scheme early to surface misconfiguration immediately
	// rather than producing confusing network errors on the first request.
	// Only http:// and https:// are accepted; anything else (e.g. a bare
	// "localhost:8089" with no scheme) would silently mis-route every request.
	if parsed, err := url.Parse(consensusURL); err != nil {
		log.Printf("[teenet-sdk] WARNING: consensusURL %q is not a valid URL: %v", consensusURL, err)
	} else if scheme := strings.ToLower(parsed.Scheme); scheme != "http" && scheme != "https" {
		log.Printf("[teenet-sdk] WARNING: consensusURL %q has scheme %q — only http:// and https:// are supported; "+
			"requests will fail. Use https:// in production to protect against network-level interception.", consensusURL, parsed.Scheme)
	}

	// Set defaults
	requestTimeout := 30 * time.Second
	pendingWaitTimeout := defaultPendingWaitTimeout
	debug := false
	keyCacheTTL := 60 * time.Second

	if opts != nil {
		if opts.RequestTimeout > 0 {
			requestTimeout = opts.RequestTimeout
		}
		if opts.PendingWaitTimeout > 0 {
			pendingWaitTimeout = opts.PendingWaitTimeout
		}
		debug = opts.Debug
		if opts.KeyCacheTTL != 0 {
			keyCacheTTL = opts.KeyCacheTTL
		}
	}

	// Create standard HTTP client
	stdHTTPClient := &http.Client{
		Timeout: requestTimeout,
	}

	return &Client{
		httpClient:         network.NewHTTPClient(consensusURL, stdHTTPClient),
		consensusURL:       consensusURL,
		pkCache:            make(map[string]pkCacheEntry),
		requestTimeout:     requestTimeout,
		pendingWaitTimeout: pendingWaitTimeout,
		debug:              debug,
		keyCacheTTL:        keyCacheTTL,
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
// This method tries to read the APP_INSTANCE_ID environment variable
// and set it as the default instance ID. If the environment variable is not set,
// a warning is logged but no error is returned.
//
// This is useful for containers deployed by the App Lifecycle Manager, which
// automatically injects APP_INSTANCE_ID and CONSENSUS_URL.
//
// Returns:
//   - Always returns nil (errors are logged as warnings)
//
// Example:
//
//	client := types.NewClient("http://localhost:8089")
//	client.Init() // Reads APP_INSTANCE_ID from environment
//	defer client.Close()
func (c *Client) Init() error {
	// Try to read APP_INSTANCE_ID from environment
	c.mu.RLock()
	appInstanceID := c.defaultAppInstanceID
	c.mu.RUnlock()

	if appInstanceID == "" {
		if err := c.SetDefaultAppInstanceIDFromEnv(); err != nil {
			// Not an error if APP_INSTANCE_ID env var is not set
			c.debugf("APP_INSTANCE_ID environment variable not set, you can set it later with SetDefaultAppInstanceID()")
		}
	}

	c.debugf("SDK client initialized successfully")
	return nil
}

// SetDefaultAppInstanceID sets the APP_INSTANCE_ID for signing operations.
//
// The APP_INSTANCE_ID identifies your application instance to the consensus service
// and determines which key material is used for signing. This must be set before
// calling Sign(), GetPublicKeys(), or Verify().
//
// When deployed via the App Lifecycle Manager, APP_INSTANCE_ID is automatically
// injected as an environment variable — use Init() instead.
//
// Parameters:
//   - appInstanceID: Your TEENet APP_INSTANCE_ID (typically a 32-character hex string)
//
// Example:
//
//	client.SetDefaultAppInstanceID("f5a8f44238cd6112b9f02f7f63a12533")
func (c *Client) SetDefaultAppInstanceID(appInstanceID string) {
	c.mu.Lock()
	c.defaultAppInstanceID = appInstanceID
	c.mu.Unlock()
	c.debugf("Default APP_INSTANCE_ID set to: %s", appInstanceID)
}

// SetDefaultAppInstanceIDFromEnv loads the APP_INSTANCE_ID from the environment variable.
//
// This is a convenience method for applications that configure the APP_INSTANCE_ID
// via environment variables. It's called automatically by Init().
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
	appInstanceID := os.Getenv("APP_INSTANCE_ID")
	if appInstanceID == "" {
		return fmt.Errorf("APP_INSTANCE_ID environment variable is not set")
	}
	c.SetDefaultAppInstanceID(appInstanceID)
	return nil
}

// GetDefaultAppInstanceID returns the currently configured APP_INSTANCE_ID.
//
// Returns:
//   - The APP_INSTANCE_ID string, or empty string if not set
//
// Example:
//
//	appInstanceID := client.GetDefaultAppInstanceID()
//	if appInstanceID == "" {
//	    log.Println("No APP_INSTANCE_ID configured")
//	}
func (c *Client) GetDefaultAppInstanceID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.defaultAppInstanceID
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
	c.httpClient.CloseIdleConnections()
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

// generateKey calls the HTTP API to generate a key and converts the response.
func (c *Client) generateKey(ctx context.Context, curve, protocol string) (*types.GenerateKeyResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}

	c.debugf("Generating %s key: curve=%s, app_id=%s", protocol, curve, appID)
	resp, err := c.httpClient.GenerateKey(ctx, appID, curve, protocol)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", protocol, err)
	}
	if !resp.Success {
		return &types.GenerateKeyResult{Success: false, Message: resp.Message}, nil
	}
	pubKey, err := convertJSON[types.PublicKeyInfo](resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode generated key: %w", err)
	}
	c.debugf("Successfully generated %s key (ID: %d)", protocol, pubKey.ID)
	return &types.GenerateKeyResult{Success: true, Message: resp.Message, PublicKey: pubKey}, nil
}

// GenerateSchnorrKey generates a new Schnorr signature key for the application.
//
// Supported curves: "ed25519", "secp256k1", "secp256r1"
func (c *Client) GenerateSchnorrKey(ctx context.Context, curve string) (*types.GenerateKeyResult, error) {
	validCurves := map[string]bool{
		crypto.CurveED25519: true, crypto.CurveSECP256K1: true, crypto.CurveSECP256R1: true,
	}
	if !validCurves[curve] {
		return nil, fmt.Errorf("invalid curve '%s' for Schnorr protocol, supported: %s, %s, %s",
			curve, crypto.CurveED25519, crypto.CurveSECP256K1, crypto.CurveSECP256R1)
	}
	return c.generateKey(ctx, curve, crypto.ProtocolSchnorr)
}

// GenerateECDSAKey generates a new ECDSA signature key for the application.
//
// Supported curves: "secp256k1", "secp256r1"
// Note: ed25519 is NOT supported for ECDSA (use GenerateSchnorrKey).
func (c *Client) GenerateECDSAKey(ctx context.Context, curve string) (*types.GenerateKeyResult, error) {
	validCurves := map[string]bool{
		crypto.CurveSECP256K1: true, crypto.CurveSECP256R1: true,
	}
	if !validCurves[curve] {
		return nil, fmt.Errorf("invalid curve '%s' for ECDSA protocol, supported: %s, %s",
			curve, crypto.CurveSECP256K1, crypto.CurveSECP256R1)
	}
	return c.generateKey(ctx, curve, crypto.ProtocolECDSA)
}

// GetAPIKey retrieves an API key value by name from the consensus service.
//
// This method queries the consensus service to retrieve an API key that was previously
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
func (c *Client) GetAPIKey(ctx context.Context, name string) (*types.APIKeyResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}

	// Validate name
	if name == "" {
		return nil, fmt.Errorf("API key name cannot be empty")
	}

	c.debugf("Retrieving API key: name=%s, app_id=%s", name, appID)

	// Call HTTP API
	resp, err := c.httpClient.GetAPIKey(ctx, appID, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	if !resp.Success {
		return &types.APIKeyResult{
			Success:       false,
			Error:         resp.Error,
			AppInstanceID: appID,
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

	c.debugf("Successfully retrieved API key: name=%s", name)
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
func (c *Client) SignWithAPISecret(ctx context.Context, name string, message []byte) (*types.APISignResult, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}

	// Validate name
	if name == "" {
		return nil, fmt.Errorf("API key name cannot be empty")
	}

	// Validate message
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	c.debugf("Signing with API secret: name=%s, app_id=%s, message_len=%d", name, appID, len(message))

	// Call HTTP API
	resp, err := c.httpClient.SignWithAPISecret(ctx, appID, name, message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with API secret: %w", err)
	}

	if !resp.Success {
		return &types.APISignResult{
			Success:       false,
			Error:         resp.Error,
			AppInstanceID: appID,
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

	c.debugf("Successfully signed message with API secret: name=%s, signature_len=%d", name, len(result.Signature))
	return result, nil
}
