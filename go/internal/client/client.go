// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

// Package sdk provides a Go client for TEENet signing services.
//
// This SDK enables applications to request cryptographic signatures from TEENet's
// Trusted Execution Environment (TEE) signing nodes. It supports both direct
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
// Basic Usage (deployed container — SERVICE_URL and APP_INSTANCE_ID are in env):
//
//	client := NewClient()
//	defer client.Close()
//
// Basic Usage (local dev):
//
//	client := NewClient("http://localhost:8089")
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

// Client is the main interface for interacting with TEENet signing services.
//
// A Client instance manages HTTP connections to the TEENet service and handles
// both direct signing and M-of-N threshold voting operations. It maintains configuration
// such as the default APP_INSTANCE_ID and timeout settings.
//
// The Client is safe for concurrent use, though typically one client per application
// is sufficient.
type Client struct {
	mu                 sync.RWMutex           // Protects defaultAppInstanceID and pkCache
	httpClient         *network.HTTPClient    // HTTP client for TEENet service communication
	serviceURL       string                 // Base URL of the TEENet service
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
// If serviceURL is omitted, the SERVICE_URL environment variable is used
// (automatically injected by the App Lifecycle Manager in deployed containers).
//
// Both SERVICE_URL and APP_INSTANCE_ID are read from environment variables
// automatically. Use SetDefaultAppInstanceID() to override.
//
// Example (deployed container — SERVICE_URL and APP_INSTANCE_ID are in env):
//
//	client := NewClient()
//	defer client.Close()
//
// Example (local dev):
//
//	client := NewClient("http://localhost:8089")
//	client.SetDefaultAppInstanceID("your-app-instance-id")
//	defer client.Close()
func NewClient(serviceURL ...string) *Client {
	return NewClientWithOptions(resolveServiceURL(serviceURL), nil)
}

// resolveServiceURL returns the first element of urls if provided,
// otherwise falls back to the SERVICE_URL environment variable.
func resolveServiceURL(urls []string) string {
	if len(urls) > 0 && urls[0] != "" {
		return urls[0]
	}
	return os.Getenv("SERVICE_URL")
}

// NewClientWithOptions creates a new SDK client with custom configuration options.
//
// Use this when you need to customize timeout values or other client behavior.
// Pass nil for opts to use default values.
//
// Parameters:
//   - serviceURL: Base URL of the TEENet service (falls back to SERVICE_URL env var if empty)
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
func NewClientWithOptions(serviceURL string, opts *types.ClientOptions) *Client {
	// Fall back to SERVICE_URL environment variable if not provided explicitly.
	if serviceURL == "" {
		serviceURL = os.Getenv("SERVICE_URL")
	}

	// Validate the URL scheme early to surface misconfiguration immediately
	// rather than producing confusing network errors on the first request.
	// Only http:// and https:// are accepted; anything else (e.g. a bare
	// "localhost:8089" with no scheme) would silently mis-route every request.
	if parsed, err := url.Parse(serviceURL); err != nil {
		log.Printf("[teenet-sdk] WARNING: serviceURL %q is not a valid URL: %v", serviceURL, err)
	} else if scheme := strings.ToLower(parsed.Scheme); scheme != "http" && scheme != "https" {
		log.Printf("[teenet-sdk] WARNING: serviceURL %q has scheme %q — only http:// and https:// are supported; "+
			"requests will fail. Use https:// in production to protect against network-level interception.", serviceURL, parsed.Scheme)
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

	c := &Client{
		httpClient:         network.NewHTTPClient(serviceURL, stdHTTPClient),
		serviceURL:       serviceURL,
		pkCache:            make(map[string]pkCacheEntry),
		requestTimeout:     requestTimeout,
		pendingWaitTimeout: pendingWaitTimeout,
		debug:              debug,
		keyCacheTTL:        keyCacheTTL,
	}

	// Auto-load APP_INSTANCE_ID from environment if available.
	if appInstanceID := os.Getenv("APP_INSTANCE_ID"); appInstanceID != "" {
		c.defaultAppInstanceID = appInstanceID
		c.debugf("APP_INSTANCE_ID loaded from environment: %s", appInstanceID)
	}

	return c
}

func (c *Client) debugf(format string, args ...interface{}) {
	if !c.debug {
		return
	}
	log.Printf("[teenet-sdk] "+format, args...)
}

// SetDefaultAppInstanceID sets the APP_INSTANCE_ID for signing operations.
//
// The APP_INSTANCE_ID identifies your application instance to the TEENet service
// and determines which key material is used for signing. This must be set before
// calling Sign(), GetPublicKeys(), or Verify().
//
// When deployed via the App Lifecycle Manager, APP_INSTANCE_ID is automatically
// injected as an environment variable and read during client construction.
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
// via environment variables. It's called automatically during client construction.
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

// GetServiceURL returns the TEENet service URL.
// This method is primarily for testing purposes.
func (c *Client) GetServiceURL() string {
	return c.serviceURL
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
// accepts CurveSECP256K1. ProtocolECDSA rejects CurveED25519.
//
// Example:
//
//	result, err := client.GenerateKey(ctx, sdk.ProtocolEdDSA, sdk.CurveED25519)
func (c *Client) GenerateKey(ctx context.Context, protocol, curve string) (*types.GenerateKeyResult, error) {
	// Resolve protocol to the backend identifier. EdDSA and SchnorrBIP340
	// are semantic aliases for Schnorr restricted to a specific curve —
	// the backend path is the same in both cases.
	var backendProtocol string
	switch protocol {
	case crypto.ProtocolEdDSA:
		if curve != crypto.CurveED25519 {
			return nil, fmt.Errorf("invalid curve '%s' for EdDSA protocol, only %s is supported",
				curve, crypto.CurveED25519)
		}
		backendProtocol = crypto.ProtocolSchnorr
	case crypto.ProtocolSchnorrBIP340:
		if curve != crypto.CurveSECP256K1 {
			return nil, fmt.Errorf("invalid curve '%s' for SchnorrBIP340 protocol, only %s is supported",
				curve, crypto.CurveSECP256K1)
		}
		backendProtocol = crypto.ProtocolSchnorr
	case crypto.ProtocolSchnorr:
		switch curve {
		case crypto.CurveED25519, crypto.CurveSECP256K1, crypto.CurveSECP256R1:
		default:
			return nil, fmt.Errorf("invalid curve '%s' for Schnorr protocol, supported: %s, %s, %s",
				curve, crypto.CurveED25519, crypto.CurveSECP256K1, crypto.CurveSECP256R1)
		}
		backendProtocol = crypto.ProtocolSchnorr
	case crypto.ProtocolECDSA:
		switch curve {
		case crypto.CurveSECP256K1, crypto.CurveSECP256R1:
		default:
			return nil, fmt.Errorf("invalid curve '%s' for ECDSA protocol, supported: %s, %s",
				curve, crypto.CurveSECP256K1, crypto.CurveSECP256R1)
		}
		backendProtocol = crypto.ProtocolECDSA
	default:
		return nil, fmt.Errorf("invalid protocol '%s', supported: %s, %s, %s, %s",
			protocol, crypto.ProtocolEdDSA, crypto.ProtocolSchnorrBIP340,
			crypto.ProtocolSchnorr, crypto.ProtocolECDSA)
	}
	return c.generateKey(ctx, curve, backendProtocol)
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
