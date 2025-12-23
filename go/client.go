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
//   - Asynchronous callback handling for voting scenarios
//
// Basic Usage:
//
//	client := sdk.NewClient("http://consensus-url:8089")
//	client.SetDefaultAppID("your-app-id")
//	defer client.Close()
//
//	// Sign a message
//	result, err := client.Sign([]byte("message to sign"))
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//
//	// Verify a signature
//	valid, err := client.Verify(message, result.Signature)
//
// For more examples, see the examples/ directory.
package sdk

import (
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/client"
)

// Client is a facade for the internal client implementation.
// It provides the public API for TEENet SDK.
type Client struct {
	impl *client.Client
}

// NewClient creates a new SDK client with default settings.
//
// This is the recommended way to create a client. It uses sensible defaults:
//   - Request timeout: 30 seconds
//   - Callback timeout: 60 seconds
//
// Parameters:
//   - consensusURL: Base URL of the consensus service (e.g., "http://localhost:8089")
//
// Returns:
//   - A new Client instance
//
// Example:
//
//	client := sdk.NewClient("http://localhost:8089")
//	client.SetDefaultAppID("your-app-id")
//	defer client.Close()
func NewClient(consensusURL string) *Client {
	return &Client{
		impl: client.NewClient(consensusURL),
	}
}

// NewClientWithOptions creates a new SDK client with custom configuration options.
//
// Use this when you need to customize timeout values or other client behavior.
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
//	opts := &sdk.ClientOptions{
//	    RequestTimeout:  45 * time.Second,
//	    CallbackTimeout: 120 * time.Second,
//	}
//	client := sdk.NewClientWithOptions("http://localhost:8089", opts)
func NewClientWithOptions(consensusURL string, opts *ClientOptions) *Client {
	return &Client{
		impl: client.NewClientWithOptions(consensusURL, opts),
	}
}

// Init initializes the client by attempting to load configuration from the environment.
//
// This method tries to read the APP_INSTANCE_ID environment variable and set it as the
// default App ID. If the environment variable is not set, a warning is logged
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
	return c.impl.Init()
}

// SetDefaultAppID sets the default application ID for signing operations.
//
// The App ID identifies your application to the consensus service and determines
// which key material is used for signing.
//
// Parameters:
//   - appID: Your TEENet application ID
//
// Example:
//
//	client.SetDefaultAppID("f5a8f44238cd6112b9f02f7f63a12533")
func (c *Client) SetDefaultAppID(appID string) {
	c.impl.SetDefaultAppID(appID)
}

// SetDefaultAppIDFromEnv loads the default App ID from the APP_INSTANCE_ID environment variable.
//
// Returns:
//   - Error if the APP_INSTANCE_ID environment variable is not set or empty
//
// Example:
//
//	if err := client.SetDefaultAppIDFromEnv(); err != nil {
//	    log.Fatal("APP_INSTANCE_ID not set in environment")
//	}
func (c *Client) SetDefaultAppIDFromEnv() error {
	return c.impl.SetDefaultAppIDFromEnv()
}

// GetDefaultAppID returns the currently configured default application ID.
//
// Returns:
//   - The default App ID string, or empty string if not set
func (c *Client) GetDefaultAppID() string {
	return c.impl.GetDefaultAppID()
}

// Sign generates a cryptographic signature for a message using TEENet consensus.
//
// This method automatically handles both direct signing and M-of-N threshold voting
// scenarios based on the App ID configuration.
//
// Parameters:
//   - message: The raw bytes to sign
//   - publicKey: Optional public key bytes. If not provided, uses the default key.
//
// Returns:
//   - SignResult: Contains the signature bytes and success status
//   - error: Non-nil if the signing operation failed
//
// Example (using default key):
//
//	result, err := client.Sign([]byte("important message"))
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Signature: %x\n", result.Signature)
//
// Example (using specific generated key):
//
//	keyResult, _ := client.GenerateSchnorrKey("my-key", sdk.CurveSECP256K1)
//	pubKeyBytes, _ := hex.DecodeString(strings.TrimPrefix(keyResult.PublicKey.KeyData, "0x"))
//	result, err := client.Sign([]byte("important message"), pubKeyBytes)
func (c *Client) Sign(message []byte, publicKey ...[]byte) (*SignResult, error) {
	return c.impl.Sign(message, publicKey...)
}

// GetPublicKey retrieves the public key information for the default App ID.
//
// Returns:
//   - publicKey: Hex-encoded public key
//   - protocol: Protocol name (e.g., "ECDSA", "Schnorr")
//   - curve: Curve name (e.g., "SECP256K1", "ED25519")
//   - err: Error if the request fails
//
// Example:
//
//	pubKey, protocol, curve, err := client.GetPublicKey()
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) GetPublicKey() (publicKey, protocol, curve string, err error) {
	return c.impl.GetPublicKey()
}

// Verify verifies a cryptographic signature against a message.
//
// This method automatically retrieves the public key and verifies the signature
// using the appropriate cryptographic algorithm.
//
// Parameters:
//   - message: The original message that was signed
//   - signature: The signature to verify (raw bytes)
//
// Returns:
//   - bool: true if the signature is valid
//   - error: Error if verification cannot be performed
//
// Example:
//
//	valid, err := client.Verify(message, signature)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if valid {
//	    fmt.Println("Signature is valid")
//	}
func (c *Client) Verify(message, signature []byte) (bool, error) {
	return c.impl.Verify(message, signature)
}

// VerifyWithPublicKey verifies a cryptographic signature against a message using a specific public key.
//
// This method verifies the signature using the provided public key, protocol, and curve.
// The verification is performed locally without contacting the consensus service.
//
// Parameters:
//   - message: The original message that was signed (raw bytes)
//   - signature: The signature to verify (raw bytes)
//   - publicKey: The public key to use for verification (raw bytes)
//   - protocol: The signature protocol (e.g., "ecdsa", "schnorr")
//   - curve: The elliptic curve (e.g., "secp256k1", "ed25519", "secp256r1")
//
// Returns:
//   - bool: true if the signature is valid
//   - error: Error if verification cannot be performed
//
// Example:
//
//	// Verify signature with Schnorr ED25519
//	valid, err := client.VerifyWithPublicKey(message, signature, publicKeyBytes, sdk.ProtocolSchnorr, sdk.CurveED25519)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify signature with ECDSA secp256k1
//	valid, err := client.VerifyWithPublicKey(message, signature, publicKeyBytes, sdk.ProtocolECDSA, sdk.CurveSECP256K1)
func (c *Client) VerifyWithPublicKey(message, signature, publicKey []byte, protocol, curve string) (bool, error) {
	return c.impl.VerifyWithPublicKey(message, signature, publicKey, protocol, curve)
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
	return c.impl.Close()
}

// GetConsensusURL returns the consensus service URL.
// This method is primarily for testing purposes.
func (c *Client) GetConsensusURL() string {
	return c.impl.GetConsensusURL()
}

// GetRequestTimeout returns the request timeout duration.
// This method is primarily for testing purposes.
func (c *Client) GetRequestTimeout() time.Duration {
	return c.impl.GetRequestTimeout()
}

// GetCallbackTimeout returns the callback timeout duration.
// This method is primarily for testing purposes.
func (c *Client) GetCallbackTimeout() time.Duration {
	return c.impl.GetCallbackTimeout()
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
//   - curve: Elliptic curve to use (see supported curves above)
//
// Returns:
//   - GenerateKeyResult: Contains the generated public key information
//   - error: Non-nil if key generation fails
//
// Example:
//
//	result, err := client.GenerateSchnorrKey("secp256k1")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated key ID: %d\n", result.PublicKey.ID)
//	fmt.Printf("Public key: %s\n", result.PublicKey.KeyData)
func (c *Client) GenerateSchnorrKey(curve string) (*GenerateKeyResult, error) {
	return c.impl.GenerateSchnorrKey(curve)
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
//   - curve: Elliptic curve to use (see supported curves above)
//
// Returns:
//   - GenerateKeyResult: Contains the generated public key information
//   - error: Non-nil if key generation fails
//
// Example:
//
//	result, err := client.GenerateECDSAKey("secp256k1")
//	if err != nil || !result.Success {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated key ID: %d\n", result.PublicKey.ID)
//	fmt.Printf("Public key: %s\n", result.PublicKey.KeyData)
func (c *Client) GenerateECDSAKey(curve string) (*GenerateKeyResult, error) {
	return c.impl.GenerateECDSAKey(curve)
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
func (c *Client) GetAPIKey(name string) (*APIKeyResult, error) {
	return c.impl.GetAPIKey(name)
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
func (c *Client) SignWithAPISecret(name string, message []byte) (*APISignResult, error) {
	return c.impl.SignWithAPISecret(name, message)
}
