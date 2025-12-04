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
//	client := types.NewClient("http://consensus-url:8089")
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
package client

import (
	"github.com/TEENet-io/teenet-sdk/internal/types"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/TEENet-io/teenet-sdk/internal/network"
)

// Client is the main interface for interacting with TEENet consensus signing services.
//
// A Client instance manages HTTP connections to the consensus service and handles
// both direct signing and M-of-N threshold voting operations. It maintains configuration
// such as the default App ID and timeout settings.
//
// The Client is safe for concurrent use, though typically one client per application
// is sufficient. A fixed-port callback server (port 19080) is created when the Client
// is initialized and reused for all signing operations.
type Client struct {
	httpClient      *network.HTTPClient     // HTTP client for consensus service communication
	consensusURL    string                  // Base URL of the consensus service
	defaultAppID    string                  // Default application ID for operations
	requestTimeout  time.Duration           // Timeout for HTTP requests (default: 30s)
	callbackTimeout time.Duration           // Timeout for waiting on voting callbacks (default: 60s)
	callbackServer  *network.CallbackServer // Fixed-port callback server for receiving signatures
}

// NewClient creates a new SDK client with default settings.
//
// This is the recommended way to create a client. It uses sensible defaults:
//   - Request timeout: 30 seconds
//   - Callback timeout: 60 seconds
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
//	opts := &types.types.ClientOptions{
//	    RequestTimeout:  45 * time.Second,
//	    CallbackTimeout: 120 * time.Second,
//	}
//	client := types.NewClientWithOptions("http://localhost:8089", opts)
func NewClientWithOptions(consensusURL string, opts *types.ClientOptions) *Client {
	// Set defaults
	requestTimeout := 30 * time.Second
	callbackTimeout := 60 * time.Second

	if opts != nil {
		if opts.RequestTimeout > 0 {
			requestTimeout = opts.RequestTimeout
		}
		if opts.CallbackTimeout > 0 {
			callbackTimeout = opts.CallbackTimeout
		}
	}

	// Create standard HTTP client
	stdHTTPClient := &http.Client{
		Timeout: requestTimeout,
	}

	// Create and start callback server
	callbackServer, err := network.NewCallbackServer()
	if err != nil {
		log.Printf("Warning: Failed to create callback server on port 19080: %v", err)
		log.Printf("Signing operations will fail until the port is available")
		// Don't return error - allow client creation to proceed
		// Sign() will return error if callback server is nil
	} else {
		if err := callbackServer.Start(); err != nil {
			log.Printf("Warning: Failed to start callback server: %v", err)
			callbackServer = nil
		} else {
			log.Printf("Callback server started successfully on port 19080")
		}
	}

	return &Client{
		httpClient:      network.NewHTTPClient(consensusURL, stdHTTPClient),
		consensusURL:    consensusURL,
		requestTimeout:  requestTimeout,
		callbackTimeout: callbackTimeout,
		callbackServer:  callbackServer,
	}
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
// GetPublicKey(), or Verify().
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
// This method stops the callback server and releases any other resources held
// by the client. It should always be called when the client is no longer needed.
//
// Returns:
//   - Always returns nil (errors are logged as warnings)
//
// Example:
//
//	client := types.NewClient("http://localhost:8089")
//	defer client.Close()
func (c *Client) Close() error {
	if c.callbackServer != nil {
		if err := c.callbackServer.Stop(); err != nil {
			log.Printf("Warning: Failed to stop callback server: %v", err)
		}
	}
	log.Printf("SDK client closed")
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

// GetCallbackTimeout returns the callback timeout duration.
// This method is primarily for testing purposes.
func (c *Client) GetCallbackTimeout() time.Duration {
	return c.callbackTimeout
}
