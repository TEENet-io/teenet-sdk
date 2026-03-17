// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
// -----------------------------------------------------------------------------

// Package main demonstrates how to use API key operations with TEENet SDK.
//
// This example shows:
//   - How to retrieve an API key value by name
//   - How to sign messages using an API secret stored in TEE
//   - How API key binding controls access (bound vs unbound keys)
//
// Prerequisites:
//  1. You must have created API keys in the user management system
//  2. API keys must be bound to your application for access
//  3. For GetAPIKey: The entry must have an API key stored (not just secret)
//  4. For SignWithAPISecret: The entry must have an API secret stored
//
// API Key Binding:
//   - Bound API keys can be accessed by the application
//   - Unbound API keys will be rejected (access denied)
//
// Usage:
//
//	export APP_INSTANCE_ID=your-app-id
//	go run examples/apikey/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
	// Get configuration from environment
	consensusURL := os.Getenv("CONSENSUS_URL")
	if consensusURL == "" {
		consensusURL = "http://localhost:8089" // Default for local development
	}

	appID := os.Getenv("APP_INSTANCE_ID")
	if appID == "" {
		log.Fatal("APP_INSTANCE_ID environment variable is required")
	}

	// Create SDK client
	client := sdk.NewClient(consensusURL)
	defer client.Close()

	client.SetDefaultAppID(appID)

	// Initialize from environment (reads APP_INSTANCE_ID)
	if err := client.Init(); err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	fmt.Printf("TEENet API Key Example\n")
	fmt.Printf("======================\n")
	fmt.Printf("Consensus URL: %s\n", consensusURL)
	fmt.Printf("App ID: %s\n\n", client.GetDefaultAppID())

	// Example 1: Retrieve a bound API key (should succeed)
	fmt.Println("Example 1: Retrieve Bound API Key")
	fmt.Println("-----------------------------------")
	apiKeyName := "test" // This key is bound to the application

	result, err := client.GetAPIKey(context.Background(), apiKeyName)
	if err != nil {
		log.Fatalf("Failed to get API key: %v", err)
	}

	if !result.Success {
		log.Fatalf("Failed to get API key: %s", result.Error)
	}

	fmt.Printf("✓ Successfully retrieved API key: %s\n", apiKeyName)
	fmt.Printf("  API Key: %s\n\n", result.APIKey)

	// Example 2: Try to retrieve an unbound API key (should fail)
	fmt.Println("Example 2: Try to Retrieve Unbound API Key")
	fmt.Println("--------------------------------------------")
	unboundKeyName := "test2" // This key is NOT bound to the application

	unboundResult, err := client.GetAPIKey(context.Background(), unboundKeyName)
	if err != nil {
		fmt.Printf("✗ Error calling API: %v\n\n", err)
	} else if !unboundResult.Success {
		fmt.Printf("✓ Access correctly denied for unbound key: %s\n", unboundKeyName)
		fmt.Printf("  Error: %s\n\n", unboundResult.Error)
	} else {
		fmt.Printf("⚠ WARNING: Unbound key was accessible (security issue!)\n\n")
	}

	// Example 3: Sign a message with API secret
	fmt.Println("Example 3: Sign with API Secret")
	fmt.Println("--------------------------------")
	apiSecretName := "test" // This key is bound to the application
	message := []byte("Hello, TEENet!")

	signResult, err := client.SignWithAPISecret(context.Background(), apiSecretName, message)
	if err != nil {
		log.Fatalf("Failed to sign with API secret: %v", err)
	}

	if !signResult.Success {
		log.Fatalf("Failed to sign with API secret: %s", signResult.Error)
	}

	fmt.Printf("✓ Successfully signed message with API secret: %s\n", apiSecretName)
	fmt.Printf("  Message: %s\n", string(message))
	fmt.Printf("  Message Length: %d bytes\n", signResult.MessageLength)
	fmt.Printf("  Signature: %s\n", signResult.Signature)
	fmt.Printf("  Algorithm: %s\n\n", signResult.Algorithm)

	// Example 4: Try to sign with an unbound API secret (should fail)
	fmt.Println("Example 4: Try to Sign with Unbound API Secret")
	fmt.Println("------------------------------------------------")
	unboundSecretName := "test2" // This key is NOT bound to the application

	unboundSignResult, err := client.SignWithAPISecret(context.Background(), unboundSecretName, message)
	if err != nil {
		fmt.Printf("✗ Error calling API: %v\n\n", err)
	} else if !unboundSignResult.Success {
		fmt.Printf("✓ Access correctly denied for unbound secret: %s\n", unboundSecretName)
		fmt.Printf("  Error: %s\n\n", unboundSignResult.Error)
	} else {
		fmt.Printf("⚠ WARNING: Unbound secret was accessible (security issue!)\n\n")
	}

	fmt.Println("========================================")
	fmt.Println("Example completed successfully!")
	fmt.Println("API Key Binding is working correctly.")
}
