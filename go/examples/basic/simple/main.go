// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

// Package main demonstrates basic signing and verification with TEENet SDK.
//
// This example shows:
//   - Creating a client and setting the app ID
//   - Getting public key information
//   - Signing a message
//   - Verifying the signature
//
// Usage:
//
//	go run examples/basic/simple/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	sdk "github.com/TEENet-io/teenet-sdk/go"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// Get configuration from environment or use placeholder values
	serviceURL := os.Getenv("SERVICE_URL")
	if serviceURL == "" {
		serviceURL = "http://localhost:8089" // Default for local development
	}

	appID := os.Getenv("APP_INSTANCE_ID")
	if appID == "" {
		log.Fatal("APP_INSTANCE_ID environment variable is required")
	}

	fmt.Println("TEENet SDK Simple Example")
	fmt.Println("=========================")
	fmt.Printf("Service URL: %s\n", serviceURL)
	fmt.Printf("App ID: %s\n\n", appID)

	// Create SDK client
	client := sdk.NewClient(serviceURL)
	defer client.Close()

	client.SetDefaultAppInstanceID(appID)

	// Get public key information
	fmt.Println("1. Get Public Keys")
	fmt.Println("-----------------")
	keys, err := client.GetPublicKeys(context.Background())
	if err != nil {
		log.Fatalf("Failed to get public keys: %v", err)
	}
	if len(keys) == 0 {
		log.Fatalf("No bound public keys found")
	}
	selectedKey := keys[0]
	pubKey := selectedKey.KeyData
	protocol := selectedKey.Protocol
	curve := selectedKey.Curve
	fmt.Printf("Public Key: %s\n", pubKey)
	fmt.Printf("Protocol: %s\n", protocol)
	fmt.Printf("Curve: %s\n\n", curve)
	keyName := selectedKey.Name

	// Sign a message
	fmt.Println("2. Sign Message")
	fmt.Println("---------------")
	message := []byte("Hello TEENet! " + time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Message: %s\n", string(message))

	// For ECDSA, the user is responsible for hashing the message before signing.
	// The TEE-DAO backend requires exactly 32 bytes (pre-hashed) for ECDSA.
	hashedMessage := crypto.Keccak256(message)
	result, err := client.Sign(context.Background(), hashedMessage, keyName)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	if !result.Success {
		log.Fatalf("Sign failed: %s", result.Error)
	}

	fmt.Printf("Signature: %x\n", result.Signature)
	if result.VotingInfo != nil {
		fmt.Printf("Voting: %d/%d (%s)\n",
			result.VotingInfo.CurrentVotes,
			result.VotingInfo.RequiredVotes,
			result.VotingInfo.Status)
	}
	fmt.Println()

	// Verify the signature
	fmt.Println("3. Verify Signature")
	fmt.Println("-------------------")
	valid, err := client.Verify(context.Background(), hashedMessage, result.Signature, keyName)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	if valid {
		fmt.Println("Signature is VALID")
	} else {
		fmt.Println("Signature is INVALID")
	}

	fmt.Println()
	fmt.Println("=========================")
	fmt.Println("Simple example completed!")
}
