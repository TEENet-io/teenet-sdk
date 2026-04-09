// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

// Example: Generate cryptographic keys using TEENet SDK
//
// This example demonstrates how to generate Schnorr and ECDSA keys for your
// application using the TEENet SDK. Generated keys are stored in the user
// management system and can be used for signing operations.
//
// Usage:
//   export APP_INSTANCE_ID="your-app-instance-id"
//   go run main.go

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"crypto/sha256"

	sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
	// Get consensus URL from environment or use default
	consensusURL := os.Getenv("CONSENSUS_URL")
	if consensusURL == "" {
		consensusURL = "http://localhost:8089" // Default for local development
	}

	// Get app ID from environment
	appID := os.Getenv("APP_INSTANCE_ID")
	if appID == "" {
		log.Fatal("APP_INSTANCE_ID environment variable is required")
	}

	// Create SDK client with extended timeout for key generation
	// ECDSA key generation requires multi-party DKG which can take 1-2 minutes
	opts := &sdk.ClientOptions{
		RequestTimeout:     120 * time.Second, // 2 minutes for key generation
		PendingWaitTimeout: 15 * time.Second,  // wait for voting completion in sign flow
	}
	client := sdk.NewClientWithOptions(consensusURL, opts)
	defer client.Close()

	client.SetDefaultAppInstanceID(appID)

	// Initialize client (loads APP_INSTANCE_ID from environment)
	if err := client.Init(); err != nil {
		log.Fatal("Failed to initialize client:", err)
	}

	fmt.Println("=== TEENet Key Generation and Signing Example ===")
	fmt.Printf("Consensus URL: %s\n", consensusURL)
	fmt.Printf("App Instance ID: %s\n\n", client.GetDefaultAppInstanceID())

	// Example 1: Generate a Schnorr key with ed25519 curve
	fmt.Println("\n📝 Generating Schnorr key (ed25519)...")
	schnorrResult, err := client.GenerateSchnorrKey(context.Background(), sdk.CurveED25519)
	if err != nil {
		log.Fatal("Failed to generate ed25519 key:", err)
	}

	if !schnorrResult.Success {
		log.Fatal("ed25519 key generation failed:", schnorrResult.Message)
	}

	fmt.Println("✅ Schnorr key generated successfully!")
	printKeyInfo(schnorrResult.PublicKey)

	// Example 2: Generate an ECDSA key with secp256k1 curve
	fmt.Println("\n📝 Generating ECDSA key (secp256k1)...")
	ecdsaResult, err := client.GenerateECDSAKey(context.Background(), sdk.CurveSECP256K1)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key:", err)
	}

	if !ecdsaResult.Success {
		log.Fatal("ECDSA key generation failed:", ecdsaResult.Message)
	}

	fmt.Println("✅ ECDSA key generated successfully!")
	printKeyInfo(ecdsaResult.PublicKey)

	fmt.Println("\n🎉 All keys generated successfully!")

	// Test message for signing
	message := []byte("Hello, TEENet!")
	fmt.Printf("\n📄 Test message: %s\n", string(message))

	// ========================================================================
	// Example 3: Sign with Schnorr key and verify
	// ========================================================================
	fmt.Println("\n" + repeat("=", 70))
	fmt.Println("🔐 Schnorr Signature Test (ED25519)")
	fmt.Println(repeat("=", 70))

	schnorrKeyName := schnorrResult.PublicKey.Name

	fmt.Println("\n📝 Signing with Schnorr key...")
	schnorrSig, err := client.Sign(context.Background(), message, schnorrKeyName)
	if err != nil {
		fmt.Printf("❌ Schnorr signing failed: %v\n", err)
	} else if !schnorrSig.Success {
		fmt.Printf("❌ Schnorr signing failed: %s\n", schnorrSig.Error)
	} else {
		fmt.Printf("✅ Schnorr signature generated successfully!\n")
		fmt.Printf("   Signature length: %d bytes\n", len(schnorrSig.Signature))
		fmt.Printf("   Signature (hex): %x...\n", schnorrSig.Signature[:min(32, len(schnorrSig.Signature))])

		// Verify Schnorr signature using SDK
		fmt.Println("\n🔍 Verifying Schnorr signature...")
		valid, err := client.Verify(context.Background(), message, schnorrSig.Signature, schnorrKeyName)
		if err != nil {
			fmt.Printf("❌ Schnorr signature verification error: %v\n", err)
		} else if valid {
			fmt.Println("✅ Schnorr signature verification PASSED!")
		} else {
			fmt.Println("❌ Schnorr signature verification FAILED!")
		}
	}

	// ========================================================================
	// Example 4: Sign with ECDSA key and verify
	// ========================================================================
	fmt.Println("\n" + repeat("=", 70))
	fmt.Println("🔐 ECDSA Signature Test (secp256k1)")
	fmt.Println(repeat("=", 70))

	ecdsaKeyName := ecdsaResult.PublicKey.Name

	// For ECDSA, hash message first (backend requires 32-byte pre-hashed input)
	fmt.Println("\n📝 Signing with ECDSA key...")
	ecdsaHashedMsg := sha256.Sum256(message)
	ecdsaSig, err := client.Sign(context.Background(), ecdsaHashedMsg[:], ecdsaKeyName)
	if err != nil {
		fmt.Printf("❌ ECDSA signing failed: %v\n", err)
	} else if !ecdsaSig.Success {
		fmt.Printf("❌ ECDSA signing failed: %s\n", ecdsaSig.Error)
	} else {
		fmt.Printf("✅ ECDSA signature generated successfully!\n")
		fmt.Printf("   Signature length: %d bytes\n", len(ecdsaSig.Signature))
		fmt.Printf("   Signature (hex): %x...\n", ecdsaSig.Signature[:min(32, len(ecdsaSig.Signature))])

		// Verify with the same hash that was signed
		fmt.Println("\n🔍 Verifying ECDSA signature...")
		valid, err := client.Verify(context.Background(), ecdsaHashedMsg[:], ecdsaSig.Signature, ecdsaKeyName)
		if err != nil {
			fmt.Printf("❌ ECDSA signature verification error: %v\n", err)
		} else if valid {
			fmt.Println("✅ ECDSA signature verification PASSED!")
		} else {
			fmt.Println("❌ ECDSA signature verification FAILED!")
		}
	}

	fmt.Println("\n" + repeat("=", 70))
	fmt.Println("🎉 All signing and verification tests completed!")
	fmt.Println(repeat("=", 70))

	// ========================================================================
	// Example 5: Test cross-app signing (using key from one app to sign for another)
	// ========================================================================
	fmt.Println("\n" + repeat("=", 70))
	fmt.Println("🔐 Cross-App Signing Test")
	fmt.Println(repeat("=", 70))
	fmt.Println("\nThis test attempts to use a key generated by one app")
	fmt.Println("to sign data for a different app.")

	// Save the current app's key info
	firstAppID := client.GetDefaultAppInstanceID()
	firstAppKeyName := schnorrResult.PublicKey.Name

	fmt.Printf("\n📋 Original App ID: %s\n", firstAppID)
	fmt.Printf("   Key ID: %d\n", schnorrResult.PublicKey.ID)
	fmt.Printf("   Public Key: %s\n", truncate(schnorrResult.PublicKey.KeyData, 40))

	// Switch to a different app ID for cross-app testing
	// Get from environment or use placeholder
	secondAppID := os.Getenv("SECOND_APP_INSTANCE_ID")
	if secondAppID == "" {
		fmt.Println("⚠️  SECOND_APP_INSTANCE_ID not set, skipping cross-app test")
		fmt.Println("   Set SECOND_APP_INSTANCE_ID to test cross-app signing")
		return
	}
	client.SetDefaultAppInstanceID(secondAppID)

	fmt.Printf("\n🔄 Switching to different App ID: %s\n", secondAppID)
	fmt.Println("\n📝 Attempting to sign with the key from the first app...")

	testMessage := []byte("Cross-app signing test message")
	crossAppSig, err := client.Sign(context.Background(), testMessage, firstAppKeyName)

	if err != nil {
		fmt.Printf("❌ Cross-app signing FAILED (Error): %v\n", err)
		fmt.Println("\n⚠️  ISSUE REPRODUCED!")
		fmt.Printf("   Key created by App ID: %s\n", firstAppID)
		fmt.Printf("   Attempted to sign for App ID: %s\n", secondAppID)
		fmt.Println("\n💡 Explanation:")
		fmt.Println("   Keys are scoped to the application that created them.")
		fmt.Println("   A key generated by one app cannot be used to sign for another app.")
		fmt.Println("\n💡 Solution:")
		fmt.Println("   Each application should generate and use its own keys.")
	} else if !crossAppSig.Success {
		fmt.Printf("❌ Cross-app signing FAILED: %s\n", crossAppSig.Error)
		fmt.Println("\n⚠️  ISSUE REPRODUCED!")
		fmt.Printf("   Key created by App ID: %s\n", firstAppID)
		fmt.Printf("   Attempted to sign for App ID: %s\n", secondAppID)
		fmt.Println("\n💡 Explanation:")
		fmt.Println("   Keys are scoped to the application that created them.")
		fmt.Println("   A key generated by one app cannot be used to sign for another app.")
		fmt.Println("\n💡 Solution:")
		fmt.Println("   Each application should generate and use its own keys.")
	} else {
		fmt.Println("✅ Cross-app signing succeeded!")
		fmt.Printf("   Signature length: %d bytes\n", len(crossAppSig.Signature))

		// Verify the signature
		valid, err := client.Verify(context.Background(), testMessage, crossAppSig.Signature, firstAppKeyName)

		if err != nil {
			fmt.Printf("❌ Verification error: %v\n", err)
		} else if valid {
			fmt.Println("✅ Signature verification PASSED!")
			fmt.Println("\n✅ Cross-app signing is supported!")
		} else {
			fmt.Println("❌ Signature verification FAILED!")
		}
	}

	// ========================================================================
	// Test with third app ID
	// ========================================================================
	thirdAppID := os.Getenv("THIRD_APP_INSTANCE_ID")
	if thirdAppID == "" {
		fmt.Println("⚠️  THIRD_APP_INSTANCE_ID not set, skipping third app test")
		// Restore original app ID
		client.SetDefaultAppInstanceID(firstAppID)
		fmt.Println("\n" + repeat("=", 70))
		fmt.Println("Cross-app signing test completed!")
		fmt.Println(repeat("=", 70))
		return
	}
	client.SetDefaultAppInstanceID(thirdAppID)

	fmt.Printf("\n🔄 Switching to third App ID: %s\n", thirdAppID)
	fmt.Println("\n📝 Attempting to sign with the key from the first app...")

	crossAppSig3, err := client.Sign(context.Background(), testMessage, firstAppKeyName)

	if err != nil {
		fmt.Printf("❌ Cross-app signing FAILED (Error): %v\n", err)
		fmt.Println("\n⚠️  ISSUE REPRODUCED!")
		fmt.Printf("   Key created by App ID: %s\n", firstAppID)
		fmt.Printf("   Attempted to sign for App ID: %s\n", thirdAppID)
		fmt.Println("\n💡 Explanation:")
		fmt.Println("   Keys are scoped to the application that created them.")
		fmt.Println("   A key generated by one app cannot be used to sign for another app.")
		fmt.Println("\n💡 Solution:")
		fmt.Println("   Each application should generate and use its own keys.")
	} else if !crossAppSig3.Success {
		fmt.Printf("❌ Cross-app signing FAILED: %s\n", crossAppSig3.Error)
		fmt.Println("\n⚠️  ISSUE REPRODUCED!")
		fmt.Printf("   Key created by App ID: %s\n", firstAppID)
		fmt.Printf("   Attempted to sign for App ID: %s\n", thirdAppID)
		fmt.Println("\n💡 Explanation:")
		fmt.Println("   Keys are scoped to the application that created them.")
		fmt.Println("   A key generated by one app cannot be used to sign for another app.")
		fmt.Println("\n💡 Solution:")
		fmt.Println("   Each application should generate and use its own keys.")
	} else {
		fmt.Println("✅ Cross-app signing succeeded!")
		fmt.Printf("   Signature length: %d bytes\n", len(crossAppSig3.Signature))

		// Verify the signature
		valid, err := client.Verify(context.Background(), testMessage, crossAppSig3.Signature, firstAppKeyName)

		if err != nil {
			fmt.Printf("❌ Verification error: %v\n", err)
		} else if valid {
			fmt.Println("✅ Signature verification PASSED!")
			fmt.Println("\n✅ Cross-app signing is supported!")
		} else {
			fmt.Println("❌ Signature verification FAILED!")
		}
	}

	// Restore original app ID
	client.SetDefaultAppInstanceID(firstAppID)

	fmt.Println("\n" + repeat("=", 70))
	fmt.Println("Cross-app signing test completed!")
	fmt.Println(repeat("=", 70))
}

// printKeyInfo prints formatted key information
func printKeyInfo(key *sdk.PublicKeyInfo) {
	fmt.Printf("  Key ID: %d\n", key.ID)
	if key.Name != "" {
		fmt.Printf("  Name: %s\n", key.Name)
	}
	fmt.Printf("  Protocol: %s\n", key.Protocol)
	fmt.Printf("  Curve: %s\n", key.Curve)
	fmt.Printf("  Public Key: %s\n", truncate(key.KeyData, 40))
	fmt.Printf("  Application ID: %d\n", key.ApplicationID)
	fmt.Printf("  Created by Instance: %s\n", key.CreatedByInstanceID)

	// Print DKG parameters if available
	if key.Threshold > 0 {
		fmt.Printf("  DKG Threshold: %d of %d participants\n", key.Threshold, key.MaxParticipantCount)
	}
}

// truncate truncates a string for display
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// repeat repeats a string n times (helper for formatting)
func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
