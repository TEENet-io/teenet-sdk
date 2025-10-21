package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	client "github.com/TEENet-io/teenet-sdk/go"
)

func testAppID(appID string) {
	fmt.Printf("\n" + strings.Repeat("=", 70) + "\n")
	fmt.Printf("Testing App ID: %s\n", appID)
	fmt.Printf(strings.Repeat("=", 70) + "\n\n")

	// Create client
	teeClient := client.NewClient()
	defer teeClient.Close()

	// Set default App ID
	teeClient.SetDefaultAppID(appID)

	// Initialize client
	if err := teeClient.Init(); err != nil {
		log.Printf("❌ Failed to initialize client: %v\n", err)
		return
	}

	fmt.Println("✓ Client initialized")

	// Get public key
	publicKey, protocol, curve, err := teeClient.GetPublicKey()
	if err != nil {
		log.Printf("❌ Failed to get public key: %v\n", err)
		return
	}

	publicKeyBytes, _ := hex.DecodeString(publicKey)
	fmt.Printf("Public Key: %s\n", publicKey)
	fmt.Printf("Protocol: %s, Curve: %s\n", protocol, curve)
	fmt.Printf("Public Key Length: %d bytes\n\n", len(publicKeyBytes))

	// Sign a message
	message := []byte("Testing " + appID)
	fmt.Printf("Signing message: %s\n", string(message))

	result, err := teeClient.Sign(message)
	if err != nil {
		log.Printf("❌ Failed to sign: %v\n", err)
		return
	}

	if !result.Success {
		log.Printf("❌ Sign failed: %s\n", result.Error)
		return
	}

	fmt.Printf("✓ Signature created\n")
	fmt.Printf("Signature: %s\n", hex.EncodeToString(result.Signature))
	fmt.Printf("Signature Length: %d bytes\n\n", len(result.Signature))

	// Verify the signature
	fmt.Println("Verifying signature...")
	valid, err := teeClient.Verify(message, result.Signature)
	if err != nil {
		log.Printf("❌ Verification error: %v\n", err)
		return
	}

	if valid {
		fmt.Println("✅ Signature verification PASSED!")
	} else {
		fmt.Println("❌ Signature verification FAILED!")
		return
	}

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	valid2, err := teeClient.Verify(wrongMessage, result.Signature)
	if err != nil {
		fmt.Printf("Verification with wrong message error: %v\n", err)
	}

	if !valid2 {
		fmt.Println("✅ Correctly rejected invalid signature!")
	} else {
		fmt.Println("❌ ERROR: Accepted invalid signature!")
	}
}

func main() {
	fmt.Println("=== Testing All App IDs ===")

	appIDs := []string{
		"secure-messaging-app",
		"financial-trading-platform",
		"digital-identity-service",
		"ethereum-wallet-app",
	}

	for _, appID := range appIDs {
		testAppID(appID)
		time.Sleep(500 * time.Millisecond) // Small delay between tests
	}

	fmt.Printf("\n" + strings.Repeat("=", 70) + "\n")
	fmt.Println("=== All App ID Tests Completed ===")
	fmt.Printf(strings.Repeat("=", 70) + "\n")
}
