// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

// TEENet SDK Test Program
// Tests the mock server functionality
//
// Usage:
//   1. Start mock server: cd mock-server && make run
//   2. Run tests: cd go/examples && go run .

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	sdk "github.com/TEENet-io/teenet-sdk/go"
	"golang.org/x/crypto/sha3"
)

func main() {
	// Redirect SDK logs to stderr
	log.SetOutput(os.Stderr)

	// Mock server URL
	serverURL := "http://localhost:8089"
	if url := os.Getenv("MOCK_SERVER_URL"); url != "" {
		serverURL = url
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  TEENet SDK Mock Server Test")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Server: %s\n", serverURL)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Test cases
	testCases := []struct {
		name     string
		appInstanceID    string
		protocol string
		curve    string
	}{
		{"ED25519 Schnorr", "mock-app-id-01", "schnorr", "ed25519"},
		{"SECP256K1 ECDSA", "mock-app-id-03", "ecdsa", "secp256k1"},
		{"SECP256K1 Schnorr", "mock-app-id-02", "schnorr", "secp256k1"},
		{"SECP256R1 ECDSA", "mock-app-id-04", "ecdsa", "secp256r1"},
	}

	passed := 0
	failed := 0

	for _, tc := range testCases {
		fmt.Printf("Test %s (%s/%s)\n", tc.name, tc.protocol, tc.curve)
		fmt.Printf("   App Instance ID: %s\n", tc.appInstanceID)

		if err := testSignAndVerify(serverURL, tc.appInstanceID); err != nil {
			fmt.Printf("   FAILED: %v\n", err)
			failed++
		} else {
			fmt.Printf("   PASSED\n")
			passed++
		}
		fmt.Println()
	}

	// Test key generation
	fmt.Println("Test Key Generation")
	if err := testKeyGeneration(serverURL); err != nil {
		fmt.Printf("   FAILED: %v\n", err)
		failed++
	} else {
		fmt.Printf("   PASSED\n")
		passed++
	}
	fmt.Println()

	// Test API Key
	fmt.Println("Test API Key")
	if err := testAPIKey(serverURL); err != nil {
		fmt.Printf("   FAILED: %v\n", err)
		failed++
	} else {
		fmt.Printf("   PASSED\n")
		passed++
	}
	fmt.Println()

	// Test API Secret signing
	fmt.Println("Test API Secret Sign")
	if err := testAPISecretSign(serverURL); err != nil {
		fmt.Printf("   FAILED: %v\n", err)
		failed++
	} else {
		fmt.Printf("   PASSED\n")
		passed++
	}
	fmt.Println()

	// Summary
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Results: %d passed, %d failed\n", passed, failed)
	fmt.Println(strings.Repeat("=", 60))

	if failed > 0 {
		os.Exit(1)
	}
}

func testSignAndVerify(serverURL, appInstanceID string) error {
	// Create client
	client := sdk.NewClient(serverURL)
	client.SetDefaultAppInstanceID(appInstanceID)
	defer client.Close()

	// Test message
	message := []byte("Hello, TEENet! This is a test message.")

	// Get bound public keys
	keys, err := client.GetPublicKeys(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get public keys: %v", err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("no bound public keys found")
	}
	key := keys[0]
	pubKey := key.KeyData
	protocol := key.Protocol
	curve := key.Curve
	fmt.Printf("   Public Key: %s...%s\n", pubKey[:16], pubKey[len(pubKey)-8:])
	fmt.Printf("   Protocol: %s, Curve: %s\n", protocol, curve)
	keyName := key.Name

	// For ECDSA, the user is responsible for hashing before Sign and Verify.
	// The TEE-DAO backend requires exactly 32 bytes (pre-hashed) for ECDSA.
	// For Schnorr/EdDSA, pass raw message (protocol handles hashing internally).
	signMsg := message
	if strings.EqualFold(protocol, "ecdsa") && strings.EqualFold(curve, "secp256k1") {
		// Ethereum-style: Keccak-256
		h := sha3.NewLegacyKeccak256()
		h.Write(message)
		signMsg = h.Sum(nil)
	} else if strings.EqualFold(protocol, "ecdsa") && strings.EqualFold(curve, "secp256r1") {
		// P-256: SHA-256
		h := sha256.Sum256(message)
		signMsg = h[:]
	}

	result, err := client.Sign(context.Background(), signMsg, keyName)
	if err != nil {
		return fmt.Errorf("failed to sign: %v", err)
	}
	if !result.Success {
		return fmt.Errorf("sign returned failure: %s", result.Error)
	}

	fmt.Printf("   Signature: %s... (%d bytes)\n", shortHex(result.Signature, 8), len(result.Signature))

	// Verify with the same message bytes that were signed
	valid, err := client.Verify(context.Background(), signMsg, result.Signature, keyName)
	if err != nil {
		return fmt.Errorf("failed to verify: %v", err)
	}
	if !valid {
		return fmt.Errorf("signature verification failed")
	}
	fmt.Printf("   Verify: OK\n")

	return nil
}

func testKeyGeneration(serverURL string) error {
	client := sdk.NewClient(serverURL)
	client.SetDefaultAppInstanceID("new-test-app")
	defer client.Close()

	// Test different protocol/curve combinations
	keyCases := []struct {
		name     string
		protocol string
		curve    string
	}{
		{"ECDSA secp256k1", "ecdsa", "secp256k1"},
		{"ECDSA secp256r1", "ecdsa", "secp256r1"},
		{"Schnorr secp256k1", "schnorr", "secp256k1"},
		{"Schnorr ed25519", "schnorr", "ed25519"},
	}

	for _, kc := range keyCases {
		var result *sdk.GenerateKeyResult
		var err error

		result, err = client.GenerateKey(context.Background(), kc.protocol, kc.curve)

		if err != nil {
			return fmt.Errorf("failed to generate %s key: %v", kc.name, err)
		}
		if !result.Success {
			return fmt.Errorf("generate %s key returned failure: %s", kc.name, result.Message)
		}

		fmt.Printf("   %s: ID=%d, Key=%s...%s\n",
			kc.name,
			result.PublicKey.ID,
			result.PublicKey.KeyData[:16],
			result.PublicKey.KeyData[len(result.PublicKey.KeyData)-8:])

		// Invalidate key cache so newly generated key is visible
		client.InvalidateKeyCache()

		message := []byte("Test message for generated key")
		// For ECDSA, hash before Sign (backend requires 32-byte pre-hashed input)
		signMsg := message
		if kc.protocol == "ecdsa" && kc.curve == "secp256k1" {
			h := sha3.NewLegacyKeccak256()
			h.Write(message)
			signMsg = h.Sum(nil)
		} else if kc.protocol == "ecdsa" && kc.curve == "secp256r1" {
			h := sha256.Sum256(message)
			signMsg = h[:]
		}
		signResult, err := client.Sign(context.Background(), signMsg, result.PublicKey.Name)
		if err != nil {
			return fmt.Errorf("failed to sign with %s key: %v", kc.name, err)
		}
		if !signResult.Success {
			return fmt.Errorf("sign with %s key returned failure: %s", kc.name, signResult.Error)
		}

		// Verify with the same bytes that were signed
		valid, err := client.Verify(context.Background(), signMsg, signResult.Signature, result.PublicKey.Name)
		if err != nil {
			return fmt.Errorf("failed to verify %s signature: %v", kc.name, err)
		}
		if !valid {
			return fmt.Errorf("%s signature verification failed", kc.name)
		}
		fmt.Printf("   %s: Sign & Verify OK\n", kc.name)
	}

	return nil
}

func testAPIKey(serverURL string) error {
	client := sdk.NewClient(serverURL)
	client.SetDefaultAppInstanceID("mock-app-id-03")
	defer client.Close()

	// Get API Key
	result, err := client.GetAPIKey(context.Background(), "test-api-key")
	if err != nil {
		return fmt.Errorf("failed to get API key: %v", err)
	}
	if !result.Success {
		return fmt.Errorf("get API key returned failure: %s", result.Error)
	}

	fmt.Printf("   API Key: %s\n", result.APIKey)

	return nil
}

func testAPISecretSign(serverURL string) error {
	client := sdk.NewClient(serverURL)
	client.SetDefaultAppInstanceID("mock-app-id-03")
	defer client.Close()

	// Sign with API Secret
	message := []byte("Message to sign with API secret")
	result, err := client.SignWithAPISecret(context.Background(), "test-api-secret", message)
	if err != nil {
		return fmt.Errorf("failed to sign with API secret: %v", err)
	}
	if !result.Success {
		return fmt.Errorf("API secret sign returned failure: %s", result.Error)
	}

	fmt.Printf("   Algorithm: %s\n", result.Algorithm)
	fmt.Printf("   Signature: %s... (%d bytes)\n", result.Signature[:16], len(result.Signature)/2)

	// Verify HMAC signature
	// Mock server uses secret "secret_mock-app-id-03_abcdef"
	secret := []byte("secret_mock-app-id-03_abcdef")
	signatureBytes, err := hex.DecodeString(result.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	// Local HMAC-SHA256 verification
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	valid := hmac.Equal(signatureBytes, expectedMAC)
	if !valid {
		return fmt.Errorf("HMAC signature verification failed")
	}
	fmt.Printf("   Verify: OK\n")

	return nil
}

func shortHex(b []byte, n int) string {
	if len(b) == 0 {
		return ""
	}
	if n > len(b) {
		n = len(b)
	}
	return hex.EncodeToString(b[:n])
}
