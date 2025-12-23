// TEENet SDK Test Program
// Tests the mock server functionality
//
// Usage:
//   1. Start mock server: cd mock-server && ./start.sh
//   2. Run tests: cd examples/mock-test && go run main.go

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	sdk "github.com/TEENet-io/teenet-sdk/go"
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
		appID    string
		protocol string
		curve    string
	}{
		{"ED25519 Schnorr", "test-schnorr-ed25519", "schnorr", "ed25519"},
		{"SECP256K1 ECDSA", "test-ecdsa-secp256k1", "ecdsa", "secp256k1"},
		{"SECP256K1 Schnorr", "test-schnorr-secp256k1", "schnorr", "secp256k1"},
		{"SECP256R1 ECDSA", "test-ecdsa-secp256r1", "ecdsa", "secp256r1"},
		{"Ethereum Wallet", "ethereum-wallet-app", "ecdsa", "secp256k1"},
	}

	passed := 0
	failed := 0

	for _, tc := range testCases {
		fmt.Printf("Test %s (%s/%s)\n", tc.name, tc.protocol, tc.curve)
		fmt.Printf("   App ID: %s\n", tc.appID)

		if err := testSignAndVerify(serverURL, tc.appID); err != nil {
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

func testSignAndVerify(serverURL, appID string) error {
	// Create client
	client := sdk.NewClient(serverURL)
	client.SetDefaultAppID(appID)
	defer client.Close()

	// Test message
	message := []byte("Hello, TEENet! This is a test message.")

	// Get public key
	pubKey, protocol, curve, err := client.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %v", err)
	}
	fmt.Printf("   Public Key: %s...%s\n", pubKey[:16], pubKey[len(pubKey)-8:])
	fmt.Printf("   Protocol: %s, Curve: %s\n", protocol, curve)

	// Sign
	result, err := client.Sign(message)
	if err != nil {
		return fmt.Errorf("failed to sign: %v", err)
	}
	if !result.Success {
		return fmt.Errorf("sign returned failure: %s", result.Error)
	}
	fmt.Printf("   Signature: %s... (%d bytes)\n", hex.EncodeToString(result.Signature[:8]), len(result.Signature))

	// Verify
	valid, err := client.Verify(message, result.Signature)
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
	client.SetDefaultAppID("new-test-app")
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

		if kc.protocol == "ecdsa" {
			result, err = client.GenerateECDSAKey(kc.curve)
		} else {
			result, err = client.GenerateSchnorrKey(kc.curve)
		}

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

		// Test signing with the generated key
		pubKeyBytes, err := hex.DecodeString(strings.TrimPrefix(result.PublicKey.KeyData, "0x"))
		if err != nil {
			return fmt.Errorf("failed to decode %s public key: %v", kc.name, err)
		}

		message := []byte("Test message for generated key")
		signResult, err := client.Sign(message, pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to sign with %s key: %v", kc.name, err)
		}
		if !signResult.Success {
			return fmt.Errorf("sign with %s key returned failure: %s", kc.name, signResult.Error)
		}

		// Verify the signature
		valid, err := client.VerifyWithPublicKey(message, signResult.Signature, pubKeyBytes, kc.protocol, kc.curve)
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
	client.SetDefaultAppID("test-ecdsa-secp256k1")
	defer client.Close()

	// Get API Key
	result, err := client.GetAPIKey("test-api-key")
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
	client.SetDefaultAppID("test-ecdsa-secp256k1")
	defer client.Close()

	// Sign with API Secret
	message := []byte("Message to sign with API secret")
	result, err := client.SignWithAPISecret("test-api-secret", message)
	if err != nil {
		return fmt.Errorf("failed to sign with API secret: %v", err)
	}
	if !result.Success {
		return fmt.Errorf("API secret sign returned failure: %s", result.Error)
	}

	fmt.Printf("   Algorithm: %s\n", result.Algorithm)
	fmt.Printf("   Signature: %s... (%d bytes)\n", result.Signature[:16], len(result.Signature)/2)

	// Verify HMAC signature
	// Mock server uses secret "secret_test-ecdsa-secp256k1_abcdef"
	secret := []byte("secret_test-ecdsa-secp256k1_abcdef")
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
