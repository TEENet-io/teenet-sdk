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


package client

import (
	"fmt"
	"strings"

	"github.com/TEENet-io/teenet-sdk/internal/crypto"
	"github.com/TEENet-io/teenet-sdk/internal/util"
)

// GetPublicKey retrieves the public key information for the default App ID.
//
// This method queries the consensus service to obtain the public key,
// signing protocol, and elliptic curve used by the application.
//
// Returns:
//   - publicKey: Hex-encoded public key (may include 0x prefix)
//   - protocol: Protocol name (e.g., "ECDSA", "Schnorr")
//   - curve: Curve name (e.g., "SECP256K1", "ED25519", "SECP256R1")
//   - err: Error if the request fails or default App ID is not set
//
// Example:
//
//	pubKey, protocol, curve, err := client.GetPublicKey()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Public Key: %s\nProtocol: %s\nCurve: %s\n", pubKey, protocol, curve)
func (c *Client) GetPublicKey() (publicKey, protocol, curve string, err error) {
	if c.defaultAppID == "" {
		return "", "", "", fmt.Errorf("default App ID is not set (use SetDefaultAppID)")
	}

	// Use HTTP client to get public key from consensus service
	return c.httpClient.GetPublicKey(c.defaultAppID)
}

// Verify verifies a cryptographic signature against a message.
//
// This method automatically retrieves the public key for the default App ID
// and verifies the signature using the appropriate cryptographic algorithm.
// The verification is performed locally without contacting the consensus service.
//
// Parameters:
//   - message: The original message that was signed (raw bytes)
//   - signature: The signature to verify (raw bytes, not hex-encoded)
//
// Returns:
//   - bool: true if the signature is valid, false otherwise
//   - error: Error if verification cannot be performed (e.g., invalid public key)
//
// Supported combinations:
//   - ED25519 + EdDSA
//   - SECP256K1 + ECDSA
//   - SECP256K1 + Schnorr
//   - SECP256R1 + ECDSA
//   - SECP256R1 + Schnorr
//
// Example:
//
//	valid, err := client.Verify(message, signature)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if valid {
//	    fmt.Println("Signature is valid")
//	} else {
//	    fmt.Println("Signature is invalid")
//	}
func (c *Client) Verify(message, signature []byte) (bool, error) {
	if c.defaultAppID == "" {
		return false, fmt.Errorf("default App ID is not set (use SetDefaultAppID)")
	}

	// Get public key information from consensus service
	publicKeyHex, protocolStr, curveStr, err := c.GetPublicKey()
	if err != nil {
		return false, fmt.Errorf("failed to get public key: %w", err)
	}

	// Decode public key from hex string
	publicKeyHex = strings.TrimPrefix(publicKeyHex, "0x")
	publicKey, err := util.DecodeHexSignature(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Verify the signature using the appropriate algorithm
	// Note: VerifySignature will hash the message internally
	return crypto.VerifySignature(message, publicKey, signature, protocolStr, curveStr)
}

// VerifyWithPublicKey verifies a cryptographic signature against a message using a specific public key.
//
// This method verifies the signature using the provided public key, protocol, and curve.
// The verification is performed locally without contacting the consensus service.
//
// Parameters:
//   - message: The original message that was signed (raw bytes)
//   - signature: The signature to verify (raw bytes, not hex-encoded)
//   - publicKey: The public key to use for verification (raw bytes)
//   - protocol: The signature protocol (e.g., "ecdsa", "schnorr")
//   - curve: The elliptic curve (e.g., "secp256k1", "ed25519", "secp256r1")
//
// Returns:
//   - bool: true if the signature is valid, false otherwise
//   - error: Error if verification cannot be performed
//
// Supported combinations:
//   - ED25519 + EdDSA
//   - SECP256K1 + ECDSA
//   - SECP256K1 + Schnorr
//   - SECP256R1 + ECDSA
//   - SECP256R1 + Schnorr
//
// Example:
//
//	publicKey := []byte{...} // raw public key bytes
//	valid, err := client.VerifyWithPublicKey(message, signature, publicKey, "schnorr", "ed25519")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if valid {
//	    fmt.Println("Signature is valid")
//	}
func (c *Client) VerifyWithPublicKey(message, signature, publicKey []byte, protocol, curve string) (bool, error) {
	return crypto.VerifySignature(message, publicKey, signature, protocol, curve)
}
