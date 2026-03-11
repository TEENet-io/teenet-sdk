// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
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
	"errors"
	"fmt"
	"strings"

	"github.com/TEENet-io/teenet-sdk/go/internal/crypto"
	"github.com/TEENet-io/teenet-sdk/go/internal/types"
	"github.com/TEENet-io/teenet-sdk/go/internal/util"
)

var ErrPublicKeyNameNotFound = errors.New("public key name not found in bound keys")

// GetPublicKeys retrieves all bound public keys for the default App ID.
func (c *Client) GetPublicKeys() ([]types.PublicKeyInfo, error) {
	if c.defaultAppID == "" {
		return nil, fmt.Errorf("default App ID is not set (use SetDefaultAppID)")
	}
	keys, err := c.httpClient.GetPublicKeys(c.defaultAppID)
	if err != nil {
		return nil, err
	}
	result := make([]types.PublicKeyInfo, len(keys))
	for i, k := range keys {
		result[i] = types.PublicKeyInfo{
			ID:       k.ID,
			Name:     k.Name,
			KeyData:  k.KeyData,
			Protocol: k.Protocol,
			Curve:    k.Curve,
		}
	}
	return result, nil
}

func (c *Client) getBoundPublicKeyByName(publicKeyName string) (*types.PublicKeyInfo, error) {
	name := strings.TrimSpace(publicKeyName)
	if name == "" {
		return nil, fmt.Errorf("public key name is required")
	}
	keys, err := c.GetPublicKeys()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].Name == name {
			return &keys[i], nil
		}
	}
	return nil, ErrPublicKeyNameNotFound
}

// Verify verifies a cryptographic signature against a message using a bound key name.
//
// Parameters:
//   - message: The original message that was signed (raw bytes)
//   - signature: The signature to verify (raw bytes, not hex-encoded)
//   - publicKeyName: The bound public key name to use for verification
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
//	valid, err := client.Verify(message, signature, "my-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if valid {
//	    fmt.Println("Signature is valid")
//	} else {
//	    fmt.Println("Signature is invalid")
//	}
func (c *Client) Verify(message, signature []byte, publicKeyName string) (bool, error) {
	if c.defaultAppID == "" {
		return false, fmt.Errorf("default App ID is not set (use SetDefaultAppID)")
	}

	key, err := c.getBoundPublicKeyByName(publicKeyName)
	if err != nil {
		return false, fmt.Errorf("failed to resolve public key by name: %w", err)
	}

	// Decode public key from hex string
	publicKeyHex := strings.TrimPrefix(key.KeyData, "0x")
	publicKey, err := util.DecodeHexSignature(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Verify the signature using the appropriate algorithm
	// Note: VerifySignature will hash the message internally
	return crypto.VerifySignature(message, publicKey, signature, key.Protocol, key.Curve)
}
