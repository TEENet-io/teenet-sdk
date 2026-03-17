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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TEENet-io/teenet-sdk/go/internal/crypto"
	"github.com/TEENet-io/teenet-sdk/go/internal/types"
	"github.com/TEENet-io/teenet-sdk/go/internal/util"
)

var ErrPublicKeyNameNotFound = errors.New("public key name not found in bound keys")

type pkCacheEntry struct {
	keys      []types.PublicKeyInfo
	expiresAt time.Time
}

const pkCacheTTL = 60 * time.Second

// GetPublicKeys retrieves all bound public keys for the default App ID.
func (c *Client) GetPublicKeys(ctx context.Context) ([]types.PublicKeyInfo, error) {
	if err := c.requireAppID(); err != nil {
		return nil, err
	}

	// Read appID while holding RLock
	c.mu.RLock()
	appID := c.defaultAppID
	entry, found := c.pkCache[appID]
	c.mu.RUnlock()

	// Check cache hit
	if found && time.Now().Before(entry.expiresAt) {
		return entry.keys, nil
	}

	// Cache miss — do HTTP call without holding lock
	keys, err := c.httpClient.GetPublicKeys(ctx, appID)
	if err != nil {
		return nil, err
	}
	result := make([]types.PublicKeyInfo, len(keys))
	for i, k := range keys {
		pk, err := convertJSON[types.PublicKeyInfo](k)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key: %w", err)
		}
		result[i] = *pk
	}

	// Update cache
	c.mu.Lock()
	c.pkCache[appID] = pkCacheEntry{
		keys:      result,
		expiresAt: time.Now().Add(pkCacheTTL),
	}
	c.mu.Unlock()

	return result, nil
}

func (c *Client) getBoundPublicKeyByName(ctx context.Context, publicKeyName string) (*types.PublicKeyInfo, error) {
	name := strings.TrimSpace(publicKeyName)
	if name == "" {
		return nil, fmt.Errorf("public key name is required")
	}
	keys, err := c.GetPublicKeys(ctx)
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
//   - ctx: Context for the HTTP request
//   - message: The message to verify. For most protocols this is the raw bytes and
//     hashing is done internally. Exception: for SECP256K1+ECDSA (Ethereum), the
//     TEE-DAO signs without hashing, so the caller must pass the pre-hashed digest
//     (e.g. a 32-byte Keccak-256 or SHA-256 hash) here.
//   - signature: The signature to verify (raw bytes, not hex-encoded)
//   - publicKeyName: The bound public key name to use for verification
//
// Returns:
//   - bool: true if the signature is valid, false otherwise
//   - error: Error if verification cannot be performed (e.g., invalid public key)
//
// Supported combinations:
//   - ED25519 + EdDSA       — message is raw bytes (hashed internally via EdDSA)
//   - SECP256K1 + ECDSA     — message must be the pre-hashed digest (no internal hashing)
//   - SECP256K1 + Schnorr   — message is raw bytes (SHA-256 applied internally)
//   - SECP256R1 + ECDSA     — message is raw bytes (SHA-256 applied internally)
//   - SECP256R1 + Schnorr   — message is raw bytes (SHA-256 applied internally)
//
// Example:
//
//	valid, err := client.Verify(ctx, message, signature, "my-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if valid {
//	    fmt.Println("Signature is valid")
//	} else {
//	    fmt.Println("Signature is invalid")
//	}
func (c *Client) Verify(ctx context.Context, message, signature []byte, publicKeyName string) (bool, error) {
	if err := c.requireAppID(); err != nil {
		return false, err
	}

	key, err := c.getBoundPublicKeyByName(ctx, publicKeyName)
	if err != nil {
		return false, fmt.Errorf("failed to resolve public key by name: %w", err)
	}

	// Decode public key from hex string
	publicKey, err := util.DecodeHexSignature(key.KeyData)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Verify the signature using the appropriate algorithm
	// Note: VerifySignature will hash the message internally
	return crypto.VerifySignature(message, publicKey, signature, key.Protocol, key.Curve)
}
