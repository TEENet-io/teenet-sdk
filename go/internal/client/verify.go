// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

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

// GetPublicKeys retrieves all bound public keys for the default APP_INSTANCE_ID.
func (c *Client) GetPublicKeys(ctx context.Context) ([]types.PublicKeyInfo, error) {
	appID, err := c.getAppInstanceID()
	if err != nil {
		return nil, err
	}

	// Read cache entry while holding RLock
	c.mu.RLock()
	entry, found := c.pkCache[appID]
	c.mu.RUnlock()

	// Check cache hit
	if found && c.keyCacheTTL > 0 && time.Now().Before(entry.expiresAt) {
		return entry.keys, nil
	}

	// Cache miss — use singleflight to collapse concurrent requests
	val, err, _ := c.pkGroup.Do(appID, func() (interface{}, error) {
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
			expiresAt: time.Now().Add(c.keyCacheTTL),
		}
		c.mu.Unlock()

		return result, nil
	})
	if err != nil {
		return nil, err
	}

	return val.([]types.PublicKeyInfo), nil
}

// InvalidateKeyCache clears the in-memory public key cache, forcing the next
// GetPublicKeys call to fetch fresh data from the TEENet service.
// Use this after key rotation to ensure stale cached keys are not used.
func (c *Client) InvalidateKeyCache() {
	c.mu.Lock()
	c.pkCache = make(map[string]pkCacheEntry)
	c.mu.Unlock()
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
	if _, err := c.getAppInstanceID(); err != nil {
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
