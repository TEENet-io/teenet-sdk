// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

// Package util provides encoding and utility functions for TEENet SDK.
package util

import (
	"encoding/hex"
	"strings"
)

// DecodeHexSignature decodes a hex-encoded string to raw bytes.
//
// This utility function handles hex strings with or without the "0x" prefix,
// making it flexible for parsing signatures and public keys from various sources.
//
// Parameters:
//   - sigHex: Hex-encoded string (with or without "0x" prefix)
//
// Returns:
//   - Decoded bytes
//   - Error if the hex string is invalid
//
// Example:
//
//	// Both of these work:
//	bytes1, _ := DecodeHexSignature("0x1234abcd")
//	bytes2, _ := DecodeHexSignature("1234abcd")
//	// bytes1 and bytes2 are identical
func DecodeHexSignature(sigHex string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
}
