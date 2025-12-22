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

// Package util provides encoding and utility functions for TEENet SDK.
package util

import (
	"encoding/hex"
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
	// Remove 0x prefix if present
	if len(sigHex) >= 2 && sigHex[0:2] == "0x" {
		sigHex = sigHex[2:]
	}
	return hex.DecodeString(sigHex)
}
