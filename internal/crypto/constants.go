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

// Package crypto provides cryptographic constants and utilities for TEENet SDK.
//
// This internal package handles protocol/curve constants, parsing, and related
// cryptographic operations. It is not intended for direct external use.
package crypto

import "fmt"

// Cryptographic protocol identifiers.
//
// These constants define the supported signature protocols for TEENet signing operations.
const (
	// ProtocolECDSA represents the Elliptic Curve Digital Signature Algorithm.
	// This is the most widely used signature scheme, compatible with Bitcoin,
	// Ethereum, and most blockchain systems.
	ProtocolECDSA uint32 = 1

	// ProtocolSchnorr represents the Schnorr signature scheme.
	// Schnorr signatures are more compact and support signature aggregation.
	// Used in Bitcoin Taproot and other modern systems.
	ProtocolSchnorr uint32 = 2
)

// Elliptic curve identifiers.
//
// These constants define the supported elliptic curves for cryptographic operations.
const (
	// CurveED25519 represents the Edwards-curve Digital Signature Algorithm curve.
	// Used with EdDSA protocol. Popular in modern systems like Signal, Tor, and SSH.
	// Provides ~128-bit security level.
	CurveED25519 uint32 = 1

	// CurveSECP256K1 represents the SECP256K1 elliptic curve.
	// Used by Bitcoin and Ethereum. Supports both ECDSA and Schnorr protocols.
	// Provides ~128-bit security level.
	CurveSECP256K1 uint32 = 2

	// CurveSECP256R1 represents the SECP256R1 (P-256) elliptic curve.
	// NIST standardized curve, widely used in TLS, government systems.
	// Also known as prime256v1. Provides ~128-bit security level.
	CurveSECP256R1 uint32 = 3
)

// ParseProtocol converts a protocol name string to its numeric constant.
//
// Supported protocol names (case-insensitive):
//   - "ECDSA", "ecdsa" → ProtocolECDSA
//   - "Schnorr", "schnorr", "SCHNORR" → ProtocolSchnorr
//
// Returns an error if the protocol name is not recognized.
func ParseProtocol(protocolStr string) (uint32, error) {
	switch protocolStr {
	case "ECDSA", "ecdsa":
		return ProtocolECDSA, nil
	case "Schnorr", "schnorr", "SCHNORR":
		return ProtocolSchnorr, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s (supported: ECDSA, Schnorr)", protocolStr)
	}
}

// ParseCurve converts a curve name string to its numeric constant.
//
// Supported curve names (case-insensitive):
//   - "ED25519", "ed25519" → CurveED25519
//   - "SECP256K1", "secp256k1" → CurveSECP256K1
//   - "SECP256R1", "secp256r1", "P256", "p256" → CurveSECP256R1
//
// Returns an error if the curve name is not recognized.
func ParseCurve(curveStr string) (uint32, error) {
	switch curveStr {
	case "ED25519", "ed25519":
		return CurveED25519, nil
	case "SECP256K1", "secp256k1":
		return CurveSECP256K1, nil
	case "SECP256R1", "secp256r1", "P256", "p256":
		return CurveSECP256R1, nil
	default:
		return 0, fmt.Errorf("unsupported curve: %s (supported: ED25519, SECP256K1, SECP256R1/P256)", curveStr)
	}
}
