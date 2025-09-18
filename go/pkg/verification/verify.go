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

// Package verification provides cryptographic signature verification for multiple curves and protocols
package verification

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/TEENet-io/teenet-sdk/go/pkg/constants"
	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/crypto/sha3"
)

// ECDSASignature represents an ECDSA signature in ASN.1 format
type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

// VerifySignature verifies a signature against a message and public key
// Supports all protocol/curve combinations:
// - ED25519 with EdDSA (protocol parameter ignored for ED25519)
// - SECP256K1 with ECDSA or Schnorr protocols (using btcec)
// - SECP256R1 with ECDSA or Schnorr protocols
func VerifySignature(message, publicKey, signature []byte, protocol, curve uint32) (bool, error) {
	switch curve {
	case constants.CurveED25519:
		return verifyED25519(message, publicKey, signature)
	case constants.CurveSECP256K1:
		return verifySecp256k1(message, publicKey, signature, protocol)
	case constants.CurveSECP256R1:
		return verifySecp256r1(message, publicKey, signature, protocol)
	default:
		return false, fmt.Errorf("unsupported curve: %d", curve)
	}
}

// verifyED25519 verifies ED25519 signatures
func verifyED25519(message, publicKey, signature []byte) (bool, error) {
	// ED25519 only supports EdDSA (not ECDSA or Schnorr)
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid ED25519 public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}
	if len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid ED25519 signature size: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// For ED25519, we verify directly (EdDSA protocol)
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature), nil
}

// verifySecp256k1 verifies signatures on secp256k1 curve using btcec
func verifySecp256k1(message, publicKeyBytes, signature []byte, protocol uint32) (bool, error) {
	// Parse the public key using btcec
	pubKey, err := btcec.ParsePubKey(publicKeyBytes)
	if err != nil {
		// Try alternative formats if standard parsing fails
		// btcec expects compressed (33 bytes) or uncompressed (65 bytes) format
		// For raw 64-byte format, we need to add the uncompressed prefix
		if len(publicKeyBytes) == 64 {
			// Add uncompressed format prefix
			uncompressed := make([]byte, 65)
			uncompressed[0] = 0x04
			copy(uncompressed[1:], publicKeyBytes)
			pubKey, err = btcec.ParsePubKey(uncompressed)
			if err != nil {
				return false, fmt.Errorf("failed to parse secp256k1 public key: %v", err)
			}
		} else {
			return false, fmt.Errorf("failed to parse secp256k1 public key: %v", err)
		}
	}

	switch protocol {
	case constants.ProtocolECDSA:
		return verifySecp256k1ECDSA(message, pubKey, signature)
	case constants.ProtocolSchnorr:
		return verifySecp256k1Schnorr(message, pubKey, signature)
	default:
		return false, fmt.Errorf("unsupported protocol for secp256k1: %d", protocol)
	}
}

// verifySecp256k1ECDSA verifies ECDSA signature on secp256k1 using btcec
func verifySecp256k1ECDSA(message []byte, pubKey *btcec.PublicKey, signature []byte) (bool, error) {
	// For Ethereum-style signatures (65 bytes), use Keccak-256
	// For other signatures, use SHA-256
	var messageHash []byte
	
	if len(signature) == 65 {
		// Ethereum uses Keccak-256 for message hashing
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(message)
		messageHash = hasher.Sum(nil)
	} else {
		// Standard uses SHA-256
		hasher := sha256.New()
		hasher.Write(message)
		messageHash = hasher.Sum(nil)
	}

	// Check signature format
	switch len(signature) {
	case 65:
		// Ethereum-style signature with recovery id: r(32) + s(32) + v(1)
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:64])
		// Recovery id is signature[64], but we don't need it for verification
		
		// Verify using standard ecdsa
		ecdsaPubKey := (*ecdsa.PublicKey)(pubKey.ToECDSA())
		return ecdsa.Verify(ecdsaPubKey, messageHash, r, s), nil
		
	case 64:
		// Raw r,s format without recovery id
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		
		// Verify using standard ecdsa
		ecdsaPubKey := (*ecdsa.PublicKey)(pubKey.ToECDSA())
		return ecdsa.Verify(ecdsaPubKey, messageHash, r, s), nil
		
	default:
		// Try parsing as DER format
		sig, err := btcecdsa.ParseSignature(signature)
		if err != nil {
			return false, fmt.Errorf("failed to parse ECDSA signature (length %d): %v", len(signature), err)
		}
		// Verify the signature
		return sig.Verify(messageHash, pubKey), nil
	}
}

// verifySecp256k1Schnorr verifies Schnorr signature on secp256k1 using btcec
func verifySecp256k1Schnorr(message []byte, pubKey *btcec.PublicKey, signature []byte) (bool, error) {
	// Parse Schnorr signature (64 bytes)
	if len(signature) != schnorr.SignatureSize {
		return false, fmt.Errorf("invalid Schnorr signature size: expected %d, got %d", schnorr.SignatureSize, len(signature))
	}

	// Parse the signature
	sig, err := schnorr.ParseSignature(signature)
	if err != nil {
		return false, fmt.Errorf("failed to parse Schnorr signature: %v", err)
	}

	// Hash the message with SHA256 for Schnorr
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Verify the signature
	return sig.Verify(messageHash, pubKey), nil
}


// verifySecp256r1 verifies signatures on secp256r1 curve (NIST P-256)
func verifySecp256r1(message, publicKeyBytes, signature []byte, protocol uint32) (bool, error) {
	// Parse public key for secp256r1 (P-256)
	x, y, err := parseSecp256r1PublicKey(publicKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse secp256r1 public key: %v", err)
	}

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Verify the point is on the curve
	if !elliptic.P256().IsOnCurve(x, y) {
		return false, fmt.Errorf("public key point is not on secp256r1 curve")
	}

	switch protocol {
	case constants.ProtocolECDSA:
		return verifyP256ECDSA(message, publicKey, signature)
	case constants.ProtocolSchnorr:
		return verifyP256Schnorr(message, publicKey, signature)
	default:
		return false, fmt.Errorf("unsupported protocol for secp256r1: %d", protocol)
	}
}

// verifyP256ECDSA verifies ECDSA signature on P-256
func verifyP256ECDSA(message []byte, publicKey *ecdsa.PublicKey, signature []byte) (bool, error) {
	// Hash the message with SHA256
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Parse ECDSA signature (DER format or raw r,s format)
	var ecdsaSig ECDSASignature

	// Try to parse as ASN.1 DER format first
	if _, err := asn1.Unmarshal(signature, &ecdsaSig); err != nil {
		// If DER parsing fails, try to parse as raw r,s format
		if len(signature) != 64 {
			return false, fmt.Errorf("invalid signature length: expected 64 bytes for raw format or valid DER encoding")
		}

		ecdsaSig.R = new(big.Int).SetBytes(signature[:32])
		ecdsaSig.S = new(big.Int).SetBytes(signature[32:])
	}

	// Verify r and s are in valid range
	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		return false, fmt.Errorf("invalid signature: r or s is zero or negative")
	}

	// Get curve order
	curveOrder := publicKey.Curve.Params().N
	if ecdsaSig.R.Cmp(curveOrder) >= 0 || ecdsaSig.S.Cmp(curveOrder) >= 0 {
		return false, fmt.Errorf("invalid signature: r or s is >= curve order")
	}

	// Verify the ECDSA signature
	return ecdsa.Verify(publicKey, messageHash, ecdsaSig.R, ecdsaSig.S), nil
}

// verifyP256Schnorr verifies Schnorr signature on P-256
// Note: This is a simplified implementation as Schnorr is not commonly used with P-256
func verifyP256Schnorr(message []byte, publicKey *ecdsa.PublicKey, signature []byte) (bool, error) {
	if len(signature) != 64 {
		return false, fmt.Errorf("invalid Schnorr signature length: expected 64, got %d", len(signature))
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Verify r and s are in valid range
	curveOrder := publicKey.Curve.Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false, fmt.Errorf("invalid Schnorr signature: r or s is zero or negative")
	}
	if r.Cmp(curveOrder) >= 0 || s.Cmp(curveOrder) >= 0 {
		return false, fmt.Errorf("invalid Schnorr signature: r or s is >= curve order")
	}

	// Hash: e = H(r || P.x || message)
	hasher := sha256.New()
	hasher.Write(r.Bytes())
	hasher.Write(publicKey.X.Bytes())
	hasher.Write(message)
	e := new(big.Int).SetBytes(hasher.Sum(nil))
	e.Mod(e, curveOrder)

	// Verify: R = s*G - e*P
	// Calculate s*G
	sGx, sGy := publicKey.Curve.ScalarBaseMult(s.Bytes())
	
	// Calculate e*P
	ePx, ePy := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, e.Bytes())
	
	// Calculate R = s*G - e*P = s*G + (-e*P)
	// Negate ePy to get -e*P
	negEPy := new(big.Int).Sub(publicKey.Curve.Params().P, ePy)
	
	// Add the points
	Rx, _ := publicKey.Curve.Add(sGx, sGy, ePx, negEPy)
	
	// Verify that R.x == r
	return Rx.Cmp(r) == 0, nil
}

// parseSecp256r1PublicKey parses a secp256r1 (P-256) public key from bytes
func parseSecp256r1PublicKey(publicKeyBytes []byte) (*big.Int, *big.Int, error) {
	switch len(publicKeyBytes) {
	case 65:
		// Uncompressed format: 0x04 + X + Y
		if publicKeyBytes[0] != 0x04 {
			return nil, nil, fmt.Errorf("invalid uncompressed public key prefix: expected 0x04, got 0x%02x", publicKeyBytes[0])
		}
		x := new(big.Int).SetBytes(publicKeyBytes[1:33])
		y := new(big.Int).SetBytes(publicKeyBytes[33:65])
		return x, y, nil

	case 33:
		// Compressed format: 0x02/0x03 + X
		if publicKeyBytes[0] != 0x02 && publicKeyBytes[0] != 0x03 {
			return nil, nil, fmt.Errorf("invalid compressed public key prefix: expected 0x02 or 0x03, got 0x%02x", publicKeyBytes[0])
		}
		
		// Use elliptic.UnmarshalCompressed for P-256
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBytes)
		if x == nil {
			return nil, nil, fmt.Errorf("failed to unmarshal compressed P-256 public key")
		}
		
		return x, y, nil

	case 64:
		// Raw format: X + Y
		x := new(big.Int).SetBytes(publicKeyBytes[:32])
		y := new(big.Int).SetBytes(publicKeyBytes[32:64])
		return x, y, nil

	default:
		return nil, nil, fmt.Errorf("unsupported secp256r1 public key format: length %d", len(publicKeyBytes))
	}
}