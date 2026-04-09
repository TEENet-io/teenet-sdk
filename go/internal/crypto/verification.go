// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

// Package crypto provides signature verification for TEENet SDK.
package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Protocol constants
const (
	ProtocolECDSA   = "ecdsa"
	ProtocolSchnorr = "schnorr"
)

// Curve constants
const (
	CurveED25519   = "ed25519"
	CurveSECP256K1 = "secp256k1"
	CurveSECP256R1 = "secp256r1"
	CurveP256      = "p256"
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
func VerifySignature(message, publicKey, signature []byte, protocolStr, curveStr string) (bool, error) {
	// Normalize to lowercase for case-insensitive comparison
	protocol := strings.ToLower(protocolStr)
	curve := strings.ToLower(curveStr)

	switch curve {
	case CurveED25519:
		return verifyED25519(message, publicKey, signature)
	case CurveSECP256K1:
		return verifySecp256k1(message, publicKey, signature, protocol)
	case CurveSECP256R1, CurveP256:
		return verifySecp256r1(message, publicKey, signature, protocol)
	default:
		return false, fmt.Errorf("unsupported curve: %s (supported: %s, %s, %s)", curveStr, CurveED25519, CurveSECP256K1, CurveSECP256R1)
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
func verifySecp256k1(message, publicKeyBytes, signature []byte, protocol string) (bool, error) {
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
	case ProtocolECDSA:
		return verifySecp256k1ECDSA(message, pubKey, signature)
	case ProtocolSchnorr:
		return verifySecp256k1Schnorr(message, pubKey, signature)
	default:
		return false, fmt.Errorf("unsupported protocol for secp256k1: %s (supported: %s, %s)", protocol, ProtocolECDSA, ProtocolSchnorr)
	}
}

// verifySecp256k1ECDSA verifies ECDSA signature on secp256k1 using btcec.
//
// No hashing is performed here. The TEE-DAO does NOT hash messages before
// signing for secp256k1 ECDSA (Ethereum). The caller must pass the
// pre-hashed message digest (e.g. a 32-byte Keccak-256 or SHA-256 hash).
// Hashing is the caller's responsibility — this prevents algorithm-confusion
// attacks where the verifier's hash choice depends on the signature format.
func verifySecp256k1ECDSA(messageHash []byte, pubKey *btcec.PublicKey, signature []byte) (bool, error) {
	ecdsaPubKey := (*ecdsa.PublicKey)(pubKey.ToECDSA())

	switch len(signature) {
	case 65:
		// 65-byte format: r(32) || s(32) || v(1) — recovery id v is not needed for verification.
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:64])

		// Enforce low-S normalization to reject malleable signatures (matching 64-byte branch).
		halfOrder := new(big.Int).Rsh(ecdsaPubKey.Curve.Params().N, 1)
		if s.Cmp(halfOrder) > 0 {
			return false, fmt.Errorf("non-canonical ECDSA signature: s exceeds half the curve order (high-S)")
		}

		return ecdsa.Verify(ecdsaPubKey, messageHash, r, s), nil

	case 64:
		// 64-byte canonical format: r(32) || s(32).
		// Enforce low-S normalization to reject malleable signatures.
		// Bitcoin and many protocols require s <= n/2; accepting high-S signatures
		// allows an attacker to produce a second valid signature for the same message.
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])

		halfOrder := new(big.Int).Rsh(ecdsaPubKey.Curve.Params().N, 1)
		if s.Cmp(halfOrder) > 0 {
			return false, fmt.Errorf("non-canonical ECDSA signature: s exceeds half the curve order (high-S)")
		}

		return ecdsa.Verify(ecdsaPubKey, messageHash, r, s), nil

	default:
		// DER-encoded format.
		sig, err := btcecdsa.ParseSignature(signature)
		if err != nil {
			return false, fmt.Errorf("failed to parse ECDSA signature (length %d): %v", len(signature), err)
		}

		// Enforce low-S normalization on DER signatures (matching 64/65-byte branches).
		// sig.S() returns a ModNScalar; convert to *big.Int for comparison.
		sScalar := sig.S()
		sBytes := sScalar.Bytes()
		s := new(big.Int).SetBytes(sBytes[:])
		halfOrder := new(big.Int).Rsh(ecdsaPubKey.Curve.Params().N, 1)
		if s.Cmp(halfOrder) > 0 {
			return false, fmt.Errorf("non-canonical ECDSA signature: s exceeds half the curve order (high-S)")
		}

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
func verifySecp256r1(message, publicKeyBytes, signature []byte, protocol string) (bool, error) {
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
	case ProtocolECDSA:
		return verifyP256ECDSA(message, publicKey, signature)
	case ProtocolSchnorr:
		return verifyP256Schnorr(message, publicKey, signature)
	default:
		return false, fmt.Errorf("unsupported protocol for secp256r1: %s (supported: %s, %s)", protocol, ProtocolECDSA, ProtocolSchnorr)
	}
}

// verifyP256ECDSA verifies ECDSA signature on P-256
func verifyP256ECDSA(messageHash []byte, publicKey *ecdsa.PublicKey, signature []byte) (bool, error) {

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

	// Enforce low-S normalization to reject malleable signatures (matching secp256k1 behavior).
	halfOrder := new(big.Int).Rsh(curveOrder, 1)
	if ecdsaSig.S.Cmp(halfOrder) > 0 {
		return false, fmt.Errorf("non-canonical ECDSA signature: s exceeds half the curve order (high-S)")
	}

	// Verify the ECDSA signature
	return ecdsa.Verify(publicKey, messageHash, ecdsaSig.R, ecdsaSig.S), nil
}

// verifyP256Schnorr verifies a TEENet-internal Schnorr signature on P-256 (secp256r1).
//
// Protocol definition (must match the TEE-DAO signer exactly):
//
//	signature = (r, s), each 32 bytes
//	challenge  e = SHA-256( r || P.x || message )  mod n
//	valid if   (s·G - e·P).x == r
//
// NOTE: This is NOT BIP-340 (which is defined only for secp256k1 and uses tagged
// hashes). This is a TEENet-proprietary Schnorr variant for P-256. Do not use it
// to verify signatures produced by other Schnorr implementations.
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

	// Hash: e = H(r || P.x || message) — fixed 32-byte big-endian encoding
	rBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	pxBytes := make([]byte, 32)
	publicKey.X.FillBytes(pxBytes)

	hasher := sha256.New()
	hasher.Write(rBytes)
	hasher.Write(pxBytes)
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
	// Note: if sG - eP is the point at infinity, Rx will be 0.
	// This is safe because we already validated r > 0 above, so Rx == 0 won't match.

	// Verify that R.x == r
	return Rx.Cmp(r) == 0, nil
}

// VerifyHMACSHA256 verifies an HMAC-SHA256 signature
//
// This function verifies that the given signature was produced by signing
// the message with the provided secret using HMAC-SHA256 algorithm.
//
// Parameters:
//   - message: The original message that was signed
//   - secret: The secret key used for HMAC signing
//   - signature: The signature to verify (raw bytes, not hex encoded)
//
// Returns:
//   - bool: true if the signature is valid, false otherwise
//   - error: nil (this function doesn't return errors, but keeps the signature
//     for consistency with other verification functions)
func VerifyHMACSHA256(message, secret, signature []byte) (bool, error) {
	// Compute expected HMAC
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	// Use constant-time comparison to prevent timing attacks
	return hmac.Equal(signature, expectedMAC), nil
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
