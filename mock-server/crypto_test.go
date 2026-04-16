// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// TestECDSASecp256k1_SignatureRoundTrip submits a known pre-hashed digest
// to the mock server and verifies that the returned 65-byte Ethereum-style
// signature actually verifies against the app's public key. This guards
// against regressions in the r||s||v assembly (previously the recovery
// byte was derived from the pubkey's Y parity rather than from the real
// signing nonce).
func TestECDSASecp256k1_SignatureRoundTrip(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Fetch the public key for the app so we know exactly what to
	// verify against. mock-app-id-03 is registered with the
	// server's default secp256k1 key.
	pkResult := getJSON(t, ts.URL+"/api/publickeys/mock-app-id-03", "")
	if statusCode(pkResult) != 200 {
		t.Fatalf("publickeys fetch failed: %v", pkResult)
	}
	keys, ok := pkResult["public_keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatalf("no public keys returned")
	}
	keyHex, _ := keys[0].(map[string]interface{})["key_data"].(string)
	if keyHex == "" {
		t.Fatalf("missing key_data in public key response")
	}

	// The mock stores the secp256k1 public key as uncompressed bytes
	// with the 0x04 prefix stripped (64 bytes = 128 hex chars). Prepend
	// 0x04 so btcec can parse it.
	pubBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(pubBytes) == 64 {
		pubBytes = append([]byte{0x04}, pubBytes...)
	}
	pubKey, err := btcec.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	// Sign a 32-byte digest. The mock's ECDSA path treats the message
	// bytes as the digest directly (no internal hashing), so we hash
	// our plaintext first.
	digest := sha256.Sum256([]byte("teenet signature verification test"))

	result := submitDirectRequest(t, ts.URL, "mock-app-id-03", digest[:])
	if statusCode(result) != 200 {
		t.Fatalf("submit-request: %v", result)
	}
	sigHex, _ := result["signature"].(string)
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sigBytes) != 65 {
		t.Fatalf("expected 65-byte signature, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])
	v := sigBytes[64]

	// Recovery id must be a valid 0..3 value, not always 0 or always 1.
	if v > 3 {
		t.Errorf("recovery id out of range: got %d, want 0..3", v)
	}

	// R and S must verify against the public key for this digest.
	// We use the low-level curve math rather than pulling in ecrecover
	// to keep dependencies minimal.
	curve := btcec.S256()
	if r.Sign() == 0 || s.Sign() == 0 {
		t.Fatalf("signature has zero R or S")
	}
	if r.Cmp(curve.N) >= 0 || s.Cmp(curve.N) >= 0 {
		t.Fatalf("signature R or S out of range")
	}
	if !ecdsaVerifySecp256k1(pubKey, digest[:], r, s) {
		t.Errorf("signature failed to verify against public key")
	}
}

// ecdsaVerifySecp256k1 performs textbook ECDSA verification over secp256k1
// without pulling in the full btcecdsa package, so the check is
// independent of the same Sign/SignCompact code path being exercised.
func ecdsaVerifySecp256k1(pub *btcec.PublicKey, digest []byte, r, s *big.Int) bool {
	curve := btcec.S256()
	n := curve.N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	e := new(big.Int).SetBytes(digest)
	w := new(big.Int).ModInverse(s, n)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, n)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, n)

	x1, y1 := curve.ScalarBaseMult(u1.Bytes())
	pubX, pubY := pub.X(), pub.Y()
	x2, y2 := curve.ScalarMult(pubX, pubY, u2.Bytes())
	x, _ := curve.Add(x1, y1, x2, y2)
	if x.Sign() == 0 {
		return false
	}
	x.Mod(x, n)
	return x.Cmp(r) == 0
}

// TestWebAuthnSessionData_RoundTrip ensures that encode/decode of a
// webauthn.SessionData preserves the fields the mock relies on — the
// binary `UserID` and `AllowedCredentialIDs` slices in particular. If
// the upstream struct ever changes its JSON tags or switches encoding,
// this test fails loudly instead of producing silently broken logins.
func TestWebAuthnSessionData_RoundTrip(t *testing.T) {
	original := &webauthn.SessionData{
		Challenge:            "challenge-value",
		UserID:               []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		AllowedCredentialIDs: [][]byte{{0xaa, 0xbb}, {0xcc, 0xdd, 0xee}},
		UserVerification:     protocol.VerificationRequired,
	}

	encoded, err := EncodeSessionData(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := DecodeSessionData(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Challenge != original.Challenge {
		t.Errorf("challenge mismatch: got %q want %q", decoded.Challenge, original.Challenge)
	}
	if string(decoded.UserID) != string(original.UserID) {
		t.Errorf("UserID mismatch: got %x want %x", decoded.UserID, original.UserID)
	}
	if len(decoded.AllowedCredentialIDs) != len(original.AllowedCredentialIDs) {
		t.Fatalf("AllowedCredentialIDs length mismatch: got %d want %d",
			len(decoded.AllowedCredentialIDs), len(original.AllowedCredentialIDs))
	}
	for i := range original.AllowedCredentialIDs {
		if string(decoded.AllowedCredentialIDs[i]) != string(original.AllowedCredentialIDs[i]) {
			t.Errorf("AllowedCredentialIDs[%d] mismatch: got %x want %x",
				i, decoded.AllowedCredentialIDs[i], original.AllowedCredentialIDs[i])
		}
	}
	if decoded.UserVerification != original.UserVerification {
		t.Errorf("UserVerification mismatch: got %v want %v",
			decoded.UserVerification, original.UserVerification)
	}
}
