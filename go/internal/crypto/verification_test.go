// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
// -----------------------------------------------------------------------------

package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/crypto/sha3"
)

// extractRSFromSignature extracts r and s values from a DER-encoded ECDSA signature
func extractRSFromSignature(derSig []byte) (r, s []byte) {
	// DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
	if len(derSig) < 8 || derSig[0] != 0x30 {
		return nil, nil
	}

	// Skip 0x30 and length byte
	pos := 2

	// Read r
	if derSig[pos] != 0x02 {
		return nil, nil
	}
	pos++
	rLen := int(derSig[pos])
	pos++
	r = derSig[pos : pos+rLen]
	pos += rLen

	// Read s
	if derSig[pos] != 0x02 {
		return nil, nil
	}
	pos++
	sLen := int(derSig[pos])
	pos++
	s = derSig[pos : pos+sLen]

	// Remove leading zeros if present (for 33-byte values with 0x00 padding)
	if len(r) > 0 && r[0] == 0x00 {
		r = r[1:]
	}
	if len(s) > 0 && s[0] == 0x00 {
		s = s[1:]
	}

	return r, s
}

// TestVerifyED25519 tests ED25519 signature verification
func TestVerifyED25519(t *testing.T) {
	// Generate a key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key: %v", err)
	}

	message := []byte("test message for ED25519")

	// Sign the message
	signature := ed25519.Sign(privateKey, message)

	// Verify the signature
	valid, err := VerifySignature(message, publicKey, signature, ProtocolSchnorr, CurveED25519)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}

	// Test with invalid signature
	invalidSig := make([]byte, 64)
	copy(invalidSig, signature)
	invalidSig[0] ^= 0xFF // Flip some bits

	valid, err = VerifySignature(message, publicKey, invalidSig, ProtocolSchnorr, CurveED25519)
	if err != nil {
		t.Fatalf("VerifySignature with invalid sig failed: %v", err)
	}
	if valid {
		t.Error("Expected invalid signature to fail verification")
	}

	// Test with wrong message
	wrongMessage := []byte("wrong message")
	valid, err = VerifySignature(wrongMessage, publicKey, signature, ProtocolSchnorr, CurveED25519)
	if err != nil {
		t.Fatalf("VerifySignature with wrong message failed: %v", err)
	}
	if valid {
		t.Error("Expected verification with wrong message to fail")
	}
}

// TestVerifyED25519_InvalidKeySize tests ED25519 with invalid key size
func TestVerifyED25519_InvalidKeySize(t *testing.T) {
	message := []byte("test message")
	signature := make([]byte, 64)
	invalidPubKey := make([]byte, 16) // Wrong size

	_, err := VerifySignature(message, invalidPubKey, signature, ProtocolSchnorr, CurveED25519)
	if err == nil {
		t.Error("Expected error for invalid public key size")
	}
}

// TestVerifyED25519_InvalidSignatureSize tests ED25519 with invalid signature size
func TestVerifyED25519_InvalidSignatureSize(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("test message")
	invalidSig := make([]byte, 32) // Wrong size

	_, err := VerifySignature(message, publicKey, invalidSig, ProtocolSchnorr, CurveED25519)
	if err == nil {
		t.Error("Expected error for invalid signature size")
	}
}

// TestVerifySecp256k1ECDSA tests SECP256K1 ECDSA signature verification
func TestVerifySecp256k1ECDSA(t *testing.T) {
	// Generate a key pair using btcec
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate secp256k1 key: %v", err)
	}
	publicKey := privateKey.PubKey()

	message := []byte("test message for secp256k1 ECDSA")

	// Hash the message with SHA256
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Sign the message
	signature := btcecdsa.Sign(privateKey, messageHash)
	sigBytes := signature.Serialize() // DER format

	// Verify the signature
	valid, err := VerifySignature(message, publicKey.SerializeCompressed(), sigBytes, ProtocolECDSA, CurveSECP256K1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected signature to be valid")
	}
}

// TestVerifySecp256k1ECDSA_EthereumStyle tests Ethereum-style signatures (65 bytes with recovery id)
func TestVerifySecp256k1ECDSA_EthereumStyle(t *testing.T) {
	// Generate a key pair
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate secp256k1 key: %v", err)
	}
	publicKey := privateKey.PubKey()

	message := []byte("test message for Ethereum-style signature")

	// Hash with Keccak-256 (Ethereum style)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Sign the message
	signature := btcecdsa.Sign(privateKey, messageHash)

	// Extract r and s from DER signature
	r, s := extractRSFromSignature(signature.Serialize())

	// Pad r and s to 32 bytes
	ethSig := make([]byte, 65)
	copy(ethSig[32-len(r):32], r)
	copy(ethSig[64-len(s):64], s)
	ethSig[64] = 27 // Recovery ID (simplified)

	// Verify the signature
	valid, err := VerifySignature(message, publicKey.SerializeCompressed(), ethSig, ProtocolECDSA, CurveSECP256K1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected Ethereum-style signature to be valid")
	}
}

// TestVerifySecp256k1ECDSA_RawFormat tests raw r,s format (64 bytes)
func TestVerifySecp256k1ECDSA_RawFormat(t *testing.T) {
	// Generate a key pair
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate secp256k1 key: %v", err)
	}
	publicKey := privateKey.PubKey()

	message := []byte("test message for raw format")

	// Hash with SHA256
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Sign the message
	signature := btcecdsa.Sign(privateKey, messageHash)

	// Extract r and s from DER signature
	rBytes, sBytes := extractRSFromSignature(signature.Serialize())

	rawSig := make([]byte, 64)
	copy(rawSig[32-len(rBytes):32], rBytes)
	copy(rawSig[64-len(sBytes):64], sBytes)

	// Verify the signature
	valid, err := VerifySignature(message, publicKey.SerializeCompressed(), rawSig, ProtocolECDSA, CurveSECP256K1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected raw format signature to be valid")
	}
}

// TestVerifySecp256k1Schnorr tests SECP256K1 Schnorr signature verification
func TestVerifySecp256k1Schnorr(t *testing.T) {
	// Generate a key pair
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate secp256k1 key: %v", err)
	}
	publicKey := privateKey.PubKey()

	message := []byte("test message for secp256k1 Schnorr")

	// Hash the message with SHA256
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Sign with Schnorr
	signature, err := schnorr.Sign(privateKey, messageHash)
	if err != nil {
		t.Fatalf("Failed to sign with Schnorr: %v", err)
	}
	sigBytes := signature.Serialize()

	// Verify the signature
	valid, err := VerifySignature(message, publicKey.SerializeCompressed(), sigBytes, ProtocolSchnorr, CurveSECP256K1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected Schnorr signature to be valid")
	}
}

// TestVerifySecp256k1_UncompressedPubKey tests with uncompressed public key (65 bytes)
func TestVerifySecp256k1_UncompressedPubKey(t *testing.T) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	publicKey := privateKey.PubKey()

	message := []byte("test with uncompressed pubkey")

	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	signature := btcecdsa.Sign(privateKey, messageHash)

	// Use uncompressed public key (65 bytes)
	valid, err := VerifySignature(message, publicKey.SerializeUncompressed(), signature.Serialize(), ProtocolECDSA, CurveSECP256K1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected signature with uncompressed pubkey to be valid")
	}
}

// TestVerifySecp256k1_RawPubKey tests with raw public key (64 bytes, no prefix)
func TestVerifySecp256k1_RawPubKey(t *testing.T) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	publicKey := privateKey.PubKey()

	message := []byte("test with raw pubkey")

	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	signature := btcecdsa.Sign(privateKey, messageHash)

	// Use raw public key (64 bytes - without 0x04 prefix)
	uncompressed := publicKey.SerializeUncompressed()
	rawPubKey := uncompressed[1:] // Remove 0x04 prefix

	valid, err := VerifySignature(message, rawPubKey, signature.Serialize(), ProtocolECDSA, CurveSECP256K1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected signature with raw pubkey to be valid")
	}
}

// TestVerifySecp256r1ECDSA tests SECP256R1 (P-256) ECDSA signature verification
func TestVerifySecp256r1ECDSA(t *testing.T) {
	// Generate a P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}

	message := []byte("test message for secp256r1 ECDSA")

	// Hash the message with SHA256
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Sign the message
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, messageHash)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Create 64-byte raw signature
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	signature := make([]byte, 64)
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Serialize public key in uncompressed format
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)

	// Verify the signature
	valid, err := VerifySignature(message, pubKeyBytes, signature, ProtocolECDSA, CurveSECP256R1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected P-256 ECDSA signature to be valid")
	}
}

// TestVerifySecp256r1ECDSA_RawPubKey tests P-256 with raw public key (64 bytes)
func TestVerifySecp256r1ECDSA_RawPubKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}

	message := []byte("test with raw P-256 pubkey")

	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, messageHash)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	signature := make([]byte, 64)
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Use raw public key (64 bytes - X + Y without prefix)
	xBytes := privateKey.X.Bytes()
	yBytes := privateKey.Y.Bytes()
	rawPubKey := make([]byte, 64)
	copy(rawPubKey[32-len(xBytes):32], xBytes)
	copy(rawPubKey[64-len(yBytes):64], yBytes)

	valid, err := VerifySignature(message, rawPubKey, signature, ProtocolECDSA, CurveSECP256R1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected P-256 signature with raw pubkey to be valid")
	}
}

// TestVerifySecp256r1Schnorr tests SECP256R1 (P-256) Schnorr signature verification
func TestVerifySecp256r1Schnorr(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}

	message := []byte("test message for P-256 Schnorr")

	// Generate a simple Schnorr signature for P-256
	// This is a simplified implementation matching the verification logic
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// R = k*G
	Rx := k.X

	// e = H(R.x || P.x || message)
	curveOrder := elliptic.P256().Params().N
	hasher := sha256.New()
	hasher.Write(Rx.Bytes())
	hasher.Write(privateKey.X.Bytes())
	hasher.Write(message)
	e := new(big.Int).SetBytes(hasher.Sum(nil))
	e.Mod(e, curveOrder)

	// s = k + e*x (mod n)
	s := new(big.Int).Mul(e, privateKey.D)
	s.Add(s, k.D)
	s.Mod(s, curveOrder)

	// Create 64-byte signature: r(32) + s(32)
	rBytes := Rx.Bytes()
	sBytes := s.Bytes()
	signature := make([]byte, 64)
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Serialize public key
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)

	// Verify the signature
	valid, err := VerifySignature(message, pubKeyBytes, signature, ProtocolSchnorr, CurveSECP256R1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected P-256 Schnorr signature to be valid")
	}
}

// TestVerifyHMACSHA256 tests HMAC-SHA256 verification
func TestVerifyHMACSHA256(t *testing.T) {
	secret := []byte("test-secret-key")
	message := []byte("test message for HMAC")

	// Compute HMAC
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	// Verify
	valid, err := VerifyHMACSHA256(message, secret, expectedMAC)
	if err != nil {
		t.Fatalf("VerifyHMACSHA256 failed: %v", err)
	}
	if !valid {
		t.Error("Expected HMAC to be valid")
	}

	// Test with wrong signature
	wrongMAC := make([]byte, len(expectedMAC))
	copy(wrongMAC, expectedMAC)
	wrongMAC[0] ^= 0xFF

	valid, err = VerifyHMACSHA256(message, secret, wrongMAC)
	if err != nil {
		t.Fatalf("VerifyHMACSHA256 failed: %v", err)
	}
	if valid {
		t.Error("Expected wrong HMAC to be invalid")
	}

	// Test with wrong secret
	wrongSecret := []byte("wrong-secret")
	valid, err = VerifyHMACSHA256(message, wrongSecret, expectedMAC)
	if err != nil {
		t.Fatalf("VerifyHMACSHA256 failed: %v", err)
	}
	if valid {
		t.Error("Expected HMAC with wrong secret to be invalid")
	}
}

// TestNormalizeString tests case normalization
func TestNormalizeString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ECDSA", "ecdsa"},
		{"Schnorr", "schnorr"},
		{"ED25519", "ed25519"},
		{"SECP256K1", "secp256k1"},
		{"secp256r1", "secp256r1"},
		{"P256", "p256"},
	}

	for _, tt := range tests {
		result := normalizeString(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeString(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

// TestUnsupportedCurve tests error handling for unsupported curves
func TestUnsupportedCurve(t *testing.T) {
	_, err := VerifySignature([]byte("test"), []byte("key"), []byte("sig"), "ecdsa", "unsupported")
	if err == nil {
		t.Error("Expected error for unsupported curve")
	}
}

// TestUnsupportedProtocol tests error handling for unsupported protocols
func TestUnsupportedProtocol(t *testing.T) {
	privateKey, _ := btcec.NewPrivateKey()
	pubKey := privateKey.PubKey().SerializeCompressed()

	_, err := VerifySignature([]byte("test"), pubKey, []byte("sig"), "unsupported", CurveSECP256K1)
	if err == nil {
		t.Error("Expected error for unsupported protocol on secp256k1")
	}
}

// TestParseSecp256r1PublicKey tests P-256 public key parsing
func TestParseSecp256r1PublicKey(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Test uncompressed format (65 bytes)
	uncompressed := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)
	x, y, err := parseSecp256r1PublicKey(uncompressed)
	if err != nil {
		t.Fatalf("Failed to parse uncompressed P-256 key: %v", err)
	}
	if x.Cmp(privateKey.X) != 0 || y.Cmp(privateKey.Y) != 0 {
		t.Error("Parsed key doesn't match original")
	}

	// Test compressed format (33 bytes)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), privateKey.X, privateKey.Y)
	x, y, err = parseSecp256r1PublicKey(compressed)
	if err != nil {
		t.Fatalf("Failed to parse compressed P-256 key: %v", err)
	}
	if x.Cmp(privateKey.X) != 0 || y.Cmp(privateKey.Y) != 0 {
		t.Error("Parsed compressed key doesn't match original")
	}

	// Test raw format (64 bytes)
	xBytes := privateKey.X.Bytes()
	yBytes := privateKey.Y.Bytes()
	raw := make([]byte, 64)
	copy(raw[32-len(xBytes):32], xBytes)
	copy(raw[64-len(yBytes):64], yBytes)
	x, y, err = parseSecp256r1PublicKey(raw)
	if err != nil {
		t.Fatalf("Failed to parse raw P-256 key: %v", err)
	}
	if x.Cmp(privateKey.X) != 0 || y.Cmp(privateKey.Y) != 0 {
		t.Error("Parsed raw key doesn't match original")
	}

	// Test invalid length
	_, _, err = parseSecp256r1PublicKey([]byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for invalid key length")
	}

	// Test invalid uncompressed prefix
	invalidUncompressed := make([]byte, 65)
	invalidUncompressed[0] = 0x05 // Wrong prefix
	_, _, err = parseSecp256r1PublicKey(invalidUncompressed)
	if err == nil {
		t.Error("Expected error for invalid uncompressed prefix")
	}

	// Test invalid compressed prefix
	invalidCompressed := make([]byte, 33)
	invalidCompressed[0] = 0x05 // Wrong prefix
	_, _, err = parseSecp256r1PublicKey(invalidCompressed)
	if err == nil {
		t.Error("Expected error for invalid compressed prefix")
	}
}

// TestCaseInsensitiveProtocolAndCurve tests that protocol and curve are case-insensitive
func TestCaseInsensitiveProtocolAndCurve(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("case insensitive test")
	signature := ed25519.Sign(privateKey, message)

	// Test various case combinations
	cases := []struct {
		protocol string
		curve    string
	}{
		{"SCHNORR", "ED25519"},
		{"schnorr", "ed25519"},
		{"Schnorr", "Ed25519"},
		{"ECDSA", "ED25519"}, // Protocol is ignored for ED25519
	}

	for _, tc := range cases {
		valid, err := VerifySignature(message, publicKey, signature, tc.protocol, tc.curve)
		if err != nil {
			t.Errorf("VerifySignature with protocol=%s, curve=%s failed: %v", tc.protocol, tc.curve, err)
		}
		if !valid {
			t.Errorf("Expected valid signature with protocol=%s, curve=%s", tc.protocol, tc.curve)
		}
	}
}

// Benchmark tests
func BenchmarkVerifyED25519(b *testing.B) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("benchmark message")
	signature := ed25519.Sign(privateKey, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifySignature(message, publicKey, signature, ProtocolSchnorr, CurveED25519)
	}
}

func BenchmarkVerifySecp256k1ECDSA(b *testing.B) {
	privateKey, _ := btcec.NewPrivateKey()
	publicKey := privateKey.PubKey()
	message := []byte("benchmark message")

	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	signature := btcecdsa.Sign(privateKey, messageHash)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifySignature(message, publicKey.SerializeCompressed(), signature.Serialize(), ProtocolECDSA, CurveSECP256K1)
	}
}

func BenchmarkVerifySecp256k1Schnorr(b *testing.B) {
	privateKey, _ := btcec.NewPrivateKey()
	publicKey := privateKey.PubKey()
	message := []byte("benchmark message")

	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	signature, _ := schnorr.Sign(privateKey, messageHash)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifySignature(message, publicKey.SerializeCompressed(), signature.Serialize(), ProtocolSchnorr, CurveSECP256K1)
	}
}

func BenchmarkVerifyHMACSHA256(b *testing.B) {
	secret := []byte("benchmark-secret")
	message := []byte("benchmark message")

	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	signature := mac.Sum(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyHMACSHA256(message, secret, signature)
	}
}

// Test vectors from known sources
func TestED25519_KnownVector(t *testing.T) {
	// Test vector from RFC 8032
	privateKeyHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	publicKeyHex := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	message := []byte("")
	expectedSigHex := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

	privateKeyBytes, _ := hex.DecodeString(privateKeyHex)
	publicKeyBytes, _ := hex.DecodeString(publicKeyHex)
	expectedSig, _ := hex.DecodeString(expectedSigHex)

	// Construct full private key (seed + public key)
	fullPrivateKey := make([]byte, 64)
	copy(fullPrivateKey[:32], privateKeyBytes)
	copy(fullPrivateKey[32:], publicKeyBytes)

	// Sign and verify
	signature := ed25519.Sign(ed25519.PrivateKey(fullPrivateKey), message)

	if hex.EncodeToString(signature) != expectedSigHex {
		t.Errorf("Signature mismatch: got %s, expected %s", hex.EncodeToString(signature), expectedSigHex)
	}

	valid, err := VerifySignature(message, publicKeyBytes, expectedSig, ProtocolSchnorr, CurveED25519)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Error("Expected RFC 8032 test vector to verify")
	}
}
