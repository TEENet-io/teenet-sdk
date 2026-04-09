// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Tests for crypto.ts — verifySignature() and verifyHMACSHA256().
//
// Strategy: use @noble/curves to generate valid key-pairs and signatures
// at test-time (deterministic private keys so results are reproducible),
// then assert that the SDK's verification functions agree.
//
// Run via: npm test  (build + node --test tests)

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// Noble primitive libraries (installed as production deps)
const { ed25519 }                          = require('../node_modules/@noble/curves/ed25519');
const { secp256k1, schnorr: k1Schnorr }   = require('../node_modules/@noble/curves/secp256k1');
const { p256 }                             = require('../node_modules/@noble/curves/p256');
const { sha256 }                           = require('../node_modules/@noble/hashes/sha256');
const { hmac }                             = require('../node_modules/@noble/hashes/hmac');

// SDK functions under test
const { verifySignature, verifyHMACSHA256 } = require('../dist/index.js');

// ─── Deterministic private keys (test-only) ──────────────────────────────────
//
// Using fixed byte arrays keeps the test vectors constant across runs.
// These are NOT secret — they exist solely to make tests reproducible.

const ED25519_PRIV = Buffer.from(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55', 'hex'
);
const K1_PRIV = Buffer.from(
  'f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315', 'hex'
);
const P256_PRIV = Buffer.from(
  'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', 'hex'
);

const MESSAGE = Buffer.from('TEENet test message — 2026');

// ─── ED25519 ─────────────────────────────────────────────────────────────────

test('verifySignature: valid ED25519 signature returns true', () => {
  const pubKey = Buffer.from(ed25519.getPublicKey(ED25519_PRIV));
  const sig    = Buffer.from(ed25519.sign(MESSAGE, ED25519_PRIV));

  const ok = verifySignature(MESSAGE, pubKey, sig, 'schnorr', 'ed25519');
  assert.equal(ok, true);
});

test('verifySignature: ED25519 rejects wrong message', () => {
  const pubKey  = Buffer.from(ed25519.getPublicKey(ED25519_PRIV));
  const sig     = Buffer.from(ed25519.sign(MESSAGE, ED25519_PRIV));
  const wrongMsg = Buffer.from('wrong message');

  const ok = verifySignature(wrongMsg, pubKey, sig, 'schnorr', 'ed25519');
  assert.equal(ok, false);
});

test('verifySignature: ED25519 rejects tampered signature', () => {
  const pubKey = Buffer.from(ed25519.getPublicKey(ED25519_PRIV));
  const sig    = Buffer.from(ed25519.sign(MESSAGE, ED25519_PRIV));
  // Flip a bit in the signature
  sig[0] ^= 0xff;

  const ok = verifySignature(MESSAGE, pubKey, sig, 'schnorr', 'ed25519');
  assert.equal(ok, false);
});

test('verifySignature: ED25519 throws for wrong public key size', () => {
  const badPub = Buffer.alloc(16, 0x01); // Must be 32 bytes
  const sig    = Buffer.from(ed25519.sign(MESSAGE, ED25519_PRIV));

  assert.throws(
    () => verifySignature(MESSAGE, badPub, sig, 'schnorr', 'ed25519'),
    /Invalid ED25519 public key size/
  );
});

test('verifySignature: ED25519 throws for wrong signature size', () => {
  const pubKey = Buffer.from(ed25519.getPublicKey(ED25519_PRIV));
  const badSig = Buffer.alloc(32, 0x01); // Must be 64 bytes

  assert.throws(
    () => verifySignature(MESSAGE, pubKey, badSig, 'schnorr', 'ed25519'),
    /Invalid ED25519 signature size/
  );
});

// ─── secp256k1 ECDSA ─────────────────────────────────────────────────────────
//
// The SDK docs explicitly state: NO hashing is done internally for
// secp256k1 ECDSA.  The caller must pass a pre-hashed digest.

test('verifySignature: valid secp256k1 ECDSA returns true (uncompressed pubkey)', () => {
  const pubKey  = Buffer.from(secp256k1.getPublicKey(K1_PRIV, false)); // 65 bytes uncompressed
  const msgHash = Buffer.from(sha256(MESSAGE));
  const sig     = Buffer.from(secp256k1.sign(msgHash, K1_PRIV).toCompactRawBytes());

  const ok = verifySignature(msgHash, pubKey, sig, 'ecdsa', 'secp256k1');
  assert.equal(ok, true);
});

test('verifySignature: secp256k1 ECDSA works with compressed pubkey', () => {
  const pubKey  = Buffer.from(secp256k1.getPublicKey(K1_PRIV, true)); // 33 bytes compressed
  const msgHash = Buffer.from(sha256(MESSAGE));
  const sig     = Buffer.from(secp256k1.sign(msgHash, K1_PRIV).toCompactRawBytes());

  const ok = verifySignature(msgHash, pubKey, sig, 'ecdsa', 'secp256k1');
  assert.equal(ok, true);
});

test('verifySignature: secp256k1 ECDSA rejects wrong hash', () => {
  const pubKey    = Buffer.from(secp256k1.getPublicKey(K1_PRIV, false));
  const msgHash   = Buffer.from(sha256(MESSAGE));
  const wrongHash = Buffer.from(sha256(Buffer.from('other')));
  const sig       = Buffer.from(secp256k1.sign(msgHash, K1_PRIV).toCompactRawBytes());

  const ok = verifySignature(wrongHash, pubKey, sig, 'ecdsa', 'secp256k1');
  assert.equal(ok, false);
});

test('verifySignature: secp256k1 ECDSA rejects high-S signature', () => {
  // Build a high-S signature by computing n - s
  const pubKey  = Buffer.from(secp256k1.getPublicKey(K1_PRIV, false));
  const msgHash = Buffer.from(sha256(MESSAGE));
  const sigObj  = secp256k1.sign(msgHash, K1_PRIV);

  const n = secp256k1.CURVE.n;
  const highS = n - sigObj.s; // force high-S
  const rHex  = sigObj.r.toString(16).padStart(64, '0');
  const sHex  = highS.toString(16).padStart(64, '0');
  const highSSig = Buffer.from(rHex + sHex, 'hex');

  // SDK rejects high-S signatures (matching Go SDK behavior)
  const ok = verifySignature(msgHash, pubKey, highSSig, 'ecdsa', 'secp256k1');
  assert.equal(ok, false);
});

test('verifySignature: secp256k1 ECDSA with raw 64-byte pubkey (no prefix)', () => {
  // Raw = 64 bytes (x || y) without 0x04 prefix
  const fullPub = secp256k1.getPublicKey(K1_PRIV, false); // 65 bytes
  const rawPub  = Buffer.from(fullPub.subarray(1)); // strip 0x04, 64 bytes

  const msgHash = Buffer.from(sha256(MESSAGE));
  const sig     = Buffer.from(secp256k1.sign(msgHash, K1_PRIV).toCompactRawBytes());

  const ok = verifySignature(msgHash, rawPub, sig, 'ecdsa', 'secp256k1');
  assert.equal(ok, true);
});

// ─── secp256k1 Schnorr (BIP-340) ─────────────────────────────────────────────
//
// The SDK sha256-hashes the message before Schnorr verification (matching
// the TEE-DAO behaviour).  The signature is produced against sha256(message).

test('verifySignature: valid secp256k1 Schnorr returns true', () => {
  // x-only public key (32 bytes) comes from the schnorr namespace
  const xOnlyPub = Buffer.from(k1Schnorr.getPublicKey(K1_PRIV)); // 32 bytes
  // Schnorr signature is over sha256(message)
  const msgHash  = Buffer.from(sha256(MESSAGE));
  const sig      = Buffer.from(k1Schnorr.sign(msgHash, K1_PRIV));

  // SDK accepts the raw 32-byte x-only public key as well as compressed keys.
  // Pass the x-only pub key; SDK will extract x-coord from compressed form
  // if given a compressed key. Here we construct a 33-byte compressed key
  // from the full point so the SDK can call ProjectivePoint.fromHex on it.
  const fullPub      = secp256k1.getPublicKey(K1_PRIV, true); // 33 bytes compressed
  const compressedPub = Buffer.from(fullPub);

  const ok = verifySignature(MESSAGE, compressedPub, sig, 'schnorr', 'secp256k1');
  assert.equal(ok, true);
});

test('verifySignature: secp256k1 Schnorr rejects wrong message', () => {
  const fullPub  = Buffer.from(secp256k1.getPublicKey(K1_PRIV, true));
  const msgHash  = Buffer.from(sha256(MESSAGE));
  const sig      = Buffer.from(k1Schnorr.sign(msgHash, K1_PRIV));
  const wrongMsg = Buffer.from('wrong message');

  const ok = verifySignature(wrongMsg, fullPub, sig, 'schnorr', 'secp256k1');
  assert.equal(ok, false);
});

test('verifySignature: secp256k1 Schnorr throws for wrong signature size', () => {
  const fullPub = Buffer.from(secp256k1.getPublicKey(K1_PRIV, true));
  const badSig  = Buffer.alloc(32); // Must be 64 bytes

  assert.throws(
    () => verifySignature(MESSAGE, fullPub, badSig, 'schnorr', 'secp256k1'),
    /Invalid Schnorr signature size/
  );
});

// ─── P-256 ECDSA ─────────────────────────────────────────────────────────────
//
// No internal hashing — caller must pass the pre-hashed message digest.

test('verifySignature: valid P-256 ECDSA returns true (uncompressed pubkey)', () => {
  const pubKey  = Buffer.from(p256.getPublicKey(P256_PRIV, false)); // 65 bytes
  const msgHash = Buffer.from(sha256(MESSAGE));
  const sig     = Buffer.from(p256.sign(msgHash, P256_PRIV).toCompactRawBytes());

  const ok = verifySignature(msgHash, pubKey, sig, 'ecdsa', 'secp256r1');
  assert.equal(ok, true);
});

test('verifySignature: P-256 ECDSA works with compressed pubkey', () => {
  const pubKey  = Buffer.from(p256.getPublicKey(P256_PRIV, true)); // 33 bytes
  const msgHash = Buffer.from(sha256(MESSAGE));
  const sig     = Buffer.from(p256.sign(msgHash, P256_PRIV).toCompactRawBytes());

  const ok = verifySignature(msgHash, pubKey, sig, 'ecdsa', 'secp256r1');
  assert.equal(ok, true);
});

test('verifySignature: P-256 ECDSA rejects tampered signature', () => {
  const pubKey  = Buffer.from(p256.getPublicKey(P256_PRIV, false));
  const msgHash = Buffer.from(sha256(MESSAGE));
  const sig     = Buffer.from(p256.sign(msgHash, P256_PRIV).toCompactRawBytes());
  sig[0] ^= 0xff; // tamper

  const ok = verifySignature(msgHash, pubKey, sig, 'ecdsa', 'secp256r1');
  assert.equal(ok, false);
});

test('verifySignature: P-256 ECDSA with raw 64-byte pubkey', () => {
  const fullPub = p256.getPublicKey(P256_PRIV, false); // 65 bytes
  const rawPub  = Buffer.from(fullPub.subarray(1));     // 64 bytes, strip 0x04

  const msgHash = Buffer.from(sha256(MESSAGE));
  const sig     = Buffer.from(p256.sign(msgHash, P256_PRIV).toCompactRawBytes());

  const ok = verifySignature(msgHash, rawPub, sig, 'ecdsa', 'secp256r1');
  assert.equal(ok, true);
});

// ─── Unsupported curve guard ──────────────────────────────────────────────────

test('verifySignature: throws for unsupported curve', () => {
  const pub = Buffer.alloc(32);
  const sig = Buffer.alloc(64);
  assert.throws(
    () => verifySignature(MESSAGE, pub, sig, 'ecdsa', 'bls12-381'),
    /Unsupported curve/
  );
});

// ─── Protocol and curve are case-insensitive ──────────────────────────────────

test('verifySignature: curve and protocol matching is case-insensitive', () => {
  const pubKey = Buffer.from(ed25519.getPublicKey(ED25519_PRIV));
  const sig    = Buffer.from(ed25519.sign(MESSAGE, ED25519_PRIV));

  // Mixed-case values should still work
  const ok = verifySignature(MESSAGE, pubKey, sig, 'Schnorr', 'ED25519');
  assert.equal(ok, true);
});

// ─── HMAC-SHA256 ──────────────────────────────────────────────────────────────

test('verifyHMACSHA256: valid HMAC returns true', () => {
  const secret = Buffer.from('my-secret-key-for-test');
  const mac    = Buffer.from(hmac(sha256, secret, MESSAGE));

  const ok = verifyHMACSHA256(MESSAGE, secret, mac);
  assert.equal(ok, true);
});

test('verifyHMACSHA256: wrong secret returns false', () => {
  const secret      = Buffer.from('correct-secret');
  const wrongSecret = Buffer.from('wrong-secret');
  const mac         = Buffer.from(hmac(sha256, secret, MESSAGE));

  const ok = verifyHMACSHA256(MESSAGE, wrongSecret, mac);
  assert.equal(ok, false);
});

test('verifyHMACSHA256: wrong message returns false', () => {
  const secret   = Buffer.from('my-secret-key');
  const mac      = Buffer.from(hmac(sha256, secret, MESSAGE));
  const wrongMsg = Buffer.from('different message');

  const ok = verifyHMACSHA256(wrongMsg, secret, mac);
  assert.equal(ok, false);
});

test('verifyHMACSHA256: tampered MAC returns false', () => {
  const secret = Buffer.from('my-secret-key');
  const mac    = Buffer.from(hmac(sha256, secret, MESSAGE));
  mac[0] ^= 0xff; // flip first byte

  const ok = verifyHMACSHA256(MESSAGE, secret, mac);
  assert.equal(ok, false);
});

test('verifyHMACSHA256: wrong-length MAC returns false', () => {
  const secret  = Buffer.from('my-secret-key');
  const shortMac = Buffer.alloc(16, 0xaa); // HMAC-SHA256 produces 32 bytes

  const ok = verifyHMACSHA256(MESSAGE, secret, shortMac);
  assert.equal(ok, false);
});

test('verifyHMACSHA256: empty message with correct HMAC returns true', () => {
  const secret  = Buffer.from('k');
  const emptyMsg = Buffer.alloc(0);
  const mac     = Buffer.from(hmac(sha256, secret, emptyMsg));

  const ok = verifyHMACSHA256(emptyMsg, secret, mac);
  assert.equal(ok, true);
});
